// Batch transfer queue on a real target: per-item states, retry, resumable
// .part downloads with remote sha256 verification, restart-on-change, the
// KiB/s read-loop rate limit, and SCP serialization on a degraded target.
//   1. four files where one is missing: 3 done, 1 failed; restore + retry done;
//   2. a big download cancelled mid-way keeps its .part, the retry resumes
//      (the item log shows the offset) and the final sha matches;
//   3. a remote file changed between attempts restarts, not resumes;
//   4. a rate-limited download takes at least bytes/rate seconds;
//   5. a local name that already exists is refused, never overwritten;
//   6. two staged uploads land in the remote directory;
//   7. the no-SFTP target serializes through SCP and restarts, saying so.
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-queue-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-sftp-queue", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-queue-"));
const localDir = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-queue-dl-"));
const checks = [];
let containerId, degradedId, sidecar;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const podman = (...args) => execFileSync("podman", [...args], { encoding: "utf8", windowsHide: true, timeout: 420_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const wslVm = (...args) => execFileSync("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000 }).replace(/\0/gu, "").trim();
function owned(id, label) {
  const current = JSON.parse(podman("inspect", id))[0];
  if (current.Id !== id || ![label, `/${label}`].includes(current.Name) ||
    current.HostConfig.Privileged || (current.Mounts ?? []).length !== 0) throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(containerId, name); return podman("exec", containerId, ...args); };
const onDegraded = (...args) => { owned(degradedId, `${name}-nosftp`); return podman("exec", degradedId, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { const hit = await fn(); if (hit) return hit; await sleep(100); } throw new Error(`Timed out: ${label}`); }
const remoteSha = (file) => onHost("sha256sum", file).split(/\s/u)[0];
const localSha = (file) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
async function pollQueue(binding, browserHandle) {
  return sidecar.call("sftp-browser.queue.poll", { bindingHandle: binding, browserHandle });
}
async function settleQueue(binding, browserHandle, timeout = 120_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const queue = await pollQueue(binding, browserHandle);
    if (queue === null) throw new Error("queue vanished");
    if (!queue.active) return queue;
    await sleep(250);
  }
  throw new Error("queue did not settle");
}

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const sshPort = 2226, degradedPort = 2227;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(containerId, name);
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client openssh-sftp-server netcat-openbsd coreutils >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  degradedId = podman("run", "-d", "--name", `${name}-nosftp`, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(degradedId, `${name}-nosftp`);
  onDegraded("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onDegraded("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onDegraded("sh", "-c", `dropbear -E -p ${degradedPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);
  await until(() => { try { onDegraded("nc", "-z", "127.0.0.1", String(degradedPort)); return true; } catch { return false; } }, "degraded dropbear listening", 30_000);

  // Fixture files: three small, one moved away (unreadable), one big for the
  // cancel window, one that will change between attempts.
  onHost("sh", "-c", "mkdir -p /opt/q && " +
    "printf 'alpha\n' > /opt/q/a.txt && printf 'beta\n' > /opt/q/b.txt && printf 'gamma\n' > /opt/q/c.txt && " +
    "printf 'missing\n' > /opt/q/missing.txt && mv /opt/q/missing.txt /opt/q/missing.away && " +
    "dd if=/dev/urandom of=/opt/q/big.bin bs=1M count=64 status=none && " +
    "printf 'version one\n' > /opt/q/changing.txt");
  onDegraded("sh", "-c", "mkdir -p /opt/q && printf 'd1\n' > /opt/q/d1.txt && printf 'd2\n' > /opt/q/d2.txt && printf 'dgone\n' > /opt/q/dghost.txt");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to the SFTP fixture", true);

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding });
  const optDir = browser.entries.find((e) => e.name === "opt");
  const optList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: optDir.entryHandle });
  const qDir = optList.entries.find((e) => e.name === "q");
  const qList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: qDir.entryHandle });
  const handleOf = (n) => qList.entries.find((e) => e.name === n)?.entryHandle;
  check("fixture files are listed", ["a.txt", "b.txt", "c.txt", "big.bin", "changing.txt"].every((n) => handleOf(n)));

  // 1. Four-file queue: a,b,c + a file moved away between the listing and
  //    the enqueue, so its item fails while the other three complete.
  onHost("sh", "-c", "printf 'gone soon\n' > /opt/q/ghost.txt");
  const qList2 = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: qDir.entryHandle });
  const ghostHandle = qList2.entries.find((e) => e.name === "ghost.txt")?.entryHandle;
  const handleOf2 = (n) => qList2.entries.find((e) => e.name === n)?.entryHandle;
  onHost("sh", "-c", "mv /opt/q/ghost.txt /opt/q/ghost.away");
  const first = await sidecar.call("sftp-browser.queue.download", {
    bindingHandle: binding, browserHandle: browser.browserHandle,
    fileHandles: [handleOf2("a.txt"), handleOf2("b.txt"), handleOf2("c.txt"), ghostHandle],
    localPath: localDir, rateLimitKiB: 0,
  });
  check("the four-file queue accepts", Array.isArray(first.items) && first.items.length === 4);
  const settled = await settleQueue(binding, browser.browserHandle);
  for (const item of settled.items) console.log(`  item ${item.name}: ${item.state} ${item.doneBytes}/${item.totalBytes} ${item.detail}`);
  const byName = Object.fromEntries(settled.items.map((item) => [item.name, item]));
  check("three downloads finished", ["a.txt", "b.txt", "c.txt"].every((n) => byName[n]?.state === "done"));
  check("the unreadable one failed with a reason",
    byName["ghost.txt"]?.state === "failed" && byName["ghost.txt"].detail.length > 0);
  check("finished files match the remote bytes",
    ["a.txt", "b.txt", "c.txt"].every((n) => localSha(path.join(localDir, n)) === remoteSha(`/opt/q/${n}`)));
  check("done items carry an integrity note",
    byName["a.txt"].detail.includes("已核对完整性") || byName["a.txt"].detail.includes("未核对完整性"));

  // Restore the file and retry: the failed item completes.
  onHost("sh", "-c", "mv /opt/q/ghost.away /opt/q/ghost.txt");
  const ghostId = byName["ghost.txt"].itemId;
  const retried = await sidecar.call("sftp-browser.queue.retry",
    { bindingHandle: binding, browserHandle: browser.browserHandle, itemId: ghostId });
  check("retry requeues the failed item", retried.items.find((i) => i.itemId === ghostId)?.state === "queued");
  const settled2 = await settleQueue(binding, browser.browserHandle);
  const ghost = settled2.items.find((i) => i.itemId === ghostId);
  check("the retried item finishes", ghost?.state === "done");
  check("the retried file matches the remote bytes", localSha(path.join(localDir, "ghost.txt")) === remoteSha("/opt/q/ghost.txt"));

  // 2. Big download, rate-limited so the cancel window is wide: cancel all
  //    mid-way, the .part stays, the retry resumes from the recorded offset
  //    and the final sha256 matches the remote.
  const bigStart = await sidecar.call("sftp-browser.queue.download", {
    bindingHandle: binding, browserHandle: browser.browserHandle,
    fileHandles: [handleOf2("big.bin")], localPath: localDir, rateLimitKiB: 2048,
  });
  check("the big download queues", bigStart.items.at(-1)?.name === "big.bin" && bigStart.items.at(-1)?.state === "queued");
  await sleep(2_500);
  const midCancel = await sidecar.call("sftp-browser.queue.cancel-all", { bindingHandle: binding, browserHandle: browser.browserHandle });
  check("cancel-all reached a running item", midCancel.cancelled >= 1);
  const cancelled = await settleQueue(binding, browser.browserHandle);
  const bigCancelled = cancelled.items.find((i) => i.name === "big.bin");
  check("the cancelled item reports cancelled", bigCancelled?.state === "cancelled");
  const partPath = path.join(localDir, "big.bin.part");
  const partLen = fs.existsSync(partPath) ? fs.statSync(partPath).size : 0;
  check("the .part file is kept for resume", partLen > 0 && partLen < 64 * 1024 * 1024);
  console.log(`partial kept: ${partLen} bytes`);
  const resume = await sidecar.call("sftp-browser.queue.retry",
    { bindingHandle: binding, browserHandle: browser.browserHandle, itemId: bigCancelled.itemId });
  const resumed = await settleQueue(binding, browser.browserHandle);
  const bigDone = resumed.items.find((i) => i.itemId === bigCancelled.itemId);
  check("the resumed download finished", bigDone?.state === "done");
  check("the item log records the resume offset",
    bigDone?.detail.includes("续传") && bigDone?.detail.includes(String(partLen)));
  console.log(`resume detail: ${bigDone?.detail}`);
  check("the resumed file matches the remote sha256", localSha(path.join(localDir, "big.bin")) === remoteSha("/opt/q/big.bin"));
  check("the integrity check ran", bigDone?.detail.includes("已核对完整性"));
  check("no .part or sidecar remains", !fs.existsSync(partPath) && !fs.existsSync(`${partPath}.lhmeta`));
  void resume;

  // 3. A remote change between attempts restarts, it does not resume: a
  //    rate-limited download is cancelled leaving .part+sidecar, the remote
  //    file is changed, and the retry must drop the partial and start over.
  onHost("sh", "-c", "dd if=/dev/urandom of=/opt/q/changing.bin bs=1M count=8 status=none");
  const qListCh = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: qDir.entryHandle });
  const changeHandle = qListCh.entries.find((e) => e.name === "changing.bin")?.entryHandle;
  await sidecar.call("sftp-browser.queue.download", {
    bindingHandle: binding, browserHandle: browser.browserHandle,
    fileHandles: [changeHandle], localPath: localDir, rateLimitKiB: 2048,
  });
  await sleep(1_500);
  await sidecar.call("sftp-browser.queue.cancel-all", { bindingHandle: binding, browserHandle: browser.browserHandle });
  const cancelledCh = await settleQueue(binding, browser.browserHandle);
  const chItem = cancelledCh.items.find((i) => i.name === "changing.bin");
  check("the changing download cancelled with a kept .part",
    chItem?.state === "cancelled" && fs.existsSync(path.join(localDir, "changing.bin.part")));
  onHost("sh", "-c", "printf 'changed between attempts\n' >> /opt/q/changing.bin");
  await sidecar.call("sftp-browser.queue.retry",
    { bindingHandle: binding, browserHandle: browser.browserHandle, itemId: chItem.itemId });
  const settled3 = await settleQueue(binding, browser.browserHandle);
  const changed = settled3.items.find((i) => i.itemId === chItem.itemId);
  check("the changed item finished by restarting", changed?.state === "done");
  check("the restart says the remote file changed", changed?.detail.includes("远端文件已变化"));
  check("the restarted file matches the new remote sha256",
    localSha(path.join(localDir, "changing.bin")) === remoteSha("/opt/q/changing.bin"));

  // 4. Rate limit: 8 MiB at 1024 KiB/s is 8 s of copy at minimum. The first
  //    256 KiB chunk lands unthrottled (~0.25 s at this rate), so the floor is
  //    ~7.75 s; the check asserts >= 7.0 s for scheduler jitter.
  onHost("sh", "-c", "dd if=/dev/urandom of=/opt/q/rated.bin bs=1M count=8 status=none");
  const qList3 = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: qDir.entryHandle });
  const ratedHandle = qList3.entries.find((e) => e.name === "rated.bin")?.entryHandle;
  const started = Date.now();
  await sidecar.call("sftp-browser.queue.download", {
    bindingHandle: binding, browserHandle: browser.browserHandle,
    fileHandles: [ratedHandle], localPath: localDir, rateLimitKiB: 1024,
  });
  await settleQueue(binding, browser.browserHandle);
  const elapsed = (Date.now() - started) / 1000;
  console.log(`rate-limited 8 MiB @ 1024 KiB/s took ${elapsed.toFixed(1)} s (floor 7.75 s)`);
  check("the rate limit held the lower bound", elapsed >= 7.0);
  check("the rated file is byte-exact", localSha(path.join(localDir, "rated.bin")) === remoteSha("/opt/q/rated.bin"));

  // 5. A local destination that already exists is refused per item, never
  //    overwritten.
  fs.writeFileSync(path.join(localDir, "a.txt"), "LOCAL CONTENT MUST SURVIVE");
  const again = await sidecar.call("sftp-browser.queue.download", {
    bindingHandle: binding, browserHandle: browser.browserHandle,
    fileHandles: [handleOf2("a.txt")], localPath: localDir, rateLimitKiB: 0,
  });
  const settled4 = await settleQueue(binding, browser.browserHandle);
  const refused = settled4.items.find((i) => i.itemId === again.items.at(-1)?.itemId);
  check("an existing local name fails without overwriting",
    refused?.state === "failed" && refused?.detail.includes("未覆盖"));
  check("the existing local file is untouched",
    fs.readFileSync(path.join(localDir, "a.txt"), "utf8") === "LOCAL CONTENT MUST SURVIVE");

  // 6. Two staged uploads into the remote directory.
  const up1 = path.join(dataRoot, "up-one.txt"), up2 = path.join(dataRoot, "up-two.txt");
  fs.writeFileSync(up1, "upload one\n");
  fs.writeFileSync(up2, "upload two\n");
  const staged = [];
  for (const [file, fileName] of [[up1, "up-one.txt"], [up2, "up-two.txt"]]) {
    const reply = await sidecar.call("sftp-browser.upload.stage",
      { bindingHandle: binding, localPath: file, name: fileName });
    staged.push({ stagedHandle: reply.stagedHandle, name: fileName });
  }
  const upQueue = await sidecar.call("sftp-browser.queue.upload", {
    bindingHandle: binding, browserHandle: browser.browserHandle,
    directoryHandle: qDir.entryHandle, staged,
  });
  const upIds = new Set(upQueue.items.slice(-2).map((i) => i.itemId));
  check("the upload queue accepts two items", upQueue.items.at(-2)?.name === "up-one.txt" && upQueue.items.at(-1)?.name === "up-two.txt");
  const settled5 = await settleQueue(binding, browser.browserHandle);
  const upDone = settled5.items.filter((i) => upIds.has(i.itemId) && i.state === "done");
  check("both uploads finish", upDone.length === 2);
  check("uploaded bytes match the local files",
    onHost("sha256sum", "/opt/q/up-one.txt").split(/\s/u)[0] === localSha(up1) &&
    onHost("sha256sum", "/opt/q/up-two.txt").split(/\s/u)[0] === localSha(up2));

  // 7. Degraded target: the queue runs one at a time through SCP, and a retry
  //    after a failed item restarts from zero, saying SCP cannot resume.
  const degraded = await connect(sidecar, { host, port: degradedPort, username: "root", password: "LabRoot#2026", id: `${runId}-d`, name: `${name}-nosftp` });
  if (degraded.stage !== "connected") throw new Error(JSON.stringify(degraded));
  const degradedBinding = degraded.bindingHandle;
  const dBrowser = await sidecar.call("sftp-browser.open", { bindingHandle: degradedBinding });
  check("the degraded browser reports degradedSftp", dBrowser.degradedSftp === true);
  const dOpt = dBrowser.entries.find((e) => e.name === "opt");
  const dOptList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: degradedBinding, browserHandle: dBrowser.browserHandle, directoryHandle: dOpt.entryHandle });
  const dQ = dOptList.entries.find((e) => e.name === "q");
  const dQList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: degradedBinding, browserHandle: dBrowser.browserHandle, directoryHandle: dQ.entryHandle });
  const dDir = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-queue-dl2-"));
  // Move one file away after its handle was minted, like ghost.txt above.
  onDegraded("sh", "-c", "mv /opt/q/dghost.txt /opt/q/dghost.away");
  const dQueue = await sidecar.call("sftp-browser.queue.download", {
    bindingHandle: degradedBinding, browserHandle: dBrowser.browserHandle,
    fileHandles: [dQList.entries.find((e) => e.name === "d1.txt").entryHandle,
      dQList.entries.find((e) => e.name === "d2.txt").entryHandle,
      dQList.entries.find((e) => e.name === "dghost.txt").entryHandle],
    localPath: dDir, rateLimitKiB: 0,
  });
  check("the degraded queue is marked degraded", dQueue.degraded === true);
  const dSettled = await settleQueue(degradedBinding, dBrowser.browserHandle);
  const dByName = Object.fromEntries(dSettled.items.map((i) => [i.name, i]));
  check("degraded downloads finish through SCP", dByName["d1.txt"]?.state === "done" && dByName["d2.txt"]?.state === "done");
  check("degraded bytes match", fs.readFileSync(path.join(dDir, "d1.txt"), "utf8") === "d1\n");
  check("the missing remote file failed", dByName["dghost.txt"]?.state === "failed");
  // Put it back, plant a stale .part (SCP ignores it — restart from zero) and
  // retry: the detail must say SCP cannot resume.
  onDegraded("sh", "-c", "mv /opt/q/dghost.away /opt/q/dghost.txt");
  fs.writeFileSync(path.join(dDir, "dghost.txt.part"), "pretend-partial");
  const dRetry = await sidecar.call("sftp-browser.queue.retry",
    { bindingHandle: degradedBinding, browserHandle: dBrowser.browserHandle, itemId: dByName["dghost.txt"].itemId });
  void dRetry;
  const dSettled2 = await settleQueue(degradedBinding, dBrowser.browserHandle);
  const dGone = dSettled2.items.find((i) => i.itemId === dByName["dghost.txt"].itemId);
  check("the degraded retry restarts and finishes", dGone?.state === "done");
  check("the retry says SCP cannot resume", dGone?.detail.includes("SCP"));
  check("the restarted file has the full remote content",
    fs.readFileSync(path.join(dDir, "dghost.txt"), "utf8") === "dgone\n");

  const report = { runId, checks, passed: checks.filter((c) => c.passed).length };
  fs.writeFileSync(path.join(evidence, "queue-report.json"), JSON.stringify(report, null, 2));
  console.log(`\n${report.passed}/${checks.length} checks passed — evidence: ${evidence}`);
} catch (error) {
  console.error("PROBE FAILED:", error);
  process.exitCode = 1;
} finally {
  try { sidecar?.close(); } catch { /* ignore */ }
  for (const id of [containerId, degradedId]) {
    try { if (id) podman("rm", "-f", id); } catch { /* ignore */ }
  }
}
