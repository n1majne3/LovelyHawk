// Whole-directory download on a real target: the target packs the directory
// into a remote tar, the archive downloads to a host-chosen path — or is
// unpacked into a chosen empty folder by the hardened extractor — and the
// remote temp archive is removed on success, refusal and cancel.
//   1. nested files plus a symlink: the tar stores the link as a link entry
//      (never followed) and the hardened extractor skips it;
//   2. a 20,001-file tree is refused with the counted numbers;
//   3. a cancel mid-transfer removes the remote temp archive;
//   4. a Dropbear/no-SFTP target is refused with the degraded message.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-dir-dl-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-dir-download", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-dirdl-"));
const checks = [];
let containerId, degradedId, sidecar, failure;
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

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const sshPort = 2225;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(containerId, name);
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client openssh-sftp-server netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);

  // Nested tree with a symlink, an over-cap tree, and a big file for the
  // cancel window.
  onHost("sh", "-c", "mkdir -p /opt/packme/sub/nested && " +
    "printf 'top file\n' > /opt/packme/top.txt && " +
    "printf 'nested content\n' > /opt/packme/sub/nested/deep.txt && " +
    "ln -s /etc/hostname /opt/packme/link && " +
    "mkdir -p /opt/bigtree && seq 1 20001 | xargs -I{} touch /opt/bigtree/f{} && " +
    "mkdir -p /opt/slowdl && dd if=/dev/urandom of=/opt/slowdl/big.bin bs=1M count=900 status=none");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to the SFTP fixture", true);

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding });
  check("browser opens with a real SFTP subsystem", browser.degradedSftp === false);
  const optDir = (browser.entries ?? []).find((e) => e.name === "opt" && e.kind === "directory");
  const optList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: optDir.entryHandle });
  const packme = (optList.entries ?? []).find((e) => e.name === "packme");
  const bigtree = (optList.entries ?? []).find((e) => e.name === "bigtree");
  check("fixture directories are listed", Boolean(packme && bigtree));

  // 1. Plain .tar download of the nested tree.
  const tarPath = path.join(evidence, "packme.tar");
  const first = await sidecar.call("sftp-browser.download-directory",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: packme.entryHandle, localPath: tarPath, extractTo: null });
  check("directory download completes", first.state === "done" && fs.statSync(tarPath).isFile());
  check("counts report the real tree", first.fileCount === "2" && Number(first.totalBytes) > 0);
  check("receipt states the symlink policy", String(first.detail).includes("符号链接"));
  // GNU tar reads `D:` as a remote host; --force-local keeps it a file.
  const listing = execFileSync("tar", ["--force-local", "-tvf", tarPath], { encoding: "utf8" });
  const linkLine = listing.split("\n").find((line) => line.includes("link"));
  check("the symlink is stored as a link entry, never followed",
    Boolean(linkLine && linkLine.startsWith("l") && linkLine.includes("/etc/hostname")));
  console.log(`symlink policy: stored as link (${linkLine?.trim()})`);
  check("nested content survives the round trip", listing.includes("sub/nested/deep.txt"));
  check("no remote temp archive is left behind",
    onHost("sh", "-c", "ls /opt/.lovelyres-download-*.tar 2>/dev/null | wc -l") === "0");

  // 2. Extraction into a chosen empty folder: files land, the link member is
  //    skipped by the hardened unpacker.
  const extractDir = path.join(evidence, "extracted");
  fs.mkdirSync(extractDir);
  const staged = path.join(dataRoot, "packme-stage.tar");
  const second = await sidecar.call("sftp-browser.download-directory",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: packme.entryHandle, localPath: staged, extractTo: extractDir });
  check("extract download completes", second.state === "done");
  check("extracted entries are counted", second.extractedEntries === "2");
  check("the report names the skipped unsafe member", String(second.detail).includes("跳过 1"));
  // GNU tar strips the leading slash, so members land under opt/packme/.
  check("plain files landed in the chosen folder",
    fs.readFileSync(path.join(extractDir, "opt", "packme", "sub", "nested", "deep.txt"), "utf8") === "nested content\n");
  check("the link member was not created on disk", !fs.existsSync(path.join(extractDir, "opt", "packme", "link")));
  check("extraction into a non-empty folder is refused", await sidecar.call("sftp-browser.download-directory",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: packme.entryHandle, localPath: path.join(dataRoot, "packme-stage-2.tar"), extractTo: extractDir })
    .then((r) => r.state === "extract-refused"));

  // 3. Over-cap tree: refused with the counted numbers before any archive
  //    work runs.
  const overCap = await sidecar.call("sftp-browser.download-directory",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: bigtree.entryHandle, localPath: path.join(evidence, "big.tar"), extractTo: null });
  check("a 20,001-file tree is refused over the cap", overCap.state === "refused-over-cap");
  check("the refusal shows the counted file number", overCap.fileCount === "20001");
  console.log(`over-cap refusal: ${overCap.detail}`);
  check("no archive was created for the refused tree", !fs.existsSync(path.join(evidence, "big.tar")) &&
    onHost("sh", "-c", "ls /opt/.lovelyres-download-*.tar 2>/dev/null | wc -l") === "0");

  // 4. Cancel while the work runs. Re-list first: the earlier listing's
  //    handles have aged out by now — a stale handle must refuse, not act.
  const freshRoot = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: browser.directoryHandle });
  const freshOpt = (freshRoot.entries ?? []).find((e) => e.name === "opt");
  const freshList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: freshOpt.entryHandle });
  const slowdl = (freshList.entries ?? []).find((e) => e.name === "slowdl");
  check("the fresh listing still offers the big file's directory", Boolean(slowdl));
  // The transfer switch is registered before
  //    the remote archive starts; once a cancel reaches it, the post-archive
  //    check — or the in-flight copy itself — stops the download either way.
  const cancelTarget = path.join(evidence, "slowdl.tar");
  const cancelled = sidecar.call("sftp-browser.download-directory",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: slowdl.entryHandle, localPath: cancelTarget, extractTo: null })
    .then((value) => ({ resolved: value }), (error) => ({ error: String(error?.message ?? error) }));
  let cancelResult = { cancelled: 0 };
  for (let attempt = 0; attempt < 50 && cancelResult.cancelled < 1; attempt++) {
    await sleep(150);
    cancelResult = await sidecar.call("sftp-browser.transfer.cancel", { bindingHandle: binding, browserHandle: browser.browserHandle });
  }
  check("cancel reaches the running operation", cancelResult.cancelled >= 1);
  const outcome = await cancelled;
  check("the cancelled operation reports cancelled",
    outcome.error !== undefined && /cancelled|sftp-browser-cancelled/u.test(outcome.error));
  check("cancel removes the remote temp archive",
    onHost("sh", "-c", "ls /opt/.lovelyres-download-*.tar 2>/dev/null | wc -l") === "0");
  check("cancel removes the partial local file", !fs.existsSync(cancelTarget));

  // 5. A no-SFTP target refuses the operation with the degraded message.
  const degradedPort = 2226;
  degradedId = podman("run", "-d", "--name", `${name}-nosftp`, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(degradedId, `${name}-nosftp`);
  onDegraded("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onDegraded("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onDegraded("sh", "-c", `dropbear -E -p ${degradedPort}`);
  await until(() => { try { onDegraded("nc", "-z", "127.0.0.1", String(degradedPort)); return true; } catch { return false; } }, "degraded dropbear listening", 30_000);
  const secondConnect = await connect(sidecar, { host, port: degradedPort, username: "root", password: "LabRoot#2026", id: `${runId}-d`, name: `${name}-nosftp` });
  if (secondConnect.stage !== "connected") throw new Error(JSON.stringify(secondConnect));
  const degradedBrowser = await sidecar.call("sftp-browser.open", { bindingHandle: secondConnect.bindingHandle });
  check("the second browser opens degraded", degradedBrowser.degradedSftp === true);
  const degradedRoot = (degradedBrowser.entries ?? []).find((e) => e.name === "root");
  const refused = await sidecar.call("sftp-browser.download-directory",
    { bindingHandle: secondConnect.bindingHandle, browserHandle: degradedBrowser.browserHandle, directoryHandle: degradedRoot.entryHandle, localPath: path.join(evidence, "never.tar"), extractTo: null })
    .then(() => "accepted", (error) => String(error?.message ?? error));
  check("a no-SFTP target refuses directory download with the degraded code",
    refused.includes("sftp-browser-subsystem-unavailable"));

  console.log(`\n${checks.length}/${checks.length} checks passed`);
} catch (error) {
  failure ??= error?.message ?? String(error);
  console.log(`FAILED: ${failure}`);
  process.exitCode = 1;
} finally {
  try { sidecar?.kill(); } catch {}
  try { if (containerId) podman("rm", "-f", containerId); } catch {}
  try { if (degradedId) podman("rm", "-f", degradedId); } catch {}
}
