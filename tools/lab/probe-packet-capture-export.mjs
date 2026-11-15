// Exports a finished live capture as a pcap, on a disposable Podman SSH
// target it creates itself, without capturing a second time.
//
// What has to hold on a real machine:
//   * while the capture runs the fifo and the raw file are both there, and
//     exporting is refused — there is nothing finished to export;
//   * after a stop the export collects the file the capture already wrote:
//     the local capture.pcap parses, holds at least as many packets as the
//     decoded lines the table showed, and its SHA-256 is the receipt's and
//     the manifest's;
//   * a verified export removes the remote pcap and fifo, and a second
//     export of the same capture is refused;
//   * "discard" removes a finished capture's remote files and refuses its
//     export afterwards;
//   * a missing remote file is refused, not silently exported as empty.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-pcapx-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-pcap-export", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pcapx-"));
const exportDir = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pcapdest-"));
const checks = [];
let containerId, imageId, sidecar, forwarder, failure;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 }).trim();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  return (target.Name === name || target.Name === `/${name}`) && target.Config?.Labels?.["lovelyres-test-run"] === runId &&
    target.Image === imageId ? target : null;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const onHostText = (command) => onHost("sh", "-c", command);
function check(label, passed, note = "") {
  checks.push({ label, passed: Boolean(passed), note });
  console.log(`  ${passed ? "PASS" : "FAIL"} ${label}${note ? ` — ${note}` : ""}`);
  if (!passed && !failure) failure = label;
}

// Counts records in a pcap without tcpdump: 24-byte global header, then
// 16-byte record headers each carrying the captured length at offset 8.
function pcapPacketCount(file) {
  const bytes = fs.readFileSync(file);
  if (bytes.length < 24) return -1;
  const magic = bytes.readUInt32LE(0);
  const little = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  if (!little && magic !== 0xd4c3b2a1 && magic !== 0x4d3cb2a1) return -1;
  let offset = 24, count = 0;
  while (offset + 16 <= bytes.length) {
    const included = little ? bytes.readUInt32LE(offset + 8) : bytes.readUInt32BE(offset + 8);
    if (offset + 16 + included > bytes.length) break;
    offset += 16 + included;
    count += 1;
  }
  return count;
}

async function finishCapture(binding, captureHandle) {
  // Status only settles once the queued events are drained: a poll returns at
  // most a hundred, and the capture looks alive until the terminal event is
  // delivered, so walk the cursor instead of re-reading the head.
  let after = 0, last = null;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const polled = await sidecar.call("packet-capture.poll", {
      bindingHandle: binding, captureHandle, afterSequence: after,
    }, 60_000).catch((error) => ({ pollError: String(error.message) }));
    // After stop() the live record is gone — the finished registry owns the
    // capture now — so "unavailable" is the expected answer, not a failure.
    if (!polled || polled.pollError) return last;
    last = polled;
    after = polled.latestSequence ?? after;
    if (attempt < 3 || polled.status !== "capturing") {
      const kinds = (polled.events ?? []).map((event) => event.kind);
      const failed = (polled.events ?? []).find((event) => event.kind === "failed");
      console.log(`    poll: status=${polled.status} packets=${polled.packets} hasMore=${polled.hasMore} seq=${after} events=${kinds.join(",") || "none"}${failed ? ` reason=${JSON.stringify(failed).slice(0, 200)}` : ""}`);
    }
    if (polled.status !== "capturing" && !polled.hasMore) return polled;
    await sleep(500);
  }
  return last;
}

async function evidenceUntilDone(binding, jobHandle) {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    const result = await sidecar.call("packet-capture.evidence", {
      action: "poll", bindingHandle: binding, jobHandle,
    }, 60_000);
    if (result.state !== "collecting" && result.state !== "capturing") return result;
    await sleep(1_000);
  }
  return null;
}

let localPort;
try {
  imageId = podman("image", "inspect", "localhost/lr-apt-test:latest", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", imageId, "sleep", "3600");
  check("pcap-export fixture is an owned container with capture caps", Boolean(owned()));

  // The image carries sshd and apt but no tcpdump; installing it on the
  // disposable fixture is the point of the fixture.
  onHostText("apt-get update >/dev/null && apt-get install -y tcpdump iproute2 >/dev/null");
  onHostText(`echo 'root:LabRoot#2026' | chpasswd && mkdir -p /run/sshd && ` +
    `sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/;s/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && /usr/sbin/sshd`);
  check("tcpdump installed and sshd is up",
    onHostText("command -v tcpdump").endsWith("tcpdump") && onHostText("pgrep -x sshd >/dev/null; echo $?") === "0");

  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  localPort = await new Promise((resolve) => {
    const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  const forwardTarget = `${owned().NetworkSettings.IPAddress}:22`;
  forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
    "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
    "-L", `127.0.0.1:${localPort}:${forwardTarget}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
  await sleep(1_500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");

  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: "LabRoot#2026", id: runId, name: `${name}-22` });
  check("SSH binding connected", status?.stage === "connected");
  const binding = status.bindingHandle;

  const list = await sidecar.call("packet-capture.interfaces.list", { bindingHandle: binding }, 60_000);
  const chosen = list.interfaces.find((entry) => entry.name !== "lo") ?? list.interfaces[0];
  check("a non-loopback interface is offered", Boolean(chosen && chosen.name !== "lo"));

  // Capture one: run, refuse the early export, stop, export, verify.
  const first = await sidecar.call("packet-capture.start", {
    bindingHandle: binding, snapshotHandle: list.snapshotHandle,
    interfaceHandle: chosen.interfaceHandle,
    input: { filter: null, packetLimit: null, durationSeconds: 120 },
  }, 60_000);
  await sleep(3_000);
  check("the raw file and its fifo exist while capturing",
    onHostText("ls /tmp/lovelyres-pcap-*.pcap 2>/dev/null | wc -l") === "1" &&
    onHostText("ls /tmp/lovelyres-pcap-*.fifo 2>/dev/null | wc -l") === "1");

  const early = await sidecar.call("packet-capture.evidence", {
    action: "export", bindingHandle: binding,
    captureHandle: first.captureHandle, selectedDirectory: exportDir,
  }, 30_000).catch((error) => ({ refused: String(error.message) }));
  check("exporting a running capture is refused",
    /packet-capture-(evidence-)?(not-finished|still-running)/u.test(String(early.refused ?? "")),
    String(early.refused ?? "accepted!").slice(0, 90));

  // The polls themselves are the traffic — this SSH session rides the same
  // interface — so no extra traffic generator is needed.
  const live = await sidecar.call("packet-capture.poll", { bindingHandle: binding, captureHandle: first.captureHandle, afterSequence: 0 }, 60_000);
  console.log(`    mid-run: status=${live.status} packets=${live.packets} events=${(live.events ?? []).map((e) => e.kind).join(",") || "none"}`);
  const stopped = await sidecar.call("packet-capture.stop", { bindingHandle: binding, captureHandle: first.captureHandle }, 60_000);
  check("the first capture stops", stopped.stopped === true);
  await finishCapture(binding, first.captureHandle);
  const shown = live.packets ?? 0;
  check("decoded packet lines were shown", shown > 0, `${shown} packets`);
  check("the fifo is gone once the capture ends",
    onHostText("ls /tmp/lovelyres-pcap-*.fifo 2>/dev/null | wc -l") === "0");
  console.log(`    remote file: ${onHostText("ls -l /tmp/lovelyres-pcap-*.pcap 2>/dev/null || echo none")}`);

  const exportResult = await sidecar.call("packet-capture.evidence", {
    action: "export", bindingHandle: binding,
    captureHandle: first.captureHandle, selectedDirectory: exportDir,
  }, 60_000);
  check("export returns a collecting evidence job", exportResult.state === "collecting");
  const done = await evidenceUntilDone(binding, exportResult.jobHandle);
  check("the evidence job completes", done?.state === "completed", done?.detail ?? "");
  check("the remote temporary file was removed", done?.temporaryFile === "removed");
  check("no remote pcap or fifo is left",
    onHostText("ls /tmp/lovelyres-pcap-* 2>/dev/null | wc -l") === "0");

  const bundle = path.join(exportDir, exportResult.folderName);
  const pcapFile = path.join(bundle, "capture.pcap");
  const manifestFile = path.join(bundle, "manifest.json");
  check("the bundle holds capture.pcap and manifest.json",
    fs.existsSync(pcapFile) && fs.existsSync(manifestFile));
  const records = fs.existsSync(pcapFile) ? pcapPacketCount(pcapFile) : -1;
  check("the exported pcap parses and covers the shown packets", records >= shown && shown > 0,
    `${records} records vs ${shown} shown`);
  if (fs.existsSync(pcapFile)) {
    const digest = createHash("sha256").update(fs.readFileSync(pcapFile)).digest("hex");
    check("the receipt's SHA-256 matches the local file", digest === done.sha256);
    const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
    check("the manifest records the same hash and the live origin",
      manifest.capture?.target_sha256 === digest && manifest.capture?.live_capture === true &&
      manifest.capture?.interface === chosen.name, `interface ${chosen.name}`);
  }

  const again = await sidecar.call("packet-capture.evidence", {
    action: "export", bindingHandle: binding,
    captureHandle: first.captureHandle, selectedDirectory: exportDir,
  }, 30_000).catch((error) => ({ refused: String(error.message) }));
  check("exporting the same capture twice is refused", typeof again.refused === "string",
    String(again.refused ?? "accepted!").slice(0, 90));

  // Capture two: stop, discard, verify everything remote is gone.
  const second = await sidecar.call("packet-capture.start", {
    bindingHandle: binding, snapshotHandle: list.snapshotHandle,
    interfaceHandle: chosen.interfaceHandle,
    input: { filter: null, packetLimit: null, durationSeconds: 120 },
  }, 60_000);
  await sleep(3_000);
  await sidecar.call("packet-capture.stop", { bindingHandle: binding, captureHandle: second.captureHandle }, 60_000);
  await finishCapture(binding, second.captureHandle);
  check("a finished capture keeps its raw file for the operator's choice",
    onHostText("ls /tmp/lovelyres-pcap-*.pcap 2>/dev/null | wc -l") === "1");
  const discarded = await sidecar.call("packet-capture.discard", {
    bindingHandle: binding, captureHandle: second.captureHandle,
  }, 60_000);
  check("discard reports itself done", discarded?.discarded === true);
  check("discard removes the remote artifacts",
    onHostText("ls /tmp/lovelyres-pcap-* 2>/dev/null | wc -l") === "0");
  const afterDiscard = await sidecar.call("packet-capture.evidence", {
    action: "export", bindingHandle: binding,
    captureHandle: second.captureHandle, selectedDirectory: exportDir,
  }, 30_000).catch((error) => ({ refused: String(error.message) }));
  check("exporting a discarded capture is refused", typeof afterDiscard.refused === "string",
    String(afterDiscard.refused ?? "accepted!").slice(0, 90));

  // Capture three: delete the file behind its back; the export must refuse.
  const third = await sidecar.call("packet-capture.start", {
    bindingHandle: binding, snapshotHandle: list.snapshotHandle,
    interfaceHandle: chosen.interfaceHandle,
    input: { filter: null, packetLimit: null, durationSeconds: 120 },
  }, 60_000);
  await sleep(3_000);
  await sidecar.call("packet-capture.stop", { bindingHandle: binding, captureHandle: third.captureHandle }, 60_000);
  await finishCapture(binding, third.captureHandle);
  onHostText("rm -f /tmp/lovelyres-pcap-*.pcap");
  const missing = await sidecar.call("packet-capture.evidence", {
    action: "export", bindingHandle: binding,
    captureHandle: third.captureHandle, selectedDirectory: exportDir,
  }, 60_000);
  const missingDone = missing.jobHandle ? await evidenceUntilDone(binding, missing.jobHandle) : missing;
  check("a missing remote file fails the export, not a silent save",
    missingDone?.state === "failed" || typeof missingDone?.refused === "string",
    String(missingDone?.state ?? missingDone?.refused ?? "").slice(0, 60));
  await sidecar.call("packet-capture.discard", {
    bindingHandle: binding, captureHandle: third.captureHandle,
  }, 60_000).catch(() => null);
} catch (error) {
  failure = failure ?? `probe error: ${error.message}`;
  console.log(`\nFAILED: ${error.message}`);
  if (sidecar?.stderr?.length) console.log(sidecar.stderr.join("").slice(-600));
} finally {
  try { sidecar?.close(); } catch { /* already gone */ }
  try { forwarder?.kill(); } catch { /* already gone */ }
  try {
    if (containerId && owned()) podman("rm", "-f", containerId);
    console.log("  fixture container removed");
  } catch { /* nothing to remove */ }
}

const failedChecks = checks.filter((entry) => !entry.passed);
fs.writeFileSync(path.join(evidence, "checks.json"), JSON.stringify({ runId, checks, failedChecks }, null, 2));
console.log(`\n${failedChecks.length === 0 && !failure ? "ALL CHECKS PASSED" : "CHECKS FAILED"} (${checks.length - failedChecks.length}/${checks.length})`);
process.exitCode = failedChecks.length === 0 && !failure ? 0 : 1;
