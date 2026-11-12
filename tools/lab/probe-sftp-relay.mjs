// Dual-host relay on two real targets: a file in host A's browser is sent to
// host B through a managed host temp file — download leg on A's binding,
// upload leg on a session the relay opens with B's own saved credentials.
//   1. the relay target list names B with its display label;
//   2. a small file relays end to end and the sha256 on B matches;
//   3. a destination that already exists refuses, never overwritten;
//   4. invented binding and connection handles are refused;
//   5. cancelling mid-relay removes the temp file;
//   6. stopping B mid-relay fails clearly and leaves no temp file.
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-relay-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-sftp-relay", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-relay-"));
const checks = [];
let containerA, containerB, sidecar;
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
const onA = (...args) => { owned(containerA, `${name}-a`); return podman("exec", containerA, ...args); };
const onB = (...args) => { owned(containerB, `${name}-b`); return podman("exec", containerB, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { const hit = await fn(); if (hit) return hit; await sleep(100); } throw new Error(`Timed out: ${label}`); }
const relayTemps = () => {
  const found = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.startsWith("lovelyhawk-relay-")) found.push(full);
    }
  };
  walk(dataRoot);
  return found;
};
async function settleRelay(binding, browserHandle, relayHandle, timeout = 120_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const relay = await sidecar.call("sftp-browser.relay.poll",
      { bindingHandle: binding, browserHandle, relayHandle });
    if (relay === null) throw new Error("relay vanished");
    if (relay.state !== "running") return relay;
    await sleep(200);
  }
  throw new Error("relay did not settle");
}

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const portA = 2228, portB = 2229;
  for (const [suffix, port, password] of [["a", portA, "LabRoot#2026"], ["b", portB, "LabBee#2026"]]) {
    const id = podman("run", "-d", "--name", `${name}-${suffix}`, "--label", `lovelyres-test-run=${runId}`,
      "--memory", "512m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
    owned(id, `${name}-${suffix}`);
    if (suffix === "a") containerA = id; else containerB = id;
    const exec = (...args) => { owned(id, `${name}-${suffix}`); return podman("exec", id, ...args); };
    exec("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client openssh-sftp-server netcat-openbsd coreutils >/dev/null 2>&1");
    exec("sh", "-c", `echo 'root:${password}' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key`);
    exec("sh", "-c", `dropbear -E -p ${port}`);
    await until(() => { try { exec("nc", "-z", "127.0.0.1", String(port)); return true; } catch { return false; } }, `dropbear ${suffix} listening`, 30_000);
  }
  onA("sh", "-c", "mkdir -p /opt/relay && printf 'relay me\n' > /opt/relay/source.bin && " +
    "dd if=/dev/urandom of=/opt/relay/large.bin bs=1M count=256 status=none");
  onB("sh", "-c", "mkdir -p /opt/relay-dest");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  // B connects first so its host key is confirmed and its own credentials are
  // stored; A connects second and keeps the live binding the browser uses.
  const connB = await connect(sidecar, { host, port: portB, username: "root", password: "LabBee#2026", id: `${runId}-b`, name: `${name}-b` });
  if (connB.stage !== "connected") throw new Error(JSON.stringify(connB));
  const connA = await connect(sidecar, { host, port: portA, username: "root", password: "LabRoot#2026", id: `${runId}-a`, name: `${name}-a` });
  if (connA.stage !== "connected") throw new Error(JSON.stringify(connA));
  const bindingA = connA.bindingHandle;
  check("both targets connect with different credentials", true);

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: bindingA });
  const browserHandle = browser.browserHandle;
  const optDir = browser.entries.find((e) => e.name === "opt");
  const optList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: bindingA, browserHandle, directoryHandle: optDir.entryHandle });
  const relayDir = optList.entries.find((e) => e.name === "relay");
  const listing = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: bindingA, browserHandle, directoryHandle: relayDir.entryHandle });
  const handleOf = (n) => listing.entries.find((e) => e.name === n)?.entryHandle;

  // 1. The target list names B (and only B) with label plus identity.
  const targets = await sidecar.call("sftp-browser.relay.targets",
    { bindingHandle: bindingA, browserHandle });
  check("relay target list offers B only", targets.length === 1 && targets[0].connectionId === `${runId}-b`);
  check("B is shown with its display label", targets[0].label.includes(`${host}:${portB}`) || targets[0].label.includes(name));

  // 2. Relay the small file and check the sha on B.
  const started = await sidecar.call("sftp-browser.relay.start", {
    bindingHandle: bindingA, browserHandle, fileHandle: handleOf("source.bin"),
    connectionId: `${runId}-b`, destDir: "/opt/relay-dest",
  });
  check("relay starts running", started.state === "running");
  const finished = await settleRelay(bindingA, browserHandle, started.relayHandle);
  check("relay finishes done", finished.state === "done");
  const sourceSha = onA("sha256sum", "/opt/relay/source.bin").split(/\s/u)[0];
  const destSha = onB("sha256sum", "/opt/relay-dest/source.bin").split(/\s/u)[0];
  check("sha256 on B matches the source", destSha === sourceSha);
  check("no temp file left after success", relayTemps().length === 0);

  // 3. The destination now exists; the same relay refuses, never overwriting.
  const again = await sidecar.call("sftp-browser.relay.start", {
    bindingHandle: bindingA, browserHandle, fileHandle: handleOf("source.bin"),
    connectionId: `${runId}-b`, destDir: "/opt/relay-dest",
  });
  const refused = await settleRelay(bindingA, browserHandle, again.relayHandle);
  check("existing destination is refused", refused.state === "failed" && refused.detail.includes("同名"));
  check("the existing file is untouched",
    onB("sha256sum", "/opt/relay-dest/source.bin").split(/\s/u)[0] === destSha);

  // 4. Invented handles are refused.
  let inventedBinding = false;
  try {
    await sidecar.call("sftp-browser.relay.start", {
      bindingHandle: "invented-binding", browserHandle, fileHandle: handleOf("source.bin"),
      connectionId: `${runId}-b`, destDir: "/opt/relay-dest",
    });
  } catch { inventedBinding = true; }
  check("an invented binding handle is refused", inventedBinding);
  let inventedConnection = false;
  try {
    const bad = await sidecar.call("sftp-browser.relay.start", {
      bindingHandle: bindingA, browserHandle, fileHandle: handleOf("source.bin"),
      connectionId: "00000000-0000-4000-8000-000000000000", destDir: "/opt/relay-dest",
    });
    const settled = await settleRelay(bindingA, browserHandle, bad.relayHandle, 30_000);
    inventedConnection = settled.state === "failed";
  } catch { inventedConnection = true; }
  check("an invented destination connection is refused", inventedConnection);

  // 5. Cancel mid-relay on the large file: the temp file is removed.
  const cancelledStart = await sidecar.call("sftp-browser.relay.start", {
    bindingHandle: bindingA, browserHandle, fileHandle: handleOf("large.bin"),
    connectionId: `${runId}-b`, destDir: "/opt/relay-dest",
  });
  await sidecar.call("sftp-browser.relay.cancel",
    { bindingHandle: bindingA, browserHandle, relayHandle: cancelledStart.relayHandle });
  const cancelled = await settleRelay(bindingA, browserHandle, cancelledStart.relayHandle);
  check("cancelled relay reports cancelled", cancelled.state === "cancelled");
  check("no temp file left after cancel", relayTemps().length === 0);
  check("no partial file landed on B", !(() => { try { onB("stat", "/opt/relay-dest/large.bin"); return true; } catch { return false; } })());

  // 6. B disappears mid-relay: clear failure, temp still removed.
  const doomedStart = await sidecar.call("sftp-browser.relay.start", {
    bindingHandle: bindingA, browserHandle, fileHandle: handleOf("large.bin"),
    connectionId: `${runId}-b`, destDir: "/opt/relay-dest",
  });
  owned(containerB, `${name}-b`);
  podman("stop", "-t", "0", containerB);
  const doomed = await settleRelay(bindingA, browserHandle, doomedStart.relayHandle, 180_000);
  check("dead peer fails clearly", doomed.state === "failed" && doomed.detail.length > 0);
  check("no temp file left after disconnect", relayTemps().length === 0);
} finally {
  try { sidecar?.close(); } catch { /* already gone */ }
  for (const suffix of ["a", "b"]) {
    try {
      const label = `${name}-${suffix}`;
      const listed = podman("ps", "-aq", "--filter", `name=^${label}$`);
      if (listed) podman("rm", "-f", listed.split("\n"));
    } catch { /* already gone */ }
  }
  fs.writeFileSync(path.join(evidence, "relay-report.json"), JSON.stringify({ runId, checks }, null, 2));
  const passed = checks.filter((entry) => entry.passed).length;
  console.log(`\n${passed}/${checks.length} checks passed — evidence: ${evidence}`);
}
