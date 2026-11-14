// Backend RPC probe for the records of past process activity a target
// already keeps (process accounting). Only runs against UUID-labelled
// disposable containers it creates itself.
//
// What has to hold on a real target:
//   * a host without accounting says so, and reading it is refused by its
//     own code rather than answered with an empty list;
//   * accounting that is installed but not recording is reported as that,
//     and nothing here switches it on;
//   * once the operator has switched it on, the records match what the
//     target's own lastcomm reports, carry program names only, and a
//     command repeated on a fixed beat is grouped as periodic;
//   * an account that cannot read the file is told so, not shown "nothing";
//   * reading leaves the accounting state and the file's identity alone.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const evidence = path.join(repository, "target/desktop-debug", `process-watch-sources-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pwsrc-"));
const checks = [], observations = { notRun: [] }, fixtures = [], forwarders = [];
let sidecar, failure;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const strip = v => String(v ?? "").replace(/^sha256:/u, "");

function startFixture(image, name, extra = []) {
  const imageId = podman("image", "inspect", image, "--format", "{{.Id}}");
  const containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "512m", "--cpus", "1", "--pids-limit", "256", ...extra, imageId, "sleep", "infinity");
  const owned = () => {
    const target = JSON.parse(podman("inspect", containerId))[0];
    if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
      target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind"))
      throw new Error("Owned process watch sources fixture identity changed");
    return target;
  };
  const sh = script => { owned(); return podman("exec", containerId, "sh", "-c", script); };
  const fixture = { name, imageId, containerId, owned, sh };
  fixtures.push(fixture);
  return fixture;
}

try {
  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  const forwardTo = async fixture => {
    const localPort = await new Promise(resolve => {
      const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
    });
    const forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-i", findKey(machine, "IdentityPath"),
      "-p", String(findKey(machine, "Port")), "-N", "-L", `127.0.0.1:${localPort}:${fixture.owned().NetworkSettings.IPAddress}:22`, "root@127.0.0.1"],
      { windowsHide: true, stdio: "ignore" });
    forwarders.push(forwarder);
    await sleep(1500);
    if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
    return localPort;
  };
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const bind = async (port, username, suffix) => {
    const status = await connect(sidecar, { host: "127.0.0.1", port, username, password: "LabRoot#2026", id: `${runId.slice(0, 8)}-${suffix}`, name: `lr-pwsrc-${suffix}` });
    check(`SSH binding connected as ${username} (${suffix})`, status?.stage === "connected");
    return status.bindingHandle;
  };
  const call = (method, params, ms = 60_000) => sidecar.call(method, params, ms);
  const refused = (method, params) => call(method, params).then(() => "accepted", error => String(error.message));
  const stateOf = (sources, kind) => sources.find(entry => entry.source === kind)?.state;

  // ---- debian: absent, then installed-not-recording, then recording ---------
  const deb = startFixture("docker.io/library/debian:12-slim", `lr-pwsrc-deb-${runId.slice(0, 8)}`,
    // Switching accounting on is the operator's step in this probe; it needs this one capability.
    ["--cap-add", "SYS_PACCT"]);
  check("debian fixture is an owned, unprivileged container without host mounts", Boolean(deb.owned()));
  deb.sh("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && " +
    "apt-get install -y -qq openssh-server procps >/dev/null 2>&1 && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && " +
    "mkdir -p /etc/ssh/sshd_config.d && printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n' > /etc/ssh/sshd_config.d/lab.conf && " +
    "echo 'root:LabRoot#2026' | chpasswd && useradd -m lhuser && echo 'lhuser:LabRoot#2026' | chpasswd && /usr/sbin/sshd");
  const debPort = await forwardTo(deb);
  const root = await bind(debPort, "root", "deb-root");

  const bare = await call("process-watch.sources", { bindingHandle: root });
  observations.debianBare = bare;
  check("every answer is exactly a source and a state",
    bare.every(entry => Object.keys(entry).sort().join() === "source,state"));
  check("a host without accounting, audit or tracing tools reports all four absent",
    ["accounting", "audit-execve", "execsnoop", "bpftrace"].every(kind => stateOf(bare, kind) === "absent"));
  const bareRead = await refused("process-watch.accounting.read", { bindingHandle: root, minutes: 15 });
  observations.bareRead = bareRead;
  check("reading accounting that does not exist is refused by its own code, not answered empty",
    /process-watch-accounting-unavailable/u.test(bareRead));

  deb.sh("export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq acct >/dev/null 2>&1; accton off >/dev/null 2>&1; " +
    "for f in /var/log/account/pacct; do [ -e $f ] && : > $f; done; command -v lastcomm dump-acct accton");
  const installed = await call("process-watch.sources", { bindingHandle: root });
  observations.debianInstalled = installed;
  check("accounting that is installed but not recording is reported as installed only",
    stateOf(installed, "accounting") === "present");
  const idleRead = await refused("process-watch.accounting.read", { bindingHandle: root, minutes: 15 });
  check("reading it then is refused the same way", /process-watch-accounting-unavailable/u.test(idleRead));
  await sleep(1_500);
  deb.sh("true; true; true");
  check("asking did not switch accounting on: the file is still empty",
    deb.sh("stat -c %s /var/log/account/pacct 2>/dev/null || echo 0") === "0");

  deb.sh("printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/lh-beacon && chmod 0755 /usr/local/bin/lh-beacon && " +
    "mkdir -p /var/log/account && touch /var/log/account/pacct && accton /var/log/account/pacct");
  deb.sh("setsid sh -c 'while :; do /usr/local/bin/lh-beacon --secret-arg hunter2; sleep 5; done' </dev/null >/dev/null 2>&1 &");
  await sleep(42_000);
  const identity = () => deb.sh("stat -c '%a %U %G %i' /var/log/account/pacct");
  const before = identity();
  const recording = await call("process-watch.sources", { bindingHandle: root });
  observations.debianRecording = recording;
  check("accounting the operator switched on is reported as readable for root", stateOf(recording, "accounting") === "readable");

  const read = await call("process-watch.accounting.read", { bindingHandle: root, minutes: 5 });
  const independent = Number(deb.sh("lastcomm lh-beacon 2>/dev/null | wc -l"));
  const beacon = read.groups.find(group => group.command === "lh-beacon");
  observations.accounting = { minutes: read.minutes, records: read.records, unparsed: read.unparsed, truncated: read.truncated,
    groups: read.groups.length, beacon: beacon ?? null, independentBeaconCount: independent, top: read.groups.slice(0, 12) };
  check("the answer has exactly the fields the page validates",
    Object.keys(read).sort().join() === "groups,minutes,records,truncated,unparsed" &&
    read.groups.every(group => Object.keys(group).sort().join() === "cadence,command,count,firstAtMs,lastAtMs,periodMs,uids"));
  check(`the beacon is in the records (app ${beacon?.count}, lastcomm ${independent})`,
    beacon !== undefined && beacon.count >= 7 && independent >= beacon.count && independent - beacon.count <= 2);
  check("the beacon is grouped as periodic at about five seconds",
    beacon.cadence === "periodic" && beacon.periodMs >= 4_000 && beacon.periodMs <= 7_000);
  check("records carry the program name only: no argument reached the answer", !JSON.stringify(read).includes("hunter2") && !JSON.stringify(read).includes("secret-arg"));
  check("record times fall inside the window that was asked for",
    read.groups.every(group => group.firstAtMs >= Date.now() - 6 * 60_000 && group.lastAtMs <= Date.now() + 60_000));
  check("nothing was left unparsed and nothing was cut off", read.unparsed === 0 && read.truncated === false);
  check("reading left accounting on and the file's owner, mode and inode alone",
    identity() === before && Number(deb.sh("stat -c %s /var/log/account/pacct")) > 0);
  const outOfRange = await refused("process-watch.accounting.read", { bindingHandle: root, minutes: 121 });
  const zero = await refused("process-watch.accounting.read", { bindingHandle: root, minutes: 0 });
  check("a window outside 1 to 120 minutes is refused", outOfRange !== "accepted" && zero !== "accepted");

  // ---- an account that cannot read the file ---------------------------------
  observations.pacctAccess = deb.sh("stat -c '%a %U %G' /var/log/account /var/log/account/pacct");
  const user = await bind(debPort, "lhuser", "deb-user");
  const userSources = await call("process-watch.sources", { bindingHandle: user });
  observations.userSources = userSources;
  check("an account without access is told there is a record it cannot read",
    stateOf(userSources, "accounting") === "unreadable");
  const userRead = await refused("process-watch.accounting.read", { bindingHandle: user, minutes: 5 });
  observations.userRead = userRead;
  check("and its read is refused rather than answered empty", /process-watch-accounting-unavailable/u.test(userRead));

  // ---- alpine: busybox has no accounting tools ------------------------------
  const alp = startFixture("docker.io/library/alpine:3.20", `lr-pwsrc-alp-${runId.slice(0, 8)}`);
  check("alpine fixture is an owned, unprivileged container without host mounts", Boolean(alp.owned()));
  alp.sh("apk add --no-cache openssh >/dev/null 2>&1 && ssh-keygen -A >/dev/null && " +
    "printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n' >> /etc/ssh/sshd_config && echo 'root:LabRoot#2026' | chpasswd && /usr/sbin/sshd");
  const alpRoot = await bind(await forwardTo(alp), "root", "alp-root");
  const alpSources = await call("process-watch.sources", { bindingHandle: alpRoot });
  observations.alpine = alpSources;
  check("alpine with busybox only reports all four absent",
    ["accounting", "audit-execve", "execsnoop", "bpftrace"].every(kind => stateOf(alpSources, kind) === "absent"));
  check("and its read is refused by the same code",
    /process-watch-accounting-unavailable/u.test(await refused("process-watch.accounting.read", { bindingHandle: alpRoot, minutes: 5 })));

  observations.notRun.push(
    "audit execve rules: auditd cannot load rules in an unprivileged container; detection is unit-tested only and its records are not read",
    "execsnoop and bpftrace: need a privileged host kernel; detected by name only and never run",
    "RPM-family accounting (psacct, /var/account/pacct) not driven",
    "a file larger than the 20000-record cap not driven; unit-tested");
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; }
finally {
  for (const forwarder of forwarders) forwarder.kill();
  sidecar?.close();
  await sleep(500);
  for (const fixture of fixtures) {
    try { fixture.owned(); podman("rm", "-f", fixture.containerId); checks.push({ label: `owned fixture ${fixture.name} removed`, passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/process_watch_sources.rs", "crates/lovelyhawk-backend/src/process_watch_api.rs",
    "tools/lab/probe-process-watch-sources.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(),
    images: fixtures.map(fixture => ({ name: fixture.name, imageId: fixture.imageId })), sourceHashes, observations, checks, error: failure ?? null,
    limits: ["backend RPC driven, no renderer", "the debian fixture has CAP_SYS_PACCT added so the probe itself can switch accounting on", "containers only: accounting here records this container's processes"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
