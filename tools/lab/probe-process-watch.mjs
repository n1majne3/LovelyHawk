// Backend RPC probe for the process watch (进程活动监视) Phase A /proc poll.
// Only runs against UUID-labelled disposable containers it creates itself.
//
// What has to hold on real targets:
//   * probe reports honest gaps (container, polling-misses-short-lived) and
//     never claims clean visibility;
//   * a 150 s watch at 500 ms sees the every-minute cron beacon at least
//     twice and the ~10 s marker at least ten times; the summary calls the
//     marker Periodic around 10 s;
//   * every row produced by the watcher or its helpers is flagged own — no
//     tool noise ever appears as a normal process event;
//   * cancel verifies the remote loop is really gone (independent ps);
//   * a second start while one runs is refused by code;
//   * killing the connection makes the watcher exit by itself no later than
//     its own deadline — nothing is left behind;
//   * the 20 000-event cap truncates and stops the remote loop;
//   * a non-root account still sees other users' command lines when
//     hidepid=0, and sees its limit honestly when it is not.
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
const evidence = path.join(repository, "target/desktop-debug", `process-watch-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pwatch-"));
const checks = [], observations = { notRun: [] };
let sidecar, failure;
const containers = [];
const forwarders = [];
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 }).trim();
const podmanTry = (...args) => {
  try { return { ok: true, out: podman(...args) }; }
  catch (error) { return { ok: false, out: String(error?.stderr ?? error?.message ?? error) }; }
};
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function note(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function makeOwned(containerId, imageId, name) {
  return () => {
    const target = JSON.parse(podman("inspect", containerId))[0];
    const strip = v => String(v ?? "").replace(/^sha256:/u, "");
    if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
      target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind"))
      throw new Error("Owned process-watch fixture identity changed");
    return target;
  };
}

// Processes of the marker itself: any /proc cmdline containing the run
// marker string is the remote watch loop.
function watcherPids(owned) {
  const out = owned.exec("sh", "-c",
    "for p in /proc/[0-9]*/cmdline; do if tr '\\0' ' ' < \"$p\" 2>/dev/null | grep -q 'lhwatc[h]-'; then echo ${p#/proc/}; fi; done");
  return out.split("\n").map(line => Number.parseInt(line, 10)).filter(pid => pid > 0);
}
function watcherTicks(owned, pid) {
  const stat = owned.exec("cat", `/proc/${pid}/stat`);
  const rest = stat.slice(stat.lastIndexOf(")") + 1).trim().split(/\s+/u);
  // utime + stime + cutime + cstime (fields 14-17): the loop's reaped helpers count too.
  return Number(rest[11]) + Number(rest[12]) + Number(rest[13]) + Number(rest[14]);
}
// Command substitutions fork short-lived copies carrying the same command
// line; the loop itself is the pid present in two samples.
async function stableWatcherPid(owned) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const first = watcherPids(owned);
    await sleep(700);
    const second = new Set(watcherPids(owned));
    const stable = first.filter(pid => second.has(pid));
    if (stable.length) return Math.min(...stable);
  }
  throw new Error("no stable watcher pid");
}
/** The remote shell needs a breath after start() returns; wait for it. */
async function waitWatcherCount(owned, want, timeoutMs = 8_000) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const found = watcherPids(owned);
    if ((want === 0 && found.length === 0) || (want > 0 && found.length >= want)) return found;
    if (Date.now() > until) return found;
    await sleep(500);
  }
}

const BEACON = "#!/bin/sh\nsleep 1\n";

try {
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  const sshKey = findKey(machine, "IdentityPath");
  const machinePort = findKey(machine, "Port");

  /** Start a disposable container and give it sshd + fixtures; returns helpers. */
  const startFixture = async (image, name, setup) => {
    const imageId = podman("image", "inspect", image, "--format", "{{.Id}}");
    const containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
      "--memory", "768m", "--cpus", "1", "--pids-limit", "256", imageId, "sleep", "infinity");
    const owned = makeOwned(containerId, imageId, name);
    owned.exec = (...args) => { owned(); return podman("exec", containerId, ...args); };
    containers.push({ containerId, imageId, name, owned });
    check(`${name}: owned unprivileged fixture up`, Boolean(owned()));
    setup(owned);
    const target = owned().NetworkSettings.IPAddress + ":22";
    const localPort = await new Promise(resolve => {
      const server = net.createServer().listen(0, "127.0.0.1", () => {
        const port = server.address().port; server.close(() => resolve(port));
      });
    });
    const forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
      "-i", sshKey, "-p", String(machinePort), "-N",
      "-L", `127.0.0.1:${localPort}:${target}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
    forwarders.push(forwarder);
    await sleep(1500);
    if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
    const openBinding = async (username, suffix) => {
      const status = await connect(sidecar, {
        host: "127.0.0.1", port: localPort, username, password: "LabRoot#2026",
        id: `${runId.slice(0, 8)}-${suffix}`, name: `${name}-${suffix}`,
      });
      check(`${name}: SSH binding connected as ${username}`, status?.stage === "connected");
      return status.bindingHandle;
    };
    const pollAll = async (binding, watchHandle) => {
      const out = { events: [], unparsed: [], last: null };
      let cursor = 0;
      for (let step = 0; step < 400; step += 1) {
        const result = await sidecar.call("process-watch.poll", {
          bindingHandle: binding, watchHandle, cursor, limit: 500,
        }, 30_000);
        out.events.push(...result.events);
        out.unparsed.push(...result.unparsed);
        cursor = result.nextCursor;
        out.last = result;
        if (result.state !== "running") break;
        await sleep(1_000);
      }
      return out;
    };
    return { owned, containerId, imageId, name, localPort, forwarder, openBinding, pollAll };
  };

  const write = (owned, target, content) => owned.exec("sh", "-c",
    `echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d > ${target}`);

  // ---- Debian fixture ------------------------------------------------------
  const deb = await startFixture("docker.io/library/debian:12-slim", `lr-pw-deb-${runId.slice(0, 8)}`, owned => {
    owned.exec("sh", "-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && " +
      "apt-get install -y -qq openssh-server cron procps >/dev/null && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && " +
      "mkdir -p /etc/ssh/sshd_config.d && printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n' > /etc/ssh/sshd_config.d/lab.conf && " +
      "echo 'root:LabRoot#2026' | chpasswd && /usr/sbin/sshd && command -v sshd cron sha256sum");
    write(owned, "/usr/local/bin/lh-beacon", BEACON);
    owned.exec("chmod", "0755", "/usr/local/bin/lh-beacon");
    owned.exec("sh", "-c", "printf 'SHELL=/bin/sh\\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\\n* * * * * root /usr/local/bin/lh-beacon\\n' > /etc/cron.d/lh-probe && service cron start && pgrep -x cron");
    // The ~10 s marker: a background loop spawning a ~800 ms process (longer than the 500 ms scan, so every cycle is catchable) every ten
    // seconds, detached from this exec so it survives it.
    owned.exec("sh", "-c", "setsid sh -c 'while :; do sh -c \"sleep 0.8\" & sleep 10; done' </dev/null >/dev/null 2>&1 &");
    owned.exec("sh", "-c", "useradd -m lhuser && echo 'lhuser:LabRoot#2026' | chpasswd");
  });
  const debBinding = await deb.openBinding("root", "root");

  // ---- probe --------------------------------------------------------------
  const probe = await sidecar.call("process-watch.probe", { bindingHandle: debBinding }, 60_000);
  check("probe readable with expected gap keys",
    probe.procReadable === true && probe.isRoot === true &&
    probe.gaps.includes("container") && probe.gaps.includes("polling-misses-short-lived"));
  observations.probe = probe;

  const start = (binding, durationSeconds, intervalMs = 500) => sidecar.call("process-watch.start", {
    bindingHandle: binding, input: { durationSeconds, intervalMs },
  }, 60_000);

  // ---- run A: second-start refusal + cancel with independent verify --------
  const runA = await start(debBinding, 150);
  check("run A started", typeof runA.watchHandle === "string");
  const second = await start(debBinding, 150).then(() => "started").catch(error => String(error.message));
  check("a second start while running is refused by code",
    /process-watch-already-running/u.test(second));
  check("watcher process visible on target while running",
    (await waitWatcherCount(deb.owned, 1)).length === 1);
  await sleep(20_000);
  const stopped = await sidecar.call("process-watch.stop", {
    bindingHandle: debBinding, watchHandle: runA.watchHandle,
  }, 30_000);
  check("cancel reports cancelled and independently verified",
    stopped.state === "cancelled" && stopped.stopVerified === true);
  check("independent ps: no watcher remains after cancel",
    (await waitWatcherCount(deb.owned, 0)).length === 0);

  // ---- run B: full 150 s watch + CPU measure --------------------------------
  const runB = await start(debBinding, 150);
  check("run B started", typeof runB.watchHandle === "string");
  const cpuPid = await stableWatcherPid(deb.owned);
  const ticks0 = watcherTicks(deb.owned, cpuPid);
  const cpuStart = Date.now();
  const polling = deb.pollAll(debBinding, runB.watchHandle);
  await sleep(60_000);
  const cpuTicks = watcherTicks(deb.owned, cpuPid) - ticks0;
  const cpuSeconds = (Date.now() - cpuStart) / 1_000;
  const collected = await polling;
  const cpuPercent = (cpuTicks / 100) / cpuSeconds * 100;
  observations.watcherCpu = {
    utimeStimeTicks: cpuTicks, wallSeconds: Math.round(cpuSeconds),
    approxPercent: Math.round(cpuPercent * 100) / 100,
  };
  check("run B reached finished within deadline", collected.last.state === "finished");
  check("baseline snapshot populated", collected.last.baselineCount > 0);
  const beacons = collected.events.filter(item => item.origin === "observed" && item.command.includes("lh-beacon"));
  const markers = collected.events.filter(item => item.origin === "observed" && item.command.includes("sleep 0.8"));
  check(`every-minute cron beacon seen at least twice (got ${beacons.length})`, beacons.length >= 2);
  check(`10 s marker seen at least ten times (got ${markers.length})`, markers.length >= 10);
  check("all observed events carry uid/pid and a raw line",
    collected.events.every(item => Number.isInteger(item.uid) && Number.isInteger(item.pid) && item.raw.length > 0));
  check("the marker's uid is read as root, not unknown", markers.length > 0 && markers.every(item => item.uid === 0));
  // Tool noise: the watcher and anything it spawned is own=true, never a
  // normal event.
  const watcherPid = cpuPid;
  const toolRows = collected.events.filter(item => item.pid === watcherPid || item.ppid === watcherPid ||
    item.command.includes("lhwatch"));
  check("watcher and its helpers are all flagged own",
    toolRows.length > 0 && toolRows.every(item => item.own === true));
  check("no own-flagged row leaks into ordinary observed commands",
    collected.events.every(item => !item.own || item.origin === "baseline" ||
      item.pid === watcherPid || item.ppid === watcherPid || item.command.includes("lhwatch") ||
      ["cat", "date", "stat", "wc", "head", "od", "base64", "grep", "tr"].some(word => item.command.startsWith(word + " ") || item.command === word)));

  const summaryB = await sidecar.call("process-watch.summary", {
    bindingHandle: debBinding, watchHandle: runB.watchHandle,
  }, 60_000);
  const markerGroup = summaryB.groups.find(group => group.normalized.includes("sleep 0.8") || group.sample.includes("sleep 0.8"));
  check("summary marks the 10 s marker periodic at ~10 s",
    markerGroup !== undefined && markerGroup.cadence === "periodic" &&
    markerGroup.periodMs !== null && markerGroup.periodMs >= 8_000 && markerGroup.periodMs <= 12_000);
  const beaconGroup = summaryB.groups.find(group => group.normalized.includes("lh-beacon") || group.sample.includes("lh-beacon"));
  check("cron beacon grouped as repeated or periodic",
    beaconGroup !== undefined && (beaconGroup.cadence === "repeated" || beaconGroup.cadence === "periodic"));
  observations.runB = { markerGroups: summaryB.groups.filter(g => g.sample.includes("sleep 0.8")).map(g => ({ sample: g.sample, count: g.count, cadence: g.cadence, periodMs: g.periodMs })),
    observed: collected.last.observedCount, baseline: collected.last.baselineCount,
    own: collected.last.ownCount, beacons: beacons.length, markers: markers.length,
    groups: summaryB.groups.length,
  };

  // ---- run C: connection drop → self-deadline --------------------------------
  const runC = await start(debBinding, 60);
  const deadlineAt = Date.now() + 61_000;
  check("run C started", typeof runC.watchHandle === "string");
  // Kill the forwarding path under the backend: the target's sshd dies and
  // the watcher must end by itself no later than its deadline.
  deb.forwarder.kill();
  let goneAt = null;
  while (Date.now() < deadlineAt + 15_000) {
    if (watcherPids(deb.owned).length === 0) { goneAt = Date.now(); break; }
    await sleep(2_000);
  }
  check("watcher self-exited after connection drop, no later than its deadline",
    goneAt !== null && goneAt <= deadlineAt);
  observations.disconnectExit = { goneAt: goneAt === null ? null : goneAt - (deadlineAt - 61_000), deadlineMs: 60_000 };
  check("no watcher left behind after disconnect",
    (await waitWatcherCount(deb.owned, 0)).length === 0);

  // Reconnect path: a fresh forward and a fresh binding must still work.
  deb.forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
    "-i", sshKey, "-p", String(machinePort), "-N",
    "-L", `127.0.0.1:${deb.localPort}:${deb.owned().NetworkSettings.IPAddress}:22`, "root@127.0.0.1"],
    { windowsHide: true, stdio: "ignore" });
  forwarders.push(deb.forwarder);
  await sleep(1_500);
  const rebinding = await deb.openBinding("root", "root2");
  const runC2 = await start(rebinding, 60);
  check("after reconnect a new watch works", typeof runC2.watchHandle === "string");
  const collectedC2 = await deb.pollAll(rebinding, runC2.watchHandle);
  check("reconnected watch finished", collectedC2.last.state === "finished");
  const markers2 = collectedC2.events.filter(item => item.command.includes("sleep 0.8"));
  check(`reconnected watch still sees the marker (got ${markers2.length})`, markers2.length >= 3);

  // ---- run D: truncation ----------------------------------------------------
  // A few processes carrying a 60 KB argument each: their command lines
  // alone fill the 4 MiB output cap, so the remote loop is stopped early.
  deb.owned.exec("sh", "-c", "setsid sh -c 'pad=$(head -c 60000 /dev/zero | tr -c x x); while :; do sh -c \"sleep 1.2\" lhpad \"$pad\" & sleep 2; done' </dev/null >/dev/null 2>&1 &");
  const runD = await start(rebinding, 300);
  const collectedD = await deb.pollAll(rebinding, runD.watchHandle);
  deb.owned.exec("sh", "-c", "pkill -f 'lhpa[d]' 2>/dev/null; true");
  const padded = collectedD.events.filter(item => item.command.includes("lhpad")).length;
  check(`the output cap truncates the watch (state ${collectedD.last.state}, ${padded} padded rows, ${collectedD.last.unparsedCount} unparsed)`,
    collectedD.last.state === "truncated" && collectedD.last.truncated === true);
  check("the remote loop stopped after truncation",
    (await waitWatcherCount(deb.owned, 0)).length === 0);
  observations.truncation = {
    state: collectedD.last.state, observed: collectedD.last.observedCount,
    unparsed: collectedD.last.unparsedCount,
  };
  deb.owned.exec("sh", "-c", "pkill -f 'lhpa[d]' 2>/dev/null; true");

  // ---- run E: non-root account sees other users' command lines --------------
  const userBinding = await deb.openBinding("lhuser", "user");
  const userProbe = await sidecar.call("process-watch.probe", { bindingHandle: userBinding }, 60_000);
  check("non-root probe: readable, isRoot false, no hidepid gap at hidepid=0",
    userProbe.procReadable === true && userProbe.isRoot === false && !userProbe.gaps.includes("hidepid"));
  const runE = await start(userBinding, 60);
  const collectedE = await deb.pollAll(userBinding, runE.watchHandle);
  const foreign = collectedE.events.filter(item => item.origin === "observed" &&
    item.command.includes("sleep 0.8") && item.uid === 0);
  check(`non-root watch sees root's marker argv (got ${foreign.length})`, foreign.length >= 2);
  observations.nonRoot = { isRoot: userProbe.isRoot, foreignSeen: foreign.length };

  // ---- run F: hidepid=2 attempt (privilege may forbid it) --------------------
  const remount = podmanTry("exec", deb.containerId, "mount", "-o", "remount,hidepid=2", "/proc");
  if (remount.ok) {
    const probe2 = await sidecar.call("process-watch.probe", { bindingHandle: userBinding }, 60_000);
    check("hidepid=2 produces the hidepid gap for a non-root account",
      probe2.gaps.includes("hidepid"));
    podmanTry("exec", deb.containerId, "mount", "-o", "remount,hidepid=0", "/proc");
  } else {
    observations.notRun.push(
      `hidepid=2 remount refused by the unprivileged container (${remount.out.split("\n")[0]}): ` +
      "an unprivileged podman container cannot remount /proc, so the hidepid gap is unit-tested only");
    console.log("NOT_RUN hidepid=2 gap check — unprivileged container cannot remount /proc");
  }

  // ---- Alpine fixture ---------------------------------------------------------
  const alp = await startFixture("docker.io/library/alpine:3.20", `lr-pw-alp-${runId.slice(0, 8)}`, owned => {
    owned.exec("sh", "-c", "apk add --no-cache -q openssh >/dev/null && ssh-keygen -A >/dev/null && " +
      "mkdir -p /etc/ssh/sshd_config.d && printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n' > /etc/ssh/sshd_config.d/lab.conf && " +
      "echo 'root:LabRoot#2026' | chpasswd && /usr/sbin/sshd && command -v sshd crond");
    write(owned, "/usr/local/bin/lh-beacon", BEACON);
    owned.exec("chmod", "0755", "/usr/local/bin/lh-beacon");
    owned.exec("sh", "-c", "mkdir -p /etc/crontabs && printf '* * * * * /usr/local/bin/lh-beacon\\n' > /etc/crontabs/root && crond && pgrep -x crond");
    owned.exec("sh", "-c", "setsid sh -c 'while :; do sh -c \"sleep 0.8\" & sleep 10; done' </dev/null >/dev/null 2>&1 &");
  });
  const alpBinding = await alp.openBinding("root", "root");
  const alpProbe = await sidecar.call("process-watch.probe", { bindingHandle: alpBinding }, 60_000);
  check("alpine probe: readable, container + short-lived gaps",
    alpProbe.procReadable === true && alpProbe.gaps.includes("container") &&
    alpProbe.gaps.includes("polling-misses-short-lived"));
  const runG = await start(alpBinding, 70);
  const collectedG = await alp.pollAll(alpBinding, runG.watchHandle);
  check("alpine watch finished under busybox sh", collectedG.last.state === "finished");
  const alpBeacon = collectedG.events.filter(item => item.command.includes("lh-beacon"));
  const alpMarker = collectedG.events.filter(item => item.command.includes("sleep 0.8"));
  check(`alpine: crond beacon seen (got ${alpBeacon.length})`, alpBeacon.length >= 1);
  check(`alpine: 10 s marker seen (got ${alpMarker.length})`, alpMarker.length >= 4);
  const alpSummary = await sidecar.call("process-watch.summary", {
    bindingHandle: alpBinding, watchHandle: runG.watchHandle,
  }, 60_000);
  const alpGroup = alpSummary.groups.find(group => group.sample.includes("sleep 0.8"));
  check("alpine: marker grouped periodic at ~10 s",
    alpGroup !== undefined && alpGroup.cadence === "periodic" &&
    alpGroup.periodMs !== null && alpGroup.periodMs >= 8_000 && alpGroup.periodMs <= 12_500);
  observations.alpine = { beacons: alpBeacon.length, markers: alpMarker.length };
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (sidecar) { try { sidecar.close(); } catch {} }
  for (const forwarder of forwarders) { try { forwarder.kill(); } catch {} }
  for (const { containerId, owned, name } of containers) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: `${name} removed`, passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  const sourceHashes = {};
  for (const file of [
    "crates/lovelyhawk-core/src/process_watch.rs",
    "crates/lovelyhawk-backend/src/process_watch_api.rs",
  ]) {
    sourceHashes[file] = createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16);
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), sourceHashes, observations,
    checks, error: failure ?? null,
    limits: [
      "backend RPC driven, no renderer",
      "container sees only its own processes — host-level visibility needs a VM or real host",
      "sudo -n path not driven; watches ran as root and as an ordinary user",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
