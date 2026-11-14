// Backend RPC probe for the process watch upload method (pspy) and the
// analysis that follows a run. Only runs against a UUID-labelled disposable
// container it creates itself. The pspy binary is not in the repository:
// pass its path as LOVELYHAWK_PSPY (default tmp/pspy/pspy64, an upstream
// v1.2.1 release asset the operator downloaded).
//
// What has to hold on a real target:
//   * the picked file is identified by its bytes, and anything that is not
//     a Linux program is refused before it is kept;
//   * the plan names where the file lands and what the run cannot see, and
//     nothing is written until the plan is started;
//   * the bytes on the target are the bytes that were picked;
//   * deadline, cancel and a dropped connection all leave no process, and
//     the first two leave no file either — checked from outside the app;
//   * what a dropped connection leaves behind is found on the next
//     connection and can be cleared;
//   * a spent plan cannot run again, and a mount that forbids running
//     programs is refused by its own code;
//   * the summary attributes the cron fixture to cron and to its crontab,
//     maps the fixture check script's steps to workbench entries, and lists
//     the step it has no entry for.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-pwup-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `process-watch-upload-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pwup-"));
const toolPath = path.resolve(repository, process.env.LOVELYHAWK_PSPY ?? "tmp/pspy/pspy64");
const checks = [], observations = { notRun: [] };
let sidecar, failure, containerId, imageId, forwarder;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 30_000) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return true; await sleep(500); } throw new Error(`Timed out: ${label}`); }
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind"))
    throw new Error("Owned process watch upload fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sh = script => onHost("sh", "-c", script);
const write = (target, content) => sh(`echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d > ${target}`);
// Everything the app wrote lives in a directory with this name; the checks
// below look for it and for anything running out of it from outside the app.
const landings = () => sh("ls -d /dev/shm/.lovelyhawk-watch-* /tmp/.lovelyhawk-watch-* /var/tmp/.lovelyhawk-watch-* /root/.lovelyhawk-watch-* /home/*/.lovelyhawk-watch-* 2>/dev/null || true")
  .split("\n").filter(Boolean);
// By command line, not /proc/<pid>/exe: this container's root has no ptrace
// capability, so it cannot read another account's exe link.
const toolProcesses = () => sh("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null | grep -qE '^/[^ ]*/\\.lovelyhawk-watch-[0-9a-f]{16}/pspy ' && echo ${p#/proc/}; done; true")
  .split("\n").filter(Boolean);

const CHECK_SCRIPT = `#!/bin/sh
sh -c 'cat /etc/crontab >/dev/null; sleep 1.6'
sh -c 'lsmod >/dev/null 2>&1; sleep 1.6'
sh -c 'find /usr/bin -perm -4000 >/dev/null 2>&1; sleep 1.6'
sh -c 'cat /etc/profile >/dev/null; sleep 1.6'
sh -c 'sleep 1.6; : lh-unmapped-step http://203.0.113.9/payload'
`;

try {
  if (!fs.existsSync(toolPath)) throw new Error(`pspy binary not found at ${toolPath}; set LOVELYHAWK_PSPY`);
  const localSha = createHash("sha256").update(fs.readFileSync(toolPath)).digest("hex");
  imageId = podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  // /tmp and /var/tmp forbid running programs, as hardened hosts do; /dev/shm
  // is too small for the program. The plan has to find its way past both.
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "768m", "--cpus", "1", "--pids-limit", "256",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--tmpfs", "/var/tmp:rw,noexec,nosuid,size=64m", "--shm-size", "1m",
    imageId, "sleep", "infinity");
  check("fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  sh("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && " +
    "apt-get install -y -qq openssh-server cron procps >/dev/null 2>&1 && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && " +
    "mkdir -p /etc/ssh/sshd_config.d && printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n' > /etc/ssh/sshd_config.d/lab.conf && " +
    "echo 'root:LabRoot#2026' | chpasswd && useradd -m lhuser && echo 'lhuser:LabRoot#2026' | chpasswd && " +
    "useradd -d /tmp/lhjail lhjail && mkdir -p /tmp/lhjail && chown lhjail /tmp/lhjail && echo 'lhjail:LabRoot#2026' | chpasswd && /usr/sbin/sshd");
  write("/usr/local/bin/lh-beacon", "#!/bin/sh\nsleep 1.5\n");
  write("/usr/local/bin/lh-check", CHECK_SCRIPT);
  sh("chmod 0755 /usr/local/bin/lh-beacon /usr/local/bin/lh-check");
  sh("printf 'SHELL=/bin/sh\\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\\n* * * * * root /usr/local/bin/lh-beacon\\n' > /etc/cron.d/lh-probe && service cron start >/dev/null && pgrep -x cron");
  sh("setsid sh -c 'while :; do sh -c \"sleep 0.8\" & sleep 10; done' </dev/null >/dev/null 2>&1 &");

  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  const localPort = await new Promise(resolve => {
    const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  const forward = () => spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-i", findKey(machine, "IdentityPath"),
    "-p", String(findKey(machine, "Port")), "-N", "-L", `127.0.0.1:${localPort}:${owned().NetworkSettings.IPAddress}:22`, "root@127.0.0.1"],
    { windowsHide: true, stdio: "ignore" });
  forwarder = forward();
  await sleep(1500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");

  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const bind = async (username, suffix) => {
    const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username, password: "LabRoot#2026", id: `${runId.slice(0, 8)}-${suffix}`, name: `${name}-${suffix}` });
    check(`SSH binding connected as ${username}`, status?.stage === "connected");
    return status.bindingHandle;
  };
  const call = (method, params, ms = 60_000) => sidecar.call(method, params, ms);
  const refused = (method, params, ms) => call(method, params, ms).then(() => "accepted", error => String(error.message));
  const pollAll = async (bindingHandle, watchHandle) => {
    const out = { events: [], unparsed: [], last: null };
    let cursor = 0;
    for (let step = 0; step < 300; step += 1) {
      const result = await call("process-watch.poll", { bindingHandle, watchHandle, cursor, limit: 500 });
      out.events.push(...result.events); out.unparsed.push(...result.unparsed);
      cursor = result.nextCursor; out.last = result;
      if (result.state !== "running") break;
      await sleep(1_000);
    }
    return out;
  };
  const root = await bind("root", "root");

  // ---- the picked file ------------------------------------------------------
  const tool = await call("process-watch.tool.load-path", { localPath: toolPath });
  observations.tool = { ...tool, toolHandle: "<handle>" };
  check("the picked file is identified by its own bytes",
    tool.sha256 === localSha && tool.size === fs.statSync(toolPath).size && tool.arch === "x86_64");
  check("an upstream release asset is recognized by digest", /^pspy64s? v1\.2\.1$/u.test(tool.recognized ?? "") || process.env.LOVELYHAWK_PSPY !== undefined);
  const notProgram = path.join(dataRoot, "notes.txt");
  fs.writeFileSync(notProgram, "not a program\n".repeat(8_000));
  check("a file that is not a Linux program is refused by code",
    /process-watch-tool-rejected/u.test(await refused("process-watch.tool.load-path", { localPath: notProgram })));
  check("a missing file is refused by code",
    /process-watch-tool-rejected/u.test(await refused("process-watch.tool.load-path", { localPath: path.join(dataRoot, "absent") })));
  check("the page-facing plan method takes no local path",
    /invalid-params/u.test(await refused("process-watch.upload.plan", { bindingHandle: root, input: { localPath: toolPath, durationSeconds: 60, fileEvents: false } })));

  // ---- plan: nothing written, the right directory chosen ----------------------
  const input = (fileEvents = false, durationSeconds = 60) => ({ toolHandle: tool.toolHandle, durationSeconds, fileEvents });
  const plan = await call("process-watch.upload.plan", { bindingHandle: root, input: input() });
  observations.plan = { ...plan, planHandle: "<handle>" };
  check("the plan skips the noexec and too-small directories and lands in the home directory",
    /^\/root\/\.lovelyhawk-watch-[0-9a-f]{16}$/u.test(plan.directory));
  check("the plan carries the digest, the account and the honest gaps",
    plan.sha256 === localSha && plan.account === "root" && plan.durationSeconds === 60 &&
    plan.gaps.includes("container") && plan.gaps.includes("tool-may-miss-short-lived") && !plan.gaps.includes("polling-misses-short-lived"));
  check("planning writes nothing to the target", landings().length === 0 && toolProcesses().length === 0);

  // ---- run to the deadline ------------------------------------------------------
  sh("setsid sh -c 'sleep 12; /usr/local/bin/lh-check' </dev/null >/dev/null 2>&1 &");
  const started = await call("process-watch.upload.start", { bindingHandle: root, planHandle: plan.planHandle }, 240_000);
  check("the confirmed plan starts a pspy watch", started.method === "pspy" && typeof started.watchHandle === "string");
  check("a spent plan cannot be started again",
    /process-watch-plan-unavailable/u.test(await refused("process-watch.upload.start", { bindingHandle: root, planHandle: plan.planHandle })));
  await until(() => toolProcesses().length > 0, "tool running");
  const landed = sh(`stat -c '%a %U' ${plan.directory} ${plan.directory}/pspy && sha256sum ${plan.directory}/pspy`).split("\n");
  observations.landed = landed;
  check("independent readback: private directory, private file, same bytes",
    landed[0] === "700 root" && landed[1] === "700 root" && landed[2].startsWith(localSha));
  check("a second watch while this one runs is refused",
    /process-watch-already-running/u.test(await refused("process-watch.start", { bindingHandle: root, input: { durationSeconds: 60, intervalMs: 500 } })));
  const run = await pollAll(root, started.watchHandle);
  fs.writeFileSync(path.join(evidence, "run-events.json"), JSON.stringify(run.events.map(event => ({ at: event.atMs, pid: event.pid, ppid: event.ppid, own: event.own, origin: event.origin, command: event.command.slice(0, 120) })), null, 1));
  observations.run = { state: run.last.state, cleanup: run.last.cleanup, observed: run.last.observedCount, baseline: run.last.baselineCount, own: run.last.ownCount, unparsed: run.unparsed.slice(0, 5) };
  check("the run ends at its deadline and reports a verified cleanup", run.last.state === "finished" && run.last.cleanup === "clean");
  check("independent readback: no tool process and no landing directory", toolProcesses().length === 0 && landings().length === 0);
  const visible = run.events.filter(event => event.origin === "observed" && !event.own);
  const markers = visible.filter(event => event.command === "sleep 0.8");
  check(`baseline came from /proc and the 10 s marker was seen (got ${markers.length})`, run.last.baselineCount > 0 && markers.length >= 4);
  check("rows carry uid, pid and parent pid", markers.every(event => event.uid === 0 && event.pid > 0 && Number.isInteger(event.ppid)));
  check("the tool and this wrapper never appear as ordinary activity",
    visible.every(event => !event.command.startsWith(plan.directory) && !event.command.includes("lhwatch-") && !event.command.startsWith("tr \\000")));
  check("the tool's banner is not counted as unreadable output", run.unparsed.every(row => !/pspy - version|Config:|Draining/u.test(row.raw)));

  // ---- analysis ---------------------------------------------------------------------
  const summary = await call("process-watch.summary", { bindingHandle: root, watchHandle: started.watchHandle });
  observations.summary = { origins: summary.origins, inferred: summary.inferred, unmatched: summary.unmatched.slice(0, 12), indicators: summary.indicators,
    scheduleRead: summary.scheduleRead, groups: summary.groups.slice(0, 12).map(group => ({ sample: group.sample, count: group.count, cadence: group.cadence, origin: group.origin, schedule: group.schedule })) };
  const beacon = summary.groups.find(group => group.sample.includes("lh-beacon"));
  check("the cron fixture is attributed to cron and to the crontab that schedules it",
    summary.scheduleRead === true && beacon?.origin === "cron" && beacon?.schedule === "/etc/cron.d/lh-probe");
  const marker = summary.groups.find(group => group.sample === "sleep 0.8");
  check("the repeating marker has no schedule and is not called cron", marker !== undefined && marker.count >= 4 && marker.cadence !== "single" && marker.schedule === null && marker.origin !== "cron");
  check("nothing but the cron fixture claims a crontab", summary.groups.every(group => group.schedule === null || /lh-beacon|CRON/u.test(group.sample)));
  const inferredIds = summary.inferred.map(item => item.entryId);
  check("each mapped step of the check script names its workbench entry",
    ["persistence-system-crontab", "system-modules", "perm-suid", "persistence-profile-content"].every(id => inferredIds.includes(id)) &&
    summary.inferred.every(item => typeof item.title === "string" && item.title.length > 0));
  check("the step with no entry is listed as unmatched, not dropped",
    summary.unmatched.some(item => item.command.includes("lh-unmapped-step")));
  check("an address on a command line becomes a lead",
    summary.indicators.some(item => item.value.includes("203.0.113.9")));

  // ---- cancel ---------------------------------------------------------------------------
  const planB = await call("process-watch.upload.plan", { bindingHandle: root, input: input() });
  const runB = await call("process-watch.upload.start", { bindingHandle: root, planHandle: planB.planHandle }, 240_000);
  await until(() => toolProcesses().length > 0, "tool running for cancel");
  await sleep(6_000);
  const stopped = await call("process-watch.stop", { bindingHandle: root, watchHandle: runB.watchHandle });
  observations.cancel = stopped;
  check("cancel reports the stop verified and the cleanup clean", stopped.state === "cancelled" && stopped.stopVerified === true && stopped.cleanup === "clean");
  check("independent readback after cancel: nothing running, nothing left", toolProcesses().length === 0 && landings().length === 0);

  // ---- file events ------------------------------------------------------------------------
  const planF = await call("process-watch.upload.plan", { bindingHandle: root, input: input(true) });
  check("file events are limited to the fixed directories and say so",
    planF.fileEvents === true && planF.gaps.includes("file-events-limited") && planF.fileEventDirs.includes("/etc") && !planF.fileEventDirs.includes("/usr"));
  const runF = await call("process-watch.upload.start", { bindingHandle: root, planHandle: planF.planHandle }, 240_000);
  await until(() => toolProcesses().length > 0, "tool running for file events");
  // pspy needs a few seconds to place its watchers; write more than once.
  for (let round = 0; round < 12; round += 1) {
    await sleep(2_500);
    sh("echo lh > /etc/lh-probe-touched; cat /etc/lh-probe-touched >/dev/null");
  }
  await sleep(2_000);
  await call("process-watch.stop", { bindingHandle: root, watchHandle: runF.watchHandle });
  const files = await pollAll(root, runF.watchHandle);
  const fileRows = files.events.filter(event => event.kind === "file" && event.command.includes("/etc/lh-probe-touched"));
  observations.fileEvents = { matching: fileRows.slice(0, 6).map(event => event.command), allFileRows: files.events.filter(event => event.kind === "file").length,
    rows: files.events.length, state: files.last.state, startedAt: runF.startedAtMs ?? null,
    otherFileRows: files.events.filter(event => event.kind === "file").slice(0, 5).concat(files.events.filter(event => event.kind === "file").slice(-5)).map(event => `${event.atMs} ${event.command}`.slice(0, 140)), unparsed: files.unparsed.slice(0, 6) };
  console.log("  file run:", JSON.stringify(observations.fileEvents).slice(0, 700));
  const paged = [];
  for (let cursor = 0, step = 0; step < 100; step += 1) {
    const part = await call("process-watch.poll", { bindingHandle: root, watchHandle: runF.watchHandle, cursor, limit: 50 });
    paged.push(...part.events.map(event => event.seq));
    if (part.nextCursor === cursor && part.state !== "running") break;
    cursor = part.nextCursor;
  }
  check(`reading fifty rows at a time returns the same rows, none skipped (got ${paged.length})`,
    paged.join() === files.events.map(event => event.seq).join());
  check(`rows reported while nobody was reading are kept when the watch is cancelled (got ${files.events.length})`, files.events.length > 64);
  check(`a file written under /etc shows up as file events (got ${fileRows.length})`, fileRows.length >= 1 && fileRows.every(event => event.pid === 0 && event.uid === -1));
  const summaryF = await call("process-watch.summary", { bindingHandle: root, watchHandle: runF.watchHandle });
  check("file events are counted apart from processes", summaryF.fileEvents >= fileRows.length && summaryF.groups.every(group => !/^(OPEN|CREATE|MODIFY|ACCESS|CLOSE_\w+|DELETE|ATTRIB) \//u.test(group.sample)));
  check("independent readback after the file-event run", toolProcesses().length === 0 && landings().length === 0);

  // ---- a mount that forbids running programs ----------------------------------------------
  const jail = await bind("lhjail", "jail");
  check("an account with only noexec directories is refused by its own code",
    /process-watch-upload-no-directory/u.test(await refused("process-watch.upload.plan", { bindingHandle: jail, input: input() })));
  check("the refusal wrote nothing", landings().length === 0);

  // ---- an ordinary account ---------------------------------------------------------------------
  const user = await bind("lhuser", "user");
  const planU = await call("process-watch.upload.plan", { bindingHandle: user, input: input() });
  check("an ordinary account lands in its own home and runs as itself", planU.directory.startsWith("/home/lhuser/.lovelyhawk-watch-") && planU.account === "lhuser" && planU.isRoot === false);
  const runU = await call("process-watch.upload.start", { bindingHandle: user, planHandle: planU.planHandle }, 240_000);
  await until(() => toolProcesses().length > 0, "tool running as user");
  check("independent readback: the tool runs as the ordinary account", sh(`stat -c %U /proc/${toolProcesses()[0]}`) === "lhuser");
  await sleep(34_000);
  const stoppedU = await call("process-watch.stop", { bindingHandle: user, watchHandle: runU.watchHandle });
  const userRun = await pollAll(user, runU.watchHandle);
  const foreign = userRun.events.filter(event => event.command === "sleep 0.8" && event.uid === 0);
  observations.userRun = { state: userRun.last?.state, events: userRun.events.length, unparsed: userRun.unparsed.length,
    sample: userRun.events.filter(event => !event.own).slice(0, 12).map(event => `${event.uid} ${event.command}`.slice(0, 120)),
    bracketed: userRun.events.filter(event => /^\[/u.test(event.command)).slice(0, 12).map(event => ({ uid: event.uid, pid: event.pid, ppid: event.ppid, own: event.own, origin: event.origin, raw: String(event.raw).slice(0, 200) })),
    markerLoopAlive: sh("pgrep -f 'while :; do sh -c' | wc -l") };
  check(`without root it still sees root's short processes (got ${foreign.length})`, foreign.length >= 1 && stoppedU.cleanup === "clean");
  check("independent readback after the ordinary account's run", toolProcesses().length === 0 && landings().length === 0);

  // ---- dropped connection, then residue -----------------------------------------------------------
  // Connecting as another account replaced the first binding.
  const rootAgain = await bind("root", "root1");
  const planC = await call("process-watch.upload.plan", { bindingHandle: rootAgain, input: input() });
  await call("process-watch.upload.start", { bindingHandle: rootAgain, planHandle: planC.planHandle }, 240_000);
  await until(() => toolProcesses().length > 0, "tool running before disconnect");
  const dropAt = Date.now();
  forwarder.kill();
  await until(() => toolProcesses().length === 0, "tool gone after disconnect", 75_000);
  observations.disconnect = { toolGoneAfterMs: Date.now() - dropAt, left: landings() };
  check(`after the connection drops the tool stops by itself well before its 60 s deadline (${Math.round((Date.now() - dropAt) / 1000)} s after the drop)`, Date.now() - dropAt < 20_000);
  check("what the dropped run left is exactly its landing directory", landings().length === 1 && landings()[0] === planC.directory);
  forwarder = forward();
  await sleep(1500);
  const again = await bind("root", "root2");
  const residues = await call("process-watch.residue.list", { bindingHandle: again });
  observations.residues = residues.map(residue => ({ ...residue, residueHandle: "<handle>" }));
  check("the next connection finds the residue on the target and knows what it is",
    residues.length === 1 && residues[0].directory === planC.directory && residues[0].sha256 === localSha && residues[0].running === false);
  check("a forged residue handle clears nothing",
    /process-watch-plan-unavailable|invalid-params/u.test(await refused("process-watch.residue.clean", { bindingHandle: again, residueHandle: randomUUID() })) && landings().length === 1);
  const cleaned = await call("process-watch.residue.clean", { bindingHandle: again, residueHandle: residues[0].residueHandle });
  check("clearing the residue is verified", cleaned.cleanup === "clean");
  check("independent readback: the residue is gone", landings().length === 0 && toolProcesses().length === 0);
  check("a residue handle works once",
    /process-watch-plan-unavailable/u.test(await refused("process-watch.residue.clean", { bindingHandle: again, residueHandle: residues[0].residueHandle })));
  check("with nothing left, the list is empty", (await call("process-watch.residue.list", { bindingHandle: again })).length === 0);

  // ---- the journal names what was written and what became of it ----------------------------------
  const journalFile = fs.readdirSync(path.join(dataRoot, "data"), { recursive: true }).map(String).find(file => /journal/iu.test(file) && file.endsWith(".json"));
  const journalText = journalFile ? fs.readFileSync(path.join(dataRoot, "data", journalFile), "utf8") : "";
  observations.journalFile = journalFile ?? null;
  check("the operation journal records the upload with its digest and the verified cleanup",
    journalText.includes(localSha) && journalText.includes("process-watch") && journalText.includes("回读确认进程不在"));
  check("no command line reached the journal", !journalText.includes("lh-unmapped-step") && !journalText.includes("sleep 0.8"));
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; }
finally {
  forwarder?.kill();
  sidecar?.close();
  await sleep(500);
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned fixture removed", passed: true }); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/process_watch.rs", "crates/lovelyhawk-core/src/process_watch_upload.rs",
    "crates/lovelyhawk-core/src/process_watch_analysis.rs", "crates/lovelyhawk-backend/src/process_watch_api.rs",
    "crates/lovelyhawk-backend/src/process_watch_api/upload.rs", "tools/lab/probe-process-watch-upload.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["backend RPC driven, no renderer", "one debian:12-slim container: only this container's processes are visible",
      "x86_64 only; other architectures and the no-space refusal are unit-tested", "sudo -n not driven"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
