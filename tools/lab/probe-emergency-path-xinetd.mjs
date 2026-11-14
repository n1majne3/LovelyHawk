// Backend RPC probe for the disable-xinetd-service path action.
// Only runs against a UUID-labelled disposable container it creates itself.
//
// What has to hold on a real target:
//   * the 超级守护进程服务 workbench entry offers each /etc/xinetd.d/<name>
//     as a handle carrying xinetdService; ignored names and symlinks refuse
//     at plan time with their own codes;
//   * the plan freezes the file digest, the effective port and the reload
//     method (verified SIGHUP when the daemon runs, 无需重载 when it does
//     not) — execute re-checks both and refuses untouched when either
//     moved on;
//   * execute moves the file into /etc/xinetd.d/.lovelyres-backups (a name
//     xinetd itself skips because it contains a dot), reloads, and only
//     passes when the port is no longer listened on — a port still held
//     fails the receipt but keeps the file isolated and undoable, it is
//     never put back automatically;
//   * undo puts the bytes back, reloads the current daemon instance and
//     the port accepts connections again — all of that verified from
//     outside the app with podman exec, never with receipts alone.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-xinetd-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `xinetd-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-xinetd-"));
const checks = [], observations = {};
let containerId, imageId, sidecar, failure, forwarder;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind"))
    throw new Error("Owned xinetd fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const write = (target, content) => onHost("sh", "-c", `echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d > ${target}`);
const append = (target, content) => onHost("sh", "-c", `echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d >> ${target}`);
const sha = target => onHost("sha256sum", target).split(/\s+/u)[0];
// bash /dev/tcp is the independent probe of "is this port really served" —
// never the app's own listener readout.
const port = p => onHost("sh", "-c", `bash -c 'exec 3<>/dev/tcp/127.0.0.1/${p}' 2>/dev/null && echo OPEN || echo CLOSED`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const service = (svc, p) => `service ${svc}\n{\n        id              = ${svc}\n        type            = UNLISTED\n        disable         = no\n        socket_type     = stream\n        protocol        = tcp\n        port            = ${p}\n        wait            = no\n        user            = root\n        server          = /bin/cat\n}\n`;
const LHSVC = service("lhsvc", 10005);
const LHSVC2 = service("lhsvc2", 10006);
const LHSVC3 = service("lhsvc3", 10007);
const LHSVC4 = service("lhsvc4", 10008);
const LHSVC5 = service("lhsvc5", 10009);

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("xinetd fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install -y -qq xinetd netcat-openbsd iproute2 >/dev/null && command -v xinetd nc ss bash sha256sum pgrep");
  write("/etc/xinetd.d/lhsvc", LHSVC);
  write("/etc/xinetd.d/lhsvc2", LHSVC2);
  write("/etc/xinetd.d/lhsvc3", LHSVC3);
  write("/etc/xinetd.d/lhsvc4", LHSVC4);
  write("/etc/xinetd.d/lhsvc5", LHSVC5);
  write("/etc/xinetd.d/svc.bak", service("baksvc", 10010));
  onHost("ln", "-s", "/etc/xinetd.d/lhsvc", "/etc/xinetd.d/lhlink");
  // A foreign process takes 10008 before xinetd starts: xinetd keeps running
  // but never owns that port, so a reload cannot free it — the deterministic
  // "another process owns the port" case.
  onHost("sh", "-c", "(nc -k -l -p 10008 </dev/null >/dev/null 2>&1 &); sleep 0.5; xinetd && sleep 1 && pgrep -x xinetd");
  check("fixture live: service port connects, hijacked port held by nc",
    port(10005) === "OPEN" && port(10008) === "OPEN" && onHost("pgrep", "-cx", "nc") !== "");
  const lhsvcSha = sha("/etc/xinetd.d/lhsvc");

  const forwardTarget = owned().NetworkSettings.IPAddress + ":22";
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
  forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
    "-L", `127.0.0.1:${localPort}:${forwardTarget}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
  await sleep(1500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: "LabRoot#2026", id: runId, name: `${name}-22` });
  check("SSH binding connected", status?.stage === "connected");
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding }, 180_000);
  const entry = catalog.commands.find(item => item.title === "超级守护进程服务");
  check("catalog carries 超级守护进程服务", Boolean(entry?.commandHandle));
  const run = await sidecar.call("emergency-command.run", {
    bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: entry.commandHandle,
  }, 300_000);
  const offer = target => {
    const found = run.paths.find(item => item.path === target);
    check(`workbench offered ${target}`, Boolean(found?.pathHandle));
    return found;
  };
  const h1 = offer("/etc/xinetd.d/lhsvc"), h2 = offer("/etc/xinetd.d/lhsvc2"), h3 = offer("/etc/xinetd.d/lhsvc3"),
    h4 = offer("/etc/xinetd.d/lhsvc4"), h5 = offer("/etc/xinetd.d/lhsvc5"),
    hBak = offer("/etc/xinetd.d/svc.bak"), hLink = offer("/etc/xinetd.d/lhlink");
  check("safe service names are flagged xinetdService, ignored name is not",
    [h1, h2, h3, h4, h5, hLink].every(item => item.xinetdService === true) && hBak.xinetdService === false);

  const plan = (pathHandle, action = "disable-xinetd-service") =>
    sidecar.call("emergency-command.path.plan", { bindingHandle: binding, pathHandle, action }, 180_000);
  const confirm = planHandle => sidecar.call("emergency-command.path.confirm", { bindingHandle: binding, planHandle }, 180_000);
  const execute = planHandle => sidecar.call("emergency-command.path.execute", { bindingHandle: binding, planHandle }, 300_000);
  const undo = planHandle => sidecar.call("emergency-command.path.undo", { bindingHandle: binding, planHandle }, 300_000);
  const refusePlan = handle => plan(handle.pathHandle).then(() => "planned").catch(error => String(error.message));

  // ---- refusals before anything else --------------------------------------
  check("a dotted name xinetd never loads refuses by code",
    /emergency-path-xinetd-ignored/u.test(await refusePlan(hBak)));
  check("a symlink service file refuses by kind",
    /emergency-path-xinetd-kind/u.test(await refusePlan(hLink)));
  const batched = await sidecar.call("emergency-command.path.batch.plan",
    { bindingHandle: binding, pathHandles: [h1.pathHandle], action: "disable-xinetd-service" }, 180_000)
    .then(() => "planned").catch(error => String(error.message));
  check("the batch entry refuses disable-xinetd-service", /emergency-path-batch-action/u.test(batched));

  // ---- lhsvc: plan, confirm, execute, independent verify, undo -------------
  const plan1 = await plan(h1.pathHandle);
  console.log(`  plan: ${plan1.summary}`);
  check("plan names the file, service, port and SIGHUP reload",
    plan1.summary.includes("/etc/xinetd.d/lhsvc") && plan1.summary.includes("lhsvc") &&
    plan1.summary.includes("10005") && /SIGHUP/u.test(plan1.summary) && plan1.dangerous === true);
  await confirm(plan1.planHandle);
  const receipt1 = await execute(plan1.planHandle);
  console.log(`  receipt: passed=${receipt1.passed} ${String(receipt1.detail).slice(0, 90)}`);
  check("disable verified", receipt1.passed === true && receipt1.undoable === true && /已停用/u.test(receipt1.detail));
  check("independent readback: file isolated under .lovelyres-backups, port refused",
    onHost("sh", "-c", "test ! -e /etc/xinetd.d/lhsvc && find /etc/xinetd.d/.lovelyres-backups -name '*lhsvc.removed' -type f | head -1 | grep .") !== "" &&
    port(10005) === "CLOSED");
  const backup1 = onHost("sh", "-c", "find /etc/xinetd.d/.lovelyres-backups -name '*lhsvc.removed' -type f | head -1");
  check("backup keeps the planted bytes", sha(backup1) === lhsvcSha);
  const again1 = await execute(plan1.planHandle).then(() => "ran twice").catch(error => String(error.message));
  check("a spent plan cannot run again", again1 !== "ran twice" && /plan-unavailable/u.test(again1));
  const undo1 = await undo(plan1.planHandle);
  console.log(`  undo: undone=${undo1.undone} ${String(undo1.detail).slice(0, 90)}`);
  check("undo reported and independent readback: file back, port connects again",
    undo1.undone === true && sha("/etc/xinetd.d/lhsvc") === lhsvcSha && port(10005) === "OPEN");

  // ---- lhsvc2: file drift between plan and execute is refused untouched ----
  const plan2 = await plan(h2.pathHandle);
  await confirm(plan2.planHandle);
  append("/etc/xinetd.d/lhsvc2", "# drift\n");
  const receipt2 = await execute(plan2.planHandle);
  console.log(`  drift: passed=${receipt2.passed} untouched=${receipt2.untouched} ${String(receipt2.detail).slice(0, 70)}`);
  check("file changed after planning refuses untouched", receipt2.passed === false && receipt2.untouched === true);
  check("the outside change stayed and the port still listens",
    sha("/etc/xinetd.d/lhsvc2") === createHash("sha256").update(`${LHSVC2}# drift\n`, "utf8").digest("hex") && port(10006) === "OPEN");

  // ---- lhsvc3: daemon restarted between plan and execute --------------------
  const plan3 = await plan(h3.pathHandle);
  await confirm(plan3.planHandle);
  onHost("sh", "-c", "kill $(pgrep -x xinetd) ; sleep 0.5; xinetd && sleep 1 && pgrep -x xinetd");
  const receipt3 = await execute(plan3.planHandle);
  console.log(`  restart: passed=${receipt3.passed} untouched=${receipt3.untouched} ${String(receipt3.detail).slice(0, 80)}`);
  check("daemon restarted after planning refuses untouched",
    receipt3.passed === false && receipt3.untouched === true && /xinetd 进程/u.test(receipt3.detail));
  check("the service file was left in place", sha("/etc/xinetd.d/lhsvc3") === createHash("sha256").update(LHSVC3, "utf8").digest("hex"));

  // ---- lhsvc4: the port stays owned by another process ----------------------
  // nc bound 10008 before xinetd started; SIGHUP cannot free it.
  const plan4 = await plan(h4.pathHandle);
  check("hijacked-port plan still plans with SIGHUP", /SIGHUP/u.test(plan4.summary));
  await confirm(plan4.planHandle);
  const receipt4 = await execute(plan4.planHandle);
  console.log(`  hijack: passed=${receipt4.passed} undoable=${receipt4.undoable} restored=${receipt4.restored} ${String(receipt4.detail).slice(0, 110)}`);
  check("port still held fails verification but stays isolated and undoable",
    receipt4.passed === false && receipt4.undoable === true && receipt4.restored === false && /10008/u.test(receipt4.detail));
  check("receipt names the foreign listener and the file stayed isolated",
    /nc/u.test(receipt4.detail) && onHost("sh", "-c", "test ! -e /etc/xinetd.d/lhsvc4 && find /etc/xinetd.d/.lovelyres-backups -name '*lhsvc4.removed' -type f | head -1 | grep .") !== "");
  onHost("sh", "-c", "kill $(pgrep -x nc) ; sleep 0.3");
  const undo4 = await undo(plan4.planHandle);
  console.log(`  undo: undone=${undo4.undone} ${String(undo4.detail).slice(0, 90)}`);
  check("undo from a failed-verify isolation puts the file back and the service binds",
    undo4.undone === true && sha("/etc/xinetd.d/lhsvc4") === createHash("sha256").update(LHSVC4, "utf8").digest("hex") && port(10008) === "OPEN");

  // ---- lhsvc5: xinetd not running -------------------------------------------
  onHost("sh", "-c", "kill $(pgrep -x xinetd); sleep 0.5; pgrep -x xinetd || echo stopped");
  const plan5 = await plan(h5.pathHandle);
  check("stopped-daemon plan says no reload is needed",
    /无需重载/u.test(plan5.summary) && plan5.dangerous === true);
  await confirm(plan5.planHandle);
  const receipt5 = await execute(plan5.planHandle);
  console.log(`  stopped: passed=${receipt5.passed} ${String(receipt5.detail).slice(0, 80)}`);
  check("not-running disable verified with the no-reload note",
    receipt5.passed === true && /无需重载/u.test(receipt5.detail) &&
    onHost("sh", "-c", "test ! -e /etc/xinetd.d/lhsvc5 && find /etc/xinetd.d/.lovelyres-backups -name '*lhsvc5.removed' -type f | head -1 | grep .") !== "");
  const undo5 = await undo(plan5.planHandle);
  check("undo puts the file back while the daemon stays down",
    undo5.undone === true && sha("/etc/xinetd.d/lhsvc5") === createHash("sha256").update(LHSVC5, "utf8").digest("hex"));

  observations.note = "the foreign-listener case binds nc on the service port before xinetd starts, so the daemon runs but never owns the port — deterministic equivalent of 'stop xinetd, nc takes the port'";
  observations.backupDir = "/etc/xinetd.d/.lovelyres-backups — xinetd skips includedir entries whose name contains a dot, so residue never loads";
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned xinetd fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  const sourceHashes = {};
  for (const file of ["crates/lovelyhawk-core/src/xinetd_service.rs", "crates/lovelyhawk-backend/src/emergency_path_api.rs"])
    sourceHashes[file] = createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16);
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId, sourceHashes, observations,
    checks, error: failure ?? null,
    limits: [
      "backend RPC driven, no renderer",
      "Debian container root; sudo -n and systemd reload paths not driven (no systemd in container)",
      "listener still held by xinetd itself (reload lost) not exercised — same verify branch as the nc case",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
