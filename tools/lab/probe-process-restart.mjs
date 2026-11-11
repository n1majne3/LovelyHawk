// Backend RPC probe for the process.restart row action.
// Only runs against a UUID-labelled disposable container it creates itself.
//
// What has to hold on a real target:
//   * a process row offers "process.restart"; planning refuses PID 1 and
//     reports managed/privilege/tool/cwd problems by code;
//   * the plan names the user, directory and original command line, is
//     dangerous, and states the restart risk;
//   * execution stops the old pid and relaunches under the original user,
//     working directory and argv — proven by an independent /proc readback;
//   * a process killed between plan and execute refuses untouched and does
//     not spawn a duplicate;
//   * a spent plan cannot run twice.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-restart-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `process-restart-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-restart-"));
const checks = [], observations = {};
let containerId, imageId, sidecar, failure, forwarder;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind" || m.Destination !== "/var/lib/postgresql/data"))
    throw new Error("Owned restart fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// Independent /proc readback: pids whose cmdline bytes match argv exactly.
const WANT = Buffer.concat([Buffer.from("sleep\0"), Buffer.from("31337\0")]).toString("hex");
const findByArgv = () => onHost("sh", "-c",
  `for d in /proc/[0-9]*/cmdline; do a=$(od -An -v -tx1 "$d" 2>/dev/null | tr -d ' \\n'); [ "$a" = "${WANT}" ] && basename "$(dirname "$d")"; done || true`)
  .split(/\r?\n/u).map(line => line.trim()).filter(line => /^\d+$/u.test(line));
const procFacts = pid => ({
  uid: onHost("sh", "-c", `awk '/^Uid:/{print $2; exit}' /proc/${pid}/status 2>/dev/null || true`),
  cwd: onHost("sh", "-c", `readlink /proc/${pid}/cwd 2>/dev/null || true`),
  argv: onHost("sh", "-c", `od -An -v -tx1 /proc/${pid}/cmdline 2>/dev/null | tr -d ' \\n' || true`),
});

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  // SYS_PTRACE mirrors a real host: without it even container-root cannot
  // read another user's /proc/<pid>/cwd and the plan refuses by design.
  containerId = podman("run", "-d", "--name", name, "--cap-add", "SYS_PTRACE", "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("restart fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", "command -v setsid su od awk getent useradd");
  check("the tools the restart path needs are present", true);
  // A hand-started business process: user labapp, cwd /opt/appdir, argv
  // "sleep 31337", detached from any session.
  onHost("sh", "-c",
    `useradd -m -s /bin/sh labapp && mkdir -p /opt/appdir && chown labapp:labapp /opt/appdir &&` +
    ` su -s /bin/sh labapp -c 'cd /opt/appdir && setsid sleep 31337 </dev/null >/dev/null 2>&1 &' && sleep 0.5`);
  const planted = findByArgv();
  check("the business process runs as planted", planted.length === 1);
  const labappUid = onHost("id", "-u", "labapp");

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

  const table = await sidecar.call("system-info.table.collect", { bindingHandle: binding, tab: "processes", maximumRows: 500 }, 300_000);
  const businessRow = table.rows.find(row => (row.cells ?? []).some(cell => String(cell).includes("31337")));
  check("the process inventory lists the planted process", Boolean(businessRow?.id));
  const actions = await sidecar.call("system-info.row.actions.list", { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: businessRow.id }, 60_000);
  const offered = (actions.groups ?? []).flatMap(group => (group.actions ?? []).map(item => item.key));
  check("the row offers process.restart", offered.includes("process.restart"));

  // ---- 拒绝路径：PID 1（落在会话链上或 init 拒绝之一）-------------------
  const planError = async rowId => sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId, action: "process.restart" }, 180_000)
    .then(() => "planned").catch(error => String(error.message));
  const initRow = table.rows.find(row => String(row.cells?.[1] ?? "") === "1");
  if (initRow) {
    check("PID 1 is refused by name",
      /process-restart-(init|session)/u.test(await planError(initRow.id)));
  }

  // ---- 按原命令行重启 ---------------------------------------------------
  const plan = await sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: businessRow.id, action: "process.restart" }, 180_000);
  console.log(`  plan: ${plan.summary}`);
  check("plan is dangerous and names user, directory and original command line",
    plan.dangerous === true && plan.summary.includes("labapp") && plan.summary.includes("/opt/appdir") &&
    plan.summary.includes("sleep") && plan.summary.includes("31337"));
  check("plan states the restart risk and no internal handles leak",
    typeof plan.restoreDescription === "string" && plan.restoreDescription.length > 0 &&
    !plan.summary.includes("planHandle") && !plan.summary.includes("binding"));
  const oldPid = planted[0];
  await sidecar.call("system-info.row.action.confirm", { bindingHandle: binding, planHandle: plan.planHandle }, 60_000);
  const receipt = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: plan.planHandle }, 300_000);
  console.log(`  receipt: verified=${receipt.verified} ${String(receipt.detail).slice(0, 80)}`);
  check("execute verified", receipt.verified === true);

  await sleep(300);
  const now = findByArgv();
  check("exactly one process carries the original argv", now.length === 1);
  check("the new process has a new pid", now[0] !== oldPid);
  const facts = procFacts(now[0]);
  check("independent readback: same user, same directory, same argv bytes",
    facts.uid === labappUid && facts.cwd === "/opt/appdir" && facts.argv === WANT);
  observations.restart = { oldPid, newPid: now[0], uid: facts.uid, cwd: facts.cwd };
  const again = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: plan.planHandle }, 60_000)
    .then(() => "ran twice").catch(error => String(error.message));
  check("a spent plan cannot run again", again !== "ran twice");

  // ---- 计划之后进程被杀：拒绝且不重复拉起 --------------------------------
  const table2 = await sidecar.call("system-info.table.collect", { bindingHandle: binding, tab: "processes", maximumRows: 500 }, 300_000);
  const liveRow = table2.rows.find(row => (row.cells ?? []).some(cell => String(cell).includes("31337")));
  check("a fresh inventory sees the restarted process", Boolean(liveRow?.id));
  const stalePlan = await sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table2.snapshotHandle, rowId: liveRow.id, action: "process.restart" }, 180_000);
  await sidecar.call("system-info.row.action.confirm", { bindingHandle: binding, planHandle: stalePlan.planHandle }, 60_000);
  onHost("kill", "-9", now[0]);
  await sleep(300);
  const stale = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: stalePlan.planHandle }, 180_000);
  console.log(`  stale: verified=${stale.verified} ${String(stale.detail).slice(0, 70)}`);
  check("a process replaced after planning refuses the execute",
    stale.verified === false);
  await sleep(300);
  check("no duplicate was spawned after the refusal", findByArgv().length === 0);
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned restart fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  const sourceHashes = {};
  for (const file of ["crates/lovelyhawk-core/src/process_restart.rs", "crates/lovelyhawk-backend/src/system_info_action_api.rs"])
    sourceHashes[file] = createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16);
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId, sourceHashes, observations,
    checks, error: failure ?? null,
    limits: [
      "backend RPC driven, no renderer",
      "root login: RootSu relaunch path only; Direct and SudoUser paths not driven",
      "container has no systemd: managed-process refusal exercised by unit tests only",
      "failed-launch relaunch retry not forced",
      "fixture adds CAP_SYS_PTRACE so root can read other users' /proc cwd links",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
