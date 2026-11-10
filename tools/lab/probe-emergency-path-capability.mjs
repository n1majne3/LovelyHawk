// Backend RPC probe for the remove-capabilities path action.
// Only runs against a UUID-labelled disposable container it creates itself.
//
// What has to hold on a real target:
//   * a workbench line that names a capped file offers "移除文件能力";
//   * the plan describes the exact set it will take away and how it goes back;
//   * execute re-checks the file (digest + capability text) before writing,
//     so a file changed mid-flight is refused untouched;
//   * verification is an independent re-read, and one undo writes the saved
//     set back — once;
//   * a file without capabilities and a non-regular path are refused with
//     their own codes.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-cap-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `capability-strip-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-cap-"));
const PLANTED = "/usr/local/bin/.sys-helper";
const SECOND = "/usr/local/bin/.dbus-helper";
const PLAIN = "/usr/local/bin/plain-tool";
const LINK = "/usr/local/bin/tool-link";
const EMPTIED = "/usr/local/bin/.cache-helper";
const SWAPPED = "/usr/local/bin/.dbus-cache";
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
    throw new Error("Owned capability fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// getcap prints names in capability order, not the order they were set with.
const caps = file => {
  const raw = onHost("sh", "-c", `getcap ${file} 2>/dev/null | sed 's|^[^ ]* ||'`).trim();
  if (!raw) return "";
  const eq = raw.indexOf("=");
  const names = (eq === -1 ? raw : raw.slice(0, eq)).split(",").sort();
  return names.join(",") + (eq === -1 ? "" : raw.slice(eq));
};

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("capability fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", `apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends libcap2-bin >/dev/null 2>&1; command -v setcap getcap sha256sum`);
  // Four planted capped helpers; the last two get neutered/symlinked under the
  // offered handles below, because getcap only ever names capped regular files.
  onHost("sh", "-c",
    `cp /bin/sh ${PLANTED}; cp /bin/sh ${SECOND}; cp /bin/sh ${PLAIN};` +
    ` cp /bin/sh ${EMPTIED}; cp /bin/sh ${SWAPPED};` +
    ` setcap 'cap_setuid=ep' ${PLANTED}; setcap 'cap_setuid,cap_dac_override=ep' ${SECOND};` +
    ` setcap 'cap_net_raw=ep' ${EMPTIED}; setcap 'cap_chown=ep' ${SWAPPED};` +
    ` ln -sf /bin/sh ${LINK}`);
  check("planted capped helpers read back their sets",
    caps(PLANTED) === "cap_setuid=ep" && caps(SECOND) === "cap_dac_override,cap_setuid=ep" &&
    caps(EMPTIED) === "cap_net_raw=ep" && caps(SWAPPED) === "cap_chown=ep");

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
  const entry = catalog.commands.find(item => item.title.includes("Capabilit"));
  check("catalog carries the file-capabilities check", entry?.title, true);
  const run = await sidecar.call("emergency-command.run", {
    bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: entry.commandHandle,
  }, 300_000);
  const lines = String(run.output).split("\n");
  const planted = run.paths.find(item => item.path === PLANTED);
  const second = run.paths.find(item => item.path === SECOND);
  const plain = run.paths.find(item => item.path === PLAIN);
  const link = run.paths.find(item => item.path === LINK);
  const emptied = run.paths.find(item => item.path === EMPTIED);
  const swapped = run.paths.find(item => item.path === SWAPPED);
  check("planted capped files were offered handles",
    planted?.pathHandle && second?.pathHandle ? true : false);
  check("each handle names its own line", run.paths.every(item => String(lines[item.line] ?? "").includes(item.path)));
  check("the capped lines were flagged", run.findingLines.length >= 2);
  check("the plain file was not offered a flagged line",
    plain === undefined || !run.findingLines.includes(plain.line));

  // ---- 移除文件能力 ----------------------------------------------------
  const plan = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: planted.pathHandle, action: "remove-capabilities" }, 180_000);
  console.log(`  plan: ${plan.summary}`);
  check("plan names the file and the set it removes",
    plan.summary.includes(PLANTED) && plan.summary.includes("cap_setuid"));
  check("plan is dangerous and says how it goes back",
    plan.dangerous === true && plan.restoreDescription.includes("cap_setuid"));

  await sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle: plan.planHandle }, 180_000);
  const receipt = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: plan.planHandle }, 300_000);
  console.log(`  receipt: passed=${receipt.passed} ${String(receipt.detail).slice(0, 70)}`);
  check("execute verified", receipt.passed === true && receipt.untouched === false);
  check("independent getcap shows the set gone", caps(PLANTED) === "");
  check("the file itself stayed", onHost("sh", "-c", `test -x ${PLANTED} && echo yes`) === "yes");
  check("receipt offers the one undo", receipt.undoable === true);

  const again = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: plan.planHandle }, 180_000)
    .then(() => "ran twice").catch(error => String(error.message));
  check("a spent plan cannot run again", again !== "ran twice");

  // ---- 撤销 ------------------------------------------------------------
  const undo = await sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle: plan.planHandle }, 300_000);
  console.log(`  undo: undone=${undo.undone} ${String(undo.detail).slice(0, 70)}`);
  check("undo verified", undo.undone === true);
  check("independent getcap shows the set back", caps(PLANTED) === "cap_setuid=ep");
  const undoTwice = await sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle: plan.planHandle }, 180_000)
    .then(() => "undid twice").catch(error => String(error.message));
  check("the same strip can only be undone once", undoTwice !== "undid twice");

  // ---- 文件在计划之后被改过 ----------------------------------------------
  const stalePlan = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: second.pathHandle, action: "remove-capabilities" }, 180_000);
  await sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle: stalePlan.planHandle }, 180_000);
  onHost("sh", "-c", `printf 'changed\\n' >> ${SECOND}`);
  const stale = await sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle: stalePlan.planHandle }, 300_000);
  console.log(`  stale: passed=${stale.passed} untouched=${stale.untouched} ${String(stale.detail).slice(0, 70)}`);
  check("a file changed after planning is refused untouched",
    stale.passed === false && stale.untouched === true && stale.undoable === false);
  // The kernel drops file caps on any write, so the appended byte also cleared
  // the set itself; "untouched" here means the product did not truncate or
  // restore the file — the appended marker must still be there.
  check("the outside change was left in place",
    onHost("sh", "-c", `tail -c 8 ${SECOND}`) === "changed");

  // ---- 各拒一种 --------------------------------------------------------
  // getcap never names a plain file or a symlink, so the refusal cases have
  // to start from handles the capped fixture legitimately offered.
  const refuse = async (handle) => sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: handle, action: "remove-capabilities" }, 180_000)
    .then(() => "planned").catch(error => String(error.message));
  check("plain files and symlinks never got handles",
    plain === undefined && link === undefined);
  check("the two swap fixtures were offered handles",
    Boolean(emptied?.pathHandle && swapped?.pathHandle));
  onHost("sh", "-c", `setcap -r ${EMPTIED}; rm -f ${SWAPPED}; ln -s /bin/sh ${SWAPPED}`);
  check("a file whose set was emptied is refused by name",
    /capability-empty/u.test(await refuse(emptied.pathHandle)));
  check("a path that became a symlink is refused by kind",
    /capability-kind/u.test(await refuse(swapped.pathHandle)));
  observations.capsAfter = { planted: caps(PLANTED), second: caps(SECOND) };
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned capability fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  const sourceHashes = {};
  for (const file of ["crates/lovelyhawk-core/src/capability_strip.rs", "crates/lovelyhawk-backend/src/emergency_path_api.rs"])
    sourceHashes[file] = createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16);
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId, sourceHashes, observations,
    checks, error: failure ?? null,
    limits: ["backend RPC driven, no renderer", "Debian container root; sudo -n path not driven"],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
