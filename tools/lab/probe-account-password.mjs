// Backend RPC probe for the account-password row action.
// Only runs against a UUID-labelled disposable container it creates itself.
//
// What has to hold on a real target:
//   * a user row offers "account.password"; planning refuses weak secrets,
//     missing privilege/tools, and non-writable shadow fields by code;
//   * the plan names the account, is dangerous, and says how it goes back;
//   * the plaintext never crosses the wire: the shadow write stores a
//     locally computed $6$ hash that openssl can independently reproduce;
//   * a locked account stays locked; a shadow field that moved after the
//     plan refuses the write untouched; a spent plan cannot run twice;
//   * operator text never echoes the password or the hash.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-acct-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `account-password-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-acct-"));
const NEW_PASS = "Str0ng-Lab!Pass42";
const LOCK_PASS = "L0cked-Lab!Pass7";
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
    throw new Error("Owned account fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const shadowField = user => onHost("sh", "-c", `getent shadow ${user} | cut -d: -f2`);
// Recompute the $6$ digest independently. The full stored field is itself a
// valid crypt salt spec, so crypt(pass, field) returns the field when the
// password matches — python3's crypt binding or openssl both work.
const recomputeHash = (field, pass) => {
  const py = onHost("sh", "-c",
    `python3 -c 'import crypt,sys; print(crypt.crypt(sys.argv[1], sys.argv[2]))' ${shQuote(pass)} ${shQuote(field)} 2>/dev/null || true`);
  if (py.startsWith("$6$")) return py;
  const salt = field.replace(/^\$6\$(?:rounds=\d+\$)?([^$]+)\$.*/u, "$1");
  const out = onHost("openssl", "passwd", "-6", "-salt", salt, pass);
  // openssl omits the rounds= marker; compare digests, not prefixes.
  return out === field ? out : (out.split("$").pop() === field.split("$").pop() ? field : out);
};
const shQuote = value => `'${String(value).replace(/'/gu, "'\\''")}'`;

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("account fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c",
    `useradd -m -s /bin/sh labpw && echo 'labpw:OldPass#2026' | chpasswd &&` +
    ` useradd -m -s /bin/sh lablock && echo 'lablock:OldPass#2026' | chpasswd && passwd -l lablock >/dev/null &&` +
    ` useradd -m -s /bin/sh svcstar && usermod -p '*' svcstar &&` +
    ` useradd -m -s /bin/sh labchg && echo 'labchg:OldPass#2026' | chpasswd &&` +
    ` command -v chpasswd usermod getent openssl`);
  check("planted accounts read back their fields",
    shadowField("labpw").startsWith("$") && shadowField("lablock").startsWith("!") &&
    shadowField("svcstar") === "*" && shadowField("labchg").startsWith("$"));

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

  const table = await sidecar.call("system-info.table.collect", { bindingHandle: binding, tab: "users", maximumRows: 200 }, 300_000);
  const userRow = table.rows.find(row => String(row.cells?.[0] ?? "") === "labpw");
  check("the users table lists the lab account", Boolean(userRow?.id));
  const actions = await sidecar.call("system-info.row.actions.list", { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: userRow.id }, 60_000);
  const offered = (actions.groups ?? []).flatMap(group => (group.actions ?? []).map(item => item.key));
  check("the row offers account.password", offered.includes("account.password"));

  // ---- 拒绝路径 --------------------------------------------------------
  const planError = async (rowId, password) => sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId, action: "account.password", password }, 180_000)
    .then(() => "planned").catch(error => String(error.message));
  const starRow = table.rows.find(row => String(row.cells?.[0] ?? "") === "svcstar");
  check("a weak secret is refused by name",
    /account-password-secret/u.test(await planError(userRow.id, "weak")));
  check("a * shadow field is refused by name",
    /account-password-field/u.test(await planError(starRow.id, NEW_PASS)));

  // ---- 改口令 ----------------------------------------------------------
  const plan = await sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: userRow.id, action: "account.password", password: NEW_PASS }, 180_000);
  console.log(`  plan: ${plan.summary}`);
  check("plan names the account and is dangerous",
    plan.summary.includes("labpw") && plan.dangerous === true);
  check("plan says how it goes back and never echoes the secret or a hash",
    typeof plan.restoreDescription === "string" && !plan.summary.includes(NEW_PASS) && !plan.summary.includes("$6$"));
  const before = shadowField("labpw");
  await sidecar.call("system-info.row.action.confirm", { bindingHandle: binding, planHandle: plan.planHandle }, 60_000);
  const receipt = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: plan.planHandle }, 300_000);
  console.log(`  receipt: verified=${receipt.verified} ${String(receipt.detail).slice(0, 70)}`);
  check("execute verified", receipt.verified === true);
  const field = shadowField("labpw");
  check("the stored field is a new sha512-crypt value", field.startsWith("$6$") && field !== before);
  check("openssl independently reproduces the stored hash from the new password",
    recomputeHash(field, NEW_PASS) === field);
  check("the old password no longer matches", recomputeHash(field, "OldPass#2026") !== field);
  check("receipt text never echoes the secret or the hash",
    !String(receipt.detail).includes(NEW_PASS) && !String(receipt.detail).includes(field));
  const again = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: plan.planHandle }, 60_000)
    .then(() => "ran twice").catch(error => String(error.message));
  check("a spent plan cannot run again", again !== "ran twice");

  // ---- 锁定账户保持锁定 -------------------------------------------------
  const lockRow = table.rows.find(row => String(row.cells?.[0] ?? "") === "lablock");
  const lockPlan = await sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: lockRow.id, action: "account.password", password: LOCK_PASS }, 180_000);
  await sidecar.call("system-info.row.action.confirm", { bindingHandle: binding, planHandle: lockPlan.planHandle }, 60_000);
  const lockReceipt = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: lockPlan.planHandle }, 300_000);
  check("locked account change verified", lockReceipt.verified === true);
  const lockField = shadowField("lablock");
  check("the account is still locked and its hash matches the new password",
    lockField.startsWith("!") && recomputeHash(lockField.replace(/^!+/u, ""), LOCK_PASS) === lockField.replace(/^!+/u, ""));

  // ---- 计划之后口令记录被改过 --------------------------------------------
  const chgRow = table.rows.find(row => String(row.cells?.[0] ?? "") === "labchg");
  const chgPlan = await sidecar.call("system-info.row.action.plan",
    { bindingHandle: binding, snapshotHandle: table.snapshotHandle, rowId: chgRow.id, action: "account.password", password: NEW_PASS }, 180_000);
  await sidecar.call("system-info.row.action.confirm", { bindingHandle: binding, planHandle: chgPlan.planHandle }, 60_000);
  onHost("usermod", "-p", "$6$outside$change", "labchg");
  const stale = await sidecar.call("system-info.row.action.execute", { bindingHandle: binding, planHandle: chgPlan.planHandle }, 180_000);
  console.log(`  stale: verified=${stale.verified} ${String(stale.detail).slice(0, 60)}`);
  check("a field changed after planning refuses the write",
    stale.verified === false && stale.restored === false);
  check("the outside change was left in place", shadowField("labchg") === "$6$outside$change");

  // ---- 秘密不落盘 --------------------------------------------------------
  const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry =>
    entry.isDirectory() ? walk(path.join(dir, entry.name)) : [path.join(dir, entry.name)]);
  const leaked = walk(dataRoot).some(file => {
    try { return fs.readFileSync(file, "utf8").includes(NEW_PASS); } catch { return false; }
  });
  check("the plaintext never reached the local data store", !leaked);
  observations.fields = { labpw: field.slice(0, 20) + "…", lablock: lockField.slice(0, 20) + "…" };
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned account fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  const sourceHashes = {};
  for (const file of ["crates/lovelyhawk-core/src/account_password.rs", "crates/lovelyhawk-backend/src/system_info_action_api.rs"])
    sourceHashes[file] = createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16);
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId, sourceHashes, observations,
    checks, error: failure ?? null,
    limits: ["backend RPC driven, no renderer", "root login; sudo -n path not driven", "verify-failure auto-restore not forced", "deletion is offered separately and not exercised here"],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
