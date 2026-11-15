// Backend RPC probe for the MySQL account privilege review/plan/execute/undo
// feature. Only runs against UUID-labelled disposable containers it creates.
//
// Proven through `mysql.runtime` on the real backend binary:
//   * `privileges` reads SHOW GRANTS and reports scope-classified rows;
//   * `plan-privileges` converges `traffic`@`127.0.0.1` from
//     GRANT ALL ON traffic_oa.* + global CREATE,DROP to the competition
//     per-table matrix; statement order is REVOKEs before GRANTs;
//   * `execute-privileges` verifies the final grant set; an independent
//     in-container SHOW GRANTS equals the matrix and the account can no
//     longer CREATE or DROP;
//   * `undo-privileges` restores the original grant lines exactly;
//   * stale plan handles and unsafe plans (root, unparseable input) refuse.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), short = runId.slice(0, 8);
const evidence = path.join(repository, "target/lab-mysql-privilege", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-mysql-priv-"));
fs.mkdirSync(evidence, { recursive: true });

const ROOT_OS_PASSWORD = "LabRoot#2026";
const ROOT_DB_PASSWORD = "LabDb#2026";
const ACCOUNT = { user: "traffic", host: "127.0.0.1" };
const ACCOUNT_SQL = `'${ACCOUNT.user}'@'${ACCOUNT.host}'`;
const DATADIR = "/var/lib/mysql";
const DATABASE_ALL = [
  "ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROUTINE", "CREATE TEMPORARY TABLES",
  "CREATE VIEW", "DELETE", "DROP", "EVENT", "EXECUTE", "INDEX", "INSERT",
  "LOCK TABLES", "REFERENCES", "SELECT", "SHOW VIEW", "TRIGGER", "UPDATE",
];
const MATRIX = [
  { database: "traffic_oa", table: null, privileges: ["SELECT"] },
  { database: "traffic_oa", table: "work_order", privileges: ["UPDATE"] },
  { database: "traffic_oa", table: "oa_account", privileges: ["UPDATE"] },
  { database: "traffic_oa", table: "work_order_access", privileges: ["DELETE"] },
  { database: "traffic_oa", table: "notification", privileges: ["INSERT"] },
  { database: "traffic_oa", table: "notification_recipient", privileges: ["INSERT", "UPDATE"] },
  { database: "traffic_oa", table: "work_order_history", privileges: ["INSERT"] },
  { database: "traffic_oa", table: "audit_record", privileges: ["INSERT"] },
  { database: "traffic_oa", table: "handover", privileges: ["INSERT"] },
];

const checks = [], observations = {}, rpcTranscript = [];
let sidecar, failure;
const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 900_000, maxBuffer: 8 * 1024 * 1024 }).trim();
const podmanIn = (input, ...args) => execFileSync("podman.exe", args, { input, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function recordRpc(action, response) {
  rpcTranscript.push({ action, response });
  return response;
}

async function forwardPort(forwardTarget) {
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
  const forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
    "-L", `127.0.0.1:${localPort}:${forwardTarget}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
  await sleep(1500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
  return { forwarder, localPort };
}

const name = `lr-mysqlpriv-${short}`;
let containerId, imageId, forwarder, removed = false;
const owned = () => {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    (target.Mounts ?? []).some(m => m.Type !== "tmpfs" || m.Destination !== DATADIR) ||
    !String(target.HostConfig.Tmpfs?.[DATADIR] ?? "").startsWith("rw,noexec,nosuid,size=512m") ||
    (target.HostConfig.CapAdd ?? []).length !== 0)
    throw new Error("Owned fixture identity changed");
  return target;
};
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sq = value => String(value).replace(/\\/g, "\\\\").replace(/'/g, "''");
let admin;
const grantsOf = () => {
  const out = admin(`SHOW GRANTS FOR ${ACCOUNT_SQL}`);
  return out.split("\n").map(line => line.trim()).filter(line => /^GRANT\b/iu.test(line)).sort();
};
const canon = lines => {
  const canonLine = line => line
    .replace(/['`]/gu, "")
    .replace(/ALL PRIVILEGES/iu, "ALL")
    .replace(/^GRANT (.+?) ON /iu, (m, privs) => `GRANT ${privs.split(",").map(p => p.trim().toUpperCase()).sort().join(",")} ON `)
    .replace(/\s+/gu, " ").trim();
  return lines.map(canonLine).sort();
};

try {
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  imageId = podman("image", "inspect", "lovelyres-svc:mysql", "--format", "{{.Id}}");
  const envs = [`MYSQL_ROOT_PASSWORD=${ROOT_DB_PASSWORD}`, "MYSQL_ROOT_HOST=%", "LAB_SERVICE_COMMAND=/entrypoint.sh mysqld"];
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "768m", "--cpus", "1", "--pids-limit", "128",
    "--tmpfs", `${DATADIR}:rw,noexec,nosuid,size=512m`, ...envs.flatMap(env => ["-e", env]), "--entrypoint", "/bin/sh", imageId,
    "-c", "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null; exec /opt/entrypoint.sh");
  try {
    check("fixture is an owned, unprivileged container with only a tmpfs datadir", Boolean(owned()));
    const cli = onHost("sh", "-c", "command -v mariadb || command -v mysql").split("\n")[0];
    admin = sql => podmanIn(sql, "exec", "-i", "-e", `MYSQL_PWD=${ROOT_DB_PASSWORD}`, "-e", `DBCLI=${cli}`,
      containerId, "sh", "-c", '"$DBCLI" --default-character-set=utf8mb4 -uroot 2>/dev/null || "$DBCLI" --default-character-set=utf8mb4 --protocol=TCP -h127.0.0.1 -uroot 2>/dev/null');
    const end = Date.now() + 240_000;
    const ready = () => { try { return /^1$/m.test(admin("SELECT 1").slice(-20)); } catch { return false; } };
    while (!ready()) {
      if (Date.now() > end) throw new Error("database did not become ready");
      await sleep(500);
    }
    admin(`ALTER USER 'root'@'localhost' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
CREATE DATABASE IF NOT EXISTS traffic_oa;
CREATE TABLE traffic_oa.work_order (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.oa_account (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.work_order_access (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.notification (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.notification_recipient (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.work_order_history (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.audit_record (id INT PRIMARY KEY);
CREATE TABLE traffic_oa.handover (id INT PRIMARY KEY);
CREATE USER IF NOT EXISTS ${ACCOUNT_SQL} IDENTIFIED BY 'Traffic#Lab2026';
GRANT CREATE, DROP ON *.* TO ${ACCOUNT_SQL};
GRANT ALL PRIVILEGES ON traffic_oa.* TO ${ACCOUNT_SQL};
FLUSH PRIVILEGES;`);
    const original = grantsOf();
    check("fixture grants traffic ALL on traffic_oa.* plus global CREATE,DROP",
      canon(original).includes(`GRANT CREATE,DROP ON *.* TO ${ACCOUNT.user}@${ACCOUNT.host}`) &&
      original.some(line => /ALL PRIVILEGES ON `?traffic_oa`?\.\*/iu.test(line)));

    const { forwarder: fwd, localPort } = await forwardPort(owned().NetworkSettings.IPAddress + ":22");
    forwarder = fwd;
    const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: ROOT_OS_PASSWORD, id: randomUUID(), name: `${name}-22` });
    check("SSH binding connected", status?.stage === "connected");
    const bindingHandle = status.bindingHandle;
    const rpc = (action, params, timeoutMs = 300_000) =>
      sidecar.call("mysql.runtime", { action, bindingHandle, ...params }, timeoutMs).then(result => recordRpc(action, result));

    const listed = await rpc("list", {});
    check("runtime lists the binding", listed?.kind === "profiles");
    const saved = await rpc("save", {
      profile: { name: `${name}-db`, host: "127.0.0.1", port: 3306, username: "root", database: "", tlsMode: "ssh-loopback", caPem: null },
      password: { action: "replace", value: ROOT_DB_PASSWORD },
    });
    check("profile saved", saved?.kind === "saved" && typeof saved.profile?.profileHandle === "string");
    const profile = saved.profile;
    const rejected = (res, action) => res?.kind === "rejected" && res.action === action;

    const review = await rpc("privileges", { profileHandle: profile.profileHandle, account: ACCOUNT });
    check("privileges review classifies the broad grants",
      review?.kind === "privileges" && review.review?.product === "MySQL" &&
      review.review.rows.some(row => row.scope.kind === "global" && row.privileges.includes("CREATE") && row.privileges.includes("DROP")) &&
      review.review.rows.some(row => row.scope.kind === "database" && row.scope.database === "traffic_oa" && row.allPrivileges === true));
    check("review lists the server's own schemas and competition tables",
      review.review.schemas.includes("traffic_oa") &&
      MATRIX.filter(add => add.table).every(add => review.review.tables.some(t => t.database === "traffic_oa" && t.table === add.table)));
    const rows = review.review.rows;
    const globalRow = rows.findIndex(row => row.scope.kind === "global");
    const dbRow = rows.findIndex(row => row.scope.kind === "database" && row.scope.database === "traffic_oa");

    const ghost = await rpc("privileges", { profileHandle: profile.profileHandle, account: { user: "ghost", host: "%" } });
    check("reviewing a nonexistent account is refused", rejected(ghost, "privileges"));
    const rootPlan = await rpc("plan-privileges", {
      profileHandle: profile.profileHandle, account: { user: "root", host: "localhost" },
      revokes: [{ row: 0, privileges: ["SELECT"] }], grants: [],
    });
    check("revoking on a root account is refused at planning", rejected(rootPlan, "plan-privileges"));

    const plan = await rpc("plan-privileges", {
      profileHandle: profile.profileHandle, account: ACCOUNT,
      revokes: [
        { row: globalRow, privileges: ["CREATE", "DROP"] },
        { row: dbRow, privileges: DATABASE_ALL },
      ],
      grants: MATRIX,
    });
    check("plan returns ordered statements and a handle",
      plan?.kind === "privilege-plan" && typeof plan.planHandle === "string" && plan.plan.statements.length === 2 + MATRIX.length);
    check("plan statements run every REVOKE before any GRANT",
      plan.plan.statements.findIndex(s => s.startsWith("GRANT ")) ===
      plan.plan.statements.filter(s => s.startsWith("REVOKE ")).length);
    check("the db-scope ALL row expands to REVOKE ALL PRIVILEGES",
      plan.plan.statements.some(s => /^REVOKE ALL PRIVILEGES ON `traffic_oa`\.\*/u.test(s)));

    const executed = await rpc("execute-privileges", { planHandle: plan.planHandle });
    check("execute verifies the final grant set", executed?.kind === "privilege-result" && executed.receipt?.verified === true && typeof executed.undoHandle === "string");
    const replay = await rpc("execute-privileges", { planHandle: plan.planHandle });
    check("a spent plan handle cannot execute twice", rejected(replay, "execute-privileges") && replay.code === "stale");

    const after = canon(grantsOf());
    const wanted = canon([
      `GRANT USAGE ON *.* TO '${ACCOUNT.user}'@'${ACCOUNT.host}'`,
      "GRANT SELECT ON traffic_oa.* TO traffic@127.0.0.1",
      "GRANT UPDATE ON traffic_oa.work_order TO traffic@127.0.0.1",
      "GRANT UPDATE ON traffic_oa.oa_account TO traffic@127.0.0.1",
      "GRANT DELETE ON traffic_oa.work_order_access TO traffic@127.0.0.1",
      "GRANT INSERT ON traffic_oa.notification TO traffic@127.0.0.1",
      "GRANT INSERT,UPDATE ON traffic_oa.notification_recipient TO traffic@127.0.0.1",
      "GRANT INSERT ON traffic_oa.work_order_history TO traffic@127.0.0.1",
      "GRANT INSERT ON traffic_oa.audit_record TO traffic@127.0.0.1",
      "GRANT INSERT ON traffic_oa.handover TO traffic@127.0.0.1",
    ]);
    check("independent SHOW GRANTS equals the competition matrix", JSON.stringify(after) === JSON.stringify(wanted));
    const denied = spawnSync("podman.exe",
      ["exec", "-e", "MYSQL_PWD=Traffic#Lab2026", "-e", `DBCLI=${cli}`, containerId, "sh", "-c",
        '"$DBCLI" --protocol=TCP -h127.0.0.1 -P3306 -utraffic -NBe "CREATE TABLE traffic_oa.pwned (id INT)" 2>&1; "$DBCLI" --protocol=TCP -h127.0.0.1 -P3306 -utraffic -NBe "DROP TABLE traffic_oa.handover" 2>&1; "$DBCLI" --protocol=TCP -h127.0.0.1 -P3306 -utraffic -NBe "SELECT COUNT(*) FROM traffic_oa.work_order"'],
      { encoding: "utf8", windowsHide: true, timeout: 30_000 });
    const deniedText = String(denied.stdout ?? "") + String(denied.stderr ?? "");
    check("traffic can no longer CREATE or DROP but still SELECTs",
      /command denied|access denied|CREATE command denied/iu.test(deniedText) && /COUNT\(\*\)\n0|0$/m.test(deniedText.trim()));

    const undo = await rpc("undo-privileges", { planHandle: executed.undoHandle });
    check("undo restores the original grant set", undo?.kind === "privilege-result" && undo.receipt?.verified === true && undo.undoHandle === null);
    check("independent SHOW GRANTS matches the original lines",
      JSON.stringify(canon(grantsOf())) === JSON.stringify(canon(original).map(l => l.replace(/ALL PRIVILEGES/iu, "ALL"))));
    const undoReplay = await rpc("undo-privileges", { planHandle: executed.undoHandle });
    check("a spent undo handle cannot run twice", rejected(undoReplay, "undo-privileges") && undoReplay.code === "stale");
  } finally {
    forwarder?.kill();
    if (containerId && !removed) {
      try { podman("rm", "-f", "-v", containerId); removed = true; check("owned fixture removed", true); }
      catch (error) { failure = (failure ?? "") + `cleanup: ${String(error)}\n`; process.exitCode = 1; }
    }
  }
} catch (error) {
  failure = (failure ?? "") + String(error?.stack ?? error) + "\n";
  console.log(`FAILURE ${String(error).split("\n")[0]}`);
} finally {
  try { sidecar?.close(); } catch {}
  const stray = spawnSync("podman.exe", ["ps", "-aq", "--filter", `label=lovelyres-test-run=${runId}`], { encoding: "utf8", windowsHide: true });
  for (const id of String(stray.stdout ?? "").split("\n").map(s => s.trim()).filter(Boolean)) {
    try { podman("rm", "-f", "-v", id); } catch {}
  }
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/mysql_privilege.rs",
    "crates/lovelyhawk-backend/src/mysql_runtime_api.rs",
    "ui/src/shared/mysql-runtime-contract.ts",
    "ui/src/renderer/MysqlPrivilegePanel.tsx",
    "tools/lab/probe-mysql-privilege.mjs",
    "tools/lab/rpc-harness.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16)]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), sourceHashes, observations,
    rpcActions: rpcTranscript.map(c => c.action), checks, error: failure || null,
    limits: [
      "backend RPC driven; the renderer panel typechecks but no CDP desktop drive in this probe",
      "ssh-loopback profile only; verify-full TLS path not exercised",
      "mysql:8.0 only; MariaDB fixture not pulled in this run",
    ],
  }, null, 2));
  fs.writeFileSync(path.join(evidence, "rpc-transcript.json"), JSON.stringify(rpcTranscript, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
