// Backend RPC probe for the MySQL/MariaDB account password change feature.
// Only runs against UUID-labelled disposable containers it creates itself.
//
// What has to hold on a real target, proven through `mysql.runtime` on the
// real backend binary (no core-test shortcut):
//   * a saved ssh-loopback profile can plan and execute a password change;
//     execution reports verification.state "passed" — an independent login
//     with the new password on a fresh channel;
//   * the new password really works (independent in-container client login)
//     and the old one no longer does;
//   * plan-password-restore + execute-password-restore put the old verifier
//     back and the old password authenticates again;
//   * weak secrets, account-named secrets, unknown accounts, and re-use of a
//     spent plan or restore handle are rejected by kind/code;
//   * neither new nor old plaintext reaches the portable data store, the
//     backend log, the RPC responses, or the evidence artifacts.
// Vendors: Oracle MySQL 8.0 and MariaDB (11 from the official image, or the
// Debian fallback fixture if the registry is unreachable — Debian 12 ships
// MariaDB 10.11, inside the reviewed version window). A vendor that cannot
// be brought up is reported with its failure, not silently skipped.
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
const evidence = path.join(repository, "target/desktop-debug", `mysql-password-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-mysql-password-"));
fs.mkdirSync(evidence, { recursive: true });

const ROOT_OS_PASSWORD = "LabRoot#2026";
const ROOT_DB_PASSWORD = "LabDb#2026";
// Canary credentials: unique per run, four character classes, and never the
// account name, so the role check and the non-disclosure scan are both real.
const ACCOUNT = { user: "lrdb1", host: "%" };
const OLD_PASSWORD = `Old'\"Db中${short}a9!`;
const NEW_PASSWORD = `New'\"Db中${short}z8!`;
const CANARIES = [OLD_PASSWORD, NEW_PASSWORD].flatMap(value => [value, JSON.stringify(value).slice(1, -1)]);
const ACCOUNT_QUOTED = `'${ACCOUNT.user}'@'${ACCOUNT.host}'`;
const DATADIR = "/var/lib/mysql";

const checks = [], observations = {}, rpcTranscript = {};
let sidecar, failure;

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 900_000, maxBuffer: 8 * 1024 * 1024 }).trim();
const podmanIn = (input, ...args) => execFileSync("podman.exe", args, { input, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function recordRpc(vendor, action, response) {
  (rpcTranscript[vendor] ??= []).push({ action, response });
  if (response?.kind === "rejected") {
    (observations[`${vendor}Rejections`] ??= []).push({ action, code: response.code, detail: response.detail });
  }
  return response;
}
function bytesHaveCanary(bytes) {
  const text = bytes.toString("utf8");
  return CANARIES.some(canary => text.includes(canary));
}
function valueHasCanary(value) {
  if (typeof value === "string") return CANARIES.some(canary => value.includes(canary));
  if (Array.isArray(value)) return value.some(valueHasCanary);
  return value !== null && typeof value === "object" && Object.values(value).some(valueHasCanary);
}
function plaintextHasCanary(directory) {
  if (!fs.existsSync(directory)) return false;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Unexpected symbolic link in ${directory}`);
    if (entry.isDirectory() ? plaintextHasCanary(file) : bytesHaveCanary(fs.readFileSync(file))) return true;
  }
  return false;
}

// `docker.m.daocloud.io` is the mirror this lab documents (Docker Hub does not
// route from here). It is flaky: pulls retry inside resolveImage.
const MIRROR = process.env.LAB_MIRROR || "docker.m.daocloud.io";
const VENDORS = [
  {
    key: "mysql",
    product: "MySQL",
    svcImage: "lovelyres-svc:mysql",
    base: "lab-base/mysql:8.0",
    mirrorBase: `${MIRROR}/library/mysql:8.0`,
    installer: "microdnf",
    service: "mysql",
    envs: [`MYSQL_ROOT_PASSWORD=${ROOT_DB_PASSWORD}`, "MYSQL_ROOT_HOST=%", "LAB_SERVICE_COMMAND=/entrypoint.sh mysqld"],
  },
  {
    key: "mariadb",
    product: "MariaDB",
    svcImage: "lovelyres-svc:mariadb",
    base: "lab-base/mariadb:11",
    mirrorBase: `${MIRROR}/library/mariadb:11`,
    installer: "apt",
    service: "mariadb",
    envs: [`MARIADB_ROOT_PASSWORD=${ROOT_DB_PASSWORD}`, "MARIADB_ROOT_HOST=%", "LAB_SERVICE_COMMAND=/usr/local/bin/docker-entrypoint.sh mariadbd"],
    fallbackImage: "lovelyres-lab:mysql-password-mariadb-debian",
  },
];

function inspectImage(ref) {
  try { return podman("image", "inspect", ref, "--format", "{{.Id}}"); } catch { return ""; }
}
// SQL string literal escaping: doubles quotes and backslashes, matching what
// both servers accept inside '...' under default sql_mode.
const sq = value => String(value).replace(/\\/g, "\\\\").replace(/'/g, "''");
function pullWithRetry(ref, attempts = 5) {
  let last;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try { podman("pull", ref); return; } catch (error) {
      last = error;
      console.log(`  pull attempt ${attempt} failed for ${ref}`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 3000);
    }
  }
  throw last;
}
function buildDebianMariadbFallback(vendor) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-mariadb-fixture-"));
  fs.writeFileSync(path.join(dir, "entry.sh"), [
    "#!/bin/sh",
    "set -e",
    "mkdir -p /run/sshd",
    "/usr/sbin/sshd -D -e &",
    'if [ ! -d /var/lib/mysql/mysql ]; then mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=socket --skip-test-db >/dev/null 2>&1; fi',
    "chown mysql:mysql /var/lib/mysql",
    "mariadbd --user=mysql --datadir=/var/lib/mysql --bind-address=0.0.0.0 --port=3306 &",
    "exec sleep infinity",
    "",
  ].join("\n"));
  fs.writeFileSync(path.join(dir, "Containerfile"), [
    `FROM ${MIRROR}/library/debian:12-slim`,
    "RUN export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends mariadb-server openssh-server procps >/dev/null && rm -rf /var/lib/apt/lists/*",
    "RUN mkdir -p /run/sshd && ssh-keygen -A" +
      ` && printf 'root:${ROOT_OS_PASSWORD}\\n' | chpasswd` +
      " && sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config" +
      " && (grep -q '^PermitRootLogin yes' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config)" +
      " && sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config",
    "COPY entry.sh /opt/entry.sh",
    "RUN chmod +x /opt/entry.sh",
    'ENTRYPOINT ["/opt/entry.sh"]',
    "",
  ].join("\n"));
  podman("build", "-t", vendor.fallbackImage, dir);
  return { imageId: inspectImage(vendor.fallbackImage), imageKind: `debian-fallback-mariadb-10.11 (${vendor.fallbackImage})`, envs: [] };
}
function resolveImage(vendor) {
  const cached = inspectImage(vendor.svcImage);
  if (cached) return { imageId: cached, imageKind: `service fixture (${vendor.svcImage})`, envs: vendor.envs };
  try {
    if (!inspectImage(vendor.base)) {
      pullWithRetry(vendor.mirrorBase);
      podman("tag", vendor.mirrorBase, vendor.base);
    }
    podman("build",
      "--build-arg", `BASE=${vendor.base}`,
      "--build-arg", `INSTALLER=${vendor.installer}`,
      "--build-arg", `SERVICE=${vendor.service}`,
      "-t", vendor.svcImage,
      path.join(repository, "tools/lab/services"));
    const built = inspectImage(vendor.svcImage);
    if (built) return { imageId: built, imageKind: `service fixture (${vendor.svcImage}, built from ${vendor.base})`, envs: vendor.envs };
    throw new Error("service fixture build produced no image");
  } catch (error) {
    if (!vendor.fallbackImage) throw error;
    console.log(`  service fixture unavailable for ${vendor.key} (${String(error).split("\n").pop()}); using Debian fallback`);
    return buildDebianMariadbFallback(vendor);
  }
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

async function runVendor(vendor) {
  const name = `lr-mysqlpw-${vendor.key}-${short}`;
  let containerId, imageId, forwarder, removed = false;
  const owned = () => {
    const target = JSON.parse(podman("inspect", containerId))[0];
    const strip = v => String(v ?? "").replace(/^sha256:/u, "");
    if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
      target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
      (target.Mounts ?? []).some(m => m.Type !== "tmpfs" || m.Destination !== DATADIR) ||
      !String(target.HostConfig.Tmpfs?.[DATADIR] ?? "").startsWith("rw,noexec,nosuid,size=512m") ||
      (target.HostConfig.CapAdd ?? []).length !== 0)
      throw new Error(`Owned ${vendor.key} fixture identity changed`);
    return target;
  };
  const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
  // Independent TCP login. `denied` marks an explicit authentication refusal
  // so "old password fails" cannot pass because the server was unreachable.
  const login = password => {
    owned();
    const res = spawnSync("podman.exe",
      ["exec", "-e", `MYSQL_PWD=${password}`, "-e", `DBCLI=${observations[`${vendor.key}Cli`]}`, "-e", `DBUSER=${ACCOUNT.user}`,
        containerId, "sh", "-c", '"$DBCLI" --protocol=TCP -h127.0.0.1 -P3306 -u"$DBUSER" -NBe "SELECT 1"'],
      { encoding: "utf8", windowsHide: true, timeout: 30_000 });
    return {
      ok: res.status === 0 && String(res.stdout ?? "").trim() === "1",
      denied: /access denied|1045|1698|1251/iu.test(String(res.stderr ?? "")),
      stderr: String(res.stderr ?? "").trim().slice(0, 200),
    };
  };
  const rpc = (action, params, timeoutMs = 300_000) =>
    sidecar.call("mysql.runtime", { action, bindingHandle: observations.bindingHandle, ...params }, timeoutMs)
      .then(result => recordRpc(vendor.key, action, result));

  const resolved = resolveImage(vendor);
  imageId = resolved.imageId;
  observations[`${vendor.key}Image`] = resolved.imageKind;
  // The svc mysql fixture's my.cnf logs to /var/log/mysql/, which the image
  // lacks — mysqld aborts before anything can create it. A one-line wrapper
  // makes the directory first, then hands over to the stock entrypoint.
  const entryArgs = resolved.envs.length ? ["--entrypoint", "/bin/sh"] : [];
  const cmdArgs = resolved.envs.length
    ? ["-c", "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null; exec /opt/entrypoint.sh"]
    : [];
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "768m", "--cpus", "1", "--pids-limit", "128",
    "--tmpfs", `${DATADIR}:rw,noexec,nosuid,size=512m`, ...resolved.envs.flatMap(env => ["-e", env]), ...entryArgs, imageId, ...cmdArgs);
  try {
    check(`[${vendor.key}] fixture is an owned, unprivileged container with only a tmpfs datadir`, Boolean(owned()));

    const cli = onHost("sh", "-c", "command -v mariadb || command -v mysql").split("\n")[0];
    observations[`${vendor.key}Cli`] = cli;
    // Admin channel: local socket as OS-root. MYSQL_PWD is always set; sockets
    // that use unix_socket auth ignore it, password sockets consume it.
    const admin = sql => {
      owned();
      return podmanIn(sql, "exec", "-i", "-e", `MYSQL_PWD=${ROOT_DB_PASSWORD}`, "-e", `DBCLI=${cli}`,
        containerId, "sh", "-c", '"$DBCLI" --default-character-set=utf8mb4 -uroot 2>/dev/null || "$DBCLI" --default-character-set=utf8mb4 --protocol=TCP -h127.0.0.1 -uroot 2>/dev/null');
    };
    const ready = () => {
      try { return /^1$/m.test(admin("SELECT 1").slice(-20)); } catch { return false; }
    };
    const end = Date.now() + 240_000;
    while (!ready()) {
      if (Date.now() > end) throw new Error(`${vendor.key} database did not become ready`);
      await sleep(500);
    }
    // Loopback TCP logins can match 'root'@'localhost', 'root'@'127.0.0.1' or
    // 'root'@'%' depending on name resolution; pin every grant row that can
    // win to the known root password before the RPC path is exercised.
    admin(`ALTER USER 'root'@'localhost' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;`);
    admin(`CREATE USER IF NOT EXISTS '${ACCOUNT.user}'@'${ACCOUNT.host}' IDENTIFIED BY '${sq(OLD_PASSWORD)}';
ALTER USER '${ACCOUNT.user}'@'${ACCOUNT.host}' IDENTIFIED BY '${sq(OLD_PASSWORD)}';
FLUSH PRIVILEGES;`);
    const plugin = admin(`SELECT plugin FROM mysql.user WHERE user='${ACCOUNT.user}' AND host='${ACCOUNT.host}';`).split("\n").pop().trim();
    observations[`${vendor.key}Plugin`] = plugin;
    check(`[${vendor.key}] fixture account exists and uses a reviewed auth plugin`, ["mysql_native_password", "caching_sha2_password", "sha256_password"].includes(plugin));
    observations[`${vendor.key}Version`] = onHost("sh", "-c", `${cli} --version 2>/dev/null | head -1`).replace(/\n.*$/us, "");
    const first = login(OLD_PASSWORD);
    check(`[${vendor.key}] the account authenticates over TCP with its initial password`, first.ok);

    const { forwarder: fwd, localPort } = await forwardPort(owned().NetworkSettings.IPAddress + ":22");
    forwarder = fwd;
    const connectionId = randomUUID();
    const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: ROOT_OS_PASSWORD, id: connectionId, name: `${name}-22` });
    check(`[${vendor.key}] SSH binding connected`, status?.stage === "connected");
    observations.bindingHandle = status.bindingHandle;
    observations[`${vendor.key}ConnectionId`] = connectionId;

    // `list` creates the per-binding runtime entry; other actions need it.
    const listed = await rpc("list", {});
    check(`[${vendor.key}] runtime lists the binding`, listed?.kind === "profiles");
    const saved = await rpc("save", {
      profile: { name: `${name}-db`, host: "127.0.0.1", port: 3306, username: "root", database: "", tlsMode: "ssh-loopback", caPem: null },
      password: { action: "replace", value: ROOT_DB_PASSWORD },
    });
    check(`[${vendor.key}] profile saved`, saved?.kind === "saved" && typeof saved.profile?.profileHandle === "string");
    const profile = saved.profile;
    check(`[${vendor.key}] saved profile reports ssh-loopback without exposing the secret`,
      profile.hasPassword === true && profile.tlsMode === "ssh-loopback" && profile.host === "127.0.0.1" &&
      profile.unassigned === false && !JSON.stringify(profile).includes(ROOT_DB_PASSWORD));
    const relisted = await rpc("list", {});
    check(`[${vendor.key}] the saved profile lists under this binding`, relisted.profiles?.some(p => p.profileHandle === profile.profileHandle));

    const rejected = (res, action) => res?.kind === "rejected" && res.action === action;
    const weakPlan = await rpc("plan-password", { profileHandle: profile.profileHandle, account: ACCOUNT, password: "weak", updateSavedPassword: false });
    check(`[${vendor.key}] a too-weak password is rejected at planning`, rejected(weakPlan, "plan-password") && weakPlan.code === "rejected");
    const namePlan = await rpc("plan-password", { profileHandle: profile.profileHandle, account: ACCOUNT, password: `Ab1${ACCOUNT.user}xYz#9!`, updateSavedPassword: false });
    check(`[${vendor.key}] a password containing the account name is rejected`, rejected(namePlan, "plan-password"));
    const ghostPlan = await rpc("plan-password", { profileHandle: profile.profileHandle, account: { user: "lrghost", host: "%" }, password: NEW_PASSWORD, updateSavedPassword: false });
    check(`[${vendor.key}] an unknown account is rejected`, rejected(ghostPlan, "plan-password"));

    const plan = await rpc("plan-password", { profileHandle: profile.profileHandle, account: ACCOUNT, password: NEW_PASSWORD, updateSavedPassword: false });
    check(`[${vendor.key}] plan-password returns a reviewed plan`, plan?.kind === "password-plan" && typeof plan.planHandle === "string" && plan.expiresInMs === 120000);
    check(`[${vendor.key}] the plan names the account, product and plugin and offers restore`,
      plan.plan?.account === ACCOUNT_QUOTED && plan.plan.product === vendor.product &&
      plan.plan.plugin === plugin && plan.plan.isConnectionAccount === false && plan.plan.restorable === true &&
      !valueHasCanary(plan.plan));
    const executed = await rpc("execute-password", { planHandle: plan.planHandle });
    check(`[${vendor.key}] execute-password verifies the new login`, executed?.kind === "password-result" && executed.result?.verification?.state === "passed");
    check(`[${vendor.key}] the outcome is restorable, journaled and carries a restore handle`,
      executed.result.restorable === true && executed.result.journalRecorded === true &&
      typeof executed.result.restoreHandle === "string" && executed.result.savedPassword === "not-requested");
    const newLogin = login(NEW_PASSWORD);
    check(`[${vendor.key}] an independent client login succeeds with the NEW password`, newLogin.ok);
    const oldLogin = login(OLD_PASSWORD);
    check(`[${vendor.key}] the OLD password is now explicitly refused`, !oldLogin.ok && oldLogin.denied);
    const replay = await rpc("execute-password", { planHandle: plan.planHandle });
    check(`[${vendor.key}] a spent plan handle cannot execute twice`, rejected(replay, "execute-password") && replay.code === "stale");

    const restorePlan = await rpc("plan-password-restore", { profileHandle: profile.profileHandle, restoreHandle: executed.result.restoreHandle });
    check(`[${vendor.key}] plan-password-restore names the account`, restorePlan?.kind === "password-restore-plan" && typeof restorePlan.planHandle === "string" && restorePlan.plan?.account === ACCOUNT_QUOTED);
    const restored = await rpc("execute-password-restore", { planHandle: restorePlan.planHandle });
    check(`[${vendor.key}] execute-password-restore verifies`, restored?.kind === "password-restore-result" && restored.result?.verified === true && restored.result.journalRecorded === true);
    const backLogin = login(OLD_PASSWORD);
    check(`[${vendor.key}] an independent client login succeeds with the OLD password again`, backLogin.ok);
    const newAgain = login(NEW_PASSWORD);
    check(`[${vendor.key}] the NEW password is now explicitly refused`, !newAgain.ok && newAgain.denied);
    const restoreReplay = await rpc("plan-password-restore", { profileHandle: profile.profileHandle, restoreHandle: executed.result.restoreHandle });
    check(`[${vendor.key}] a spent restore handle cannot plan twice`, rejected(restoreReplay, "plan-password-restore") && restoreReplay.code === "stale");

    const serviceLog = [onHost("sh", "-c", "cat /var/log/lab-service.log 2>/dev/null; for f in /var/log/mysql/*.log /var/lib/mysql/*.err; do [ -f \"$f\" ] && tail -n 300 \"$f\"; done; true"),
      podman("logs", "--tail", "400", containerId)].join("\n");
    check(`[${vendor.key}] server logs contain no new/old password plaintext`, !bytesHaveCanary(Buffer.from(serviceLog)));
  } finally {
    try {
      const lateLog = [podman("exec", containerId, "sh", "-c", "cat /var/log/lab-service.log 2>/dev/null; for f in /var/log/mysql/*.log /var/lib/mysql/*.err; do [ -f \"$f\" ] && tail -n 300 \"$f\"; done; true"),
        podman("logs", "--tail", "400", containerId)].join("\n");
      if (lateLog.trim()) fs.writeFileSync(path.join(evidence, `service-log-${vendor.key}.txt`), lateLog);
    } catch {}
    try { fs.writeFileSync(path.join(evidence, `rpc-transcript-${vendor.key}.json`), JSON.stringify(rpcTranscript[vendor.key] ?? [], null, 2)); } catch {}
    forwarder?.kill();
    if (containerId && !removed) {
      try { podman("rm", "-f", "-v", containerId); removed = true; check(`[${vendor.key}] owned fixture removed`, true); }
      catch (error) { failure = (failure ?? "") + `[${vendor.key}] cleanup: ${String(error)}\n`; process.exitCode = 1; }
    }
  }
}

try {
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  for (const vendor of VENDORS) {
    try {
      await runVendor(vendor);
    } catch (error) {
      failure = (failure ?? "") + `[${vendor.key}] ${String(error?.stack ?? error)}\n`;
      console.log(`VENDOR FAILURE [${vendor.key}] ${String(error).split("\n")[0]}`);
    }
  }
  check("RPC responses never carry a plaintext canary", !valueHasCanary(rpcTranscript));
  fs.writeFileSync(path.join(evidence, "sidecar-stderr.log"), sidecar.stderr.join(""));
  check("backend stderr contains no plaintext canary", !bytesHaveCanary(Buffer.from(sidecar.stderr.join(""))));
  check("portable data store contains no plaintext canary", !plaintextHasCanary(dataRoot));
  check("evidence artifacts contain no plaintext canary", !plaintextHasCanary(evidence));
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
    "crates/lovelyhawk-core/src/mysql_password.rs",
    "crates/lovelyhawk-core/src/mysql_native.rs",
    "crates/lovelyhawk-core/src/mysql_wire.rs",
    "crates/lovelyhawk-core/src/database.rs",
    "crates/lovelyhawk-backend/src/mysql_runtime_api.rs",
    "tools/lab/probe-mysql-password.mjs",
    "tools/lab/rpc-harness.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16)]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), sourceHashes, observations,
    rpcActions: Object.fromEntries(Object.entries(rpcTranscript).map(([vendor, calls]) => [vendor, calls.map(c => c.action)])),
    checks, error: failure || null,
    limits: [
      "backend RPC driven; no renderer or desktop UI claim",
      "profile auth uses ssh-loopback over a container loopback; verify-full TLS path not exercised",
      "updateSavedPassword=false only; the connection-account saved-secret update path is not covered",
      "verification is trusted but also proven independently by in-container client logins; no second network vantage point",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
