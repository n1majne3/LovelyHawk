// Real PostgreSQL account password change through the core SSH actor.
// Only runs against a UUID-labelled disposable container it creates itself.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
function probe(cmd, args) { try { execFileSync(cmd, args, { stdio: "ignore", windowsHide: true }); return true; } catch { return false; } }
// The lab CLI is docker normally; podman inside its own WSL machine also works.
const cli = process.env.LOVELYHAWK_LAB_CONTAINER_CLI ||
  (probe("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "version"]) ? "docker"
    : probe("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", "podman", "version"]) ? "podman" : "docker");
const distro = process.env.LOVELYHAWK_LAB_DISTRO || (cli === "podman" ? "podman-machine-default" : "Ubuntu");
const runId = randomUUID(), name = `lr-pg-password-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-postgresql-password", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pg-password-"));
const pgdata = "/var/lib/postgresql/data";
const newPassword = "Lab'\"New中#2026z"; // Fixture canary, never a user credential.
const newPasswordB = "Lab'\"New中#2026y";
const checks = [], observations = {};
let containerId, imageId, version, platform, sidecar, failure, forwarder;
fs.mkdirSync(evidence, { recursive: true });
const keepalive = spawn("wsl.exe", ["-d", distro, "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", error => { failure ??= String(error); });
const proxyEnv = { HTTP_PROXY: process.env.LAB_REGISTRY_PROXY || "http://192.168.6.4:7890", HTTPS_PROXY: process.env.LAB_REGISTRY_PROXY || "http://192.168.6.4:7890" };
const wsl = (...args) => execFileSync("wsl.exe", ["-d", distro, "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
// podman runs through the Windows client so -p ports are gvproxy-forwarded to
// localhost; docker stays inside its WSL distro.
const runCli = (...args) => cli === "podman"
  ? execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim()
  : wsl(...args);
const docker = (...args) => runCli(...args);
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  const stripDigest = value => String(value ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || stripDigest(target.Image) !== stripDigest(imageId) || (target.Name !== `/${name}` && target.Name !== name) || target.Config.Labels?.["lovelyres-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" ||
    (target.Mounts ?? []).some(mount => mount.Type !== "tmpfs" || mount.Destination !== pgdata) ||
    !String(target.HostConfig.Tmpfs?.[pgdata] ?? "").startsWith("rw,noexec,nosuid,size=256m") || target.HostConfig.Memory !== 512 * 1024 * 1024 ||
    target.HostConfig.NanoCpus !== 1_000_000_000 || target.HostConfig.PidsLimit !== 128 || !["", "private"].includes(target.HostConfig.PidMode) || (target.HostConfig.CapAdd ?? []).length !== 0) throw new Error("Owned PostgreSQL fixture identity or resource limits changed");
  return target;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
function script(input) {
  owned();
  return execFileSync(cli === "podman" ? "podman.exe" : "wsl.exe",
    cli === "podman" ? ["exec", "-i", containerId, "sh", "-se"] : ["-d", distro, "-u", "root", "--", cli, "exec", "-i", containerId, "sh", "-se"],
    { input, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
}
const sql = statement => onHost("runuser", "-u", "postgres", "--", "psql", "-X", "-w", "-At", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", statement);
async function until(fn) {
  const end = Date.now() + 60_000;
  while (Date.now() < end) { try { if (fn()) return; } catch {} await new Promise(resolve => setTimeout(resolve, 250)); }
  throw new Error("Owned PostgreSQL startup timed out");
}
async function coreSuite() {
  await new Promise((resolve, reject) => {
    let transcript = "";
    const child = spawn("cargo", ["test", "--locked", "--package", "lovelyhawk-core", "database_password::lab::owned_postgresql_password_change", "--lib", "--", "--ignored", "--exact", "--nocapture"],
      { cwd: repository, windowsHide: true, env: { ...process.env, RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN || "1.99.1-x86_64-pc-windows-msvc", LOVELYHAWK_PG_PASSWORD_ROOT: dataRoot, LOVELYHAWK_PG_PASSWORD_RUN: runId } });
    const log = fs.createWriteStream(path.join(evidence, "core-password.log"));
    const timer = setTimeout(() => { child.kill(); reject(new Error("Owned password core suite exceeded four minutes")); }, 240_000);
    child.stdout.on("data", chunk => { transcript += chunk.toString(); log.write(chunk); process.stdout.write(chunk); });
    child.stderr.on("data", chunk => { log.write(chunk); process.stdout.write(chunk); });
    child.once("error", error => { clearTimeout(timer); log.end(); reject(error); });
    child.once("close", code => {
      clearTimeout(timer); log.end();
      for (const line of transcript.split(/\r?\n/u)) if (line.startsWith("POSTGRESQL_PASSWORD_CHECK ")) checks.push({ label: line.slice("POSTGRESQL_PASSWORD_CHECK ".length), passed: true });
      if (code === 0 && transcript.includes("POSTGRESQL_PASSWORD_SUITE_COMPLETE") && transcript.includes("1 passed; 0 failed")) resolve();
      else reject(new Error(`Owned password core suite failed (exit ${code})`));
    });
  });
}
function bytesHaveCanary(bytes) {
  const text = bytes.toString("utf8");
  return text.includes(newPassword) || text.includes(newPasswordB) ||
    text.includes(JSON.stringify(newPassword).slice(1, -1)) || text.includes(JSON.stringify(newPasswordB).slice(1, -1));
}
function plaintextHasCanary(directory, predicate = bytesHaveCanary) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error("Unexpected symbolic link in isolated application data");
    if (entry.isDirectory() ? plaintextHasCanary(file, predicate) : predicate(fs.readFileSync(file))) return true;
  }
  return false;
}

try {
  try { imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}"); } catch {
    // Build the lab image from tools/lab/services when it is not cached.
    if (!probe("wsl.exe", ["-d", distro, "-u", "root", "--", cli, "image", "inspect", "lab-base/postgres:16"])) {
      const mirror = process.env.LAB_MIRROR || "docker.m.daocloud.io";
      execFileSync(cli === "podman" ? "podman.exe" : "wsl.exe",
        cli === "podman" ? ["pull", `${mirror}/library/postgres:16`] : ["-d", distro, "-u", "root", "--", "env", `HTTP_PROXY=${proxyEnv.HTTP_PROXY}`, `HTTPS_PROXY=${proxyEnv.HTTPS_PROXY}`, cli, "pull", `${mirror}/library/postgres:16`],
        { encoding: "utf8", windowsHide: true, timeout: 900_000, env: { ...process.env, ...proxyEnv } });
      docker("tag", `${mirror}/library/postgres:16`, "lab-base/postgres:16");
    }
    const context = cli === "podman" ? path.join(repository, "tools/lab/services") : "/mnt/d/code/LovelyHawk/tools/lab/services";
    execFileSync(cli === "podman" ? "podman.exe" : "wsl.exe",
      cli === "podman" ? ["build", "--build-arg", "BASE=lab-base/postgres:16", "--build-arg", "INSTALLER=apt", "--build-arg", "SERVICE=postgres", "-t", "lovelyres-svc:postgres", context] : ["-d", distro, "-u", "root", "--", "env", `HTTP_PROXY=${proxyEnv.HTTP_PROXY}`, `HTTPS_PROXY=${proxyEnv.HTTPS_PROXY}`, cli, "build", "--build-arg", "BASE=lab-base/postgres:16", "--build-arg", "INSTALLER=apt", "--build-arg", "SERVICE=postgres", "-t", "lovelyres-svc:postgres", context],
      { encoding: "utf8", windowsHide: true, timeout: 900_000, env: { ...process.env, ...proxyEnv } });
    imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}") ||
      docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Digest}}");
    if (!imageId) throw new Error("Cannot resolve built image identity");
    imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  }
  let host = "127.0.0.1";
  if (cli === "docker") {
    let hostAddresses = "";
    try { hostAddresses = wsl("hostname", "-I"); } catch {
      hostAddresses = wsl("ip", "-4", "-o", "addr", "show").replaceAll(/\/\d+/gu, " ");
    }
    host = hostAddresses.split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip)) ?? "";
    if (!host) throw new Error("Missing private WSL address");
  }
  const publishArgs = cli === "podman" ? [] : ["-p", `${host}::22`];
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "--tmpfs", `${pgdata}:rw,noexec,nosuid,size=256m`, ...publishArgs, "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=/usr/local/bin/docker-entrypoint.sh postgres", imageId);
  check("password fixture uses bounded resources and only its own container storage", Boolean(owned()));
  await until(() => sql("SELECT 1") === "1");
  version = onHost("postgres", "--version"); platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  script(`
printf '%s' '${runId}' > /tmp/lovelyres-pg-password-run
runuser -u postgres -- psql -X -w -v ON_ERROR_STOP=1 -d postgres <<'SQL'
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SQL
runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres -c 'SELECT pg_reload_conf()'
runuser -u postgres -- psql -X -w -v ON_ERROR_STOP=1 -d postgres <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE lr_super LOGIN SUPERUSER PASSWORD 'Lab''"Sup中#2026a';
CREATE ROLE lr_other LOGIN PASSWORD 'Lab''"Oth中#2026b';
CREATE ROLE lr_nologin NOLOGIN;
CREATE ROLE lr_crole LOGIN CREATEROLE PASSWORD 'Lab''"Cro中#2026c';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_connections = 'on';
SQL
cd ${pgdata}
cat > pg_hba.conf <<'HBA'
local all all trust
host all all 127.0.0.0/8 md5
host all all ::1/128 md5
host all all 0.0.0.0/0 reject
host all all ::0/0 reject
HBA
chown postgres:postgres pg_hba.conf
runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres -c 'SELECT pg_reload_conf()'
`);
  observations.roles = sql("SELECT rolname || ':' || CASE WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram' WHEN rolpassword LIKE 'md5%' THEN 'md5' ELSE 'none' END FROM pg_authid WHERE rolname LIKE 'lr\\_%' ORDER BY rolname");
  const roleKinds = Object.fromEntries(observations.roles.split("\n").map(line => line.split(":")));
  check("fixture roles hold initial SCRAM verifiers", ["lr_super", "lr_other", "lr_crole"].every(role => roleKinds[role] === "scram") && roleKinds.lr_nologin === "none");
  let sshHost = host, sshPort;
  let forwardTarget = "";
  if (cli === "podman") {
    sshHost = "127.0.0.1";
    forwardTarget = owned().NetworkSettings.IPAddress + ":22";
  } else {
    sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  }
  if (cli === "podman") {
    // Windows cannot route to the machine's address; forward a local port
    // through the machine's own SSH endpoint instead.
    const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
    const findKey = (node, key) => {
      if (!node || typeof node !== "object") return undefined;
      if (node[key] !== undefined) return node[key];
      for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
      return undefined;
    };
    const identity = findKey(machine, "IdentityPath"), machinePort = findKey(machine, "Port");
    const localPort = await new Promise(resolve => {
      const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
    });
    forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-i", identity, "-p", String(machinePort), "-N",
      "-L", `127.0.0.1:${localPort}:${forwardTarget}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
    await new Promise(resolve => setTimeout(resolve, 1500));
    if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
    sshPort = localPort; sshHost = "127.0.0.1";
  }
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const status = await connect(sidecar, { host: sshHost, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  observations.connectStatus = { stage: status?.stage ?? null, error: status?.error ?? null, detail: status?.detail ?? null, forwarderExit: forwarder?.exitCode ?? null };
  check("owned SSH fixture is saved with a confirmed host key", status?.stage === "connected");
  sidecar.close(); sidecar = undefined;
  owned();
  await coreSuite();
  check("portable data does not contain either new-password canary", !plaintextHasCanary(dataRoot));
  const serviceLog = onHost("tail", "-n", "2000", "/var/log/lab-service.log");
  fs.writeFileSync(path.join(evidence, "service-log.txt"), serviceLog);
  check("server log shows the password change application name and ALTER ROLE statements", /application_name=LovelyHawk password change/u.test(serviceLog) && /ALTER ROLE/u.test(serviceLog));
  check("server log never contains a plaintext new-password canary (log_statement=all)", !bytesHaveCanary(Buffer.from(serviceLog)));
  check("statement text in the server log contains verifiers, not plaintext", /ALTER ROLE[^;]*PASSWORD 'SCRAM-SHA-256\$'/u.test(serviceLog) || /ALTER ROLE[^;]*PASSWORD 'md5/u.test(serviceLog));
  check("no password-change database sessions remain", sql("SELECT count(*) FROM pg_stat_activity WHERE application_name IN ('LovelyHawk password change', 'LovelyHawk runtime review')") === "0");
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; }
finally {
  forwarder?.kill();
  sidecar?.close();
  if (containerId) {
    try { fs.writeFileSync(path.join(evidence, "service-log.txt"), onHost("tail", "-n", "2000", "/var/log/lab-service.log")); } catch {}
    try { owned(); docker("rm", "-f", containerId); check("owned password PostgreSQL container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-pg-password-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected fixture data root");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated application data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  const sourceHashes = Object.fromEntries(["crates/lovelyhawk-core/src/database_password.rs", "crates/lovelyhawk-core/src/database_password_tests.rs", "crates/lovelyhawk-core/src/database_password_lab.rs", "crates/lovelyhawk-core/src/postgresql_native.rs", "crates/lovelyhawk-core/src/ssh.rs", "crates/lovelyhawk-core/src/database.rs", "tools/lab/probe-postgresql-password.mjs"].map(file =>
    [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, version, platform, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["core integration; no backend, shared DTO, desktop UI or RPC acceptance claim", "only this PostgreSQL fixture version on this OS/architecture is real tested", "fixture writes are not production repair behavior", "saved-profile update and restore covered inside the disposable container only"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
