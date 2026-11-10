// Desktop UI PostgreSQL password change through the debug build and CDP.
// Only runs against a UUID-labelled disposable container it creates itself.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";
import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
function probe(cmd, args) { try { execFileSync(cmd, args, { stdio: "ignore", windowsHide: true }); return true; } catch { return false; } }
const cli = process.env.LOVELYHAWK_LAB_CONTAINER_CLI ||
  (probe("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "docker", "version"]) ? "docker"
    : probe("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", "podman", "version"]) ? "podman" : "docker");
const distro = process.env.LOVELYHAWK_LAB_DISTRO || (cli === "podman" ? "podman-machine-default" : "Ubuntu");
const runId = randomUUID(), name = `lr-pg-pwui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `postgresql-password-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pg-pwui-"));
const pgdata = "/var/lib/postgresql/data";
// Fixture canaries, never user credentials.
const oldPw = "Lab'\"Old中#2026o";
const newPw = "Lab'\"New中#2026p";
const auditPw = "Lab'\"Aud中#2026a";
const auditNew = "Lab'\"Au2中#2026b";
const weakPw = "short";
const checks = [], observations = {};
let containerId, imageId, version, platform, sidecar, failure, forwarder, app;
fs.mkdirSync(evidence, { recursive: true });
const proxyEnv = { HTTP_PROXY: process.env.LAB_REGISTRY_PROXY || "http://192.168.6.4:7890", HTTPS_PROXY: process.env.LAB_REGISTRY_PROXY || "http://192.168.6.4:7890" };
const wsl = (...args) => execFileSync("wsl.exe", ["-d", distro, "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const runCli = (...args) => cli === "podman"
  ? execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim()
  : wsl(...args);
const docker = (...args) => runCli(...args);
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(docker("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) || target.Config.Labels?.["lovelyres-test-run"] !== runId ||
    target.HostConfig.Privileged || target.HostConfig.NetworkMode !== "bridge" ||
    (target.Mounts ?? []).some(m => m.Type !== "tmpfs" || m.Destination !== pgdata) ||
    target.HostConfig.NanoCpus !== 1_000_000_000 || target.HostConfig.PidsLimit !== 128 || (target.HostConfig.CapAdd ?? []).length !== 0) throw new Error("Owned PostgreSQL fixture identity or resource limits changed");
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
const psqlWorks = (user, password) => {
  try { onHost("env", `PGPASSWORD=${password}`, "psql", "-X", "-w", "-h", "127.0.0.1", "-U", user, "-d", "postgres", "-Atc", "SELECT 1"); return true; } catch { return false; }
};
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 90000) { const end = Date.now() + ms; while (Date.now() < end) { try { if (await fn()) return; } catch {} await sleep(150); } throw new Error(`Timed out: ${label}`); }
function canaryBytes() {
  const canaries = [newPw, auditNew, oldPw, auditPw].flatMap(p => [p, JSON.stringify(p).slice(1, -1)]);
  return { has: bytes => canaries.some(c => bytes.includes(c)), canaries };
}
function plaintextHasCanary(directory) {
  const { has } = canaryBytes();
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error("Unexpected symbolic link in isolated application data");
    if (entry.isDirectory() ? plaintextHasCanary(file) : has(fs.readFileSync(file))) return true;
  }
  return false;
}

try {
  try { imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}"); } catch {
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
    imageId = docker("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  }
  let host = "127.0.0.1";
  if (cli === "docker") {
    let hostAddresses = "";
    try { hostAddresses = wsl("hostname", "-I"); } catch { hostAddresses = wsl("ip", "-4", "-o", "addr", "show").replaceAll(/\/\d+/gu, " "); }
    host = hostAddresses.split(/\s+/u).find(ip => /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/u.test(ip)) ?? "";
    if (!host) throw new Error("Missing private WSL address");
  }
  const publishArgs = cli === "podman" ? [] : ["-p", `${host}::22`];
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "--tmpfs", `${pgdata}:rw,noexec,nosuid,size=256m`, ...publishArgs, "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=/usr/local/bin/docker-entrypoint.sh postgres", imageId);
  check("password UI fixture uses bounded resources and only its own container storage", Boolean(owned()));
  await until(() => { try { return sql("SELECT 1") === "1"; } catch { return false; } }, "postgres ready");
  version = onHost("postgres", "--version"); platform = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  const esc = value => value.replaceAll("'", "''");
  script(`
printf '%s' '${runId}' > /tmp/lovelyres-pg-pwui-run
cd ${pgdata}
openssl req -new -x509 -newkey rsa:2048 -nodes -keyout fixture-ca.key -out fixture-ca.pem -days 2 -subj /CN=LovelyHawkOwnedCA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout fixture-server.key -out fixture-server.csr -subj /CN=127.0.0.1 >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
' > fixture-server.ext
openssl x509 -req -in fixture-server.csr -CA fixture-ca.pem -CAkey fixture-ca.key -CAcreateserial -out fixture-server.pem -days 2 -extfile fixture-server.ext >/dev/null 2>&1
chown postgres:postgres fixture-server.key fixture-server.pem
chmod 600 fixture-server.key
runuser -u postgres -- psql -X -w -v ON_ERROR_STOP=1 -d postgres <<SQL
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '${pgdata}/fixture-server.pem';
ALTER SYSTEM SET ssl_key_file = '${pgdata}/fixture-server.key';
SELECT pg_reload_conf();
SET password_encryption = 'scram-sha-256';
ALTER ROLE postgres PASSWORD '${esc(oldPw)}';
CREATE ROLE lhaudit LOGIN PASSWORD '${esc(auditPw)}';
SQL
cat > pg_hba.conf <<'HBA'
local all all trust
host all all 127.0.0.0/8 scram-sha-256
host all all ::1/128 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::0/0 reject
HBA
chown postgres:postgres pg_hba.conf
runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres -c 'SELECT pg_reload_conf()'
`);
  await until(() => { try { return sql("SHOW ssl") === "on"; } catch { return false; } }, "ssl enabled");
  // WSL can run ahead of the Windows clock; wait for the certificates to be
  // valid at the client before connecting.
  const validFrom = Date.parse(onHost("openssl", "x509", "-in", `${pgdata}/fixture-server.pem`, "-noout", "-startdate").replace(/^notBefore=/u, ""));
  await until(() => Date.now() >= validFrom, "certificate valid at client clock");
  fs.writeFileSync(path.join(dataRoot, "fixture-ca.pem"), onHost("cat", `${pgdata}/fixture-ca.pem`));
  check("fixture roles authenticate over TCP before the lab", psqlWorks("postgres", oldPw) && psqlWorks("lhaudit", auditPw));
  let sshHost = host, sshPort, forwardTarget = "";
  if (cli === "podman") {
    forwardTarget = owned().NetworkSettings.IPAddress + ":22";
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
    await sleep(1500);
    if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
    sshPort = localPort;
  } else {
    sshPort = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  }
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const status = await connect(sidecar, { host: sshHost, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name: `${name}-22` });
  check("owned SSH fixture is saved with a confirmed host key", status?.stage === "connected");
  sidecar.close(); sidecar = undefined;

  // ---- Desktop drive ---------------------------------------------------
  const errors = [];
  app = await startDesktop({ dataRoot, evidence, onConsoleError: entry => errors.push(entry) });
  const session = app.session;
  const page = {
    shot: file => session.shot(file),
    async evaluate(expression) {
      try {
        return await Promise.race([session.evaluate(expression), new Promise((_, reject) => setTimeout(() => reject(new Error("evaluate timeout")), 15000))]);
      } catch (error) { throw new Error(`CDP: ${String(error)}`); }
    },
    async key(key) { await session.evaluate(`document.dispatchEvent(new KeyboardEvent('keydown',{key:${JSON.stringify('')}}))`.replace("''", `'${key}'`)); },
  };
  await app.recordHostCalls();
  await app.setViewport(1080, 700);
  const uiWait = (expression, label) => until(() => page.evaluate(expression), label);
  const click = (selector, label) => page.evaluate(`(()=>{const b=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.includes(${JSON.stringify(label)})&&!e.disabled);if(!b)throw Error('Control missing: '+${JSON.stringify(label)});b.click();})()`);
  const dialogText = () => page.evaluate("document.querySelector('.dialog')?.textContent ?? ''");
  const field = (label, value) => page.evaluate(`(()=>{const label=[...document.querySelectorAll('.database-editor label, .dialog label')].find(e=>e.firstChild.textContent.trim()===${JSON.stringify(label)});const el=label?.querySelector('input,select,textarea');if(!el)throw Error('Field missing: '+${JSON.stringify(label)});const proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(el,${JSON.stringify(value)});el.dispatchEvent(new Event(el.tagName==='SELECT'?'change':'input',{bubbles:true}));})()`);

  await uiWait("document.querySelector('.connection-card') !== null", "saved SSH card");
  await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.querySelector('strong').textContent===${JSON.stringify(`${name}-22-22/tcp`)} || e.textContent.includes(${JSON.stringify(name)})).querySelector('button').click()`);
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
  await click(".nav-item", "数据库"); await uiWait("document.querySelector('.database-empty, .database-page')!==null", "database page");

  const makeProfile = async (profileName, user, password) => {
    await click(".database-toolbar button", "添加连接"); await uiWait("document.querySelector('.database-editor input')!==null", "new connection form");
    await field("连接名称", profileName); await field("数据库用户名", user);
    await field("CA 证书（PEM，可选）", fs.readFileSync(path.join(dataRoot, "fixture-ca.pem"), "utf8"));
    await field("口令处理", "replace"); await field("新口令", password);
    await click(".database-editor button", "保存连接");
    await uiWait("!document.querySelector('.database-editor')", "connection saved");
  };
  const selectProfile = profileName => page.evaluate(`(()=>{const s=document.querySelector('.database-toolbar select');if(!s)throw Error('no profile select');s.value=[...s.options].find(o=>o.textContent===${JSON.stringify(profileName)})?.value;s.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  const readState = async () => {
    await click(".database-toolbar button", "读取数据库状态");
    await uiWait("['读取完成','读取未完成'].includes(document.querySelector('.database-result h3')?.textContent ?? '')", "read finished");
    observations.lastRead = await page.evaluate("document.querySelector('.database-result')?.textContent ?? ''");
  };

  await makeProfile("PG super lab", "postgres", oldPw);
  await readState();
  check("superuser review reads successfully", await page.evaluate("document.querySelector('.database-result h3').textContent==='读取完成'"));
  await page.shot("01-review-read.png");

  const passwordCalls = async action => (await app.hostCallCounts())["postgresql.runtime"]?.[action] ?? 0;

  // Weak password first: inline rule, no request.
  await click(".database-toolbar button", "修改此账号的口令");
  await uiWait("document.querySelector('.dialog input[type=password]')!==null", "password dialog input");
  check("first password field gets initial focus", await page.evaluate("document.activeElement===document.querySelector('.dialog input[type=password]')"));
  const before = await passwordCalls("plan-password");
  await field("新口令", weakPw); await field("再次输入新口令", weakPw);
  await click(".dialog button", "检查并生成计划");
  await sleep(400);
  check("weak password rejected inline without a plan request", (await passwordCalls("plan-password")) === before && (await dialogText()).includes("口令"));
  await page.shot("02-weak-inline.png");

  // Valid plan.
  await field("新口令", newPw); await field("再次输入新口令", newPw);
  check("saved-password update checkbox defaults on for the connection role", await page.evaluate("document.querySelector('.dialog input[type=checkbox]')?.checked === true"));
  await click(".dialog button", "检查并生成计划");
  try {
    await uiWait("(document.querySelector('.dialog')?.textContent ?? '').includes('确认修改')", "confirm step", 30000);
  } catch (error) {
    observations.planFailure = { dialog: await dialogText(), calls: (await app.hostCallCounts())["postgresql.runtime"], last: await app.lastHostCall({ method: "postgresql.runtime" }) };
    throw error;
  }
  const confirmText = await dialogText();
  check("confirm shows host:port/db, impact sentence and focus on 取消",
    confirmText.includes("127.0.0.1:5432/postgres") && confirmText.includes("已经连上的会话不受影响，业务程序下次用旧口令连接会失败，请同步更新应用配置。") &&
    await page.evaluate("document.activeElement?.textContent === '取消'"));
  await page.shot("03-confirm.png");
  // Tab stays inside the dialog.
  await page.evaluate("document.querySelector('.dialog button:last-child')?.focus()");
  await page.evaluate("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Tab'}))");
  check("Tab wraps focus inside the dialog", await page.evaluate("document.querySelector('.dialog').contains(document.activeElement)"));

  // Execute; Escape during executing must be ignored — send it while the
  // executing step may still be up, then wait for the result step.
  await click(".dialog button", "确认修改");
  // Escape must be ignored while executing; the step can pass quickly, so a
  // late Escape would hit the result step instead — wait for the busy text
  // first, with a short bound, and record what was observed.
  const executingSeen = await until(() => page.evaluate("(document.querySelector('.dialog')?.textContent ?? '').includes('正在修改')"), "executing step", 5000).catch(() => false);
  if (executingSeen) {
    await page.evaluate("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))");
    await sleep(150);
    check("Escape is ignored while executing", await page.evaluate("document.querySelector('.dialog') !== null"));
  } else observations.escapeDuringExecuting = "executing step finished before Escape could be sent";
  await uiWait("(document.querySelector('.dialog')?.textContent ?? '').includes('口令已修改并用新口令完成独立登录复核')", "passed result");
  const resultText = await dialogText();
  check("result shows passed verification and saved-password update",
    resultText.includes("已保存连接已更新为新口令") && resultText.includes("放回旧口令"));
  await uiWait("(document.body.textContent ?? '').includes('重新读取数据库状态') && document.querySelector('.database-result') === null", "re-read empty state");
  check("page returns to the re-read empty state after a result", true);
  await page.shot("04-result-passed.png");

  check("inside the container the new password works and the old fails",
    psqlWorks("postgres", newPw) && !psqlWorks("postgres", oldPw));

  // Restore through the UI.
  await click(".dialog button", "放回旧口令");
  await uiWait("(document.querySelector('.dialog')?.textContent ?? '').includes('确认放回')", "restore confirm");
  await page.shot("05-restore-confirm.png");
  await click(".dialog button", "确认放回");
  await uiWait("(document.querySelector('.dialog')?.textContent ?? '').includes('旧口令已放回并回读复核一致')", "restore passed");
  check("restore result reports saved password put back", (await dialogText()).includes("已保存口令已改回修改前的值"));
  await page.shot("06-restored.png");
  check("inside the container the old password works and the new fails after restore",
    psqlWorks("postgres", oldPw) && !psqlWorks("postgres", newPw));
  await click(".dialog button", "关闭");
  await uiWait("document.querySelector('.dialog') === null", "dialog closed");
  await readState();
  check("re-read succeeds after restore with the saved profile", await page.evaluate("document.querySelector('.database-result h3').textContent==='读取完成'"));

  // Escape closes from the input step and focus returns to the opener.
  await click(".database-toolbar button", "修改此账号的口令");
  await uiWait("document.querySelector('.dialog') !== null", "dialog reopened");
  await page.evaluate("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))");
  await uiWait("document.querySelector('.dialog') === null", "Escape closed input");
  check("focus returns to the opener button", await page.evaluate("document.activeElement?.textContent?.includes('修改此账号的口令')"));

  // Non-superuser profile: change own password, not restorable.
  await makeProfile("PG audit lab", "lhaudit", auditPw);
  await selectProfile("PG audit lab");
  await readState();
  await click(".database-toolbar button", "修改此账号的口令");
  await uiWait("document.querySelector('.dialog input[type=password]')!==null", "audit dialog");
  await field("新口令", auditNew); await field("再次输入新口令", auditNew);
  await click(".dialog button", "检查并生成计划");
  await uiWait("(document.querySelector('.dialog')?.textContent ?? '').includes('确认修改')", "audit confirm");
  check("non-superuser confirm says the old password cannot be put back", (await dialogText()).includes("改后无法取回旧口令"));
  await page.shot("07-audit-confirm.png");
  await click(".dialog button", "确认修改");
  await uiWait("(document.querySelector('.dialog')?.textContent ?? '').includes('口令已修改并用新口令完成独立登录复核')", "audit passed");
  check("non-superuser result has no restore button", await page.evaluate("![...document.querySelectorAll('.dialog button')].some(b=>b.textContent.includes('放回旧口令'))"));
  check("audit role new password works and old fails", psqlWorks("lhaudit", auditNew) && !psqlWorks("lhaudit", auditPw));
  await page.shot("08-audit-result.png");
  await click(".dialog button", "关闭");

  observations.consoleErrors = errors;
  check("no renderer console errors", errors.length === 0);
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; }
finally {
  forwarder?.kill();
  sidecar?.close();
  if (app) { try { await Promise.race([app.requestClose(), new Promise(resolve => setTimeout(resolve, 8000))]); } catch {} }
  try { process.kill(app?.child?.pid); } catch {}
  await new Promise(resolve => setTimeout(resolve, 1500));
  if (containerId) {
    try { owned(); docker("rm", "-f", containerId); check("owned password UI PostgreSQL container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    // Portable data and the app log must not contain any password canary.
    const logFile = path.join(dataRoot, "data", "logs", "lovelyhawk.log");
    checks.push({ label: "app log contains no password canary", passed: !(fs.existsSync(logFile) && canaryBytes().has(fs.readFileSync(logFile))) });
    checks.push({ label: "portable data contains no password canary", passed: !plaintextHasCanary(dataRoot) });
  } catch (error) { failure ??= String(error); }
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/database_password.rs", "crates/lovelyhawk-backend/src/postgresql_runtime_api.rs",
    "ui/src/shared/postgresql-runtime-contract.ts", "ui/src/host/main-api.ts", "ui/src/host/backend-client.ts",
    "ui/src/renderer/PostgresqlPasswordDialog.tsx", "ui/src/renderer/DatabasePage.tsx", "ui/src/renderer/postgresql-runtime-controller.ts",
    "tools/lab/probe-ui-postgresql-password.mjs", "tools/lab/desktop.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, version, platform, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP; release build not exercised", "only this PostgreSQL fixture version on this OS/architecture is real tested", "fixture writes are not production repair behavior"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
}
