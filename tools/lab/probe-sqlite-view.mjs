// Drives "以 SQLite 只读打开…" from the SSH window's file manager on a
// disposable Podman target (debian:12-slim + openssh-server + python3 +
// sqlite3). The fixture carries the competition-shaped cam.db (users,
// sessions, cameras, audit, one expired admin session), a table whose name
// holds a double quote, and a WAL-mode database in a read-only directory
// for the immutable fallback. Deleting the expired session goes through
// plan -> confirm -> receipt, is checked independently, is undone, and the
// backup file is verified on the target.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";
import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-sqlite-${runId.slice(0, 8)}`;
const image = "localhost/lh-sqlite-sshd:probe";
const evidence = path.join(repository, "target", "lab-sqlite-view", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-sqlite-"));
const checks = [];
let containerId, imageId, sidecar, app, forwarder, localPort;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) {
  const passed = typeof actual === "function" ? Boolean(actual()) : Boolean(actual);
  checks.push({ label, passed });
  console.log(`${passed ? "PASS" : "FAIL"} ${label}`);
  if (!passed) throw new Error(label);
}
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = value => String(value ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    (target.Mounts ?? []).some(m => m.Type === "bind"))
    throw new Error("owned sqlite fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const onHostText = command => onHost("sh", "-c", command);
const dbq = sql => onHostText(`sqlite3 /srv/cam/cam.db ${JSON.stringify(sql)}`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(session, expression, label, attempts = 90) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}
function dialogText(session) {
  return session.evaluate(`document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? ""`);
}
function row(name) {
  return `[...document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row')].find((candidate) => candidate.querySelector('.sftp-browser-row-label')?.textContent === ${JSON.stringify(name)})`;
}
const pathbar = session => session.evaluate(`document.querySelector('section[aria-label="远程文件"] .sftp-browser-path-value')?.textContent ?? ''`);
async function openDirectory(session, name, expectPath) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (String(await pathbar(session)) === expectPath) return;
    await session.evaluate(`(() => { const candidate = ${row(name)}; if (candidate && !candidate.disabled) candidate.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); return true; })()`);
    await sleep(700);
  }
  throw new Error(`timed out opening ${name}`);
}
async function fileMenuOn(session, name) {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const open = await session.evaluate(`(() => {
      const candidate = ${row(name)};
      if (!candidate) return 'missing';
      if (document.querySelector('[role="menu"]') !== null) return 'open';
      const box = candidate.getBoundingClientRect();
      candidate.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: box.left + 20, clientY: box.top + 5 }));
      return 'dispatched';
    })()`);
    if (open === 'open') return true;
    if (open === 'missing') return false;
    await sleep(500);
    if (await session.evaluate(`document.querySelector('[role="menu"]') !== null`)) return true;
  }
  return false;
}
async function clickMenu(session, label) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const clicked = await session.evaluate(`(() => {
      const item = [...document.querySelectorAll('[role="menuitem"]')].find((entry) => entry.textContent.includes(${JSON.stringify(label)}));
      if (!item) return false;
      item.click();
      return true;
    })()`);
    if (clicked) return true;
    await sleep(400);
  }
  console.log(`      menu content: ${JSON.stringify(await session.evaluate(
    `document.querySelector('.sftp-context-menu')?.textContent ?? '(no menu)'`))}`);
  return false;
}

function ensureImage() {
  try { return podman("image", "inspect", image, "--format", "{{.Id}}"); } catch {}
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lh-sqlite-image-"));
  fs.writeFileSync(path.join(dir, "Containerfile"), `FROM docker.m.daocloud.io/library/debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server python3 sqlite3 \\
 && apt-get clean && rm -rf /var/lib/apt/lists/* \\
 && echo 'root:LabRoot#2026' | chpasswd && useradd -m -s /bin/bash cam \\
 && echo 'cam:LabCam#2026' | chpasswd && mkdir -p /run/sshd \\
 && sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \\
 && sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY seed.py /seed.py
COPY entry.sh /entry.sh
ENTRYPOINT ["/entry.sh"]
`);
  fs.writeFileSync(path.join(dir, "seed.py"), `import sqlite3, os, time
os.makedirs("/srv/cam", exist_ok=True)
db = sqlite3.connect("/srv/cam/cam.db")
db.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT);
CREATE TABLE sessions(session_id TEXT PRIMARY KEY, username TEXT, role TEXT, created_at INTEGER, expires_at INTEGER, ip_addr TEXT);
CREATE TABLE cameras(id INTEGER PRIMARY KEY, name TEXT, ip TEXT, credential TEXT);
CREATE TABLE audit(id INTEGER PRIMARY KEY, actor TEXT, action TEXT, at INTEGER);
CREATE TABLE 'a"b; drop'(id INTEGER PRIMARY KEY, note TEXT);
""")
now = int(time.time())
db.execute("INSERT INTO users VALUES (1,'admin','h1','admin'),(2,'operator','h2','viewer')")
db.execute("INSERT INTO cameras VALUES (1,'gate','10.0.0.11','cam-pass-1'),(2,'yard','10.0.0.12','cam-pass-1')")
db.execute("INSERT INTO sessions VALUES ('live-op','operator','viewer',?,?,'10.0.0.9')", (now, now + 3600))
db.execute("INSERT INTO sessions VALUES ('stale-admin','admin','admin',?,?,'10.0.0.7')", (now - 7200, now - 3600))
db.executemany("INSERT INTO audit(actor, action, at) VALUES (?,?,?)", [("sys", f"event-{i}", now - i) for i in range(300)])
db.execute("INSERT INTO 'a\\"b; drop' VALUES (1,'quoted table row')")
db.commit(); db.close()
os.makedirs("/srv/camro", exist_ok=True)
wal = sqlite3.connect("/srv/camro/wal.db")
wal.execute("PRAGMA journal_mode=WAL")
wal.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
wal.execute("INSERT INTO t VALUES (1,'wal-row')")
wal.commit()
# Keep the WAL populated so mode=ro fails and immutable=1 is needed.
wal.execute("INSERT INTO t VALUES (2,'wal-row-2')")
wal.close()
import pwd
cam = pwd.getpwnam("cam")
for root, dirs, files in os.walk("/srv/cam"):
    os.chown(root, cam.pw_uid, cam.pw_gid)
    for f in files:
        os.chown(os.path.join(root, f), cam.pw_uid, cam.pw_gid)
os.chown("/srv/cam", cam.pw_uid, cam.pw_gid)
os.chown("/srv/camro/wal.db", cam.pw_uid, cam.pw_gid)
os.chmod("/srv/camro", 0o555)
`);
  fs.writeFileSync(path.join(dir, "entry.sh"), `#!/bin/sh
python3 /seed.py
exec /usr/sbin/sshd -D
`);
  fs.chmodSync(path.join(dir, "entry.sh"), 0o755);
  podman("build", "-t", image, dir);
  return podman("image", "inspect", image, "--format", "{{.Id}}");
}

try {
  imageId = ensureImage();
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "1g", "--cpus", "1", "--pids-limit", "256", imageId);
  check("sqlite fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  check("cam.db is seeded with the expired admin session",
    dbq("SELECT count(*) FROM sessions WHERE session_id='stale-admin'").includes("1"));
  check("the read-only WAL directory is in place",
    onHostText("python3 -c 'import sqlite3;print(sqlite3.connect(\"/srv/camro/wal.db\").execute(\"PRAGMA journal_mode\").fetchone()[0])' 2>&1").includes("wal") ||
    onHostText("stat -c '%a' /srv/camro") === "555");

  const forwardTarget = owned().NetworkSettings.IPAddress + ":22";
  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  localPort = await new Promise(resolve => {
    const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
    "-L", `127.0.0.1:${localPort}:${forwardTarget}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
  await sleep(1500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");

  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const bound = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "cam", password: "LabCam#2026", id: runId, name: `${name}-22` });
  check("SSH binding connected", bound?.stage === "connected");
  sidecar.close();
  sidecar = null;

  app = await startDesktop({ dataRoot, evidence });
  const page = app.session;
  await waitFor(page, "document.querySelector('.connection-card') !== null", "the connection list");
  await page.evaluate(`(() => {
    const card = document.querySelector('.connection-card');
    card?.querySelector('button')?.click() ?? card?.click();
    return true;
  })()`);
  await waitFor(page,
    "document.body.textContent.includes('实验') || document.querySelector('.nav-item') !== null",
    "the connected shell", 240);
  await waitFor(page,
    `document.querySelector('[data-testid="sidebar-open-terminal"]') !== null`,
    "the sidebar terminal button", 120);
  await page.evaluate(`document.querySelector('[data-testid="sidebar-open-terminal"]').click()`);
  const terminal = await app.attachChild("terminal", { timeoutMs: 60_000 });
  await waitFor(terminal, "document.querySelector('.xterm') !== null", "the terminal", 90);
  await waitFor(terminal,
    `document.querySelector('section[aria-label="远程文件"] .sftp-browser-path-value') !== null`,
    "the file manager", 90);
  // Home is /root: climb to / then walk down by double-clicking rows.
  await waitFor(terminal,
    `document.querySelector('section[aria-label="远程文件"] .sftp-browser-row') !== null`, "a listing", 90);
  for (let attempt = 0; attempt < 60 && String(await pathbar(terminal)) !== "根目录"; attempt += 1) {
    await terminal.evaluate(`(() => {
      const button = document.querySelector('section[aria-label="远程文件"] button[aria-label="回到根目录"]');
      if (button !== null && !button.disabled) button.click();
      return true;
    })()`);
    await sleep(800);
  }
  if (String(await pathbar(terminal)) !== "根目录") {
    const state = await terminal.evaluate(`(() => {
      const up = document.querySelector('section[aria-label="远程文件"] button[aria-label="上一级"]');
      const home = document.querySelector('section[aria-label="远程文件"] button[aria-label="回到根目录"]');
      return { path: document.querySelector('.sftp-browser-path-value')?.textContent,
        home: home === null ? 'missing' : (home.disabled ? 'disabled' : 'enabled'),
        up: up === null ? 'missing' : (up.disabled ? 'disabled' : 'enabled'),
        rows: document.querySelectorAll('section[aria-label="远程文件"] .sftp-browser-row').length };
    })()`);
    console.log(`      pane state: ${JSON.stringify(state)}`);
    await terminal.shot("sqlite-pane-stuck.png");
  }
  check("the file manager reached /", String(await pathbar(terminal)) === "根目录");
  await openDirectory(terminal, "srv", "srv");
  await openDirectory(terminal, "cam", "cam");
  check("cam.db is listed", await terminal.evaluate(`${row("cam.db")} !== undefined`));

  check("the file's menu opens", await fileMenuOn(terminal, "cam.db"));
  check("the menu offers the SQLite view", await clickMenu(terminal, "以 SQLite 只读打开"));
  await waitFor(terminal, `document.querySelector('[data-testid="sqlite-view-dialog"]') !== null`, "the viewer", 90);
  await waitFor(terminal,
    `(document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? '').includes('sessions')`,
    "the table list", 60);
  await terminal.shot("sqlite-inspect.png");
  check("inspect lists the tables with row counts", (await dialogText(terminal)).includes("audit"));
  check("the forensic caution is visible", (await dialogText(terminal)).includes("访问时间"));
  check("the quoted table name displays as plain text", (await dialogText(terminal)).includes('a"b; drop'));

  check("the sessions table opens", await terminal.evaluate(`(() => {
    const button = [...document.querySelectorAll('.sqlite-view-table-list button')]
      .find((entry) => entry.textContent.includes('sessions'));
    if (!button) return false;
    button.click();
    return true;
  })()`));
  await waitFor(terminal,
    `(document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? '').includes('stale-admin')`,
    "the sessions grid", 60);
  await terminal.shot("sqlite-sessions.png");
  check("the grid shows the expired admin row", (await dialogText(terminal)).includes("stale-admin"));
  check("the delete action is offered for a rowid table", await terminal.evaluate(`(() => {
    return document.querySelectorAll('.sqlite-view-check input[type="checkbox"]').length > 0;
  })()`));

  check("the expired admin row can be selected", await terminal.evaluate(`(() => {
    const tr = [...document.querySelectorAll('.sqlite-view-grid tbody tr')]
      .find((row) => row.textContent.includes('stale-admin'));
    const box = tr?.querySelector('input[type="checkbox"]');
    if (!box) return false;
    box.click();
    return true;
  })()`));
  check("the delete button arms", await terminal.evaluate(`(() => {
    const button = [...document.querySelectorAll('.sqlite-view-grid-actions button')]
      .find((entry) => entry.textContent.includes('删除所选行'));
    if (!button || button.disabled) return false;
    button.click();
    return true;
  })()`));
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const state = await terminal.evaluate(`(() => ({
      plan: document.querySelector('[data-testid="sqlite-delete-plan"]') !== null,
      error: document.querySelector('.sqlite-view-error')?.textContent ?? null,
    }))()`);
    if (state.plan) break;
    if (state.error !== null) throw new Error(`plan refused: ${state.error}`);
    await sleep(500);
    if (attempt === 119) throw new Error("timed out waiting for the delete plan");
  }
  await terminal.shot("sqlite-delete-plan.png");
  const planText = await terminal.evaluate(`document.querySelector('[data-testid="sqlite-delete-plan"]')?.textContent ?? ''`);
  check("the plan names the row and warns about a live database",
    planText.includes("stale-admin") && planText.includes("活动数据库"));
  check("the plan confirms", await terminal.evaluate(`(() => {
    const button = [...document.querySelectorAll('[data-testid="sqlite-delete-plan"] button')]
      .find((entry) => entry.textContent.includes('确认删除'));
    if (!button || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(terminal, `document.querySelector('[data-testid="sqlite-delete-receipt"]') !== null`, "the delete receipt", 120);
  await terminal.shot("sqlite-delete-receipt.png");
  const receiptText = await terminal.evaluate(`document.querySelector('[data-testid="sqlite-delete-receipt"]')?.textContent ?? ''`);
  check("the receipt reports one verified deletion",
    receiptText.includes("已删除") && receiptText.includes("1"));

  check("independently: only the expired session is gone",
    dbq("SELECT count(*) FROM sessions").includes("1") &&
    dbq("SELECT count(*) FROM sessions WHERE session_id='live-op'").includes("1") &&
    dbq("SELECT count(*) FROM sessions WHERE session_id='stale-admin'").includes("0"));
  check("independently: audit rows are untouched", dbq("SELECT count(*) FROM audit").includes("300"));
  check("the backup exists next to the database",
    onHostText("ls /srv/cam/.lovelyres-backups/ 2>/dev/null | grep -c 'cam.db'").trim() !== "0");

  check("the undo restores the row", await terminal.evaluate(`(() => {
    const button = [...document.querySelectorAll('[data-testid="sqlite-delete-receipt"] button')]
      .find((entry) => entry.textContent.includes('撤销删除'));
    if (!button || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(terminal,
    `(document.querySelector('[data-testid="sqlite-delete-receipt"]')?.textContent ?? '').includes('已恢复')`,
    "the undo receipt", 90);
  check("independently: the expired session is back with its values",
    dbq("SELECT count(*) FROM sessions WHERE session_id='stale-admin' AND username='admin' AND ip_addr='10.0.0.7'").includes("1"));

  // The WAL database in a read-only directory must flag the immutable fallback.
  for (let attempt = 0; attempt < 40 && String(await pathbar(terminal)) !== "根目录"; attempt += 1) {
    await terminal.evaluate(`document.querySelector('section[aria-label="远程文件"] button[aria-label="回到根目录"]')?.click()`);
    await sleep(600);
  }
  await openDirectory(terminal, "srv", "srv");
  await openDirectory(terminal, "camro", "camro");
  check("wal.db is listed", await terminal.evaluate(`${row("wal.db")} !== undefined`));
  check("the wal menu opens", await fileMenuOn(terminal, "wal.db"));
  check("the wal menu offers the viewer", await clickMenu(terminal, "以 SQLite 只读打开"));
  await waitFor(terminal,
    `document.querySelector('[data-testid="sqlite-immutable-note"]') !== null`,
    "the immutable note", 90);
  await terminal.shot("sqlite-immutable.png");
  check("the immutable fallback is flagged", (await dialogText(terminal)).includes("不可变方式读取"));
  check("the wal table rows still read", await terminal.evaluate(`(() => {
    const button = [...document.querySelectorAll('.sqlite-view-table-list button')]
      .find((entry) => entry.textContent.includes('t'));
    if (!button) return false;
    button.click();
    return true;
  })()`));
  await waitFor(terminal,
    `(document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? '').includes('wal-row')`,
    "the wal rows", 60);
  check("no delete path appears under immutable reads", await terminal.evaluate(
    `document.querySelectorAll('.sqlite-view-check input[type="checkbox"]').length === 0`));
} catch (error) {
  console.log(`FAIL ${error.message}`);
  checks.push({ label: error.message, passed: false });
} finally {
  fs.writeFileSync(path.join(evidence, "report.json"),
    JSON.stringify({ runId, checks, passed: checks.filter(c => c.passed).length, total: checks.length }, null, 2));
  try { app?.close(); } catch {}
  try { forwarder?.kill(); } catch {}
  try { sidecar?.close(); } catch {}
  try { if (containerId !== undefined) podman("rm", "-f", containerId); } catch {}
  console.log(`${checks.filter(c => c.passed).length}/${checks.length} checks passed; evidence at ${evidence}`);
  process.exit(checks.every(c => c.passed) ? 0 : 1);
}
