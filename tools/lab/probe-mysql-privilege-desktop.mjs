// Desktop CDP probe for the MySQL 账号权限 panel on a disposable
// mysql:8.0 + sshd fixture. The whole flow goes through the rendered UI:
// save a loopback profile, run 检查实例, open 账号权限 for
// traffic@127.0.0.1, tick the global CREATE/DROP and the database ALL
// members, add the competition matrix grants through the form, plan,
// confirm, read the verified receipt, then undo — with independent
// in-container SHOW GRANTS checks both ways.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";
import { startDesktop } from "./desktop.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), short = runId.slice(0, 8);
const evidence = path.join(repository, "target", "lab-mysql-privilege-desktop", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-mysql-priv-desktop-"));
fs.mkdirSync(evidence, { recursive: true });

const ROOT_OS_PASSWORD = "LabRoot#2026";
const ROOT_DB_PASSWORD = "LabDb#2026";
const ACCOUNT = { user: "traffic", host: "127.0.0.1" };
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

const checks = [];
let sidecar, app, containerId, imageId, forwarder, removed = false, failure;
const name = `lr-mysqlprivdesk-${short}`;
const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 }).trim();
const podmanIn = (input, ...args) => execFileSync("podman.exe", args, { input, encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(session, expression, label, attempts = 240) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}
async function scrollAndSee(session, selector, needed, label) {
  const result = await session.evaluate(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return 'missing';
    el.scrollIntoView({ block: 'center' });
    const box = el.getBoundingClientRect();
    if (!(box.bottom > 0 && box.top < window.innerHeight && box.right > 0 && box.left < window.innerWidth)) return 'offscreen';
    return ${JSON.stringify(needed)}.every(text => el.textContent.includes(text)) ? true : 'text-missing';
  })()`);
  check(label, result === true);
}
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
    (target.Mounts ?? []).some(m => m.Type !== "tmpfs" || m.Destination !== DATADIR) ||
    !String(target.HostConfig.Tmpfs?.[DATADIR] ?? "").startsWith("rw,noexec,nosuid,size=512m"))
    throw new Error("owned fixture identity changed");
  return target;
}
const sq = value => String(value).replace(/\\/g, "\\\\").replace(/'/g, "''");
let admin;
const grantsOf = () => admin(`SHOW GRANTS FOR 'traffic'@'127.0.0.1'`).split("\n")
  .map(line => line.trim()).filter(line => /^GRANT\b/iu.test(line)).sort();
const canon = lines => lines.map(line => line
  .replace(/['`]/gu, "")
  .replace(/ALL PRIVILEGES/iu, "ALL")
  .replace(/^GRANT (.+?) ON /iu, (m, privs) => `GRANT ${privs.split(",").map(p => p.trim().toUpperCase()).sort().join(",")} ON `)
  .replace(/\s+/gu, " ").trim()).sort();

const fill = (page, selector, value) => page.evaluate(`(() => {
  const el = document.querySelector(${JSON.stringify(selector)});
  if (!el) throw new Error('missing field ' + ${JSON.stringify(selector)});
  const proto = el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(value)});
  el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
})()`);
const clickText = (page, scope, text) => page.evaluate(`(() => {
  const button = [...document.querySelectorAll(${JSON.stringify(scope)})]
    .find((entry) => entry.textContent.includes(${JSON.stringify(text)}) && !entry.disabled);
  if (!button) return false;
  button.click();
  return true;
})()`);

try {
  imageId = podman("image", "inspect", "lovelyres-svc:mysql", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "768m", "--cpus", "1", "--pids-limit", "128",
    "--tmpfs", `${DATADIR}:rw,noexec,nosuid,size=512m`,
    "-e", `MYSQL_ROOT_PASSWORD=${ROOT_DB_PASSWORD}`, "-e", "MYSQL_ROOT_HOST=%", "-e", "LAB_SERVICE_COMMAND=/entrypoint.sh mysqld",
    "--entrypoint", "/bin/sh", imageId,
    "-c", "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null; exec /opt/entrypoint.sh");
  try {
    check("fixture is an owned, unprivileged container with only a tmpfs datadir", Boolean(owned()));
    const cli = podman("exec", containerId, "sh", "-c", "command -v mariadb || command -v mysql").split("\n")[0];
    admin = sql => podmanIn(sql, "exec", "-i", "-e", `MYSQL_PWD=${ROOT_DB_PASSWORD}`, "-e", `DBCLI=${cli}`,
      containerId, "sh", "-c", '"$DBCLI" --default-character-set=utf8mb4 -uroot 2>/dev/null || "$DBCLI" --default-character-set=utf8mb4 --protocol=TCP -h127.0.0.1 -uroot 2>/dev/null');
    const end = Date.now() + 240_000;
    const ready = () => { try { return /^1$/m.test(admin("SELECT 1").slice(-20)); } catch { return false; } };
    while (!ready()) {
      if (Date.now() > end) throw new Error("database did not become ready");
      await sleep(500);
    }
    admin(`ALTER USER 'root'@'localhost' IDENTIFIED BY '${sq(ROOT_DB_PASSWORD)}';
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
CREATE USER IF NOT EXISTS 'traffic'@'127.0.0.1' IDENTIFIED BY 'Traffic#Lab2026';
GRANT CREATE, DROP ON *.* TO 'traffic'@'127.0.0.1';
GRANT ALL PRIVILEGES ON traffic_oa.* TO 'traffic'@'127.0.0.1';
FLUSH PRIVILEGES;`);
    const original = canon(grantsOf());
    check("fixture grants traffic ALL on traffic_oa.* plus global CREATE,DROP",
      original.includes("GRANT CREATE,DROP ON *.* TO traffic@127.0.0.1") &&
      original.some(line => /ALL ON traffic_oa\.\*/u.test(line)));

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
      "-L", `127.0.0.1:${localPort}:${owned().NetworkSettings.IPAddress}:22`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
    await sleep(1500);
    if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");

    sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
    const bound = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: ROOT_OS_PASSWORD, id: runId, name: `${name}-22` });
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
    await waitFor(page, "document.querySelector('.nav-item') !== null || document.body.textContent.includes('实验')", "the connected shell", 240);
    check("the MySQL page opens", await clickText(page, "nav button", "MySQL"));
    await waitFor(page, `document.querySelector('section[aria-label="MySQL 数据库"]') !== null`, "the MySQL page");
    await clickText(page, "section[aria-label='MySQL 数据库'] button", "新建连接");
    await waitFor(page, `document.querySelector('section[aria-label="新建数据库连接"]') !== null`, "the connection editor");
    const setInput = (label, value) => page.evaluate(`(() => {
      const field = [...document.querySelectorAll('section[aria-label="新建数据库连接"] label')]
        .find((entry) => entry.firstChild?.textContent?.trim() === ${JSON.stringify(label)});
      const el = field?.querySelector('input');
      if (!el) throw new Error('missing field ' + ${JSON.stringify(label)});
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, ${JSON.stringify(value)});
      el.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    await setInput("连接名称", "traffic-oa");
    await setInput("数据库用户名", "root");
    await page.evaluate(`(() => {
      const radio = [...document.querySelectorAll('section[aria-label="新建数据库连接"] input[name="mysql-tls-mode"]')]
        .find((entry) => entry.closest('label')?.textContent.includes('仅 SSH 加密'));
      if (!radio) return false;
      radio.click();
      return true;
    })()`);
    await page.evaluate(`(() => {
      const radio = [...document.querySelectorAll('section[aria-label="新建数据库连接"] input[name="mysql-password-action"]')]
        .find((entry) => entry.closest('label')?.textContent.includes('设置新口令'));
      if (!radio) return false;
      radio.click();
      return true;
    })()`);
    await setInput("新口令", ROOT_DB_PASSWORD);
    await clickText(page, `section[aria-label="新建数据库连接"] button[type="submit"]`, "保存连接");
    await waitFor(page, `[...document.querySelectorAll('section[aria-label="MySQL 数据库"] td')].some((cell) => cell.textContent === 'root')`, "the saved profile row", 120);
    await page.shot("mysql-profile-saved.png");
    check("the profile saved through the dialog", true);
    check("实例检查 runs", await clickText(page, "section[aria-label='MySQL 数据库'] button", "检查实例"));
    await waitFor(page, `document.querySelector('section[aria-label^="实例检查"]') !== null`, "the review panel", 240);
    await sleep(1500);
    await page.shot("mysql-review.png");
    const reviewText = await page.evaluate(`document.querySelector('section[aria-label^="实例检查"]')?.textContent?.slice(0, 3000) ?? ''`);
    fs.writeFileSync(path.join(evidence, "review-text.txt"), reviewText);
    await waitFor(page, `document.querySelector('[data-testid="mysql-privileges-traffic-127.0.0.1"]') !== null`, "the account-privileges button", 240);
    check("the review lists traffic@127.0.0.1", await clickText(page, `[data-testid="mysql-privileges-traffic-127.0.0.1"]`, "账号权限"));
    await waitFor(page, `document.querySelector('[data-testid="mysql-privilege-panel"] .mysql-priv-row') !== null`, "the privilege rows", 240);
    check("focus lands inside the privilege panel", await page.evaluate(`document.querySelector('[data-testid="mysql-privilege-panel"]')?.contains(document.activeElement) === true`));
    await scrollAndSee(page, '[data-testid="mysql-privilege-panel"]', ["账号权限", "traffic@127.0.0.1"], "the privilege panel is in view");

    const scopeText = row => page.evaluate(`document.querySelector('[data-testid="mysql-priv-row-${row}"] strong')?.textContent ?? ''`);
    let globalRow = -1, dbRow = -1;
    for (let index = 0; index < 12; index += 1) {
      const text = String(await scopeText(index));
      if (text === "") break;
      if (text.includes("全局")) globalRow = index;
      if (text.includes("数据库 traffic_oa")) dbRow = index;
    }
    check("the panel shows the global and traffic_oa rows", globalRow >= 0 && dbRow >= 0);
    const tick = (rowIndex, names) => page.evaluate(`(() => {
      const row = document.querySelector('[data-testid="mysql-priv-row-${rowIndex}"]');
      if (!row) return 'no-row';
      const wanted = ${JSON.stringify(names)};
      const boxes = [...row.querySelectorAll('input[type="checkbox"]')];
      let ticked = 0;
      for (const box of boxes) {
        const label = box.closest('label')?.textContent ?? '';
        if (wanted.some((name) => label === '收回 ' + name) && !box.checked) { box.click(); ticked += 1; }
      }
      return ticked;
    })()`);
    check("global CREATE and DROP ticked", (await tick(globalRow, ["CREATE", "DROP"])) === 2);
    check("all traffic_oa members ticked", (await tick(dbRow, DATABASE_ALL)) === DATABASE_ALL.length);
    await scrollAndSee(page, '[data-testid="mysql-privilege-panel"]', ["收回 CREATE", "收回 DROP"], "the ticked rows are in view");
    await page.shot("mysql-priv-ticks.png");

    for (const add of MATRIX) {
      await fill(page, '[data-testid="mysql-priv-add-db"]', add.database);
      if (add.table !== null) await fill(page, '[data-testid="mysql-priv-add-table"]', add.table);
      const added = await page.evaluate(`(() => {
        const group = document.querySelector('[data-testid="mysql-privilege-panel"] .mysql-priv-add .mysql-priv-checks');
        const wanted = ${JSON.stringify(add.privileges)};
        let ticked = 0;
        for (const box of group.querySelectorAll('input[type="checkbox"]')) {
          const label = box.closest('label')?.textContent ?? '';
          if (wanted.includes(label) && !box.checked) { box.click(); ticked += 1; }
        }
        const submit = document.querySelector('[data-testid="mysql-priv-add-submit"]');
        if (ticked === wanted.length && submit && !submit.disabled) { submit.click(); return true; }
        return 'ticked ' + ticked;
      })()`);
      check(`added grant ${add.database}.${add.table ?? "*"}`, added === true);
    }
    await scrollAndSee(page, '[data-testid="mysql-privilege-panel"]', ["新增授权"], "the added grants are in view");
    await page.shot("mysql-priv-adds.png");
    check("生成执行计划 arms", await clickText(page, '[data-testid="mysql-priv-plan"]', "生成执行计划"));
    await waitFor(page, `document.querySelector('[data-testid="mysql-priv-plan-view"]')?.textContent?.includes('执行计划') === true`, "the plan", 120);
    await scrollAndSee(page, '[data-testid="mysql-priv-plan-view"]', ["执行计划", "REVOKE"], "the plan is visible in the viewport");
    check("focus stays on the plan region", await page.evaluate(`document.querySelector('[data-testid="mysql-priv-plan-view"]')?.contains(document.activeElement) === true`));
    await page.shot("mysql-priv-plan.png");
    const focus = await page.evaluate(`(() => {
      const danger = document.querySelector('[data-testid="mysql-priv-execute"]');
      return document.activeElement !== danger;
    })()`);
    check("confirm is not pre-focused on the danger button", focus);
    check("确认执行", await clickText(page, '[data-testid="mysql-priv-execute"]', "确认执行"));
    await waitFor(page, `document.querySelector('[data-testid="mysql-priv-receipt"]')?.textContent?.includes('已执行并复核') === true`, "the verified receipt", 240);
    await scrollAndSee(page, '[data-testid="mysql-priv-receipt"]', ["已执行并复核"], "the receipt is visible in the viewport");
    check("focus stays on the receipt region", await page.evaluate(`document.querySelector('[data-testid="mysql-priv-receipt"]')?.contains(document.activeElement) === true`));
    await page.shot("mysql-priv-receipt.png");
    const wanted = canon([
      "GRANT USAGE ON *.* TO traffic@127.0.0.1",
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
    const after = canon(grantsOf());
    check("independent SHOW GRANTS equals the competition matrix", JSON.stringify(after) === JSON.stringify(wanted));
    await waitFor(page, `document.querySelector('[data-testid="mysql-priv-undo"]') !== null`, "the undo button", 60);
    check("恢复原授权", await clickText(page, '[data-testid="mysql-priv-undo"]', "恢复原授权"));
    await waitFor(page, `document.querySelector('[data-testid="mysql-priv-receipt"]')?.textContent?.includes('已恢复') === true`, "the undo receipt", 240);
    await scrollAndSee(page, '[data-testid="mysql-priv-receipt"]', ["已恢复"], "the undo receipt is visible in the viewport");
    await page.shot("mysql-priv-undone.png");
    check("independent SHOW GRANTS matches the original lines",
      JSON.stringify(canon(grantsOf())) === JSON.stringify(original));
  } finally {
    try { await app?.close(); } catch {}
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
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), checks, error: failure || null }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
