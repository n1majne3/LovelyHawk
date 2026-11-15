// Desktop CDP probe for the SQLite viewer's engine fallback lanes, on
// disposable containers derived from the probe image
// (debian:12-slim + openssh-server + python3 + sqlite3):
//   * lane "cli": python3 removed, sqlite3 CLI left -> inspect and rows
//     render through the CLI engine, the delete action is not offered and
//     the dialog explains that row deletion needs python3;
//   * lane "none": both removed -> the viewer shows the no-engine refusal.
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
const image = "localhost/lh-sqlite-sshd:probe";
const evidence = path.join(repository, "target", "lab-sqlite-view-engines", runId);
fs.mkdirSync(evidence, { recursive: true });
const checks = [];
let failure;

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) {
  const passed = typeof actual === "function" ? Boolean(actual()) : Boolean(actual);
  checks.push({ label, passed });
  console.log(`${passed ? "PASS" : "FAIL"} ${label}`);
  if (!passed) throw new Error(label);
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(session, expression, label, attempts = 120) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}
const dialogText = session => session.evaluate(`document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? ""`);
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
  return false;
}

async function runLane(lane, strip) {
  const name = `lr-sqliteeng-${lane}-${short}`;
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), `lovelyhawk-sqlite-${lane}-`));
  let containerId, sidecar, app, forwarder, removed = false;
  const owned = () => {
    const target = JSON.parse(podman("inspect", containerId))[0];
    const stripId = value => String(value ?? "").replace(/^sha256:/u, "");
    if (target.Id !== containerId || (target.Name !== `/${name}` && target.Name !== name) ||
      target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged ||
      (target.Mounts ?? []).some(m => m.Type === "bind"))
      throw new Error("owned fixture identity changed");
    return target;
  };
  try {
    imageId = podman("image", "inspect", image, "--format", "{{.Id}}");
    containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
      "--memory", "1g", "--cpus", "1", "--pids-limit", "256", imageId);
    check(`[${lane}] fixture is an owned, unprivileged container`, Boolean(owned()));
    podman("exec", containerId, "sh", "-c", strip);
    const engines = podman("exec", containerId, "sh", "-c", "command -v python3; command -v sqlite3; true");
    check(`[${lane}] the intended engines were removed`,
      lane === "cli" ? !engines.includes("python3") && engines.includes("sqlite3")
                     : !engines.includes("python3") && !engines.includes("sqlite3"));

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
    if (forwarder.exitCode !== null) throw new Error("port forward failed");

    sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
    const bound = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "cam", password: "LabCam#2026", id: randomUUID(), name: `${name}-22` });
    check(`[${lane}] SSH binding connected`, bound?.stage === "connected");
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
    await waitFor(page, `document.querySelector('[data-testid="sidebar-open-terminal"]') !== null`, "the sidebar terminal button", 240);
    await page.evaluate(`document.querySelector('[data-testid="sidebar-open-terminal"]').click()`);
    const terminal = await app.attachChild("terminal", { timeoutMs: 60_000 });
    await waitFor(terminal,
      `document.querySelector('section[aria-label="远程文件"] .sftp-browser-row') !== null`, "the file manager", 120);
    for (let attempt = 0; attempt < 60 && String(await pathbar(terminal)) !== "根目录"; attempt += 1) {
      await terminal.evaluate(`(() => {
        const button = document.querySelector('section[aria-label="远程文件"] button[aria-label="回到根目录"]');
        if (button !== null && !button.disabled) button.click();
        return true;
      })()`);
      await sleep(800);
    }
    check(`[${lane}] the file manager reached /`, String(await pathbar(terminal)) === "根目录");
    await openDirectory(terminal, "srv", "srv");
    await openDirectory(terminal, "cam", "cam");
    check(`[${lane}] cam.db is listed`, await terminal.evaluate(`${row("cam.db")} !== undefined`));
    check(`[${lane}] the menu offers the SQLite view`,
      (await fileMenuOn(terminal, "cam.db")) && (await clickMenu(terminal, "以 SQLite 只读打开")));
    await waitFor(terminal, `document.querySelector('[data-testid="sqlite-view-dialog"]') !== null`, "the viewer", 90);

    if (lane === "cli") {
      await waitFor(terminal,
        `(document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? '').includes('sessions')`,
        "the table list", 120);
      await terminal.shot("sqlite-cli-inspect.png");
      check("[cli] inspect lists the tables", (await dialogText(terminal)).includes("audit"));
      check("[cli] the sqlite3 engine is named", (await dialogText(terminal)).includes("sqlite3"));
      check("[cli] the sessions table opens", await terminal.evaluate(`(() => {
        const button = [...document.querySelectorAll('.sqlite-view-table-list button')]
          .find((entry) => entry.textContent.includes('sessions'));
        if (!button) return false;
        button.click();
        return true;
      })()`));
      await waitFor(terminal,
        `(document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? '').includes('stale-admin')`,
        "the sessions grid", 120);
      await terminal.shot("sqlite-cli-sessions.png");
      check("[cli] rows render through the CLI engine", (await dialogText(terminal)).includes("stale-admin"));
      check("[cli] no delete checkboxes are offered", await terminal.evaluate(
        `document.querySelectorAll('.sqlite-view-check input[type="checkbox"]').length === 0`));
      check("[cli] the dialog explains deletion needs python3",
        (await dialogText(terminal)).includes("删除行需要目标上有 python3"));
    } else {
      await waitFor(terminal,
        `(document.querySelector('[data-testid="sqlite-view-dialog"]')?.textContent ?? '').includes('python3')`,
        "the refusal", 120);
      await terminal.shot("sqlite-none-refusal.png");
      check("[none] the no-engine refusal is shown",
        (await dialogText(terminal)).includes("需要目标上有 python3 或 sqlite3 3.33 以上"));
    }
  } finally {
    try { await app?.close(); } catch {}
    forwarder?.kill();
    if (containerId && !removed) {
      try { podman("rm", "-f", "-v", containerId); removed = true; check(`[${lane}] owned fixture removed`, true); }
      catch (error) { failure = (failure ?? "") + `[${lane}] cleanup: ${String(error)}\n`; process.exitCode = 1; }
    }
  }
}

let imageId;
try {
  await runLane("cli", "rm -f /usr/bin/python3*");
  await runLane("none", "rm -f /usr/bin/python3* /usr/bin/sqlite3");
} catch (error) {
  failure = (failure ?? "") + String(error?.stack ?? error) + "\n";
  console.log(`FAILURE ${String(error).split("\n")[0]}`);
} finally {
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
