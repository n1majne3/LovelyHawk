// Drives the "Supervisor 程序" tab on a disposable Podman target that runs
// supervisord (debian:12-slim + supervisor + openssh-server + python3). Two
// managed programs — an HTTP service on 127.0.0.1:18080 and a sleeper — are
// listed, restarted with a loopback health check, stopped and started again
// through the desktop UI, and the supervised pid is shown to refuse the
// generic process restart. Independently checked from outside SSH.
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
const runId = randomUUID(), name = `lr-supv-${runId.slice(0, 8)}`;
const image = "localhost/lh-supervisor-sshd:probe";
const evidence = path.join(repository, "target", "lab-supervisor", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-supv-"));
const checks = [];
let containerId, imageId, sidecar, app, forwarder, failure, localPort;
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
    throw new Error("owned supervisor fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const onHostText = command => onHost("sh", "-c", command);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const dialogText = session => session.evaluate(
  `document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? ""`);

async function waitFor(session, expression, label, attempts = 90) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await session.evaluate(expression) === true) return;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}`);
}
function contextMenuOnRow(session, text) {
  return session.evaluate(`(() => {
    const row = [...document.querySelectorAll('.system-info-table-scroll tbody tr')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(text)}));
    if (row === undefined) return false;
    (row.querySelector('td') ?? row).dispatchEvent(new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, clientX: 300, clientY: 300
    }));
    return true;
  })()`);
}
function clickMenuItem(session, label) {
  return session.evaluate(`(async () => {
    const button = [...document.querySelectorAll('.system-info-row-menu button:not(.system-info-row-menu-parent)')]
      .find(candidate => candidate.textContent.includes(${JSON.stringify(label)}));
    if (button === undefined) return false;
    const submenu = button.closest('.system-info-row-submenu');
    if (submenu !== null) {
      if (submenu.hidden) submenu.previousElementSibling.click();
      for (let frame = 0; frame < 60 && (submenu.hidden || submenu.style.visibility === 'hidden'); frame += 1) {
        await new Promise(resolve => setTimeout(resolve, 16));
      }
      if (submenu.hidden || submenu.style.visibility === 'hidden') return false;
    }
    button.click();
    return true;
  })()`);
}
function closeDialog(session) {
  return session.evaluate(`(() => {
    const dialog = document.querySelector('[data-testid="system-info-row-action-dialog"]');
    if (dialog === null) return true;
    const button = [...dialog.querySelectorAll('button')]
      .find(candidate => candidate.textContent.trim() === '关闭' || candidate.textContent.trim() === '取消');
    button?.click();
    return button !== undefined;
  })()`);
}

function ensureImage() {
  try {
    return podman("image", "inspect", image, "--format", "{{.Id}}");
  } catch {}
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lh-supervisor-image-"));
  fs.writeFileSync(path.join(dir, "Containerfile"), `FROM docker.m.daocloud.io/library/debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server supervisor python3 curl sudo procps iproute2 \\
 && apt-get clean && rm -rf /var/lib/apt/lists/* \\
 && echo 'root:LabRoot#2026' | chpasswd \\
 && mkdir -p /run/sshd /var/log/supervisor /srv/oa \\
 && echo '<h1>oa ok</h1>' > /srv/oa/index.html \\
 && sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \\
 && sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY oa.conf worker.conf /etc/supervisor/conf.d/
COPY entry.sh /entry.sh
ENTRYPOINT ["/entry.sh"]
`);
  fs.writeFileSync(path.join(dir, "oa.conf"), `[program:oa]
command=python3 -m http.server 18080 --bind 127.0.0.1 --directory /srv/oa
autostart=true
autorestart=true
stdout_logfile=/var/log/supervisor/oa.log
`);
  fs.writeFileSync(path.join(dir, "worker.conf"), `[program:worker]
command=/bin/sleep 3600
autostart=true
autorestart=true
`);
  fs.writeFileSync(path.join(dir, "entry.sh"), `#!/bin/sh
/usr/sbin/sshd
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
`);
  fs.chmodSync(path.join(dir, "entry.sh"), 0o755);
  podman("build", "-t", image, dir);
  return podman("image", "inspect", image, "--format", "{{.Id}}");
}

try {
  imageId = ensureImage();
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "1g", "--cpus", "1", "--pids-limit", "256", imageId);
  check("supervisor fixture is an owned, unprivileged container without host mounts", Boolean(owned()));

  let status = "";
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try { status = onHostText("supervisorctl status 2>/dev/null || true"); } catch {}
    if (status.includes("oa") && status.includes("RUNNING") && status.includes("worker")) break;
    await sleep(1000);
  }
  check("supervisord runs both planted programs", status.includes("oa") && status.includes("worker"));
  console.log(`      supervisorctl status: ${JSON.stringify(status)}`);
  const oaPidBefore = onHostText("supervisorctl pid oa 2>/dev/null || echo 0");
  check("the HTTP program answers on 127.0.0.1:18080",
    onHostText("curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:18080/") === "200");

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
  const bound = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: "LabRoot#2026", id: runId, name: `${name}-22` });
  check("SSH binding connected", bound?.stage === "connected");
  sidecar.close();
  sidecar = null;

  app = await startDesktop({ dataRoot, evidence });
  const session = app.session;
  await waitFor(session, "document.querySelector('.connection-card') !== null", "the connection list");
  await session.evaluate(`(() => {
    const card = document.querySelector('.connection-card');
    card?.querySelector('button')?.click() ?? card?.click();
    return true;
  })()`);
  await waitFor(session,
    "document.body.textContent.includes('实验') || document.querySelector('.nav-item') !== null",
    "the connected shell", 240);
  await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.nav-item')]
      .find(candidate => candidate.textContent?.includes('主机全景'));
    button?.click();
    return true;
  })()`);
  await waitFor(session, "document.querySelector('.system-info-tabs') !== null", "the page", 120);
  check("the supervisor tab exists", await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === 'Supervisor 程序');
    if (button === undefined) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`));
  await waitFor(session,
    `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes('oa')) &&
     [...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes('worker'))`,
    "both program rows", 240);
  await session.shot("supervisor-table.png");
  check("both programs list with their state", await session.evaluate(`(() => {
    const rows = [...document.querySelectorAll('.system-info-table-scroll tbody tr')].map(row => row.textContent);
    return rows.some(row => row.includes('oa') && row.includes('RUNNING')) &&
      rows.some(row => row.includes('worker') && row.includes('RUNNING'));
  })()`));

  // Restart the HTTP program with a loopback health check.
  check("the oa row can be right-clicked", await contextMenuOnRow(session, "oa"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions");
  const menuText = await session.evaluate(
    `document.querySelector('.system-info-row-menu')?.textContent ?? ""`);
  check("the menu offers restart", menuText.includes("重启程序"));
  await session.shot("supervisor-menu.png");
  check("the restart item clicks", await clickMenuItem(session, "重启程序"));

  await waitFor(session,
    `document.querySelector('[data-testid="system-info-row-health-port"]') !== null`,
    "the health-check step", 60);
  await session.shot("supervisor-health-step.png");
  check("the health fields take input", await session.evaluate(`(() => {
    const port = document.querySelector('[data-testid="system-info-row-health-port"]');
    const path = document.querySelector('[data-testid="system-info-row-health-path"]');
    if (port === null || path === null) return false;
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    set.call(port, '18080'); port.dispatchEvent(new Event('input', { bubbles: true }));
    set.call(path, '/'); path.dispatchEvent(new Event('input', { bubbles: true }));
    return port.value === '18080';
  })()`));
  await sleep(500);
  check("the plan button is armed", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-health-submit"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(session,
    `(() => {
      const dialog = document.querySelector('[data-testid="system-info-row-action-dialog"]');
      const button = dialog?.querySelector('[data-testid="system-info-row-action-execute"]');
      return (dialog?.textContent ?? '').includes('oa') && button !== null && button !== undefined && !button.disabled;
    })()`,
    "the restart plan", 120);
  await session.shot("supervisor-restart-plan.png");
  check("the restart plan dialog confirms", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-action-execute"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return text.includes('核对过') || text.includes('没有完成') || text.includes('与预期不符');
    })()`,
    "the restart receipt", 240);
  const restartReceipt = await dialogText(session);
  await session.shot("supervisor-restart-receipt.png");
  check("the restart verified with the HTTP observation", restartReceipt.includes("核对过") && restartReceipt.includes("200"));
  console.log(`      receipt excerpt: ${JSON.stringify(restartReceipt.slice(0, 300))}`);
  const oaPidAfter = onHostText("supervisorctl pid oa 2>/dev/null || echo 0");
  check("the program runs under a new pid", oaPidAfter !== "0" && oaPidAfter !== oaPidBefore);
  check("the program still answers HTTP afterwards",
    onHostText("curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:18080/") === "200");
  check("the dialog closes", await closeDialog(session));
  await sleep(1000);

  // Stop then start the same program.
  await session.evaluate("window.dispatchEvent(new Event('keydown'))");
  check("the oa row can be right-clicked for stop", await contextMenuOnRow(session, "oa"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions for stop");
  check("the stop item clicks", await clickMenuItem(session, "停止程序"));
  await waitFor(session,
    `(() => {
      const button = document.querySelector('[data-testid="system-info-row-action-execute"]');
      return button !== null && button !== undefined && !button.disabled;
    })()`,
    "the stop plan", 120);
  check("the stop plan dialog confirms", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-action-execute"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return text.includes('核对过') || text.includes('没有完成') || text.includes('与预期不符');
    })()`,
    "the stop receipt", 240);
  const stopReceipt = await dialogText(session);
  await session.shot("supervisor-stop-receipt.png");
  check("the stop verified", stopReceipt.includes("核对过"));
  check("supervisord says the program is stopped",
    onHostText("supervisorctl status oa | awk '{print $2}'") === "STOPPED");
  check("the port stopped answering",
    onHostText("curl -s --max-time 5 -o /dev/null http://127.0.0.1:18080/ && echo up || echo down") === "down");
  check("the dialog closes after stop", await closeDialog(session));
  await sleep(1000);

  check("the stopped row can be right-clicked for start", await contextMenuOnRow(session, "oa"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions for start");
  check("the start item clicks", await clickMenuItem(session, "启动程序"));
  await waitFor(session,
    `document.querySelector('[data-testid="system-info-row-health-port"]') !== null`,
    "the health step for start", 60);
  check("start plans without a health check too", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-health-submit"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(session,
    `(() => {
      const button = document.querySelector('[data-testid="system-info-row-action-execute"]');
      return button !== null && button !== undefined && !button.disabled;
    })()`,
    "the start plan", 120);
  check("the start plan dialog confirms", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-action-execute"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));
  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return text.includes('核对过') || text.includes('没有完成') || text.includes('与预期不符');
    })()`,
    "the start receipt", 240);
  const startReceipt = await dialogText(session);
  await session.shot("supervisor-start-receipt.png");
  check("the start verified", startReceipt.includes("核对过"));
  check("supervisord says the program runs again",
    onHostText("supervisorctl status oa | awk '{print $2}'") === "RUNNING");
  check("the dialog closes after start", await closeDialog(session));
  await sleep(1000);

  // The managed pid must refuse the generic process restart.
  const oaPid = onHostText("supervisorctl pid oa 2>/dev/null || echo 0");
  check("the process tab exists", await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === '进程详情');
    if (button === undefined) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`));
  await waitFor(session,
    `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes('${oaPid}'))`,
    "the supervised pid row", 240);
  check("the supervised pid row can be right-clicked", await contextMenuOnRow(session, oaPid));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the process menu");
  check("the generic restart item clicks", await clickMenuItem(session, "按原命令行重启"));
  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return text.includes('Supervisor') || text.includes('拒绝') || text.includes('托管');
    })()`,
    "the supervised refusal", 120);
  const refusalText = await dialogText(session);
  await session.shot("supervisor-process-refusal.png");
  check("the refusal points at the Supervisor page", refusalText.includes("Supervisor"));
  console.log(`      refusal excerpt: ${JSON.stringify(refusalText.slice(0, 300))}`);
  check("the managed process was not touched",
    onHostText("supervisorctl pid oa 2>/dev/null || echo 0") === oaPid);
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (app) { try { await app.close(); } catch {} }
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned supervisor fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId,
    sourceHash: createHash("sha256").update(fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/supervisor.rs"))).digest("hex").slice(0, 16),
    checks, error: failure ?? null,
    limits: [
      "supervisord in one container: unix-socket auth and multiple supervisord instances are not exercised",
      "the health check observes an HTTP status on 127.0.0.1 only, it is not a business-level recovery check",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
