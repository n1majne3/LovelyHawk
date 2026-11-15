// Drives the kernel-module "卸载模块" row action on a disposable Podman SSH
// target. Containers share the host kernel and cannot load or unload
// modules, so what this can honestly check is the *reachable* half of the
// feature: the menu entry exists, the plan stage refuses with a concrete
// reason (missing tool, missing privilege, in-use, or unreadable state —
// whichever the shared-kernel table produces), and nothing on the host is
// touched. A real unload needs a VM and is reported NOT_RUN.
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
const runId = randomUUID(), name = `lr-kmod-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-kernel-module-unload", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-kmod-"));
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
    (target.Mounts ?? []).some(m => m.Type === "bind" || m.Destination !== "/var/lib/postgresql/data"))
    throw new Error("owned kernel-module fixture identity changed");
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

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("kernel-module fixture is an owned, unprivileged container without host mounts", Boolean(owned()));

  // What the shared kernel exposes in this container decides which refusal
  // is reachable: any listed module is a row, and whether rmmod exists at all
  // decides between the tools refusal and a later one.
  const moduleName = onHostText("awk 'NR==1 {print $1}' /proc/modules");
  check("the container lists at least one host kernel module", moduleName.length > 0);
  const hasRmmod = onHostText("command -v rmmod >/dev/null 2>&1 && echo yes || echo no");
  console.log(`      first module: ${moduleName}; rmmod present: ${hasRmmod}`);

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
  const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: "LabRoot#2026", id: runId, name: `${name}-22` });
  check("SSH binding connected", status?.stage === "connected");
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
  check("the kernel modules tab exists", await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === '内核模块');
    if (button === undefined) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`));
  await waitFor(session,
    `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes(${JSON.stringify(moduleName)}))`,
    "a kernel module row", 240);
  await session.shot("kernel-modules-table.png");

  check("the module row can be right-clicked", await contextMenuOnRow(session, moduleName));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions");
  const menuText = await session.evaluate(
    `document.querySelector('.system-info-row-menu')?.textContent ?? ""`);
  check("the menu offers 卸载模块", menuText.includes("卸载模块"));
  await session.shot("kernel-module-menu.png");
  check("the unload item clicks", await clickMenuItem(session, "卸载模块"));

  // Inside a container the plan stage must refuse: no usable rmmod, no
  // privilege that survives to the host kernel, an in-use module, or a field
  // the shared /proc exposes ambiguously. Any of these is a correct answer;
  // "accepted" is the only wrong one.
  try {
    await waitFor(session,
      `(() => {
        const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
        return ['缺少 rmmod', '免密码 sudo', '卸载会失败', '读不出来', 'modules_disabled', '没有出现在运行中的模块表', '拒绝']
          .some(fragment => text.includes(fragment));
      })()`,
      "a concrete refusal", 120);
  } catch (error) {
    console.log(`      dialog at timeout: ${JSON.stringify((await dialogText(session)).slice(0, 400))}`);
    await session.shot("kernel-module-timeout.png");
    throw error;
  }
  const refusalText = await dialogText(session);
  await session.shot("kernel-module-refusal.png");
  check("the refusal text is shown", refusalText.length > 0);
  console.log(`      refusal excerpt: ${JSON.stringify(refusalText.slice(0, 200))}`);
  check("the module is still listed afterwards",
    onHostText(`awk '$1=="${moduleName}" {print $1}' /proc/modules`) === moduleName);
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (app) { try { await app.close(); } catch {} }
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned kernel-module fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId,
    sourceHash: createHash("sha256").update(fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/kernel_module_unload.rs"))).digest("hex").slice(0, 16),
    checks, error: failure ?? null,
    limits: [
      "containers share the host kernel: a real module unload is NOT_RUN here and needs a VM",
      "only the plan-stage refusal paths a shared /proc/modules can produce are exercised",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
