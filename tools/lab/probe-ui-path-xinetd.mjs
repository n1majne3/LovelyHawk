// Desktop UI xinetd service disable through the debug build and CDP.
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
const runId = randomUUID(), name = `lr-xinetdui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `ui-xinetd-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-xinetdui-"));
const checks = [], observations = {};
let containerId, imageId, sidecar, failure, forwarder, app;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind"))
    throw new Error("Owned xinetd UI fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const write = (target, content) => onHost("sh", "-c", `echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d > ${target}`);
const port = p => onHost("sh", "-c", `bash -c 'exec 3<>/dev/tcp/127.0.0.1/${p}' 2>/dev/null && echo OPEN || echo CLOSED`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 90000) { const end = Date.now() + ms; while (Date.now() < end) { try { if (await fn()) return; } catch {} await sleep(150); } throw new Error(`Timed out: ${label}`); }

const LHSVC = "service lhsvc\n{\n        id              = lhsvc\n        type            = UNLISTED\n        disable         = no\n        socket_type     = stream\n        protocol        = tcp\n        port            = 10005\n        wait            = no\n        user            = root\n        server          = /bin/cat\n}\n";

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("xinetd UI fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install -y -qq xinetd iproute2 >/dev/null && command -v xinetd bash sha256sum pgrep");
  write("/etc/xinetd.d/lhsvc", LHSVC);
  write("/etc/xinetd.d/svc.bak", LHSVC.replaceAll("lhsvc", "baksvc").replace("10005", "10010"));
  onHost("sh", "-c", "xinetd && sleep 1 && pgrep -x xinetd");
  check("fixture live: the service port connects", port(10005) === "OPEN");
  const lhsvcSha = onHost("sha256sum", "/etc/xinetd.d/lhsvc").split(/\s+/u)[0];

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
  check("owned SSH fixture is saved with a confirmed host key", status?.stage === "connected");
  sidecar.close(); sidecar = undefined;

  const errors = [];
  app = await startDesktop({ dataRoot, evidence, onConsoleError: entry => errors.push(entry) });
  const session = app.session;
  const page = {
    shot: file => session.shot(file),
    evaluate: expression => Promise.race([session.evaluate(expression), new Promise((_, reject) => setTimeout(() => reject(new Error("evaluate timeout")), 15000))]),
  };
  await app.setViewport(1280, 800);
  const uiWait = (expression, label, ms) => until(() => page.evaluate(expression), label, ms);
  const click = (selector, label) => page.evaluate(`(()=>{const b=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.includes(${JSON.stringify(label)})&&!e.disabled);if(!b)throw Error('Control missing: '+${JSON.stringify(label)});b.click();})()`);

  await uiWait("document.querySelector('.connection-card') !== null", "saved SSH card");
  await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.textContent.includes(${JSON.stringify(name)})).querySelector('button').click()`);
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
  await click(".nav-item", "命令工作台");
  await uiWait("document.querySelector('.emergency-commands-workbench') !== null", "workbench page");

  // 超级守护进程服务 lists /etc/xinetd.d/* with full paths, which is what
  // offers the path handle for the service file in this output.
  await page.evaluate(`(()=>{const b=[...document.querySelectorAll('.emergency-command-group-items button')].find(e=>e.querySelector('strong')?.textContent==='超级守护进程服务');if(!b)throw Error('command missing');b.click();})()`);
  await click("button.emergency-command-run", "运行只读调查");
  await uiWait("document.querySelector('[aria-label=\"文件操作：/etc/xinetd.d/lhsvc\"]') !== null", "service handle offered", 120000);
  await page.shot("01-run.png");

  // A name xinetd never loads keeps the menu honest too.
  await page.evaluate("document.querySelector('[aria-label=\"文件操作：/etc/xinetd.d/svc.bak\"]')?.click()");
  await uiWait("document.querySelector('[data-testid=emergency-path-menu]') !== null", "bak menu open");
  check("the ignored .bak name is not offered the xinetd action", !(await page.evaluate(
    "[...document.querySelectorAll('[data-testid=emergency-path-menu] [role=menuitem]')].some(b=>b.textContent.includes('停用此 xinetd 服务'))")));
  await page.evaluate("window.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))");
  await uiWait("document.querySelector('[data-testid=emergency-path-menu]') === null", "menu dismissed");

  await page.evaluate("document.querySelector('[aria-label=\"文件操作：/etc/xinetd.d/lhsvc\"]').click()");
  await uiWait("document.querySelector('[data-testid=emergency-path-menu]') !== null", "path menu open");
  check("the menu offers 停用此 xinetd 服务…", await page.evaluate(
    "[...document.querySelectorAll('[data-testid=emergency-path-menu] [role=menuitem]')].some(b=>b.textContent.includes('停用此 xinetd 服务'))"));
  await click("[data-testid=emergency-path-menu] [role=menuitem]", "停用此 xinetd 服务");
  await uiWait("document.querySelector('[data-testid=emergency-path-dialog]') !== null", "xinetd dialog open");
  const dialogText = () => page.evaluate("document.querySelector('[data-testid=emergency-path-dialog]')?.textContent ?? ''");

  await uiWait("document.querySelector('[data-testid=emergency-path-execute]')?.disabled === false", "plan ready", 120000);
  const planText = await dialogText();
  observations.plan = planText;
  check("the dialog states the isolation-before-restore intent",
    planText.includes("复核未通过时文件仍保持隔离"));
  check("plan names the service, port and reload method",
    planText.includes("/etc/xinetd.d/lhsvc") && planText.includes("lhsvc") && planText.includes("10005") &&
    planText.includes("SIGHUP") && planText.includes("lovelyres-backups"));
  await page.shot("02-plan.png");

  await click("[data-testid=emergency-path-execute]", "确认并执行");
  await uiWait("document.querySelector('[data-testid=emergency-path-undo]') !== null", "receipt with undo", 120000);
  await page.shot("03-done.png");
  check("receipt reports the verified disable", (await dialogText()).includes("已完成"));
  check("independent readback: file isolated, port refuses connections",
    onHost("sh", "-c", "test ! -e /etc/xinetd.d/lhsvc && find /etc/xinetd.d/.lovelyres-backups -name '*lhsvc.removed' -type f | head -1 | grep .") !== "" &&
    port(10005) === "CLOSED");

  await click("[data-testid=emergency-path-undo]", "撤销这次操作");
  await uiWait("document.querySelector('[data-testid=emergency-path-undo-ask]') !== null", "undo ask");
  await click("[data-testid=emergency-path-undo-confirm]", "确认撤销");
  await uiWait("(document.querySelector('[data-testid=emergency-path-undo-result]')?.textContent ?? '').includes('已撤销')", "undo done", 120000);
  await page.shot("04-undone.png");
  const undoText = await dialogText();
  check("independent readback: undo put the planned bytes back",
    onHost("sha256sum", "/etc/xinetd.d/lhsvc").split(/\s+/u)[0] === lhsvcSha);
  // xinetd can die on its SIGHUP reconfigure (seen on 2.3.15.4 in this
  // image): the undo then honestly reports 配置已放回但未被加载, and the
  // service only comes back once the daemon runs again — restart it and
  // prove the restored file loads.
  if (undoText.includes("未被加载")) {
    observations.daemonDiedOnSighup = true;
    onHost("sh", "-c", "xinetd; sleep 1");
  }
  await until(() => port(10005) === "OPEN", "service accepts connections again", 15000);
  check("undo re-enabled the service, port connects again", true);
  await click("[data-testid=emergency-path-dialog] button", "关闭");

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
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned xinetd UI fixture removed", passed: true }); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    const logFile = path.join(dataRoot, "data", "logs", "lovelyhawk.log");
    if (fs.existsSync(logFile)) fs.copyFileSync(logFile, path.join(evidence, "lovelyhawk.log"));
  } catch {}
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/xinetd_service.rs", "crates/lovelyhawk-backend/src/emergency_path_api.rs",
    "ui/src/shared/emergency-command-contract.ts", "ui/src/renderer/EmergencyPathDialog.tsx",
    "ui/src/renderer/EmergencyPathMenu.tsx", "tools/lab/probe-ui-path-xinetd.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP", "one Debian container; SIGHUP reload driven, systemd reload unreachable without systemd"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
