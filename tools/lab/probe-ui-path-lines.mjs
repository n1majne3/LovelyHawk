// Desktop UI line deletion through the debug build and CDP.
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
const runId = randomUUID(), name = `lr-linesui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `ui-line-delete-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-linesui-"));
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
    throw new Error("Owned line-delete UI fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const raw = target => Buffer.from(onHost("base64", target), "base64").toString("utf8");
const sha256 = text => createHash("sha256").update(text, "utf8").digest("hex");
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 90000) { const end = Date.now() + ms; while (Date.now() < end) { try { if (await fn()) return; } catch {} await sleep(150); } throw new Error(`Timed out: ${label}`); }

const BEACON_LINE = "* * * * * root /tmp/.lhbeacon\n";

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("line-delete UI fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", "test -f /etc/crontab || { printf '# probe crontab\\nSHELL=/bin/sh\\nPATH=/usr/bin:/bin\\n' > /etc/crontab; }");
  onHost("sh", "-c", `echo ${Buffer.from(BEACON_LINE, "utf8").toString("base64")} | base64 -d >> /etc/crontab`);
  const planted = raw("/etc/crontab");
  const plantedSha = sha256(planted);
  check("beacon line is the last line of /etc/crontab", planted.endsWith(BEACON_LINE));

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
  const key = (selector, value) => page.evaluate(`(()=>{const el=document.querySelector(${JSON.stringify(selector)});if(!el)throw Error('Element missing: '+${JSON.stringify(selector)});el.dispatchEvent(new KeyboardEvent('keydown',{key:${JSON.stringify(value)},bubbles:true}));})()`);

  await uiWait("document.querySelector('.connection-card') !== null", "saved SSH card");
  await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.textContent.includes(${JSON.stringify(name)})).querySelector('button').click()`);
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
  await click(".nav-item", "命令工作台");
  await uiWait("document.querySelector('.emergency-commands-workbench') !== null", "workbench page");

  // 关键文件权限 prints `ls -l … /etc/crontab`, which is what offers the
  // path handle for /etc/crontab in this output.
  await page.evaluate(`(()=>{const b=[...document.querySelectorAll('.emergency-command-group-items button')].find(e=>e.querySelector('strong')?.textContent==='关键文件权限');if(!b)throw Error('command missing');b.click();})()`);
  await click("button.emergency-command-run", "运行只读调查");
  await uiWait("document.querySelector('[aria-label=\"文件操作：/etc/crontab\"]') !== null", "crontab handle offered", 120000);
  await page.shot("01-run.png");

  await page.evaluate("document.querySelector('[aria-label=\"文件操作：/etc/crontab\"]').click()");
  await uiWait("document.querySelector('[data-testid=emergency-path-menu]') !== null", "path menu open");
  check("the menu offers line deletion", await page.evaluate(
    "[...document.querySelectorAll('[data-testid=emergency-path-menu] [role=menuitem]')].some(b=>b.textContent.includes('删除指定行'))"));
  await click("[data-testid=emergency-path-menu] [role=menuitem]", "删除指定行");
  await uiWait("document.querySelector('[data-testid=emergency-path-lines-dialog]') !== null", "lines dialog open");
  await uiWait("document.querySelectorAll('[data-testid=emergency-path-lines] [role=option]').length > 0", "preview lines shown", 60000);
  const dialogText = () => page.evaluate("document.querySelector('[data-testid=emergency-path-lines-dialog]')?.textContent ?? ''");
  check("the dialog explains delete versus comment",
    (await dialogText()).includes("彻底移除") && (await dialogText()).includes("注释"));
  check("the plan button waits for a selection", await page.evaluate(
    "document.querySelector('[data-testid=emergency-path-lines-plan]')?.disabled === true"));

  // Keyboard only: focus the listbox, End to the last line, Enter selects it.
  await page.evaluate("document.querySelector('[data-testid=emergency-path-lines]')?.focus()");
  await key("[data-testid=emergency-path-lines]", "End");
  await key("[data-testid=emergency-path-lines]", "Enter");
  await uiWait("document.querySelector('[data-testid=emergency-path-lines-plan]')?.disabled === false", "line selected");
  const total = await page.evaluate("document.querySelectorAll('[data-testid=emergency-path-lines] [role=option]').length");
  check("keyboard selection picked the last (beacon) line", await page.evaluate(
    `document.querySelector('[data-testid=emergency-path-first-line]')?.value === '${total}' && ` +
    `document.querySelector('[data-testid=emergency-path-last-line]')?.value === '${total}'`));
  await page.shot("02-selected.png");

  await click("[data-testid=emergency-path-lines-plan]", "生成删除计划");
  await uiWait("document.querySelector('[data-testid=emergency-path-lines-plan-heading]') !== null", "plan shown", 60000);
  const planText = await dialogText();
  observations.plan = planText;
  check("plan names the file, the line and the backup",
    planText.includes("/etc/crontab") && planText.includes("备份") && planText.includes("lhbeacon"));
  check("focus moved to the plan heading, not the dangerous button", await page.evaluate(
    "document.activeElement?.dataset?.testid === 'emergency-path-lines-plan-heading'"));
  await page.shot("03-plan.png");

  await click("[data-testid=emergency-path-execute]", "确认并删除");
  await uiWait("document.querySelector('[data-testid=emergency-path-undo]') !== null", "receipt with undo", 120000);
  await page.shot("04-done.png");
  check("independent readback: beacon line is gone and the rest is byte-identical",
    raw("/etc/crontab") === planted.replace(BEACON_LINE, ""));

  await click("[data-testid=emergency-path-undo]", "撤销这次操作");
  await uiWait("document.querySelector('[data-testid=emergency-path-undo-ask]') !== null", "undo ask");
  await click("[data-testid=emergency-path-undo-confirm]", "确认撤销");
  await uiWait("(document.querySelector('[data-testid=emergency-path-undo-result]')?.textContent ?? '').includes('已撤销')", "undo done", 120000);
  await page.shot("05-undone.png");
  check("independent readback: undo restored the file byte for byte",
    sha256(raw("/etc/crontab")) === plantedSha);
  await click("[data-testid=emergency-path-lines-dialog] button", "关闭");

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
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned line-delete UI fixture removed", passed: true }); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    const logFile = path.join(dataRoot, "data", "logs", "lovelyhawk.log");
    if (fs.existsSync(logFile)) fs.copyFileSync(logFile, path.join(evidence, "lovelyhawk.log"));
  } catch {}
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/line_delete.rs", "crates/lovelyhawk-backend/src/emergency_path_api.rs",
    "ui/src/shared/emergency-command-contract.ts", "ui/src/renderer/EmergencyPathLinesDialog.tsx",
    "ui/src/renderer/EmergencyPathMenu.tsx", "tools/lab/probe-ui-path-lines.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP", "one Debian container; only the /etc/crontab path driven end to end"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
