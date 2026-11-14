// Desktop UI process activity watch, upload method (pspy), through the debug
// build and CDP. The pspy binary is not in the repository: LOVELYHAWK_PSPY or
// tmp/pspy/pspy64.
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
const runId = randomUUID(), name = `lr-pwupui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `ui-process-watch-upload-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pwupui-"));
const toolPath = path.resolve(repository, process.env.LOVELYHAWK_PSPY ?? "tmp/pspy/pspy64");
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
    throw new Error("Owned process watch UI fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sh = script => onHost("sh", "-c", script);
const landings = () => sh("ls -d /dev/shm/.lovelyhawk-watch-* /tmp/.lovelyhawk-watch-* /var/tmp/.lovelyhawk-watch-* /root/.lovelyhawk-watch-* 2>/dev/null || true").split("\n").filter(Boolean);
const toolProcesses = () => sh("for p in /proc/[0-9]*; do tr '\\0' ' ' 2>/dev/null < $p/cmdline | grep -qE '^/[^ ]*/\\.lovelyhawk-watch-[0-9a-f]{16}/pspy ' && echo ${p#/proc/}; done; true").split("\n").filter(Boolean);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 90000) { const end = Date.now() + ms; while (Date.now() < end) { try { if (await fn()) return; } catch {} await sleep(150); } throw new Error(`Timed out: ${label}`); }

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("process watch UI fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  // A process that outlives one 500 ms scan, every ten seconds.
  sh("setsid sh -c 'while :; do sh -c \"sleep 0.8\" & sleep 10; done' </dev/null >/dev/null 2>&1 &");
  onHost("sh", "-c", `echo ${Buffer.from("#!/bin/sh\nsh -c 'cat /etc/crontab >/dev/null 2>&1; sleep 1.6'\nsh -c 'sleep 1.6; : lh-unmapped-step'\n", "utf8").toString("base64")} | base64 -d > /usr/local/bin/lh-check && chmod 755 /usr/local/bin/lh-check`);

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
  app = await startDesktop({ dataRoot, evidence, dialogAnswers: [toolPath], onConsoleError: entry => errors.push(entry) });
  const session = app.session;
  const page = {
    shot: file => session.shot(file),
    evaluate: expression => Promise.race([session.evaluate(expression), new Promise((_, reject) => setTimeout(() => reject(new Error("evaluate timeout")), 15000))]),
  };
  await app.setViewport(1280, 800);
  const uiWait = (expression, label, ms) => until(() => page.evaluate(expression), label, ms);
  const click = (selector, label) => page.evaluate(`(()=>{const b=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.includes(${JSON.stringify(label)})&&!e.disabled);if(!b)throw Error('Control missing: '+${JSON.stringify(label)});b.click();})()`);
  const tid = id => `document.querySelector('[data-testid=${id}]')`;
  const text = id => page.evaluate(`${tid(id)}?.textContent ?? ''`);
  const setSelect = (id, value) => page.evaluate(`(()=>{const s=${tid(id)};Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(s,${JSON.stringify(String(value))});s.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  const setInput = (id, value) => page.evaluate(`(()=>{const s=${tid(id)};Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(s,${JSON.stringify(value)});s.dispatchEvent(new Event('input',{bubbles:true}));})()`);
  const rowCount = () => page.evaluate("document.querySelectorAll('[data-testid=process-watch-row]').length");

  await uiWait("document.querySelector('.connection-card') !== null", "saved SSH card");
  await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.textContent.includes(${JSON.stringify(name)})).querySelector('button').click()`);
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
  await click(".nav-item", "命令工作台");
  await uiWait(`${tid("process-watch-open")}?.disabled === false`, "watch entry enabled", 120000);
  const open = async () => {
    await page.evaluate(`(()=>{const b=${tid("process-watch-open")};b.focus();b.click();})()`);
    await uiWait(`${tid("process-watch-dialog")} !== null`, "panel open", 60000);
  };
  await open();
  await uiWait(`${tid("process-watch-method-pspy")} !== null`, "method choice", 60000);
  check("the no-upload method is the default", await page.evaluate(`${tid("process-watch-method-poll")}.checked === true`));
  await page.evaluate(`${tid("process-watch-method-pspy")}.click()`);
  await uiWait(`${tid("process-watch-pick")} !== null`, "pick button");
  check("the upload cannot be planned before a program is picked", await page.evaluate(`${tid("process-watch-plan")}.disabled === true`));
  await page.shot("01-method.png");
  await click("[data-testid=process-watch-pick]", "选择 pspy 程序文件");
  await uiWait(`${tid("process-watch-tool")} !== null`, "tool identified", 60000);
  const toolText = await text("process-watch-tool");
  observations.tool = toolText;
  check("the picked file is named and matched to an upstream release, with no local path shown",
    toolText.includes("pspy64") && toolText.includes("v1.2.1") && !(await text("process-watch-dialog")).includes(path.dirname(toolPath)));
  check("picking a file writes nothing to the target", landings().length === 0);

  await setSelect("process-watch-duration", 60);
  await click("[data-testid=process-watch-plan]", "查看将要做什么");
  await uiWait(`${tid("process-watch-plan-view")} !== null`, "plan shown", 60000);
  const planText = await text("process-watch-plan-view");
  observations.plan = planText;
  check("the plan says where, what, as whom, how long, what is left and what is removed",
    /\/\.lovelyhawk-watch-[0-9a-f]{16}/u.test(planText) && /[0-9a-f]{64}/u.test(planText) && planText.includes("root") &&
    planText.includes("1 分钟") && planText.includes("痕迹") && planText.includes("删除文件和目录") && planText.includes("只对这一次运行有效"));
  check("focus is on the plan heading, not on the confirm button",
    await page.evaluate(`document.activeElement?.tagName === 'H3' && document.activeElement !== ${tid("process-watch-confirm")}`));
  check("showing the plan writes nothing to the target", landings().length === 0 && toolProcesses().length === 0);
  await page.shot("02-plan.png");

  await click("[data-testid=process-watch-plan-back]", "返回");
  await uiWait(`${tid("process-watch-plan-view")} === null && ${tid("process-watch-plan")} !== null`, "back to setup");
  check("backing out of the plan still wrote nothing", landings().length === 0);
  await click("[data-testid=process-watch-plan]", "查看将要做什么");
  await uiWait(`${tid("process-watch-confirm")}?.disabled === false`, "plan shown again", 60000);
  sh("setsid sh -c 'sleep 15; /usr/local/bin/lh-check' </dev/null >/dev/null 2>&1 &");
  await page.evaluate(`(()=>{const b=${tid("process-watch-confirm")};b.click();b.click();})()`);
  await uiWait(`${tid("process-watch-progress")} !== null`, "running", 240000);
  await until(() => toolProcesses().length > 0, "tool on target", 30000);
  check("independent check: one landing directory and the tool running from it", landings().length === 1 && toolProcesses().length >= 1);
  await page.shot("03-running.png");

  await uiWait(`${tid("process-watch-conclusion")} !== null`, "finished", 150000);
  await uiWait(`${tid("process-watch-cleanup")} !== null`, "cleanup reported", 60000);
  const cleanupText = await text("process-watch-cleanup");
  observations.conclusion = await text("process-watch-conclusion");
  observations.cleanup = cleanupText;
  check("the result says the upload was removed and verified", cleanupText.includes("已停止并删除") && cleanupText.includes("回读确认"));
  check("independent check: no tool process and no landing directory", toolProcesses().length === 0 && landings().length === 0);
  check("the result still names what the tool can miss", (await text("process-watch-dialog")).includes("仍可能看不到"));
  await page.shot("04-finished.png");

  await click("[data-testid=process-watch-view-origins]", "会话与来源");
  await uiWait(`${tid("process-watch-origins")} !== null`, "origins view", 60000);
  const originsText = await text("process-watch-origins");
  observations.origins = originsText.slice(0, 600);
  check("the origins view groups by source and says it is an inference", originsText.includes("推断") && /（\d+ 个进程）/u.test(originsText));
  await page.shot("05-origins.png");

  await click("[data-testid=process-watch-view-checks]", "检查动作推断");
  await uiWait(`${tid("process-watch-checks")} !== null`, "checks view", 60000);
  const checksText = await text("process-watch-checks");
  observations.checks = checksText.slice(0, 800);
  const inferredTitle = await page.evaluate(`[...document.querySelectorAll('[data-testid=process-watch-inferred-row]')].find(r=>r.textContent.includes('/etc/crontab'))?.querySelector('td')?.textContent ?? ''`);
  check("the check script's crontab read is mapped to a workbench entry", inferredTitle.length > 0);
  check("the unmapped step is listed, and the view does not claim completeness",
    (await text("process-watch-unmatched")).includes("lh-unmapped-step") && checksText.includes("不代表"));
  await page.shot("06-checks.png");
  await page.evaluate(`[...document.querySelectorAll('[data-testid=process-watch-inferred-row]')].find(r=>r.textContent.includes('/etc/crontab')).querySelector('[data-testid=process-watch-open-entry]').click()`);
  await uiWait(`${tid("process-watch-dialog")} === null`, "panel closed for the entry");
  check("前往该检查项 selects that entry in the workbench",
    await page.evaluate(`[...document.querySelectorAll('h2')].some(h=>h.textContent===${JSON.stringify(inferredTitle)})`));
  await page.shot("07-entry.png");

  await open();
  await uiWait(`${tid("process-watch-conclusion")} !== null`, "result restored after reopening", 60000);
  check("reopening the panel brings the kept result back", (await rowCount()) > 0 && (await text("process-watch-cleanup")).includes("已停止并删除"));
  check("reopening started nothing on the target", toolProcesses().length === 0 && landings().length === 0);
  await click("[data-testid=process-watch-close]", "");
  await uiWait(`${tid("process-watch-dialog")} === null`, "dialog closed");

  observations.consoleErrors = errors;
  check("no renderer console errors", errors.length === 0);
} catch (error) { failure = String(error); console.error(failure); process.exitCode = 1; try { await app?.session.shot("99-failure.png"); } catch {} }
finally {
  forwarder?.kill();
  sidecar?.close();
  if (app) { try { await Promise.race([app.requestClose(), new Promise(resolve => setTimeout(resolve, 8000))]); } catch {} }
  try { process.kill(app?.child?.pid); } catch {}
  await new Promise(resolve => setTimeout(resolve, 1500));
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned process watch UI fixture removed", passed: true }); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    const logFile = path.join(dataRoot, "data", "logs", "lovelyhawk.log");
    if (fs.existsSync(logFile)) fs.copyFileSync(logFile, path.join(evidence, "lovelyhawk.log"));
  } catch {}
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/process_watch.rs", "crates/lovelyhawk-backend/src/process_watch_api.rs",
    "ui/src/shared/process-watch-contract.ts", "ui/src/renderer/ProcessWatchPanel.tsx",
    "ui/src/renderer/process-watch-state.ts", "crates/lovelyhawk-core/src/process_watch_upload.rs", "tools/lab/probe-ui-process-watch-upload.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP", "one Debian container: only this container's processes are visible", "the residue list after a dropped connection is driven by the backend probe, not here"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
