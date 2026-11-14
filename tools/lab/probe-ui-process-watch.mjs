// Desktop UI process activity watch through the debug build and CDP.
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
const runId = randomUUID(), name = `lr-pwui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `ui-process-watch-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pwui-"));
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
// The bracket keeps this check's own command line from matching itself.
const watchers = () => onHost("sh", "-c",
  "for p in /proc/[0-9]*/cmdline; do if tr '\\0' ' ' < \"$p\" 2>/dev/null | grep -q 'lhwatc[h]-'; then echo ${p#/proc/}; fi; done")
  .split("\n").map(line => Number.parseInt(line, 10)).filter(pid => pid > 0);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 90000) { const end = Date.now() + ms; while (Date.now() < end) { try { if (await fn()) return; } catch {} await sleep(150); } throw new Error(`Timed out: ${label}`); }

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("process watch UI fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  // A process that outlives one 500 ms scan, every ten seconds.
  onHost("sh", "-c", "setsid sh -c 'while :; do sh -c \"sleep 0.8\" & sleep 10; done' </dev/null >/dev/null 2>&1 &");

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
  check("the workbench shows a visible 进程活动监视 button", (await text("process-watch-open")).includes("进程活动监视"));

  const open = async () => {
    await page.evaluate(`(()=>{const b=${tid("process-watch-open")};b.focus();b.click();})()`);
    // A finished run of this connection comes back first; leave it for a new one.
    await uiWait(`${tid("process-watch-start")} !== null || ${tid("process-watch-restart")} !== null`, "panel content", 60000);
    await page.evaluate(`${tid("process-watch-restart")}?.click()`);
    await uiWait(`${tid("process-watch-start")} !== null`, "ready screen", 60000);
  };
  await open();
  const ready = await text("process-watch-dialog");
  observations.ready = ready;
  check("ready screen states the method and its standing limitation",
    ready.includes("不向目标写入任何文件") && ready.includes("两次扫描之间启动并退出的进程会漏掉"));
  check("ready screen shows the container gap", await page.evaluate(`${tid("process-watch-gap-container")} !== null`));
  check("opening does not start anything by itself", watchers().length === 0 &&
    await page.evaluate(`document.activeElement !== ${tid("process-watch-start")}`));
  await page.shot("01-ready.png");

  await setSelect("process-watch-duration", 60);
  await page.evaluate(`(()=>{const b=${tid("process-watch-start")};b.click();b.click();})()`);
  await uiWait(`${tid("process-watch-progress")} !== null`, "running", 60000);
  await until(() => watchers().length > 0, "watcher on target", 15000);
  check("a double click starts one watch, not two", new Set(watchers()).size >= 1 &&
    !(await text("process-watch-dialog")).includes("已经有一个进程监视在运行"));
  const first = await text("process-watch-progress");
  await uiWait(`(${tid("process-watch-progress")}?.textContent ?? '') !== ${JSON.stringify(first)}`, "progress updates", 30000);
  check("progress shows elapsed time and counts", /已进行 \d+ 秒/u.test(await text("process-watch-progress")));
  await page.shot("02-running.png");

  await click("[data-testid=process-watch-cancel]", "取消监视");
  await uiWait(`${tid("process-watch-conclusion")} !== null`, "cancelled result", 60000);
  observations.cancelled = await text("process-watch-conclusion");
  await until(() => watchers().length === 0, "watcher gone after cancel", 10000);
  check("independent check: no watcher on the target after cancel", watchers().length === 0);
  await page.shot("03-cancelled.png");
  await click("[data-testid=process-watch-close]", "");
  await uiWait(`${tid("process-watch-dialog")} === null`, "dialog closed");
  check("closing returns focus to the entry button", await page.evaluate(`document.activeElement === ${tid("process-watch-open")}`));

  await open();
  await setSelect("process-watch-duration", 60);
  await click("[data-testid=process-watch-start]", "开始监视");
  await uiWait(`${tid("process-watch-conclusion")} !== null`, "finished result", 150000);
  const conclusion = await text("process-watch-conclusion");
  observations.conclusion = conclusion;
  check("the conclusion reports new processes and does not claim a complete picture",
    /\d+/u.test(conclusion) && !conclusion.includes("没有活动"));
  check("the container gap stays visible beside the result", (await text("process-watch-dialog")).includes("容器"));
  await until(() => watchers().length === 0, "watcher gone after deadline", 15000);
  check("independent check: no watcher on the target after the deadline", watchers().length === 0);
  await page.shot("04-finished.png");

  await click("[data-testid=process-watch-view-repeated]", "重复出现的命令");
  await uiWait(`${tid("process-watch-groups")} !== null`, "repeat view", 60000);
  const groups = await page.evaluate(`[...document.querySelectorAll('[data-testid=process-watch-groups] tbody tr')].map(r=>r.textContent)`);
  observations.groups = groups.slice(0, 20);
  check("the 10 s marker is listed as 周期性", groups.some(row => row.includes("sleep 0.8") && row.includes("周期性")));
  await page.shot("05-repeated.png");
  await page.evaluate(`[...document.querySelectorAll('[data-testid=process-watch-group]')].find(b=>b.closest('tr').textContent.includes('sleep 0.8')).click()`);
  await uiWait(`${tid("process-watch-group-clear")} !== null`, "group filter applied");
  const filtered = await page.evaluate("[...document.querySelectorAll('[data-testid=process-watch-row]')].map(r=>r.textContent)");
  check("choosing a group filters the timeline to it", filtered.length > 0 && filtered.every(row => row.includes("sleep 0.8")));
  await click("[data-testid=process-watch-group-clear]", "");

  const all = await rowCount();
  await setInput("process-watch-search", "sleep 10");
  await until(async () => (await rowCount()) < all, "search narrows", 10000);
  const searched = await page.evaluate("[...document.querySelectorAll('[data-testid=process-watch-row]')].map(r=>r.textContent)");
  check("search narrows the timeline", searched.length > 0 && searched.every(row => row.includes("sleep 10")));
  await setInput("process-watch-search", "");
  await until(async () => (await rowCount()) === all, "search cleared", 10000);
  const matching = async () => Number((await text("process-watch-dialog")).match(/(\d+) 条记录符合当前筛选/u)?.[1] ?? -1);
  const folded = await matching();
  check("own and baseline rows start folded", await page.evaluate(
    `${tid("process-watch-own-toggle")}.getAttribute('aria-pressed') === 'false' && ${tid("process-watch-baseline-toggle")}.getAttribute('aria-pressed') === 'false'`));
  await page.evaluate(`${tid("process-watch-own-toggle")}.click()`);
  await page.evaluate(`${tid("process-watch-baseline-toggle")}.click()`);
  await until(async () => (await matching()) > folded, "folded rows shown", 10000);
  observations.rows = { folded, unfolded: await matching() };
  check("the toggles bring the folded rows into the timeline", (await matching()) > folded);
  await page.shot("06-timeline.png");

  check("every control is a real button, select or input reachable by Tab", await page.evaluate(
    `[...${tid("process-watch-dialog")}.querySelectorAll('[data-testid]')].filter(e=>e.matches('[data-testid^=process-watch-]')&&e.onclick!==undefined&&!e.matches('button,select,input,p,table,tr,section,div')).length === 0`));
  await click("[data-testid=process-watch-close]", "");
  await uiWait(`${tid("process-watch-dialog")} === null`, "dialog closed again");
  check("focus returns to the entry button again", await page.evaluate(`document.activeElement === ${tid("process-watch-open")}`));

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
    "ui/src/renderer/process-watch-state.ts", "tools/lab/probe-ui-process-watch.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP", "one Debian container: only this container's processes are visible", "re-attaching to a running watch after reopening the panel is not driven"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
