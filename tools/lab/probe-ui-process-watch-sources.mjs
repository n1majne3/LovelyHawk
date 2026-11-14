// Desktop UI for the records a target already keeps (process accounting),
// through the debug build and CDP.
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
const runId = randomUUID(), name = `lr-pwsrcui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `ui-process-watch-sources-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pwsrcui-"));
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
    throw new Error("Owned process watch sources UI fixture identity changed");
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
  imageId = podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  // The one added capability lets the probe itself switch accounting on, as an operator would have.
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
    "--cap-add", "SYS_PACCT", imageId, "sleep", "infinity");
  check("sources UI fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  const sh = script => onHost("sh", "-c", script);
  sh("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && " +
    "apt-get install -y -qq openssh-server procps acct >/dev/null 2>&1 && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && " +
    "mkdir -p /etc/ssh/sshd_config.d && printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/lab.conf && " +
    "echo 'root:LabRoot#2026' | chpasswd && /usr/sbin/sshd && accton off >/dev/null 2>&1; : > /var/log/account/pacct");
  sh("printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/lh-beacon && chmod 0755 /usr/local/bin/lh-beacon");

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
  forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
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

  const connectCard = async () => {
    await uiWait("document.querySelector('.connection-card') !== null", "saved SSH card");
    await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.textContent.includes(${JSON.stringify(name)})).querySelector('button').click()`);
    await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
    await click(".nav-item", "命令工作台");
    await uiWait(`${tid("process-watch-open")}?.disabled === false`, "watch entry enabled", 120000);
  };
  const open = async () => {
    await page.evaluate(`(()=>{const b=${tid("process-watch-open")};b.focus();b.click();})()`);
    await uiWait(`${tid("process-watch-start")} !== null`, "ready screen", 60000);
    await uiWait(`${tid("process-watch-sources")} !== null`, "existing records section", 30000);
  };
  const close = async () => {
    await click("[data-testid=process-watch-close]", "");
    await uiWait(`${tid("process-watch-dialog")} === null`, "dialog closed");
  };
  await connectCard();

  await open();
  observations.installed = await text("process-watch-sources");
  check("installed but not recording: said so, with no read control offered",
    observations.installed.includes("已安装，但没有发现正在记录的文件") && observations.installed.includes("不会替你开启") &&
    await page.evaluate(`${tid("process-watch-accounting-read")} === null`));
  check("sources this host does not have are not listed",
    await page.evaluate(`${tid("process-watch-source-bpftrace")} === null && ${tid("process-watch-source-execsnoop")} === null && ${tid("process-watch-source-audit-execve")} === null`));
  check("opening the panel did not switch accounting on", sh("stat -c %s /var/log/account/pacct") === "0");
  await page.shot("01-installed.png");
  await close();

  sh("accton /var/log/account/pacct");
  sh("setsid sh -c 'while :; do /usr/local/bin/lh-beacon --secret-arg hunter2; sleep 5; done' </dev/null >/dev/null 2>&1 &");
  await sleep(32_000);
  await open();
  observations.recording = await text("process-watch-sources");
  check("recording: said so, and a visible read button with a window choice appears",
    observations.recording.includes("正在记录，可以直接读取") &&
    await page.evaluate(`${tid("process-watch-accounting-read")}?.tagName === 'BUTTON' && ${tid("process-watch-accounting-window")}?.tagName === 'SELECT'`));
  check("nothing is read until asked", await page.evaluate(`${tid("process-watch-accounting")} === null`));
  await setSelect("process-watch-accounting-window", 5);
  await page.evaluate(`(()=>{const b=${tid("process-watch-accounting-read")};b.click();b.click();})()`);
  await uiWait(`${tid("process-watch-accounting")} !== null`, "accounting result", 60000);
  const result = await text("process-watch-accounting");
  observations.result = result.slice(0, 1500);
  check("the result states what accounting cannot show", result.includes("最近 5 分钟") && result.includes("只有程序名，没有参数") && result.includes("还在运行的进程要等结束才会出现"));
  const beaconRow = await page.evaluate(`[...document.querySelectorAll('[data-testid=process-watch-accounting-row]')].map(r=>[...r.cells].map(c=>c.textContent)).find(c=>c[0]==='lh-beacon') ?? null`);
  const independent = Number(sh("lastcomm lh-beacon 2>/dev/null | wc -l"));
  observations.beaconRow = beaconRow; observations.independentBeaconCount = independent;
  check(`the beacon row matches the target's own lastcomm (row ${beaconRow?.[1]}, lastcomm ${independent})`,
    beaconRow !== null && Number(beaconRow[1]) >= 5 && independent - Number(beaconRow[1]) >= 0 && independent - Number(beaconRow[1]) <= 2);
  check("the beacon is shown with an interval and as periodic", beaconRow[5] !== "—" && beaconRow[6] === "周期性");
  observations.beaconCadence = beaconRow[6];
  check("no argument is on the page", !(await text("process-watch-dialog")).includes("hunter2"));
  check("reading did not start a watch", watchers().length === 0 && await page.evaluate(`${tid("process-watch-start")} !== null`));
  check("the read button and window are real controls reachable by Tab",
    await page.evaluate(`[${tid("process-watch-accounting-read")}, ${tid("process-watch-accounting-window")}].every(e => e.tabIndex >= 0 && !e.disabled)`));
  check("the table stays inside the dialog at 1280x800",
    await page.evaluate(`(()=>{const d=${tid("process-watch-dialog")}.getBoundingClientRect();const t=${tid("process-watch-accounting")}.getBoundingClientRect();return t.left>=d.left-1&&t.right<=d.right+1;})()`));
  await page.shot("02-accounting.png");
  await close();
  check("focus returns to the entry button", await page.evaluate(`document.activeElement === ${tid("process-watch-open")}`));
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
    "ui/src/renderer/process-watch-state.ts", "tools/lab/probe-ui-process-watch-sources.mjs", "crates/lovelyhawk-core/src/process_watch_sources.rs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP", "one debian:12-slim container with CAP_SYS_PACCT added: accounting records only this container's processes", "unreadable-for-this-account state is driven by the backend probe only"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
