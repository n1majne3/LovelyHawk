// Desktop UI firewall block through the debug build and CDP.
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
const runId = randomUUID(), name = `lr-fwui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `firewall-block-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-fwui-"));
const proxy = process.env.LAB_REGISTRY_PROXY || "http://192.168.6.4:7890";
const blocked = "203.0.113.7";
const checks = [], observations = {};
let containerId, imageId, platform, sidecar, failure, forwarder, app;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind" || m.Destination !== "/var/lib/postgresql/data"))
    throw new Error("Owned firewall fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label, ms = 90000) { const end = Date.now() + ms; while (Date.now() < end) { try { if (await fn()) return; } catch {} await sleep(150); } throw new Error(`Timed out: ${label}`); }
const taggedRules = () => onHost("sh", "-c", "iptables -S INPUT 2>/dev/null | grep -c lovelyhawk-block- || true");

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "--cap-add", "NET_ADMIN", "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=/usr/local/bin/docker-entrypoint.sh postgres", imageId);
  check("firewall fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", `export http_proxy=${proxy} https_proxy=${proxy}; apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends iptables iproute2 >/dev/null 2>&1; command -v iptables`);
  platform = onHost("sh", "-c", "cat /etc/os-release | head -n 2; uname -m; iptables -V");
  check("iptables works inside the fixture", onHost("sh", "-c", "iptables -S INPUT >/dev/null && echo ok") === "ok");

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
  const dialogText = () => page.evaluate("document.querySelector('[data-testid=firewall-block-dialog]')?.textContent ?? ''");
  const setAddress = value => page.evaluate(`(()=>{const el=document.querySelector('[data-testid=firewall-block-dialog] input:not([type=radio])');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,${JSON.stringify(value)});el.dispatchEvent(new Event('input',{bubbles:true}));})()`);
  const setDirection = value => page.evaluate(`document.querySelector('[data-testid=firewall-block-dialog] input[type=radio][value=${value}]').click()`);

  await uiWait("document.querySelector('.connection-card') !== null", "saved SSH card");
  await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.textContent.includes(${JSON.stringify(name)})).querySelector('button').click()`);
  await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
  await click(".nav-item", "主机全景");
  await uiWait("document.querySelector('.system-info-tabs') !== null", "system info page");
  await click(".system-info-tabs button", "防火墙");
  await uiWait("[...document.querySelectorAll('.system-info-panel-actions button')].some(b=>b.textContent.includes('封禁地址'))", "firewall toolbar button");

  // Block, verify independently, undo.
  await click(".system-info-panel-actions button", "封禁地址");
  await uiWait("document.querySelector('[data-testid=firewall-block-dialog]') !== null", "dialog open");
  check("address field gets initial focus", await page.evaluate("document.activeElement === document.querySelector('[data-testid=firewall-block-dialog] input:not([type=radio])')"));
  await setAddress(blocked); await setDirection("inbound");
  await click("[data-testid=firewall-block-dialog] button", "检查并生成计划");
  await uiWait("(document.querySelector('[data-testid=firewall-block-dialog]')?.textContent ?? '').includes('确认封禁')", "confirm step", 45000);
  const confirmText = await dialogText();
  observations.confirm = confirmText;
  check("confirm names iptables, the tagged rule and the runtime-only limit",
    confirmText.includes("iptables") && confirmText.includes("lovelyhawk-block-") && confirmText.includes("重启"));
  check("confirm puts focus on 取消", await page.evaluate("document.activeElement?.textContent === '取消'"));
  await page.shot("01-confirm.png");
  check("no rule exists before confirming", taggedRules() === "0");
  await click("[data-testid=firewall-block-dialog] button", "确认封禁");
  await uiWait("(document.querySelector('[data-testid=firewall-block-dialog]')?.textContent ?? '').includes('回读确认规则存在')", "block verified", 60000);
  await page.shot("02-blocked.png");
  check("independent iptables read shows exactly one tagged rule for the address",
    taggedRules() === "1" && onHost("sh", "-c", "iptables -S INPUT").includes(blocked));
  await click("[data-testid=firewall-block-dialog] button", "撤销封禁");
  await uiWait("(document.querySelector('[data-testid=firewall-block-dialog]')?.textContent ?? '').includes('确认撤销封禁')", "undo confirm");
  await click("[data-testid=firewall-block-dialog] button", "确认撤销封禁");
  try {
    await uiWait("(document.querySelector('[data-testid=firewall-block-dialog]')?.textContent ?? '').includes('不再存在')", "undo verified", 60000);
  } catch (error) {
    observations.undoDialog = await dialogText();
    observations.undoRules = onHost("sh", "-c", "iptables -S INPUT");
    await page.shot("03-undo-failed.png");
    throw error;
  }
  await page.shot("03-undone.png");
  check("independent iptables read shows the tagged rule removed", taggedRules() === "0");
  await click("[data-testid=firewall-block-dialog] button", "关闭");
  await uiWait("document.querySelector('[data-testid=firewall-block-dialog]') === null", "dialog closed");

  // Self-lockout: the SSH client address as the container sees it.
  const peer = onHost("sh", "-c", "ss -Htn state established '( sport = :22 )' | awk '{print $4}' | sed 's/:[0-9]*$//; s/^\\[//; s/\\]$//' | sed 's/^::ffff://' | head -n 1");
  observations.sshPeer = peer;
  check("the container sees an SSH client address", /^[0-9a-f.:]+$/iu.test(peer));
  await click(".system-info-panel-actions button", "封禁地址");
  await uiWait("document.querySelector('[data-testid=firewall-block-dialog]') !== null", "dialog reopened");
  await setAddress(peer); await setDirection("inbound");
  await click("[data-testid=firewall-block-dialog] button", "检查并生成计划");
  await uiWait("(document.querySelector('[data-testid=firewall-block-dialog] [role=alert]')?.textContent ?? '').length > 0", "refusal shown", 45000);
  const refusal = await dialogText();
  observations.refusal = refusal;
  await page.shot("04-self-lockout.png");
  check("blocking the SSH client inbound is refused in plain Chinese", refusal.includes("这是当前 SSH 连接的来源地址"));
  check("the refusal added no rule", taggedRules() === "0");
  await page.evaluate("window.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))");
  await uiWait("document.querySelector('[data-testid=firewall-block-dialog]') === null", "Escape closed");
  check("Escape closes the dialog at the input step", true);

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
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned firewall fixture removed", passed: true }); } catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  try {
    const logFile = path.join(dataRoot, "data", "logs", "lovelyhawk.log");
    if (fs.existsSync(logFile)) fs.copyFileSync(logFile, path.join(evidence, "lovelyhawk.log"));
  } catch {}
  try { fs.rmSync(dataRoot, { recursive: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  const sourceHashes = Object.fromEntries([
    "crates/lovelyhawk-core/src/firewall_block.rs", "crates/lovelyhawk-backend/src/system_info_action_api.rs",
    "ui/src/shared/system-info-contract.ts", "ui/src/renderer/FirewallBlockDialog.tsx", "ui/src/renderer/SystemInfoPage.tsx",
    "tools/lab/probe-ui-firewall-block.mjs",
  ].map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex")]));
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), imageId, platform, sourceHashes, observations, checks, error: failure ?? null,
    limits: ["debug desktop build driven over CDP", "iptables (nf_tables backend) in one Debian container; firewalld, ufw and nftables-only paths not driven here"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
}
