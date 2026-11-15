// Exports a finished live capture through the real window, on a disposable
// Podman SSH target it creates itself.
//
//   * 停止抓包 leaves the raw file on the target and the page offers
//     导出为 pcap… and 丢弃原始包;
//   * the folder dialog is answered by the test hook, the evidence job lands
//     completed, and the SHA-256 the page shows is the local capture.pcap's;
//   * 离线分析这份抓包 opens the traffic-analysis page on that same file;
//   * a second capture's 丢弃原始包 removes the remote artifacts;
//   * the whole flow also runs as a non-root user whose only privilege is
//     passwordless sudo — the writer is sudo tcpdump, the file is tee's, so
//     the export still works.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startDesktop } from "./desktop.mjs";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-pcapui-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-pcap-export-desktop", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pcapui-"));
const exportDir = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pcapui-dest-"));
const checks = [];
let containerId, imageId, sidecar, app, forwarder, failure, localPort;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 600_000, maxBuffer: 8 * 1024 * 1024 }).trim();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  if ((target.Name === name || target.Name === `/${name}`) &&
    target.Config?.Labels?.["lovelyres-test-run"] === runId && target.Image === imageId) return target;
  throw new Error("The export fixture's identity changed");
}
const onHost = (command) => { owned(); return podman("exec", containerId, "sh", "-c", command); };
function check(label, passed, note = "") {
  checks.push({ label, passed: Boolean(passed), note });
  console.log(`  ${passed ? "PASS" : "FAIL"} ${label}${note ? ` — ${String(note).slice(0, 200)}` : ""}`);
  if (!passed && !failure) failure = label;
}
const evaluate = (expression) => app.session.evaluate(expression);
async function until(predicate, label, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if (await predicate()) return true; } catch {}
    await sleep(300);
  }
  throw new Error(`Timed out: ${label}`);
}
const uiWait = (expression, label, timeoutMs = 90_000) =>
  until(async () => (await evaluate(expression)) === true, label, timeoutMs);
const clickButton = (text, scope = "button") => evaluate(`(() => {
  const b = [...document.querySelectorAll('${scope}')].find((x) => x.textContent.trim() === ${JSON.stringify(text)});
  if (!b || b.disabled) return false; b.click(); return true;
})()`);
const clickInterface = () => evaluate(`(() => {
  const b = [...document.querySelectorAll('.packet-capture-interface-list button')].find((x) => x.textContent.includes('eth0'));
  if (!b) return false; b.click(); return true;
})()`);
const status = () => evaluate("document.querySelector('.packet-capture-status')?.textContent ?? ''");
const managedFiles = () => onHost("ls /tmp/lovelyres-pcap-* 2>/dev/null | wc -l");
const navigate = (title) => evaluate(`[...document.querySelectorAll('.nav-item')].find((item) => item.textContent.includes(${JSON.stringify(title)}))?.click(), true`);

async function runCaptureExport(label) {
  await uiWait("[...document.querySelectorAll('.packet-capture-interface-list button')].some((b) => b.textContent.includes('eth0'))", `${label}: interfaces`);
  await clickInterface();
  await evaluate(`(() => {
    const inputs = [...document.querySelectorAll('.packet-capture-form input')];
    for (const [index, value] of [[1, "40"], [2, "120"]]) {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(inputs[index], value);
      inputs[index].dispatchEvent(new Event('input', { bubbles: true }));
    }
    return true;
  })()`);
  check(`${label}: start begins the capture`, await clickButton("开始抓包", ".packet-capture-actions button"));
  await until(async () => (await status()).includes("正在采集"), `${label}: capture running`);
  // Polls ride the same interface the capture watches; a few seconds is
  // enough packets on an idle fixture.
  await sleep(4_000);
  check(`${label}: stop ends the capture`, await clickButton("停止抓包", ".packet-capture-actions button"));
  await until(async () => (await status()).includes("已停止"), `${label}: capture stopped`);
  check(`${label}: raw file waits on the target`, managedFiles() === "1");
  check(`${label}: export and discard are offered`,
    await evaluate("[...document.querySelectorAll('.packet-capture-raw-actions button')].map((b) => b.textContent.trim()).join(',') === '导出为 pcap…,丢弃原始包'"));

  app.setDialogAnswers([exportDir]);
  check(`${label}: 导出为 pcap… starts the job`, await clickButton("导出为 pcap…", ".packet-capture-raw-actions button"));
  await until(async () => ["completed", "saved-unlinked", "failed"].includes(
    await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-result\"]')?.dataset.state ?? ''")),
    `${label}: export to settle`, 120_000);
  const state = await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-result\"]')?.dataset.state ?? ''");
  check(`${label}: the export completes`, state === "completed",
    await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-result\"]')?.textContent?.slice(0, 300) ?? ''"));
  const shownSha = await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-sha256\"]')?.textContent ?? ''");
  const folderName = await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence\"] dd code')?.textContent ?? ''");
  const temporary = await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-temporary\"]')?.textContent ?? ''");
  check(`${label}: remote artifacts are gone after a verified export`, managedFiles() === "0" && temporary === "已删除");
  const pcapFile = path.join(exportDir, folderName, "capture.pcap");
  const localSha = fs.existsSync(pcapFile)
    ? createHash("sha256").update(fs.readFileSync(pcapFile)).digest("hex") : "";
  check(`${label}: shown SHA-256 is the local capture.pcap's`, shownSha.length === 64 && localSha === shownSha, `${shownSha} vs ${localSha}`);
  await app.session.shot(`${label}-exported.png`);
  return { shownSha, folderName };
}

try {
  imageId = podman("image", "inspect", "localhost/lr-apt-test:latest", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", imageId, "sleep", "3600");
  owned();
  // sudo so the non-root pass exercises the `sudo -n tcpdump` writer branch.
  onHost("apt-get update >/dev/null && apt-get install -y tcpdump iproute2 sudo >/dev/null");
  onHost("echo 'root:LabRoot#2026' | chpasswd && useradd -m probe && echo 'probe:Probe#2026' | chpasswd && " +
    "echo 'probe ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/probe && mkdir -p /run/sshd && " +
    "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/;s/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && /usr/sbin/sshd");
  check("fixture carries tcpdump, sshd and a sudo-only user",
    onHost("command -v tcpdump").endsWith("tcpdump") && onHost("sudo -n -u probe sudo -n true && echo ok") === "ok");

  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  localPort = await new Promise((resolve) => {
    const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
    "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
    "-L", `127.0.0.1:${localPort}:${owned().NetworkSettings.IPAddress}:22`, "root@127.0.0.1"],
    { windowsHide: true, stdio: "ignore" });
  await sleep(1_500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");

  // Both connection cards into the same data root, then the real window.
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  for (const [id, username, password, card] of [
    ["44444444-4444-4444-8444-444444444401", "root", "LabRoot#2026", `${name}-root`],
    ["44444444-4444-4444-8444-444444444402", "probe", "Probe#2026", `${name}-probe`],
  ]) {
    const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username, password, id, name: card });
    if (status?.stage !== "connected") throw new Error(`fixture connect failed for ${username}`);
  }
  sidecar.close(); sidecar = null;
  check("both connections recorded", true);

  const consoleErrors = [];
  app = await startDesktop({ dataRoot, evidence, dialogAnswers: [],
    onConsoleError: (event) => consoleErrors.push(JSON.stringify(event.params ?? event).slice(0, 400)) });
  await uiWait("[...document.querySelectorAll('.connection-card')].length >= 1", "the connection cards");
  await uiWait(`(() => {
    const card = [...document.querySelectorAll('.connection-card')].find((c) => c.textContent.includes('${name}-root'));
    if (!card) return false;
    card.querySelector('button')?.click(); return true;
  })()`, "the root connection card", 30_000);
  await uiWait("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null", "the root connection", 120_000);
  check("the first pass really runs as root",
    await evaluate("document.body.textContent.includes('root@')"));
  await navigate("网络抓包");

  // Root pass: export, check the file, open it in the offline analyzer.
  const root = await runCaptureExport("root");
  check("offline analysis is offered on the saved capture",
    await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-analyze-offline\"]') !== null"));
  await evaluate("document.querySelector('[data-testid=\"packet-capture-evidence-analyze-offline\"]').click(), true");
  await uiWait("document.querySelector('[data-testid=\"traffic-analysis-page\"]') !== null", "the traffic-analysis page");
  await uiWait("document.querySelector('[data-testid=\"pcap-tab-summary\"]') !== null || document.querySelector('[data-testid=\"pcap-failed\"]') !== null", "the offline result", 120_000);
  check("the offline analyzer loads the exported file",
    await evaluate("document.querySelector('[data-testid=\"pcap-tab-summary\"]') !== null"),
    await evaluate("document.querySelector('[data-testid=\"pcap-failed\"]')?.textContent?.slice(0, 200) ?? ''"));
  await app.session.shot("root-offline.png");

  // Second capture on the same binding: discard removes the remote artifacts.
  await navigate("网络抓包");
  await uiWait("[...document.querySelectorAll('.packet-capture-interface-list button')].some((b) => b.textContent.includes('eth0'))", "interfaces for the discard run");
  await clickInterface();
  check("the discard run's capture starts", await clickButton("开始抓包", ".packet-capture-actions button"));
  await until(async () => (await status()).includes("正在采集"), "the discard run to run");
  await sleep(2_000);
  await clickButton("停止抓包", ".packet-capture-actions button");
  await until(async () => (await status()).includes("已停止"), "the discard run to stop");
  check("丢弃原始包 removes the remote artifacts",
    await clickButton("丢弃原始包", ".packet-capture-raw-actions button") &&
    await until(async () => managedFiles() === "0" &&
      (await evaluate("document.querySelector('.packet-capture-raw') === null")), "the discard to settle", 30_000)
      .then(() => true).catch(() => managedFiles() === "0" && evaluate("document.querySelector('.packet-capture-raw') === null")));
  await app.session.shot("discarded.png");

  // Probe pass: same flow as a sudo-only user.
  await evaluate("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]')?.click(), true");
  // The disconnected page offers the recent connections as chips by name.
  await uiWait(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.includes('${name}-probe')); if (!b) return false; b.click(); return true; })()`, "the probe connection chip", 30_000);
  await uiWait("document.querySelector('[data-testid=\"sidebar-disconnect-target\"]') !== null", "the probe connection", 120_000);
  check("the second pass really runs as the sudo-only user",
    await evaluate("document.body.textContent.includes('probe@')"));
  await navigate("网络抓包");
  await runCaptureExport("probe");
  check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2));
} catch (error) {
  failure = failure ?? `probe error: ${error.message}`;
  console.log(`\nFAILED: ${error.message}`);
  try { await app?.session?.shot("failure.png"); } catch {}
} finally {
  try { await app?.close(); } catch {}
  try { sidecar?.close(); } catch {}
  try { forwarder?.kill(); } catch {}
  try { if (containerId) { owned(); podman("rm", "-f", containerId); console.log("  fixture container removed"); } } catch {}
}
const failedChecks = checks.filter((entry) => !entry.passed);
fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, checks, failedChecks }, null, 2));
console.log(`\n${failedChecks.length === 0 && !failure ? "ALL CHECKS PASSED" : "CHECKS FAILED"} (${checks.length - failedChecks.length}/${checks.length})`);
process.exitCode = failedChecks.length === 0 && !failure ? 0 : 1;
