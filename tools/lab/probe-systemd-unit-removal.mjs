// Drives the "移除服务单元" row action on a disposable Podman target that
// really runs systemd (debian:12-slim + systemd + openssh-server, started
// with --systemd=always). A planted lh-beacon.service — local fragment,
// drop-in directory and a multi-user.target.wants link — is removed through
// the desktop UI, independently checked from outside SSH, then put back
// through the receipt's undo, and a package-owned unit is shown to refuse.
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
const runId = randomUUID(), name = `lr-sysd-${runId.slice(0, 8)}`;
const image = "localhost/lh-systemd-sshd:probe";
const evidence = path.join(repository, "target", "lab-systemd-unit-removal", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-sysd-"));
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
    throw new Error("owned systemd fixture identity changed");
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

function ensureImage() {
  try {
    return podman("image", "inspect", image, "--format", "{{.Id}}");
  } catch {}
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lh-systemd-image-"));
  fs.writeFileSync(path.join(dir, "Containerfile"), `FROM docker.m.daocloud.io/library/debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv openssh-server sudo dbus \\
 && apt-get clean && rm -rf /var/lib/apt/lists/* \\
 && echo 'root:LabRoot#2026' | chpasswd \\
 && mkdir -p /run/sshd \\
 && sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \\
 && sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \\
 && systemctl enable ssh
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
`);
  podman("build", "-t", image, dir);
  return podman("image", "inspect", image, "--format", "{{.Id}}");
}

try {
  imageId = ensureImage();
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--systemd=always", "--memory", "1g", "--cpus", "1", "--pids-limit", "256", imageId);
  check("systemd fixture is an owned, unprivileged container without host mounts", Boolean(owned()));

  let systemdState = "";
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try { systemdState = onHostText("systemctl is-system-running 2>/dev/null || true"); } catch {}
    if (["running", "degraded"].includes(systemdState)) break;
    await sleep(1000);
  }
  check("systemd is running inside the container", ["running", "degraded"].includes(systemdState));
  console.log(`      systemctl is-system-running: ${systemdState}`);

  // Plant the malicious-looking unit: local fragment, one drop-in, one
  // enablement link, running main process.
  onHostText(`mkdir -p /etc/systemd/system/lh-beacon.service.d && \
    printf '[Unit]\\nDescription=lh-beacon lab fixture\\n[Service]\\nExecStart=/bin/sleep 3600\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/lh-beacon.service && \
    printf '[Service]\\nEnvironment=LAB_FIXTURE=1\\n' > /etc/systemd/system/lh-beacon.service.d/override.conf && \
    systemctl daemon-reload && systemctl enable --now lh-beacon.service`);
  const mainPid = onHostText("systemctl show -p MainPID --value lh-beacon.service");
  const mainPidStart = onHostText(`awk '{print $22}' /proc/${mainPid}/stat 2>/dev/null || true`);
  const fragmentSha = onHostText("sha256sum /etc/systemd/system/lh-beacon.service | awk '{print $1}'");
  check("the planted unit is loaded, enabled and running",
    mainPid !== "0" && onHostText("systemctl is-enabled lh-beacon.service") === "enabled");

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
  check("the services tab exists", await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === '系统服务');
    if (button === undefined) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`));
  await waitFor(session,
    `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes('lh-beacon.service'))`,
    "the planted service row", 240);
  await session.shot("services-table.png");

  check("the beacon row can be right-clicked", await contextMenuOnRow(session, "lh-beacon.service"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions");
  const menuText = await session.evaluate(
    `document.querySelector('.system-info-row-menu')?.textContent ?? ""`);
  check("the menu offers 移除服务单元", menuText.includes("移除服务单元"));
  await session.shot("service-remove-menu.png");
  check("the removal item clicks", await clickMenuItem(session, "移除服务单元"));

  // The plan dialog must describe the move-out before any confirmation.
  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return text.includes('lh-beacon.service') && text.includes('确认并执行');
    })()`,
    "the removal plan", 120);
  await session.shot("service-remove-plan.png");
  check("the plan dialog clicks through the explicit confirmation", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-action-execute"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));

  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return text.includes('核对过') || text.includes('没有完成') || text.includes('已还原');
    })()`,
    "the removal receipt", 180);
  const receiptText = await dialogText(session);
  await session.shot("service-remove-receipt.png");
  check("the removal verified", receiptText.includes("核对过"));
  console.log(`      receipt excerpt: ${JSON.stringify(receiptText.slice(0, 200))}`);

  check("LoadState reads not-found afterwards",
    onHostText("systemctl show -p LoadState --value lh-beacon.service") === "not-found");
  check("the fragment, drop-in dir and enablement link are all gone",
    onHostText("test ! -e /etc/systemd/system/lh-beacon.service && \
      test ! -d /etc/systemd/system/lh-beacon.service.d && \
      test ! -e /etc/systemd/system/multi-user.target.wants/lh-beacon.service && echo gone") === "gone");
  check("the moved pieces sit in the backup tree with a manifest",
    onHostText("test -f /var/lib/lovelyres-unit-backups/*/manifest.txt && \
      test -f /var/lib/lovelyres-unit-backups/*/fragment/lh-beacon.service && \
      test -f /var/lib/lovelyres-unit-backups/*/dropins/override.conf && echo kept") === "kept");
  check("the recorded main process is gone",
    onHostText(`awk '{print $22}' /proc/${mainPid}/stat 2>/dev/null || true`) !== mainPidStart);
  check("the undo offer is on the receipt", await session.evaluate(
    `document.querySelector('[data-testid="system-info-row-action-undo"]') !== null`));

  check("the undo button clicks", await session.evaluate(`(() => {
    const button = document.querySelector('[data-testid="system-info-row-action-undo"]');
    if (button === null || button.disabled) return false;
    button.click();
    return true;
  })()`));
  try {
    await waitFor(session,
      `document.querySelector('[data-testid="system-info-row-undo-result"]') !== null ||
       document.querySelector('[data-testid="system-info-row-action-dialog"] [role="alert"]') !== null`,
      "the undo result", 120);
  } catch (error) {
    console.log(`      dialog at timeout: ${JSON.stringify((await dialogText(session)).slice(0, 500))}`);
    await session.shot("service-remove-undo-timeout.png");
    throw error;
  }
  await session.shot("service-remove-undo.png");
  const undoText = await session.evaluate(
    `document.querySelector('[data-testid="system-info-row-undo-result"]')?.textContent ?? ''`);
  check("the undo reported the restored unit state", undoText.includes("已恢复"));

  check("the unit is loaded again with the same bytes",
    onHostText("systemctl show -p LoadState --value lh-beacon.service") === "loaded" &&
    onHostText("sha256sum /etc/systemd/system/lh-beacon.service | awk '{print $1}'") === fragmentSha);
  check("the drop-in and the enablement link are back",
    onHostText("test -f /etc/systemd/system/lh-beacon.service.d/override.conf && \
      test -L /etc/systemd/system/multi-user.target.wants/lh-beacon.service && echo back") === "back");
  check("the unit file state is enabled again but the service was not restarted",
    onHostText("systemctl show -p UnitFileState --value lh-beacon.service") === "enabled" &&
    onHostText("systemctl show -p MainPID --value lh-beacon.service") === "0");

  // A package unit under /lib must refuse at the plan stage, before anything
  // is staged or moved.
  await session.evaluate(`(() => {
    document.querySelector('[data-testid="system-info-row-action-dialog"] button')?.click();
    return true;
  })()`);
  await sleep(1000);
  check("the ssh.service row can be right-clicked", await contextMenuOnRow(session, "ssh.service"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions again");
  check("the removal item clicks for a package unit", await clickMenuItem(session, "移除服务单元"));
  await waitFor(session,
    `(() => {
      const text = document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '';
      return ['软件包或运行时位置', '软件包', '禁用或屏蔽', '没有可移除', '拒绝'].some(fragment => text.includes(fragment));
    })()`,
    "the package-unit refusal", 120);
  const refusalText = await dialogText(session);
  await session.shot("service-remove-package-refusal.png");
  check("the refusal text is shown", refusalText.length > 0);
  console.log(`      refusal excerpt: ${JSON.stringify(refusalText.slice(0, 200))}`);
  check("ssh.service was not touched",
    onHostText("systemctl is-active ssh.service") === "active" &&
    onHostText("test -f /lib/systemd/system/ssh.service && echo kept") === "kept");
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (app) { try { await app.close(); } catch {} }
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned systemd fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId,
    sourceHash: createHash("sha256").update(fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/systemd_unit_removal.rs"))).digest("hex").slice(0, 16),
    checks, error: failure ?? null,
    limits: [
      "Podman systemd runs one container init: host-level units and real boot ordering are not exercised",
      "the ExecStart program (/bin/sleep) staying behind is asserted absent only as a process, its file is out of scope by design",
    ],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
