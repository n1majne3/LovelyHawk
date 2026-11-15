// Deletes one public key out of root's authorized_keys through the real
// window, on a disposable Podman SSH target it creates itself.
//
// What has to hold on a real machine:
//   * an SSH-key row offers "ssh-key.delete"; the plan names the line, the
//     OpenSSH fingerprint and how many usable keys remain, and is dangerous;
//   * exactly the selected line leaves the file — every other byte, the 600
//     mode and the root owner stay; a restorable copy sits in
//     .lovelyres-backups;
//   * a login with a surviving key still works, and the removed key no
//     longer does;
//   * restoring the backup puts the original bytes back exactly;
//   * deleting the last usable key in root's file is refused, not executed.
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
const runId = randomUUID(), name = `lr-sshkey-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-ssh-key-delete", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-sshkey-"));
const KEYS_FILE = "/root/.ssh/authorized_keys";
const checks = [];
let containerId, imageId, sidecar, app, forwarder, failure;
fs.mkdirSync(evidence, { recursive: true });

// exec output is trimmed, so byte comparisons against remote files compare
// the trimmed form throughout — the exact-bytes check lives in the sha256.
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
    throw new Error("owned ssh-key fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const onHostText = command => onHost("sh", "-c", command);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

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

const sha256hex = bytes => createHash("sha256").update(bytes).digest("hex");
const remoteSha = file => onHostText(`sha256sum ${file}`).split(/\s+/u)[0];

const dialogText = session => session.evaluate(
  `document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? ""`);

// Logs in with a key file over the forwarded port; publickey only, so a
// password fallback can never make a dead key look alive.
function keyLogin(keyFile, marker) {
  return execFileSync("ssh.exe", [
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
    "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
    "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
    "-i", keyFile, "-p", String(localPort), "root@127.0.0.1", "echo", marker,
  ], { encoding: "utf8", windowsHide: true, timeout: 30_000 }).trim();
}

let localPort;
try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("ssh-key fixture is an owned, unprivileged container without host mounts", Boolean(owned()));

  // Three keys: an options-prefixed one first (the kind a competition box
  // carries), a plain middle one to delete, and a plain one that must keep
  // logging root in. The login check needs the private halves on Windows.
  const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), "lr-sshkey-"));
  const lineOf = index => {
    execFileSync("ssh-keygen.exe", ["-t", "ed25519", "-N", "", "-C", `probe-${index}`,
      "-f", path.join(keyDir, `k${index}`)], { windowsHide: true, stdio: "ignore" });
    return fs.readFileSync(path.join(keyDir, `k${index}.pub`), "utf8").trim().split(/\s+/u).slice(0, 2).join(" ");
  };
  const [pub1, pub2, pub3] = [lineOf(1), lineOf(2), lineOf(3)];
  const authorized = [
    `command="echo a b",no-pty ${pub1} probe-first`,
    `${pub2} probe-middle`,
    `${pub3} probe-last`,
  ].join("\n") + "\n";
  const planted = path.join(keyDir, "authorized_keys");
  fs.writeFileSync(planted, authorized);
  onHostText("mkdir -p /root/.ssh && chmod 700 /root/.ssh");
  podman("cp", planted, `${containerId}:${KEYS_FILE}`);
  onHostText(`chmod 600 ${KEYS_FILE} && chown root:root ${KEYS_FILE}`);
  check("the fixture carries three keys, mode 600 root:root",
    onHostText(`stat -c '%a %U' ${KEYS_FILE}`) === "600 root" && onHostText(`wc -l < ${KEYS_FILE}`) === "3");

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
  check("the middle key logs root in before the delete", keyLogin(path.join(keyDir, "k2"), "alive") === "alive");

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
  check("the SSH keys tab exists", await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === 'SSH 密钥');
    if (button === undefined) return false;
    if (button.getAttribute('aria-pressed') !== 'true') button.click();
    return true;
  })()`));
  await waitFor(session,
    `[...document.querySelectorAll('.system-info-table-scroll tbody tr')].some(row => row.textContent.includes('probe-middle'))`,
    "the middle key row", 240);
  await session.shot("ssh-keys-table");

  check("the middle row can be right-clicked", await contextMenuOnRow(session, "probe-middle"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu actions");
  const menuText = await session.evaluate(
    `document.querySelector('.system-info-row-menu')?.textContent ?? ""`);
  check("the menu offers 删除此公钥", menuText.includes("删除此公钥"));
  await session.shot("ssh-key-menu");
  check("the delete item clicks", await clickMenuItem(session, "删除此公钥"));

  await waitFor(session,
    "document.querySelector('[data-testid=\"system-info-row-action-execute\"]:not([disabled])') !== null",
    "the plan", 120);
  const planText = await dialogText(session);
  check("the plan names the fingerprint", planText.includes("SHA256:"));
  check("the plan names the line and the count that stays", planText.includes("第 2 行") && planText.includes("还剩 2 条"));
  check("the plan warns the session key cannot be told apart", planText.includes("指纹"));
  await session.shot("ssh-key-delete-plan");

  await session.evaluate("document.querySelector('[data-testid=\"system-info-row-action-execute\"]').click(), true");
  await waitFor(session,
    "document.querySelector('[data-testid=\"system-info-row-action-dialog\"]')?.textContent.includes('目标机反馈') === true",
    "the receipt", 120);
  const receiptText = await dialogText(session);
  await session.shot("ssh-key-delete-receipt");
  check("the delete verified on target", receiptText.includes("已完成，并在目标机上核对过"));

  // ---- independent read-back -------------------------------------------
  const expectedAfter = [`command="echo a b",no-pty ${pub1} probe-first`, `${pub3} probe-last`].join("\n") + "\n";
  check("exactly the middle line left the file",
    remoteSha(KEYS_FILE) === sha256hex(expectedAfter));
  check("mode and owner survived the rewrite", onHostText(`stat -c '%a %U' ${KEYS_FILE}`) === "600 root");
  const backup = onHostText(`find /root/.ssh/.lovelyres-backups -type f 2>/dev/null | head -1`);
  check("a restorable copy was kept", backup.length > 0);
  check("the backup is byte-identical to the file that was collected",
    remoteSha(backup) === sha256hex(authorized));
  check("login with the surviving key still works", keyLogin(path.join(keyDir, "k3"), "alive") === "alive");
  let removedLogin = "unexpected";
  try { removedLogin = keyLogin(path.join(keyDir, "k2"), "alive"); } catch { removedLogin = "refused"; }
  check("the removed key no longer logs in", removedLogin === "refused");

  // ---- the backup puts the file back exactly ----------------------------
  onHostText(`cp -p ${backup} ${KEYS_FILE}`);
  check("restoring the backup returns the original bytes", remoteSha(KEYS_FILE) === sha256hex(authorized));
  check("the restored key logs in again", keyLogin(path.join(keyDir, "k2"), "alive") === "alive");

  // ---- the last root key is refused --------------------------------------
  const single = path.join(keyDir, "authorized_keys.single");
  fs.writeFileSync(single, `${pub1} probe-only\n`);
  podman("cp", single, `${containerId}:${KEYS_FILE}`);
  onHostText(`chmod 600 ${KEYS_FILE} && chown root:root ${KEYS_FILE}`);
  await session.evaluate(`(() => {
    [...document.querySelectorAll('[data-testid="system-info-row-action-dialog"] header button')]
      .find(button => button.textContent.includes('关闭'))?.click();
    return true;
  })()`);
  await session.evaluate(`(() => {
    const button = [...document.querySelectorAll('.system-info-tabs button')]
      .find(candidate => candidate.textContent.trim() === 'SSH 密钥');
    button?.click();
    return true;
  })()`);
  await waitFor(session,
    `document.querySelectorAll('.system-info-table-scroll tbody tr').length === 1`,
    "the single-key table", 240);
  check("the only-key row can be right-clicked", await contextMenuOnRow(session, "probe-only"));
  await waitFor(session, "document.querySelector('.system-info-row-menu-parent') !== null", "the menu again");
  check("the delete item clicks again", await clickMenuItem(session, "删除此公钥"));
  try {
    await waitFor(session,
      `(document.querySelector('[data-testid="system-info-row-action-dialog"]')?.textContent ?? '').includes('仅剩的可用公钥')`,
      "the refusal", 120);
  } catch (error) {
    console.log(`      dialog at timeout: ${JSON.stringify((await dialogText(session)).slice(0, 400))}`);
    await session.shot("ssh-key-last-timeout");
    throw error;
  }
  await session.shot("ssh-key-last-refusal");
  check("the single-key file was left untouched", remoteSha(KEYS_FILE) === sha256hex(`${pub1} probe-only\n`));
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (app) { try { await app.close(); } catch {} }
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned ssh-key fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId,
    sourceHash: createHash("sha256").update(fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/system_info.rs"))).digest("hex").slice(0, 16),
    checks, error: failure ?? null,
    limits: ["debug desktop over CDP; the restore step replays the on-target backup, the same bytes the journal records"],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
