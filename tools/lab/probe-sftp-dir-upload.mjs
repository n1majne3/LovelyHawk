// Whole-directory upload on a real target: the host packs a picked local
// folder into a tar (the packer itself is covered by core tests — the probe
// feeds the same RPC boundary a staged archive crosses), the archive goes
// through UploadStaged + remote extract, and the extracted tree is undoable
// through the ExtractedDirectory recovery token.
//   1. a nested folder uploads and the remote bytes match;
//   2. undo removes the extracted tree after re-verifying it;
//   3. a destination that already exists is refused before any write;
//   4. an over-cap archive is refused before upload;
//   5. a Dropbear/no-SFTP target is refused with the degraded message.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-dir-ul-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-dir-upload", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-dirul-"));
const localRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-local-"));
const checks = [];
let containerId, degradedId, sidecar, failure;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const podman = (...args) => execFileSync("podman", [...args], { encoding: "utf8", windowsHide: true, timeout: 420_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const wslVm = (...args) => execFileSync("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000 }).replace(/\0/gu, "").trim();
function owned(id, label) {
  const current = JSON.parse(podman("inspect", id))[0];
  if (current.Id !== id || ![label, `/${label}`].includes(current.Name) ||
    current.HostConfig.Privileged || (current.Mounts ?? []).length !== 0) throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(containerId, name); return podman("exec", containerId, ...args); };
const onDegraded = (...args) => { owned(degradedId, `${name}-nosftp`); return podman("exec", degradedId, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { const hit = await fn(); if (hit) return hit; await sleep(100); } throw new Error(`Timed out: ${label}`); }
function buildTar(folderName, files) {
  const root = path.join(localRoot, `${folderName}-root`);
  fs.mkdirSync(path.join(root, folderName), { recursive: true });
  for (const [member, content] of Object.entries(files)) {
    const file = path.join(root, folderName, member);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  }
  const tar = path.join(localRoot, `${folderName}.tar`);
  // Members are relative: the remote extraction creates <cwd>/<name> itself.
  // bsdtar reads `D:` as a remote host; --force-local keeps it a file.
  const members = fs.readdirSync(path.join(root, folderName));
  execFileSync("tar", ["--force-local", "-cf", tar, "-C", path.join(root, folderName), ...members]);
  return tar;
}

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const sshPort = 2227;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(containerId, name);
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client openssh-sftp-server netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);
  onHost("sh", "-c", "mkdir -p /opt/dest && mkdir -p /opt/dest/taken && printf 'existing\n' > /opt/dest/taken/old.txt");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to the SFTP fixture", true);

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding });
  check("browser opens with a real SFTP subsystem", browser.degradedSftp === false);
  const optDir = (browser.entries ?? []).find((e) => e.name === "opt" && e.kind === "directory");
  const optList = await sidecar.call("sftp-browser.directory.list",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: optDir.entryHandle });
  const dest = (optList.entries ?? []).find((e) => e.name === "dest");
  check("the destination directory is listed", Boolean(dest));

  const stage = async (tar, folderName) => sidecar.call("sftp-browser.upload-directory.stage",
    { bindingHandle: binding, browserHandle: browser.browserHandle, localPath: tar, name: folderName });
  const run = (stagedHandle) => sidecar.call("sftp-browser.upload-directory",
    { bindingHandle: binding, browserHandle: browser.browserHandle, directoryHandle: dest.entryHandle, stagedHandle });

  // 1. A nested folder uploads; remote bytes match byte for byte.
  const tar = buildTar("site", {
    "index.html": "<h1>ok</h1>",
    "sub/deep.txt": "nested content\n",
    "sub/more/even.bin": Buffer.from([7, 7, 7, 7]),
  });
  const staged = await stage(tar, "site");
  check("packing stages the archive", typeof staged.stagedHandle === "string" && staged.name === "site");
  const first = await run(staged.stagedHandle);
  check("directory upload completes", first.state === "done");
  check("a verified upload is undoable", first.undoable === true && typeof first.planHandle === "string");
  check("the receipt states the temp cleanup", String(first.detail).includes("临时包"));
  check("nested remote bytes match",
    onHost("sh", "-c", "cat /opt/dest/site/sub/deep.txt") === "nested content" &&
    onHost("sh", "-c", "cat /opt/dest/site/index.html") === "<h1>ok</h1>" &&
    onHost("sh", "-c", "wc -c < /opt/dest/site/sub/more/even.bin") === "4" &&
    onHost("sh", "-c", "sha256sum /opt/dest/site/sub/deep.txt | awk '{print $1}'") ===
      execFileSync("certutil", ["-hashfile", path.join(localRoot, "site-root/site/sub/deep.txt"), "SHA256"], { encoding: "utf8" }).split("\n")[1]?.trim().toLowerCase());
  check("no remote temp archive is left behind",
    onHost("sh", "-c", "ls /opt/dest/.lovelyhawk-upload-*.tar 2>/dev/null | wc -l") === "0");

  // 2. Undo removes the extracted tree after the target re-verifies it.
  const undone = await sidecar.call("sftp-browser.operation.undo",
    { bindingHandle: binding, planHandle: first.planHandle });
  check("undo removes the extracted tree", undone.undone === true);
  check("the destination is gone after undo",
    onHost("sh", "-c", "test -e /opt/dest/site && echo still-there || echo gone") === "gone");

  // 3. A destination that already exists is refused before any write.
  const takenTar = buildTar("taken", { "fresh.txt": "new content\n" });
  const takenStaged = await stage(takenTar, "taken");
  const refused = await run(takenStaged.stagedHandle);
  check("an existing destination is refused", refused.state === "refused-destination");
  check("the refusal says nothing was written",
    String(refused.detail).includes("已存在") && refused.undoable === false);
  check("the existing directory is untouched",
    onHost("sh", "-c", "cat /opt/dest/taken/old.txt") === "existing" &&
    onHost("sh", "-c", "test -e /opt/dest/taken/fresh.txt && echo wrote || echo untouched") === "untouched");
  check("the refused upload leaves no remote temp",
    onHost("sh", "-c", "ls /opt/dest/.lovelyhawk-upload-*.tar 2>/dev/null | wc -l") === "0");
  check("a staged handle is single use",
    await run(takenStaged.stagedHandle).then(() => "accepted", (error) => String(error?.message ?? error))
      .then((text) => text.length > 0 && text !== "accepted"));

  // 4. An over-cap archive is refused at staging, before anything remote.
  const overCap = path.join(localRoot, "toobig.tar");
  const fd = fs.openSync(overCap, "w");
  fs.ftruncateSync(fd, 1100 * 1024 * 1024); // sparse; the metadata cap refuses it
  fs.closeSync(fd);
  const overCapStage = await stage(overCap, "toobig").then(
    () => "accepted", (error) => String(error?.message ?? error));
  check("an over-cap archive is refused before upload",
    overCapStage.includes("capacity") || overCapStage.includes("sftp-browser-capacity"));

  // 5. A no-SFTP target refuses the operation with the degraded message.
  const degradedPort = 2228;
  degradedId = podman("run", "-d", "--name", `${name}-nosftp`, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(degradedId, `${name}-nosftp`);
  onDegraded("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onDegraded("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onDegraded("sh", "-c", `dropbear -E -p ${degradedPort}`);
  await until(() => { try { onDegraded("nc", "-z", "127.0.0.1", String(degradedPort)); return true; } catch { return false; } }, "degraded dropbear listening", 30_000);
  const secondConnect = await connect(sidecar, { host, port: degradedPort, username: "root", password: "LabRoot#2026", id: `${runId}-d`, name: `${name}-nosftp` });
  if (secondConnect.stage !== "connected") throw new Error(JSON.stringify(secondConnect));
  const degradedBrowser = await sidecar.call("sftp-browser.open", { bindingHandle: secondConnect.bindingHandle });
  check("the second browser opens degraded", degradedBrowser.degradedSftp === true);
  const degradedStage = await sidecar.call("sftp-browser.upload-directory.stage",
    { bindingHandle: secondConnect.bindingHandle, browserHandle: degradedBrowser.browserHandle, localPath: tar, name: "site" });
  const degradedRun = await sidecar.call("sftp-browser.upload-directory",
    { bindingHandle: secondConnect.bindingHandle, browserHandle: degradedBrowser.browserHandle, directoryHandle: degradedBrowser.directoryHandle, stagedHandle: degradedStage.stagedHandle })
    .then(() => "accepted", (error) => String(error?.message ?? error));
  check("a no-SFTP target refuses directory upload with the degraded code",
    degradedRun.includes("sftp-browser-subsystem-unavailable"));

  console.log(`\n${checks.length}/${checks.length} checks passed`);
} catch (error) {
  failure ??= error?.message ?? String(error);
  console.log(`FAILED: ${failure}`);
  process.exitCode = 1;
} finally {
  try { sidecar?.kill(); } catch {}
  try { if (containerId) podman("rm", "-f", containerId); } catch {}
  try { if (degradedId) podman("rm", "-f", degradedId); } catch {}
  try { fs.rmSync(localRoot, { recursive: true, force: true }); } catch {}
}
