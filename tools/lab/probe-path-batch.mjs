// Batch path disposal on a real target: a disposable Dropbear container gets
// three planted webshell files. The webshell scan offers one path handle per
// file; a batch disarm plan is previewed and confirmed, one file is
// changed between plan and execute so its item is refused in place, the other
// two complete, and each completed item is undone through its own receipt.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-path-batch-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-path-batch", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-pathbatch-"));
const checks = [];
let containerId, sidecar, failure;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const podman = (...args) => execFileSync("podman", [...args], { encoding: "utf8", windowsHide: true, timeout: 420_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const wslVm = (...args) => execFileSync("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000 }).replace(/\0/gu, "").trim();
function owned() {
  const current = JSON.parse(podman("inspect", containerId))[0];
  if (current.Id !== containerId || ![name, `/${name}`].includes(current.Name) || current.Config.Labels?.["lovelyres-test-run"] !== runId ||
    current.HostConfig.Privileged || (current.Mounts ?? []).length !== 0) throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { if (await fn()) return; await sleep(150); } throw new Error(`Timed out: ${label}`); }

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const sshPort = 2224;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned();
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client openssh-sftp-server netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);

  onHost("sh", "-c", "mkdir -p /var/www/html && " +
    "printf '<?php @eval($_POST[\"a\"]); ?>' > /var/www/html/aa.php && " +
    "printf '<?php system($_GET[\"b\"]); ?>' > /var/www/html/bb.php && " +
    "printf '<?php @eval($_REQUEST[\"c\"]); ?>' > /var/www/html/cc.php && " +
    "chmod 755 /var/www/html/aa.php /var/www/html/bb.php /var/www/html/cc.php");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to the fixture", true);

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const webshell = catalog.commands.find((c) => c.title === "WebShell 扫描");
  const output = await sidecar.call("emergency-command.run",
    { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: webshell.commandHandle, containerHandle: null });
  const handles = ["aa.php", "bb.php", "cc.php"]
    .map((file) => (output.paths ?? []).find((p) => p.path === `/var/www/html/${file}`))
    .filter(Boolean);
  check("three planted webshells each earn a path handle", handles.length === 3);

  const overCap = await sidecar.call("emergency-command.path.batch.plan",
    { bindingHandle: binding, pathHandles: Array(51).fill(handles[0].pathHandle), action: "disarm" })
    .then(() => "accepted", (error) => String(error.message ?? error));
  check("a batch over the 50-item cap is refused", overCap !== "accepted");
  // An invented handle is refused in place rather than failing the batch the
  // operator is still previewing.
  const bogus = await sidecar.call("emergency-command.path.batch.plan",
    { bindingHandle: binding, pathHandles: ["invented-handle"], action: "disarm" });
  check("an invented handle is refused in place, never planned",
    bogus.planned === 0 && bogus.refused === 1 && bogus.items[0].refusal === "path-stale" && bogus.items[0].planHandle === null);

  const plan = await sidecar.call("emergency-command.path.batch.plan",
    { bindingHandle: binding, pathHandles: handles.map((h) => h.pathHandle), action: "disarm" });
  check("batch plan previews every item planned", plan.kind !== "done" && plan.planned === 3 && plan.refused === 0 && plan.state === "planned" && plan.items.length === 3 &&
    plan.items.every((item) => item.planHandle !== null && item.summary !== null && item.restoreDescription !== null));

  // The operator reads the preview, confirms once — then one file changes on
  // the target before the batch steps through it.
  const confirmed = await sidecar.call("emergency-command.path.batch.confirm", { bindingHandle: binding, batchHandle: plan.batchHandle });
  check("one confirmation covers the whole preview", confirmed.state === "confirmed" && confirmed.planned === 3);
  onHost("sh", "-c", "chmod 600 /var/www/html/bb.php && printf 'changed after plan' >> /var/www/html/bb.php");

  const steps = [];
  for (let i = 0; i < 5; i += 1) {
    const step = await sidecar.call("emergency-command.path.batch.step", { bindingHandle: binding, batchHandle: plan.batchHandle });
    steps.push(step);
    if (step.finished) break;
  }
  const receipts = steps.map((s) => s.receipt).filter(Boolean);
  const done = receipts.filter((r) => r.passed);
  const refused = receipts.filter((r) => !r.passed);
  check("two items complete and one refuses because it changed since the plan",
    receipts.length === 3 && done.length === 2 && refused.length === 1 && refused[0].untouched === true && refused[0].path === "/var/www/html/bb.php");
  const modes = onHost("sh", "-c", "stat -c '%a %n' /var/www/html/aa.php /var/www/html/bb.php /var/www/html/cc.php; cat /var/www/html/bb.php");
  check("two files are disarmed, the changed one is untouched",
    modes.includes("644 /var/www/html/aa.php") && modes.includes("600 /var/www/html/bb.php") && modes.includes("644 /var/www/html/cc.php") && modes.includes("changed after plan"));
  check("each completed item is individually undoable", done.every((r) => r.undoable === true));

  for (const receipt of done) {
    const undo = await sidecar.call("emergency-command.path.undo", { bindingHandle: binding, planHandle: receipt.planHandle });
    check(`undo restores ${receipt.path}`, undo.undone === true && undo.path === receipt.path);
  }
  const restored = onHost("sh", "-c", "stat -c '%a %n' /var/www/html/aa.php /var/www/html/cc.php");
  check("undo puts both execute bits back", restored.includes("755 /var/www/html/aa.php") && restored.includes("755 /var/www/html/cc.php"));

  console.log(`\n${checks.length}/${checks.length} checks passed`);
} catch (error) {
  failure ??= error?.message ?? String(error);
  console.log(`FAILED: ${failure}`);
  for (const chunk of sidecar?.stderr ?? []) process.stderr.write(chunk);
  process.exitCode = 1;
} finally {
  try { sidecar?.kill(); } catch {}
  try { if (containerId) podman("rm", "-f", containerId); } catch {}
  try { fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); } catch {}
}
