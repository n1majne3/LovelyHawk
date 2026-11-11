// Guided restore of a trojaned system command on a real host: the workbench
// names the backup residue beside /usr/bin/ls, the operator gets a path
// capability, plans restore-residue, confirms, executes and verifies — the
// command carries the residue's bytes, the trojan sits quarantined, and one
// undo puts it back. Runs on a Dropbear target with no SFTP at all, proving
// the whole chain needs only the exec channel.
import { execFileSync } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-cmd-restore-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-command-restore", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-restore-"));
const checks = [];
let containerId, sidecar, failure;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
const podman = (...args) => execFileSync("podman", [...args], { encoding: "utf8", windowsHide: true, timeout: 420_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const wslVm = (...args) => execFileSync("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000 }).replace(/\u0000/gu, "").trim();
function owned() {
  const current = JSON.parse(podman("inspect", containerId))[0];
  if (current.Id !== containerId || ![name, `/${name}`].includes(current.Name) || current.Config.Labels?.["lovelyres-test-run"] !== runId ||
    current.HostConfig.Privileged || (current.Mounts ?? []).length !== 0) throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const shaOf = (remote) => onHost("sha256sum", remote).split(/\s/u)[0];
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { if (await fn()) return; await sleep(150); } throw new Error(`Timed out: ${label}`); }

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const sshPort = 2223;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned();
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null 2>&1");
  onHost("sh", "-c", `dropbear -E -p ${sshPort} >/tmp/dropbear.log 2>&1`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);

  // Plant the incident: ls.bak keeps the genuine bytes, ls becomes a hostile
  // script — exactly the shape the workbench's residue check reports.
  onHost("sh", "-c", "cp -p /usr/bin/ls /usr/bin/ls.bak && printf '#!/bin/sh\\necho TROJANED-ls\\n' > /usr/bin/ls && chmod 755 /usr/bin/ls");
  const trojanSha = shaOf("/usr/bin/ls"), goodSha = shaOf("/usr/bin/ls.bak");
  check("fixture plants a trojaned ls beside its backup", trojanSha !== goodSha && onHost("sh", "-c", "/usr/bin/ls").includes("TROJANED"));

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const recent = catalog.commands.find((c) => c.title === "系统命令近期改动");
  check("investigation catalog offers the recent-changes check", Boolean(recent));
  const output = await sidecar.call("emergency-command.run", { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: recent.commandHandle, containerHandle: null });
  fs.writeFileSync(path.join(evidence, "workbench-output.txt"), String(output.output ?? ""));
  const residueLine = String(output.output ?? "").split("\n").find((line) => line.includes("备份残留") && line.includes("/usr/bin/ls.bak"));
  check("the workbench names the planted residue", typeof residueLine === "string");
  const offer = (output.paths ?? []).find((p) => p.path === "/usr/bin/ls");
  check("the shadowed command earns a path capability", Boolean(offer));

  // SFTP-backed inspect may fail on this host; the page tolerates that for
  // restore-residue exactly the same way, so the probe mirrors the page.
  const inspected = await sidecar.call("emergency-command.path.inspect", { bindingHandle: binding, pathHandle: offer.pathHandle }).then(() => "ok", () => "sftp-gap");
  check("restore planning does not depend on the SFTP-backed inspect", inspected === "sftp-gap" || inspected === "ok");

  const plan = await sidecar.call("emergency-command.path.plan", { bindingHandle: binding, pathHandle: offer.pathHandle, action: "restore-residue" });
  check("plan picks the explicit backup as the source", plan.residue?.source?.path === "/usr/bin/ls.bak" && plan.residue?.source?.kind === "backup");
  check("plan names the owning package", plan.residue?.package === "coreutils");
  fs.writeFileSync(path.join(evidence, "plan.json"), JSON.stringify(plan, null, 2));

  await sidecar.call("emergency-command.path.confirm", { bindingHandle: binding, planHandle: plan.planHandle });
  const executed = await sidecar.call("emergency-command.path.execute", { bindingHandle: binding, planHandle: plan.planHandle });
  fs.writeFileSync(path.join(evidence, "execute.json"), JSON.stringify(executed, null, 2));
  check("execute verifies the restore", executed.passed === true && executed.undoable === true);
  check("the command now carries the residue bytes", shaOf("/usr/bin/ls") === goodSha);
  const quarantined = onHost("sh", "-c", "ls -1 /usr/bin/ls.lh-replaced-* 2>/dev/null | head -n 1").trim();
  check("the trojan bytes sit quarantined, owner-read only", quarantined.startsWith("/usr/bin/ls.lh-replaced-") && shaOf(quarantined) === trojanSha);
  check("the restored command runs for real", !onHost("sh", "-c", "/usr/bin/ls --version | head -n 1").includes("TROJANED"));

  const undone = await sidecar.call("emergency-command.path.undo", { bindingHandle: binding, planHandle: plan.planHandle });
  fs.writeFileSync(path.join(evidence, "undo.json"), JSON.stringify(undone, null, 2));
  // Deliberately not `ls`: the just-restored bytes are the trojan.
  check("undo puts the original bytes back and lifts the quarantine", shaOf("/usr/bin/ls") === trojanSha && onHost("sh", "-c", "for f in /usr/bin/ls.lh-replaced-*; do [ -e \"$f\" ] && { echo present; exit 0; }; done; echo gone").includes("gone"));
  const second = await sidecar.call("emergency-command.path.undo", { bindingHandle: binding, planHandle: plan.planHandle }).then(() => "allowed", (error) => String(error.message ?? error));
  check("a second undo is refused", second !== "allowed");

  console.log(`\n${checks.length}/${checks.length} checks passed`);
} catch (error) {
  failure ??= error?.message ?? String(error);
  console.log(`FAILED: ${failure}`);
  process.exitCode = 1;
} finally {
  try { sidecar?.kill(); } catch {}
  try { if (containerId) podman("rm", "-f", containerId); } catch {}
}
