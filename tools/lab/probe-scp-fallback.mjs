// Classic-SCP fallback on a real host: a Dropbear target offers SSH with no
// `Subsystem sftp` at all, so every file feature used to be dead. The probe
// proves the SFTP surface still fails honestly while evidence collection —
// the incident-critical transfer — completes over `scp -f` exec channels
// with the same double-read verification.
import { execFileSync } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-scp-fallback-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-scp-fallback", runId);
const exportsRoot = path.join(evidence, "exports"); fs.mkdirSync(exportsRoot, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-scp-"));
const checks = [];
const sample = Buffer.concat([Buffer.from("scp-fallback-evidence-token\u0000"), Buffer.from(Array.from({ length: 151_789 }, (_, i) => (i * 7) % 256))]);
const digest = createHash("sha256").update(sample).digest("hex");
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
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { if (await fn()) return; await sleep(150); } throw new Error(`Timed out: ${label}`); }

try {
  // The podman machine VM's address: published ports are reachable from
  // Windows only through it, not through localhost.
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  // Host networking: the podman machine's DNAT does not forward to the VM's
  // eth0, so the fixture shares the VM netns and dropbear listens on 2222.
  const sshPort = 2222;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned();
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);
  const port = sshPort;
  const scpCheck = onHost("sh", "-c", "command -v scp; command -v sftp-server || echo none");
  check("fixture has scp but no sftp-server", scpCheck.includes("/usr/bin/scp") && scpCheck.includes("none"));
  fs.writeFileSync(path.join(evidence, "sample.bin"), sample);
  podman("cp", path.join(evidence, "sample.bin"), `${containerId}:/root/scp-evidence.bin`);
  onHost("chmod", "4700", "/root/scp-evidence.bin");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to a host with no SFTP subsystem", true);

  const browser = await sidecar.call("sftp-browser.open", { bindingHandle: binding }).then(() => "opened", (error) => String(error.message ?? error));
  check("sftp browser still reports the subsystem gap honestly", browser !== "opened");

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const suid = catalog.commands.find((c) => c.title === "SUID 可执行");
  check("investigation catalog offers SUID review on the dropbear host", Boolean(suid));
  const output = await sidecar.call("emergency-command.run", { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: suid.commandHandle, containerHandle: null });
  const offer = (output.paths ?? []).find((p) => p.path === "/root/scp-evidence.bin");
  check("planted file earns a path capability through the workbench", Boolean(offer));

  const begin = await sidecar.call("emergency.file-evidence", { action: "begin", bindingHandle: binding, pathHandle: offer.pathHandle, selectedDirectory: exportsRoot });
  let job = begin;
  await until(async () => { job = await sidecar.call("emergency.file-evidence", { action: "poll", bindingHandle: binding, jobHandle: job.jobHandle }); return job.state !== "collecting"; }, "scp evidence collection", 120_000);
  check("evidence collection completes over the scp fallback", job.state === "completed" && job.sha256 === digest && job.totalBytes === sample.length);

  const folder = path.join(exportsRoot, job.folderName);
  const manifest = JSON.parse(fs.readFileSync(path.join(folder, "manifest.json"), "utf8"));
  check("manifest names the scp transport and its own limitations", manifest.observation.transport === "scp" && manifest.limitations.includes("SCP"));
  check("bytes survive the exec-channel transfer exactly", fs.readFileSync(path.join(folder, "sample.bin")).equals(sample));
  console.log(`\n${checks.length}/${checks.length} checks passed`);
} catch (error) {
  failure ??= error?.message ?? String(error);
  console.log(`FAILED: ${failure}`);
  process.exitCode = 1;
} finally {
  try { sidecar?.kill(); } catch {}
  try { if (containerId) podman("rm", "-f", containerId); } catch {}
}
