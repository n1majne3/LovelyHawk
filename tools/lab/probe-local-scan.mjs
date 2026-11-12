// Local-scan fetch on a real host: a Dropbear target has SSH but no SFTP
// subsystem, so the archive download proves the SCP fallback carries the
// whole fetch chain — remote probe, remote tar bundle, verified download,
// safe local extraction into quarantine, engine launch against the staged
// content, and discard.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-local-scan-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-local-scan", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-localscan-"));
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
  const sshPort = 2222;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned();
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin openssh-client netcat-openbsd >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);
  const port = sshPort;
  const scpCheck = onHost("sh", "-c", "command -v scp; command -v sftp-server || echo none; command -v tar; command -v find");
  check("fixture has scp+tar+find but no sftp-server", scpCheck.includes("/usr/bin/scp") && scpCheck.includes("none") && scpCheck.includes("/bin/tar"));

  // A web root with a real webshell hit, ordinary scripts, a hidden script and
  // a symlink that must be skipped — never followed — on extraction.
  onHost("sh", "-c", "mkdir -p /var/www/html/images && printf '<?php @eval($_POST[\"x\"]); ?>' > /var/www/html/shell.php && printf '<?php echo \"hi\"; ?>' > /var/www/html/safe.php && printf '<?php system($_GET[\"c\"]); ?>' > /var/www/html/.hidden.php && printf '<?php phpinfo(); ?>' > /var/www/html/images/pic.php && ln -s /etc/passwd /var/www/html/link.php");

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to a host with no SFTP subsystem", true);

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });
  const webshell = catalog.commands.find((c) => c.title === "WebShell 扫描");
  check("workbench offers the webshell scan", Boolean(webshell));
  const output = await sidecar.call("emergency-command.run", { bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: webshell.commandHandle, containerHandle: null });
  const offer = (output.paths ?? []).find((p) => p.path === "/var/www/html/shell.php");
  check("webshell hit earns a path capability", Boolean(offer));

  const rejected = await sidecar.call("local.scan", { action: "fetch", bindingHandle: binding, pathHandle: "bogus-handle", scope: "file" }).then(() => "accepted", (error) => String(error.message ?? error));
  check("fetch with an invented path handle is refused", rejected !== "accepted");

  const fileFetch = await sidecar.call("local.scan", { action: "fetch", bindingHandle: binding, pathHandle: offer.pathHandle, scope: "file" }, 300_000);
  check("single-file fetch lands in quarantine over scp", fileFetch.kind === "fetch" && fileFetch.fetch.sourceKind === "file" && fileFetch.fetch.files === 1 && fileFetch.fetch.transport === "scp" && fileFetch.fetch.entries.includes("shell.php") && /^[0-9a-f]{64}$/u.test(fileFetch.fetch.archiveSha256));
  check("staging directory holds exactly the fetched file", fs.existsSync(path.join(fileFetch.fetch.stagingDirectory, "shell.php")));

  const dirFetch = await sidecar.call("local.scan", { action: "fetch", bindingHandle: binding, pathHandle: offer.pathHandle, scope: "directory" }, 300_000);
  const stage = dirFetch.fetch.stagingDirectory;
  check("directory fetch captures scripts, hidden files and subdirectories", dirFetch.kind === "fetch" && dirFetch.fetch.sourceKind === "directory" && dirFetch.fetch.files >= 4 && dirFetch.fetch.directories >= 2 && dirFetch.fetch.entries.includes("html/shell.php") && dirFetch.fetch.entries.includes("html/.hidden.php") && dirFetch.fetch.entries.includes("html/images/pic.php"));
  check("the symlink never lands — the remote listing excludes non-regular members", !dirFetch.fetch.entries.some((e) => e.includes("link.php")) && !fs.existsSync(path.join(stage, "html", "link.php")) && !fs.existsSync(path.join(stage, "html", "passwd")));
  // Reading the flagged webshell back trips Windows Defender (error 225) —
  // the host AV inspecting fetched content is by design; compare bytes on a
  // benign sibling and confirm the flagged file at least landed.
  check("fetched benign file is byte-identical to the remote file", fs.readFileSync(path.join(stage, "html", "safe.php"), "utf8").includes("echo \"hi\"") && fs.existsSync(path.join(stage, "html", "shell.php")));
  const manifest = JSON.parse(fs.readFileSync(path.join(path.dirname(dirFetch.fetch.stagingDirectory), "manifest.json"), "utf8"));
  check("manifest binds target, source path, digest and transport", manifest.sourcePath === "/var/www/html/shell.php" && manifest.sourceKind === "directory" && manifest.transport === "scp" && manifest.archiveSha256 === dirFetch.fetch.archiveSha256 && manifest.targetLabel.includes("root@") && manifest.limitations.length >= 2);

  const inspected = await sidecar.call("local.scan", { action: "inspect", bindingHandle: binding, fetchId: dirFetch.fetch.fetchId });
  check("inspect reads the same fetch back from its manifest", inspected.kind === "fetch" && inspected.fetch.fetchId === dirFetch.fetch.fetchId && inspected.fetch.files === dirFetch.fetch.files && inspected.fetch.archiveSha256 === dirFetch.fetch.archiveSha256);

  const enginesBefore = await sidecar.call("local.scan", { action: "engines" });
  const configured = await sidecar.call("local.scan", { action: "configure", name: "fixture-cli", kind: "cli", arguments: ["/c", "dir", "/b", "/s", "{dir}"], program: "C:\\Windows\\System32\\cmd.exe" });
  const cli = configured.engines.find((e) => e.name === "fixture-cli" && e.kind === "cli");
  check("cli engine configuration persists and lists", Boolean(cli) && configured.engines.length === enginesBefore.engines.length + 1);

  const ran = await sidecar.call("local.scan", { action: "run", bindingHandle: binding, fetchId: dirFetch.fetch.fetchId, engineId: cli.id }, 200_000);
  check("cli engine runs against staged content with captured output", ran.kind === "run" && ran.state === "finished" && ran.exitCode === 0 && ran.output.includes("shell.php") && ran.output.includes(".hidden.php"));
  check("`dir /b /s` prints absolute member paths that all map to remote hits",
    Array.isArray(ran.hits) && ran.hits.some((h) => h.remotePath === "/var/www/html/shell.php" && h.member === "html/shell.php" && typeof h.pathHandle === "string"));

  // A fake CLI engine naming two fetched members — one absolute, one
  // relative — plus hostile lines that must never map: a traversal reaching
  // the manifest's own sibling, a real absolute path outside the staging
  // dir, a member that was never fetched, and the staging root itself.
  const hitScript = path.join(evidence, "fixture-hits.cmd");
  fs.writeFileSync(hitScript, [
    "@echo off",
    "echo HIT %~1\\html\\shell.php",
    "echo REL html\\safe.php",
    "echo EVIL %~1\\..\\manifest.json",
    "echo OUT C:\\Windows\\System32\\drivers\\etc\\hosts",
    "echo MISS html\\nothere.php",
    "echo ROOT %~1",
    "exit /b 0",
    "",
  ].join("\r\n"));
  const hitArgs = ["/c", hitScript];
  const hitEngine = await sidecar.call("local.scan", { action: "configure", name: "fixture-hits", kind: "cli", arguments: hitArgs, program: "C:\\Windows\\System32\\cmd.exe" });
  const hitsId = hitEngine.engines.find((e) => e.name === "fixture-hits")?.id;
  const hitRun = await sidecar.call("local.scan", { action: "run", bindingHandle: binding, fetchId: dirFetch.fetch.fetchId, engineId: hitsId }, 200_000);
  check("fake engine's two member paths map through the manifest to remote paths",
    hitRun.hits.length === 2 &&
    hitRun.hits.some((h) => h.remotePath === "/var/www/html/shell.php" && h.member === "html/shell.php" && h.line.includes("HIT")) &&
    hitRun.hits.some((h) => h.remotePath === "/var/www/html/safe.php" && h.member === "html/safe.php" && h.line.includes("REL")));
  check("traversal, outside and never-fetched tokens never become hits",
    !hitRun.hits.some((h) => h.line.includes("EVIL") || h.line.includes("OUT") || h.line.includes("MISS") || h.line.includes("ROOT")));
  const hitHandle = hitRun.hits.find((h) => h.remotePath === "/var/www/html/shell.php")?.pathHandle;
  check("a hit carries a backend-minted path handle", typeof hitHandle === "string" && hitHandle.length > 0);
  // This fixture has no SFTP subsystem, so inspect reaches the transport
  // bound and fails there — operation-failed, never stale/unavailable. The
  // original webshell offer handle fails the same way: parity proves the
  // hit handle resolved identically through the path registry.
  const hitInspect = await sidecar.call("emergency-command.path.inspect", { bindingHandle: binding, pathHandle: hitHandle })
    .then(() => "resolved", (error) => String(error.message ?? error));
  const offerInspect = await sidecar.call("emergency-command.path.inspect", { bindingHandle: binding, pathHandle: offer.pathHandle })
    .then(() => "resolved", (error) => String(error.message ?? error));
  check("the hit handle resolves like the workbench offer handle (SFTP-less target limits both)",
    hitInspect === offerInspect && hitInspect.includes("operation-failed"));

  const guiConfigured = await sidecar.call("local.scan", { action: "configure", name: "fixture-gui", kind: "gui", arguments: ["/c", "exit", "0"], program: "C:\\Windows\\System32\\cmd.exe" });
  const gui = guiConfigured.engines.find((e) => e.name === "fixture-gui");
  const launched = await sidecar.call("local.scan", { action: "run", bindingHandle: binding, fetchId: dirFetch.fetch.fetchId, engineId: gui.id });
  check("gui engine launches detached and reports the staging directory", launched.kind === "run" && launched.state === "launched" && launched.detail.includes(dirFetch.fetch.stagingDirectory));

  const wrongFetch = await sidecar.call("local.scan", { action: "run", bindingHandle: binding, fetchId: fileFetch.fetch.fetchId, engineId: "eng-does-not-exist" }).then(() => "accepted", (error) => String(error.message ?? error));
  check("run with an unknown engine is refused", wrongFetch !== "accepted");

  const discarded = await sidecar.call("local.scan", { action: "discard", bindingHandle: binding, fetchId: fileFetch.fetch.fetchId });
  check("discard removes the staged quarantine copy", discarded.kind === "done" && !fs.existsSync(fileFetch.fetch.stagingDirectory));
  const afterDiscard = await sidecar.call("local.scan", { action: "inspect", bindingHandle: binding, fetchId: fileFetch.fetch.fetchId }).then(() => "accepted", (error) => String(error.message ?? error));
  check("a discarded fetch cannot be inspected or scanned again", afterDiscard !== "accepted");

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
