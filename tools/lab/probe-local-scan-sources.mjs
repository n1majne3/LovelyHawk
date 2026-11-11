// Local-scan fetch from the two new sources on one real target: the podman
// machine VM runs OpenSSH (with the SFTP subsystem) AND the podman daemon, so
// a single connection exercises `fetch-browser` against listed SFTP entries
// and `fetch-container` against a labelled disposable podman container.
// The container is verified by its ownership label before and after, then
// removed. No password is used: the VM's own machine key authenticates root.
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lh-scanfix-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-local-scan-sources", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-localscan-src-"));
const checks = [];
let containerId, sidecar, failure;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) {
  checks.push({ label, passed: Boolean(actual) });
  console.log(`${actual ? "PASS" : "FAIL"} ${label}`);
  if (!actual) throw new Error(label);
}
const podman = (...args) =>
  execFileSync("podman", [...args], { encoding: "utf8", windowsHide: true, timeout: 420_000, maxBuffer: 2 * 1024 * 1024 }).trim();
function owned() {
  const current = JSON.parse(podman("inspect", containerId))[0];
  if (current.Id !== containerId || ![name, `/${name}`].includes(current.Name) ||
    current.Config.Labels?.["lovelyres-test-run"] !== runId ||
    current.HostConfig.Privileged || (current.Mounts ?? []).length !== 0) throw new Error("Fixture identity changed");
  return current;
}
const inContainer = (...args) => { owned(); return podman("exec", containerId, ...args); };
const sshTarget = {
  host: "127.0.0.1",
  port: 60338,
  username: "root",
  key: "C:\\Users\\Benjamin\\.local\\share\\containers\\podman\\machine\\machine",
};

async function connectWithKey() {
  const connectionId = `scan-src-${runId.slice(0, 8)}`;
  await sidecar.call("connections.create", {
    connection: {
      id: connectionId, name: "podman-machine-vm", host: sshTarget.host, port: sshTarget.port,
      username: sshTarget.username, authMethod: "public-key", privateKeyPath: sshTarget.key,
      certificatePath: null, agentIdentityFingerprint: null, jumpHost: null, tags: [], notes: null,
      environment: null, role: null, group: null,
    },
    secrets: {},
  });
  const started = await sidecar.call("ssh.connect.start", { connectionId });
  let status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
  for (let step = 0; step < 80; step += 1) {
    if (status.hostKeyPrompt?.promptHandle !== undefined) {
      status = await sidecar.call("ssh.host-key.confirm", {
        attemptHandle: started.attemptHandle, promptHandle: status.hostKeyPrompt.promptHandle,
      });
      continue;
    }
    if (status.stage === "connected" || status.stage === "failed") break;
    await sleep(400);
    status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
  }
  if (status.stage !== "connected") throw new Error(`connect failed: ${JSON.stringify(status)}`);
  return status.bindingHandle;
}

try {
  // The labelled fixture container on the same daemon the SSH target sees.
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "256m", "--cpus", "1", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned();
  inContainer("sh", "-c", "mkdir -p /var/www/html && printf '<?php @eval($_POST[\"x\"]); ?>' > /var/www/html/shell.php && printf 'plain text\\n' > /var/www/html/note.txt && mkdir -p /var/www/html/sub && printf 'body{}\\n' > /var/www/html/sub/style.css");
  check("fixture container runs podman with a small web dir", true);

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const binding = await connectWithKey();
  check("connects to the podman machine VM by key", true);

  // ---- fetch-browser ----------------------------------------------------
  const opened = await sidecar.call("sftp-browser.open", { bindingHandle: binding }, 60_000);
  const etc = (opened.entries ?? []).find((entry) => entry.name === "etc");
  check("sftp browser opens on the VM and lists /etc", Boolean(etc));
  const listing = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding, browserHandle: opened.browserHandle, directoryHandle: etc.entryHandle,
  }, 60_000);
  const hostname = (listing.entries ?? []).find((entry) => entry.name === "hostname" && entry.kind === "file");
  check("/etc/hostname is listed as a regular file", Boolean(hostname));

  const refusedEntry = await sidecar.call("local.scan", {
    action: "fetch-browser", bindingHandle: binding,
    browserHandle: opened.browserHandle, entryHandle: "forged-entry", scope: "file",
  }).then(() => "accepted", (error) => String(error.message ?? error));
  check("fetch-browser with a forged entry handle is refused", refusedEntry !== "accepted");

  const fileFetch = await sidecar.call("local.scan", {
    action: "fetch-browser", bindingHandle: binding,
    browserHandle: opened.browserHandle, entryHandle: hostname.entryHandle, scope: "file",
  }, 300_000);
  check("browser file fetch lands in quarantine over sftp",
    fileFetch.kind === "fetch" && fileFetch.fetch.sourceKind === "file" && fileFetch.fetch.files === 1 &&
    fileFetch.fetch.origin === "host" && fileFetch.fetch.originLabel === "" &&
    fileFetch.fetch.entries.includes("hostname") && /^[0-9a-f]{64}$/u.test(fileFetch.fetch.archiveSha256));
  check("staged file is byte-identical to the remote /etc/hostname",
    fs.existsSync(path.join(fileFetch.fetch.stagingDirectory, "hostname")));

  // A directory row: a controlled folder under /var, scope file = the listed
  // directory itself.
  const ssh = (command) => {
    try {
      return execFileSync("ssh", ["-i", sshTarget.key, "-p", String(sshTarget.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", `UserKnownHostsFile=${path.join(evidence, "known_hosts")}`,
        `${sshTarget.username}@${sshTarget.host}`, command],
        { encoding: "utf8", windowsHide: true, timeout: 60_000 }).trim();
    } catch (error) { return String(error.stdout ?? error.message); }
  };
  ssh("mkdir -p /var/lhdir/sub && printf 'one\\n' > /var/lhdir/a.txt && printf 'two\\n' > /var/lhdir/sub/b.txt && ln -sf /etc/passwd /var/lhdir/link");
  // The first fetch may advance the browser's generation; reopen so the next
  // entry handle belongs to a listing that is provably current.
  const reopened = await sidecar.call("sftp-browser.open", { bindingHandle: binding }, 60_000);
  const varDir = (reopened.entries ?? []).find((entry) => entry.name === "var");
  const varListing = await sidecar.call("sftp-browser.directory.list", {
    bindingHandle: binding, browserHandle: reopened.browserHandle, directoryHandle: varDir.entryHandle,
  }, 60_000);
  const lhdir = (varListing.entries ?? []).find((entry) => entry.name === "lhdir");
  check("the controlled directory is listed as a folder", Boolean(lhdir) && lhdir.kind === "directory");
  const dirFetch = await sidecar.call("local.scan", {
    action: "fetch-browser", bindingHandle: binding,
    browserHandle: reopened.browserHandle, entryHandle: lhdir.entryHandle, scope: "file",
  }, 300_000);
  check("browser directory fetch stages the folder content",
    dirFetch.kind === "fetch" && dirFetch.fetch.directories >= 2 && dirFetch.fetch.files >= 2 &&
    fs.existsSync(path.join(dirFetch.fetch.stagingDirectory, "lhdir", "a.txt")) &&
    fs.existsSync(path.join(dirFetch.fetch.stagingDirectory, "lhdir", "sub", "b.txt")));
  check("the symlink inside never lands",
    !dirFetch.fetch.entries.some((e) => e.includes("link")) &&
    !fs.existsSync(path.join(dirFetch.fetch.stagingDirectory, "lhdir", "link")));
  const dirManifest = JSON.parse(fs.readFileSync(
    path.join(path.dirname(dirFetch.fetch.stagingDirectory), "manifest.json"), "utf8"));
  check("manifest records the host origin",
    dirManifest.origin === "host" && dirManifest.sourceKind === "directory");
  ssh("rm -rf /var/lhdir");

  // A large real directory: the whole /etc tree mixes regular files, pax
  // long names and hardlinks — the exact archive shape that used to abort
  // extraction with local-scan-unavailable.
  const again = await sidecar.call("sftp-browser.open", { bindingHandle: binding }, 60_000);
  const etcDir = (again.entries ?? []).find((entry) => entry.name === "etc");
  const etcFetch = await sidecar.call("local.scan", {
    action: "fetch-browser", bindingHandle: binding,
    browserHandle: again.browserHandle, entryHandle: etcDir.entryHandle, scope: "file",
  }, 300_000);
  check("a whole-/etc browser fetch succeeds",
    etcFetch.kind === "fetch" && etcFetch.fetch.sourceKind === "directory" && etcFetch.fetch.files > 0);
  check("skipped members are counted with bounded reasons",
    typeof etcFetch.fetch.skipped === "number" &&
    Array.isArray(etcFetch.fetch.skippedReasons) &&
    etcFetch.fetch.skippedReasons.every((reason) => typeof reason === "string" && reason.length < 200));

  // ---- fetch-container ---------------------------------------------------
  const snapshot = await sidecar.call("docker.containers.refresh", { bindingHandle: binding }, 90_000);
  const row = (snapshot.containers ?? []).find((item) => item.name === name);
  check("the labelled fixture appears in the remote runtime snapshot", Boolean(row));

  const refusedPath = await sidecar.call("local.scan", {
    action: "fetch-container", bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle, containerHandle: row.containerHandle,
    path: "/var/../etc", scope: "file",
  }).then(() => "accepted", (error) => String(error.message ?? error));
  check("fetch-container with a traversal path is refused", refusedPath !== "accepted");

  const ctrFile = await sidecar.call("local.scan", {
    action: "fetch-container", bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle, containerHandle: row.containerHandle,
    path: "/var/www/html/shell.php", scope: "file",
  }, 300_000);
  check("container file fetch lands with the container origin",
    ctrFile.kind === "fetch" && ctrFile.fetch.sourceKind === "file" && ctrFile.fetch.files === 1 &&
    ctrFile.fetch.origin === "container" && ctrFile.fetch.originLabel.includes(name) &&
    ctrFile.fetch.originLabel.includes("podman") &&
    fs.existsSync(path.join(ctrFile.fetch.stagingDirectory, "shell.php")));
  const ctrFileManifest = JSON.parse(fs.readFileSync(
    path.join(path.dirname(ctrFile.fetch.stagingDirectory), "manifest.json"), "utf8"));
  check("container limitation text explains cp semantics",
    (ctrFileManifest.limitations ?? []).some((line) => line.includes("容器运行时 cp")));

  const ctrDir = await sidecar.call("local.scan", {
    action: "fetch-container", bindingHandle: binding,
    snapshotHandle: snapshot.snapshotHandle, containerHandle: row.containerHandle,
    path: "/var/www/html/shell.php", scope: "directory",
  }, 300_000);
  check("container directory scope stages the parent layer",
    ctrDir.kind === "fetch" && ctrDir.fetch.sourceKind === "directory" &&
    fs.existsSync(path.join(ctrDir.fetch.stagingDirectory, "html", "shell.php")) &&
    fs.existsSync(path.join(ctrDir.fetch.stagingDirectory, "html", "sub", "style.css")));
  const ctrManifest = JSON.parse(fs.readFileSync(
    path.join(path.dirname(ctrDir.fetch.stagingDirectory), "manifest.json"), "utf8"));
  check("manifest records the container origin and label",
    ctrManifest.origin === "container" && ctrManifest.originLabel.includes(name));

  const discarded = await sidecar.call("local.scan", {
    action: "discard", bindingHandle: binding, fetchId: ctrFile.fetch.fetchId,
  });
  check("discard removes a container fetch the same as a host fetch",
    discarded.kind === "done" && !fs.existsSync(ctrFile.fetch.stagingDirectory));

  fs.writeFileSync(path.join(evidence, "checks.json"), JSON.stringify(checks, null, 2));
  console.log(`\n${checks.length}/${checks.length} checks passed — evidence: ${evidence}`);
} catch (error) {
  failure ??= error?.message ?? String(error);
  console.log(`FAILED: ${failure}`);
  for (const chunk of sidecar?.stderr ?? []) process.stderr.write(chunk);
  process.exitCode = 1;
} finally {
  try { sidecar?.kill(); } catch {}
  try { if (containerId) { owned(); podman("rm", "-f", containerId); } } catch {}
  try { fs.rmSync(dataRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); } catch {}
}
