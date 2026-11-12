// SFTP 子系统修复链路：在缺少 Subsystem sftp 的靶机上计划、确认、写入
// `Subsystem sftp internal-sftp`、sshd -t 校验并重载，随后用仓库自己的 SFTP
// 浏览器做一次真实会话；再经历史放回，SFTP 会话再次失败。
//
// 靶机由本脚本用 podman 创建（lovelyres-svc:mariadb 镜像已含 sshd 与实验口令），
// 删除其 Subsystem 行；脚本结束按创建 ID 只删除自己启动的容器。
//
//   node tools/lab/probe-baseline-sftp.mjs
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar, backendBinary, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID();
const name = `lr-sftp-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target", "lab-baseline-sftp", runId);
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-baseline-sftp-"));
const checks = [];
let failures = 0;
let containerId = null;
fs.mkdirSync(evidence, { recursive: true });

const PODMAN = process.env.LOVELYHAWK_PODMAN
  ?? "C:/Users/Benjamin/AppData/Local/Programs/Podman/podman.exe";
const IMAGE = process.env.SFTP_IMAGE ?? "localhost/lovelyres-svc:mariadb";

const podman = (...args) => execFileSync(PODMAN, args, { encoding: "utf8" }).trim();
const inContainer = (...args) => execFileSync(PODMAN, ["exec", "-i", containerId, ...args], { encoding: "utf8" }).trim();

function check(label, ok, ...rest) {
  const comparing = typeof ok !== "boolean";
  const detail = rest.length > 0 ? rest[0] : null;
  const passed = comparing ? rest.length > 0 && ok === detail : ok;
  const shown = comparing ? { actual: ok, expected: detail } : detail;
  checks.push({ label, passed, detail: shown });
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"} ${label}${passed || shown === null ? "" : ` — ${JSON.stringify(shown).slice(0, 400)}`}`);
}

function owned() {
  const inspect = JSON.parse(podman("container", "inspect", containerId))[0];
  const labels = inspect.Config.Labels ?? {};
  if (inspect.Name !== name && inspect.Name !== `/${name}` || labels["lovelyres-test-run"] !== runId) {
    throw new Error("refusing to touch a container this run did not create");
  }
  return inspect;
}

const sftpState = () => inContainer("sh", "-c", "sshd -T 2>/dev/null | awk '$1==\"subsystem\" && $2==\"sftp\"{print $0}'");
const sftpOpen = (sidecar, binding) =>
  sidecar.call("sftp-browser.open", { bindingHandle: binding }, 60_000)
    .then(() => "opened", (error) => String(error.message ?? error).slice(0, 200));

let sidecar = null;
try {
  podman("image", "inspect", IMAGE, "--format", "{{.Id}}");
  // Podman's port publishing never reaches Windows' localhost on this host;
  // the container shares the machine VM's address instead (its eth0 IP is
  // routable from Windows, as probe-baseline-sftp verified).
  const host = podman("machine", "ssh", "--", "ip", "-4", "-o", "addr", "show", "eth0")
    .match(/inet (\d+\.\d+\.\d+\.\d+)/)?.[1];
  if (!host) throw new Error("no podman machine address");
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`,
    "--memory", "256m", "--cpus", "1", "--pids-limit", "256", "--network", "host", IMAGE);
  owned();
  const sshPort = 22;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      if (inContainer("sh", "-c", "pgrep -x sshd >/dev/null && echo up || echo down") === "up") break;
    } catch { /* container still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  check("fixture sshd is up", true);

  // Plant the failure: no effective Subsystem sftp line anywhere sshd reads.
  inContainer("sh", "-c", "sed -i '/^[[:space:]]*Subsystem[[:space:]]/d' /etc/ssh/sshd_config && sshd -t && kill -HUP $(pgrep -x sshd | head -1)");
  check("fixture starts without an sftp subsystem", sftpState(), "");

  sidecar = new Sidecar(backendBinary(), dataRoot);
  const target = { host, port: sshPort, username: "root", password: "LabRoot#2026",
    id: "55555555-5555-4555-8555-5555555555f1", name: "SFTP 靶机" };
  const status = await connect(sidecar, target);
  if (status?.stage !== "connected") throw new Error(`fixture connect failed: ${JSON.stringify(status)}`);
  let binding = status.bindingHandle;
  // OpenSSH resolves the subsystem table when a connection is set up, so a
  // channel on a pre-repair session never sees the new line. The SFTP check
  // needs a fresh session after every config change.
  const reconnect = async () => {
    await sidecar.call("ssh.binding.disconnect", { bindingHandle: binding }).catch(() => {});
    const again = await connect(sidecar, target);
    if (again?.stage !== "connected") throw new Error(`fixture reconnect failed: ${JSON.stringify(again)}`);
    binding = again.bindingHandle;
  };

  // A real SFTP session cannot start before the change.
  const before = await sftpOpen(sidecar, binding);
  check("SFTP cannot open before the repair", before !== "opened", before);

  const catalog = await sidecar.call("baseline.catalog.get", {});
  const item = catalog.items.find((entry) => entry.title.includes("SFTP"));
  check("the catalog carries the sftp item, writable", item !== undefined && item.writable === true, item);

  let scan = await sidecar.call("baseline.scan", { bindingHandle: binding }, 120_000);
  const row = scan.statuses.find((entry) => entry.itemHandle === item.itemHandle);
  check("the scan reads the subsystem as absent", row?.observed === "absent" && row.compliant === false, row);

  const plan = (action) => sidecar.call("baseline.action.plan", { bindingHandle: binding, action }, 180_000);
  const confirm = (planHandle) => sidecar.call("baseline.action.confirm", { bindingHandle: binding, planHandle }, 60_000);
  const execute = (planHandle) => sidecar.call("baseline.action.execute", { bindingHandle: binding, planHandle }, 300_000);

  const planned = await plan({ kind: "change", changes: [{ itemHandle: item.itemHandle, value: item.recommendation }], reload: "apply-now" });
  check("the plan names sshd_config as the changed file",
    planned.changes[0]?.file === "/etc/ssh/sshd_config", planned.changes?.[0]);
  await confirm(planned.planHandle);
  const applied = await execute(planned.planHandle);
  check("the write is applied, checked and read back", applied.verified === true, applied);
  check("sshd -T now reports the internal subsystem", sftpState().startsWith("subsystem sftp internal-sftp"), sftpState());

  await reconnect();
  const opened = await sftpOpen(sidecar, binding);
  check("a real SFTP session opens after the repair", opened === "opened", opened);

  let history = await sidecar.call("baseline.history.list", { bindingHandle: binding }, 60_000);
  const entry = history.entries[0];
  check("the change is in history, applied and restorable", entry?.state === "applied" && entry?.restorable === true, entry);
  const restore = await plan({ kind: "restore", historyHandle: history.historyHandle, historyItemHandle: entry.historyItemHandle });
  await confirm(restore.planHandle);
  const restored = await execute(restore.planHandle);
  check("the file is put back and verified", restored.verified === true, restored);
  check("sshd -T no longer reports an sftp subsystem", sftpState(), "");

  await reconnect();
  const after = await sftpOpen(sidecar, binding);
  check("SFTP fails again after the restore", after !== "opened", after);
} catch (error) {
  check("probe completed without an exception", false,
    `${String(error.stack ?? error)}\nSTDERR: ${(sidecar?.stderr ?? []).join("").slice(-3000)}`);
} finally {
  if (containerId !== null) {
    try { owned(); podman("rm", "-f", containerId); } catch { /* leave the labelled container for inspection */ }
  }
  sidecar?.close();
}
fs.writeFileSync(path.join(evidence, "checks.json"), JSON.stringify(checks, null, 2));
console.log(`${checks.length} checks, ${failures} failures — evidence in ${evidence}`);
process.exit(failures === 0 ? 0 : 1);
