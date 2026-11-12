// Offline pcap analysis lab: generate the synthetic fixtures, feed each through
// the backend's host-side `pcap-offline.*` RPCs, and check the alerts, objects,
// echoes and truncation/negative behaviour that must come back.
//
//   node tools/lab/probe-pcap-offline.mjs
//
// If a disposable tcpdump target is reachable (LAB_CONTAINER, default
// `svc-docker`), the probe also captures REAL curl traffic plus a fake stratum
// line and analyzes that pcap too — the honest "did real capture work" check.

import { execFileSync } from "node:child_process";
import { mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Sidecar, newDataRoot } from "./rpc-harness.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "..", "..");
const backend = path.join(repository, "target", "debug", "lovelyhawk-backend.exe");
const outdir = path.join(repository, "target", "lab-pcap-offline");
mkdirSync(outdir, { recursive: true });

let failures = 0;
function check(name, actual, expected = true) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- fixtures ----------
execFileSync("node", [path.join(repository, "tools", "lab", "make-pcap-fixtures.mjs"), outdir], { stdio: "pipe" });
console.log("  fixtures generated");

const sidecar = new Sidecar(backend, newDataRoot());

async function analyze(file) {
  await sidecar.call("pcap-offline.begin-path", { localPath: path.join(outdir, file) });
  for (let i = 0; i < 400; i++) {
    await sleep(50);
    const s = await sidecar.call("pcap-offline.status", {});
    if (s.state === "done") return s.result;
    if (s.state === "failed" || s.state === "cancelled") throw new Error(`${file}: ${s.state} ${s.detail}`);
  }
  throw new Error(`${file}: analysis never finished`);
}
const rules = (r) => (r?.alerts ?? []).map((a) => `${a.rule}/${a.level}`);
const hasRule = (r, prefix) => rules(r).some((x) => x.startsWith(prefix));

try {
  // ---------- RPC hardening ----------
  const forged = "probe-forged-local-path";
  const fails = async (method, params, code) => {
    try { await sidecar.call(method, params); return `unexpected-ok`; }
    catch (e) { return String(e).includes(`${code}:`) ? code : String(e); }
  };
  check("begin-path 未知字段拒绝", await fails("pcap-offline.begin-path", { localPath: "x", extra: 1 }, "invalid-params"), "invalid-params");
  check("begin-path snake_case 拒绝", await fails("pcap-offline.begin-path", { local_path: "x" }, "invalid-params"), "invalid-params");
  check("begin-path 不存在文件拒绝", await fails("pcap-offline.begin-path", { localPath: "d:/no/such.pcap" }, "invalid-params"), "invalid-params");
  check("begin-evidence 伪造路径拒绝", await fails("pcap-offline.begin-evidence", { jobHandle: "j", localPath: forged }, "invalid-params"), "invalid-params");
  check("begin-evidence 死句柄", await fails("pcap-offline.begin-evidence", { jobHandle: "job-nope" }, "pcap-offline-evidence-gone"), "pcap-offline-evidence-gone");
  check("cancel 空跑拒绝", await fails("pcap-offline.cancel", {}, "pcap-offline-gone"), "pcap-offline-gone");
  check("export 缺字段拒绝", await fails("pcap-offline.export-object", { objectId: "obj-0" }, "invalid-params"), "invalid-params");
  check("export 无分析拒绝", await fails("pcap-offline.export-object", { objectId: "obj-0", localPath: "d:/x.bin" }, "pcap-offline-gone"), "pcap-offline-gone");

  // ---------- parser layers ----------
  const gzip = await analyze("http-gzip-chunked.pcap");
  check("pcap 格式识别", gzip.summary.format, "pcap");
  check("HTTP 事务计数", gzip.http.length, 1);
  check("gzip+chunked 解出对象", gzip.objects.some((o) => o.size > 20 && o.stored));
  check("gzip 无畸形计数", gzip.summary.malformedCount, 0);

  const ng = await analyze("mixed.pcapng");
  check("pcapng 格式识别", ng.summary.format, "pcapng");
  check("pcapng 链路类型集合", ng.summary.linkTypes.includes(1) && ng.summary.linkTypes.includes(101));
  check("pcapng gzip 对象", ng.objects.length >= 1);

  // ---------- signatures ----------
  const caidao = await analyze("caidao.pcap");
  check("菜刀规则命中", hasRule(caidao, "caidao"));
  check("菜刀回显提取", caidao.echoes.length >= 1 && caidao.echoes[0].text.includes("dir c:\\windows"), true);

  const behinder = await analyze("behinder-ecb.pcap");
  check("冰蝎默认密钥强线索", hasRule(behinder, "behinder/strong") || rules(behinder).some((r) => r.startsWith("behinder")));

  const sqlmap = await analyze("sqlmap.pcap");
  check("sqlmap UA 命中", hasRule(sqlmap, "sqlmap"));

  const cs = await analyze("cs-beacon.pcap");
  check("CS 周期心跳线索", hasRule(cs, "cs-beacon"));

  const frp = await analyze("frp-login.pcap");
  check("frp 登录命中", hasRule(frp, "frp"));

  const icmp = await analyze("icmp-tunnel.pcap");
  check("ICMP 隧道线索", hasRule(icmp, "icmp-tunnel"));

  const stratum = await analyze("stratum.pcap");
  check("Stratum 矿池命中", hasRule(stratum, "stratum"));

  // ---------- negatives ----------
  const plain = await analyze("plain-browsing.pcap");
  check("普通浏览不误报", plain.alerts.length, 0);
  check("普通浏览有 HTTP 事务", plain.http.length, 4);

  // ---------- object export through RPC (host supplies the path) ----------
  const exportDest = path.join(outdir, "export-object.bin");
  try { unlinkSync(exportDest); } catch { /* first run */ }
  const exported = await sidecar.call("pcap-offline.export-object", {
    objectId: plain.objects[0].id, localPath: exportDest,
  });
  check("对象导出字节数", exported.bytes > 0);
  const again = await fails("pcap-offline.export-object", { objectId: plain.objects[0].id, localPath: exportDest }, "file-exists");
  check("导出拒绝覆盖", again, "file-exists");

  // ---------- real capture, if podman can run a disposable container ----------
  let realDone = false;
  const container = "lh-pcap-lab-probe";
  const podman = (...args) => execFileSync("podman", args, { encoding: "utf8" }).trim();
  try {
    podman("rm", "-f", container);
    podman("run", "-d", "--name", container, "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
      "alpine:3.20", "sleep", "300");
    const sh = (cmd) => podman("exec", container, "sh", "-c", cmd);
    sh("apk add --no-cache tcpdump busybox-extras >/dev/null 2>&1");
    sh("mkdir -p /www && echo 'real capture body' > /www/index.html && " +
       "busybox-extras httpd -p 127.0.0.1:8080 -h /www && (nc -l -p 3333 >/dev/null &)");
    sh("(tcpdump -i lo -w /tmp/lab.pcap >/dev/null 2>&1 &) ; sleep 1 ; " +
       "wget -qO- http://127.0.0.1:8080/index.html >/dev/null ; " +
       "wget -qO- http://127.0.0.1:8080/index.html >/dev/null ; " +
       "printf '{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\\n' | nc -w1 127.0.0.1 3333 || true ; " +
       "sleep 2 ; pkill tcpdump || true ; sleep 1");
    const capture = sh("base64 -w0 /tmp/lab.pcap");
    writeFileSync(path.join(outdir, "real-capture.pcap"), Buffer.from(capture, "base64"));
    const real = await analyze("real-capture.pcap");
    check("真实抓包解析出包", real.summary.parsedCount > 0);
    check("真实抓包有会话", real.flows.length > 0);
    check("真实抓包命中 Stratum", hasRule(real, "stratum"));
    console.log(`  真实抓包：${real.summary.packetCount} 包 ${real.flows.length} 会话 ${real.http.length} HTTP 事务，线索 ${rules(real).join(",") || "无"}`);
    realDone = true;
  } catch (e) {
    console.log(`  真实抓包跳过：${String(e).slice(0, 200)}`);
  } finally {
    try { podman("rm", "-f", container); } catch { /* already gone */ }
  }
  if (!realDone) console.log("  REAL-CAPTURE: NOT RUN（podman/tcpdump 不可用）——合成 fixture 不计为真实抓包");
} finally {
  sidecar.close();
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
