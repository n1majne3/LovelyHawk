// Local SSH port forwarding on a real target: a loopback listener on the
// workstation tunnels to a service bound on the target's own loopback.
//   1. forward to a private 127.0.0.1:8080 service, fetch the body;
//   2. three concurrent fetches land and the counters move;
//   3. a destination not in the target's LISTEN table is refused;
//   4. a destination host that is not loopback is refused;
//   5. a local port already in use is refused;
//   6. the ninth forward on one binding is refused (cap is eight);
//   7. stopping the forward makes the local port refuse connections;
//   8. disconnecting the binding kills the forward.
import net from "node:net";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runId = randomUUID(), name = `lr-pfwd-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-port-forward", runId);
fs.mkdirSync(evidence, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(path.dirname(evidence), "data-"));
const checks = [];
let containerId, sidecar;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function checkError(label, promise, needle) {
  return promise.then(
    () => { checks.push({ label, passed: false }); console.log(`FAIL ${label}`); throw new Error(label); },
    (error) => check(label, String(error?.message ?? error).includes(needle)),
  );
}
const podman = (...args) => execFileSync("podman", [...args], { encoding: "utf8", windowsHide: true, timeout: 420_000, maxBuffer: 2 * 1024 * 1024 }).trim();
const wslVm = (...args) => execFileSync("wsl.exe", ["-d", "podman-machine-default", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000 }).replace(/\0/gu, "").trim();
function owned(id, label) {
  const current = JSON.parse(podman("inspect", id))[0];
  if (current.Id !== id || ![label, `/${label}`].includes(current.Name) ||
    current.HostConfig.Privileged || (current.Mounts ?? []).length !== 0) throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(containerId, name); return podman("exec", containerId, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { const hit = await fn(); if (hit) return hit; await sleep(100); } throw new Error(`Timed out: ${label}`); }
const MARKER = `lovelyhawk-forward-${runId.slice(0, 8)}`;
// agent:false forces a fresh TCP connection per fetch — a pooled socket would
// measure Node's keep-alive against busybox httpd's close-per-request, not
// the forward's ability to carry concurrent channels.
const freshAgent = new http.Agent({ keepAlive: false });
function getBody(port) {
  return new Promise((resolve, reject) => {
    const request = http.get(
      { host: "127.0.0.1", port, path: "/marker.txt", agent: freshAgent, timeout: 15_000 },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      },
    );
    request.on("timeout", () => request.destroy(new Error("fetch timeout")));
    request.on("error", reject);
  });
}
const localPortOf = (forward) => Number(forward.localAddress.split(":")[1]);
const start = (binding, localPort, host, port) =>
  sidecar.call("port-forward.start", { bindingHandle: binding, localPort, destinationHost: host, destinationPort: port });

try {
  const host = wslVm("ip", "-4", "addr", "show", "eth0").match(/inet (\d+\.\d+\.\d+\.\d+)/u)[1];
  podman("image", "inspect", "docker.io/library/debian:12-slim", "--format", "{{.Id}}");
  const sshPort = 2229;
  containerId = podman("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "512m", "--cpus", "1", "--network", "host", "docker.io/library/debian:12-slim", "sleep", "3600");
  owned(containerId, name);
  onHost("sh", "-c", "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq dropbear-bin busybox-static netcat-openbsd python3-minimal >/dev/null 2>&1");
  onHost("sh", "-c", "echo 'root:LabRoot#2026' | chpasswd; mkdir -p /etc/dropbear; dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key");
  onHost("sh", "-c", `dropbear -E -p ${sshPort}`);
  // A private service on the target's own loopback, not published anywhere.
  // ThreadingHTTPServer accepts concurrent clients; busybox httpd serializes
  // accepts on a short backlog, which would measure the fixture, not the
  // forward.
  onHost("sh", "-c", `mkdir -p /srv/www && printf '%s\\n' '${MARKER}' > /srv/www/marker.txt && cd /srv/www && ` +
    `printf '%s\\n' 'from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler' 'ThreadingHTTPServer.request_queue_size = 64' ` +
    `'ThreadingHTTPServer(("127.0.0.1", 8080), SimpleHTTPRequestHandler).serve_forever()' > /tmp/serve.py && ` +
    "nohup python3 /tmp/serve.py >/tmp/httpd.log 2>&1 &");
  await until(() => { try { onHost("nc", "-z", "127.0.0.1", String(sshPort)); return true; } catch { return false; } }, "dropbear listening", 30_000);
  await until(() => { try { return onHost("sh", "-c", "busybox wget -qO- http://127.0.0.1:8080/marker.txt").includes(MARKER); } catch { return false; } }, "httpd serving", 60_000);

  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port: sshPort, username: "root", password: "LabRoot#2026", id: runId, name });
  if (connected.stage !== "connected") throw new Error(JSON.stringify(connected));
  const binding = connected.bindingHandle;
  check("connects to the forward fixture", true);

  // 1. Forward and fetch the marker body through the tunnel.
  const forward = await start(binding, 0, "127.0.0.1", 8080);
  check("forward reports a loopback local address", /^127\.0\.0\.1:\d+$/u.test(forward.localAddress) && forward.destination === "127.0.0.1:8080");
  const body = await until(async () => { try { return await getBody(localPortOf(forward)); } catch { return false; } }, "first fetch through the forward");
  check("fetched the marker through the forward", body.includes(MARKER));

  // The service must take concurrent clients for the tunnel test to mean
  // anything; check it on the target itself first.
  const localConcurrency = onHost("sh", "-c", "busybox wget -qO- http://127.0.0.1:8080/marker.txt & busybox wget -qO- http://127.0.0.1:8080/marker.txt & busybox wget -qO- http://127.0.0.1:8080/marker.txt & wait");
  check("the fixture serves three concurrent local clients", localConcurrency.split("\n").filter((line) => line.trim() === MARKER).length === 3);

  // 2. Three concurrent fetches over raw sockets. A loopback-intercepting
  // proxy on this host (FlClash TUN; reproduced against a plain local HTTP
  // server with no forward or SSH involved) delivers the payload but mangles
  // the FIN/RST close on roughly half of concurrent connections, so a
  // complete body counts even on a dirty close and each fetch retries.
  const rawFetch = (port, tag) => new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    const chunks = [];
    socket.setTimeout(15_000, () => socket.destroy(new Error(`${tag}: socket timeout`)));
    socket.on("connect", () => { console.log(`  ${tag} connected`); socket.write("GET /marker.txt HTTP/1.0\r\nHost: x\r\n\r\n"); });
    socket.on("data", (chunk) => { console.log(`  ${tag} +${chunk.length}B`); chunks.push(chunk); });
    socket.on("close", (hadError) => {
      console.log(`  ${tag} close error=${hadError}`);
      const text = Buffer.concat(chunks).toString("utf8");
      if (text.includes(MARKER)) resolve(text); else reject(new Error(`${tag}: incomplete response`));
    });
    socket.on("end", () => console.log(`  ${tag} done`));
    socket.on("error", () => {});
  });
  const fetchWithRetry = async (port, tag) => {
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      try { return await rawFetch(port, `${tag}-try${attempt}`); }
      catch (error) { if (attempt === 5) throw error; }
    }
    return "";
  };
  const firstAttempt = await Promise.allSettled([1, 2, 3].map((n) => rawFetch(localPortOf(forward), `fetch${n}`)));
  const firstHits = firstAttempt.filter((result) => result.status === "fulfilled" && result.value.includes(MARKER)).length;
  console.log(`  first-attempt concurrent successes: ${firstHits}/3`);
  check("concurrent first attempt reaches the fixture at least once", firstHits >= 1);
  const bodies = await Promise.all([1, 2, 3].map((n) => fetchWithRetry(localPortOf(forward), `fetch${n}`)))
    .catch(async (error) => {
      const list = await sidecar.call("port-forward.list", { bindingHandle: binding });
      console.log("forward state after concurrent failure:", JSON.stringify(list));
      throw error;
    });
  check("three concurrent fetches land", bodies.every((text) => text.includes(MARKER)));
  const listed = await sidecar.call("port-forward.list", { bindingHandle: binding });
  const me = listed.find((entry) => entry.forwardHandle === forward.forwardHandle);
  check("list shows the forward with moved counters", me !== undefined && BigInt(me.bytesIn) > 0n && BigInt(me.bytesOut) > 0n);

  // 3-4. Destination rules: loopback is always allowed; a non-loopback
  // address:port must appear in the target's LISTEN table. The dropbear
  // listener is on 0.0.0.0, so the target's own eth0 address at the SSH port
  // qualifies; the same host at a port nobody listens on does not, and nor
  // does an address off the target entirely.
  const targetIp = onHost("sh", "-c", "hostname -I | awk '{print $1}'");
  const sshForward = await start(binding, 0, targetIp, sshPort);
  const banner = await new Promise((resolve, reject) => {
    const socket = net.createConnection(localPortOf(sshForward), "127.0.0.1");
    socket.setTimeout(10_000, () => socket.destroy(new Error("banner timeout")));
    socket.once("data", (data) => { socket.destroy(); resolve(data.toString("utf8")); });
    socket.on("error", reject);
  });
  check("a LISTEN-table destination on the target's own address forwards", banner.includes("SSH-"));
  await sidecar.call("port-forward.stop", { bindingHandle: binding, forwardHandle: sshForward.forwardHandle });
  await checkError("a destination not in the LISTEN table is refused", start(binding, 0, targetIp, 9090), "destination");
  await checkError("a destination off the target is refused", start(binding, 0, "10.0.0.9", 8080), "destination");

  // 5. Local port already in use on the workstation.
  const taken = net.createServer();
  await new Promise((resolve) => taken.listen(0, "127.0.0.1", resolve));
  const takenPort = taken.address().port;
  await checkError("a local port already in use is refused", start(binding, takenPort, "127.0.0.1", 8080), "port");
  await new Promise((resolve) => taken.close(resolve));

  // 6. Eight is the cap on one binding.
  const extras = [];
  for (let index = 0; index < 7; index += 1) extras.push(await start(binding, 0, "127.0.0.1", 8080));
  await checkError("a ninth forward is refused", start(binding, 0, "127.0.0.1", 8080), "capacity");
  for (const extra of extras) await sidecar.call("port-forward.stop", { bindingHandle: binding, forwardHandle: extra.forwardHandle });
  check("the extra forwards stop cleanly", (await sidecar.call("port-forward.list", { bindingHandle: binding })).length === 1);

  // 7. Stop: the local port refuses afterwards.
  await sidecar.call("port-forward.stop", { bindingHandle: binding, forwardHandle: forward.forwardHandle });
  check("the stopped forward leaves the list", (await sidecar.call("port-forward.list", { bindingHandle: binding })).length === 0);
  let refused = false;
  for (let attempt = 0; attempt < 20 && !refused; attempt += 1) {
    try { await getBody(localPortOf(forward)); } catch { refused = true; }
    if (!refused) await sleep(100);
  }
  check("after stop the local port refuses", refused);

  // 8. A live forward dies with its binding.
  const doomed = await start(binding, 0, "127.0.0.1", 8080);
  const doomedPort = localPortOf(doomed);
  check("the new forward answers", (await getBody(doomedPort)).includes(MARKER));
  await sidecar.call("ssh.binding.disconnect", { bindingHandle: binding });
  refused = false;
  for (let attempt = 0; attempt < 30 && !refused; attempt += 1) {
    try { await getBody(doomedPort); } catch { refused = true; }
    if (!refused) await sleep(100);
  }
  check("disconnecting the binding kills the forward", refused);
  await checkError("listing on a dead binding fails", sidecar.call("port-forward.list", { bindingHandle: binding }), "");
} catch (error) {
  console.error(error);
  if (sidecar !== undefined) console.error("sidecar stderr tail:", sidecar.stderr.slice(-40).join(""));
} finally {
  try { sidecar?.close(); } catch { /* already gone */ }
  if (containerId !== undefined) { try { podman("rm", "-f", containerId); } catch { /* already gone */ } }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ checks }, null, 2));
  console.log(`${checks.filter((entry) => entry.passed).length}/${checks.length} checks passed`);
}
