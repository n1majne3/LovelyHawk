#!/usr/bin/env node
/**
 * Synthetic pcap/pcapng fixture generator for the offline traffic analyzer.
 * Every fixture is built byte-for-byte here — Ethernet/IPv4/TCP/ICMP framing,
 * checksums, and both container formats — so tests never depend on a capture
 * tool. Usage: node tools/lab/make-pcap-fixtures.mjs [outdir]
 */
import { gzipSync } from "node:zlib";
import { createCipheriv as cipher } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// ---------------- L2/L3/L4 framing ----------------

function csum16(data) {
  let sum = 0;
  for (let i = 0; i + 1 < data.length; i += 2) sum += data.readUInt16BE(i);
  if (data.length % 2) sum += data[data.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function eth(payload, ethertype = 0x0800) {
  const f = Buffer.alloc(14);
  f.writeUInt16BE(ethertype, 12);
  return Buffer.concat([f, payload]);
}

function ipv4(src, dst, proto, l4) {
  const p = Buffer.alloc(20);
  p[0] = 0x45;
  p.writeUInt16BE(20 + l4.length, 2);
  p[8] = 64;
  p[9] = proto;
  p.set(src, 12);
  p.set(dst, 16);
  p.writeUInt16BE(csum16(p), 10);
  return Buffer.concat([p, l4]);
}

function tcp(src, sport, dst, dport, seq, flags, payload) {
  const t = Buffer.alloc(20);
  t.writeUInt16BE(sport, 0);
  t.writeUInt16BE(dport, 2);
  t.writeUInt32BE(seq >>> 0, 4);
  t[12] = 0x50;
  t[13] = flags;
  t.writeUInt16BE(65535, 14);
  return eth(ipv4(src, dst, 6, Buffer.concat([t, payload])));
}

function udp(src, sport, dst, dport, payload) {
  const u = Buffer.alloc(8);
  u.writeUInt16BE(sport, 0);
  u.writeUInt16BE(dport, 2);
  u.writeUInt16BE(8 + payload.length, 4);
  return eth(ipv4(src, dst, 17, Buffer.concat([u, payload])));
}

function icmpEcho(src, dst, request, id, seq, payload) {
  const p = Buffer.alloc(8);
  p[0] = request ? 8 : 0;
  p.writeUInt16BE(id, 4);
  p.writeUInt16BE(seq, 6);
  const full = Buffer.concat([p, payload]);
  full.writeUInt16BE(csum16(full), 2);
  return eth(ipv4(src, dst, 1, full));
}

// ---------------- containers ----------------

function pcapRecord(sec, usec, payload) {
  const r = Buffer.alloc(16);
  r.writeUInt32LE(sec, 0);
  r.writeUInt32LE(usec, 4);
  r.writeUInt32LE(payload.length, 8);
  r.writeUInt32LE(payload.length, 12);
  return Buffer.concat([r, payload]);
}

function pcapFile(linktype, records) {
  const h = Buffer.alloc(24);
  h.set([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0], 0);
  h.writeUInt32LE(65535, 16);
  h.writeUInt32LE(linktype, 20);
  return Buffer.concat([h, ...records]);
}

function block(type, body) {
  const pad = Buffer.alloc((4 - (body.length % 4)) % 4);
  const len = 12 + body.length + pad.length;
  const b = Buffer.alloc(len);
  b.writeUInt32LE(type, 0);
  b.writeUInt32LE(len, 4);
  b.set(body, 8);
  b.set(pad, 8 + body.length);
  b.writeUInt32LE(len, len - 4);
  return b;
}

function pcapngFile(packets /* [{tsUs, data, linktype?}] */) {
  const shb = block(0x0a0d0d0a, (() => {
    const b = Buffer.alloc(16);
    b.set([0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0], 0);
    return b;
  })());
  const idbs = [];
  const epbs = [];
  const types = new Map();
  for (const p of packets) {
    const lt = p.linktype ?? 1;
    if (!types.has(lt)) {
      types.set(lt, types.size);
      const idb = Buffer.alloc(8);
      idb.writeUInt16LE(lt, 0);
      idb.writeUInt32LE(65535, 4);
      idbs.push(block(1, idb));
    }
    const epb = Buffer.alloc(20 + p.data.length);
    const tsUs = BigInt(p.tsUs);
    epb.writeUInt32LE(types.get(lt), 0);
    epb.writeUInt32LE(Number(tsUs >> 32n), 4);
    epb.writeUInt32LE(Number(tsUs & 0xffffffffn), 8);
    epb.writeUInt32LE(p.data.length, 12);
    epb.writeUInt32LE(p.data.length, 16);
    epb.set(p.data, 20);
    epbs.push(block(6, epb));
  }
  return Buffer.concat([shb, ...idbs, ...epbs]);
}

// ---------------- payloads ----------------

const CLIENT = [10, 0, 0, 9];
const SERVER = [10, 0, 0, 5];
const SEC = 1_700_000_000;

function httpExchange({ method = "GET", uri = "/", reqHeaders = "", reqBody = Buffer.alloc(0),
  status = "200 OK", respHeaders = "", respBody = Buffer.alloc(0), seqA = 1000, seqB = 5000, usec = 0 }) {
  const reqLen = reqBody.length > 0 ? `Content-Length: ${reqBody.length}\r\n` : "";
  const req = Buffer.from(`${method} ${uri} HTTP/1.1\r\nHost: target.local\r\n${reqHeaders}${reqLen}\r\n`);
  const head = Buffer.concat([req, reqBody]);
  const chunked = /transfer-encoding:\s*chunked/i.test(respHeaders);
  const respLen = respBody.length > 0 && !chunked ? `Content-Length: ${respBody.length}\r\n` : "";
  const resp = Buffer.concat([
    Buffer.from(`HTTP/1.1 ${status}\r\n${respHeaders}${respLen}\r\n`), respBody]);
  return [
    pcapRecord(SEC, usec, tcp(CLIENT, 40000, SERVER, 80, seqA, 0x18, head)),
    pcapRecord(SEC, usec + 50000, tcp(SERVER, 80, CLIENT, 40000, seqB, 0x18, resp)),
  ];
}

// 1. HTTP gzip + chunked
function httpGzipChunked() {
  const gz = gzipSync(Buffer.from("<html><body>gzip chunked fixture</body></html>"));
  const chunkLine = Buffer.from(gz.length.toString(16) + "\r\n");
  const body = Buffer.concat([chunkLine, gz, Buffer.from("\r\n0\r\n\r\n")]);
  return pcapFile(1, httpExchange({
    uri: "/data.gz",
    respHeaders: "Content-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
    respBody: body,
  }));
}

// 2. 菜刀 (caidao): z0/z1 base64 params + X@Y echo
function caidao() {
  const reqBody = Buffer.from("pass=1&z0=" + Buffer.from("@eval($_POST[z1]);").toString("base64") +
    "&z1=" + Buffer.from("system('dir');").toString("base64"));
  return pcapFile(1, httpExchange({
    method: "POST", uri: "/shell.php",
    reqHeaders: "Content-Type: application/x-www-form-urlencoded\r\n",
    reqBody,
    respHeaders: "Content-Type: text/html\r\n",
    respBody: Buffer.from("X@Ydir c:\\windows\r\nX@Y"),
  }));
}

// 3. 冰蝎 (Behinder): POST octet-stream body = AES-128-ECB(default key) of PHP
function behinder() {
  const key = Buffer.from("e45e329feb5d925b", "utf8");
  const plain = Buffer.from("@error_reporting(0);$a=$_POST['x'];eval($a);".padEnd(64, " "));
  const ecb = cipher("aes-128-ecb", key, null);
  ecb.setAutoPadding(true);
  const body = Buffer.concat([ecb.update(plain), ecb.final()]);
  return pcapFile(1, httpExchange({
    method: "POST", uri: "/images/logo.php",
    reqHeaders: "Content-Type: application/octet-stream\r\n",
    reqBody: body,
    respBody: Buffer.concat([cipher("aes-128-ecb", key, null).update(Buffer.alloc(16)) ?? Buffer.alloc(16)]),
  }));
}

// 4. sqlmap
function sqlmap() {
  return pcapFile(1, httpExchange({
    uri: "/item.php?id=1%20AND%20GTID_SUBSET(CONCAT(0x71,0x70,0x62,0x7a,0x71),31337)",
    reqHeaders: "User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\n",
    respBody: Buffer.from("ok"),
  }));
}

// 5. CS-like periodic beacon: 6 GETs to /__utm.gif, ~2s apart, low jitter, base64 cookie
function csBeacon() {
  const records = [];
  for (let i = 0; i < 6; i++) {
    records.push(...httpExchange({
      uri: "/__utm.gif",
      reqHeaders: `Cookie: session=${Buffer.from("beacon-data-" + i).toString("base64")}\r\n`,
      respBody: Buffer.from("GIF89a"),
      seqA: 1000 + i * 200, seqB: 5000 + i * 200,
      usec: i * 2_000_000 + (i % 2) * 40_000,
    }));
  }
  return pcapFile(1, records);
}

// 6. frp login JSON on a non-HTTP port
function frpLogin() {
  const login = Buffer.from(JSON.stringify({
    type: "login", version: "0.51.3", hostname: "ops-pc",
    privilege_key: "secret-key", run_id: "runid123", pool_count: 1,
  }) + "\n");
  return pcapFile(1, [
    pcapRecord(SEC, 0, tcp(CLIENT, 51000, SERVER, 7000, 700, 0x18, login)),
    pcapRecord(SEC, 50_000, tcp(SERVER, 7000, CLIENT, 51000, 900, 0x18, Buffer.from('{"type":"login_resp","version":"0.51.3"}\n'))),
  ]);
}

// 7. ICMP tunnel: large varied echo payloads to one peer
function icmpTunnel() {
  const records = [];
  for (let i = 0; i < 8; i++) {
    const payload = Buffer.alloc(200);
    for (let j = 0; j < payload.length; j++) payload[j] = (i * 37 + j * 13) & 0xff;
    records.push(pcapRecord(SEC, i * 100_000, icmpEcho(CLIENT, SERVER, true, 0x1234, i, payload)));
    records.push(pcapRecord(SEC, i * 100_000 + 20_000, icmpEcho(SERVER, CLIENT, false, 0x1234, i, payload)));
  }
  return pcapFile(1, records);
}

// 8. Stratum mining JSON-RPC
function stratum() {
  return pcapFile(1, [
    pcapRecord(SEC, 0, tcp(CLIENT, 40001, SERVER, 3333, 300, 0x18,
      Buffer.from('{"id":1,"method":"mining.subscribe","params":[]}\n'))),
    pcapRecord(SEC, 50_000, tcp(SERVER, 3333, CLIENT, 40001, 800, 0x18,
      Buffer.from('{"id":1,"result":[],"error":null}\n'))),
    pcapRecord(SEC, 100_000, tcp(CLIENT, 40001, SERVER, 3333, 340, 0x18,
      Buffer.from('{"id":2,"method":"mining.authorize","params":["wallet.worker","x"]}\n'))),
  ]);
}

// 9. pcapng variant: same HTTP exchange in pcapng, two interfaces (eth + raw-ip)
function pcapngMixed() {
  const gz = gzipSync(Buffer.from("pcapng body"));
  const rawIpGet = (() => {
    const req = Buffer.from("GET /raw HTTP/1.1\r\nHost: a\r\n\r\n");
    const t = Buffer.alloc(20);
    t.writeUInt16BE(40002, 0); t.writeUInt16BE(80, 2); t.writeUInt32BE(1, 4);
    t[12] = 0x50; t[13] = 0x18;
    return ipv4(CLIENT, SERVER, 6, Buffer.concat([t, req]));
  })();
  const pkts = [
    { tsUs: 0n, data: tcp(CLIENT, 40000, SERVER, 80, 1000, 0x18, Buffer.from("GET / HTTP/1.1\r\nHost: x\r\n\r\n")), linktype: 1 },
    { tsUs: 50_000n, data: tcp(SERVER, 80, CLIENT, 40000, 5000, 0x18, Buffer.from(`HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${gz.length}\r\n\r\n`)), linktype: 1 },
    { tsUs: 60_000n, data: tcp(SERVER, 80, CLIENT, 40000, 5060, 0x18, gz), linktype: 1 },
    { tsUs: 100_000n, data: rawIpGet, linktype: 101 },
  ];
  return pcapngFile(pkts);
}

// 10. ordinary browsing — the negative control
function plainBrowsing() {
  const records = [];
  const uris = ["/index.html", "/style.css", "/script.js", "/logo.png"];
  uris.forEach((uri, i) => {
    records.push(...httpExchange({ uri, respBody: Buffer.from("x".repeat(500)), seqA: 1000 + i * 500, seqB: 5000 + i * 500, usec: i * 3_700_000 }));
  });
  return pcapFile(1, records);
}

const FIXTURES = {
  "http-gzip-chunked.pcap": httpGzipChunked,
  "caidao.pcap": caidao,
  "behinder-ecb.pcap": behinder,
  "sqlmap.pcap": sqlmap,
  "cs-beacon.pcap": csBeacon,
  "frp-login.pcap": frpLogin,
  "icmp-tunnel.pcap": icmpTunnel,
  "stratum.pcap": stratum,
  "mixed.pcapng": pcapngMixed,
  "plain-browsing.pcap": plainBrowsing,
};

const outdir = process.argv[2] ?? join("target", "pcap-fixtures");
mkdirSync(outdir, { recursive: true });
for (const [name, build] of Object.entries(FIXTURES)) {
  const bytes = build();
  writeFileSync(join(outdir, name), bytes);
  console.log(`${name}\t${bytes.length} bytes`);
}
console.log(`wrote ${Object.keys(FIXTURES).length} fixtures to ${outdir}`);
