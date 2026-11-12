//! Offline pcap/pcapng analysis: containers, TCP reassembly, HTTP/1.x, object
//! extraction and malicious-traffic leads. Fully self-written — no external
//! dissector. Every malformed or truncated input is counted and reported;
//! nothing here may panic on hostile bytes.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_STREAM_BYTES: usize = 128 * 1024 * 1024;
const MAX_FLOWS: usize = 20_000;
const MAX_PACKETS: u64 = 4_000_000;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_DECOMPRESSED: usize = 32 * 1024 * 1024;
const MAX_OBJECTS: usize = 500;
const MAX_OBJECT_STORE: usize = 32 * 1024 * 1024;
const MAX_HTTP_TXS: usize = 1_000;
const MAX_ALERTS: usize = 500;
const MAX_ECHOES: usize = 100;
const MAX_ECHO_TEXT: usize = 4096;
const MAX_GAPS_PER_STREAM: usize = 64;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub const BEHINDER_DEFAULT_KEY: &str = "e45e329feb5d925b";

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapSummary {
    pub format: String,
    pub link_types: Vec<u32>,
    pub packet_count: u64,
    pub parsed_count: u64,
    pub malformed_count: u64,
    pub fragment_count: u64,
    pub flow_cap_hit: bool,
    pub stream_cap_hit: bool,
    pub packet_cap_hit: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    pub id: u64,
    pub proto: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub packets: u64,
    pub bytes: u64,
    pub first_ms: i64,
    pub last_ms: i64,
    pub tcp_gaps: u32,
    pub stream_truncated: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpTransaction {
    pub id: u64,
    pub flow_id: u64,
    pub method: String,
    pub uri: String,
    pub host: String,
    pub status: u32,
    pub req_content_type: String,
    pub resp_content_type: String,
    pub req_body_size: u64,
    pub resp_body_size: u64,
    pub req_object_id: Option<String>,
    pub resp_object_id: Option<String>,
    pub req_headers: Vec<String>,
    pub resp_headers: Vec<String>,
    pub incomplete: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapObjectInfo {
    pub id: String,
    pub sha256: String,
    pub size: u64,
    pub content_type: String,
    pub uri: String,
    pub kind: String,
    pub stored: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapAlert {
    pub rule: String,
    /// "lead" | "strong" | "weak" — a lead with the rule stated, never a verdict.
    pub level: String,
    pub message: String,
    pub flow_id: Option<u64>,
    pub tx_id: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaidaoEcho {
    pub tx_id: Option<u64>,
    pub flow_id: u64,
    /// "x@y" or "arrow" — which caidao marker wrapped the echo.
    pub marker: String,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct PcapAnalysis {
    pub summary: PcapSummary,
    pub flows: Vec<FlowSummary>,
    pub http: Vec<HttpTransaction>,
    pub objects: Vec<PcapObjectInfo>,
    pub alerts: Vec<PcapAlert>,
    pub echoes: Vec<CaidaoEcho>,
    /// Object bytes kept for host export; never serialized to the page.
    pub object_bytes: HashMap<String, Vec<u8>>,
}

// ---------------------------------------------------------------- packets

struct RawPacket {
    ts_ms: i64,
    linktype: u32,
    data: Vec<u8>,
}

fn parse_container(
    data: &[u8],
    cancelled: &AtomicBool,
    progress: &dyn Fn(u64),
    warn: &mut Vec<String>,
    malformed: &mut u64,
) -> Vec<RawPacket> {
    if data.len() < 4 {
        *malformed += 1;
        warn.push("文件太短，既不是 pcap 也不是 pcapng。".into());
        return Vec::new();
    }
    match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => parse_pcap(data, true, false, cancelled, progress, malformed),
        [0xa1, 0xb2, 0xc3, 0xd4] => parse_pcap(data, false, false, cancelled, progress, malformed),
        [0x4d, 0x3c, 0xb2, 0xa1] => parse_pcap(data, true, true, cancelled, progress, malformed),
        [0xa1, 0xb2, 0x3c, 0x4d] => parse_pcap(data, false, true, cancelled, progress, malformed),
        [0x0a, 0x0d, 0x0d, 0x0a] => parse_pcapng(data, cancelled, progress, warn, malformed),
        _ => {
            *malformed += 1;
            warn.push("无法识别的抓包文件格式。".into());
            Vec::new()
        }
    }
}

fn rd16(data: &[u8], off: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}
fn rd32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

fn parse_pcap(
    data: &[u8],
    le: bool,
    nano: bool,
    cancelled: &AtomicBool,
    progress: &dyn Fn(u64),
    malformed: &mut u64,
) -> Vec<RawPacket> {
    let mut out = Vec::new();
    if data.len() < 24 {
        *malformed += 1;
        return out;
    }
    let linktype = rd32(data, 20, le).unwrap_or(1);
    let mut off = 24usize;
    while off + 16 <= data.len() {
        if cancelled.load(Ordering::Relaxed) || out.len() as u64 >= MAX_PACKETS {
            break;
        }
        let ts = rd32(data, off, le).unwrap_or(0);
        let sub = rd32(data, off + 4, le).unwrap_or(0);
        let incl = rd32(data, off + 8, le).unwrap_or(0) as usize;
        if incl > 64 * 1024 * 1024 {
            *malformed += 1;
            break;
        }
        let body = off + 16;
        if body + incl > data.len() {
            *malformed += 1; // trailing truncated record
            break;
        }
        let ts_ms = ts as i64 * 1000
            + if nano {
                sub as i64 / 1_000_000
            } else {
                sub as i64 / 1_000
            };
        out.push(RawPacket {
            ts_ms,
            linktype,
            data: data[body..body + incl].to_vec(),
        });
        off = body + incl;
        if off % (64 * 1024) < 16 {
            progress(off as u64);
        }
    }
    out
}

fn parse_pcapng(
    data: &[u8],
    cancelled: &AtomicBool,
    progress: &dyn Fn(u64),
    warn: &mut Vec<String>,
    malformed: &mut u64,
) -> Vec<RawPacket> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut le = true;
    let mut ifaces: Vec<(u32, u64)> = Vec::new(); // (linktype, ts resolution divisor)
    while off + 12 <= data.len() {
        if cancelled.load(Ordering::Relaxed) || out.len() as u64 >= MAX_PACKETS {
            break;
        }
        let block_type = rd32(data, off, le).unwrap_or(0);
        let block_len = rd32(data, off + 4, le).unwrap_or(0) as usize;
        if block_len < 12 || off + block_len > data.len() {
            *malformed += 1;
            break;
        }
        match block_type {
            0x0a0d_0d0a => {
                // SHB: byte-order magic at body start.
                if off + 12 <= data.len() {
                    le = matches!(&data[off + 8..off + 12], [0x4d, 0x3c, 0x2b, 0x1a]);
                    ifaces.clear();
                }
            }
            0x0000_0001 => {
                // IDB
                let linktype = rd16(data, off + 8, le).unwrap_or(1) as u32;
                let mut resol = 1_000_000u64;
                // options start at off+16, padded to 32-bit
                let mut o = off + 16;
                while o + 4 <= off + block_len - 4 {
                    let code = rd16(data, o, le).unwrap_or(0);
                    let len = rd16(data, o + 2, le).unwrap_or(0) as usize;
                    if code == 0 {
                        break;
                    }
                    if code == 9 && len >= 1 {
                        let raw = data[o + 4];
                        resol = if raw & 0x80 != 0 {
                            1u64 << (raw & 0x7f).min(62)
                        } else {
                            10u64.pow((raw & 0x7f).min(9) as u32)
                        };
                    }
                    o += 4 + ((len + 3) & !3);
                }
                ifaces.push((linktype, resol));
            }
            0x0000_0006 => {
                // EPB
                if let (Some(iface), Some(hi), Some(lo), Some(caplen)) = (
                    rd32(data, off + 8, le),
                    rd32(data, off + 12, le),
                    rd32(data, off + 16, le),
                    rd32(data, off + 20, le),
                ) {
                    let caplen = caplen as usize;
                    let body = off + 28;
                    if body + caplen > off + block_len || caplen > 64 * 1024 * 1024 {
                        *malformed += 1;
                    } else {
                        let (linktype, resol) = ifaces
                            .get(iface as usize)
                            .copied()
                            .unwrap_or((1, 1_000_000));
                        let ticks = ((hi as u64) << 32) | lo as u64;
                        let ts_ms = (ticks * 1000 / resol.max(1)) as i64;
                        out.push(RawPacket {
                            ts_ms,
                            linktype,
                            data: data[body..body + caplen].to_vec(),
                        });
                    }
                } else {
                    *malformed += 1;
                }
            }
            0x0000_0003 => {
                // SPB
                if let (Some((linktype, _)), Some(_orig)) =
                    (ifaces.first().copied(), rd32(data, off + 8, le))
                {
                    let caplen = (block_len - 16).min(64 * 1024 * 1024);
                    out.push(RawPacket {
                        ts_ms: 0,
                        linktype,
                        data: data[off + 12..off + 12 + caplen].to_vec(),
                    });
                } else {
                    *malformed += 1;
                }
            }
            _ => {}
        }
        off += block_len;
        if off % (64 * 1024) < 12 {
            progress(off as u64);
        }
    }
    if ifaces.is_empty() && !out.is_empty() {
        warn.push("pcapng 缺少接口描述块，链路类型按以太网处理。".into());
    }
    out
}

// ---------------------------------------------------------------- decode

#[derive(Hash, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Debug)]
struct Endpoint {
    addr: [u8; 16],
    port: u16,
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FlowKey {
    proto: u8,
    a: Endpoint,
    b: Endpoint,
}

#[derive(Debug)]
struct Decoded {
    proto: u8, // 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6
    src: Endpoint,
    dst: Endpoint,
    fragmented: bool,
    icmp_echo: Option<(bool, u16, Vec<u8>)>, // (is_request, id+seq packed, payload)
    tcp: Option<TcpSeg>,
}

#[derive(Debug)]
struct TcpSeg {
    seq: u32,
    /// SYN without ACK — only the connection's opener sends that; SYN+ACK
    /// is the *responder* and must not flip the client direction.
    syn_open: bool,
    payload_start: usize,
    payload_len: usize,
}

fn decode_l3(data: &[u8], off: usize, ethertype: u16) -> Option<Decoded> {
    match ethertype {
        0x0800 => decode_ipv4(data, off),
        0x86dd => decode_ipv6(data, off),
        _ => None,
    }
}

fn decode_ipv4(data: &[u8], off: usize) -> Option<Decoded> {
    let hdr = data.get(off..off + 20)?;
    if hdr[0] >> 4 != 4 {
        return None;
    }
    let ihl = (hdr[0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let total = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let frag = u16::from_be_bytes([hdr[6], hdr[7]]);
    if frag & 0x3fff != 0 {
        // Any MF flag or nonzero offset: counted as a gap, not reassembled.
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src[12..16].copy_from_slice(&hdr[12..16]);
        dst[12..16].copy_from_slice(&hdr[16..20]);
        return Some(Decoded {
            proto: hdr[9],
            src: Endpoint { addr: src, port: 0 },
            dst: Endpoint { addr: dst, port: 0 },
            fragmented: true,
            icmp_echo: None,
            tcp: None,
        });
    }
    let end = (off + total).min(data.len());
    let l4 = off + ihl;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src[12..16].copy_from_slice(&hdr[12..16]);
    dst[12..16].copy_from_slice(&hdr[16..20]);
    decode_l4(data, l4, end, hdr[9], src, dst)
}

fn decode_ipv6(data: &[u8], off: usize) -> Option<Decoded> {
    let hdr = data.get(off..off + 40)?;
    if hdr[0] >> 4 != 6 {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&hdr[8..24]);
    dst.copy_from_slice(&hdr[24..40]);
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let end = (off + 40 + payload_len).min(data.len());
    let mut next = hdr[6];
    let mut cursor = off + 40;
    // Walk extension headers: hop-by-hop 0, routing 43, fragment 44, AH 51,
    // dest-opts 60. ESP 50 stops parsing — payload is encrypted.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let len = (*data.get(cursor + 1)? as usize + 1) * 8;
                next = *data.get(cursor)?;
                cursor += len;
            }
            51 => {
                let len = (*data.get(cursor + 1)? as usize + 2) * 4;
                next = *data.get(cursor)?;
                cursor += len;
            }
            44 => {
                // IPv6 fragment: counted as a gap.
                return Some(Decoded {
                    proto: 59,
                    src: Endpoint { addr: src, port: 0 },
                    dst: Endpoint { addr: dst, port: 0 },
                    fragmented: true,
                    icmp_echo: None,
                    tcp: None,
                });
            }
            50 => return None, // ESP
            _ => break,
        }
        if cursor >= end {
            return None;
        }
    }
    decode_l4(data, cursor, end, next, src, dst)
}

fn decode_l4(
    data: &[u8],
    off: usize,
    end: usize,
    proto: u8,
    src: [u8; 16],
    dst: [u8; 16],
) -> Option<Decoded> {
    match proto {
        6 => {
            let hdr = data.get(off..off + 20)?;
            let doff = ((hdr[12] >> 4) as usize) * 4;
            if doff < 20 || off + doff > end {
                return None;
            }
            let seq = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            let flags = hdr[13];
            let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
            let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
            let payload_start = off + doff;
            Some(Decoded {
                proto,
                src: Endpoint {
                    addr: src,
                    port: sport,
                },
                dst: Endpoint {
                    addr: dst,
                    port: dport,
                },
                fragmented: false,
                icmp_echo: None,
                tcp: Some(TcpSeg {
                    seq,
                    syn_open: flags & 0x12 == 0x02,
                    payload_start,
                    payload_len: end - payload_start,
                }),
            })
        }
        17 => {
            let hdr = data.get(off..off + 8)?;
            let sport = u16::from_be_bytes([hdr[0], hdr[1]]);
            let dport = u16::from_be_bytes([hdr[2], hdr[3]]);
            Some(Decoded {
                proto,
                src: Endpoint {
                    addr: src,
                    port: sport,
                },
                dst: Endpoint {
                    addr: dst,
                    port: dport,
                },
                fragmented: false,
                icmp_echo: None,
                tcp: None,
            })
        }
        1 | 58 => {
            let hdr = data.get(off..off + 8)?;
            let ty = hdr[0];
            let echo = if (proto == 1 && (ty == 8 || ty == 0))
                || (proto == 58 && (ty == 128 || ty == 129))
            {
                let id_seq = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
                Some((
                    ty == 8 || ty == 128,
                    id_seq as u16,
                    data[off + 8..end].to_vec(),
                ))
            } else {
                None
            };
            Some(Decoded {
                proto,
                src: Endpoint { addr: src, port: 0 },
                dst: Endpoint { addr: dst, port: 0 },
                fragmented: false,
                icmp_echo: echo,
                tcp: None,
            })
        }
        _ => None,
    }
}

fn decode_packet(linktype: u32, data: &[u8]) -> Option<Decoded> {
    match linktype {
        1 => {
            // Ethernet (+ up to 2 VLAN tags)
            let mut off = 0usize;
            let mut etype = u16::from_be_bytes([*data.get(12)?, *data.get(13)?]);
            off += 14;
            for _ in 0..2 {
                if etype == 0x8100 || etype == 0x88a8 {
                    etype = u16::from_be_bytes([*data.get(off + 2)?, *data.get(off + 3)?]);
                    off += 4;
                }
            }
            decode_l3(data, off, etype)
        }
        101 => {
            // raw IP
            match data.first()? >> 4 {
                4 => decode_ipv4(data, 0),
                6 => decode_ipv6(data, 0),
                _ => None,
            }
        }
        113 => {
            // Linux SLL: 16B header, protocol at 14
            let etype = u16::from_be_bytes([*data.get(14)?, *data.get(15)?]);
            decode_l3(data, 16, etype)
        }
        276 => {
            // SLL2: 20B header, protocol at 0
            let etype = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            decode_l3(data, 20, etype)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------- TCP reassembly

struct TcpStream {
    chunks: Vec<(u32, Vec<u8>)>,
    buffered: usize,
    capped: bool,
}

impl TcpStream {
    fn add(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() || self.capped {
            return;
        }
        if self.buffered + payload.len() > MAX_STREAM_BYTES {
            self.capped = true;
            return;
        }
        self.buffered += payload.len();
        self.chunks.push((seq, payload.to_vec()));
    }

    /// Assemble ordered by seq with wrap arithmetic; returns (bytes, gaps).
    /// The anchor is the earliest seq under wrap ordering relative to the
    /// first-arriving chunk, so out-of-order captures still reassemble.
    fn assemble(&self) -> (Vec<u8>, Vec<(usize, usize)>) {
        if self.chunks.is_empty() {
            return (Vec::new(), Vec::new());
        }
        let first = self.chunks[0].0;
        let anchor = self
            .chunks
            .iter()
            .map(|c| c.0)
            .min_by_key(|s| s.wrapping_sub(first) as i32)
            .unwrap_or(first);
        let mut chunks: Vec<(u32, &[u8])> = self
            .chunks
            .iter()
            .map(|(s, b)| (*s, b.as_slice()))
            .collect();
        chunks.sort_by_key(|(s, _)| s.wrapping_sub(anchor));
        let mut out = Vec::with_capacity(self.buffered);
        let mut gaps = Vec::new();
        let mut cursor = anchor;
        for (seq, bytes) in chunks {
            let diff = seq.wrapping_sub(cursor) as i32;
            if diff < 0 {
                // Retransmit / overlap: keep the first copy, trim the overlap.
                let overlap = (-diff) as usize;
                if overlap >= bytes.len() {
                    continue;
                }
                out.extend_from_slice(&bytes[overlap..]);
                cursor = cursor.wrapping_add((bytes.len() - overlap) as u32);
            } else {
                if diff > 0 && gaps.len() < MAX_GAPS_PER_STREAM {
                    gaps.push((out.len(), diff as usize));
                }
                out.extend_from_slice(bytes);
                cursor = seq.wrapping_add(bytes.len() as u32);
            }
        }
        (out, gaps)
    }
}

// ---------------------------------------------------------------- HTTP

struct ParsedHeaders {
    fields: Vec<(String, String)>,
    body_start: usize,
}

fn parse_headers(data: &[u8], start: usize) -> Option<(String, ParsedHeaders)> {
    let end = start.checked_add(MAX_HEADER_BYTES)?.min(data.len());
    let window = &data[start..end];
    let pos = window.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = String::from_utf8_lossy(&window[..pos]);
    let mut lines = text.split("\r\n");
    let first = lines.next()?.to_owned();
    let fields = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some((
        first,
        ParsedHeaders {
            fields,
            body_start: start + pos + 4,
        },
    ))
}

fn header<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Read one message body at `pos`; returns (body, next_pos, complete).
fn read_body(
    data: &[u8],
    pos: usize,
    fields: &[(String, String)],
    is_request: bool,
    method: &str,
    status: u32,
) -> (Vec<u8>, usize, bool) {
    if !is_request && (status / 100 == 1 || status == 204 || status == 304 || method == "HEAD") {
        return (Vec::new(), pos, true);
    }
    if let Some(te) = header(fields, "transfer-encoding")
        && te.to_ascii_lowercase().contains("chunked")
    {
        let mut out = Vec::new();
        let mut p = pos;
        loop {
            let Some(line_end) = data[p..(p + 64).min(data.len())]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|i| p + i)
            else {
                return (out, p, false);
            };
            let size_str = String::from_utf8_lossy(&data[p..line_end]);
            let size_str = size_str.split(';').next().unwrap_or("").trim();
            let Ok(size) = usize::from_str_radix(size_str, 16) else {
                return (out, p, false);
            };
            let body_pos = line_end + 2;
            if size == 0 {
                // optional trailers then final CRLF
                let mut t = body_pos;
                loop {
                    let Some(e) = data[t..(t + 4096).min(data.len())]
                        .windows(2)
                        .position(|w| w == b"\r\n")
                        .map(|i| t + i)
                    else {
                        return (out, t, false);
                    };
                    if e == t {
                        return (out, t + 2, true);
                    }
                    t = e + 2;
                }
            }
            if body_pos + size > data.len() || out.len() + size > MAX_DECOMPRESSED {
                return (out, data.len(), false);
            }
            out.extend_from_slice(&data[body_pos..body_pos + size]);
            p = body_pos + size + 2; // skip chunk CRLF
            if p > data.len() {
                return (out, data.len(), false);
            }
        }
    }
    if let Some(cl) = header(fields, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        if pos + cl > data.len() {
            return (data[pos..].to_vec(), data.len(), false);
        }
        return (data[pos..pos + cl].to_vec(), pos + cl, true);
    }
    // No declared length: request bodies default to empty; responses run to EOF.
    if is_request {
        (Vec::new(), pos, true)
    } else {
        (data[pos..].to_vec(), data.len(), true)
    }
}

fn decompress(body: &[u8], encoding: &str) -> Option<Vec<u8>> {
    let encoding = encoding.to_ascii_lowercase();
    let reader: Option<Box<dyn Read>> = if encoding.contains("gzip") {
        Some(Box::new(flate2::read::GzDecoder::new(body)))
    } else if encoding.contains("deflate") {
        Some(Box::new(flate2::read::DeflateDecoder::new(body)))
    } else {
        None
    };
    let mut r = reader?;
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Some(out),
            Ok(n) => {
                if out.len() + n > MAX_DECOMPRESSED {
                    out.extend_from_slice(&buf[..MAX_DECOMPRESSED - out.len()]);
                    return Some(out); // bounded: anti-zip-bomb cap reached
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(_) => return None,
        }
    }
}

const METHODS: [&str; 10] = [
    "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND",
];

fn looks_like_request(data: &[u8]) -> bool {
    METHODS.iter().any(|m| {
        data.len() > m.len() + 1 && &data[..m.len()] == m.as_bytes() && data[m.len()] == b' '
    })
}

// ---------------------------------------------------------------- signatures

fn mostly_printable(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let good = bytes
        .iter()
        .filter(|b| matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
        .count();
    good as f64 / bytes.len() as f64
}

fn aes128_decrypt(key: &[u8; 16], cbc: bool, data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    if data.is_empty() || !data.len().is_multiple_of(16) || data.len() > 4 * 1024 * 1024 {
        return None;
    }
    let cipher = aes::Aes128::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut prev = [0u8; 16];
    for block in data.as_chunks::<16>().0 {
        let mut b = aes::Block::from(*block);
        let plain_prev = prev;
        cipher.decrypt_block(&mut b);
        if cbc {
            for (x, p) in b.iter_mut().zip(plain_prev.iter()) {
                *x ^= p;
            }
            prev.copy_from_slice(block);
        }
        out.extend_from_slice(&b);
    }
    Some(out)
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()
        .filter(|b| !b.is_empty())
}

fn looks_base64(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len().is_multiple_of(4)
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn extract_between<'a>(hay: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = hay.find(open)? + open.len();
    let end = hay[start..].find(close)? + start;
    Some(&hay[start..end])
}

// ---------------------------------------------------------------- driver

struct FlowState {
    id: u64,
    proto: u8,
    a: Endpoint,
    b: Endpoint,
    packets: u64,
    bytes: u64,
    first_ms: i64,
    last_ms: i64,
    tcp: [TcpStream; 2], // 0 = a→b, 1 = b→a
    a_to_b_is_client: bool,
    capped: bool,
}

pub fn analyze_pcap(
    data: &[u8],
    progress: &dyn Fn(u64),
    cancelled: &AtomicBool,
) -> Result<PcapAnalysis, String> {
    if data.len() as u64 > MAX_FILE_BYTES {
        return Err("文件超过 4 GiB 上限。".into());
    }
    let mut warnings = Vec::new();
    let mut malformed = 0u64;
    let format = match &data[..4.min(data.len())] {
        [0x0a, 0x0d, 0x0d, 0x0a] => "pcapng",
        [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0xc3, 0xd4]
        | [0x4d, 0x3c, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d] => "pcap",
        _ => "unknown",
    }
    .to_owned();
    let packets = parse_container(data, cancelled, progress, &mut warnings, &mut malformed);
    if cancelled.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }

    let mut link_types: Vec<u32> = Vec::new();
    let mut flows: HashMap<FlowKey, FlowState> = HashMap::new();
    let mut parsed = 0u64;
    let mut fragments = 0u64;
    let mut flow_cap_hit = false;
    let mut stream_cap_hit = false;
    let packet_cap_hit = packets.len() as u64 >= MAX_PACKETS;
    let mut total_stream_bytes = 0usize;
    let mut next_flow_id = 1u64;
    let mut icmp_echoes: HashMap<[u8; 16], Vec<(bool, Vec<u8>)>> = HashMap::new();
    let mut http_starts: Vec<HttpStart> = Vec::new();

    for pkt in &packets {
        if cancelled.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if !link_types.contains(&pkt.linktype) {
            link_types.push(pkt.linktype);
        }
        let Some(decoded) = decode_packet(pkt.linktype, &pkt.data) else {
            malformed += 1;
            continue;
        };
        if decoded.fragmented {
            fragments += 1;
            continue;
        }
        if let Some((is_request, _id, payload)) = &decoded.icmp_echo {
            icmp_echoes
                .entry(decoded.src.addr)
                .or_default()
                .push((*is_request, payload.clone()));
            parsed += 1;
            continue;
        }
        if decoded.proto != 6 && decoded.proto != 17 {
            continue;
        }
        parsed += 1;
        let (a, b, dir) =
            if (decoded.src.addr, decoded.src.port) <= (decoded.dst.addr, decoded.dst.port) {
                (decoded.src, decoded.dst, 0usize)
            } else {
                (decoded.dst, decoded.src, 1usize)
            };
        let key = FlowKey {
            proto: decoded.proto,
            a,
            b,
        };
        let payload_len = decoded.tcp.as_ref().map(|t| t.payload_len).unwrap_or(0);
        let state = match flows.get_mut(&key) {
            Some(s) => s,
            None => {
                if flows.len() >= MAX_FLOWS {
                    flow_cap_hit = true;
                    continue;
                }
                let id = next_flow_id;
                next_flow_id += 1;
                flows.insert(
                    key,
                    FlowState {
                        id,
                        proto: decoded.proto,
                        a,
                        b,
                        packets: 0,
                        bytes: 0,
                        first_ms: pkt.ts_ms,
                        last_ms: pkt.ts_ms,
                        tcp: [
                            TcpStream {
                                chunks: Vec::new(),
                                buffered: 0,
                                capped: false,
                            },
                            TcpStream {
                                chunks: Vec::new(),
                                buffered: 0,
                                capped: false,
                            },
                        ],
                        a_to_b_is_client: false,
                        capped: false,
                    },
                );
                flows.get_mut(&key).unwrap()
            }
        };
        state.packets += 1;
        state.bytes += payload_len as u64;
        state.first_ms = state.first_ms.min(pkt.ts_ms);
        state.last_ms = state.last_ms.max(pkt.ts_ms);
        if let Some(tcp) = &decoded.tcp {
            // A request line that starts at a segment boundary carries real
            // per-request timing for beacon periodicity.
            let seg = &pkt.data[tcp.payload_start..tcp.payload_start + tcp.payload_len];
            if looks_like_request(seg)
                && let Some((line, hdrs)) = parse_headers(seg, 0)
            {
                let mut parts = line.splitn(3, ' ');
                let _method = parts.next().unwrap_or("");
                let uri = parts.next().unwrap_or("").to_owned();
                let host = header(&hdrs.fields, "host").unwrap_or("").to_owned();
                let cookie = header(&hdrs.fields, "cookie").unwrap_or("").to_owned();
                http_starts.push(HttpStart {
                    host,
                    uri,
                    ts_ms: pkt.ts_ms,
                    cookie,
                });
            }
            if tcp.payload_len > 0 {
                if total_stream_bytes + tcp.payload_len > MAX_TOTAL_STREAM_BYTES {
                    stream_cap_hit = true;
                    state.capped = true;
                } else {
                    let stream = &mut state.tcp[dir];
                    let before = stream.buffered;
                    stream.add(
                        tcp.seq,
                        &pkt.data[tcp.payload_start..tcp.payload_start + tcp.payload_len],
                    );
                    total_stream_bytes += stream.buffered.saturating_sub(before);
                    if stream.capped {
                        stream_cap_hit = true;
                        state.capped = true;
                    }
                }
            }
            if tcp.syn_open && dir == 0 {
                state.a_to_b_is_client = true;
            }
        }
    }

    // ------------------------------------------------ HTTP + signatures
    let mut analysis = PcapAnalysis {
        summary: PcapSummary {
            format,
            link_types,
            packet_count: packets.len() as u64,
            parsed_count: parsed,
            malformed_count: malformed,
            fragment_count: fragments,
            flow_cap_hit,
            stream_cap_hit,
            packet_cap_hit,
            warnings: warnings.clone(),
        },
        ..Default::default()
    };

    let mut tx_seq = 1u64;
    let mut object_seq = 1u64;
    let mut flow_gaps: HashMap<u64, u32> = HashMap::new();

    let mut flow_list: Vec<(&FlowKey, &FlowState)> = flows.iter().collect();
    flow_list.sort_by_key(|(_, s)| s.id);

    for (_key, flow) in &flow_list {
        if cancelled.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if flow.proto != 6 {
            continue;
        }
        let (a2b, gaps_a2b) = flow.tcp[0].assemble();
        let (b2a, gaps_b2a) = flow.tcp[1].assemble();
        flow_gaps.insert(flow.id, (gaps_a2b.len() + gaps_b2a.len()) as u32);
        // HTTP: requests on the client direction, responses on the other.
        let client_dir = if flow.a_to_b_is_client || looks_like_request(&a2b) {
            0
        } else {
            1
        };

        let (req_bytes, resp_bytes) = if client_dir == 0 {
            (&a2b, &b2a)
        } else {
            (&b2a, &a2b)
        };
        if looks_like_request(req_bytes) && analysis.http.len() < MAX_HTTP_TXS {
            parse_http_stream(
                flow.id,
                req_bytes,
                resp_bytes,
                &mut analysis,
                &mut tx_seq,
                &mut object_seq,
            );
        }
        // frp + stratum scan on both directions.
        scan_tcp_text(flow, &a2b, &b2a, &mut analysis);
    }

    // ICMP tunnel lead
    detect_icmp_tunnel(&icmp_echoes, &mut analysis);
    // Cobalt Strike periodic beacon lead (real per-request timestamps)
    detect_cs_beacon(&http_starts, &mut analysis);

    // Flow summaries last (after HTTP knows flow ids)
    for (_, flow) in &flow_list {
        analysis.flows.push(FlowSummary {
            id: flow.id,
            proto: if flow.proto == 6 {
                "TCP".into()
            } else {
                "UDP".into()
            },
            endpoint_a: fmt_endpoint(&flow.a),
            endpoint_b: fmt_endpoint(&flow.b),
            packets: flow.packets,
            bytes: flow.bytes,
            first_ms: flow.first_ms,
            last_ms: flow.last_ms,
            tcp_gaps: flow_gaps.get(&flow.id).copied().unwrap_or(0),
            stream_truncated: flow.capped,
        });
    }
    Ok(analysis)
}

fn fmt_endpoint(ep: &Endpoint) -> String {
    let v4 = ep.addr[..12] == [0u8; 12];
    let addr = if v4 {
        format!(
            "{}.{}.{}.{}",
            ep.addr[12], ep.addr[13], ep.addr[14], ep.addr[15]
        )
    } else {
        let segs: Vec<String> = ep
            .addr
            .chunks(2)
            .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
            .collect();
        segs.join(":")
    };
    if ep.port == 0 {
        addr
    } else {
        format!("{addr}:{}", ep.port)
    }
}

fn parse_http_stream(
    flow_id: u64,
    reqs: &[u8],
    resps: &[u8],
    analysis: &mut PcapAnalysis,
    tx_seq: &mut u64,
    object_seq: &mut u64,
) {
    let mut rp = 0usize;
    let mut sp = 0usize;
    while rp < reqs.len() && analysis.http.len() < MAX_HTTP_TXS {
        // skip stray bytes until a method token
        if !looks_like_request(&reqs[rp..]) {
            rp += 1;
            continue;
        }
        let Some((req_line, req_hdrs)) = parse_headers(reqs, rp) else {
            break;
        };
        let mut parts = req_line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_owned();
        let uri = parts.next().unwrap_or("").to_owned();
        let host = header(&req_hdrs.fields, "host").unwrap_or("").to_owned();
        let ua = header(&req_hdrs.fields, "user-agent")
            .unwrap_or("")
            .to_owned();
        let (req_body, req_next, req_ok) = read_body(
            reqs,
            req_hdrs.body_start,
            &req_hdrs.fields,
            true,
            &method,
            0,
        );
        rp = req_next.max(req_hdrs.body_start);

        // matching response
        let mut status = 0u32;
        let mut resp_fields: Vec<(String, String)> = Vec::new();
        let mut resp_body = Vec::new();
        let mut resp_ok = true;
        if sp < resps.len()
            && resps[sp..].starts_with(b"HTTP/")
            && let Some((line, hdrs)) = parse_headers(resps, sp)
        {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let (body, next, ok) =
                read_body(resps, hdrs.body_start, &hdrs.fields, false, &method, status);
            resp_body = body;
            sp = next.max(hdrs.body_start);
            resp_ok = ok;
            resp_fields = hdrs.fields;
        }

        let tx_id = *tx_seq;
        *tx_seq += 1;
        let req_ct = header(&req_hdrs.fields, "content-type")
            .unwrap_or("")
            .to_owned();
        let resp_ct = header(&resp_fields, "content-type")
            .unwrap_or("")
            .to_owned();
        let resp_enc = header(&resp_fields, "content-encoding")
            .unwrap_or("")
            .to_owned();

        // decode response for objects/echoes/signatures
        let resp_decoded = decompress(&resp_body, &resp_enc).unwrap_or_else(|| resp_body.clone());
        let req_decoded = decompress(
            &req_body,
            header(&req_hdrs.fields, "content-encoding").unwrap_or(""),
        )
        .unwrap_or_else(|| req_body.clone());

        let mut req_object_id = None;
        let mut resp_object_id = None;
        if !req_decoded.is_empty() && analysis.objects.len() < MAX_OBJECTS {
            let id = format!("obj-{}", *object_seq);
            *object_seq += 1;
            store_object(analysis, &id, &req_decoded, &req_ct, &uri, "request");
            req_object_id = Some(id);
        }
        if !resp_decoded.is_empty() && analysis.objects.len() < MAX_OBJECTS {
            let id = format!("obj-{}", *object_seq);
            *object_seq += 1;
            store_object(analysis, &id, &resp_decoded, &resp_ct, &uri, "response");
            resp_object_id = Some(id);
        }

        let tx = HttpTransaction {
            id: tx_id,
            flow_id,
            method: method.clone(),
            uri: uri.clone(),
            host: host.clone(),
            status,
            req_content_type: req_ct.clone(),
            resp_content_type: resp_ct.clone(),
            req_body_size: req_decoded.len() as u64,
            resp_body_size: resp_decoded.len() as u64,
            req_object_id,
            resp_object_id,
            req_headers: req_hdrs
                .fields
                .iter()
                .take(24)
                .map(|(k, v)| format!("{k}: {v}"))
                .collect(),
            resp_headers: resp_fields
                .iter()
                .take(24)
                .map(|(k, v)| format!("{k}: {v}"))
                .collect(),
            incomplete: !(req_ok && resp_ok),
        };
        analysis.http.push(tx);

        // ------- signatures on this transaction
        let uri_low = uri.to_ascii_lowercase();
        let req_text = String::from_utf8_lossy(&req_decoded);
        let resp_text = String::from_utf8_lossy(&resp_decoded);

        // caidao echoes in the response body
        if let Some(echo) = extract_between(&resp_text, "X@Y", "X@Y") {
            push_echo(analysis, tx_id, flow_id, "x@y", echo);
        }
        if let Some(echo) = extract_between(&resp_text, "->|", "|<-") {
            push_echo(analysis, tx_id, flow_id, "arrow", echo);
        }
        // caidao request markers
        if uri.contains("z0=")
            || uri.contains("z1=")
            || req_text.contains("z0=") && req_text.contains("z1=")
        {
            alert(
                analysis,
                "caidao",
                "lead",
                Some(tx_id),
                Some(flow_id),
                format!("菜刀特征：请求参数包含 z0=/z1= Base64 字段（{method} {uri}）。"),
            );
        }
        if req_text.contains("@eval(base64_decode($_POST[") {
            alert(
                analysis,
                "caidao",
                "strong",
                Some(tx_id),
                Some(flow_id),
                format!("菜刀特征：请求体包含 @eval(base64_decode($_POST[…)（{uri}）。"),
            );
        }
        // sqlmap
        if ua.to_ascii_lowercase().contains("sqlmap/") {
            alert(
                analysis,
                "sqlmap",
                "strong",
                Some(tx_id),
                Some(flow_id),
                format!("User-Agent 声明 sqlmap（{ua}），URI {uri}。"),
            );
        } else {
            let probe = format!("{uri_low} {}", req_text.to_ascii_lowercase());
            for marker in [
                "union%20select",
                "union+select",
                " union select",
                "%20or%20",
                "' or '",
                "sleep(",
                "benchmark(",
                "extractvalue(",
                "updatexml(",
                "randomblob(",
            ] {
                if probe.contains(marker) {
                    alert(
                        analysis,
                        "sqlmap",
                        "lead",
                        Some(tx_id),
                        Some(flow_id),
                        format!("疑似注入载荷标记 {marker}（{method} {uri}）。"),
                    );
                    break;
                }
            }
        }
        // behinder
        if method == "POST" && is_script_uri(&uri_low) {
            let candidate = if req_ct.contains("octet-stream") {
                Some(req_decoded.clone())
            } else {
                b64_decode(req_text.trim())
            };
            if let Some(blob) = candidate
                && !blob.is_empty()
                && blob.len().is_multiple_of(16)
            {
                let key: [u8; 16] = BEHINDER_DEFAULT_KEY.as_bytes().try_into().unwrap();
                let mut strong = false;
                for cbc in [false, true] {
                    if let Some(plain) = aes128_decrypt(&key, cbc, &blob) {
                        let text = String::from_utf8_lossy(&plain);
                        if mostly_printable(&plain) > 0.7
                            || [
                                "@error_reporting",
                                "eval",
                                "assert",
                                "javax",
                                "class",
                                "function",
                            ]
                            .iter()
                            .any(|m| text.contains(m))
                        {
                            strong = true;
                            break;
                        }
                    }
                }
                alert(
                    analysis,
                    "behinder",
                    if strong { "strong" } else { "lead" },
                    Some(tx_id),
                    Some(flow_id),
                    if strong {
                        format!(
                            "冰蝎特征：POST {uri} 的载荷按默认密钥 AES-128 解密后得到可识别代码。规则：脚本 URI + 16 字节倍数 + 默认密钥可解。"
                        )
                    } else {
                        format!(
                            "疑似冰蝎：POST {uri} 携带 16 字节倍数载荷（octet-stream 或 Base64 外观），默认密钥未解出明文。规则：脚本 URI + 16 字节倍数。v4 的 Accept/Content-Type 默认头缺乏可靠出处，未纳入判定。"
                        )
                    },
                );
            }
        }
    }
}

fn store_object(
    analysis: &mut PcapAnalysis,
    id: &str,
    body: &[u8],
    ct: &str,
    uri: &str,
    kind: &str,
) {
    let stored = analysis.object_bytes.values().map(Vec::len).sum::<usize>() + body.len()
        <= MAX_OBJECT_STORE;
    let mut hasher = Sha256::new();
    hasher.update(body);
    if stored {
        analysis.object_bytes.insert(id.to_owned(), body.to_vec());
    }
    analysis.objects.push(PcapObjectInfo {
        id: id.to_owned(),
        sha256: format!("{:x}", hasher.finalize()),
        size: body.len() as u64,
        content_type: ct.to_owned(),
        uri: uri.to_owned(),
        kind: kind.to_owned(),
        stored,
    });
}

fn push_echo(analysis: &mut PcapAnalysis, tx_id: u64, flow_id: u64, marker: &str, text: &str) {
    if analysis.echoes.len() >= MAX_ECHOES {
        return;
    }
    let mut text = text.trim().chars().take(MAX_ECHO_TEXT).collect::<String>();
    if text.is_empty() {
        return;
    }
    if text.len() > MAX_ECHO_TEXT {
        text.truncate(MAX_ECHO_TEXT);
    }
    analysis.echoes.push(CaidaoEcho {
        tx_id: Some(tx_id),
        flow_id,
        marker: marker.to_owned(),
        text,
    });
}

fn alert(
    analysis: &mut PcapAnalysis,
    rule: &str,
    level: &str,
    tx_id: Option<u64>,
    flow_id: Option<u64>,
    message: String,
) {
    if analysis.alerts.len() >= MAX_ALERTS {
        return;
    }
    analysis.alerts.push(PcapAlert {
        rule: rule.to_owned(),
        level: level.to_owned(),
        message,
        flow_id,
        tx_id,
    });
}

fn is_script_uri(uri: &str) -> bool {
    let path = uri.split(['?', '#']).next().unwrap_or("");
    [
        ".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cfm", ".do", ".action",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
}

fn scan_tcp_text(flow: &FlowState, a2b: &[u8], b2a: &[u8], analysis: &mut PcapAnalysis) {
    for bytes in [a2b, b2a] {
        let text = String::from_utf8_lossy(bytes);
        // frp plaintext login JSON
        if text.contains("\"type\":\"login\"")
            || text.contains("privilege_key")
            || (text.contains("run_id") && text.contains("pool_count"))
        {
            alert(analysis, "frp", "strong", None, Some(flow.id), "frp 登录特征：TCP 载荷含 login JSON 键（privilege_key / run_id / pool_count），为明文模式。".into());
            break;
        }
        if text.contains("\"version\"")
            && text.contains("\"hostname\"")
            && bytes.len() < 8192
            && text.trim_start().starts_with('{')
        {
            alert(
                analysis,
                "frp",
                "lead",
                None,
                Some(flow.id),
                "疑似 frp 握手：TCP 载荷为含 version/hostname 的 JSON。".into(),
            );
            break;
        }
        // stratum
        for marker in ["mining.subscribe", "mining.authorize", "mining.submit"] {
            if text.contains(marker) {
                alert(
                    analysis,
                    "stratum",
                    "strong",
                    None,
                    Some(flow.id),
                    format!("矿池协议特征：JSON-RPC {marker}。"),
                );
                break;
            }
        }
        if text.contains("\"method\":\"login\"") && text.contains("XMRig") {
            alert(
                analysis,
                "stratum",
                "strong",
                None,
                Some(flow.id),
                "XMRig 登录特征：method=login 且 agent 为 XMRig。".into(),
            );
            break;
        }
        // frp TLS weak hint: TLS-looking record to/from default port 7000
    }
    if flow.a.port == 7000 || flow.b.port == 7000 {
        let tlsish = [a2b, b2a]
            .iter()
            .any(|b| b.starts_with(&[0x17, 0x03]) || b.starts_with(&[0x16, 0x03]));
        if tlsish {
            alert(analysis, "frp", "weak", None, Some(flow.id), "7000 端口上的 TLS 会话：仅按端口+TLS 形态提示，可能为 frp TLS 模式或其他服务，证据弱。".into());
        }
    }
}

const CS_DEFAULT_URIS: [&str; 5] = ["/ca", "/dpixel", "/__utm.gif", "/pixel.gif", "/submit.php"];

struct HttpStart {
    host: String,
    uri: String,
    ts_ms: i64,
    cookie: String,
}

/// Cobalt Strike HTTP beacon lead: >=5 requests to the same host+URI with a
/// coefficient of variation of inter-request intervals below 0.2.
/// Justification for 0.2: Malleable C2's default jitter is 20% of the sleep,
/// so a working beacon lands under ~0.2 CV; human browsing almost never
/// repeats the same URI at that regularity. Strength rises when the URI is a
/// well-known default or the Cookie looks base64.
fn detect_cs_beacon(starts: &[HttpStart], analysis: &mut PcapAnalysis) {
    let mut groups: HashMap<(String, String), Vec<&HttpStart>> = HashMap::new();
    for s in starts {
        groups
            .entry((s.host.clone(), s.uri.clone()))
            .or_default()
            .push(s);
    }
    for ((host, uri), list) in groups {
        if list.len() < 5 {
            continue;
        }
        let mut ts: Vec<i64> = list.iter().map(|s| s.ts_ms).collect();
        ts.sort_unstable();
        let intervals: Vec<f64> = ts
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .filter(|d| *d > 0.0)
            .collect();
        if intervals.len() < 4 {
            continue;
        }
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean <= 0.0 {
            continue;
        }
        let var =
            intervals.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = var.sqrt() / mean;
        if cv >= 0.2 {
            continue;
        }
        let known_uri = CS_DEFAULT_URIS.iter().any(|u| uri == *u);
        let b64_cookie = list
            .iter()
            .any(|s| s.cookie.len() >= 16 && looks_base64(&s.cookie));
        let level = if known_uri || b64_cookie {
            "strong"
        } else {
            "lead"
        };
        alert(
            analysis,
            "cs-beacon",
            level,
            None,
            None,
            format!(
                "Cobalt Strike 心跳线索：对 {host}{uri} 共 {} 次周期请求，间隔均值 {mean:.0}ms、变异系数 {cv:.3}（阈值 0.2）。{}{}",
                list.len(),
                if known_uri {
                    "命中已知默认 URI。"
                } else {
                    ""
                },
                if b64_cookie {
                    "Cookie 呈 Base64 形态。"
                } else {
                    ""
                }
            ),
        );
    }
}

fn detect_icmp_tunnel(
    echoes: &HashMap<[u8; 16], Vec<(bool, Vec<u8>)>>,
    analysis: &mut PcapAnalysis,
) {
    for (addr, list) in echoes {
        if list.len() < 4 {
            continue;
        }
        let payloads: Vec<&[u8]> = list.iter().map(|(_, p)| p.as_slice()).collect();
        let default_win = payloads.iter().all(|p| p.len() == 32 && is_windows_ping(p));
        let default_lin = payloads.iter().all(|p| p.len() == 48);
        let varied = payloads
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            > payloads.len() / 2;
        let large = payloads.iter().any(|p| p.len() > 64);
        if large && varied && !default_win && !default_lin {
            alert(
                analysis,
                "icmp-tunnel",
                "lead",
                None,
                None,
                format!(
                    "ICMP 隧道线索：{addr:x?} 收到 {} 个 echo，载荷偏大（最大 {} B）且内容各异，不符合常规 ping 载荷。",
                    list.len(),
                    payloads.iter().map(|p| p.len()).max().unwrap_or(0)
                ),
            );
        } else if list.len() > 64 {
            alert(
                analysis,
                "icmp-tunnel",
                "weak",
                None,
                None,
                format!(
                    "ICMP echo 数量异常：对 {addr:x?} 共 {} 个 echo 包，可能为高频探测或隧道，证据弱。",
                    list.len()
                ),
            );
        }
    }
}

fn is_windows_ping(p: &[u8]) -> bool {
    p.len() == 32 && p == b"abcdefghijklmnopqrstuvwabcdefghi"
}
