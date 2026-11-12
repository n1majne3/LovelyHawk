//! Logon chain analysis over Security events 4624/4625/4634/4647/4648/4672/4776
//! (and System 7045 service installs when collected).
//!
//! Events are grouped by `(source, account)` into chains whose neighbouring
//! events sit inside a ten-minute gap; each chain is then matched against
//! remote-control logon fingerprints. Every fingerprint is a heuristic shown
//! as a 线索 together with the rule that produced it — it is evidence to
//! investigate, never a verdict.

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

/// Ten minutes without activity starts a new chain for the same pair.
const CHAIN_GAP_MS: i64 = 10 * 60 * 1_000;
/// WMIC-style bursts: this many type-3 logons inside a short span.
const WMIC_BURST_COUNT: usize = 4;
const WMIC_BURST_SPAN_MS: i64 = 10 * 1_000;
/// Brute-force threshold: this many failures before a success.
const BRUTE_FORCE_FAILURES: u32 = 5;

/// One normalized logon-related event as the collector reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogonEvent {
    pub record_id: u64,
    /// RFC 3339 timestamp from the event itself.
    pub time: String,
    pub id: u32,
    pub logon_type: u32,
    pub account: String,
    pub domain: String,
    pub source_ip: String,
    pub workstation: String,
    pub logon_id: String,
    pub process: String,
    pub auth_package: String,
}

/// A heuristic match: the kind plus the rule the operator should read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogonFingerprint {
    /// `"ipc"` | `"psexec"` | `"wmic"` | `"sharp-rdp"` | `"brute-force"`
    pub kind: String,
    /// Chinese statement of the rule that matched.
    pub rule: String,
}

/// Events from one source against one account inside a ten-minute window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogonChain {
    pub source_ip: String,
    pub workstation: String,
    pub account: String,
    pub events: Vec<LogonEvent>,
    pub first: String,
    pub last: String,
    pub fingerprint: Option<LogonFingerprint>,
    /// Failure events (4625/4776) that precede the first success in the chain.
    pub failed_before_success: u32,
}

/// The parsed logon-chain collection: chains plus the gaps the page must
/// show. `permission_gap` is true when the Security log itself could not be
/// read — it must never render as "no logons".
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsLogonChainSnapshot {
    pub permission_gap: bool,
    pub truncated: bool,
    pub event_count: u32,
    pub chains: Vec<LogonChain>,
    pub warnings: Vec<String>,
}

/// Logon-type number to a short Chinese label.
pub fn logon_type_label(logon_type: u32) -> &'static str {
    match logon_type {
        2 => "交互",
        3 => "网络",
        4 => "批处理",
        5 => "服务",
        7 => "解锁",
        8 => "明文网络",
        9 => "新凭据",
        10 => "远程交互",
        11 => "缓存",
        _ => "其他",
    }
}

/// Accounts that create background noise rather than investigation signal.
/// Machine accounts are kept: PsExec/WMI lateral movement authenticates as
/// `HOST$`.
fn is_system_noise(account: &str) -> bool {
    matches!(
        account.to_ascii_lowercase().as_str(),
        "" | "-" | "system" | "local service" | "network service" | "anonymous logon"
    )
}

fn event_ms(event: &LogonEvent) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(&event.time)
        .ok()
        .map(|stamp| stamp.timestamp_millis())
}

/// The identity a chain is keyed on: the remote source first, the workstation
/// when no address was logged, and the target itself for interactive logons.
fn source_key(event: &LogonEvent) -> String {
    let ip = event.source_ip.trim();
    if !ip.is_empty() && ip != "-" && ip != "127.0.0.1" && ip != "::1" {
        return ip.to_owned();
    }
    let station = event.workstation.trim();
    if !station.is_empty() && station != "-" {
        return station.to_owned();
    }
    "本机".to_owned()
}

fn is_failure(event: &LogonEvent) -> bool {
    // 4776 is a credential validation attempt; only failures matter for the
    // brute-force count, and the collector only forwards non-success ones.
    event.id == 4625
}

fn is_success(event: &LogonEvent) -> bool {
    event.id == 4624
}

fn fingerprint(
    chain: &[&LogonEvent],
    install_times: &[i64],
    first_ms: i64,
    last_ms: i64,
) -> Option<LogonFingerprint> {
    let stamp = |event: &LogonEvent| event_ms(event).unwrap_or(0);
    let type3: Vec<i64> = chain
        .iter()
        .filter(|event| is_success(event) && event.logon_type == 3)
        .map(|event| stamp(event))
        .collect();
    let failures_before = chain
        .iter()
        .position(|event| is_success(event))
        .map(|index| &chain[..index])
        .unwrap_or(chain)
        .iter()
        .filter(|event| is_failure(event))
        .count() as u32;
    if failures_before >= BRUTE_FORCE_FAILURES {
        return Some(LogonFingerprint {
            kind: "brute-force".to_owned(),
            rule: "同一来源连续 5 次以上 4625 登录失败后才出现 4624 成功，符合口令爆破后成功登录"
                .to_owned(),
        });
    }
    // WMIC executes one command per connection, so a burst of type-3 logons
    // from one source inside seconds is its fingerprint.
    let burst = type3
        .windows(WMIC_BURST_COUNT)
        .any(|window| window[WMIC_BURST_COUNT - 1] - window[0] <= WMIC_BURST_SPAN_MS);
    if burst {
        return Some(LogonFingerprint {
            kind: "wmic".to_owned(),
            rule: "同一来源在数秒内建立 4 次以上 type 3 网络登录，符合 WMIC 每次命令新建连接的特征"
                .to_owned(),
        });
    }
    // PsExec stages a service: a type-3 logon followed by an interactive
    // type-2, or a 7045 service install anywhere on the target inside the
    // chain window — the install carries no source address of its own.
    let installed = install_times
        .iter()
        .any(|stamp| *stamp >= first_ms && *stamp <= last_ms + CHAIN_GAP_MS);
    let mut saw_type3 = false;
    for event in chain {
        if installed && saw_type3 {
            return Some(LogonFingerprint {
                kind: "psexec".to_owned(),
                rule:
                    "type 3 网络登录后同一窗口内出现 7045 服务安装，符合 PsExec 创建远程服务的特征"
                        .to_owned(),
            });
        }
        if is_success(event) && event.logon_type == 2 && saw_type3 {
            return Some(LogonFingerprint {
                kind: "psexec".to_owned(),
                rule: "type 3 网络登录后出现 type 2 交互登录，符合 PsExec 等服务工具的双段登录特征"
                    .to_owned(),
            });
        }
        if is_success(event) && event.logon_type == 3 {
            saw_type3 = true;
        }
    }
    // SharpRDP runs a real RDP session after the network logon: 3 then 10.
    let mut saw_type3 = false;
    for event in chain {
        if is_success(event) && event.logon_type == 10 && saw_type3 {
            return Some(LogonFingerprint {
                kind: "sharp-rdp".to_owned(),
                rule:
                    "type 3 网络登录后出现 type 10 远程交互登录，符合 SharpRDP 先验证再开桌面的特征"
                        .to_owned(),
            });
        }
        if is_success(event) && event.logon_type == 3 {
            saw_type3 = true;
        }
    }
    // A single type-3 with no follow-up is the classic IPC$ tree connect.
    if chain.len() == 1 && is_success(chain[0]) && chain[0].logon_type == 3 {
        return Some(LogonFingerprint {
            kind: "ipc".to_owned(),
            rule: "孤立的单次 type 3 网络登录、没有后续活动，符合 IPC$ 连接试探的特征".to_owned(),
        });
    }
    None
}

/// Groups parsed events into chains and assigns fingerprints. Service
/// installs (7045) are not events in a chain — they have no source — so the
/// caller hands their timestamps in separately.
pub fn build_logon_chains(mut events: Vec<LogonEvent>, install_times: &[i64]) -> Vec<LogonChain> {
    events.sort_by(|a, b| a.time.cmp(&b.time).then(a.record_id.cmp(&b.record_id)));
    let mut grouped: Vec<(String, String, Vec<&LogonEvent>)> = Vec::new();
    for event in &events {
        if is_system_noise(&event.account) {
            continue;
        }
        let key = (source_key(event), event.account.clone());
        if let Some((_, _, list)) = grouped
            .iter_mut()
            .find(|(source, account, _)| *source == key.0 && *account == key.1)
        {
            list.push(event);
        } else {
            grouped.push((key.0, key.1, vec![event]));
        }
    }
    let mut chains = Vec::new();
    for (_, _, list) in grouped {
        let mut start = 0;
        for index in 1..=list.len() {
            let gap = index < list.len()
                && event_ms(list[index])
                    .zip(event_ms(list[index - 1]))
                    .map(|(now, before)| now - before > CHAIN_GAP_MS)
                    .unwrap_or(false);
            if index == list.len() || gap {
                let slice = &list[start..index];
                let failures_before_success = slice
                    .iter()
                    .position(|event| is_success(event))
                    .map(|pos| {
                        slice[..pos]
                            .iter()
                            .filter(|event| is_failure(event))
                            .count()
                    })
                    .unwrap_or(0) as u32;
                chains.push(LogonChain {
                    source_ip: slice
                        .iter()
                        .find_map(|event| {
                            (!event.source_ip.trim().is_empty() && event.source_ip != "-")
                                .then(|| event.source_ip.clone())
                        })
                        .unwrap_or_default(),
                    workstation: slice
                        .iter()
                        .find_map(|event| {
                            (!event.workstation.trim().is_empty() && event.workstation != "-")
                                .then(|| event.workstation.clone())
                        })
                        .unwrap_or_default(),
                    account: slice[0].account.clone(),
                    first: slice[0].time.clone(),
                    last: slice[slice.len() - 1].time.clone(),
                    fingerprint: fingerprint(
                        slice,
                        install_times,
                        event_ms(slice[0]).unwrap_or(0),
                        event_ms(slice[slice.len() - 1]).unwrap_or(0),
                    ),
                    failed_before_success: failures_before_success,
                    events: slice.iter().map(|event| (*event).clone()).collect(),
                });
                start = index;
            }
        }
    }
    chains.sort_by(|a, b| a.first.cmp(&b.first));
    chains
}

/// Parses the collector's `{events, truncated, warnings, readError}` payload
/// into the snapshot the page receives.
pub fn parse_logon_chain_json(json_str: &str) -> CoreResult<WindowsLogonChainSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload {
        #[serde(default)]
        events: Vec<LogonEvent>,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        read_error: String,
        #[serde(default)]
        warnings: Vec<String>,
    }
    let trimmed = json_str.trim();
    let payload: Payload = serde_json::from_str(trimmed).map_err(|_| {
        CoreError::validation("windows_incident.logon_chain", "无法解析登录链采集结果")
    })?;
    if payload.events.len() > 20_000 || payload.warnings.len() > 64 {
        return Err(CoreError::validation(
            "windows_incident.logon_chain",
            "登录链结果超过读取上限",
        ));
    }
    let event_count = payload.events.len() as u32;
    let mut warnings = payload.warnings;
    let permission_gap = !payload.read_error.is_empty();
    if permission_gap {
        warnings.push(payload.read_error);
    }
    if payload.truncated {
        warnings
            .push("事件达到本次 20000 条上限，仅分析了最近的一部分，登录链可能不完整。".to_owned());
    }
    // 7045 service installs are timestamps for the PsExec rule, not chain
    // members: they carry no source address of their own.
    let (installs, events): (Vec<LogonEvent>, Vec<LogonEvent>) = payload
        .events
        .into_iter()
        .partition(|event| event.id == 7045);
    let install_times: Vec<i64> = installs.iter().filter_map(event_ms).collect();
    Ok(WindowsLogonChainSnapshot {
        permission_gap,
        truncated: payload.truncated,
        event_count,
        chains: build_logon_chains(events, &install_times),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u32, logon_type: u32, account: &str, ip: &str, time: &str) -> LogonEvent {
        LogonEvent {
            record_id: 0,
            time: time.to_owned(),
            id,
            logon_type,
            account: account.to_owned(),
            domain: "LAB".to_owned(),
            source_ip: ip.to_owned(),
            workstation: "KIOSK".to_owned(),
            logon_id: "0x1".to_owned(),
            process: "C:\\Windows\\System32\\svchost.exe".to_owned(),
            auth_package: "NTLM".to_owned(),
        }
    }

    fn at(second: u32) -> String {
        format!("2026-11-10T08:00:{second:02}.0000000+08:00")
    }

    fn kinds(chains: &[LogonChain]) -> Vec<&str> {
        chains
            .iter()
            .filter_map(|chain| chain.fingerprint.as_ref().map(|fp| fp.kind.as_str()))
            .collect()
    }

    #[test]
    fn a_plain_interactive_logon_earns_no_fingerprint() {
        let chains = build_logon_chains(
            vec![
                event(4624, 2, "alice", "", &at(10)),
                event(4634, 0, "alice", "", &at(40)),
            ],
            &[],
        );
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].account, "alice");
        assert!(chains[0].fingerprint.is_none());
        assert_eq!(chains[0].failed_before_success, 0);
    }

    #[test]
    fn fingerprints_match_their_rules() {
        // IPC: one lone type-3.
        let ipc = build_logon_chains(vec![event(4624, 3, "admin", "10.0.0.9", &at(1))], &[]);
        assert_eq!(kinds(&ipc), ["ipc"]);

        // PsExec: type-3 then type-2.
        let psexec = build_logon_chains(
            vec![
                event(4624, 3, "admin", "10.0.0.9", &at(1)),
                event(4624, 2, "admin", "10.0.0.9", &at(2)),
            ],
            &[],
        );
        assert_eq!(kinds(&psexec), ["psexec"]);

        // SharpRDP: type-3 then type-10.
        let sharp = build_logon_chains(
            vec![
                event(4624, 3, "admin", "10.0.0.9", &at(1)),
                event(4624, 10, "admin", "10.0.0.9", &at(2)),
            ],
            &[],
        );
        assert_eq!(kinds(&sharp), ["sharp-rdp"]);

        // WMIC: four type-3 in ten seconds.
        let wmic = build_logon_chains(
            [3u32, 5, 6, 9]
                .iter()
                .map(|second| event(4624, 3, "admin", "10.0.0.9", &at(*second)))
                .collect(),
            &[],
        );
        assert_eq!(kinds(&wmic), ["wmic"]);
        // Spread the same four over minutes and the burst rule does not fire.
        let spaced = build_logon_chains(
            [3u32, 13, 23, 33]
                .iter()
                .map(|second| event(4624, 3, "admin", "10.0.0.9", &at(*second)))
                .collect(),
            &[],
        );
        assert_eq!(kinds(&spaced), Vec::<&str>::new());

        // Brute force: five 4625 then a 4624.
        let mut events: Vec<LogonEvent> = (0..5)
            .map(|n| event(4625, 3, "admin", "10.0.0.9", &at(n)))
            .collect();
        events.push(event(4624, 3, "admin", "10.0.0.9", &at(6)));
        let brute = build_logon_chains(events, &[]);
        assert_eq!(kinds(&brute), ["brute-force"]);
        assert_eq!(brute[0].failed_before_success, 5);
    }

    #[test]
    fn chains_split_after_a_ten_minute_gap() {
        let chains = build_logon_chains(
            vec![
                event(4624, 3, "admin", "10.0.0.9", "2026-11-10T08:00:00+08:00"),
                event(4624, 3, "admin", "10.0.0.9", "2026-11-10T08:09:00+08:00"),
                event(4624, 3, "admin", "10.0.0.9", "2026-11-10T08:30:00+08:00"),
            ],
            &[],
        );
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].events.len(), 2);
        assert_eq!(chains[1].events.len(), 1);
    }

    #[test]
    fn system_noise_and_unparseable_times_do_not_break_grouping() {
        let mut noisy = event(4624, 3, "SYSTEM", "10.0.0.9", &at(1));
        let mut bad_time = event(4624, 3, "alice", "10.0.0.9", "not-a-time");
        noisy.account = "NETWORK SERVICE".to_owned();
        bad_time.record_id = 7;
        let chains = build_logon_chains(vec![noisy, bad_time], &[]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].events[0].record_id, 7);
    }

    #[test]
    fn payload_marks_permission_gap_and_truncation() {
        let denied = parse_logon_chain_json(
            r#"{"events":[],"truncated":false,"readError":"Security 日志读取被拒绝，需要管理员或日志读取权限","warnings":[]}"#,
        )
        .unwrap();
        assert!(denied.permission_gap);
        assert!(denied.chains.is_empty());
        assert!(denied.warnings.iter().any(|line| line.contains("拒绝")));

        let truncated = parse_logon_chain_json(
            r#"{"events":[{"recordId":1,"time":"2026-11-10T08:00:00+08:00","id":4624,"logonType":3,"account":"admin","domain":"D","sourceIp":"10.0.0.9","workstation":"W","logonId":"0x1","process":"p","authPackage":"NTLM"}],"truncated":true,"readError":"","warnings":[]}"#,
        )
        .unwrap();
        assert!(truncated.truncated);
        assert_eq!(truncated.event_count, 1);
        assert!(truncated.warnings.iter().any(|line| line.contains("20000")));
        assert_eq!(truncated.chains[0].events[0].account, "admin");
        assert!(parse_logon_chain_json("not json").is_err());
        assert!(parse_logon_chain_json("{}").unwrap().chains.is_empty());
    }
}
