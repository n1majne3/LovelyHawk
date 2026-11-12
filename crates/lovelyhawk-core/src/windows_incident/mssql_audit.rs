//! MSSQL log audit on the Windows target: SQL Server instance discovery from
//! the registry, bounded ERRORLOG tails, Application 18454/18456 failed-login
//! events, and feature-restoration clues (`xp_cmdshell`, OLE automation,
//! `xplog70.dll`/`odsole70.dll`, `sp_addextendedproc`).
//!
//! Missing instances, denied registry reads and unreadable logs are separate
//! visible states — none of them may render as "no findings".

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

/// How many failed-login groups and clue lines a snapshot may carry.
const MAX_FAILED_GROUPS: usize = 512;
const MAX_CLUES: usize = 512;
const MAX_LINE_BYTES: usize = 1_024;

/// One discovered instance and what the collector could read of it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MssqlInstance {
    pub name: String,
    /// Instance ID under `Microsoft SQL Server\<ID>`, e.g. `MSSQL15.MSSQLSERVER`.
    pub instance_id: String,
    pub errorlog_path: String,
    /// `"ok"` | `"missing"` | `"unreadable"` — the file state, kept separate.
    pub errorlog_state: String,
    pub errorlog_size: u64,
    /// Bounded tail lines of ERRORLOG, newest at the end.
    pub errorlog_tail: Vec<String>,
    pub trace_path: String,
    pub trace_size: u64,
}

/// One Application 18454/18456 event from a `MSSQL*` provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MssqlAuditEvent {
    pub record_id: u64,
    pub time_created: String,
    pub event_id: u32,
    pub provider: String,
    pub client_ip: String,
    pub account: String,
    pub message: String,
}

/// Failed logins aggregated by `(client_ip, account)` across the window.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MssqlFailedLogin {
    pub client_ip: String,
    pub account: String,
    pub count: u32,
    pub first: String,
    pub last: String,
}

/// A line worth investigating: which clue rule matched and where it was seen.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MssqlClue {
    /// `"errorlog"` or `"application"`.
    pub source: String,
    pub instance: String,
    /// Short rule id the UI explains: `"xp-cmdshell"` | `"ole-automation"` |
    /// `"extended-proc-dll"` | `"add-extended-proc"`.
    pub rule: String,
    pub line: String,
}

/// The MSSQL audit snapshot the page receives.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsMssqlAuditSnapshot {
    /// No `Instance Names\SQL` key: the "no SQL Server" state, kept separate
    /// from "found but unreadable".
    pub no_instances: bool,
    pub instances: Vec<MssqlInstance>,
    pub failed_logins: Vec<MssqlFailedLogin>,
    pub clues: Vec<MssqlClue>,
    pub event_count: u32,
    pub warnings: Vec<String>,
}

/// The clue rules, in the order they are reported. Matching is a plain
/// substring scan — the patterns come from a fixed list, never user input.
fn clue_rule(line: &str) -> Option<&'static str> {
    if line.contains("Configuration option 'xp_cmdshell' changed") {
        Some("xp-cmdshell")
    } else if line.contains("'Ole Automation Procedures'") {
        Some("ole-automation")
    } else if line.contains("Using 'xplog70.dll'") || line.contains("Using 'odsole70.dll'") {
        Some("extended-proc-dll")
    } else if line.contains("sp_addextendedproc") {
        Some("add-extended-proc")
    } else {
        None
    }
}

fn bounded_line(line: &str) -> String {
    let trimmed = line.trim_end();
    if trimmed.len() > MAX_LINE_BYTES {
        trimmed.chars().take(MAX_LINE_BYTES).collect()
    } else {
        trimmed.to_owned()
    }
}

/// Parses the collector payload into the page snapshot: failed-login
/// aggregation and clue flagging both happen here, in core.
pub fn parse_mssql_audit_json(json_str: &str) -> CoreResult<WindowsMssqlAuditSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawInstance {
        #[serde(default)]
        name: String,
        #[serde(default)]
        instance_id: String,
        #[serde(default)]
        errorlog_path: String,
        #[serde(default)]
        errorlog_state: String,
        #[serde(default)]
        errorlog_size: u64,
        #[serde(default)]
        errorlog_tail: Vec<String>,
        #[serde(default)]
        trace_path: String,
        #[serde(default)]
        trace_size: u64,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload {
        #[serde(default)]
        no_instances: bool,
        #[serde(default)]
        instances: Vec<RawInstance>,
        #[serde(default)]
        events: Vec<MssqlAuditEvent>,
        #[serde(default)]
        warnings: Vec<String>,
    }
    let payload: Payload = serde_json::from_str(json_str.trim()).map_err(|_| {
        CoreError::validation("windows_incident.mssql", "无法解析 SQL Server 日志采集结果")
    })?;
    if payload.instances.len() > 32
        || payload.events.len() > 4_096
        || payload.warnings.len() > 64
        || payload
            .instances
            .iter()
            .any(|instance| instance.errorlog_tail.len() > 1_024)
    {
        return Err(CoreError::validation(
            "windows_incident.mssql",
            "SQL Server 日志结果超过读取上限",
        ));
    }

    let mut warnings = payload.warnings;
    let mut clues = Vec::new();
    let mut instances = Vec::with_capacity(payload.instances.len());
    for raw in payload.instances {
        let state = match raw.errorlog_state.as_str() {
            "ok" | "missing" | "unreadable" => raw.errorlog_state.clone(),
            _ => "unreadable".to_owned(),
        };
        if state != "ok" {
            warnings.push(format!(
                "实例 {} 的 ERRORLOG {}，{}。",
                raw.name,
                if raw.errorlog_path.is_empty() {
                    "路径未找到".to_owned()
                } else {
                    raw.errorlog_path.clone()
                },
                if state == "missing" {
                    "文件不存在"
                } else {
                    "读取被拒绝"
                }
            ));
        }
        if clues.len() < MAX_CLUES {
            for line in &raw.errorlog_tail {
                if let Some(rule) = clue_rule(line) {
                    clues.push(MssqlClue {
                        source: "errorlog".to_owned(),
                        instance: raw.name.clone(),
                        rule: rule.to_owned(),
                        line: bounded_line(line),
                    });
                    if clues.len() >= MAX_CLUES {
                        break;
                    }
                }
            }
        }
        instances.push(MssqlInstance {
            name: raw.name,
            instance_id: raw.instance_id,
            errorlog_path: raw.errorlog_path,
            errorlog_state: state,
            errorlog_size: raw.errorlog_size,
            errorlog_tail: raw
                .errorlog_tail
                .into_iter()
                .map(|line| bounded_line(&line))
                .collect(),
            trace_path: raw.trace_path,
            trace_size: raw.trace_size,
        });
    }

    // Aggregate Application 18454/18456 by client and account.
    let mut groups: Vec<MssqlFailedLogin> = Vec::new();
    let mut event_count = 0u32;
    for event in payload.events {
        event_count = event_count.saturating_add(1);
        if let Some(rule) = clue_rule(&event.message)
            && clues.len() < MAX_CLUES
        {
            clues.push(MssqlClue {
                source: "application".to_owned(),
                instance: event.provider.clone(),
                rule: rule.to_owned(),
                line: bounded_line(&event.message),
            });
        }
        if event.client_ip.is_empty() && event.account.is_empty() {
            continue;
        }
        let index = groups
            .iter()
            .position(|group| group.client_ip == event.client_ip && group.account == event.account);
        match index {
            Some(index) => {
                let group = &mut groups[index];
                group.count = group.count.saturating_add(1);
                if event.time_created < group.first {
                    group.first = event.time_created.clone();
                }
                if event.time_created > group.last {
                    group.last = event.time_created.clone();
                }
            }
            None if groups.len() < MAX_FAILED_GROUPS => groups.push(MssqlFailedLogin {
                client_ip: event.client_ip.clone(),
                account: event.account.clone(),
                count: 1,
                first: event.time_created.clone(),
                last: event.time_created,
            }),
            None => {}
        }
    }
    groups.sort_by(|a, b| b.count.cmp(&a.count).then(a.client_ip.cmp(&b.client_ip)));

    Ok(WindowsMssqlAuditSnapshot {
        no_instances: payload.no_instances,
        instances,
        failed_logins: groups,
        clues,
        event_count,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "noInstances": false,
      "instances": [
        {
          "name": "MSSQLSERVER",
          "instanceId": "MSSQL15.MSSQLSERVER",
          "errorlogPath": "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG",
          "errorlogState": "ok",
          "errorlogSize": 51200,
          "errorlogTail": [
            "2026-11-10 08:00:01.12 Server      SQL Server is now ready for client connections.",
            "2026-11-10 08:10:44.00 spid51      Configuration option 'xp_cmdshell' changed from 0 to 1.",
            "2026-11-10 08:10:45.01 spid51      Using 'xplog70.dll' version '2019.150.2000' to execute extended stored procedure 'xp_cmdshell'.",
            "2026-11-10 08:11:00.00 Logon       Login failed for user 'sa'. [CLIENT: 10.0.0.44]"
          ],
          "tracePath": "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Log\\log.trc",
          "traceSize": 1048576
        },
        {
          "name": "BROKEN",
          "instanceId": "MSSQL15.BROKEN",
          "errorlogPath": "D:\\SQL\\Log\\ERRORLOG",
          "errorlogState": "unreadable",
          "errorlogSize": 0,
          "errorlogTail": [],
          "tracePath": "",
          "traceSize": 0
        }
      ],
      "events": [
        {"recordId":1,"timeCreated":"2026-11-10T08:20:00+08:00","eventId":18456,"provider":"MSSQLSERVER","clientIp":"10.0.0.44","account":"sa","message":"Login failed for user 'sa'. [CLIENT: 10.0.0.44]"},
        {"recordId":2,"timeCreated":"2026-11-10T08:21:00+08:00","eventId":18456,"provider":"MSSQLSERVER","clientIp":"10.0.0.44","account":"sa","message":"Login failed for user 'sa'. [CLIENT: 10.0.0.44]"},
        {"recordId":3,"timeCreated":"2026-11-10T08:22:00+08:00","eventId":18456,"provider":"MSSQLSERVER","clientIp":"10.0.0.51","account":"report","message":"Login failed for user 'report'."},
        {"recordId":4,"timeCreated":"2026-11-10T08:23:00+08:00","eventId":18454,"provider":"MSSQLSERVER","clientIp":"","account":"","message":"SSPI handshake failed."}
      ],
      "warnings": []
    }"#;

    #[test]
    fn parses_instances_aggregation_and_clues() {
        let snapshot = parse_mssql_audit_json(FIXTURE).unwrap();
        assert!(!snapshot.no_instances);
        assert_eq!(snapshot.instances.len(), 2);
        assert_eq!(snapshot.instances[0].errorlog_state, "ok");
        assert_eq!(snapshot.instances[1].errorlog_state, "unreadable");
        assert_eq!(snapshot.instances[0].trace_size, 1_048_576);
        // The unreadable instance surfaces as its own warning, not silence.
        assert!(snapshot.warnings.iter().any(|line| line.contains("BROKEN")));

        let rules: Vec<&str> = snapshot
            .clues
            .iter()
            .map(|clue| clue.rule.as_str())
            .collect();
        assert!(rules.contains(&"xp-cmdshell"));
        assert!(rules.contains(&"extended-proc-dll"));
        assert!(!rules.contains(&"ole-automation"));

        assert_eq!(snapshot.failed_logins.len(), 2);
        assert_eq!(snapshot.failed_logins[0].client_ip, "10.0.0.44");
        assert_eq!(snapshot.failed_logins[0].account, "sa");
        assert_eq!(snapshot.failed_logins[0].count, 2);
        assert_eq!(snapshot.event_count, 4);
    }

    #[test]
    fn clue_rules_match_exact_phrases_only() {
        assert_eq!(
            clue_rule("Configuration option 'xp_cmdshell' changed from 0 to 1."),
            Some("xp-cmdshell")
        );
        assert_eq!(
            clue_rule("Configuration option 'Ole Automation Procedures' changed from 0 to 1."),
            Some("ole-automation")
        );
        assert_eq!(
            clue_rule("Using 'odsole70.dll' version 'x' to execute extended stored procedure."),
            Some("extended-proc-dll")
        );
        assert_eq!(
            clue_rule("EXEC sp_addextendedproc xp_evil, 'evil.dll'"),
            Some("add-extended-proc")
        );
        // Lookalikes without the fixed phrase are not clues.
        assert_eq!(clue_rule("xp_cmdshell is enabled"), None);
        assert_eq!(clue_rule("ordinary startup line"), None);
    }

    #[test]
    fn no_instances_and_bad_payloads_are_distinct() {
        let empty = parse_mssql_audit_json(
            r#"{"noInstances":true,"instances":[],"events":[],"warnings":["未发现实例"]}"#,
        )
        .unwrap();
        assert!(empty.no_instances);
        assert!(empty.instances.is_empty());
        assert!(empty.failed_logins.is_empty());
        assert!(parse_mssql_audit_json("not json").is_err());
        // An oversized tail is refused rather than truncated silently.
        let huge_tail = format!(
            r#"{{"noInstances":false,"instances":[{{"errorlogTail":[{}]}}],"events":[],"warnings":[]}}"#,
            vec!["\"x\""; 2_000].join(",")
        );
        assert!(parse_mssql_audit_json(&huge_tail).is_err());
    }
}
