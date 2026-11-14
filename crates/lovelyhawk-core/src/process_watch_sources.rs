//! Records of past process activity the target already keeps, read without
//! starting anything: process accounting today, with the other sources
//! (audit execve rules, execsnoop, bpftrace) only detected and named.
//!
//! Nothing here turns a source on. A source that is installed but not
//! recording, or recording but unreadable by this account, is reported as
//! that — never as "no activity".

use std::time::Duration;

use chrono::NaiveDateTime;

use crate::process_watch::{
    EventOrigin, ProcessWatchEvent, ProcessWatchEventKind, ProcessWatchService, validate_ssh_output,
};
use crate::ssh::BoundSshSession;
use crate::{CoreError, CoreResult};

pub const ACCOUNTING_MIN_MINUTES: u32 = 1;
pub const ACCOUNTING_MAX_MINUTES: u32 = 120;
const MAX_ACCOUNTING_RECORDS: usize = 20_000;
const MAX_SOURCE_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

pub const ACCOUNTING_UNAVAILABLE: &str = "process accounting unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Accounting,
    AuditExecve,
    Execsnoop,
    Bpftrace,
}

impl SourceKind {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Accounting => "accounting",
            Self::AuditExecve => "audit-execve",
            Self::Execsnoop => "execsnoop",
            Self::Bpftrace => "bpftrace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    /// Recording, and this account can read it.
    Readable,
    /// There is a record but this account cannot read it.
    Unreadable,
    /// The tool is installed; whether it records anything was not, or
    /// could not be, established.
    Present,
    Absent,
}

impl SourceState {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::Unreadable => "unreadable",
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingSource {
    pub kind: SourceKind,
    pub state: SourceState,
}

const SOURCES_SCRIPT: &str = r#"LH_TAG=sources
echo "K|v1"
PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin
f=''; hidden=''
for c in /var/log/account/pacct /var/account/pacct /var/log/pacct /var/adm/pacct; do
  [ -s "$c" ] && { f=$c; break; }
  [ -d "${c%/*}" ] && [ ! -x "${c%/*}" ] && hidden=1
done
if [ -n "$f" ] && [ ! -r "$f" ]; then
  echo "S|accounting|unreadable"
elif [ -n "$f" ] && command -v dump-acct >/dev/null 2>&1; then
  echo "S|accounting|readable"
elif [ -n "$hidden" ]; then
  echo "S|accounting|unreadable"
elif command -v accton >/dev/null 2>&1 || command -v lastcomm >/dev/null 2>&1; then
  echo "S|accounting|present"
else
  echo "S|accounting|absent"
fi
if command -v auditctl >/dev/null 2>&1; then
  r=$(auditctl -l 2>/dev/null)
  case "$r" in *execve*) if command -v ausearch >/dev/null 2>&1; then echo "S|audit-execve|readable"; else echo "S|audit-execve|present"; fi ;; *) echo "S|audit-execve|present" ;; esac
else
  echo "S|audit-execve|absent"
fi
if command -v execsnoop >/dev/null 2>&1 || command -v execsnoop-bpfcc >/dev/null 2>&1; then echo "S|execsnoop|present"; else echo "S|execsnoop|absent"; fi
if command -v bpftrace >/dev/null 2>&1; then echo "S|bpftrace|present"; else echo "S|bpftrace|absent"; fi
"#;

fn parse_sources(output: &str) -> CoreResult<Vec<ExistingSource>> {
    let mut versioned = false;
    let mut sources = Vec::new();
    for line in output.lines() {
        let mut fields = line.trim().split('|');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("K"), Some("v1"), None) => versioned = true,
            (Some("S"), Some(kind), Some(state)) => {
                let kind = match kind {
                    "accounting" => SourceKind::Accounting,
                    "audit-execve" => SourceKind::AuditExecve,
                    "execsnoop" => SourceKind::Execsnoop,
                    "bpftrace" => SourceKind::Bpftrace,
                    _ => continue,
                };
                let state = match state {
                    "readable" => SourceState::Readable,
                    "unreadable" => SourceState::Unreadable,
                    "present" => SourceState::Present,
                    "absent" => SourceState::Absent,
                    _ => continue,
                };
                if !sources
                    .iter()
                    .any(|known: &ExistingSource| known.kind == kind)
                {
                    sources.push(ExistingSource { kind, state });
                }
            }
            _ => {}
        }
    }
    if !versioned || sources.is_empty() {
        return Err(CoreError::validation(
            "process watch existing sources",
            "the target did not answer",
        ));
    }
    Ok(sources)
}

/// What the accounting file says about one finished process. Accounting
/// keeps the program name only — no arguments — and writes the record when
/// the process exits, stamped with when it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingRecords {
    pub events: Vec<ProcessWatchEvent>,
    pub truncated: bool,
    /// Lines the reader could not parse; kept as a count, not hidden.
    pub unparsed: usize,
}

fn accounting_script(minutes: u32) -> String {
    // The file is append-only and can be large: only its tail is read, and
    // the cut-off is applied here from the record's own start time.
    format!(
        r#"LH_TAG=accounting
echo "K|v1"
PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin
f=''
for c in /var/log/account/pacct /var/account/pacct /var/log/pacct /var/adm/pacct; do
  [ -s "$c" ] && {{ f=$c; break; }}
done
if [ -z "$f" ] || [ ! -r "$f" ] || ! command -v dump-acct >/dev/null 2>&1; then echo "X|unavailable"; exit 0; fi
echo "Z|$(date +%z)|$(date +%s)|{minutes}"
dump-acct "$f" 2>/dev/null | tail -n {limit}
"#,
        minutes = minutes,
        limit = MAX_ACCOUNTING_RECORDS + 1,
    )
}

fn offset_seconds(text: &str) -> Option<i64> {
    let (sign, digits) = match text.as_bytes().first()? {
        b'+' => (1, &text[1..]),
        b'-' => (-1, &text[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let minutes: i64 = digits[2..].parse().ok()?;
    Some(sign * (hours * 3600 + minutes * 60))
}

fn parse_accounting(output: &str) -> CoreResult<AccountingRecords> {
    let mut lines = output.lines();
    if lines.next().map(str::trim) != Some("K|v1") {
        return Err(CoreError::validation(
            "process accounting",
            "the target did not answer",
        ));
    }
    let header = lines.next().unwrap_or("").trim();
    if header == "X|unavailable" {
        return Err(CoreError::validation(
            ACCOUNTING_UNAVAILABLE,
            "no readable accounting file or no dump-acct",
        ));
    }
    let fields: Vec<&str> = header.split('|').collect();
    let (Some(offset), Some(now), Some(minutes)) = (
        fields.get(1).and_then(|text| offset_seconds(text)),
        fields.get(2).and_then(|text| text.parse::<i64>().ok()),
        fields.get(3).and_then(|text| text.parse::<i64>().ok()),
    ) else {
        return Err(CoreError::validation(
            "process accounting",
            "the target's clock line could not be read",
        ));
    };
    let cutoff = now - minutes * 60;
    let mut events = Vec::new();
    let mut unparsed = 0;
    let mut seen = 0_usize;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        seen += 1;
        // comm|v3|utime|stime|etime|uid|gid|mem|io|pid|ppid|flags|exit|tty|date
        let fields: Vec<&str> = line.split('|').collect();
        let parsed = (|| {
            if fields.len() != 15 {
                return None;
            }
            let started = NaiveDateTime::parse_from_str(fields[14].trim(), "%a %b %e %H:%M:%S %Y")
                .ok()?
                .and_utc()
                .timestamp()
                - offset;
            Some((
                fields[0].trim().to_owned(),
                fields[5].trim().parse::<u32>().ok()?,
                fields[9].trim().parse::<u32>().ok()?,
                fields[10].trim().parse::<u32>().ok()?,
                started,
            ))
        })();
        let Some((name, uid, pid, ppid, started)) = parsed else {
            unparsed += 1;
            continue;
        };
        if started < cutoff || name.is_empty() {
            continue;
        }
        let command: String = name
            .chars()
            .map(|character| {
                if character.is_control() {
                    '\u{fffd}'
                } else {
                    character
                }
            })
            .take(64)
            .collect();
        events.push(ProcessWatchEvent {
            kind: ProcessWatchEventKind::Process,
            seq: events.len() as u64 + 1,
            at_ms: u64::try_from(started).unwrap_or(0).saturating_mul(1000),
            uid,
            pid,
            ppid: Some(ppid),
            start_ticks: None,
            command,
            clipped: false,
            origin: EventOrigin::Observed,
            own: false,
            raw: String::new(),
        });
    }
    events.sort_by_key(|event| event.at_ms);
    for (index, event) in events.iter_mut().enumerate() {
        event.seq = index as u64 + 1;
    }
    Ok(AccountingRecords {
        events,
        truncated: seen > MAX_ACCOUNTING_RECORDS,
        unparsed,
    })
}

impl ProcessWatchService {
    /// Which records of past process activity this target already keeps.
    pub async fn existing_sources(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<Vec<ExistingSource>> {
        self.target_context().validate(session.target())?;
        let output = self
            .ssh()
            .execute_bound(session, SOURCES_SCRIPT.to_owned(), Duration::from_secs(15))
            .await?;
        self.target_context().validate(session.target())?;
        validate_ssh_output("process watch existing sources", &output, 16 * 1024)?;
        parse_sources(&output.output)
    }

    /// The processes the accounting file recorded as started in the last
    /// `minutes`. Read-only: accounting is never switched on from here.
    pub async fn read_accounting(
        &self,
        session: &BoundSshSession,
        minutes: u32,
    ) -> CoreResult<AccountingRecords> {
        if !(ACCOUNTING_MIN_MINUTES..=ACCOUNTING_MAX_MINUTES).contains(&minutes) {
            return Err(CoreError::validation(
                "process accounting window",
                "outside the allowed range",
            ));
        }
        self.target_context().validate(session.target())?;
        let output = self
            .ssh()
            .execute_bound(session, accounting_script(minutes), Duration::from_secs(30))
            .await?;
        self.target_context().validate(session.target())?;
        validate_ssh_output("process accounting", &output, MAX_SOURCE_OUTPUT_BYTES)?;
        parse_accounting(&output.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_source_keeps_the_state_the_target_reported() {
        let sources = parse_sources(
            "K|v1\nS|accounting|unreadable\nS|audit-execve|present\nS|execsnoop|absent\n\
             S|bpftrace|present\nS|made-up|readable\nS|accounting|readable\n",
        )
        .unwrap();
        let states: Vec<(&str, &str)> = sources
            .iter()
            .map(|source| (source.kind.key(), source.state.key()))
            .collect();
        assert_eq!(
            states,
            vec![
                ("accounting", "unreadable"),
                ("audit-execve", "present"),
                ("execsnoop", "absent"),
                ("bpftrace", "present"),
            ]
        );
        assert!(parse_sources("S|accounting|readable\n").is_err());
        assert!(parse_sources("K|v1\n").is_err());
    }

    #[test]
    fn accounting_records_are_cut_to_the_window_in_the_targets_own_zone() {
        // 2026-11-14 14:10:13 +0800 is 06:10:13 UTC = 1794636613.
        let now = 1_794_636_613_i64 + 30;
        let output = format!(
            "K|v1\nZ|+0800|{now}|5\n\
sleep           |v3|     0.00|     0.00|    20.00|     0|     0|  2500.00|     0.00|     147|     146|     |       0|__      |Sat Nov 14 14:10:13 2026\n\
old             |v3|     0.00|     0.00|    20.00|     0|     0|  2500.00|     0.00|      90|       1|     |       0|__      |Sat Nov 14 13:00:00 2026\n\
lh-beacon       |v3|     0.00|     0.00|   150.00|  1000|  1000|  2592.00|     0.00|     150|     149|     |       0|__      |Sat Nov 14 14:10:01 2026\n\
garbage line\n"
        );
        let records = parse_accounting(&output).unwrap();
        let names: Vec<(&str, u32, u32, Option<u32>)> = records
            .events
            .iter()
            .map(|event| (event.command.as_str(), event.uid, event.pid, event.ppid))
            .collect();
        assert_eq!(
            names,
            vec![
                ("lh-beacon", 1000, 150, Some(149)),
                ("sleep", 0, 147, Some(146))
            ]
        );
        assert_eq!(records.events[1].at_ms, 1_794_636_613_000);
        assert_eq!(records.unparsed, 1);
        assert!(!records.truncated);
    }

    #[test]
    fn an_unreadable_file_is_a_refusal_not_an_empty_result() {
        let error = parse_accounting("K|v1\nX|unavailable\n").unwrap_err();
        assert!(
            matches!(error, CoreError::Validation { subject, .. } if subject == ACCOUNTING_UNAVAILABLE)
        );
        assert!(parse_accounting("K|v1\nZ|bad|1|5\n").is_err());
        assert_eq!(offset_seconds("-0530"), Some(-19_800));
        assert_eq!(offset_seconds("0800"), None);
    }
}
