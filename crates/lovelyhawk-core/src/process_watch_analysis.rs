//! What a finished process watch can say beyond "these commands ran": where
//! each one came from, which scheduled job it belongs to, and which workbench
//! check a read-only command resembles.
//!
//! All of it is inference from command lines and parent links. A parent that
//! exited before it was seen leaves the origin unknown, a command that looks
//! like a check says nothing about what was done with its output, and a
//! missing match is not evidence that nothing is scheduled.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use crate::process_watch::{
    EventOrigin, ProcessWatchEvent, ProcessWatchEventKind, ProcessWatchService, RepeatGroup,
    normalize_command, validate_ssh_output,
};
use crate::ssh::BoundSshSession;
use crate::{CoreError, CoreResult};

const MAX_ANCESTOR_HOPS: usize = 12;
const MAX_SCHEDULED: usize = 500;
const MAX_SCHEDULE_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_UNMATCHED: usize = 50;

/// Where a process came from, as far as its ancestors show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessOrigin {
    Cron,
    SshLogin,
    /// A web or database service spawned it.
    Service,
    /// The chain was followed to init without meeting any of the above.
    Other,
    /// The chain broke: no parent recorded, or the parent was never seen.
    Unknown,
}

impl ProcessOrigin {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Cron => "cron",
            Self::SshLogin => "ssh",
            Self::Service => "service",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginVerdict {
    pub origin: ProcessOrigin,
    /// The ancestor command that decided it; empty for `Other`/`Unknown`.
    pub via: String,
}

const SERVICE_NAMES: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    "php",
    "php-cgi",
    "java",
    "node",
    "gunicorn",
    "uwsgi",
    "caddy",
    "mysqld",
    "mariadbd",
    "postgres",
    "redis-server",
    "mongod",
];

fn program_name(command: &str) -> &str {
    let first = command.split_whitespace().next().unwrap_or("");
    let first = first.trim_matches(|character| matches!(character, '[' | ']' | ':' | '-'));
    first.rsplit('/').next().unwrap_or(first)
}

fn ancestor_origin(command: &str) -> Option<ProcessOrigin> {
    let name = program_name(command);
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "cron" | "crond" | "anacron" | "atd") {
        return Some(ProcessOrigin::Cron);
    }
    if lower == "sshd" || command.starts_with("sshd:") {
        return Some(ProcessOrigin::SshLogin);
    }
    // `php-fpm: pool www`, `nginx: worker process`, `postgres: writer`.
    let base = lower.split(':').next().unwrap_or(&lower);
    let versionless =
        base.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.');
    if SERVICE_NAMES.contains(&base) || SERVICE_NAMES.contains(&versionless) {
        return Some(ProcessOrigin::Service);
    }
    None
}

/// The origin of every process event, by sequence number.
pub fn classify_origins(events: &[ProcessWatchEvent]) -> HashMap<u64, OriginVerdict> {
    // A pid can be reused inside one window, so each keeps every sighting
    // and a lookup takes the latest one not after the child.
    let mut by_pid: HashMap<u32, Vec<&ProcessWatchEvent>> = HashMap::new();
    for event in events {
        if event.kind == ProcessWatchEventKind::Process {
            by_pid.entry(event.pid).or_default().push(event);
        }
    }
    for sightings in by_pid.values_mut() {
        sightings.sort_by_key(|event| (event.origin == EventOrigin::Observed, event.at_ms));
    }
    let lookup = |pid: u32, at_ms: u64| -> Option<&ProcessWatchEvent> {
        let sightings = by_pid.get(&pid)?;
        sightings
            .iter()
            .rev()
            .find(|event| event.origin == EventOrigin::Baseline || event.at_ms <= at_ms)
            .or_else(|| sightings.first())
            .copied()
    };
    let unknown = || OriginVerdict {
        origin: ProcessOrigin::Unknown,
        via: String::new(),
    };
    let mut verdicts = HashMap::new();
    for event in events {
        if event.kind != ProcessWatchEventKind::Process {
            continue;
        }
        let mut verdict = None;
        let mut current = event.ppid;
        for _ in 0..MAX_ANCESTOR_HOPS {
            let Some(pid) = current else {
                verdict = Some(unknown());
                break;
            };
            if pid <= 1 {
                verdict = Some(OriginVerdict {
                    origin: ProcessOrigin::Other,
                    via: String::new(),
                });
                break;
            }
            let Some(parent) = lookup(pid, event.at_ms) else {
                verdict = Some(unknown());
                break;
            };
            if let Some(origin) = ancestor_origin(&parent.command) {
                verdict = Some(OriginVerdict {
                    origin,
                    via: parent.command.chars().take(120).collect(),
                });
                break;
            }
            current = parent.ppid;
        }
        verdicts.insert(event.seq, verdict.unwrap_or_else(unknown));
    }
    verdicts
}

/// The origin a repeat group is shown under: the one most of its members
/// have, earliest member winning a tie.
pub fn group_origin(
    group: &RepeatGroup,
    events: &[ProcessWatchEvent],
    verdicts: &HashMap<u64, OriginVerdict>,
) -> OriginVerdict {
    let mut counts: BTreeMap<ProcessOrigin, (usize, u64, String)> = BTreeMap::new();
    for event in events {
        if event.kind != ProcessWatchEventKind::Process
            || event.own
            || event.origin == EventOrigin::Baseline
            || normalize_command(&event.command) != group.normalized
        {
            continue;
        }
        if let Some(verdict) = verdicts.get(&event.seq) {
            let entry = counts
                .entry(verdict.origin)
                .or_insert((0, event.seq, verdict.via.clone()));
            entry.0 += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|left, right| left.1.0.cmp(&right.1.0).then(right.1.1.cmp(&left.1.1)))
        .map(|(origin, (_, _, via))| OriginVerdict { origin, via })
        .unwrap_or(OriginVerdict {
            origin: ProcessOrigin::Unknown,
            via: String::new(),
        })
}

/// One command a cron file schedules, and the file that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledCommand {
    pub source: String,
    pub command: String,
}

/// What could be read of the target's schedules. `unreadable` lists sources
/// that exist but could not be read: with any of those, "no match" is not
/// "not scheduled".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduleListing {
    pub commands: Vec<ScheduledCommand>,
    pub unreadable: Vec<String>,
    pub truncated: bool,
}

const SCHEDULE_SCRIPT: &str = r#"LH_TAG=schedule
set -f
echo "K|v1"
n=0
emit_file() {
  f=$1; sys=$2
  [ -e "$f" ] || return 0
  if [ ! -r "$f" ]; then echo "G|$f"; return 0; fi
  while read -r m h dom mon dow rest; do
    case "$m" in ''|'#'*|*=*) continue ;; esac
    case "$m" in
      @*) cmd="$h $dom $mon $dow $rest" ;;
      *) cmd=$rest ;;
    esac
    if [ "$sys" = 1 ]; then cmd=${cmd#* }; fi
    [ -n "$cmd" ] || continue
    n=$((n+1)); [ "$n" -gt 500 ] && { echo "T|"; return 1; }
    printf '%s\n' "C|$f|$cmd"
  done < "$f"
  return 0
}
emit_file /etc/crontab 1 || exit 0
set +f
for f in /etc/cron.d/*; do
  set -f
  [ -f "$f" ] || continue
  emit_file "$f" 1 || exit 0
done
set +f
for d in /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/tabs; do
  if [ -d "$d" ] && [ ! -r "$d" ]; then echo "G|$d"; continue; fi
  for f in "$d"/*; do
    set -f
    [ -f "$f" ] || continue
    emit_file "$f" 0 || exit 0
  done
  set +f
done
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    n=$((n+1)); [ "$n" -gt 500 ] && { echo "T|"; exit 0; }
    printf '%s\n' "C|$d|$f"
  done
done
"#;

fn parse_schedule(output: &str) -> CoreResult<ScheduleListing> {
    let mut listing = ScheduleListing::default();
    let mut versioned = false;
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "K" => versioned = value == "v1",
            "T" => listing.truncated = true,
            "G" => listing.unreadable.push(value.chars().take(256).collect()),
            "C" => {
                if let Some((source, command)) = value.split_once('|') {
                    if listing.commands.len() < MAX_SCHEDULED && !command.trim().is_empty() {
                        listing.commands.push(ScheduledCommand {
                            source: source.chars().take(256).collect(),
                            command: command.trim().chars().take(1024).collect(),
                        });
                    } else if listing.commands.len() >= MAX_SCHEDULED {
                        listing.truncated = true;
                    }
                }
            }
            _ => {}
        }
    }
    if !versioned {
        return Err(CoreError::validation(
            "process watch schedule listing",
            "the target did not answer",
        ));
    }
    Ok(listing)
}

/// The program a scheduled command starts: its first word that is neither an
/// environment assignment nor a wrapper that only runs something else.
fn scheduled_program(command: &str) -> Option<&str> {
    let mut words = command.split_whitespace();
    while let Some(word) = words.next() {
        if word == "cd" {
            // The directory changed into is not the program.
            words.next();
            continue;
        }
        let word = word.trim_matches(|character| matches!(character, '"' | '\'' | ';' | '{' | '}'));
        let skipped = word.contains('=')
            || word.starts_with('-')
            || matches!(
                word,
                "sh" | "bash" | "/bin/sh" | "/bin/bash" | "exec" | "nice" | "nohup" | "test"
                    | "[" | "]" | "&&" | "||" | "run-parts"
            )
            // A path has to name something: "/" alone would match everything.
            || !word.chars().any(|character| character.is_ascii_alphanumeric());
        if !skipped {
            return Some(word);
        }
    }
    None
}

/// The schedule a command belongs to, when one names the same program.
///
/// A path matches when the command line contains it; a bare name only when
/// it is the program of one of the command's words, so `date` in a crontab
/// does not claim every command line with "date" somewhere in it.
pub fn match_schedule<'a>(
    command: &str,
    listing: &'a ScheduleListing,
) -> Option<&'a ScheduledCommand> {
    listing.commands.iter().find(|scheduled| {
        let Some(program) = scheduled_program(&scheduled.command) else {
            return false;
        };
        if program.starts_with('/') {
            command.contains(program)
        } else {
            command
                .split_whitespace()
                .any(|word| word.rsplit('/').next() == Some(program))
        }
    })
}

impl ProcessWatchService {
    /// Reads what the cron files schedule, for matching against a finished
    /// watch. Read-only and bounded; unreadable sources are named.
    pub async fn scheduled_commands(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<ScheduleListing> {
        self.target_context().validate(session.target())?;
        let output = self
            .ssh()
            .execute_bound(session, SCHEDULE_SCRIPT.to_owned(), Duration::from_secs(15))
            .await?;
        self.target_context().validate(session.target())?;
        validate_ssh_output(
            "process watch schedule listing",
            &output,
            MAX_SCHEDULE_OUTPUT_BYTES,
        )?;
        parse_schedule(&output.output)
    }
}

/// A workbench check that an observed read-only command resembles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredCheck {
    /// Catalogue id of the workbench entry.
    pub entry_id: &'static str,
    pub count: usize,
    pub sample: String,
}

/// Fragments of a command line and the workbench entry that looks at the
/// same thing. Order matters: the first rule that matches takes the command.
const CHECK_RULES: &[(&[&str], &str)] = &[
    (
        &[
            "/etc/crontab",
            "/etc/cron.",
            "/var/spool/cron",
            "crontab -l",
        ],
        "persistence-system-crontab",
    ),
    (
        &["lsmod", "/proc/modules", "/sys/module", "modinfo "],
        "system-modules",
    ),
    (&["getcap"], "perm-capabilities"),
    (&["-perm "], "perm-suid"),
    (&["authorized_keys"], "account-authorized-keys"),
    (&["sshd_config", "sshd -T"], "account-sshd-config"),
    (&["/etc/sudoers", "sudo -l"], "account-sudoers"),
    (
        &["/etc/passwd", "/etc/shadow", "getent passwd"],
        "account-users",
    ),
    (&["/etc/xinetd", "/etc/inetd.conf"], "persistence-inetd"),
    (&[".vimrc", "/etc/vim"], "persistence-editor-config"),
    (
        &["/etc/init.d", "/etc/rc.local", "/etc/rc.d"],
        "persistence-rc",
    ),
    (
        &[
            "/etc/profile",
            ".bashrc",
            ".bash_profile",
            "/etc/bash.bashrc",
        ],
        "persistence-profile-content",
    ),
    (
        &[
            "systemctl list-",
            "systemctl is-enabled",
            "/etc/systemd/system",
        ],
        "persistence-services",
    ),
    (
        &["iptables", "nft list", "firewall-cmd", "ufw status"],
        "network-firewall",
    ),
    (
        &["ss -", "netstat", "lsof -i", "/proc/net/tcp"],
        "network-listen",
    ),
    (&["ps -", "ps aux", "ps auxf", "pstree"], "process-all"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckInference {
    pub checks: Vec<InferredCheck>,
    /// Observed commands no rule covers, most frequent first. Listed so
    /// "not mapped" stays visible instead of looking like "nothing ran".
    pub unmatched: Vec<(String, usize)>,
    pub unmatched_truncated: bool,
}

fn rule_for(command: &str) -> Option<&'static str> {
    // `ps` as a whole word, so "ps -ef" matches and "cups -x" does not.
    CHECK_RULES.iter().find_map(|(fragments, entry)| {
        fragments
            .iter()
            .any(|fragment| {
                if let Some(word) = fragment.strip_prefix("ps ") {
                    command.split_once(' ').is_some_and(|(program, rest)| {
                        program.rsplit('/').next() == Some("ps") && rest.starts_with(word)
                    })
                } else {
                    command.contains(fragment)
                }
            })
            .then_some(*entry)
    })
}

/// Maps the watch's own observations (not baseline, not this tool) to the
/// workbench entries that examine the same thing.
pub fn infer_checks(events: &[ProcessWatchEvent]) -> CheckInference {
    let mut matched: BTreeMap<&'static str, (usize, String)> = BTreeMap::new();
    let mut unmatched: BTreeMap<String, usize> = BTreeMap::new();
    for event in events {
        if event.own || event.origin == EventOrigin::Baseline {
            continue;
        }
        match rule_for(&event.command) {
            Some(entry) => {
                let slot = matched
                    .entry(entry)
                    .or_insert_with(|| (0, event.command.chars().take(240).collect()));
                slot.0 += 1;
            }
            None if event.kind == ProcessWatchEventKind::Process => {
                *unmatched
                    .entry(normalize_command(&event.command))
                    .or_default() += 1;
            }
            None => {}
        }
    }
    let mut checks: Vec<InferredCheck> = matched
        .into_iter()
        .map(|(entry_id, (count, sample))| InferredCheck {
            entry_id,
            count,
            sample,
        })
        .collect();
    checks.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then(left.entry_id.cmp(right.entry_id))
    });
    let mut unmatched: Vec<(String, usize)> = unmatched.into_iter().collect();
    unmatched.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    let unmatched_truncated = unmatched.len() > MAX_UNMATCHED;
    unmatched.truncate(MAX_UNMATCHED);
    CheckInference {
        checks,
        unmatched,
        unmatched_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_workbench::shipped_catalog;
    use crate::process_watch::repeat_groups;

    fn process(
        seq: u64,
        pid: u32,
        ppid: Option<u32>,
        at_ms: u64,
        command: &str,
    ) -> ProcessWatchEvent {
        ProcessWatchEvent {
            kind: ProcessWatchEventKind::Process,
            seq,
            at_ms,
            uid: 0,
            pid,
            ppid,
            start_ticks: None,
            command: command.to_owned(),
            clipped: false,
            origin: EventOrigin::Observed,
            own: false,
            raw: String::new(),
        }
    }

    fn baseline(seq: u64, pid: u32, ppid: u32, command: &str) -> ProcessWatchEvent {
        ProcessWatchEvent {
            origin: EventOrigin::Baseline,
            ..process(seq, pid, Some(ppid), 0, command)
        }
    }

    #[test]
    fn origins_follow_the_parent_chain_and_admit_a_broken_one() {
        let events = vec![
            baseline(1, 1, 0, "/sbin/init"),
            baseline(2, 300, 1, "/usr/sbin/cron -f"),
            baseline(3, 400, 1, "sshd: /usr/sbin/sshd -D [listener]"),
            baseline(4, 500, 1, "nginx: master process /usr/sbin/nginx"),
            baseline(5, 600, 1, "/usr/lib/systemd/systemd-journald"),
            process(6, 900, Some(300), 1_000, "/usr/sbin/CRON -f"),
            process(7, 901, Some(900), 1_000, "/bin/sh -c /usr/local/bin/job"),
            process(8, 902, Some(901), 1_100, "/usr/local/bin/job"),
            process(9, 910, Some(400), 2_000, "sshd: root@pts/0"),
            process(10, 911, Some(910), 2_100, "-bash"),
            process(11, 912, Some(911), 2_200, "id"),
            process(12, 920, Some(500), 3_000, "sh -c whoami"),
            process(13, 930, Some(600), 4_000, "logger hello"),
            process(14, 940, Some(7777), 5_000, "orphan"),
            process(15, 950, None, 6_000, "no parent recorded"),
        ];
        let verdicts = classify_origins(&events);
        let origin = |seq: u64| verdicts[&seq].origin;
        assert_eq!(origin(8), ProcessOrigin::Cron);
        assert_eq!(verdicts[&8].via, "/usr/sbin/CRON -f");
        assert_eq!(origin(11), ProcessOrigin::SshLogin);
        assert_eq!(origin(12), ProcessOrigin::Service);
        assert_eq!(origin(13), ProcessOrigin::Other);
        assert_eq!(origin(14), ProcessOrigin::Unknown);
        assert_eq!(origin(15), ProcessOrigin::Unknown);
    }

    #[test]
    fn a_reused_pid_takes_the_parent_that_was_there_at_the_time() {
        let events = vec![
            baseline(1, 300, 1, "/usr/sbin/cron -f"),
            process(2, 800, Some(300), 1_000, "/usr/sbin/CRON -f"),
            process(3, 801, Some(800), 1_100, "first-job"),
            process(4, 800, Some(1), 9_000, "unrelated"),
            process(5, 802, Some(800), 9_100, "second-job"),
        ];
        let verdicts = classify_origins(&events);
        assert_eq!(verdicts[&3].origin, ProcessOrigin::Cron);
        assert_eq!(verdicts[&5].origin, ProcessOrigin::Other);
    }

    #[test]
    fn a_group_is_shown_under_the_origin_most_members_have() {
        let mut events = vec![baseline(1, 300, 1, "/usr/sbin/cron -f")];
        for index in 0..3_u32 {
            events.push(process(
                u64::from(index) + 2,
                900 + index,
                Some(300),
                u64::from(index) * 60_000,
                "/usr/local/bin/job",
            ));
        }
        events.push(process(9, 990, Some(1), 500_000, "/usr/local/bin/job"));
        let groups = repeat_groups(&events);
        let verdicts = classify_origins(&events);
        let verdict = group_origin(&groups[0], &events, &verdicts);
        assert_eq!(verdict.origin, ProcessOrigin::Cron);
    }

    #[test]
    fn schedules_are_read_per_file_format_and_matched_by_program() {
        let listing = parse_schedule(
            "K|v1\nC|/etc/crontab|/usr/local/bin/lh-beacon --quiet\n\
             C|/var/spool/cron/crontabs/alice|cd /srv && ./rotate.sh\n\
             C|/etc/cron.d/sys|date >> /var/log/tick\n\
             C|/etc/cron.daily|/etc/cron.daily/logrotate\nG|/var/spool/cron/crontabs\n\
             C|/etc/crontab|cd / && run-parts --report /etc/cron.hourly\n\
             C|/etc/crontab|test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }\n",
        )
        .unwrap();
        assert_eq!(listing.commands.len(), 6);
        assert_eq!(
            scheduled_program("cd / && run-parts --report /etc/cron.hourly"),
            Some("/etc/cron.hourly")
        );
        assert_eq!(scheduled_program("cd /"), None);
        assert_eq!(
            listing.unreadable,
            vec!["/var/spool/cron/crontabs".to_owned()]
        );
        let source =
            |command: &str| match_schedule(command, &listing).map(|found| found.source.as_str());
        assert_eq!(
            source("/bin/sh -c /usr/local/bin/lh-beacon --quiet"),
            Some("/etc/crontab")
        );
        assert_eq!(
            source("/bin/sh /etc/cron.daily/logrotate"),
            Some("/etc/cron.daily")
        );
        assert_eq!(source("date"), Some("/etc/cron.d/sys"));
        assert_eq!(source("/usr/bin/date +%s"), Some("/etc/cron.d/sys"));
        assert_eq!(
            source("/bin/sh /etc/cron.hourly/0anacron"),
            Some("/etc/crontab")
        );
        assert_eq!(source("/usr/local/bin/lh-check"), None);
        assert_eq!(source("update-ca-certificates"), None);
        assert_eq!(source("sleep 10"), None);
        assert!(parse_schedule("C|/etc/crontab|x\n").is_err());
    }

    #[test]
    fn every_inference_rule_names_a_real_workbench_entry() {
        let catalog: Vec<&str> = shipped_catalog().iter().map(|entry| entry.id).collect();
        for (_, entry) in CHECK_RULES {
            assert!(catalog.contains(entry), "{entry} is not in the catalogue");
        }
    }

    #[test]
    fn observed_checks_map_to_entries_and_the_rest_stays_listed() {
        let mut events = vec![
            process(1, 10, Some(1), 1, "cat /etc/crontab"),
            process(2, 11, Some(1), 2, "lsmod"),
            process(3, 12, Some(1), 3, "find / -perm -4000 -type f"),
            process(4, 13, Some(1), 4, "ps -ef"),
            process(5, 14, Some(1), 5, "cups -x"),
            process(6, 15, Some(1), 6, "grep insmod /etc/profile"),
            process(7, 16, Some(1), 7, "cat /etc/crontab"),
            process(8, 17, Some(1), 8, "sleep 5"),
        ];
        events.push(ProcessWatchEvent {
            own: true,
            ..process(9, 18, Some(1), 9, "cat /etc/shadow")
        });
        events.push(baseline(10, 19, 1, "ss -lntp"));
        events.push(ProcessWatchEvent {
            kind: ProcessWatchEventKind::File,
            ..process(11, 0, None, 10, "OPEN /root/.ssh/authorized_keys")
        });
        let inference = infer_checks(&events);
        let found: Vec<(&str, usize)> = inference
            .checks
            .iter()
            .map(|check| (check.entry_id, check.count))
            .collect();
        assert_eq!(
            found,
            vec![
                ("persistence-system-crontab", 2),
                ("account-authorized-keys", 1),
                ("perm-suid", 1),
                ("persistence-profile-content", 1),
                ("process-all", 1),
                ("system-modules", 1),
            ]
        );
        assert_eq!(
            inference.unmatched,
            vec![("cups -x".to_owned(), 1), ("sleep 5".to_owned(), 1)]
        );
    }
}
