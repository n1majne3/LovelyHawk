//! The upload method of the process watch: an operator-supplied pspy binary
//! is written to a private directory on the target, run for a bounded time
//! under a wrapper that speaks the same wire protocol as the `/proc` poll,
//! and removed again however the run ended.
//!
//! Nothing here is bundled: the binary comes from a file the operator picked,
//! and the digest table only says which upstream release a file is. pspy is
//! GPL-3.0 (github.com/DominicBreuker/pspy, LICENSE), which is why it is not
//! shipped inside this application.

use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::process_watch::{
    LiveProcessWatch, ProcessWatchMethod, ProcessWatchService, WATCH_HEADER, truncate_utf8_bytes,
    validate_marker, validate_ssh_output, watch_marker, watch_prelude,
};
use crate::sftp::content_sha256;
use crate::shell_escape::shq;
use crate::ssh::{BoundSshSession, SshSensitiveCommandLimits};
use crate::{CoreError, CoreResult};

pub const TOOL_MIN_BYTES: usize = 64 * 1024;
pub const TOOL_MAX_BYTES: usize = 16 * 1024 * 1024;
const UPLOAD_CHUNK_BYTES: usize = 48 * 1024;
const UPLOAD_STEP_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_UPLOAD_PROBE_BYTES: usize = 256 * 1024;
const SPACE_MARGIN_BYTES: u64 = 1024 * 1024;
const LOW_INOTIFY_WATCHES: u64 = 8_192;
const MAX_RESIDUES: usize = 16;
/// The one name a landing directory can have; cleanup refuses anything else.
const LANDING_PREFIX: &str = ".lovelyhawk-watch-";
const TOOL_FILE: &str = "pspy";

pub const UPLOAD_ARCH_REFUSAL: &str = "process watch upload architecture";
pub const UPLOAD_TOOL_REFUSAL: &str = "process watch upload tool";
pub const UPLOAD_DIRECTORY_REFUSAL: &str = "process watch upload directory";
pub const UPLOAD_SPACE_REFUSAL: &str = "process watch upload space";
pub const UPLOAD_TOOLS_REFUSAL: &str = "process watch upload tools";
pub const UPLOAD_RUNNING_REFUSAL: &str = "process watch upload running";
pub const UPLOAD_DIGEST_REFUSAL: &str = "process watch upload digest";

/// SHA-256 of the four assets of upstream release v1.2.1, computed on
/// 2026-11-14 from files downloaded from
/// github.com/DominicBreuker/pspy/releases/tag/v1.2.1 (sizes matched the
/// release listing; upstream publishes no digests of its own).
const KNOWN_TOOLS: &[(&str, &str)] = &[
    (
        "1e38ac09d7851b22e16980abc58f93cabdc4a02859c56a2810aa51930277d450",
        "pspy32 v1.2.1",
    ),
    (
        "f2e8ed736e90aa38fd23606937e9e8393db6d10cb3be426afe4b65564860df35",
        "pspy32s v1.2.1",
    ),
    (
        "c93f29a5cc1347bdb90e14a12424e6469c8cfea9a20b800bc249755f0043a3bb",
        "pspy64 v1.2.1",
    ),
    (
        "e0277c164facb2d0fb95682a77887dd908b0e1dacb28a2bcafd6728b34835425",
        "pspy64s v1.2.1",
    ),
];

/// Directories whose file events are printed when the operator asks for
/// them. A fixed, short list: every watched directory's events are printed,
/// so the wide default set would drown the process rows.
const FILE_EVENT_DIRS: &[&str] = &[
    "/etc",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/var/spool/cron",
    "/var/www",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolArch {
    X86,
    X86_64,
    Other,
}

impl ToolArch {
    pub const fn key(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Other => "other",
        }
    }
}

/// What the picked file is, read from its own bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolFacts {
    pub sha256: String,
    pub size: u64,
    pub arch: ToolArch,
    /// The upstream asset this digest belongs to, when it is one.
    pub recognized: Option<&'static str>,
}

/// The upstream release asset a digest belongs to, when it is one.
pub fn known_tool(sha256: &str) -> Option<&'static str> {
    KNOWN_TOOLS
        .iter()
        .find(|(digest, _)| *digest == sha256)
        .map(|(_, name)| *name)
}

pub fn inspect_tool(bytes: &[u8]) -> CoreResult<ToolFacts> {
    if bytes.len() < TOOL_MIN_BYTES || bytes.len() > TOOL_MAX_BYTES {
        return Err(CoreError::validation(
            UPLOAD_TOOL_REFUSAL,
            "the file is not the size of a pspy program",
        ));
    }
    if !bytes.starts_with(b"\x7fELF") || bytes[5] != 1 {
        return Err(CoreError::validation(
            UPLOAD_TOOL_REFUSAL,
            "the file is not a little-endian Linux ELF program",
        ));
    }
    let arch = match (bytes[4], u16::from_le_bytes([bytes[18], bytes[19]])) {
        (1, 3) => ToolArch::X86,
        (2, 62) => ToolArch::X86_64,
        _ => ToolArch::Other,
    };
    let sha256 = content_sha256(bytes);
    let recognized = known_tool(&sha256);
    Ok(ToolFacts {
        sha256,
        size: bytes.len() as u64,
        arch,
        recognized,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryCandidate {
    pub path: String,
    pub free_bytes: u64,
    pub noexec: bool,
}

/// A landing directory from an earlier run that is still on the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResidue {
    pub directory: String,
    pub size: u64,
    pub sha256: String,
    pub running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadProbe {
    pub machine: String,
    pub account: String,
    pub is_root: bool,
    pub candidates: Vec<DirectoryCandidate>,
    pub has_sha256sum: bool,
    pub has_readlink: bool,
    pub inotify_watches: Option<u64>,
    pub residues: Vec<ToolResidue>,
    pub file_event_dirs: Vec<String>,
    pub watch_running: bool,
}

/// The immutable description of one upload run. Everything the wrapper and
/// the cleanup need is fixed here; nothing is re-read from the page later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPlan {
    pub marker: String,
    pub directory: String,
    pub tool_path: String,
    pub tool: ToolFacts,
    pub duration_secs: u32,
    pub file_events: bool,
    pub file_event_dirs: Vec<String>,
    pub account: String,
    pub is_root: bool,
    pub machine: String,
    pub low_inotify: bool,
}

fn machine_arch(machine: &str) -> Option<ToolArch> {
    match machine {
        "x86_64" | "amd64" => Some(ToolArch::X86_64),
        "i386" | "i486" | "i586" | "i686" => Some(ToolArch::X86),
        _ => None,
    }
}

fn safe_directory(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 200
        && !path.contains("//")
        && !path.split('/').any(|part| part == "." || part == "..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

/// Whether `directory` is exactly a landing directory this module creates.
pub fn is_landing_directory(directory: &str) -> bool {
    let Some((parent, name)) = directory.rsplit_once('/') else {
        return false;
    };
    safe_directory(parent)
        && name
            .strip_prefix(LANDING_PREFIX)
            .is_some_and(|marker| validate_marker(marker).is_ok())
}

/// Decide where the tool lands and whether this run can happen at all.
pub fn plan_upload(
    probe: &UploadProbe,
    tool: &ToolFacts,
    duration_secs: u32,
    file_events: bool,
) -> CoreResult<UploadPlan> {
    if !(crate::process_watch::PROCESS_WATCH_MIN_SECONDS
        ..=crate::process_watch::PROCESS_WATCH_MAX_SECONDS)
        .contains(&duration_secs)
    {
        return Err(CoreError::validation(
            "process watch duration",
            "outside the allowed range",
        ));
    }
    if probe.watch_running {
        return Err(CoreError::validation(
            UPLOAD_RUNNING_REFUSAL,
            "a watch is already running on the target",
        ));
    }
    let wanted = machine_arch(&probe.machine).ok_or_else(|| {
        CoreError::validation(
            UPLOAD_ARCH_REFUSAL,
            "upstream publishes pspy for x86 only; this machine is another architecture",
        )
    })?;
    // A 32-bit static program runs on a 64-bit x86 kernel; the reverse does not.
    let runnable =
        tool.arch == wanted || (wanted == ToolArch::X86_64 && tool.arch == ToolArch::X86);
    if !runnable {
        return Err(CoreError::validation(
            UPLOAD_TOOL_REFUSAL,
            "the chosen program is built for a different architecture than the target",
        ));
    }
    if !probe.has_sha256sum || !probe.has_readlink {
        return Err(CoreError::validation(
            UPLOAD_TOOLS_REFUSAL,
            "sha256sum and readlink are needed to verify the upload and to stop it by identity",
        ));
    }
    let usable: Vec<&DirectoryCandidate> = probe
        .candidates
        .iter()
        .filter(|candidate| !candidate.noexec && safe_directory(&candidate.path))
        .collect();
    if usable.is_empty() {
        return Err(CoreError::validation(
            UPLOAD_DIRECTORY_REFUSAL,
            "no writable directory that allows running programs was found",
        ));
    }
    let needed = tool.size.saturating_add(SPACE_MARGIN_BYTES);
    let chosen = usable
        .iter()
        .find(|candidate| candidate.free_bytes >= needed)
        .ok_or_else(|| {
            CoreError::validation(
                UPLOAD_SPACE_REFUSAL,
                "not enough free space in any usable directory",
            )
        })?;
    let marker = watch_marker();
    let directory = format!(
        "{}/{LANDING_PREFIX}{marker}",
        chosen.path.trim_end_matches('/')
    );
    Ok(UploadPlan {
        tool_path: format!("{directory}/{TOOL_FILE}"),
        marker,
        directory,
        tool: tool.clone(),
        duration_secs,
        file_events,
        file_event_dirs: if file_events {
            probe.file_event_dirs.clone()
        } else {
            Vec::new()
        },
        account: probe.account.clone(),
        is_root: probe.is_root,
        machine: probe.machine.clone(),
        low_inotify: probe
            .inotify_watches
            .is_some_and(|watches| watches < LOW_INOTIFY_WATCHES),
    })
}

/// How a cleanup ended. Only `Clean` means the target was looked at and
/// neither the process nor the files are there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    Clean,
    /// The target answered and something is still there.
    Residue {
        directory: String,
        running: u32,
    },
    /// The target could not be asked (connection gone, command failed).
    Unverified {
        directory: String,
    },
}

/// What an upload run leaves to remove, and the one answer removing it gave.
#[derive(Debug)]
pub struct ToolCleanup {
    service: ProcessWatchService,
    session: BoundSshSession,
    directory: String,
    done: tokio::sync::Mutex<Option<CleanupOutcome>>,
}

impl ToolCleanup {
    pub async fn run(&self) -> CleanupOutcome {
        let mut done = self.done.lock().await;
        if let Some(outcome) = done.as_ref() {
            // A residue or an unanswered check is worth asking again; a
            // clean answer is final.
            if *outcome == CleanupOutcome::Clean {
                return outcome.clone();
            }
        }
        let outcome = self
            .service
            .clean_landing_directory(&self.session, &self.directory)
            .await;
        *done = Some(outcome.clone());
        outcome
    }

    pub fn directory(&self) -> &str {
        &self.directory
    }
}

impl ProcessWatchService {
    /// Read-only look at whether and where an upload could run, and at what
    /// earlier runs left behind.
    pub async fn upload_probe(&self, session: &BoundSshSession) -> CoreResult<UploadProbe> {
        self.target_context().validate(session.target())?;
        let output = self
            .ssh()
            .execute_bound(session, UPLOAD_PROBE.to_owned(), Duration::from_secs(20))
            .await?;
        self.target_context().validate(session.target())?;
        validate_ssh_output(
            "process watch upload probe",
            &output,
            MAX_UPLOAD_PROBE_BYTES,
        )?;
        parse_upload_probe(&output.output)
    }

    /// Writes the tool into a new private directory and proves the bytes on
    /// the target are the bytes that were picked. Any failure removes what
    /// was written before the error is returned.
    pub async fn upload_tool(
        &self,
        session: &BoundSshSession,
        plan: &UploadPlan,
        bytes: &[u8],
    ) -> CoreResult<()> {
        if !is_landing_directory(&plan.directory) || content_sha256(bytes) != plan.tool.sha256 {
            return Err(CoreError::validation(
                UPLOAD_DIGEST_REFUSAL,
                "the upload no longer matches its plan",
            ));
        }
        self.target_context().validate(session.target())?;
        let result = self.write_tool(session, plan, bytes).await;
        if result.is_err() {
            let _ = self.clean_landing_directory(session, &plan.directory).await;
        }
        result
    }

    async fn write_tool(
        &self,
        session: &BoundSshSession,
        plan: &UploadPlan,
        bytes: &[u8],
    ) -> CoreResult<()> {
        let directory = shq(&plan.directory);
        let tool = shq(&plan.tool_path);
        // `mkdir` without -p: an existing directory is somebody else's.
        self.upload_step(
            session,
            format!("umask 077 && mkdir {directory} && : > {tool}"),
            Vec::new(),
        )
        .await?;
        for chunk in bytes.chunks(UPLOAD_CHUNK_BYTES) {
            self.upload_step(session, format!("cat >> {tool}"), chunk.to_vec())
                .await?;
            self.target_context().validate(session.target())?;
        }
        let digest = self
            .upload_step(
                session,
                format!("chmod 700 {tool} && sha256sum {tool}"),
                Vec::new(),
            )
            .await?;
        let remote = digest.split_whitespace().next().unwrap_or("");
        if remote != plan.tool.sha256 {
            return Err(CoreError::validation(
                UPLOAD_DIGEST_REFUSAL,
                "the file on the target does not match the chosen program",
            ));
        }
        Ok(())
    }

    async fn upload_step(
        &self,
        session: &BoundSshSession,
        command: String,
        stdin: Vec<u8>,
    ) -> CoreResult<String> {
        let output = self
            .ssh()
            .execute_bound_sensitive(
                session,
                Zeroizing::new(command),
                Zeroizing::new(stdin),
                UPLOAD_STEP_TIMEOUT,
                SshSensitiveCommandLimits::new(4096, 4096)?,
            )
            .await?;
        if output.exit_code != Some(0) {
            return Err(CoreError::validation(
                "process watch upload",
                format!("a write step failed (exit={:?})", output.exit_code),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Runs the uploaded tool under the wrapper. The returned watch carries
    /// the cleanup, so every way of ending it removes the tool.
    pub async fn start_uploaded(
        &self,
        session: &BoundSshSession,
        plan: &UploadPlan,
    ) -> CoreResult<LiveProcessWatch> {
        let command = generate_tool_command(plan)?;
        let cleanup = Arc::new(ToolCleanup {
            service: self.clone(),
            session: session.clone(),
            directory: plan.directory.clone(),
            done: tokio::sync::Mutex::new(None),
        });
        match self
            .start_command(
                session,
                plan.marker.clone(),
                command,
                plan.duration_secs,
                ProcessWatchMethod::Pspy,
                Some(cleanup.clone()),
            )
            .await
        {
            Ok(live) => Ok(live),
            Err(error) => {
                let _ = cleanup.run().await;
                Err(error)
            }
        }
    }

    /// Stops whatever still runs from `directory` — found by its executable
    /// path, never by name — removes the tool and the directory, and looks
    /// again. Refuses any path that is not a landing directory.
    pub async fn clean_landing_directory(
        &self,
        session: &BoundSshSession,
        directory: &str,
    ) -> CleanupOutcome {
        if !is_landing_directory(directory) {
            return CleanupOutcome::Unverified {
                directory: directory.to_owned(),
            };
        }
        let unverified = || CleanupOutcome::Unverified {
            directory: directory.to_owned(),
        };
        if self.target_context().validate(session.target()).is_err() {
            return unverified();
        }
        let command = CLEANUP_SCRIPT.replace("@DIR@", &shq(directory));
        let Ok(output) = self
            .ssh()
            .execute_bound(session, command, CLEANUP_TIMEOUT)
            .await
        else {
            return unverified();
        };
        if output.timed_out {
            return unverified();
        }
        match parse_cleanup(&output.output) {
            Some((0, false)) => CleanupOutcome::Clean,
            Some((running, _)) => CleanupOutcome::Residue {
                directory: directory.to_owned(),
                running,
            },
            None => unverified(),
        }
    }
}

fn parse_cleanup(output: &str) -> Option<(u32, bool)> {
    let line = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("R|"))?;
    let (running, present) = line.split_once('|')?;
    Some((running.parse().ok()?, present == "present"))
}

/// Lines pspy prints that are not events: its banner and start/exit notes.
pub fn is_tool_banner(text: &str) -> bool {
    let line = text.trim();
    line.is_empty()
        || line == "done"
        || line.starts_with("pspy - version")
        || line.starts_with("Config: ")
        || line.starts_with("Draining file system events")
        || line.starts_with("Exiting program")
        || line.chars().all(|character| {
            character.is_whitespace()
                || matches!(character, '█' | '▓' | '▒' | '░' | '▄' | '▐' | '▌' | '▀')
        })
}

const UPLOAD_PROBE: &str = r#"LH_TAG="lh""watch"
echo "K|v1"
echo "M|$(uname -m 2>/dev/null)"
echo "A|$(id -un 2>/dev/null || echo '?')"
echo "U|$(id -u 2>/dev/null)"
if command -v sha256sum >/dev/null 2>&1; then echo "S|yes"; else echo "S|no"; fi
if command -v readlink >/dev/null 2>&1; then echo "L|yes"; else echo "L|no"; fi
if [ -r /proc/sys/fs/inotify/max_user_watches ]; then
  echo "N|$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null)"
fi
if [ -r /proc/mounts ]; then
  n=0
  while read -r dev mp fst opts rest; do
    n=$((n+1)); [ "$n" -gt 400 ] && break
    echo "O|$mp|$opts"
  done < /proc/mounts
fi
for d in "$XDG_RUNTIME_DIR" /dev/shm /tmp /var/tmp "$HOME"; do
  [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && [ -x "$d" ] || continue
  av=$(df -Pk "$d" 2>/dev/null | { read -r _h; read -r _f _b _u a _r; echo "$a"; })
  echo "D|$d|$av"
  for r in "$d"/.lovelyhawk-watch-*; do
    [ -d "$r" ] || continue
    sz=0; sum=''
    if [ -f "$r/pspy" ]; then
      sz=$(wc -c < "$r/pspy" 2>/dev/null)
      sum=$(sha256sum "$r/pspy" 2>/dev/null | { read -r s _n; echo "$s"; })
    fi
    run=0
    for pd in /proc/[0-9]*; do
      e=$(readlink "$pd/exe" 2>/dev/null) || continue
      case "$e" in "$r/pspy"|"$r/pspy (deleted)") run=1; break ;; esac
    done
    echo "R|$r|$sz|$sum|$run"
  done
done
for d in /etc /tmp /var/tmp /dev/shm /var/spool/cron /var/www; do
  [ -d "$d" ] && echo "F|$d"
done
found=0
for sf in /proc/[0-9]*/cmdline; do
  cmd="$(tr '\000' ' ' < "$sf" 2>/dev/null)" || continue
  case "$cmd" in *"$LH_TAG"-*) found=1; break ;; esac
done
echo "W|$found"
"#;

fn parse_upload_probe(output: &str) -> CoreResult<UploadProbe> {
    let mut probe = UploadProbe {
        machine: String::new(),
        account: "?".to_owned(),
        is_root: false,
        candidates: Vec::new(),
        has_sha256sum: false,
        has_readlink: false,
        inotify_watches: None,
        residues: Vec::new(),
        file_event_dirs: Vec::new(),
        watch_running: false,
    };
    let mut mounts: Vec<(String, bool)> = Vec::new();
    let mut versioned = false;
    for line in output.lines() {
        let Some((key, value)) = line.trim_end().split_once('|') else {
            continue;
        };
        match key {
            "K" => versioned = value == "v1",
            "M" => probe.machine = truncate_utf8_bytes(value.trim(), 32),
            "A" => probe.account = truncate_utf8_bytes(value.trim(), 128),
            "U" => probe.is_root = value.trim() == "0",
            "S" => probe.has_sha256sum = value == "yes",
            "L" => probe.has_readlink = value == "yes",
            "N" => probe.inotify_watches = value.trim().parse().ok(),
            "O" => {
                if let Some((mount, options)) = value.split_once('|') {
                    mounts.push((
                        mount.to_owned(),
                        options.split(',').any(|option| option == "noexec"),
                    ));
                }
            }
            "D" => {
                if let Some((path, free)) = value.split_once('|')
                    && safe_directory(path)
                    && !probe.candidates.iter().any(|known| known.path == path)
                {
                    probe.candidates.push(DirectoryCandidate {
                        path: path.to_owned(),
                        free_bytes: free.trim().parse::<u64>().unwrap_or(0).saturating_mul(1024),
                        noexec: false,
                    });
                }
            }
            "R" => {
                let fields: Vec<&str> = value.split('|').collect();
                if fields.len() == 4
                    && is_landing_directory(fields[0])
                    && probe.residues.len() < MAX_RESIDUES
                {
                    probe.residues.push(ToolResidue {
                        directory: fields[0].to_owned(),
                        size: fields[1].trim().parse().unwrap_or(0),
                        sha256: if fields[2].len() == 64
                            && fields[2].bytes().all(|byte| byte.is_ascii_hexdigit())
                        {
                            fields[2].to_owned()
                        } else {
                            String::new()
                        },
                        running: fields[3] == "1",
                    });
                }
            }
            "F" => {
                if FILE_EVENT_DIRS.contains(&value) {
                    probe.file_event_dirs.push(value.to_owned());
                }
            }
            "W" => probe.watch_running = value.trim() == "1",
            _ => {}
        }
    }
    if !versioned || probe.machine.is_empty() {
        return Err(CoreError::validation(
            "process watch upload probe",
            "the target did not answer the probe",
        ));
    }
    for candidate in &mut probe.candidates {
        candidate.noexec = mounts
            .iter()
            .filter(|(mount, _)| {
                candidate.path == *mount
                    || mount == "/"
                    || candidate.path.starts_with(&format!("{mount}/"))
            })
            .max_by_key(|(mount, _)| mount.len())
            .is_some_and(|(_, noexec)| *noexec);
    }
    Ok(probe)
}

/// The wrapper: baseline from `/proc`, then pspy's own lines passed through
/// with nothing forked per line — a helper process per row would itself be
/// reported by pspy and feed the stream it is printing. Rows go out through
/// `printf '%s'`, never `echo`, which would act on backslashes in a command.
fn generate_tool_command(plan: &UploadPlan) -> CoreResult<String> {
    if !is_landing_directory(&plan.directory)
        || plan.tool_path != format!("{}/{TOOL_FILE}", plan.directory)
    {
        return Err(CoreError::validation(
            UPLOAD_DIRECTORY_REFUSAL,
            "the plan does not name a landing directory",
        ));
    }
    let mut arguments = String::new();
    if plan.file_events {
        arguments.push_str("-f");
        for directory in &plan.file_event_dirs {
            if !FILE_EVENT_DIRS.contains(&directory.as_str()) {
                return Err(CoreError::validation(
                    UPLOAD_DIRECTORY_REFUSAL,
                    "file events are limited to the fixed directory list",
                ));
            }
            arguments.push_str(" -r ");
            arguments.push_str(directory);
        }
    }
    let mut script = watch_prelude(&plan.marker, plan.duration_secs, "1")?;
    script.push_str(
        &TOOL_SETUP
            .replace("@BIN@", &shq(&plan.tool_path))
            .replace("@ARGS@", &shq(&arguments)),
    );
    script.push_str(WATCH_HEADER);
    script.push_str(TOOL_LOOP);
    Ok(script)
}

const TOOL_SETUP: &str = r#"LH_BIN=@BIN@
LH_ARGS=@ARGS@
kill_tool() {
  set +f
  for pd in /proc/[0-9]*; do
    set -f
    e=$(readlink "$pd/exe" 2>/dev/null) || continue
    case "$e" in "$LH_BIN"|"$LH_BIN (deleted)") kill "${pd#/proc/}" 2>/dev/null ;; esac
  done
  set -f
}
if [ ! -x "$LH_BIN" ]; then echo 'X|tool-missing'; exit 2; fi
"#;

const TOOL_LOOP: &str = r#"read -r up _idle 2>/dev/null < /proc/uptime
LH_UP0=${up%%.*}
( s=0; while [ "$s" -lt "$LH_DUR" ]; do sleep 1; s=$((s+1)); done; kill_tool ) &
LH_GUARD=$!
trap 'kill_tool; kill "$LH_GUARD" 2>/dev/null; echo "F|stop"; exit 0' INT TERM HUP
last=''
drop=0
# In the background and waited for: a shell runs a trap only between
# commands, so a foreground pipeline would hold the hang-up until pspy ended
# on its own.
TZ= "$LH_BIN" -c=false --ppid -i 1000 -t 4096 $LH_ARGS 2>&1 | {
IFS= read -r sl 2>/dev/null < /proc/self/stat
LH_LOOP=${sl%% *}
while IFS= read -r line; do
  case "$line" in
    *' CMD: UID='*' | '*|*' CMD: UID='*' |')
      meta=${line%%' |'*}
      dt=${line%% CMD: *}
      case "$line" in *' | '*) cmd=${line#*' | '} ;; *) cmd='' ;; esac
      cmd=${cmd% }
      u=${meta#*UID=}; u=${u%% *}
      p=${meta#* PID=}; p=${p%% *}
      case "$meta" in *PPID=*) pp=${meta#*PPID=}; pp=${pp%% *} ;; *) pp='' ;; esac
      case "$p" in ''|*[!0-9]*) [ "$drop" = 1 ] || printf '%s\n' "I|$line"; continue ;; esac
      case "$u" in ''|*[!0-9]*) u='-' ;; esac
      st=''; comm=''
      if IFS= read -r sl 2>/dev/null < "/proc/$p/stat"; then
        inner=${sl#*(}; comm=${inner%)*}; rest=${sl##*)}
        set -- $rest
        st=${20}
        [ -n "$pp" ] || pp=$2
      fi
      case "$seen" in
        *";$p:"*)
          if [ -n "$st" ]; then
            case "$seen" in *";$p:$st;"*) continue ;; esac
          else
            # pspy lists what was already running first; a baseline pid it
            # names in those opening seconds is that listing, not a reuse.
            read -r up _idle 2>/dev/null < /proc/uptime
            [ "$(( ${up%%.*} - LH_UP0 ))" -gt 3 ] || continue
          fi ;;
      esac
      own=0
      if [ "$p" = "$self_pid" ] || [ "$pp" = "$self_pid" ] || [ "$pp" = "$parent_pid" ] || [ "$pp" = "$LH_GUARD" ] || [ "$pp" = "$LH_LOOP" ]; then
        own=1
      elif [ -n "$st" ] && is_own "$p"; then
        own=1
      elif [ -z "$st" ] && [ -n "$pp" ] && is_own "$pp"; then
        own=1
      else
        # The second pattern is the one helper this loop forks, below.
        case "$cmd" in *LH_TAG=*|"tr \\000  ") own=1 ;; esac
      fi
      # Nothing was read and the process is already gone: there is no
      # command to show, only a pid that existed.
      if [ -z "$st" ]; then
        case "$cmd" in ''|'???') continue ;; esac
      fi
      # pspy often reads a command line in the instant after fork, when it
      # is still the parent's or empty. A process that is still there is
      # asked again; this forks once, and the helper it forks is a child of
      # this loop, so it is dropped as own.
      if [ -n "$st" ] && [ "$own" = 0 ]; then
        again=$(tr '\000' ' ' 2>/dev/null < "/proc/$p/cmdline")
        again=${again% }
        [ -z "$again" ] || cmd=$again
      fi
      if [ -z "$cmd" ] && [ -n "$comm" ]; then cmd="[$comm]"; fi
      drop=$own
      printf '%s\n' "P|$dt|$u|$p|$pp|$st|$own|$cmd" ;;
    *' FS: '*' | '*)
      dt=${line%% FS: *}
      meta=${line%%' | '*}; path=${line#*' | '}; ev=${meta##* }
      [ "$ev $path" = "$last" ] && continue
      last="$ev $path"
      drop=0
      printf '%s\n' "Q|$dt|$ev|$path" ;;
    *)
      # pspy prints a command line with newlines in it as several lines.
      # The rest of this wrapper's own command line is dropped; the rest of
      # anyone else's is kept as it came.
      [ "$drop" = 1 ] && continue
      printf '%s\n' "I|$line" ;;
  esac
done
} &
wait $!
kill "$LH_GUARD" 2>/dev/null
cs=$(date +%s)
if [ "$cs" -lt "$((deadline - 3))" ]; then echo 'X|tool-exited'; else echo "F|deadline"; fi
"#;

const CLEANUP_SCRIPT: &str = r#"LH_TAG=cleanup
D=@DIR@
B="$D/pspy"
running() {
  n=0
  for pd in /proc/[0-9]*; do
    e=$(readlink "$pd/exe" 2>/dev/null) || continue
    case "$e" in "$B"|"$B (deleted)") n=$((n+1)); [ -n "$1" ] && kill "$1" "${pd#/proc/}" 2>/dev/null ;; esac
  done
  echo "$n"
}
if [ "$(running -TERM)" != 0 ]; then
  sleep 1
  if [ "$(running -KILL)" != 0 ]; then sleep 1; fi
fi
rm -f "$B" 2>/dev/null
rmdir "$D" 2>/dev/null
if [ -e "$D" ]; then p=present; else p=absent; fi
echo "R|$(running '')|$p"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(class: u8, machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; TOOL_MIN_BYTES];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = class;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn probe() -> UploadProbe {
        parse_upload_probe(
            "K|v1\nM|x86_64\nA|alice\nU|1000\nS|yes\nL|yes\nN|524288\n\
             O|/|rw,relatime\nO|/tmp|rw,nosuid,nodev,noexec\nO|/dev/shm|rw,nosuid,nodev\n\
             D|/dev/shm|65536\nD|/tmp|900000\nD|/home/alice|900000\n\
             R|/tmp/.lovelyhawk-watch-0123456789abcdef|3104768|c93f29a5cc1347bdb90e14a12424e6469c8cfea9a20b800bc249755f0043a3bb|0\n\
             R|/tmp/elsewhere|1|x|0\nF|/etc\nF|/usr\nW|0\n",
        )
        .unwrap()
    }

    #[test]
    fn a_picked_file_is_identified_by_its_own_bytes() {
        let facts = inspect_tool(&elf(2, 62)).unwrap();
        assert_eq!(facts.arch, ToolArch::X86_64);
        assert_eq!(facts.recognized, None);
        assert_eq!(inspect_tool(&elf(1, 3)).unwrap().arch, ToolArch::X86);
        assert_eq!(inspect_tool(&elf(2, 183)).unwrap().arch, ToolArch::Other);
        assert!(inspect_tool(b"#!/bin/sh\n").is_err());
        let mut script = elf(2, 62);
        script[..4].copy_from_slice(b"#!/b");
        assert!(inspect_tool(&script).is_err());
        assert!(inspect_tool(&vec![0x7f; TOOL_MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn the_digest_table_holds_four_distinct_sha256_values() {
        let mut digests: Vec<&str> = KNOWN_TOOLS.iter().map(|(digest, _)| *digest).collect();
        digests.sort_unstable();
        digests.dedup();
        assert_eq!(digests.len(), 4);
        assert!(digests.iter().all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        }));
    }

    #[test]
    fn the_probe_reads_mount_options_by_longest_prefix() {
        let probe = probe();
        let noexec: Vec<(&str, bool)> = probe
            .candidates
            .iter()
            .map(|candidate| (candidate.path.as_str(), candidate.noexec))
            .collect();
        assert_eq!(
            noexec,
            vec![("/dev/shm", false), ("/tmp", true), ("/home/alice", false)]
        );
        assert_eq!(probe.residues.len(), 1);
        assert_eq!(probe.file_event_dirs, vec!["/etc".to_owned()]);
        assert!(!probe.is_root);
    }

    #[test]
    fn a_plan_skips_noexec_and_full_directories() {
        let probe = probe();
        let tool = ToolFacts {
            sha256: "a".repeat(64),
            size: 3 * 1024 * 1024,
            arch: ToolArch::X86_64,
            recognized: None,
        };
        // /dev/shm allows running but has 64 MiB free: it is chosen.
        let plan = plan_upload(&probe, &tool, 180, false).unwrap();
        assert!(plan.directory.starts_with("/dev/shm/.lovelyhawk-watch-"));
        assert!(is_landing_directory(&plan.directory));
        assert_eq!(plan.tool_path, format!("{}/pspy", plan.directory));
        assert!(plan.file_event_dirs.is_empty());

        let mut tight = probe.clone();
        tight.candidates[0].free_bytes = 1024;
        let plan = plan_upload(&tight, &tool, 180, true).unwrap();
        assert!(plan.directory.starts_with("/home/alice/"));
        assert_eq!(plan.file_event_dirs, vec!["/etc".to_owned()]);

        tight.candidates[2].free_bytes = 1024;
        let refusal = plan_upload(&tight, &tool, 180, false).unwrap_err();
        assert!(
            matches!(refusal, CoreError::Validation { subject, .. } if subject == UPLOAD_SPACE_REFUSAL)
        );
    }

    #[test]
    fn each_reason_an_upload_cannot_run_has_its_own_refusal() {
        let tool = ToolFacts {
            sha256: "a".repeat(64),
            size: 1024 * 1024,
            arch: ToolArch::X86_64,
            recognized: None,
        };
        let subject =
            |probe: &UploadProbe, tool: &ToolFacts| match plan_upload(probe, tool, 180, false) {
                Err(CoreError::Validation { subject, .. }) => subject,
                other => panic!("expected a refusal, got {other:?}"),
            };
        let mut arm = probe();
        arm.machine = "aarch64".to_owned();
        assert_eq!(subject(&arm, &tool), UPLOAD_ARCH_REFUSAL);

        let mut old = probe();
        old.machine = "i686".to_owned();
        assert_eq!(subject(&old, &tool), UPLOAD_TOOL_REFUSAL);
        let small = ToolFacts {
            arch: ToolArch::X86,
            ..tool.clone()
        };
        assert!(plan_upload(&probe(), &small, 180, false).is_ok());

        let mut bare = probe();
        bare.has_sha256sum = false;
        assert_eq!(subject(&bare, &tool), UPLOAD_TOOLS_REFUSAL);

        let mut locked = probe();
        for candidate in &mut locked.candidates {
            candidate.noexec = true;
        }
        assert_eq!(subject(&locked, &tool), UPLOAD_DIRECTORY_REFUSAL);

        let mut busy = probe();
        busy.watch_running = true;
        assert_eq!(subject(&busy, &tool), UPLOAD_RUNNING_REFUSAL);
        assert!(plan_upload(&probe(), &tool, 30, false).is_err());
    }

    #[test]
    fn only_a_landing_directory_can_be_cleaned() {
        assert!(is_landing_directory(
            "/tmp/.lovelyhawk-watch-0123456789abcdef"
        ));
        assert!(is_landing_directory(
            "/run/user/1000/.lovelyhawk-watch-0123456789abcdef"
        ));
        for refused in [
            "/tmp",
            "/",
            "/tmp/.lovelyhawk-watch-",
            "/tmp/.lovelyhawk-watch-0123456789abcdeg",
            "/tmp/.lovelyhawk-watch-0123456789abcdef/pspy",
            "/tmp/../etc/.lovelyhawk-watch-0123456789abcdef",
            "/tmp/a b/.lovelyhawk-watch-0123456789abcdef",
            "/tmp/$(id)/.lovelyhawk-watch-0123456789abcdef",
            "tmp/.lovelyhawk-watch-0123456789abcdef",
        ] {
            assert!(!is_landing_directory(refused), "{refused}");
        }
    }

    #[test]
    fn the_wrapper_takes_only_the_plan_and_the_fixed_arguments() {
        let probe = probe();
        let tool = ToolFacts {
            sha256: "a".repeat(64),
            size: 1024 * 1024,
            arch: ToolArch::X86_64,
            recognized: None,
        };
        let mut plan = plan_upload(&probe, &tool, 120, true).unwrap();
        let script = generate_tool_command(&plan).unwrap();
        assert!(script.contains(&format!("LH_BIN='{}'", plan.tool_path)));
        assert!(script.contains("LH_ARGS='-f -r /etc'"));
        assert!(script.contains("LH_DUR=120"));
        assert!(script.contains("-c=false --ppid -i 1000 -t 4096"));

        plan.file_event_dirs.push("/home; rm -rf /".to_owned());
        assert!(generate_tool_command(&plan).is_err());
        plan.file_event_dirs.pop();
        plan.directory = "/etc".to_owned();
        assert!(generate_tool_command(&plan).is_err());
    }

    #[test]
    fn cleanup_answers_are_read_strictly() {
        assert_eq!(parse_cleanup("R|0|absent\n"), Some((0, false)));
        assert_eq!(parse_cleanup("noise\nR|2|present\n"), Some((2, true)));
        assert_eq!(parse_cleanup("R|x|absent"), None);
        assert_eq!(parse_cleanup(""), None);
    }

    #[test]
    fn the_banner_is_noise_and_a_complaint_is_not() {
        for line in [
            "pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d",
            "     ██▓███    ██████  ██▓███ ▓██   ██▓",
            "Config: Printing events (colored=false): processes=true",
            "Draining file system events due to startup...",
            "done",
            "Exiting program... (terminated)",
            "",
        ] {
            assert!(is_tool_banner(line), "{line}");
        }
        assert!(!is_tool_banner("Can't create watcher: too many open files"));
        assert!(!is_tool_banner("sh: 1: /tmp/x/pspy: Exec format error"));
    }
}
