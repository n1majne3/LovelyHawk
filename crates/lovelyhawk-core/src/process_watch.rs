//! Watching for processes that appear during a window: a fixed POSIX sh loop
//! that rescans `/proc` on the target and streams one line per new process
//! identity, so a minutely cron job or a backdoor that respawns shows up even
//! though every one-shot `ps` snapshot missed it.
//!
//! Phase A implements only the no-upload method: nothing is written to the
//! target's disk, the loop bounds itself by the deadline it was handed, and a
//! dropped connection never leaves it running past that deadline. Types are
//! shaped so a later upload method (pspy, auditd readers) plugs in behind the
//! same probe/start/stop/summary surface.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::events::{
    EventChannelDefaults, ProcessWatchStreamEvent, ProcessWatchStreamEventKind,
    ProcessWatchStreamEventReceiver, ProcessWatchStreamEventSender, TerminalEventKind,
    process_watch_event_channel,
};
use crate::ssh::{
    BoundSshSession, PacketCapturePtyRequest, SshCommandOutput, SshService, SshTerminalSession,
};
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult};

pub const PROCESS_WATCH_MIN_SECONDS: u32 = 60;
pub const PROCESS_WATCH_MAX_SECONDS: u32 = 1800;
pub const PROCESS_WATCH_DEFAULT_SECONDS: u32 = 180;
pub const PROCESS_WATCH_DEFAULT_INTERVAL_MS: u32 = 500;
/// New-process rows before the pump calls it enough and stops the loop.
pub const PROCESS_WATCH_MAX_EVENTS: u64 = 20_000;
/// Streamed output before the pump calls it enough and stops the loop.
pub const PROCESS_WATCH_MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_WATCH_LINE_BYTES: usize = 512 * 1024;
const MAX_COMMAND_CHARS: usize = 4_096;
const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;
const STOP_VERIFY_SECONDS: u64 = 10;
const STOP_VERIFY_ATTEMPTS: u32 = 8;
const STOP_VERIFY_PAUSE: Duration = Duration::from_millis(500);

/// How a watch observes. `proc-poll` scans `/proc` on a fixed interval; later
/// phases add upload and existing-source methods behind the same enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessWatchMethod {
    ProcPoll,
    /// An operator-supplied pspy binary, uploaded for this one run.
    Pspy,
}

impl ProcessWatchMethod {
    pub const fn key(self) -> &'static str {
        match self {
            Self::ProcPoll => "proc-poll",
            Self::Pspy => "pspy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWatchRequest {
    pub method: ProcessWatchMethod,
    pub duration_secs: u32,
    pub interval_ms: u32,
}

impl Default for ProcessWatchRequest {
    fn default() -> Self {
        Self {
            method: ProcessWatchMethod::ProcPoll,
            duration_secs: PROCESS_WATCH_DEFAULT_SECONDS,
            interval_ms: PROCESS_WATCH_DEFAULT_INTERVAL_MS,
        }
    }
}

impl ProcessWatchRequest {
    pub fn validate(&self) -> CoreResult<()> {
        if !(PROCESS_WATCH_MIN_SECONDS..=PROCESS_WATCH_MAX_SECONDS).contains(&self.duration_secs) {
            return Err(CoreError::validation(
                "process watch duration",
                format!(
                    "must be {PROCESS_WATCH_MIN_SECONDS}..={PROCESS_WATCH_MAX_SECONDS} seconds"
                ),
            ));
        }
        if !matches!(self.interval_ms, 200 | 500 | 1000) {
            return Err(CoreError::validation(
                "process watch interval",
                "must be one of 200, 500 or 1000 milliseconds",
            ));
        }
        Ok(())
    }
}

/// A gap is a reason the window may not show everything, not a failure. Each
/// key is stable: the page maps it to a fixed explanation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessWatchGap {
    /// `/proc` mounted with hidepid and not root: other users invisible.
    Hidepid,
    /// Inside a container: the host and other containers are invisible.
    Container,
    /// `sleep` takes no fractions, so polling runs once a second.
    CoarseInterval,
    /// `/proc` itself cannot be read; the watch cannot run at all.
    ProcUnreadable,
    /// Always true for proc-poll: processes that start and exit between two
    /// scans are missed.
    PollingMissesShortLived,
    /// Another watch carrying our marker is already running there.
    AlreadyRunning,
}

impl ProcessWatchGap {
    pub fn key(self) -> &'static str {
        match self {
            Self::Hidepid => "hidepid",
            Self::Container => "container",
            Self::CoarseInterval => "coarse-interval",
            Self::ProcUnreadable => "proc-unreadable",
            Self::PollingMissesShortLived => "polling-misses-short-lived",
            Self::AlreadyRunning => "already-running",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWatchProbe {
    pub proc_readable: bool,
    pub gaps: Vec<ProcessWatchGap>,
    /// Whether `sleep` accepts fractions; when false an interval below one
    /// second silently becomes one second on the target.
    pub fractional_sleep: bool,
    pub account: String,
    pub is_root: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EventOrigin {
    /// Running when the watch started.
    Baseline,
    /// First seen during the window.
    Observed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessWatchEventKind {
    Process,
    /// A file-system event the uploaded tool reported; `command` holds the
    /// event name and the path, and there is no process identity.
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWatchEvent {
    pub kind: ProcessWatchEventKind,
    pub seq: u64,
    /// Target clock, epoch milliseconds (second resolution when the target
    /// has no millisecond `date`).
    pub at_ms: u64,
    pub uid: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    /// `/proc/<pid>/stat` starttime: distinguishes a reused pid.
    pub start_ticks: Option<u64>,
    /// argv joined by single spaces; `[comm]` when the kernel keeps no argv.
    pub command: String,
    pub clipped: bool,
    pub origin: EventOrigin,
    /// Spawned by the watcher or by this SSH session.
    pub own: bool,
    /// The wire line as received, for the operator's own read.
    pub raw: String,
}

/// A line the watcher (or anything sharing its channel) printed that the
/// protocol cannot read. Kept and counted, never dropped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWatchUnparsed {
    pub seq: u64,
    pub raw: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessWatchEndState {
    /// The remote loop reached its own deadline.
    Finished,
    Cancelled,
    /// Event or byte limit hit; the loop was stopped.
    Truncated,
    Failed,
    /// The stream ended because the connection did, not the watch.
    Disconnected,
}

/// Stable failure reasons the remote script can print and this side maps,
/// rather than passing target stderr through to the page.
const WATCH_PREFLIGHT_REASONS: &[(&str, &str)] = &[
    (
        "proc-unreadable",
        "这台机器上读不到 /proc，进程监视无法开始。",
    ),
    (
        "no-encoder",
        "这台机器上找不到 od、xxd、hexdump 或 base64，无法安全地传送命令行，监视没有开始。",
    ),
    (
        "already-running",
        "这台机器上已经有一个 LovelyHawk 进程监视在运行，没有重复开始。",
    ),
    (
        "tool-missing",
        "上传的程序在开始前已经不在原位置（可能被安全软件删除），监视没有开始。",
    ),
    (
        "tool-exited",
        "上传的程序提前退出了（可能无法在这台机器上运行，或被安全软件终止），结果不完整。",
    ),
];

pub fn known_watch_failure(code: &str) -> Option<&'static str> {
    WATCH_PREFLIGHT_REASONS
        .iter()
        .find(|(key, _)| *key == code)
        .map(|(_, reason)| *reason)
}

/// A running watch on one target. `Drop` asks the terminal to close so a
/// forgotten handle cannot leave the loop running past its deadline.
#[derive(Debug)]
pub struct LiveProcessWatch {
    watch_id: String,
    marker: String,
    target: TargetGuard,
    terminal: Arc<SshTerminalSession>,
    events: ProcessWatchStreamEventReceiver,
    /// Identity of the remote loop, filled once its header arrives; the
    /// backend needs it to verify a stop without trusting a name.
    remote: Arc<std::sync::Mutex<Option<RemoteWatchIdentity>>>,
    method: ProcessWatchMethod,
    /// Present only for an upload run: what must be removed from the target
    /// once the run is over, however it ended.
    cleanup: Option<Arc<crate::process_watch_upload::ToolCleanup>>,
}

/// `pid + starttime` of the remote loop, for the post-stop identity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteWatchIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub deadline_at_ms: u64,
}

impl LiveProcessWatch {
    pub fn watch_id(&self) -> &str {
        &self.watch_id
    }

    /// The per-run token baked into the remote command line, needed for the
    /// post-stop identity check.
    pub fn marker(&self) -> &str {
        &self.marker
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub fn events(&self) -> &ProcessWatchStreamEventReceiver {
        &self.events
    }

    pub fn remote_identity(&self) -> Option<RemoteWatchIdentity> {
        self.remote.lock().ok().and_then(|remote| *remote)
    }

    pub const fn method(&self) -> ProcessWatchMethod {
        self.method
    }

    /// Stops the uploaded tool and removes it. `None` for a run that wrote
    /// nothing. Safe to call more than once: the first answer is kept.
    pub async fn cleanup(&self) -> Option<crate::process_watch_upload::CleanupOutcome> {
        match &self.cleanup {
            Some(cleanup) => Some(cleanup.run().await),
            None => None,
        }
    }

    /// Types Ctrl-C into the terminal and closes it: the trap in the remote
    /// loop then ends the scan and the loop prints its footer.
    pub async fn stop(&self) -> CoreResult<()> {
        self.terminal.interrupt_and_close();
        Ok(())
    }

    pub fn request_stop(&self) {
        self.terminal.interrupt_and_close();
    }
}

impl Drop for LiveProcessWatch {
    fn drop(&mut self) {
        self.terminal.interrupt_and_close();
    }
}

#[derive(Debug, Clone)]
pub struct ProcessWatchService {
    ssh: SshService,
    target: Arc<TargetContext>,
}

impl ProcessWatchService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self { ssh, target }
    }

    /// Read-only capability check, before the operator is offered a start.
    ///
    /// One bounded script answers: can `/proc` be read, is it mounted with
    /// hidepid, are we inside a container, does `sleep` take fractions, is a
    /// watcher with our marker already running, who is the account.
    pub async fn probe(&self, session: &BoundSshSession) -> CoreResult<ProcessWatchProbe> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                generate_probe_command().to_owned(),
                Duration::from_secs(15),
            )
            .await?;
        self.target.validate(session.target())?;
        validate_ssh_output("process watch probe", &output, MAX_PROBE_OUTPUT_BYTES)?;
        parse_probe_output(&output.output)
    }

    /// Start the proc-poll loop on the target and hand back its event stream.
    ///
    /// The remote program is fixed text plus three validated values (marker,
    /// duration, interval); nothing the operator typed is ever interpolated.
    /// Its own deadline bounds how long a lost connection can leave it.
    pub async fn start(
        &self,
        session: &BoundSshSession,
        request: ProcessWatchRequest,
    ) -> CoreResult<LiveProcessWatch> {
        request.validate()?;
        let marker = watch_marker();
        let command = generate_watch_command(&marker, &request)?;
        self.start_command(
            session,
            marker,
            command,
            request.duration_secs,
            ProcessWatchMethod::ProcPoll,
            None,
        )
        .await
    }

    /// Runs an already-built watch program and pumps its wire lines. Both
    /// methods end here; only the program and what must be cleaned differ.
    pub(crate) async fn start_command(
        &self,
        session: &BoundSshSession,
        marker: String,
        command: String,
        duration_secs: u32,
        method: ProcessWatchMethod,
        cleanup: Option<Arc<crate::process_watch_upload::ToolCleanup>>,
    ) -> CoreResult<LiveProcessWatch> {
        validate_marker(&marker)?;
        self.target.validate(session.target())?;
        let watch_id = format!("procwatch-{}", uuid::Uuid::new_v4().simple());
        let terminal = Arc::new(
            self.ssh
                .open_packet_capture_bound(
                    session,
                    PacketCapturePtyRequest::new(watch_id.clone(), command)?,
                )
                .await?,
        );
        if let Err(error) = self.target.validate(session.target()) {
            terminal.request_close();
            return Err(error);
        }
        let (sender, events) =
            process_watch_event_channel(EventChannelDefaults::default().process_watch)?;
        let remote = Arc::new(std::sync::Mutex::new(None));
        tokio::spawn(pump_process_watch(
            watch_id.clone(),
            duration_secs,
            session.target().clone(),
            self.target.clone(),
            terminal.clone(),
            remote.clone(),
            sender,
        ));
        Ok(LiveProcessWatch {
            watch_id,
            marker,
            target: session.target().clone(),
            terminal,
            events,
            remote,
            method,
            cleanup,
        })
    }

    pub(crate) fn ssh(&self) -> &SshService {
        &self.ssh
    }

    pub(crate) fn target_context(&self) -> &Arc<TargetContext> {
        &self.target
    }

    /// After `stop`, independently ask whether a process with the recorded
    /// pid, start time and marker still exists on the target.
    ///
    /// `Ok(true)` means nothing with that identity remains. A pid that now
    /// holds a different process, or a same-pid process without the marker,
    /// counts as stopped — a reused pid is not our loop.
    pub async fn verify_stopped(
        &self,
        session: &BoundSshSession,
        identity: &RemoteWatchIdentity,
        marker: &str,
    ) -> CoreResult<bool> {
        validate_marker(marker)?;
        self.target.validate(session.target())?;
        // The loop needs a moment to run its trap after the interrupt, so
        // one immediate look would report a stopping loop as still alive.
        for attempt in 0..STOP_VERIFY_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(STOP_VERIFY_PAUSE).await;
            }
            let output = self
                .ssh
                .execute_bound(
                    session,
                    generate_stop_verify_command(identity, marker),
                    Duration::from_secs(STOP_VERIFY_SECONDS),
                )
                .await?;
            self.target.validate(session.target())?;
            validate_ssh_output("process watch stop check", &output, 4 * 1024)?;
            if output.output.trim() == "GONE" {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Remote programs
// ---------------------------------------------------------------------------

/// `[a-f0-9]{16}` — the identity a stop check looks for in the target's
/// process table and the probe looks for an existing watch.
pub(crate) fn watch_marker() -> String {
    let raw = uuid::Uuid::new_v4().simple().to_string();
    raw[..16].to_owned()
}

pub(crate) fn validate_marker(marker: &str) -> CoreResult<()> {
    if marker.len() == 16 && marker.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(CoreError::validation(
        "process watch marker",
        "must be 16 hexadecimal characters",
    ))
}

/// The read-only probe. Every answer line is `KEY|value` so the parser can
/// refuse an unrecognized target rather than guess.
fn generate_probe_command() -> &'static str {
    // The marker token is assembled, never written as one literal: the probe
    // script's own command line would otherwise look like a running watcher.
    r#"LH_TAG="lh""watch"
echo "K|v1"
if [ -r /proc/self/stat ]; then echo "P|yes"; else echo "P|no"; fi
echo "A|$(id -un 2>/dev/null || id -u 2>/dev/null || echo '?')"
uid="$(id -u 2>/dev/null)"
case "$uid" in ''|*[!0-9]*) uid='-' ;; esac
echo "U|$uid"
if [ -r /proc/mounts ]; then
  hp=0
  while read -r dev mp rest; do
    if [ "$mp" = "/proc" ]; then
      case " $rest " in *" hidepid="*) hp=1 ;; esac
      case " $rest " in *"hidepid=2"*|*"hidepid=1"*) hp=1 ;; esac
    fi
  done < /proc/mounts
  echo "H|$hp"
else
  echo "H|?"
fi
if sleep 0.05 2>/dev/null; then echo "S|yes"; else echo "S|no"; fi
# The same three tells the workbench container check reads, condensed into
# one verdict: a marker file or a non-host cgroup means this PID namespace
# is not the host's, so the watch cannot see host processes.
cw=no
if [ -e /.dockerenv ] || [ -e /run/.containerenv ]; then cw=yes; fi
if [ "$cw" = no ] && [ -r /proc/1/cgroup ]; then
  if grep -qE 'docker|kubepods|containerd|libpod|lxc|podman' /proc/1/cgroup 2>/dev/null; then cw=yes; fi
fi
if [ "$cw" = no ] && [ -r /proc/self/mountinfo ]; then
  if grep -qE 'docker/containers|libpod|kubepods|containerd|lxc/' /proc/self/mountinfo 2>/dev/null; then cw=yes; fi
fi
echo "C|$cw"
found=0
for sf in /proc/[0-9]*/cmdline; do
  cmd="$(tr '\000' ' ' < "$sf" 2>/dev/null)" || continue
  case "$cmd" in *"$LH_TAG"-*) found=1; break ;; esac
done
echo "W|$found"
"#
}

/// The bounded watch loop. Steady-state scans fork nothing per process —
/// `/proc` globbing, `read <` and shell string tests are all builtins — and
/// only a newly seen identity pays for `date`, `od`/`tr` and the status read.
fn generate_watch_command(marker: &str, request: &ProcessWatchRequest) -> CoreResult<String> {
    request.validate()?;
    let sleep_arg = match request.interval_ms {
        200 => "0.2",
        500 => "0.5",
        _ => "1",
    };
    let mut script = watch_prelude(marker, request.duration_secs, sleep_arg)?;
    script.push_str(WATCH_HEADER);
    script.push_str(PROC_POLL_LOOP);
    Ok(script)
}

/// Everything both methods share: the encoder choice, the already-running
/// refusal, and the functions that read one process out of `/proc`.
pub(crate) fn watch_prelude(
    marker: &str,
    duration_secs: u32,
    sleep_arg: &str,
) -> CoreResult<String> {
    validate_marker(marker)?;
    Ok(format!(
        r#"LH_TAG="lh""watch"
LH_ID='lhwatch-{marker}'
LH_MARKER='{marker}'
LH_DUR={duration}
LH_SLEEP_ARG='{sleep_arg}'
LH_NOW_MS=1
case "$(date +%s%3N 2>/dev/null)" in ''|*[!0-9]*) LH_NOW_MS=0 ;; esac
LH_FRAC=1
sleep 0.05 2>/dev/null || LH_FRAC=0
set -f
self_pid=$$
parent_pid=${{PPID:-0}}
seen=';'
if [ ! -r /proc/self/stat ]; then echo 'X|proc-unreadable'; exit 2; fi
LH_ENC=''
for c in od xxd hexdump base64; do
  if command -v "$c" >/dev/null 2>&1; then LH_ENC=$c; break; fi
done
if [ -z "$LH_ENC" ]; then echo 'X|no-encoder'; exit 2; fi
set +f
for sf in /proc/[0-9]*/cmdline; do
  set -f
  case "${{sf%/cmdline}}" in /proc/$self_pid) continue ;; esac
  c="$(tr '\000' ' ' < "$sf" 2>/dev/null)"
  case "$c" in *"$LH_TAG"-*"$LH_MARKER"*) continue ;; *"$LH_TAG"-*) echo 'X|already-running'; exit 3 ;; esac
done
set -f
start_epoch=$(date +%s)
deadline=$((start_epoch + LH_DUR))
trap 'echo "F|stop"; exit 0' INT TERM HUP
now() {{
  if [ "$LH_NOW_MS" = 1 ]; then date +%s%3N; else printf '%s000\n' "$(date +%s)"; fi
}}
hex_file() {{
  case "$LH_ENC" in
    od) od -An -v -tx1 < "$1" 2>/dev/null | tr -d ' \n' ;;
    xxd) xxd -p "$1" 2>/dev/null | tr -d '\n' ;;
    hexdump) hexdump -v -e '1/1 "%02x"' "$1" 2>/dev/null ;;
    base64) base64 < "$1" 2>/dev/null | tr -d '\n' ;;
  esac
}}
hex_str() {{
  case "$LH_ENC" in
    od) printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n' ;;
    xxd) printf '%s' "$1" | xxd -p | tr -d '\n' ;;
    hexdump) printf '%s' "$1" | hexdump -v -e '1/1 "%02x"' ;;
    base64) printf '%s' "$1" | base64 | tr -d '\n' ;;
  esac
}}
uid_of() {{
  u=''
  while read -r k v _r; do
    if [ "$k" = "Uid:" ]; then u=$v; break; fi
  done 2>/dev/null < "/proc/$1/status"
  case "$u" in ''|*[!0-9]*) u='-' ;; esac
  printf '%s\n' "$u"
}}
is_own() {{
  hops=0; cur=$1
  while [ "$hops" -lt 8 ] && [ -n "$cur" ] && [ "$cur" != "1" ] && [ "$cur" != "0" ]; do
    if [ "$cur" = "$self_pid" ] || [ "$cur" = "$parent_pid" ]; then return 0; fi
    # Every program this tool sends starts by setting LH_TAG, so anything
    # under one of them is this tool's too, whichever channel ran it.
    IFS= read -r cl 2>/dev/null < "/proc/$cur/cmdline"
    case "$cl" in *LH_TAG=*) return 0 ;; esac
    IFS= read -r l 2>/dev/null < "/proc/$cur/stat" || break
    r=${{l##*)}}
    set -- $r
    cur=$2
    hops=$((hops + 1))
  done
  return 1
}}
emit() {{
  o=$1; p=$2; ppid=$3; st=$4; comm=$5
  at=$(now)
  uid=$(uid_of "$p")
  if is_own "$p"; then own=1; else own=0; fi
  chex=$(hex_str "$comm")
  xhex=$(hex_file "/proc/$p/cmdline")
  echo "E|$o|$at|$uid|$p|$ppid|$st|$own|$chex|$xhex"
}}
scan() {{
  org=$1
  set +f
  for sf in /proc/[0-9]*/stat; do
    set -f
    dp=${{sf%/stat}}; dp=${{dp#/proc/}}
    IFS= read -r line 2>/dev/null < "$sf" || continue
    inner=${{line#*(}}
    comm=${{inner%)*}}
    rest=${{line##*)}}
    set -- $rest
    ppid=$2; st=${{20}}
    id="$dp:$st"
    case "$seen" in
      *";$id;"*) continue ;;
    esac
    seen="$seen$id;"
    emit "$org" "$dp" "$ppid" "$st" "$comm"
  done
  set -f
}}
"#,
        marker = marker,
        duration = duration_secs,
        sleep_arg = sleep_arg,
    ))
}

/// The identity line: the loop's own pid and start time are what a stop
/// check later looks for.
pub(crate) const WATCH_HEADER: &str = r#"IFS= read -r selfstat 2>/dev/null < /proc/self/stat
r=${selfstat##*)}
set -- $r
self_ticks=${20}
echo "H|v1|$self_pid|$start_epoch|$LH_MARKER|st=$self_ticks|ms=$LH_NOW_MS|enc=$LH_ENC|frac=$LH_FRAC"
scan B
"#;

const PROC_POLL_LOOP: &str = r#"while :; do
  cs=$(date +%s)
  [ "$cs" -ge "$deadline" ] && break
  sleep "$LH_SLEEP_ARG" 2>/dev/null || sleep 1
  cs=$(date +%s)
  [ "$cs" -ge "$deadline" ] && break
  scan N
done
echo "F|deadline"
"#;

/// Identity check for stop verification: gone, or pid reused / different
/// process — anything that is not exactly the recorded loop counts as stopped.
fn generate_stop_verify_command(identity: &RemoteWatchIdentity, marker: &str) -> String {
    format!(
        "LH_TAG=verify\n\
if [ ! -r /proc/{pid}/stat ]; then echo GONE; exit 0; fi\n\
IFS= read -r l < /proc/{pid}/stat 2>/dev/null || {{ echo GONE; exit 0; }}\n\
r=${{l##*)}}\nset -- $r\nst=${{20}}\n\
if [ \"$st\" != \"{start}\" ]; then echo GONE; exit 0; fi\n\
c=$(tr '\\000' ' ' < /proc/{pid}/cmdline 2>/dev/null)\n\
case \"$c\" in *'{marker}'*) echo ALIVE ;; *) echo GONE ;; esac\n",
        pid = identity.pid,
        start = identity.start_ticks,
        marker = marker,
    )
}

pub(crate) fn validate_ssh_output(
    subject: &'static str,
    output: &SshCommandOutput,
    maximum_bytes: usize,
) -> CoreResult<()> {
    if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
        return Err(CoreError::validation(
            subject,
            format!(
                "remote command failed (exit={:?}, timed_out={})",
                output.exit_code, output.timed_out
            ),
        ));
    }
    if output.output.len() > maximum_bytes {
        return Err(CoreError::validation(
            subject,
            format!("remote output exceeds {maximum_bytes} bytes"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Probe and wire parsing
// ---------------------------------------------------------------------------

fn parse_probe_output(output: &str) -> CoreResult<ProcessWatchProbe> {
    let mut proc_readable = None;
    let mut account = String::new();
    let mut is_root = false;
    let mut hidepid = None;
    let mut fractional = None;
    let mut container = None;
    let mut already = false;
    for line in output.lines() {
        let mut fields = line.trim().splitn(2, '|');
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        match key {
            "P" => proc_readable = Some(value.trim() == "yes"),
            "A" => account = truncate_utf8_bytes(value.trim(), 128),
            "U" => {
                is_root = value.trim() == "0";
            }
            "H" => hidepid = Some(value.trim() == "1"),
            "S" => fractional = Some(value.trim() == "yes"),
            "C" => container = Some(value.trim() == "yes"),
            "W" => already = value.trim() == "1",
            _ => {}
        }
    }
    let Some(proc_readable) = proc_readable else {
        return Err(CoreError::validation(
            "process watch probe",
            "remote probe returned no readable-verdict line",
        ));
    };
    let mut gaps = Vec::new();
    if !proc_readable {
        gaps.push(ProcessWatchGap::ProcUnreadable);
    }
    if hidepid == Some(true) && !is_root {
        gaps.push(ProcessWatchGap::Hidepid);
    }
    if container == Some(true) {
        gaps.push(ProcessWatchGap::Container);
    }
    let fractional_sleep = fractional.unwrap_or(false);
    if !fractional_sleep {
        gaps.push(ProcessWatchGap::CoarseInterval);
    }
    if already {
        gaps.push(ProcessWatchGap::AlreadyRunning);
    }
    // ProcPoll always carries this one: a short-lived process can start and
    // exit between two scans, and no interval makes that impossible.
    gaps.push(ProcessWatchGap::PollingMissesShortLived);
    if account.is_empty() {
        account = "?".to_owned();
    }
    Ok(ProcessWatchProbe {
        proc_readable,
        gaps,
        fractional_sleep,
        account,
        is_root,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WireLine {
    Header {
        pid: u32,
        start_epoch_s: u64,
        /// `/proc/<pid>/stat` starttime of the loop itself — the identity a
        /// stop verification re-checks, since a pid alone can be reused.
        start_ticks: u64,
        deadline_at_ms: u64,
        millis: bool,
        base64: bool,
    },
    Event(WatchRow),
    Footer,
    Failure(&'static str),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchRow {
    origin: EventOrigin,
    at_ms: u64,
    uid: Option<u32>,
    pid: u32,
    ppid: Option<u32>,
    start_ticks: Option<u64>,
    own: bool,
    /// A file-system event row: `comm_hex` is the event name and `cmd_hex`
    /// the path.
    file: bool,
    /// The uploaded tool's rows carry their text as printed, not encoded:
    /// `cmd_hex` is then the command line itself and `comm_hex` is empty.
    plain: bool,
    comm_hex: String,
    cmd_hex: String,
    raw: String,
}

/// One output line from the remote loop. Hostile text cannot fake fields:
/// comm and argv travel hex/base64-encoded and `|` never appears inside them.
fn parse_watch_line(line: &str, base64: bool, duration_secs: u32) -> WireLine {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return WireLine::Other(String::new());
    }
    if let Some(rest) = trimmed.strip_prefix("H|v1|") {
        let mut fields = rest.split('|');
        let pid = fields.next().and_then(|v| v.parse::<u32>().ok());
        let start = fields.next().and_then(|v| v.parse::<u64>().ok());
        let _marker = fields.next();
        let mut millis = false;
        let mut enc_base64 = base64;
        let mut start_ticks = None;
        for field in fields.by_ref() {
            match field.split_once('=') {
                Some(("ms", "1")) => millis = true,
                Some(("enc", "base64")) => enc_base64 = true,
                Some(("st", ticks)) => start_ticks = ticks.parse::<u64>().ok(),
                _ => {}
            }
        }
        return match (pid, start, start_ticks) {
            (Some(pid), Some(start), Some(start_ticks)) => WireLine::Header {
                pid,
                start_epoch_s: start,
                start_ticks,
                deadline_at_ms: start.saturating_add(u64::from(duration_secs)) * 1000,
                millis,
                base64: enc_base64,
            },
            _ => WireLine::Other(trimmed.to_owned()),
        };
    }
    if let Some(rest) = trimmed.strip_prefix("E|") {
        let fields: Vec<&str> = rest.split('|').collect();
        if fields.len() != 9 {
            return WireLine::Other(trimmed.to_owned());
        }
        let origin = match fields[0] {
            "B" => EventOrigin::Baseline,
            "N" => EventOrigin::Observed,
            _ => return WireLine::Other(trimmed.to_owned()),
        };
        return WireLine::Event(WatchRow {
            origin,
            at_ms: fields[1].parse::<u64>().unwrap_or(0),
            uid: fields[2].parse::<u32>().ok(),
            pid: match fields[3].parse::<u32>() {
                Ok(pid) => pid,
                Err(_) => return WireLine::Other(trimmed.to_owned()),
            },
            ppid: fields[4].parse::<u32>().ok(),
            start_ticks: fields[5].parse::<u64>().ok(),
            own: fields[6] == "1",
            file: false,
            plain: false,
            comm_hex: fields[7].to_owned(),
            cmd_hex: fields[8].to_owned(),
            raw: trimmed.to_owned(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("F|") {
        let _ = rest;
        return WireLine::Footer;
    }
    if let Some(code) = trimmed.strip_prefix("X|") {
        return match code {
            "proc-unreadable" => WireLine::Failure("proc-unreadable"),
            "no-encoder" => WireLine::Failure("no-encoder"),
            "already-running" => WireLine::Failure("already-running"),
            "tool-missing" => WireLine::Failure("tool-missing"),
            "tool-exited" => WireLine::Failure("tool-exited"),
            _ => WireLine::Other(trimmed.to_owned()),
        };
    }
    if let Some(rest) = trimmed.strip_prefix("P|") {
        // The command is the last field and is taken whole, so a `|` typed
        // into a command line cannot move the fields before it.
        let fields: Vec<&str> = rest.splitn(7, '|').collect();
        let (Some(at_ms), Some(pid)) = (
            fields.first().and_then(|value| tool_clock_ms(value)),
            fields.get(2).and_then(|value| value.parse::<u32>().ok()),
        ) else {
            return WireLine::Other(trimmed.to_owned());
        };
        if fields.len() != 7 {
            return WireLine::Other(trimmed.to_owned());
        }
        return WireLine::Event(WatchRow {
            origin: EventOrigin::Observed,
            at_ms,
            uid: fields[1].parse::<u32>().ok(),
            pid,
            ppid: fields[3].parse::<u32>().ok(),
            start_ticks: fields[4].parse::<u64>().ok(),
            own: fields[5] == "1",
            file: false,
            plain: true,
            comm_hex: String::new(),
            cmd_hex: fields[6].to_owned(),
            raw: trimmed.to_owned(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("Q|") {
        let fields: Vec<&str> = rest.splitn(3, '|').collect();
        let Some(at_ms) = fields.first().and_then(|value| tool_clock_ms(value)) else {
            return WireLine::Other(trimmed.to_owned());
        };
        if fields.len() != 3 || fields[1].is_empty() {
            return WireLine::Other(trimmed.to_owned());
        }
        return WireLine::Event(WatchRow {
            origin: EventOrigin::Observed,
            at_ms,
            uid: None,
            pid: 0,
            ppid: None,
            start_ticks: None,
            own: false,
            file: true,
            plain: true,
            comm_hex: fields[1].to_owned(),
            cmd_hex: fields[2].to_owned(),
            raw: trimmed.to_owned(),
        });
    }
    if let Some(text) = trimmed.strip_prefix("I|") {
        // What the uploaded tool printed besides events. Its banner is
        // noise; anything else (an inotify limit, a refusal) is kept.
        return if crate::process_watch_upload::is_tool_banner(text) {
            WireLine::Other(String::new())
        } else {
            WireLine::Other(text.to_owned())
        };
    }
    WireLine::Other(trimmed.to_owned())
}

/// The uploaded tool stamps rows `YYYY/MM/DD HH:MM:SS`; the wrapper runs it
/// with an empty `TZ`, so that text is UTC.
fn tool_clock_ms(text: &str) -> Option<u64> {
    chrono::NaiveDateTime::parse_from_str(text.trim(), "%Y/%m/%d %H:%M:%S")
        .ok()
        .and_then(|time| u64::try_from(time.and_utc().timestamp_millis()).ok())
}

fn decode_wire_text(encoded: &str, base64: bool) -> Option<Vec<u8>> {
    if encoded.is_empty() {
        return Some(Vec::new());
    }
    if base64 {
        return decode_base64(encoded);
    }
    if !encoded.len().is_multiple_of(2) || encoded.len() > 512 * 1024 {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    let raw = encoded.as_bytes();
    for pair in raw.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes.push(((high << 4) | low) as u8);
    }
    Some(bytes)
}

fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() > 512 * 1024 {
        return None;
    }
    let mut out = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in encoded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// argv arrives as NUL-separated bytes: joined by single spaces, control
/// characters flattened so a hostile `argv[0]` cannot forge terminal output
/// or a second event row, then clipped at [`MAX_COMMAND_CHARS`].
fn decode_command(encoded: &str, comm: &str, base64: bool) -> (String, bool) {
    let Some(bytes) = decode_wire_text(encoded, base64) else {
        return ("[无法解码]".to_owned(), true);
    };
    decode_command_bytes(&bytes, comm)
}

fn decode_command_bytes(bytes: &[u8], comm: &str) -> (String, bool) {
    if bytes.is_empty() {
        return (format!("[{comm}]"), false);
    }
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.split(|byte| *byte == 0) {
        if chunk.is_empty() {
            continue;
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&String::from_utf8_lossy(chunk));
    }
    let mut flattened = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            flattened.push('\u{fffd}');
        } else {
            flattened.push(character);
        }
    }
    if flattened.chars().count() > MAX_COMMAND_CHARS {
        let clipped = flattened
            .chars()
            .take(MAX_COMMAND_CHARS)
            .collect::<String>();
        return (clipped, true);
    }
    (flattened, false)
}

fn decode_comm(encoded: &str, base64: bool) -> String {
    let Some(bytes) = decode_wire_text(encoded, base64) else {
        return "?".to_owned();
    };
    let mut text = String::from_utf8_lossy(&bytes).to_string();
    text.retain(|character| !character.is_control());
    if text.is_empty() {
        "?".to_owned()
    } else {
        truncate_utf8_bytes(&text, 128)
    }
}

pub(crate) fn truncate_utf8_bytes(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn drain_watch_lines(pending: &mut Vec<u8>, flush: bool) -> Vec<String> {
    let mut lines = Vec::new();
    while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
        let mut bytes = pending.drain(..=position).collect::<Vec<_>>();
        while bytes
            .last()
            .is_some_and(|byte| matches!(*byte, b'\n' | b'\r'))
        {
            bytes.pop();
        }
        if !bytes.is_empty() {
            lines.push(truncate_utf8_bytes(
                &String::from_utf8_lossy(&bytes),
                MAX_WATCH_LINE_BYTES,
            ));
        }
    }
    if pending.len() > MAX_WATCH_LINE_BYTES || (flush && !pending.is_empty()) {
        lines.push(truncate_utf8_bytes(
            &String::from_utf8_lossy(pending),
            MAX_WATCH_LINE_BYTES,
        ));
        pending.clear();
    }
    lines
}

// ---------------------------------------------------------------------------
// Pump: bytes from the PTY become typed, bounded stream events
// ---------------------------------------------------------------------------

async fn pump_process_watch(
    watch_id: String,
    duration_secs: u32,
    guard: TargetGuard,
    target: Arc<TargetContext>,
    terminal: Arc<SshTerminalSession>,
    remote: Arc<std::sync::Mutex<Option<RemoteWatchIdentity>>>,
    sender: ProcessWatchStreamEventSender,
) {
    let mut sequence = 0_u64;
    let mut emitted = 0_u64;
    let mut bytes_seen = 0_u64;
    let mut base64 = false;
    let mut truncated = false;
    let mut pending = Vec::new();

    macro_rules! send {
        ($kind:expr) => {
            send_watch_event(&sender, &watch_id, &mut sequence, $kind).await
        };
    }
    macro_rules! send_event_row {
        ($row:expr) => {{
            let row: WatchRow = $row;
            let (command, clipped) = if row.plain {
                let (text, clipped) = decode_command_bytes(row.cmd_hex.as_bytes(), "?");
                if row.file {
                    let (event, _) = decode_command_bytes(row.comm_hex.as_bytes(), "?");
                    (format!("{event} {text}"), clipped)
                } else {
                    (text, clipped)
                }
            } else {
                let comm = decode_comm(&row.comm_hex, base64);
                decode_command(&row.cmd_hex, &comm, base64)
            };
            // The row's seq mirrors the stream sequence it will carry.
            let event_seq = sequence.saturating_add(1);
            send_watch_event(
                &sender,
                &watch_id,
                &mut sequence,
                ProcessWatchStreamEventKind::Process(ProcessWatchEvent {
                    kind: if row.file {
                        ProcessWatchEventKind::File
                    } else {
                        ProcessWatchEventKind::Process
                    },
                    seq: event_seq,
                    at_ms: row.at_ms,
                    uid: row.uid.unwrap_or(u32::MAX),
                    pid: row.pid,
                    ppid: row.ppid,
                    start_ticks: row.start_ticks,
                    command,
                    clipped,
                    origin: row.origin,
                    own: row.own,
                    raw: row.raw,
                }),
            )
            .await
        }};
    }

    loop {
        if let Err(error) = target.validate(&guard) {
            terminal.request_close();
            let _ = send!(ProcessWatchStreamEventKind::Failed {
                message: format!("watch target changed: {error}"),
            });
            break;
        }
        match terminal.recv().await {
            Ok(event) => match event.kind {
                TerminalEventKind::Output(chunk) => {
                    bytes_seen = bytes_seen.saturating_add(chunk.len() as u64);
                    if bytes_seen > PROCESS_WATCH_MAX_OUTPUT_BYTES && !truncated {
                        truncated = true;
                        terminal.interrupt_and_close();
                        if !send!(ProcessWatchStreamEventKind::Stopped {
                            reason: ProcessWatchEndState::Truncated,
                        }) {
                            terminal.request_close();
                            return;
                        }
                    }
                    pending.extend_from_slice(&chunk);
                    for line in drain_watch_lines(&mut pending, false) {
                        if truncated {
                            continue;
                        }
                        match parse_watch_line(&line, base64, duration_secs) {
                            WireLine::Header {
                                pid,
                                start_ticks,
                                deadline_at_ms,
                                base64: enc,
                                ..
                            } => {
                                base64 = enc;
                                if let Ok(mut identity) = remote.lock() {
                                    *identity = Some(RemoteWatchIdentity {
                                        pid,
                                        start_ticks,
                                        deadline_at_ms,
                                    });
                                }
                                if !send!(ProcessWatchStreamEventKind::Started {
                                    pid,
                                    deadline_at_ms,
                                }) {
                                    terminal.request_close();
                                    return;
                                }
                            }
                            WireLine::Event(row) => {
                                emitted = emitted.saturating_add(1);
                                if emitted > PROCESS_WATCH_MAX_EVENTS {
                                    truncated = true;
                                    terminal.interrupt_and_close();
                                    if !send!(ProcessWatchStreamEventKind::Stopped {
                                        reason: ProcessWatchEndState::Truncated,
                                    }) {
                                        terminal.request_close();
                                        return;
                                    }
                                    continue;
                                }
                                if !send_event_row!(row) {
                                    terminal.request_close();
                                    return;
                                }
                            }
                            WireLine::Footer => {
                                let _ = send!(ProcessWatchStreamEventKind::Stopped {
                                    reason: ProcessWatchEndState::Finished,
                                });
                            }
                            WireLine::Failure(code) => {
                                let _ = send!(ProcessWatchStreamEventKind::Failed {
                                    message: code.to_owned(),
                                });
                                terminal.request_close();
                            }
                            WireLine::Other(raw) => {
                                if raw.is_empty() {
                                    continue;
                                }
                                if !send!(ProcessWatchStreamEventKind::Unparsed { raw }) {
                                    terminal.request_close();
                                    return;
                                }
                            }
                        }
                    }
                }
                TerminalEventKind::Exited { .. } => {
                    for line in drain_watch_lines(&mut pending, true) {
                        match parse_watch_line(&line, base64, duration_secs) {
                            WireLine::Event(row) if !truncated => {
                                emitted = emitted.saturating_add(1);
                                if emitted <= PROCESS_WATCH_MAX_EVENTS {
                                    let _ = send_event_row!(row);
                                }
                            }
                            WireLine::Footer => {
                                let _ = send!(ProcessWatchStreamEventKind::Stopped {
                                    reason: ProcessWatchEndState::Finished,
                                });
                            }
                            WireLine::Failure(code) => {
                                let _ = send!(ProcessWatchStreamEventKind::Failed {
                                    message: code.to_owned(),
                                });
                            }
                            WireLine::Other(raw) if !raw.is_empty() => {
                                let _ = send!(ProcessWatchStreamEventKind::Unparsed { raw });
                            }
                            _ => {}
                        }
                    }
                    break;
                }
                TerminalEventKind::Failed { message } => {
                    let _ = send!(ProcessWatchStreamEventKind::Failed {
                        message: truncate_utf8_bytes(&message, 4_096),
                    });
                    break;
                }
                TerminalEventKind::TitleChanged(_) | TerminalEventKind::Bell => {}
            },
            Err(error) => {
                if !matches!(error, CoreError::ChannelClosed { .. }) {
                    let _ = send!(ProcessWatchStreamEventKind::Failed {
                        message: format!("watch stream failed: {error}"),
                    });
                }
                break;
            }
        }
    }
    sender.close();
}

async fn send_watch_event(
    sender: &ProcessWatchStreamEventSender,
    watch_id: &str,
    sequence: &mut u64,
    kind: ProcessWatchStreamEventKind,
) -> bool {
    *sequence = sequence.saturating_add(1);
    sender
        .send(ProcessWatchStreamEvent {
            watch_id: watch_id.to_owned(),
            sequence: *sequence,
            kind,
        })
        .await
        .is_ok()
}

// ---------------------------------------------------------------------------
// Analysis: normalize, group, summarize — pure functions over parsed events
// ---------------------------------------------------------------------------

/// Fold a command line so repeats of "the same job with different random
/// parts" land in one group. Conservative on purpose: digit runs of four or
/// more (timestamps, ports, pids, sizes), whole-token hex of eight or more
/// (digests, ids), and mktemp-style suffixes (`tmp.a1b2c3`) collapse to `#`;
/// everything else survives verbatim.
pub fn normalize_command(command: &str) -> String {
    command
        .split_whitespace()
        .map(normalize_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_token(token: &str) -> String {
    // Whole-token hex, eight or more with at least one letter: digests and
    // generated ids. Pure-digit tokens fall through to the run collapse.
    if token.len() >= 8
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        && token.bytes().any(|byte| byte.is_ascii_alphabetic())
    {
        return "#".to_owned();
    }
    // mktemp-style: a trailing segment of six or more alphanumerics that
    // mixes letters and digits, behind `.` or `/`.
    let mut body = token.to_owned();
    if let Some(position) = body.rfind(['.', '/']) {
        let suffix = &body[position + 1..];
        if suffix.len() >= 6
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            && suffix.bytes().any(|byte| byte.is_ascii_digit())
            && suffix.bytes().any(|byte| byte.is_ascii_alphabetic())
        {
            body.truncate(position + 1);
            body.push('#');
        }
    }
    collapse_digit_runs(&body)
}

fn collapse_digit_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    for character in text.chars() {
        if character.is_ascii_digit() {
            run.push(character);
        } else {
            if run.len() >= 4 {
                out.push('#');
            } else {
                out.push_str(&run);
            }
            run.clear();
            out.push(character);
        }
    }
    if run.len() >= 4 {
        out.push('#');
    } else {
        out.push_str(&run);
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Cadence {
    /// At least three sightings whose gaps all sit within ±20% of the median.
    Periodic {
        period_ms: u64,
    },
    /// Seen more than once, without a stable gap.
    Repeated,
    Single,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepeatGroup {
    pub normalized: String,
    /// One full command line from the group, for display.
    pub sample: String,
    pub count: usize,
    pub uids: Vec<u32>,
    pub first_at_ms: u64,
    pub last_at_ms: u64,
    /// Gaps between consecutive sightings, for the expert view.
    pub intervals_ms: Vec<u64>,
    pub cadence: Cadence,
}

/// Group observed events by their normalized command. The watcher's own
/// helpers are never "interesting repeats"; baseline rows are a single
/// snapshot, not a recurrence.
pub fn repeat_groups(events: &[ProcessWatchEvent]) -> Vec<RepeatGroup> {
    let mut groups: BTreeMap<String, Vec<&ProcessWatchEvent>> = BTreeMap::new();
    for event in events {
        if event.own
            || event.origin == EventOrigin::Baseline
            || event.kind == ProcessWatchEventKind::File
        {
            continue;
        }
        groups
            .entry(normalize_command(&event.command))
            .or_default()
            .push(event);
    }
    let mut result = Vec::new();
    for (normalized, mut members) in groups {
        members.sort_by_key(|event| event.at_ms);
        let count = members.len();
        let intervals_ms: Vec<u64> = members
            .windows(2)
            .map(|pair| pair[1].at_ms.saturating_sub(pair[0].at_ms))
            .collect();
        let cadence = if count < 2 {
            Cadence::Single
        } else if count >= 3
            && intervals_within_twenty_percent(&intervals_ms)
            && median(&intervals_ms) > 0
        {
            Cadence::Periodic {
                period_ms: median(&intervals_ms),
            }
        } else {
            Cadence::Repeated
        };
        result.push(RepeatGroup {
            normalized,
            sample: members[0].command.clone(),
            count,
            uids: members
                .iter()
                .map(|event| event.uid)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            first_at_ms: members[0].at_ms,
            last_at_ms: members[count - 1].at_ms,
            intervals_ms,
            cadence,
        });
    }
    result.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.normalized.cmp(&right.normalized))
    });
    result
}

fn median(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn intervals_within_twenty_percent(intervals: &[u64]) -> bool {
    if intervals.is_empty() {
        return false;
    }
    let middle = median(intervals);
    if middle == 0 {
        return intervals.iter().all(|value| *value == 0);
    }
    intervals.iter().all(|value| {
        let difference = value.abs_diff(middle);
        difference.saturating_mul(5) <= middle
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWatchSummary {
    pub observed: usize,
    pub baseline: usize,
    pub own: usize,
    pub unparsed: usize,
    pub periodic_groups: usize,
    pub repeated_groups: usize,
    pub distinct_uids: usize,
    pub file_events: usize,
    pub gaps: Vec<ProcessWatchGap>,
    pub state: ProcessWatchEndState,
}

/// The numbers the page's conclusion sentence and next-step hint are made
/// of; gaps and end state travel with them so "nothing seen" is never shown
/// as "nothing happened".
pub fn summarize(
    events: &[ProcessWatchEvent],
    unparsed: usize,
    groups: &[RepeatGroup],
    gaps: Vec<ProcessWatchGap>,
    state: ProcessWatchEndState,
) -> ProcessWatchSummary {
    ProcessWatchSummary {
        observed: events
            .iter()
            .filter(|event| {
                event.origin == EventOrigin::Observed
                    && !event.own
                    && event.kind == ProcessWatchEventKind::Process
            })
            .count(),
        file_events: events
            .iter()
            .filter(|event| event.kind == ProcessWatchEventKind::File)
            .count(),
        baseline: events
            .iter()
            .filter(|event| event.origin == EventOrigin::Baseline)
            .count(),
        own: events.iter().filter(|event| event.own).count(),
        unparsed,
        periodic_groups: groups
            .iter()
            .filter(|group| matches!(group.cadence, Cadence::Periodic { .. }))
            .count(),
        repeated_groups: groups
            .iter()
            .filter(|group| matches!(group.cadence, Cadence::Repeated))
            .count(),
        distinct_uids: events
            .iter()
            .filter(|event| !event.own && event.kind == ProcessWatchEventKind::Process)
            .map(|event| event.uid)
            .collect::<BTreeSet<_>>()
            .len(),
        gaps,
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64, at_ms: u64, pid: u32, uid: u32, command: &str) -> ProcessWatchEvent {
        ProcessWatchEvent {
            kind: ProcessWatchEventKind::Process,
            seq,
            at_ms,
            uid,
            pid,
            ppid: Some(1),
            start_ticks: Some(1000 + u64::from(pid)),
            command: command.to_owned(),
            clipped: false,
            origin: EventOrigin::Observed,
            own: false,
            raw: format!("E|N|{at_ms}|{uid}|{pid}|1|1000|0||"),
        }
    }

    #[test]
    fn request_bounds_duration_and_interval() {
        assert!(ProcessWatchRequest::default().validate().is_ok());
        for duration in [0, 59, 1801, u32::MAX] {
            assert!(
                ProcessWatchRequest {
                    method: ProcessWatchMethod::ProcPoll,
                    duration_secs: duration,
                    interval_ms: 500,
                }
                .validate()
                .is_err()
            );
        }
        for interval in [0, 100, 250, 750, 2000] {
            assert!(
                ProcessWatchRequest {
                    method: ProcessWatchMethod::ProcPoll,
                    duration_secs: 60,
                    interval_ms: interval,
                }
                .validate()
                .is_err()
            );
        }
        for interval in [200, 500, 1000] {
            assert!(
                ProcessWatchRequest {
                    method: ProcessWatchMethod::ProcPoll,
                    duration_secs: 60,
                    interval_ms: interval,
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn generated_script_interpolates_only_validated_values() {
        let request = ProcessWatchRequest {
            method: ProcessWatchMethod::ProcPoll,
            duration_secs: 120,
            interval_ms: 500,
        };
        let script = generate_watch_command("0123456789abcdef", &request).unwrap();
        assert!(script.contains("LH_MARKER='0123456789abcdef'"));
        assert!(script.contains("LH_DUR=120"));
        assert!(script.contains("LH_SLEEP_ARG='0.5'"));
        assert!(generate_watch_command("not-hex!!", &request).is_err());
        assert!(generate_watch_command("0123456789ABCDEF", &request).is_ok());
    }

    #[test]
    fn probe_parses_gaps_and_never_claims_clean() {
        let output = "K|v1\nP|yes\nA|root\nU|0\nH|0\nS|yes\nC|no\nW|0\n";
        let probe = parse_probe_output(output).unwrap();
        assert!(probe.proc_readable);
        assert!(probe.is_root);
        assert_eq!(probe.account, "root");
        // Even a clean probe still says polling misses short-lived processes.
        assert_eq!(probe.gaps, vec![ProcessWatchGap::PollingMissesShortLived]);

        let output = "K|v1\nP|yes\nA|worker\nU|1000\nH|1\nS|no\nC|yes\nW|1\n";
        let probe = parse_probe_output(output).unwrap();
        assert!(probe.gaps.contains(&ProcessWatchGap::Hidepid));
        assert!(probe.gaps.contains(&ProcessWatchGap::Container));
        assert!(probe.gaps.contains(&ProcessWatchGap::CoarseInterval));
        assert!(probe.gaps.contains(&ProcessWatchGap::AlreadyRunning));
        // hidepid without root is a gap; hidepid with root is not.
        let output = "K|v1\nP|yes\nA|root\nU|0\nH|1\nS|yes\nC|no\nW|0\n";
        assert!(
            !parse_probe_output(output)
                .unwrap()
                .gaps
                .contains(&ProcessWatchGap::Hidepid)
        );
        // An answer the parser cannot read is a failure, not a clean target.
        assert!(parse_probe_output("garbage\n").is_err());
    }

    #[test]
    fn wire_rows_parse_and_hostile_argv_cannot_inject_fields() {
        // A command line containing `|` and a fake `E|` prefix inside its
        // payload stays one event: it travels hex-encoded.
        let hostile = "E|B|1|0|1|0|0|0||injected";
        let encoded = hostile
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let line = format!("E|N|1700000000123|0|4242|1|777|0|7368|{encoded}");
        let WireLine::Event(row) = parse_watch_line(&line, false, 60) else {
            panic!("event line must parse");
        };
        assert_eq!(row.pid, 4242);
        assert_eq!(row.origin, EventOrigin::Observed);
        let comm = decode_comm(&row.comm_hex, false);
        let (command, _) = decode_command(&row.cmd_hex, &comm, false);
        assert!(command.contains("injected"));
        assert!(command.contains('E'));
        // A wrong field count is kept as an unparsed row, not half-read.
        assert!(matches!(
            parse_watch_line("E|N|1|2|3", false, 60),
            WireLine::Other(_)
        ));
        assert!(matches!(
            parse_watch_line("E|X|1|0|1|1|1|0|aa|bb", false, 60),
            WireLine::Other(_)
        ));
    }

    #[test]
    fn wire_control_bytes_and_non_utf8_flatten_safely() {
        // argv containing ESC, newline and invalid UTF-8 flattens, never
        // breaks a line open, and clips at the bound.
        let mut bytes = b"sh -c \x1b[31mecho hi\x1b[0m".to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&[0xff, 0xfe, b'x']);
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (command, _) = decode_command(&encoded, "sh", false);
        assert!(!command.chars().any(|c| c.is_control() && c != ' '));
        assert!(command.contains('\u{fffd}'));
        let long = "a".repeat(6000);
        let encoded = long.bytes().map(|b| format!("{b:02x}")).collect::<String>();
        let (_, clipped) = decode_command(&encoded, "x", false);
        assert!(clipped);
        // Kernel threads carry no argv: comm stands in.
        let (command, _) = decode_command("", "kworker/1:2", false);
        assert_eq!(command, "[kworker/1:2]");
    }

    #[test]
    fn normalize_collapses_digits_hex_and_mktemp_suffixes() {
        assert_eq!(normalize_command("sleep 1000"), "sleep #");
        assert_eq!(
            normalize_command("/usr/bin/beacon 1699999999"),
            "/usr/bin/beacon #"
        );
        assert_eq!(normalize_command("/tmp/x 0123456789abcdef0123"), "/tmp/x #");
        assert_eq!(
            normalize_command("/tmp/job.a1b2c3 /var/tmp/job.d4e5f6"),
            "/tmp/job.# /var/tmp/job.#"
        );
        // Short numbers and ordinary names stay verbatim: over-normalizing
        // would glue different commands into one group.
        assert_eq!(normalize_command("cat /etc/passwd"), "cat /etc/passwd");
        // Short runs stay; a four-digit port is a run and collapses — ports
        // differ between repeats anyway, so this still groups correctly.
        assert_eq!(normalize_command("curl 10.0.0.8:443"), "curl 10.0.0.8:443");
        assert_eq!(normalize_command("curl 10.0.0.8:8080"), "curl 10.0.0.8:#");
        assert_eq!(
            normalize_command("curl http://a/ 12345"),
            "curl http://a/ #"
        );
        assert_eq!(normalize_command("  spaced   out  "), "spaced out");
    }

    #[test]
    fn repeat_groups_find_cadence_and_exclude_own_and_baseline() {
        let mut events = vec![
            event(1, 1_000, 10, 0, "/usr/local/bin/beacon"),
            event(2, 11_000, 20, 0, "/usr/local/bin/beacon"),
            event(3, 21_000, 30, 0, "/usr/local/bin/beacon"),
            event(4, 31_000, 40, 0, "/usr/local/bin/beacon"),
        ];
        // A helper of the watch itself must never be a finding.
        events.push(ProcessWatchEvent {
            own: true,
            ..event(5, 2_000, 50, 0, "od -An -v -tx1")
        });
        events.push(ProcessWatchEvent {
            origin: EventOrigin::Baseline,
            ..event(6, 0, 60, 0, "/sbin/init")
        });
        let groups = repeat_groups(&events);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 4);
        assert_eq!(groups[0].intervals_ms, vec![10_000, 10_000, 10_000]);
        assert_eq!(groups[0].cadence, Cadence::Periodic { period_ms: 10_000 });
        assert_eq!(groups[0].uids, vec![0]);
    }

    #[test]
    fn a_burst_with_one_timestamp_is_repeated_not_periodic() {
        let events: Vec<ProcessWatchEvent> = (1..=4)
            .map(|seq| event(seq, 5_000, 10 + seq as u32, 0, "df"))
            .collect();
        assert_eq!(repeat_groups(&events)[0].cadence, Cadence::Repeated);
    }

    #[test]
    fn repeat_groups_normalize_repeats_with_random_parts() {
        let events = vec![
            event(1, 1_000, 10, 33, "/tmp/job.a1b2c3 arg"),
            event(2, 5_000, 20, 33, "/tmp/job.z9y8x7 arg"),
            event(3, 10_000, 30, 33, "/tmp/job.q2w3e4 arg"),
        ];
        let groups = repeat_groups(&events);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].normalized, "/tmp/job.# arg");
        assert_eq!(groups[0].count, 3);
        // Intervals [4s, 5s]: the median index picks 5 s, and 4 s sits
        // inside its ±20% band, so the group is periodic at 5 s.
        assert_eq!(groups[0].cadence, Cadence::Periodic { period_ms: 5_000 });
    }

    #[test]
    fn repeat_groups_repeated_when_cadence_unstable() {
        let events = vec![
            event(1, 1_000, 10, 0, "worker"),
            event(2, 2_000, 20, 0, "worker"),
            event(3, 50_000, 30, 0, "worker"),
        ];
        let groups = repeat_groups(&events);
        assert_eq!(groups[0].cadence, Cadence::Repeated);
        assert_eq!(
            repeat_groups(&[event(1, 0, 1, 0, "one-off")])[0].cadence,
            Cadence::Single
        );
    }

    #[test]
    fn pid_reuse_makes_distinct_identities() {
        // Same pid with a different starttime is a new process, not a dupe:
        // the wire identity is pid+start_ticks and both rows must survive.
        let old = "E|B|1000|0|100|1|111|0|696e6974|";
        let new = "E|N|2000|0|100|1|222|0|7368|";
        let WireLine::Event(a) = parse_watch_line(old, false, 60) else {
            panic!()
        };
        let WireLine::Event(b) = parse_watch_line(new, false, 60) else {
            panic!()
        };
        assert_eq!(a.pid, b.pid);
        assert_ne!(a.start_ticks, b.start_ticks);
    }

    #[test]
    fn summary_counts_what_the_sentence_needs() {
        let events = vec![
            event(1, 1_000, 10, 0, "beacon"),
            event(2, 2_000, 11, 0, "beacon"),
            event(3, 3_000, 12, 33, "other"),
            ProcessWatchEvent {
                own: true,
                ..event(4, 500, 99, 0, "helper")
            },
            ProcessWatchEvent {
                origin: EventOrigin::Baseline,
                ..event(5, 0, 1, 0, "init")
            },
        ];
        let groups = repeat_groups(&events);
        let summary = summarize(
            &events,
            2,
            &groups,
            vec![
                ProcessWatchGap::Container,
                ProcessWatchGap::PollingMissesShortLived,
            ],
            ProcessWatchEndState::Finished,
        );
        assert_eq!(summary.observed, 3);
        assert_eq!(summary.baseline, 1);
        assert_eq!(summary.own, 1);
        assert_eq!(summary.unparsed, 2);
        assert_eq!(summary.repeated_groups, 1);
        assert_eq!(summary.distinct_uids, 2);
        assert_eq!(summary.state, ProcessWatchEndState::Finished);
        assert_eq!(summary.gaps.len(), 2);
    }

    #[test]
    fn base64_round_trips_for_targets_without_hex_tools() {
        let encoded = "c2ggLWMgZWNobw==";
        assert_eq!(
            decode_wire_text(encoded, true).unwrap(),
            b"sh -c echo".to_vec()
        );
        assert!(decode_wire_text("!!!not-base64!!!", true).is_none());
        assert!(decode_wire_text("0f0", false).is_none());
    }
}
