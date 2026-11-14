//! Process activity watch: bounded handles around `ProcessWatchService` so
//! the page can probe, start, stream, stop and summarize a `/proc` poll watch
//! without ever touching a target, a command line, or a process directly.
//!
//! One live watch per binding, a small global pool, and a finished watch's
//! events stay readable for a retention window so the operator can still read
//! the result after the run ends — but never after the binding closed or a
//! new watch replaced it. Command lines may carry credentials: they cross
//! only inside the typed DTO, never into logs, tracing, or the AI context.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use lovelyhawk_core::CoreError;
use lovelyhawk_core::events::{
    ProcessWatchStreamEvent, ProcessWatchStreamEventKind as CoreEventKind,
};
use lovelyhawk_core::process_watch::{
    Cadence, EventOrigin, LiveProcessWatch, ProcessWatchEndState, ProcessWatchEvent,
    ProcessWatchEventKind, ProcessWatchGap, ProcessWatchMethod, ProcessWatchRequest,
    known_watch_failure, repeat_groups, summarize,
};
use lovelyhawk_core::process_watch_analysis::{
    ScheduleListing, classify_origins, group_origin, infer_checks, match_schedule,
};
use lovelyhawk_core::process_watch_upload::CleanupOutcome;
use lovelyhawk_core::ssh::BoundSshSession;
use lovelyhawk_core::target::TargetGuard;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::BackendServices;
use crate::ssh_api::SshApi;

mod upload;

pub(crate) use upload::ProcessWatchUploadInput;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_WATCHES: usize = 4;
const MAX_WATCHES_PER_BINDING: usize = 1;
const MAX_RETAINED_EVENTS: usize = 20_000;
const MAX_RETAINED_UNPARSED: usize = 256;
const MAX_JOURNAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_POLL_EVENTS: usize = 500;
const MAX_POLL_BYTES: usize = 4 * 1024 * 1024;
const MAX_CORE_DRAIN_PER_POLL: usize = 256;
const PRE_STOP_DRAIN: Duration = Duration::from_secs(2);
const MAX_COMMAND_BYTES: usize = 8 * 1024;
const MAX_RAW_BYTES: usize = 16 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_GLOBAL_OPERATIONS: usize = 12;
const MAX_OPERATIONS_PER_BINDING: usize = 3;
const MAX_SUMMARY_GROUPS: usize = 500;
const MAX_GROUP_INTERVALS: usize = 50;
const START_TIMEOUT: Duration = Duration::from_secs(30);
const START_RESERVATION_TTL: Duration = Duration::from_secs(35);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const RUNNING_GRACE: Duration = Duration::from_secs(30);
const FINISHED_RETENTION: Duration = Duration::from_secs(30 * 60);
const CLOSED_BINDING_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CLOSED_BINDINGS: usize = 128;
const CLEANUP_DEADLINE: Duration = Duration::from_secs(30);
const SCHEDULE_DEADLINE: Duration = Duration::from_secs(20);
const MAX_INFERRED: usize = 32;
const MAX_INDICATORS: usize = 50;

pub(crate) struct ProcessWatchApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    watches: Mutex<WatchRegistry>,
    operations: Arc<Mutex<OperationState>>,
    uploads: Mutex<upload::UploadRegistry>,
}

impl fmt::Debug for ProcessWatchApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessWatchApi")
            .finish_non_exhaustive()
    }
}

impl ProcessWatchApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            watches: Mutex::new(WatchRegistry::default()),
            operations: Arc::new(Mutex::new(OperationState::default())),
            uploads: Mutex::new(upload::UploadRegistry::default()),
        }
    }

    pub(crate) async fn probe(
        &self,
        binding_handle: &str,
    ) -> Result<ProcessWatchProbeDto, ProcessWatchApiError> {
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let probe = self.services.process_watch().probe(&binding).await?;
        self.ensure_binding(&scope, &binding)?;
        Ok(ProcessWatchProbeDto {
            proc_readable: probe.proc_readable,
            gaps: gap_keys(&probe.gaps),
            fractional_sleep: probe.fractional_sleep,
            account: bounded_single_line(&probe.account, 128).0,
            is_root: probe.is_root,
        })
    }

    pub(crate) async fn start(
        &self,
        binding_handle: &str,
        input: ProcessWatchStartInput,
    ) -> Result<ProcessWatchStartedDto, ProcessWatchApiError> {
        input.validate()?;
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        // The probe runs again rather than trusting a page-held one: gaps
        // bound into the start answer must be the target's present state.
        let probe = self.services.process_watch().probe(&binding).await?;
        self.ensure_binding(&scope, &binding)?;
        if !probe.proc_readable {
            return Err(ProcessWatchApiError::ProcUnreadable);
        }
        let request = ProcessWatchRequest {
            method: lovelyhawk_core::process_watch::ProcessWatchMethod::ProcPoll,
            duration_secs: input.duration_seconds,
            interval_ms: input.interval_ms,
        };
        request
            .validate()
            .map_err(|_| ProcessWatchApiError::InvalidInput)?;
        let (watch_handle, evicted) = self
            .lock_watches()?
            .reserve(scope.clone(), Instant::now())?;
        close_live_watches(evicted).await;
        let started = tokio::time::timeout(
            START_TIMEOUT,
            self.services
                .process_watch()
                .start(&binding, request.clone()),
        )
        .await;
        let live = match started {
            Ok(Ok(live)) => Arc::new(live),
            Ok(Err(_)) => {
                self.remove_slot(&watch_handle);
                return Err(ProcessWatchApiError::Core);
            }
            Err(_) => {
                self.remove_slot(&watch_handle);
                return Err(ProcessWatchApiError::TimedOut);
            }
        };
        if self.ensure_binding(&scope, &binding).is_err() {
            self.remove_slot(&watch_handle);
            close_live_watch(&live).await;
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        self.activate_watch(
            binding_handle,
            binding,
            scope,
            watch_handle,
            live,
            request,
            gap_keys(&probe.gaps),
        )
        .await
    }

    /// Registers a started watch under its reserved handle. Shared by both
    /// methods, so an upload run is tracked, polled and reaped like a poll.
    #[allow(clippy::too_many_arguments)]
    async fn activate_watch(
        &self,
        binding_handle: &str,
        binding: BoundSshSession,
        scope: BindingScope,
        watch_handle: String,
        live: Arc<LiveProcessWatch>,
        request: ProcessWatchRequest,
        gaps: Vec<String>,
    ) -> Result<ProcessWatchStartedDto, ProcessWatchApiError> {
        let method = request.method.key();
        let active = Arc::new(ActiveWatch {
            binding_handle: binding_handle.to_owned(),
            binding,
            scope: scope.clone(),
            live,
            request,
            gaps,
            started_at: Instant::now(),
            state: Mutex::new(WatchState::default()),
            schedule: tokio::sync::Mutex::new(None),
        });
        let activation = self.lock_watches().and_then(|mut watches| {
            watches.activate(&watch_handle, &scope, Arc::clone(&active), Instant::now())
        });
        if let Err(error) = activation {
            close_live_watch(&active.live).await;
            return Err(error);
        }
        if let Err(error) = self.ensure_active(&active) {
            let _ = self.remove_active(&watch_handle, &active);
            close_live_watch(&active.live).await;
            return Err(error);
        }
        Ok(ProcessWatchStartedDto {
            watch_handle,
            method,
            started_at_ms: 0,
            deadline_at_ms: 0,
            gaps: active.gaps.clone(),
        })
    }

    pub(crate) async fn poll(
        &self,
        binding_handle: &str,
        watch_handle: &str,
        cursor: u64,
        limit: u32,
    ) -> Result<ProcessWatchPollDto, ProcessWatchApiError> {
        validate_handle(watch_handle)?;
        if cursor > MAX_SAFE_JSON_INTEGER || limit == 0 || limit as usize > MAX_POLL_EVENTS {
            return Err(ProcessWatchApiError::InvalidCursor);
        }
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let active = self.active(watch_handle)?;
        if active.scope != scope || active.binding != binding {
            self.invalidate(watch_handle, &active).await;
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(watch_handle, &active).await;
            return Err(error);
        }
        let polled = {
            let mut state = active.lock_state()?;
            state.poll(&active, watch_handle, cursor, limit as usize)
        };
        let mut response = match polled {
            Ok(response) => response,
            Err(error) => {
                self.invalidate(watch_handle, &active).await;
                return Err(error);
            }
        };
        // An upload run is not over until what it wrote is gone: the first
        // poll that sees the end removes it and reports what it found.
        if response.state != "running" && response.cleanup.is_none() {
            response.cleanup = self.finish_cleanup(&active).await;
        }
        Ok(response)
    }

    /// Ask the remote loop to end, then independently ask the target whether
    /// the recorded process identity is really gone.
    ///
    /// The answer keeps the truth even when the second part cannot run: a
    /// binding that went away mid-watch reports `stopVerified: null` and the
    /// loop's own deadline instead of a clean "stopped".
    pub(crate) async fn stop(
        &self,
        binding_handle: &str,
        watch_handle: &str,
    ) -> Result<ProcessWatchStoppedDto, ProcessWatchApiError> {
        validate_handle(watch_handle)?;
        let (binding, scope) = match self.watch_binding(binding_handle) {
            Ok(pair) => pair,
            Err(error) => {
                let active = self
                    .lock_watches()?
                    .take_for_binding(watch_handle, binding_handle);
                if let Some(active) = active {
                    if let Ok(mut state) = active.state.lock() {
                        if state.status == WatchStatus::Running {
                            state.status = WatchStatus::Disconnected;
                        }
                        state.finished_at.get_or_insert_with(Instant::now);
                    }
                    close_live_watch(&active.live).await;
                }
                return Err(error);
            }
        };
        self.reap_stale(Some(&scope)).await;
        let active = self.active(watch_handle)?;
        if active.scope != scope || active.binding != binding {
            self.invalidate(watch_handle, &active).await;
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        // Closing the channel discards what is still queued behind a full
        // buffer, so rows the target already reported are taken first.
        let settle = Instant::now();
        let mut quiet = 0;
        while quiet < 3 && settle.elapsed() < PRE_STOP_DRAIN {
            let advanced = {
                let mut state = active.lock_state()?;
                let before = state.last_sequence;
                state.drain(&active.live)?;
                state.last_sequence != before
            };
            if advanced {
                quiet = 0;
            } else {
                quiet += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        let (identity, marker) = {
            let mut state = active.lock_state()?;
            if state.status == WatchStatus::Running {
                state.status = WatchStatus::Cancelled;
                state.finished_at.get_or_insert_with(Instant::now);
            }
            (
                active.live.remote_identity(),
                active.live.marker().to_owned(),
            )
        };
        active.live.request_stop();
        let _ = tokio::time::timeout(CONTROL_TIMEOUT, active.live.stop()).await;
        let stop_verified = match identity {
            Some(identity) => self
                .services
                .process_watch()
                .verify_stopped(&active.binding, &identity, &marker)
                .await
                .ok(),
            // No header ever arrived: nothing to name. The channel close
            // already ended anything that was there.
            None => Some(true),
        };
        let status = {
            let mut state = active.lock_state()?;
            state.stop_verified = stop_verified;
            state.status.as_str().to_owned()
        };
        let cleanup = self.finish_cleanup(&active).await;
        Ok(ProcessWatchStoppedDto {
            state: status,
            stop_verified,
            cleanup,
        })
    }

    pub(crate) async fn summary(
        &self,
        binding_handle: &str,
        watch_handle: &str,
    ) -> Result<ProcessWatchSummaryDto, ProcessWatchApiError> {
        validate_handle(watch_handle)?;
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let active = self.active(watch_handle)?;
        if active.scope != scope || active.binding != binding {
            self.invalidate(watch_handle, &active).await;
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        if let Err(error) = self.ensure_active(&active) {
            self.invalidate(watch_handle, &active).await;
            return Err(error);
        }
        let schedule = self.schedule_for(&active).await;
        let mut state = active.lock_state()?;
        state.drain(&active.live)?;
        Ok(state.summary(&active.gaps, schedule.as_ref()))
    }

    /// Removes an upload run's tool once, remembers the answer, and writes
    /// it to the operation journal. `None` for a run that wrote nothing.
    async fn finish_cleanup(&self, active: &Arc<ActiveWatch>) -> Option<&'static str> {
        if active.live.method() != ProcessWatchMethod::Pspy {
            return None;
        }
        if let Some(done) = active.lock_state().ok().and_then(|state| state.cleanup)
            && done == "clean"
        {
            return Some(done);
        }
        let outcome = tokio::time::timeout(CLEANUP_DEADLINE, active.live.cleanup())
            .await
            .ok()
            .flatten();
        let key = cleanup_key(outcome.as_ref());
        let first = active
            .lock_state()
            .map(|mut state| state.cleanup.replace(key) != Some(key))
            .unwrap_or(false);
        if first {
            self.journal_cleanup(active, outcome.as_ref());
        }
        Some(key)
    }

    /// The target's cron schedules, read once per watch and kept: the same
    /// summary asked twice must not read the target twice.
    async fn schedule_for(&self, active: &Arc<ActiveWatch>) -> Option<ScheduleListing> {
        let mut cached = active.schedule.lock().await;
        if cached.is_none() {
            let listing = tokio::time::timeout(
                SCHEDULE_DEADLINE,
                self.services
                    .process_watch()
                    .scheduled_commands(&active.binding),
            )
            .await
            .ok()
            .and_then(Result::ok);
            *cached = Some(listing);
        }
        cached.clone().flatten()
    }

    pub(crate) async fn close_binding(&self, binding_handle: &str) {
        let active = self
            .watches
            .lock()
            .map(|mut watches| watches.close_binding(binding_handle, Instant::now()))
            .unwrap_or_default();
        if let Ok(mut operations) = self.operations.lock() {
            operations.close_binding(binding_handle);
        }
        if let Ok(mut uploads) = self.uploads.lock() {
            uploads.close_binding(binding_handle);
        }
        close_live_watches(active).await;
    }

    fn watch_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), ProcessWatchApiError> {
        validate_handle(binding_handle)?;
        let binding = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| ProcessWatchApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(binding.target())
            .map_err(|_| ProcessWatchApiError::BindingUnavailable)?;
        let scope = BindingScope::from_binding(binding_handle, &binding);
        self.ensure_binding_open(binding_handle)?;
        Ok((binding, scope))
    }

    fn ensure_binding(
        &self,
        expected: &BindingScope,
        binding: &BoundSshSession,
    ) -> Result<(), ProcessWatchApiError> {
        self.ensure_binding_open(&expected.binding_handle)?;
        self.services
            .target()
            .validate(binding.target())
            .map_err(|_| ProcessWatchApiError::BindingUnavailable)?;
        if &BindingScope::from_binding(&expected.binding_handle, binding) != expected {
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        let current = self
            .ssh_api
            .binding_session_clone(&expected.binding_handle)
            .map_err(|_| ProcessWatchApiError::BindingUnavailable)?;
        if BindingScope::from_binding(&expected.binding_handle, &current) != *expected {
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        self.services
            .target()
            .validate(current.target())
            .map_err(|_| ProcessWatchApiError::BindingUnavailable)?;
        self.ensure_binding_open(&expected.binding_handle)
    }

    fn ensure_active(&self, active: &ActiveWatch) -> Result<(), ProcessWatchApiError> {
        if active.binding.target() != &active.scope.target {
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        self.ensure_binding(&active.scope, &active.binding)
    }

    fn acquire_operation(
        &self,
        scope: &BindingScope,
    ) -> Result<OperationPermit, ProcessWatchApiError> {
        OperationPermit::acquire(
            Arc::clone(&self.operations),
            scope.binding_handle.clone(),
            scope.concurrency_key(),
        )
    }

    fn ensure_binding_open(&self, binding_handle: &str) -> Result<(), ProcessWatchApiError> {
        self.lock_watches()?
            .ensure_binding_open(binding_handle, Instant::now())
    }

    async fn reap_stale(&self, current: Option<&BindingScope>) {
        let stale = self
            .watches
            .lock()
            .map(|mut watches| watches.take_stale(Instant::now(), current))
            .unwrap_or_default();
        close_live_watches(stale).await;
    }

    fn active(&self, handle: &str) -> Result<Arc<ActiveWatch>, ProcessWatchApiError> {
        self.lock_watches()?.active(handle, Instant::now())
    }

    async fn invalidate(&self, handle: &str, active: &Arc<ActiveWatch>) {
        let _ = self.remove_active(handle, active);
        close_live_watch(&active.live).await;
    }

    fn remove_active(
        &self,
        handle: &str,
        active: &Arc<ActiveWatch>,
    ) -> Result<(), ProcessWatchApiError> {
        self.lock_watches()?.remove_active(handle, active)
    }

    fn remove_slot(&self, handle: &str) {
        if let Ok(mut watches) = self.watches.lock() {
            watches.slots.remove(handle);
        }
    }

    fn lock_watches(&self) -> Result<MutexGuard<'_, WatchRegistry>, ProcessWatchApiError> {
        self.watches
            .lock()
            .map_err(|_| ProcessWatchApiError::RegistryUnavailable)
    }
}

impl Drop for ProcessWatchApi {
    fn drop(&mut self) {
        if let Ok(watches) = self.watches.lock() {
            for slot in watches.slots.values() {
                if let WatchSlot::Active(active) = slot {
                    active.live.request_stop();
                }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProcessWatchStartInput {
    duration_seconds: u32,
    interval_ms: u32,
}

impl fmt::Debug for ProcessWatchStartInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessWatchStartInput")
            .field("duration_seconds", &self.duration_seconds)
            .field("interval_ms", &self.interval_ms)
            .finish()
    }
}

impl ProcessWatchStartInput {
    fn validate(&self) -> Result<(), ProcessWatchApiError> {
        if !(60..=1800).contains(&self.duration_seconds)
            || !matches!(self.interval_ms, 200 | 500 | 1000)
        {
            return Err(ProcessWatchApiError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchProbeDto {
    proc_readable: bool,
    gaps: Vec<String>,
    fractional_sleep: bool,
    account: String,
    is_root: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchStartedDto {
    watch_handle: String,
    method: &'static str,
    /// Filled from the first poll once the remote header arrived; zero until
    /// then rather than a guessed clock.
    started_at_ms: u64,
    deadline_at_ms: u64,
    gaps: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchPollDto {
    watch_handle: String,
    state: &'static str,
    elapsed_seconds: u64,
    observed_count: u64,
    baseline_count: u64,
    own_count: u64,
    unparsed_count: u64,
    truncated: bool,
    gaps: Vec<String>,
    /// `None` while running and when the stop check could not reach the
    /// target — a missing answer, not a clean one.
    stop_verified: Option<bool>,
    self_ends_at_ms: u64,
    next_cursor: u64,
    /// For an upload run that ended: `clean`, `residue` or `unverified`.
    cleanup: Option<&'static str>,
    events: Vec<ProcessWatchEventDto>,
    unparsed: Vec<ProcessWatchUnparsedDto>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchEventDto {
    kind: &'static str,
    seq: u64,
    at_ms: u64,
    /// `-1` when the target could not name an owner.
    uid: i64,
    pid: u32,
    ppid: Option<u32>,
    start_ticks: Option<u64>,
    command: String,
    clipped: bool,
    origin: &'static str,
    own: bool,
    raw: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchUnparsedDto {
    seq: u64,
    raw: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchStoppedDto {
    state: String,
    stop_verified: Option<bool>,
    cleanup: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchSummaryDto {
    state: &'static str,
    observed: usize,
    baseline: usize,
    own: usize,
    unparsed: usize,
    periodic_groups: usize,
    repeated_groups: usize,
    distinct_uids: usize,
    file_events: usize,
    gaps: Vec<String>,
    groups: Vec<ProcessWatchGroupDto>,
    /// `false` when the cron files could not be read at all; a group with
    /// no schedule then means "not checked", not "not scheduled".
    schedule_read: bool,
    schedule_unreadable: Vec<String>,
    origins: Vec<ProcessWatchOriginCountDto>,
    inferred: Vec<ProcessWatchInferredDto>,
    unmatched: Vec<ProcessWatchUnmatchedDto>,
    unmatched_truncated: bool,
    indicators: Vec<ProcessWatchIndicatorDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchOriginCountDto {
    origin: &'static str,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchInferredDto {
    entry_id: &'static str,
    title: &'static str,
    count: usize,
    sample: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchUnmatchedDto {
    command: String,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchIndicatorDto {
    kind: &'static str,
    value: String,
    scope: &'static str,
    hits: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessWatchGroupDto {
    normalized: String,
    sample: String,
    count: usize,
    uids: Vec<u32>,
    first_at_ms: u64,
    last_at_ms: u64,
    intervals_ms: Vec<u64>,
    cadence: &'static str,
    period_ms: Option<u64>,
    origin: &'static str,
    origin_via: String,
    /// The cron file that schedules this command, when one was matched.
    schedule: Option<String>,
}

#[derive(Clone, Eq, PartialEq)]
struct BindingScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BindingScope {
    fn from_binding(binding_handle: &str, binding: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: binding.session_id().to_owned(),
            connection_id: binding.connection_id().to_owned(),
            target: binding.target().clone(),
        }
    }

    fn concurrency_key(&self) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}",
            self.binding_handle,
            self.session_id,
            self.connection_id,
            self.target.identity.as_str(),
            self.target.generation,
        )
    }
}

impl fmt::Debug for BindingScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessWatchBindingScope([REDACTED])")
    }
}

struct ActiveWatch {
    binding_handle: String,
    binding: BoundSshSession,
    scope: BindingScope,
    live: Arc<LiveProcessWatch>,
    request: ProcessWatchRequest,
    gaps: Vec<String>,
    started_at: Instant,
    state: Mutex<WatchState>,
    /// `Some(None)` once the schedules were asked for and could not be read.
    schedule: tokio::sync::Mutex<Option<Option<ScheduleListing>>>,
}

impl ActiveWatch {
    fn lock_state(&self) -> Result<MutexGuard<'_, WatchState>, ProcessWatchApiError> {
        self.state
            .lock()
            .map_err(|_| ProcessWatchApiError::RegistryUnavailable)
    }

    /// While running the slot lives until the remote deadline plus grace;
    /// once finished, its retained events stay readable for the retention
    /// window — never longer, never past a binding close.
    fn expires_at(&self) -> Instant {
        let state = self.state.lock().ok();
        if let Some(finished) = state.as_ref().and_then(|state| state.finished_at) {
            return finished + FINISHED_RETENTION;
        }
        self.started_at
            + Duration::from_secs(u64::from(self.request.duration_secs))
            + RUNNING_GRACE
            + FINISHED_RETENTION
    }
}

impl fmt::Debug for ActiveWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveProcessWatch([REDACTED])")
    }
}

#[derive(Default)]
struct WatchRegistry {
    slots: HashMap<String, WatchSlot>,
    closed_bindings: HashMap<String, Instant>,
    closed_overflow_until: Option<Instant>,
}

enum WatchSlot {
    Opening {
        scope: BindingScope,
        expires_at: Instant,
    },
    Active(Arc<ActiveWatch>),
}

impl WatchSlot {
    fn scope(&self) -> &BindingScope {
        match self {
            Self::Opening { scope, .. } => scope,
            Self::Active(active) => &active.scope,
        }
    }
}

impl WatchRegistry {
    /// A live watch refuses a second start on its binding; a finished one
    /// keeps the slot only until a new watch needs it.
    fn reserve(
        &mut self,
        scope: BindingScope,
        now: Instant,
    ) -> Result<(String, Vec<Arc<ActiveWatch>>), ProcessWatchApiError> {
        self.ensure_binding_open(&scope.binding_handle, now)?;
        let finished = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.scope().binding_handle == scope.binding_handle)
            .filter_map(|(handle, slot)| match slot {
                WatchSlot::Active(active) => active
                    .lock_state()
                    .ok()
                    .filter(|state| state.status != WatchStatus::Running)
                    .map(|_| handle.clone()),
                WatchSlot::Opening { .. } => None,
            })
            .collect::<Vec<_>>();
        let mut evicted = Vec::new();
        for handle in finished {
            if let Some(WatchSlot::Active(active)) = self.slots.remove(&handle) {
                evicted.push(active);
            }
        }
        if self
            .slots
            .values()
            .filter(|slot| slot.scope().binding_handle == scope.binding_handle)
            .count()
            >= MAX_WATCHES_PER_BINDING
        {
            return Err(ProcessWatchApiError::WatchAlreadyActive);
        }
        if self.slots.len() >= MAX_WATCHES {
            let oldest = self
                .slots
                .iter()
                .filter_map(|(handle, slot)| match slot {
                    WatchSlot::Active(active) => Some((handle.clone(), active.expires_at())),
                    WatchSlot::Opening { .. } => None,
                })
                .min_by_key(|(_, expires_at)| *expires_at)
                .map(|(handle, _)| handle)
                .ok_or(ProcessWatchApiError::RegistryCapacity)?;
            if let Some(WatchSlot::Active(active)) = self.slots.remove(&oldest) {
                evicted.push(active);
            }
        }
        for _ in 0..8 {
            let handle = Uuid::new_v4().to_string();
            if self.slots.contains_key(&handle) {
                continue;
            }
            self.slots.insert(
                handle.clone(),
                WatchSlot::Opening {
                    scope,
                    expires_at: now + START_RESERVATION_TTL,
                },
            );
            return Ok((handle, evicted));
        }
        Err(ProcessWatchApiError::RegistryCapacity)
    }

    fn activate(
        &mut self,
        handle: &str,
        scope: &BindingScope,
        active: Arc<ActiveWatch>,
        now: Instant,
    ) -> Result<(), ProcessWatchApiError> {
        let Some(slot) = self.slots.get_mut(handle) else {
            return Err(ProcessWatchApiError::WatchUnavailable);
        };
        match slot {
            WatchSlot::Opening {
                scope: reserved,
                expires_at,
            } if reserved == scope && *expires_at > now => {
                *slot = WatchSlot::Active(active);
                Ok(())
            }
            _ => Err(ProcessWatchApiError::BindingUnavailable),
        }
    }

    fn active(&self, handle: &str, now: Instant) -> Result<Arc<ActiveWatch>, ProcessWatchApiError> {
        match self.slots.get(handle) {
            Some(WatchSlot::Active(active)) if active.expires_at() > now => Ok(Arc::clone(active)),
            _ => Err(ProcessWatchApiError::WatchUnavailable),
        }
    }

    fn remove_active(
        &mut self,
        handle: &str,
        expected: &Arc<ActiveWatch>,
    ) -> Result<(), ProcessWatchApiError> {
        match self.slots.get(handle) {
            Some(WatchSlot::Active(active)) if Arc::ptr_eq(active, expected) => {
                self.slots.remove(handle);
                Ok(())
            }
            _ => Err(ProcessWatchApiError::WatchUnavailable),
        }
    }

    fn take_for_binding(&mut self, handle: &str, binding_handle: &str) -> Option<Arc<ActiveWatch>> {
        let matches = matches!(
            self.slots.get(handle),
            Some(WatchSlot::Active(active)) if active.binding_handle == binding_handle
        );
        if !matches {
            return None;
        }
        match self.slots.remove(handle) {
            Some(WatchSlot::Active(active)) => Some(active),
            _ => None,
        }
    }

    fn take_stale(
        &mut self,
        now: Instant,
        current: Option<&BindingScope>,
    ) -> Vec<Arc<ActiveWatch>> {
        self.prune_closed_bindings(now);
        let handles = self
            .slots
            .iter()
            .filter_map(|(handle, slot)| {
                let expired = match slot {
                    WatchSlot::Opening { expires_at, .. } => *expires_at <= now,
                    WatchSlot::Active(active) => active.expires_at() <= now,
                };
                let binding_changed = current.is_some_and(|current| {
                    slot.scope().binding_handle == current.binding_handle && slot.scope() != current
                });
                (expired || binding_changed).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        let mut active = Vec::new();
        for handle in handles {
            if let Some(WatchSlot::Active(watch)) = self.slots.remove(&handle) {
                active.push(watch);
            }
        }
        active
    }

    fn ensure_binding_open(
        &mut self,
        binding_handle: &str,
        now: Instant,
    ) -> Result<(), ProcessWatchApiError> {
        self.prune_closed_bindings(now);
        if self
            .closed_overflow_until
            .is_some_and(|expires_at| expires_at > now)
            || self.closed_bindings.contains_key(binding_handle)
        {
            return Err(ProcessWatchApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn close_binding(&mut self, binding_handle: &str, now: Instant) -> Vec<Arc<ActiveWatch>> {
        self.prune_closed_bindings(now);
        if self.closed_bindings.len() >= MAX_CLOSED_BINDINGS
            && !self.closed_bindings.contains_key(binding_handle)
        {
            self.closed_overflow_until = Some(now + CLOSED_BINDING_TTL);
        } else {
            self.closed_bindings
                .insert(binding_handle.to_owned(), now + CLOSED_BINDING_TTL);
        }
        let handles = self
            .slots
            .iter()
            .filter_map(|(handle, slot)| {
                (slot.scope().binding_handle == binding_handle).then_some(handle.clone())
            })
            .collect::<Vec<_>>();
        let mut active = Vec::new();
        for handle in handles {
            if let Some(WatchSlot::Active(watch)) = self.slots.remove(&handle) {
                active.push(watch);
            }
        }
        active
    }

    fn prune_closed_bindings(&mut self, now: Instant) {
        self.closed_bindings
            .retain(|_, expires_at| *expires_at > now);
        if self
            .closed_overflow_until
            .is_some_and(|expires_at| expires_at <= now)
        {
            self.closed_overflow_until = None;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum WatchStatus {
    #[default]
    Running,
    Finished,
    Cancelled,
    Truncated,
    Failed,
    Disconnected,
}

impl WatchStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Cancelled => "cancelled",
            Self::Truncated => "truncated",
            Self::Failed => "failed",
            Self::Disconnected => "disconnected",
        }
    }
}

#[derive(Default)]
struct WatchState {
    events: VecDeque<ProcessWatchEventDto>,
    unparsed: VecDeque<ProcessWatchUnparsedDto>,
    event_bytes: usize,
    last_sequence: u64,
    status: WatchStatus,
    stop_verified: Option<bool>,
    deadline_at_ms: u64,
    observed_count: u64,
    baseline_count: u64,
    own_count: u64,
    unparsed_count: u64,
    dropped_events: u64,
    truncated_output: bool,
    failure_reason: Option<&'static str>,
    finished_at: Option<Instant>,
    cleanup: Option<&'static str>,
}

impl WatchState {
    /// Pull whatever the core pump has queued. A closed channel mid-run is a
    /// disconnect, not a quiet end.
    fn drain(&mut self, live: &LiveProcessWatch) -> Result<(), ProcessWatchApiError> {
        for _ in 0..MAX_CORE_DRAIN_PER_POLL {
            match live.events().try_recv() {
                Ok(Some(event)) => self.apply_event(event)?,
                Ok(None) => break,
                Err(CoreError::ChannelClosed { .. }) => {
                    if self.status == WatchStatus::Running {
                        self.status = WatchStatus::Disconnected;
                        self.finished_at.get_or_insert_with(Instant::now);
                    }
                    break;
                }
                Err(_) => return Err(ProcessWatchApiError::Core),
            }
        }
        Ok(())
    }

    /// The rows after `cursor` that fit one answer, and the sequence the
    /// answer reaches. Both lists stop at that sequence, so the next read
    /// resumes exactly where this one ended.
    #[allow(clippy::type_complexity)]
    fn page(
        &self,
        cursor: u64,
        limit: usize,
    ) -> Result<(Vec<ProcessWatchEventDto>, Vec<ProcessWatchUnparsedDto>, u64), ProcessWatchApiError>
    {
        let mut events = Vec::new();
        let mut unparsed = Vec::new();
        let mut response_bytes = 1024_usize;
        let mut horizon = self.last_sequence;
        for event in self.events.iter().filter(|event| event.seq > cursor) {
            let bytes = serde_json::to_vec(event)
                .map_err(|_| ProcessWatchApiError::OutputLimit)?
                .len();
            if events.len() >= limit || response_bytes.saturating_add(bytes) > MAX_POLL_BYTES {
                horizon = event.seq - 1;
                break;
            }
            response_bytes = response_bytes.saturating_add(bytes);
            events.push(event.clone());
        }
        for row in self
            .unparsed
            .iter()
            .filter(|row| row.seq > cursor && row.seq <= horizon)
        {
            let bytes = serde_json::to_vec(row)
                .map_err(|_| ProcessWatchApiError::OutputLimit)?
                .len();
            if response_bytes.saturating_add(bytes) > MAX_POLL_BYTES {
                horizon = row.seq - 1;
                events.retain(|event| event.seq <= horizon);
                break;
            }
            response_bytes = response_bytes.saturating_add(bytes);
            unparsed.push(row.clone());
        }
        Ok((events, unparsed, horizon))
    }

    fn poll(
        &mut self,
        active: &ActiveWatch,
        watch_handle: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<ProcessWatchPollDto, ProcessWatchApiError> {
        self.drain(&active.live)?;
        if cursor > self.last_sequence {
            return Err(ProcessWatchApiError::InvalidCursor);
        }
        let (events, unparsed, horizon) = self.page(cursor, limit)?;
        let response = ProcessWatchPollDto {
            watch_handle: watch_handle.to_owned(),
            // Rows are still to be read: an end reported now would stop the
            // reader before it has them.
            state: if horizon < self.last_sequence {
                WatchStatus::Running.as_str()
            } else {
                self.status.as_str()
            },
            elapsed_seconds: active.started_at.elapsed().as_secs(),
            observed_count: self.observed_count,
            baseline_count: self.baseline_count,
            own_count: self.own_count,
            unparsed_count: self.unparsed_count,
            truncated: self.truncated_output || self.dropped_events > 0,
            gaps: active.gaps.clone(),
            stop_verified: self.stop_verified,
            self_ends_at_ms: self.deadline_at_ms,
            next_cursor: horizon,
            cleanup: self.cleanup,
            events,
            unparsed,
        };
        if serde_json::to_vec(&response)
            .map_err(|_| ProcessWatchApiError::OutputLimit)?
            .len()
            > MAX_POLL_BYTES
        {
            return Err(ProcessWatchApiError::OutputLimit);
        }
        Ok(response)
    }

    fn apply_event(&mut self, event: ProcessWatchStreamEvent) -> Result<(), ProcessWatchApiError> {
        if event.sequence != self.last_sequence.saturating_add(1) {
            return Err(ProcessWatchApiError::ProtocolViolation);
        }
        self.last_sequence = event.sequence;
        match event.kind {
            CoreEventKind::Started { deadline_at_ms, .. } => {
                self.deadline_at_ms = deadline_at_ms;
            }
            CoreEventKind::Process(process) => {
                match (process.kind, process.origin) {
                    (ProcessWatchEventKind::File, _) => {}
                    (_, EventOrigin::Baseline) => {
                        self.baseline_count = self.baseline_count.saturating_add(1)
                    }
                    (_, EventOrigin::Observed) => {
                        self.observed_count = self.observed_count.saturating_add(1)
                    }
                }
                if process.own {
                    self.own_count = self.own_count.saturating_add(1);
                }
                self.append_event(project_event(&process))?;
            }
            CoreEventKind::Unparsed { raw } => {
                self.unparsed_count = self.unparsed_count.saturating_add(1);
                if self.unparsed.len() >= MAX_RETAINED_UNPARSED {
                    self.unparsed.pop_front();
                    self.dropped_events = self.dropped_events.saturating_add(1);
                }
                self.unparsed.push_back(ProcessWatchUnparsedDto {
                    seq: event.sequence,
                    raw: bounded_single_line(&raw, MAX_RAW_BYTES).0,
                });
            }
            CoreEventKind::Stopped { reason } => {
                if self.status == WatchStatus::Running {
                    self.status = match reason {
                        ProcessWatchEndState::Finished => WatchStatus::Finished,
                        ProcessWatchEndState::Cancelled => WatchStatus::Cancelled,
                        ProcessWatchEndState::Truncated => {
                            self.truncated_output = true;
                            WatchStatus::Truncated
                        }
                        ProcessWatchEndState::Failed => WatchStatus::Failed,
                        ProcessWatchEndState::Disconnected => WatchStatus::Disconnected,
                    };
                    self.finished_at.get_or_insert_with(Instant::now);
                }
            }
            CoreEventKind::Failed { message } => {
                self.status = WatchStatus::Failed;
                self.finished_at.get_or_insert_with(Instant::now);
                // Only a sentence the core chose itself may cross; target-side
                // text stays on the target.
                self.failure_reason = known_watch_failure(&message);
            }
        }
        Ok(())
    }

    fn append_event(&mut self, event: ProcessWatchEventDto) -> Result<(), ProcessWatchApiError> {
        let bytes = serde_json::to_vec(&event)
            .map_err(|_| ProcessWatchApiError::OutputLimit)?
            .len();
        if bytes > MAX_EVENT_BYTES {
            return Err(ProcessWatchApiError::OutputLimit);
        }
        while self.events.len() >= MAX_RETAINED_EVENTS
            || self.event_bytes.saturating_add(bytes) > MAX_JOURNAL_BYTES
        {
            let Some(removed) = self.events.pop_front() else {
                return Err(ProcessWatchApiError::OutputLimit);
            };
            let removed_bytes = serde_json::to_vec(&removed)
                .map_err(|_| ProcessWatchApiError::OutputLimit)?
                .len();
            self.event_bytes = self.event_bytes.saturating_sub(removed_bytes);
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.event_bytes = self.event_bytes.saturating_add(bytes);
        self.events.push_back(event);
        Ok(())
    }

    fn summary(
        &self,
        gaps: &[String],
        schedule: Option<&ScheduleListing>,
    ) -> ProcessWatchSummaryDto {
        let events: Vec<ProcessWatchEvent> = self
            .events
            .iter()
            .map(|event| ProcessWatchEvent {
                kind: if event.kind == "file" {
                    ProcessWatchEventKind::File
                } else {
                    ProcessWatchEventKind::Process
                },
                seq: event.seq,
                at_ms: event.at_ms,
                uid: if event.uid < 0 {
                    u32::MAX
                } else {
                    event.uid as u32
                },
                pid: event.pid,
                ppid: event.ppid,
                start_ticks: event.start_ticks,
                command: event.command.clone(),
                clipped: event.clipped,
                origin: if event.origin == "baseline" {
                    EventOrigin::Baseline
                } else {
                    EventOrigin::Observed
                },
                own: event.own,
                raw: event.raw.clone(),
            })
            .collect();
        let groups = repeat_groups(&events);
        let verdicts = classify_origins(&events);
        let mut origin_counts: std::collections::BTreeMap<&'static str, usize> =
            std::collections::BTreeMap::new();
        for event in &events {
            if event.own
                || event.origin == EventOrigin::Baseline
                || event.kind == ProcessWatchEventKind::File
            {
                continue;
            }
            if let Some(verdict) = verdicts.get(&event.seq) {
                *origin_counts.entry(verdict.origin.key()).or_default() += 1;
            }
        }
        let inference = infer_checks(&events);
        let catalog = lovelyhawk_core::command_workbench::shipped_catalog();
        let indicators = lovelyhawk_core::ioc_extract::extract_iocs(
            events
                .iter()
                .filter(|event| !event.own && event.kind == ProcessWatchEventKind::Process)
                .map(|event| ("进程活动监视", event.command.as_str())),
        );
        let end_state = match self.status {
            WatchStatus::Running => ProcessWatchEndState::Finished,
            WatchStatus::Finished => ProcessWatchEndState::Finished,
            WatchStatus::Cancelled => ProcessWatchEndState::Cancelled,
            WatchStatus::Truncated => ProcessWatchEndState::Truncated,
            WatchStatus::Failed => ProcessWatchEndState::Failed,
            WatchStatus::Disconnected => ProcessWatchEndState::Disconnected,
        };
        let gap_enums = gaps
            .iter()
            .filter_map(|key| match key.as_str() {
                "hidepid" => Some(ProcessWatchGap::Hidepid),
                "container" => Some(ProcessWatchGap::Container),
                "coarse-interval" => Some(ProcessWatchGap::CoarseInterval),
                "proc-unreadable" => Some(ProcessWatchGap::ProcUnreadable),
                "polling-misses-short-lived" => Some(ProcessWatchGap::PollingMissesShortLived),
                "already-running" => Some(ProcessWatchGap::AlreadyRunning),
                _ => None,
            })
            .collect::<Vec<_>>();
        let summary = summarize(
            &events,
            self.unparsed_count as usize,
            &groups,
            gap_enums,
            end_state,
        );
        ProcessWatchSummaryDto {
            state: self.status.as_str(),
            observed: summary.observed,
            baseline: summary.baseline,
            own: summary.own,
            unparsed: summary.unparsed,
            periodic_groups: summary.periodic_groups,
            repeated_groups: summary.repeated_groups,
            distinct_uids: summary.distinct_uids,
            file_events: summary.file_events,
            schedule_read: schedule.is_some(),
            schedule_unreadable: schedule
                .map(|listing| {
                    listing
                        .unreadable
                        .iter()
                        .take(16)
                        .map(|source| bounded_single_line(source, 256).0)
                        .collect()
                })
                .unwrap_or_default(),
            origins: origin_counts
                .into_iter()
                .map(|(origin, count)| ProcessWatchOriginCountDto { origin, count })
                .collect(),
            inferred: inference
                .checks
                .iter()
                .take(MAX_INFERRED)
                .filter_map(|check| {
                    catalog
                        .iter()
                        .find(|entry| entry.id == check.entry_id)
                        .map(|entry| ProcessWatchInferredDto {
                            entry_id: check.entry_id,
                            title: entry.title,
                            count: check.count,
                            sample: bounded_single_line(&check.sample, 512).0,
                        })
                })
                .collect(),
            unmatched: inference
                .unmatched
                .iter()
                .map(|(command, count)| ProcessWatchUnmatchedDto {
                    command: bounded_single_line(command, 512).0,
                    count: *count,
                })
                .collect(),
            unmatched_truncated: inference.unmatched_truncated,
            indicators: indicators
                .entries
                .iter()
                .take(MAX_INDICATORS)
                .map(|entry| ProcessWatchIndicatorDto {
                    kind: match entry.kind {
                        lovelyhawk_core::ioc_extract::IocKind::Ipv4 => "ipv4",
                        lovelyhawk_core::ioc_extract::IocKind::Ipv6 => "ipv6",
                        lovelyhawk_core::ioc_extract::IocKind::Domain => "domain",
                        lovelyhawk_core::ioc_extract::IocKind::Url => "url",
                    },
                    value: bounded_single_line(&entry.value, 512).0,
                    scope: match entry.scope {
                        lovelyhawk_core::ioc_extract::IocScope::Public => "public",
                        lovelyhawk_core::ioc_extract::IocScope::Private => "private",
                        lovelyhawk_core::ioc_extract::IocScope::Loopback => "loopback",
                        lovelyhawk_core::ioc_extract::IocScope::Reserved => "reserved",
                    },
                    hits: entry.hits,
                })
                .collect(),
            gaps: gaps.to_vec(),
            groups: groups
                .iter()
                .take(MAX_SUMMARY_GROUPS)
                .map(|group| {
                    let verdict = group_origin(group, &events, &verdicts);
                    ProcessWatchGroupDto {
                        origin: verdict.origin.key(),
                        origin_via: bounded_single_line(&verdict.via, 256).0,
                        schedule: schedule
                            .and_then(|listing| match_schedule(&group.sample, listing))
                            .map(|found| bounded_single_line(&found.source, 256).0),
                        normalized: bounded_single_line(&group.normalized, MAX_COMMAND_BYTES).0,
                        sample: bounded_single_line(&group.sample, MAX_COMMAND_BYTES).0,
                        count: group.count,
                        uids: group
                            .uids
                            .iter()
                            .copied()
                            .filter(|uid| *uid != u32::MAX)
                            .collect(),
                        first_at_ms: group.first_at_ms,
                        last_at_ms: group.last_at_ms,
                        intervals_ms: group
                            .intervals_ms
                            .iter()
                            .take(MAX_GROUP_INTERVALS)
                            .copied()
                            .collect(),
                        cadence: match group.cadence {
                            Cadence::Periodic { .. } => "periodic",
                            Cadence::Repeated => "repeated",
                            Cadence::Single => "single",
                        },
                        period_ms: match group.cadence {
                            Cadence::Periodic { period_ms } => Some(period_ms),
                            _ => None,
                        },
                    }
                })
                .collect(),
        }
    }
}

fn cleanup_key(outcome: Option<&CleanupOutcome>) -> &'static str {
    match outcome {
        Some(CleanupOutcome::Clean) => "clean",
        Some(CleanupOutcome::Residue { .. }) => "residue",
        Some(CleanupOutcome::Unverified { .. }) | None => "unverified",
    }
}

fn project_event(event: &ProcessWatchEvent) -> ProcessWatchEventDto {
    ProcessWatchEventDto {
        kind: match event.kind {
            ProcessWatchEventKind::Process => "process",
            ProcessWatchEventKind::File => "file",
        },
        seq: event.seq,
        at_ms: event.at_ms,
        uid: if event.uid == u32::MAX {
            -1
        } else {
            i64::from(event.uid)
        },
        pid: event.pid,
        ppid: event.ppid,
        start_ticks: event.start_ticks,
        command: bounded_single_line(&event.command, MAX_COMMAND_BYTES).0,
        clipped: event.clipped,
        origin: match event.origin {
            EventOrigin::Baseline => "baseline",
            EventOrigin::Observed => "observed",
        },
        own: event.own,
        raw: bounded_single_line(&event.raw, MAX_RAW_BYTES).0,
    }
}

#[derive(Default)]
struct OperationState {
    active: HashMap<Uuid, OperationEntry>,
}

struct OperationEntry {
    binding_handle: String,
    key: String,
}

impl OperationState {
    fn close_binding(&mut self, binding_handle: &str) {
        self.active
            .retain(|_, entry| entry.binding_handle != binding_handle);
    }
}

struct OperationPermit {
    state: Arc<Mutex<OperationState>>,
    token: Uuid,
}

impl OperationPermit {
    fn acquire(
        state: Arc<Mutex<OperationState>>,
        binding_handle: String,
        key: String,
    ) -> Result<Self, ProcessWatchApiError> {
        let token = Uuid::new_v4();
        {
            let mut current = state
                .lock()
                .map_err(|_| ProcessWatchApiError::RegistryUnavailable)?;
            let binding_operations = current
                .active
                .values()
                .filter(|entry| entry.key == key)
                .count();
            if current.active.len() >= MAX_GLOBAL_OPERATIONS
                || binding_operations >= MAX_OPERATIONS_PER_BINDING
            {
                return Err(ProcessWatchApiError::ConcurrencyLimit);
            }
            current.active.insert(
                token,
                OperationEntry {
                    binding_handle,
                    key,
                },
            );
        }
        Ok(Self { state, token })
    }
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active.remove(&self.token);
        }
    }
}

async fn close_live_watch(watch: &LiveProcessWatch) {
    watch.request_stop();
    let _ = tokio::time::timeout(CONTROL_TIMEOUT, watch.stop()).await;
    let _ = tokio::time::timeout(CLEANUP_DEADLINE, watch.cleanup()).await;
}

async fn close_live_watches(watches: Vec<Arc<ActiveWatch>>) {
    for watch in &watches {
        watch.live.request_stop();
    }
    let _ = tokio::time::timeout(CONTROL_TIMEOUT, async {
        for watch in &watches {
            let _ = watch.live.stop().await;
        }
    })
    .await;
    for watch in &watches {
        let _ = tokio::time::timeout(CLEANUP_DEADLINE, watch.live.cleanup()).await;
    }
}

fn gap_keys(gaps: &[ProcessWatchGap]) -> Vec<String> {
    gaps.iter().map(|gap| gap.key().to_owned()).collect()
}

fn bounded_single_line(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut sanitized = String::with_capacity(value.len());
    let mut changed = false;
    for character in value.chars() {
        if character.is_control() {
            sanitized.push('\u{fffd}');
            changed = true;
        } else {
            sanitized.push(character);
        }
    }
    let (bounded, truncated) = truncate_utf8(&sanitized, maximum_bytes);
    (bounded, changed || truncated)
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value.to_owned(), false);
    }
    let mut end = maximum_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

pub(crate) fn validate_handle(handle: &str) -> Result<(), ProcessWatchApiError> {
    let canonical = Uuid::parse_str(handle)
        .is_ok_and(|parsed| handle.len() == 36 && parsed.to_string() == handle);
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES || !canonical {
        return Err(ProcessWatchApiError::InvalidHandle);
    }
    Ok(())
}

pub(crate) enum ProcessWatchApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    InvalidInput,
    InvalidCursor,
    ProcUnreadable,
    WatchUnavailable,
    WatchAlreadyActive,
    RegistryCapacity,
    RegistryUnavailable,
    ConcurrencyLimit,
    OutputLimit,
    ProtocolViolation,
    TimedOut,
    /// The picked file is not a program this can upload.
    ToolRejected,
    /// The tool or plan handle is gone, expired or already used.
    PlanUnavailable,
    /// An upload cannot run here; the code says why.
    UploadRefused(&'static str),
    /// The bytes on the target did not match the chosen program.
    UploadMismatch,
}

impl fmt::Debug for ProcessWatchApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidCursor => "InvalidCursor",
            Self::ProcUnreadable => "ProcUnreadable",
            Self::WatchUnavailable => "WatchUnavailable",
            Self::WatchAlreadyActive => "WatchAlreadyActive",
            Self::RegistryCapacity => "RegistryCapacity",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::ConcurrencyLimit => "ConcurrencyLimit",
            Self::OutputLimit => "OutputLimit",
            Self::ProtocolViolation => "ProtocolViolation",
            Self::TimedOut => "TimedOut",
            Self::ToolRejected => "ToolRejected",
            Self::PlanUnavailable => "PlanUnavailable",
            Self::UploadRefused(_) => "UploadRefused",
            Self::UploadMismatch => "UploadMismatch",
        })
    }
}

impl fmt::Display for ProcessWatchApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the process watch operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the process watch capability is invalid",
            Self::InvalidInput => "the process watch parameters are invalid",
            Self::InvalidCursor => "the process watch cursor is invalid",
            Self::ProcUnreadable => "the target's process table is unreadable",
            Self::WatchUnavailable => "the process watch capability is missing or stale",
            Self::WatchAlreadyActive => "a process watch is already active for this binding",
            Self::RegistryCapacity => "the process watch registry is full",
            Self::RegistryUnavailable => "the process watch registry is unavailable",
            Self::ConcurrencyLimit => "too many process watch operations are active",
            Self::OutputLimit => "the process watch output exceeded its safety limit",
            Self::ProtocolViolation => "the process watch stream is invalid",
            Self::TimedOut => "the process watch operation timed out",
            Self::ToolRejected => "the chosen file is not an uploadable program",
            Self::PlanUnavailable => "the upload plan is missing, expired or used",
            Self::UploadRefused(_) => "the upload cannot run on this target",
            Self::UploadMismatch => "the uploaded file did not match the chosen program",
        })
    }
}

impl std::error::Error for ProcessWatchApiError {}

impl From<CoreError> for ProcessWatchApiError {
    fn from(error: CoreError) -> Self {
        tracing::warn!(operation = "ProcessWatch", error = %error, "core operation failed");
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
        Self::Core
    }
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::target::TargetIdentity;

    use super::*;

    fn scope(name: &str, generation: u64) -> BindingScope {
        BindingScope {
            binding_handle: format!("binding-{name}"),
            session_id: format!("session-{generation}"),
            connection_id: name.to_owned(),
            target: TargetGuard {
                identity: TargetIdentity::new(name).unwrap(),
                generation,
            },
        }
    }

    #[test]
    fn start_input_accepts_only_bounded_values() {
        for (duration, interval) in [(60, 200), (180, 500), (1800, 1000)] {
            let input: ProcessWatchStartInput = serde_json::from_value(serde_json::json!({
                "durationSeconds": duration,
                "intervalMs": interval,
            }))
            .unwrap();
            assert!(input.validate().is_ok());
        }
        for (duration, interval) in [
            (0, 500),
            (59, 500),
            (1801, 500),
            (60, 100),
            (60, 250),
            (60, 2000),
        ] {
            let input: ProcessWatchStartInput = serde_json::from_value(serde_json::json!({
                "durationSeconds": duration,
                "intervalMs": interval,
            }))
            .unwrap();
            assert!(input.validate().is_err());
        }
        // Unknown fields are refused outright.
        assert!(
            serde_json::from_value::<ProcessWatchStartInput>(serde_json::json!({
                "durationSeconds": 60,
                "intervalMs": 500,
                "command": "rm -rf /",
            }))
            .is_err()
        );
    }

    #[test]
    fn handle_validation_pins_uuid_shape() {
        assert!(validate_handle("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_handle("").is_err());
        assert!(validate_handle("not-a-uuid").is_err());
        assert!(validate_handle(&"x".repeat(200)).is_err());
    }

    fn stream_event(seq: u64, watch_id: &str, command: &str) -> ProcessWatchStreamEvent {
        ProcessWatchStreamEvent {
            watch_id: watch_id.to_owned(),
            sequence: seq,
            kind: CoreEventKind::Process(ProcessWatchEvent {
                kind: ProcessWatchEventKind::Process,
                seq,
                at_ms: 1_000 + seq,
                uid: 0,
                pid: seq as u32 + 100,
                ppid: Some(1),
                start_ticks: Some(7_777),
                command: command.to_owned(),
                clipped: false,
                origin: EventOrigin::Observed,
                own: false,
                raw: format!("E|N|{}|0|{}|1|7777|0|aa|bb", 1_000 + seq, seq + 100),
            }),
        }
    }

    #[test]
    fn state_enforces_sequence_order_and_counts() {
        let mut state = WatchState::default();
        state.apply_event(stream_event(1, "w", "beacon")).unwrap();
        state.apply_event(stream_event(2, "w", "beacon")).unwrap();
        // A gap in the sequence is a protocol violation, not a guess.
        assert!(matches!(
            state.apply_event(stream_event(5, "w", "beacon")),
            Err(ProcessWatchApiError::ProtocolViolation)
        ));
        assert_eq!(state.observed_count, 2);
        assert_eq!(state.last_sequence, 2);
        // Out-of-order resend is rejected too.
        assert!(state.apply_event(stream_event(2, "w", "dup")).is_err());
    }

    #[test]
    fn a_read_cut_by_its_limit_resumes_at_the_next_row() {
        let mut state = WatchState::default();
        for seq in 1..=7 {
            state.apply_event(stream_event(seq, "w", "beacon")).unwrap();
        }
        let (first, _, horizon) = state.page(0, 3).unwrap();
        assert_eq!(
            first.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(horizon, 3);
        let (second, _, horizon) = state.page(horizon, 3).unwrap();
        assert_eq!(
            second.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [4, 5, 6]
        );
        let (last, _, horizon) = state.page(horizon, 3).unwrap();
        assert_eq!(last.iter().map(|event| event.seq).collect::<Vec<_>>(), [7]);
        assert_eq!(horizon, state.last_sequence);
    }

    #[test]
    fn state_terminal_reasons_map_to_public_states() {
        for (reason, status) in [
            (ProcessWatchEndState::Finished, WatchStatus::Finished),
            (ProcessWatchEndState::Truncated, WatchStatus::Truncated),
            (
                ProcessWatchEndState::Disconnected,
                WatchStatus::Disconnected,
            ),
        ] {
            let mut state = WatchState::default();
            state
                .apply_event(ProcessWatchStreamEvent {
                    watch_id: "w".to_owned(),
                    sequence: 1,
                    kind: CoreEventKind::Stopped { reason },
                })
                .unwrap();
            assert_eq!(state.status, status);
            assert!(state.finished_at.is_some());
        }
        // A stop the operator asked for stays "cancelled" even when the
        // footer later says the deadline ended the loop.
        let mut state = WatchState {
            status: WatchStatus::Cancelled,
            ..WatchState::default()
        };
        state
            .apply_event(ProcessWatchStreamEvent {
                watch_id: "w".to_owned(),
                sequence: 1,
                kind: CoreEventKind::Stopped {
                    reason: ProcessWatchEndState::Finished,
                },
            })
            .unwrap();
        assert_eq!(state.status, WatchStatus::Cancelled);
    }

    #[test]
    fn failed_event_reason_crosses_only_when_core_chose_it() {
        let mut state = WatchState::default();
        state
            .apply_event(ProcessWatchStreamEvent {
                watch_id: "w".to_owned(),
                sequence: 1,
                kind: CoreEventKind::Failed {
                    message: "proc-unreadable".to_owned(),
                },
            })
            .unwrap();
        assert_eq!(state.status, WatchStatus::Failed);
        assert!(state.failure_reason.is_some());
        let mut state = WatchState::default();
        state
            .apply_event(ProcessWatchStreamEvent {
                watch_id: "w".to_owned(),
                sequence: 1,
                kind: CoreEventKind::Failed {
                    message: "target's own stderr text".to_owned(),
                },
            })
            .unwrap();
        assert!(state.failure_reason.is_none());
    }

    #[test]
    fn registry_refuses_a_second_live_watch_on_one_binding() {
        let mut registry = WatchRegistry::default();
        let scope_a = scope("a", 0);
        let (handle, evicted) = registry.reserve(scope_a.clone(), Instant::now()).unwrap();
        assert!(evicted.is_empty());
        // A reserved (still-opening) slot already blocks the binding.
        assert!(matches!(
            registry.reserve(scope_a.clone(), Instant::now()),
            Err(ProcessWatchApiError::WatchAlreadyActive)
        ));
        // A different binding can still open.
        assert!(registry.reserve(scope("b", 0), Instant::now()).is_ok());
        // The reserved slot expires with its TTL.
        let later = Instant::now() + START_RESERVATION_TTL + Duration::from_secs(1);
        assert!(matches!(
            registry.slots.get(&handle),
            Some(WatchSlot::Opening { expires_at, .. }) if *expires_at <= later
        ));
    }

    #[test]
    fn closing_a_binding_removes_its_watches_and_blocks_reopen() {
        let mut registry = WatchRegistry::default();
        let scope_a = scope("a", 0);
        registry.reserve(scope_a.clone(), Instant::now()).unwrap();
        registry.close_binding("binding-a", Instant::now());
        assert!(matches!(
            registry.reserve(scope_a.clone(), Instant::now()),
            Err(ProcessWatchApiError::BindingUnavailable)
        ));
        // An unrelated binding is unaffected.
        assert!(registry.reserve(scope("b", 0), Instant::now()).is_ok());
        // The block lifts once the closed-binding TTL passes.
        let after = Instant::now() + CLOSED_BINDING_TTL + Duration::from_secs(1);
        assert!(registry.ensure_binding_open("binding-a", after).is_ok());
    }
}
