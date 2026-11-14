//! The upload method's side of the process watch API: holding the program
//! the host read from a dialog-chosen file, describing one run before it
//! happens, running it once, and clearing what an earlier run left behind.
//!
//! The page never names a path, a digest or a directory. It holds a tool
//! handle, a plan handle and residue handles; everything they stand for
//! stays here, bound to the binding that asked.

use std::path::Path;

use chrono::Utc;
use lovelyhawk_core::operations::{JournalPhase, OperationJournal, OperationJournalEntry};
use lovelyhawk_core::process_watch_upload::{
    TOOL_MAX_BYTES, ToolFacts, UPLOAD_ARCH_REFUSAL, UPLOAD_DIGEST_REFUSAL,
    UPLOAD_DIRECTORY_REFUSAL, UPLOAD_RUNNING_REFUSAL, UPLOAD_SPACE_REFUSAL, UPLOAD_TOOL_REFUSAL,
    UPLOAD_TOOLS_REFUSAL, UploadPlan, inspect_tool, plan_upload,
};

use super::*;

const TOOL_TTL: Duration = Duration::from_secs(30 * 60);
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const RESIDUE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_TOOLS: usize = 2;
const MAX_PLANS: usize = 4;
const MAX_RESIDUE_HANDLES: usize = 64;
const MAX_RUN_RECORDS: usize = 16;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(180);

struct StoredTool {
    bytes: Arc<Vec<u8>>,
    facts: ToolFacts,
    expires_at: Instant,
}

struct StoredPlan {
    scope: BindingScope,
    plan: UploadPlan,
    bytes: Arc<Vec<u8>>,
    gaps: Vec<String>,
    expires_at: Instant,
}

struct StoredResidue {
    scope: BindingScope,
    directory: String,
    expires_at: Instant,
}

#[derive(Default)]
pub(super) struct UploadRegistry {
    tools: HashMap<String, StoredTool>,
    plans: HashMap<String, StoredPlan>,
    residues: HashMap<String, StoredResidue>,
    /// Journal summary of each run that uploaded something, by marker, so
    /// the cleanup entry names the same operation as the upload entry.
    runs: VecDeque<(String, String)>,
}

impl UploadRegistry {
    fn prune(&mut self, now: Instant) {
        self.tools.retain(|_, tool| tool.expires_at > now);
        self.plans.retain(|_, plan| plan.expires_at > now);
        self.residues.retain(|_, residue| residue.expires_at > now);
    }

    pub(super) fn close_binding(&mut self, binding_handle: &str) {
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
        self.residues
            .retain(|_, residue| residue.scope.binding_handle != binding_handle);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolDto {
    tool_handle: String,
    file_name: String,
    size: u64,
    sha256: String,
    /// The upstream release asset this file is, when its digest is known.
    recognized: Option<&'static str>,
    arch: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProcessWatchUploadInput {
    tool_handle: String,
    duration_seconds: u32,
    file_events: bool,
}

impl fmt::Debug for ProcessWatchUploadInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessWatchUploadInput")
            .field("duration_seconds", &self.duration_seconds)
            .field("file_events", &self.file_events)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadPlanDto {
    plan_handle: String,
    directory: String,
    size: u64,
    sha256: String,
    recognized: Option<&'static str>,
    account: String,
    is_root: bool,
    machine: String,
    duration_seconds: u32,
    file_events: bool,
    file_event_dirs: Vec<String>,
    gaps: Vec<String>,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResidueDto {
    residue_handle: String,
    directory: String,
    size: u64,
    sha256: String,
    recognized: Option<&'static str>,
    running: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResidueCleanedDto {
    cleanup: &'static str,
}

fn refusal(error: &CoreError) -> ProcessWatchApiError {
    let CoreError::Validation { subject, .. } = error else {
        return ProcessWatchApiError::Core;
    };
    match *subject {
        UPLOAD_ARCH_REFUSAL => ProcessWatchApiError::UploadRefused("process-watch-upload-arch"),
        UPLOAD_TOOL_REFUSAL => {
            ProcessWatchApiError::UploadRefused("process-watch-upload-tool-mismatch")
        }
        UPLOAD_DIRECTORY_REFUSAL => {
            ProcessWatchApiError::UploadRefused("process-watch-upload-no-directory")
        }
        UPLOAD_SPACE_REFUSAL => {
            ProcessWatchApiError::UploadRefused("process-watch-upload-no-space")
        }
        UPLOAD_TOOLS_REFUSAL => {
            ProcessWatchApiError::UploadRefused("process-watch-upload-missing-tools")
        }
        UPLOAD_RUNNING_REFUSAL => ProcessWatchApiError::WatchAlreadyActive,
        UPLOAD_DIGEST_REFUSAL => ProcessWatchApiError::UploadMismatch,
        _ => ProcessWatchApiError::Core,
    }
}

/// What an upload run cannot promise that the poll's fixed gap also could
/// not: pspy scans on file-system activity, so it misses less, not nothing.
fn upload_gaps(probe_gaps: &[ProcessWatchGap], plan: &UploadPlan) -> Vec<String> {
    let mut gaps: Vec<String> = probe_gaps
        .iter()
        .filter(|gap| {
            !matches!(
                gap,
                ProcessWatchGap::PollingMissesShortLived | ProcessWatchGap::CoarseInterval
            )
        })
        .map(|gap| gap.key().to_owned())
        .collect();
    gaps.push("tool-may-miss-short-lived".to_owned());
    if plan.low_inotify {
        gaps.push("inotify-low".to_owned());
    }
    if plan.file_events {
        gaps.push("file-events-limited".to_owned());
    }
    gaps
}

impl ProcessWatchApi {
    fn lock_uploads(&self) -> Result<MutexGuard<'_, UploadRegistry>, ProcessWatchApiError> {
        self.uploads
            .lock()
            .map_err(|_| ProcessWatchApiError::RegistryUnavailable)
    }

    /// Host-only: reads the dialog-chosen file and keeps its bytes behind a
    /// handle. The path goes no further than this call.
    pub(crate) fn load_tool(&self, local_path: &Path) -> Result<ToolDto, ProcessWatchApiError> {
        let metadata =
            std::fs::metadata(local_path).map_err(|_| ProcessWatchApiError::ToolRejected)?;
        if !metadata.is_file() || metadata.len() > TOOL_MAX_BYTES as u64 {
            return Err(ProcessWatchApiError::ToolRejected);
        }
        let bytes = std::fs::read(local_path).map_err(|_| ProcessWatchApiError::ToolRejected)?;
        let facts = inspect_tool(&bytes).map_err(|_| ProcessWatchApiError::ToolRejected)?;
        let file_name = local_path
            .file_name()
            .map(|name| bounded_single_line(&name.to_string_lossy(), 128).0)
            .unwrap_or_default();
        let tool_handle = Uuid::new_v4().to_string();
        let dto = ToolDto {
            tool_handle: tool_handle.clone(),
            file_name,
            size: facts.size,
            sha256: facts.sha256.clone(),
            recognized: facts.recognized,
            arch: facts.arch.key(),
        };
        let now = Instant::now();
        let mut uploads = self.lock_uploads()?;
        uploads.prune(now);
        while uploads.tools.len() >= MAX_TOOLS {
            let Some(oldest) = uploads
                .tools
                .iter()
                .min_by_key(|(_, tool)| tool.expires_at)
                .map(|(handle, _)| handle.clone())
            else {
                break;
            };
            uploads.tools.remove(&oldest);
        }
        uploads.tools.insert(
            tool_handle,
            StoredTool {
                bytes: Arc::new(bytes),
                facts,
                expires_at: now + TOOL_TTL,
            },
        );
        Ok(dto)
    }

    /// Looks at the target and describes the one run that would follow:
    /// where the file lands, as whom it runs, for how long, and what it
    /// cannot see. Nothing is written.
    pub(crate) async fn upload_plan(
        &self,
        binding_handle: &str,
        input: ProcessWatchUploadInput,
    ) -> Result<UploadPlanDto, ProcessWatchApiError> {
        validate_handle(&input.tool_handle)?;
        if !(60..=1800).contains(&input.duration_seconds) {
            return Err(ProcessWatchApiError::InvalidInput);
        }
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let (bytes, facts) = {
            let mut uploads = self.lock_uploads()?;
            uploads.prune(Instant::now());
            let tool = uploads
                .tools
                .get(&input.tool_handle)
                .ok_or(ProcessWatchApiError::PlanUnavailable)?;
            (Arc::clone(&tool.bytes), tool.facts.clone())
        };
        let service = self.services.process_watch();
        let probe = service.probe(&binding).await?;
        if !probe.proc_readable {
            return Err(ProcessWatchApiError::ProcUnreadable);
        }
        let upload_probe = service.upload_probe(&binding).await?;
        self.ensure_binding(&scope, &binding)?;
        let plan = plan_upload(
            &upload_probe,
            &facts,
            input.duration_seconds,
            input.file_events,
        )
        .map_err(|error| refusal(&error))?;
        let gaps = upload_gaps(&probe.gaps, &plan);
        let plan_handle = Uuid::new_v4().to_string();
        let dto = UploadPlanDto {
            plan_handle: plan_handle.clone(),
            directory: plan.directory.clone(),
            size: plan.tool.size,
            sha256: plan.tool.sha256.clone(),
            recognized: plan.tool.recognized,
            account: bounded_single_line(&plan.account, 128).0,
            is_root: plan.is_root,
            machine: bounded_single_line(&plan.machine, 32).0,
            duration_seconds: plan.duration_secs,
            file_events: plan.file_events,
            file_event_dirs: plan.file_event_dirs.clone(),
            gaps: gaps.clone(),
            expires_in_seconds: PLAN_TTL.as_secs(),
        };
        let now = Instant::now();
        let mut uploads = self.lock_uploads()?;
        uploads.prune(now);
        // A new plan for a binding replaces its old one: one confirmation
        // dialog, one plan.
        uploads
            .plans
            .retain(|_, stored| stored.scope.binding_handle != scope.binding_handle);
        if uploads.plans.len() >= MAX_PLANS {
            return Err(ProcessWatchApiError::RegistryCapacity);
        }
        uploads.plans.insert(
            plan_handle,
            StoredPlan {
                scope,
                plan,
                bytes,
                gaps,
                expires_at: now + PLAN_TTL,
            },
        );
        Ok(dto)
    }

    /// Carries out a confirmed plan exactly once: upload, verify the digest
    /// on the target, start the bounded run.
    pub(crate) async fn upload_start(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<ProcessWatchStartedDto, ProcessWatchApiError> {
        validate_handle(plan_handle)?;
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let stored = {
            let mut uploads = self.lock_uploads()?;
            uploads.prune(Instant::now());
            uploads
                .plans
                .remove(plan_handle)
                .ok_or(ProcessWatchApiError::PlanUnavailable)?
        };
        if stored.scope != scope {
            return Err(ProcessWatchApiError::PlanUnavailable);
        }
        let plan = stored.plan;
        let request = ProcessWatchRequest {
            method: ProcessWatchMethod::Pspy,
            duration_secs: plan.duration_secs,
            interval_ms: 1000,
        };
        let (watch_handle, evicted) = self
            .lock_watches()?
            .reserve(scope.clone(), Instant::now())?;
        close_live_watches(evicted).await;
        let service = self.services.process_watch();
        let uploaded = tokio::time::timeout(
            UPLOAD_TIMEOUT,
            service.upload_tool(&binding, &plan, &stored.bytes),
        )
        .await;
        match uploaded {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.remove_slot(&watch_handle);
                return Err(refusal(&error));
            }
            Err(_) => {
                self.remove_slot(&watch_handle);
                // The write may have got part-way: say so by trying to
                // clear the directory the plan named.
                let _ = service
                    .clean_landing_directory(&binding, &plan.directory)
                    .await;
                return Err(ProcessWatchApiError::TimedOut);
            }
        }
        let summary = format!(
            "进程活动监视：向 {} 写入 pspy（{} 字节，SHA-256 {}{}），以 {} 运行 {} 秒{}，结束后删除。",
            plan.directory,
            plan.tool.size,
            plan.tool.sha256,
            plan.tool
                .recognized
                .map(|name| format!("，{name}"))
                .unwrap_or_else(|| "，未识别的文件".to_owned()),
            plan.account,
            plan.duration_secs,
            if plan.file_events {
                "，同时记录文件访问"
            } else {
                ""
            },
        );
        self.journal(
            binding.target(),
            &plan.marker,
            &summary,
            JournalPhase::Executed,
            "已上传并在目标上核对摘要一致。".to_owned(),
        );
        if let Ok(mut uploads) = self.lock_uploads() {
            if uploads.runs.len() >= MAX_RUN_RECORDS {
                uploads.runs.pop_front();
            }
            uploads.runs.push_back((plan.marker.clone(), summary));
        }
        let started =
            tokio::time::timeout(START_TIMEOUT, service.start_uploaded(&binding, &plan)).await;
        let live = match started {
            Ok(Ok(live)) => Arc::new(live),
            Ok(Err(_)) => {
                self.remove_slot(&watch_handle);
                return Err(ProcessWatchApiError::Core);
            }
            Err(_) => {
                self.remove_slot(&watch_handle);
                let _ = service
                    .clean_landing_directory(&binding, &plan.directory)
                    .await;
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
            stored.gaps,
        )
        .await
    }

    /// Landing directories earlier runs left on this target, found by
    /// looking at the target rather than trusting a local record.
    pub(crate) async fn residues(
        &self,
        binding_handle: &str,
    ) -> Result<Vec<ResidueDto>, ProcessWatchApiError> {
        let (binding, scope) = self.watch_binding(binding_handle)?;
        self.reap_stale(Some(&scope)).await;
        let _permit = self.acquire_operation(&scope)?;
        let probe = self.services.process_watch().upload_probe(&binding).await?;
        self.ensure_binding(&scope, &binding)?;
        let now = Instant::now();
        let mut uploads = self.lock_uploads()?;
        uploads.prune(now);
        uploads
            .residues
            .retain(|_, stored| stored.scope.binding_handle != scope.binding_handle);
        let mut found = Vec::new();
        for residue in probe.residues {
            if uploads.residues.len() >= MAX_RESIDUE_HANDLES {
                break;
            }
            let residue_handle = Uuid::new_v4().to_string();
            uploads.residues.insert(
                residue_handle.clone(),
                StoredResidue {
                    scope: scope.clone(),
                    directory: residue.directory.clone(),
                    expires_at: now + RESIDUE_TTL,
                },
            );
            let recognized = inspect_known(&residue.sha256);
            found.push(ResidueDto {
                residue_handle,
                directory: residue.directory,
                size: residue.size,
                sha256: residue.sha256,
                recognized,
                running: residue.running,
            });
        }
        Ok(found)
    }

    pub(crate) async fn clean_residue(
        &self,
        binding_handle: &str,
        residue_handle: &str,
    ) -> Result<ResidueCleanedDto, ProcessWatchApiError> {
        validate_handle(residue_handle)?;
        let (binding, scope) = self.watch_binding(binding_handle)?;
        let _permit = self.acquire_operation(&scope)?;
        let stored = {
            let mut uploads = self.lock_uploads()?;
            uploads.prune(Instant::now());
            uploads
                .residues
                .remove(residue_handle)
                .ok_or(ProcessWatchApiError::PlanUnavailable)?
        };
        if stored.scope != scope {
            return Err(ProcessWatchApiError::PlanUnavailable);
        }
        // A directory a live watch on this same connection is running from
        // is that watch's to clean. A watch whose connection is gone cannot
        // clean anything, so its directory is exactly what this is for.
        let in_use = self.lock_watches()?.slots.values().any(|slot| match slot {
            WatchSlot::Active(active) => {
                active.scope == scope
                    && active
                        .lock_state()
                        .map(|state| state.status == WatchStatus::Running)
                        .unwrap_or(true)
                    && stored
                        .directory
                        .ends_with(&format!("-{}", active.live.marker()))
            }
            WatchSlot::Opening { .. } => false,
        });
        if in_use {
            return Err(ProcessWatchApiError::WatchAlreadyActive);
        }
        let outcome = self
            .services
            .process_watch()
            .clean_landing_directory(&binding, &stored.directory)
            .await;
        let key = cleanup_key(Some(&outcome));
        self.journal(
            binding.target(),
            stored.directory.rsplit('-').next().unwrap_or("residue"),
            &format!(
                "进程活动监视：清理上次监视留在 {} 的文件。",
                stored.directory
            ),
            if key == "clean" {
                JournalPhase::VerificationPassed
            } else {
                JournalPhase::VerificationFailed
            },
            cleanup_detail(Some(&outcome)),
        );
        Ok(ResidueCleanedDto { cleanup: key })
    }

    pub(super) fn journal_cleanup(&self, active: &ActiveWatch, outcome: Option<&CleanupOutcome>) {
        let marker = active.live.marker().to_owned();
        let summary = self
            .lock_uploads()
            .ok()
            .and_then(|uploads| {
                uploads
                    .runs
                    .iter()
                    .find(|(known, _)| *known == marker)
                    .map(|(_, summary)| summary.clone())
            })
            .unwrap_or_else(|| "进程活动监视：上传运行结束后的清理。".to_owned());
        self.journal(
            active.binding.target(),
            &marker,
            &summary,
            if cleanup_key(outcome) == "clean" {
                JournalPhase::VerificationPassed
            } else {
                JournalPhase::VerificationFailed
            },
            cleanup_detail(outcome),
        );
    }

    fn journal(
        &self,
        target: &TargetGuard,
        marker: &str,
        summary: &str,
        phase: JournalPhase,
        detail: String,
    ) {
        let entry = OperationJournalEntry {
            entry_id: Uuid::new_v4().to_string(),
            operation_id: format!("process-watch-{marker}"),
            target: target.clone(),
            summary: summary.to_owned(),
            dangerous: true,
            source: "process-watch".to_owned(),
            restore_description: None,
            phase,
            detail,
            occurred_at: Utc::now(),
        };
        if let Err(error) = self.services.operation_journal().append(entry) {
            tracing::warn!(error = %error, "process watch journal entry could not be saved");
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExistingSourceDto {
    source: &'static str,
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountingGroupDto {
    command: String,
    count: usize,
    uids: Vec<u32>,
    first_at_ms: u64,
    last_at_ms: u64,
    cadence: &'static str,
    period_ms: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountingDto {
    minutes: u32,
    records: usize,
    unparsed: usize,
    truncated: bool,
    groups: Vec<AccountingGroupDto>,
}

impl ProcessWatchApi {
    /// Records of past process activity the target already keeps.
    pub(crate) async fn existing_sources(
        &self,
        binding_handle: &str,
    ) -> Result<Vec<ExistingSourceDto>, ProcessWatchApiError> {
        let (binding, scope) = self.watch_binding(binding_handle)?;
        let _permit = self.acquire_operation(&scope)?;
        let sources = self
            .services
            .process_watch()
            .existing_sources(&binding)
            .await?;
        self.ensure_binding(&scope, &binding)?;
        Ok(sources
            .iter()
            .map(|source| ExistingSourceDto {
                source: source.kind.key(),
                state: source.state.key(),
            })
            .collect())
    }

    /// What process accounting recorded in the last `minutes`, grouped the
    /// way a watch's repeats are. Program names only: accounting keeps no
    /// arguments.
    pub(crate) async fn read_accounting(
        &self,
        binding_handle: &str,
        minutes: u32,
    ) -> Result<AccountingDto, ProcessWatchApiError> {
        if !(1..=120).contains(&minutes) {
            return Err(ProcessWatchApiError::InvalidInput);
        }
        let (binding, scope) = self.watch_binding(binding_handle)?;
        let _permit = self.acquire_operation(&scope)?;
        let records = self
            .services
            .process_watch()
            .read_accounting(&binding, minutes)
            .await
            .map_err(|error| match &error {
                CoreError::Validation { subject, .. }
                    if *subject
                        == lovelyhawk_core::process_watch_sources::ACCOUNTING_UNAVAILABLE =>
                {
                    ProcessWatchApiError::UploadRefused("process-watch-accounting-unavailable")
                }
                _ => ProcessWatchApiError::from(error),
            })?;
        self.ensure_binding(&scope, &binding)?;
        let groups = repeat_groups(&records.events);
        // Accounting stamps whole seconds: a beat shorter than two of them
        // cannot be told from a burst.
        let period = |group: &lovelyhawk_core::process_watch::RepeatGroup| match group.cadence {
            Cadence::Periodic { period_ms } if period_ms >= 2_000 => Some(period_ms),
            _ => None,
        };
        Ok(AccountingDto {
            minutes,
            records: records.events.len(),
            unparsed: records.unparsed,
            truncated: records.truncated,
            groups: groups
                .iter()
                .take(MAX_SUMMARY_GROUPS)
                .map(|group| AccountingGroupDto {
                    command: bounded_single_line(&group.sample, 256).0,
                    count: group.count,
                    uids: group.uids.clone(),
                    first_at_ms: group.first_at_ms,
                    last_at_ms: group.last_at_ms,
                    cadence: match (&group.cadence, period(group)) {
                        (Cadence::Single, _) => "single",
                        (_, Some(_)) => "periodic",
                        _ => "repeated",
                    },
                    period_ms: period(group),
                })
                .collect(),
        })
    }
}

fn inspect_known(sha256: &str) -> Option<&'static str> {
    lovelyhawk_core::process_watch_upload::known_tool(sha256)
}

fn cleanup_detail(outcome: Option<&CleanupOutcome>) -> String {
    match outcome {
        Some(CleanupOutcome::Clean) => "已停止并删除，回读确认进程不在、目录不存在。".to_owned(),
        Some(CleanupOutcome::Residue { directory, running }) => {
            format!("清理后仍有残留：{directory}（仍在运行的进程 {running} 个）。")
        }
        Some(CleanupOutcome::Unverified { directory }) => {
            format!("未能连到目标确认清理结果，{directory} 可能仍在。")
        }
        None => "未能在时限内确认清理结果。".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::process_watch_upload::ToolArch;

    use super::*;

    fn plan(file_events: bool, low_inotify: bool) -> UploadPlan {
        UploadPlan {
            marker: "0123456789abcdef".to_owned(),
            directory: "/tmp/.lovelyhawk-watch-0123456789abcdef".to_owned(),
            tool_path: "/tmp/.lovelyhawk-watch-0123456789abcdef/pspy".to_owned(),
            tool: ToolFacts {
                sha256: "a".repeat(64),
                size: 1,
                arch: ToolArch::X86_64,
                recognized: None,
            },
            duration_secs: 120,
            file_events,
            file_event_dirs: Vec::new(),
            account: "root".to_owned(),
            is_root: true,
            machine: "x86_64".to_owned(),
            low_inotify,
        }
    }

    #[test]
    fn each_upload_refusal_has_its_own_code() {
        let code = |subject: &'static str| match refusal(&CoreError::Validation {
            subject,
            message: "m".to_owned(),
        }) {
            ProcessWatchApiError::UploadRefused(code) => code,
            ProcessWatchApiError::WatchAlreadyActive => "running",
            ProcessWatchApiError::UploadMismatch => "mismatch",
            _ => "core",
        };
        assert_eq!(code(UPLOAD_ARCH_REFUSAL), "process-watch-upload-arch");
        assert_eq!(
            code(UPLOAD_TOOL_REFUSAL),
            "process-watch-upload-tool-mismatch"
        );
        assert_eq!(
            code(UPLOAD_DIRECTORY_REFUSAL),
            "process-watch-upload-no-directory"
        );
        assert_eq!(code(UPLOAD_SPACE_REFUSAL), "process-watch-upload-no-space");
        assert_eq!(
            code(UPLOAD_TOOLS_REFUSAL),
            "process-watch-upload-missing-tools"
        );
        assert_eq!(code(UPLOAD_RUNNING_REFUSAL), "running");
        assert_eq!(code(UPLOAD_DIGEST_REFUSAL), "mismatch");
        assert_eq!(code("something else"), "core");
    }

    #[test]
    fn an_upload_run_swaps_the_polling_gap_for_its_own() {
        let probe = [
            ProcessWatchGap::Container,
            ProcessWatchGap::CoarseInterval,
            ProcessWatchGap::PollingMissesShortLived,
        ];
        assert_eq!(
            upload_gaps(&probe, &plan(false, false)),
            vec!["container", "tool-may-miss-short-lived"]
        );
        assert_eq!(
            upload_gaps(&probe, &plan(true, true)),
            vec![
                "container",
                "tool-may-miss-short-lived",
                "inotify-low",
                "file-events-limited"
            ]
        );
    }

    #[test]
    fn a_cleanup_that_could_not_be_checked_is_never_called_clean() {
        assert_eq!(cleanup_key(Some(&CleanupOutcome::Clean)), "clean");
        assert_eq!(
            cleanup_key(Some(&CleanupOutcome::Residue {
                directory: "/tmp/x".to_owned(),
                running: 0
            })),
            "residue"
        );
        assert_eq!(
            cleanup_key(Some(&CleanupOutcome::Unverified {
                directory: "/tmp/x".to_owned()
            })),
            "unverified"
        );
        assert_eq!(cleanup_key(None), "unverified");
    }

    #[test]
    fn closing_a_binding_drops_its_plans_and_residue_handles() {
        let scope_of = |name: &str| BindingScope {
            binding_handle: format!("binding-{name}"),
            session_id: "session".to_owned(),
            connection_id: name.to_owned(),
            target: TargetGuard {
                identity: lovelyhawk_core::target::TargetIdentity::new(name).unwrap(),
                generation: 0,
            },
        };
        let later = Instant::now() + Duration::from_secs(60);
        let mut registry = UploadRegistry::default();
        for name in ["a", "b"] {
            registry.plans.insert(
                format!("plan-{name}"),
                StoredPlan {
                    scope: scope_of(name),
                    plan: plan(false, false),
                    bytes: Arc::new(Vec::new()),
                    gaps: Vec::new(),
                    expires_at: later,
                },
            );
            registry.residues.insert(
                format!("residue-{name}"),
                StoredResidue {
                    scope: scope_of(name),
                    directory: "/tmp/.lovelyhawk-watch-0123456789abcdef".to_owned(),
                    expires_at: later,
                },
            );
        }
        registry.close_binding("binding-a");
        assert!(registry.plans.contains_key("plan-b") && registry.plans.len() == 1);
        assert!(registry.residues.contains_key("residue-b") && registry.residues.len() == 1);
        registry.prune(later + Duration::from_secs(1));
        assert!(registry.plans.is_empty() && registry.residues.is_empty());
    }
}
