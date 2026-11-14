//! Acting on a file a read-only command run just named.
//!
//! The renderer sees an output line and asks for the path on it. It never
//! sends a path: the sidecar extracted every path from the output it produced
//! itself, kept them under opaque handles, and will only act on one of those.
//! A forged handle names nothing, so the worst a compromised renderer can do
//! is act on a file the host already printed to the operator.
//!
//! Each action goes through the same plan, confirm, execute and verify
//! pipeline the file browser uses, so it is described before it runs, runs at
//! most once, and is put back when verification fails.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError, CoreResult,
    capability_strip::{
        CAPABILITY_EMPTY_REFUSAL, CAPABILITY_KIND_REFUSAL, CAPABILITY_PRIVILEGE_REFUSAL,
        CAPABILITY_TOOLS_REFUSAL, CapabilityStripOperation,
    },
    command_paths::paths_in_output,
    command_restore::{
        CommandRestoreOperation, RESTORE_AMBIGUOUS_REFUSAL, RESTORE_EMPTY_REFUSAL,
        RESTORE_KIND_REFUSAL, RESTORE_LOCATION_REFUSAL, RESTORE_PRIVILEGE_REFUSAL,
        RESTORE_TOOLS_REFUSAL,
    },
    line_delete::{
        LINE_DELETE_KIND_REFUSAL, LINE_DELETE_LOCATION_REFUSAL, LINE_DELETE_RANGE_REFUSAL,
        LINE_DELETE_SIZE_REFUSAL, LINE_DELETE_STALE_REFUSAL, LineDeleteOperation, PreviewLine,
        line_delete_path_allowed, preview_lines,
    },
    operations::{DangerousConfirmation, OperationPlan, OperationState, VerificationResult},
    sftp::{
        BoundSftpSession, MAX_EDIT_BYTES, RemotePath, SftpFileKind, SftpMutation,
        SftpPlannedOperation, content_sha256,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
    xinetd_service::{
        XINETD_IGNORED_REFUSAL, XINETD_KIND_REFUSAL, XINETD_LOCATION_REFUSAL,
        XINETD_PRIVILEGE_REFUSAL, XINETD_TOOLS_REFUSAL, XinetdDisableOperation, XinetdPathCheck,
        xinetd_service_path_check,
    },
};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
/// Paths retained across all pages and bindings. A workbench run offers at
/// most 500; keep earlier group results usable without an unbounded cache.
const MAX_STORED_PATHS: usize = 2_000;
const MAX_PLANS: usize = 16;
/// One batch never previews more files than the operator can still read.
const MAX_BATCH_ITEMS: usize = 50;
/// A binding drives one batch dialog at a time; older ones are dropped.
const MAX_BATCHES: usize = 8;
const MAX_PATH_DISPLAY_BYTES: usize = 1_024;
const MAX_PLAN_TEXT_BYTES: usize = 512;
/// Long enough to read a page of results and decide, short enough that a stale
/// window cannot act on a host that has moved on.
const PATH_TTL: Duration = Duration::from_secs(15 * 60);
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
const BIND_DEADLINE: Duration = Duration::from_secs(15);
const INSPECT_DEADLINE: Duration = Duration::from_secs(20);
const EXECUTE_DEADLINE: Duration = Duration::from_secs(60);
/// How long a finished action can still be undone from its receipt.
const UNDO_TTL: Duration = Duration::from_secs(10 * 60);

/// The bits that let a file run, cleared together so no owner keeps the
/// ability to run it and nothing is left to elevate with. The set-user-ID and
/// set-group-ID bits go with them: a file left at `4644` reads as still armed
/// and comes back with a single `chmod +x`. The sticky bit is not touched,
/// because on a directory it means something else entirely.
const EXECUTE_BITS: u32 = 0o6111;
/// The permission bits `chmod` may set, so a stored mode never carries file
/// type bits into a change.
const PERMISSION_BITS: u32 = 0o7777;

#[derive(Clone)]
pub(crate) struct EmergencyPathApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<PathRegistry>>,
}

/// What the operator may do to a file the output named.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EmergencyPathAction {
    /// Clear the execute bits. The file stops running and stays readable, so
    /// it can still be examined afterwards.
    Disarm,
    /// Move the file into the recoverable backup namespace.
    Quarantine,
    /// Remove the file's Linux capability set (the `security.capability`
    /// xattr) via `setcap -r`; the saved set can be written back once.
    RemoveCapabilities,
    /// Write a backup residue found beside a system command back over the
    /// command, keeping the replaced bytes for one undo.
    RestoreResidue,
    /// Remove a contiguous range of lines from a managed startup or cron
    /// file. Needs the preview-and-range flow of `path.lines`/`path.plan-lines`;
    /// `plan` and `plan_batch` refuse it.
    DeleteLines,
    /// Isolate a service file under /etc/xinetd.d and reload the daemon.
    /// Emergency semantics: once the file is moved it stays isolated even
    /// when the port check fails — putting it back would re-arm the service.
    DisableXinetdService,
}

impl EmergencyPathAction {
    fn label(self) -> &'static str {
        match self {
            Self::Disarm => "disarm",
            Self::Quarantine => "quarantine",
            Self::RemoveCapabilities => "remove-capabilities",
            Self::RestoreResidue => "restore-residue",
            Self::DeleteLines => "delete-lines",
            Self::DisableXinetdService => "disable-xinetd-service",
        }
    }
}

/// A path one run's own output named, handed back as a capability.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathDto {
    pub(crate) path_handle: String,
    /// Which displayed output line this path was read from.
    pub(crate) line: u32,
    /// The path as the host printed it, so the menu can name what it will act
    /// on. The renderer displays it; it cannot act with it.
    pub(crate) path: String,
    /// Whether the path sits in the line-delete allow-list, so the menu only
    /// offers the entry where it can apply.
    pub(crate) line_editable: bool,
    /// Whether the path is a file xinetd would load, so the menu can offer
    /// the service-disable action where it applies.
    pub(crate) xinetd_service: bool,
}

/// What the host says about the file right now.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathDetailDto {
    pub(crate) path_handle: String,
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) size: String,
    pub(crate) mode: Option<String>,
    pub(crate) owner_id: Option<u32>,
    pub(crate) group_id: Option<u32>,
    pub(crate) modified_at: Option<String>,
    /// Whether anyone can currently run it, which is what disarming changes.
    pub(crate) executable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) path_handle: String,
    pub(crate) path: String,
    pub(crate) action: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) state: String,
    pub(crate) expires_in_seconds: u32,
    /// What a restore plan found beside the command; absent for other
    /// actions. All text is bounded at the boundary like the summary.
    pub(crate) residue: Option<ResiduePlanDto>,
}

/// One display-safe line of a file preview or a removal list.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathLineDto {
    pub(crate) number: u32,
    pub(crate) text: String,
    pub(crate) clipped: bool,
}

impl From<&PreviewLine> for EmergencyPathLineDto {
    fn from(line: &PreviewLine) -> Self {
        Self {
            number: line.number,
            text: bounded_text(&line.text),
            clipped: line.clipped,
        }
    }
}

/// The numbered, sanitized lines of a file the operator may delete from. The
/// preview handle binds the digest of exactly these bytes to whatever plan is
/// made from them; it never crosses the boundary.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathLinesPreviewDto {
    pub(crate) preview_handle: String,
    pub(crate) path_handle: String,
    pub(crate) path: String,
    pub(crate) total_lines: u32,
    pub(crate) lines: Vec<EmergencyPathLineDto>,
    /// The file has more lines than `lines` carries.
    pub(crate) truncated: bool,
}

/// A line-deletion plan: the same plan DTO `plan` returns, plus the exact
/// lines the delete would take out so the confirmation lists all of them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathLinesPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) path_handle: String,
    pub(crate) path: String,
    pub(crate) action: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) state: String,
    pub(crate) expires_in_seconds: u32,
    pub(crate) residue: Option<ResiduePlanDto>,
    pub(crate) removed_lines: Vec<EmergencyPathLineDto>,
}

/// One regular file the restore probe saw beside the command.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResidueCandidateDto {
    pub(crate) path: String,
    /// Enough of the digest to compare with a hash the operator ran by hand.
    pub(crate) sha256: String,
    pub(crate) size: String,
    /// `backup` for an explicit backup spelling, `variant` for a known
    /// `name+d` planted copy.
    pub(crate) kind: String,
}

/// The residue a restore plan would write, and everything else it saw.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResiduePlanDto {
    pub(crate) source: ResidueCandidateDto,
    /// The owning package name, when a package manager could name one.
    pub(crate) package: Option<String>,
    pub(crate) candidates: Vec<ResidueCandidateDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathReceiptDto {
    pub(crate) plan_handle: String,
    pub(crate) path: String,
    pub(crate) action: String,
    pub(crate) passed: bool,
    pub(crate) detail: String,
    pub(crate) restored: bool,
    /// Refused by a check that runs before anything is written.
    pub(crate) untouched: bool,
    /// Done, verified and reversible: the receipt may offer to undo it.
    pub(crate) undoable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathUndoDto {
    pub(crate) plan_handle: String,
    pub(crate) path: String,
    pub(crate) undone: bool,
    pub(crate) detail: String,
}

/// One row of a batch preview: the file as it stood, and either what would
/// happen to it or the refusal that stands instead.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathBatchItemDto {
    path_handle: String,
    /// The stored path, or nothing where the handle already went stale.
    path: String,
    kind: String,
    size: String,
    mode: Option<String>,
    executable: bool,
    plan_handle: Option<String>,
    summary: Option<String>,
    restore_description: Option<String>,
    refusal: Option<String>,
}

/// The whole batch as one preview, and the state the shared confirmation is in.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathBatchPlanDto {
    batch_handle: String,
    action: String,
    items: Vec<EmergencyPathBatchItemDto>,
    planned: u32,
    refused: u32,
    /// `planned` while it waits for approval, `confirmed` while it steps.
    state: String,
    expires_in_seconds: u32,
}

/// One finished item's own receipt plus where the batch stands after it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyPathBatchStepDto {
    batch_handle: String,
    receipt: Option<EmergencyPathReceiptDto>,
    remaining: u32,
    refused: u32,
    finished: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PathScope {
    pub(crate) binding_handle: String,
    pub(crate) session_id: String,
    pub(crate) connection_id: String,
    pub(crate) target: TargetGuard,
}

/// Which page offered a path. Workbench groups display several runs together;
/// integrity and log analysis each display only their latest collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathOfferSource {
    /// Lines of a command-workbench run.
    Workbench,
    /// Findings of a file-integrity comparison.
    Integrity,
    /// Log files a log investigation listed as sources.
    LogAnalysis,
    /// Fetched members a local-scan engine named in its output.
    LocalScan,
}

struct StoredPath {
    scope: PathScope,
    source: PathOfferSource,
    path: RemotePath,
    expires_at: Instant,
}

/// What a `path.lines` preview read: the digest the plan must bind, kept on
/// this side so a file that moved between preview and planning is refused.
struct StoredPreview {
    scope: PathScope,
    preview_handle: String,
    path_handle: String,
    path: RemotePath,
    sha256: String,
    expires_at: Instant,
}

struct PlannedPath {
    plan_handle: String,
    path_handle: String,
    path: String,
    action: EmergencyPathAction,
    scope: PathScope,
    operation: PathOperation,
    expires_at: Instant,
}

/// One member of a batch: the file as it looked at preview time, and either
/// the immutable plan waiting for one shared confirmation or the reason the
/// plan refused to exist.
struct StoredBatchItem {
    path_handle: String,
    path: String,
    plan_handle: String,
    kind: String,
    size: String,
    mode: Option<String>,
    executable: bool,
    operation: Option<PathOperation>,
    /// Why no plan was made — a stable key the page translates.
    refusal: Option<&'static str>,
    finished: bool,
}

/// A confirmed-once set of per-path plans the operator steps through one at
/// a time. Each item keeps its own plan handle, so a finished item's undo is
/// the same undo a single action would leave behind.
struct StoredBatch {
    batch_handle: String,
    scope: PathScope,
    action: EmergencyPathAction,
    items: Vec<StoredBatchItem>,
    confirmed: bool,
    expires_at: Instant,
}

impl StoredBatchItem {
    /// A row that never got a plan. Whatever was already known about the
    /// file still shows — a stale handle shows nothing but the refusal.
    fn refused(path_handle: &str, path: String, refusal: &'static str) -> Self {
        Self {
            path_handle: path_handle.to_owned(),
            path,
            plan_handle: String::new(),
            kind: String::new(),
            size: String::new(),
            mode: None,
            executable: false,
            operation: None,
            refusal: Some(refusal),
            finished: true,
        }
    }

    /// Fills in what a preview stat learned, so a refused row still names
    /// the file it was refused for.
    fn with_metadata(mut self, metadata: &lovelyhawk_core::sftp::SftpMetadata) -> Self {
        let permissions = metadata.permissions.map(|mode| mode & PERMISSION_BITS);
        self.kind = match metadata.kind {
            SftpFileKind::File => "file",
            SftpFileKind::Directory => "directory",
            SftpFileKind::Symlink => "symlink",
            SftpFileKind::Other => "other",
        }
        .to_owned();
        self.size = metadata.size.to_string();
        self.mode = permissions.map(|mode| format!("{mode:04o}"));
        self.executable = permissions.is_some_and(|mode| mode & 0o111 != 0);
        self
    }

    /// The row's immutable plan, minted with its own handle so its receipt
    /// and undo name exactly what a single action's would.
    fn planned(mut self, operation: SftpPlannedOperation) -> Self {
        self.plan_handle = Uuid::new_v4().to_string();
        self.operation = Some(PathOperation::Sftp(operation));
        self.refusal = None;
        self.finished = false;
        self
    }
}

impl StoredBatch {
    /// Items still waiting to run — refused ones finished before it began.
    fn pending_count(&self) -> u32 {
        self.items.iter().filter(|item| !item.finished).count() as u32
    }

    fn refused_count(&self) -> u32 {
        self.items
            .iter()
            .filter(|item| item.refusal.is_some())
            .count() as u32
    }
}

/// The one lifecycle a stored plan goes through, whichever transport carries
/// the change: SFTP mutations, SSH-carried xattr edits and SSH-carried
/// command restores share the plan/confirm/execute/verify/restore/undo
/// surface.
#[derive(Debug)]
enum PathOperation {
    Sftp(SftpPlannedOperation),
    CapabilityStrip(CapabilityStripOperation),
    CommandRestore(CommandRestoreOperation),
    LineDelete(Box<LineDeleteOperation>),
    XinetdDisable(Box<XinetdDisableOperation>),
}

impl PathOperation {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::Sftp(operation) => operation.definition(),
            Self::CapabilityStrip(operation) => operation.definition(),
            Self::CommandRestore(operation) => operation.definition(),
            Self::LineDelete(operation) => operation.definition(),
            Self::XinetdDisable(operation) => operation.definition(),
        }
    }

    fn state(&self) -> OperationState {
        match self {
            Self::Sftp(operation) => operation.state(),
            Self::CapabilityStrip(operation) => operation.state(),
            Self::CommandRestore(operation) => operation.state(),
            Self::LineDelete(operation) => operation.state(),
            Self::XinetdDisable(operation) => operation.state(),
        }
    }

    fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        match self {
            Self::Sftp(operation) => operation.confirm(confirmation),
            Self::CapabilityStrip(operation) => operation.confirm(confirmation),
            Self::CommandRestore(operation) => operation.confirm(confirmation),
            Self::LineDelete(operation) => operation.confirm(confirmation),
            Self::XinetdDisable(operation) => operation.confirm(confirmation),
        }
    }

    async fn execute_and_verify(&mut self) -> CoreResult<VerificationResult> {
        match self {
            Self::Sftp(operation) => operation.execute_and_verify().await,
            Self::CapabilityStrip(operation) => operation.execute_and_verify().await,
            Self::CommandRestore(operation) => operation.execute_and_verify().await,
            Self::LineDelete(operation) => operation.execute_and_verify().await,
            Self::XinetdDisable(operation) => operation.execute_and_verify().await,
        }
    }

    async fn restore(&mut self) -> CoreResult<()> {
        match self {
            Self::Sftp(operation) => operation.restore().await,
            Self::CapabilityStrip(operation) => operation.restore().await,
            Self::CommandRestore(operation) => operation.restore().await,
            Self::LineDelete(operation) => operation.restore().await,
            Self::XinetdDisable(operation) => operation.restore().await,
        }
    }

    fn can_undo(&self) -> bool {
        match self {
            Self::Sftp(operation) => operation.can_undo(),
            Self::CapabilityStrip(operation) => operation.can_undo(),
            Self::CommandRestore(operation) => operation.can_undo(),
            Self::LineDelete(operation) => operation.can_undo(),
            Self::XinetdDisable(operation) => operation.can_undo(),
        }
    }

    async fn undo(&mut self) -> CoreResult<String> {
        match self {
            Self::Sftp(operation) => operation.undo().await,
            Self::CapabilityStrip(operation) => operation.undo().await,
            Self::CommandRestore(operation) => operation.undo().await,
            Self::LineDelete(operation) => operation.undo().await,
            Self::XinetdDisable(operation) => operation.undo().await,
        }
    }

    /// Whether a failed verification puts the file back. The xinetd disable
    /// keeps the file isolated by design: an automatic put-back would re-arm
    /// the service on the next reload, so undo — an explicit ask — is the
    /// only way back.
    fn restores_on_failed_verification(&self) -> bool {
        !matches!(self, Self::XinetdDisable(_))
    }

    /// The residue facts a restore plan gathered; other actions have none.
    fn residue(&self) -> Option<ResiduePlanDto> {
        match self {
            Self::CommandRestore(operation) => Some(ResiduePlanDto {
                source: residue_candidate_dto(operation.source()),
                package: operation.package_name().map(bounded_text),
                candidates: operation
                    .candidates()
                    .iter()
                    .map(residue_candidate_dto)
                    .collect(),
            }),
            _ => None,
        }
    }
}

/// Whether the operator may undo after execution. A completed isolation that
/// does not auto-restore stays undoable even when verification failed — the
/// failed check is exactly when undo matters most. Operations that restore on
/// failure keep the older rule: once the original is put back there is nothing
/// left to undo.
fn undoable_after_verification(
    passed: bool,
    restores_on_failed_verification: bool,
    can_undo: bool,
) -> bool {
    (passed || !restores_on_failed_verification) && can_undo
}

/// Digests are host-reported text: bounded like every other boundary string,
/// and no longer than the 64 hex characters a sha256 can be.
fn residue_candidate_dto(
    candidate: &lovelyhawk_core::command_restore::ResidueCandidate,
) -> ResidueCandidateDto {
    ResidueCandidateDto {
        path: bounded_text(candidate.path().as_str()),
        sha256: candidate.sha256().chars().take(64).collect::<String>(),
        size: candidate.size().to_string(),
        kind: candidate.kind().as_str().to_owned(),
    }
}

#[derive(Default)]
struct PathRegistry {
    paths: HashMap<String, StoredPath>,
    previews: HashMap<String, StoredPreview>,
    plans: HashMap<String, PlannedPath>,
    /// Verified and reversible: kept for a while so the operator can undo
    /// them from the receipt.
    done: HashMap<String, PlannedPath>,
    batches: HashMap<String, StoredBatch>,
}

impl PathRegistry {
    fn prune(&mut self, now: Instant) {
        self.paths.retain(|_, stored| stored.expires_at > now);
        self.previews.retain(|_, stored| stored.expires_at > now);
        self.plans.retain(|_, plan| plan.expires_at > now);
        self.done.retain(|_, plan| plan.expires_at > now);
        self.batches.retain(|_, batch| batch.expires_at > now);
    }

    fn close_binding(&mut self, binding_handle: &str) {
        self.paths
            .retain(|_, stored| stored.scope.binding_handle != binding_handle);
        self.previews
            .retain(|_, stored| stored.scope.binding_handle != binding_handle);
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
        self.done
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
        self.batches
            .retain(|_, batch| batch.scope.binding_handle != binding_handle);
    }

    /// One batch per binding — an earlier one the window walked away from
    /// must not keep its plans armed.
    fn store_batch(&mut self, batch: StoredBatch) -> Result<(), EmergencyPathApiError> {
        self.batches
            .retain(|_, stored| stored.scope.binding_handle != batch.scope.binding_handle);
        if self.batches.len() >= MAX_BATCHES {
            return Err(EmergencyPathApiError::Capacity);
        }
        self.batches.insert(batch.batch_handle.clone(), batch);
        Ok(())
    }

    fn batch_mut(
        &mut self,
        scope: &PathScope,
        batch_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredBatch, EmergencyPathApiError> {
        let batch = self
            .batches
            .get_mut(batch_handle)
            .ok_or(EmergencyPathApiError::PlanStale)?;
        if batch.scope != *scope || batch.expires_at <= now {
            return Err(EmergencyPathApiError::PlanStale);
        }
        Ok(batch)
    }

    /// Keeps the newest; the oldest undo offer goes first.
    fn store_done(&mut self, plan: PlannedPath) {
        if self.done.len() >= MAX_PLANS
            && let Some(oldest) = self
                .done
                .iter()
                .min_by_key(|(_, stored)| stored.expires_at)
                .map(|(handle, _)| handle.clone())
        {
            self.done.remove(&oldest);
        }
        self.done.insert(plan.plan_handle.clone(), plan);
    }

    /// Takes a finished plan out, so it can be undone once.
    fn take_done(
        &mut self,
        scope: &PathScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<PlannedPath, EmergencyPathApiError> {
        let plan = self
            .done
            .get(plan_handle)
            .ok_or(EmergencyPathApiError::PlanStale)?;
        if !still_live(&plan.scope, plan.expires_at, scope, now) {
            return Err(EmergencyPathApiError::PlanStale);
        }
        self.done
            .remove(plan_handle)
            .ok_or(EmergencyPathApiError::PlanStale)
    }

    /// Workbench results accumulate during a group run. Do not invalidate
    /// their file entries when the next command returns (even with no paths).
    /// Other pages replace their previous collection. All entries remain
    /// bounded by the original TTL, target identity and shared cache ceiling.
    fn store_for_binding(
        &mut self,
        scope: &PathScope,
        source: PathOfferSource,
        offered: Vec<(String, RemotePath)>,
    ) {
        self.paths.retain(|_, stored| {
            stored.scope.binding_handle != scope.binding_handle
                || (stored.scope == *scope
                    && (stored.source != source || source == PathOfferSource::Workbench))
        });
        let incoming = offered.len().min(MAX_STORED_PATHS);
        let remove_count = self
            .paths
            .len()
            .saturating_add(incoming)
            .saturating_sub(MAX_STORED_PATHS);
        if remove_count > 0 {
            // Prefer fresh results at capacity; never issue an entry that was
            // not stored. Expired/evicted output remains readable and can be
            // collected again, without renewing an old mutation plan.
            let mut oldest: Vec<_> = self
                .paths
                .iter()
                .map(|(handle, stored)| (stored.expires_at, handle.clone()))
                .collect();
            oldest.sort_unstable();
            for (_, handle) in oldest.into_iter().take(remove_count) {
                self.paths.remove(&handle);
            }
        }
        let expires_at = Instant::now() + PATH_TTL;
        for (handle, path) in offered.into_iter().take(MAX_STORED_PATHS) {
            self.paths.insert(
                handle,
                StoredPath {
                    scope: scope.clone(),
                    source,
                    path,
                    expires_at,
                },
            );
        }
    }

    fn path(
        &self,
        scope: &PathScope,
        path_handle: &str,
        now: Instant,
    ) -> Result<RemotePath, EmergencyPathApiError> {
        let stored = self
            .paths
            .get(path_handle)
            .ok_or(EmergencyPathApiError::PathStale)?;
        if !still_live(&stored.scope, stored.expires_at, scope, now) {
            return Err(EmergencyPathApiError::PathStale);
        }
        Ok(stored.path.clone())
    }

    fn store_plan(&mut self, plan: PlannedPath) -> Result<(), EmergencyPathApiError> {
        // A binding drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(EmergencyPathApiError::Capacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    /// One preview per binding: a new `path.lines` call replaces whichever
    /// file the same window was looking at before.
    fn store_preview(&mut self, preview: StoredPreview) -> Result<(), EmergencyPathApiError> {
        self.previews
            .retain(|_, stored| stored.scope.binding_handle != preview.scope.binding_handle);
        if self.previews.len() >= MAX_PLANS {
            return Err(EmergencyPathApiError::Capacity);
        }
        self.previews
            .insert(preview.preview_handle.clone(), preview);
        Ok(())
    }

    /// The stored preview's own copy — a plan is bound to what the preview
    /// read, not to anything the caller claims about it.
    fn preview(
        &self,
        scope: &PathScope,
        preview_handle: &str,
        now: Instant,
    ) -> Result<StoredPreview, EmergencyPathApiError> {
        let stored = self
            .previews
            .get(preview_handle)
            .ok_or(EmergencyPathApiError::PlanStale)?;
        if !still_live(&stored.scope, stored.expires_at, scope, now) {
            return Err(EmergencyPathApiError::PlanStale);
        }
        Ok(StoredPreview {
            scope: stored.scope.clone(),
            preview_handle: stored.preview_handle.clone(),
            path_handle: stored.path_handle.clone(),
            path: stored.path.clone(),
            sha256: stored.sha256.clone(),
            expires_at: stored.expires_at,
        })
    }

    fn plan_mut(
        &mut self,
        scope: &PathScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut PlannedPath, EmergencyPathApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(EmergencyPathApiError::PlanStale)?;
        if !still_live(&plan.scope, plan.expires_at, scope, now) {
            return Err(EmergencyPathApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes a confirmed plan out of the registry, so it can never run twice.
    fn take_confirmed_plan(
        &mut self,
        scope: &PathScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<PlannedPath, EmergencyPathApiError> {
        let plan = self.plan_mut(scope, plan_handle, now)?;
        if plan.operation.state() != OperationState::Confirmed {
            return Err(EmergencyPathApiError::PlanStale);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(EmergencyPathApiError::PlanStale)
    }
}

pub(crate) enum EmergencyPathApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    PathStale,
    PlanStale,
    Capacity,
    Deadline,
    RegistryUnavailable,
    /// The batch held zero items or more than the preview can show.
    BatchSize,
    /// The action asked of a batch is a single-path decision only.
    UnsupportedBatchAction,
    /// A read the core ran while planning said the file cannot be changed as
    /// asked. The code tells the page which reason to show.
    Refused(PathRefusal),
}

/// Which plan-time refusal the core reported, as a stable key.
#[derive(Clone, Copy)]
pub(crate) enum PathRefusal {
    Tools,
    Privilege,
    Kind,
    Empty,
    /// Disarming a file that has no execute bit set would change nothing.
    NotExecutable,
    RestoreTools,
    RestorePrivilege,
    RestoreKind,
    RestoreLocation,
    RestoreEmpty,
    RestoreAmbiguous,
    /// The path is not one of the managed startup/cron files.
    LineLocation,
    /// Not a regular file (symlink, directory, anything else).
    LineKind,
    /// Empty or past the managed-edit size cap.
    LineSize,
    /// Line numbers outside the file or past the per-delete cap.
    LineRange,
    /// The file moved between preview and planning.
    LineStale,
    /// Outside /etc/xinetd.d or an unusable name there.
    XinetdLocation,
    /// Not a regular file.
    XinetdKind,
    /// A name xinetd itself does not load (contains a dot or ends with ~).
    XinetdIgnored,
    /// Needs root or passwordless sudo.
    XinetdPrivilege,
    /// The host lacks a tool the isolation cannot proceed without.
    XinetdTools,
}

/// The refusal key a batch item carries back to the page.
fn path_refusal_key(refusal: PathRefusal) -> &'static str {
    match refusal {
        PathRefusal::Tools => "tools",
        PathRefusal::Privilege => "privilege",
        PathRefusal::Kind => "kind",
        PathRefusal::Empty => "empty",
        PathRefusal::NotExecutable => "not-executable",
        PathRefusal::RestoreTools => "restore-tools",
        PathRefusal::RestorePrivilege => "restore-privilege",
        PathRefusal::RestoreKind => "restore-kind",
        PathRefusal::RestoreLocation => "restore-location",
        PathRefusal::RestoreEmpty => "restore-empty",
        PathRefusal::RestoreAmbiguous => "restore-ambiguous",
        PathRefusal::LineLocation => "line-location",
        PathRefusal::LineKind => "line-kind",
        PathRefusal::LineSize => "line-size",
        PathRefusal::LineRange => "line-range",
        PathRefusal::LineStale => "line-stale",
        PathRefusal::XinetdLocation => "xinetd-location",
        PathRefusal::XinetdKind => "xinetd-kind",
        PathRefusal::XinetdIgnored => "xinetd-ignored",
        PathRefusal::XinetdPrivilege => "xinetd-privilege",
        PathRefusal::XinetdTools => "xinetd-tools",
    }
}

/// Plan-time refusals the page can translate; anything else stays behind the
/// generic boundary message.
fn capability_plan_failure(error: &CoreError) -> EmergencyPathApiError {
    let refusal = match error {
        CoreError::Validation { subject, .. } => match *subject {
            CAPABILITY_TOOLS_REFUSAL => PathRefusal::Tools,
            CAPABILITY_PRIVILEGE_REFUSAL => PathRefusal::Privilege,
            CAPABILITY_KIND_REFUSAL => PathRefusal::Kind,
            CAPABILITY_EMPTY_REFUSAL => PathRefusal::Empty,
            _ => return EmergencyPathApiError::Core,
        },
        _ => return EmergencyPathApiError::Core,
    };
    EmergencyPathApiError::Refused(refusal)
}

/// The same bargain for a restore plan: each refusal the core named gets a
/// code the page can translate, everything else stays generic.
fn restore_plan_failure(error: &CoreError) -> EmergencyPathApiError {
    let refusal = match error {
        CoreError::Validation { subject, .. } => match *subject {
            RESTORE_TOOLS_REFUSAL => PathRefusal::RestoreTools,
            RESTORE_PRIVILEGE_REFUSAL => PathRefusal::RestorePrivilege,
            RESTORE_KIND_REFUSAL => PathRefusal::RestoreKind,
            RESTORE_LOCATION_REFUSAL => PathRefusal::RestoreLocation,
            RESTORE_EMPTY_REFUSAL => PathRefusal::RestoreEmpty,
            RESTORE_AMBIGUOUS_REFUSAL => PathRefusal::RestoreAmbiguous,
            _ => return EmergencyPathApiError::Core,
        },
        _ => return EmergencyPathApiError::Core,
    };
    EmergencyPathApiError::Refused(refusal)
}

/// Line-delete planning refuses for reasons the page names one by one;
/// anything else stays generic.
fn line_delete_plan_failure(error: &CoreError) -> EmergencyPathApiError {
    let refusal = match error {
        CoreError::Validation { subject, .. } => match *subject {
            LINE_DELETE_LOCATION_REFUSAL => PathRefusal::LineLocation,
            LINE_DELETE_KIND_REFUSAL => PathRefusal::LineKind,
            LINE_DELETE_SIZE_REFUSAL => PathRefusal::LineSize,
            LINE_DELETE_RANGE_REFUSAL => PathRefusal::LineRange,
            LINE_DELETE_STALE_REFUSAL => PathRefusal::LineStale,
            _ => return EmergencyPathApiError::Core,
        },
        _ => return EmergencyPathApiError::Core,
    };
    EmergencyPathApiError::Refused(refusal)
}

/// Xinetd-disable planning refuses for reasons the page names one by one.
fn xinetd_plan_failure(error: &CoreError) -> EmergencyPathApiError {
    let refusal = match error {
        CoreError::Validation { subject, .. } => match *subject {
            XINETD_LOCATION_REFUSAL => PathRefusal::XinetdLocation,
            XINETD_KIND_REFUSAL => PathRefusal::XinetdKind,
            XINETD_IGNORED_REFUSAL => PathRefusal::XinetdIgnored,
            XINETD_PRIVILEGE_REFUSAL => PathRefusal::XinetdPrivilege,
            XINETD_TOOLS_REFUSAL => PathRefusal::XinetdTools,
            _ => return EmergencyPathApiError::Core,
        },
        _ => return EmergencyPathApiError::Core,
    };
    EmergencyPathApiError::Refused(refusal)
}

impl fmt::Debug for EmergencyPathApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::PathStale => "PathStale",
            Self::PlanStale => "PlanStale",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::BatchSize => "BatchSize",
            Self::UnsupportedBatchAction => "UnsupportedBatchAction",
            Self::Refused(_) => "Refused",
        })
    }
}

impl EmergencyPathApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(PathRegistry::default())),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.close_binding(binding_handle);
        }
    }

    /// Reads every path out of one run's output and offers each as a handle.
    ///
    /// Called with output the sidecar just received from the host, before it
    /// crosses the boundary. A path the renderer cannot see here is a path it
    /// can never ask to act on.
    /// `clipped_lines` names displayed lines that lost their tail to the
    /// per-line ceiling; what remains of those is a fragment, so no action is
    /// offered on them.
    pub(crate) fn offer(
        &self,
        scope: &PathScope,
        output: &str,
        clipped_lines: &[u32],
    ) -> Vec<EmergencyPathDto> {
        let mut offered = Vec::new();
        let mut stored = Vec::new();
        for (line, path) in paths_in_output(output) {
            if path.len() > MAX_PATH_DISPLAY_BYTES || clipped_lines.contains(&line) {
                continue;
            }
            let Ok(remote) = RemotePath::new(path.clone()) else {
                continue;
            };
            let path_handle = Uuid::new_v4().to_string();
            let line_editable = line_delete_path_allowed(&remote);
            let xinetd_service = matches!(
                xinetd_service_path_check(&remote),
                XinetdPathCheck::Applicable
            );
            offered.push(EmergencyPathDto {
                path_handle: path_handle.clone(),
                line,
                path,
                line_editable,
                xinetd_service,
            });
            stored.push((path_handle, remote));
        }
        let Ok(mut registry) = self.registry.lock() else {
            // Without a registry the handles resolve to nothing, and offering
            // an action that cannot run is worse than offering none.
            return Vec::new();
        };
        registry.prune(Instant::now());
        registry.store_for_binding(scope, PathOfferSource::Workbench, stored);
        offered.retain(|offer| registry.paths.contains_key(&offer.path_handle));
        offered
    }

    /// Offers whole paths another page found (an integrity comparison), each
    /// as a handle the same actions accept. The answer lines up with `paths`:
    /// None where a path cannot be acted on. Replaces only that page's offers.
    pub(crate) fn offer_paths(
        &self,
        scope: &PathScope,
        source: PathOfferSource,
        paths: &[String],
    ) -> Vec<Option<String>> {
        let mut handles = Vec::with_capacity(paths.len());
        let mut stored = Vec::new();
        for path in paths {
            let handle = (path.len() <= MAX_PATH_DISPLAY_BYTES)
                .then(|| RemotePath::new(path.clone()).ok())
                .flatten()
                .map(|remote| {
                    let handle = Uuid::new_v4().to_string();
                    stored.push((handle.clone(), remote));
                    handle
                });
            handles.push(handle);
        }
        let Ok(mut registry) = self.registry.lock() else {
            return vec![None; paths.len()];
        };
        registry.prune(Instant::now());
        registry.store_for_binding(scope, source, stored);
        for handle in &mut handles {
            if handle
                .as_ref()
                .is_some_and(|value| !registry.paths.contains_key(value))
            {
                *handle = None;
            }
        }
        handles
    }

    /// What the host says about the file right now. Reads nothing else.
    pub(crate) async fn inspect(
        &self,
        binding_handle: &str,
        path_handle: &str,
    ) -> Result<EmergencyPathDetailDto, EmergencyPathApiError> {
        validate_handle(path_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let path = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.path(&scope, path_handle, now)?
        };
        let session = self.bind_sftp(&scope).await?;
        let metadata = timeout(
            INSPECT_DEADLINE,
            self.services.sftp().metadata(&session, &path, false),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|_| EmergencyPathApiError::Core)?;
        self.validate_binding(&scope)?;
        let permissions = metadata.permissions.map(|mode| mode & PERMISSION_BITS);
        Ok(EmergencyPathDetailDto {
            path_handle: path_handle.to_owned(),
            path: path.as_str().to_owned(),
            kind: match metadata.kind {
                SftpFileKind::File => "file",
                SftpFileKind::Directory => "directory",
                SftpFileKind::Symlink => "symlink",
                SftpFileKind::Other => "other",
            }
            .to_owned(),
            size: metadata.size.to_string(),
            mode: permissions.map(|mode| format!("{mode:04o}")),
            owner_id: metadata.uid,
            group_id: metadata.gid,
            modified_at: metadata.modified_at.map(|at| at.to_rfc3339()),
            // SUID/SGID alone do not grant execute permission. Disarming still
            // clears those privilege bits as well as the three execute bits.
            executable: permissions.is_some_and(|mode| mode & 0o111 != 0),
        })
    }

    /// The numbered, sanitized lines of a managed file, so the operator can
    /// pick the range to delete. The digest of the bytes read stays behind
    /// the preview handle: a file that moves between preview and planning is
    /// refused rather than edited blind.
    pub(crate) async fn preview_lines(
        &self,
        binding_handle: &str,
        path_handle: &str,
    ) -> Result<EmergencyPathLinesPreviewDto, EmergencyPathApiError> {
        validate_handle(path_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let path = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.path(&scope, path_handle, now)?
        };
        if !line_delete_path_allowed(&path) {
            return Err(EmergencyPathApiError::Refused(PathRefusal::LineLocation));
        }
        let session = self.bind_sftp(&scope).await?;
        let metadata = timeout(
            INSPECT_DEADLINE,
            self.services.sftp().metadata(&session, &path, false),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|_| EmergencyPathApiError::Core)?;
        if metadata.kind != SftpFileKind::File {
            return Err(EmergencyPathApiError::Refused(PathRefusal::LineKind));
        }
        if metadata.size == 0 || metadata.size > MAX_EDIT_BYTES {
            return Err(EmergencyPathApiError::Refused(PathRefusal::LineSize));
        }
        let content = timeout(
            INSPECT_DEADLINE,
            self.services.sftp().read_file(&session, &path),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|_| EmergencyPathApiError::Core)?;
        self.validate_binding(&scope)?;

        let preview = preview_lines(&content);
        let preview_handle = Uuid::new_v4().to_string();
        let dto = EmergencyPathLinesPreviewDto {
            preview_handle: preview_handle.clone(),
            path_handle: path_handle.to_owned(),
            path: path.as_str().to_owned(),
            total_lines: preview.total_lines,
            lines: preview
                .lines
                .iter()
                .map(EmergencyPathLineDto::from)
                .collect(),
            truncated: preview.truncated,
        };
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_preview(StoredPreview {
            scope,
            preview_handle,
            path_handle: path_handle.to_owned(),
            path,
            sha256: preview.sha256,
            expires_at: now + PLAN_TTL,
        })?;
        Ok(dto)
    }

    /// Plans a contiguous-line delete from the preview the operator picked
    /// the range on. The plan is the same single-use kind `plan` stores, so
    /// confirm, execute, cancel and undo all work on it unchanged.
    pub(crate) async fn plan_lines(
        &self,
        binding_handle: &str,
        preview_handle: &str,
        first_line: u32,
        last_line: u32,
    ) -> Result<EmergencyPathLinesPlanDto, EmergencyPathApiError> {
        validate_handle(preview_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let preview = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.preview(&scope, preview_handle, now)?
        };
        let session = self.bound_ssh(&scope)?;
        let operation = timeout(
            INSPECT_DEADLINE,
            self.services.system_info().plan_line_delete(
                &session,
                &preview.path,
                first_line,
                last_line,
                &preview.sha256,
            ),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|error| line_delete_plan_failure(&error))?;
        self.validate_binding(&scope)?;

        let removed_lines: Vec<EmergencyPathLineDto> = operation
            .removed_lines()
            .iter()
            .map(EmergencyPathLineDto::from)
            .collect();
        let now = Instant::now();
        let plan = PlannedPath {
            plan_handle: Uuid::new_v4().to_string(),
            path_handle: preview.path_handle.clone(),
            path: preview.path.as_str().to_owned(),
            action: EmergencyPathAction::DeleteLines,
            scope,
            operation: PathOperation::LineDelete(Box::new(operation)),
            expires_at: now + PLAN_TTL,
        };
        let definition = plan.operation.definition();
        let remaining = plan.expires_at.saturating_duration_since(now).as_secs();
        let dto = EmergencyPathLinesPlanDto {
            plan_handle: plan.plan_handle.clone(),
            path_handle: plan.path_handle.clone(),
            path: plan.path.clone(),
            action: plan.action.label().to_owned(),
            summary: bounded_text(&definition.summary),
            dangerous: definition.dangerous,
            restore_description: definition.restore_description.as_deref().map(bounded_text),
            state: "planned".to_owned(),
            expires_in_seconds: u32::try_from(remaining.max(1))
                .map_err(|_| EmergencyPathApiError::Core)?,
            residue: None,
            removed_lines,
        };
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_plan(plan)?;
        Ok(dto)
    }

    /// Describes what an action would do, without doing any of it.
    pub(crate) async fn plan(
        &self,
        binding_handle: &str,
        path_handle: &str,
        action: EmergencyPathAction,
    ) -> Result<EmergencyPathPlanDto, EmergencyPathApiError> {
        validate_handle(path_handle)?;
        // A delete needs the range the preview flow carries, so the generic
        // plan entry is where it gets refused — not where it guesses one.
        if action == EmergencyPathAction::DeleteLines {
            return Err(EmergencyPathApiError::UnsupportedBatchAction);
        }
        let scope = self.capture_binding(binding_handle)?;
        let path = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.path(&scope, path_handle, now)?
        };
        let operation = self.build_operation(&scope, &path, action).await?;
        self.validate_binding(&scope)?;

        let now = Instant::now();
        let plan = PlannedPath {
            plan_handle: Uuid::new_v4().to_string(),
            path_handle: path_handle.to_owned(),
            path: path.as_str().to_owned(),
            action,
            scope,
            operation,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&plan, now)?;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_plan(plan)?;
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<EmergencyPathPlanDto, EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        let confirmation = DangerousConfirmation::approve(plan.operation.definition());
        plan.operation
            .confirm(confirmation)
            .map_err(|_| EmergencyPathApiError::PlanStale)?;
        plan_dto(plan, now)
    }

    /// Runs the confirmed plan once, verifies it, and puts it back on failure.
    pub(crate) async fn execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<EmergencyPathReceiptDto, EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let plan = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_confirmed_plan(&scope, plan_handle, now)?
        };
        self.execute_plan(plan).await
    }

    /// The confirmed operation's one run: execute, verify, and put back on
    /// failure. A single action and each batch item share this, so a batch
    /// receipt means exactly what a single receipt does.
    async fn execute_plan(
        &self,
        mut plan: PlannedPath,
    ) -> Result<EmergencyPathReceiptDto, EmergencyPathApiError> {
        let scope = plan.scope.clone();
        let outcome = timeout(EXECUTE_DEADLINE, plan.operation.execute_and_verify()).await;
        self.validate_binding(&scope)?;
        let verification = match outcome {
            Err(_) => return Err(EmergencyPathApiError::Deadline),
            Ok(Err(error)) => {
                // Same bargain as the file manager's: the machine's own words
                // stay on the other side of the boundary, but a failure the
                // core recognises is worth naming.
                let advice = lovelyhawk_core::sftp::operation_failure_advice(&error);
                // A refusal before writing changed nothing; there is nothing
                // to put back, and saying "could not restore" would send the
                // operator looking for damage that does not exist.
                let untouched = lovelyhawk_core::sftp::operation_left_untouched(&error);
                // An executor error leaves the plan without a receipt, so its
                // own restore cannot run — a multi-step write that already
                // put itself back says so through the error instead.
                let restored = !untouched
                    && (lovelyhawk_core::sftp::operation_put_back(&error)
                        || plan.operation.restore().await.is_ok());
                return Ok(EmergencyPathReceiptDto {
                    plan_handle: plan.plan_handle,
                    path: plan.path,
                    action: plan.action.label().to_owned(),
                    passed: false,
                    detail: advice.unwrap_or("操作未能完成。").to_owned(),
                    restored,
                    untouched,
                    undoable: false,
                });
            }
            Ok(Ok(verification)) => verification,
        };
        let restored = !verification.passed
            && plan.operation.restores_on_failed_verification()
            && plan.operation.restore().await.is_ok();
        let undoable = undoable_after_verification(
            verification.passed,
            plan.operation.restores_on_failed_verification(),
            plan.operation.can_undo(),
        );
        let receipt = EmergencyPathReceiptDto {
            plan_handle: plan.plan_handle.clone(),
            path: plan.path.clone(),
            action: plan.action.label().to_owned(),
            passed: verification.passed,
            detail: bounded_text(&verification.detail),
            restored,
            untouched: false,
            undoable,
        };
        if undoable {
            plan.expires_at = Instant::now() + UNDO_TTL;
            self.lock_registry()?.store_done(plan);
        }
        Ok(receipt)
    }

    /// Puts a finished action back, when the file is still exactly as the
    /// action left it; the core checks that, restores, and reads it again.
    pub(crate) async fn undo(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<EmergencyPathUndoDto, EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let mut plan = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_done(&scope, plan_handle, now)?
        };
        let outcome = timeout(EXECUTE_DEADLINE, plan.operation.undo()).await;
        self.validate_binding(&scope)?;
        match outcome {
            Err(_) => Err(EmergencyPathApiError::Deadline),
            Ok(Ok(detail)) => Ok(EmergencyPathUndoDto {
                plan_handle: plan.plan_handle,
                path: plan.path,
                undone: true,
                detail: bounded_text(&detail),
            }),
            Ok(Err(error)) => Ok(EmergencyPathUndoDto {
                plan_handle: plan.plan_handle,
                path: plan.path,
                undone: false,
                detail: lovelyhawk_core::sftp::operation_failure_advice(&error)
                    .unwrap_or("撤销没有完成，请在目标机上检查这个文件现在的状态。")
                    .to_owned(),
            }),
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), EmergencyPathApiError> {
        validate_handle(plan_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        if registry
            .plans
            .get(plan_handle)
            .is_some_and(|plan| plan.scope == scope)
        {
            registry.plans.remove(plan_handle);
        }
        Ok(())
    }

    /// Plans every offered handle for the same containment action. Each item
    /// is the same immutable plan a single action would make — SFTP mutations
    /// on one shared session — and an item that cannot be planned is refused
    /// in place rather than failing the batch the operator is still previewing.
    pub(crate) async fn plan_batch(
        &self,
        binding_handle: &str,
        path_handles: &[String],
        action: EmergencyPathAction,
    ) -> Result<EmergencyPathBatchPlanDto, EmergencyPathApiError> {
        // Restore and capability edits each need their own reading of what
        // the plan found; they stay single-path decisions.
        if !matches!(
            action,
            EmergencyPathAction::Disarm | EmergencyPathAction::Quarantine
        ) {
            return Err(EmergencyPathApiError::UnsupportedBatchAction);
        }
        validate_batch_request(path_handles)?;
        let scope = self.capture_binding(binding_handle)?;
        let session = self.bind_sftp(&scope).await?;

        let mut items = Vec::with_capacity(path_handles.len());
        for path_handle in path_handles {
            let path = {
                let now = Instant::now();
                let mut registry = self.lock_registry()?;
                registry.prune(now);
                registry.path(&scope, path_handle, now)
            };
            let Ok(path) = path else {
                items.push(StoredBatchItem::refused(
                    path_handle,
                    String::new(),
                    "path-stale",
                ));
                continue;
            };
            // What the preview shows about the file comes from the same stat
            // a single inspect would make; a file that cannot be read cannot
            // be previewed, and that is its refusal.
            let metadata = timeout(
                INSPECT_DEADLINE,
                self.services.sftp().metadata(&session, &path, false),
            )
            .await
            .ok()
            .and_then(std::result::Result::ok);
            let Some(metadata) = metadata else {
                items.push(StoredBatchItem::refused(
                    path_handle,
                    path.as_str().to_owned(),
                    "inspect-failed",
                ));
                continue;
            };
            let mutation = match self.sftp_mutation(&session, &path, action).await {
                Ok(mutation) => mutation,
                Err(EmergencyPathApiError::Refused(refusal)) => {
                    items.push(
                        StoredBatchItem::refused(
                            path_handle,
                            path.as_str().to_owned(),
                            path_refusal_key(refusal),
                        )
                        .with_metadata(&metadata),
                    );
                    continue;
                }
                Err(_) => {
                    items.push(
                        StoredBatchItem::refused(
                            path_handle,
                            path.as_str().to_owned(),
                            "unavailable",
                        )
                        .with_metadata(&metadata),
                    );
                    continue;
                }
            };
            match self.services.sftp().plan(&session, mutation) {
                Ok(operation) => {
                    items.push(
                        StoredBatchItem::refused(
                            path_handle,
                            path.as_str().to_owned(),
                            "unavailable",
                        )
                        .with_metadata(&metadata)
                        .planned(operation),
                    );
                }
                Err(_) => items.push(
                    StoredBatchItem::refused(path_handle, path.as_str().to_owned(), "unavailable")
                        .with_metadata(&metadata),
                ),
            }
        }
        self.validate_binding(&scope)?;

        let batch = StoredBatch {
            batch_handle: Uuid::new_v4().to_string(),
            scope,
            action,
            items,
            confirmed: false,
            expires_at: Instant::now() + PLAN_TTL,
        };
        let now = Instant::now();
        let dto = batch_dto(&batch, now)?;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_batch(batch)?;
        Ok(dto)
    }

    /// The one confirmation the whole preview asked for. An item whose own
    /// plan can no longer be confirmed is refused in place; the rest still
    /// stand behind the approval the operator just gave.
    pub(crate) fn confirm_batch(
        &self,
        binding_handle: &str,
        batch_handle: &str,
    ) -> Result<EmergencyPathBatchPlanDto, EmergencyPathApiError> {
        validate_handle(batch_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let batch = registry.batch_mut(&scope, batch_handle, now)?;
        if batch.confirmed {
            return Err(EmergencyPathApiError::PlanStale);
        }
        for item in &mut batch.items {
            let Some(operation) = item.operation.as_mut() else {
                continue;
            };
            let confirmation = DangerousConfirmation::approve(operation.definition());
            if operation.confirm(confirmation).is_err() {
                item.operation = None;
                item.refusal = Some("confirm-failed");
                item.finished = true;
            }
        }
        batch.confirmed = true;
        batch_dto(batch, now)
    }

    /// Executes the next pending item, exactly one per call, so the operator
    /// can stop between items. Refused items are already done and stay
    /// visible in the preview the dialog keeps.
    pub(crate) async fn step_batch(
        &self,
        binding_handle: &str,
        batch_handle: &str,
    ) -> Result<EmergencyPathBatchStepDto, EmergencyPathApiError> {
        validate_handle(batch_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let plan = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            let batch = registry.batch_mut(&scope, batch_handle, now)?;
            if !batch.confirmed {
                return Err(EmergencyPathApiError::PlanStale);
            }
            let mut taken = None;
            for item in &mut batch.items {
                if item.finished {
                    continue;
                }
                item.finished = true;
                if let Some(operation) = item.operation.take() {
                    taken = Some(PlannedPath {
                        plan_handle: item.plan_handle.clone(),
                        path_handle: item.path_handle.clone(),
                        path: item.path.clone(),
                        action: batch.action,
                        scope: batch.scope.clone(),
                        operation,
                        expires_at: batch.expires_at,
                    });
                    break;
                }
            }
            taken
        };
        let Some(plan) = plan else {
            let mut registry = self.lock_registry()?;
            let batch = registry.batches.get_mut(batch_handle);
            return Ok(EmergencyPathBatchStepDto {
                batch_handle: batch_handle.to_owned(),
                receipt: None,
                remaining: 0,
                refused: batch.map_or(0, |stored| stored.refused_count()),
                finished: true,
            });
        };
        let receipt = self.execute_plan(plan).await?;
        let mut registry = self.lock_registry()?;
        let batch = registry.batches.get_mut(batch_handle);
        let (remaining, refused) = batch.map_or((0, 0), |stored| {
            (stored.pending_count(), stored.refused_count())
        });
        Ok(EmergencyPathBatchStepDto {
            batch_handle: batch_handle.to_owned(),
            receipt: Some(receipt),
            remaining,
            refused,
            finished: remaining == 0,
        })
    }

    /// Drops the items the operator did not run. Finished items keep their
    /// undo entries; only what never ran goes away.
    pub(crate) fn cancel_batch(
        &self,
        binding_handle: &str,
        batch_handle: &str,
    ) -> Result<(), EmergencyPathApiError> {
        validate_handle(batch_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        if registry
            .batches
            .get(batch_handle)
            .is_some_and(|batch| batch.scope == scope)
        {
            registry.batches.remove(batch_handle);
        }
        Ok(())
    }

    /// Turns a capability and an action into the one planned operation the
    /// core takes. SFTP mutations go through the file service; capability
    /// removal and command restore plan over the bound SSH channel instead —
    /// extended attributes are outside the SFTP protocol, and a restore must
    /// work on a host whose SFTP never came up.
    async fn build_operation(
        &self,
        scope: &PathScope,
        path: &RemotePath,
        action: EmergencyPathAction,
    ) -> Result<PathOperation, EmergencyPathApiError> {
        match action {
            EmergencyPathAction::RemoveCapabilities => {
                let session = self.bound_ssh(scope)?;
                let operation = timeout(
                    INSPECT_DEADLINE,
                    self.services.system_info().plan_capability_strip(
                        &session,
                        path,
                        self.services.operation_journal().clone(),
                    ),
                )
                .await
                .map_err(|_| EmergencyPathApiError::Deadline)?
                .map_err(|error| capability_plan_failure(&error))?;
                Ok(PathOperation::CapabilityStrip(operation))
            }
            EmergencyPathAction::RestoreResidue => {
                let session = self.bound_ssh(scope)?;
                let operation = timeout(
                    INSPECT_DEADLINE,
                    self.services.system_info().plan_command_restore(
                        &session,
                        path,
                        self.services.operation_journal().clone(),
                    ),
                )
                .await
                .map_err(|_| EmergencyPathApiError::Deadline)?
                .map_err(|error| restore_plan_failure(&error))?;
                Ok(PathOperation::CommandRestore(operation))
            }
            EmergencyPathAction::DisableXinetdService => {
                let session = self.bound_ssh(scope)?;
                let operation = timeout(
                    INSPECT_DEADLINE,
                    self.services.system_info().plan_xinetd_disable(
                        &session,
                        path,
                        self.services.operation_journal().clone(),
                    ),
                )
                .await
                .map_err(|_| EmergencyPathApiError::Deadline)?
                .map_err(|error| xinetd_plan_failure(&error))?;
                Ok(PathOperation::XinetdDisable(Box::new(operation)))
            }
            _ => {
                let session = self.bind_sftp(scope).await?;
                let mutation = self.sftp_mutation(&session, path, action).await?;
                self.validate_binding(scope)?;
                let operation = self
                    .services
                    .sftp()
                    .plan(&session, mutation)
                    .map_err(|_| EmergencyPathApiError::Core)?;
                Ok(PathOperation::Sftp(operation))
            }
        }
    }

    /// The SFTP-carried mutation an action plans. Batch items call this with
    /// the one session the whole batch shares; a single action binds its own.
    /// Only Disarm and Quarantine reach it — the SSH-carried variants are
    /// matched above the SFTP arm in `build_operation`, and a batch plan
    /// refuses them before any item is read.
    async fn sftp_mutation(
        &self,
        session: &BoundSftpSession,
        path: &RemotePath,
        action: EmergencyPathAction,
    ) -> Result<SftpMutation, EmergencyPathApiError> {
        let mutation = match action {
            EmergencyPathAction::Disarm => {
                let metadata = timeout(
                    INSPECT_DEADLINE,
                    self.services.sftp().metadata(session, path, false),
                )
                .await
                .map_err(|_| EmergencyPathApiError::Deadline)?
                .map_err(|_| EmergencyPathApiError::Core)?;
                let expected_mode = metadata
                    .permissions
                    .map(|mode| mode & PERMISSION_BITS)
                    .ok_or(EmergencyPathApiError::Core)?;
                // Nothing to disarm, and a chmod to the mode it already
                // has would verify as a change that never happened.
                if expected_mode & EXECUTE_BITS == 0 {
                    return Err(EmergencyPathApiError::Refused(PathRefusal::NotExecutable));
                }
                // The expected mode makes the change fail rather than
                // apply to a file altered between reading and acting.
                SftpMutation::ChmodIfMode {
                    path: path.clone(),
                    expected_mode,
                    mode: expected_mode & !EXECUTE_BITS,
                }
            }
            EmergencyPathAction::Quarantine => {
                let metadata = timeout(
                    INSPECT_DEADLINE,
                    self.services.sftp().metadata(session, path, false),
                )
                .await
                .map_err(|_| EmergencyPathApiError::Deadline)?
                .map_err(|_| EmergencyPathApiError::Core)?;
                // A regular file quarantines under a content check: the hash
                // is read while planning and the move refuses to touch
                // anything that changed since. Everything else — directories,
                // links, oversized or unreadable files — keeps the plain move
                // and the plan text says it carries no content check.
                if metadata.kind == SftpFileKind::File && metadata.size <= MAX_EDIT_BYTES {
                    let content = timeout(
                        INSPECT_DEADLINE,
                        self.services.sftp().read_file(session, path),
                    )
                    .await
                    .map_err(|_| EmergencyPathApiError::Deadline)?
                    .map_err(|_| EmergencyPathApiError::Core)?;
                    SftpMutation::RemoveFileIfMatch {
                        path: path.clone(),
                        expected_sha256: content_sha256(&content),
                    }
                } else {
                    SftpMutation::Remove { path: path.clone() }
                }
            }
            // SSH-carried actions are matched above the SFTP arm; a
            // new variant must pick a transport there, not fall into
            // this match silently.
            EmergencyPathAction::RemoveCapabilities
            | EmergencyPathAction::RestoreResidue
            | EmergencyPathAction::DeleteLines
            | EmergencyPathAction::DisableXinetdService => {
                unreachable!()
            }
        };
        Ok(mutation)
    }

    /// The SSH session behind the stored scope, checked against the session
    /// and connection it was captured under. Restore and capability plans
    /// both run through it; neither needs SFTP.
    fn bound_ssh(&self, scope: &PathScope) -> Result<BoundSshSession, EmergencyPathApiError> {
        let session = self
            .ssh_api
            .binding_session_clone(&scope.binding_handle)
            .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        if session.session_id() != scope.session_id
            || session.connection_id() != scope.connection_id
        {
            return Err(EmergencyPathApiError::BindingUnavailable);
        }
        Ok(session)
    }

    pub(crate) fn resolve_evidence_path(
        &self,
        binding_handle: &str,
        path_handle: &str,
    ) -> Result<(PathScope, RemotePath), EmergencyPathApiError> {
        validate_handle(path_handle)?;
        let scope = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let path = registry.path(&scope, path_handle, now)?;
        Ok((scope, path))
    }

    fn capture_binding(&self, binding_handle: &str) -> Result<PathScope, EmergencyPathApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        Ok(PathScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    pub(crate) fn validate_binding(
        &self,
        expected: &PathScope,
    ) -> Result<(), EmergencyPathApiError> {
        let current = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(EmergencyPathApiError::BindingUnavailable);
        }
        Ok(())
    }

    pub(crate) async fn bind_sftp(
        &self,
        scope: &PathScope,
    ) -> Result<BoundSftpSession, EmergencyPathApiError> {
        let session = timeout(
            BIND_DEADLINE,
            self.services
                .sftp()
                .bind_session(scope.target.clone(), &scope.session_id),
        )
        .await
        .map_err(|_| EmergencyPathApiError::Deadline)?
        .map_err(|_| EmergencyPathApiError::BindingUnavailable)?;
        if session.session_id() != scope.session_id
            || session.connection_id() != scope.connection_id
        {
            return Err(EmergencyPathApiError::BindingUnavailable);
        }
        Ok(session)
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, PathRegistry>, EmergencyPathApiError> {
        self.registry
            .lock()
            .map_err(|_| EmergencyPathApiError::RegistryUnavailable)
    }
}

/// The batch as the preview dialog draws it. Refused rows carry their reason;
/// planned rows carry the same summary text a single-path dialog would show.
fn batch_dto(
    batch: &StoredBatch,
    now: Instant,
) -> Result<EmergencyPathBatchPlanDto, EmergencyPathApiError> {
    let remaining = batch.expires_at.saturating_duration_since(now).as_secs();
    Ok(EmergencyPathBatchPlanDto {
        batch_handle: batch.batch_handle.clone(),
        action: batch.action.label().to_owned(),
        items: batch
            .items
            .iter()
            .map(|item| {
                let definition = item
                    .operation
                    .as_ref()
                    .map(|operation| operation.definition());
                EmergencyPathBatchItemDto {
                    path_handle: item.path_handle.clone(),
                    path: item.path.clone(),
                    kind: item.kind.clone(),
                    size: item.size.clone(),
                    mode: item.mode.clone(),
                    executable: item.executable,
                    plan_handle: item.operation.as_ref().map(|_| item.plan_handle.clone()),
                    summary: definition.map(|planned| bounded_text(&planned.summary)),
                    restore_description: definition.and_then(|planned| {
                        planned.restore_description.as_deref().map(bounded_text)
                    }),
                    refusal: item.refusal.map(str::to_owned),
                }
            })
            .collect(),
        planned: batch
            .items
            .iter()
            .filter(|item| item.operation.is_some())
            .count() as u32,
        refused: batch.refused_count(),
        state: if batch.confirmed {
            "confirmed"
        } else {
            "planned"
        }
        .to_owned(),
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| EmergencyPathApiError::Core)?,
    })
}

fn plan_dto(
    plan: &PlannedPath,
    now: Instant,
) -> Result<EmergencyPathPlanDto, EmergencyPathApiError> {
    let definition = plan.operation.definition();
    let remaining = plan.expires_at.saturating_duration_since(now).as_secs();
    Ok(EmergencyPathPlanDto {
        plan_handle: plan.plan_handle.clone(),
        path_handle: plan.path_handle.clone(),
        path: plan.path.clone(),
        action: plan.action.label().to_owned(),
        summary: bounded_text(&definition.summary),
        dangerous: definition.dangerous,
        restore_description: definition.restore_description.as_deref().map(bounded_text),
        state: match plan.operation.state() {
            OperationState::Planned => "planned".to_owned(),
            OperationState::Confirmed => "confirmed".to_owned(),
            _ => "spent".to_owned(),
        },
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| EmergencyPathApiError::Core)?,
        residue: plan.operation.residue(),
    })
}

/// Plan text is written by the core, but it still crosses a boundary: keep it
/// drawable in a dialog. A control character becomes a replacement character
/// rather than disappearing, so nothing the core said is silently dropped.
fn bounded_text(value: &str) -> String {
    let mut text = String::with_capacity(value.len().min(MAX_PLAN_TEXT_BYTES));
    for character in value.chars() {
        let drawable = if character.is_control() {
            char::REPLACEMENT_CHARACTER
        } else {
            character
        };
        if text.len().saturating_add(drawable.len_utf8()) > MAX_PLAN_TEXT_BYTES {
            break;
        }
        text.push(drawable);
    }
    text
}

/// Whether a stored capability still belongs to the caller asking for it.
///
/// The binding, the session, the connection and the target generation all have
/// to be the ones it was minted under. A window that reconnected, or that is
/// now looking at a different host, is a different caller.
fn still_live(stored: &PathScope, expires_at: Instant, asking: &PathScope, now: Instant) -> bool {
    stored == asking && expires_at > now
}

fn validate_handle(handle: &str) -> Result<(), EmergencyPathApiError> {
    if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
        return Err(EmergencyPathApiError::InvalidHandle);
    }
    Ok(())
}

/// Request-level checks on the handles a batch names. The page only ever
/// sends minted handles; an empty, oversized, malformed or repeated list is a
/// broken caller, so the whole request fails rather than half-planning it.
fn validate_batch_request(path_handles: &[String]) -> Result<(), EmergencyPathApiError> {
    if path_handles.is_empty() || path_handles.len() > MAX_BATCH_ITEMS {
        return Err(EmergencyPathApiError::BatchSize);
    }
    let mut seen = HashSet::with_capacity(path_handles.len());
    for path_handle in path_handles {
        validate_handle(path_handle)?;
        if !seen.insert(path_handle) {
            return Err(EmergencyPathApiError::InvalidHandle);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::target::{TargetContext, TargetIdentity};

    use super::*;

    fn scope(binding: &str, identity: &str, generation: usize) -> PathScope {
        let target = TargetContext::new();
        let mut guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        for _ in 0..generation {
            guard = target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap();
        }
        PathScope {
            binding_handle: binding.to_owned(),
            session_id: format!("session-{identity}"),
            connection_id: identity.to_owned(),
            target: guard,
        }
    }

    fn offered(paths: &[&str]) -> Vec<(String, RemotePath)> {
        paths
            .iter()
            .enumerate()
            .map(|(index, path)| (format!("handle-{index}"), RemotePath::new(*path).unwrap()))
            .collect()
    }

    #[test]
    fn hands_back_only_the_paths_the_asking_binding_was_offered() {
        let mine = scope("binding-a", "target-a", 0);
        let theirs = scope("binding-b", "target-b", 0);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(
            &mine,
            PathOfferSource::Workbench,
            offered(&["/tmp/.x", "/tmp/.y"]),
        );

        let now = Instant::now();
        assert_eq!(
            registry.path(&mine, "handle-0", now).unwrap().as_str(),
            "/tmp/.x",
        );
        // Another binding cannot spend a capability it was never handed.
        assert!(matches!(
            registry.path(&theirs, "handle-0", now),
            Err(EmergencyPathApiError::PathStale),
        ));
        // Nor can a handle nobody was handed at all.
        assert!(matches!(
            registry.path(&mine, "handle-forged", now),
            Err(EmergencyPathApiError::PathStale),
        ));
    }

    #[test]
    fn refuses_a_capability_from_a_target_that_moved_on() {
        let before = scope("binding-a", "target-a", 0);
        let after = scope("binding-a", "target-a", 1);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(&before, PathOfferSource::Workbench, offered(&["/tmp/.x"]));
        assert!(matches!(
            registry.path(&after, "handle-0", Instant::now()),
            Err(EmergencyPathApiError::PathStale),
        ));
    }

    #[test]
    fn later_group_results_keep_earlier_file_entries_usable() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(
            &scope,
            PathOfferSource::Workbench,
            vec![(
                "suid-file".to_owned(),
                RemotePath::new("/tmp/first").unwrap(),
            )],
        );
        registry.store_for_binding(
            &scope,
            PathOfferSource::Workbench,
            vec![(
                "pam-file".to_owned(),
                RemotePath::new("/etc/pam.d/sshd").unwrap(),
            )],
        );
        // A subsequent check with no file output must not clear the group either.
        registry.store_for_binding(&scope, PathOfferSource::Workbench, Vec::new());
        for (handle, expected) in [("suid-file", "/tmp/first"), ("pam-file", "/etc/pam.d/sshd")] {
            assert_eq!(
                registry
                    .path(&scope, handle, Instant::now())
                    .unwrap()
                    .as_str(),
                expected
            );
        }
    }

    #[test]
    fn a_fresh_comparison_replaces_what_the_previous_one_offered() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(
            &scope,
            PathOfferSource::Integrity,
            offered(&["/tmp/.x", "/tmp/.y"]),
        );
        registry.store_for_binding(&scope, PathOfferSource::Integrity, offered(&["/tmp/.z"]));

        let now = Instant::now();
        assert_eq!(
            registry.path(&scope, "handle-0", now).unwrap().as_str(),
            "/tmp/.z",
        );
        // The second run offered one path, so the first run's second handle is
        // gone rather than left pointing at a line nobody is looking at.
        assert!(matches!(
            registry.path(&scope, "handle-1", now),
            Err(EmergencyPathApiError::PathStale),
        ));
        assert_eq!(registry.paths.len(), 1);
    }

    /// The workbench and the integrity page each replace only their own
    /// offers: a new comparison does not take away a workbench line's action.
    #[test]
    fn each_page_replaces_only_its_own_offers() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        // Handles are unique in use; give each offer its own here too.
        let named =
            |handle: &str, path: &str| vec![(handle.to_owned(), RemotePath::new(path).unwrap())];
        registry.store_for_binding(&scope, PathOfferSource::Workbench, named("w", "/tmp/.x"));
        registry.store_for_binding(
            &scope,
            PathOfferSource::Integrity,
            named("i1", "/usr/bin/.y"),
        );
        assert_eq!(registry.paths.len(), 2);
        registry.store_for_binding(
            &scope,
            PathOfferSource::Integrity,
            named("i2", "/usr/bin/.z"),
        );
        let mut paths: Vec<&str> = registry
            .paths
            .values()
            .map(|stored| stored.path.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(paths, ["/tmp/.x", "/usr/bin/.z"]);
        registry.store_for_binding(&scope, PathOfferSource::Integrity, Vec::new());
        assert_eq!(registry.paths.len(), 1);
        assert_eq!(
            registry.path(&scope, "w", Instant::now()).unwrap().as_str(),
            "/tmp/.x"
        );
    }

    #[test]
    fn stops_offering_at_the_ceiling() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        let many: Vec<String> = (0..MAX_STORED_PATHS + 50)
            .map(|index| format!("/tmp/.f{index}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        registry.store_for_binding(&scope, PathOfferSource::Workbench, offered(&refs));
        assert_eq!(registry.paths.len(), MAX_STORED_PATHS);
    }

    #[test]
    fn a_full_cache_admits_fresh_results_and_only_evicts_the_oldest_entries() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        let many: Vec<String> = (0..MAX_STORED_PATHS)
            .map(|index| format!("/tmp/file-{index}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        registry.store_for_binding(&scope, PathOfferSource::Workbench, offered(&refs));
        registry.paths.get_mut("handle-42").unwrap().expires_at -= Duration::from_secs(30);
        registry.store_for_binding(
            &scope,
            PathOfferSource::Workbench,
            vec![(
                "fresh-entry".to_owned(),
                RemotePath::new("/tmp/fresh").unwrap(),
            )],
        );
        let now = Instant::now();
        assert_eq!(registry.paths.len(), MAX_STORED_PATHS);
        assert_eq!(
            registry.path(&scope, "fresh-entry", now).unwrap().as_str(),
            "/tmp/fresh"
        );
        assert!(matches!(
            registry.path(&scope, "handle-42", now),
            Err(EmergencyPathApiError::PathStale)
        ));
        assert_eq!(
            registry.path(&scope, "handle-0", now).unwrap().as_str(),
            "/tmp/file-0"
        );
    }

    #[test]
    fn new_results_do_not_extend_old_expiry_or_keep_an_old_target_generation() {
        let before = scope("binding-a", "target-a", 0);
        let after = scope("binding-a", "target-a", 1);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(&before, PathOfferSource::Workbench, offered(&["/tmp/old"]));
        let deadline = registry.paths["handle-0"].expires_at;
        registry.store_for_binding(&before, PathOfferSource::Workbench, Vec::new());
        assert_eq!(registry.paths["handle-0"].expires_at, deadline);
        registry.store_for_binding(
            &after,
            PathOfferSource::Workbench,
            vec![(
                "new-target".to_owned(),
                RemotePath::new("/tmp/new").unwrap(),
            )],
        );
        assert_eq!(registry.paths.len(), 1);
        assert!(matches!(
            registry.path(&before, "handle-0", Instant::now()),
            Err(EmergencyPathApiError::PathStale)
        ));
        assert!(matches!(
            registry.path(&before, "new-target", Instant::now()),
            Err(EmergencyPathApiError::PathStale)
        ));
    }

    #[test]
    fn an_expired_capability_names_nothing() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(&scope, PathOfferSource::Workbench, offered(&["/tmp/.x"]));
        let later = Instant::now() + PATH_TTL + Duration::from_secs(1);
        assert!(matches!(
            registry.path(&scope, "handle-0", later),
            Err(EmergencyPathApiError::PathStale),
        ));
        registry.prune(later);
        assert!(registry.paths.is_empty());
    }

    #[test]
    fn closing_a_binding_takes_its_capabilities_with_it() {
        let mine = scope("binding-a", "target-a", 0);
        let theirs = scope("binding-b", "target-b", 0);
        let mut registry = PathRegistry::default();
        registry.store_for_binding(&mine, PathOfferSource::Workbench, offered(&["/tmp/.x"]));
        registry.store_for_binding(
            &theirs,
            PathOfferSource::Workbench,
            vec![("neighbor".to_owned(), RemotePath::new("/tmp/.y").unwrap())],
        );
        assert_eq!(registry.paths.len(), 2);
        registry.close_binding("binding-a");

        let now = Instant::now();
        assert!(matches!(
            registry.path(&mine, "handle-0", now),
            Err(EmergencyPathApiError::PathStale),
        ));
        // A neighbouring window keeps working.
        assert_eq!(
            registry.path(&theirs, "neighbor", now).unwrap().as_str(),
            "/tmp/.y",
        );
    }

    #[test]
    fn a_capability_is_live_only_for_the_caller_it_was_minted_for() {
        // Plans are held under the same rule as paths, and a plan cannot be
        // built without a live session, so the rule itself is checked here.
        let mine = scope("binding-a", "target-a", 0);
        let now = Instant::now();
        let expires_at = now + PLAN_TTL;

        assert!(still_live(&mine, expires_at, &mine, now));
        // A different window, a reconnected session, and a target that was
        // reactivated under the same name are each a different caller.
        assert!(!still_live(
            &mine,
            expires_at,
            &scope("binding-b", "target-a", 0),
            now
        ));
        assert!(!still_live(
            &mine,
            expires_at,
            &scope("binding-a", "target-b", 0),
            now
        ));
        assert!(!still_live(
            &mine,
            expires_at,
            &scope("binding-a", "target-a", 1),
            now
        ));
        // And an expired capability is nobody's.
        assert!(!still_live(&mine, expires_at, &mine, expires_at));
        assert!(!still_live(
            &mine,
            expires_at,
            &mine,
            expires_at + Duration::from_secs(1)
        ));
    }

    #[test]
    fn disarming_clears_every_way_to_run_a_file_and_nothing_else() {
        // 4755 is the classic planted backdoor: runnable by anyone, and
        // running as root. What is left has to be neither.
        assert_eq!(0o4755 & !EXECUTE_BITS, 0o0644);
        assert_eq!(0o2755 & !EXECUTE_BITS, 0o0644);
        assert_eq!(0o0755 & !EXECUTE_BITS, 0o0644);
        // The sticky bit belongs to directories and means something else.
        assert_eq!(0o1777 & !EXECUTE_BITS, 0o1666);
        // Read and write are untouched, so the file can still be examined.
        assert_eq!(0o0700 & !EXECUTE_BITS, 0o0600);
    }

    #[test]
    fn the_capability_action_round_trips_kebab_case_and_label() {
        let action: EmergencyPathAction = serde_json::from_str("\"remove-capabilities\"").unwrap();
        assert!(matches!(action, EmergencyPathAction::RemoveCapabilities));
        assert_eq!(action.label(), "remove-capabilities");
        // Existing actions keep their wire names.
        assert!(matches!(
            serde_json::from_str::<EmergencyPathAction>("\"disarm\"").unwrap(),
            EmergencyPathAction::Disarm
        ));
        assert!(serde_json::from_str::<EmergencyPathAction>("\"removeCapabilities\"").is_err());
    }

    #[test]
    fn the_restore_action_round_trips_kebab_case_and_label() {
        let action: EmergencyPathAction = serde_json::from_str("\"restore-residue\"").unwrap();
        assert!(matches!(action, EmergencyPathAction::RestoreResidue));
        assert_eq!(action.label(), "restore-residue");
        assert!(serde_json::from_str::<EmergencyPathAction>("\"restoreResidue\"").is_err());
    }

    #[test]
    fn plan_refusals_map_to_their_own_codes_and_nothing_else() {
        for (subject, expected) in [
            (CAPABILITY_TOOLS_REFUSAL, PathRefusal::Tools),
            (CAPABILITY_PRIVILEGE_REFUSAL, PathRefusal::Privilege),
            (CAPABILITY_KIND_REFUSAL, PathRefusal::Kind),
            (CAPABILITY_EMPTY_REFUSAL, PathRefusal::Empty),
        ] {
            let error = CoreError::Validation {
                subject,
                message: "m".to_owned(),
            };
            match capability_plan_failure(&error) {
                EmergencyPathApiError::Refused(found) => {
                    assert!(std::mem::discriminant(&found) == std::mem::discriminant(&expected));
                }
                _ => panic!("{subject} should be a named refusal"),
            }
        }
        // An unrelated validation failure and a non-validation error keep the
        // generic boundary message.
        let other = CoreError::Validation {
            subject: "something else",
            message: "m".to_owned(),
        };
        assert!(matches!(
            capability_plan_failure(&other),
            EmergencyPathApiError::Core
        ));
        let io = CoreError::InvalidOperationState {
            state: "planned",
            action: "confirm",
        };
        assert!(matches!(
            capability_plan_failure(&io),
            EmergencyPathApiError::Core
        ));
    }

    #[test]
    fn restore_refusals_map_to_their_own_codes_and_nothing_else() {
        for (subject, expected) in [
            (RESTORE_TOOLS_REFUSAL, PathRefusal::RestoreTools),
            (RESTORE_PRIVILEGE_REFUSAL, PathRefusal::RestorePrivilege),
            (RESTORE_KIND_REFUSAL, PathRefusal::RestoreKind),
            (RESTORE_LOCATION_REFUSAL, PathRefusal::RestoreLocation),
            (RESTORE_EMPTY_REFUSAL, PathRefusal::RestoreEmpty),
            (RESTORE_AMBIGUOUS_REFUSAL, PathRefusal::RestoreAmbiguous),
        ] {
            let error = CoreError::Validation {
                subject,
                message: "m".to_owned(),
            };
            match restore_plan_failure(&error) {
                EmergencyPathApiError::Refused(found) => {
                    assert!(std::mem::discriminant(&found) == std::mem::discriminant(&expected));
                }
                _ => panic!("{subject} should be a named refusal"),
            }
        }
        // A capability subject does not leak into restore codes, and an
        // unrelated failure keeps the generic message.
        let other = CoreError::Validation {
            subject: CAPABILITY_TOOLS_REFUSAL,
            message: "m".to_owned(),
        };
        assert!(matches!(
            restore_plan_failure(&other),
            EmergencyPathApiError::Core
        ));
        let io = CoreError::InvalidOperationState {
            state: "planned",
            action: "confirm",
        };
        assert!(matches!(
            restore_plan_failure(&io),
            EmergencyPathApiError::Core
        ));
    }

    #[test]
    fn the_delete_lines_action_round_trips_kebab_case_and_label() {
        let action: EmergencyPathAction = serde_json::from_str("\"delete-lines\"").unwrap();
        assert!(matches!(action, EmergencyPathAction::DeleteLines));
        assert_eq!(action.label(), "delete-lines");
        assert!(serde_json::from_str::<EmergencyPathAction>("\"deleteLines\"").is_err());
    }

    #[test]
    fn line_delete_refusals_map_to_their_own_codes_and_nothing_else() {
        for (subject, expected) in [
            (LINE_DELETE_LOCATION_REFUSAL, PathRefusal::LineLocation),
            (LINE_DELETE_KIND_REFUSAL, PathRefusal::LineKind),
            (LINE_DELETE_SIZE_REFUSAL, PathRefusal::LineSize),
            (LINE_DELETE_RANGE_REFUSAL, PathRefusal::LineRange),
            (LINE_DELETE_STALE_REFUSAL, PathRefusal::LineStale),
        ] {
            let error = CoreError::Validation {
                subject,
                message: "m".to_owned(),
            };
            match line_delete_plan_failure(&error) {
                EmergencyPathApiError::Refused(found) => {
                    assert!(std::mem::discriminant(&found) == std::mem::discriminant(&expected));
                }
                _ => panic!("{subject} should be a named refusal"),
            }
        }
        let other = CoreError::Validation {
            subject: CAPABILITY_TOOLS_REFUSAL,
            message: "m".to_owned(),
        };
        assert!(matches!(
            line_delete_plan_failure(&other),
            EmergencyPathApiError::Core
        ));
        let io = CoreError::InvalidOperationState {
            state: "planned",
            action: "confirm",
        };
        assert!(matches!(
            line_delete_plan_failure(&io),
            EmergencyPathApiError::Core
        ));
    }

    #[test]
    fn xinetd_refusals_map_to_their_own_codes_and_nothing_else() {
        for (subject, expected) in [
            (XINETD_LOCATION_REFUSAL, PathRefusal::XinetdLocation),
            (XINETD_KIND_REFUSAL, PathRefusal::XinetdKind),
            (XINETD_IGNORED_REFUSAL, PathRefusal::XinetdIgnored),
            (XINETD_PRIVILEGE_REFUSAL, PathRefusal::XinetdPrivilege),
            (XINETD_TOOLS_REFUSAL, PathRefusal::XinetdTools),
        ] {
            let error = CoreError::Validation {
                subject,
                message: "m".to_owned(),
            };
            match xinetd_plan_failure(&error) {
                EmergencyPathApiError::Refused(found) => {
                    assert!(std::mem::discriminant(&found) == std::mem::discriminant(&expected));
                }
                _ => panic!("{subject} should be a named refusal"),
            }
        }
        let other = CoreError::Validation {
            subject: LINE_DELETE_KIND_REFUSAL,
            message: "m".to_owned(),
        };
        assert!(matches!(
            xinetd_plan_failure(&other),
            EmergencyPathApiError::Core
        ));
    }

    #[test]
    fn the_xinetd_action_round_trips_kebab_case_and_label() {
        let action: EmergencyPathAction =
            serde_json::from_str("\"disable-xinetd-service\"").unwrap();
        assert_eq!(action, EmergencyPathAction::DisableXinetdService);
        assert_eq!(action.label(), "disable-xinetd-service");
    }

    #[test]
    fn a_preview_is_live_only_for_the_binding_and_window_that_made_it() {
        let mine = scope("binding-a", "target-a", 0);
        let theirs = scope("binding-b", "target-a", 0);
        let mut registry = PathRegistry::default();
        let now = Instant::now();
        registry
            .store_preview(StoredPreview {
                scope: mine.clone(),
                preview_handle: "preview-1".to_owned(),
                path_handle: "path-1".to_owned(),
                path: RemotePath::new("/etc/crontab").unwrap(),
                sha256: "a".repeat(64),
                expires_at: now + PLAN_TTL,
            })
            .unwrap();
        assert!(registry.preview(&mine, "preview-1", now).is_ok());
        // Another binding naming the same handle names nothing.
        assert!(matches!(
            registry.preview(&theirs, "preview-1", now),
            Err(EmergencyPathApiError::PlanStale)
        ));
        // An expired preview names nothing either.
        assert!(matches!(
            registry.preview(&mine, "preview-1", now + PLAN_TTL),
            Err(EmergencyPathApiError::PlanStale)
        ));
        // A newer preview for the same binding replaces the first.
        registry
            .store_preview(StoredPreview {
                scope: mine.clone(),
                preview_handle: "preview-2".to_owned(),
                path_handle: "path-2".to_owned(),
                path: RemotePath::new("/etc/profile").unwrap(),
                sha256: "b".repeat(64),
                expires_at: now + PLAN_TTL,
            })
            .unwrap();
        assert!(registry.preview(&mine, "preview-1", now).is_err());
        assert!(registry.preview(&mine, "preview-2", now).is_ok());
        // Closing the binding drops them all.
        registry.close_binding("binding-a");
        assert!(registry.preview(&mine, "preview-2", now).is_err());
    }

    /// A previewable row at this level has no live operation behind it —
    /// the step path that runs one is exercised against a real target in the
    /// lab. `finished` controls whether the row still counts as pending.
    fn batch_item(plan_handle: &str) -> StoredBatchItem {
        StoredBatchItem {
            path_handle: format!("handle-{plan_handle}"),
            path: "/tmp/.planted".to_owned(),
            plan_handle: plan_handle.to_owned(),
            kind: "file".to_owned(),
            size: "12".to_owned(),
            mode: Some("0755".to_owned()),
            executable: true,
            operation: None,
            refusal: None,
            finished: false,
        }
    }

    fn batch(scope: &PathScope, items: Vec<StoredBatchItem>) -> StoredBatch {
        StoredBatch {
            batch_handle: Uuid::new_v4().to_string(),
            scope: scope.clone(),
            action: EmergencyPathAction::Quarantine,
            items,
            confirmed: false,
            expires_at: Instant::now() + PLAN_TTL,
        }
    }

    #[test]
    fn a_batch_request_is_bounded_and_free_of_repeats() {
        assert!(matches!(
            validate_batch_request(&[]),
            Err(EmergencyPathApiError::BatchSize),
        ));
        let over: Vec<String> = (0..=MAX_BATCH_ITEMS).map(|i| format!("h-{i}")).collect();
        assert!(matches!(
            validate_batch_request(&over),
            Err(EmergencyPathApiError::BatchSize),
        ));
        let full: Vec<String> = (0..MAX_BATCH_ITEMS).map(|i| format!("h-{i}")).collect();
        assert!(validate_batch_request(&full).is_ok());
        assert!(matches!(
            validate_batch_request(&["a".to_owned(), "a".to_owned()]),
            Err(EmergencyPathApiError::InvalidHandle),
        ));
        assert!(matches!(
            validate_batch_request(&["a".to_owned(), "x".repeat(129)]),
            Err(EmergencyPathApiError::InvalidHandle),
        ));
        assert!(matches!(
            validate_batch_request(&[String::new()]),
            Err(EmergencyPathApiError::InvalidHandle),
        ));
    }

    #[test]
    fn a_batch_answers_only_the_binding_that_made_it() {
        let mine = scope("binding-a", "target-a", 0);
        let theirs = scope("binding-a", "target-b", 0);
        let mut registry = PathRegistry::default();
        let stored = batch(&mine, vec![batch_item("p1")]);
        let handle = stored.batch_handle.clone();
        registry.store_batch(stored).unwrap();

        let now = Instant::now();
        // Another binding — or the same binding after the target moved on —
        // meets a stale plan, never the items inside it.
        assert!(matches!(
            registry.batch_mut(&theirs, &handle, now),
            Err(EmergencyPathApiError::PlanStale),
        ));
        assert!(matches!(
            registry.batch_mut(&mine, "forged", now),
            Err(EmergencyPathApiError::PlanStale),
        ));
        assert!(registry.batch_mut(&mine, &handle, now).is_ok());
    }

    #[test]
    fn a_new_batch_for_the_binding_walks_away_from_the_old_one() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        let first = batch(&scope, vec![batch_item("p1")]);
        let first_handle = first.batch_handle.clone();
        registry.store_batch(first).unwrap();
        registry
            .store_batch(batch(&scope, vec![batch_item("p2")]))
            .unwrap();
        assert!(matches!(
            registry.batch_mut(&scope, &first_handle, Instant::now()),
            Err(EmergencyPathApiError::PlanStale),
        ));
    }

    #[test]
    fn batch_counts_keep_refused_rows_visible_and_pending_rows_counted() {
        let scope = scope("binding-a", "target-a", 0);
        let mut refused = StoredBatchItem::refused("stale-handle", String::new(), "path-stale");
        assert!(refused.finished);
        refused.refusal = Some("path-stale");
        let stored = batch(&scope, vec![batch_item("p1"), refused, batch_item("p2")]);
        assert_eq!(stored.pending_count(), 2);
        // Refused rows finished before the batch began; without a live
        // operation they do not count as pending work.
        assert_eq!(stored.refused_count(), 1);
    }

    #[test]
    fn closing_the_binding_takes_its_batches_with_it() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        let stored = batch(&scope, vec![batch_item("p1")]);
        let handle = stored.batch_handle.clone();
        registry.store_batch(stored).unwrap();
        registry.close_binding("binding-a");
        assert!(matches!(
            registry.batch_mut(&scope, &handle, Instant::now()),
            Err(EmergencyPathApiError::PlanStale),
        ));
    }

    #[test]
    fn an_expired_batch_prunes_like_a_plan() {
        let scope = scope("binding-a", "target-a", 0);
        let mut registry = PathRegistry::default();
        let mut stored = batch(&scope, vec![batch_item("p1")]);
        stored.expires_at = Instant::now() - Duration::from_secs(1);
        registry.store_batch(stored).unwrap();
        registry.prune(Instant::now());
        assert!(registry.batches.is_empty());
    }

    #[test]
    fn undo_after_verification_keeps_failed_restores_closed_and_isolations_open() {
        // A verified change is undoable either way.
        assert!(undoable_after_verification(true, true, true));
        assert!(undoable_after_verification(true, false, true));
        // Failed verification on a restoring action already put the file
        // back: offering undo would act on the restored original.
        assert!(!undoable_after_verification(false, true, true));
        // Failed verification on an action that keeps the file isolated is
        // exactly when the operator needs undo.
        assert!(undoable_after_verification(false, false, true));
        // Nothing is ever undoable when the operation has no undo.
        assert!(!undoable_after_verification(true, false, false));
        assert!(!undoable_after_verification(false, false, false));
    }
}
