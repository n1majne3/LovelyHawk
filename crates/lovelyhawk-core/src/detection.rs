//! Target-bound quick-detection planning and execution.
//!
//! Detection commands are private, static templates selected by a closed enum.
//! Callers can select modules and limits, but cannot supply shell text. The disk
//! benchmark is the sole bounded write probe and cleans its random temporary file.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::baseline::{BaselineChangeRequest, BaselineReloadPolicy};
use crate::sftp::{RemotePath, SftpMutation};
use crate::ssh::{BoundSshSession, SshCommandOutput, SshService};
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult, PortableStore};

pub const MAX_FINDINGS_PER_MODULE: usize = 1_000;
pub const MAX_DETECTION_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RAW_TEXT_CHARS: usize = 256 * 1024;
pub const MAX_DETECTION_EVENT_CAPACITY: usize = 256;
pub const DETECTION_REPORT_EXPORT_SCHEMA: &str = "lovelyres-detection-report/v1";
const STANDARD_CONCURRENCY: usize = 3;
const DETECTION_HISTORY_VERSION: u32 = 1;
const DETECTION_HISTORY_LIMIT: usize = 64;
const DETECTION_HISTORY_RAW_CHARS: usize = 8 * 1024;
const WEBSHELL_NOT_APPLICABLE: &str = "LOVELYRES_WEB_ROOT_NOT_APPLICABLE_V1";
const DISK_TEST_NOT_APPLICABLE: &str = "LOVELYRES_DISK_TEST_NOT_APPLICABLE_V1";
const NETWORK_TEST_NOT_APPLICABLE: &str = "LOVELYRES_NETWORK_TEST_NOT_APPLICABLE_V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectionKind {
    #[serde(rename = "port-scan")]
    PortScan,
    #[serde(rename = "user-audit")]
    UserAudit,
    #[serde(rename = "backdoor-scan")]
    BackdoorScan,
    #[serde(rename = "process-analysis")]
    ProcessAnalysis,
    #[serde(rename = "file-permission")]
    FilePermission,
    #[serde(rename = "ssh-audit")]
    SshAudit,
    #[serde(rename = "firewall-check")]
    FirewallCheck,
    #[serde(rename = "log-analysis")]
    LogAnalysis,
    #[serde(rename = "webshell-scan")]
    WebshellScan,
    #[serde(rename = "cpu-test")]
    CpuTest,
    #[serde(rename = "memory-test")]
    MemoryTest,
    #[serde(rename = "disk-test")]
    DiskTest,
    #[serde(rename = "network-test")]
    NetworkTest,
}

impl DetectionKind {
    pub const ALL: [Self; 13] = [
        Self::PortScan,
        Self::UserAudit,
        Self::BackdoorScan,
        Self::ProcessAnalysis,
        Self::FilePermission,
        Self::SshAudit,
        Self::FirewallCheck,
        Self::LogAnalysis,
        Self::WebshellScan,
        Self::CpuTest,
        Self::MemoryTest,
        Self::DiskTest,
        Self::NetworkTest,
    ];

    pub const COMPETITION_TRIAGE: [Self; 6] = [
        Self::BackdoorScan,
        Self::ProcessAnalysis,
        Self::UserAudit,
        Self::WebshellScan,
        Self::PortScan,
        Self::SshAudit,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::PortScan => "port-scan",
            Self::UserAudit => "user-audit",
            Self::BackdoorScan => "backdoor-scan",
            Self::ProcessAnalysis => "process-analysis",
            Self::FilePermission => "file-permission",
            Self::SshAudit => "ssh-audit",
            Self::FirewallCheck => "firewall-check",
            Self::LogAnalysis => "log-analysis",
            Self::WebshellScan => "webshell-scan",
            Self::CpuTest => "cpu-test",
            Self::MemoryTest => "memory-test",
            Self::DiskTest => "disk-test",
            Self::NetworkTest => "network-test",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::PortScan => "端口安全扫描",
            Self::UserAudit => "用户权限审计",
            Self::BackdoorScan => "后门与持久化",
            Self::ProcessAnalysis => "可疑进程分析",
            Self::FilePermission => "文件权限检测",
            Self::SshAudit => "SSH 安全审计",
            Self::FirewallCheck => "防火墙检查",
            Self::LogAnalysis => "日志分析",
            Self::WebshellScan => "WebShell 扫描",
            Self::CpuTest => "CPU 性能测试",
            Self::MemoryTest => "内存性能测试",
            Self::DiskTest => "磁盘 I/O 测试",
            Self::NetworkTest => "网络延迟测试",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::PortScan => "检测监听端口和常见高风险服务",
            Self::UserAudit => "检查 UID 0、交互账号和空密码账号",
            Self::BackdoorScan => "检查可疑 cron、自启动文件和授权密钥数量",
            Self::ProcessAnalysis => "检查异常启动位置、反弹 Shell 特征和高资源进程",
            Self::FilePermission => "检查 SUID 文件与关键系统文件权限",
            Self::SshAudit => "检查 root 登录、密码认证、认证尝试次数和默认端口",
            Self::FirewallCheck => "检查防火墙状态和全网放行规则",
            Self::LogAnalysis => "统计 SSH 失败认证并列出近期登录记录",
            Self::WebshellScan => "在站点目录查找脚本特征、图片马、配置后门与隐藏脚本",
            Self::CpuTest => "采样 CPU 核心数、频率与一秒平均使用率",
            Self::MemoryTest => "读取总内存、可用内存与当前使用率",
            Self::DiskTest => "用随机临时文件执行并清理 100 MiB 读写探测",
            Self::NetworkTest => "从远端测试固定探针的真实往返延迟，不伪造带宽",
        }
    }

    pub const fn category(self) -> DetectionCategory {
        match self {
            Self::WebshellScan => DetectionCategory::Competition,
            Self::CpuTest | Self::MemoryTest | Self::DiskTest | Self::NetworkTest => {
                DetectionCategory::Performance
            }
            _ => DetectionCategory::Security,
        }
    }
}

impl fmt::Display for DetectionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionCategory {
    Security,
    Competition,
    Performance,
}

impl DetectionCategory {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Security => "安全",
            Self::Competition => "竞赛",
            Self::Performance => "性能",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionScanProfile {
    Selected,
    CompetitionTriage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionScanRequest {
    profile: DetectionScanProfile,
    modules: Vec<DetectionKind>,
    max_findings: usize,
}

impl DetectionScanRequest {
    pub fn selected(modules: impl IntoIterator<Item = DetectionKind>) -> CoreResult<Self> {
        let request = Self {
            profile: DetectionScanProfile::Selected,
            modules: modules.into_iter().collect(),
            max_findings: 200,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn competition_triage() -> Self {
        Self {
            profile: DetectionScanProfile::CompetitionTriage,
            modules: DetectionKind::COMPETITION_TRIAGE.to_vec(),
            max_findings: 200,
        }
    }

    pub fn with_max_findings(mut self, max_findings: usize) -> CoreResult<Self> {
        self.max_findings = max_findings;
        self.validate()?;
        Ok(self)
    }

    pub const fn profile(&self) -> DetectionScanProfile {
        self.profile
    }

    pub fn modules(&self) -> &[DetectionKind] {
        &self.modules
    }

    pub const fn max_findings(&self) -> usize {
        self.max_findings
    }

    fn validate(&self) -> CoreResult<()> {
        if self.modules.is_empty() || self.modules.len() > DetectionKind::ALL.len() {
            return Err(CoreError::validation(
                "detection module selection",
                format!("must contain 1..={} modules", DetectionKind::ALL.len()),
            ));
        }
        let mut modules = self.modules.clone();
        modules.sort_unstable();
        modules.dedup();
        if modules.len() != self.modules.len() {
            return Err(CoreError::validation(
                "detection module selection",
                "duplicate module ids are not allowed",
            ));
        }
        if !(1..=MAX_FINDINGS_PER_MODULE).contains(&self.max_findings) {
            return Err(CoreError::validation(
                "detection finding limit",
                format!("must be 1..={MAX_FINDINGS_PER_MODULE}"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DetectionScanPlan {
    id: String,
    target: TargetGuard,
    profile: DetectionScanProfile,
    modules: Vec<DetectionKind>,
    max_findings: usize,
    concurrency: usize,
}

impl DetectionScanPlan {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub const fn profile(&self) -> DetectionScanProfile {
        self.profile
    }

    pub fn modules(&self) -> &[DetectionKind] {
        &self.modules
    }

    pub const fn max_findings(&self) -> usize {
        self.max_findings
    }

    pub const fn concurrency(&self) -> usize {
        self.concurrency
    }

    pub fn summary(&self) -> String {
        format!(
            "目标 {}@{} · {} 个封闭检测模块 · 并发上限 {} · 每模块最多 {} 项",
            self.target.identity.as_str(),
            self.target.generation,
            self.modules.len(),
            self.concurrency,
            self.max_findings
        )
    }
}

#[derive(Clone, Default)]
pub struct DetectionCancellation {
    inner: Arc<DetectionCancellationInner>,
}

#[derive(Debug, Default)]
struct DetectionCancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl fmt::Debug for DetectionCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectionCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl DetectionCancellation {
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.inner.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionOutcome {
    Passed,
    Failed,
    NotApplicable,
    Error,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectionFinding {
    pub title: String,
    pub description: String,
    pub severity: DetectionSeverity,
    pub recommendation: Option<String>,
    #[serde(default)]
    pub remediation: Option<DetectionRemediation>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SensitiveSystemFile {
    Passwd,
    Shadow,
    Sudoers,
}

impl SensitiveSystemFile {
    pub const fn path(self) -> &'static str {
        match self {
            Self::Passwd => "/etc/passwd",
            Self::Shadow => "/etc/shadow",
            Self::Sudoers => "/etc/sudoers",
        }
    }

    pub const fn secure_mode(self) -> u32 {
        match self {
            Self::Passwd => 0o644,
            Self::Shadow => 0o640,
            Self::Sudoers => 0o440,
        }
    }
}

/// Closed remediations offered by typed detection findings. No shell text or
/// caller-provided path crosses this boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionRemediation {
    DisableSshRootLogin,
    DisableSshPasswordAuthentication,
    LimitSshAuthenticationAttempts,
    RepairSensitiveFilePermissions {
        file: SensitiveSystemFile,
        expected_mode: u32,
    },
}

#[derive(Debug, Clone)]
pub enum DetectionRemediationRequest {
    Baseline {
        request: BaselineChangeRequest,
        reload_policy: BaselineReloadPolicy,
    },
    Sftp(SftpMutation),
}

impl DetectionRemediation {
    pub const SSH_ONLY: [Self; 3] = [
        Self::DisableSshRootLogin,
        Self::DisableSshPasswordAuthentication,
        Self::LimitSshAuthenticationAttempts,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::DisableSshRootLogin => "禁止 SSH root 直接登录",
            Self::DisableSshPasswordAuthentication => "关闭 SSH 密码认证",
            Self::LimitSshAuthenticationAttempts => "限制 SSH 认证尝试次数",
            Self::RepairSensitiveFilePermissions { file, .. } => match file {
                SensitiveSystemFile::Passwd => "修复 /etc/passwd 权限",
                SensitiveSystemFile::Shadow => "修复 /etc/shadow 权限",
                SensitiveSystemFile::Sudoers => "修复 /etc/sudoers 权限",
            },
        }
    }

    pub const fn explanation(self) -> &'static str {
        match self {
            Self::DisableSshRootLogin => "设置 PermitRootLogin no",
            Self::DisableSshPasswordAuthentication => {
                "设置 PasswordAuthentication no；执行前请确认密钥登录可用"
            }
            Self::LimitSshAuthenticationAttempts => "设置 MaxAuthTries 4",
            Self::RepairSensitiveFilePermissions {
                file,
                expected_mode: _,
            } => match file {
                SensitiveSystemFile::Passwd => "仅在权限仍与检测结果一致时设置为 0644",
                SensitiveSystemFile::Shadow => "仅在权限仍与检测结果一致时设置为 0640",
                SensitiveSystemFile::Sudoers => "仅在权限仍与检测结果一致时设置为 0440",
            },
        }
    }

    pub fn baseline_request(self) -> CoreResult<BaselineChangeRequest> {
        let item_id = match self {
            Self::DisableSshRootLogin => "ssh-permit-root-login",
            Self::DisableSshPasswordAuthentication => "ssh-password-authentication",
            Self::LimitSshAuthenticationAttempts => "ssh-max-auth-tries",
            Self::RepairSensitiveFilePermissions { .. } => {
                return Err(CoreError::validation(
                    "detection remediation",
                    "file permission remediation is not a baseline change",
                ));
            }
        };
        BaselineChangeRequest::recommended(item_id)
    }

    pub const fn reload_policy(self) -> BaselineReloadPolicy {
        BaselineReloadPolicy::ApplyNow
    }

    pub fn request(self) -> CoreResult<DetectionRemediationRequest> {
        match self {
            Self::DisableSshRootLogin
            | Self::DisableSshPasswordAuthentication
            | Self::LimitSshAuthenticationAttempts => Ok(DetectionRemediationRequest::Baseline {
                request: self.baseline_request()?,
                reload_policy: self.reload_policy(),
            }),
            Self::RepairSensitiveFilePermissions {
                file,
                expected_mode,
            } => Ok(DetectionRemediationRequest::Sftp(
                SftpMutation::ChmodIfMode {
                    path: RemotePath::new(file.path())?,
                    expected_mode,
                    mode: file.secure_mode(),
                },
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectionModuleReport {
    pub kind: DetectionKind,
    pub outcome: DetectionOutcome,
    pub score: u8,
    pub findings: Vec<DetectionFinding>,
    pub raw_text: String,
    pub raw_text_truncated: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectionSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub failed_modules: usize,
    pub not_applicable_modules: usize,
    pub error_modules: usize,
    pub cancelled_modules: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionScanStatus {
    Completed,
    Partial,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectionScanReport {
    pub id: String,
    pub target: TargetGuard,
    pub profile: DetectionScanProfile,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub status: DetectionScanStatus,
    pub overall_score: u8,
    pub modules: Vec<DetectionModuleReport>,
    pub summary: DetectionSummary,
    pub dropped_progress_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DetectionHistoryDocument {
    version: u32,
    reports: Vec<DetectionScanReport>,
}

impl Default for DetectionHistoryDocument {
    fn default() -> Self {
        Self {
            version: DETECTION_HISTORY_VERSION,
            reports: Vec::new(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetectionReportExport<'a> {
    schema: &'static str,
    report: &'a DetectionScanReport,
}

pub fn detection_report_json(report: &DetectionScanReport) -> CoreResult<String> {
    serde_json::to_string_pretty(&DetectionReportExport {
        schema: DETECTION_REPORT_EXPORT_SCHEMA,
        report,
    })
    .map_err(|source| CoreError::Encode {
        subject: "detection report export",
        source,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DetectionScanEvent {
    ModuleStarted {
        scan_id: String,
        module: DetectionKind,
        ordinal: usize,
        total: usize,
    },
    ModuleFinished {
        scan_id: String,
        module: DetectionKind,
        outcome: DetectionOutcome,
        completed: usize,
        total: usize,
    },
    ScanFinished {
        scan_id: String,
        status: DetectionScanStatus,
        total: usize,
    },
}

#[derive(Debug, Clone)]
pub struct DetectionEventSender {
    sender: async_channel::Sender<DetectionScanEvent>,
    dropped: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub struct DetectionEventReceiver {
    receiver: async_channel::Receiver<DetectionScanEvent>,
}

pub fn detection_event_channel(
    capacity: usize,
) -> CoreResult<(DetectionEventSender, DetectionEventReceiver)> {
    if capacity == 0 || capacity > MAX_DETECTION_EVENT_CAPACITY {
        return Err(CoreError::validation(
            "detection event capacity",
            format!("must be 1..={MAX_DETECTION_EVENT_CAPACITY}"),
        ));
    }
    let (sender, receiver) = async_channel::bounded(capacity);
    Ok((
        DetectionEventSender {
            sender,
            dropped: Arc::new(AtomicUsize::new(0)),
        },
        DetectionEventReceiver { receiver },
    ))
}

impl DetectionEventSender {
    fn emit(&self, event: DetectionScanEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl DetectionEventReceiver {
    pub async fn recv(&self) -> Option<DetectionScanEvent> {
        self.receiver.recv().await.ok()
    }

    pub fn try_recv(&self) -> Option<DetectionScanEvent> {
        self.receiver.try_recv().ok()
    }
}

#[derive(Debug, Clone)]
pub struct DetectionService {
    ssh: SshService,
    target: Arc<TargetContext>,
    store: PortableStore,
    history_lock: Arc<Mutex<()>>,
}

impl DetectionService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>, store: PortableStore) -> Self {
        Self {
            ssh,
            target,
            store,
            history_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn history_for_target(&self, target: &TargetGuard) -> CoreResult<Vec<DetectionScanReport>> {
        self.target.validate(target)?;
        let _guard = self.history_lock.lock();
        let document = self.read_history()?;
        Ok(document
            .reports
            .into_iter()
            .filter(|report| report.target == *target)
            .collect())
    }

    fn persist_report(&self, report: &DetectionScanReport) -> CoreResult<()> {
        self.target.validate(&report.target)?;
        let _guard = self.history_lock.lock();
        let mut document = self.read_history()?;
        document.reports.retain(|stored| stored.id != report.id);
        document
            .reports
            .insert(0, compact_detection_history(report));
        document.reports.truncate(DETECTION_HISTORY_LIMIT);
        self.store.write(StoreFile::DetectionHistory, &document)
    }

    fn read_history(&self) -> CoreResult<DetectionHistoryDocument> {
        let document: DetectionHistoryDocument = self
            .store
            .read(StoreFile::DetectionHistory)?
            .unwrap_or_default();
        if document.version != DETECTION_HISTORY_VERSION {
            return Err(CoreError::UnsupportedSchema {
                document: "detection history",
                expected: DETECTION_HISTORY_VERSION,
                actual: document.version,
            });
        }
        Ok(document)
    }

    pub fn plan_scan(
        &self,
        session: &BoundSshSession,
        request: DetectionScanRequest,
    ) -> CoreResult<DetectionScanPlan> {
        self.target.validate(session.target())?;
        request.validate()?;
        Ok(DetectionScanPlan {
            id: Uuid::new_v4().to_string(),
            target: session.target().clone(),
            profile: request.profile,
            modules: request.modules,
            max_findings: request.max_findings,
            concurrency: STANDARD_CONCURRENCY,
        })
    }

    pub async fn run_scan(
        &self,
        session: &BoundSshSession,
        plan: DetectionScanPlan,
        cancellation: DetectionCancellation,
        events: DetectionEventSender,
    ) -> CoreResult<DetectionScanReport> {
        self.ensure_binding(session, &plan)?;
        let runner = SshDetectionRunner {
            ssh: &self.ssh,
            session,
        };
        self.run_scan_with_runner(&runner, plan, cancellation, events)
            .await
    }

    fn ensure_binding(
        &self,
        session: &BoundSshSession,
        plan: &DetectionScanPlan,
    ) -> CoreResult<()> {
        self.target.validate(session.target())?;
        if plan.target != *session.target() {
            return Err(CoreError::validation(
                "detection scan target",
                "scan plan is not bound to this SSH target epoch",
            ));
        }
        Ok(())
    }

    async fn run_scan_with_runner<R: DetectionRemoteRunner + Sync>(
        &self,
        runner: &R,
        plan: DetectionScanPlan,
        cancellation: DetectionCancellation,
        events: DetectionEventSender,
    ) -> CoreResult<DetectionScanReport> {
        self.target.validate(&plan.target)?;
        let started_at = Utc::now();
        let started = Instant::now();
        let total = plan.modules.len();
        let completed = Arc::new(AtomicUsize::new(0));
        let scan_id = plan.id.clone();
        let target = plan.target.clone();
        let max_findings = plan.max_findings;

        let work = stream::iter(plan.modules.iter().copied().enumerate()).map(|(index, kind)| {
            let cancellation = cancellation.clone();
            let events = events.clone();
            let completed = completed.clone();
            let scan_id = scan_id.clone();
            let target = target.clone();
            async move {
                self.target.validate(&target)?;
                events.emit(DetectionScanEvent::ModuleStarted {
                    scan_id: scan_id.clone(),
                    module: kind,
                    ordinal: index + 1,
                    total,
                });
                let module_started = Instant::now();
                let report = if cancellation.is_cancelled() {
                    cancelled_module(kind, module_started.elapsed())
                } else {
                    let command = command_for(kind);
                    let remote = tokio::select! {
                        _ = cancellation.cancelled() => None,
                        result = runner.run(command, timeout_for(kind)) => Some(result),
                    };
                    match remote {
                        None => cancelled_module(kind, module_started.elapsed()),
                        Some(Ok(output)) => {
                            self.target.validate(&target)?;
                            match parse_module(kind, &output, max_findings) {
                                Ok(mut report) => {
                                    report.duration_ms = elapsed_millis(module_started.elapsed());
                                    report
                                }
                                Err(error) => error_module(kind, error, module_started.elapsed()),
                            }
                        }
                        Some(Err(error)) if matches!(error, CoreError::TargetChanged { .. }) => {
                            return Err(error);
                        }
                        Some(Err(error)) => error_module(kind, error, module_started.elapsed()),
                    }
                };
                let done = completed.fetch_add(1, Ordering::AcqRel) + 1;
                events.emit(DetectionScanEvent::ModuleFinished {
                    scan_id,
                    module: kind,
                    outcome: report.outcome,
                    completed: done,
                    total,
                });
                Ok((index, report))
            }
        });

        let mut modules: Vec<(usize, DetectionModuleReport)> = work
            .buffer_unordered(plan.concurrency)
            .try_collect()
            .await?;
        self.target.validate(&plan.target)?;
        modules.sort_by_key(|(index, _)| *index);
        let modules: Vec<_> = modules.into_iter().map(|(_, report)| report).collect();
        let summary = summarize(&modules);
        let status = if cancellation.is_cancelled() || summary.cancelled_modules > 0 {
            DetectionScanStatus::Cancelled
        } else if summary.error_modules > 0 {
            DetectionScanStatus::Partial
        } else {
            DetectionScanStatus::Completed
        };
        let mut report = DetectionScanReport {
            id: plan.id,
            target: plan.target,
            profile: plan.profile,
            started_at,
            duration_ms: elapsed_millis(started.elapsed()),
            status,
            overall_score: overall_score(&modules),
            modules,
            summary,
            dropped_progress_events: 0,
        };
        self.persist_report(&report)?;
        events.emit(DetectionScanEvent::ScanFinished {
            scan_id: report.id.clone(),
            status,
            total,
        });
        report.dropped_progress_events = events.dropped_count();
        Ok(report)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteDetectionOutput {
    text: String,
}

#[async_trait]
trait DetectionRemoteRunner {
    async fn run(
        &self,
        command: &'static str,
        timeout: Duration,
    ) -> CoreResult<RemoteDetectionOutput>;
}

#[derive(Debug)]
struct SshDetectionRunner<'a> {
    ssh: &'a SshService,
    session: &'a BoundSshSession,
}

#[async_trait]
impl DetectionRemoteRunner for SshDetectionRunner<'_> {
    async fn run(
        &self,
        command: &'static str,
        timeout: Duration,
    ) -> CoreResult<RemoteDetectionOutput> {
        let output = self
            .ssh
            .execute_bound(self.session, command.to_owned(), timeout)
            .await?;
        remote_output(output)
    }
}

fn remote_output(output: SshCommandOutput) -> CoreResult<RemoteDetectionOutput> {
    if output.timed_out {
        return Err(CoreError::validation(
            "detection command",
            "remote command timed out",
        ));
    }
    if output.exit_code != Some(0) {
        return Err(CoreError::validation(
            "detection command",
            format!("remote command exited with {:?}", output.exit_code),
        ));
    }
    bounded_remote_output(output.output)
}

fn bounded_remote_output(text: String) -> CoreResult<RemoteDetectionOutput> {
    if text.len() > MAX_DETECTION_OUTPUT_BYTES {
        return Err(CoreError::validation(
            "detection output",
            format!("exceeds the {MAX_DETECTION_OUTPUT_BYTES}-byte limit"),
        ));
    }
    Ok(RemoteDetectionOutput { text })
}

/// Remote program for the webshell module. It emits the collector contract so
/// the output is directly displayable in the command workbench, where each
/// `关注：<path> | …` line names exactly one file and is offered as a path
/// action, while the parser can still separate hits from coverage and gaps:
/// `# 站点根：<dir>` marks each discovered web root,
/// `# 站点 <root>：候选 <listed>，已检查 <scanned>` records per-root coverage,
/// `关注：<path> | <kindzh>，第 <line> 行：<excerpt>` is one match (kindzh is
/// 代码特征, 图片标记 or 配置指令; `关注：<path> | 隐藏脚本` marks a hidden
/// script by name alone), `缺口：<text>` marks a partial gap, and
/// `# 扫描未执行：<text>` means the scan could not run at all. A `|` inside an
/// excerpt is rewritten so the ` | ` delimiter stays unique per line.
/// Everything else in the stream is untrusted and ignored.
pub(crate) const WEBSHELL_SCAN_COMMAND: &str = r#"LC_ALL=C; export LC_ALL
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH; export PATH
printf 'LOVELYRES_WEBSHELL_V2\n'
if ! command -v find >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then printf '# 扫描未执行：find 或 awk 不可用\nLOVELYRES_WEBSHELL_END_V2\n'; exit 0; fi
lh_roots=''
lh_add_root() {
  case "$1" in /*) ;; *) return 0;; esac
  [ -d "$1" ] || return 0
  for lh_p in $lh_roots; do
    [ "$lh_p" = "$1" ] && return 0
    case "$1" in "$lh_p"/*) return 0;; esac
  done
  lh_roots="$lh_roots $1"
  printf '# 站点根：%s\n' "$1"
}
lh_roots_from_conf() {
  awk '{
    line = $0
    sub(/[[:space:]]*#.*$/, "", line)
    p = ""
    if (line ~ /^[[:space:]]*root[[:space:]]+[^[:space:]]/) p = $2
    else if (line ~ /^[[:space:]]*[Dd]ocument[Rr]oot[[:space:]]+/) p = $2
    else if (match(line, /docBase="[^"]+"/)) p = substr(line, RSTART + 9, RLENGTH - 10)
    if (p != "") { gsub(/^"|"$|;$/, "", p); if (p ~ /^\//) print p }
  }'
}
for lh_r in /var/www /usr/share/nginx /srv/www /srv/http /var/www/*/html /var/www/*/public_html /var/www/*/htdocs /home/*/public_html /home/*/www /usr/local/apache2/htdocs /usr/local/nginx/html /opt/tomcat*/webapps /usr/share/tomcat*/webapps /var/lib/tomcat*/webapps /usr/local/tomcat*/webapps /opt/*/webapps /usr/local/openresty/nginx/html; do lh_add_root "$lh_r"; done
lh_conf=0
for lh_c in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* /etc/nginx/vhosts.d/* /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/vhost/*.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /etc/apache2/sites-available/*.conf /usr/local/apache2/conf/httpd.conf /usr/local/apache2/conf/extra/*.conf /etc/tomcat*/conf/server.xml /etc/tomcat*/server.xml /usr/share/tomcat*/conf/server.xml /var/lib/tomcat*/conf/server.xml /opt/tomcat*/conf/server.xml; do
  [ -f "$lh_c" ] || continue
  lh_conf=1
  for lh_p in $(lh_roots_from_conf < "$lh_c" 2>/dev/null); do lh_add_root "$lh_p"; done
done
if command -v nginx >/dev/null 2>&1; then
  lh_conf=1
  for lh_p in $(nginx -T 2>&1 | lh_roots_from_conf 2>/dev/null); do lh_add_root "$lh_p"; done
fi
[ "$lh_conf" = 1 ] && printf '# 已结合 Web 服务配置文件推导站点目录\n'
if [ -z "$lh_roots" ]; then printf '# 未发现站点目录，未执行扫描\nLOVELYRES_WEB_ROOT_NOT_APPLICABLE_V1\nLOVELYRES_WEBSHELL_END_V2\n'; exit 0; fi
lh_n=0
for lh_root in $lh_roots; do
  lh_n=$((lh_n + 1))
  if [ "$lh_n" -gt 12 ]; then printf '缺口：站点目录超过 12 个，其余未扫描\n'; break; fi
  if [ ! -r "$lh_root" ] || [ ! -x "$lh_root" ]; then printf '缺口：站点目录不可读，未扫描：%s\n' "$lh_root"; continue; fi
  find "$lh_root" -xdev -type f -size -2048k \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.pht' -o -name '*.phar' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp' -o -name '*.aspx' -o -name '*.asa' -o -name '*.cer' -o -name '*.ashx' -o -name '*.jpg' -o -name '*.jpeg' -o -name '*.png' -o -name '*.gif' -o -name '.htaccess' -o -name '.user.ini' \) -exec printf '%s\036' {} + 2>/dev/null | awk -v root="$lh_root" '
BEGIN {
  gsub(/[[:cntrl:]]/, "?", root)
  # \036 (RS) as the record delimiter: BusyBox awk cannot split on NUL.
  RS = sprintf("%c", 30)
  emitted = 0
  scanned = 0
  listed = 0
  hid = 0
  unread = 0
  capped = 0
}
{
  listed++
  path = $0
  b = path
  sub(/^.*\//, "", b)
  tl = tolower(b)
  kind = ""
  if (tl ~ /\.(php|php[0-9]|phtml|pht|phar|jsp|jspx|asp|aspx|asa|cer|ashx)$/) kind = "signature"
  else if (tl ~ /\.(jpg|jpeg|png|gif)$/) kind = "image"
  else if (tl == ".htaccess" || tl == ".user.ini") kind = "config"
  if (tl ~ /^\./ && kind == "signature") {
    if (hid < 40) {
      p = path
      gsub(/[[:cntrl:]]/, "?", p)
      printf "关注：%s | 隐藏脚本\n", p
    }
    hid++
    if (hid == 41) printf "缺口：%s：隐藏脚本记录超过 40 条，其余未列出\n", root
  }
  if (kind == "") next
  if (scanned >= 6000) { capped = 1; next }
  scanned++
  ln = 0
  nhits = 0
  rc = 0
  RS = "\n"
  while (nhits < 4) {
    rc = getline line < path
    if (rc <= 0) break
    ln++
    m = 0
    rst = 1
    if (kind == "signature") {
      m = match(line, /eval[[:space:]]*\(|assert[[:space:]]*\(|base64_decode[[:space:]]*\(|Runtime\.getRuntime|ProcessBuilder|WScript\.Shell|system[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|popen[[:space:]]*\(|exec[[:space:]]*\(|proc_open[[:space:]]*\(|pcntl_exec[[:space:]]*\(|call_user_func(_array)?[[:space:]]*\(|create_function[[:space:]]*\(|preg_replace[[:space:]]*\([^)]*\/e[[:alnum:]]*[^[:alnum:]]|dl[[:space:]]*\(|(gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|hex2bin|strrev)[[:space:]]*\(|(base64_decode|urldecode|rawurldecode)[[:space:]]*\([^)]*(gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|hex2bin|strrev|urldecode|rawurldecode|base64_decode)[[:space:]]*\(|(include|require)(_once)?[[:space:]]*\(?[[:space:]]*[$]_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)|[$]_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)[[:space:]]*\[[^]]*\][[:space:]]*\(|CreateObject[[:space:]]*\(|Server\.CreateObject|ProcessStartInfo|Process\.Start[[:space:]]*\(|[[:alnum:]\/+=]{120,}/)
      rst = RSTART
    } else if (kind == "image") {
      m = match(line, /<\?php|<\?=|<\?[[:alpha:]]|<%/)
      rst = RSTART
    } else if (kind == "config") {
      if (line ~ /^[[:space:]]*(AddType|AddHandler|SetHandler|php_value|php_admin_value|php_flag|php_admin_flag|auto_prepend_file|auto_append_file)[[:space:]=]/ && line ~ /php|x-httpd|auto_(prepend|append)_file/) m = 1
    }
    if (m) {
      nhits++
      s = substr(line, (rst > 40 ? rst - 20 : 1), 140)
      gsub(/[[:cntrl:]]/, "?", s)
      gsub(/\|/, "/", s)
      p = path
      gsub(/[[:cntrl:]]/, "?", p)
      kz = (kind == "image" ? "图片标记" : (kind == "config" ? "配置指令" : "代码特征"))
      if (emitted < 300) {
        emitted++
        printf "关注：%s | %s，第 %d 行：%s\n", p, kz, ln, s
      } else if (emitted == 300) {
        emitted++
        printf "缺口：%s：命中记录超过 300 条，其余未列出\n", root
      }
    }
  }
  close(path)
  RS = sprintf("%c", 30)
  if (rc < 0 && ln == 0 && unread < 40) {
    unread++
    p = path
    gsub(/[[:cntrl:]]/, "?", p)
    printf "缺口：文件不可读，未检查：%s\n", p
  }
}
END {
  printf "%s %s：候选 %d，已检查 %d\n", sprintf("%c 站点", 35), root, listed, scanned
  if (capped) printf "缺口：%s：候选文件超过 6000 个，其余未检查\n", root
  if (unread >= 40) printf "缺口：%s：不可读文件超过 40 个，其余未列出\n", root
}'
done
printf 'LOVELYRES_WEBSHELL_END_V2\n'
exit 0
"#;

fn command_for(kind: DetectionKind) -> &'static str {
    match kind {
        DetectionKind::PortScan => "ss -H -lntup 2>/dev/null || netstat -tlnup 2>/dev/null",
        DetectionKind::UserAudit => {
            "cat /etc/passwd; printf '\\nLOVELYRES_EMPTY_PASSWORDS_V1\\n'; if [ \"$(id -u)\" -eq 0 ]; then cat /etc/shadow; elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then sudo -n cat /etc/shadow; fi | awk -F: '$2 == \"\" {print $1}'"
        }
        DetectionKind::BackdoorScan => {
            "(crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; cat /etc/cron.d/* 2>/dev/null) | grep -Ev '^[[:space:]]*(#|$)' | grep -E '(curl|wget|nc|ncat|bash|python|/dev/tcp)' || true; printf '\\nLOVELYRES_AUTOSTART_V1\\n'; find /etc/init.d /etc/systemd/system -maxdepth 2 -type f 2>/dev/null | head -n 1000; printf '\\nLOVELYRES_KEY_COUNT_V1\\n'; find /home /root -name authorized_keys -type f -exec awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' {} + 2>/dev/null"
        }
        DetectionKind::ProcessAnalysis => "ps auxww 2>/dev/null | head -n 5000",
        DetectionKind::FilePermission => {
            "find / -xdev -perm -4000 -type f 2>/dev/null | head -n 1000; printf '\\nLOVELYRES_SENSITIVE_FILES_V1\\n'; stat -c '%A|%a|%n' /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null"
        }
        DetectionKind::SshAudit => {
            "sshd -T 2>/dev/null || sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' /etc/ssh/sshd_config 2>/dev/null"
        }
        DetectionKind::FirewallCheck => {
            "if command -v nft >/dev/null 2>&1; then echo active; elif command -v iptables >/dev/null 2>&1; then echo active; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state 2>/dev/null; else echo inactive; fi; printf '\\nLOVELYRES_FIREWALL_RULES_V1\\n'; iptables -S 2>/dev/null || nft list ruleset 2>/dev/null || firewall-cmd --list-all 2>/dev/null"
        }
        DetectionKind::LogAnalysis => {
            r#"LC_ALL=C; export LC_ALL; printf 'LOVELYRES_LOG_ANALYSIS_V1\n'; attempts=$(grep -is 'failed password' /var/log/auth.log /var/log/secure 2>/dev/null | wc -l); printf 'ATTEMPTS\t%s\n' "$attempts"; printf 'LOVELYRES_LOG_FAILURES_V1\n'; grep -is 'failed password' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 5; printf 'LOVELYRES_LOG_LOGINS_V1\n'; last -10 2>/dev/null | grep -v 'wtmp begins' | head -n 5 || true"#
        }
        DetectionKind::WebshellScan => WEBSHELL_SCAN_COMMAND,
        DetectionKind::CpuTest => {
            r#"LC_ALL=C; export LC_ALL; cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || awk '/^processor[[:space:]]*:/{count++} END {print count+0}' /proc/cpuinfo 2>/dev/null); frequency=$(awk -F: '/cpu MHz/{gsub(/[[:space:]]/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null); first=$(awk '/^cpu /{idle=$5+$6; total=0; for (i=2; i<=NF; i++) total+=$i; printf "%.0f %.0f", total, idle; exit}' /proc/stat 2>/dev/null); sleep 1; second=$(awk '/^cpu /{idle=$5+$6; total=0; for (i=2; i<=NF; i++) total+=$i; printf "%.0f %.0f", total, idle; exit}' /proc/stat 2>/dev/null); usage=$(awk -v first="$first" -v second="$second" 'BEGIN {split(first,a," "); split(second,b," "); delta=b[1]-a[1]; idle=b[2]-a[2]; if (delta>0) printf "%.2f", 100*(delta-idle)/delta}' 2>/dev/null); printf 'LOVELYRES_CPU_TEST_V1\nCORES\t%s\nFREQUENCY_MHZ\t%s\nUSAGE_PERCENT\t%s\n' "$cores" "$frequency" "$usage""#
        }
        DetectionKind::MemoryTest => {
            r#"LC_ALL=C; export LC_ALL; printf 'LOVELYRES_MEMORY_TEST_V1\n'; awk '/^MemTotal:/{total=$2} /^MemAvailable:/{available=$2} /^MemFree:/{free=$2} /^Buffers:/{buffers=$2} /^Cached:/{cached=$2} END {if (available==0) available=free+buffers+cached; printf "TOTAL_KIB\t%.0f\nAVAILABLE_KIB\t%.0f\n", total, available}' /proc/meminfo 2>/dev/null"#
        }
        DetectionKind::DiskTest => {
            r#"LC_ALL=C; export LC_ALL; if ! command -v mktemp >/dev/null 2>&1 || ! command -v dd >/dev/null 2>&1; then printf 'LOVELYRES_DISK_TEST_NOT_APPLICABLE_V1\n'; exit 0; fi; tmp=$(mktemp /tmp/lovelyres-disk-test.XXXXXX 2>/dev/null) || { printf 'LOVELYRES_DISK_TEST_NOT_APPLICABLE_V1\n'; exit 0; }; trap 'rm -f "$tmp"' EXIT HUP INT TERM; write_result=$(dd if=/dev/zero of="$tmp" bs=1M count=100 conv=fsync 2>&1) || { printf 'LOVELYRES_DISK_TEST_NOT_APPLICABLE_V1\n'; exit 0; }; read_result=$(dd if="$tmp" of=/dev/null bs=1M 2>&1) || { printf 'LOVELYRES_DISK_TEST_NOT_APPLICABLE_V1\n'; exit 0; }; printf 'LOVELYRES_DISK_TEST_V1\nWRITE\t%s\nREAD\t%s\n' "$(printf '%s\n' "$write_result" | tail -n 1)" "$(printf '%s\n' "$read_result" | tail -n 1)""#
        }
        DetectionKind::NetworkTest => {
            r#"LC_ALL=C; export LC_ALL; if ! command -v ping >/dev/null 2>&1; then printf 'LOVELYRES_NETWORK_TEST_NOT_APPLICABLE_V1\n'; exit 0; fi; ping_result=$(ping -c 3 -W 3 8.8.8.8 2>/dev/null) || { printf 'LOVELYRES_NETWORK_TEST_NOT_APPLICABLE_V1\n'; exit 0; }; latency=$(printf '%s\n' "$ping_result" | awk -F= '/min\/avg\/max/ {split($2,a,"/"); gsub(/[[:space:]]/,"",a[2]); print a[2]; exit}'); if [ -z "$latency" ]; then printf 'LOVELYRES_NETWORK_TEST_NOT_APPLICABLE_V1\n'; exit 0; fi; printf 'LOVELYRES_NETWORK_TEST_V1\nDESTINATION\t8.8.8.8\nLATENCY_MS\t%s\n' "$latency""#
        }
    }
}

const fn timeout_for(kind: DetectionKind) -> Duration {
    match kind {
        DetectionKind::BackdoorScan | DetectionKind::FilePermission => Duration::from_secs(45),
        DetectionKind::WebshellScan => Duration::from_secs(60),
        DetectionKind::DiskTest => Duration::from_secs(120),
        _ => Duration::from_secs(20),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "result", rename_all = "kebab-case")]
enum TypedDetectionResult {
    PortScan(PortScanResult),
    UserAudit(UserAuditResult),
    ProcessAnalysis(ProcessAnalysisResult),
    SshAudit(SshAuditResult),
    FirewallCheck(FirewallCheckResult),
    BackdoorScan(BackdoorScanResult),
    FilePermission(FilePermissionResult),
    WebshellScan(WebshellScanResult),
    LogAnalysis(LogAnalysisResult),
    CpuTest(CpuTestResult),
    MemoryTest(MemoryTestResult),
    DiskTest(DiskTestResult),
    NetworkTest(NetworkTestResult),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PortInfo {
    port: u16,
    service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PortScanResult {
    open_ports: Vec<PortInfo>,
    total_scanned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UserInfo {
    username: String,
    uid: u32,
    gid: u32,
    shell: String,
    home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UserAuditResult {
    root_users: Vec<UserInfo>,
    empty_password_users: Vec<String>,
    interactive_users: Vec<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ProcessInfo {
    pid: u32,
    name: String,
    user: String,
    cpu_percent: f32,
    memory_percent: f32,
    command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ProcessAnalysisResult {
    suspicious_processes: Vec<ProcessInfo>,
    high_resource_processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SshAuditResult {
    permit_root_login: bool,
    password_authentication: bool,
    max_auth_tries: Option<u32>,
    default_port: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FirewallCheckResult {
    firewall_active: bool,
    risky_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BackdoorScanResult {
    suspicious_cron: Vec<String>,
    suspicious_autostart: Vec<String>,
    authorized_key_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FilePermissionResult {
    suid_files: Vec<String>,
    sensitive_file_issues: Vec<SensitiveFileIssue>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct SensitiveFileIssue {
    file: SensitiveSystemFile,
    observed_mode: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum WebshellLevel {
    Suspect,
    Confirmed,
}

impl WebshellLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Suspect => "疑似",
            Self::Confirmed => "确证",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum WebshellHitKind {
    Signature,
    Image,
    Config,
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WebshellEvidence {
    kind: WebshellHitKind,
    feature: String,
    level: WebshellLevel,
    severity: DetectionSeverity,
    line: Option<u32>,
    excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WebshellFileHit {
    path: String,
    evidences: Vec<WebshellEvidence>,
}

impl WebshellFileHit {
    fn top(&self) -> &WebshellEvidence {
        self.evidences
            .iter()
            .max_by_key(|evidence| (evidence.level, evidence.severity))
            .expect("a webshell file hit always carries evidence")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct WebshellScanResult {
    not_applicable: bool,
    roots: Vec<String>,
    files: Vec<WebshellFileHit>,
    notes: Vec<String>,
    listed_candidates: usize,
    scanned_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LogAnalysisResult {
    brute_force_attempts: u32,
    brute_force_details: Vec<String>,
    recent_logins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct CpuTestResult {
    cores: u32,
    frequency_mhz: Option<f64>,
    usage_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct MemoryTestResult {
    total_mib: f64,
    available_mib: f64,
    usage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct DiskTestResult {
    not_applicable: bool,
    read_mib_per_second: Option<f64>,
    write_mib_per_second: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct NetworkTestResult {
    not_applicable: bool,
    destination: Option<String>,
    latency_ms: Option<f64>,
}

fn parse_module(
    kind: DetectionKind,
    output: &RemoteDetectionOutput,
    limit: usize,
) -> CoreResult<DetectionModuleReport> {
    let typed = match kind {
        DetectionKind::PortScan => TypedDetectionResult::PortScan(parse_ports(&output.text, limit)),
        DetectionKind::UserAudit => {
            TypedDetectionResult::UserAudit(parse_users(&output.text, limit)?)
        }
        DetectionKind::BackdoorScan => {
            TypedDetectionResult::BackdoorScan(parse_backdoors(&output.text, limit)?)
        }
        DetectionKind::ProcessAnalysis => {
            TypedDetectionResult::ProcessAnalysis(parse_processes(&output.text, limit))
        }
        DetectionKind::FilePermission => {
            TypedDetectionResult::FilePermission(parse_file_permissions(&output.text, limit)?)
        }
        DetectionKind::SshAudit => TypedDetectionResult::SshAudit(parse_ssh(&output.text)),
        DetectionKind::FirewallCheck => {
            TypedDetectionResult::FirewallCheck(parse_firewall(&output.text, limit)?)
        }
        DetectionKind::WebshellScan => {
            TypedDetectionResult::WebshellScan(parse_webshell(&output.text, limit)?)
        }
        DetectionKind::LogAnalysis => {
            TypedDetectionResult::LogAnalysis(parse_log_analysis(&output.text, limit)?)
        }
        DetectionKind::CpuTest => TypedDetectionResult::CpuTest(parse_cpu_test(&output.text)?),
        DetectionKind::MemoryTest => {
            TypedDetectionResult::MemoryTest(parse_memory_test(&output.text)?)
        }
        DetectionKind::DiskTest => TypedDetectionResult::DiskTest(parse_disk_test(&output.text)?),
        DetectionKind::NetworkTest => {
            TypedDetectionResult::NetworkTest(parse_network_test(&output.text)?)
        }
    };
    evaluate(kind, typed, &output.text)
}

fn parse_ports(output: &str, limit: usize) -> PortScanResult {
    let mut open_ports = Vec::new();
    for line in output.lines().take(10_000) {
        if let Some(port) = extract_port(line) {
            open_ports.push(PortInfo {
                port,
                service: identify_service(port).map(str::to_owned),
            });
        }
    }
    open_ports.sort_by_key(|entry| entry.port);
    open_ports.dedup_by_key(|entry| entry.port);
    let total_scanned = open_ports.len();
    open_ports.truncate(limit);
    PortScanResult {
        open_ports,
        total_scanned,
    }
}

fn extract_port(line: &str) -> Option<u16> {
    line.split_whitespace().find_map(|field| {
        let field = field.trim_matches(|character| matches!(character, '[' | ']'));
        field
            .rsplit_once(':')
            .and_then(|(_, port)| port.trim_end_matches(',').parse::<u16>().ok())
    })
}

fn identify_service(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("SSH"),
        80 | 8080 => Some("HTTP"),
        443 => Some("HTTPS"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        27017 => Some("MongoDB"),
        9200 => Some("Elasticsearch"),
        _ => None,
    }
}

fn parse_users(output: &str, limit: usize) -> CoreResult<UserAuditResult> {
    const MARKER: &str = "LOVELYRES_EMPTY_PASSWORDS_V1";
    let (passwd, empty_passwords) = output
        .split_once(MARKER)
        .ok_or_else(|| CoreError::validation("user audit output", "missing section marker"))?;
    let mut root_users = Vec::new();
    let mut interactive_users = Vec::new();
    for line in passwd.lines().take(100_000) {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (fields[2].parse::<u32>(), fields[3].parse::<u32>()) else {
            continue;
        };
        let user = UserInfo {
            username: bounded_line(fields[0], 128),
            uid,
            gid,
            home: bounded_line(fields[5], 1_024),
            shell: bounded_line(fields[6], 1_024),
        };
        if uid == 0 {
            root_users.push(user.clone());
        }
        if (1_000..60_000).contains(&uid) && !user.shell.ends_with("nologin") {
            interactive_users.push(user);
        }
    }
    root_users.truncate(limit);
    interactive_users.truncate(limit);
    let empty_password_users = empty_passwords
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && line.len() <= 32
                && line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .take(limit)
        .map(str::to_owned)
        .collect();
    Ok(UserAuditResult {
        root_users,
        empty_password_users,
        interactive_users,
    })
}

fn parse_processes(output: &str, limit: usize) -> ProcessAnalysisResult {
    let mut suspicious_processes = Vec::new();
    let mut high_resource_processes = Vec::new();
    for line in output.lines().skip(1).take(5_000) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 11 {
            continue;
        }
        let process = ProcessInfo {
            user: bounded_line(fields[0], 128),
            pid: fields[1].parse().unwrap_or_default(),
            cpu_percent: finite_percent(fields[2]),
            memory_percent: finite_percent(fields[3]),
            name: bounded_line(fields[10], 512),
            command: bounded_line(&fields[10..].join(" "), 2_048),
        };
        if process.cpu_percent > 50.0 || process.memory_percent > 50.0 {
            high_resource_processes.push(process.clone());
        }
        if process.command.contains("(deleted)")
            || process.command.starts_with("/tmp/")
            || process.command.starts_with("/dev/shm/")
            || process.command.starts_with("/var/tmp/")
            || process.command.contains("bash -i")
            || process.command.contains("/dev/tcp")
            || process.command.contains("/dev/udp")
        {
            suspicious_processes.push(process);
        }
    }
    suspicious_processes.truncate(limit);
    high_resource_processes.truncate(limit);
    ProcessAnalysisResult {
        suspicious_processes,
        high_resource_processes,
    }
}

fn finite_percent(value: &str) -> f32 {
    value
        .parse::<f32>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or_default()
}

fn parse_ssh(output: &str) -> SshAuditResult {
    let mut permit_root_login = false;
    let mut password_authentication = true;
    let mut max_auth_tries = None;
    let mut default_port = true;
    for line in output.lines().take(10_000) {
        let lower = line.trim().to_ascii_lowercase();
        if lower.starts_with("permitrootlogin") && lower.ends_with("yes") {
            permit_root_login = true;
        }
        if lower.starts_with("passwordauthentication") && lower.ends_with("no") {
            password_authentication = false;
        }
        let mut fields = lower.split_whitespace();
        if fields.next() == Some("maxauthtries") {
            max_auth_tries = fields
                .next()
                .filter(|_| fields.next().is_none())
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value <= 100);
        }
        if let Some(value) = lower.strip_prefix("port ") {
            default_port = value.trim() == "22";
        }
    }
    SshAuditResult {
        permit_root_login,
        password_authentication,
        max_auth_tries,
        default_port,
    }
}

fn parse_firewall(output: &str, limit: usize) -> CoreResult<FirewallCheckResult> {
    const MARKER: &str = "LOVELYRES_FIREWALL_RULES_V1";
    let (status, rules) = output
        .split_once(MARKER)
        .ok_or_else(|| CoreError::validation("firewall output", "missing section marker"))?;
    let risky_rules = rules
        .lines()
        .filter(|line| {
            (line.contains("ACCEPT") || line.contains(" accept"))
                && (line.contains("0.0.0.0/0") || line.contains("::/0"))
        })
        .take(limit)
        .map(|line| bounded_line(line, 2_048))
        .collect();
    Ok(FirewallCheckResult {
        firewall_active: status.lines().any(|line| line.trim() == "active"),
        risky_rules,
    })
}

fn parse_backdoors(output: &str, limit: usize) -> CoreResult<BackdoorScanResult> {
    const AUTOSTART: &str = "LOVELYRES_AUTOSTART_V1";
    const KEY_COUNT: &str = "LOVELYRES_KEY_COUNT_V1";
    let (cron, rest) = output.split_once(AUTOSTART).ok_or_else(|| {
        CoreError::validation("backdoor audit output", "missing autostart marker")
    })?;
    let (autostart, key_count) = rest.split_once(KEY_COUNT).ok_or_else(|| {
        CoreError::validation("backdoor audit output", "missing key-count marker")
    })?;
    Ok(BackdoorScanResult {
        suspicious_cron: bounded_lines(cron, limit),
        suspicious_autostart: bounded_lines(autostart, limit),
        authorized_key_count: key_count
            .lines()
            .filter_map(|line| line.trim().parse::<usize>().ok())
            .fold(0usize, usize::saturating_add)
            .min(1_000_000),
    })
}

fn parse_file_permissions(output: &str, limit: usize) -> CoreResult<FilePermissionResult> {
    const MARKER: &str = "LOVELYRES_SENSITIVE_FILES_V1";
    let (suid, sensitive) = output.split_once(MARKER).ok_or_else(|| {
        CoreError::validation("permission audit output", "missing section marker")
    })?;
    let mut sensitive_file_issues = Vec::new();
    for line in sensitive.lines().take(100) {
        let fields: Vec<_> = line.trim().split('|').collect();
        if fields.len() != 3 {
            continue;
        }
        let mode_text = fields[1];
        if mode_text.is_empty()
            || mode_text.len() > 4
            || !mode_text.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
        {
            continue;
        }
        let Ok(observed_mode) = u32::from_str_radix(mode_text, 8) else {
            continue;
        };
        let file = match fields[2] {
            "/etc/passwd" => SensitiveSystemFile::Passwd,
            "/etc/shadow" => SensitiveSystemFile::Shadow,
            "/etc/sudoers" => SensitiveSystemFile::Sudoers,
            _ => continue,
        };
        let insecure = match file {
            SensitiveSystemFile::Shadow => !matches!(observed_mode, 0o000 | 0o400 | 0o600 | 0o640),
            SensitiveSystemFile::Passwd | SensitiveSystemFile::Sudoers => {
                observed_mode & 0o022 != 0
            }
        };
        if insecure
            && !sensitive_file_issues
                .iter()
                .any(|issue: &SensitiveFileIssue| issue.file == file)
        {
            sensitive_file_issues.push(SensitiveFileIssue {
                file,
                observed_mode,
            });
        }
    }
    sensitive_file_issues.truncate(limit);
    Ok(FilePermissionResult {
        suid_files: bounded_lines(suid, limit),
        sensitive_file_issues,
    })
}

const WEBSHELL_END_MARKER: &str = "LOVELYRES_WEBSHELL_END_V2";

struct WebshellLineRule {
    kind: WebshellHitKind,
    pattern: Regex,
    feature: &'static str,
    level: WebshellLevel,
    severity: DetectionSeverity,
}

/// Ordered line rules: the first matching rule grades an emitted excerpt.
/// Confirmed entries keep the previous five signatures and add direct
/// request-parameter code execution; suspected entries are looser variants
/// that always require manual review.
fn webshell_line_rules() -> &'static [WebshellLineRule] {
    static RULES: OnceLock<Vec<WebshellLineRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut rules = Vec::new();
        let mut rule = |kind, pattern, feature, level, severity| {
            rules.push(WebshellLineRule {
                kind,
                pattern: Regex::new(pattern).expect("static webshell pattern compiles"),
                feature,
                level,
                severity,
            });
        };
        use DetectionSeverity::{Critical, High, Medium};
        use WebshellHitKind::{Config, Image, Signature};
        use WebshellLevel::{Confirmed, Suspect};
        rule(
            Signature,
            r"(?i)(eval|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV)",
            "请求参数进入 eval/assert 执行",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"(?i)(system|shell_exec|passthru|popen|exec|proc_open|pcntl_exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV)",
            "请求参数进入命令执行函数",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"(?i)(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|strrev|urldecode|rawurldecode|hex2bin)",
            "解码结果进入 eval/assert",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"(?i)\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV)\s*\[[^\]]*\]\s*\(",
            "请求参数驱动的可变函数调用",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"(?i)(include|require)(_once)?\s*\(?\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV)",
            "请求参数控制文件包含",
            Confirmed,
            Critical,
        );
        rule(Signature, r"(?i)eval\s*\(", "eval 代码执行", Confirmed, Critical);
        rule(
            Signature,
            r"(?i)base64_decode\s*\(",
            "base64_decode 解码",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"Runtime\.getRuntime|ProcessBuilder",
            "Java 进程执行",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"(?i)WScript\.Shell",
            "WScript.Shell 组件调用",
            Confirmed,
            Critical,
        );
        rule(
            Signature,
            r"(?i)call_user_func(_array)?\s*\([^)]*\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV)",
            "call_user_func 与请求参数同现",
            Suspect,
            High,
        );
        rule(
            Signature,
            r#"(?i)preg_replace\s*\([^)]*["'][^"']*/e[[:alnum:]]*["']"#,
            "preg_replace /e 修饰符",
            Suspect,
            High,
        );
        rule(
            Signature,
            r"(?i)create_function\s*\(",
            "create_function 动态函数",
            Suspect,
            High,
        );
        rule(
            Signature,
            r"(?i)(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|hex2bin|strrev|urldecode|rawurldecode)\s*\([^)]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|hex2bin|strrev|urldecode|rawurldecode)\s*\(",
            "多层解码函数链",
            Suspect,
            High,
        );
        rule(
            Signature,
            r"(?i)(gzinflate|gzuncompress|gzdecode|str_rot13|openssl_decrypt|hex2bin|strrev|urldecode|rawurldecode)\s*\(",
            "可疑解码或混淆函数",
            Suspect,
            Medium,
        );
        rule(
            Signature,
            r"[[:alnum:]/+=]{120,}",
            "超长高熵字符串（疑似编码载荷）",
            Suspect,
            Medium,
        );
        rule(
            Signature,
            r"(?i)(system|shell_exec|passthru|popen|exec|proc_open|pcntl_exec|call_user_func(_array)?|assert|dl)\s*\(",
            "执行类函数调用（需核对参数来源）",
            Suspect,
            Medium,
        );
        rule(
            Signature,
            r"(?i)(CreateObject|ProcessStartInfo|Process\.Start|Server\.CreateObject)",
            "组件或进程创建调用",
            Suspect,
            Medium,
        );
        rule(
            Image,
            r"<\?php|<\?=|<\?[[:alpha:]]",
            "图片文件内嵌脚本标记",
            Confirmed,
            Critical,
        );
        rule(
            Config,
            r"(?i)auto_(prepend|append)_file",
            "PHP 自动前置/附加文件指令",
            Confirmed,
            Critical,
        );
        rule(
            Config,
            r"(?i)(AddType|AddHandler|SetHandler)\s+[^\s]*(x-httpd|php[0-9]-?script|php-fcgi|php-cgi|lsapi)",
            "PHP 处理器映射指令",
            Confirmed,
            Critical,
        );
        rules
    })
}

fn classify_webshell_hit(
    kind: WebshellHitKind,
    excerpt: &str,
) -> (&'static str, WebshellLevel, DetectionSeverity) {
    for rule in webshell_line_rules() {
        if rule.kind == kind && rule.pattern.is_match(excerpt) {
            return (rule.feature, rule.level, rule.severity);
        }
    }
    match kind {
        WebshellHitKind::Signature => (
            "可疑代码特征",
            WebshellLevel::Suspect,
            DetectionSeverity::Medium,
        ),
        WebshellHitKind::Image => (
            "图片文件内嵌可疑标记（需排除巧合）",
            WebshellLevel::Suspect,
            DetectionSeverity::Medium,
        ),
        WebshellHitKind::Config => (
            "PHP 相关配置指令",
            WebshellLevel::Suspect,
            DetectionSeverity::Medium,
        ),
        WebshellHitKind::Hidden => (
            "Web 目录内隐藏脚本文件",
            WebshellLevel::Suspect,
            DetectionSeverity::Medium,
        ),
    }
}

fn parse_webshell_hit(
    line: &str,
    files: &mut BTreeMap<String, Vec<WebshellEvidence>>,
) -> Result<(), ()> {
    // `关注：<path> | <kindzh>，第 <line> 行：<excerpt>` or the hidden-script
    // variant `关注：<path> | 隐藏脚本`. The ` | ` split takes the last
    // delimiter, matching how the path offer reads the same displayed line.
    let Some(record) = line.strip_prefix("关注：") else {
        return Err(());
    };
    let Some((raw_path, detail)) = record.rsplit_once(" | ") else {
        return Err(());
    };
    let path = bounded_line(raw_path, 1_024);
    if path.is_empty() {
        return Err(());
    }
    let (kind, line_field, excerpt) = if detail == "隐藏脚本" {
        (WebshellHitKind::Hidden, "", "")
    } else {
        let Some((kind_zh, rest)) = detail.split_once('，') else {
            return Err(());
        };
        let kind = match kind_zh {
            "代码特征" => WebshellHitKind::Signature,
            "图片标记" => WebshellHitKind::Image,
            "配置指令" => WebshellHitKind::Config,
            _ => return Err(()),
        };
        let Some(rest) = rest.strip_prefix("第 ") else {
            return Err(());
        };
        let Some((number, excerpt)) = rest.split_once(" 行：") else {
            return Err(());
        };
        (kind, number, excerpt)
    };
    let (feature, level, severity) = classify_webshell_hit(kind, excerpt);
    let evidence = WebshellEvidence {
        kind,
        feature: feature.to_owned(),
        level,
        severity,
        line: line_field.parse::<u32>().ok(),
        excerpt: bounded_line(excerpt, 200),
    };
    let entries = files.entry(path).or_default();
    if entries.len() < 6
        && !entries.iter().any(|existing| {
            existing.kind == evidence.kind
                && existing.line == evidence.line
                && existing.feature == evidence.feature
        })
    {
        entries.push(evidence);
    }
    Ok(())
}

fn parse_webshell(output: &str, limit: usize) -> CoreResult<WebshellScanResult> {
    let mut result = WebshellScanResult::default();
    let mut by_path: BTreeMap<String, Vec<WebshellEvidence>> = BTreeMap::new();
    let mut end_seen = false;
    let mut malformed = 0usize;
    for raw_line in output.lines().take(200_000) {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with("LOVELYRES_") {
            if line == WEBSHELL_NOT_APPLICABLE {
                result.not_applicable = true;
            }
            if line == WEBSHELL_END_MARKER {
                end_seen = true;
            }
            continue;
        }
        if let Some(record) = line.strip_prefix("# 站点根：") {
            if result.roots.len() < limit {
                result.roots.push(bounded_line(record, 1_024));
            }
            continue;
        }
        if let Some(record) = line.strip_prefix("# 站点 ") {
            if let Some((root, counts)) = record.split_once("：候选 ")
                && let Some((listed, scanned)) = counts.split_once("，已检查 ")
            {
                let _ = root;
                result.listed_candidates = result
                    .listed_candidates
                    .saturating_add(listed.parse::<usize>().unwrap_or(0).min(1_000_000));
                result.scanned_files = result
                    .scanned_files
                    .saturating_add(scanned.parse::<usize>().unwrap_or(0).min(1_000_000));
            }
            continue;
        }
        if let Some(record) = line.strip_prefix("# 扫描未执行：") {
            return Err(CoreError::validation(
                "webshell scan output",
                bounded_line(record, 256),
            ));
        }
        if line.starts_with("# ") {
            continue;
        }
        if let Some(record) = line.strip_prefix("缺口：") {
            if result.notes.len() < limit {
                result.notes.push(bounded_line(record, 512));
            }
            continue;
        }
        if line.starts_with("关注：") {
            if parse_webshell_hit(line, &mut by_path).is_err() {
                malformed += 1;
            }
            continue;
        }
        malformed += 1;
    }
    if result.not_applicable {
        return Ok(result);
    }
    if result.roots.is_empty() {
        return Err(CoreError::validation(
            "webshell scan output",
            "no scan records present",
        ));
    }
    if !end_seen {
        result
            .notes
            .push("输出未完整返回，结果可能不完整".to_owned());
    }
    if malformed > 0 {
        result
            .notes
            .push(format!("{malformed} 条输出记录无法解析，已跳过"));
    }
    let mut files: Vec<WebshellFileHit> = by_path
        .into_iter()
        .map(|(path, evidences)| WebshellFileHit { path, evidences })
        .collect();
    files.sort_by(|left, right| {
        let rank = |file: &WebshellFileHit| (file.top().level, file.top().severity);
        rank(right)
            .cmp(&rank(left))
            .then_with(|| left.path.cmp(&right.path))
    });
    files.truncate(limit);
    result.files = files;
    Ok(result)
}

fn parse_log_analysis(output: &str, limit: usize) -> CoreResult<LogAnalysisResult> {
    const HEADER: &str = "LOVELYRES_LOG_ANALYSIS_V1";
    const FAILURES: &str = "LOVELYRES_LOG_FAILURES_V1";
    const LOGINS: &str = "LOVELYRES_LOG_LOGINS_V1";
    let body = after_marker(output, HEADER, "log analysis output")?;
    let (attempts, rest) = body.split_once(FAILURES).ok_or_else(|| {
        CoreError::validation(
            "log analysis output",
            "missing failed-authentication marker",
        )
    })?;
    let (details, logins) = rest.split_once(LOGINS).ok_or_else(|| {
        CoreError::validation("log analysis output", "missing recent-login marker")
    })?;
    let attempts = tab_value(attempts, "ATTEMPTS")
        .ok_or_else(|| CoreError::validation("log analysis output", "missing attempt count"))?
        .parse::<u32>()
        .map_err(|_| CoreError::validation("log analysis output", "invalid attempt count"))?;
    Ok(LogAnalysisResult {
        brute_force_attempts: attempts,
        brute_force_details: bounded_lines(details, limit),
        recent_logins: bounded_lines(logins, limit.min(5)),
    })
}

fn parse_cpu_test(output: &str) -> CoreResult<CpuTestResult> {
    let body = after_marker(output, "LOVELYRES_CPU_TEST_V1", "CPU test output")?;
    let cores = tab_value(body, "CORES")
        .ok_or_else(|| CoreError::validation("CPU test output", "missing core count"))?
        .parse::<u32>()
        .ok()
        .filter(|cores| (1..=1_048_576).contains(cores))
        .ok_or_else(|| CoreError::validation("CPU test output", "invalid core count"))?;
    Ok(CpuTestResult {
        cores,
        frequency_mhz: optional_finite_metric(
            "CPU frequency",
            tab_value(body, "FREQUENCY_MHZ").unwrap_or_default(),
            0.0,
            100_000.0,
        )?,
        usage_percent: optional_finite_metric(
            "CPU usage",
            tab_value(body, "USAGE_PERCENT").unwrap_or_default(),
            0.0,
            100.0,
        )?,
    })
}

fn parse_memory_test(output: &str) -> CoreResult<MemoryTestResult> {
    let body = after_marker(output, "LOVELYRES_MEMORY_TEST_V1", "memory test output")?;
    let total_kib = tab_value(body, "TOTAL_KIB")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| CoreError::validation("memory test output", "invalid total memory"))?;
    let available_kib = tab_value(body, "AVAILABLE_KIB")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value <= total_kib)
        .ok_or_else(|| CoreError::validation("memory test output", "invalid available memory"))?;
    Ok(MemoryTestResult {
        total_mib: total_kib as f64 / 1_024.0,
        available_mib: available_kib as f64 / 1_024.0,
        usage_percent: (total_kib - available_kib) as f64 * 100.0 / total_kib as f64,
    })
}

fn parse_disk_test(output: &str) -> CoreResult<DiskTestResult> {
    if output
        .lines()
        .any(|line| line.trim() == DISK_TEST_NOT_APPLICABLE)
    {
        return Ok(DiskTestResult {
            not_applicable: true,
            read_mib_per_second: None,
            write_mib_per_second: None,
        });
    }
    let body = after_marker(output, "LOVELYRES_DISK_TEST_V1", "disk test output")?;
    let write = tab_value(body, "WRITE")
        .and_then(parse_dd_rate_mib)
        .ok_or_else(|| CoreError::validation("disk test output", "invalid write rate"))?;
    let read = tab_value(body, "READ")
        .and_then(parse_dd_rate_mib)
        .ok_or_else(|| CoreError::validation("disk test output", "invalid read rate"))?;
    Ok(DiskTestResult {
        not_applicable: false,
        read_mib_per_second: Some(read),
        write_mib_per_second: Some(write),
    })
}

fn parse_network_test(output: &str) -> CoreResult<NetworkTestResult> {
    if output
        .lines()
        .any(|line| line.trim() == NETWORK_TEST_NOT_APPLICABLE)
    {
        return Ok(NetworkTestResult {
            not_applicable: true,
            destination: None,
            latency_ms: None,
        });
    }
    let body = after_marker(output, "LOVELYRES_NETWORK_TEST_V1", "network test output")?;
    let destination = tab_value(body, "DESTINATION")
        .filter(|value| *value == "8.8.8.8")
        .ok_or_else(|| CoreError::validation("network test output", "invalid destination"))?;
    let latency_ms = optional_finite_metric(
        "network latency",
        tab_value(body, "LATENCY_MS").unwrap_or_default(),
        0.0,
        60_000.0,
    )?
    .ok_or_else(|| CoreError::validation("network test output", "missing latency"))?;
    Ok(NetworkTestResult {
        not_applicable: false,
        destination: Some(destination.to_owned()),
        latency_ms: Some(latency_ms),
    })
}

fn after_marker<'a>(output: &'a str, marker: &str, subject: &'static str) -> CoreResult<&'a str> {
    output
        .strip_prefix(marker)
        .map(|body| body.trim_start_matches(['\r', '\n']))
        .ok_or_else(|| CoreError::validation(subject, "missing version marker"))
}

fn tab_value<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('\t'))
            .map(str::trim)
    })
}

fn optional_finite_metric(
    subject: &'static str,
    value: &str,
    minimum: f64,
    maximum: f64,
) -> CoreResult<Option<f64>> {
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= minimum && *value <= maximum)
        .map(Some)
        .ok_or_else(|| CoreError::validation(subject, "metric is outside the accepted range"))
}

fn parse_dd_rate_mib(line: &str) -> Option<f64> {
    let fields: Vec<_> = line.split_whitespace().collect();
    for (index, field) in fields.iter().enumerate().rev() {
        let field = field.trim_matches(|character| matches!(character, ',' | '(' | ')'));
        if !field.ends_with("/s") {
            continue;
        }
        let first_unit = field.find(|character: char| character.is_ascii_alphabetic());
        let (value, unit) = match first_unit {
            Some(0) if index > 0 => (fields[index - 1], field),
            Some(offset) => field.split_at(offset),
            _ => continue,
        };
        let value = value
            .trim_matches(|character| matches!(character, ',' | '(' | ')'))
            .parse::<f64>()
            .ok()?;
        let multiplier = match unit.to_ascii_lowercase().as_str() {
            "b/s" => 1.0 / 1_048_576.0,
            "kb/s" => 1_000.0 / 1_048_576.0,
            "kib/s" => 1.0 / 1_024.0,
            "mb/s" => 1_000_000.0 / 1_048_576.0,
            "mib/s" => 1.0,
            "gb/s" => 1_000_000_000.0 / 1_048_576.0,
            "gib/s" => 1_024.0,
            "tb/s" => 1_000_000_000_000.0 / 1_048_576.0,
            "tib/s" => 1_048_576.0,
            _ => return None,
        };
        let rate = value * multiplier;
        return (rate.is_finite() && rate > 0.0 && rate <= 1_000_000_000.0).then_some(rate);
    }
    None
}

fn evaluate(
    kind: DetectionKind,
    result: TypedDetectionResult,
    raw: &str,
) -> CoreResult<DetectionModuleReport> {
    let mut findings = Vec::new();
    let not_applicable = match result {
        TypedDetectionResult::PortScan(result) => {
            for port in result.open_ports {
                if is_high_risk_port(port.port) {
                    findings.push(finding(
                        DetectionSeverity::High,
                        format!("高风险端口开放：{}", port.port),
                        format!(
                            "端口 {}（{}）处于监听状态",
                            port.port,
                            port.service.as_deref().unwrap_or("未知服务")
                        ),
                        "确认服务来源并限制暴露范围",
                    ));
                }
            }
            false
        }
        TypedDetectionResult::UserAudit(result) => {
            if result.root_users.len() > 1 {
                findings.push(finding(
                    DetectionSeverity::Medium,
                    "存在多个 UID 0 账号",
                    format!("发现 {} 个 UID 0 账号", result.root_users.len()),
                    "审核并移除非必要高权限账号",
                ));
            }
            if !result.empty_password_users.is_empty() {
                findings.push(finding(
                    DetectionSeverity::Critical,
                    "存在空密码账号",
                    format!("账号：{}", result.empty_password_users.join(", ")),
                    "立即设置强密码或禁用账号",
                ));
            }
            false
        }
        TypedDetectionResult::ProcessAnalysis(result) => {
            for process in result.suspicious_processes {
                findings.push(finding(
                    DetectionSeverity::High,
                    format!("可疑进程：{}", process.name),
                    format!("PID {} · {}", process.pid, process.command),
                    "核实进程来源、父进程和网络连接",
                ));
            }
            if !result.high_resource_processes.is_empty() {
                findings.push(finding(
                    DetectionSeverity::Medium,
                    "高资源占用进程",
                    format!("发现 {} 个高资源进程", result.high_resource_processes.len()),
                    "检查是否为异常计算或资源耗尽行为",
                ));
            }
            false
        }
        TypedDetectionResult::SshAudit(result) => {
            if result.permit_root_login {
                findings.push(remediable_finding(
                    DetectionSeverity::High,
                    "SSH 允许 root 登录",
                    "PermitRootLogin 当前允许直接 root 登录",
                    "完成完整变更计划与回滚验证后再禁用",
                    DetectionRemediation::DisableSshRootLogin,
                ));
            }
            if result.password_authentication {
                findings.push(remediable_finding(
                    DetectionSeverity::Medium,
                    "SSH 允许密码认证",
                    "PasswordAuthentication 未禁用",
                    "确认密钥登录可用后再迁移认证方式",
                    DetectionRemediation::DisableSshPasswordAuthentication,
                ));
            }
            if let Some(attempts) = result.max_auth_tries.filter(|attempts| *attempts > 4) {
                findings.push(remediable_finding(
                    DetectionSeverity::Medium,
                    "SSH 认证尝试次数过高",
                    format!("MaxAuthTries 当前为 {attempts}"),
                    "通过受管基线将 MaxAuthTries 限制为 4",
                    DetectionRemediation::LimitSshAuthenticationAttempts,
                ));
            }
            if result.default_port {
                findings.push(finding(
                    DetectionSeverity::Low,
                    "SSH 使用默认端口",
                    "SSH 监听默认 22 端口",
                    "端口变更不是认证加固替代方案",
                ));
            }
            false
        }
        TypedDetectionResult::FirewallCheck(result) => {
            if !result.firewall_active {
                findings.push(finding(
                    DetectionSeverity::High,
                    "未检测到活动防火墙",
                    "nftables、iptables 或 firewalld 均未报告活动状态",
                    "先盘点业务流量，再通过可恢复计划启用策略",
                ));
            }
            for rule in result.risky_rules {
                findings.push(finding(
                    DetectionSeverity::High,
                    "发现全网放行规则",
                    rule,
                    "核实规则用途并限制来源网段",
                ));
            }
            false
        }
        TypedDetectionResult::LogAnalysis(result) => {
            if result.brute_force_attempts > 0 {
                let details = if result.brute_force_details.is_empty() {
                    format!("检测到 {} 次失败认证", result.brute_force_attempts)
                } else {
                    format!(
                        "检测到 {} 次失败认证；最近记录：\n{}",
                        result.brute_force_attempts,
                        result.brute_force_details.join("\n")
                    )
                };
                findings.push(finding(
                    DetectionSeverity::High,
                    "检测到暴力破解尝试",
                    details,
                    "核实来源地址，并按现场策略配置限速或 fail2ban",
                ));
            }
            if !result.recent_logins.is_empty() {
                findings.push(finding(
                    DetectionSeverity::Medium,
                    "发现近期登录记录",
                    format!(
                        "需人工核验的最近 {} 条记录：\n{}",
                        result.recent_logins.len(),
                        result.recent_logins.join("\n")
                    ),
                    "结合授权名单、源地址和时间线确认是否为合法访问",
                ));
            }
            false
        }
        TypedDetectionResult::BackdoorScan(result) => {
            for line in result.suspicious_cron {
                findings.push(finding(
                    DetectionSeverity::High,
                    "可疑计划任务",
                    line,
                    "核实任务所有者和载荷，勿直接删除未取证内容",
                ));
            }
            for line in result.suspicious_autostart {
                findings.push(finding(
                    DetectionSeverity::Medium,
                    "待核查自启动文件",
                    line,
                    "结合文件哈希、时间线和包管理器来源核查",
                ));
            }
            false
        }
        TypedDetectionResult::FilePermission(result) => {
            for issue in result.sensitive_file_issues {
                findings.push(remediable_finding(
                    DetectionSeverity::High,
                    "关键文件权限异常",
                    format!(
                        "{} 当前权限为 {:04o}，安全修复目标为 {:04o}",
                        issue.file.path(),
                        issue.observed_mode,
                        issue.file.secure_mode()
                    ),
                    "通过带备份和读回验证的变更计划修复",
                    DetectionRemediation::RepairSensitiveFilePermissions {
                        file: issue.file,
                        expected_mode: issue.observed_mode,
                    },
                ));
            }
            if !result.suid_files.is_empty() {
                findings.push(finding(
                    DetectionSeverity::Info,
                    "SUID 文件清单",
                    format!(
                        "发现 {} 个 SUID 文件，需与系统基线比对",
                        result.suid_files.len()
                    ),
                    "对照发行版包清单核验，不应批量移除",
                ));
            }
            false
        }
        TypedDetectionResult::CpuTest(result) => {
            let frequency = result
                .frequency_mhz
                .map(|value| format!("{value:.1} MHz"))
                .unwrap_or_else(|| "不可用".to_owned());
            let usage = result
                .usage_percent
                .map(|value| format!("{value:.1}%"))
                .unwrap_or_else(|| "不可用".to_owned());
            findings.push(finding(
                DetectionSeverity::Info,
                "CPU 性能测试",
                format!(
                    "逻辑核心 {} · 频率 {} · 一秒平均使用率 {}",
                    result.cores, frequency, usage
                ),
                "性能值用于现场参考，不作为安全风险评分依据",
            ));
            false
        }
        TypedDetectionResult::MemoryTest(result) => {
            findings.push(finding(
                DetectionSeverity::Info,
                "内存性能测试",
                format!(
                    "总内存 {:.1} MiB · 可用 {:.1} MiB · 使用率 {:.1}%",
                    result.total_mib, result.available_mib, result.usage_percent
                ),
                "结合进程占用与业务基线判断是否存在内存压力",
            ));
            false
        }
        TypedDetectionResult::DiskTest(result) => {
            if result.not_applicable {
                true
            } else {
                let read = result.read_mib_per_second.ok_or_else(|| {
                    CoreError::validation("disk test result", "missing read rate")
                })?;
                let write = result.write_mib_per_second.ok_or_else(|| {
                    CoreError::validation("disk test result", "missing write rate")
                })?;
                findings.push(finding(
                    DetectionSeverity::Info,
                    "磁盘 I/O 测试",
                    format!("读取 {read:.1} MiB/s · 写入 {write:.1} MiB/s"),
                    "该结果来自已清理的 100 MiB 临时文件，仅用于粗略现场判断",
                ));
                false
            }
        }
        TypedDetectionResult::NetworkTest(result) => {
            if result.not_applicable {
                true
            } else {
                let destination = result.destination.ok_or_else(|| {
                    CoreError::validation("network test result", "missing destination")
                })?;
                let latency = result.latency_ms.ok_or_else(|| {
                    CoreError::validation("network test result", "missing latency")
                })?;
                findings.push(finding(
                    DetectionSeverity::Info,
                    "网络延迟测试",
                    format!("{destination} 平均往返延迟 {latency:.2} ms；未执行带宽压测"),
                    "网络不可达时应结合现场隔离策略判断，不应使用伪造默认值",
                ));
                false
            }
        }
        TypedDetectionResult::WebshellScan(result) => {
            if result.not_applicable {
                true
            } else {
                for file in &result.files {
                    findings.push(webshell_finding(file));
                }
                for note in &result.notes {
                    findings.push(finding(
                        DetectionSeverity::Info,
                        "扫描存在缺口",
                        note,
                        "缺口范围内的文件未被检查，不能据此判定无风险",
                    ));
                }
                if result.files.is_empty() {
                    findings.push(finding(
                        DetectionSeverity::Info,
                        "未发现 WebShell 命中",
                        format!(
                            "已扫描 {} 个站点目录，{} 个候选文件中已打开核对 {} 个",
                            result.roots.len(),
                            result.listed_candidates,
                            result.scanned_files
                        ),
                        "未命中不等于安全；变形与加密马需要结合日志与人工复核",
                    ));
                }
                false
            }
        }
    };
    let (raw_text, raw_text_truncated) = bounded_raw(raw);
    if not_applicable {
        let (description, recommendation) = match kind {
            DetectionKind::WebshellScan => (
                "常见站点目录与 Web 服务配置中均未发现站点根",
                "如站点位于自定义目录，可补齐站点配置后重试，或人工指定目录复核",
            ),
            DetectionKind::DiskTest => (
                "目标缺少 mktemp/dd、临时目录不可写，或安全探测无法完成",
                "检查临时目录容量与工具可用性后重试；不会使用固定文件名覆盖目标文件",
            ),
            DetectionKind::NetworkTest => (
                "目标缺少 ping，或固定探针 8.8.8.8 当前不可达",
                "离线或隔离环境属于预期状态；本模块不会伪造延迟或带宽",
            ),
            _ => (
                "目标环境不满足该检测模块的前置条件",
                "核实目标能力后再决定是否重试",
            ),
        };
        return Ok(DetectionModuleReport {
            kind,
            outcome: DetectionOutcome::NotApplicable,
            score: 0,
            findings: vec![finding(
                DetectionSeverity::Info,
                "不适用",
                description,
                recommendation,
            )],
            raw_text,
            raw_text_truncated,
            duration_ms: 0,
        });
    }
    let outcome = if findings
        .iter()
        .any(|finding| finding.severity != DetectionSeverity::Info)
    {
        DetectionOutcome::Failed
    } else {
        DetectionOutcome::Passed
    };
    let score = score_findings(&findings);
    Ok(DetectionModuleReport {
        kind,
        outcome,
        score,
        findings,
        raw_text,
        raw_text_truncated,
        duration_ms: 0,
    })
}

fn webshell_finding(file: &WebshellFileHit) -> DetectionFinding {
    let top = file.top();
    let kind_label = match top.kind {
        WebshellHitKind::Signature => "WebShell 特征",
        WebshellHitKind::Image => "图片文件内嵌脚本",
        WebshellHitKind::Config => "Web 配置指令",
        WebshellHitKind::Hidden => "Web 目录隐藏脚本",
    };
    let mut description = format!("文件：{}", file.path);
    for evidence in &file.evidences {
        match evidence.line {
            Some(line) => description.push_str(&format!(
                "\n第 {line} 行 · {}（{}） · {}",
                evidence.feature,
                evidence.level.label(),
                evidence.excerpt
            )),
            None => description.push_str(&format!(
                "\n{}（{}）",
                evidence.feature,
                evidence.level.label()
            )),
        }
    }
    let recommendation = match (top.kind, top.level) {
        (WebshellHitKind::Config, WebshellLevel::Confirmed) => {
            "核对该指令的用途与生效范围；非脚本文件可能因此被当作 PHP 执行"
        }
        (WebshellHitKind::Image, _) => {
            "图片扩展名内嵌脚本，常配合文件包含或解析配置利用；先下载留证再核查"
        }
        (WebshellHitKind::Hidden, _) => "隐藏命名常用于后门驻留；人工核对文件内容与来源后再处置",
        (_, WebshellLevel::Confirmed) => {
            "先下载留证并人工核对代码与文件归属；确认后再按范围处置，勿直接隔离或删除"
        }
        (_, WebshellLevel::Suspect) => "特征可能来自正常代码，须人工打开文件复核后才可视为确证",
    };
    finding(
        top.severity,
        format!("{} {}", top.level.label(), kind_label),
        description,
        recommendation,
    )
}

fn finding(
    severity: DetectionSeverity,
    title: impl AsRef<str>,
    description: impl AsRef<str>,
    recommendation: impl AsRef<str>,
) -> DetectionFinding {
    finding_with_remediation(severity, title, description, recommendation, None)
}

fn remediable_finding(
    severity: DetectionSeverity,
    title: impl AsRef<str>,
    description: impl AsRef<str>,
    recommendation: impl AsRef<str>,
    remediation: DetectionRemediation,
) -> DetectionFinding {
    finding_with_remediation(
        severity,
        title,
        description,
        recommendation,
        Some(remediation),
    )
}

fn finding_with_remediation(
    severity: DetectionSeverity,
    title: impl AsRef<str>,
    description: impl AsRef<str>,
    recommendation: impl AsRef<str>,
    remediation: Option<DetectionRemediation>,
) -> DetectionFinding {
    DetectionFinding {
        title: bounded_multiline(title.as_ref(), 512),
        description: bounded_multiline(description.as_ref(), 2_048),
        severity,
        recommendation: Some(bounded_multiline(recommendation.as_ref(), 2_048)),
        remediation,
    }
}

fn score_findings(findings: &[DetectionFinding]) -> u8 {
    let deduction = findings.iter().fold(0u16, |sum, finding| {
        sum.saturating_add(match finding.severity {
            DetectionSeverity::Critical => 40,
            DetectionSeverity::High => 20,
            DetectionSeverity::Medium => 10,
            DetectionSeverity::Low => 5,
            DetectionSeverity::Info => 0,
        })
    });
    100u16.saturating_sub(deduction).min(100) as u8
}

fn is_high_risk_port(port: u16) -> bool {
    matches!(
        port,
        21 | 23
            | 25
            | 111
            | 135
            | 137
            | 138
            | 139
            | 445
            | 512
            | 513
            | 514
            | 873
            | 1433
            | 1521
            | 2049
            | 2375
            | 2376
            | 3389
            | 5900
            | 11211
            | 27017
    )
}

fn cancelled_module(kind: DetectionKind, elapsed: Duration) -> DetectionModuleReport {
    DetectionModuleReport {
        kind,
        outcome: DetectionOutcome::Cancelled,
        score: 0,
        findings: Vec::new(),
        raw_text: String::new(),
        raw_text_truncated: false,
        duration_ms: elapsed_millis(elapsed),
    }
}

fn error_module(kind: DetectionKind, error: CoreError, elapsed: Duration) -> DetectionModuleReport {
    DetectionModuleReport {
        kind,
        outcome: DetectionOutcome::Error,
        score: 0,
        findings: vec![finding(
            DetectionSeverity::Info,
            "检测失败",
            error.to_string(),
            "检查目标连接与命令可用性后重试",
        )],
        raw_text: String::new(),
        raw_text_truncated: false,
        duration_ms: elapsed_millis(elapsed),
    }
}

fn summarize(modules: &[DetectionModuleReport]) -> DetectionSummary {
    let mut summary = DetectionSummary::default();
    for module in modules {
        match module.outcome {
            DetectionOutcome::Failed => summary.failed_modules += 1,
            DetectionOutcome::NotApplicable => summary.not_applicable_modules += 1,
            DetectionOutcome::Error => summary.error_modules += 1,
            DetectionOutcome::Cancelled => summary.cancelled_modules += 1,
            DetectionOutcome::Passed => {}
        }
        for finding in &module.findings {
            match finding.severity {
                DetectionSeverity::Critical => summary.critical += 1,
                DetectionSeverity::High => summary.high += 1,
                DetectionSeverity::Medium => summary.medium += 1,
                DetectionSeverity::Low => summary.low += 1,
                DetectionSeverity::Info => summary.info += 1,
            }
        }
    }
    summary
}

fn overall_score(modules: &[DetectionModuleReport]) -> u8 {
    let scored: Vec<_> = modules
        .iter()
        .filter(|module| {
            matches!(
                module.outcome,
                DetectionOutcome::Passed | DetectionOutcome::Failed
            )
        })
        .collect();
    if scored.is_empty() {
        return 0;
    }
    let mut score = (scored
        .iter()
        .map(|module| usize::from(module.score))
        .sum::<usize>()
        / scored.len()) as u8;
    if score > 60
        && scored.iter().any(|module| {
            module
                .findings
                .iter()
                .any(|finding| finding.severity == DetectionSeverity::Critical)
        })
    {
        score = 60;
    }
    score
}

fn compact_detection_history(report: &DetectionScanReport) -> DetectionScanReport {
    let mut report = report.clone();
    for module in &mut report.modules {
        let raw = std::mem::take(&mut module.raw_text);
        let mut chars = raw.chars();
        module.raw_text = chars.by_ref().take(DETECTION_HISTORY_RAW_CHARS).collect();
        module.raw_text_truncated |= chars.next().is_some();
    }
    report
}

fn bounded_lines(output: &str, limit: usize) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(limit)
        .map(|line| bounded_line(line, 2_048))
        .collect()
}

fn bounded_line(value: &str, maximum_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '\0' | '\r' | '\n'))
        .take(maximum_chars)
        .collect()
}

fn bounded_multiline(value: &str, maximum_chars: usize) -> String {
    value
        .chars()
        .filter(|character| *character != '\0')
        .take(maximum_chars)
        .collect()
}

fn bounded_raw(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let text: String = chars.by_ref().take(MAX_RAW_TEXT_CHARS).collect();
    let truncated = chars.next().is_some();
    (text, truncated)
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::{Mutex, atomic::AtomicUsize},
    };

    use super::*;
    use crate::{
        BackendServices, PortableStore,
        domain::{CommandOutput, CommandRunner},
        ssh::SshConnectionStatus,
        target::TargetIdentity,
    };

    #[derive(Debug)]
    struct StubRunner {
        outputs: Mutex<Vec<String>>,
    }

    impl StubRunner {
        fn new(outputs: &[&str]) -> Self {
            Self {
                outputs: Mutex::new(
                    outputs
                        .iter()
                        .rev()
                        .map(|value| (*value).to_owned())
                        .collect(),
                ),
            }
        }
    }

    impl CommandRunner for StubRunner {
        fn run(&self, _command: &str) -> CoreResult<CommandOutput> {
            Ok(CommandOutput::success(
                self.outputs.lock().unwrap().pop().unwrap(),
            ))
        }
    }

    fn run_with_command_runner(
        runner: &dyn CommandRunner,
        kind: DetectionKind,
        limit: usize,
    ) -> CoreResult<DetectionModuleReport> {
        let output = runner
            .run(command_for(kind))?
            .into_stdout("quick detection")?;
        let output = bounded_remote_output(output)?;
        parse_module(kind, &output, limit)
    }

    #[derive(Debug)]
    struct AsyncStubRunner {
        outputs: Mutex<VecDeque<RemoteDetectionOutput>>,
        delay: Duration,
        active: AtomicUsize,
        maximum_active: AtomicUsize,
        calls: AtomicUsize,
        switch_target: Option<(Arc<TargetContext>, TargetIdentity)>,
    }

    impl AsyncStubRunner {
        fn repeated(output: &str, count: usize, delay: Duration) -> Self {
            Self {
                outputs: Mutex::new(
                    (0..count)
                        .map(|_| RemoteDetectionOutput {
                            text: output.to_owned(),
                        })
                        .collect(),
                ),
                delay,
                active: AtomicUsize::new(0),
                maximum_active: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
                switch_target: None,
            }
        }
    }

    #[async_trait]
    impl DetectionRemoteRunner for AsyncStubRunner {
        async fn run(
            &self,
            _command: &'static str,
            _timeout: Duration,
        ) -> CoreResult<RemoteDetectionOutput> {
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.maximum_active.fetch_max(active, Ordering::AcqRel);
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            tokio::time::sleep(self.delay).await;
            if call == 0
                && let Some((target, identity)) = &self.switch_target
            {
                target.activate(identity.clone())?;
            }
            self.active.fetch_sub(1, Ordering::AcqRel);
            Ok(self.outputs.lock().unwrap().pop_front().unwrap())
        }
    }

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-detection-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn services(&self) -> BackendServices {
            BackendServices::new(PortableStore::prepare(self.0.clone()).unwrap()).unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn bound_session(services: &BackendServices, identity: &str) -> BoundSshSession {
        let target = services
            .activate_target(TargetIdentity::new(identity).unwrap())
            .unwrap();
        BoundSshSession::from_status(
            target,
            &SshConnectionStatus {
                session_id: format!("session-{identity}"),
                connection_id: identity.to_owned(),
                host: "127.0.0.1".to_owned(),
                port: 22,
                username: "root".to_owned(),
                host_key_fingerprint: "SHA256:test".to_owned(),
                connected_at: Utc::now(),
            },
            "detection test",
        )
        .unwrap()
    }

    #[test]
    fn legacy_port_golden_is_typed_scored_and_deduplicated() {
        let runner = StubRunner::new(&[
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\ntcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*",
        ]);
        let result = run_with_command_runner(&runner, DetectionKind::PortScan, 10).unwrap();
        assert_eq!(result.outcome, DetectionOutcome::Failed);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].title.contains("23"));
        assert_eq!(result.score, 80);
    }

    #[test]
    fn user_audit_requires_marker_and_rejects_attacker_usernames() {
        let runner = StubRunner::new(&[concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "alice:x:1000:1000::/home/alice:/bin/bash\n",
            "LOVELYRES_EMPTY_PASSWORDS_V1\n",
            "alice\nroot;id\n",
        )]);
        let result = run_with_command_runner(&runner, DetectionKind::UserAudit, 10).unwrap();
        assert_eq!(result.outcome, DetectionOutcome::Failed);
        assert!(result.findings[0].description.contains("alice"));
        assert!(!result.findings[0].description.contains("root;id"));
    }

    #[test]
    fn webshell_without_a_web_root_is_not_applicable_not_a_failure() {
        let runner = StubRunner::new(&[WEBSHELL_NOT_APPLICABLE]);
        let result = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert_eq!(result.outcome, DetectionOutcome::NotApplicable);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn webshell_command_covers_extended_file_types_roots_and_discovery() {
        let command = command_for(DetectionKind::WebshellScan);
        for extension in [
            "php", "php[0-9]", "phtml", "pht", "phar", "jsp", "jspx", "asp", "aspx", "asa", "cer",
            "ashx", "jpg", "jpeg", "png", "gif",
        ] {
            assert!(
                command.contains(&format!("*.{extension}'")),
                "missing extension {extension}"
            );
        }
        assert!(command.contains("'.htaccess'"));
        assert!(command.contains("'.user.ini'"));
        assert!(!command.contains("-mtime"), "age restriction must be gone");
        assert!(command.contains("-size -2048k"), "per-file size cap stays");
        for needle in [
            "/home/*/public_html",
            "/var/www/*/html",
            "webapps",
            "nginx -T",
            "LOVELYRES_WEBSHELL_END_V2",
            "command -v find",
        ] {
            assert!(command.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn webshell_confirmed_signatures_grade_as_confirmed() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "关注：/var/www/a.php | 代码特征，第 2 行：<?php eval($_POST['x']);?>\n",
            "关注：/var/www/b.php | 代码特征，第 4 行：<?php $_POST['x']($_GET['a']);\n",
            "关注：/var/www/c.php | 代码特征，第 6 行：<?php eval(gzinflate(base64_decode($c)));\n",
            "关注：/var/www/d.php | 代码特征，第 8 行：system($_GET['c']);\n",
            "# 站点 /var/www：候选 4，已检查 4\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert_eq!(report.outcome, DetectionOutcome::Failed);
        assert_eq!(report.findings.len(), 4);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.severity == DetectionSeverity::Critical
                    && finding.title.contains("确证"))
        );
        assert!(report.findings[0].description.contains("eval"));
    }

    #[test]
    fn webshell_variant_patterns_stay_suspect_for_manual_review() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "关注：/var/www/u.php | 代码特征，第 1 行：call_user_func($_GET['fn'], 'x');\n",
            "关注：/var/www/v.php | 代码特征，第 2 行：preg_replace('/.+/e', 'phpinfo()', $x);\n",
            "关注：/var/www/w.php | 代码特征，第 3 行：create_function('$a', 'return $a;');\n",
            "关注：/var/www/x.php | 代码特征，第 4 行：echo str_rot13(gzinflate($x));\n",
            "关注：/var/www/y.php | 代码特征，第 5 行：$blob = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';\n",
            "关注：/var/www/z.php | 代码特征，第 6 行：assert($x);\n",
            "# 站点 /var/www：候选 6，已检查 6\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert_eq!(report.findings.len(), 6);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.title.contains("疑似")
                    && !finding.title.contains("确证")
                    && finding.severity != DetectionSeverity::Critical)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.severity == DetectionSeverity::High)
        );
        assert!(report.findings.iter().all(|finding| {
            finding
                .recommendation
                .as_deref()
                .is_some_and(|text| text.contains("复核"))
        }));
    }

    #[test]
    fn webshell_image_config_and_hidden_kinds_report_their_features() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "关注：/var/www/u/photo.jpg | 图片标记，第 1 行：binary<?php phpinfo();\n",
            "关注：/var/www/.htaccess | 配置指令，第 5 行：AddType application/x-httpd-php .jpg\n",
            "关注：/var/www/.user.ini | 配置指令，第 1 行：auto_prepend_file = /tmp/evil.php\n",
            "关注：/var/www/.a.php | 隐藏脚本\n",
            "关注：/var/www/.htaccess | 配置指令，第 9 行：AddType text/plain .php\n",
            "# 站点 /var/www：候选 5，已检查 5\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert_eq!(report.findings.len(), 4);
        let image = report
            .findings
            .iter()
            .find(|finding| finding.title.contains("图片文件内嵌脚本"))
            .expect("image hit");
        assert_eq!(image.severity, DetectionSeverity::Critical);
        assert!(image.title.contains("确证"));
        let htaccess = report
            .findings
            .iter()
            .find(|finding| finding.description.contains(".htaccess"))
            .expect("htaccess hit");
        assert!(htaccess.title.contains("确证"));
        assert!(htaccess.description.contains("PHP 处理器映射指令"));
        assert!(htaccess.description.contains("PHP 相关配置指令"));
        let ini = report
            .findings
            .iter()
            .find(|finding| finding.description.contains(".user.ini"))
            .expect("user.ini hit");
        assert!(ini.description.contains("自动前置/附加文件指令"));
        let hidden = report
            .findings
            .iter()
            .find(|finding| finding.title.contains("隐藏脚本"))
            .expect("hidden hit");
        assert_eq!(hidden.severity, DetectionSeverity::Medium);
        assert!(hidden.title.contains("疑似"));
    }

    #[test]
    fn webshell_same_path_merges_kinds_and_strongest_level_wins() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "关注：/var/www/.x.php | 隐藏脚本\n",
            "关注：/var/www/.x.php | 代码特征，第 1 行：<?php eval($_GET['c']);\n",
            "# 站点 /var/www：候选 1，已检查 1\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity, DetectionSeverity::Critical);
        assert!(finding.title.contains("确证"));
        assert!(finding.description.contains("隐藏脚本"));
        assert!(finding.description.contains("第 1 行"));
    }

    #[test]
    fn webshell_gaps_and_unfinished_output_are_visible_not_silent() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "缺口：站点目录不可读，未扫描：/var/www/private\n",
            "garbage line that is not a record\n",
            "# 站点 /var/www：候选 3，已检查 3\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert!(report.findings.iter().any(
            |finding| finding.title == "扫描存在缺口" && finding.description.contains("不可读")
        ));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.description.contains("未完整返回"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.description.contains("无法解析"))
        );

        let fatal = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 扫描未执行：find 或 awk 不可用\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        )]);
        assert!(run_with_command_runner(&fatal, DetectionKind::WebshellScan, 10).is_err());
    }

    #[test]
    fn webshell_clean_scan_reports_coverage_not_absence_of_risk() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "# 站点根：/srv/www\n",
            "# 站点 /var/www：候选 30，已检查 30\n",
            "# 站点 /srv/www：候选 12，已检查 12\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::WebshellScan, 10).unwrap();
        assert_eq!(report.outcome, DetectionOutcome::Passed);
        assert_eq!(report.findings.len(), 1);
        let summary = &report.findings[0];
        assert_eq!(summary.severity, DetectionSeverity::Info);
        assert!(summary.description.contains("2 个站点目录"));
        assert!(summary.description.contains("42"));
        assert!(
            summary
                .recommendation
                .as_deref()
                .is_some_and(|text| text.contains("未命中不等于"))
        );
    }

    /// The collector contract doubles as the workbench display format: every
    /// `关注：` line names exactly one file, so the path-offer mechanism can
    /// attach evidence, disarm and quarantine actions without a second pass.
    #[test]
    fn webshell_hit_lines_name_their_file_for_path_offers() {
        let output = concat!(
            "LOVELYRES_WEBSHELL_V2\n",
            "# 站点根：/var/www\n",
            "关注：/var/www/a.php | 代码特征，第 2 行：<?php eval($_POST['x']);?>\n",
            "关注：/var/www/.a.php | 隐藏脚本\n",
            "关注：/var/www/bak | pipe.php | 代码特征，第 1 行：eval($x)\n",
            "缺口：文件不可读，未检查：/var/www/private/x.php\n",
            "# 站点 /var/www：候选 4，已检查 4\n",
            "LOVELYRES_WEBSHELL_END_V2\n",
        );
        assert_eq!(
            crate::command_paths::paths_in_output(output),
            vec![
                (2, "/var/www/a.php".to_owned()),
                (3, "/var/www/.a.php".to_owned()),
            ],
            "only lines naming one complete safe path may be offered"
        );
        // The ambiguous `|` path still parses as a displayed hit, but the
        // offer extractor refuses it rather than acting on a guessed file.
        let mut by_path = BTreeMap::new();
        assert!(
            parse_webshell_hit(
                "关注：/var/www/bak | pipe.php | 代码特征，第 9 行：eval($x)",
                &mut by_path
            )
            .is_ok()
        );
        assert!(by_path.contains_key("/var/www/bak | pipe.php"));
    }

    #[test]
    fn legacy_log_analysis_is_typed_bounded_and_scored() {
        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_LOG_ANALYSIS_V1\n",
            "ATTEMPTS\t7\n",
            "LOVELYRES_LOG_FAILURES_V1\n",
            "Aug 13 host sshd[1]: Failed password for root from <script>\n",
            "LOVELYRES_LOG_LOGINS_V1\n",
            "root pts/0 10.0.0.8 Thu Aug 13 10:00 still logged in\n",
        )]);
        let result = run_with_command_runner(&runner, DetectionKind::LogAnalysis, 10).unwrap();
        assert_eq!(result.outcome, DetectionOutcome::Failed);
        assert_eq!(result.score, 70);
        assert_eq!(result.findings.len(), 2);
        assert!(result.findings[0].description.contains("7 次失败认证"));
        assert!(result.findings[0].description.contains("<script>"));
        assert!(result.findings[1].description.contains("10.0.0.8"));
    }

    #[test]
    fn cpu_and_memory_metrics_preserve_legacy_information_without_fake_defaults() {
        let cpu = StubRunner::new(&[concat!(
            "LOVELYRES_CPU_TEST_V1\n",
            "CORES\t16\n",
            "FREQUENCY_MHZ\t2394.50\n",
            "USAGE_PERCENT\t12.25\n",
        )]);
        let cpu = run_with_command_runner(&cpu, DetectionKind::CpuTest, 10).unwrap();
        assert_eq!(cpu.outcome, DetectionOutcome::Passed);
        assert_eq!(cpu.score, 100);
        assert!(cpu.findings[0].description.contains("16"));
        assert!(cpu.findings[0].description.contains("12.2%"));

        let memory = StubRunner::new(&[concat!(
            "LOVELYRES_MEMORY_TEST_V1\n",
            "TOTAL_KIB\t8388608\n",
            "AVAILABLE_KIB\t2097152\n",
        )]);
        let memory = run_with_command_runner(&memory, DetectionKind::MemoryTest, 10).unwrap();
        assert_eq!(memory.outcome, DetectionOutcome::Passed);
        assert!(memory.findings[0].description.contains("8192.0 MiB"));
        assert!(memory.findings[0].description.contains("75.0%"));

        let invalid_cpu = StubRunner::new(&[concat!(
            "LOVELYRES_CPU_TEST_V1\n",
            "CORES\t0\n",
            "FREQUENCY_MHZ\tNaN\n",
            "USAGE_PERCENT\t150\n",
        )]);
        assert!(run_with_command_runner(&invalid_cpu, DetectionKind::CpuTest, 10).is_err());
    }

    #[test]
    fn disk_probe_uses_random_cleanup_and_parses_real_dd_units() {
        let command = command_for(DetectionKind::DiskTest);
        assert!(command.contains("mktemp /tmp/lovelyres-disk-test.XXXXXX"));
        assert!(command.contains("trap 'rm -f \"$tmp\"' EXIT HUP INT TERM"));
        assert!(command.contains("bs=1M count=100 conv=fsync"));
        assert!(!command.contains("/tmp/test_disk_speed"));

        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_DISK_TEST_V1\n",
            "WRITE\t104857600 bytes copied, 0.200 s, 524 MB/s\n",
            "READ\t104857600 bytes copied, 0.050 s, 2.1 GB/s\n",
        )]);
        let result = run_with_command_runner(&runner, DetectionKind::DiskTest, 10).unwrap();
        assert_eq!(result.outcome, DetectionOutcome::Passed);
        assert!(result.findings[0].description.contains("499.7 MiB/s"));
        assert!(result.findings[0].description.contains("2002.7 MiB/s"));

        let unavailable = StubRunner::new(&[DISK_TEST_NOT_APPLICABLE]);
        let unavailable =
            run_with_command_runner(&unavailable, DetectionKind::DiskTest, 10).unwrap();
        assert_eq!(unavailable.outcome, DetectionOutcome::NotApplicable);
    }

    #[test]
    fn network_probe_never_invents_bandwidth_or_offline_latency() {
        let command = command_for(DetectionKind::NetworkTest);
        assert!(command.contains("ping -c 3 -W 3 8.8.8.8"));
        assert!(!command.to_ascii_lowercase().contains("bandwidth"));

        let runner = StubRunner::new(&[concat!(
            "LOVELYRES_NETWORK_TEST_V1\n",
            "DESTINATION\t8.8.8.8\n",
            "LATENCY_MS\t18.75\n",
        )]);
        let result = run_with_command_runner(&runner, DetectionKind::NetworkTest, 10).unwrap();
        assert_eq!(result.outcome, DetectionOutcome::Passed);
        assert!(result.findings[0].description.contains("18.75 ms"));
        assert!(result.findings[0].description.contains("未执行带宽压测"));

        let unavailable = StubRunner::new(&[NETWORK_TEST_NOT_APPLICABLE]);
        let unavailable =
            run_with_command_runner(&unavailable, DetectionKind::NetworkTest, 10).unwrap();
        assert_eq!(unavailable.outcome, DetectionOutcome::NotApplicable);
        assert!(unavailable.findings[0].description.contains("不可达"));
        assert!(!unavailable.findings[0].description.contains("10 ms"));
        assert!(!unavailable.findings[0].description.contains("100 Mbps"));
    }

    #[test]
    fn detector_errors_are_distinct_from_security_failures() {
        let error = error_module(
            DetectionKind::PortScan,
            CoreError::validation("detection test", "unavailable"),
            Duration::ZERO,
        );
        let runner = StubRunner::new(&["tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*"]);
        let failed = run_with_command_runner(&runner, DetectionKind::PortScan, 10).unwrap();
        assert_eq!(error.outcome, DetectionOutcome::Error);
        assert_eq!(failed.outcome, DetectionOutcome::Failed);
    }

    #[test]
    fn not_applicable_and_errors_do_not_lower_trusted_score() {
        let passed = DetectionModuleReport {
            kind: DetectionKind::PortScan,
            outcome: DetectionOutcome::Passed,
            score: 100,
            findings: Vec::new(),
            raw_text: String::new(),
            raw_text_truncated: false,
            duration_ms: 0,
        };
        let mut not_applicable = passed.clone();
        not_applicable.kind = DetectionKind::WebshellScan;
        not_applicable.outcome = DetectionOutcome::NotApplicable;
        not_applicable.score = 0;
        let mut error = passed.clone();
        error.kind = DetectionKind::SshAudit;
        error.outcome = DetectionOutcome::Error;
        error.score = 0;
        assert_eq!(overall_score(&[passed, not_applicable, error]), 100);
    }

    #[test]
    fn module_ids_and_scan_parameters_fail_closed() {
        assert!(serde_json::from_str::<DetectionKind>("\"raw-shell\"").is_err());
        assert!(DetectionScanRequest::selected([]).is_err());
        assert!(
            DetectionScanRequest::selected([DetectionKind::PortScan, DetectionKind::PortScan,])
                .is_err()
        );
        assert!(
            DetectionScanRequest::selected([DetectionKind::PortScan])
                .unwrap()
                .with_max_findings(MAX_FINDINGS_PER_MODULE + 1)
                .is_err()
        );
    }

    #[test]
    fn ssh_findings_expose_only_closed_managed_baseline_remediations() {
        let runner = StubRunner::new(&[concat!(
            "permitrootlogin yes\n",
            "passwordauthentication yes\n",
            "maxauthtries 6\n",
            "port 22\n",
        )]);
        let report = run_with_command_runner(&runner, DetectionKind::SshAudit, 10).unwrap();
        let remediations = report
            .findings
            .iter()
            .filter_map(|finding| finding.remediation)
            .collect::<Vec<_>>();
        assert_eq!(remediations, DetectionRemediation::SSH_ONLY);
        assert_eq!(report.findings.len(), 4);
        assert!(report.findings[3].remediation.is_none());

        let requests = remediations
            .into_iter()
            .map(|remediation| remediation.baseline_request().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requests[0].item_id, "ssh-permit-root-login");
        assert_eq!(requests[0].value, "no");
        assert_eq!(requests[1].item_id, "ssh-password-authentication");
        assert_eq!(requests[1].value, "no");
        assert_eq!(requests[2].item_id, "ssh-max-auth-tries");
        assert_eq!(requests[2].value, "4");
        assert!(
            DetectionRemediation::SSH_ONLY
                .into_iter()
                .all(|item| item.reload_policy() == BaselineReloadPolicy::ApplyNow)
        );
        assert!(serde_json::from_str::<DetectionRemediation>("\"execute-raw-shell\"").is_err());
    }

    #[test]
    fn sensitive_file_findings_mint_only_fixed_mode_bound_sftp_repairs() {
        let report = run_with_command_runner(
            &StubRunner::new(&[concat!(
                "LOVELYRES_SENSITIVE_FILES_V1\n",
                "-rw-rw-rw-|666|/etc/passwd\n",
                "-rw-r--r--|644|/etc/shadow\n",
                "-rw-rw-rw-|666|/etc/sudoers\n",
                "-rwxrwxrwx|777|/tmp/attacker-controlled\n",
                "-rw-------|6x0|/etc/shadow\n",
            )]),
            DetectionKind::FilePermission,
            10,
        )
        .unwrap();
        assert_eq!(report.findings.len(), 3);

        let expected = [
            (SensitiveSystemFile::Passwd, 0o666, 0o644),
            (SensitiveSystemFile::Shadow, 0o644, 0o640),
            (SensitiveSystemFile::Sudoers, 0o666, 0o440),
        ];
        for (finding, (file, observed_mode, secure_mode)) in report.findings.iter().zip(expected) {
            let remediation = finding.remediation.expect("finding must be repairable");
            assert_eq!(
                remediation,
                DetectionRemediation::RepairSensitiveFilePermissions {
                    file,
                    expected_mode: observed_mode,
                }
            );
            match remediation.request().unwrap() {
                DetectionRemediationRequest::Sftp(SftpMutation::ChmodIfMode {
                    path,
                    expected_mode,
                    mode,
                }) => {
                    assert_eq!(path.as_str(), file.path());
                    assert_eq!(expected_mode, observed_mode);
                    assert_eq!(mode, secure_mode);
                }
                request => panic!("unexpected remediation request: {request:?}"),
            }
        }
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.description.contains("attacker-controlled"))
        );
    }

    #[test]
    fn ssh_remediation_parser_rejects_unbounded_or_non_numeric_auth_tries() {
        for value in ["-1", "101", "999999999999999999999", "6;id", "NaN"] {
            let report = run_with_command_runner(
                &StubRunner::new(&[&format!("maxauthtries {value}\n")]),
                DetectionKind::SshAudit,
                10,
            )
            .unwrap();
            assert!(report.findings.iter().all(|finding| {
                finding.remediation != Some(DetectionRemediation::LimitSshAuthenticationAttempts)
            }));
        }
    }

    #[test]
    fn legacy_persisted_findings_without_remediation_remain_readable() {
        let finding = serde_json::from_str::<DetectionFinding>(
            r#"{"title":"legacy","description":"plain","severity":"medium","recommendation":null}"#,
        )
        .unwrap();
        assert_eq!(finding.remediation, None);
    }

    #[test]
    fn remote_output_is_rejected_before_parser_allocation() {
        assert!(bounded_remote_output("x".repeat(MAX_DETECTION_OUTPUT_BYTES + 1)).is_err());
    }

    #[test]
    fn portable_history_is_target_bound_bounded_and_exports_typed_json() {
        let root = TestRoot::new();
        let services = root.services();
        let session = bound_session(&services, "host-a");
        for index in 0..(DETECTION_HISTORY_LIMIT + 3) {
            let report = DetectionScanReport {
                id: format!("scan-{index:03}"),
                target: session.target().clone(),
                profile: DetectionScanProfile::Selected,
                started_at: Utc::now(),
                duration_ms: 1,
                status: DetectionScanStatus::Completed,
                overall_score: 100,
                modules: vec![DetectionModuleReport {
                    kind: DetectionKind::LogAnalysis,
                    outcome: DetectionOutcome::Passed,
                    score: 100,
                    findings: vec![finding(
                        DetectionSeverity::Info,
                        "<script>remote()</script>",
                        "attacker text remains data",
                        "none",
                    )],
                    raw_text: "攻".repeat(DETECTION_HISTORY_RAW_CHARS + 4),
                    raw_text_truncated: false,
                    duration_ms: 1,
                }],
                summary: DetectionSummary {
                    info: 1,
                    ..DetectionSummary::default()
                },
                dropped_progress_events: 0,
            };
            services.detection().persist_report(&report).unwrap();
        }

        let history = services
            .detection()
            .history_for_target(session.target())
            .unwrap();
        assert_eq!(history.len(), DETECTION_HISTORY_LIMIT);
        assert_eq!(history[0].id, "scan-066");
        assert_eq!(
            history[0].modules[0].raw_text.chars().count(),
            DETECTION_HISTORY_RAW_CHARS
        );
        assert!(history[0].modules[0].raw_text_truncated);
        assert_eq!(
            services
                .store()
                .path_for(StoreFile::DetectionHistory)
                .file_name()
                .and_then(|name| name.to_str()),
            Some("detection-history.json")
        );

        let export = detection_report_json(&history[0]).unwrap();
        let export: serde_json::Value = serde_json::from_str(&export).unwrap();
        assert_eq!(export["schema"], DETECTION_REPORT_EXPORT_SCHEMA);
        assert_eq!(export["report"]["id"], "scan-066");
        assert_eq!(
            export["report"]["modules"][0]["findings"][0]["title"],
            "<script>remote()</script>"
        );

        let stale = session.target().clone();
        services
            .activate_target(TargetIdentity::new("host-b").unwrap())
            .unwrap();
        assert!(matches!(
            services.detection().history_for_target(&stale),
            Err(CoreError::TargetChanged { .. })
        ));
    }

    #[tokio::test]
    async fn cancellation_stops_in_flight_work_and_returns_a_partial_report() {
        let root = TestRoot::new();
        let services = root.services();
        let session = bound_session(&services, "host-a");
        let request = DetectionScanRequest::selected(DetectionKind::ALL).unwrap();
        let plan = services.detection().plan_scan(&session, request).unwrap();
        let runner =
            AsyncStubRunner::repeated("", DetectionKind::ALL.len(), Duration::from_secs(10));
        let cancellation = DetectionCancellation::default();
        let cancel = cancellation.clone();
        let (events, _) = detection_event_channel(8).unwrap();
        let task = services
            .detection()
            .run_scan_with_runner(&runner, plan, cancellation, events);
        tokio::pin!(task);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => cancel.cancel(),
            result = &mut task => panic!("scan finished before cancellation: {result:?}"),
        }
        let report = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.status, DetectionScanStatus::Cancelled);
        assert!(report.summary.cancelled_modules > 0);
    }

    #[tokio::test]
    async fn concurrency_and_progress_backpressure_are_bounded() {
        let root = TestRoot::new();
        let services = root.services();
        let session = bound_session(&services, "host-a");
        let plan = services
            .detection()
            .plan_scan(
                &session,
                DetectionScanRequest::selected(DetectionKind::ALL).unwrap(),
            )
            .unwrap();
        let runner = AsyncStubRunner::repeated(
            WEBSHELL_NOT_APPLICABLE,
            DetectionKind::ALL.len(),
            Duration::from_millis(5),
        );
        let (events, _receiver) = detection_event_channel(1).unwrap();
        let report = services
            .detection()
            .run_scan_with_runner(&runner, plan, DetectionCancellation::default(), events)
            .await
            .unwrap();
        assert!(runner.maximum_active.load(Ordering::Acquire) <= STANDARD_CONCURRENCY);
        assert!(report.dropped_progress_events > 0);
        assert_eq!(
            services
                .detection()
                .history_for_target(session.target())
                .unwrap()
                .first()
                .map(|stored| stored.id.as_str()),
            Some(report.id.as_str())
        );
    }

    #[tokio::test]
    async fn target_change_after_dispatch_rejects_the_whole_late_report() {
        let root = TestRoot::new();
        let services = root.services();
        let session = bound_session(&services, "host-a");
        let plan = services
            .detection()
            .plan_scan(
                &session,
                DetectionScanRequest::selected([DetectionKind::PortScan]).unwrap(),
            )
            .unwrap();
        let runner = AsyncStubRunner {
            switch_target: Some((
                services.target().clone(),
                TargetIdentity::new("host-b").unwrap(),
            )),
            ..AsyncStubRunner::repeated("", 1, Duration::from_millis(1))
        };
        let (events, _) = detection_event_channel(4).unwrap();
        let error = services
            .detection()
            .run_scan_with_runner(&runner, plan, DetectionCancellation::default(), events)
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
    }

    #[test]
    fn detection_source_has_no_public_raw_shell_surface() {
        let source = include_str!("detection.rs");
        for forbidden in [
            ["pub async fn ", "execute("].concat(),
            ["pub async fn ", "run_command("].concat(),
            ["pub command", ": String"].concat(),
            ["pub shell", ": String"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "found {forbidden}");
        }
    }
}
