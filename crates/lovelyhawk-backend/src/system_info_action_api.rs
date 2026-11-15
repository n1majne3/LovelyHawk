//! Acting on a row the system-information page already showed.
//!
//! The page holds a snapshot handle and row ids the sidecar minted. When the
//! operator right-clicks a row it asks which actions apply, and the answer is
//! computed here from the snapshot the sidecar kept — a row the renderer made
//! up names nothing, and a tab that has no actions offers none.
//!
//! Every action is one the core already knows how to carry out. Read-only
//! ones ("排查") run a bounded command and hand the output back. The ones that
//! change the host ("处置") go through the core's plan, confirm, execute,
//! journal and verify pipeline, with the same handle-per-plan rule the Docker
//! and Kubernetes panes use: a plan is described before it runs, approval and
//! execution are separate calls, and a plan leaves the registry as it is
//! taken so it can never run twice.

use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    CoreError, CoreResult,
    account_password::AccountPasswordPlan,
    kernel_module_unload::KernelModuleUnloadPlan,
    systemd_unit_removal::{SystemdUnitRemovalPlan, SystemdUnitRemovalUndo},
    crypto::SecretValue,
    firewall_block::{
        FirewallBlockOutcome, FirewallBlockPlan, FirewallBlockRequest, FirewallBlockRestorePlan,
        FirewallDirection,
    },
    operations::{DangerousConfirmation, OperationPlan, VerificationResult},
    process_restart::ProcessRestartPlan,
    system_info::{
        ArtifactInvestigationAction, ArtifactMutationAction, ArtifactMutationPlan,
        BootScriptRuntimePlan, COMMAND_TIMEOUT_MARKER, CronInvestigationAction,
        EnvVarInvestigationAction, KernelModuleInvestigationAction, LoginInvestigationAction,
        NetworkDisconnectPlan, NetworkInvestigationAction, PackageInvestigationAction,
        ProcessInvestigationAction, ProcessSignal, ProcessSignalPlan, RuntimeChangeRequest,
        ServiceInvestigationAction, ServiceRuntimeAction, ServiceRuntimePlan,
        ShellConfigInvestigationAction, SshKeyInvestigationAction, StartupInvestigationAction,
        SudoersInvestigationAction, SuidFileInvestigationAction, SystemInfoRow, SystemInfoTab,
        SystemInfoTable, TimerInvestigationAction, UserAccountAction, UserAccountPlan,
        UserInvestigationAction,
    },
    target::TargetGuard,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::time::timeout;
use uuid::Uuid;

use crate::system_info_api::{SystemInfoApi, SystemInfoApiError, tab_key};

const MAX_PLANS: usize = 16;
const MAX_ACTION_KEY_BYTES: usize = 64;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_PLAN_TEXT_BYTES: usize = 2_048;
/// Long enough to read what the plan says and decide; short enough that an
/// abandoned dialog cannot be executed from later.
const PLAN_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a verified unit removal can still be undone from its receipt.
const UNDO_TTL: Duration = Duration::from_secs(10 * 60);
/// The slowest read-only action the core allows itself is thirty seconds.
const INSPECT_DEADLINE: Duration = Duration::from_secs(45);
const PLAN_DEADLINE: Duration = Duration::from_secs(30);
/// Execution covers the change, the journal write, the verification read and
/// a restore if verification failed.
const EXECUTE_DEADLINE: Duration = Duration::from_secs(120);

/// One thing the operator may ask of one row: a closed set, addressed by a
/// fixed key such as `process.open-files` or `process.signal.kill`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowAction {
    ProcessInspect(ProcessInvestigationAction),
    ProcessSignal(ProcessSignal),
    /// `process.restart` — stop a hand-started process and relaunch it with
    /// its captured argv/cwd/user.
    ProcessRestart,
    ServiceInspect(ServiceInvestigationAction),
    ServiceRuntime(ServiceRuntimeAction),
    UserInspect(UserInvestigationAction),
    UserAccount(UserAccountAction),
    /// `account.password` — the change needs a secret the renderer supplies
    /// once, so it is its own variant rather than a `UserAccountAction`.
    UserPassword,
    LoginInspect(LoginInvestigationAction),
    NetworkInspect(NetworkInvestigationAction),
    NetworkDisconnect,
    ArtifactInspect(ArtifactInvestigationAction),
    ArtifactMutation(ArtifactMutationAction),
    /// `kernel-module.unload` — rmmod a Live, refcount-0 module the kernel
    /// module inventory listed.
    KernelModuleUnload,
    /// `service.remove-unit` — move a local unit's fragment, drop-ins and
    /// enablement links into a backup tree, with an undo handle.
    ServiceRemoveUnit,
}

impl RowAction {
    /// The key the renderer addresses this action by. Stable, kebab-case, and
    /// namespaced by the family of row it applies to.
    pub(crate) fn key(self) -> String {
        match self {
            Self::ProcessInspect(action) => format!("process.{}", kebab(action)),
            Self::ProcessSignal(signal) => format!("process.signal.{}", kebab(signal)),
            Self::ProcessRestart => "process.restart".to_owned(),
            Self::ServiceInspect(action) => format!("service.{}", kebab(action)),
            Self::ServiceRuntime(action) => format!("service.runtime.{}", kebab(action)),
            Self::UserInspect(action) => format!("user.{}", kebab(action)),
            Self::UserAccount(action) => format!("account.{}", kebab(action)),
            Self::UserPassword => "account.password".to_owned(),
            Self::LoginInspect(action) => format!("login.{}", kebab(action)),
            Self::NetworkInspect(action) => format!("network.{}", kebab(action)),
            Self::NetworkDisconnect => "network.disconnect".to_owned(),
            Self::ArtifactInspect(action) => match action {
                ArtifactInvestigationAction::Package(inner) => format!("package.{}", kebab(inner)),
                ArtifactInvestigationAction::KernelModule(inner) => {
                    format!("module.{}", kebab(inner))
                }
                ArtifactInvestigationAction::Environment(inner) => format!("env.{}", kebab(inner)),
                ArtifactInvestigationAction::Startup(inner) => format!("startup.{}", kebab(inner)),
                ArtifactInvestigationAction::Cron(inner) => format!("cron.{}", kebab(inner)),
                ArtifactInvestigationAction::Timer(inner) => format!("timer.{}", kebab(inner)),
                ArtifactInvestigationAction::ShellConfig(inner) => {
                    format!("shell.{}", kebab(inner))
                }
                ArtifactInvestigationAction::Sudoers(inner) => format!("sudoers.{}", kebab(inner)),
                ArtifactInvestigationAction::SuidFile(inner) => format!("suid.{}", kebab(inner)),
                ArtifactInvestigationAction::SshKey(inner) => format!("ssh-key.{}", kebab(inner)),
            },
            Self::KernelModuleUnload => "kernel-module.unload".to_owned(),
            Self::ServiceRemoveUnit => "service.remove-unit".to_owned(),
            Self::ArtifactMutation(action) => match action {
                ArtifactMutationAction::DeleteCronFile => "cron.delete-file",
                ArtifactMutationAction::CommentShellLine => "shell.comment-line",
                ArtifactMutationAction::DeleteShellLine => "shell.delete-line",
                ArtifactMutationAction::DeleteSshKey => "ssh-key.delete",
                ArtifactMutationAction::RemoveSuidBits => "suid.remove-bits",
                ArtifactMutationAction::QuarantineSuidFile => "suid.quarantine",
                ArtifactMutationAction::AddManagedModuleBlacklist => "module.blacklist.add",
                ArtifactMutationAction::RemoveManagedModuleBlacklist => "module.blacklist.remove",
            }
            .to_owned(),
        }
    }

    /// The inverse of [`RowAction::key`]. Anything that is not exactly one of
    /// the keys this module hands out is nothing.
    pub(crate) fn parse(key: &str) -> Option<Self> {
        if key.is_empty() || key.len() > MAX_ACTION_KEY_BYTES {
            return None;
        }
        let (family, rest) = key.split_once('.')?;
        match family {
            "process" => match rest.strip_prefix("signal.") {
                Some(signal) => from_kebab(signal).map(Self::ProcessSignal),
                None if rest == "restart" => Some(Self::ProcessRestart),
                None => from_kebab(rest).map(Self::ProcessInspect),
            },
            "service" => match rest {
                "remove-unit" => Some(Self::ServiceRemoveUnit),
                _ => match rest.strip_prefix("runtime.") {
                    Some(action) => from_kebab(action).map(Self::ServiceRuntime),
                    None => from_kebab(rest).map(Self::ServiceInspect),
                },
            },
            "user" => from_kebab(rest).map(Self::UserInspect),
            "account" => match rest {
                "password" => Some(Self::UserPassword),
                _ => from_kebab(rest).map(Self::UserAccount),
            },
            "login" => from_kebab(rest).map(Self::LoginInspect),
            "network" => match rest {
                "disconnect" => Some(Self::NetworkDisconnect),
                _ => from_kebab(rest).map(Self::NetworkInspect),
            },
            "package" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Package)
                .map(Self::ArtifactInspect),
            "module" => match rest {
                "blacklist.add" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::AddManagedModuleBlacklist,
                )),
                "blacklist.remove" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::RemoveManagedModuleBlacklist,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::KernelModule)
                    .map(Self::ArtifactInspect),
            },
            "kernel-module" => match rest {
                "unload" => Some(Self::KernelModuleUnload),
                _ => None,
            },
            "env" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Environment)
                .map(Self::ArtifactInspect),
            "startup" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Startup)
                .map(Self::ArtifactInspect),
            "cron" => match rest {
                "delete-file" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteCronFile,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::Cron)
                    .map(Self::ArtifactInspect),
            },
            "timer" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Timer)
                .map(Self::ArtifactInspect),
            "shell" => match rest {
                "comment-line" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::CommentShellLine,
                )),
                "delete-line" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteShellLine,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::ShellConfig)
                    .map(Self::ArtifactInspect),
            },
            "sudoers" => from_kebab(rest)
                .map(ArtifactInvestigationAction::Sudoers)
                .map(Self::ArtifactInspect),
            "suid" => match rest {
                "remove-bits" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::RemoveSuidBits,
                )),
                "quarantine" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::QuarantineSuidFile,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::SuidFile)
                    .map(Self::ArtifactInspect),
            },
            "ssh-key" => match rest {
                "delete" => Some(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteSshKey,
                )),
                _ => from_kebab(rest)
                    .map(ArtifactInvestigationAction::SshKey)
                    .map(Self::ArtifactInspect),
            },
            _ => None,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ProcessInspect(action) => action.label(),
            Self::ProcessSignal(signal) => signal.label(),
            Self::ProcessRestart => "按原命令行重启",
            Self::ServiceInspect(action) => action.label(),
            Self::ServiceRuntime(action) => action.label(),
            Self::UserInspect(action) => action.label(),
            Self::UserAccount(action) => action.label(),
            Self::UserPassword => "修改账户口令",
            Self::LoginInspect(action) => action.label(),
            Self::NetworkInspect(action) => action.label(),
            Self::NetworkDisconnect => "断开此连接",
            Self::ArtifactInspect(action) => action.label(),
            Self::ArtifactMutation(action) => action.label(),
            Self::KernelModuleUnload => "卸载模块",
            Self::ServiceRemoveUnit => "移除服务单元",
        }
    }

    /// Whether choosing this only reads, or asks for a plan to change the host.
    pub(crate) const fn changes_host(self) -> bool {
        matches!(
            self,
            Self::ProcessSignal(_)
                | Self::ProcessRestart
                | Self::ServiceRuntime(_)
                | Self::UserAccount(_)
                | Self::UserPassword
                | Self::NetworkDisconnect
                | Self::ArtifactMutation(_)
                | Self::KernelModuleUnload
                | Self::ServiceRemoveUnit
        )
    }

    /// Whether the menu should show this in the colour that means "this
    /// stops or removes something". A change that only turns something on is
    /// still confirmed through a plan, but is not painted red.
    const fn dangerous(self) -> bool {
        match self {
            Self::ProcessSignal(_)
            | Self::ProcessRestart
            | Self::NetworkDisconnect
            | Self::ArtifactMutation(_)
            | Self::KernelModuleUnload
            | Self::ServiceRemoveUnit => true,
            Self::ServiceRuntime(action) => matches!(
                action,
                ServiceRuntimeAction::Stop
                    | ServiceRuntimeAction::Disable
                    | ServiceRuntimeAction::Mask
            ),
            Self::UserAccount(action) => {
                matches!(action, UserAccountAction::Lock | UserAccountAction::Delete)
            }
            Self::UserPassword => true,
            _ => false,
        }
    }

    /// Which heading the menu files this under.
    fn group(self) -> (String, &'static str) {
        match self {
            Self::ProcessInspect(action) => (kebab(action.group()), action.group().label()),
            Self::ServiceInspect(action) => (kebab(action.group()), action.group().label()),
            Self::UserInspect(action) => (kebab(action.group()), action.group().label()),
            Self::LoginInspect(action) => (kebab(action.group()), action.group().label()),
            Self::NetworkInspect(action) => (kebab(action.group()), action.group().label()),
            Self::ArtifactInspect(_) => ("inspect".to_owned(), "排查"),
            Self::ProcessSignal(_)
            | Self::ProcessRestart
            | Self::ServiceRuntime(_)
            | Self::UserAccount(_)
            | Self::UserPassword
            | Self::NetworkDisconnect
            | Self::ArtifactMutation(_)
            | Self::KernelModuleUnload
            | Self::ServiceRemoveUnit => ("change".to_owned(), "处置"),
        }
    }

    /// Every action a tab could offer, in menu order. Which of them a given
    /// row actually gets is decided by [`applies`].
    pub(crate) fn candidates(tab: SystemInfoTab) -> Vec<Self> {
        let mut actions = Vec::new();
        match tab {
            SystemInfoTab::Processes => {
                actions.extend(ProcessInvestigationAction::ALL.map(Self::ProcessInspect));
                actions.extend(
                    [ProcessSignal::Terminate, ProcessSignal::Kill].map(Self::ProcessSignal),
                );
                actions.push(Self::ProcessRestart);
            }
            SystemInfoTab::Services => {
                actions.extend(ServiceInvestigationAction::ALL.map(Self::ServiceInspect));
                actions.extend(ServiceRuntimeAction::ALL.map(Self::ServiceRuntime));
                actions.push(Self::ServiceRemoveUnit);
            }
            SystemInfoTab::Autostart => {
                actions.extend(
                    StartupInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::Startup)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(ServiceRuntimeAction::AUTOSTART.map(Self::ServiceRuntime));
                actions.push(Self::ServiceRemoveUnit);
            }
            SystemInfoTab::Timers => {
                actions.extend(
                    TimerInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::Timer)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(ServiceRuntimeAction::TIMER.map(Self::ServiceRuntime));
            }
            SystemInfoTab::Users => {
                actions.extend(UserInvestigationAction::ALL.map(Self::UserInspect));
                // Deletion last, after the reversible lock; root and UID 0
                // rows are refused by the core and so never offered it.
                actions.extend(
                    [
                        UserAccountAction::Lock,
                        UserAccountAction::Unlock,
                        UserAccountAction::Delete,
                    ]
                    .map(Self::UserAccount),
                );
                actions.push(Self::UserPassword);
            }
            SystemInfoTab::LoginHistory => {
                actions.extend(LoginInvestigationAction::ALL.map(Self::LoginInspect));
                actions.extend(
                    [UserAccountAction::Lock, UserAccountAction::Unlock].map(Self::UserAccount),
                );
            }
            SystemInfoTab::Network | SystemInfoTab::Established | SystemInfoTab::OpenPorts => {
                actions.extend(NetworkInvestigationAction::ALL.map(Self::NetworkInspect));
                actions.push(Self::NetworkDisconnect);
            }
            SystemInfoTab::Packages => actions.extend(
                PackageInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::Package)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::KernelModules => {
                actions.extend(
                    KernelModuleInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::KernelModule)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(
                    [
                        ArtifactMutationAction::AddManagedModuleBlacklist,
                        ArtifactMutationAction::RemoveManagedModuleBlacklist,
                    ]
                    .map(Self::ArtifactMutation),
                );
                actions.push(Self::KernelModuleUnload);
            }
            SystemInfoTab::EnvVars => actions.extend(
                EnvVarInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::Environment)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::Cron => {
                actions.extend(
                    CronInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::Cron)
                        .map(Self::ArtifactInspect),
                );
                actions.push(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteCronFile,
                ));
            }
            SystemInfoTab::ShellConfigs => {
                actions.extend(
                    ShellConfigInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::ShellConfig)
                        .map(Self::ArtifactInspect),
                );
                actions.push(Self::ArtifactMutation(
                    ArtifactMutationAction::CommentShellLine,
                ));
                actions.push(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteShellLine,
                ));
            }
            SystemInfoTab::Sudoers => actions.extend(
                SudoersInvestigationAction::ALL
                    .map(ArtifactInvestigationAction::Sudoers)
                    .map(Self::ArtifactInspect),
            ),
            SystemInfoTab::SuidFiles => {
                actions.extend(
                    SuidFileInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::SuidFile)
                        .map(Self::ArtifactInspect),
                );
                actions.extend(
                    [
                        ArtifactMutationAction::RemoveSuidBits,
                        ArtifactMutationAction::QuarantineSuidFile,
                    ]
                    .map(Self::ArtifactMutation),
                );
            }
            SystemInfoTab::SshKeys => {
                actions.extend(
                    SshKeyInvestigationAction::ALL
                        .map(ArtifactInvestigationAction::SshKey)
                        .map(Self::ArtifactInspect),
                );
                actions.push(Self::ArtifactMutation(
                    ArtifactMutationAction::DeleteSshKey,
                ));
            }
            SystemInfoTab::Firewall
            | SystemInfoTab::Autoruns
            | SystemInfoTab::Rootcheck
            | SystemInfoTab::Sensitive
            | SystemInfoTab::RecentFiles
            | SystemInfoTab::Docker
            | SystemInfoTab::Kubernetes
            | SystemInfoTab::WebApps => {}
        }
        actions
    }
}

/// Whether the core would accept this action for this row. The request
/// builders are pure: they read the row's cells and nothing else, so this
/// costs nothing and never touches the host.
fn applies(table: &SystemInfoTable, row_id: &str, action: RowAction) -> bool {
    match action {
        RowAction::ProcessInspect(inner) => {
            table.process_investigation_request(row_id, inner).is_ok()
        }
        RowAction::ProcessSignal(inner) => table.process_signal_request(row_id, inner).is_ok(),
        RowAction::ProcessRestart => table.process_restart_request(row_id).is_ok(),
        RowAction::ServiceInspect(inner) => {
            table.service_investigation_request(row_id, inner).is_ok()
        }
        RowAction::ServiceRuntime(inner) => table.runtime_change_request(row_id, inner).is_ok(),
        RowAction::UserInspect(inner) => table.user_investigation_request(row_id, inner).is_ok(),
        RowAction::UserAccount(inner) => table.user_account_request(row_id, inner).is_ok(),
        RowAction::UserPassword => table.user_password_request(row_id).is_ok(),
        RowAction::LoginInspect(inner) => table.login_investigation_request(row_id, inner).is_ok(),
        RowAction::NetworkInspect(inner) => {
            table.network_investigation_request(row_id, inner).is_ok()
        }
        RowAction::NetworkDisconnect => table.network_disconnect_request(row_id).is_ok(),
        RowAction::ArtifactInspect(inner) => {
            table.artifact_investigation_request(row_id, inner).is_ok()
        }
        RowAction::ArtifactMutation(inner) => {
            table.artifact_mutation_request(row_id, inner).is_ok()
        }
        RowAction::KernelModuleUnload => table.kernel_module_unload_request(row_id).is_ok(),
        RowAction::ServiceRemoveUnit => table.systemd_unit_removal_request(row_id).is_ok(),
    }
}

fn kebab<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn from_kebab<T: DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowActionsDto {
    tab: &'static str,
    row_id: String,
    /// What the row is, in the words the table used, so the menu can say what
    /// it is about. Display only; nothing resolves through it.
    subject: String,
    groups: Vec<SystemInfoRowActionGroupDto>,
}

impl fmt::Debug for SystemInfoRowActionsDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowActionsDto")
            .field("tab", &self.tab)
            .field("group_count", &self.groups.len())
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoRowActionGroupDto {
    key: String,
    label: &'static str,
    actions: Vec<SystemInfoRowActionDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfoRowActionDto {
    key: String,
    label: &'static str,
    kind: &'static str,
    dangerous: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowInspectionDto {
    tab: &'static str,
    row_id: String,
    action: String,
    label: &'static str,
    subject: String,
    output: String,
    truncated: bool,
}

impl fmt::Debug for SystemInfoRowInspectionDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowInspectionDto")
            .field("tab", &self.tab)
            .field("action", &self.action)
            .field("output_bytes", &self.output.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowPlanDto {
    plan_handle: String,
    tab: &'static str,
    row_id: String,
    action: String,
    label: &'static str,
    subject: String,
    summary: String,
    dangerous: bool,
    restore_description: Option<String>,
    confirmed: bool,
    expires_in_seconds: u32,
}

impl fmt::Debug for SystemInfoRowPlanDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowPlanDto")
            .field("tab", &self.tab)
            .field("action", &self.action)
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowReceiptDto {
    plan_handle: String,
    tab: &'static str,
    row_id: String,
    action: String,
    label: &'static str,
    subject: String,
    /// Whether the host, read back afterwards, is in the state the plan said
    /// it would be. A command that returned zero is not the same thing.
    verified: bool,
    detail: String,
    restored: bool,
    /// A typed follow-up the page may offer, or none. This is a field, not a
    /// marker inside `detail`: remote-controlled text never switches UI
    /// affordances.
    next_step: Option<&'static str>,
    /// A stored undo the receipt can offer; only actions that moved files
    /// into a backup tree hand one back.
    undo_handle: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInfoRowUndoDto {
    undone: bool,
    detail: String,
}

impl fmt::Debug for SystemInfoRowUndoDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowUndoDto")
            .field("undone", &self.undone)
            .finish()
    }
}

impl fmt::Debug for SystemInfoRowReceiptDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemInfoRowReceiptDto")
            .field("tab", &self.tab)
            .field("action", &self.action)
            .field("verified", &self.verified)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RowScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

enum RowPlan {
    ProcessSignal(ProcessSignalPlan),
    ProcessRestart(ProcessRestartPlan),
    ServiceRuntime(ServiceRuntimePlan),
    /// The same request on a host that boots with scripts instead of units.
    BootScriptRuntime(BootScriptRuntimePlan),
    UserAccount(UserAccountPlan),
    UserPassword(AccountPasswordPlan),
    NetworkDisconnect(NetworkDisconnectPlan),
    ArtifactMutation(ArtifactMutationPlan),
    KernelModuleUnload(KernelModuleUnloadPlan),
    ServiceRemoveUnit(SystemdUnitRemovalPlan),
}

impl RowPlan {
    fn definition(&self) -> &OperationPlan {
        match self {
            Self::ProcessSignal(plan) => plan.definition(),
            Self::ProcessRestart(plan) => plan.definition(),
            Self::ServiceRuntime(plan) => plan.definition(),
            Self::BootScriptRuntime(plan) => plan.definition(),
            Self::UserAccount(plan) => plan.definition(),
            Self::UserPassword(plan) => plan.definition(),
            Self::NetworkDisconnect(plan) => plan.definition(),
            Self::ArtifactMutation(plan) => plan.definition(),
            Self::KernelModuleUnload(plan) => plan.definition(),
            Self::ServiceRemoveUnit(plan) => plan.definition(),
        }
    }
}

struct StoredRowPlan {
    plan_handle: String,
    scope: RowScope,
    tab: SystemInfoTab,
    row_id: String,
    action: RowAction,
    subject: String,
    plan: RowPlan,
    /// Set by `confirm` and never unset. `execute` refuses without it, and the
    /// plan leaves the registry as it is taken, so approval covers one run.
    confirmed: bool,
    expires_at: Instant,
}

/// A verified removal's way back: the operation's undo plus the scope that
/// owns it, kept for the same window every undoable change gets.
struct StoredRowUndo {
    undo_handle: String,
    scope: RowScope,
    undo: SystemdUnitRemovalUndo,
    expires_at: Instant,
}

#[derive(Default)]
pub(crate) struct RowPlanRegistry {
    plans: HashMap<String, StoredRowPlan>,
    undos: HashMap<String, StoredRowUndo>,
}

impl fmt::Debug for RowPlanRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowPlanRegistry")
            .field("plan_count", &self.plans.len())
            .finish()
    }
}

impl RowPlanRegistry {
    fn prune(&mut self, now: Instant) {
        self.plans.retain(|_, plan| plan.expires_at > now);
        self.undos.retain(|_, undo| undo.expires_at > now);
    }

    pub(crate) fn close_binding(&mut self, binding_handle: &str) {
        self.plans
            .retain(|_, plan| plan.scope.binding_handle != binding_handle);
        self.undos
            .retain(|_, undo| undo.scope.binding_handle != binding_handle);
    }

    fn store(&mut self, plan: StoredRowPlan) -> Result<(), SystemInfoApiError> {
        // A page drives one dialog at a time, so an older plan of the same
        // binding is one the operator already walked away from.
        self.plans
            .retain(|_, stored| stored.scope.binding_handle != plan.scope.binding_handle);
        if self.plans.len() >= MAX_PLANS {
            return Err(SystemInfoApiError::SnapshotCapacity);
        }
        self.plans.insert(plan.plan_handle.clone(), plan);
        Ok(())
    }

    fn plan_mut(
        &mut self,
        scope: &RowScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut StoredRowPlan, SystemInfoApiError> {
        let plan = self
            .plans
            .get_mut(plan_handle)
            .ok_or(SystemInfoApiError::PlanStale)?;
        if &plan.scope != scope || plan.expires_at <= now {
            return Err(SystemInfoApiError::PlanStale);
        }
        Ok(plan)
    }

    /// Takes an approved plan out, so it can never run twice.
    fn take_confirmed(
        &mut self,
        scope: &RowScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<StoredRowPlan, SystemInfoApiError> {
        if !self.plan_mut(scope, plan_handle, now)?.confirmed {
            return Err(SystemInfoApiError::PlanNotConfirmed);
        }
        self.plans
            .remove(plan_handle)
            .ok_or(SystemInfoApiError::PlanStale)
    }

    fn remove(&mut self, scope: &RowScope, plan_handle: &str) {
        if self
            .plans
            .get(plan_handle)
            .is_some_and(|plan| &plan.scope == scope)
        {
            self.plans.remove(plan_handle);
        }
    }

    fn store_undo(&mut self, undo: StoredRowUndo) {
        self.undos.insert(undo.undo_handle.clone(), undo);
    }

    /// Takes a stored undo out, so it can never run twice.
    fn take_undo(
        &mut self,
        scope: &RowScope,
        undo_handle: &str,
        now: Instant,
    ) -> Result<StoredRowUndo, SystemInfoApiError> {
        let stored = self
            .undos
            .get(undo_handle)
            .ok_or(SystemInfoApiError::PlanStale)?;
        if &stored.scope != scope || stored.expires_at <= now {
            return Err(SystemInfoApiError::PlanStale);
        }
        self.undos
            .remove(undo_handle)
            .ok_or(SystemInfoApiError::PlanStale)
    }
}

impl SystemInfoApi {
    /// Which actions this row can take, grouped the way the menu shows them.
    /// Reads the snapshot only; the host is not asked anything.
    pub(crate) fn row_actions(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
    ) -> Result<SystemInfoRowActionsDto, SystemInfoApiError> {
        let (_, table) = self.snapshot_for(binding_handle, snapshot_handle, row_id)?;
        let row = find_row(&table, row_id)?;
        let mut groups: Vec<SystemInfoRowActionGroupDto> = Vec::new();
        for action in RowAction::candidates(table.tab) {
            if !applies(&table, row_id, action) {
                continue;
            }
            let (key, label) = action.group();
            let entry = SystemInfoRowActionDto {
                key: action.key(),
                label: action.label(),
                kind: if action.changes_host() {
                    "change"
                } else {
                    "inspect"
                },
                dangerous: action.dangerous(),
            };
            match groups.iter_mut().find(|group| group.key == key) {
                Some(group) => group.actions.push(entry),
                None => groups.push(SystemInfoRowActionGroupDto {
                    key,
                    label,
                    actions: vec![entry],
                }),
            }
        }
        Ok(SystemInfoRowActionsDto {
            tab: tab_key(table.tab),
            row_id: row.id.clone(),
            subject: row_subject(&table, row),
            groups,
        })
    }

    /// Runs one read-only action and hands the bounded output back.
    pub(crate) async fn inspect_row(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
        action_key: &str,
    ) -> Result<SystemInfoRowInspectionDto, SystemInfoApiError> {
        let action = RowAction::parse(action_key).ok_or(SystemInfoApiError::InvalidAction)?;
        if action.changes_host() {
            return Err(SystemInfoApiError::InvalidAction);
        }
        let (session, table) = self.snapshot_for(binding_handle, snapshot_handle, row_id)?;
        let row = find_row(&table, row_id)?;
        let subject = row_subject(&table, row);
        let service = self.services.system_info();
        let outcome = timeout(INSPECT_DEADLINE, async {
            match action {
                RowAction::ProcessInspect(inner) => {
                    let request = table.process_investigation_request(row_id, inner)?;
                    let result = service.investigate_process(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::ServiceInspect(inner) => {
                    let request = table.service_investigation_request(row_id, inner)?;
                    let result = service.investigate_service(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::UserInspect(inner) => {
                    let request = table.user_investigation_request(row_id, inner)?;
                    let result = service.investigate_user(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::LoginInspect(inner) => {
                    let request = table.login_investigation_request(row_id, inner)?;
                    let result = service.investigate_login(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::NetworkInspect(inner) => {
                    let request = table.network_investigation_request(row_id, inner)?;
                    let result = service.investigate_network(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::ArtifactInspect(inner) => {
                    let request = table.artifact_investigation_request(row_id, inner)?;
                    let result = service.investigate_artifact(&session, &request).await?;
                    Ok((result.output, result.truncated))
                }
                RowAction::ProcessSignal(_)
                | RowAction::ProcessRestart
                | RowAction::ServiceRuntime(_)
                | RowAction::UserAccount(_)
                | RowAction::UserPassword
                | RowAction::NetworkDisconnect
                | RowAction::ArtifactMutation(_)
                | RowAction::KernelModuleUnload
                | RowAction::ServiceRemoveUnit => Err(CoreError::Validation {
                    subject: "system-information row action",
                    message: "this action changes the host and must be planned".to_owned(),
                }),
            }
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let (output, truncated) = outcome;
        Ok(SystemInfoRowInspectionDto {
            tab: tab_key(table.tab),
            row_id: row.id.clone(),
            action: action.key(),
            label: action.label(),
            subject,
            output,
            truncated,
        })
    }

    /// Describes what a change would do, without doing any of it.
    ///
    /// The row's current state is read from the host here rather than taken
    /// from the snapshot: the snapshot may be minutes old, and the
    /// precondition the core checks has to be checked against now.
    pub(crate) async fn plan_row_action(
        &self,
        binding_handle: &str,
        snapshot_handle: &str,
        row_id: &str,
        action_key: &str,
        password: Option<SecretValue>,
    ) -> Result<SystemInfoRowPlanDto, SystemInfoApiError> {
        let action = RowAction::parse(action_key).ok_or(SystemInfoApiError::InvalidAction)?;
        if !action.changes_host() {
            return Err(SystemInfoApiError::InvalidAction);
        }
        // A secret is only meaningful to the one action that asks for it;
        // anywhere else its presence is a boundary violation, not a hint.
        if !matches!(action, RowAction::UserPassword) && password.is_some() {
            return Err(SystemInfoApiError::InvalidAction);
        }
        let scope = self.capture_scope(binding_handle)?;
        let (session, table) = self.snapshot_for(binding_handle, snapshot_handle, row_id)?;
        let row = find_row(&table, row_id)?;
        let subject = row_subject(&table, row);
        let service = self.services.system_info();
        let plan = timeout(PLAN_DEADLINE, async {
            match action {
                RowAction::ProcessSignal(signal) => {
                    let request = table.process_signal_request(row_id, signal)?;
                    service
                        .plan_process_signal(&session, &request)
                        .await
                        .map(RowPlan::ProcessSignal)
                }
                RowAction::ProcessRestart => {
                    let pid = table.process_restart_request(row_id)?;
                    service
                        .plan_process_restart(&session, row_id, pid)
                        .await
                        .map(RowPlan::ProcessRestart)
                }
                RowAction::ServiceRuntime(inner) => {
                    // Which of the two this row is was decided by the row
                    // itself, not by anything the window said.
                    match table.runtime_change_request(row_id, inner)? {
                        RuntimeChangeRequest::Service(request) => service
                            .plan_service_runtime(&session, &request)
                            .await
                            .map(RowPlan::ServiceRuntime),
                        RuntimeChangeRequest::BootScript(request) => service
                            .plan_boot_script_runtime(&session, &request)
                            .await
                            .map(RowPlan::BootScriptRuntime),
                    }
                }
                RowAction::UserAccount(inner) => {
                    let request = table.user_account_request(row_id, inner)?;
                    service
                        .plan_user_account(&session, &request)
                        .await
                        .map(RowPlan::UserAccount)
                }
                RowAction::UserPassword => {
                    let identity = table.user_password_request(row_id)?;
                    let password = password.ok_or_else(|| CoreError::Validation {
                        subject: "system-information row action",
                        message: "the password change needs the new password".to_owned(),
                    })?;
                    service
                        .plan_account_password(&session, row_id, &identity.username, password)
                        .await
                        .map(RowPlan::UserPassword)
                }
                RowAction::NetworkDisconnect => {
                    let request = table.network_disconnect_request(row_id)?;
                    service
                        .plan_network_disconnect(&session, &request)
                        .await
                        .map(RowPlan::NetworkDisconnect)
                }
                RowAction::ArtifactMutation(inner) => {
                    let request = table.artifact_mutation_request(row_id, inner)?;
                    service
                        .plan_artifact_mutation(&session, &request)
                        .await
                        .map(RowPlan::ArtifactMutation)
                }
                RowAction::KernelModuleUnload => {
                    let request = table.kernel_module_unload_request(row_id)?;
                    service
                        .plan_kernel_module_unload(&session, &request)
                        .await
                        .map(RowPlan::KernelModuleUnload)
                }
                RowAction::ServiceRemoveUnit => {
                    let request = table.systemd_unit_removal_request(row_id)?;
                    service
                        .plan_systemd_unit_removal(&session, &request)
                        .await
                        .map(RowPlan::ServiceRemoveUnit)
                }
                RowAction::ProcessInspect(_)
                | RowAction::ServiceInspect(_)
                | RowAction::UserInspect(_)
                | RowAction::LoginInspect(_)
                | RowAction::NetworkInspect(_)
                | RowAction::ArtifactInspect(_) => Err(CoreError::Validation {
                    subject: "system-information row action",
                    message: "this action only reads and has nothing to plan".to_owned(),
                }),
            }
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.validate_scope(&scope)?;

        let now = Instant::now();
        let stored = StoredRowPlan {
            plan_handle: Uuid::new_v4().to_string(),
            scope,
            tab: table.tab,
            row_id: row.id.clone(),
            action,
            subject,
            plan,
            confirmed: false,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&stored, now);
        let mut registry = self.lock_plans()?;
        registry.prune(now);
        registry.store(stored)?;
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm_row_action(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SystemInfoRowPlanDto, SystemInfoApiError> {
        validate_plan_handle(plan_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_plans()?;
        registry.prune(now);
        let plan = registry.plan_mut(&scope, plan_handle, now)?;
        plan.confirmed = true;
        Ok(plan_dto(plan, now))
    }

    /// Runs the approved plan once, verifies it, and reports what the host
    /// said afterwards.
    pub(crate) async fn execute_row_action(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SystemInfoRowReceiptDto, SystemInfoApiError> {
        validate_plan_handle(plan_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_plans()?;
            registry.prune(now);
            registry.take_confirmed(&scope, plan_handle, now)?
        };
        let session = self.binding_session(&scope.binding_handle)?;
        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let service = self.services.system_info();
        let journal = self.services.operation_journal();
        let StoredRowPlan {
            plan_handle,
            tab,
            row_id,
            action,
            subject,
            plan,
            ..
        } = stored;
        type Executed = CoreResult<(
            VerificationResult,
            bool,
            Option<&'static str>,
            Option<SystemdUnitRemovalUndo>,
        )>;
        let outcome: Result<Executed, _> =
            timeout(EXECUTE_DEADLINE, async move {
                match plan {
                    RowPlan::ProcessSignal(plan) => service
                        .execute_process_signal(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| (outcome.verification, false, None, None)),
                    RowPlan::ProcessRestart(plan) => service
                        .execute_process_restart(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.relaunched_after_failure,
                                None,
                                None,
                            )
                        }),
                    RowPlan::ServiceRuntime(plan) => service
                        .execute_service_runtime(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                                None,
                                None,
                            )
                        }),
                    RowPlan::BootScriptRuntime(plan) => service
                        .execute_boot_script_runtime(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                                None,
                                None,
                            )
                        }),
                    RowPlan::UserAccount(plan) => service
                        .execute_user_account(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                                outcome.tool_suspect.then_some("verify-account-tool"),
                                None,
                            )
                        }),
                    RowPlan::UserPassword(plan) => service
                        .execute_account_password(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                                None,
                                None,
                            )
                        }),
                    RowPlan::NetworkDisconnect(plan) => service
                        .execute_network_disconnect(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| (outcome.verification, false, None, None)),
                    RowPlan::ArtifactMutation(plan) => service
                        .execute_artifact_mutation(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (
                                outcome.verification,
                                outcome.restored_after_failed_verification,
                                None,
                                None,
                            )
                        }),
                    RowPlan::KernelModuleUnload(plan) => service
                        .execute_kernel_module_unload(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| (outcome.verification, false, None, None)),
                    RowPlan::ServiceRemoveUnit(plan) => service
                        .execute_systemd_unit_removal(&session, plan, confirmation, journal)
                        .await
                        .map(|outcome| {
                            (outcome.verification, false, None, outcome.undo)
                        }),
                }
            })
            .await;
        self.validate_scope(&scope)?;

        let receipt = |verified: bool,
                       detail: String,
                       restored: bool,
                       next_step: Option<&'static str>,
                       undo_handle: Option<String>| {
            SystemInfoRowReceiptDto {
                plan_handle: plan_handle.clone(),
                tab: tab_key(tab),
                row_id: row_id.clone(),
                action: action.key(),
                label: action.label(),
                subject: subject.clone(),
                verified,
                detail,
                restored,
                next_step,
                undo_handle,
            }
        };
        match outcome {
            Err(_) => Err(SystemInfoApiError::Deadline),
            // The core restores on failed verification itself and journals
            // whatever it got to, so a failure here is reported rather than
            // retried: retrying a half-applied change is worse than telling
            // the operator to look.
            Ok(Err(error)) => Ok(receipt(
                false,
                execution_failure_detail(&error),
                false,
                None,
                None,
            )),
            Ok(Ok((verification, restored, next_step, undo))) => {
                let undo_handle = match undo {
                    Some(undo) => {
                        let now = Instant::now();
                        let mut registry = self.lock_plans()?;
                        registry.prune(now);
                        let undo_handle = Uuid::new_v4().to_string();
                        registry.store_undo(StoredRowUndo {
                            undo_handle: undo_handle.clone(),
                            scope: scope.clone(),
                            undo,
                            expires_at: now + UNDO_TTL,
                        });
                        Some(undo_handle)
                    }
                    None => None,
                };
                Ok(receipt(
                    verification.passed,
                    bounded_text(&verification.detail, MAX_PLAN_TEXT_BYTES),
                    restored,
                    next_step,
                    undo_handle,
                ))
            }
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel_row_action(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), SystemInfoApiError> {
        validate_plan_handle(plan_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        self.lock_plans()?.remove(&scope, plan_handle);
        Ok(())
    }

    /// Puts back what a verified removal moved out. The undo is taken from
    /// the registry before it runs, so one handle restores exactly once.
    pub(crate) async fn undo_row_action(
        &self,
        binding_handle: &str,
        undo_handle: &str,
    ) -> Result<SystemInfoRowUndoDto, SystemInfoApiError> {
        validate_plan_handle(undo_handle)?;
        let scope = self.capture_scope(binding_handle)?;
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_plans()?;
            registry.prune(now);
            registry.take_undo(&scope, undo_handle, now)?
        };
        let session = self.binding_session(&scope.binding_handle)?;
        let service = self.services.system_info();
        let detail = timeout(EXECUTE_DEADLINE, stored.undo.undo(service, &session))
            .await
            .map_err(|_| SystemInfoApiError::Deadline)?
            .map_err(action_failure)?;
        self.validate_scope(&scope)?;
        Ok(SystemInfoRowUndoDto {
            undone: true,
            detail: bounded_text(&detail, MAX_PLAN_TEXT_BYTES),
        })
    }

    fn capture_scope(&self, binding_handle: &str) -> Result<RowScope, SystemInfoApiError> {
        let session = self.binding_session(binding_handle)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| SystemInfoApiError::BindingUnavailable)?;
        Ok(RowScope {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_scope(&self, expected: &RowScope) -> Result<(), SystemInfoApiError> {
        let current = self.capture_scope(&expected.binding_handle)?;
        if &current != expected {
            return Err(SystemInfoApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn lock_plans(&self) -> Result<std::sync::MutexGuard<'_, RowPlanRegistry>, SystemInfoApiError> {
        self.plans
            .lock()
            .map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }
}

fn find_row<'a>(
    table: &'a SystemInfoTable,
    row_id: &str,
) -> Result<&'a SystemInfoRow, SystemInfoApiError> {
    table
        .rows
        .iter()
        .find(|row| row.id == row_id)
        .ok_or(SystemInfoApiError::InvalidRow)
}

fn validate_plan_handle(handle: &str) -> Result<(), SystemInfoApiError> {
    if handle.is_empty() || handle.len() > 128 {
        return Err(SystemInfoApiError::InvalidSnapshot);
    }
    Ok(())
}

/// What the row is, in the words the table used. Chosen per tab so the menu
/// title reads as the thing, not as the first cell.
fn row_subject(table: &SystemInfoTable, row: &SystemInfoRow) -> String {
    let cell = |index: usize| row.cells.get(index).map(String::as_str).unwrap_or("");
    let subject = match table.tab {
        SystemInfoTab::Processes => format!("PID {} · {}", cell(1), cell(8)),
        SystemInfoTab::Network => match cell(2) {
            "" | "-" | "*" => format!("{} {}", cell(0), cell(1)),
            remote => format!("{} {} → {}", cell(0), cell(1), remote),
        },
        SystemInfoTab::Established => format!("{} → {}", cell(0), cell(1)),
        SystemInfoTab::OpenPorts => format!("{} {}:{}", cell(0), cell(1), cell(2)),
        SystemInfoTab::LoginHistory => match cell(2) {
            "" | "-" => cell(0).to_owned(),
            source => format!("{} ← {}", cell(0), source),
        },
        SystemInfoTab::Cron => format!("{}: {}", cell(0), cell(2)),
        SystemInfoTab::ShellConfigs => format!("{}:{}", cell(0), cell(3)),
        SystemInfoTab::SshKeys => format!("{} {}", cell(0), cell(1)),
        _ => cell(0).to_owned(),
    };
    bounded_text(subject.trim(), MAX_SUBJECT_BYTES)
}

fn plan_dto(stored: &StoredRowPlan, now: Instant) -> SystemInfoRowPlanDto {
    let definition = stored.plan.definition();
    let remaining = stored.expires_at.saturating_duration_since(now).as_secs();
    SystemInfoRowPlanDto {
        plan_handle: stored.plan_handle.clone(),
        tab: tab_key(stored.tab),
        row_id: stored.row_id.clone(),
        action: stored.action.key(),
        label: stored.action.label(),
        subject: stored.subject.clone(),
        summary: bounded_text(&definition.summary, MAX_PLAN_TEXT_BYTES),
        dangerous: definition.dangerous,
        restore_description: definition
            .restore_description
            .as_deref()
            .map(|text| bounded_text(text, MAX_PLAN_TEXT_BYTES)),
        confirmed: stored.confirmed,
        expires_in_seconds: u32::try_from(remaining.max(1)).unwrap_or(u32::MAX),
    }
}

/// A core refusal that is about this row — the process is gone, the row is
/// not a TCP connection, the line is already a comment — is a different thing
/// from the feature failing, and is reported as such.
///
/// A target that never answered is a third thing again, and must not be
/// reported as either. Saying "this action no longer applies to this row"
/// about a host that is merely slow sends an operator looking for a change on
/// the target that never happened.
fn action_failure(error: CoreError) -> SystemInfoApiError {
    match error {
        CoreError::Validation { message, .. } if message.contains(COMMAND_TIMEOUT_MARKER) => {
            SystemInfoApiError::Deadline
        }
        error @ (CoreError::Validation { .. } | CoreError::NotFound { .. }) => {
            SystemInfoApiError::ActionUnavailable(error)
        }
        other => SystemInfoApiError::from(other),
    }
}

fn execution_failure_detail(error: &CoreError) -> String {
    match error {
        CoreError::Validation { .. } | CoreError::NotFound { .. } => {
            "目标机上的状态在确认之后变了，这次没有执行。请刷新后再看。".to_owned()
        }
        _ => "操作没有完成，目标机上的状态请再确认一次。".to_owned(),
    }
}

fn bounded_text(text: &str, maximum_bytes: usize) -> String {
    if text.len() <= maximum_bytes {
        return text.to_owned();
    }
    let mut end = maximum_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

// ---- firewall block (batch 7b) ----
const FIREWALL_PLAN_TTL: Duration = Duration::from_secs(120);
const FIREWALL_RESTORE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

struct StoredFirewallPlan {
    binding_handle: String,
    request: FirewallBlockRequest,
    plan: FirewallBlockPlan,
    expires_at: Instant,
}

struct StoredFirewallRestorePlan {
    binding_handle: String,
    request: FirewallBlockRequest,
    plan: FirewallBlockRestorePlan,
    expires_at: Instant,
}

struct StoredFirewallRestore {
    binding_handle: String,
    request: FirewallBlockRequest,
    token: String,
    expires_at: Instant,
}

#[derive(Default)]
pub(crate) struct FirewallRegistry {
    plans: HashMap<String, StoredFirewallPlan>,
    restore_plans: HashMap<String, StoredFirewallRestorePlan>,
    restores: HashMap<String, StoredFirewallRestore>,
}

impl FirewallRegistry {
    pub(crate) fn close_binding(&mut self, binding_handle: &str) {
        self.plans.retain(|_, p| p.binding_handle != binding_handle);
        self.restore_plans
            .retain(|_, p| p.binding_handle != binding_handle);
        self.restores
            .retain(|_, r| r.binding_handle != binding_handle);
    }

    fn prune(&mut self, now: Instant) {
        self.plans.retain(|_, p| p.expires_at > now);
        self.restore_plans.retain(|_, p| p.expires_at > now);
        self.restores.retain(|_, r| r.expires_at > now);
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum FirewallRequest {
    Plan {
        #[serde(rename = "bindingHandle")]
        binding_handle: String,
        address: String,
        direction: String,
    },
    Execute {
        #[serde(rename = "bindingHandle")]
        binding_handle: String,
        #[serde(rename = "planHandle")]
        plan_handle: String,
    },
    #[serde(rename = "plan-restore")]
    PlanRestore {
        #[serde(rename = "bindingHandle")]
        binding_handle: String,
        #[serde(rename = "restoreHandle")]
        restore_handle: String,
    },
    #[serde(rename = "execute-restore")]
    ExecuteRestore {
        #[serde(rename = "bindingHandle")]
        binding_handle: String,
        #[serde(rename = "planHandle")]
        plan_handle: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallPlanDto {
    plan_handle: String,
    backend: String,
    address: String,
    direction: String,
    commands: Vec<String>,
    warnings: Vec<String>,
    expires_in_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallResultDto {
    verified: bool,
    detail: String,
    restore_handle: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallRestorePlanDto {
    plan_handle: String,
    backend: String,
    address: String,
    direction: String,
    expires_in_ms: u64,
}

fn firewall_direction(value: &str) -> Result<FirewallDirection, SystemInfoApiError> {
    match value {
        "inbound" => Ok(FirewallDirection::Inbound),
        "outbound" => Ok(FirewallDirection::Outbound),
        "both" => Ok(FirewallDirection::Both),
        _ => Err(SystemInfoApiError::InvalidAction),
    }
}

fn direction_key(direction: FirewallDirection) -> &'static str {
    match direction {
        FirewallDirection::Inbound => "inbound",
        FirewallDirection::Outbound => "outbound",
        FirewallDirection::Both => "both",
    }
}
impl SystemInfoApi {
    pub(crate) async fn firewall(
        &self,
        request: FirewallRequest,
    ) -> Result<serde_json::Value, SystemInfoApiError> {
        match request {
            FirewallRequest::Plan {
                binding_handle,
                address,
                direction,
            } => {
                self.firewall_plan(&binding_handle, &address, &direction)
                    .await
            }
            FirewallRequest::Execute {
                binding_handle,
                plan_handle,
            } => self.firewall_execute(&binding_handle, &plan_handle).await,
            FirewallRequest::PlanRestore {
                binding_handle,
                restore_handle,
            } => {
                self.firewall_plan_restore(&binding_handle, &restore_handle)
                    .await
            }
            FirewallRequest::ExecuteRestore {
                binding_handle,
                plan_handle,
            } => {
                self.firewall_execute_restore(&binding_handle, &plan_handle)
                    .await
            }
        }
    }

    async fn firewall_plan(
        &self,
        binding_handle: &str,
        address: &str,
        direction: &str,
    ) -> Result<serde_json::Value, SystemInfoApiError> {
        let direction = firewall_direction(direction)?;
        let address = address
            .parse::<std::net::IpAddr>()
            .map_err(|_| SystemInfoApiError::InvalidAction)?;
        let request = FirewallBlockRequest::new(address, direction)
            .map_err(SystemInfoApiError::ActionUnavailable)?;
        let session = self.binding_session(binding_handle)?;
        let plan = timeout(PLAN_DEADLINE, async {
            self.services
                .system_info()
                .plan_firewall_block(&session, &request)
                .await
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let now = Instant::now();
        let dto = FirewallPlanDto {
            plan_handle: Uuid::new_v4().to_string(),
            backend: plan.backend().name().to_owned(),
            address: request.address().to_string(),
            direction: direction_key(request.direction()).to_owned(),
            commands: plan.commands().to_vec(),
            warnings: plan.warnings().to_vec(),
            expires_in_ms: FIREWALL_PLAN_TTL.as_millis() as u64,
        };
        self.lock_firewall()?.plans.insert(
            dto.plan_handle.clone(),
            StoredFirewallPlan {
                binding_handle: binding_handle.to_owned(),
                request,
                plan,
                expires_at: now + FIREWALL_PLAN_TTL,
            },
        );
        serde_json::to_value(&dto).map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }

    async fn firewall_execute(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<serde_json::Value, SystemInfoApiError> {
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_firewall()?;
            registry.prune(now);
            let stored = registry
                .plans
                .remove(plan_handle)
                .ok_or(SystemInfoApiError::PlanStale)?;
            if stored.binding_handle != binding_handle || stored.expires_at <= now {
                return Err(SystemInfoApiError::PlanStale);
            }
            stored
        };
        let session = self.binding_session(binding_handle)?;
        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let journal = self.services.operation_journal();
        let request = stored.request.clone();
        let outcome = timeout(EXECUTE_DEADLINE, async {
            self.services
                .system_info()
                .execute_firewall_block(&session, stored.plan, confirmation, journal)
                .await
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let dto = FirewallResultDto {
            verified: outcome.verification.passed,
            detail: bounded_text(&outcome.verification.detail, MAX_PLAN_TEXT_BYTES),
            restore_handle: outcome.restore_handle().map(|_| Uuid::new_v4().to_string()),
        };
        if let (Some(handle), Some(token)) = (&dto.restore_handle, outcome.restore_handle()) {
            self.lock_firewall()?.restores.insert(
                handle.clone(),
                StoredFirewallRestore {
                    binding_handle: binding_handle.to_owned(),
                    request,
                    token: token.to_owned(),
                    expires_at: Instant::now() + FIREWALL_RESTORE_TTL,
                },
            );
        }
        serde_json::to_value(&dto).map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }
    async fn firewall_plan_restore(
        &self,
        binding_handle: &str,
        restore_handle: &str,
    ) -> Result<serde_json::Value, SystemInfoApiError> {
        let session = self.binding_session(binding_handle)?;
        let now = Instant::now();
        let (request, token) = {
            let mut registry = self.lock_firewall()?;
            registry.prune(now);
            let stored = registry
                .restores
                .get(restore_handle)
                .ok_or(SystemInfoApiError::PlanStale)?;
            if stored.binding_handle != binding_handle || stored.expires_at <= now {
                return Err(SystemInfoApiError::PlanStale);
            }
            (stored.request.clone(), stored.token.clone())
        };
        // The outcome shape the core planner expects is re-materialized from
        // the stored token; the UUID itself is never handed to the core.
        let outcome = FirewallBlockOutcome::from_token(token);
        let plan = timeout(PLAN_DEADLINE, async {
            self.services
                .system_info()
                .plan_firewall_block_restore(&session, &request, &outcome)
                .await
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        let dto = FirewallRestorePlanDto {
            plan_handle: Uuid::new_v4().to_string(),
            backend: plan.backend().name().to_owned(),
            address: request.address().to_string(),
            direction: direction_key(request.direction()).to_owned(),
            expires_in_ms: FIREWALL_PLAN_TTL.as_millis() as u64,
        };
        self.lock_firewall()?.restore_plans.insert(
            dto.plan_handle.clone(),
            StoredFirewallRestorePlan {
                binding_handle: binding_handle.to_owned(),
                request,
                plan,
                expires_at: now + FIREWALL_PLAN_TTL,
            },
        );
        serde_json::to_value(&dto).map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }

    async fn firewall_execute_restore(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<serde_json::Value, SystemInfoApiError> {
        let stored = {
            let now = Instant::now();
            let mut registry = self.lock_firewall()?;
            registry.prune(now);
            let stored = registry
                .restore_plans
                .remove(plan_handle)
                .ok_or(SystemInfoApiError::PlanStale)?;
            if stored.binding_handle != binding_handle || stored.expires_at <= now {
                return Err(SystemInfoApiError::PlanStale);
            }
            stored
        };
        let session = self.binding_session(binding_handle)?;
        let confirmation = DangerousConfirmation::approve(stored.plan.definition());
        let journal = self.services.operation_journal();
        let outcome = timeout(EXECUTE_DEADLINE, async {
            self.services
                .system_info()
                .execute_firewall_block_restore(
                    &session,
                    stored.plan,
                    &stored.request,
                    confirmation,
                    journal,
                )
                .await
        })
        .await
        .map_err(|_| SystemInfoApiError::Deadline)?
        .map_err(action_failure)?;
        self.ensure_binding_unchanged(binding_handle, &session)?;
        // The plan is taken before the run, so a second execute for the same
        // tag fails here first and in the core precondition either way.
        serde_json::to_value(&FirewallResultDto {
            verified: outcome.verification.passed,
            detail: bounded_text(&outcome.verification.detail, MAX_PLAN_TEXT_BYTES),
            restore_handle: None,
        })
        .map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }

    fn lock_firewall(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, FirewallRegistry>, SystemInfoApiError> {
        self.firewall
            .lock()
            .map_err(|_| SystemInfoApiError::RegistryUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::system_info::SystemInfoRisk;

    use super::*;

    fn table(tab: SystemInfoTab, rows: Vec<Vec<&str>>) -> SystemInfoTable {
        SystemInfoTable {
            tab,
            columns: tab
                .columns()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            rows: rows
                .into_iter()
                .enumerate()
                .map(|(index, cells)| SystemInfoRow {
                    id: format!("row-{index}"),
                    cells: cells.into_iter().map(str::to_owned).collect(),
                    risk: SystemInfoRisk::Normal,
                })
                .collect(),
            truncated: false,
            missing_tool: None,
            failed_tool: None,
        }
    }

    fn actions_for(table: &SystemInfoTable, row_id: &str) -> Vec<(String, String, bool)> {
        RowAction::candidates(table.tab)
            .into_iter()
            .filter(|action| applies(table, row_id, *action))
            .map(|action| (action.group().0, action.key(), action.dangerous()))
            .collect()
    }

    #[test]
    fn every_action_key_round_trips_and_is_unique() {
        // Two or three kebab-case segments, nothing else: the renderer's
        // validator accepts exactly this shape.
        fn well_formed(key: &str) -> bool {
            let segments: Vec<&str> = key.split('.').collect();
            (2..=3).contains(&segments.len())
                && segments.iter().all(|segment| {
                    segment
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase())
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
        }
        let mut seen: HashMap<String, RowAction> = HashMap::new();
        let mut total = 0;
        for tab in SystemInfoTab::ALL {
            for action in RowAction::candidates(tab) {
                let key = action.key();
                assert!(well_formed(&key), "{key} is not a well-formed key");
                assert!(key.len() <= MAX_ACTION_KEY_BYTES);
                assert_eq!(
                    RowAction::parse(&key),
                    Some(action),
                    "{key} does not parse back"
                );
                assert!(!action.label().is_empty());
                // The same action may be offered by several tabs (network
                // rows, account locks), but one key must always mean one thing.
                if let Some(previous) = seen.insert(key.clone(), action) {
                    assert_eq!(previous, action, "{key} maps to two actions");
                }
                total += 1;
            }
        }
        assert!(total > 200, "expected the full catalogue, got {total}");
        assert!(
            seen.len() > 150,
            "expected distinct keys, got {}",
            seen.len()
        );
    }

    #[test]
    fn forged_keys_name_nothing() {
        for hostile in [
            "",
            "process",
            "process.",
            "process.signal",
            "process.signal.hup",
            "process.kill -9",
            "network.disconnect.now",
            "shell.rm-rf",
            "module.blacklist.everything",
            "../process.open-files",
            "Process.Open-Files",
            &"process.".repeat(20),
        ] {
            assert_eq!(RowAction::parse(hostile), None, "{hostile:?} parsed");
        }
    }

    #[test]
    fn process_rows_offer_grouped_inspection_and_dangerous_signals() {
        let table = table(
            SystemInfoTab::Processes,
            vec![vec![
                "normal",
                "4242",
                "1",
                "root",
                "S",
                "0.1",
                "0.5",
                "120",
                "/usr/bin/sshd -D",
            ]],
        );
        let actions = actions_for(&table, "row-0");
        assert!(actions.iter().any(|(group, key, dangerous)| {
            group == "basics" && key == "process.command-line" && !dangerous
        }));
        assert!(actions.iter().any(|(group, key, dangerous)| {
            group == "change" && key == "process.signal.kill" && *dangerous
        }));
        assert_eq!(actions.len(), ProcessInvestigationAction::ALL.len() + 3);
        // The change group comes last, after every read-only group.
        let first_change = actions
            .iter()
            .position(|(group, ..)| group == "change")
            .unwrap();
        assert!(
            actions[first_change..]
                .iter()
                .all(|(group, ..)| group == "change")
        );
        assert_eq!(
            row_subject(&table, &table.rows[0]),
            "PID 4242 · /usr/bin/sshd -D"
        );
    }

    #[test]
    fn rows_that_cannot_take_an_action_are_not_offered_it() {
        let ports = table(
            SystemInfoTab::OpenPorts,
            vec![
                vec![
                    "udp",
                    "0.0.0.0",
                    "53",
                    "12",
                    "systemd-resolve",
                    "systemd-resolve",
                ],
                vec!["tcp", "0.0.0.0", "22", "33", "sshd", "root"],
            ],
        );
        // A listening socket has no peer to disconnect, whatever the transport.
        for row in ["row-0", "row-1"] {
            assert!(
                actions_for(&ports, row)
                    .iter()
                    .all(|(_, key, _)| key != "network.disconnect")
            );
        }
        // Nor can a UDP row be TCP-probed, while the TCP one can be asked
        // which process owns the port.
        assert!(
            actions_for(&ports, "row-0")
                .iter()
                .all(|(_, key, _)| key != "network.tcp-probe")
        );
        assert!(
            actions_for(&ports, "row-1")
                .iter()
                .any(|(_, key, _)| key == "network.port-process")
        );

        let established = table(
            SystemInfoTab::Established,
            vec![vec![
                "10.0.0.5:44210",
                "203.0.113.9",
                "4444",
                "777",
                "nc",
                "www-data",
            ]],
        );
        let keys: Vec<_> = actions_for(&established, "row-0")
            .into_iter()
            .map(|(_, key, _)| key)
            .collect();
        assert!(keys.contains(&"network.disconnect".to_owned()));
        assert!(keys.contains(&"network.whois".to_owned()));
        assert_eq!(
            row_subject(&established, &established.rows[0]),
            "10.0.0.5:44210 → 203.0.113.9"
        );

        // A shell line that is already a comment cannot be commented again.
        let shell = table(
            SystemInfoTab::ShellConfigs,
            vec![
                vec![
                    "/root/.bashrc",
                    "root",
                    "1700000000",
                    "3",
                    "# harmless",
                    "normal",
                ],
                vec![
                    "/root/.bashrc",
                    "root",
                    "1700000000",
                    "9",
                    "curl x | sh",
                    "high",
                ],
            ],
        );
        assert!(
            actions_for(&shell, "row-0")
                .iter()
                .all(|(_, key, _)| key != "shell.comment-line")
        );
        assert!(
            actions_for(&shell, "row-1")
                .iter()
                .any(|(_, key, _)| key == "shell.comment-line")
        );

        // An authorized-key row can be deleted; one whose cells no longer
        // describe a key cannot.
        let keys = table(
            SystemInfoTab::SshKeys,
            vec![
                vec![
                    "root",
                    "ssh-rsa",
                    "AAAAB3NzaC1yc2EAAAADAQABAAABAQDa",
                    "ops@laptop",
                    "/root/.ssh/authorized_keys",
                ],
                vec![
                    "root",
                    "ssh-rsa",
                    "not a blob",
                    "ops@laptop",
                    "/root/.ssh/authorized_keys",
                ],
            ],
        );
        assert!(
            actions_for(&keys, "row-0")
                .iter()
                .any(|(group, key, dangerous)| {
                    group == "change" && key == "ssh-key.delete" && *dangerous
                })
        );
        assert!(
            actions_for(&keys, "row-1")
                .iter()
                .all(|(_, key, _)| key != "ssh-key.delete")
        );

        // Tabs without a row vocabulary offer nothing, and a missing row is
        // refused rather than answered with the tab's defaults.
        let firewall = table(
            SystemInfoTab::Firewall,
            vec![vec![
                "INPUT",
                "ACCEPT",
                "tcp",
                "0.0.0.0/0",
                "0.0.0.0/0",
                "dpt:22",
            ]],
        );
        assert!(actions_for(&firewall, "row-0").is_empty());
        assert!(RowAction::candidates(SystemInfoTab::Rootcheck).is_empty());
        assert!(matches!(
            find_row(&firewall, "row-99"),
            Err(SystemInfoApiError::InvalidRow)
        ));
    }

    #[test]
    fn hostile_cells_are_bounded_and_never_echoed_by_debug() {
        let hostile = "<script>steal()</script>".repeat(40);
        let table = table(
            SystemInfoTab::Users,
            vec![vec![&hostile, "0", "0", "/root", "/bin/bash"]],
        );
        let subject = row_subject(&table, &table.rows[0]);
        assert!(subject.len() <= MAX_SUBJECT_BYTES + "…".len());
        assert!(subject.ends_with('…'));
        // An invalid username means the user vocabulary does not apply.
        assert!(actions_for(&table, "row-0").is_empty());
        let dto = SystemInfoRowInspectionDto {
            tab: "users",
            row_id: "row-0".to_owned(),
            action: "user.details".to_owned(),
            label: "用户详情",
            subject,
            output: hostile.clone(),
            truncated: false,
        };
        let debug = format!("{dto:?}");
        assert!(!debug.contains("steal()"));
        assert!(!format!("{:?}", RowPlanRegistry::default()).contains("row-0"));
    }

    #[test]
    fn execution_failures_are_described_without_the_core_wording() {
        let stale = CoreError::Validation {
            subject: "process signal precondition",
            message: "identity changed".to_owned(),
        };
        assert!(execution_failure_detail(&stale).contains("刷新"));
        assert!(!execution_failure_detail(&stale).contains("identity"));
        // A target that never answered is a timeout, not a row that moved on.
        let timed_out = action_failure(CoreError::Validation {
            subject: "system information command",
            message: "process identity failed (exit=None, timed_out=true)".to_owned(),
        });
        assert!(matches!(timed_out, SystemInfoApiError::Deadline));

        let refusal = action_failure(stale);
        assert!(matches!(refusal, SystemInfoApiError::ActionUnavailable(_)));
        // The reason is kept for the log, and never printed by Debug.
        assert!(!format!("{refusal:?}").contains("identity changed"));
        assert!(matches!(
            action_failure(CoreError::NotFound {
                entity: "process",
                id: "1".to_owned()
            }),
            SystemInfoApiError::ActionUnavailable(_)
        ));
    }

    #[test]
    fn firewall_requests_reject_extra_fields_and_bad_values() {
        // Extra field anywhere is refused before any action runs.
        assert!(serde_json::from_str::<FirewallRequest>(
            r#"{"action":"plan","bindingHandle":"b","address":"1.2.3.4","direction":"both","extra":1}"#
        )
        .is_err());
        // Unknown action tag.
        assert!(
            serde_json::from_str::<FirewallRequest>(
                r#"{"action":"flush-all","bindingHandle":"b"}"#
            )
            .is_err()
        );
        // Missing required field per action.
        assert!(
            serde_json::from_str::<FirewallRequest>(r#"{"action":"execute","bindingHandle":"b"}"#)
                .is_err()
        );
        for bad in ["", "in", "INBOUND", "everything"] {
            assert!(
                matches!(
                    firewall_direction(bad),
                    Err(SystemInfoApiError::InvalidAction)
                ),
                "{bad}"
            );
        }
        for bad in [
            "",
            "not-an-ip",
            "10.0.0.0/8",
            "127.0.0.1",
            "0.0.0.0",
            "ff02::1",
            "1.2.3.4/32",
            "x".repeat(46).as_str(),
        ] {
            let parsed: Result<std::net::IpAddr, _> = bad.parse();
            let rejected = parsed
                .map_err(|_| ())
                .and_then(|ip| {
                    FirewallBlockRequest::new(ip, FirewallDirection::Both).map_err(|_| ())
                })
                .is_err();
            assert!(rejected, "{bad}");
        }
        assert!(matches!(
            firewall_direction("inbound"),
            Ok(FirewallDirection::Inbound)
        ));
        assert!(
            FirewallBlockRequest::new("198.51.100.9".parse().unwrap(), FirewallDirection::Outbound)
                .is_ok()
        );
        assert_eq!(direction_key(FirewallDirection::Outbound), "outbound");
    }

    #[test]
    fn firewall_registry_drops_state_on_close_binding() {
        let now = Instant::now();
        let mut registry = FirewallRegistry::default();
        let request =
            FirewallBlockRequest::new("198.51.100.9".parse().unwrap(), FirewallDirection::Both)
                .unwrap();
        registry.restores.insert(
            "h1".to_owned(),
            StoredFirewallRestore {
                binding_handle: "b1".to_owned(),
                request: request.clone(),
                token: "iptables|lovelyhawk-block-a1b2c3d4|0".to_owned(),
                expires_at: now + FIREWALL_RESTORE_TTL,
            },
        );
        registry.restores.insert(
            "h2".to_owned(),
            StoredFirewallRestore {
                binding_handle: "b2".to_owned(),
                request,
                token: "iptables|lovelyhawk-block-a1b2c3d5|0".to_owned(),
                expires_at: now + FIREWALL_RESTORE_TTL,
            },
        );
        // A second binding's handle is foreign to the first binding.
        assert!(
            registry
                .restores
                .get("h2")
                .is_some_and(|r| r.binding_handle != "b1")
        );
        registry.close_binding("b1");
        assert!(!registry.restores.contains_key("h1"));
        assert!(registry.restores.contains_key("h2"));
        // Expired restores are pruned, so a stale handle can never restore.
        let mut registry = FirewallRegistry::default();
        registry.restores.insert(
            "old".to_owned(),
            StoredFirewallRestore {
                binding_handle: "b".to_owned(),
                request: FirewallBlockRequest::new(
                    "198.51.100.9".parse().unwrap(),
                    FirewallDirection::Both,
                )
                .unwrap(),
                token: "t".to_owned(),
                expires_at: now - Duration::from_secs(1),
            },
        );
        registry.prune(now);
        assert!(registry.restores.is_empty());
    }

    #[test]
    fn firewall_response_shapes_are_camel_case() {
        let plan = serde_json::to_value(FirewallPlanDto {
            plan_handle: "p".to_owned(),
            backend: "iptables".to_owned(),
            address: "198.51.100.9".to_owned(),
            direction: "both".to_owned(),
            commands: vec!["iptables -I INPUT 1".to_owned()],
            warnings: vec!["w".to_owned()],
            expires_in_ms: 120_000,
        })
        .unwrap();
        assert!(
            serde_json::to_string(&plan)
                .unwrap()
                .contains("\"planHandle\":")
        );
        for key in ["planHandle", "expiresInMs", "commands", "warnings"] {
            assert!(plan.get(key).is_some(), "{key}");
        }
        assert!(plan.get("plan_handle").is_none());
        let result = serde_json::to_value(FirewallResultDto {
            verified: true,
            detail: "d".to_owned(),
            restore_handle: Some("r".to_owned()),
        })
        .unwrap();
        for key in ["verified", "detail", "restoreHandle"] {
            assert!(result.get(key).is_some(), "{key}");
        }
        let restore = serde_json::to_value(FirewallRestorePlanDto {
            plan_handle: "p".to_owned(),
            backend: "nft".to_owned(),
            address: "fd00::9".to_owned(),
            direction: "inbound".to_owned(),
            expires_in_ms: 120_000,
        })
        .unwrap();
        for key in [
            "planHandle",
            "backend",
            "address",
            "direction",
            "expiresInMs",
        ] {
            assert!(restore.get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn kernel_module_rows_offer_unload_as_a_dangerous_change() {
        let modules = table(
            SystemInfoTab::KernelModules,
            vec![vec!["nf_conntrack", "172032", "1", "normal"]],
        );
        let actions = actions_for(&modules, "row-0");
        let unload = actions
            .iter()
            .find(|(_, key, _)| key == "kernel-module.unload")
            .expect("kernel module rows offer unload");
        assert_eq!(unload.0, "change");
        assert!(unload.2, "unload is marked dangerous");
        assert_eq!(RowAction::KernelModuleUnload.label(), "卸载模块");
        assert!(RowAction::KernelModuleUnload.changes_host());
        // A row whose first cell is not a module name still cannot take it.
        let broken = table(
            SystemInfoTab::KernelModules,
            vec![vec!["", "0", "0", "normal"]],
        );
        assert!(!applies(&broken, "row-0", RowAction::KernelModuleUnload));
        assert!(
            !actions_for(&broken, "row-0")
                .iter()
                .any(|(_, key, _)| key == "kernel-module.unload")
        );
    }

    #[test]
    fn kernel_module_unload_key_parses_to_exactly_one_action() {
        assert_eq!(
            RowAction::parse("kernel-module.unload"),
            Some(RowAction::KernelModuleUnload)
        );
        assert_eq!(
            RowAction::KernelModuleUnload.key(),
            "kernel-module.unload"
        );
        for near_miss in [
            "kernel-module.unload-now",
            "kernel-module",
            "module.unload",
            "kernel-module.remove",
        ] {
            assert_eq!(RowAction::parse(near_miss), None, "{near_miss} parsed");
        }
    }

    #[test]
    fn service_and_autostart_rows_offer_remove_unit_as_a_dangerous_change() {
        let services = table(
            SystemInfoTab::Services,
            vec![vec!["lh-beacon.service", "active (running)", "enabled", "beacon"]],
        );
        let actions = actions_for(&services, "row-0");
        let removal = actions
            .iter()
            .find(|(_, key, _)| key == "service.remove-unit")
            .expect("service rows offer unit removal");
        assert_eq!(removal.0, "change");
        assert!(removal.2, "unit removal is marked dangerous");
        assert_eq!(RowAction::ServiceRemoveUnit.label(), "移除服务单元");
        assert!(RowAction::ServiceRemoveUnit.changes_host());
        // A non-unit first cell cannot take it.
        let broken = table(
            SystemInfoTab::Services,
            vec![vec!["not a unit", "active", "enabled", "x"]],
        );
        assert!(!applies(&broken, "row-0", RowAction::ServiceRemoveUnit));
        // Autostart rows only offer it for systemd service entries.
        let autostart = table(
            SystemInfoTab::Autostart,
            vec![
                vec!["lh-beacon.service", "sleep 3600", "enabled", "systemd"],
                vec!["lh-rc", "/etc/init.d/lh-rc", "enabled", "init.d"],
                vec!["lh.timer", "sleep 60", "enabled", "systemd"],
            ],
        );
        let offered: Vec<String> = actions_for(&autostart, "row-0")
            .into_iter()
            .map(|(_, key, _)| key)
            .collect();
        assert!(offered.contains(&"service.remove-unit".to_owned()));
        for row_id in ["row-1", "row-2"] {
            assert!(!applies(&autostart, row_id, RowAction::ServiceRemoveUnit));
        }
        // Other tabs never offer it, whatever the row looks like.
        let timers = table(
            SystemInfoTab::Timers,
            vec![vec!["lh.timer", "*-*-* *:00", "-", "-"]],
        );
        assert!(
            !actions_for(&timers, "row-0")
                .iter()
                .any(|(_, key, _)| key == "service.remove-unit")
        );
    }

    #[test]
    fn service_remove_unit_key_parses_to_exactly_one_action() {
        assert_eq!(
            RowAction::parse("service.remove-unit"),
            Some(RowAction::ServiceRemoveUnit)
        );
        assert_eq!(RowAction::ServiceRemoveUnit.key(), "service.remove-unit");
        for near_miss in [
            "service.remove",
            "service.remove-unit-now",
            "systemd.remove-unit",
            "service.runtime.remove-unit",
        ] {
            assert_eq!(RowAction::parse(near_miss), None, "{near_miss} parsed");
        }
    }
}
