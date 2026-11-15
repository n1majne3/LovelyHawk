//! Unloading a loaded kernel module by name — the `kernel-module.unload` row
//! action on the kernel-module inventory.
//!
//! The mutation is a remote command rather than a file write, so it follows
//! the process-signal shape: one bounded probe feeds an immutable plan,
//! execution re-reads every identity field and refuses to act on any drift,
//! and verification reads the kernel tables again afterwards. Removal is not
//! reversible from here, so the plan says so up front.

use std::time::Duration;

use async_trait::async_trait;

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::shq;
use crate::ssh::{BoundSshSession, SshCommandOutput};
use crate::system_info::{is_valid_module_name, SystemInfoService, PRECONDITION_TIMEOUT};

/// Refusal subjects the backend maps to operator-facing codes.
pub const KERNEL_MODULE_ABSENT_REFUSAL: &str = "kernel module absent";
pub const KERNEL_MODULE_IN_USE_REFUSAL: &str = "kernel module in use";
pub const KERNEL_MODULE_DISABLED_REFUSAL: &str = "kernel module disabled";
pub const KERNEL_MODULE_TOOLS_REFUSAL: &str = "kernel module tools";
pub const KERNEL_MODULE_PRIVILEGE_REFUSAL: &str = "kernel module privilege";
pub const KERNEL_MODULE_CHANGED_REFUSAL: &str = "kernel module changed";
pub const KERNEL_MODULE_PROBE_REFUSAL: &str = "kernel module probe";

const RMMOD_TIMEOUT: Duration = Duration::from_secs(15);

/// A kernel-module row resolved to the name the kernel would unload.
#[derive(Debug, Clone)]
pub struct KernelModuleUnloadRequest {
    pub row_id: String,
    pub module: String,
}

/// Which rmmod spelling the host answered to at plan time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnloadTool {
    Rmmod,
    Busybox,
}

/// What one bounded probe learns about the module and the account that would
/// unload it. Fields that distinguish a refusal from a malformed answer stay
/// `Option` so an unreadable field refuses instead of being guessed.
#[derive(Debug, Default)]
struct ModuleProbe {
    is_root: bool,
    sudo: bool,
    tool: Option<UnloadTool>,
    modules_disabled: Option<bool>,
    /// `Some` when /proc/modules carried a line for exactly this name.
    line: Option<ProcModulesLine>,
    /// The /proc/modules read failed or its line for this name was ambiguous:
    /// neither "listed" nor "absent" can be claimed.
    line_unreadable: bool,
    line_absent: bool,
    sys_module_present: Option<bool>,
    sys_refcnt: Option<Option<u32>>,
    holders: Option<Vec<String>>,
    taint: Option<String>,
}

/// The /proc/modules line, split: `name size refcount deps state address`.
/// The refcount is `Option` because kernels built without module unload put
/// `-` there — that is a refusal of its own, not a zero.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcModulesLine {
    size: String,
    refcount: Option<u32>,
    deps: String,
    state: String,
    address: String,
}

/// The identity a plan is bound to: if any of this moves before execution,
/// the plan refuses rather than unload something it did not describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelModuleSnapshot {
    pub name: String,
    pub size: String,
    pub address: String,
    pub refcount: u32,
    pub state: String,
    pub taint: String,
    pub holders: Vec<String>,
    /// /sys/module/<name>/refcnt when readable; `None` when the file was not
    /// there or not readable while the module directory existed.
    pub sys_refcnt: Option<u32>,
    sys_module_present: bool,
}

/// The confirmed, target-bound description of one unload.
#[derive(Debug)]
pub struct KernelModuleUnloadPlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: KernelModuleSnapshot,
    tool: UnloadTool,
    /// Run through `sudo -n` when the session is not root.
    sudo: bool,
}

impl KernelModuleUnloadPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }
}

/// What a completed unload reports back.
#[derive(Debug)]
pub struct KernelModuleUnloadOutcome {
    pub module: String,
    pub verification: VerificationResult,
}

fn probe_command(module: &str) -> String {
    let n = shq(module);
    format!(
        "n={n}; \
         printf 'UID|%s\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         if command -v rmmod >/dev/null 2>&1; then echo 'RMMOD|rmmod'; \
         elif command -v busybox >/dev/null 2>&1 && busybox --list 2>/dev/null | grep -qx rmmod; then echo 'RMMOD|busybox'; \
         else echo 'RMMOD|none'; fi; \
         if [ -r /proc/sys/kernel/modules_disabled ]; then printf 'MDIS|%s\n' \"$(cat /proc/sys/kernel/modules_disabled)\"; else echo 'MDIS|missing'; fi; \
         awk -v m=\"$n\" '$1==m{{print \"MOD|\"$2\"|\"$3\"|\"$4\"|\"$5\"|\"$6; found=1}} END{{if(!found) print \"MOD|absent\"}}' /proc/modules 2>/dev/null || echo 'MOD|unreadable'; \
         if [ -d \"/sys/module/$n\" ]; then echo 'SYSMOD|present'; \
         if [ -r \"/sys/module/$n/refcnt\" ]; then printf 'REFCNT|%s\n' \"$(cat \"/sys/module/$n/refcnt\")\"; else echo 'REFCNT|unreadable'; fi; \
         if [ -d \"/sys/module/$n/holders\" ]; then printf 'HOLDERS|%s\n' \"$(ls \"/sys/module/$n/holders\" 2>/dev/null | tr '\\n' ' ')\"; else echo 'HOLDERS|unreadable'; fi; \
         if [ -r \"/sys/module/$n/taint\" ]; then printf 'TAINT|%s\n' \"$(tr ' ' ',' < \"/sys/module/$n/taint\")\"; else echo 'TAINT|unreadable'; fi; \
         else echo 'SYSMOD|absent'; fi"
    )
}

/// The /proc/modules answers that veto an unload before any tool runs: a
/// `[permanent]` dep means the module has no exit path at all, and a refcount
/// that is not a number means the kernel cannot unload (or the field could not
/// be read) — either way not a zero.
fn unload_veto(line: &ProcModulesLine) -> Option<CoreError> {
    if line.deps.contains("[permanent]") {
        return Some(CoreError::validation(
            KERNEL_MODULE_IN_USE_REFUSAL,
            "模块没有卸载入口，只能重启后不再加载",
        ));
    }
    if line.refcount.is_none() {
        return Some(CoreError::validation(
            KERNEL_MODULE_PROBE_REFUSAL,
            "内核不支持卸载模块或无法读取引用计数",
        ));
    }
    None
}

fn parse_probe(output: &str) -> ModuleProbe {
    let mut probe = ModuleProbe::default();
    for line in output.lines() {
        let mut parts = line.split('|');
        match parts.next() {
            Some("UID") => probe.is_root = parts.next().is_some_and(|v| v.trim() == "0"),
            Some("SUDO") => probe.sudo = parts.next().is_some_and(|v| v.trim() == "yes"),
            Some("RMMOD") => {
                probe.tool = match parts.next().map(str::trim) {
                    Some("rmmod") => Some(UnloadTool::Rmmod),
                    Some("busybox") => Some(UnloadTool::Busybox),
                    _ => None,
                };
            }
            Some("MDIS") => {
                probe.modules_disabled = parts.next().and_then(|v| match v.trim() {
                    "0" => Some(false),
                    "1" => Some(true),
                    _ => None,
                });
            }
            Some("MOD") => {
                // MOD|size|refcount|deps|state|address, MOD|absent, or
                // MOD|unreadable.
                let rest: Vec<&str> = line.split('|').skip(1).collect();
                match rest.first().map(|v| v.trim()) {
                    Some("absent") => probe.line_absent = true,
                    Some("unreadable") => probe.line_unreadable = true,
                    _ if rest.len() >= 5 => {
                        probe.line = Some(ProcModulesLine {
                            size: rest[0].trim().to_owned(),
                            refcount: rest[1].trim().parse().ok(),
                            deps: rest[2].trim().to_owned(),
                            state: rest[3].trim().to_owned(),
                            address: rest[4].trim().to_owned(),
                        });
                    }
                    _ => probe.line_unreadable = true,
                }
            }
            Some("SYSMOD") => {
                probe.sys_module_present = Some(parts.next().is_some_and(|v| v.trim() == "present"));
            }
            Some("REFCNT") => {
                probe.sys_refcnt = Some(parts.next().and_then(|v| v.trim().parse().ok()));
            }
            Some("HOLDERS") => {
                let value = parts.next().unwrap_or_default();
                probe.holders = match value.trim() {
                    "unreadable" => None,
                    other => Some(
                        other
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect::<Vec<String>>(),
                    ),
                };
            }
            Some("TAINT") => {
                probe.taint = match parts.next().map(|v| v.trim().trim_end_matches(',')) {
                    Some("unreadable") | None => None,
                    other => other.map(str::to_owned),
                };
            }
            _ => {}
        }
    }
    probe
}

impl SystemInfoService {
    /// Describe unloading the module the row named.
    ///
    /// The probe reads /proc/modules, /sys/module/<name> and the tools that
    /// could act on it once, and every readable field has to agree with what
    /// an unload needs: listed, refcount zero, Live, no holders, modules
    /// still mutable on this boot.
    pub async fn plan_kernel_module_unload(
        &self,
        session: &BoundSshSession,
        request: &KernelModuleUnloadRequest,
    ) -> CoreResult<KernelModuleUnloadPlan> {
        self.target.validate(session.target())?;
        if !is_valid_module_name(&request.module) {
            return Err(CoreError::validation(
                KERNEL_MODULE_PROBE_REFUSAL,
                "invalid kernel module name",
            ));
        }
        let output = self
            .ssh
            .execute_bound(session, probe_command(&request.module), PRECONDITION_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(CoreError::validation(
                KERNEL_MODULE_PROBE_REFUSAL,
                "kernel module probe timed out",
            ));
        }
        let probe = parse_probe(&output.output);
        if probe.line_unreadable {
            return Err(CoreError::validation(
                KERNEL_MODULE_PROBE_REFUSAL,
                "/proc/modules 读不回来或解析不出这个模块的行，无法确认能安全按名卸载",
            ));
        }
        let Some(line) = probe.line else {
            return Err(CoreError::validation(
                KERNEL_MODULE_ABSENT_REFUSAL,
                "模块未出现在 /proc/modules：可能已卸载、为内核内置，或已自我隐藏，隐藏模块无法按名卸载",
            ));
        };
        if probe.modules_disabled == Some(true) {
            return Err(CoreError::validation(
                KERNEL_MODULE_DISABLED_REFUSAL,
                "模块加载/卸载已被内核禁用（modules_disabled=1），重启之前无法卸载",
            ));
        }
        if probe.tool.is_none() {
            return Err(CoreError::validation(
                KERNEL_MODULE_TOOLS_REFUSAL,
                "目标机缺少 rmmod 或 busybox rmmod，无法按名卸载模块",
            ));
        }
        if !(probe.is_root || probe.sudo) {
            return Err(CoreError::validation(
                KERNEL_MODULE_PRIVILEGE_REFUSAL,
                "需要 root 或免密码 sudo 才能卸载内核模块",
            ));
        }
        // Every readable field that can veto has to say "unloaded-able"; a
        // missing answer is a probe failure, not a pass.
        if probe.modules_disabled.is_none()
            || probe.sys_module_present != Some(true)
            || probe.sys_refcnt.is_none()
            || probe.holders.is_none()
            || probe.taint.is_none()
        {
            return Err(CoreError::validation(
                KERNEL_MODULE_PROBE_REFUSAL,
                "内核模块探测结果不完整或有字段读不出来，未敢按名卸载",
            ));
        }
        let holders = probe.holders.unwrap_or_default();
        let sys_refcnt = probe.sys_refcnt.flatten();
        if let Some(veto) = unload_veto(&line) {
            return Err(veto);
        }
        let refcount = line.refcount.unwrap_or_default();
        if refcount != 0 {
            return Err(CoreError::validation(
                KERNEL_MODULE_IN_USE_REFUSAL,
                format!("模块仍在被引用（/proc/modules 引用计数 {}），卸载会失败", refcount),
            ));
        }
        if line.state != "Live" {
            return Err(CoreError::validation(
                KERNEL_MODULE_IN_USE_REFUSAL,
                format!("模块当前状态为 {}，只有 Live 状态的模块可以按名卸载", line.state),
            ));
        }
        if !holders.is_empty() {
            return Err(CoreError::validation(
                KERNEL_MODULE_IN_USE_REFUSAL,
                format!("仍有模块依赖它（holders: {}），先处理依赖再卸载", holders.join(", ")),
            ));
        }
        if sys_refcnt.is_some_and(|count| count != 0) {
            return Err(CoreError::validation(
                KERNEL_MODULE_IN_USE_REFUSAL,
                format!(
                    "sysfs 引用计数为 {}，仍有内核代码持有它，卸载会失败",
                    sys_refcnt.unwrap_or_default()
                ),
            ));
        }
        let taint = probe.taint.unwrap_or_default();
        let snapshot = KernelModuleSnapshot {
            name: request.module.clone(),
            size: line.size,
            address: line.address,
            refcount,
            state: line.state,
            taint: taint.clone(),
            holders,
            sys_refcnt,
            sys_module_present: true,
        };
        let tool = probe.tool.unwrap_or(UnloadTool::Rmmod);
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "卸载内核模块 {}（大小 {}，地址 {}，污点：{}，holders：无）。\
                 卸载一个正在挂钩内核的模块可能导致系统立即崩溃或断开连接；建议先用‘模块复活点’条目清掉所有自动加载位置，再卸载或直接重启。\
                 卸载后不提供自动恢复；重新加载需要原模块文件，而它可能就是恶意程序。\
                 成功只说明内核不再列出这个模块，不等于这台主机已经干净。",
                snapshot.name,
                snapshot.size,
                snapshot.address,
                if taint.is_empty() { "无".to_owned() } else { taint },
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-kernel-module".to_owned());
        operation
            .metadata
            .insert("module".to_owned(), snapshot.name.clone());
        operation
            .metadata
            .insert("address".to_owned(), snapshot.address.clone());
        Ok(KernelModuleUnloadPlan {
            operation,
            row_id: request.row_id.clone(),
            snapshot,
            tool,
            sudo: !probe.is_root,
        })
    }

    pub async fn execute_kernel_module_unload(
        &self,
        session: &BoundSshSession,
        plan: KernelModuleUnloadPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<KernelModuleUnloadOutcome> {
        let executor = KernelModuleUnloadExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        Ok(KernelModuleUnloadOutcome {
            module: plan.snapshot.name,
            verification,
        })
    }
}

#[derive(Debug)]
struct KernelModuleUnloadExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a KernelModuleUnloadPlan,
}

impl KernelModuleUnloadExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "kernel module unload operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn probe(&self) -> CoreResult<(KernelModuleSnapshot, ModuleProbe)> {
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                probe_command(&self.plan.snapshot.name),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        if output.timed_out {
            return Err(CoreError::validation(
                KERNEL_MODULE_PROBE_REFUSAL,
                "kernel module re-probe timed out",
            ));
        }
        let probe = parse_probe(&output.output);
        let snapshot = KernelModuleSnapshot {
            name: self.plan.snapshot.name.clone(),
            size: probe
                .line
                .as_ref()
                .map(|line| line.size.clone())
                .unwrap_or_default(),
            address: probe
                .line
                .as_ref()
                .map(|line| line.address.clone())
                .unwrap_or_default(),
            refcount: probe
                .line
                .as_ref()
                .and_then(|line| line.refcount)
                .unwrap_or(u32::MAX),
            state: probe
                .line
                .as_ref()
                .map(|line| line.state.clone())
                .unwrap_or_default(),
            taint: probe.taint.clone().unwrap_or_default(),
            holders: probe.holders.clone().unwrap_or_default(),
            sys_refcnt: probe.sys_refcnt.flatten(),
            sys_module_present: probe.sys_module_present == Some(true),
        };
        Ok((snapshot, probe))
    }
}

#[async_trait]
impl OperationExecutor for KernelModuleUnloadExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let (observed, _probe) = self.probe().await?;
        if observed != self.plan.snapshot {
            return Err(CoreError::validation(
                KERNEL_MODULE_CHANGED_REFUSAL,
                "内核模块的标识在确认之后变了（大小、地址、引用计数或依赖），这次没有卸载",
            ));
        }
        self.service.target.validate(&operation.target)?;
        let prefix = if self.plan.sudo { "sudo -n " } else { "" };
        let command = match self.plan.tool {
            UnloadTool::Rmmod => format!("n={}; {prefix}rmmod -- \"$n\"", shq(&self.plan.snapshot.name)),
            UnloadTool::Busybox => format!(
                "n={}; {prefix}busybox rmmod -- \"$n\"",
                shq(&self.plan.snapshot.name)
            ),
        };
        let output: SshCommandOutput = self
            .service
            .ssh
            .execute_bound(self.session, command, RMMOD_TIMEOUT)
            .await?;
        let stderr_tail: String = output
            .output
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" / ");
        let dispatch_summary = if output.timed_out {
            "indeterminate-timeout".to_owned()
        } else if output.exit_code == Some(0) {
            "accepted".to_owned()
        } else {
            format!(
                "rejected-exit-{:?}{}",
                output.exit_code,
                if stderr_tail.is_empty() {
                    String::new()
                } else {
                    format!("：{stderr_tail}")
                }
            )
        };
        Ok(ExecutionReceipt {
            summary: format!(
                "rmmod {}（地址 {}，污点 {}）：{dispatch_summary}",
                self.plan.snapshot.name, self.plan.snapshot.address, self.plan.snapshot.taint
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let (observed, probe) = self.probe().await?;
        let passed = probe.line_absent && !observed.sys_module_present;
        let detail = if passed {
            format!(
                "回读：/proc/modules 与 /sys/module 都不再列出 {}。",
                self.plan.snapshot.name
            )
        } else if probe.line_absent && observed.sys_module_present {
            format!(
                "内核表已不列出但 /sys/module 仍在，需要重启后复核（{}）。",
                self.plan.snapshot.name
            )
        } else if probe.line_unreadable {
            format!(
                "回读：/proc/modules 这次读不回来，{} 是否已卸载无法确认，请手工复核。",
                self.plan.snapshot.name
            )
        } else {
            format!(
                "回读：{} 仍出现在内核模块表中（状态 {}），卸载可能没有生效。",
                self.plan.snapshot.name, observed.state
            )
        };
        Ok(VerificationResult { passed, detail })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(CoreError::validation(
            "kernel module unload restore",
            "unloading a kernel module cannot be reversed",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_output(extra: &str) -> String {
        format!(
            "UID|0\nSUDO|no\nRMMOD|rmmod\nMDIS|0\n\
             MOD|16384|0|-|Live|0xffffffffc0000000\n\
             SYSMOD|present\nREFCNT|0\nHOLDERS|\nTAINT|\n{extra}"
        )
    }

    #[test]
    fn probe_parses_a_live_unloadable_module() {
        let probe = parse_probe(&probe_output(""));
        let line = probe.line.expect("module line parsed");
        assert!(probe.is_root && !probe.sudo);
        assert_eq!(probe.tool, Some(UnloadTool::Rmmod));
        assert_eq!(probe.modules_disabled, Some(false));
        assert_eq!(line.size, "16384");
        assert_eq!(line.refcount, Some(0));
        assert_eq!(line.deps, "-");
        assert_eq!(line.state, "Live");
        assert_eq!(line.address, "0xffffffffc0000000");
        assert_eq!(probe.sys_module_present, Some(true));
        assert_eq!(probe.sys_refcnt, Some(Some(0)));
        assert_eq!(probe.holders, Some(Vec::new()));
        assert_eq!(probe.taint.as_deref(), Some(""));
    }

    #[test]
    fn probe_marks_an_absent_module() {
        let probe = parse_probe(
            "UID|0\nSUDO|no\nRMMOD|rmmod\nMDIS|0\nMOD|absent\nSYSMOD|absent\n",
        );
        assert!(probe.line.is_none());
        assert_eq!(probe.sys_module_present, Some(false));
    }

    #[test]
    fn probe_keeps_unreadable_fields_distinct_from_empty() {
        let probe = parse_probe(
            "UID|0\nRMMOD|none\nMDIS|missing\nMOD|unreadable\n\
             SYSMOD|present\nREFCNT|unreadable\nHOLDERS|unreadable\nTAINT|unreadable\n",
        );
        assert!(probe.line.is_none());
        assert!(probe.line_unreadable);
        assert!(!probe.line_absent);
        assert_eq!(probe.modules_disabled, None);
        assert_eq!(probe.sys_refcnt, Some(None));
        assert_eq!(probe.holders, None);
        assert_eq!(probe.taint, None);
    }

    #[test]
    fn probe_collects_holders_and_taint() {
        let probe = parse_probe(
            "UID|1000\nSUDO|yes\nRMMOD|busybox\nMDIS|0\n\
             MOD|32768|2|dep_a,dep_b,|Live|0xffffffffc0010000\n\
             SYSMOD|present\nREFCNT|2\nHOLDERS|dep_a dep_b\nTAINT|O,E\n",
        );
        assert!(!probe.is_root && probe.sudo);
        assert_eq!(probe.tool, Some(UnloadTool::Busybox));
        assert_eq!(probe.holders, Some(vec!["dep_a".to_owned(), "dep_b".to_owned()]));
        assert_eq!(probe.taint.as_deref(), Some("O,E"));
    }

    #[test]
    fn a_permanent_module_and_a_missing_refcount_each_refuse_their_own_way() {
        let permanent = parse_probe(
            "UID|0\nSUDO|no\nRMMOD|rmmod\nMDIS|0\n\
             MOD|16384|-|[permanent],|Live|0xffffffffc0000000\n\
             SYSMOD|present\nREFCNT|0\nHOLDERS|\nTAINT|\n",
        );
        let line = permanent.line.expect("permanent module line parsed");
        assert_eq!(line.deps, "[permanent],");
        assert_eq!(line.refcount, None);
        let veto = unload_veto(&line).expect("permanent module refused");
        assert!(format!("{veto:?}").contains(KERNEL_MODULE_IN_USE_REFUSAL));

        let no_refcount = parse_probe(
            "UID|0\nSUDO|no\nRMMOD|rmmod\nMDIS|0\n\
             MOD|16384|-|-|Live|0xffffffffc0000000\n\
             SYSMOD|present\nREFCNT|0\nHOLDERS|\nTAINT|\n",
        );
        let line = no_refcount.line.expect("dashed refcount line parsed");
        let veto = unload_veto(&line).expect("unreadable refcount refused");
        assert!(format!("{veto:?}").contains(KERNEL_MODULE_PROBE_REFUSAL));
        assert!(veto.to_string().contains("无法读取引用计数"));
    }

    #[test]
    fn probe_command_quotes_and_bounds_every_read() {
        let command = probe_command("wire'guard");
        assert!(command.contains("n='wire'\\''guard'"));
        assert!(command.contains("awk -v m=\"$n\""));
        assert!(command.contains("/sys/module/$n/holders"));
        assert!(command.contains("busybox --list"));
    }
}
