//! Restarting a non-service process with its original command line — the
//! roadmap's "restart a business process as it was" remediation item.
//!
//! The writeup scenario: after repairing `app.py` the operator restarts the
//! hand-started `nohup python3 app.py`. A restart is a stop followed by a
//! launch, so the honesty rules differ from a file write:
//!
//! * Planning captures everything the relaunch needs — argv, cwd, uid,
//!   start-time ticks — and refuses processes that must not go through this
//!   path: PID 1 and kernel threads, processes in this SSH connection's own
//!   ancestry (stopping them cuts the channel doing the work), anything
//!   systemd already manages (the service action is the right tool), and
//!   processes the operator cannot signal or relaunch as.
//! * Execution re-probes the identity first; a process that exited or was
//!   replaced since the plan refuses untouched. Then SIGTERM, a grace wait,
//!   SIGKILL if needed, and the launch runs detached (`setsid`) under the
//!   original user in the original working directory.
//! * Verification scans `/proc` for a *new* process carrying the same argv,
//!   uid and cwd — a re-exec of the same binary under a different directory
//!   or user does not count — and confirms the old PID is gone or a zombie.
//! * There is no un-kill. When the launch fails and the old process is gone,
//!   the one restore retries the launch once; when the old process is still
//!   alive the restore refuses rather than spawn a duplicate. Either way the
//!   receipt keeps the original command line for manual recovery.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::shq;
use crate::ssh::BoundSshSession;
use crate::system_info::{
    PRECONDITION_TIMEOUT, SystemInfoService, command_failed, invalid_detail_key,
};

/// Refusal subjects the backend maps to operator-facing codes.
pub const RESTART_SESSION_REFUSAL: &str = "process restart session";
pub const RESTART_INIT_REFUSAL: &str = "process restart init";
pub const RESTART_MANAGED_REFUSAL: &str = "process restart managed";
pub const RESTART_PRIVILEGE_REFUSAL: &str = "process restart privilege";
pub const RESTART_TOOLS_REFUSAL: &str = "process restart tools";
pub const RESTART_CWD_REFUSAL: &str = "process restart cwd";
pub const RESTART_CHANGED_REFUSAL: &str = "process restart changed";

const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
/// The backend registry expires plans after five minutes.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);
const MAX_ARGV: usize = 64;
const MAX_ARG_BYTES: usize = 8 * 1_024;

/// Which channel puts the new process under the original user — decided by
/// the plan probe and reused verbatim by the launch.
#[derive(Clone, Debug)]
enum RunAs {
    /// The process owner is who we already are.
    Direct,
    /// Root drops to the user with `su` (no password needed as root).
    RootSu,
    /// A non-root operator needs passwordless sudo into that account.
    SudoUser,
}

#[derive(Debug)]
pub struct ProcessRestartPlan {
    operation: OperationPlan,
    row_id: String,
    pid: u32,
    start_time_ticks: u64,
    argv: Vec<String>,
    /// `od`-hex of `/proc/<pid>/cmdline` — the exact byte match a re-probe
    /// and the post-launch scan compare against.
    argv_hex: String,
    cwd: String,
    cwd_hex: String,
    uid: u32,
    user: String,
    run_as: RunAs,
    /// `""` when the operator can signal directly, `sudo -n ` otherwise.
    kill_prefix: &'static str,
}

impl ProcessRestartPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }
}

#[derive(Debug)]
pub struct ProcessRestartOutcome {
    pub pid: u32,
    pub verification: VerificationResult,
    /// The one relaunch retry after a failed verification — not a
    /// restoration of the killed process itself.
    pub relaunched_after_failure: bool,
}

/// What one bounded probe learns about the process and the tools around it.
#[derive(Debug, Default)]
struct RestartProbe {
    gone: bool,
    zombie: bool,
    start_time_ticks: u64,
    command_name: String,
    argv_hex: String,
    cwd_hex: String,
    uid: Option<u32>,
    user: String,
    /// The target's session id and every ancestor pid of our own shell — the
    /// chain whose death would sever this connection.
    ancestors: Vec<u32>,
    managed: bool,
    can_signal: bool,
    euid: Option<u32>,
    sudo: bool,
    setsid: bool,
    su: bool,
    sudo_u_ok: bool,
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> CoreResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid_detail_key("process hex field"));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| invalid_detail_key("process hex field"))
        })
        .collect()
}

fn decode_cwd(hex_text: &str) -> CoreResult<String> {
    let bytes = unhex(hex_text)?;
    String::from_utf8(bytes).map_err(|_| invalid_detail_key("process working directory"))
}

fn decode_argv(hex_text: &str) -> CoreResult<Vec<String>> {
    let bytes = unhex(hex_text)?;
    if bytes.is_empty() {
        return Err(CoreError::validation(
            RESTART_INIT_REFUSAL,
            "这个进程没有命令行（内核线程），不是这里处理的对象",
        ));
    }
    let argv: CoreResult<Vec<String>> = bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8(arg.to_vec()).map_err(|_| invalid_detail_key("process argv")))
        .collect();
    let argv = argv?;
    if argv.is_empty() || argv.len() > MAX_ARGV {
        return Err(invalid_detail_key("process argv"));
    }
    if argv.iter().map(String::len).sum::<usize>() > MAX_ARG_BYTES {
        return Err(CoreError::validation(
            RESTART_CWD_REFUSAL,
            "命令行过长，超出本次操作的安全边界",
        ));
    }
    Ok(argv)
}

/// One bounded probe: the process identity, everything a relaunch needs, and
/// the privilege/tool facts — all hex-encoded where target bytes cross the
/// wire so odd filenames and arguments stay exact.
fn probe_command(pid: u32) -> String {
    let p = shq(&pid.to_string());
    format!(
        "p={p}; \
         if [ ! -r \"/proc/$p/stat\" ]; then echo 'GONE|yes'; exit 0; fi; \
         stat=$(cat \"/proc/$p/stat\") || exit 44; \
         rest=${{stat##*) }}; st=${{rest%% *}}; \
         if [ \"$st\" = 'Z' ]; then echo 'ZOMBIE|yes'; exit 0; fi; \
         start=$(printf '%s\\n' \"$rest\" | awk '{{print $20}}'); \
         name=${{stat%)*}}; name=${{name#*(}}; \
         printf 'IDENT|%s|%s\\n' \"$start\" \"$name\"; \
         printf 'ARGV|%s\\n' \"$(od -An -v -tx1 \"/proc/$p/cmdline\" 2>/dev/null | tr -d ' \\n')\"; \
         cwd=$(readlink \"/proc/$p/cwd\" 2>/dev/null); \
         printf 'CWD|%s\\n' \"$(printf '%s' \"$cwd\" | od -An -v -tx1 | tr -d ' \\n')\"; \
         printf 'UID|%s\\n' \"$(awk '/^Uid:/{{print $2; exit}}' \"/proc/$p/status\" 2>/dev/null)\"; \
         uid_n=$(awk '/^Uid:/{{print $2; exit}}' \"/proc/$p/status\" 2>/dev/null); \
         printf 'USER|%s\\n' \"$(getent passwd \"$uid_n\" 2>/dev/null | cut -d: -f1)\"; \
         grep -q '[.]service' \"/proc/$p/cgroup\" 2>/dev/null && echo 'MANAGED|yes' || echo 'MANAGED|no'; \
         kill -0 \"$p\" 2>/dev/null && echo 'SIGNAL|yes' || echo 'SIGNAL|no'; \
         printf 'EUID|%s\\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         command -v setsid >/dev/null 2>&1 && echo 'SETSID|yes' || echo 'SETSID|no'; \
         command -v su >/dev/null 2>&1 && echo 'SU|yes' || echo 'SU|no'; \
         uname_r=$(getent passwd \"$uid_n\" 2>/dev/null | cut -d: -f1); \
         [ -n \"$uname_r\" ] && sudo -n -u \"$uname_r\" true >/dev/null 2>&1 && echo 'SUDOU|yes' || echo 'SUDOU|no'; \
         c=$$; chain=''; i=0; \
         while [ \"$i\" -lt 64 ] && [ -n \"$c\" ] && [ \"$c\" -gt 1 ]; do \
           c=$(cat \"/proc/$c/stat\" 2>/dev/null | awk -F')' '{{print $NF}}' | awk '{{print $2}}'); \
           [ -z \"$c\" ] && break; \
           chain=\"$chain $c\"; i=$((i+1)); \
         done; \
         printf 'ANCESTORS|%s\\n' \"$chain\""
    )
}

fn parse_probe(output: &str) -> RestartProbe {
    let mut probe = RestartProbe::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        let value = value.trim_end();
        match key {
            "GONE" => probe.gone = true,
            "ZOMBIE" => probe.zombie = true,
            "IDENT" => {
                let mut fields = value.splitn(2, '|');
                probe.start_time_ticks = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                probe.command_name = fields.next().unwrap_or("").to_owned();
            }
            "ARGV" => probe.argv_hex = value.to_owned(),
            "CWD" => probe.cwd_hex = value.to_owned(),
            "UID" => probe.uid = value.parse().ok(),
            "USER" => probe.user = value.to_owned(),
            "MANAGED" => probe.managed = value == "yes",
            "SIGNAL" => probe.can_signal = value == "yes",
            "EUID" => probe.euid = value.parse().ok(),
            "SUDO" => probe.sudo = value == "yes",
            "SETSID" => probe.setsid = value == "yes",
            "SU" => probe.su = value == "yes",
            "SUDOU" => probe.sudo_u_ok = value == "yes",
            "ANCESTORS" => {
                probe.ancestors = value
                    .split(' ')
                    .filter_map(|item| item.parse().ok())
                    .collect();
            }
            _ => {}
        }
    }
    probe
}

/// The same probe doubles as the execute-time re-check and the post-launch
/// state read; matching the planned snapshot field-for-field is what makes a
/// write safe.
fn probe_matches(plan: &ProcessRestartPlan, probe: &RestartProbe) -> bool {
    !probe.gone
        && !probe.zombie
        && probe.start_time_ticks == plan.start_time_ticks
        && probe.argv_hex == plan.argv_hex
        && probe.cwd_hex == plan.cwd_hex
        && probe.uid == Some(plan.uid)
}

/// Post-launch scan: a *new* pid carrying the planned argv, uid and cwd, and
/// the old pid confirmed gone or reaped-pending.
fn scan_command(plan: &ProcessRestartPlan) -> String {
    format!(
        "old={old}; want_a='{argv}'; want_u={uid}; want_c='{cwd}'; \
         for d in /proc/[0-9]*; do n=${{d#/proc/}}; [ \"$n\" = \"$old\" ] && continue; \
           stat=$(cat \"$d/stat\" 2>/dev/null) || continue; \
           [ \"${{stat##*) }}\" = \"${{stat}}\" ] && continue; \
           st=$(printf '%s\\n' \"${{stat##*) }}\" | awk '{{print $1}}'); [ \"$st\" = 'Z' ] && continue; \
           a=$(od -An -v -tx1 \"$d/cmdline\" 2>/dev/null | tr -d ' \\n'); [ \"$a\" = \"$want_a\" ] || continue; \
           u=$(awk '/^Uid:/{{print $2; exit}}' \"$d/status\" 2>/dev/null); [ \"$u\" = \"$want_u\" ] || continue; \
           c=$(printf '%s' \"$(readlink \"$d/cwd\" 2>/dev/null)\" | od -An -v -tx1 | tr -d ' \\n'); [ \"$c\" = \"$want_c\" ] || continue; \
           echo \"NEWPID|$n\"; break; \
         done; \
         if [ ! -r \"/proc/$old/stat\" ]; then echo 'OLD|absent'; else \
           ost=$(cat \"/proc/$old/stat\" | awk -F')' '{{print $NF}}' | awk '{{print $1}}'); \
           [ \"$ost\" = 'Z' ] && echo 'OLD|zombie' || echo 'OLD|alive'; fi",
        argv = plan.argv_hex,
        cwd = plan.cwd_hex,
        uid = plan.uid,
        old = plan.pid,
    )
}

/// The detached relaunch in the original directory under the original user.
fn launch_command(plan: &ProcessRestartPlan) -> String {
    let inner = format!(
        "cd {cwd} && setsid {argv} </dev/null >>/dev/null 2>&1 &",
        cwd = shq(&plan.cwd),
        argv = plan
            .argv
            .iter()
            .map(|arg| shq(arg))
            .collect::<Vec<_>>()
            .join(" "),
    );
    match plan.run_as {
        RunAs::Direct => inner,
        RunAs::RootSu => format!("su -s /bin/sh {} -c {}", shq(&plan.user), shq(&inner)),
        RunAs::SudoUser => format!("sudo -n -u {} -- sh -c {}", shq(&plan.user), shq(&inner)),
    }
}

/// SIGTERM, a grace wait, then SIGKILL when the process will not leave. A
/// zombie counts as stopped: only its parent's wait() keeps it listed.
fn stop_command(plan: &ProcessRestartPlan) -> String {
    let prefix = plan.kill_prefix;
    format!(
        "p={pid}; \
         {prefix}kill -TERM \"$p\" 2>/dev/null || true; \
         i=0; \
         while [ \"$i\" -lt 80 ]; do \
           if [ ! -r \"/proc/$p/stat\" ]; then echo 'STOPPED|yes'; exit 0; fi; \
           st=$(cat \"/proc/$p/stat\" | awk -F')' '{{print $NF}}' | awk '{{print $1}}'); \
           [ \"$st\" = 'Z' ] && {{ echo 'STOPPED|yes'; exit 0; }}; \
           sleep 0.1; i=$((i+1)); \
         done; \
         {prefix}kill -KILL \"$p\" 2>/dev/null || true; \
         i=0; \
         while [ \"$i\" -lt 50 ]; do \
           if [ ! -r \"/proc/$p/stat\" ]; then echo 'STOPPED|yes'; exit 0; fi; \
           st=$(cat \"/proc/$p/stat\" | awk -F')' '{{print $NF}}' | awk '{{print $1}}'); \
           [ \"$st\" = 'Z' ] && {{ echo 'STOPPED|yes'; exit 0; }}; \
           sleep 0.1; i=$((i+1)); \
         done; \
         echo 'STOPPED|no'",
        pid = plan.pid,
        prefix = prefix,
    )
}

impl SystemInfoService {
    /// Describe restarting the process in `request`, without touching it.
    pub async fn plan_process_restart(
        &self,
        session: &BoundSshSession,
        row_id: &str,
        pid: u32,
    ) -> CoreResult<ProcessRestartPlan> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, probe_command(pid), PRECONDITION_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("process restart probe", &output));
        }
        let probe = parse_probe(&output.output);
        if probe.gone || probe.zombie || probe.start_time_ticks == 0 {
            return Err(CoreError::NotFound {
                entity: "process",
                id: pid.to_string(),
            });
        }
        let argv = decode_argv(&probe.argv_hex)?;
        if probe.ancestors.contains(&pid) || probe.user.is_empty() && probe.uid != probe.euid {
            return Err(CoreError::validation(
                RESTART_SESSION_REFUSAL,
                "这个进程在本次 SSH 连接自己的进程链上，停掉它会切断正在执行的连接",
            ));
        }
        if pid <= 1 {
            return Err(CoreError::validation(
                RESTART_INIT_REFUSAL,
                "1 号进程/内核线程不能走这个通道，请用系统自带方式处理",
            ));
        }
        if probe.managed {
            return Err(CoreError::validation(
                RESTART_MANAGED_REFUSAL,
                "这个进程由 systemd 管理，请改用服务行上的启动/停止操作，避免与托管状态脱节",
            ));
        }
        if probe.cwd_hex.is_empty() {
            return Err(CoreError::validation(
                RESTART_CWD_REFUSAL,
                "读取不到原工作目录（可能已删除），按原样拉起会落空；请手动确认后重启",
            ));
        }
        let cwd = decode_cwd(&probe.cwd_hex)?;
        let uid = probe.uid.ok_or_else(|| invalid_detail_key("process uid"))?;
        let euid = probe
            .euid
            .ok_or_else(|| invalid_detail_key("operator euid"))?;
        if !probe.setsid {
            return Err(CoreError::validation(
                RESTART_TOOLS_REFUSAL,
                "目标机缺少 setsid，无法安全地脱离本次会话拉起进程",
            ));
        }
        let run_as = if uid == euid {
            RunAs::Direct
        } else if euid == 0 && probe.su && !probe.user.is_empty() {
            RunAs::RootSu
        } else if probe.sudo_u_ok && !probe.user.is_empty() {
            RunAs::SudoUser
        } else {
            return Err(CoreError::validation(
                RESTART_PRIVILEGE_REFUSAL,
                "无法以原进程的用户身份重新拉起（需要 root 的 su 或免密 sudo -u）",
            ));
        };
        let can_stop = euid == 0 || uid == euid || probe.can_signal || probe.sudo;
        if !can_stop {
            return Err(CoreError::validation(
                RESTART_PRIVILEGE_REFUSAL,
                "没有停止这个进程的权限（需要属主、root 或免密 sudo）",
            ));
        }
        let kill_prefix = if euid == 0 || uid == euid || probe.can_signal {
            ""
        } else {
            "sudo -n "
        };
        let argv_display = argv.join(" ");
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "重启进程 {}（PID {}，启动时钟 {}）：先 SIGTERM 停止（8 秒未退出再 SIGKILL），再以用户 {}（UID {}）、目录 {}、命令行 {} 重新拉起（setsid 脱离本次会话）。不还原原进程的环境变量与已打开的文件/网络连接。执行前会重核进程身份，身份变了就拒绝；启动失败且原进程已停时会再尝试拉起一次，回执保留原命令行供手动恢复。",
                probe.command_name,
                pid,
                probe.start_time_ticks,
                probe.user,
                uid,
                cwd,
                argv_display,
            ),
            true,
            Some(
                "启动失败且原进程已停止时，按原命令行再拉起一次；原进程仍在运行则拒绝恢复，避免出现双实例。"
                    .to_owned(),
            ),
        )?;
        operation.metadata.insert(
            "source".to_owned(),
            "system-info-process-restart".to_owned(),
        );
        operation.metadata.insert("pid".to_owned(), pid.to_string());
        operation.metadata.insert(
            "start-time-ticks".to_owned(),
            probe.start_time_ticks.to_string(),
        );
        operation.metadata.insert("uid".to_owned(), uid.to_string());
        Ok(ProcessRestartPlan {
            operation,
            row_id: row_id.to_owned(),
            pid,
            start_time_ticks: probe.start_time_ticks,
            argv,
            argv_hex: probe.argv_hex,
            cwd,
            cwd_hex: probe.cwd_hex,
            uid,
            user: probe.user,
            run_as,
            kill_prefix,
        })
    }

    /// Runs the confirmed restart once: identity re-check, stop, detached
    /// relaunch, new-process verification; a failed verification retries the
    /// launch once when the old process is really gone.
    pub async fn execute_process_restart(
        &self,
        session: &BoundSshSession,
        plan: ProcessRestartPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<ProcessRestartOutcome> {
        let executor = ProcessRestartExecutor {
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
        let verification = match operation.verify(&self.target, &executor, journal).await {
            Ok(verification) => verification,
            Err(verification_error) => {
                return match operation.restore(&self.target, &executor, journal).await {
                    Ok(()) => Err(verification_error),
                    Err(restore_error) => Err(CoreError::validation(
                        "process restart verification",
                        format!(
                            "{verification_error}; relaunch retry also failed: {restore_error}"
                        ),
                    )),
                };
            }
        };
        let relaunched = if verification.passed {
            false
        } else {
            operation.restore(&self.target, &executor, journal).await?;
            true
        };
        Ok(ProcessRestartOutcome {
            pid: plan.pid,
            verification,
            relaunched_after_failure: relaunched,
        })
    }
}

#[derive(Debug)]
struct ProcessRestartExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a ProcessRestartPlan,
}

impl ProcessRestartExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "process restart operation",
                "executor is bound to a different immutable plan",
            ));
        }
        if Utc::now() - self.plan.operation.created_at > PLAN_TTL {
            return Err(CoreError::validation(
                "process restart operation",
                "计划已过期，请重新规划",
            ));
        }
        Ok(())
    }

    async fn probe(&self) -> CoreResult<RestartProbe> {
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                probe_command(self.plan.pid),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        if output.timed_out {
            return Err(command_failed("process restart probe", &output));
        }
        Ok(parse_probe(&output.output))
    }

    async fn launch(&self) -> CoreResult<()> {
        let output = self
            .service
            .ssh
            .execute_bound(self.session, launch_command(self.plan), WRITE_TIMEOUT)
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(command_failed("process relaunch", &output));
        }
        Ok(())
    }

    /// Whether the old pid is really gone — the only state in which a retry
    /// launch cannot produce a duplicate.
    async fn old_is_gone(&self) -> CoreResult<bool> {
        let probe = self.probe().await?;
        Ok(probe.gone || probe.zombie || probe.start_time_ticks != self.plan.start_time_ticks)
    }
}

#[async_trait]
impl OperationExecutor for ProcessRestartExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.service.target.validate(&operation.target)?;
        let probe = self.probe().await?;
        if !probe_matches(self.plan, &probe) {
            return Err(CoreError::validation(
                RESTART_CHANGED_REFUSAL,
                "这个进程在计划之后已经退出或被替换，这次没有动它",
            ));
        }
        let output = self
            .service
            .ssh
            .execute_bound(self.session, stop_command(self.plan), WRITE_TIMEOUT)
            .await?;
        if output.timed_out || !output.output.contains("STOPPED|yes") {
            return Err(command_failed("process stop", &output));
        }
        self.launch().await?;
        self.service.target.validate(&operation.target)?;
        Ok(ExecutionReceipt {
            summary: format!(
                "已停止 PID {} 并按原命令行重新拉起（用户 {}、目录 {}）",
                self.plan.pid, self.plan.user, self.plan.cwd,
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
        let output = self
            .service
            .ssh
            .execute_bound(self.session, scan_command(self.plan), WRITE_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(command_failed("process restart scan", &output));
        }
        let new_pid = output
            .output
            .lines()
            .find_map(|line| line.strip_prefix("NEWPID|"))
            .map(str::to_owned);
        let old_state = output
            .output
            .lines()
            .find_map(|line| line.strip_prefix("OLD|"))
            .unwrap_or("alive")
            .to_owned();
        let passed = new_pid.is_some() && old_state != "alive";
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "回读：新进程 PID {} 与原命令行、用户、工作目录一致；原 PID {} 已退出。",
                    new_pid.clone().unwrap_or_default(),
                    self.plan.pid,
                )
            } else if old_state == "alive" {
                format!(
                    "回读：原进程 PID {} 仍在运行，没有重复拉起；请人工核对。原命令行：{}",
                    self.plan.pid,
                    self.plan.argv.join(" "),
                )
            } else {
                format!(
                    "回读：没有找到按原命令行、原用户、原目录运行的新进程（原 PID {} 已退出）。原命令行：{}",
                    self.plan.pid,
                    self.plan.argv.join(" "),
                )
            },
        })
    }

    /// The honest "restore": the old process cannot come back. When it is
    /// really gone, one more launch puts an equivalent process back; when it
    /// survived, relaunching would create a duplicate and is refused.
    async fn restore(
        &self,
        _operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        if !self.old_is_gone().await? {
            return Err(CoreError::validation(
                "process restart restore",
                "原进程仍在运行，不重复拉起，请人工核对",
            ));
        }
        self.launch().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_hex_round_trips_and_rejects_empty() {
        let blob = b"/usr/bin/python3\0app.py\0--port\0" as &[u8];
        let text = hex(blob);
        assert_eq!(
            decode_argv(&text).unwrap(),
            vec![
                "/usr/bin/python3".to_owned(),
                "app.py".to_owned(),
                "--port".to_owned(),
            ]
        );
        assert!(decode_argv("").is_err());
        assert!(decode_argv("00").is_err(), "a lone NUL is not an argv");
    }

    #[test]
    fn cwd_decodes_utf8_path() {
        assert_eq!(decode_cwd(&hex(b"/opt/app dir")).unwrap(), "/opt/app dir");
    }

    #[test]
    fn probe_parses_all_keys() {
        let probe = parse_probe(
            "IDENT|12345|python3\nARGV|61670a\nCWD|2f74\nUID|1000\nUSER|app\n\
             MANAGED|no\nSIGNAL|yes\nEUID|0\nSUDO|no\nSETSID|yes\nSU|yes\nSUDOU|no\nANCESTORS| 1 99\n",
        );
        assert_eq!(probe.start_time_ticks, 12345);
        assert_eq!(probe.command_name, "python3");
        assert_eq!(probe.argv_hex, "61670a");
        assert_eq!(probe.uid, Some(1000));
        assert_eq!(probe.ancestors, vec![1, 99]);
        assert!(probe.setsid && !probe.managed && probe.can_signal);
    }

    #[test]
    fn launch_quotes_every_argument_and_dir() {
        let target = crate::target::TargetContext::new();
        let guard = target
            .activate(crate::target::TargetIdentity::new("test-host").unwrap())
            .unwrap();
        let plan = ProcessRestartPlan {
            operation: OperationPlan::new(guard, "t".to_owned(), true, None).unwrap(),
            row_id: "r".to_owned(),
            pid: 42,
            start_time_ticks: 1,
            argv: vec!["python3".to_owned(), "my app.py".to_owned()],
            argv_hex: String::new(),
            cwd: "/opt/a b".to_owned(),
            cwd_hex: String::new(),
            uid: 1000,
            user: "app".to_owned(),
            run_as: RunAs::Direct,
            kill_prefix: "",
        };
        let command = launch_command(&plan);
        assert!(command.contains("cd '/opt/a b'"));
        assert!(command.contains("setsid 'python3' 'my app.py'"));
        assert!(command.ends_with('&'));
    }
}
