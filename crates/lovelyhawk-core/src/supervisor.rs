//! Starting, stopping and restarting a Supervisor program from its row —
//! `supervisorctl` is the manager that already owns the program's state, so
//! going around it (kill-and-relaunch like `process_restart` does) would
//! fight the daemon's own accounting.
//!
//! The shape follows the other runtime actions: a bounded probe fixes the
//! program's name, state, pid and start-time ticks into an immutable plan;
//! execution re-reads that state and refuses untouched when it moved; the
//! `supervisorctl` call itself is the only write; verification re-reads
//! `supervisorctl status` until the program is in the expected state — a
//! restart also demands a *new* pid that stays RUNNING. An optional loopback
//! HTTP probe then records a status code as an observation, never as proof
//! the business recovered. There is no undo for runtime actions; the plan
//! says so.

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

/// The probe could not get `supervisorctl` to answer: the tool is missing,
/// the daemon is down, or the login has no access. This is not "no programs".
pub const SUPERVISOR_TOOL_REFUSAL: &str = "supervisorctl unavailable";
/// The program moved between the plan and its execution.
pub const SUPERVISOR_STALE_REFUSAL: &str = "supervisor program changed";

const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
/// The backend registry expires plans after five minutes.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);
/// Settle polling after `supervisorctl` accepts: status is re-read this many
/// times at the interval below before verification gives up.
const VERIFY_ATTEMPTS: usize = 60;
const VERIFY_INTERVAL: Duration = Duration::from_millis(300);
/// A restarted program must keep its new pid and RUNNING state this long.
const RESTART_SETTLE: Duration = Duration::from_secs(3);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SupervisorAction {
    Start,
    Stop,
    Restart,
}

impl SupervisorAction {
    pub const ALL: [Self; 3] = [Self::Start, Self::Stop, Self::Restart];
    /// The actions an optional loopback health check may follow.
    pub const HEALTH_CHECKABLE: [Self; 2] = [Self::Start, Self::Restart];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Start => "启动程序",
            Self::Stop => "停止程序",
            Self::Restart => "重启程序",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

/// A program name as `supervisorctl status` prints it — `name` or
/// `group:name`. The leading character may not be a dash so the name can
/// never be mistaken for an option by `supervisorctl`.
pub fn is_valid_program_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
        })
}

/// The optional loopback HTTP probe a start or restart can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorHealthCheck {
    pub port: u16,
    pub path: String,
}

pub fn supervisor_health_check(port: u16, path: &str) -> CoreResult<SupervisorHealthCheck> {
    if port == 0 {
        return Err(CoreError::validation(
            "supervisor health check",
            "健康检查端口需要在 1–65535 之间。",
        ));
    }
    if path.is_empty()
        || !path.starts_with('/')
        || path.len() > 256
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_.~%?&=-".contains(&byte))
    {
        return Err(CoreError::validation(
            "supervisor health check",
            "健康检查路径需要以 / 开头、不超过 256 字节，只能含字母、数字和 /_.~%?&=-。",
        ));
    }
    Ok(SupervisorHealthCheck {
        port,
        path: path.to_owned(),
    })
}

#[derive(Debug, Clone)]
pub struct SupervisorActionRequest {
    pub row_id: String,
    pub name: String,
    pub action: SupervisorAction,
    pub health: Option<SupervisorHealthCheck>,
}

/// What `supervisorctl status` said about the program when the plan was made.
/// Any difference at execution time means the program moved underneath the
/// plan, so the plan refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorProgramSnapshot {
    pub name: String,
    pub state: String,
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat` — distinguishes a recycled pid.
    pub start_ticks: u64,
    /// The remainder of the status line (uptime or stop text), for the plan.
    pub detail: String,
}

#[derive(Debug)]
pub struct SupervisorPlan {
    pub operation: OperationPlan,
    pub row_id: String,
    pub name: String,
    pub action: SupervisorAction,
    pub snapshot: SupervisorProgramSnapshot,
    pub health: Option<SupervisorHealthCheck>,
}

impl SupervisorPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
}

#[derive(Debug)]
pub struct SupervisorOutcome {
    pub verification: VerificationResult,
}

/// `supervisorctl` under the login's privilege: root plainly, a non-root
/// login through `sudo -n` when that answers, otherwise plainly in case the
/// socket is world-accessible. Prints `SVDENIED` when none of them work and
/// `SVTOOL` when the tool is absent, so the caller refuses rather than
/// reporting an empty list.
fn run_prefix() -> &'static str {
    "run=''; \
     if ! command -v supervisorctl >/dev/null 2>&1; then echo 'SVTOOL|missing'; exit 0; fi; \
     if [ \"$(id -u)\" -eq 0 ]; then run=''; \
     elif sudo -n supervisorctl status >/dev/null 2>&1; then run='sudo -n'; \
     elif supervisorctl status >/dev/null 2>&1; then run=''; \
     else echo 'SVDENIED|yes'; exit 0; fi;"
}

/// `supervisorctl status` filtered to the one program's line, followed by its
/// `/proc/<pid>` start-time ticks when it has a pid. The name never goes on
/// the command line here: the whole listing is taken and matched, so an
/// unusual name cannot reach a shell position it should not.
fn snapshot_command(name: &str) -> String {
    format!(
        "{prefix} n={name}; line=$($run supervisorctl status 2>/dev/null | awk -v n=\"$n\" '$1 == n {{print; exit}}'); \
         if [ -z \"$line\" ]; then echo 'SVABSENT|yes'; exit 0; fi; \
         st=$(printf '%s\\n' \"$line\" | awk '{{print $2}}'); \
         pid=$(printf '%s\\n' \"$line\" | awk '{{for (i=3;i<=NF;i++) if ($i == \"pid\") {{print $(i+1); exit}}}}' | tr -d ','); \
         case \"$pid\" in ''|*[!0-9]*) pid=0;; esac; \
         ticks=0; if [ \"$pid\" -gt 0 ] && [ -r \"/proc/$pid/stat\" ]; then \
           stat=$(cat \"/proc/$pid/stat\" 2>/dev/null); ticks=$(printf '%s\\n' \"${{stat##*) }}\" | awk '{{print $20}}'); \
         fi; \
         rest=$(printf '%s\\n' \"$line\" | awk '{{out=\"\"; for(i=3;i<=NF;i++) out=out (i==3?\"\":\" \") $i; print out}}'); \
         printf 'SVSTATE|%s|%s|%s|%s|%s\\n' \"$n\" \"$st\" \"$pid\" \"${{ticks:-0}}\" \"$rest\"",
        prefix = run_prefix(),
        name = shq(name),
    )
}

fn parse_snapshot(name: &str, output: &str) -> CoreResult<SupervisorProgramSnapshot> {
    let first = output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim_end();
    match first.split_once('|').map(|(marker, _)| marker) {
        Some("SVTOOL") | Some("SVDENIED") => {
            return Err(CoreError::validation(
                SUPERVISOR_TOOL_REFUSAL,
                "读不到 supervisorctl 状态：可能没有安装 Supervisor、当前账户没有权限或 supervisord 没在运行。",
            ));
        }
        Some("SVABSENT") => {
            return Err(CoreError::NotFound {
                entity: "Supervisor 程序",
                id: name.to_owned(),
            });
        }
        Some("SVSTATE") => {}
        _ => {
            return Err(CoreError::validation(
                SUPERVISOR_TOOL_REFUSAL,
                "supervisorctl 没有返回可识别的状态。",
            ));
        }
    }
    let fields: Vec<&str> = first.splitn(6, '|').collect();
    if fields.len() != 6 || fields[1] != name {
        return Err(invalid_detail_key("supervisor status line"));
    }
    let state = fields[2];
    if !is_valid_state(state) {
        return Err(invalid_detail_key("supervisor program state"));
    }
    let pid: u32 = fields[3]
        .parse()
        .map_err(|_| invalid_detail_key("supervisor program pid"))?;
    let ticks: u64 = fields[4]
        .parse()
        .map_err(|_| invalid_detail_key("supervisor program start time"))?;
    Ok(SupervisorProgramSnapshot {
        name: name.to_owned(),
        state: state.to_owned(),
        pid,
        start_ticks: ticks,
        detail: fields[5].to_owned(),
    })
}

/// States `supervisorctl status` reports — RUNNING, STOPPED, FATAL, BACKOFF,
/// EXITED, STARTING, STOPPING, UNKNOWN — kept to a charset rather than a list
/// so a newer state still parses instead of breaking the whole read.
fn is_valid_state(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
}

fn snapshots_equal(left: &SupervisorProgramSnapshot, right: &SupervisorProgramSnapshot) -> bool {
    left.name == right.name
        && left.state == right.state
        && left.pid == right.pid
        && left.start_ticks == right.start_ticks
}

/// Whether the re-read state is what the action was supposed to reach.
fn state_satisfied(snapshot: &SupervisorProgramSnapshot, planned: &SupervisorProgramSnapshot, action: SupervisorAction) -> bool {
    match action {
        SupervisorAction::Start => snapshot.state == "RUNNING" && snapshot.pid > 0,
        SupervisorAction::Stop => {
            matches!(snapshot.state.as_str(), "STOPPED" | "EXITED" | "FATAL")
        }
        // A restart must bring a *new* RUNNING process; the same pid passing
        // as RUNNING would mean `supervisorctl` never actually restarted it.
        // Stopped-program restarts have no old pid, so RUNNING alone counts.
        SupervisorAction::Restart => {
            snapshot.state == "RUNNING"
                && snapshot.pid > 0
                && (planned.pid == 0 || snapshot.pid != planned.pid)
        }
    }
}

/// Loopback probe of the operator's port and path, plus the listening TCP
/// ports the program's current pid holds. Both are observations for the
/// receipt; neither gates the verified state.
fn health_command(pid: u32, check: &SupervisorHealthCheck) -> String {
    format!(
        "p={pid}; url={url}; \
         if command -v curl >/dev/null 2>&1; then \
           code=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 \"$url\" 2>/dev/null); \
           case \"$code\" in ''|*[!0-9]*) echo 'HTTP|unreachable';; *) echo \"HTTP|$code\";; esac; \
         elif command -v wget >/dev/null 2>&1; then \
           if wget -q -T 5 -O /dev/null \"$url\" 2>/dev/null; then echo 'HTTP|reachable-wget'; else echo 'HTTP|unreachable'; fi; \
         else echo 'HTTP|no-tool'; fi; \
         if command -v ss >/dev/null 2>&1; then \
           listen=$(ss -tlnpH 2>/dev/null | grep -F \"pid=$p,\" | awk '{{print $4}}' | sed 's/.*://' | tr '\\n' ' '); \
         elif command -v netstat >/dev/null 2>&1; then \
           listen=$(netstat -tlnp 2>/dev/null | awk -v p=\"$p/\" '$6 ~ /^LISTEN/ && $7 ~ p {{n=split($4,a,\":\"); print a[n]}}' | tr '\\n' ' '); \
         else listen=''; fi; \
         printf 'PORTS|%s\\n' \"${{listen:-}}\"",
        pid = pid,
        url = shq(&format!("http://127.0.0.1:{}{}", check.port, check.path)),
    )
}

/// Listening TCP ports attributed to one pid without a health check to run.
fn ports_command(pid: u32) -> String {
    format!(
        "p={pid}; \
         if command -v ss >/dev/null 2>&1; then \
           listen=$(ss -tlnpH 2>/dev/null | grep -F \"pid=$p,\" | awk '{{print $4}}' | sed 's/.*://' | tr '\\n' ' '); \
         elif command -v netstat >/dev/null 2>&1; then \
           listen=$(netstat -tlnp 2>/dev/null | awk -v p=\"$p/\" '$6 ~ /^LISTEN/ && $7 ~ p {{n=split($4,a,\":\"); print a[n]}}' | tr '\\n' ' '); \
         else listen=''; fi; \
         printf 'PORTS|%s\\n' \"${{listen:-}}\"",
        pid = pid,
    )
}

impl SystemInfoService {
    /// `supervisorctl status` for one program, as a comparable snapshot.
    async fn supervisor_snapshot(
        &self,
        session: &BoundSshSession,
        name: &str,
    ) -> CoreResult<SupervisorProgramSnapshot> {
        let output = self
            .ssh
            .execute_bound(session, snapshot_command(name), PRECONDITION_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(command_failed("supervisor status probe", &output));
        }
        parse_snapshot(name, &output.output)
    }

    /// Plans one `supervisorctl` action against the program's live state.
    pub async fn plan_supervisor_action(
        &self,
        session: &BoundSshSession,
        request: &SupervisorActionRequest,
    ) -> CoreResult<SupervisorPlan> {
        self.target.validate(session.target())?;
        if !is_valid_program_name(&request.name) {
            return Err(invalid_detail_key("supervisor program name"));
        }
        if request.health.is_some() && !SupervisorAction::HEALTH_CHECKABLE.contains(&request.action)
        {
            return Err(CoreError::validation(
                "supervisor action",
                "health checks only follow a start or restart",
            ));
        }
        let snapshot = self.supervisor_snapshot(session, &request.name).await?;
        self.target.validate(session.target())?;
        let state_note = match snapshot.state.as_str() {
            "RUNNING" => format!("RUNNING，PID {}", snapshot.pid),
            other => format!("{other}（{}）", snapshot.detail),
        };
        let health_note = request.health.as_ref().map_or(String::new(), |check| {
            format!(
                "随后向 http://127.0.0.1:{}{} 探测一次；HTTP 200 只说明该地址有响应，不代表业务已经恢复。",
                check.port, check.path
            )
        });
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "{} {}（当前：{}）。执行 supervisorctl {} 后重新读取状态验证；运行状态操作无法自动恢复。{}",
                request.action.label(),
                snapshot.name,
                state_note,
                request.action.command(),
                health_note,
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-supervisor".to_owned());
        operation
            .metadata
            .insert("program".to_owned(), snapshot.name.clone());
        operation
            .metadata
            .insert("action".to_owned(), request.action.command().to_owned());
        Ok(SupervisorPlan {
            operation,
            row_id: request.row_id.clone(),
            name: snapshot.name.clone(),
            action: request.action,
            snapshot,
            health: request.health.clone(),
        })
    }

    /// Runs the confirmed action once: re-check, `supervisorctl`, verify.
    pub async fn execute_supervisor_action(
        &self,
        session: &BoundSshSession,
        plan: SupervisorPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<SupervisorOutcome> {
        let executor = SupervisorExecutor {
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
        Ok(SupervisorOutcome { verification })
    }
}

#[derive(Debug)]
struct SupervisorExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a SupervisorPlan,
}

impl SupervisorExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "supervisor operation",
                "executor is bound to a different immutable plan",
            ));
        }
        if Utc::now() - self.plan.operation.created_at > PLAN_TTL {
            return Err(CoreError::validation(
                "supervisor operation",
                "计划已过期，请重新规划",
            ));
        }
        Ok(())
    }

    /// HTTP probe + owned-listener observation text appended to the receipt.
    async fn observations(
        &self,
        snapshot: &SupervisorProgramSnapshot,
    ) -> String {
        let Some(pid) = (snapshot.pid > 0).then_some(snapshot.pid) else {
            return String::new();
        };
        let command = match &self.plan.health {
            Some(check) => health_command(pid, check),
            None => ports_command(pid),
        };
        let output = self
            .service
            .ssh
            .execute_bound(self.session, command, HEALTH_TIMEOUT)
            .await;
        let Ok(output) = output else {
            return "附加观察未取到。".to_owned();
        };
        if output.timed_out {
            return "附加观察超时。".to_owned();
        }
        let mut http = None;
        let mut ports = None;
        for line in output.output.lines() {
            if let Some(value) = line.strip_prefix("HTTP|") {
                http = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("PORTS|") {
                ports = Some(value.trim().to_owned());
            }
        }
        let mut text = String::new();
        if let Some(code) = http {
            let note = match code.as_str() {
                "no-tool" => "目标机没有 curl 或 wget，未做 HTTP 探测".to_owned(),
                "unreachable" => "HTTP 探测没有应答".to_owned(),
                "reachable-wget" => "HTTP 探测可达（wget，未取状态码）".to_owned(),
                other => format!("HTTP 探测返回 {other}；这只说明该地址有响应，不代表业务已经恢复"),
            };
            text.push_str(&note);
            text.push('。');
        }
        match ports.as_deref() {
            Some(list) if !list.is_empty() => {
                text.push_str(&format!("新进程监听端口：{list}。"));
            }
            _ => {
                text.push_str("未发现新进程持有的监听端口。");
            }
        }
        text
    }
}

#[async_trait]
impl OperationExecutor for SupervisorExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .supervisor_snapshot(self.session, &self.plan.name)
            .await?;
        if !snapshots_equal(&observed, &self.plan.snapshot) {
            return Err(CoreError::validation(
                SUPERVISOR_STALE_REFUSAL,
                "supervisorctl 状态在确认之后变了，这次没有执行。请刷新后再看。",
            ));
        }
        self.service.target.validate(&operation.target)?;
        let name = shq(&self.plan.name);
        let command = format!(
            "{prefix} n={name}; $run supervisorctl {action} \"$n\"",
            prefix = run_prefix(),
            name = name,
            action = self.plan.action.command(),
        );
        let dispatch = match self
            .service
            .ssh
            .execute_bound(self.session, command, ACTION_TIMEOUT)
            .await
        {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => {
                "accepted".to_owned()
            }
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{error}"),
        };
        Ok(ExecutionReceipt {
            summary: format!(
                "supervisorctl {} {}: {dispatch}",
                self.plan.action.command(),
                self.plan.name,
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
        let mut observed = self
            .service
            .supervisor_snapshot(self.session, &self.plan.name)
            .await?;
        for _ in 0..VERIFY_ATTEMPTS {
            if state_satisfied(&observed, &self.plan.snapshot, self.plan.action) {
                break;
            }
            tokio::time::sleep(VERIFY_INTERVAL).await;
            observed = self
                .service
                .supervisor_snapshot(self.session, &self.plan.name)
                .await?;
        }
        let passed = state_satisfied(&observed, &self.plan.snapshot, self.plan.action);
        // A restart's new process still has to be alive a moment later —
        // BACKOFF loops otherwise read as success.
        if passed && self.plan.action == SupervisorAction::Restart {
            let settled_pid = observed.pid;
            tokio::time::sleep(RESTART_SETTLE).await;
            let again = self
                .service
                .supervisor_snapshot(self.session, &self.plan.name)
                .await?;
            let stable = again.state == "RUNNING" && again.pid == settled_pid;
            if !stable {
                return Ok(VerificationResult {
                    passed: false,
                    detail: format!(
                        "重启后 {} 先是 RUNNING 又变为 {}（PID {}）；可能进入重启循环，请查看程序日志。",
                        self.plan.name, again.state, again.pid,
                    ),
                });
            }
            observed = again;
        }
        let observations = if matches!(self.plan.action, SupervisorAction::Start | SupervisorAction::Restart) {
            self.observations(&observed).await
        } else {
            String::new()
        };
        Ok(VerificationResult {
            passed,
            detail: format!(
                "{}后回读：{} 状态 {}{}。{}{}",
                self.plan.action.label(),
                observed.name,
                observed.state,
                if observed.pid > 0 {
                    format!("，PID {}", observed.pid)
                } else {
                    String::new()
                },
                if passed { "与预期一致。" } else { "与预期不符。" },
                observations,
            ),
        })
    }

    /// A runtime action has no way back; refusing keeps the journal honest.
    async fn restore(&self, operation: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(CoreError::validation(
            "supervisor operation",
            "运行状态操作无法自动恢复。",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_names_follow_the_supervisor_charset() {
        for name in ["oa", "web:oa", "a.b_c-d", "x".repeat(128).as_str()] {
            assert!(is_valid_program_name(name), "{name}");
        }
        for name in ["", "-oa", "a b", "a/n", "a;n", "a\tn", "x".repeat(129).as_str()] {
            assert!(!is_valid_program_name(name), "{name}");
        }
    }

    #[test]
    fn health_check_input_is_checked() {
        assert!(supervisor_health_check(18080, "/").is_ok());
        assert!(supervisor_health_check(65535, "/a/b?x=1&y=%20").is_ok());
        for (port, path) in [
            (0, "/"),
            (18080, ""),
            (18080, "health"),
            (18080, "/$(x)"),
            (18080, "/a b"),
            (18080, "/a'b"),
            (18080, &"/".repeat(257)),
        ] {
            assert!(
                supervisor_health_check(port, path).is_err(),
                "{port} {path}"
            );
        }
    }

    #[test]
    fn snapshot_parses_running_stopped_and_grouped() {
        let running = parse_snapshot(
            "oa",
            "SVSTATE|oa|RUNNING|1234|987654|pid 1234, uptime 0:12:34\n",
        )
        .unwrap();
        assert_eq!(running.state, "RUNNING");
        assert_eq!(running.pid, 1234);
        assert_eq!(running.start_ticks, 987654);
        let stopped = parse_snapshot("web:oa", "SVSTATE|web:oa|STOPPED|0|0|Oct 20 03:45 PM\n").unwrap();
        assert_eq!(stopped.name, "web:oa");
        assert_eq!(stopped.pid, 0);
        for state in ["FATAL", "BACKOFF", "EXITED", "STARTING", "UNKNOWN"] {
            let snapshot =
                parse_snapshot("p", &format!("SVSTATE|p|{state}|0|0|some text\n")).unwrap();
            assert_eq!(snapshot.state, state);
        }
    }

    #[test]
    fn snapshot_refusals_are_distinct() {
        assert!(matches!(
            parse_snapshot("oa", "SVTOOL|missing\n"),
            Err(CoreError::Validation { ref subject, .. }) if *subject == SUPERVISOR_TOOL_REFUSAL
        ));
        assert!(matches!(
            parse_snapshot("oa", "SVDENIED|yes\n"),
            Err(CoreError::Validation { ref subject, .. }) if *subject == SUPERVISOR_TOOL_REFUSAL
        ));
        assert!(matches!(
            parse_snapshot("oa", "SVABSENT|yes\n"),
            Err(CoreError::NotFound { .. })
        ));
        assert!(matches!(
            parse_snapshot("oa", "garbage in garbage out\n"),
            Err(CoreError::Validation { .. })
        ));
        // A status line for a different program never satisfies this request.
        assert!(matches!(
            parse_snapshot("oa", "SVSTATE|other|RUNNING|1|1|x\n"),
            Err(CoreError::Validation { .. })
        ));
    }

    #[test]
    fn satisfied_state_matches_the_action() {
        let running = |pid| SupervisorProgramSnapshot {
            name: "oa".to_owned(),
            state: "RUNNING".to_owned(),
            pid,
            start_ticks: 7,
            detail: String::new(),
        };
        let stopped = || SupervisorProgramSnapshot {
            name: "oa".to_owned(),
            state: "STOPPED".to_owned(),
            pid: 0,
            start_ticks: 0,
            detail: String::new(),
        };
        assert!(state_satisfied(&running(9), &stopped(), SupervisorAction::Start));
        assert!(!state_satisfied(&stopped(), &stopped(), SupervisorAction::Start));
        assert!(state_satisfied(&stopped(), &running(9), SupervisorAction::Stop));
        assert!(!state_satisfied(&running(9), &running(9), SupervisorAction::Stop));
        // A restart must carry a new pid, or RUNNING alone would pass a no-op.
        assert!(state_satisfied(&running(10), &running(9), SupervisorAction::Restart));
        assert!(!state_satisfied(&running(9), &running(9), SupervisorAction::Restart));
        // Restarting a program that was stopped only needs RUNNING.
        assert!(state_satisfied(&running(10), &stopped(), SupervisorAction::Restart));
        // A program that came up and fell back out is not a success.
        let fatal = SupervisorProgramSnapshot {
            name: "oa".to_owned(),
            state: "FATAL".to_owned(),
            pid: 0,
            start_ticks: 0,
            detail: String::new(),
        };
        assert!(!state_satisfied(&fatal, &stopped(), SupervisorAction::Restart));
    }

    #[test]
    fn snapshots_compare_on_identity_not_text() {
        let mut a = parse_snapshot("oa", "SVSTATE|oa|RUNNING|1|7|pid 1, uptime 0:00:01\n").unwrap();
        let mut b = a.clone();
        assert!(snapshots_equal(&a, &b));
        b.detail = "pid 1, uptime 0:00:02".to_owned();
        // Uptime text moves constantly; it is not part of identity.
        assert!(snapshots_equal(&a, &b));
        b.pid = 2;
        assert!(!snapshots_equal(&a, &b));
        a.state = "STOPPED".to_owned();
        a.pid = 0;
        assert!(!snapshots_equal(&a, &b));
    }
}
