//! Removing Linux file capabilities (the `security.capability` xattr) from a
//! file a read-only run already named — the write half of the roadmap's
//! `setcap` repair item.
//!
//! Extended attributes are outside the SFTP protocol, so the change runs over
//! the same bound SSH channel the command workbench reads through, inside the
//! usual plan/confirm/execute/verify/restore lifecycle. The plan snapshots the
//! file's sha256 and its capability text: execution refuses when either moved,
//! verification re-reads both, and undo writes the saved set back only while
//! the file is still exactly what the strip left.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::sftp::RemotePath;
use crate::shell_escape::shq;
use crate::ssh::BoundSshSession;
use crate::system_info::SystemInfoService;
use crate::target::TargetContext;

/// Refusal subjects the backend maps to operator-facing codes.
pub const CAPABILITY_PRIVILEGE_REFUSAL: &str = "capability strip privilege";
pub const CAPABILITY_TOOLS_REFUSAL: &str = "capability strip tools";
pub const CAPABILITY_KIND_REFUSAL: &str = "capability strip kind";
pub const CAPABILITY_EMPTY_REFUSAL: &str = "capability strip empty";
pub const CAPABILITY_CHANGED_REFUSAL: &str = "capability strip changed";

const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(15);
/// The backend registry expires plans after five minutes; the executor keeps
/// the same ceiling so a plan held elsewhere cannot run later either.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);

/// What one bounded probe learns about the file and the account that would
/// change it.
#[derive(Debug, Default)]
struct CapabilityProbe {
    is_root: bool,
    sudo: bool,
    setcap: bool,
    getcap: bool,
    regular: bool,
    sha256: Option<String>,
    /// The capability text exactly as `getcap` printed it, e.g.
    /// `cap_setuid=ep`; empty when the file carries none.
    caps: Option<String>,
}

fn probe_command(path: &RemotePath) -> String {
    let quoted = shq(path.as_str());
    format!(
        "printf 'UID|%s\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         command -v setcap >/dev/null 2>&1 && echo 'SETCAP|yes' || echo 'SETCAP|no'; \
         command -v getcap >/dev/null 2>&1 && echo 'GETCAP|yes' || echo 'GETCAP|no'; \
         if [ -f {quoted} ] && [ ! -L {quoted} ]; then echo 'FILE|regular'; else echo 'FILE|other'; fi; \
         sha256sum -- {quoted} 2>/dev/null | awk '{{print \"SHA|\" $1}}'; \
         getcap -- {quoted} 2>/dev/null | head -n 1 | sed 's/^/CAPSRAW|/'"
    )
}

/// The same two reads, run again before and after the write: the file digest
/// proves nobody swapped the file mid-flight, and the capability line is the
/// state the plan and the restore both compare against.
fn state_command(path: &RemotePath) -> String {
    let quoted = shq(path.as_str());
    format!(
        "sha256sum -- {quoted} 2>/dev/null | awk '{{print \"SHA|\" $1}}'; \
         getcap -- {quoted} 2>/dev/null | head -n 1 | sed 's/^/CAPSRAW|/'"
    )
}

fn parse_probe(output: &str, path: &RemotePath) -> CapabilityProbe {
    let mut probe = CapabilityProbe::default();
    let caps_prefix = format!("{} ", path.as_str());
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "UID" => probe.is_root = value.trim() == "0",
            "SUDO" => probe.sudo = value.trim() == "yes",
            "SETCAP" => probe.setcap = value.trim() == "yes",
            "GETCAP" => probe.getcap = value.trim() == "yes",
            "FILE" => probe.regular = value.trim() == "regular",
            "SHA" => probe.sha256 = Some(value.trim().to_owned()),
            "CAPSRAW" => {
                // `getcap <path>` prints `<path> cap_x=ep`; anything that does
                // not begin with our exact path is not capability text.
                probe.caps = Some(
                    value
                        .strip_prefix(&caps_prefix)
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            _ => {}
        }
    }
    probe
}

impl SystemInfoService {
    /// Describe removing every capability `getcap` reports for `path`.
    ///
    /// Refuses before planning when the tools or the privilege to change the
    /// xattr are missing, when the path is not a plain regular file, when it
    /// carries no capabilities, or when its digest cannot be snapshot for the
    /// later same-file check.
    pub async fn plan_capability_strip(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
        journal: PortableOperationJournal,
    ) -> CoreResult<CapabilityStripOperation> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, probe_command(path), PROBE_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("capability probe", &output));
        }
        let probe = parse_probe(&output.output, path);
        if !(probe.getcap && probe.setcap && probe.sha256.is_some()) {
            return Err(CoreError::validation(
                CAPABILITY_TOOLS_REFUSAL,
                "目标机缺少 getcap/setcap/sha256sum，无法安全移除并复核文件能力",
            ));
        }
        if !probe.regular {
            return Err(CoreError::validation(
                CAPABILITY_KIND_REFUSAL,
                "只能移除普通文件的能力；符号链接、目录与其他类型不支持",
            ));
        }
        if !(probe.is_root || probe.sudo) {
            return Err(CoreError::validation(
                CAPABILITY_PRIVILEGE_REFUSAL,
                "需要 root 或免密码 sudo 才能修改文件能力",
            ));
        }
        let caps = probe.caps.unwrap_or_default();
        if caps.is_empty() {
            return Err(CoreError::validation(
                CAPABILITY_EMPTY_REFUSAL,
                "该文件当前没有文件能力，无需移除",
            ));
        }
        let prefix = if probe.is_root { "" } else { "sudo -n " };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "移除 {path} 的文件能力（当前：{caps}）。文件保留，但依赖这些能力的提权不再生效。",
                path = path.as_str(),
            ),
            true,
            Some(format!("把移除前的能力集（{caps}）写回该文件")),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "capability-strip".to_owned());
        operation
            .metadata
            .insert("action".to_owned(), "strip".to_owned());
        operation
            .metadata
            .insert("path".to_owned(), path.as_str().to_owned());
        operation
            .metadata
            .insert("capabilities".to_owned(), caps.clone());
        let executor = CapabilityStripExecutor {
            service: self.clone(),
            session: session.clone(),
            path: path.clone(),
            saved_caps: caps,
            sha256: probe.sha256.unwrap_or_default(),
            prefix,
            plan: operation.clone(),
        };
        Ok(CapabilityStripOperation {
            operation: PlannedOperation::plan(operation),
            executor,
            target: self.target.clone(),
            journal,
        })
    }
}

/// The stored operation the backend registry holds between plan and undo.
#[derive(Debug)]
pub struct CapabilityStripOperation {
    operation: PlannedOperation,
    executor: CapabilityStripExecutor,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
}

impl CapabilityStripOperation {
    pub fn definition(&self) -> &OperationPlan {
        self.operation.definition()
    }

    pub fn state(&self) -> OperationState {
        self.operation.state()
    }

    pub fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        self.operation.confirm(confirmation)
    }

    pub async fn execute_and_verify(&mut self) -> CoreResult<VerificationResult> {
        if let Err(error) = self.operation.execute(&self.target, &self.executor).await {
            if self.operation.state() == OperationState::StaleAfterExecution {
                self.operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        self.operation.journal(&self.journal)?;
        self.operation
            .verify(&self.target, &self.executor, &self.journal)
            .await
    }

    pub async fn restore(&mut self) -> CoreResult<()> {
        self.operation
            .restore(&self.target, &self.executor, &self.journal)
            .await
    }

    /// A verified strip is undoable until the file moves on: the undo first
    /// re-runs the strip's own check, so a later change is never overwritten.
    pub fn can_undo(&self) -> bool {
        self.operation.state() == OperationState::Verified
    }

    pub async fn undo(&mut self) -> CoreResult<String> {
        if !self.can_undo() {
            return Err(CoreError::validation(
                "undo",
                "only a completed, verified capability strip can be undone",
            ));
        }
        self.target.validate(&self.operation.definition().target)?;
        let receipt = self.operation.execution_receipt()?.clone();
        let still = self
            .executor
            .verify(self.operation.definition(), &receipt)
            .await?;
        if !still.passed {
            return Err(CoreError::validation(
                "undo target",
                "target changed after the operation; nothing was undone",
            ));
        }
        self.restore().await?;
        self.executor.confirm_restored().await
    }
}

struct CapabilityStripExecutor {
    service: SystemInfoService,
    session: BoundSshSession,
    path: RemotePath,
    saved_caps: String,
    sha256: String,
    /// `""` as root, `"sudo -n "` otherwise.
    prefix: &'static str,
    plan: OperationPlan,
}

/// The file's digest and capability text, read together so they describe one
/// moment.
#[derive(Debug, PartialEq, Eq)]
struct CapabilityState {
    sha256: Option<String>,
    caps: Option<String>,
}

impl CapabilityStripExecutor {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.id || operation.target != self.plan.target {
            return Err(CoreError::validation(
                "capability strip operation",
                "executor is bound to a different immutable plan",
            ));
        }
        if Utc::now() - self.plan.created_at > PLAN_TTL {
            return Err(CoreError::validation(
                "capability strip operation",
                "计划已过期，请重新规划",
            ));
        }
        Ok(())
    }

    async fn read_state(&self) -> CoreResult<CapabilityState> {
        let output = self
            .service
            .ssh
            .execute_bound(&self.session, state_command(&self.path), PROBE_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(command_failed("capability read", &output));
        }
        let mut state = CapabilityState {
            sha256: None,
            caps: None,
        };
        let caps_prefix = format!("{} ", self.path.as_str());
        for line in output.output.lines() {
            if let Some(sha) = line.strip_prefix("SHA|") {
                state.sha256 = Some(sha.trim().to_owned());
            } else if let Some(raw) = line.strip_prefix("CAPSRAW|") {
                state.caps = Some(
                    raw.strip_prefix(&caps_prefix)
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
        }
        Ok(state)
    }

    /// Whether the file is still exactly the file and capability set the plan
    /// was built on. The "file content changed" wording keeps
    /// `operation_left_untouched` honest: this refusal ran before any write.
    fn expect_planned_state(&self, state: &CapabilityState) -> CoreResult<()> {
        if state.sha256.as_deref() != Some(self.sha256.as_str()) {
            return Err(CoreError::validation(
                CAPABILITY_CHANGED_REFUSAL,
                "file content changed after the operation was planned; nothing was modified",
            ));
        }
        if state.caps.as_deref() != Some(self.saved_caps.as_str()) {
            return Err(CoreError::validation(
                CAPABILITY_CHANGED_REFUSAL,
                "capability set changed after the operation was planned; nothing was modified",
            ));
        }
        Ok(())
    }

    async fn run(&self, command: String) -> CoreResult<crate::ssh::SshCommandOutput> {
        let output = self
            .service
            .ssh
            .execute_bound(&self.session, command, EXECUTE_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(command_failed("capability command", &output));
        }
        Ok(output)
    }

    /// After undo's restore: the saved set is back on the same file.
    async fn confirm_restored(&self) -> CoreResult<String> {
        let state = self.read_state().await?;
        if state.caps.as_deref() == Some(self.saved_caps.as_str())
            && state.sha256.as_deref() == Some(self.sha256.as_str())
        {
            Ok(format!(
                "回读：{} 的能力集已恢复为 {}。",
                self.path.as_str(),
                self.saved_caps
            ))
        } else {
            Err(CoreError::validation(
                "capability restore check",
                "放回后复核不一致，请人工检查目标文件的能力与内容",
            ))
        }
    }
}

impl std::fmt::Debug for CapabilityStripExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapabilityStripExecutor")
            .field("path", &self.path.as_str())
            .field("saved_caps", &self.saved_caps)
            .finish()
    }
}

#[async_trait]
impl OperationExecutor for CapabilityStripExecutor {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.service.target.validate(&operation.target)?;
        let state = self.read_state().await?;
        self.expect_planned_state(&state)?;
        let quoted = shq(self.path.as_str());
        let output = self
            .run(format!("{}setcap -r {quoted}", self.prefix))
            .await?;
        if output.exit_code != Some(0) {
            return Err(command_failed("setcap -r", &output));
        }
        self.service.target.validate(&operation.target)?;
        Ok(ExecutionReceipt {
            summary: format!(
                "setcap -r {}（原能力：{}）",
                self.path.as_str(),
                self.saved_caps
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
        let state = self.read_state().await?;
        let unchanged = state.sha256.as_deref() == Some(self.sha256.as_str());
        let empty = state.caps.as_deref().unwrap_or_default().is_empty();
        let passed = unchanged && empty;
        Ok(VerificationResult {
            passed,
            detail: if !unchanged {
                format!(
                    "回读：{} 的摘要已变化，文件可能被替换，未自动放回。",
                    self.path.as_str()
                )
            } else if passed {
                format!("回读：{} 已无文件能力。", self.path.as_str())
            } else {
                format!(
                    "回读：{} 仍显示能力 {}，未自动放回。",
                    self.path.as_str(),
                    state.caps.unwrap_or_default()
                )
            },
        })
    }

    async fn restore(
        &self,
        _operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        let quoted = shq(self.path.as_str());
        let output = self
            .run(format!(
                "{}setcap {} {quoted}",
                self.prefix,
                shq(&self.saved_caps)
            ))
            .await?;
        if output.exit_code != Some(0) {
            return Err(command_failed("setcap restore", &output));
        }
        Ok(())
    }
}

fn command_failed(subject: &'static str, output: &crate::ssh::SshCommandOutput) -> CoreError {
    CoreError::Validation {
        subject: "capability strip command",
        message: format!(
            "{subject} failed (exit={:?}, timed_out={})",
            output.exit_code, output.timed_out
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RemotePath {
        RemotePath::new(value).unwrap()
    }

    #[test]
    fn probe_collects_privilege_tools_kind_digest_and_caps() {
        let probe = parse_probe(
            "UID|0\nSUDO|no\nSETCAP|yes\nGETCAP|yes\nFILE|regular\nSHA|abc123\nCAPSRAW|/opt/tool cap_setuid=ep\n",
            &path("/opt/tool"),
        );
        assert!(probe.is_root && !probe.sudo && probe.regular);
        assert!(probe.setcap && probe.getcap);
        assert_eq!(probe.sha256.as_deref(), Some("abc123"));
        assert_eq!(probe.caps.as_deref(), Some("cap_setuid=ep"));
    }

    #[test]
    fn probe_without_caps_or_tools_stays_explicit() {
        let probe = parse_probe(
            "UID|1000\nSUDO|yes\nSETCAP|no\nGETCAP|yes\nFILE|regular\nSHA|abc\n",
            &path("/bin/ls"),
        );
        assert!(!probe.is_root && probe.sudo);
        assert!(!probe.setcap);
        assert_eq!(probe.caps, None);
        let probe = parse_probe("UID|0\nFILE|other\n", &path("/bin/ls"));
        assert!(!probe.regular);
        assert_eq!(probe.sha256, None);
    }

    #[test]
    fn probe_caps_must_follow_the_exact_path() {
        // getcap echoes the argument; a line that does not start with our
        // path contributes nothing rather than a wrong capability set.
        let probe = parse_probe(
            "UID|0\nFILE|regular\nSHA|s\nCAPSRAW|/other/file cap_setuid=ep\n",
            &path("/opt/tool"),
        );
        assert_eq!(probe.caps.as_deref(), Some(""));
        // A path containing a space is still matched by prefix.
        let probe = parse_probe(
            "UID|0\nFILE|regular\nSHA|s\nCAPSRAW|/opt/my tool cap_net_raw=ep\n",
            &path("/opt/my tool"),
        );
        assert_eq!(probe.caps.as_deref(), Some("cap_net_raw=ep"));
    }

    #[test]
    fn probe_command_quotes_the_path() {
        let command = probe_command(&path("/opt/weird dir/x"));
        assert!(command.contains("sha256sum -- '/opt/weird dir/x'"));
        assert!(command.contains("getcap -- '/opt/weird dir/x'"));
    }
}
