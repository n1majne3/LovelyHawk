//! Changing a Linux account's password from the user inventory — the
//! roadmap's "system-account password" remediation item.
//!
//! The plaintext never leaves the controller and never appears in a target
//! command line, `ps` listing, shell history, or audit entry: core computes
//! the SHA-512 crypt hash itself and the write puts only the hash on the
//! target. Preferred write is `chpasswd -e`, fed `user:hash` over the
//! sensitive channel's stdin; `usermod -p` is the fallback and carries the
//! same string the shadow file was going to hold anyway. Planning snapshots
//! the current shadow field; execution refuses when it moved, verification
//! re-reads it for an exact match — crypt output is deterministic, so a
//! stored field equal to the computed hash is the proof the new password
//! authenticates — and a failed verification writes the saved field back.
//!
//! A locked account keeps its lock: the `!` prefixes are preserved, so
//! changing the password of a locked account can never quietly unlock it.
//! Fields that deny password login outright (`*`, `x`, or shapes this code
//! does not recognise) are refused rather than rewritten into a login.

use std::fmt;
use std::time::Duration;

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use async_trait::async_trait;
use chrono::Utc;
use sha_crypt::{PasswordHasher, ShaCrypt};
use zeroize::Zeroizing;

use crate::crypto::SecretValue;
use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::{is_valid_username, shq};
use crate::ssh::{BoundSshSession, SshSensitiveCommandLimits};
use crate::system_info::{
    PRECONDITION_TIMEOUT, SystemInfoService, UserAccountSnapshot, command_failed,
    invalid_detail_key, same_user_account_identity, user_account_snapshot_sha256,
};

/// Refusal subjects the backend maps to operator-facing codes.
pub const ACCOUNT_PASSWORD_PRIVILEGE_REFUSAL: &str = "account password privilege";
pub const ACCOUNT_PASSWORD_TOOLS_REFUSAL: &str = "account password tools";
pub const ACCOUNT_PASSWORD_FIELD_REFUSAL: &str = "account password field";
pub const ACCOUNT_PASSWORD_SECRET_REFUSAL: &str = "account password secret";
pub const ACCOUNT_PASSWORD_CHANGED_REFUSAL: &str = "account password changed";

const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// The backend registry expires plans after five minutes; the executor keeps
/// the same ceiling so a plan held elsewhere cannot run later either.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);

const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

/// The shadow field's character set once the lock `!`s are stripped: modular
/// crypt (`$6$…`), classic DES, or empty. Anything else — `*` and `x` deny
/// password logins outright — is refused rather than rewritten.
const DES_CHARS: &str = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// How the new field gets onto the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PasswordTool {
    /// `chpasswd -e` reads `user:hash` from the sensitive channel's stdin.
    Chpasswd,
    /// `usermod -p <field>` — the hash rides in the command line, which is as
    /// visible as the shadow entry it is about to become.
    Usermod,
}

#[derive(Debug)]
pub struct AccountPasswordPlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: UserAccountSnapshot,
    /// The shadow field at plan time: restore value and the same-file check.
    shadow_field: String,
    /// `!`s preserved plus the locally computed hash. A hash, not the
    /// password; zeroized because it never needs to be read back aloud.
    new_field: Zeroizing<String>,
    tool: PasswordTool,
    /// `""` as root, `"sudo -n "` otherwise — decided by the plan probe.
    prefix: &'static str,
}

impl AccountPasswordPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }
}

#[derive(Debug)]
pub struct AccountPasswordOutcome {
    pub username: String,
    pub verification: VerificationResult,
    pub restored_after_failed_verification: bool,
}

/// What one bounded probe learns about the account's password slot and the
/// tools that could change it.
#[derive(Debug, Default)]
struct PasswordProbe {
    is_root: bool,
    sudo: bool,
    chpasswd_e: bool,
    usermod: bool,
    /// The whole `getent shadow`/`awk` line for the account; None when the
    /// read itself produced nothing.
    shadow_line: Option<String>,
}

fn probe_command(username: &str) -> String {
    let quoted = shq(username);
    format!(
        "u={quoted}; printf 'UID|%s\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         if [ \"$(id -u)\" -eq 0 ]; then run=; else run='sudo -n'; fi; \
         command -v usermod >/dev/null 2>&1 && echo 'USERMOD|yes' || echo 'USERMOD|no'; \
         if command -v chpasswd >/dev/null 2>&1; then \
           printf '' | $run chpasswd -e >/dev/null 2>&1 && echo 'CHPASSWDE|yes' || echo 'CHPASSWDE|no'; \
         else echo 'CHPASSWDE|no'; fi; \
         line=$($run getent shadow \"$u\" 2>/dev/null); \
         [ -n \"$line\" ] || line=$($run awk -F: -v u=\"$u\" '$1==u' /etc/shadow 2>/dev/null | head -n 1); \
         printf 'SHADOWLINE|%s\n' \"$line\""
    )
}

/// The shadow field re-read, before the write (same-file check) and after it
/// (verification). Emits `SHADOWLINE|<line>` so a missing entry and an empty
/// field stay distinguishable.
fn shadow_command(username: &str) -> String {
    let quoted = shq(username);
    format!(
        "u={quoted}; if [ \"$(id -u)\" -eq 0 ]; then run=; else run='sudo -n'; fi; \
         line=$($run getent shadow \"$u\" 2>/dev/null); \
         [ -n \"$line\" ] || line=$($run awk -F: -v u=\"$u\" '$1==u' /etc/shadow 2>/dev/null | head -n 1); \
         printf 'SHADOWLINE|%s\n' \"$line\""
    )
}

fn parse_probe(output: &str, username: &str) -> PasswordProbe {
    let mut probe = PasswordProbe::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "UID" => probe.is_root = value.trim() == "0",
            "SUDO" => probe.sudo = value.trim() == "yes",
            "USERMOD" => probe.usermod = value.trim() == "yes",
            "CHPASSWDE" => probe.chpasswd_e = value.trim() == "yes",
            "SHADOWLINE" => {
                // Only a line that names this exact account counts: a stray
                // match on another user's line would compare — and write —
                // the wrong field.
                let entry = value.trim_end();
                if entry.split(':').next() == Some(username) {
                    probe.shadow_line = Some(entry.to_owned());
                }
            }
            _ => {}
        }
    }
    probe
}

/// Field 2 of a shadow line — may legitimately be empty (`user::…` is an
/// account with no password, not a missing entry).
fn shadow_field(line: &str) -> CoreResult<String> {
    let mut fields = line.split(':');
    let _name = fields.next();
    fields
        .next()
        .map(str::to_owned)
        .ok_or_else(|| invalid_detail_key("account shadow field"))
}

/// The same password policy the PostgreSQL change enforces: nothing the
/// target's own pam_pwquality would wave through as trivial.
fn validate_new_password(password: &SecretValue, username: &str) -> CoreResult<()> {
    let invalid =
        |message: &str| CoreError::validation(ACCOUNT_PASSWORD_SECRET_REFUSAL, message.to_owned());
    let value = password.expose();
    if value.is_empty() {
        return Err(invalid("请填写新口令"));
    }
    if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&value.len()) {
        return Err(invalid("新口令长度需在 12 到 1024 字节之间"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("新口令不能包含控制字符"));
    }
    let classes = [
        value.chars().any(|c| c.is_uppercase()),
        value.chars().any(|c| c.is_lowercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value
            .chars()
            .any(|c| !c.is_uppercase() && !c.is_lowercase() && !c.is_ascii_digit()),
    ];
    if classes.iter().filter(|present| **present).count() < 3 {
        return Err(invalid(
            "新口令至少需要包含大写字母、小写字母、数字、其他字符中的三类",
        ));
    }
    if !username.is_empty() && value.to_lowercase().contains(&username.to_lowercase()) {
        return Err(invalid("新口令不能包含账号名"));
    }
    Ok(())
}

/// SHA-512 crypt in Modular Crypt Format — `$6$rounds=5000$salt$digest`,
/// accepted by glibc and musl pam_unix everywhere a `$` field is.
fn hash_password(password: &SecretValue) -> CoreResult<Zeroizing<String>> {
    // Twelve raw bytes encode to exactly sixteen crypt-base64 salt chars.
    let mut salt = [0_u8; 12];
    OsRng.fill_bytes(&mut salt);
    let hash = ShaCrypt::SHA512
        .hash_password_with_salt(password.expose().as_bytes(), &salt)
        .map_err(|_| invalid_detail_key("account password hash"))?
        .to_string();
    if !hash.starts_with("$6$") {
        return Err(invalid_detail_key("account password hash"));
    }
    Ok(Zeroizing::new(hash))
}

/// What the field becomes: the leading `!`s move over verbatim so a locked
/// account stays locked, and the rest must be a shape a rewrite cannot turn
/// into a password login the old field did not allow.
fn planned_field(current: &str, new_hash: &str) -> CoreResult<String> {
    let bangs = current.chars().take_while(|c| *c == '!').count();
    let rest = &current[bangs..];
    let writable = rest.is_empty()
        || rest.starts_with('$')
        || (rest.len() == 13 && rest.chars().all(|c| DES_CHARS.contains(c)));
    if !writable {
        return Err(CoreError::validation(
            ACCOUNT_PASSWORD_FIELD_REFUSAL,
            "该账号的口令槽位为禁止登录标记或无法识别的格式，改写它可能意外放行口令登录；请改用锁定",
        ));
    }
    Ok(format!("{}{}", "!".repeat(bangs), new_hash))
}

impl SystemInfoService {
    /// Describe changing `username`'s password, without changing anything.
    ///
    /// Refuses before planning when the secret violates the policy, when the
    /// privilege or the tools are missing, or when the shadow field is a
    /// shape a rewrite would change the meaning of. `password` is hashed
    /// here and dropped; the plan keeps only the field it will write.
    pub async fn plan_account_password(
        &self,
        session: &BoundSshSession,
        row_id: &str,
        username: &str,
        password: SecretValue,
    ) -> CoreResult<AccountPasswordPlan> {
        self.target.validate(session.target())?;
        if !is_valid_username(username) {
            return Err(invalid_detail_key("Linux username"));
        }
        validate_new_password(&password, username)?;
        let snapshot = self
            .user_account_snapshot(session, username)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "user account",
                id: username.to_owned(),
            })?;
        let output = self
            .ssh
            .execute_bound(session, probe_command(username), PRECONDITION_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("account password probe", &output));
        }
        let probe = parse_probe(&output.output, username);
        if !(probe.is_root || probe.sudo) {
            return Err(CoreError::validation(
                ACCOUNT_PASSWORD_PRIVILEGE_REFUSAL,
                "需要 root 或免密码 sudo 才能修改账户口令",
            ));
        }
        let tool = if probe.chpasswd_e {
            PasswordTool::Chpasswd
        } else if probe.usermod {
            PasswordTool::Usermod
        } else {
            return Err(CoreError::validation(
                ACCOUNT_PASSWORD_TOOLS_REFUSAL,
                "目标机缺少可用的改口令工具（chpasswd -e 或 usermod）",
            ));
        };
        let field = match &probe.shadow_line {
            Some(line) => shadow_field(line)?,
            None => {
                return Err(CoreError::validation(
                    ACCOUNT_PASSWORD_FIELD_REFUSAL,
                    "读取不到该账号的本地口令记录；可能是域/目录账号或权限不足",
                ));
            }
        };
        let prefix = if probe.is_root { "" } else { "sudo -n " };
        let new_hash = hash_password(&password)?;
        let new_field = planned_field(&field, &new_hash)?;
        let preserved = field.starts_with('!');
        let session_warning = if snapshot.username == snapshot.session_username {
            "这是当前 SSH 登录账户：改口令不影响已建立的连接，但下次登录和本机保存的连接口令都要用新口令。"
        } else {
            "改口令可能使依赖该账户口令登录的服务、计划任务或自动化失效，执行前请确认影响范围。"
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "修改账户 {}（UID {}，当前{}）的登录口令。本地计算 SHA-512 crypt 散列，目标机只会收到散列本身，明文口令不离开本机{}。执行前会重读口令记录，被改过就拒绝；执行后回读散列一致才算成功，不一致自动写回原值。{}",
                snapshot.username,
                snapshot.uid,
                snapshot.password_state.display(),
                if preserved {
                    "；账户的锁定状态保持不变"
                } else {
                    ""
                },
                session_warning,
            ),
            true,
            Some(format!(
                "把账户 {} 的口令散列写回操作前的值（锁定状态一并还原）。",
                snapshot.username,
            )),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-user-password".to_owned());
        operation
            .metadata
            .insert("username".to_owned(), snapshot.username.clone());
        operation
            .metadata
            .insert("uid".to_owned(), snapshot.uid.to_string());
        operation
            .metadata
            .insert("action".to_owned(), "password".to_owned());
        operation
            .metadata
            .insert("hash-algorithm".to_owned(), "sha512-crypt".to_owned());
        operation
            .metadata
            .insert("lock-preserved".to_owned(), preserved.to_string());
        operation.metadata.insert(
            "snapshot-sha256".to_owned(),
            user_account_snapshot_sha256(&snapshot),
        );
        Ok(AccountPasswordPlan {
            operation,
            row_id: row_id.to_owned(),
            snapshot,
            shadow_field: field,
            new_field: Zeroizing::new(new_field),
            tool,
            prefix,
        })
    }

    /// Runs the confirmed plan once: pre-checks the shadow field, writes the
    /// new one, verifies the field re-reads exactly, and restores on a failed
    /// verification.
    pub async fn execute_account_password(
        &self,
        session: &BoundSshSession,
        plan: AccountPasswordPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<AccountPasswordOutcome> {
        let executor = AccountPasswordExecutor {
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
                        "account password verification",
                        format!(
                            "{verification_error}; automatic restore also failed: {restore_error}"
                        ),
                    )),
                };
            }
        };
        let restored_after_failed_verification = if verification.passed {
            false
        } else {
            operation.restore(&self.target, &executor, journal).await?;
            true
        };
        Ok(AccountPasswordOutcome {
            username: plan.snapshot.username.clone(),
            verification,
            restored_after_failed_verification,
        })
    }
}

struct AccountPasswordExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a AccountPasswordPlan,
}

impl fmt::Debug for AccountPasswordExecutor<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountPasswordExecutor")
            .field("username", &self.plan.snapshot.username)
            .field("tool", &self.plan.tool)
            .finish()
    }
}

impl AccountPasswordExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "account password operation",
                "executor is bound to a different immutable plan",
            ));
        }
        if Utc::now() - self.plan.operation.created_at > PLAN_TTL {
            return Err(CoreError::validation(
                "account password operation",
                "计划已过期，请重新规划",
            ));
        }
        Ok(())
    }

    /// The current shadow field for the account; `None` when the read
    /// produced no entry at all.
    async fn read_field(&self) -> CoreResult<Option<String>> {
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                shadow_command(&self.plan.snapshot.username),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        if output.timed_out {
            return Err(command_failed("account shadow read", &output));
        }
        let probe = parse_probe(&output.output, &self.plan.snapshot.username);
        match &probe.shadow_line {
            Some(line) => shadow_field(line).map(Some),
            None => Ok(None),
        }
    }

    /// Whether the shadow entry is still the one the plan was built on. The
    /// refusal names "changed" rather than a write failure so the receipt can
    /// honestly say nothing was touched.
    fn expect_planned_field(&self, current: &Option<String>) -> CoreResult<()> {
        if current.as_deref() == Some(self.plan.shadow_field.as_str()) {
            return Ok(());
        }
        Err(CoreError::validation(
            ACCOUNT_PASSWORD_CHANGED_REFUSAL,
            "口令记录在计划之后变了，这次没有写入；请重新查看账户状态后再操作",
        ))
    }

    /// Writes one shadow field: `chpasswd -e` over the sensitive channel's
    /// stdin, or `usermod -p` as the fallback. Either way only the hash ever
    /// reaches the target; `prefix` is the privilege the plan probe decided.
    async fn write_field(&self, field: &str) -> CoreResult<()> {
        let prefix = self.plan.prefix;
        let username = &self.plan.snapshot.username;
        match self.plan.tool {
            PasswordTool::Chpasswd => {
                let command = Zeroizing::new(format!("{prefix}chpasswd -e"));
                let stdin = Zeroizing::new(format!("{username}:{field}\n").into_bytes());
                let output = self
                    .service
                    .ssh
                    .execute_bound_sensitive(
                        self.session,
                        command,
                        stdin,
                        WRITE_TIMEOUT,
                        SshSensitiveCommandLimits::new(4096, 4096)?,
                    )
                    .await?;
                if output.exit_code != Some(0) {
                    return Err(CoreError::Validation {
                        subject: "account password write",
                        message: format!("chpasswd failed (exit={:?})", output.exit_code),
                    });
                }
            }
            PasswordTool::Usermod => {
                let output = self
                    .service
                    .ssh
                    .execute_bound(
                        self.session,
                        format!("{prefix}usermod -p {} {}", shq(field), shq(username)),
                        WRITE_TIMEOUT,
                    )
                    .await?;
                if output.timed_out || output.exit_code != Some(0) {
                    return Err(command_failed("usermod -p", &output));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for AccountPasswordExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.service.target.validate(&operation.target)?;
        let current = self.read_field().await?;
        self.expect_planned_field(&current)?;
        self.write_field(&self.plan.new_field).await?;
        self.service.target.validate(&operation.target)?;
        Ok(ExecutionReceipt {
            summary: format!(
                "修改 {} 的口令散列（计划时账户摘要 {}）",
                self.plan.snapshot.username,
                user_account_snapshot_sha256(&self.plan.snapshot),
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
        let observed = self.read_field().await?;
        let passed = observed.as_deref() == Some(self.plan.new_field.as_str());
        // The account identity must not have moved either: a userdel/recreate
        // between plan and write could carry our field onto a different uid.
        let identity_held = self
            .service
            .user_account_snapshot(self.session, &self.plan.snapshot.username)
            .await?
            .is_some_and(|snapshot| same_user_account_identity(&snapshot, &self.plan.snapshot));
        let passed = passed && identity_held;
        Ok(VerificationResult {
            passed,
            detail: if passed {
                let lock = if self.plan.new_field.starts_with('!') {
                    "，账户仍是锁定状态"
                } else {
                    ""
                };
                format!(
                    "回读：账户 {} 的口令散列与写入值一致{}；散列即新口令的验证依据。",
                    self.plan.snapshot.username, lock
                )
            } else if !identity_held {
                format!(
                    "回读：账户 {} 的身份在写入后发生了变化，未自动放回，请人工核对。",
                    self.plan.snapshot.username
                )
            } else {
                format!(
                    "回读：账户 {} 的口令记录与写入值不一致，未自动放回，请人工核对。",
                    self.plan.snapshot.username
                )
            },
        })
    }

    async fn restore(
        &self,
        _operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.write_field(&self.plan.shadow_field).await?;
        let restored = self.read_field().await?;
        if restored.as_deref() != Some(self.plan.shadow_field.as_str()) {
            return Err(CoreError::validation(
                "account password restore",
                "放回后口令记录与操作前值不一致，请人工核对 shadow",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> SecretValue {
        SecretValue::new(value)
    }

    #[test]
    fn planned_field_preserves_lock_bangs_and_refuses_denial_marks() {
        assert_eq!(planned_field("$1$old", "NEW").unwrap(), "NEW");
        assert_eq!(planned_field("!$6$old", "NEW").unwrap(), "!NEW");
        assert_eq!(planned_field("!!", "NEW").unwrap(), "!!NEW");
        assert_eq!(planned_field("", "NEW").unwrap(), "NEW");
        // A classic 13-character DES hash is a writable shape.
        assert_eq!(planned_field("abCDEF0123456", "NEW").unwrap(), "NEW");
        for denied in ["*", "x", "!x", "*LK*", "!!*"] {
            assert!(
                planned_field(denied, "NEW").is_err(),
                "{denied} should refuse"
            );
        }
    }

    #[test]
    fn password_policy_matches_the_database_change() {
        assert!(validate_new_password(&secret("short1!"), "u").is_err());
        assert!(validate_new_password(&secret("alllowercase12"), "u").is_err());
        assert!(validate_new_password(&secret("My-user-Passw0rd"), "user").is_err());
        assert!(validate_new_password(&secret("GoodPassw0rd!"), "u").is_ok());
        assert!(
            validate_new_password(&secret(&"aA1!".repeat(300)), "u").is_err(),
            "over the byte ceiling refuses"
        );
        assert!(validate_new_password(&secret("line\nbreakA1!"), "u").is_err());
    }

    #[test]
    fn hash_is_sha512_crypt_mcf() {
        let hash = hash_password(&secret("GoodPassw0rd!")).unwrap();
        // glibc/musl pam_unix accepts either `$6$salt$digest` or the explicit
        // `$6$rounds=N$salt$digest`; both start the same way.
        assert!(hash.starts_with("$6$"));
        assert!(hash.len() >= 80);
    }

    #[test]
    fn probe_reads_only_the_named_accounts_shadow_line() {
        let probe = parse_probe(
            "UID|0\nSUDO|no\nUSERMOD|yes\nCHPASSWDE|yes\nSHADOWLINE|root:$6$abc:1:2:3:4:5:6:\n",
            "root",
        );
        assert!(probe.is_root && probe.usermod && probe.chpasswd_e);
        assert_eq!(
            probe.shadow_line.as_deref(),
            Some("root:$6$abc:1:2:3:4:5:6:")
        );
        assert_eq!(
            shadow_field(probe.shadow_line.as_ref().unwrap()).unwrap(),
            "$6$abc"
        );
        // Another account's line must not be mistaken for ours.
        let probe = parse_probe("SHADOWLINE|daemon:*:1:2:3::::\n", "root");
        assert_eq!(probe.shadow_line, None);
        // Empty field is a real state (passwordless), not a missing entry.
        let probe = parse_probe("SHADOWLINE|svc::1:2:3::::\n", "svc");
        assert_eq!(
            shadow_field(probe.shadow_line.as_ref().unwrap()).unwrap(),
            ""
        );
    }
}
