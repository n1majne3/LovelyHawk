//! PostgreSQL database account password change over the bound SSH session.
//! Only the closed statements built here reach the database; the plaintext
//! password never enters SQL text, journal entries, logs, or public values.

use std::fmt;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::{Client, Row};
use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult,
    crypto::SecretValue,
    database::{
        DatabaseEngine, DatabaseProfileChanges, DatabaseProfileSnapshot, DatabaseSecretChange,
        DatabaseService, validate_profile_session,
    },
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal,
        OperationPlan, OperationState, PlannedOperation, VerificationResult,
    },
    postgresql_native::{
        NativeConnectClass, NativeRuntimeRequest, NativeSessionProfile, connect, database_error,
        invalid,
    },
    ssh::BoundSshSession,
    target::TargetGuard,
};

/// Plan entries and restore tokens live only in backend memory.
const PLAN_TTL: Duration = Duration::from_secs(120);
const RESTORE_TOKEN_TTL: Duration = Duration::from_secs(600);
const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresqlPasswordRole {
    Current,
    Oid(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PostgresqlPasswordFormat {
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    #[serde(rename = "md5")]
    Md5,
}

impl PostgresqlPasswordFormat {
    fn label(self) -> &'static str {
        match self {
            Self::ScramSha256 => "scram-sha-256",
            Self::Md5 => "md5",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresqlPasswordWarning {
    Md5Weak,
    ReplicationRole,
    SuperuserRole,
    ConnectionRole,
    NotRestorable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabasePasswordPlanView {
    pub role_name: String,
    pub is_connection_role: bool,
    pub superuser: bool,
    pub replication: bool,
    pub format: PostgresqlPasswordFormat,
    pub restorable: bool,
    pub updates_saved_password: bool,
    pub warnings: Vec<PostgresqlPasswordWarning>,
}

/// Immutable plan holding the plaintext password only in backend memory.
/// `Debug` is redacted; nothing here is serializable.
pub struct DatabasePasswordPlan {
    operation: OperationPlan,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    role_oid: u32,
    role_name: String,
    is_connection_role: bool,
    restorable: bool,
    format: PostgresqlPasswordFormat,
    update_saved_password: bool,
    new_password: SecretValue,
    created: Instant,
    view: DatabasePasswordPlanView,
}

impl fmt::Debug for DatabasePasswordPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabasePasswordPlan")
            .field("operation_id", &self.operation.id)
            .field("role_oid", &self.role_oid)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl DatabasePasswordPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn view(&self) -> &DatabasePasswordPlanView {
        &self.view
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresqlVerifyBlock {
    AccessRule,
    Network,
    Timeout,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "reason")]
pub enum PostgresqlPasswordVerification {
    Passed,
    Rejected,
    Unverifiable(PostgresqlVerifyBlock),
}

impl PostgresqlPasswordVerification {
    fn detail(self) -> &'static str {
        match self {
            Self::Passed => "verification:passed",
            Self::Rejected => "verification:rejected",
            Self::Unverifiable(PostgresqlVerifyBlock::AccessRule) => {
                "verification:unverifiable:access-rule"
            }
            Self::Unverifiable(PostgresqlVerifyBlock::Network) => {
                "verification:unverifiable:network"
            }
            Self::Unverifiable(PostgresqlVerifyBlock::Timeout) => {
                "verification:unverifiable:timeout"
            }
            Self::Unverifiable(PostgresqlVerifyBlock::Other) => "verification:unverifiable:other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SavedPasswordUpdate {
    NotRequested,
    Updated,
    ProfileChanged,
    SkippedVerificationNotPassed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabasePasswordOutcome {
    pub operation_id: String,
    pub verification: PostgresqlPasswordVerification,
    pub saved_password: SavedPasswordUpdate,
    pub restorable: bool,
    /// False when the post-commit journal append itself failed; the remote
    /// change is still committed.
    pub journal_recorded: bool,
}

/// Secret-free outcome plus the in-memory restore token, kept out of
/// serialization so the old verifier can never reach a DTO.
pub struct DatabasePasswordExecution {
    pub outcome: DatabasePasswordOutcome,
    pub restore_token: Option<DatabasePasswordRestoreToken>,
}

impl fmt::Debug for DatabasePasswordExecution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabasePasswordExecution")
            .field("outcome", &self.outcome)
            .field("restore_token", &self.restore_token.is_some())
            .finish()
    }
}

/// One-shot in-memory handle for putting back the captured old verifier.
/// Never serialized, expires after ten minutes.
pub struct DatabasePasswordRestoreToken {
    role_oid: u32,
    role_name: String,
    old_verifier: Zeroizing<Option<String>>,
    profile_id: String,
    target: TargetGuard,
    saved_password_updated: bool,
    /// Password the restore connection must use: the new one when the
    /// connection role changed and the saved profile was not updated.
    connect_password: Option<SecretValue>,
    /// The saved profile secret captured at execute time, put back after a
    /// verified restore when the saved password was updated.
    previous_saved_password: Option<SecretValue>,
    created: Instant,
    claimed: AtomicBool,
}

impl DatabasePasswordRestoreToken {
    fn expired(&self) -> bool {
        self.created.elapsed() > RESTORE_TOKEN_TTL
    }
}

impl fmt::Debug for DatabasePasswordRestoreToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabasePasswordRestoreToken")
            .field("role_oid", &self.role_oid)
            .field("role_name", &self.role_name)
            .finish_non_exhaustive()
    }
}

pub struct DatabasePasswordRestorePlan {
    operation: OperationPlan,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    role_oid: u32,
    role_name: String,
    old_verifier: Zeroizing<Option<String>>,
    connect_password: Option<SecretValue>,
    previous_saved_password: Option<SecretValue>,
    saved_password_updated: bool,
    view: DatabasePasswordRestorePlanView,
}

impl fmt::Debug for DatabasePasswordRestorePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabasePasswordRestorePlan")
            .field("operation_id", &self.operation.id)
            .field("role_oid", &self.role_oid)
            .finish_non_exhaustive()
    }
}

impl DatabasePasswordRestorePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn view(&self) -> &DatabasePasswordRestorePlanView {
        &self.view
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabasePasswordRestorePlanView {
    pub role_name: String,
    /// Whether the saved connection password was replaced by the new one and
    /// therefore has to be changed back manually after restoring.
    pub saved_password_was_updated: bool,
}

/// Closed read-back result for a committed restore; the journal keeps the
/// generic VerificationResult.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresqlRestoreVerification {
    Passed,
    Mismatch,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SavedPasswordRestore {
    NotApplicable,
    Restored,
    ProfileChanged,
    SkippedVerificationNotPassed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabasePasswordRestoreOutcome {
    pub operation_id: String,
    pub verification: PostgresqlRestoreVerification,
    pub saved_password: SavedPasswordRestore,
    pub journal_recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InspectTarget {
    Current,
    Oid(u32),
}

/// One SSH-actor step; each variant opens its own direct-tcpip channel.
pub(crate) enum PostgresqlPasswordStep {
    Inspect {
        request: NativeRuntimeRequest,
        role: InspectTarget,
    },
    Apply {
        request: NativeRuntimeRequest,
        role_oid: u32,
        role_name: String,
        capture_old: bool,
        verifier: Zeroizing<String>,
    },
    VerifyLogin {
        request: NativeRuntimeRequest,
        expected_user: String,
    },
    ReadVerifier {
        request: NativeRuntimeRequest,
        role_oid: u32,
    },
    Restore {
        request: NativeRuntimeRequest,
        role_oid: u32,
        role_name: String,
        old_verifier: Zeroizing<Option<String>>,
    },
}

impl fmt::Debug for PostgresqlPasswordStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Inspect { .. } => "Inspect",
            Self::Apply { .. } => "Apply",
            Self::VerifyLogin { .. } => "VerifyLogin",
            Self::ReadVerifier { .. } => "ReadVerifier",
            Self::Restore { .. } => "Restore",
        };
        f.debug_tuple("PostgresqlPasswordStep")
            .field(&name)
            .finish_non_exhaustive()
    }
}

impl PostgresqlPasswordStep {
    pub(crate) fn endpoint(&self) -> (String, u16) {
        let request = match self {
            Self::Inspect { request, .. }
            | Self::Apply { request, .. }
            | Self::VerifyLogin { request, .. }
            | Self::ReadVerifier { request, .. }
            | Self::Restore { request, .. } => request,
        };
        (request.host().to_owned(), request.port())
    }
}

pub(crate) struct PostgresqlInspect {
    pub(crate) server_version_num: u32,
    pub(crate) password_encryption: String,
    pub(crate) connecting_oid: u32,
    pub(crate) connecting_superuser: bool,
    pub(crate) target_oid: u32,
    pub(crate) target_name: String,
    pub(crate) target_can_login: bool,
    pub(crate) target_superuser: bool,
    pub(crate) target_replication: bool,
}

pub(crate) enum PostgresqlPasswordResult {
    Inspected(Box<PostgresqlInspect>),
    Applied {
        old_verifier: Zeroizing<Option<String>>,
    },
    VerifiedLogin(PostgresqlPasswordVerification),
    Verifier(Zeroizing<Option<String>>),
    /// Read-back performed on the restore connection after COMMIT: the
    /// connection role cannot reconnect when its own password was restored,
    /// so the verifier is captured before the channel closes. `None` means
    /// the read-back itself failed.
    Restored {
        verifier: Option<Zeroizing<Option<String>>>,
    },
}

impl fmt::Debug for PostgresqlPasswordResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Inspected(_) => "Inspected",
            Self::Applied { .. } => "Applied",
            Self::VerifiedLogin(_) => "VerifiedLogin",
            Self::Verifier(_) => "Verifier",
            Self::Restored { .. } => "Restored",
        };
        f.debug_tuple("PostgresqlPasswordResult")
            .field(&name)
            .finish()
    }
}

fn password_error(error: tokio_postgres::Error) -> CoreError {
    if error.code().map(|code| code.code()) == Some("42501") {
        invalid("当前连接账号无权修改该角色的口令")
    } else {
        database_error("数据库口令修改未能完成", error)
    }
}

fn check_error(error: tokio_postgres::Error) -> CoreError {
    database_error("数据库口令修改前的检查未能执行", error)
}

fn quote_ident(name: &str) -> CoreResult<String> {
    if name.is_empty() || name.contains('\0') {
        return Err(invalid("角色名包含不支持的字符"));
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

fn quote_literal(value: &str) -> CoreResult<String> {
    if value.contains('\0') {
        return Err(invalid("口令校验值包含不支持的字符"));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// `on` is the legacy alias of `md5` that PostgreSQL 10–13 can still report.
fn parse_encryption(value: &str, server_version_num: u32) -> CoreResult<PostgresqlPasswordFormat> {
    match value {
        "scram-sha-256" => Ok(PostgresqlPasswordFormat::ScramSha256),
        "md5" | "on" if value != "on" || server_version_num < 140_000 => {
            Ok(PostgresqlPasswordFormat::Md5)
        }
        _ => Err(invalid(
            "数据库的 password_encryption 配置不受支持，未执行修改",
        )),
    }
}

fn parse_oid(value: String) -> CoreResult<u32> {
    value
        .parse()
        .map_err(|_| invalid("数据库角色 OID 未能识别"))
}

fn one_row(rows: Vec<Row>) -> CoreResult<Row> {
    if rows.len() != 1 {
        return Err(invalid("数据库检查返回了不符合约定的行数"));
    }
    Ok(rows.into_iter().next().expect("one row"))
}

pub(crate) fn validate_new_password(password: &SecretValue) -> CoreResult<()> {
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
    Ok(())
}

pub(crate) fn validate_password_against_role(
    password: &SecretValue,
    role_name: &str,
) -> CoreResult<()> {
    if !role_name.is_empty()
        && password
            .expose()
            .to_lowercase()
            .contains(&role_name.to_lowercase())
    {
        return Err(invalid("新口令不能包含账号名"));
    }
    Ok(())
}

fn constant_time_eq(left: &Option<String>, right: &Option<String>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            let left = left.as_bytes();
            let right = right.as_bytes();
            if left.len() != right.len() {
                return false;
            }
            left.iter()
                .zip(right.iter())
                .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        }
        (None, None) => true,
        _ => false,
    }
}

async fn inspect_roles(client: &Client, role: InspectTarget) -> CoreResult<PostgresqlInspect> {
    let settings = one_row(
        client
            .query(
                "SELECT current_setting('server_version_num'), current_setting('password_encryption')",
                &[],
            )
            .await
            .map_err(check_error)?,
    )?;
    let server_version_num: u32 = settings
        .get::<_, String>(0)
        .parse()
        .map_err(|_| invalid("数据库版本未能识别"))?;
    let connecting = one_row(
        client
            .query(
                "SELECT oid::text, rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(check_error)?,
    )?;
    let target = one_row(match role {
        InspectTarget::Current => client
            .query(
                "SELECT oid::text, rolname::text, rolcanlogin, rolsuper, rolreplication \
                     FROM pg_catalog.pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(check_error)?,
        InspectTarget::Oid(oid) => client
            .query(
                "SELECT oid::text, rolname::text, rolcanlogin, rolsuper, rolreplication \
                     FROM pg_catalog.pg_roles WHERE oid = $1",
                &[&oid],
            )
            .await
            .map_err(check_error)?,
    })?;
    Ok(PostgresqlInspect {
        server_version_num,
        password_encryption: settings.get(1),
        connecting_oid: parse_oid(connecting.get(0))?,
        connecting_superuser: connecting.get(1),
        target_oid: parse_oid(target.get(0))?,
        target_name: target.get(1),
        target_can_login: target.get(2),
        target_superuser: target.get(3),
        target_replication: target.get(4),
    })
}

async fn apply_password(
    client: &Client,
    role_oid: u32,
    role_name: &str,
    capture_old: bool,
    verifier: &str,
) -> CoreResult<Zeroizing<Option<String>>> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(password_error)?;
    let outcome = async {
        let role = one_row(
            client
                .query(
                    "SELECT rolname::text, rolcanlogin FROM pg_catalog.pg_roles WHERE oid = $1",
                    &[&role_oid],
                )
                .await
                .map_err(password_error)?,
        )?;
        let actual: String = role.get(0);
        if actual != role_name || !role.get::<_, bool>(1) {
            return Err(invalid("目标角色在修改前已变化，未执行口令修改"));
        }
        let old_verifier = if capture_old {
            Zeroizing::new(
                client
                    .query_opt(
                        "SELECT rolpassword FROM pg_catalog.pg_authid WHERE oid = $1",
                        &[&role_oid],
                    )
                    .await
                    .map_err(password_error)?
                    .and_then(|row| row.get::<_, Option<String>>(0)),
            )
        } else {
            Zeroizing::new(None)
        };
        let statement = format!(
            "ALTER ROLE {} PASSWORD {}",
            quote_ident(&actual)?,
            quote_literal(verifier)?
        );
        client
            .batch_execute(&statement)
            .await
            .map_err(password_error)?;
        Ok(old_verifier)
    }
    .await;
    let old_verifier = match outcome {
        Ok(old_verifier) => old_verifier,
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            return Err(error);
        }
    };
    // COMMIT may already be applied even if this call reports an error; the
    // remote state is then unknown and must be refreshed, never "unchanged".
    client
        .batch_execute("COMMIT")
        .await
        .map_err(|_| invalid("口令修改的提交结果未确认，数据库上的口令状态未知，请刷新核对"))?;
    Ok(old_verifier)
}

async fn restore_password(
    client: &Client,
    role_oid: u32,
    role_name: &str,
    old_verifier: &Option<String>,
) -> CoreResult<()> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(password_error)?;
    let outcome = async {
        let role = one_row(
            client
                .query(
                    "SELECT rolname::text FROM pg_catalog.pg_roles WHERE oid = $1",
                    &[&role_oid],
                )
                .await
                .map_err(password_error)?,
        )?;
        let actual: String = role.get(0);
        if actual != role_name {
            return Err(invalid("目标角色在恢复前已变化，未执行口令恢复"));
        }
        let statement = match old_verifier {
            Some(verifier) => format!(
                "ALTER ROLE {} PASSWORD {}",
                quote_ident(&actual)?,
                quote_literal(verifier)?
            ),
            None => format!("ALTER ROLE {} PASSWORD NULL", quote_ident(&actual)?),
        };
        client
            .batch_execute(&statement)
            .await
            .map_err(password_error)?;
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        let _ = client.batch_execute("ROLLBACK").await;
        return Err(error);
    }
    client
        .batch_execute("COMMIT")
        .await
        .map_err(|_| invalid("口令恢复的提交结果未确认，数据库上的口令状态未知，请刷新核对"))?;
    Ok(())
}

async fn read_verifier(client: &Client, role_oid: u32) -> CoreResult<Zeroizing<Option<String>>> {
    Ok(Zeroizing::new(
        client
            .query_opt(
                "SELECT rolpassword FROM pg_catalog.pg_authid WHERE oid = $1",
                &[&role_oid],
            )
            .await
            .map_err(password_error)?
            .and_then(|row| row.get::<_, Option<String>>(0)),
    ))
}

async fn verify_login(client: &Client, expected_user: &str) -> CoreResult<()> {
    let row = one_row(
        client
            .query("SELECT current_user", &[])
            .await
            .map_err(check_error)?,
    )?;
    if row.get::<_, String>(0) == expected_user {
        Ok(())
    } else {
        Err(invalid("复核连接报告了不同的数据库账号"))
    }
}

/// Executes one step on its own channel stream; the caller (SSH actor) owns
/// channel open/close and cancellation.
pub(crate) async fn run_step_on_stream<S>(
    stream: S,
    step: PostgresqlPasswordStep,
) -> CoreResult<PostgresqlPasswordResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match step {
        PostgresqlPasswordStep::Inspect { request, role } => {
            let connection = connect(stream, request, NativeSessionProfile::ReadOnlyReview).await?;
            let (inspected, _) = connection
                .run(|client| Box::pin(inspect_roles(client, role)))
                .await?;
            Ok(PostgresqlPasswordResult::Inspected(Box::new(inspected)))
        }
        PostgresqlPasswordStep::Apply {
            request,
            role_oid,
            role_name,
            capture_old,
            verifier,
        } => {
            let connection = connect(stream, request, NativeSessionProfile::PasswordChange).await?;
            let (old_verifier, _) = connection
                .run(|client| {
                    Box::pin(async move {
                        apply_password(client, role_oid, &role_name, capture_old, &verifier).await
                    })
                })
                .await?;
            Ok(PostgresqlPasswordResult::Applied { old_verifier })
        }
        PostgresqlPasswordStep::VerifyLogin {
            request,
            expected_user,
        } => {
            let connection = match connect(stream, request, NativeSessionProfile::ReadOnlyReview)
                .await
            {
                Ok(connection) => connection,
                Err(error) => {
                    let verification = match error.class {
                        NativeConnectClass::Authentication => {
                            PostgresqlPasswordVerification::Rejected
                        }
                        NativeConnectClass::AccessRule => {
                            PostgresqlPasswordVerification::Unverifiable(
                                PostgresqlVerifyBlock::AccessRule,
                            )
                        }
                        NativeConnectClass::Timeout => {
                            PostgresqlPasswordVerification::Unverifiable(
                                PostgresqlVerifyBlock::Timeout,
                            )
                        }
                        NativeConnectClass::Other => PostgresqlPasswordVerification::Unverifiable(
                            PostgresqlVerifyBlock::Other,
                        ),
                    };
                    return Ok(PostgresqlPasswordResult::VerifiedLogin(verification));
                }
            };
            match connection
                .run(|client| {
                    let expected_user = expected_user.clone();
                    Box::pin(async move { verify_login(client, &expected_user).await })
                })
                .await
            {
                Ok(((), _)) => Ok(PostgresqlPasswordResult::VerifiedLogin(
                    PostgresqlPasswordVerification::Passed,
                )),
                Err(_) => Ok(PostgresqlPasswordResult::VerifiedLogin(
                    PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Other),
                )),
            }
        }
        PostgresqlPasswordStep::ReadVerifier { request, role_oid } => {
            let connection = connect(stream, request, NativeSessionProfile::ReadOnlyReview).await?;
            let (verifier, _) = connection
                .run(|client| Box::pin(read_verifier(client, role_oid)))
                .await?;
            Ok(PostgresqlPasswordResult::Verifier(verifier))
        }
        PostgresqlPasswordStep::Restore {
            request,
            role_oid,
            role_name,
            old_verifier,
        } => {
            let connection = connect(stream, request, NativeSessionProfile::PasswordChange).await?;
            let (verifier, _) = connection
                .run(|client| {
                    Box::pin(async move {
                        restore_password(client, role_oid, &role_name, &old_verifier).await?;
                        Ok(read_verifier(client, role_oid).await.ok())
                    })
                })
                .await?;
            Ok(PostgresqlPasswordResult::Restored { verifier })
        }
    }
}

#[derive(Debug)]
struct PasswordChangeExecutor {
    service: DatabaseService,
    session: BoundSshSession,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    request: NativeRuntimeRequest,
    role_oid: u32,
    role_name: String,
    restorable: bool,
    format: PostgresqlPasswordFormat,
    update_saved_password: bool,
    new_password: SecretValue,
    plan: OperationPlan,
    captured: Mutex<Option<Zeroizing<Option<String>>>>,
    outcome: Mutex<Option<(PostgresqlPasswordVerification, SavedPasswordUpdate)>>,
}

impl PasswordChangeExecutor {
    fn verify_request(&self) -> CoreResult<NativeRuntimeRequest> {
        self.request.for_user(
            &self.role_name,
            Some(SecretValue::new(self.new_password.expose())),
        )
    }
}

#[async_trait]
impl OperationExecutor for PasswordChangeExecutor {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if plan != &self.plan {
            return Err(CoreError::validation(
                "database password change",
                "executor received a different immutable plan",
            ));
        }
        let password = self.new_password.expose();
        let verifier = Zeroizing::new(match self.format {
            PostgresqlPasswordFormat::ScramSha256 => {
                postgres_protocol::password::scram_sha_256(password.as_bytes())
            }
            PostgresqlPasswordFormat::Md5 => {
                postgres_protocol::password::md5(password.as_bytes(), &self.role_name)
            }
        });
        let result = self
            .service
            .password_step_write(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                PostgresqlPasswordStep::Apply {
                    request: self.request_for_apply()?,
                    role_oid: self.role_oid,
                    role_name: self.role_name.clone(),
                    capture_old: self.restorable,
                    verifier,
                },
            )
            .await?;
        let PostgresqlPasswordResult::Applied { old_verifier } = result else {
            return Err(invalid("数据库口令修改返回了不符合约定的结果"));
        };
        *self.captured.lock().expect("executor state") = Some(old_verifier);
        Ok(ExecutionReceipt {
            summary: format!(
                "postgresql password change committed for role {}",
                self.role_name
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        if plan != &self.plan {
            return Err(CoreError::validation(
                "database password change",
                "verification received a different immutable plan",
            ));
        }
        let verification = match self
            .service
            .password_step(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                PostgresqlPasswordStep::VerifyLogin {
                    request: self.verify_request()?,
                    expected_user: self.role_name.clone(),
                },
            )
            .await
        {
            Ok(PostgresqlPasswordResult::VerifiedLogin(verification)) => verification,
            Ok(_) => return Err(invalid("数据库口令复核返回了不符合约定的结果")),
            Err(CoreError::Ssh { .. }) => {
                PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Network)
            }
            Err(error) => return Err(error),
        };
        let saved_password = match (self.update_saved_password, verification) {
            (false, _) => SavedPasswordUpdate::NotRequested,
            (true, PostgresqlPasswordVerification::Passed) => {
                match self.service.save_profile_if_unchanged(
                    self.snapshot.view().config.clone(),
                    DatabaseProfileChanges {
                        password: DatabaseSecretChange::Replace(SecretValue::new(
                            self.new_password.expose(),
                        )),
                    },
                    Some(&self.snapshot),
                ) {
                    Ok(_) => SavedPasswordUpdate::Updated,
                    Err(CoreError::Validation { .. }) => SavedPasswordUpdate::ProfileChanged,
                    Err(_) => SavedPasswordUpdate::Failed,
                }
            }
            (true, _) => SavedPasswordUpdate::SkippedVerificationNotPassed,
        };
        *self.outcome.lock().expect("executor state") = Some((verification, saved_password));
        Ok(VerificationResult {
            passed: verification == PostgresqlPasswordVerification::Passed,
            detail: verification.detail().to_owned(),
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "automatic PostgreSQL password restore",
        })
    }
}

impl PasswordChangeExecutor {
    fn request_for_apply(&self) -> CoreResult<NativeRuntimeRequest> {
        NativeRuntimeRequest::new(
            self.request.connection.clone(),
            self.request.tls.clone(),
            self.request
                .password
                .as_ref()
                .map(|password| SecretValue::new(password.expose())),
        )
    }
}

#[derive(Debug)]
struct PasswordRestoreExecutor {
    service: DatabaseService,
    session: BoundSshSession,
    profile_id: String,
    profile_digest: String,
    request: NativeRuntimeRequest,
    role_oid: u32,
    role_name: String,
    old_verifier: Zeroizing<Option<String>>,
    read_back: Mutex<Option<Option<Zeroizing<Option<String>>>>>,
    plan: OperationPlan,
}

impl PasswordRestoreExecutor {
    fn step_request(&self) -> CoreResult<NativeRuntimeRequest> {
        NativeRuntimeRequest::new(
            self.request.connection.clone(),
            self.request.tls.clone(),
            self.request
                .password
                .as_ref()
                .map(|password| SecretValue::new(password.expose())),
        )
    }
}

#[async_trait]
impl OperationExecutor for PasswordRestoreExecutor {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if plan != &self.plan {
            return Err(CoreError::validation(
                "database password restore",
                "executor received a different immutable plan",
            ));
        }
        let result = self
            .service
            .password_step_write(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                PostgresqlPasswordStep::Restore {
                    request: self.step_request()?,
                    role_oid: self.role_oid,
                    role_name: self.role_name.clone(),
                    old_verifier: self.old_verifier.clone(),
                },
            )
            .await?;
        let PostgresqlPasswordResult::Restored { verifier } = result else {
            return Err(invalid("数据库口令恢复返回了不符合约定的结果"));
        };
        *self.read_back.lock().expect("executor state") = Some(verifier);
        Ok(ExecutionReceipt {
            summary: format!(
                "postgresql password restore committed for role {}",
                self.role_name
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        if plan != &self.plan {
            return Err(CoreError::validation(
                "database password restore",
                "verification received a different immutable plan",
            ));
        }
        let read_back = self
            .read_back
            .lock()
            .expect("executor state")
            .clone()
            .flatten();
        // When the in-connection read-back failed, a separate read connection
        // can still work for restores of roles other than the connection role.
        let read_back = match read_back {
            Some(verifier) => Some(verifier),
            None => match self
                .service
                .password_step(
                    &self.session,
                    &self.profile_id,
                    &self.profile_digest,
                    PostgresqlPasswordStep::ReadVerifier {
                        request: self.step_request()?,
                        role_oid: self.role_oid,
                    },
                )
                .await
            {
                Ok(PostgresqlPasswordResult::Verifier(actual)) => Some(actual),
                Ok(_) => {
                    return Err(invalid("数据库口令恢复复核返回了不符合约定的结果"));
                }
                Err(_) => None,
            },
        };
        let (passed, detail) = match read_back {
            Some(actual) => {
                let passed = constant_time_eq(&actual, &self.old_verifier);
                (
                    passed,
                    if passed {
                        "restore-verification:passed"
                    } else {
                        "restore-verification:mismatch"
                    },
                )
            }
            None => (false, "restore-verification:unverified"),
        };
        Ok(VerificationResult {
            passed,
            detail: detail.to_owned(),
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "re-restoring a PostgreSQL password",
        })
    }
}

impl DatabaseService {
    /// Plans a password change after the server reports the reviewed role
    /// facts. The returned plan binds target epoch, profile digest, role OID,
    /// verifier format and restorability, and expires after 120 seconds.
    pub async fn plan_postgresql_password(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        role: PostgresqlPasswordRole,
        new_password: SecretValue,
        update_saved_password: bool,
    ) -> CoreResult<DatabasePasswordPlan> {
        self.target.validate(session.target())?;
        let profile_id = expected.view().config.id.clone();
        let (profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before planning",
            ));
        }
        validate_profile_session(&profile, session)?;
        if profile.connection.engine != DatabaseEngine::Postgresql {
            return Err(invalid("仅 PostgreSQL 连接支持修改账号口令"));
        }
        validate_new_password(&new_password)?;
        let request = NativeRuntimeRequest::new(
            profile.connection.clone(),
            profile.postgresql_tls.clone().unwrap_or_default(),
            profile.password(),
        )?;
        let inspect_target = match role {
            PostgresqlPasswordRole::Current => InspectTarget::Current,
            PostgresqlPasswordRole::Oid(oid) => InspectTarget::Oid(oid),
        };
        let result = self
            .password_step(
                session,
                &profile_id,
                &digest,
                PostgresqlPasswordStep::Inspect {
                    request,
                    role: inspect_target,
                },
            )
            .await?;
        let PostgresqlPasswordResult::Inspected(inspected) = result else {
            return Err(invalid("数据库口令修改前的检查返回了不符合约定的结果"));
        };
        if inspected.server_version_num < 100_000 {
            return Err(invalid("PostgreSQL 10 以下不支持预计算的口令校验值"));
        }
        let format =
            parse_encryption(&inspected.password_encryption, inspected.server_version_num)?;
        if !inspected.target_can_login {
            return Err(invalid("该角色不能登录，设置口令没有作用"));
        }
        if inspected.target_superuser && !inspected.connecting_superuser {
            return Err(invalid("只有超级用户才能修改超级用户角色的口令"));
        }
        validate_password_against_role(&new_password, &inspected.target_name)?;
        let is_connection_role = inspected.target_oid == inspected.connecting_oid;
        let restorable = inspected.connecting_superuser;
        let update_saved_password = update_saved_password && is_connection_role;
        let warnings = {
            let mut warnings = Vec::new();
            if format == PostgresqlPasswordFormat::Md5 {
                warnings.push(PostgresqlPasswordWarning::Md5Weak);
            }
            if inspected.target_replication {
                warnings.push(PostgresqlPasswordWarning::ReplicationRole);
            }
            if inspected.target_superuser {
                warnings.push(PostgresqlPasswordWarning::SuperuserRole);
            }
            if is_connection_role {
                warnings.push(PostgresqlPasswordWarning::ConnectionRole);
            }
            if !restorable {
                warnings.push(PostgresqlPasswordWarning::NotRestorable);
            }
            warnings
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "修改 PostgreSQL 账号 {} 的口令（{} 格式）。已经连上的会话不受影响，业务程序下次用旧口令连接会失败，请同步更新应用配置。{}",
                inspected.target_name,
                format.label(),
                if restorable {
                    "执行后可在限定时间内放回旧口令校验值。"
                } else {
                    "改后无法取回旧口令。"
                }
            ),
            true,
            if restorable {
                Some("放回该角色修改前的口令校验值".to_owned())
            } else {
                None
            },
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "database-password".to_owned());
        operation
            .metadata
            .insert("database-engine".to_owned(), "postgresql".to_owned());
        Ok(DatabasePasswordPlan {
            view: DatabasePasswordPlanView {
                role_name: inspected.target_name.clone(),
                is_connection_role,
                superuser: inspected.target_superuser,
                replication: inspected.target_replication,
                format,
                restorable,
                updates_saved_password: update_saved_password,
                warnings,
            },
            operation,
            profile_id,
            profile_digest: digest,
            snapshot: expected.clone(),
            role_oid: inspected.target_oid,
            role_name: inspected.target_name,
            is_connection_role,
            restorable,
            format,
            update_saved_password,
            new_password,
            created: Instant::now(),
        })
    }

    pub async fn execute_postgresql_password(
        &self,
        session: &BoundSshSession,
        plan: DatabasePasswordPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<DatabasePasswordExecution> {
        self.target.validate(session.target())?;
        if plan.created.elapsed() > PLAN_TTL {
            return Err(invalid("口令修改计划已过期，请重新修改"));
        }
        let (profile, digest) = self.profiles.resolve_with_digest(&plan.profile_id)?;
        if digest != plan.profile_digest {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before executing",
            ));
        }
        validate_profile_session(&profile, session)?;
        let request = NativeRuntimeRequest::new(
            profile.connection.clone(),
            profile.postgresql_tls.clone().unwrap_or_default(),
            profile.password(),
        )?;
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = PasswordChangeExecutor {
            service: self.clone(),
            session: session.clone(),
            profile_id: plan.profile_id.clone(),
            profile_digest: plan.profile_digest.clone(),
            snapshot: plan.snapshot.clone(),
            request,
            role_oid: plan.role_oid,
            role_name: plan.role_name.clone(),
            restorable: plan.restorable,
            format: plan.format,
            update_saved_password: plan.update_saved_password,
            new_password: SecretValue::new(plan.new_password.expose()),
            plan: plan.operation.clone(),
            captured: Mutex::new(None),
            outcome: Mutex::new(None),
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                let _ = operation.journal(journal);
            }
            return Err(error);
        }
        // The change may already be committed; reporting must not lose the
        // outcome or the restore token from here on.
        let journal_recorded = operation.journal(journal).is_ok();
        let skipped_saved = if plan.update_saved_password {
            SavedPasswordUpdate::SkippedVerificationNotPassed
        } else {
            SavedPasswordUpdate::NotRequested
        };
        let executor_parts = |executor: &PasswordChangeExecutor| {
            executor
                .outcome
                .lock()
                .expect("executor state")
                .take()
                .unwrap_or((
                    PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Other),
                    skipped_saved,
                ))
        };
        let (classification, saved_password) = if journal_recorded {
            match operation.verify(&self.target, &executor, journal).await {
                Ok(_) => executor_parts(&executor),
                Err(_) => (
                    PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Other),
                    skipped_saved,
                ),
            }
        } else {
            match operation.execution_receipt() {
                Ok(receipt) => match executor.verify(operation.definition(), receipt).await {
                    Ok(_) => executor_parts(&executor),
                    Err(_) => (
                        PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Other),
                        skipped_saved,
                    ),
                },
                Err(_) => (
                    PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Other),
                    skipped_saved,
                ),
            }
        };
        let saved_updated = saved_password == SavedPasswordUpdate::Updated;
        let restore_token = if plan.restorable {
            executor
                .captured
                .lock()
                .expect("executor state")
                .take()
                .map(|old_verifier| DatabasePasswordRestoreToken {
                    role_oid: plan.role_oid,
                    role_name: plan.role_name.clone(),
                    old_verifier,
                    profile_id: plan.profile_id.clone(),
                    target: session.target().clone(),
                    saved_password_updated: saved_updated,
                    // When the connection role's own password changed but the
                    // saved profile was not updated, only the new password can
                    // connect for the restore.
                    connect_password: (plan.is_connection_role && !saved_updated)
                        .then(|| SecretValue::new(plan.new_password.expose())),
                    previous_saved_password: saved_updated.then(|| profile.password()).flatten(),
                    created: Instant::now(),
                    claimed: AtomicBool::new(false),
                })
        } else {
            None
        };
        Ok(DatabasePasswordExecution {
            outcome: DatabasePasswordOutcome {
                operation_id: plan.operation.id.clone(),
                verification: classification,
                saved_password,
                restorable: plan.restorable,
                journal_recorded,
            },
            restore_token,
        })
    }

    /// Plans putting back the verifier captured during execution. The token
    /// is consumed by value: it expires after ten minutes and can only plan
    /// once.
    pub async fn plan_postgresql_password_restore(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        token: DatabasePasswordRestoreToken,
    ) -> CoreResult<DatabasePasswordRestorePlan> {
        self.target.validate(session.target())?;
        if token.claimed.swap(true, Ordering::SeqCst) {
            return Err(invalid("恢复令牌只能使用一次"));
        }
        if token.expired() {
            return Err(invalid("恢复令牌已过期"));
        }
        if token.target != *session.target() || token.profile_id != expected.view().config.id {
            return Err(invalid("恢复令牌不属于当前目标或连接配置"));
        }
        let profile_id = expected.view().config.id.clone();
        let (_profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before planning restore",
            ));
        }
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "将 PostgreSQL 账号 {} 的口令恢复为修改前保存的校验值。{}",
                token.role_name,
                if token.saved_password_updated {
                    "已保存的连接口令已改为新口令，回读复核通过后会自动改回修改前的已存口令。"
                } else {
                    ""
                }
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "database-password".to_owned());
        operation
            .metadata
            .insert("database-engine".to_owned(), "postgresql".to_owned());
        Ok(DatabasePasswordRestorePlan {
            view: DatabasePasswordRestorePlanView {
                role_name: token.role_name.clone(),
                saved_password_was_updated: token.saved_password_updated,
            },
            operation,
            profile_id,
            profile_digest: digest,
            snapshot: expected.clone(),
            role_oid: token.role_oid,
            role_name: token.role_name,
            old_verifier: token.old_verifier,
            connect_password: token.connect_password,
            previous_saved_password: token.previous_saved_password,
            saved_password_updated: token.saved_password_updated,
        })
    }

    /// Executes a reviewed restore. The write connection uses the currently
    /// saved profile credentials, re-resolved and re-checked against the
    /// digest captured when the restore was planned.
    pub async fn execute_postgresql_password_restore(
        &self,
        session: &BoundSshSession,
        plan: DatabasePasswordRestorePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<DatabasePasswordRestoreOutcome> {
        self.target.validate(session.target())?;
        let (profile, digest) = self.profiles.resolve_with_digest(&plan.profile_id)?;
        if digest != plan.profile_digest {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before executing restore",
            ));
        }
        validate_profile_session(&profile, session)?;
        let request = NativeRuntimeRequest::new(
            profile.connection.clone(),
            profile.postgresql_tls.clone().unwrap_or_default(),
            plan.connect_password
                .as_ref()
                .map(|password| SecretValue::new(password.expose()))
                .or_else(|| profile.password()),
        )?;
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = PasswordRestoreExecutor {
            service: self.clone(),
            session: session.clone(),
            profile_id: plan.profile_id.clone(),
            profile_digest: plan.profile_digest.clone(),
            request,
            role_oid: plan.role_oid,
            role_name: plan.role_name.clone(),
            old_verifier: plan.old_verifier.clone(),
            read_back: Mutex::new(None),
            plan: plan.operation.clone(),
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                let _ = operation.journal(journal);
            }
            return Err(error);
        }
        // The restore may already be committed; do not lose that fact.
        let journal_recorded = operation.journal(journal).is_ok();
        let verification = {
            let classify = |result: CoreResult<VerificationResult>| match result {
                Ok(result) if result.passed => PostgresqlRestoreVerification::Passed,
                Ok(result) if result.detail == "restore-verification:unverified" => {
                    PostgresqlRestoreVerification::Unverified
                }
                Ok(_) => PostgresqlRestoreVerification::Mismatch,
                Err(_) => PostgresqlRestoreVerification::Unverified,
            };
            if journal_recorded {
                classify(operation.verify(&self.target, &executor, journal).await)
            } else {
                match operation.execution_receipt() {
                    Ok(receipt) => classify(executor.verify(operation.definition(), receipt).await),
                    Err(_) => PostgresqlRestoreVerification::Unverified,
                }
            }
        };
        let saved_password = match (plan.saved_password_updated, verification) {
            (false, _) => SavedPasswordRestore::NotApplicable,
            (true, PostgresqlRestoreVerification::Passed) => {
                let change = match &plan.previous_saved_password {
                    Some(previous) => {
                        DatabaseSecretChange::Replace(SecretValue::new(previous.expose()))
                    }
                    None => DatabaseSecretChange::Remove,
                };
                match self.save_profile_if_unchanged(
                    plan.snapshot.view().config.clone(),
                    DatabaseProfileChanges { password: change },
                    Some(&plan.snapshot),
                ) {
                    Ok(_) => SavedPasswordRestore::Restored,
                    Err(CoreError::Validation { .. }) => SavedPasswordRestore::ProfileChanged,
                    Err(_) => SavedPasswordRestore::Failed,
                }
            }
            (true, _) => SavedPasswordRestore::SkippedVerificationNotPassed,
        };
        Ok(DatabasePasswordRestoreOutcome {
            operation_id: plan.operation.id,
            verification,
            saved_password,
            journal_recorded,
        })
    }

    /// Every step runs inside the SSH actor on its own channel while the
    /// target epoch and profile revision keep being re-checked.
    async fn password_step(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        profile_digest: &str,
        step: PostgresqlPasswordStep,
    ) -> CoreResult<PostgresqlPasswordResult> {
        self.target.validate(session.target())?;
        let pending = self.ssh.postgresql_password_step_bound(session, step);
        tokio::pin!(pending);
        let mut target_check = tokio::time::interval(Duration::from_millis(100));
        let result = loop {
            tokio::select! {
                result = &mut pending => break result,
                _ = target_check.tick() => {
                    self.target.validate(session.target())?;
                    self.profiles.ensure_snapshot(profile_id, profile_digest, "database password change")?;
                }
            }
        };
        self.target.validate(session.target())?;
        self.profiles
            .ensure_snapshot(profile_id, profile_digest, "database password change")?;
        result
    }

    /// Write steps are validated before dispatch and then run to completion
    /// inside the actor bound; aborting after COMMIT could strand an unknown
    /// remote state. A transport failure after dispatch reports that the
    /// password may already have changed, never "unchanged".
    async fn password_step_write(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        profile_digest: &str,
        step: PostgresqlPasswordStep,
    ) -> CoreResult<PostgresqlPasswordResult> {
        self.target.validate(session.target())?;
        self.profiles
            .ensure_snapshot(profile_id, profile_digest, "database password change")?;
        self.ssh
            .postgresql_password_step_bound(session, step)
            .await
            .map_err(write_step_error)
    }
}

/// A failed reply path on a write step means the remote state is unknown:
/// the step may have committed before the channel or actor failed.
pub const UNKNOWN_STATE_REASON: &str =
    "口令修改的执行结果未确认，数据库上的口令可能已经改变，请刷新核对";

fn write_step_error(error: CoreError) -> CoreError {
    match error {
        CoreError::Ssh { .. } | CoreError::OperationCancelled { .. } => {
            invalid(UNKNOWN_STATE_REASON)
        }
        other => other,
    }
}

/// Closed (code, Chinese detail) mapping for page-facing rejection of a core
/// password error; keeps `CoreError`'s English prefixes out of the UI.
pub fn public_reason(error: &CoreError) -> (&'static str, String) {
    let text = error.to_string();
    if text.contains(UNKNOWN_STATE_REASON) {
        return ("unknown-state", UNKNOWN_STATE_REASON.to_owned());
    }
    match error {
        CoreError::TargetChanged { .. } | CoreError::OperationCancelled { .. } => (
            "stale",
            "连接、配置或计划已变化或过期，请刷新后重试。".to_owned(),
        ),
        CoreError::Validation { message, .. } => {
            if message.contains("profile")
                || message.contains("connection")
                || message.contains("session")
                || message.contains("令牌")
            {
                (
                    "stale",
                    "连接、配置或计划已变化或过期，请刷新后重试。".to_owned(),
                )
            } else {
                ("rejected", text)
            }
        }
        _ => (
            "rejected",
            "数据库口令操作未能完成，请刷新核对后重试。".to_owned(),
        ),
    }
}
#[cfg(test)]
#[path = "database_password_lab.rs"]
mod lab;

#[cfg(test)]
#[path = "database_password_tests.rs"]
mod tests;
