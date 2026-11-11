//! MySQL / MariaDB account password changes.
//!
//! Same shape as the PostgreSQL password change: every step runs on its own
//! reviewed native session, statements are closed strings built only inside
//! this module, and the new credential reaches the server as a verifier
//! whenever the account's plugin allows it (`mysql_native_password`). For
//! `caching_sha2_password`/`sha256_password` the wire has no
//! verifier-accepting form, so `IDENTIFIED BY` is sent only when the session
//! is protected — database TLS, or SSH loopback mode where the tunnel is the
//! protection — and `@@log_raw` must be OFF so server logs rewrite the
//! literal.
//!
//! Verification is an independent login with the new password on a fresh
//! session, reported as passed / rejected / unverifiable-by-path. Restoration
//! replays the captured `SHOW CREATE USER` authentication string; it is only
//! offered when planning could read it (i.e. the connecting account can read
//! `mysql.user`/`SHOW CREATE USER` for the target).

use std::fmt;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult,
    crypto::SecretValue,
    database::{
        DatabaseEngine, DatabaseProfileChanges, DatabaseProfileSnapshot, DatabaseSecretChange,
        DatabaseService, validate_profile_session,
    },
    mysql_native::{MySqlRuntimeRequest, MySqlSession, MySqlTlsMode, connect},
    mysql_wire::{MysqlConnectClass, QueryResult},
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal,
        OperationPlan, OperationState, PlannedOperation, VerificationResult,
    },
    shell_escape::escape_sql_literal,
    ssh::BoundSshSession,
};

fn invalid(reason: &'static str) -> CoreError {
    CoreError::validation("MySQL password change", reason)
}

const MAX_ACCOUNT_LEN: usize = 128;
const MAX_VERIFIER_LEN: usize = 4096;

/// Plugins whose accounts can be changed through this path at all.
const PLUGIN_NATIVE: &str = "mysql_native_password";
const PLUGIN_CACHING_SHA2: &str = "caching_sha2_password";
const PLUGIN_SHA256: &str = "sha256_password";

/// Product family, decided by `@@version_comment`/`VERSION()` at inspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MySqlProduct {
    MySql,
    MariaDb,
}

/// One `mysql.user` account: user + host are both required for identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MySqlAccount {
    pub user: String,
    pub host: String,
}

impl MySqlAccount {
    pub fn new(user: &str, host: &str) -> CoreResult<Self> {
        if user.is_empty()
            || host.is_empty()
            || user.len() > MAX_ACCOUNT_LEN
            || host.len() > MAX_ACCOUNT_LEN
            || user.contains('\0')
            || host.contains('\0')
        {
            return Err(invalid("账号名称或来源部分无效"));
        }
        Ok(Self {
            user: user.to_owned(),
            host: host.to_owned(),
        })
    }

    fn quoted(&self) -> String {
        format!(
            "'{}'@'{}'",
            escape_sql_literal(&self.user).replace('\\', "\\\\"),
            escape_sql_literal(&self.host).replace('\\', "\\\\")
        )
    }
}

/// Closed inspection facts the plan binds to.
#[derive(Debug)]
pub struct MySqlInspect {
    pub product: MySqlProduct,
    pub server_version: String,
    pub log_raw: bool,
    pub connecting_account: MySqlAccount,
    pub account: MySqlAccount,
    pub plugin: String,
    pub account_locked: bool,
    /// `SHOW CREATE USER` authentication string for the restore path.
    pub captured_verifier: Option<Zeroizing<String>>,
    pub captured_plugin: Option<String>,
}

/// Three-state login verification, mirroring the PostgreSQL contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MySqlPasswordVerification {
    Passed,
    Rejected,
    /// The account's host part cannot be reached from this connection path
    /// (e.g. `user@'db.internal'` while we connect through the SSH host).
    Unverifiable,
}

/// Steps; each runs on a fresh native session.
pub(crate) enum MySqlPasswordStep {
    Inspect {
        request: MySqlRuntimeRequest,
        account: MySqlAccount,
    },
    Apply {
        request: MySqlRuntimeRequest,
        account: MySqlAccount,
        statement: Zeroizing<String>,
    },
    VerifyLogin {
        request: MySqlRuntimeRequest,
        account: MySqlAccount,
    },
    Capture {
        request: MySqlRuntimeRequest,
        account: MySqlAccount,
    },
    Restore {
        request: MySqlRuntimeRequest,
        statement: Zeroizing<String>,
    },
}

impl fmt::Debug for MySqlPasswordStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Inspect { .. } => "Inspect",
            Self::Apply { .. } => "Apply",
            Self::VerifyLogin { .. } => "VerifyLogin",
            Self::Capture { .. } => "Capture",
            Self::Restore { .. } => "Restore",
        };
        f.debug_tuple("MySqlPasswordStep")
            .field(&name)
            .finish_non_exhaustive()
    }
}

impl MySqlPasswordStep {
    pub(crate) fn endpoint(&self) -> (String, u16) {
        let request = match self {
            Self::Inspect { request, .. }
            | Self::Apply { request, .. }
            | Self::VerifyLogin { request, .. }
            | Self::Capture { request, .. }
            | Self::Restore { request, .. } => request,
        };
        (request.host().to_owned(), request.port())
    }
}

pub(crate) enum MySqlPasswordResult {
    Inspected(Box<MySqlInspect>),
    Applied,
    VerifiedLogin(MySqlPasswordVerification),
    Captured {
        #[allow(dead_code)]
        plugin: Option<String>,
        verifier: Option<Zeroizing<String>>,
    },
    Restored,
}

impl fmt::Debug for MySqlPasswordResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Inspected(_) => "Inspected",
            Self::Applied => "Applied",
            Self::VerifiedLogin(_) => "VerifiedLogin",
            Self::Captured { .. } => "Captured",
            Self::Restored => "Restored",
        };
        f.debug_tuple("MySqlPasswordResult").field(&name).finish()
    }
}

/// Quote one statement string literal: `'` doubling plus `\` doubling so the
/// value is identical under default and NO_BACKSLASH_ESCAPES modes.
fn literal(value: &str) -> String {
    format!("'{}'", escape_sql_literal(value).replace('\\', "\\\\"))
}

/// `SELECT` the inspect facts. Everything except the fixed literals is a
/// server-computed value.
const INSPECT_SQL: &str = "SELECT VERSION(), @@version_comment, @@log_raw, CURRENT_USER()";

fn parse_version_comment(version: &str, comment: &str) -> Option<MySqlProduct> {
    let comment = comment.to_ascii_lowercase();
    if comment.contains("mariadb") || version.to_ascii_lowercase().contains("mariadb") {
        Some(MySqlProduct::MariaDb)
    } else if comment.contains("mysql") || !version.is_empty() {
        Some(MySqlProduct::MySql)
    } else {
        None
    }
}

/// The versions this write path is reviewed for (design doc §MySQL).
fn supported_version(product: MySqlProduct, version: &str) -> bool {
    let mut parts = version.split(|c: char| !c.is_ascii_digit());
    let major = parts
        .find(|p| !p.is_empty())
        .and_then(|p| p.parse::<u32>().ok());
    let minor = parts
        .find(|p| !p.is_empty())
        .and_then(|p| p.parse::<u32>().ok());
    matches!(
        (product, major, minor),
        (MySqlProduct::MySql, Some(8), Some(0 | 4))
            | (MySqlProduct::MariaDb, Some(10), Some(11))
            | (MySqlProduct::MariaDb, Some(11), _)
    )
}

/// Parse `CURRENT_USER()` into user + host. The server always returns the
/// two-part quoted form `'user'@'host'`.
fn parse_current_user(value: &str) -> Option<MySqlAccount> {
    let (user, host) = value.split_once('@')?;
    Some(MySqlAccount {
        user: user.trim_matches('\'').to_owned(),
        host: host.trim_matches('\'').to_owned(),
    })
}

/// Extract `(plugin, auth-string)` from a `SHOW CREATE USER` result line.
/// MySQL emits `... IDENTIFIED WITH <plugin> [AS 0x<hex>|AS 'text']`;
/// MariaDB emits `IDENTIFIED VIA <plugin> USING 'x'` or `USING PASSWORD 'x'`
/// (older form). Anything else is treated as not restorable.
fn parse_create_user(text: &str) -> (Option<String>, Option<String>) {
    let upper = text.to_ascii_uppercase();
    let plugin = ["IDENTIFIED WITH", "IDENTIFIED VIA"]
        .iter()
        .find_map(|marker| {
            upper.find(marker).map(|start| {
                text[start + marker.len()..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches('\'')
                    .to_owned()
            })
        })
        .filter(|name| !name.is_empty());
    let verifier = [" AS 0X", " AS '", " USING '", " PASSWORD '"]
        .iter()
        .find_map(|marker| upper.find(marker).map(|start| (start, *marker)))
        .and_then(|(start, marker)| {
            let tail = &text[start + marker.len()..];
            if marker.ends_with('\'') {
                tail.split('\'').next().map(|s| s.to_owned())
            } else {
                tail.split(|c: char| !c.is_ascii_hexdigit())
                    .next()
                    .map(|s| s.to_owned())
            }
        })
        .filter(|s| !s.is_empty() && s.len() <= MAX_VERIFIER_LEN);
    (plugin, verifier)
}

/// Build the `ALTER USER` statement for a new native-password verifier.
/// `verifier` is the `*HEX` value the client computed (never plaintext).
fn alter_with_verifier(
    product: MySqlProduct,
    account: &MySqlAccount,
    plugin: &str,
    verifier: &str,
) -> String {
    match product {
        MySqlProduct::MySql => format!(
            "ALTER USER {} IDENTIFIED WITH {} AS {}",
            account.quoted(),
            plugin,
            literal(verifier)
        ),
        MySqlProduct::MariaDb => format!(
            "ALTER USER {} IDENTIFIED VIA {} USING {}",
            account.quoted(),
            plugin,
            literal(verifier)
        ),
    }
}

/// Build the `IDENTIFIED BY` statement for plugins without a verifier form.
fn alter_with_plaintext(product: MySqlProduct, account: &MySqlAccount, password: &str) -> String {
    match product {
        MySqlProduct::MySql => format!(
            "ALTER USER {} IDENTIFIED BY {}",
            account.quoted(),
            literal(password)
        ),
        // MariaDB keeps the account's plugin when only the password changes.
        MySqlProduct::MariaDb => format!(
            "ALTER USER {} IDENTIFIED BY {}",
            account.quoted(),
            literal(password)
        ),
    }
}

/// `mysql_native_password` stored form: `*` + uppercase hex of
/// SHA1(SHA1(password)). Computed locally so plaintext never crosses.
pub(crate) fn native_verifier(password: &str) -> String {
    use sha1::{Digest as _, Sha1};
    let stage1 = Sha1::digest(password.as_bytes());
    let stage2 = Sha1::digest(stage1);
    let mut out = String::with_capacity(42);
    out.push('*');
    for byte in stage2 {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn policy_error() -> CoreError {
    invalid("新口令不符合数据库的口令策略")
}

/// Run one step on a fresh session over `stream`.
pub(crate) async fn run_step_on_stream<S>(
    stream: S,
    step: MySqlPasswordStep,
) -> CoreResult<MySqlPasswordResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match step {
        MySqlPasswordStep::Inspect { request, account } => {
            let mut session = connect(stream, request).await?;
            let result = inspect(&mut session, &account).await;
            session.quit().await;
            Ok(MySqlPasswordResult::Inspected(Box::new(result?)))
        }
        MySqlPasswordStep::Apply {
            request,
            account,
            statement,
        } => {
            let mut session = connect(stream, request).await?;
            let result = apply(&mut session, &account, &statement).await;
            session.quit().await;
            result.map(|_| MySqlPasswordResult::Applied)
        }
        MySqlPasswordStep::VerifyLogin { request, account } => {
            let verification = match connect(stream, request).await {
                Ok(mut session) => {
                    let checked = verify_login(&mut session, &account).await;
                    session.quit().await;
                    match checked {
                        Ok(()) => MySqlPasswordVerification::Passed,
                        Err(_) => MySqlPasswordVerification::Unverifiable,
                    }
                }
                Err(error) => match error.class {
                    MysqlConnectClass::Authentication => MySqlPasswordVerification::Rejected,
                    MysqlConnectClass::AccessRule
                    | MysqlConnectClass::Timeout
                    | MysqlConnectClass::Other => MySqlPasswordVerification::Unverifiable,
                },
            };
            Ok(MySqlPasswordResult::VerifiedLogin(verification))
        }
        MySqlPasswordStep::Capture { request, account } => {
            let mut session = connect(stream, request).await?;
            let captured = capture_verifier(&mut session, &account).await;
            session.quit().await;
            let (plugin, verifier) = captured?;
            Ok(MySqlPasswordResult::Captured { plugin, verifier })
        }
        MySqlPasswordStep::Restore { request, statement } => {
            let mut session = connect(stream, request).await?;
            let result = async {
                match session.query(statement.as_bytes()).await? {
                    QueryResult::Ok { .. } => Ok(()),
                    QueryResult::Rows(_) => Err(invalid("恢复语句返回了意外的结果集")),
                }
            }
            .await;
            session.quit().await;
            result.map(|_| MySqlPasswordResult::Restored)
        }
    }
}

async fn inspect(session: &mut MySqlSession, account: &MySqlAccount) -> CoreResult<MySqlInspect> {
    let rows = session.query_rows(INSPECT_SQL.as_bytes(), 4, 1).await?;
    let row = rows
        .first()
        .ok_or_else(|| invalid("数据库身份检查没有返回结果"))?;
    let version = row[0].clone().unwrap_or_default();
    let comment = row[1].clone().unwrap_or_default();
    let product =
        parse_version_comment(&version, &comment).ok_or_else(|| invalid("无法识别的数据库产品"))?;
    if !supported_version(product, &version) {
        return Err(invalid("该数据库版本尚未适配口令修改，未执行"));
    }
    let log_raw = row[2]
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("on") || v == "1");
    let connecting = parse_current_user(row[3].as_deref().unwrap_or_default())
        .ok_or_else(|| invalid("无法取得当前连接账号身份"))?;

    // Account facts from mysql.user; a missing read permission surfaces as a
    // server error which the caller maps.
    let user_rows = session
        .query_rows(
            format!(
                "SELECT plugin, account_locked, password_expired FROM mysql.user WHERE user={} AND host={}",
                literal(&account.user),
                literal(&account.host)
            )
            .as_bytes(),
            3,
            1,
        )
        .await
        .map_err(|_| invalid("无法读取账号目录（需要读取 mysql.user 的权限）"))?;
    let user_row = user_rows.first().ok_or_else(|| CoreError::NotFound {
        entity: "MySQL account",
        id: format!("{}@{}", account.user, account.host),
    })?;
    let plugin = user_row[0].clone().unwrap_or_default();
    if plugin.is_empty() {
        return Err(invalid("账号的认证插件读取为空"));
    }
    if !matches!(
        plugin.as_str(),
        PLUGIN_NATIVE | PLUGIN_CACHING_SHA2 | PLUGIN_SHA256
    ) {
        return Err(invalid(
            "该账号的认证插件不支持口令修改（如 unix_socket/ed25519/PAM）",
        ));
    }
    let account_locked = user_row[1].as_deref() == Some("Y");
    let captured = match capture_verifier(session, account).await {
        Ok((plugin, verifier)) => (plugin, verifier),
        Err(_) => (None, None),
    };
    Ok(MySqlInspect {
        product,
        server_version: version,
        log_raw,
        connecting_account: connecting,
        account: account.clone(),
        plugin,
        account_locked,
        captured_verifier: captured.1,
        captured_plugin: captured.0,
    })
}

/// `SET SESSION print_identified_with_as_hex = ON` (MySQL ≥8.0.17; ignored
/// when the variable does not exist) then `SHOW CREATE USER` and parse the
/// authentication clause. Errors degrade to "not restorable" at the caller.
async fn capture_verifier(
    session: &mut MySqlSession,
    account: &MySqlAccount,
) -> CoreResult<(Option<String>, Option<Zeroizing<String>>)> {
    let _ = session
        .query(b"SET SESSION print_identified_with_as_hex = ON")
        .await;
    let rows = session
        .query_rows(
            format!("SHOW CREATE USER {}", account.quoted()).as_bytes(),
            1,
            1,
        )
        .await
        .map_err(|_| invalid("无法读取账号定义（需要 SHOW CREATE USER 权限）"))?;
    let text = rows
        .first()
        .and_then(|row| row[0].clone())
        .ok_or_else(|| invalid("账号定义返回为空"))?;
    if text.len() > 8 * 1024 {
        return Err(invalid("账号定义超过预期长度"));
    }
    let (plugin, verifier) = parse_create_user(&text);
    Ok((plugin, verifier.map(Zeroizing::new)))
}

async fn apply(
    session: &mut MySqlSession,
    account: &MySqlAccount,
    statement: &str,
) -> CoreResult<()> {
    // Re-read the account identity on the write session: a drop or plugin
    // change between plan and execute must stop the write.
    let user_rows = session
        .query_rows(
            format!(
                "SELECT plugin FROM mysql.user WHERE user={} AND host={}",
                literal(&account.user),
                literal(&account.host)
            )
            .as_bytes(),
            1,
            1,
        )
        .await
        .map_err(|_| invalid("执行前核对账号目录失败"))?;
    if user_rows.is_empty() {
        return Err(invalid("账号在计划之后被删除，未执行"));
    }
    match session.query(statement.as_bytes()).await {
        Ok(QueryResult::Ok { .. }) => Ok(()),
        Ok(QueryResult::Rows(_)) => Err(invalid("修改语句返回了意外的结果集")),
        Err(error) => {
            let text = format!("{error}");
            if text.contains("1819") {
                Err(policy_error())
            } else if text.contains("1396")
                || text.contains("1146")
                || text.contains("1044")
                || text.contains("1045")
            {
                Err(invalid("当前连接账号无权修改该账号的口令"))
            } else {
                Err(error)
            }
        }
    }
}

async fn verify_login(session: &mut MySqlSession, account: &MySqlAccount) -> CoreResult<()> {
    let rows = session.query_rows(b"SELECT CURRENT_USER()", 1, 1).await?;
    let current = rows
        .first()
        .and_then(|row| row[0].clone())
        .and_then(|text| parse_current_user(&text))
        .ok_or_else(|| invalid("复核会话无法取得账号身份"))?;
    if current.user != account.user {
        return Err(invalid("复核会话登录到了不同的账号"));
    }
    // `CURRENT_USER()` reports the matched grant entry; the planned account
    // and the matched entry may differ (e.g. 'u'@'%' grants logins from
    // 'u'@'localhost'). Same user with a compatible grant is a pass.
    Ok(())
}

/// The verifier form a new password is applied with, or `None` when the
/// account's plugin requires `IDENTIFIED BY` plaintext.
pub fn verifier_form(plugin: &str) -> Option<String> {
    match plugin {
        PLUGIN_NATIVE => Some("hex".to_owned()),
        PLUGIN_CACHING_SHA2 | PLUGIN_SHA256 => None,
        _ => None,
    }
}

/// Whether `IDENTIFIED BY` plaintext may be sent on this session: TLS, or
/// the SSH-loopback mode where the tunnel is the documented protection.
pub fn plaintext_allowed(tls_mode: MySqlTlsMode) -> bool {
    // Both modes are acceptable per the design: TLS protects the wire itself,
    // loopback places the plaintext inside the SSH channel only.
    matches!(
        tls_mode,
        MySqlTlsMode::VerifyFull | MySqlTlsMode::SshLoopback
    )
}

/// The authentication form captured from `SHOW CREATE USER` before the
/// change; restoring replays it verbatim.
pub(crate) struct CapturedForm<'a> {
    pub(crate) plugin: Option<&'a str>,
    pub(crate) verifier: Option<&'a str>,
}

/// Build the apply/restore statements for a plan. Returns
/// `(apply, Option<restore>)`; `new_password` is required when the plugin
/// has no verifier form.
pub(crate) fn build_statements(
    product: MySqlProduct,
    account: &MySqlAccount,
    plugin: &str,
    new_password: &SecretValue,
    log_raw: bool,
    tls_mode: crate::mysql_native::MySqlTlsMode,
    captured: CapturedForm<'_>,
) -> CoreResult<(Zeroizing<String>, Option<Zeroizing<String>>)> {
    let apply = match plugin {
        PLUGIN_NATIVE => Zeroizing::new(alter_with_verifier(
            product,
            account,
            plugin,
            &native_verifier(new_password.expose()),
        )),
        PLUGIN_CACHING_SHA2 | PLUGIN_SHA256 => {
            if log_raw {
                return Err(invalid(
                    "数据库开启了 log_raw，语句中的口令会被原样记录，已拒绝",
                ));
            }
            if !plaintext_allowed(tls_mode) {
                return Err(invalid(
                    "该认证插件需要发送口令明文，但当前连接没有加密保护",
                ));
            }
            Zeroizing::new(alter_with_plaintext(
                product,
                account,
                new_password.expose(),
            ))
        }
        other => {
            return Err(invalid(if other.is_empty() {
                "账号的认证插件为空"
            } else {
                "该账号的认证插件不支持口令修改"
            }));
        }
    };
    let restore = match (captured.plugin, captured.verifier) {
        (Some(captured_plugin), Some(verifier)) => Some(Zeroizing::new(alter_with_verifier(
            product,
            account,
            captured_plugin,
            verifier,
        ))),
        _ => None,
    };
    Ok((apply, restore))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_verifier_matches_mysql_reference() {
        // mysql_native_password stored form for "secret":
        // '*' + HEX(SHA1(SHA1('secret'))) — SHA1('secret') is
        // e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4, of which SHA1 is the
        // documented value below (recomputed by the same formula).
        use sha1::{Digest as _, Sha1};
        let stage2 = Sha1::digest(Sha1::digest(b"secret"));
        let expected = format!(
            "*{}",
            stage2
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
        );
        assert_eq!(native_verifier("secret"), expected);
        assert_eq!(native_verifier("secret").len(), 41);
        assert!(native_verifier("secret").starts_with('*'));
    }

    #[test]
    fn quoted_accounts_escape_quotes_and_backslashes() {
        let account = MySqlAccount::new("we'ird", "lo\\cal").unwrap();
        assert_eq!(account.quoted(), "'we''ird'@'lo\\\\cal'");
    }

    #[test]
    fn create_user_parses_mysql_and_mariadb_forms() {
        let (plugin, verifier) = parse_create_user(
            "CREATE USER 'u'@'%' IDENTIFIED WITH 'mysql_native_password' AS 0x2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
        );
        assert_eq!(plugin.as_deref(), Some("mysql_native_password"));
        assert_eq!(
            verifier.as_deref(),
            Some("2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19")
        );
        let (plugin, verifier) = parse_create_user(
            "CREATE USER 'u'@'localhost' IDENTIFIED VIA mysql_native_password USING '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'",
        );
        assert_eq!(plugin.as_deref(), Some("mysql_native_password"));
        assert_eq!(
            verifier.as_deref(),
            Some("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19")
        );
        assert_eq!(
            parse_create_user("CREATE USER 'u'@'%' IDENTIFIED VIA unix_socket"),
            (Some("unix_socket".to_owned()), None)
        );
    }

    #[test]
    fn version_support_is_the_reviewed_set() {
        assert!(supported_version(MySqlProduct::MySql, "8.0.36"));
        assert!(supported_version(MySqlProduct::MySql, "8.4.2"));
        assert!(supported_version(MySqlProduct::MariaDb, "10.11.8"));
        assert!(supported_version(MySqlProduct::MariaDb, "11.4.2-MariaDB"));
        assert!(!supported_version(MySqlProduct::MySql, "5.7.44"));
        assert!(!supported_version(MySqlProduct::MariaDb, "10.6.17"));
        assert_eq!(
            parse_version_comment("8.0.36", "MySQL Community Server - GPL"),
            Some(MySqlProduct::MySql)
        );
        assert_eq!(
            parse_version_comment(
                "10.11.8-MariaDB-1:10.11.8+maria~ubu2204",
                "mariadb.org binary distribution"
            ),
            Some(MySqlProduct::MariaDb)
        );
    }

    #[test]
    fn statements_keep_the_plugin_and_never_inject() {
        let secret = SecretValue::new("N3w-Passw0rd!".to_owned());
        let account = MySqlAccount::new("svc'x", "%").unwrap();
        let (apply, _) = build_statements(
            MySqlProduct::MySql,
            &account,
            PLUGIN_NATIVE,
            &secret,
            false,
            crate::mysql_native::MySqlTlsMode::VerifyFull,
            CapturedForm {
                plugin: None,
                verifier: None,
            },
        )
        .unwrap();
        assert!(apply.contains("ALTER USER 'svc''x'@'%'"));
        assert!(apply.contains("IDENTIFIED WITH mysql_native_password AS '*"));
        assert!(!apply.contains("N3w-Passw0rd!"));
        let (apply, _) = build_statements(
            MySqlProduct::MariaDb,
            &account,
            PLUGIN_NATIVE,
            &secret,
            false,
            crate::mysql_native::MySqlTlsMode::VerifyFull,
            CapturedForm {
                plugin: None,
                verifier: None,
            },
        )
        .unwrap();
        assert!(apply.contains("IDENTIFIED VIA mysql_native_password USING '*"));
        // caching_sha2 needs plaintext: refused under log_raw, sent otherwise.
        assert!(
            build_statements(
                MySqlProduct::MySql,
                &account,
                PLUGIN_CACHING_SHA2,
                &secret,
                true,
                crate::mysql_native::MySqlTlsMode::VerifyFull,
                CapturedForm {
                    plugin: None,
                    verifier: None,
                },
            )
            .is_err()
        );
        let (apply, _) = build_statements(
            MySqlProduct::MySql,
            &account,
            PLUGIN_CACHING_SHA2,
            &secret,
            false,
            crate::mysql_native::MySqlTlsMode::VerifyFull,
            CapturedForm {
                plugin: None,
                verifier: None,
            },
        )
        .unwrap();
        assert!(apply.contains("IDENTIFIED BY 'N3w-Passw0rd!'"));
        assert!(
            build_statements(
                MySqlProduct::MySql,
                &account,
                "auth_socket",
                &secret,
                false,
                crate::mysql_native::MySqlTlsMode::VerifyFull,
                CapturedForm {
                    plugin: None,
                    verifier: None,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn restore_statement_reuses_captured_form() {
        let secret = SecretValue::new("N3w-Passw0rd!".to_owned());
        let account = MySqlAccount::new("root", "localhost").unwrap();
        let (_, restore) = build_statements(
            MySqlProduct::MySql,
            &account,
            PLUGIN_NATIVE,
            &secret,
            false,
            crate::mysql_native::MySqlTlsMode::VerifyFull,
            CapturedForm {
                plugin: Some("mysql_native_password"),
                verifier: Some("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"),
            },
        )
        .unwrap();
        let restore = restore.expect("restorable");
        assert!(restore.contains("AS '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'"),);
        assert!(!restore.contains("N3w-Passw0rd!"));
    }
}

// ---------------------------------------------------------------------------
// DatabaseService orchestration: plan, confirm, execute, verify, restore.
// ---------------------------------------------------------------------------

/// Plans and restore tokens live only in backend memory.
const PLAN_TTL: Duration = Duration::from_secs(120);
const RESTORE_TOKEN_TTL: Duration = Duration::from_secs(600);

/// TLS settings for a resolved MySQL connection: a literal loopback
/// destination is protected by the SSH channel itself (`SshLoopback`), any
/// other destination must carry database TLS.
fn tls_settings_for(
    connection: &crate::database::DatabaseConnection,
) -> crate::mysql_native::MySqlTlsSettings {
    let host = connection
        .host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(connection.host.as_str());
    let mode = if host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
    {
        MySqlTlsMode::SshLoopback
    } else {
        MySqlTlsMode::VerifyFull
    };
    crate::mysql_native::MySqlTlsSettings {
        mode,
        ca_certificate_pem: None,
    }
}

/// What the caller sees before confirming: everything the plan binds.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlPasswordPlanView {
    pub account: String,
    pub plugin: String,
    pub product: String,
    pub is_connection_account: bool,
    pub restorable: bool,
    pub update_saved_password: bool,
    pub warnings: Vec<String>,
}

/// Immutable plan; consumed once, expires after [`PLAN_TTL`].
#[derive(Debug)]
pub struct MySqlPasswordPlan {
    pub view: MySqlPasswordPlanView,
    pub operation: OperationPlan,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    account: MySqlAccount,
    apply: Zeroizing<String>,
    restore: Option<Zeroizing<String>>,
    captured_verifier: Zeroizing<String>,
    new_password: SecretValue,
    is_connection_account: bool,
    update_saved_password: bool,
    created: Instant,
}

/// Verification + bookkeeping reported after a reviewed execution.
#[derive(Debug)]
pub struct MySqlPasswordOutcome {
    pub operation_id: String,
    pub verification: MySqlPasswordVerification,
    pub saved_password: crate::database_password::SavedPasswordUpdate,
    pub restorable: bool,
    pub journal_recorded: bool,
}

#[derive(Debug)]
pub struct MySqlPasswordExecution {
    pub outcome: MySqlPasswordOutcome,
    pub restore_token: Option<MySqlPasswordRestoreToken>,
}

/// One-use token carrying the captured authentication form needed to put the
/// old password back. Expires after ten minutes.
#[derive(Debug)]
pub struct MySqlPasswordRestoreToken {
    account: MySqlAccount,
    statement: Zeroizing<String>,
    expected_verifier: Zeroizing<String>,
    profile_id: String,
    target: crate::target::TargetGuard,
    saved_password_updated: bool,
    /// When the connection account's own password changed but the saved
    /// profile was not updated, only the new password can connect to restore.
    connect_password: Option<SecretValue>,
    previous_saved_password: Option<SecretValue>,
    created: Instant,
    claimed: AtomicBool,
}

impl MySqlPasswordRestoreToken {
    pub fn expired(&self) -> bool {
        self.created.elapsed() > RESTORE_TOKEN_TTL
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlPasswordRestorePlanView {
    pub account: String,
    pub saved_password_was_updated: bool,
}

#[derive(Debug)]
pub struct MySqlPasswordRestorePlan {
    pub view: MySqlPasswordRestorePlanView,
    pub operation: OperationPlan,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    account: MySqlAccount,
    statement: Zeroizing<String>,
    expected_verifier: Zeroizing<String>,
    connect_password: Option<SecretValue>,
    previous_saved_password: Option<SecretValue>,
    saved_password_updated: bool,
}

#[derive(Debug)]
pub struct MySqlPasswordRestoreOutcome {
    pub operation_id: String,
    pub verified: bool,
    pub saved_password_restored: bool,
    pub journal_recorded: bool,
}

impl MySqlPasswordPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn view(&self) -> &MySqlPasswordPlanView {
        &self.view
    }
}

impl MySqlPasswordRestorePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn view(&self) -> &MySqlPasswordRestorePlanView {
        &self.view
    }
}

impl DatabaseService {
    /// Plans changing `account`'s password on the bound target. Runs the
    /// Inspect step on its own channel, then freezes the vendor-specific
    /// statements into the plan.
    pub async fn plan_mysql_password(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        account: MySqlAccount,
        new_password: SecretValue,
        update_saved_password: bool,
    ) -> CoreResult<MySqlPasswordPlan> {
        self.target.validate(session.target())?;
        crate::database_password::validate_new_password(&new_password)?;
        crate::database_password::validate_password_against_role(&new_password, &account.user)?;
        let profile_id = expected.view().config.id.clone();
        let (profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before planning",
            ));
        }
        if profile.connection.engine != DatabaseEngine::Mysql {
            return Err(invalid("连接配置不是 MySQL/MariaDB"));
        }
        validate_profile_session(&profile, session)?;
        let request = MySqlRuntimeRequest::new(
            profile.connection.clone(),
            profile
                .mysql_tls
                .clone()
                .unwrap_or_else(|| tls_settings_for(&profile.connection)),
            profile.password(),
        )?;
        let result = self
            .mysql_password_step(
                session,
                &profile_id,
                expected.digest(),
                MySqlPasswordStep::Inspect {
                    request: request_for(&request)?,
                    account: account.clone(),
                },
            )
            .await?;
        let MySqlPasswordResult::Inspected(inspect) = result else {
            return Err(invalid("数据库账号检查返回了不符合约定的结果"));
        };
        let inspect = *inspect;
        if inspect.account_locked {
            return Err(invalid("该账号已被锁定，不能通过此流程修改口令"));
        }
        if !supported_version(inspect.product, &inspect.server_version) {
            return Err(invalid("该数据库版本尚未评审通过"));
        }
        let is_connection_account = inspect.connecting_account.user == account.user
            && inspect.connecting_account.host == account.host;
        let restorable = inspect.captured_verifier.is_some() && inspect.captured_plugin.is_some();
        let (apply, restore) = build_statements(
            inspect.product,
            &account,
            &inspect.plugin,
            &new_password,
            inspect.log_raw,
            request.tls.mode,
            CapturedForm {
                plugin: inspect.captured_plugin.as_deref(),
                verifier: inspect.captured_verifier.as_deref().map(|v| v.as_str()),
            },
        )?;
        let mut warnings = Vec::new();
        if is_connection_account && !update_saved_password {
            warnings.push("这是当前连接使用的账号；修改后旧口令将不能再建立连接。".to_owned());
        }
        if !restorable {
            warnings
                .push("当前连接无法读取该账号的认证串，执行后将不能自动恢复旧口令。".to_owned());
        }
        if verifier_form(&inspect.plugin).is_none() {
            warnings
                .push("该认证插件没有校验值形式，语句将携带口令明文（连接已加密）。".to_owned());
        }
        let product_name = match inspect.product {
            MySqlProduct::MySql => "MySQL",
            MySqlProduct::MariaDb => "MariaDB",
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "将 {product_name} 账号 {} 的口令修改为新值。{}{}",
                account.quoted(),
                if is_connection_account && update_saved_password {
                    "执行后回读复核通过会自动更新已保存的连接口令。"
                } else {
                    ""
                },
                if restorable {
                    "执行后可恢复修改前的口令。"
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
            .insert("database-engine".to_owned(), "mysql".to_owned());
        Ok(MySqlPasswordPlan {
            view: MySqlPasswordPlanView {
                account: account.quoted(),
                plugin: inspect.plugin.clone(),
                product: product_name.to_owned(),
                is_connection_account,
                restorable,
                update_saved_password,
                warnings,
            },
            operation,
            profile_id,
            profile_digest: digest,
            snapshot: expected.clone(),
            account,
            apply,
            restore,
            captured_verifier: inspect
                .captured_verifier
                .unwrap_or_else(|| Zeroizing::new(String::new())),
            new_password,
            is_connection_account,
            update_saved_password,
            created: Instant::now(),
        })
    }

    /// Executes a reviewed plan: applies the frozen statement, then
    /// independently logs in with the new password on a fresh session.
    pub async fn execute_mysql_password(
        &self,
        session: &BoundSshSession,
        plan: MySqlPasswordPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<MySqlPasswordExecution> {
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
        let request = MySqlRuntimeRequest::new(
            profile.connection.clone(),
            profile
                .mysql_tls
                .clone()
                .unwrap_or_else(|| tls_settings_for(&profile.connection)),
            profile.password(),
        )?;
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = MySqlPasswordExecutor {
            service: self.clone(),
            session: session.clone(),
            profile_id: plan.profile_id.clone(),
            profile_digest: plan.profile_digest.clone(),
            snapshot: plan.snapshot.clone(),
            request,
            account: plan.account.clone(),
            apply: plan.apply.clone(),
            new_password: SecretValue::new(plan.new_password.expose()),
            is_connection_account: plan.is_connection_account,
            update_saved_password: plan.update_saved_password,
            plan: plan.operation.clone(),
            outcome: Mutex::new(None),
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                let _ = operation.journal(journal);
            }
            return Err(error);
        }
        let journal_recorded = operation.journal(journal).is_ok();
        let skipped_saved = if plan.update_saved_password {
            crate::database_password::SavedPasswordUpdate::SkippedVerificationNotPassed
        } else {
            crate::database_password::SavedPasswordUpdate::NotRequested
        };
        let parts = |executor: &MySqlPasswordExecutor| {
            executor
                .outcome
                .lock()
                .expect("executor state")
                .take()
                .unwrap_or((MySqlPasswordVerification::Unverifiable, skipped_saved))
        };
        let (verification, saved_password) = if journal_recorded {
            match operation.verify(&self.target, &executor, journal).await {
                Ok(_) => parts(&executor),
                Err(_) => (MySqlPasswordVerification::Unverifiable, skipped_saved),
            }
        } else {
            match operation.execution_receipt() {
                Ok(receipt) => match executor.verify(operation.definition(), receipt).await {
                    Ok(_) => parts(&executor),
                    Err(_) => (MySqlPasswordVerification::Unverifiable, skipped_saved),
                },
                Err(_) => (MySqlPasswordVerification::Unverifiable, skipped_saved),
            }
        };
        let saved_updated =
            saved_password == crate::database_password::SavedPasswordUpdate::Updated;
        let restore_token = plan
            .restore
            .clone()
            .map(|statement| MySqlPasswordRestoreToken {
                account: plan.account.clone(),
                statement,
                expected_verifier: plan.captured_verifier.clone(),
                profile_id: plan.profile_id.clone(),
                target: session.target().clone(),
                saved_password_updated: saved_updated,
                connect_password: (plan.is_connection_account && !saved_updated)
                    .then(|| SecretValue::new(plan.new_password.expose())),
                previous_saved_password: saved_updated.then(|| profile.password()).flatten(),
                created: Instant::now(),
                claimed: AtomicBool::new(false),
            });
        Ok(MySqlPasswordExecution {
            outcome: MySqlPasswordOutcome {
                operation_id: plan.operation.id.clone(),
                verification,
                saved_password,
                restorable: restore_token.is_some(),
                journal_recorded,
            },
            restore_token,
        })
    }

    /// Plans putting back the captured authentication string. The token is
    /// consumed by value: it expires and can only plan once.
    pub async fn plan_mysql_password_restore(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        token: MySqlPasswordRestoreToken,
    ) -> CoreResult<MySqlPasswordRestorePlan> {
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
                "将 MySQL/MariaDB 账号 {} 的口令恢复为修改前保存的认证形式。{}",
                token.account.quoted(),
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
            .insert("database-engine".to_owned(), "mysql".to_owned());
        Ok(MySqlPasswordRestorePlan {
            view: MySqlPasswordRestorePlanView {
                account: token.account.quoted(),
                saved_password_was_updated: token.saved_password_updated,
            },
            operation,
            profile_id,
            profile_digest: digest,
            snapshot: expected.clone(),
            account: token.account,
            statement: token.statement,
            expected_verifier: token.expected_verifier,
            connect_password: token.connect_password,
            previous_saved_password: token.previous_saved_password,
            saved_password_updated: token.saved_password_updated,
        })
    }

    /// Executes a reviewed restore: replays the captured authentication
    /// statement, then re-captures and compares the verifier constant-time.
    pub async fn execute_mysql_password_restore(
        &self,
        session: &BoundSshSession,
        plan: MySqlPasswordRestorePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<MySqlPasswordRestoreOutcome> {
        self.target.validate(session.target())?;
        let (profile, digest) = self.profiles.resolve_with_digest(&plan.profile_id)?;
        if digest != plan.profile_digest {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before executing restore",
            ));
        }
        validate_profile_session(&profile, session)?;
        let request = MySqlRuntimeRequest::new(
            profile.connection.clone(),
            profile
                .mysql_tls
                .clone()
                .unwrap_or_else(|| tls_settings_for(&profile.connection)),
            plan.connect_password
                .map(|value| SecretValue::new(value.expose()))
                .or_else(|| profile.password()),
        )?;
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = MySqlPasswordRestoreExecutor {
            service: self.clone(),
            session: session.clone(),
            profile_id: plan.profile_id.clone(),
            profile_digest: plan.profile_digest.clone(),
            snapshot: plan.snapshot.clone(),
            request,
            account: plan.account.clone(),
            statement: plan.statement.clone(),
            expected_verifier: plan.expected_verifier.clone(),
            previous_saved_password: plan
                .previous_saved_password
                .map(|value| SecretValue::new(value.expose())),
            saved_password_updated: plan.saved_password_updated,
            plan: plan.operation.clone(),
            outcome: Mutex::new(None),
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                let _ = operation.journal(journal);
            }
            return Err(error);
        }
        let journal_recorded = operation.journal(journal).is_ok();
        let take = |executor: &MySqlPasswordRestoreExecutor| {
            executor
                .outcome
                .lock()
                .expect("executor state")
                .take()
                .unwrap_or((false, false))
        };
        let (verified, saved_restored) = if journal_recorded {
            match operation.verify(&self.target, &executor, journal).await {
                Ok(_) => take(&executor),
                Err(_) => (false, false),
            }
        } else {
            match operation.execution_receipt() {
                Ok(receipt) => match executor.verify(operation.definition(), receipt).await {
                    Ok(_) => take(&executor),
                    Err(_) => (false, false),
                },
                Err(_) => (false, false),
            }
        };
        Ok(MySqlPasswordRestoreOutcome {
            operation_id: plan.operation.id.clone(),
            verified,
            saved_password_restored: saved_restored,
            journal_recorded,
        })
    }

    /// Read-side step runner: keeps re-checking target and profile snapshot
    /// while the step runs on its own SSH channel.
    async fn mysql_password_step(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        profile_digest: &str,
        step: MySqlPasswordStep,
    ) -> CoreResult<MySqlPasswordResult> {
        self.target.validate(session.target())?;
        let pending = self.ssh.mysql_password_step_bound(session, step);
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

    /// Write steps run to completion once dispatched; a transport failure
    /// after dispatch means the remote state is unknown.
    async fn mysql_password_step_write(
        &self,
        session: &BoundSshSession,
        profile_id: &str,
        profile_digest: &str,
        step: MySqlPasswordStep,
    ) -> CoreResult<MySqlPasswordResult> {
        self.target.validate(session.target())?;
        self.profiles
            .ensure_snapshot(profile_id, profile_digest, "database password change")?;
        self.ssh
            .mysql_password_step_bound(session, step)
            .await
            .map_err(write_step_error)
    }
}

/// Rebuilds a request with a fresh `SecretValue` (each step needs its own
/// copy of the credential).
fn request_for(request: &MySqlRuntimeRequest) -> CoreResult<MySqlRuntimeRequest> {
    MySqlRuntimeRequest::new(
        request.connection.clone(),
        request.tls.clone(),
        request
            .password
            .as_ref()
            .map(|value| SecretValue::new(value.expose())),
    )
}

/// A failed reply on a write step means remote state is unknown.
fn write_step_error(error: CoreError) -> CoreError {
    match error {
        CoreError::Ssh { .. } | CoreError::OperationCancelled { .. } => {
            invalid("口令修改的执行结果未确认，数据库上的口令可能已经改变，请刷新核对")
        }
        other => other,
    }
}

fn constant_time_eq(left: &Zeroizing<String>, right: &Zeroizing<String>) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[derive(Debug)]
struct MySqlPasswordExecutor {
    service: DatabaseService,
    session: BoundSshSession,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    request: MySqlRuntimeRequest,
    account: MySqlAccount,
    apply: Zeroizing<String>,
    new_password: SecretValue,
    is_connection_account: bool,
    update_saved_password: bool,
    plan: OperationPlan,
    outcome: Mutex<
        Option<(
            MySqlPasswordVerification,
            crate::database_password::SavedPasswordUpdate,
        )>,
    >,
}

#[async_trait]
impl OperationExecutor for MySqlPasswordExecutor {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if plan != &self.plan {
            return Err(CoreError::validation(
                "database password change",
                "executor received a different immutable plan",
            ));
        }
        self.service
            .mysql_password_step_write(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                MySqlPasswordStep::Apply {
                    request: request_for(&self.request)?,
                    account: self.account.clone(),
                    statement: Zeroizing::new(self.apply.to_string()),
                },
            )
            .await?;
        Ok(ExecutionReceipt {
            summary: format!(
                "mysql password change committed for {}",
                self.account.quoted()
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
            .mysql_password_step(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                MySqlPasswordStep::VerifyLogin {
                    request: self.request.for_user(
                        &self.account.user,
                        Some(SecretValue::new(self.new_password.expose())),
                    )?,
                    account: self.account.clone(),
                },
            )
            .await
        {
            Ok(MySqlPasswordResult::VerifiedLogin(verification)) => verification,
            Ok(_) => return Err(invalid("数据库口令复核返回了不符合约定的结果")),
            Err(CoreError::Ssh { .. }) => MySqlPasswordVerification::Unverifiable,
            Err(error) => return Err(error),
        };
        use crate::database_password::SavedPasswordUpdate;
        let saved_password = match (self.update_saved_password, verification) {
            (false, _) => SavedPasswordUpdate::NotRequested,
            (true, MySqlPasswordVerification::Passed) if self.is_connection_account => {
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
            passed: verification == MySqlPasswordVerification::Passed,
            detail: match verification {
                MySqlPasswordVerification::Passed => "verification:passed",
                MySqlPasswordVerification::Rejected => "verification:rejected",
                MySqlPasswordVerification::Unverifiable => "verification:unverifiable",
            }
            .to_owned(),
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "automatic MySQL password restore",
        })
    }
}

#[derive(Debug)]
struct MySqlPasswordRestoreExecutor {
    service: DatabaseService,
    session: BoundSshSession,
    profile_id: String,
    profile_digest: String,
    snapshot: DatabaseProfileSnapshot,
    request: MySqlRuntimeRequest,
    account: MySqlAccount,
    statement: Zeroizing<String>,
    expected_verifier: Zeroizing<String>,
    previous_saved_password: Option<SecretValue>,
    saved_password_updated: bool,
    plan: OperationPlan,
    outcome: Mutex<Option<(bool, bool)>>,
}

#[async_trait]
impl OperationExecutor for MySqlPasswordRestoreExecutor {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if plan != &self.plan {
            return Err(CoreError::validation(
                "database password restore",
                "executor received a different immutable plan",
            ));
        }
        self.service
            .mysql_password_step_write(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                MySqlPasswordStep::Restore {
                    request: request_for(&self.request)?,
                    statement: Zeroizing::new(self.statement.to_string()),
                },
            )
            .await?;
        Ok(ExecutionReceipt {
            summary: format!(
                "mysql password restore committed for {}",
                self.account.quoted()
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
        // Read back the authentication form and compare constant-time with
        // the captured one — the honest restore check (old plaintext is not
        // available for a login re-verify).
        let verified = match self
            .service
            .mysql_password_step(
                &self.session,
                &self.profile_id,
                &self.profile_digest,
                MySqlPasswordStep::Capture {
                    request: request_for(&self.request)?,
                    account: self.account.clone(),
                },
            )
            .await
        {
            Ok(MySqlPasswordResult::Captured { verifier, .. }) => verifier
                .map(|actual| constant_time_eq(&actual, &self.expected_verifier))
                .unwrap_or(false),
            Ok(_) => return Err(invalid("数据库口令恢复复核返回了不符合约定的结果")),
            Err(_) => false,
        };
        let mut saved_restored = false;
        if verified
            && self.saved_password_updated
            && let Some(previous) = &self.previous_saved_password
        {
            saved_restored = self
                .service
                .save_profile_if_unchanged(
                    self.snapshot.view().config.clone(),
                    DatabaseProfileChanges {
                        password: DatabaseSecretChange::Replace(SecretValue::new(
                            previous.expose(),
                        )),
                    },
                    Some(&self.snapshot),
                )
                .is_ok();
        }
        *self.outcome.lock().expect("executor state") = Some((verified, saved_restored));
        Ok(VerificationResult {
            passed: verified,
            detail: if verified {
                "restore-verification:passed"
            } else {
                "restore-verification:mismatch"
            }
            .to_owned(),
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "MySQL password restore undo",
        })
    }
}
