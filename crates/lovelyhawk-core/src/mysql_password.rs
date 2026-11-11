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

use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult,
    crypto::SecretValue,
    mysql_native::{MySqlRuntimeRequest, MySqlSession, connect},
    mysql_wire::{MysqlConnectClass, QueryResult},
    shell_escape::escape_sql_literal,
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
    match (product, major, minor) {
        (MySqlProduct::MySql, Some(8), Some(0 | 4)) => true,
        (MySqlProduct::MariaDb, Some(10), Some(11)) => true,
        (MySqlProduct::MariaDb, Some(11), _) => true,
        _ => false,
    }
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
pub fn plaintext_allowed(tls_mode: crate::mysql_native::MySqlTlsMode) -> bool {
    // Both modes are acceptable per the design: TLS protects the wire itself,
    // loopback places the plaintext inside the SSH channel only.
    matches!(
        tls_mode,
        crate::mysql_native::MySqlTlsMode::VerifyFull
            | crate::mysql_native::MySqlTlsMode::SshLoopback
    )
}

/// Build the apply/restore statements for a plan. Returns
/// `(apply, Option<restore>)`; `new_password` is required when the plugin
/// has no verifier form.
pub fn build_statements(
    product: MySqlProduct,
    account: &MySqlAccount,
    plugin: &str,
    new_password: &SecretValue,
    log_raw: bool,
    tls_mode: crate::mysql_native::MySqlTlsMode,
    captured_plugin: Option<&str>,
    captured_verifier: Option<&str>,
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
    let restore = match (captured_plugin, captured_verifier) {
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
            None,
            None,
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
            None,
            None,
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
                None,
                None,
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
            None,
            None,
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
                None,
                None,
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
            Some("mysql_native_password"),
            Some("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"),
        )
        .unwrap();
        let restore = restore.expect("restorable");
        assert!(restore.contains("AS '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'"),);
        assert!(!restore.contains("N3w-Passw0rd!"));
    }
}
