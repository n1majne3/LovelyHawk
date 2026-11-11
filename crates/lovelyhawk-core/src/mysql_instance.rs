//! MySQL / MariaDB live instance review — read-only checks over the native
//! session plus a bounded `general_log` tail read over a separate SSH exec
//! channel. Everything collected is evidence for a human review: findings are
//! graded clues, never a claim of compromise, and every unreadable section is
//! recorded as a gap rather than reported clean.
//!
//! Scope (roadmap "数据库应急"): anonymous accounts, remotely reachable root,
//! empty credentials, non-root FILE/GRANT/SUPER privilege (the INTO OUTFILE
//! webshell precondition), `mysql.func` UDF registrations, `general_log`
//! pointed at a web root, `local_infile`, unrestricted `secure_file_priv`,
//! and a bounded general-log tail for Access-denied bursts and
//! OUTFILE/DUMPFILE/DDL account writes.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use crate::{
    CoreError, CoreResult,
    database::{
        DatabaseEngine, DatabaseProfileSnapshot, DatabaseService, validate_profile_session,
    },
    mysql_native::{MySqlRuntimeRequest, MySqlSession},
    mysql_password::{
        MySqlAccount, MySqlPasswordResult, MySqlPasswordStep, MySqlProduct, parse_current_user,
        parse_version_comment, request_for, supported_version, tls_settings_for,
    },
    ssh::{BoundSshSession, SshCommandOutput},
};

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::validation("MySQL instance review", reason)
}

const IDENTITY_SQL: &str = "SELECT VERSION(), @@version_comment, CURRENT_USER()";
const ACCOUNTS_MYSQL: &str = "SELECT user, host, plugin, authentication_string, Super_priv, \
     File_priv, Grant_priv, account_locked FROM mysql.user";
const ACCOUNTS_MARIADB: &str = "SELECT user, host, plugin, authentication_string, Super_priv, \
     File_priv, Grant_priv FROM mysql.user";
const UDF_SQL: &str = "SELECT name, dl FROM mysql.func";
const VARIABLES_SQL: &str = "SHOW GLOBAL VARIABLES WHERE Variable_name IN (\
     'general_log','general_log_file','log_output','local_infile',\
     'secure_file_priv','datadir','skip_networking','bind_address',\
     'sql_mode','version_compile_machine')";

const MAX_ACCOUNTS: usize = 512;
const MAX_UDFS: usize = 64;
const MAX_VARIABLES: usize = 48;
/// Bytes tailed from general_log; larger tails are truncated at the file end.
const LOG_TAIL_BYTES: u64 = 256 * 1024;
const MAX_LOG_HITS: usize = 40;
const MAX_DENIED_SOURCES: usize = 8;
/// One failed-auth source above this count in the tail window is a brute-force
/// clue worth surfacing.
const DENIED_BURST_THRESHOLD: u64 = 10;
const MAX_EXCERPT_CHARS: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MySqlInstanceLevel {
    /// 参考信息，未见异常。
    Info,
    /// 需人工核对的线索。
    Review,
    /// 高风险发现（可写马通道、空口令、远程 root、UDF 注册）。
    High,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlInstanceFinding {
    pub level: MySqlInstanceLevel,
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlAccountRow {
    pub user: String,
    pub host: String,
    pub plugin: String,
    pub empty_secret: bool,
    pub superuser: bool,
    pub file_priv: bool,
    pub grant_priv: bool,
    /// `None` on MariaDB (lock state lives in global_priv JSON; not read here).
    pub locked: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlUdfRow {
    pub name: String,
    pub library: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlDeniedSource {
    pub user: String,
    pub host: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlLogHit {
    pub kind: &'static str,
    pub excerpt: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlLogTrace {
    pub path: String,
    pub tail_bytes: usize,
    pub denied: Vec<MySqlDeniedSource>,
    pub hits: Vec<MySqlLogHit>,
}

fn serialize_product<S: serde::Serializer>(
    product: &MySqlProduct,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(match product {
        MySqlProduct::MySql => "MySQL",
        MySqlProduct::MariaDb => "MariaDB",
    })
}

fn serialize_account<S: serde::Serializer>(
    account: &MySqlAccount,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("'{}'@'{}'", account.user, account.host))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MySqlInstanceReview {
    #[serde(serialize_with = "serialize_product")]
    pub product: MySqlProduct,
    pub server_version: String,
    #[serde(serialize_with = "serialize_account")]
    pub connecting: MySqlAccount,
    pub accounts: Vec<MySqlAccountRow>,
    pub account_total: usize,
    pub udfs: Vec<MySqlUdfRow>,
    pub udf_total: usize,
    pub variables: BTreeMap<String, String>,
    pub findings: Vec<MySqlInstanceFinding>,
    /// Sections that could not be read, with the reason — visible instead of
    /// an implied "clean".
    pub gaps: Vec<String>,
    pub log: Option<MySqlLogTrace>,
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn cell(row: &[Option<String>], index: usize) -> String {
    row.get(index)
        .and_then(|c| c.as_deref())
        .map(clean)
        .unwrap_or_default()
}

fn excerpt(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if out.chars().count() >= MAX_EXCERPT_CHARS {
            out.push('…');
            break;
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}

/// True when an absolute path lands inside a well-known web root — the
/// general-log-as-webshell precondition.
fn path_in_web_root(path: &str) -> bool {
    const ROOTS: &[&str] = &[
        "/var/www/",
        "/srv/www/",
        "/srv/http",
        "/usr/share/nginx/",
        "/usr/local/apache",
        "/usr/local/openresty/",
        "/www/",
        "/opt/lampp/htdocs/",
    ];
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    if ROOTS.iter().any(|root| lower.starts_with(root)) {
        return true;
    }
    lower.contains("/public_html/") || lower.contains("/webapps/") || lower.contains("/htdocs/")
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['\'', '`']);
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.starts_with("127.")
}

fn account_findings(row: &MySqlAccountRow, out: &mut Vec<MySqlInstanceFinding>) {
    let name = if row.user.is_empty() {
        "匿名账号".to_owned()
    } else {
        format!("'{}'@'{}'", row.user, row.host)
    };
    if row.user.is_empty() {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::High,
            code: "anonymous-account",
            detail: format!("存在匿名账号 {name}，任何用户名都可能以它登录。"),
        });
        return;
    }
    if row.user.eq_ignore_ascii_case("root") && !is_loopback_host(&row.host) {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::High,
            code: "root-remote",
            detail: format!(
                "root 可从 {host} 登录，远程弱口令与爆破都会直接命中超级用户。",
                host = row.host
            ),
        });
    }
    if row.empty_secret {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::High,
            code: "empty-password",
            detail: format!("账号 {name} 的认证串为空（空口令或插件免密），需人工核对。"),
        });
    }
    if row.file_priv && !row.user.eq_ignore_ascii_case("root") {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::High,
            code: "file-priv",
            detail: format!("非 root 账号 {name} 持有 FILE 权限，满足 INTO OUTFILE 写文件的前提。"),
        });
    }
    if row.grant_priv && !row.user.eq_ignore_ascii_case("root") {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::Review,
            code: "grant-priv",
            detail: format!("非 root 账号 {name} 持有 GRANT OPTION，可自行放大权限。"),
        });
    }
    if row.superuser && !row.user.eq_ignore_ascii_case("root") {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::Review,
            code: "super-priv",
            detail: format!("非 root 账号 {name} 持有 SUPER 权限（mysqladmin 权限级别）。"),
        });
    }
}

fn variable_findings(variables: &BTreeMap<String, String>, out: &mut Vec<MySqlInstanceFinding>) {
    let get = |key: &str| variables.get(key).map(String::as_str).unwrap_or("");
    let general_log_on = get("general_log").eq_ignore_ascii_case("ON");
    let log_output = get("log_output").to_ascii_uppercase();
    let log_file = get("general_log_file");
    if general_log_on {
        if !log_file.is_empty() && path_in_web_root(log_file) {
            out.push(MySqlInstanceFinding {
                level: MySqlInstanceLevel::High,
                code: "general-log-web-root",
                detail: format!(
                    "general_log 已开启且日志文件 {log_file} 位于 Web 目录内，攻击者可经日志写入 Webshell。"
                ),
            });
        } else {
            out.push(MySqlInstanceFinding {
                level: MySqlInstanceLevel::Info,
                code: "general-log-on",
                detail: format!("general_log 已开启，输出位置 {log_file}。"),
            });
        }
    }
    if !log_output.is_empty() && !log_output.contains("FILE") && general_log_on {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::Info,
            code: "general-log-not-file",
            detail: "general_log 输出到表而非文件，日志溯源只能查 general_log 表。".to_owned(),
        });
    }
    if get("local_infile").eq_ignore_ascii_case("ON") {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::Review,
            code: "local-infile",
            detail: "local_infile 已开启，客户端可读取其本机文件（含社工读敏感文件风险）。"
                .to_owned(),
        });
    }
    if get("secure_file_priv").is_empty() {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::Review,
            code: "secure-file-priv-empty",
            detail: "secure_file_priv 未限制导出目录，FILE 权限账号可向任意可写路径导出。"
                .to_owned(),
        });
    }
}

fn udf_findings(udfs: &[MySqlUdfRow], out: &mut Vec<MySqlInstanceFinding>) {
    for udf in udfs {
        let interesting = ["sys_", "exec_", "do_system", "lib_mysqludf", "cmdshell"]
            .iter()
            .any(|mark| udf.name.to_ascii_lowercase().contains(mark));
        out.push(MySqlInstanceFinding {
            level: if interesting {
                MySqlInstanceLevel::High
            } else {
                MySqlInstanceLevel::Review
            },
            code: "udf-registered",
            detail: format!(
                "mysql.func 注册了 UDF {}({})，外部库函数可执行系统命令，需人工核对来源。",
                udf.name, udf.library
            ),
        });
    }
}

/// Parse a bounded general_log tail: count `Access denied` per user@host and
/// flag statements that write files or change accounts.
pub(crate) fn analyze_log_tail(path: &str, tail: &[u8]) -> MySqlLogTrace {
    let text = String::from_utf8_lossy(tail);
    let mut denied: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut hits = Vec::new();
    const KINDS: &[(&str, &str)] = &[
        ("outfile", "INTO OUTFILE"),
        ("outfile", "INTO DUMPFILE"),
        ("load-file", "LOAD_FILE"),
        ("udf-ddl", "CREATE FUNCTION"),
        ("udf-ddl", "CREATE AGGREGATE FUNCTION"),
        ("plugin-ddl", "INSTALL PLUGIN"),
        ("account-ddl", "CREATE USER"),
        ("account-ddl", "ALTER USER"),
        ("account-ddl", "DROP USER"),
        ("account-ddl", "SET PASSWORD"),
        ("grant-ddl", "GRANT "),
        ("table-drop", "DROP TABLE"),
    ];
    for line in text.lines() {
        if let Some(at) = line.find("Access denied for user") {
            let rest = &line[at + "Access denied for user".len()..];
            let user = rest
                .trim_start_matches(['\'', ' '])
                .split('\'')
                .next()
                .unwrap_or("")
                .to_owned();
            let host = rest
                .split("'@'")
                .nth(1)
                .and_then(|tail| tail.trim_start_matches('\'').split('\'').next())
                .unwrap_or("")
                .to_owned();
            *denied.entry((user, host)).or_default() += 1;
            continue;
        }
        let upper = line.to_ascii_uppercase();
        for (kind, marker) in KINDS {
            if upper.contains(marker) && hits.len() < MAX_LOG_HITS {
                hits.push(MySqlLogHit {
                    kind,
                    excerpt: excerpt(line),
                });
                break;
            }
        }
    }
    let mut denied: Vec<MySqlDeniedSource> = denied
        .into_iter()
        .map(|((user, host), count)| MySqlDeniedSource { user, host, count })
        .collect();
    denied.sort_by_key(|a| std::cmp::Reverse(a.count));
    denied.truncate(MAX_DENIED_SOURCES);
    MySqlLogTrace {
        path: path.to_owned(),
        tail_bytes: tail.len(),
        denied,
        hits,
    }
}

fn log_findings(log: &MySqlLogTrace, out: &mut Vec<MySqlInstanceFinding>) {
    for source in &log.denied {
        if source.count >= DENIED_BURST_THRESHOLD {
            out.push(MySqlInstanceFinding {
                level: MySqlInstanceLevel::Review,
                code: "log-brute-force",
                detail: format!(
                    "general_log 尾部内 '{}'@'{}' 有 {} 次 Access denied，疑似爆破来源。",
                    source.user, source.host, source.count
                ),
            });
        }
    }
    let mut outfile = 0usize;
    let mut udf = 0usize;
    let mut account_ddl = 0usize;
    for hit in &log.hits {
        match hit.kind {
            "outfile" | "load-file" => outfile += 1,
            "udf-ddl" | "plugin-ddl" => udf += 1,
            "account-ddl" | "grant-ddl" => account_ddl += 1,
            _ => {}
        }
    }
    if outfile > 0 {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::High,
            code: "log-outfile",
            detail: format!(
                "general_log 尾部含 {outfile} 条 INTO OUTFILE/DUMPFILE 或 LOAD_FILE 语句，写马手法典型特征，需逐条人工核对。"
            ),
        });
    }
    if udf > 0 {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::High,
            code: "log-udf-ddl",
            detail: format!(
                "general_log 尾部含 {udf} 条 CREATE FUNCTION / INSTALL PLUGIN 语句，与 UDF 提权路径一致。"
            ),
        });
    }
    if account_ddl > 0 {
        out.push(MySqlInstanceFinding {
            level: MySqlInstanceLevel::Review,
            code: "log-account-ddl",
            detail: format!(
                "general_log 尾部含 {account_ddl} 条账号/授权类 DDL，需核对是否授权内变更。"
            ),
        });
    }
}

/// The read-only query batch; runs on its own native session like the other
/// password-flow steps. Every section failure degrades to a visible gap.
pub(crate) async fn run_review(session: &mut MySqlSession) -> CoreResult<MySqlInstanceReview> {
    let rows = session.query_rows(IDENTITY_SQL.as_bytes(), 3, 1).await?;
    let row = rows
        .first()
        .ok_or_else(|| invalid("数据库身份检查没有返回结果"))?;
    let version = cell(row, 0);
    let comment = cell(row, 1);
    let product =
        parse_version_comment(&version, &comment).ok_or_else(|| invalid("无法识别的数据库产品"))?;
    let connecting =
        parse_current_user(&cell(row, 2)).ok_or_else(|| invalid("无法取得当前连接账号身份"))?;
    if !supported_version(product, &version) {
        return Err(invalid("该数据库版本尚未适配实例检查"));
    }

    let mut gaps = Vec::new();
    let mut accounts = Vec::new();
    let mut account_total = 0usize;
    let (account_sql, account_cols) = match product {
        MySqlProduct::MySql => (ACCOUNTS_MYSQL, 8),
        MySqlProduct::MariaDb => (ACCOUNTS_MARIADB, 7),
    };
    match session
        .query_rows(account_sql.as_bytes(), account_cols, MAX_ACCOUNTS)
        .await
    {
        Ok(rows) => {
            account_total = rows.len();
            for row in rows.iter().take(MAX_ACCOUNTS) {
                accounts.push(MySqlAccountRow {
                    user: cell(row, 0),
                    host: cell(row, 1),
                    plugin: cell(row, 2),
                    empty_secret: cell(row, 3).is_empty(),
                    superuser: cell(row, 4) == "Y",
                    file_priv: cell(row, 5) == "Y",
                    grant_priv: cell(row, 6) == "Y",
                    locked: if product == MySqlProduct::MySql {
                        Some(cell(row, 7) == "Y")
                    } else {
                        None
                    },
                });
            }
        }
        Err(_) => gaps.push(
            "账号目录 mysql.user 不可读（需 SELECT mysql.* 权限），账号类检查未执行。".to_owned(),
        ),
    }

    let mut udfs = Vec::new();
    let mut udf_total = 0usize;
    match session.query_rows(UDF_SQL.as_bytes(), 2, MAX_UDFS).await {
        Ok(rows) => {
            udf_total = rows.len();
            for row in rows.iter().take(MAX_UDFS) {
                udfs.push(MySqlUdfRow {
                    name: cell(row, 0),
                    library: cell(row, 1),
                });
            }
        }
        Err(_) => gaps.push("mysql.func 不可读，UDF 注册痕迹未检查。".to_owned()),
    }

    let mut variables = BTreeMap::new();
    match session
        .query_rows(VARIABLES_SQL.as_bytes(), 2, MAX_VARIABLES)
        .await
    {
        Ok(rows) => {
            for row in rows {
                variables.insert(cell(&row, 0), cell(&row, 1));
            }
        }
        Err(_) => gaps.push("全局变量不可读，日志与文件权限类检查未执行。".to_owned()),
    }

    let mut findings = Vec::new();
    for row in &accounts {
        account_findings(row, &mut findings);
    }
    udf_findings(&udfs, &mut findings);
    variable_findings(&variables, &mut findings);

    Ok(MySqlInstanceReview {
        product,
        server_version: version,
        connecting,
        accounts,
        account_total,
        udfs,
        udf_total,
        variables,
        findings,
        gaps,
        log: None,
    })
}

/// Decide whether a general-log tail read is meaningful and return the shell
/// command for it (run over a separate SSH exec channel by the caller).
/// `log_output` may be `FILE`, `TABLE`, `FILE,TABLE` or `NONE`.
pub(crate) fn general_log_tail_command(review: &MySqlInstanceReview) -> Option<String> {
    let on = review
        .variables
        .get("general_log")
        .is_some_and(|v| v.eq_ignore_ascii_case("ON"));
    let file_output = review
        .variables
        .get("log_output")
        .is_some_and(|v| v.to_ascii_uppercase().contains("FILE"));
    if !on || !file_output {
        return None;
    }
    let path = review.variables.get("general_log_file")?;
    let (dir, name) = if let Some(stripped) = path.strip_prefix('/') {
        ("/", stripped)
    } else if path.contains('/') {
        path.rsplit_once('/')?
    } else {
        // Relative path resolves inside datadir.
        let datadir = review.variables.get("datadir")?;
        (datadir.as_str(), path.as_str())
    };
    let full = if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    };
    if full.len() > 512 || full.contains('\0') || full.contains('\n') {
        return None;
    }
    let quoted = crate::shell_escape::shq(&full);
    Some(format!(
        "if [ -f {q} ] && [ -r {q} ]; then tail -c {bytes} -- {q} 2>/dev/null; \
         else printf '__LH_LOG_UNREADABLE__'; fi",
        q = quoted,
        bytes = LOG_TAIL_BYTES
    ))
}

/// Merge the exec output of [`general_log_tail_command`] into the review.
pub(crate) fn attach_log_tail(review: &mut MySqlInstanceReview, output: &SshCommandOutput) {
    let stdout = &output.output;
    if stdout.contains("__LH_LOG_UNREADABLE__") {
        review
            .gaps
            .push("general_log 日志文件不可读（不存在或权限不足），日志溯源未执行。".to_owned());
        return;
    }
    let bytes = stdout.as_bytes();
    let tail = if bytes.len() as u64 > LOG_TAIL_BYTES {
        &bytes[bytes.len() - LOG_TAIL_BYTES as usize..]
    } else {
        bytes
    };
    let trace = analyze_log_tail(
        review
            .variables
            .get("general_log_file")
            .cloned()
            .unwrap_or_default()
            .as_str(),
        tail,
    );
    log_findings(&trace, &mut review.findings);
    review.log = Some(trace);
}

const LOG_TAIL_TIMEOUT: Duration = Duration::from_secs(30);

impl DatabaseService {
    /// Runs the read-only live-instance review: one native session answers
    /// the query batch on its own direct-tcpip channel, then — only when the
    /// server says the general log is enabled and file-based — a separate SSH
    /// exec channel tails the log file. Each failure is a gap, not silence.
    pub async fn mysql_instance_review(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
    ) -> CoreResult<MySqlInstanceReview> {
        self.target.validate(session.target())?;
        let profile_id = expected.view().config.id.clone();
        let (profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(CoreError::validation(
                "database profile conflict",
                "profile changed before the review",
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
                MySqlPasswordStep::Review {
                    request: request_for(&request)?,
                },
            )
            .await?;
        let MySqlPasswordResult::Reviewed(review) = result else {
            return Err(invalid("数据库实例检查返回了不符合约定的结果"));
        };
        let mut review = *review;
        if let Some(command) = general_log_tail_command(&review) {
            match self
                .ssh
                .execute_bound(session, command, LOG_TAIL_TIMEOUT)
                .await
            {
                Ok(output) => attach_log_tail(&mut review, &output),
                Err(_) => review
                    .gaps
                    .push("general_log 日志尾部读取的 SSH 通道失败，日志溯源未执行。".to_owned()),
            }
        }
        self.target.validate(session.target())?;
        self.profiles.ensure_snapshot(
            profile_id.as_str(),
            expected.digest(),
            "MySQL instance review",
        )?;
        Ok(review)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(user: &str, host: &str) -> MySqlAccountRow {
        MySqlAccountRow {
            user: user.to_owned(),
            host: host.to_owned(),
            plugin: "mysql_native_password".to_owned(),
            empty_secret: false,
            superuser: false,
            file_priv: false,
            grant_priv: false,
            locked: Some(false),
        }
    }

    #[test]
    fn account_findings_flag_the_reviewed_set() {
        let mut findings = Vec::new();
        account_findings(&account("", "localhost"), &mut findings);
        assert!(findings.iter().any(|f| f.code == "anonymous-account"));

        let mut findings = Vec::new();
        account_findings(&account("root", "%"), &mut findings);
        assert!(findings.iter().any(|f| f.code == "root-remote"));
        let mut findings = Vec::new();
        account_findings(&account("root", "localhost"), &mut findings);
        assert!(findings.is_empty());
        let mut findings = Vec::new();
        account_findings(&account("root", "127.0.0.1"), &mut findings);
        assert!(findings.is_empty());

        let mut row = account("app", "%");
        row.empty_secret = true;
        let mut findings = Vec::new();
        account_findings(&row, &mut findings);
        assert!(findings.iter().any(|f| f.code == "empty-password"));

        let mut row = account("app", "%");
        row.file_priv = true;
        let mut findings = Vec::new();
        account_findings(&row, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "file-priv" && f.level == MySqlInstanceLevel::High)
        );

        let mut row = account("app", "%");
        row.grant_priv = true;
        row.superuser = true;
        let mut findings = Vec::new();
        account_findings(&row, &mut findings);
        assert!(findings.iter().any(|f| f.code == "grant-priv"));
        assert!(findings.iter().any(|f| f.code == "super-priv"));
    }

    #[test]
    fn web_root_paths_cover_the_common_layouts() {
        assert!(path_in_web_root("/var/www/html/mysql.log"));
        assert!(path_in_web_root("/home/shop/public_html/x.log"));
        assert!(path_in_web_root("/opt/tomcat/webapps/ROOT/../log.txt"));
        assert!(!path_in_web_root("/var/log/mysql/general.log"));
        assert!(!path_in_web_root("/var/lib/mysql/host.log"));
    }

    #[test]
    fn variable_findings_grade_log_and_file_settings() {
        let mut vars = BTreeMap::new();
        vars.insert("general_log".to_owned(), "ON".to_owned());
        vars.insert("log_output".to_owned(), "FILE".to_owned());
        vars.insert(
            "general_log_file".to_owned(),
            "/var/www/html/shell.php".to_owned(),
        );
        vars.insert("local_infile".to_owned(), "ON".to_owned());
        vars.insert("secure_file_priv".to_owned(), "".to_owned());
        let mut findings = Vec::new();
        variable_findings(&vars, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "general-log-web-root" && f.level == MySqlInstanceLevel::High)
        );
        assert!(findings.iter().any(|f| f.code == "local-infile"));
        assert!(findings.iter().any(|f| f.code == "secure-file-priv-empty"));

        vars.insert("general_log".to_owned(), "OFF".to_owned());
        vars.insert(
            "secure_file_priv".to_owned(),
            "/var/lib/mysql-files/".to_owned(),
        );
        let mut findings = Vec::new();
        variable_findings(&vars, &mut findings);
        assert!(findings.iter().all(|f| f.code != "general-log-web-root"));
    }

    #[test]
    fn log_tail_counts_denied_and_flags_file_writes() {
        let text = concat!(
            "2026-11-10T10:00:01Z  12 Connect  root@attacker on  using TCP/IP\n",
            "2026-11-10T10:00:02Z  12 Query    Access denied for user 'root'@'10.0.0.9' (using password: YES)\n",
            "2026-11-10T10:00:03Z  12 Query    Access denied for user 'root'@'10.0.0.9' (using password: YES)\n",
            "2026-11-10T10:01:00Z  13 Query    select 'x' INTO OUTFILE '/var/www/html/x.php'\n",
            "2026-11-10T10:02:00Z  13 Query    CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so'\n",
        );
        let mut trace = analyze_log_tail("/var/log/mysql/general.log", text.as_bytes());
        assert_eq!(trace.denied.len(), 1);
        assert_eq!(trace.denied[0].user, "root");
        assert_eq!(trace.denied[0].host, "10.0.0.9");
        assert_eq!(trace.denied[0].count, 2);
        assert!(trace.hits.iter().any(|h| h.kind == "outfile"));
        assert!(trace.hits.iter().any(|h| h.kind == "udf-ddl"));

        let mut findings = Vec::new();
        trace.denied[0].count = 50;
        log_findings(&trace, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "log-brute-force" && f.level == MySqlInstanceLevel::Review)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.code == "log-outfile" && f.level == MySqlInstanceLevel::High)
        );
        assert!(findings.iter().any(|f| f.code == "log-udf-ddl"));
    }

    #[test]
    fn tail_command_only_runs_for_file_logging() {
        let mut review = MySqlInstanceReview {
            product: MySqlProduct::MySql,
            server_version: "8.0.46".to_owned(),
            connecting: MySqlAccount::new("root", "localhost").unwrap(),
            accounts: Vec::new(),
            account_total: 0,
            udfs: Vec::new(),
            udf_total: 0,
            variables: BTreeMap::new(),
            findings: Vec::new(),
            gaps: Vec::new(),
            log: None,
        };
        assert!(general_log_tail_command(&review).is_none());
        review
            .variables
            .insert("general_log".to_owned(), "ON".to_owned());
        review
            .variables
            .insert("log_output".to_owned(), "FILE".to_owned());
        review.variables.insert(
            "general_log_file".to_owned(),
            "/var/log/mysql/general.log".to_owned(),
        );
        let command = general_log_tail_command(&review).expect("file logging yields a command");
        assert!(command.contains("tail -c 262144"));
        assert!(command.contains("/var/log/mysql/general.log"));
    }

    #[test]
    fn udf_rows_become_review_findings() {
        let mut findings = Vec::new();
        udf_findings(
            &[MySqlUdfRow {
                name: "sys_eval".to_owned(),
                library: "lib_mysqludf_sys.so".to_owned(),
            }],
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].level, MySqlInstanceLevel::High);
        assert_eq!(findings[0].code, "udf-registered");
    }
}
