//! `SHOW GRANTS` review and least-privilege plans for one MySQL/MariaDB
//! account. Statements the parser cannot classify are kept verbatim and block
//! planning; the operator ticks privileges per scope row and adds grants only
//! from a closed privilege list on database or table scopes the server itself
//! reported. Execution re-reads the grants first, runs each statement in
//! order, stops at the first failure and verifies the final grant set; undo
//! replays the inverse statements inside a ten-minute window.

use std::collections::BTreeSet;
use crate::{
    CoreError, CoreResult,
    database::{DatabaseEngine, DatabaseProfileSnapshot, DatabaseService, validate_profile_session},
    mysql_native::{MySqlRuntimeRequest, MySqlSession},
    mysql_password::{
        MySqlAccount, MySqlPasswordResult, MySqlPasswordStep, MySqlProduct, parse_current_user,
        parse_version_comment, request_for, supported_version, tls_settings_for,
    },
    mysql_wire::QueryResult,
    operations::OperationPlan,
    shell_escape::escape_sql_literal,
    ssh::BoundSshSession,
};

fn invalid(reason: &str) -> CoreError {
    CoreError::validation("MySQL 账号权限", reason)
}

/// The privileges the operator may tick or add. Anything outside this list in
/// a `SHOW GRANTS` line keeps the whole line verbatim and unplannable.
pub const PRIVILEGE_NAMES: &[&str] = &[
    "ALTER",
    "ALTER ROUTINE",
    "CREATE",
    "CREATE ROUTINE",
    "CREATE TEMPORARY TABLES",
    "CREATE VIEW",
    "DELETE",
    "DROP",
    "EVENT",
    "EXECUTE",
    "INDEX",
    "INSERT",
    "LOCK TABLES",
    "REFERENCES",
    "SELECT",
    "SHOW VIEW",
    "TRIGGER",
    "UPDATE",
];

/// Static members of `ALL PRIVILEGES` at `db.*` scope (MySQL 8 and MariaDB).
const DATABASE_ALL: &[&str] = &[
    "ALTER",
    "ALTER ROUTINE",
    "CREATE",
    "CREATE ROUTINE",
    "CREATE TEMPORARY TABLES",
    "CREATE VIEW",
    "DELETE",
    "DROP",
    "EVENT",
    "EXECUTE",
    "INDEX",
    "INSERT",
    "LOCK TABLES",
    "REFERENCES",
    "SELECT",
    "SHOW VIEW",
    "TRIGGER",
    "UPDATE",
];

/// Static members of `ALL PRIVILEGES` at `db.table` scope.
const TABLE_ALL: &[&str] = &[
    "ALTER",
    "CREATE VIEW",
    "DELETE",
    "DROP",
    "INDEX",
    "INSERT",
    "REFERENCES",
    "SELECT",
    "SHOW VIEW",
    "TRIGGER",
    "UPDATE",
];

/// Global privileges the UI highlights but can only be revoked verbatim
/// (they are members of global `ALL` that we never expand).
const GLOBAL_PRIVILEGE_NAMES: &[&str] = &[
    "CREATE USER",
    "FILE",
    "PROCESS",
    "RELOAD",
    "REPLICATION CLIENT",
    "REPLICATION SLAVE",
    "SHOW DATABASES",
    "SHUTDOWN",
    "SUPER",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantScope {
    Global,
    Database(String),
    Table(String, String),
    /// `db.routine(...)`, proxies, roles, column grants — verbatim only.
    Other,
}

impl GrantScope {
    fn sql(&self) -> String {
        match self {
            GrantScope::Global => "*.*".to_owned(),
            GrantScope::Database(db) => format!("{}.*", quote_ident(db)),
            GrantScope::Table(db, table) => format!("{}.{}", quote_ident(db), quote_ident(table)),
            GrantScope::Other => String::new(),
        }
    }
}

/// One `SHOW GRANTS` line, classified. `parseable == false` rows are shown
/// verbatim and refuse planning for the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    pub raw: String,
    pub parseable: bool,
    pub scope: GrantScope,
    /// Canonical privilege names; `ALL PRIVILEGES` keeps `all_privileges` set
    /// and an empty list.
    pub privileges: Vec<String>,
    pub all_privileges: bool,
    pub grant_option: bool,
}

impl GrantRow {
    /// Effective member privileges (ALL expanded for db/table scopes; global
    /// ALL expands to every name we know, which is only used for display).
    pub fn members(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        if self.all_privileges {
            let members: &[&str] = match &self.scope {
                GrantScope::Database(_) => DATABASE_ALL,
                GrantScope::Table(..) => TABLE_ALL,
                _ => &[],
            };
            out.extend(members.iter().map(|p| (*p).to_owned()));
            if self.scope == GrantScope::Global {
                out.extend(GLOBAL_PRIVILEGE_NAMES.iter().map(|p| (*p).to_owned()));
                out.extend(DATABASE_ALL.iter().map(|p| (*p).to_owned()));
            }
        } else {
            out.extend(self.privileges.iter().cloned());
        }
        out
    }

    /// Scope + privileges + grant option in one canonical key for
    /// set-equality checks between reads.
    fn key(&self) -> (String, BTreeSet<String>, bool, bool) {
        (
            self.scope.sql(),
            self.members(),
            self.all_privileges,
            self.grant_option,
        )
    }
}

/// `'` and `\` are both doubled: the account literal survives servers with or
/// without `NO_BACKSLASH_ESCAPES` because `\` inside a `'` literal only needs
/// to not terminate the quote.
fn account_literal(account: &MySqlAccount) -> String {
    format!(
        "'{}'@'{}'",
        escape_sql_literal(&account.user).replace('\\', "\\\\"),
        escape_sql_literal(&account.host).replace('\\', "\\\\"),
    )
}

fn quote_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

fn unquote_ident(token: &str) -> Option<String> {
    let token = token.trim();
    if token == "*" {
        return Some("*".to_owned());
    }
    let inner = token.strip_prefix('`')?.strip_suffix('`')?;
    Some(inner.replace("``", "`"))
}

fn parse_scope(token: &str) -> Option<GrantScope> {
    let (left, right) = token.split_once('.')?;
    let db = unquote_ident(left)?;
    let tail = unquote_ident(right)?;
    if tail.contains('(') {
        return Some(GrantScope::Other);
    }
    match (db.as_str(), tail.as_str()) {
        ("*", "*") => Some(GrantScope::Global),
        ("*", _) => None,
        (db, "*") => Some(GrantScope::Database(db.to_owned())),
        (db, table) => Some(GrantScope::Table(db.to_owned(), table.to_owned())),
    }
}

/// Parse one `SHOW GRANTS` statement. `None` for anything outside the plain
/// `GRANT <privs> ON <scope> TO` / `GRANT <role> TO` shapes.
fn parse_grant_line(raw: &str) -> Option<GrantRow> {
    let text = raw.trim();
    let upper = text.to_ascii_uppercase();
    if !upper.starts_with("GRANT ") {
        return None;
    }
    let grant_option = upper.ends_with("WITH GRANT OPTION")
        || upper.contains(" WITH GRANT OPTION");
    // Role grants (`GRANT 'r'@'%' TO 'u'@'h'`) have no ON; proxies use
    // `GRANT PROXY ON ... TO`. Both stay verbatim.
    let Some(on_at) = find_top_keyword(text, " ON ") else {
        return Some(GrantRow {
            raw: raw.to_owned(),
            parseable: false,
            scope: GrantScope::Other,
            privileges: Vec::new(),
            all_privileges: false,
            grant_option,
        });
    };
    let to_at = find_top_keyword(text, " TO ").filter(|at| *at >= on_at)?;
    let privs = text["GRANT ".len()..on_at].trim();
    let scope_text = text[on_at + " ON ".len()..to_at].trim();
    if privs.starts_with('\'') || privs.starts_with('`') {
        // A quoted first token is a role name, not a privilege list.
        return Some(GrantRow {
            raw: raw.to_owned(),
            parseable: false,
            scope: GrantScope::Other,
            privileges: Vec::new(),
            all_privileges: false,
            grant_option,
        });
    }
    let mut privileges = Vec::new();
    let mut all_privileges = false;
    let mut usage_only = false;
    for part in privs.split(',') {
        let name = part.trim();
        if name.eq_ignore_ascii_case("USAGE") {
            usage_only = true;
            continue;
        }
        if name.eq_ignore_ascii_case("ALL PRIVILEGES") || name.eq_ignore_ascii_case("ALL") {
            all_privileges = true;
            continue;
        }
        if name.contains('(') {
            // Column-level grants are verbatim rows.
            return Some(GrantRow {
                raw: raw.to_owned(),
                parseable: false,
                scope: GrantScope::Other,
                privileges: Vec::new(),
                all_privileges: false,
                grant_option,
            });
        }
        let canonical = PRIVILEGE_NAMES
            .iter()
            .chain(GLOBAL_PRIVILEGE_NAMES.iter())
            .find(|known| name.eq_ignore_ascii_case(known))
            .copied();
        match canonical {
            Some(name) => privileges.push(name.to_owned()),
            None => {
                return Some(GrantRow {
                    raw: raw.to_owned(),
                    parseable: false,
                    scope: GrantScope::Other,
                    privileges: Vec::new(),
                    all_privileges: false,
                    grant_option,
                });
            }
        }
    }
    if privileges.is_empty() && !all_privileges && !usage_only {
        return None;
    }
    let scope = parse_scope(scope_text).unwrap_or(GrantScope::Other);
    let parseable = scope != GrantScope::Other;
    Some(GrantRow {
        raw: raw.to_owned(),
        parseable,
        scope,
        privileges,
        all_privileges,
        grant_option,
    })
}

/// Find ` keyword ` outside quotes/backticks; returns its byte offset.
fn find_top_keyword(text: &str, keyword: &str) -> Option<usize> {
    let upper = text.to_ascii_uppercase();
    let needle = keyword.to_ascii_uppercase();
    let mut in_quote = false;
    let mut in_ident = false;
    let bytes = upper.as_bytes();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        let b = bytes[i];
        if in_quote {
            if b == b'\'' {
                in_quote = bytes.get(i + 1) != Some(&b'\'');
                if in_quote {
                    i += 1;
                }
            } else if b == b'\\' {
                i += 1;
            }
        } else if in_ident {
            if b == b'`' {
                in_ident = false;
            }
        } else {
            match b {
                b'\'' => in_quote = true,
                b'`' => in_ident = true,
                _ => {
                    if upper[i..].starts_with(&needle) {
                        return Some(i);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

pub fn parse_show_grants(lines: &[String]) -> Vec<GrantRow> {
    lines
        .iter()
        .map(|line| {
            parse_grant_line(line).unwrap_or_else(|| GrantRow {
                raw: line.clone(),
                parseable: false,
                scope: GrantScope::Other,
                privileges: Vec::new(),
                all_privileges: false,
                grant_option: false,
            })
        })
        .collect()
}

/// What the read step pulled out of the server for one account.
#[derive(Debug)]
pub struct MySqlPrivilegeRead {
    pub product: MySqlProduct,
    pub server_version: String,
    pub connecting: MySqlAccount,
    pub grant_lines: Vec<String>,
    pub schemas: Vec<String>,
    pub tables: Vec<(String, String)>,
}

/// One operator tick against a parsed row: row index + privilege names.
/// `"GRANT OPTION"` is the pseudo-privilege for the grant-option flag.
#[derive(Clone, Debug, PartialEq)]
pub struct RevokeChoice {
    pub row: usize,
    pub privileges: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AddChoice {
    pub scope: GrantScope,
    pub privileges: Vec<String>,
}

/// One statement plus the inverse statements that undo exactly it.
#[derive(Clone, Debug)]
pub struct PlanStep {
    pub statement: String,
    pub inverse: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PrivilegePlan {
    /// Ordered: REVOKEs first, then GRANTs.
    pub steps: Vec<PlanStep>,
    /// Canonical expected rows used to verify the final `SHOW GRANTS`.
    pub expected: Vec<GrantRow>,
    pub before_lines: Vec<String>,
    pub notes: Vec<String>,
    /// Rows the operator ticked that this plan actually changes.
    pub changes: usize,
}

impl PrivilegePlan {
    pub fn statements(&self) -> Vec<String> {
        self.steps.iter().map(|step| step.statement.clone()).collect()
    }

    /// Inverses of the first `applied` statements, latest first.
    pub fn undo_statements(&self, applied: usize) -> Vec<String> {
        self.steps
            .iter()
            .take(applied)
            .rev()
            .flat_map(|step| step.inverse.iter().cloned())
            .collect()
    }
}

fn scope_members(scope: &GrantScope) -> Option<&'static [&'static str]> {
    match scope {
        GrantScope::Database(_) => Some(DATABASE_ALL),
        GrantScope::Table(..) => Some(TABLE_ALL),
        _ => None,
    }
}

fn check_privilege(name: &str) -> CoreResult<String> {
    if name.eq_ignore_ascii_case("GRANT OPTION") {
        return Ok("GRANT OPTION".to_owned());
    }
    PRIVILEGE_NAMES
        .iter()
        .chain(GLOBAL_PRIVILEGE_NAMES.iter())
        .find(|known| name.eq_ignore_ascii_case(known))
        .map(|p| (*p).to_owned())
        .ok_or_else(|| invalid("权限名不在允许清单内"))
}

/// Build the ordered statements, inverses and the expected final set. Every
/// refusal names the reason; nothing partial leaves this function.
pub fn build_plan(
    account: &MySqlAccount,
    connecting: &MySqlAccount,
    rows: &[GrantRow],
    revokes: &[RevokeChoice],
    adds: &[AddChoice],
) -> CoreResult<PrivilegePlan> {
    let literal = account_literal(account);
    if rows.iter().any(|row| !row.parseable) {
        return Err(invalid("该账号存在无法解析的授权行（例如角色、列级或 PROXY 授权），请人工核对后再规划"));
    }
    if revokes.is_empty() && adds.is_empty() {
        return Err(invalid("没有勾选要收回的权限，也没有添加新授权"));
    }
    if account.user == "root" && !revokes.is_empty() {
        return Err(invalid("root 类高权限账号只允许添加授权，不允许收回"));
    }
    let mut steps: Vec<PlanStep> = Vec::new();
    let mut notes = Vec::new();
    let mut expected: Vec<GrantRow> = rows.to_vec();
    let mut changes = 0usize;
    let mut touched_scopes: BTreeSet<GrantScope> = BTreeSet::new();

    for choice in revokes {
        let row = rows
            .get(choice.row)
            .ok_or_else(|| invalid("收回项指向的授权行不存在，请重新读取"))?;
        if !row.parseable {
            return Err(invalid("勾选的授权行无法解析，不能规划"));
        }
        if choice.privileges.is_empty() {
            return Err(invalid("收回项没有勾选任何权限"));
        }
        if row.scope == GrantScope::Global && *account == *connecting {
            return Err(invalid(
                "目标是当前连接使用的账号，收回全局权限后无法再复核或恢复，已拒绝规划",
            ));
        }
        let mut revoke_names = Vec::new();
        let mut drop_grant_option = false;
        for name in &choice.privileges {
            let name = check_privilege(name)?;
            if name == "GRANT OPTION" {
                drop_grant_option = true;
            } else {
                revoke_names.push(name);
            }
        }
        let effective = row.members();
        for name in &revoke_names {
            if !effective.contains(name) {
                return Err(invalid("勾选的权限不在该授权行内，请重新读取后再勾选"));
            }
        }
        if drop_grant_option && !row.grant_option {
            return Err(invalid("该授权行没有 GRANT OPTION 可收回"));
        }
        touched_scopes.insert(row.scope.clone());
        let expected_row = &mut expected[choice.row];
        if row.all_privileges && !revoke_names.is_empty() {
            let Some(members) = scope_members(&row.scope) else {
                return Err(invalid(
                    "全局 ALL PRIVILEGES 无法安全展开成员权限，请整体收回或人工处理",
                ));
            };
            let kept: Vec<String> = members
                .iter()
                .filter(|member| !revoke_names.iter().any(|r| r == *member))
                .map(|m| (*m).to_owned())
                .collect();
            // The re-grant of the original line undoes both the REVOKE ALL
            // and the replacement GRANT, so it hangs off the first step.
            steps.push(PlanStep {
                statement: format!(
                    "REVOKE ALL PRIVILEGES{} ON {} FROM {}",
                    if drop_grant_option { ", GRANT OPTION" } else { "" },
                    row.scope.sql(),
                    literal
                ),
                inverse: vec![row.raw.clone()],
            });
            if !kept.is_empty() {
                steps.push(PlanStep {
                    statement: format!(
                        "GRANT {} ON {} TO {}{}",
                        kept.join(", "),
                        row.scope.sql(),
                        literal,
                        if row.grant_option && !drop_grant_option {
                            " WITH GRANT OPTION"
                        } else {
                            ""
                        }
                    ),
                    inverse: Vec::new(),
                });
            }
            expected_row.all_privileges = false;
            expected_row.privileges = kept;
        } else if !revoke_names.is_empty() {
            steps.push(PlanStep {
                statement: format!(
                    "REVOKE {}{} ON {} FROM {}",
                    revoke_names.join(", "),
                    if drop_grant_option { ", GRANT OPTION" } else { "" },
                    row.scope.sql(),
                    literal
                ),
                inverse: vec![row.raw.clone()],
            });
            expected_row.privileges.retain(|p| !revoke_names.contains(p));
        } else if drop_grant_option {
            steps.push(PlanStep {
                statement: format!(
                    "REVOKE GRANT OPTION ON {} FROM {}",
                    row.scope.sql(),
                    literal
                ),
                inverse: vec![row.raw.clone()],
            });
        }
        if drop_grant_option {
            expected_row.grant_option = false;
        }
        changes += 1;
    }

    for add in adds {
        if !matches!(add.scope, GrantScope::Database(_) | GrantScope::Table(..)) {
            return Err(invalid("新增授权只能选择数据库或数据表范围"));
        }
        if add.privileges.is_empty() {
            return Err(invalid("新增授权没有勾选权限"));
        }
        let mut names = Vec::new();
        for name in &add.privileges {
            let name = check_privilege(name)?;
            if name == "GRANT OPTION" {
                return Err(invalid("GRANT OPTION 不能通过新增授权下发"));
            }
            names.push(name);
        }
        names.dedup();
        // Table-scope grants only accept table-level privileges.
        if matches!(add.scope, GrantScope::Table(..)) {
            for name in &names {
                if !TABLE_ALL.contains(&name.as_str()) {
                    return Err(invalid("勾选的权限不能授予到数据表范围"));
                }
            }
        }
        let statement = format!(
            "GRANT {} ON {} TO {}",
            names.join(", "),
            add.scope.sql(),
            literal
        );
        steps.push(PlanStep {
            statement: statement.clone(),
            inverse: vec![format!(
                "REVOKE {} ON {} FROM {}",
                names.join(", "),
                add.scope.sql(),
                literal
            )],
        });
        changes += 1;
        touched_scopes.insert(add.scope.clone());
        let merged = expected
            .iter()
            .enumerate()
            .find(|(index, row)| {
                row.parseable && row.scope == add.scope && !revokes.iter().any(|r| r.row == *index)
            })
            .map(|(index, _)| index);
        match merged {
            Some(index) => expected[index].privileges.extend(names.iter().cloned()),
            None => expected.push(GrantRow {
                raw: statement,
                parseable: true,
                scope: add.scope.clone(),
                privileges: names,
                all_privileges: false,
                grant_option: false,
            }),
        }
    }

    if touched_scopes.is_empty() {
        return Err(invalid("没有可执行的权限变更"));
    }
    // A scope whose privileges all went away drops out of SHOW GRANTS,
    // except the global row which the server keeps as GRANT USAGE.
    expected.retain(|row| {
        !row.parseable
            || row.scope == GrantScope::Global
            || !row.privileges.is_empty()
            || row.all_privileges
    });
    notes.push("REVOKE/GRANT 立即生效，不需要 FLUSH PRIVILEGES。".to_owned());
    notes.push("最小权限以业务矩阵为准；本工具只执行勾选的变更。".to_owned());
    Ok(PrivilegePlan {
        steps,
        expected,
        before_lines: rows.iter().map(|row| row.raw.clone()).collect(),
        notes,
        changes,
    })
}

/// Multiset-equality between two grant reads, on the canonical row keys.
pub fn same_grant_set(left: &[GrantRow], right: &[GrantRow]) -> bool {
    let keys = |rows: &[GrantRow]| -> BTreeSet<(String, BTreeSet<String>, bool, bool)> {
        rows.iter().map(GrantRow::key).collect()
    };
    keys(left) == keys(right)
}

/// Result of one apply/undo step on the native session.
#[derive(Debug)]
pub struct PrivilegeApplyOutcome {
    /// Grants as they stood when the step began.
    pub before_lines: Vec<String>,
    /// The account's lines changed between plan and execute.
    pub stale: bool,
    /// Per-statement outcomes; stops at the first failure.
    pub applied: usize,
    pub failed: Option<String>,
    /// Grants read back after the statements ran.
    pub after_lines: Vec<String>,
}

const MAX_GRANT_LINES: usize = 500;
const MAX_SCHEMA_ROWS: usize = 2000;
const MAX_TABLE_ROWS: usize = 8000;
const MAX_STATEMENTS: usize = 200;

async fn show_grants(session: &mut MySqlSession, account: &MySqlAccount) -> CoreResult<Vec<String>> {
    let sql = format!("SHOW GRANTS FOR {}", account_literal(account));
    let rows = session
        .query_rows(sql.as_bytes(), 1, MAX_GRANT_LINES)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| row[0].clone().unwrap_or_default())
        .collect())
}

async fn privilege_read(
    session: &mut MySqlSession,
    account: &MySqlAccount,
) -> CoreResult<MySqlPrivilegeRead> {
    let rows = session
        .query_rows(b"SELECT VERSION(), @@version_comment, CURRENT_USER()", 3, 1)
        .await?;
    let row = rows
        .first()
        .ok_or_else(|| invalid("数据库身份检查没有返回结果"))?;
    let version = row[0].clone().unwrap_or_default();
    let comment = row[1].clone().unwrap_or_default();
    let product =
        parse_version_comment(&version, &comment).ok_or_else(|| invalid("无法识别的数据库产品"))?;
    if !supported_version(product, &version) {
        return Err(invalid("该数据库版本尚未评审通过"));
    }
    let connecting = parse_current_user(row[2].as_deref().unwrap_or_default())
        .ok_or_else(|| invalid("无法取得当前连接账号身份"))?;
    let grant_lines = show_grants(session, account).await?;
    let schemas = session
        .query_rows(
            b"SELECT schema_name FROM information_schema.schemata ORDER BY schema_name",
            1,
            MAX_SCHEMA_ROWS,
        )
        .await?
        .into_iter()
        .filter_map(|row| row[0].clone())
        .collect();
    let tables = session
        .query_rows(
            b"SELECT table_schema, table_name FROM information_schema.tables \
              WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema') \
              ORDER BY table_schema, table_name",
            2,
            MAX_TABLE_ROWS,
        )
        .await?
        .into_iter()
        .map(|row| (row[0].clone().unwrap_or_default(), row[1].clone().unwrap_or_default()))
        .collect();
    Ok(MySqlPrivilegeRead {
        product,
        server_version: version,
        connecting,
        grant_lines,
        schemas,
        tables,
    })
}

async fn privilege_apply(
    session: &mut MySqlSession,
    account: &MySqlAccount,
    expected_before: &[String],
    statements: &[String],
) -> CoreResult<PrivilegeApplyOutcome> {
    if statements.is_empty() || statements.len() > MAX_STATEMENTS {
        return Err(invalid("计划语句数量超出范围"));
    }
    let before = show_grants(session, account).await?;
    let stale = !same_grant_set(
        &parse_show_grants(&before),
        &parse_show_grants(expected_before),
    );
    if stale {
        return Ok(PrivilegeApplyOutcome {
            before_lines: before,
            stale: true,
            applied: 0,
            failed: None,
            after_lines: Vec::new(),
        });
    }
    let mut applied = 0usize;
    let mut failed = None;
    for statement in statements {
        match session.query(statement.as_bytes()).await {
            Ok(QueryResult::Ok { .. }) => applied += 1,
            Ok(QueryResult::Rows(_)) => {
                failed = Some(format!("语句返回了意外的结果集：{}", clipped(statement)));
                break;
            }
            Err(error) => {
                failed = Some(format!("{}：{}", error, clipped(statement)));
                break;
            }
        }
    }
    let after = show_grants(session, account).await.unwrap_or_default();
    Ok(PrivilegeApplyOutcome {
        before_lines: before,
        stale: false,
        applied,
        failed,
        after_lines: after,
    })
}

fn clipped(statement: &str) -> String {
    const CAP: usize = 160;
    if statement.len() <= CAP {
        statement.to_owned()
    } else {
        format!("{}…", &statement[..CAP])
    }
}

pub(crate) async fn run_privilege_read(
    session: &mut MySqlSession,
    account: &MySqlAccount,
) -> CoreResult<MySqlPrivilegeRead> {
    privilege_read(session, account).await
}

pub(crate) async fn run_privilege_apply(
    session: &mut MySqlSession,
    account: &MySqlAccount,
    expected_before: &[String],
    statements: &[String],
) -> CoreResult<PrivilegeApplyOutcome> {
    privilege_apply(session, account, expected_before, statements).await
}

/// Verified plan + receipt state the backend freezes.
#[derive(Debug)]
pub struct MySqlPrivilegePlan {
    pub view: PrivilegePlanView,
    pub account: MySqlAccount,
    pub before_lines: Vec<String>,
    pub steps: Vec<PlanStep>,
    pub expected: Vec<GrantRow>,
    pub operation: OperationPlan,
}

impl MySqlPrivilegePlan {
    fn statements(&self) -> Vec<String> {
        self.steps.iter().map(|step| step.statement.clone()).collect()
    }

    fn undo_statements(&self, applied: usize) -> Vec<String> {
        self.steps
            .iter()
            .take(applied)
            .rev()
            .flat_map(|step| step.inverse.iter().cloned())
            .collect()
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegePlanView {
    pub account: String,
    pub summary: String,
    pub statements: Vec<String>,
    pub notes: Vec<String>,
    pub dangerous: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeReceipt {
    pub applied: usize,
    pub failed: Option<String>,
    pub verified: bool,
    pub detail: String,
    pub final_lines: Vec<String>,
}

impl DatabaseService {
    /// Read one account's grants plus the server's own schema/table lists.
    pub async fn mysql_privilege_review(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        account: MySqlAccount,
    ) -> CoreResult<(MySqlPrivilegeRead, String)> {
        self.target.validate(session.target())?;
        let profile_id = expected.view().config.id.clone();
        let (profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(invalid("连接配置在读取前已变化，请刷新"));
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
                MySqlPasswordStep::PrivilegeRead {
                    request: request_for(&request)?,
                    account,
                },
            )
            .await?;
        let MySqlPasswordResult::PrivilegeRead(read) = result else {
            return Err(invalid("数据库账号权限读取返回了不符合约定的结果"));
        };
        Ok((*read, profile_id))
    }

    /// Bind the just-read grants into an immutable plan the backend stores.
    pub async fn plan_mysql_privileges(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        account: MySqlAccount,
        revokes: Vec<RevokeChoice>,
        adds: Vec<AddChoice>,
    ) -> CoreResult<MySqlPrivilegePlan> {
        let (read, _profile_id) = self
            .mysql_privilege_review(session, expected, account.clone())
            .await?;
        let rows = parse_show_grants(&read.grant_lines);
        let plan = build_plan(&account, &read.connecting, &rows, &revokes, &adds)?;
        let summary = format!(
            "将对 {} 执行 {} 条语句（先收回、后授权），预计改动 {} 处授权；GRANT/REVOKE 立即生效。",
            account_literal(&account),
            plan.steps.len(),
            plan.changes,
        );
        let operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "调整 MySQL 账号 {} 的权限：收回与新增以勾选为准，执行前重新核对 SHOW GRANTS，10 分钟内可恢复。",
                account_literal(&account)
            ),
            true,
            Some("10 分钟内可将本次变更恢复为原授权集合".to_owned()),
        )?;
        Ok(MySqlPrivilegePlan {
            view: PrivilegePlanView {
                account: format!("{}@{}", account.user, account.host),
                summary,
                statements: plan.statements(),
                notes: plan.notes,
                dangerous: true,
            },
            account,
            before_lines: plan.before_lines,
            steps: plan.steps,
            expected: plan.expected,
            operation,
        })
    }

    /// Runs REVOKEs then GRANTs in one native session; the step itself
    /// re-reads grants first and refuses on drift.
    pub async fn execute_mysql_privileges(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        plan: &MySqlPrivilegePlan,
    ) -> CoreResult<(PrivilegeReceipt, PrivilegeApplyOutcome)> {
        self.target.validate(session.target())?;
        let profile_id = expected.view().config.id.clone();
        let (profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(invalid("连接配置在执行前已变化，请刷新"));
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
            .mysql_password_step_write(
                session,
                &profile_id,
                expected.digest(),
                MySqlPasswordStep::PrivilegeApply {
                    request: request_for(&request)?,
                    account: plan.account.clone(),
                    expected_before: plan.before_lines.clone(),
                    statements: plan.statements(),
                },
            )
            .await?;
        let MySqlPasswordResult::PrivilegeApplied(outcome) = result else {
            return Err(invalid("权限执行返回了不符合约定的结果"));
        };
        let outcome = *outcome;
        if outcome.stale {
            return Err(invalid("执行前授权已变化，本次未改动任何语句，请重新规划"));
        }
        let verified = outcome.failed.is_none()
            && same_grant_set(&parse_show_grants(&outcome.after_lines), &plan.expected);
        let detail = if let Some(failed) = &outcome.failed {
            format!("第 {} 条语句失败，已应用 {} 条：{}", outcome.applied + 1, outcome.applied, failed)
        } else if verified {
            "已执行全部语句并复核授权集合与计划一致。".to_owned()
        } else {
            "语句已执行，但最终授权集合与计划预期不符，请人工核对。".to_owned()
        };
        Ok((
            PrivilegeReceipt {
                applied: outcome.applied,
                failed: outcome.failed.clone(),
                verified,
                detail,
                final_lines: outcome.after_lines.clone(),
            },
            outcome,
        ))
    }

    /// Undo within the stored window: re-checks current grants equal the
    /// execution output, replays the inverse statements, verifies the set is
    /// back to the original lines.
    pub async fn undo_mysql_privileges(
        &self,
        session: &BoundSshSession,
        expected: &DatabaseProfileSnapshot,
        plan: &MySqlPrivilegePlan,
        applied_lines: &[String],
        applied: usize,
    ) -> CoreResult<PrivilegeReceipt> {
        self.target.validate(session.target())?;
        let profile_id = expected.view().config.id.clone();
        let (profile, digest) = self.profiles.resolve_with_digest(&profile_id)?;
        if digest != expected.digest() {
            return Err(invalid("连接配置在恢复前已变化，请刷新"));
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
            .mysql_password_step_write(
                session,
                &profile_id,
                expected.digest(),
                MySqlPasswordStep::PrivilegeApply {
                    request: request_for(&request)?,
                    account: plan.account.clone(),
                    expected_before: applied_lines.to_vec(),
                    statements: plan.undo_statements(applied),
                },
            )
            .await?;
        let MySqlPasswordResult::PrivilegeApplied(outcome) = result else {
            return Err(invalid("权限恢复返回了不符合约定的结果"));
        };
        let outcome = *outcome;
        if outcome.stale {
            return Err(invalid("恢复前授权与执行结果不一致，已拒绝恢复，请人工核对"));
        }
        let verified = outcome.failed.is_none()
            && same_grant_set(
                &parse_show_grants(&outcome.after_lines),
                &parse_show_grants(&plan.before_lines),
            );
        let detail = if let Some(failed) = &outcome.failed {
            format!("恢复语句第 {} 条失败，已应用 {} 条：{}", outcome.applied + 1, outcome.applied, failed)
        } else if verified {
            "已恢复为原授权集合并复核一致。".to_owned()
        } else {
            "恢复语句已执行，但复核结果与原授权不一致，请人工核对。".to_owned()
        };
        Ok(PrivilegeReceipt {
            applied: outcome.applied,
            failed: outcome.failed,
            verified,
            detail,
            final_lines: outcome.after_lines,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(user: &str, host: &str) -> MySqlAccount {
        MySqlAccount::new(user, host).expect("account")
    }

    fn mysql8_grants() -> Vec<String> {
        vec![
            "GRANT CREATE, DROP ON *.* TO `traffic`@`127.0.0.1`".to_owned(),
            "GRANT ALL PRIVILEGES ON `traffic_oa`.* TO `traffic`@`127.0.0.1`".to_owned(),
            "GRANT SELECT ON `traffic_oa`.`work_order` TO `traffic`@`127.0.0.1`".to_owned(),
        ]
    }

    #[test]
    fn parses_mysql80_global_db_and_table_rows() {
        let rows = parse_show_grants(&mysql8_grants());
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].scope, GrantScope::Global);
        assert_eq!(rows[0].privileges, vec!["CREATE", "DROP"]);
        assert_eq!(rows[1].scope, GrantScope::Database("traffic_oa".to_owned()));
        assert!(rows[1].all_privileges);
        assert_eq!(rows[1].members().len(), DATABASE_ALL.len());
        assert_eq!(
            rows[2].scope,
            GrantScope::Table("traffic_oa".to_owned(), "work_order".to_owned())
        );
    }

    #[test]
    fn parses_mariadb_rows_with_grant_option() {
        let lines = vec![
            "GRANT SELECT, INSERT ON `traffic_oa`.* TO 'traffic'@'127.0.0.1' WITH GRANT OPTION"
                .to_owned(),
            "GRANT USAGE ON *.* TO 'traffic'@'127.0.0.1'".to_owned(),
        ];
        let rows = parse_show_grants(&lines);
        assert!(rows[0].grant_option);
        assert_eq!(rows[0].privileges, vec!["SELECT", "INSERT"]);
        // USAGE parses to a global row with no privileges; it cannot be
        // revoked or added to, but it must not block planning.
        assert!(rows[1].parseable);
        assert_eq!(rows[1].scope, GrantScope::Global);
        assert!(rows[1].members().is_empty());
        assert_eq!(rows[1].raw, lines[1]);
    }

    #[test]
    fn column_role_and_proxy_rows_stay_verbatim() {
        let lines = vec![
            "GRANT SELECT (name), UPDATE (name) ON `traffic_oa`.`oa_account` TO 'u'@'h'".to_owned(),
            "GRANT 'app_role' TO 'u'@'h'".to_owned(),
            "GRANT PROXY ON 'a'@'b' TO 'u'@'h'".to_owned(),
        ];
        let rows = parse_show_grants(&lines);
        assert!(rows.iter().all(|row| !row.parseable));
        assert!(rows.iter().zip(&lines).all(|(row, raw)| row.raw == *raw));
    }

    #[test]
    fn unparseable_rows_block_planning() {
        let rows = parse_show_grants(&["GRANT PROXY ON 'a'@'b' TO 'u'@'h'".to_owned()]);
        let err = build_plan(
            &account("u", "h"),
            &account("root", "localhost"),
            &rows,
            &[],
            &[AddChoice {
                scope: GrantScope::Database("d".to_owned()),
                privileges: vec!["SELECT".to_owned()],
            }],
        )
        .unwrap_err();
        assert!(err.to_string().contains("无法解析"));
    }

    #[test]
    fn partial_revoke_of_db_all_expands_to_members() {
        let rows = parse_show_grants(&mysql8_grants());
        let plan = build_plan(
            &account("traffic", "127.0.0.1"),
            &account("root", "localhost"),
            &rows,
            &[RevokeChoice {
                row: 1,
                privileges: vec!["CREATE".to_owned(), "DROP".to_owned()],
            }],
            &[],
        )
        .expect("plan");
        assert_eq!(
            plan.steps[0].statement,
            "REVOKE ALL PRIVILEGES ON `traffic_oa`.* FROM 'traffic'@'127.0.0.1'"
        );
        assert!(plan.steps[1].statement.starts_with("GRANT "));
        let expected_members: Vec<&str> = DATABASE_ALL
            .iter()
            .filter(|p| !["CREATE", "DROP"].contains(p))
            .copied()
            .collect();
        for member in &expected_members {
            assert!(plan.steps[1].statement.contains(member), "missing {member}");
        }
        assert!(!plan.steps[1].statement.contains("CREATE,"));
        assert!(!plan.steps[1].statement.contains("DROP,"));
        // The inverse is the verbatim original ALL line.
        assert_eq!(plan.steps[0].inverse[0], rows[1].raw);
        assert!(!plan.expected[1].all_privileges);
        assert_eq!(plan.expected[1].privileges.len(), DATABASE_ALL.len() - 2);
    }

    #[test]
    fn partial_revoke_of_global_all_is_refused() {
        let rows = parse_show_grants(&[
            "GRANT ALL PRIVILEGES ON *.* TO 'u'@'%' WITH GRANT OPTION".to_owned(),
        ]);
        let err = build_plan(
            &account("u", "%"),
            &account("root", "localhost"),
            &rows,
            &[RevokeChoice {
                row: 0,
                privileges: vec!["SELECT".to_owned()],
            }],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("无法安全展开"));
    }

    #[test]
    fn revoke_names_quoting_and_grant_option() {
        let rows = parse_show_grants(&[
            "GRANT SELECT, INSERT ON `d`.* TO 'u\\'s'@'h' WITH GRANT OPTION".to_owned(),
        ]);
        let plan = build_plan(
            &account("u's", "h"),
            &account("root", "localhost"),
            &rows,
            &[RevokeChoice {
                row: 0,
                privileges: vec!["INSERT".to_owned(), "GRANT OPTION".to_owned()],
            }],
            &[],
        )
        .expect("plan");
        assert_eq!(
            plan.steps[0].statement,
            "REVOKE INSERT, GRANT OPTION ON `d`.* FROM 'u''s'@'h'"
        );
        assert!(!plan.expected[0].grant_option);
        assert_eq!(plan.expected[0].privileges, vec!["SELECT"]);
    }

    #[test]
    fn grant_option_only_revoke() {
        let rows = parse_show_grants(&[
            "GRANT SELECT ON `d`.* TO 'u'@'h' WITH GRANT OPTION".to_owned(),
        ]);
        let plan = build_plan(
            &account("u", "h"),
            &account("root", "localhost"),
            &rows,
            &[RevokeChoice {
                row: 0,
                privileges: vec!["GRANT OPTION".to_owned()],
            }],
            &[],
        )
        .expect("plan");
        assert_eq!(
            plan.steps[0].statement,
            "REVOKE GRANT OPTION ON `d`.* FROM 'u'@'h'"
        );
    }

    #[test]
    fn adds_use_backtick_quoting_and_merge_expected() {
        let rows = parse_show_grants(&mysql8_grants());
        let plan = build_plan(
            &account("traffic", "127.0.0.1"),
            &account("root", "localhost"),
            &rows,
            &[],
            &[
                AddChoice {
                    scope: GrantScope::Table("traffic_oa".to_owned(), "we`ird".to_owned()),
                    privileges: vec!["UPDATE".to_owned()],
                },
                AddChoice {
                    scope: GrantScope::Table("traffic_oa".to_owned(), "work_order".to_owned()),
                    privileges: vec!["UPDATE".to_owned()],
                },
            ],
        )
        .expect("plan");
        assert_eq!(
            plan.steps[0].statement,
            "GRANT UPDATE ON `traffic_oa`.`we``ird` TO 'traffic'@'127.0.0.1'"
        );
        assert_eq!(
            plan.steps[0].inverse[0],
            "REVOKE UPDATE ON `traffic_oa`.`we``ird` FROM 'traffic'@'127.0.0.1'"
        );
        // The existing work_order row gained UPDATE; we`ird is a new row.
        assert_eq!(plan.expected.len(), 4);
        assert_eq!(plan.expected[2].privileges, vec!["SELECT", "UPDATE"]);
        // Non-table privileges are refused at table scope.
        let err = build_plan(
            &account("traffic", "127.0.0.1"),
            &account("root", "localhost"),
            &rows,
            &[],
            &[AddChoice {
                scope: GrantScope::Table("d".to_owned(), "t".to_owned()),
                privileges: vec!["CREATE TEMPORARY TABLES".to_owned()],
            }],
        )
        .unwrap_err();
        assert!(err.to_string().contains("数据表范围"));
    }

    #[test]
    fn self_connection_account_refuses_global_revokes() {
        let rows = parse_show_grants(&[
            "GRANT CREATE ON *.* TO 'app'@'127.0.0.1'".to_owned(),
            "GRANT SELECT ON `d`.* TO 'app'@'127.0.0.1'".to_owned(),
        ]);
        let err = build_plan(
            &account("app", "127.0.0.1"),
            &account("app", "127.0.0.1"),
            &rows,
            &[RevokeChoice {
                row: 0,
                privileges: vec!["CREATE".to_owned()],
            }],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("当前连接使用的账号"));
        // Non-global revokes on the same account are allowed.
        let plan = build_plan(
            &account("app", "127.0.0.1"),
            &account("app", "127.0.0.1"),
            &rows,
            &[RevokeChoice {
                row: 1,
                privileges: vec!["SELECT".to_owned()],
            }],
            &[],
        )
        .expect("db-scope revoke on own account is allowed");
        assert_eq!(plan.steps.len(), 1);
    }

    #[test]
    fn root_refuses_revokes_but_allows_adds() {
        let rows = parse_show_grants(&[
            "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION".to_owned(),
        ]);
        let err = build_plan(
            &account("root", "localhost"),
            &account("root", "localhost"),
            &rows,
            &[RevokeChoice {
                row: 0,
                privileges: vec!["SELECT".to_owned()],
            }],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("root"));
        let plan = build_plan(
            &account("root", "localhost"),
            &account("root", "localhost"),
            &rows,
            &[],
            &[AddChoice {
                scope: GrantScope::Database("d".to_owned()),
                privileges: vec!["SELECT".to_owned()],
            }],
        )
        .expect("adds on root are allowed");
        assert_eq!(plan.steps.len(), 1);
    }

    #[test]
    fn grant_option_add_is_refused() {
        let rows = parse_show_grants(&mysql8_grants());
        let err = build_plan(
            &account("traffic", "127.0.0.1"),
            &account("root", "localhost"),
            &rows,
            &[],
            &[AddChoice {
                scope: GrantScope::Database("traffic_oa".to_owned()),
                privileges: vec!["GRANT OPTION".to_owned()],
            }],
        )
        .unwrap_err();
        assert!(err.to_string().contains("GRANT OPTION"));
    }

    #[test]
    fn same_grant_set_compares_canonically() {
        let left = parse_show_grants(&mysql8_grants());
        let right = parse_show_grants(&[
            "GRANT ALL PRIVILEGES ON `traffic_oa`.* TO `traffic`@`127.0.0.1`".to_owned(),
            "GRANT DROP, CREATE ON *.* TO `traffic`@`127.0.0.1`".to_owned(),
            "GRANT SELECT ON `traffic_oa`.`work_order` TO `traffic`@`127.0.0.1`".to_owned(),
        ]);
        assert!(same_grant_set(&left, &right));
        let changed = parse_show_grants(&[
            "GRANT DROP ON *.* TO `traffic`@`127.0.0.1`".to_owned(),
        ]);
        assert!(!same_grant_set(&left, &changed));
    }

    #[test]
    fn expected_set_after_revoke_matches_reread() {
        let rows = parse_show_grants(&["GRANT SELECT, UPDATE ON `d`.* TO 'u'@'h'".to_owned()]);
        let plan = build_plan(
            &account("u", "h"),
            &account("root", "localhost"),
            &rows,
            &[RevokeChoice {
                row: 0,
                privileges: vec!["UPDATE".to_owned()],
            }],
            &[],
        )
        .expect("plan");
        let reread = parse_show_grants(&["GRANT SELECT ON `d`.* TO 'u'@'h'".to_owned()]);
        assert!(same_grant_set(&plan.expected, &reread));
    }
}
