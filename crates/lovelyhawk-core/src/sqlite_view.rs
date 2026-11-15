//! Read-only SQLite viewing on a connected target.
//!
//! One self-contained command chooses the engine on the target: python3 with a
//! const script on stdin first, then the sqlite3 CLI (3.33+ for `-json`-era
//! JSON1), otherwise an explicit refusal marker. Both engines emit the same
//! `LH-<TAG> <json>` line protocol so one parser serves both.
//!
//! The file is opened `mode=ro` and retried `immutable=1` when the read-only
//! open fails (WAL/shm or directory permissions); the immutable note is part of
//! the result, never hidden. Reading still changes the access time and a live
//! view is not a forensic image — the UI says so.

use serde::Deserialize;

use crate::error::{CoreError, CoreResult};
use crate::sftp::RemotePath;
use crate::shell_escape::shq;
use std::time::Duration;

/// Rows ops are deliberately short: the page polls nothing, it just waits.
pub const SQLITE_VIEW_TIMEOUT: Duration = Duration::from_secs(20);
/// Rows returned per page, matching the remote `LIMIT`.
pub const ROWS_PER_PAGE: u32 = 100;
/// Hard cap for the whole remote reply.
const OUTPUT_CAP_BYTES: usize = 1024 * 1024;
/// Remote emitters stop a little under the wire cap so the end marker fits.
const EMIT_CAP_BYTES: usize = 900_000;
const MAX_TABLES: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteViewOp {
    Inspect,
    Rows { table: String, offset: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SqliteCell {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    TruncatedText(String),
    Blob { bytes: u64, hex_prefix: String },
}

impl SqliteCell {
    fn parse(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => SqliteCell::Null,
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    SqliteCell::Integer(i)
                } else {
                    SqliteCell::Real(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(text) => SqliteCell::Text(bounded_text(text)),
            serde_json::Value::Object(map) => {
                if let (Some(b), Some(h)) = (
                    map.get("b").and_then(serde_json::Value::as_u64),
                    map.get("h").and_then(serde_json::Value::as_str),
                ) {
                    return SqliteCell::Blob {
                        bytes: b,
                        hex_prefix: bounded_text(h),
                    };
                }
                if map.get("t").is_some() {
                    let text = map
                        .get("v")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    return SqliteCell::TruncatedText(bounded_text(text));
                }
                SqliteCell::Text("…".to_owned())
            }
            other => SqliteCell::Text(bounded_text(&other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqliteTableRow {
    pub name: String,
    pub kind: String,
    pub sql: String,
    /// None means the count was skipped (time budget or failure), not zero.
    pub rows: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqliteColumn {
    pub name: String,
    pub declared_type: String,
    pub rowid: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqliteFileInfo {
    pub size: u64,
    pub mtime_epoch: u64,
    pub owner: String,
    pub mode: String,
    pub wal: bool,
    pub shm: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqliteEngineInfo {
    pub engine: String,
    pub sqlite_version: String,
    pub immutable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SqliteViewResult {
    Inspect {
        engine: SqliteEngineInfo,
        file: SqliteFileInfo,
        tables: Vec<SqliteTableRow>,
        tables_truncated: bool,
        notes: Vec<String>,
    },
    Rows {
        engine: SqliteEngineInfo,
        columns: Vec<SqliteColumn>,
        rows: Vec<Vec<SqliteCell>>,
        truncated: bool,
        notes: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteViewError {
    NoEngine,
    NotSqlite,
    NoTable,
    NoFile,
    Unparseable(String),
}

impl SqliteViewError {
    pub fn code(&self) -> &'static str {
        match self {
            SqliteViewError::NoEngine => "sqlite-no-engine",
            SqliteViewError::NotSqlite => "sqlite-not-database",
            SqliteViewError::NoTable => "sqlite-no-table",
            SqliteViewError::NoFile => "sqlite-no-file",
            SqliteViewError::Unparseable(_) => "sqlite-opaque",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            SqliteViewError::NoEngine => "需要目标上有 python3 或 sqlite3 3.33 以上",
            SqliteViewError::NotSqlite => {
                "无法按 SQLite 数据库打开（不是数据库、已加密或已损坏）"
            }
            SqliteViewError::NoTable => "表不存在或已变化，请重新打开",
            SqliteViewError::NoFile => "文件不可读或不存在",
            SqliteViewError::Unparseable(_) => "目标返回了无法解析的结果，请重新打开",
        }
    }
}

/// Table identifiers are operator-supplied only through the inspect list, but
/// they still pass through argv, so length is bounded before quoting.
fn validate_table_name(table: &str) -> CoreResult<()> {
    if table.is_empty() || table.len() > 512 || table.chars().any(char::is_control) {
        return Err(CoreError::validation(
            "sqlite table",
            "must be 1..=512 bytes without control characters",
        ));
    }
    Ok(())
}

/// The python engine script. argv is `path op table offset`; the script is a
/// const so no operator text ever reaches the interpreter.
const PY_VIEW: &str = r##"
import sys, os, json, sqlite3, time
from urllib.parse import quote

path = sys.argv[1]
op = sys.argv[2]
table = sys.argv[3] if len(sys.argv) > 3 else ""
offset = int(sys.argv[4]) if len(sys.argv) > 4 else 0

EMIT_CAP = __EMIT_CAP__
MAX_TABLES = __MAX_TABLES__
written = 0
truncated = False

class StopEmit(Exception):
    pass

def emit(tag, obj):
    global written
    line = "LH-%s %s\n" % (tag, json.dumps(obj, ensure_ascii=False))
    if written + len(line.encode("utf-8", "replace")) > EMIT_CAP:
        raise StopEmit()
    written += len(line.encode("utf-8", "replace"))
    sys.stdout.write(line)

def cell(v):
    if v is None:
        return None
    if isinstance(v, bytes):
        return {"b": len(v), "h": v[:32].hex()}
    if isinstance(v, str) and len(v) > 1024:
        return {"t": 1, "v": v[:1024]}
    return v

def ident(name):
    return '"%s"' % name.replace('"', '""')

emit("BEGIN", {"op": op})
try:
    st = os.stat(path)
    try:
        import pwd
        owner = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        owner = str(st.st_uid)
    emit("FILE", {"size": st.st_size, "mtimeEpoch": int(st.st_mtime),
                  "owner": owner, "mode": oct(st.st_mode & 0o777)[2:],
                  "wal": os.path.exists(path + "-wal"),
                  "shm": os.path.exists(path + "-shm")})
except Exception:
    emit("ERR", {"code": "no-file", "message": "文件不可读或不存在"})
    raise SystemExit(0)

conn = None
immutable = False
for imm in (False, True):
    try:
        uri = "file:%s?mode=ro%s" % (quote(path), "&immutable=1" if imm else "")
        probe = sqlite3.connect(uri, uri=True)
        probe.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
        conn, immutable = probe, imm
        if imm:
            emit("NOTE", {"text": "以不可变方式读取，可能看不到尚未合并到主文件的写入"})
        break
    except Exception:
        continue
if conn is None:
    emit("ERR", {"code": "not-sqlite",
                 "message": "无法按 SQLite 数据库打开（不是数据库、已加密或已损坏）"})
    raise SystemExit(0)
emit("ENGINE", {"engine": "python3",
                "sqliteVersion": sqlite3.sqlite_version,
                "immutable": immutable})
try:
    if op == "inspect":
        listing = conn.execute(
            "SELECT name,type,sql FROM sqlite_master "
            "WHERE type IN ('table','view') ORDER BY name").fetchall()
        deadline = time.monotonic() + 4.0
        for name, typ, sql in listing[:MAX_TABLES]:
            count = None
            if typ == "table" and time.monotonic() < deadline:
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM %s" % ident(name)).fetchone()[0]
                except Exception:
                    count = None
            emit("TABLE", {"name": name, "kind": typ, "sql": sql or "",
                           "rows": count})
        if len(listing) > MAX_TABLES:
            emit("NOTE", {"text": "对象较多，仅列出前 %d 个表/视图" % MAX_TABLES})
    elif op == "rows":
        found = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name=? AND type IN ('table','view')",
            (table,)).fetchone()
        if found is None:
            emit("ERR", {"code": "no-table", "message": "表不存在或已变化，请重新打开"})
            raise SystemExit(0)
        cols = conn.execute("PRAGMA table_info(%s)" % ident(table)).fetchall()
        has_rowid = not any(c[1].lower() == "rowid" for c in cols)
        if has_rowid:
            try:
                conn.execute("SELECT rowid FROM %s LIMIT 0" % ident(table)).fetchone()
            except Exception:
                has_rowid = False
        if has_rowid:
            emit("COL", {"name": "rowid", "decl": "", "rowid": True})
        for c in cols:
            emit("COL", {"name": c[1], "decl": c[2] or "", "rowid": False})
        select = (["rowid"] if has_rowid else []) + [ident(c[1]) for c in cols]
        cursor = conn.execute(
            "SELECT %s FROM %s LIMIT 100 OFFSET %d"
            % (",".join(select), ident(table), offset))
        for row in cursor:
            emit("ROW", [cell(v) for v in row])
except StopEmit:
    truncated = True
except Exception:
    emit("ERR", {"code": "op-failed", "message": "读取执行失败，请重新打开"})
    raise SystemExit(0)
emit("END", {"truncated": truncated})
"##;

/// The sqlite3-CLI engine. Same protocol; json_object/json_array come from
/// JSON1, which is what `-json` itself requires (3.33+ gate).
const SH_CLI_VIEW: &str = r##"
lh_esc=$(printf '%s' "$lh_table" | sed 's/"/""/g')
lh_escq=$(printf '%s' "$lh_table" | sed "s/'/''/g")
lh_uri() {
  printf '%s' "$1" | od -A n -v -t x1 | tr -d ' \n' | sed 's/../%&/g'
}
lh_open() {
  lh_flags='-readonly'
  if ! sqlite3 -readonly "$lh_db" "SELECT 1 FROM sqlite_master LIMIT 1" >/dev/null 2>&1; then
    lh_db="file:$(lh_uri "$lh_db")?mode=ro&immutable=1"
    lh_flags='-readonly -uri'
    if sqlite3 $lh_flags "$lh_db" "SELECT 1 FROM sqlite_master LIMIT 1" >/dev/null 2>&1; then
      lh_immutable=1
      echo 'LH-NOTE {"text":"以不可变方式读取，可能看不到尚未合并到主文件的写入"}'
    else
      echo 'LH-ERR {"code":"not-sqlite","message":"无法按 SQLite 数据库打开（不是数据库、已加密或已损坏）"}'
      return 1
    fi
  fi
  lh_ver=$(sqlite3 -version 2>/dev/null | awk '{print $1}')
  printf 'LH-ENGINE {"engine":"sqlite3","sqliteVersion":"%s","immutable":%s}\n' "$lh_ver" "$( [ -n "$lh_immutable" ] && echo true || echo false )"
  return 0
}
printf 'LH-BEGIN {"op":"%s"}\n' "$lh_op"
lh_size=$(stat -c %s -- "$lh_db" 2>/dev/null); [ -z "$lh_size" ] && lh_size=$(wc -c < "$lh_db" 2>/dev/null)
if [ -z "$lh_size" ]; then
  echo 'LH-ERR {"code":"no-file","message":"文件不可读或不存在"}'
  exit 0
fi
lh_mode=$(stat -c %a -- "$lh_db" 2>/dev/null)
lh_owner=$(stat -c %U -- "$lh_db" 2>/dev/null | tr -c 'A-Za-z0-9_.@-' '?'); [ -z "$lh_owner" ] && lh_owner=$(stat -c %u -- "$lh_db" 2>/dev/null)
lh_mtime=$(stat -c %Y -- "$lh_db" 2>/dev/null)
lh_wal=false; [ -e "$lh_db-wal" ] && lh_wal=true
lh_shm=false; [ -e "$lh_db-shm" ] && lh_shm=true
printf 'LH-FILE {"size":%s,"mtimeEpoch":%s,"owner":"%s","mode":"%s","wal":%s,"shm":%s}\n' "${lh_size:-0}" "${lh_mtime:-0}" "${lh_owner:-?}" "${lh_mode:-?}" "$lh_wal" "$lh_shm"
lh_immutable=''
lh_open || exit 0
if [ "$lh_op" = "inspect" ]; then
  sqlite3 $lh_flags "$lh_db" "SELECT json_object('name',name,'kind',type,'sql',COALESCE(sql,''),'rows',null) FROM sqlite_master WHERE type IN ('table','view') ORDER BY name" 2>/dev/null | head -n __MAX_TABLES__ | sed 's/^/LH-TABLE /'
  lh_t0=$(date +%s)
  sqlite3 $lh_flags "$lh_db" "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name" 2>/dev/null | head -n __MAX_TABLES__ | while IFS= read -r lh_n; do
    [ $(( $(date +%s) - lh_t0 )) -gt 6 ] && break
    lh_e=$(printf '%s' "$lh_n" | sed 's/"/""/g')
    lh_h=$(printf '%s' "$lh_n" | od -A n -v -t x1 | tr -d ' \n')
    if command -v timeout >/dev/null 2>&1; then
      lh_c=$(timeout 3 sqlite3 $lh_flags "$lh_db" "SELECT COUNT(*) FROM \"$lh_e\"" 2>/dev/null)
    else
      lh_c=$(sqlite3 $lh_flags "$lh_db" "SELECT COUNT(*) FROM \"$lh_e\"" 2>/dev/null)
    fi
    [ -n "$lh_c" ] && echo "LH-TCOUNT $lh_h=$lh_c" || echo "LH-TCOUNT $lh_h=?"
  done
elif [ "$lh_op" = "rows" ]; then
  lh_found=$(sqlite3 $lh_flags "$lh_db" "SELECT 1 FROM sqlite_master WHERE name='$lh_escq' AND type IN ('table','view')" 2>/dev/null | head -n 1)
  if [ -z "$lh_found" ]; then
    echo 'LH-ERR {"code":"no-table","message":"表不存在或已变化，请重新打开"}'
    exit 0
  fi
  lh_cols=$(sqlite3 $lh_flags "$lh_db" "PRAGMA table_info(\"$lh_esc\")" 2>/dev/null)
  lh_rid=0
  sqlite3 $lh_flags "$lh_db" "SELECT rowid FROM \"$lh_esc\" LIMIT 0" >/dev/null 2>&1 && lh_rid=1
  while IFS='|' read -r lh_cid lh_cn lh_rest; do
    [ "$(printf '%s' "$lh_cn" | tr 'A-Z' 'a-z')" = "rowid" ] && lh_rid=0
  done <<LH_COLS
$lh_cols
LH_COLS
  lh_sel=''
  if [ "$lh_rid" = 1 ]; then
    echo 'LH-COL {"name":"rowid","decl":"","rowid":true}'
    lh_sel='rowid'
  fi
  sqlite3 $lh_flags -list "$lh_db" "SELECT json_object('name',name,'decl',type,'rowid',json('false')) FROM pragma_table_info('$lh_escq')" 2>/dev/null | sed 's/^/LH-COL /'
  while IFS='|' read -r lh_cid lh_cn lh_rest; do
    lh_ne=$(printf '%s' "$lh_cn" | sed 's/"/""/g')
    lh_e="\"$lh_ne\""
    lh_sel="$lh_sel, CASE WHEN typeof($lh_e)='blob' THEN json_object('b',length($lh_e),'h',lower(hex(substr($lh_e,1,32)))) WHEN typeof($lh_e)='text' AND length($lh_e)>1024 THEN json_object('t',1,'v',substr($lh_e,1,1024)) ELSE $lh_e END"
  done <<LH_COLS2
$lh_cols
LH_COLS2
  lh_out=$(sqlite3 $lh_flags -list "$lh_db" "SELECT json_array(${lh_sel#,}) FROM \"$lh_esc\" LIMIT 100 OFFSET $lh_off" 2>/dev/null | head -c __OUTPUT_CAP__)
  printf '%s\n' "$lh_out" | sed 's/^/LH-ROW /'
  lh_len=$(printf '%s' "$lh_out" | wc -c)
  [ "$lh_len" -gt __EMIT_CAP__ ] && echo 'LH-END {"truncated":true}' || echo 'LH-END {"truncated":false}'
  exit 0
fi
echo 'LH-END {"truncated":false}'
"##;

/// Builds the whole view command: engine probe, python3 branch, CLI branch,
/// refusal marker. Path and table go through argv/variables shell-quoted once.
pub fn build_view_command(path: &RemotePath, op: &SqliteViewOp) -> CoreResult<String> {
    let (op_name, table, offset) = match op {
        SqliteViewOp::Inspect => ("inspect".to_owned(), String::new(), 0_u32),
        SqliteViewOp::Rows { table, offset } => {
            validate_table_name(table)?;
            ("rows".to_owned(), table.clone(), *offset)
        }
    };
    if offset > 100_000 {
        return Err(CoreError::validation(
            "sqlite rows offset",
            "must be at most 100000",
        ));
    }
    let py = PY_VIEW
        .replace("__EMIT_CAP__", &EMIT_CAP_BYTES.to_string())
        .replace("__MAX_TABLES__", &MAX_TABLES.to_string());
    let sh_cli = SH_CLI_VIEW
        .replace("__MAX_TABLES__", &MAX_TABLES.to_string())
        .replace("__EMIT_CAP__", &EMIT_CAP_BYTES.to_string())
        .replace("__OUTPUT_CAP__", &(OUTPUT_CAP_BYTES + 1).to_string());
    let command = format!(
        "lh_db={db}\nlh_op={op}\nlh_table={table}\nlh_off={offset}\n\
         if command -v python3 >/dev/null 2>&1; then\n\
         \x20 python3 -I - \"$lh_db\" \"$lh_op\" \"$lh_table\" \"$lh_off\" <<'LH_PY'\n{py}\nLH_PY\n\
         elif command -v sqlite3 >/dev/null 2>&1 && \
         awk -v v=\"$(sqlite3 -version 2>/dev/null | awk '{{print $1}}')\" \
         'BEGIN{{split(v,a,\".\"); exit !(a[1]>3 || (a[1]==3 && a[2]>=33))}}'; then\n\
         {sh_cli}\n\
         else\n\
         \x20 echo 'LH-ERR {{\"code\":\"no-engine\",\"message\":\"需要目标上有 python3 或 sqlite3 3.33 以上\"}}'\n\
         fi\n",
        db = shq(path.as_str()),
        op = shq(&op_name),
        table = shq(&table),
        offset = offset,
        py = py,
        sh_cli = sh_cli,
    );
    Ok(command)
}

fn bounded_text(text: &str) -> String {
    const CAP: usize = 2048;
    if text.len() <= CAP {
        return text.to_owned();
    }
    let mut end = CAP;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn hex_to_name(hex: &str) -> Option<String> {
    if !hex.len().is_multiple_of(2) || hex.len() > 2048 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

#[derive(Deserialize)]
struct WireEngine {
    engine: String,
    #[serde(rename = "sqliteVersion")]
    sqlite_version: Option<String>,
    immutable: Option<bool>,
}

#[derive(Deserialize)]
struct WireFile {
    size: Option<u64>,
    #[serde(rename = "mtimeEpoch")]
    mtime_epoch: Option<u64>,
    owner: Option<String>,
    mode: Option<String>,
    wal: Option<bool>,
    shm: Option<bool>,
}

#[derive(Deserialize)]
struct WireTable {
    name: String,
    kind: Option<String>,
    sql: Option<String>,
    rows: Option<u64>,
}

#[derive(Deserialize)]
struct WireCol {
    name: String,
    decl: Option<String>,
    rowid: Option<bool>,
}

#[derive(Deserialize)]
struct WireNote {
    text: String,
}

#[derive(Deserialize)]
struct WireEnd {
    truncated: Option<bool>,
}

#[derive(Deserialize)]
struct WireErr {
    code: String,
}

fn parse_json<'a, T: Deserialize<'a>>(tag: &str, payload: &'a str) -> Result<T, SqliteViewError> {
    serde_json::from_str(payload)
        .map_err(|_| SqliteViewError::Unparseable(format!("{tag} payload is not JSON")))
}

/// Parses the `LH-` protocol. Non-LH lines are ignored: the remote shell can
/// print warnings around the records and the result still parses.
pub fn parse_view_output(
    op: &SqliteViewOp,
    output: &str,
) -> Result<SqliteViewResult, SqliteViewError> {
    let mut engine: Option<SqliteEngineInfo> = None;
    let mut file: Option<SqliteFileInfo> = None;
    let mut tables: Vec<SqliteTableRow> = Vec::new();
    let mut counts: Vec<(String, Option<u64>)> = Vec::new();
    let mut columns: Vec<SqliteColumn> = Vec::new();
    let mut rows: Vec<Vec<SqliteCell>> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut truncated = false;
    let mut tables_truncated = false;
    let mut ended = false;
    let mut row_truncated = false;

    for line in output.lines().take(200_000) {
        let Some((tag, payload)) = line.split_once(' ') else {
            continue;
        };
        if !tag.starts_with("LH-") {
            continue;
        }
        match &tag[3..] {
            "ERR" => {
                let err = parse_json::<WireErr>(tag, payload)?;
                return Err(match err.code.as_str() {
                    "no-engine" => SqliteViewError::NoEngine,
                    "not-sqlite" => SqliteViewError::NotSqlite,
                    "no-table" => SqliteViewError::NoTable,
                    "no-file" => SqliteViewError::NoFile,
                    other => SqliteViewError::Unparseable(other.to_owned()),
                });
            }
            "ENGINE" => {
                let parsed = parse_json::<WireEngine>(tag, payload)?;
                engine = Some(SqliteEngineInfo {
                    engine: parsed.engine,
                    sqlite_version: parsed.sqlite_version.unwrap_or_default(),
                    immutable: parsed.immutable.unwrap_or(false),
                });
            }
            "FILE" => {
                let parsed = parse_json::<WireFile>(tag, payload)?;
                file = Some(SqliteFileInfo {
                    size: parsed.size.unwrap_or(0),
                    mtime_epoch: parsed.mtime_epoch.unwrap_or(0),
                    owner: parsed.owner.unwrap_or_else(|| "?".to_owned()),
                    mode: parsed.mode.unwrap_or_else(|| "?".to_owned()),
                    wal: parsed.wal.unwrap_or(false),
                    shm: parsed.shm.unwrap_or(false),
                });
            }
            "NOTE" => {
                if notes.len() < 32 {
                    notes.push(bounded_text(&parse_json::<WireNote>(tag, payload)?.text));
                }
            }
            "TABLE" => {
                if tables.len() >= MAX_TABLES {
                    tables_truncated = true;
                    continue;
                }
                let parsed = parse_json::<WireTable>(tag, payload)?;
                tables.push(SqliteTableRow {
                    name: parsed.name,
                    kind: parsed.kind.unwrap_or_else(|| "table".to_owned()),
                    sql: bounded_text(parsed.sql.as_deref().unwrap_or("")),
                    rows: parsed.rows,
                });
            }
            "TCOUNT" => {
                if let Some((hex, value)) = payload.split_once('=')
                    && let Some(name) = hex_to_name(hex)
                {
                    let count = if value == "?" {
                        None
                    } else {
                        value.parse::<u64>().ok()
                    };
                    counts.push((name, count));
                }
            }
            "COL" => {
                if columns.len() < 512 {
                    let parsed = parse_json::<WireCol>(tag, payload)?;
                    columns.push(SqliteColumn {
                        name: parsed.name,
                        declared_type: parsed.decl.unwrap_or_default(),
                        rowid: parsed.rowid.unwrap_or(false),
                    });
                }
            }
            "ROW" => {
                if let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(payload) {
                    rows.push(values.iter().map(SqliteCell::parse).collect());
                } else {
                    // A row cut by the remote byte cap is dropped, not parsed
                    // into invented cells.
                    row_truncated = true;
                }
            }
            "END" => {
                ended = true;
                truncated = parse_json::<WireEnd>(tag, payload)?
                    .truncated
                    .unwrap_or(false);
            }
            _ => {}
        }
    }

    for (name, count) in counts {
        if let Some(table) = tables.iter_mut().find(|row| row.name == name) {
            table.rows = count;
        }
    }
    let engine = engine.ok_or_else(|| {
        SqliteViewError::Unparseable("no engine record in output".to_owned())
    })?;
    if !ended {
        return Err(SqliteViewError::Unparseable(
            "output ended without an END record".to_owned(),
        ));
    }

    match op {
        SqliteViewOp::Inspect => {
            let file = file.ok_or_else(|| {
                SqliteViewError::Unparseable("inspect output lacks file info".to_owned())
            })?;
            Ok(SqliteViewResult::Inspect {
                engine,
                file,
                tables,
                tables_truncated: tables_truncated || truncated,
                notes,
            })
        }
        SqliteViewOp::Rows { .. } => Ok(SqliteViewResult::Rows {
            engine,
            columns,
            rows,
            truncated: truncated || row_truncated,
            notes,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> RemotePath {
        RemotePath::new("/var/lib/app/cam.db").unwrap()
    }

    #[test]
    fn view_command_is_self_contained_and_quotes_everything() {
        for op in [
            SqliteViewOp::Inspect,
            SqliteViewOp::Rows {
                table: "a\"b; drop".to_owned(),
                offset: 200,
            },
        ] {
            let command = build_view_command(&path(), &op).unwrap();
            assert!(command.contains("python3 -I - \"$lh_db\""));
            assert!(command.contains("sqlite3 -version"));
            assert!(command.contains("no-engine"));
            assert!(command.contains("LH_PY"));
            assert!(!command.contains("sudo"));
        }
        let command = build_view_command(
            &path(),
            &SqliteViewOp::Rows {
                table: "a\"b; drop".to_owned(),
                offset: 0,
            },
        )
        .unwrap();
        assert!(command.contains("lh_table='a\"b; drop'"));
    }

    #[test]
    fn table_name_validation_bounds_and_rejects_controls() {
        for bad in ["", &"x".repeat(513), "a\nb", "a\rb"] {
            assert!(validate_table_name(bad).is_err(), "{bad:?}");
        }
        validate_table_name("cam sessions").unwrap();
        validate_table_name("a\"b; drop").unwrap();
    }

    #[test]
    fn inspect_output_parses_python_engine_records() {
        let output = concat!(
            "LH-BEGIN {\"op\":\"inspect\"}\n",
            "LH-FILE {\"size\":4096,\"mtimeEpoch\":1700000000,\"owner\":\"app\",\"mode\":\"644\",\"wal\":true,\"shm\":false}\n",
            "LH-NOTE {\"text\":\"以不可变方式读取，可能看不到尚未合并到主文件的写入\"}\n",
            "LH-ENGINE {\"engine\":\"python3\",\"sqliteVersion\":\"3.40.1\",\"immutable\":true}\n",
            "LH-TABLE {\"name\":\"sessions\",\"kind\":\"table\",\"sql\":\"CREATE TABLE sessions(id)\",\"rows\":3}\n",
            "LH-TABLE {\"name\":\"users\",\"kind\":\"view\",\"sql\":\"CREATE VIEW users AS\",\"rows\":null}\n",
            "LH-END {\"truncated\":false}\n"
        );
        let result = parse_view_output(&SqliteViewOp::Inspect, output).unwrap();
        let SqliteViewResult::Inspect {
            engine,
            file,
            tables,
            notes,
            ..
        } = result
        else {
            panic!("expected inspect");
        };
        assert!(engine.immutable);
        assert_eq!(engine.engine, "python3");
        assert!(file.wal);
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].rows, Some(3));
        assert_eq!(tables[1].rows, None);
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn cli_engine_tcounts_merge_into_tables() {
        let output = concat!(
            "LH-BEGIN {\"op\":\"inspect\"}\n",
            "LH-FILE {\"size\":4096,\"mtimeEpoch\":1700000000,\"owner\":\"root\",\"mode\":\"600\",\"wal\":false,\"shm\":false}\n",
            "LH-ENGINE {\"engine\":\"sqlite3\",\"sqliteVersion\":\"3.34.1\",\"immutable\":false}\n",
            "LH-TABLE {\"name\":\"audit\",\"kind\":\"table\",\"sql\":\"CREATE TABLE audit(id)\",\"rows\":null}\n",
            "LH-TCOUNT 6175646974=412\n",
            "LH-END {\"truncated\":false}\n"
        );
        let SqliteViewResult::Inspect { tables, .. } =
            parse_view_output(&SqliteViewOp::Inspect, output).unwrap()
        else {
            panic!("expected inspect");
        };
        assert_eq!(tables[0].rows, Some(412));
    }

    #[test]
    fn rows_output_parses_cells_and_rowid() {
        let output = concat!(
            "LH-BEGIN {\"op\":\"rows\"}\n",
            "LH-ENGINE {\"engine\":\"python3\",\"sqliteVersion\":\"3.40.1\",\"immutable\":false}\n",
            "LH-COL {\"name\":\"rowid\",\"decl\":\"\",\"rowid\":true}\n",
            "LH-COL {\"name\":\"name\",\"decl\":\"TEXT\",\"rowid\":false}\n",
            "LH-ROW [7,\"alice\",null,1.5]\n",
            "LH-ROW [8,{\"t\":1,\"v\":\"cut\"},{\"b\":40,\"h\":\"aabb\"},9]\n",
            "LH-END {\"truncated\":false}\n"
        );
        let SqliteViewResult::Rows { columns, rows, .. } = parse_view_output(
            &SqliteViewOp::Rows {
                table: "users".to_owned(),
                offset: 0,
            },
            output,
        )
        .unwrap()
        else {
            panic!("expected rows");
        };
        assert!(columns[0].rowid);
        assert_eq!(rows.len(), 2);
        assert!(matches!(rows[0][0], SqliteCell::Integer(7)));
        assert!(matches!(rows[0][1], SqliteCell::Text(ref t) if t == "alice"));
        assert!(matches!(rows[1][1], SqliteCell::TruncatedText(ref t) if t == "cut"));
        assert!(matches!(rows[1][2], SqliteCell::Blob { bytes: 40, .. }));
    }

    #[test]
    fn a_broken_row_line_is_dropped_and_marked() {
        let output = concat!(
            "LH-ENGINE {\"engine\":\"python3\",\"sqliteVersion\":\"3.40.1\",\"immutable\":false}\n",
            "LH-ROW [1,\"ok\"]\n",
            "LH-ROW [2,\"cu\n",
            "LH-END {\"truncated\":true}\n"
        );
        let SqliteViewResult::Rows { rows, truncated, .. } = parse_view_output(
            &SqliteViewOp::Rows {
                table: "t".to_owned(),
                offset: 0,
            },
            output,
        )
        .unwrap()
        else {
            panic!("expected rows");
        };
        assert_eq!(rows.len(), 1);
        assert!(truncated);
    }

    #[test]
    fn refusal_markers_map_to_errors() {
        for (payload, expected) in [
            ("no-engine", SqliteViewError::NoEngine),
            ("not-sqlite", SqliteViewError::NotSqlite),
            ("no-table", SqliteViewError::NoTable),
            ("no-file", SqliteViewError::NoFile),
        ] {
            let output = format!("LH-ERR {{\"code\":\"{payload}\"}}\n");
            let err = parse_view_output(&SqliteViewOp::Inspect, &output).unwrap_err();
            assert_eq!(err, expected, "{payload}");
        }
    }

    #[test]
    fn output_without_engine_or_end_is_untrusted() {
        for output in ["", "LH-BEGIN {}\nLH-ROW [1]\n", "LH-ENGINE {}\n"] {
            assert!(
                matches!(
                    parse_view_output(&SqliteViewOp::Inspect, output),
                    Err(SqliteViewError::Unparseable(_))
                ),
                "{output:?}"
            );
        }
    }

    #[test]
    fn hex_to_name_decodes_and_bounds() {
        assert_eq!(hex_to_name("6175646974"), Some("audit".to_owned()));
        assert_eq!(hex_to_name("f09f9880"), Some("😀".to_owned()));
        assert_eq!(hex_to_name("0"), None);
        assert_eq!(hex_to_name("zz"), None);
        assert_eq!(hex_to_name(&"61".repeat(2000)), None);
    }
}

// =========================================================================
// P1-5b — bounded row deletion.
//
// Plan: a probe re-reads the chosen rows by rowid, binds each row's canonical
// values and hash, plus the file's sha256 and size. Execute re-checks the file
// hash, backs the database up with the sqlite online backup API, verifies
// every row still matches its bound hash inside one IMMEDIATE transaction,
// deletes, commits and independently verifies. Undo re-inserts the saved
// values — including rowids — in one transaction. Everything runs through
// python3 only; the CLI engine cannot do an online backup.
// =========================================================================

/// Row selection is operator-bounded, not result-bounded.
pub const DELETE_MAX_ROWS: usize = 50;
/// Canonical values travel inside the plan; a row too large to bind is
/// refused rather than silently truncated, because undo needs every byte.
const ROW_CANONICAL_CAP_BYTES: usize = 16 * 1024;
/// Whole plan payload cap for the execute/undo command argv.
const PLAN_PAYLOAD_CAP_BYTES: usize = 512 * 1024;

/// One row's identity for the delete plan.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundRowDelete {
    pub rowid: i64,
    /// sha256 of the row's canonical JSON, as computed on the target.
    pub hash: String,
    /// Full canonical JSON array — needed only by undo.
    pub canonical: String,
    /// Bounded display form for the plan summary.
    pub display: Vec<SqliteCell>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqliteDeleteProbe {
    pub file_sha256: String,
    pub file_size: u64,
    pub has_rowid: bool,
    pub columns: Vec<SqliteColumn>,
    /// Rows the target still has with the requested rowids, in request order.
    /// A rowid that vanished between grid and plan is reported, not invented.
    pub rows: Vec<BoundRowDelete>,
    pub missing_rowids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SqliteDeleteStage {
    /// File changed since the plan was confirmed — re-plan.
    StaleFile,
    /// At least one bound row no longer matches — nothing was deleted.
    RowChanged,
    /// The table has no usable rowid.
    NoRowid,
    NoTable,
    NoPython,
    /// Backup or transaction failed before any delete.
    Failed(String),
    /// Deleted N rows and independently verified it.
    Deleted(u32),
    /// Undo refused: one of the rowids already exists again.
    RowidExists,
    /// Undo re-inserted N rows and verified them.
    Restored(u32),
}

impl SqliteDeleteStage {
    pub fn code(&self) -> &'static str {
        match self {
            SqliteDeleteStage::StaleFile => "sqlite-delete-stale-file",
            SqliteDeleteStage::RowChanged => "sqlite-delete-row-changed",
            SqliteDeleteStage::NoRowid => "sqlite-delete-no-rowid",
            SqliteDeleteStage::NoTable => "sqlite-no-table",
            SqliteDeleteStage::NoPython => "sqlite-delete-no-python",
            SqliteDeleteStage::Failed(_) => "sqlite-delete-failed",
            SqliteDeleteStage::Deleted(_) => "sqlite-delete-done",
            SqliteDeleteStage::RowidExists => "sqlite-undo-rowid-exists",
            SqliteDeleteStage::Restored(_) => "sqlite-undo-done",
        }
    }
}

fn canonical_cell(cell: &serde_json::Value) -> String {
    // Compact JSON, sorted-free but deterministic because emitters build the
    // map in a fixed key order through tagged objects.
    serde_json::to_string(cell).unwrap_or_else(|_| "null".to_owned())
}

/// Probe command: file identity + the requested rows re-read by rowid.
/// Emits `LH-FILEHASH`, `LH-COL`, `LH-ROWDATA` and `LH-MISSING` records.
pub fn build_delete_probe_command(
    path: &RemotePath,
    table: &str,
    rowids: &[i64],
) -> CoreResult<String> {
    validate_table_name(table)?;
    if rowids.is_empty() || rowids.len() > DELETE_MAX_ROWS {
        return Err(CoreError::validation(
            "sqlite row selection",
            "must select 1..=50 rows",
        ));
    }
    if rowids.iter().any(|id| *id < 0) {
        return Err(CoreError::validation("sqlite rowid", "must be non-negative"));
    }
    let rid_list = rowids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let command = format!(
        "lh_db={db}\nlh_table={table}\n\
         if command -v python3 >/dev/null 2>&1; then\n\
         \x20 python3 -I - \"$lh_db\" \"$lh_table\" {rid_list} <<'LH_PY'\n{py}\nLH_PY\n\
         else\n\
         \x20 echo 'LH-ERR {{\"code\":\"no-python\",\"message\":\"删除行需要目标上有 python3（SQLite 备份与事务校验依赖它）\"}}'\n\
         fi\n",
        db = shq(path.as_str()),
        table = shq(table),
        rid_list = rid_list,
        py = PY_PROBE_DELETE.replace("__EMIT_CAP__", &EMIT_CAP_BYTES.to_string()),
    );
    Ok(command)
}

const PY_PROBE_DELETE: &str = r##"
import sys, os, json, sqlite3, hashlib

path, table = sys.argv[1], sys.argv[2]
want = [int(x) for x in sys.argv[3:] if x]
EMIT_CAP = __EMIT_CAP__
written = 0

def emit(tag, obj):
    global written
    line = "LH-%s %s\n" % (tag, json.dumps(obj, ensure_ascii=False))
    if written + len(line.encode("utf-8", "replace")) > EMIT_CAP:
        return
    written += len(line.encode("utf-8", "replace"))
    sys.stdout.write(line)

def canon(v):
    if v is None:
        return {"n": 1}
    if isinstance(v, bool):
        return {"i": int(v)}
    if isinstance(v, int):
        return {"i": v}
    if isinstance(v, float):
        return {"r": repr(v)}
    if isinstance(v, bytes):
        return {"b": v.hex()}
    return {"s": v}

def display(v):
    if v is None:
        return None
    if isinstance(v, bytes):
        return {"b": len(v), "h": v[:32].hex()}
    if isinstance(v, str) and len(v) > 1024:
        return {"t": 1, "v": v[:1024]}
    return v

def ident(name):
    return '"%s"' % name.replace('"', '""')

def rowhash(cells):
    return hashlib.sha256(
        json.dumps(cells, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

emit("BEGIN", {"op": "delete-probe"})
try:
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    emit("FILEHASH", {"sha256": digest, "size": os.stat(path).st_size})
except Exception:
    emit("ERR", {"code": "no-file", "message": "文件不可读或不存在"})
    raise SystemExit(0)
conn = sqlite3.connect(path)
found = conn.execute(
    "SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone()
if found is None:
    emit("ERR", {"code": "no-table", "message": "表不存在或已变化，请重新打开"})
    raise SystemExit(0)
cols = conn.execute("PRAGMA table_info(%s)" % ident(table)).fetchall()
has_rowid = not any(c[1].lower() == "rowid" for c in cols)
if has_rowid:
    try:
        conn.execute("SELECT rowid FROM %s LIMIT 0" % ident(table)).fetchone()
    except Exception:
        has_rowid = False
if not has_rowid:
    emit("ERR", {"code": "no-rowid",
                 "message": "这个表没有 rowid（WITHOUT ROWID 或被列名占用），不支持按行删除"})
    raise SystemExit(0)
emit("COL", {"name": "rowid", "decl": "", "rowid": True})
for c in cols:
    emit("COL", {"name": c[1], "decl": c[2] or "", "rowid": False})
select = ",".join(["rowid"] + [ident(c[1]) for c in cols])
for rid in want:
    row = conn.execute(
        "SELECT %s FROM %s WHERE rowid=?" % (select, ident(table)), (rid,)).fetchone()
    if row is None:
        emit("MISSING", {"rowid": rid})
        continue
    cells = [canon(v) for v in row[1:]]
    emit("ROWDATA", {"rowid": rid, "hash": rowhash(cells),
                     "cells": cells,
                     "display": [display(v) for v in row]})
emit("END", {"truncated": False})
"##;

/// Execute command: identity re-check, online backup, one IMMEDIATE
/// transaction that re-verifies every bound hash then deletes.
pub fn build_delete_execute_command(
    path: &RemotePath,
    table: &str,
    plan_id: &str,
    file_sha256: &str,
    file_size: u64,
    rows: &[(i64, String)],
) -> CoreResult<String> {
    validate_table_name(table)?;
    if rows.is_empty() || rows.len() > DELETE_MAX_ROWS {
        return Err(CoreError::validation(
            "sqlite row selection",
            "must delete 1..=50 rows",
        ));
    }
    for (rid, hash) in rows {
        if *rid < 0 || hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CoreError::validation(
                "sqlite bound row",
                "rowid must be non-negative and hash a sha256 hex string",
            ));
        }
    }
    if file_sha256.len() != 64 || !file_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CoreError::validation("sqlite file hash", "must be sha256 hex"));
    }
    let bound = serde_json::to_string(rows)
        .map_err(|_| CoreError::validation("sqlite bound rows", "unserializable"))?;
    if bound.len() > PLAN_PAYLOAD_CAP_BYTES {
        return Err(CoreError::validation(
            "sqlite bound rows",
            "bound row payload exceeds 512 KiB",
        ));
    }
    let command = format!(
        "lh_db={db}\nlh_table={table}\nlh_plan={plan}\nlh_sha={sha}\nlh_size={size}\n\
         lh_bound={bound}\n\
         if command -v python3 >/dev/null 2>&1; then\n\
         \x20 python3 -I - \"$lh_db\" \"$lh_table\" \"$lh_plan\" \"$lh_sha\" \"$lh_size\" \"$lh_bound\" <<'LH_PY'\n{py}\nLH_PY\n\
         else\n\
         \x20 echo 'LH-ERR {{\"code\":\"no-python\",\"message\":\"删除行需要目标上有 python3（SQLite 备份与事务校验依赖它）\"}}'\n\
         fi\n",
        db = shq(path.as_str()),
        table = shq(table),
        plan = shq(plan_id),
        sha = shq(file_sha256),
        size = file_size,
        bound = shq(&bound),
        py = PY_EXECUTE_DELETE,
    );
    Ok(command)
}

const PY_EXECUTE_DELETE: &str = r##"
import sys, os, json, sqlite3, hashlib

path, table, plan_id, expect_sha, expect_size, bound_json = sys.argv[1:7]
expect_size = int(expect_size)
bound = json.loads(bound_json)

def emit(tag, obj):
    sys.stdout.write("LH-%s %s\n" % (tag, json.dumps(obj, ensure_ascii=False)))

def canon(v):
    if v is None:
        return {"n": 1}
    if isinstance(v, bool):
        return {"i": int(v)}
    if isinstance(v, int):
        return {"i": v}
    if isinstance(v, float):
        return {"r": repr(v)}
    if isinstance(v, bytes):
        return {"b": v.hex()}
    return {"s": v}

def ident(name):
    return '"%s"' % name.replace('"', '""')

def rowhash(cells):
    return hashlib.sha256(
        json.dumps(cells, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

emit("BEGIN", {"op": "delete"})
try:
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != expect_sha or os.stat(path).st_size != expect_size:
        emit("ERR", {"code": "stale-file",
                     "message": "数据库文件在确认后被写入了（哈希或大小变化），没有动任何行；请重新规划"})
        raise SystemExit(0)
except SystemExit:
    raise
except Exception:
    emit("ERR", {"code": "no-file", "message": "文件不可读或不存在"})
    raise SystemExit(0)

st = os.stat(path)
backup_dir = os.path.join(os.path.dirname(path) or "/", ".lovelyres-backups")
backup = os.path.join(backup_dir, "%s.%s.bak" % (os.path.basename(path), plan_id))
try:
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    source = sqlite3.connect("file:%s?mode=ro" % path, uri=False)
    target = sqlite3.connect(backup)
    source.backup(target)
    target.close()
    source.close()
    os.chmod(backup, st.st_mode & 0o777 if st.st_mode else 0o600)
except Exception:
    emit("ERR", {"code": "backup-failed", "message": "备份数据库失败，没有动任何行"})
    raise SystemExit(0)

conn = sqlite3.connect(path)
try:
    conn.execute("BEGIN IMMEDIATE")
    select = ",".join(
        ["rowid"] + [ident(c[1]) for c in
        conn.execute("PRAGMA table_info(%s)" % ident(table)).fetchall()])
    for rid, expect_hash in bound:
        row = conn.execute(
            "SELECT %s FROM %s WHERE rowid=?" % (select, ident(table)), (rid,)).fetchone()
        if row is None or rowhash([canon(v) for v in row[1:]]) != expect_hash:
            conn.execute("ROLLBACK")
            emit("ERR", {"code": "row-changed",
                         "message": "某一行在确认后发生了变化，没有动任何行；请重新打开并重新规划"})
            raise SystemExit(0)
    for rid, _ in bound:
        conn.execute("DELETE FROM %s WHERE rowid=?" % ident(table), (rid,))
    conn.execute("COMMIT")
except SystemExit:
    raise
except Exception:
    try:
        conn.execute("ROLLBACK")
    except Exception:
        pass
    emit("ERR", {"code": "txn-failed", "message": "删除事务失败，没有动任何行"})
    raise SystemExit(0)

remaining = conn.execute(
    "SELECT COUNT(*) FROM %s WHERE rowid IN (%s)"
    % (ident(table), ",".join(str(r) for r, _ in bound))).fetchone()[0]
if remaining == 0:
    emit("DONE", {"code": "deleted", "count": len(bound), "backup": backup})
else:
    emit("ERR", {"code": "verify-failed",
                 "message": "删除后复核仍能看到这些 rowid，请人工检查"})
"##;

/// Undo command: re-inserts the bound values with their original rowids in one
/// transaction, refusing when a rowid already exists again.
pub fn build_delete_undo_command(
    path: &RemotePath,
    table: &str,
    rows: &[(i64, String)],
) -> CoreResult<String> {
    validate_table_name(table)?;
    if rows.is_empty() || rows.len() > DELETE_MAX_ROWS {
        return Err(CoreError::validation(
            "sqlite undo rows",
            "must restore 1..=50 rows",
        ));
    }
    for (rid, canonical) in rows {
        if *rid < 0 || canonical.len() > ROW_CANONICAL_CAP_BYTES {
            return Err(CoreError::validation(
                "sqlite undo row",
                "rowid must be non-negative and canonical payload bounded",
            ));
        }
    }
    let payload = serde_json::to_string(rows)
        .map_err(|_| CoreError::validation("sqlite undo rows", "unserializable"))?;
    if payload.len() > PLAN_PAYLOAD_CAP_BYTES {
        return Err(CoreError::validation(
            "sqlite undo rows",
            "undo payload exceeds 512 KiB",
        ));
    }
    let command = format!(
        "lh_db={db}\nlh_table={table}\nlh_rows={rows}\n\
         if command -v python3 >/dev/null 2>&1; then\n\
         \x20 python3 -I - \"$lh_db\" \"$lh_table\" \"$lh_rows\" <<'LH_PY'\n{py}\nLH_PY\n\
         else\n\
         \x20 echo 'LH-ERR {{\"code\":\"no-python\",\"message\":\"恢复行需要目标上有 python3\"}}'\n\
         fi\n",
        db = shq(path.as_str()),
        table = shq(table),
        rows = shq(&payload),
        py = PY_UNDO_DELETE,
    );
    Ok(command)
}

const PY_UNDO_DELETE: &str = r##"
import sys, json, sqlite3

path, table, rows_json = sys.argv[1:4]
saved = json.loads(rows_json)

def emit(tag, obj):
    sys.stdout.write("LH-%s %s\n" % (tag, json.dumps(obj, ensure_ascii=False)))

def decanon(cell):
    if "n" in cell:
        return None
    if "i" in cell:
        return cell["i"]
    if "r" in cell:
        return float(cell["r"])
    if "b" in cell:
        return bytes.fromhex(cell["b"])
    return cell.get("s", "")

def ident(name):
    return '"%s"' % name.replace('"', '""')

emit("BEGIN", {"op": "undo"})
conn = sqlite3.connect(path)
found = conn.execute(
    "SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone()
if found is None:
    emit("ERR", {"code": "no-table", "message": "表不存在或已变化，无法恢复"})
    raise SystemExit(0)
try:
    conn.execute("BEGIN IMMEDIATE")
    cols = [c[1] for c in conn.execute("PRAGMA table_info(%s)" % ident(table)).fetchall()]
    for rid, cells_json in saved:
        exists = conn.execute(
            "SELECT 1 FROM %s WHERE rowid=?" % ident(table), (rid,)).fetchone()
        if exists is not None:
            conn.execute("ROLLBACK")
            emit("ERR", {"code": "rowid-exists",
                         "message": "被删的 rowid 里已有值重新出现，自动恢复已拒绝；请人工核对"})
            raise SystemExit(0)
    placeholders = ",".join("?" for _ in cols)
    for rid, cells_json in saved:
        cells = json.loads(cells_json)
        values = [decanon(c) for c in cells]
        if len(values) != len(cols):
            conn.execute("ROLLBACK")
            emit("ERR", {"code": "shape-changed",
                         "message": "表结构已变化，保存的行与现在的列数不一致，无法恢复"})
            raise SystemExit(0)
        conn.execute(
            "INSERT INTO %s (rowid,%s) VALUES (?,%s)"
            % (ident(table), ",".join(ident(c) for c in cols), placeholders),
            [rid] + values)
    conn.execute("COMMIT")
except SystemExit:
    raise
except Exception:
    try:
        conn.execute("ROLLBACK")
    except Exception:
        pass
    emit("ERR", {"code": "txn-failed", "message": "恢复事务失败"})
    raise SystemExit(0)
emit("DONE", {"code": "restored", "count": len(saved)})
"##;

/// Parses `LH-FILEHASH`, `LH-COL`, `LH-ROWDATA`, `LH-MISSING` probe records.
pub fn parse_delete_probe_output(
    output: &str,
    want: &[i64],
) -> Result<SqliteDeleteProbe, SqliteDeleteStage> {
    let mut sha = None;
    let mut size = 0_u64;
    let mut columns = Vec::new();
    let mut rows = Vec::new();
    let mut missing = Vec::new();
    for line in output.lines().take(200_000) {
        let Some((tag, payload)) = line.split_once(' ') else {
            continue;
        };
        if !tag.starts_with("LH-") {
            continue;
        }
        match &tag[3..] {
            "ERR" => {
                if let Ok(err) = serde_json::from_str::<WireErr>(payload) {
                    return Err(match err.code.as_str() {
                        "no-python" => SqliteDeleteStage::NoPython,
                        "no-table" => SqliteDeleteStage::NoTable,
                        "no-rowid" => SqliteDeleteStage::NoRowid,
                        other => SqliteDeleteStage::Failed(other.to_owned()),
                    });
                }
                return Err(SqliteDeleteStage::Failed("opaque".to_owned()));
            }
            "FILEHASH" => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload) {
                    sha = parsed
                        .get("sha256")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    size = parsed
                        .get("size")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                }
            }
            "COL" => {
                if let Ok(parsed) = serde_json::from_str::<WireCol>(payload) {
                    columns.push(SqliteColumn {
                        name: parsed.name,
                        declared_type: parsed.decl.unwrap_or_default(),
                        rowid: parsed.rowid.unwrap_or(false),
                    });
                }
            }
            "ROWDATA" => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload) {
                    let rowid = parsed
                        .get("rowid")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(-1);
                    if !want.contains(&rowid) {
                        continue;
                    }
                    let hash = parsed
                        .get("hash")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let canonical = parsed
                        .get("cells")
                        .map(canonical_cell)
                        .unwrap_or_default();
                    let display = parsed
                        .get("display")
                        .and_then(serde_json::Value::as_array)
                        .map(|cells| cells.iter().map(SqliteCell::parse).collect())
                        .unwrap_or_default();
                    if hash.len() == 64 && canonical.len() <= ROW_CANONICAL_CAP_BYTES {
                        rows.push(BoundRowDelete {
                            rowid,
                            hash,
                            canonical,
                            display,
                        });
                    }
                }
            }
            "MISSING" => {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload)
                    && let Some(rid) = parsed.get("rowid").and_then(serde_json::Value::as_i64)
                {
                    missing.push(rid);
                }
            }
            _ => {}
        }
    }
    let sha = sha.ok_or_else(|| SqliteDeleteStage::Failed("no file hash".to_owned()))?;
    let has_rowid = columns.first().is_some_and(|c| c.rowid);
    if !has_rowid {
        return Err(SqliteDeleteStage::NoRowid);
    }
    rows.sort_by_key(|row| {
        want.iter()
            .position(|id| *id == row.rowid)
            .unwrap_or(usize::MAX)
    });
    Ok(SqliteDeleteProbe {
        file_sha256: sha,
        file_size: size,
        has_rowid,
        columns,
        rows,
        missing_rowids: missing,
    })
}

/// Parses `LH-DONE`/`LH-ERR` from execute and undo runs.
pub fn parse_delete_result_output(output: &str) -> SqliteDeleteStage {
    let mut stage = SqliteDeleteStage::Failed("no result record".to_owned());
    for line in output.lines().take(200_000) {
        let Some((tag, payload)) = line.split_once(' ') else {
            continue;
        };
        if tag == "LH-ERR" {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload) {
                let code = parsed
                    .get("code")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                stage = match code {
                    "stale-file" => SqliteDeleteStage::StaleFile,
                    "row-changed" => SqliteDeleteStage::RowChanged,
                    "rowid-exists" => SqliteDeleteStage::RowidExists,
                    "no-python" => SqliteDeleteStage::NoPython,
                    "no-table" => SqliteDeleteStage::NoTable,
                    other => SqliteDeleteStage::Failed(other.to_owned()),
                };
            }
        } else if tag == "LH-DONE"
            && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload)
        {
            let count = parsed
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            stage = match parsed
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
            {
                "deleted" => SqliteDeleteStage::Deleted(count),
                "restored" => SqliteDeleteStage::Restored(count),
                other => SqliteDeleteStage::Failed(other.to_owned()),
            };
        }
    }
    stage
}

#[cfg(test)]
mod delete_tests {
    use super::*;

    fn path() -> RemotePath {
        RemotePath::new("/var/lib/app/cam.db").unwrap()
    }

    #[test]
    fn probe_command_passes_rowids_as_argv_and_quotes_path_and_table() {
        let command =
            build_delete_probe_command(&path(), "a\"b; drop", &[1, 42, 7]).unwrap();
        assert!(command.contains("python3 -I - \"$lh_db\" \"$lh_table\" 1,42,7"));
        assert!(command.contains("lh_table='a\"b; drop'"));
        assert!(command.contains("no-python"));
        assert!(!command.contains("DROP TABLE"));
        assert!(build_delete_probe_command(&path(), "t", &[]).is_err());
        assert!(build_delete_probe_command(&path(), "t", &[0; 51]).is_err());
    }

    #[test]
    fn execute_command_binds_hashes_and_refuses_bad_identity() {
        let rows = vec![(1_i64, "a".repeat(64)), (2_i64, "b".repeat(64))];
        let command = build_delete_execute_command(
            &path(),
            "sessions",
            "plan-1",
            &"f".repeat(64),
            4096,
            &rows,
        )
        .unwrap();
        assert!(command.contains("lh_plan='plan-1'"));
        assert!(command.contains("[[1,"));
        assert!(command.contains("BEGIN IMMEDIATE"));
        assert!(build_delete_execute_command(
            &path(),
            "t",
            "p",
            &"bad".to_owned(),
            1,
            &rows,
        )
        .is_err());
        assert!(build_delete_execute_command(
            &path(),
            "t",
            "p",
            &"f".repeat(64),
            1,
            &[(-1, "a".repeat(64))],
        )
        .is_err());
    }

    #[test]
    fn probe_parse_binds_rows_in_request_order_and_flags_missing() {
        let output = concat!(
            "LH-BEGIN {\"op\":\"delete-probe\"}\n",
            "LH-FILEHASH {\"sha256\":\"",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "\",\"size\":8192}\n",
            "LH-COL {\"name\":\"rowid\",\"decl\":\"\",\"rowid\":true}\n",
            "LH-COL {\"name\":\"name\",\"decl\":\"TEXT\",\"rowid\":false}\n",
            "LH-ROWDATA {\"rowid\":7,\"hash\":\"",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "\",\"cells\":[{\"s\":\"x\"}],\"display\":[\"x\",7]}\n",
            "LH-MISSING {\"rowid\":42}\n",
            "LH-END {\"truncated\":false}\n"
        );
        let probe = parse_delete_probe_output(output, &[7, 42]).unwrap();
        assert_eq!(probe.file_size, 8192);
        assert!(probe.has_rowid);
        assert_eq!(probe.rows.len(), 1);
        assert_eq!(probe.rows[0].rowid, 7);
        assert_eq!(probe.missing_rowids, vec![42]);
    }

    #[test]
    fn probe_parse_maps_refusals() {
        for (code, expected) in [
            ("no-python", SqliteDeleteStage::NoPython),
            ("no-rowid", SqliteDeleteStage::NoRowid),
            ("no-table", SqliteDeleteStage::NoTable),
        ] {
            let output = format!("LH-ERR {{\"code\":\"{code}\"}}\n");
            assert_eq!(
                parse_delete_probe_output(&output, &[1]).unwrap_err(),
                expected,
                "{code}"
            );
        }
    }

    #[test]
    fn result_parse_maps_done_and_refusals() {
        for (output, expected) in [
            (
                "LH-DONE {\"code\":\"deleted\",\"count\":3}",
                SqliteDeleteStage::Deleted(3),
            ),
            (
                "LH-DONE {\"code\":\"restored\",\"count\":2}",
                SqliteDeleteStage::Restored(2),
            ),
            (
                "LH-ERR {\"code\":\"stale-file\"}",
                SqliteDeleteStage::StaleFile,
            ),
            (
                "LH-ERR {\"code\":\"row-changed\"}",
                SqliteDeleteStage::RowChanged,
            ),
            (
                "LH-ERR {\"code\":\"rowid-exists\"}",
                SqliteDeleteStage::RowidExists,
            ),
            ("nothing useful", SqliteDeleteStage::Failed("no result record".to_owned())),
        ] {
            assert_eq!(parse_delete_result_output(output), expected, "{output}");
        }
    }

    #[test]
    fn undo_command_carries_canonical_values() {
        let rows = vec![(9_i64, "[{\"s\":\"alice\"},{\"i\":5}]".to_owned())];
        let command = build_delete_undo_command(&path(), "sessions", &rows).unwrap();
        assert!(command.contains("BEGIN IMMEDIATE"));
        assert!(command.contains("rowid-exists"));
        assert!(command.contains("INSERT INTO"));
        assert!(build_delete_undo_command(
            &path(),
            "t",
            &[(1, "x".repeat(17 * 1024))],
        )
        .is_err());
    }
}
