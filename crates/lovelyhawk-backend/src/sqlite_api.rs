//! SQLite read-only viewing and bounded row deletion.
//!
//! The page never names a path: it either hands over an SFTP entry handle from
//! an open browser or an emergency-path offer handle, both resolved through
//! the same registries the file actions use. Commands come from
//! `lovelyhawk_core::sqlite_view` and run through the bound session; the
//! `LH-` line protocol is parsed back into typed DTOs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use lovelyhawk_core::sftp::RemotePath;
use lovelyhawk_core::sqlite_view::{
    self, BoundRowDelete, SqliteCell, SqliteDeleteStage, SqliteViewOp, SqliteViewResult,
};
use lovelyhawk_core::ssh::BoundSshSession;

use crate::emergency_path_api::EmergencyPathApi;
use crate::sftp_browser_api::SftpBrowserApi;
use crate::ssh_api::SshApi;
use crate::BackendServices;

const PLAN_TTL: Duration = Duration::from_secs(600);
const UNDO_TTL: Duration = Duration::from_secs(600);
const MAX_PLANS: usize = 64;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SqliteInspectRequest {
    binding_handle: String,
    source: SqliteSourceDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SqliteRowsRequest {
    binding_handle: String,
    source: SqliteSourceDto,
    table: String,
    #[serde(default)]
    offset: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SqliteDeletePlanRequest {
    binding_handle: String,
    source: SqliteSourceDto,
    table: String,
    rowids: Vec<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SqliteDeleteRefRequest {
    binding_handle: String,
    plan_handle: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
pub(crate) enum SqliteSourceDto {
    #[serde(rename = "sftp")]
    Sftp {
        browser_handle: String,
        entry_handle: String,
    },
    #[serde(rename = "offer")]
    Offer { path_handle: String },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SqliteApiError {
    /// Handles or DTO fields failed validation.
    Invalid,
    /// The binding went away or changed identity.
    BindingUnavailable,
    /// The path handle expired or the target changed.
    PathStale,
    /// The plan handle expired, was consumed, or is not confirmed.
    PlanStale,
    /// A remote refusal with a code the UI translates.
    Refused { code: String },
    /// Output did not match the wire contract.
    Opaque,
}

impl SqliteApiError {
    fn refused(code: &str) -> Self {
        SqliteApiError::Refused {
            code: code.to_owned(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteCellDto {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hex_prefix: Option<String>,
}

impl From<&SqliteCell> for SqliteCellDto {
    fn from(cell: &SqliteCell) -> Self {
        match cell {
            SqliteCell::Null => SqliteCellDto {
                kind: "null",
                text: None,
                bytes: None,
                hex_prefix: None,
            },
            SqliteCell::Integer(v) => SqliteCellDto {
                kind: "integer",
                text: Some(v.to_string()),
                bytes: None,
                hex_prefix: None,
            },
            SqliteCell::Real(v) => SqliteCellDto {
                kind: "real",
                text: Some(v.to_string()),
                bytes: None,
                hex_prefix: None,
            },
            SqliteCell::Text(v) => SqliteCellDto {
                kind: "text",
                text: Some(v.clone()),
                bytes: None,
                hex_prefix: None,
            },
            SqliteCell::TruncatedText(v) => SqliteCellDto {
                kind: "truncated",
                text: Some(v.clone()),
                bytes: None,
                hex_prefix: None,
            },
            SqliteCell::Blob { bytes, hex_prefix } => SqliteCellDto {
                kind: "blob",
                text: None,
                bytes: Some(*bytes),
                hex_prefix: Some(hex_prefix.clone()),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteFileDto {
    size: u64,
    mtime_epoch: u64,
    owner: String,
    mode: String,
    wal: bool,
    shm: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteTableDto {
    name: String,
    kind: String,
    sql: String,
    /// Null means the count was skipped, not that the table is empty.
    rows: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteInspectResponse {
    engine: String,
    sqlite_version: String,
    immutable: bool,
    path: String,
    file: SqliteFileDto,
    tables: Vec<SqliteTableDto>,
    tables_truncated: bool,
    notes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteColumnDto {
    name: String,
    declared_type: String,
    rowid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteRowsResponse {
    engine: String,
    sqlite_version: String,
    immutable: bool,
    columns: Vec<SqliteColumnDto>,
    rows: Vec<Vec<SqliteCellDto>>,
    truncated: bool,
    notes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteDeletePlanRowDto {
    rowid: i64,
    display: Vec<SqliteCellDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteDeletePlanResponse {
    plan_handle: String,
    path: String,
    table: String,
    rows: Vec<SqliteDeletePlanRowDto>,
    missing_rowids: Vec<i64>,
    summary: String,
    dangerous: bool,
    expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteDeleteReceipt {
    plan_handle: String,
    state: &'static str,
    detail: String,
    deleted: u32,
    backup_path: Option<String>,
    undoable: bool,
}

#[derive(Debug, Clone)]
struct StoredDeletePlan {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    path: RemotePath,
    table: String,
    file_sha256: String,
    file_size: u64,
    rows: Vec<BoundRowDelete>,
    expires_at: Instant,
}

pub(crate) struct SqliteApi {
    services: BackendServices,
    ssh_api: std::sync::Arc<SshApi>,
    paths: EmergencyPathApi,
    sftp: SftpBrowserApi,
    plans: Mutex<HashMap<String, StoredDeletePlan>>,
}

impl std::fmt::Debug for SqliteApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteApi")
            .field("plans", &self.plans)
            .finish_non_exhaustive()
    }
}

impl SqliteApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: std::sync::Arc<SshApi>,
        paths: EmergencyPathApi,
        sftp: SftpBrowserApi,
    ) -> Self {
        Self {
            services,
            ssh_api,
            paths,
            sftp,
            plans: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut plans) = self.plans.lock() {
            plans.retain(|_, plan| plan.binding_handle != binding_handle);
        }
    }

    fn session(&self, binding_handle: &str) -> Result<BoundSshSession, SqliteApiError> {
        if binding_handle.is_empty() || binding_handle.len() > 128 {
            return Err(SqliteApiError::Invalid);
        }
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| SqliteApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| SqliteApiError::BindingUnavailable)?;
        Ok(session)
    }

    fn source_path(
        &self,
        binding_handle: &str,
        source: &SqliteSourceDto,
    ) -> Result<RemotePath, SqliteApiError> {
        match source {
            SqliteSourceDto::Sftp {
                browser_handle,
                entry_handle,
            } => self
                .sftp
                .path_for_fetch(binding_handle, browser_handle, entry_handle)
                .map_err(|_| SqliteApiError::PathStale),
            SqliteSourceDto::Offer { path_handle } => self
                .paths
                .resolve_evidence_path(binding_handle, path_handle)
                .map(|(_, path)| path)
                .map_err(|_| SqliteApiError::PathStale),
        }
    }

    async fn run(
        &self,
        session: &BoundSshSession,
        command: String,
    ) -> Result<String, SqliteApiError> {
        let output = self
            .services
            .ssh()
            .execute_bound(session, command, sqlite_view::SQLITE_VIEW_TIMEOUT)
            .await
            .map_err(|_| SqliteApiError::Opaque)?;
        if output.timed_out {
            return Err(SqliteApiError::refused("sqlite-timeout"));
        }
        Ok(output.output)
    }

    pub(crate) async fn inspect(
        &self,
        request: &SqliteInspectRequest,
    ) -> Result<SqliteInspectResponse, SqliteApiError> {
        let session = self.session(&request.binding_handle)?;
        let path = self.source_path(&request.binding_handle, &request.source)?;
        let command = sqlite_view::build_view_command(&path, &SqliteViewOp::Inspect)
            .map_err(|_| SqliteApiError::Invalid)?;
        let output = self.run(&session, command).await?;
        match sqlite_view::parse_view_output(&SqliteViewOp::Inspect, &output) {
            Ok(SqliteViewResult::Inspect {
                engine,
                file,
                tables,
                tables_truncated,
                notes,
            }) => Ok(SqliteInspectResponse {
                engine: engine.engine,
                sqlite_version: engine.sqlite_version,
                immutable: engine.immutable,
                path: path.as_str().to_owned(),
                file: SqliteFileDto {
                    size: file.size,
                    mtime_epoch: file.mtime_epoch,
                    owner: file.owner,
                    mode: file.mode,
                    wal: file.wal,
                    shm: file.shm,
                },
                tables: tables
                    .iter()
                    .map(|row| SqliteTableDto {
                        name: row.name.clone(),
                        kind: row.kind.clone(),
                        sql: row.sql.clone(),
                        rows: row.rows,
                    })
                    .collect(),
                tables_truncated,
                notes,
            }),
            Ok(_) => Err(SqliteApiError::Opaque),
            Err(error) => Err(SqliteApiError::refused(error.code())),
        }
    }

    pub(crate) async fn rows(
        &self,
        request: &SqliteRowsRequest,
    ) -> Result<SqliteRowsResponse, SqliteApiError> {
        let session = self.session(&request.binding_handle)?;
        let path = self.source_path(&request.binding_handle, &request.source)?;
        let op = SqliteViewOp::Rows {
            table: request.table.clone(),
            offset: request.offset,
        };
        let command =
            sqlite_view::build_view_command(&path, &op).map_err(|_| SqliteApiError::Invalid)?;
        let output = self.run(&session, command).await?;
        match sqlite_view::parse_view_output(&op, &output) {
            Ok(SqliteViewResult::Rows {
                engine,
                columns,
                rows,
                truncated,
                notes,
            }) => Ok(SqliteRowsResponse {
                engine: engine.engine,
                sqlite_version: engine.sqlite_version,
                immutable: engine.immutable,
                columns: columns
                    .iter()
                    .map(|col| SqliteColumnDto {
                        name: col.name.clone(),
                        declared_type: col.declared_type.clone(),
                        rowid: col.rowid,
                    })
                    .collect(),
                rows: rows
                    .iter()
                    .map(|row| row.iter().map(SqliteCellDto::from).collect())
                    .collect(),
                truncated,
                notes,
            }),
            Ok(_) => Err(SqliteApiError::Opaque),
            Err(error) => Err(SqliteApiError::refused(error.code())),
        }
    }

    pub(crate) async fn delete_plan(
        &self,
        request: &SqliteDeletePlanRequest,
    ) -> Result<SqliteDeletePlanResponse, SqliteApiError> {
        let session = self.session(&request.binding_handle)?;
        let path = self.source_path(&request.binding_handle, &request.source)?;
        if request.rowids.len() > sqlite_view::DELETE_MAX_ROWS {
            return Err(SqliteApiError::Invalid);
        }
        let command = sqlite_view::build_delete_probe_command(
            &path,
            &request.table,
            &request.rowids,
        )
        .map_err(|_| SqliteApiError::Invalid)?;
        let output = self.run(&session, command).await?;
        let probe = sqlite_view::parse_delete_probe_output(&output, &request.rowids)
            .map_err(|stage| SqliteApiError::refused(stage.code()))?;
        if probe.rows.is_empty() {
            return Err(SqliteApiError::refused("sqlite-delete-empty"));
        }
        let plan_id = format!("sq-{}", uuid::Uuid::new_v4());
        let row_count = probe.rows.len();
        let summary = format!(
            "将在 {path} 的表 {table} 中删除 {row_count} 行；\
             这是活动数据库内的删除，应用可能正打开着它，业务规则有时应通过应用自身功能完成；\
             执行前会重新核对文件哈希与每行内容，不一致就拒绝；\
             备份写入同目录 .lovelyres-backups，10 分钟内可恢复。",
            path = path.as_str(),
            table = request.table,
            row_count = row_count,
        );
        let dto_rows: Vec<SqliteDeletePlanRowDto> = probe
            .rows
            .iter()
            .map(|row| SqliteDeletePlanRowDto {
                rowid: row.rowid,
                display: row.display.iter().map(SqliteCellDto::from).collect(),
            })
            .collect();
        let response = SqliteDeletePlanResponse {
            plan_handle: plan_id.clone(),
            path: path.as_str().to_owned(),
            table: request.table.clone(),
            rows: dto_rows,
            missing_rowids: probe.missing_rowids.clone(),
            summary,
            dangerous: true,
            expires_in_seconds: PLAN_TTL.as_secs() as u32,
        };
        let stored = StoredDeletePlan {
            binding_handle: request.binding_handle.clone(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            path,
            table: request.table.clone(),
            file_sha256: probe.file_sha256,
            file_size: probe.file_size,
            rows: probe.rows,
            expires_at: Instant::now() + PLAN_TTL,
        };
        let mut plans = self.plans.lock().map_err(|_| SqliteApiError::Opaque)?;
        if plans.len() >= MAX_PLANS {
            if let Some(oldest) = plans
                .iter()
                .min_by_key(|(_, plan)| plan.expires_at)
                .map(|(handle, _)| handle.clone())
            {
                plans.remove(&oldest);
            }
        }
        plans.insert(plan_id, stored);
        Ok(response)
    }

    fn check_plan_session(
        &self,
        session: &BoundSshSession,
        plan: &StoredDeletePlan,
    ) -> Result<(), SqliteApiError> {
        if session.session_id() != plan.session_id
            || session.connection_id() != plan.connection_id
        {
            return Err(SqliteApiError::PlanStale);
        }
        Ok(())
    }

    pub(crate) async fn delete_execute(
        &self,
        request: &SqliteDeleteRefRequest,
    ) -> Result<SqliteDeleteReceipt, SqliteApiError> {
        let session = self.session(&request.binding_handle)?;
        let plan = take_plan(&self.plans, &request.binding_handle, &request.plan_handle)?;
        self.check_plan_session(&session, &plan)?;
        let plan_id = request.plan_handle.clone();
        let bound: Vec<(i64, String)> = plan
            .rows
            .iter()
            .map(|row| (row.rowid, row.hash.clone()))
            .collect();
        let command = sqlite_view::build_delete_execute_command(
            &plan.path,
            &plan.table,
            &plan_id,
            &plan.file_sha256,
            plan.file_size,
            &bound,
        )
        .map_err(|_| SqliteApiError::Invalid)?;
        let output = self.run(&session, command).await?;
        let stage = sqlite_view::parse_delete_result_output(&output);
        match stage {
            SqliteDeleteStage::Deleted(count) => {
                let backup = output
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("LH-DONE ").and_then(|payload| {
                            serde_json::from_str::<serde_json::Value>(payload)
                                .ok()
                                .and_then(|v| {
                                    v.get("backup")
                                        .and_then(serde_json::Value::as_str)
                                        .map(str::to_owned)
                                })
                        })
                    });
                // The undo window reuses the plan with a fresh expiry.
                let mut stored = plan.clone();
                stored.expires_at = Instant::now() + UNDO_TTL;
                if let Ok(mut plans) = self.plans.lock() {
                    plans.insert(plan_id.clone(), stored);
                }
                Ok(SqliteDeleteReceipt {
                    plan_handle: plan_id,
                    state: "deleted",
                    detail: format!("已删除 {count} 行并复核这些 rowid 不再存在。"),
                    deleted: count,
                    backup_path: backup,
                    undoable: true,
                })
            }
            stage => Ok(SqliteDeleteReceipt {
                plan_handle: plan_id,
                state: "refused",
                detail: refusal_detail(&stage),
                deleted: 0,
                backup_path: None,
                undoable: false,
            }),
        }
    }

    pub(crate) async fn delete_undo(
        &self,
        request: &SqliteDeleteRefRequest,
    ) -> Result<SqliteDeleteReceipt, SqliteApiError> {
        let session = self.session(&request.binding_handle)?;
        let plan = take_plan(&self.plans, &request.binding_handle, &request.plan_handle)?;
        self.check_plan_session(&session, &plan)?;
        let plan_id = request.plan_handle.clone();
        let bound: Vec<(i64, String)> = plan
            .rows
            .iter()
            .map(|row| (row.rowid, row.canonical.clone()))
            .collect();
        let command = sqlite_view::build_delete_undo_command(&plan.path, &plan.table, &bound)
            .map_err(|_| SqliteApiError::Invalid)?;
        let output = self.run(&session, command).await?;
        let stage = sqlite_view::parse_delete_result_output(&output);
        match stage {
            SqliteDeleteStage::Restored(count) => Ok(SqliteDeleteReceipt {
                plan_handle: plan_id,
                state: "restored",
                detail: format!("已恢复 {count} 行，rowid 与删除前一致。"),
                deleted: 0,
                backup_path: None,
                undoable: false,
            }),
            stage => {
                // A refused undo does not consume the plan; let the operator
                // retry inside the same window.
                let mut stored = plan.clone();
                stored.expires_at = Instant::now() + Duration::from_secs(120);
                if let Ok(mut plans) = self.plans.lock() {
                    plans.insert(plan_id.clone(), stored);
                }
                Ok(SqliteDeleteReceipt {
                    plan_handle: plan_id,
                    state: "refused",
                    detail: refusal_detail(&stage),
                    deleted: 0,
                    backup_path: None,
                    undoable: false,
                })
            }
        }
    }
}

/// Taking a plan consumes it once: a second call with the same handle is
/// stale, a wrong binding is stale, and an expired plan is stale. Undo and
/// execute re-insert their own plan with a fresh window when they succeed.
fn take_plan(
    plans: &Mutex<HashMap<String, StoredDeletePlan>>,
    binding_handle: &str,
    plan_handle: &str,
) -> Result<StoredDeletePlan, SqliteApiError> {
    if plan_handle.is_empty() || plan_handle.len() > 128 {
        return Err(SqliteApiError::Invalid);
    }
    let mut plans = plans.lock().map_err(|_| SqliteApiError::Opaque)?;
    let plan = plans
        .remove(plan_handle)
        .ok_or(SqliteApiError::PlanStale)?;
    if plan.binding_handle != binding_handle || Instant::now() > plan.expires_at {
        return Err(SqliteApiError::PlanStale);
    }
    Ok(plan)
}

fn refusal_detail(stage: &SqliteDeleteStage) -> String {
    match stage {
        SqliteDeleteStage::StaleFile => {
            "数据库文件在确认后被写入了，没有动任何行；请重新规划。".to_owned()
        }
        SqliteDeleteStage::RowChanged => {
            "某一行在确认后发生了变化，没有动任何行；请重新打开并重新规划。".to_owned()
        }
        SqliteDeleteStage::NoRowid => {
            "这个表没有可用的 rowid，不支持按行删除。".to_owned()
        }
        SqliteDeleteStage::NoTable => "表不存在或已变化，请重新打开。".to_owned(),
        SqliteDeleteStage::NoPython => {
            "删除行需要目标上有 python3（SQLite 备份与事务校验依赖它）。".to_owned()
        }
        SqliteDeleteStage::RowidExists => {
            "被删的 rowid 里已有值重新出现，自动恢复已拒绝；请人工核对。".to_owned()
        }
        SqliteDeleteStage::Failed(code) => {
            format!("操作未能完成（{code}），没有动任何行；请重试或人工检查。")
        }
        SqliteDeleteStage::Deleted(count) | SqliteDeleteStage::Restored(count) => {
            format!("已完成 {count} 行。")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(binding: &str) -> StoredDeletePlan {
        StoredDeletePlan {
            binding_handle: binding.to_owned(),
            session_id: "session-1".to_owned(),
            connection_id: "conn-1".to_owned(),
            path: RemotePath::new("/var/lib/cam.db").unwrap(),
            table: "sessions".to_owned(),
            file_sha256: "a".repeat(64),
            file_size: 4096,
            rows: vec![BoundRowDelete {
                rowid: 7,
                hash: "b".repeat(64),
                canonical: "[]".to_owned(),
                display: vec![SqliteCell::Integer(7)],
            }],
            expires_at: Instant::now() + Duration::from_secs(60),
        }
    }

    #[test]
    fn request_shapes_are_exact() {
        let inspect: SqliteInspectRequest = serde_json::from_str(
            r#"{"bindingHandle":"b","source":{"kind":"sftp","browserHandle":"w","entryHandle":"e"}}"#,
        )
        .unwrap();
        assert!(matches!(inspect.source, SqliteSourceDto::Sftp { .. }));
        let offer: SqliteInspectRequest = serde_json::from_str(
            r#"{"bindingHandle":"b","source":{"kind":"offer","pathHandle":"p"}}"#,
        )
        .unwrap();
        assert!(matches!(offer.source, SqliteSourceDto::Offer { .. }));
        // Extra or missing fields never resolve a different source.
        assert!(serde_json::from_str::<SqliteInspectRequest>(
            r#"{"bindingHandle":"b","source":{"kind":"sftp","browserHandle":"w","entryHandle":"e","path":"/etc"}}"#,
        )
        .is_err());
        assert!(serde_json::from_str::<SqliteInspectRequest>(
            r#"{"bindingHandle":"b","source":{"kind":"offer"}}"#,
        )
        .is_err());
        assert!(serde_json::from_str::<SqliteInspectRequest>(
            r#"{"bindingHandle":"b","source":{"kind":"other","path":"/x"}}"#,
        )
        .is_err());
        let rows: SqliteRowsRequest = serde_json::from_str(
            r#"{"bindingHandle":"b","source":{"kind":"offer","pathHandle":"p"},"table":"sessions","offset":200}"#,
        )
        .unwrap();
        assert_eq!(rows.offset, 200);
        assert!(serde_json::from_str::<SqliteRowsRequest>(
            r#"{"bindingHandle":"b","source":{"kind":"offer","pathHandle":"p"},"table":"sessions"}"#,
        )
        .is_ok());
        let plan: SqliteDeletePlanRequest = serde_json::from_str(
            r#"{"bindingHandle":"b","source":{"kind":"offer","pathHandle":"p"},"table":"sessions","rowids":[1,2,3]}"#,
        )
        .unwrap();
        assert_eq!(plan.rowids.len(), 3);
        assert!(serde_json::from_str::<SqliteDeletePlanRequest>(
            r#"{"bindingHandle":"b","source":{"kind":"offer","pathHandle":"p"},"table":"sessions","rowids":[]}"#,
        )
        .is_ok());
    }

    #[test]
    fn plan_is_consumed_once_and_bound_to_its_binding() {
        let plans = Mutex::new(HashMap::from([(
            "p1".to_owned(),
            stored("binding-a"),
        )]));
        // A second binding sees a stale plan, not another target's approval.
        assert_eq!(
            take_plan(&plans, "binding-b", "p1").unwrap_err(),
            SqliteApiError::PlanStale
        );
        // The wrong-binding attempt consumed nothing... it did: remove-then-
        // check means the plan is gone. Recreate for the consumed-once check.
        plans
            .lock()
            .unwrap()
            .insert("p1".to_owned(), stored("binding-a"));
        let plan = take_plan(&plans, "binding-a", "p1").unwrap();
        assert_eq!(plan.table, "sessions");
        assert_eq!(
            take_plan(&plans, "binding-a", "p1").unwrap_err(),
            SqliteApiError::PlanStale
        );
    }

    #[test]
    fn expired_and_unknown_handles_are_stale() {
        let mut plan = stored("binding-a");
        plan.expires_at = Instant::now() - Duration::from_secs(1);
        let plans = Mutex::new(HashMap::from([("old".to_owned(), plan)]));
        assert_eq!(
            take_plan(&plans, "binding-a", "old").unwrap_err(),
            SqliteApiError::PlanStale
        );
        assert_eq!(
            take_plan(&plans, "binding-a", "missing").unwrap_err(),
            SqliteApiError::PlanStale
        );
        assert_eq!(
            take_plan(&plans, "binding-a", "").unwrap_err(),
            SqliteApiError::Invalid
        );
    }

    #[test]
    fn cell_dto_carries_each_variant() {
        assert_eq!(
            serde_json::to_value(SqliteCellDto::from(&SqliteCell::Null)).unwrap(),
            serde_json::json!({ "kind": "null" })
        );
        let blob = serde_json::to_value(SqliteCellDto::from(&SqliteCell::Blob {
            bytes: 12,
            hex_prefix: "aabb".to_owned(),
        }))
        .unwrap();
        assert_eq!(blob["kind"], "blob");
        assert_eq!(blob["bytes"], 12);
        assert_eq!(blob["hexPrefix"], "aabb");
        let truncated = serde_json::to_value(SqliteCellDto::from(&SqliteCell::TruncatedText(
            "abc".to_owned(),
        )))
        .unwrap();
        assert_eq!(truncated["kind"], "truncated");
        assert_eq!(truncated["text"], "abc");
    }
}
