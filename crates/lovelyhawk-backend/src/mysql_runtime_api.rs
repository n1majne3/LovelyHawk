//! MySQL / MariaDB runtime surface: connection profiles plus the reviewed
//! password-change lifecycle. Mirrors the PostgreSQL API shape — opaque
//! handles, plan → confirm → execute → independent verify → explicit restore.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, MutexGuard};

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use lovelyhawk_core::{
    CoreError,
    crypto::SecretValue,
    database::{
        DatabaseEngine, DatabaseProfileChanges, DatabaseProfileConfig, DatabaseProfileSnapshot,
        DatabaseSecretChange,
    },
    database_password::SavedPasswordUpdate,
    mysql_native::{MySqlTlsMode, MySqlTlsSettings},
    mysql_privilege::{self, GrantScope, MySqlPrivilegePlan},
    mysql_password::{
        MySqlAccount, MySqlPasswordPlan, MySqlPasswordRestorePlan, MySqlPasswordRestoreToken,
        MySqlPasswordVerification,
    },
    operations::DangerousConfirmation,
    ssh::BoundSshSession,
    target::TargetGuard,
};

use crate::{BackendServices, ssh_api::SshApi};

const TTL: std::time::Duration = std::time::Duration::from_secs(1800);
const MAX_BINDINGS: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum MySqlRuntimeRequest {
    List {
        binding_handle: String,
    },
    Save {
        binding_handle: String,
        profile_handle: Option<String>,
        profile: ProfileInput,
        password: PasswordChange,
    },
    PlanDelete {
        binding_handle: String,
        profile_handle: String,
    },
    Inspect {
        binding_handle: String,
        profile_handle: String,
    },
    Delete {
        binding_handle: String,
        plan_handle: String,
    },
    PlanPassword {
        binding_handle: String,
        profile_handle: String,
        account: AccountInput,
        #[serde(deserialize_with = "read_password")]
        password: SecretValue,
        update_saved_password: bool,
    },
    ExecutePassword {
        binding_handle: String,
        plan_handle: String,
    },
    PlanPasswordRestore {
        binding_handle: String,
        profile_handle: String,
        restore_handle: String,
    },
    ExecutePasswordRestore {
        binding_handle: String,
        plan_handle: String,
    },
    Privileges {
        binding_handle: String,
        profile_handle: String,
        account: AccountInput,
    },
    PlanPrivileges {
        binding_handle: String,
        profile_handle: String,
        account: AccountInput,
        revokes: Vec<RevokeInput>,
        grants: Vec<PrivilegeAddInput>,
    },
    ExecutePrivileges {
        binding_handle: String,
        plan_handle: String,
    },
    UndoPrivileges {
        binding_handle: String,
        plan_handle: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RevokeInput {
    pub row: usize,
    pub privileges: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrivilegeAddInput {
    pub database: String,
    #[serde(default)]
    pub table: Option<String>,
    pub privileges: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AccountInput {
    pub user: String,
    pub host: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileInput {
    name: String,
    host: String,
    port: u16,
    username: String,
    #[serde(default)]
    database: String,
    tls_mode: MySqlTlsMode,
    #[serde(deserialize_with = "required_option")]
    ca_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PasswordChange {
    Keep,
    Remove,
    Replace {
        #[serde(deserialize_with = "read_password")]
        value: SecretValue,
    },
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileDto {
    profile_handle: String,
    name: String,
    host: String,
    port: u16,
    database: String,
    username: String,
    tls_mode: MySqlTlsMode,
    has_ca: bool,
    has_password: bool,
    unassigned: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct Scope {
    binding: String,
    session: String,
    connection: String,
    target: TargetGuard,
}

struct DeletePlan {
    handle: String,
    profile: ProfileDto,
    core: lovelyhawk_core::database::DatabaseProfileDeletePlan,
}

struct PasswordPlan {
    handle: String,
    core: MySqlPasswordPlan,
    profile_id: String,
    profile_handle: String,
}

struct RestorePlan {
    handle: String,
    core: MySqlPasswordRestorePlan,
    profile_id: String,
    profile_handle: String,
}

struct RestoreSlot {
    handle: String,
    token: MySqlPasswordRestoreToken,
}

struct PrivilegePlanSlot {
    handle: String,
    profile_handle: String,
    plan: MySqlPrivilegePlan,
}

struct PrivilegeUndoSlot {
    handle: String,
    profile_handle: String,
    plan: MySqlPrivilegePlan,
    applied_lines: Vec<String>,
    applied: usize,
    at: Instant,
}

struct Entry {
    scope: Scope,
    touched: Instant,
    profiles: HashMap<String, DatabaseProfileSnapshot>,
    delete: Option<DeletePlan>,
    deleting: bool,
    password_plan: Option<PasswordPlan>,
    restore_plan: Option<RestorePlan>,
    restore: Option<RestoreSlot>,
    password_busy: bool,
    privilege_plan: Option<PrivilegePlanSlot>,
    privilege_undo: Option<PrivilegeUndoSlot>,
    privilege_busy: bool,
}

/// Ten minutes, like the other guarded-undo windows.
const UNDO_TTL: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Clone)]
pub(crate) struct MySqlRuntimeApi {
    services: BackendServices,
    ssh: Arc<SshApi>,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

impl std::fmt::Debug for MySqlRuntimeApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlRuntimeApi").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) enum MySqlRuntimeError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    Store,
    Rejected(&'static str, String),
}

type Result<T> = std::result::Result<T, MySqlRuntimeError>;

fn text(value: &str, cap: usize, empty: bool) -> bool {
    value.len() <= cap
        && (empty || !value.trim().is_empty())
        && !value.chars().any(char::is_control)
}

fn handle(value: &str) -> Result<()> {
    if text(value, 128, false) {
        Ok(())
    } else {
        Err(MySqlRuntimeError::Invalid)
    }
}

fn action_name(request: &MySqlRuntimeRequest) -> &'static str {
    match request {
        MySqlRuntimeRequest::List { .. } => "list",
        MySqlRuntimeRequest::Save { .. } => "save",
        MySqlRuntimeRequest::PlanDelete { .. } => "plan-delete",
        MySqlRuntimeRequest::Inspect { .. } => "inspect",
        MySqlRuntimeRequest::Delete { .. } => "delete",
        MySqlRuntimeRequest::PlanPassword { .. } => "plan-password",
        MySqlRuntimeRequest::ExecutePassword { .. } => "execute-password",
        MySqlRuntimeRequest::PlanPasswordRestore { .. } => "plan-password-restore",
        MySqlRuntimeRequest::ExecutePasswordRestore { .. } => "execute-password-restore",
        MySqlRuntimeRequest::Privileges { .. } => "privileges",
        MySqlRuntimeRequest::PlanPrivileges { .. } => "plan-privileges",
        MySqlRuntimeRequest::ExecutePrivileges { .. } => "execute-privileges",
        MySqlRuntimeRequest::UndoPrivileges { .. } => "undo-privileges",
    }
}

fn core_error(error: CoreError) -> MySqlRuntimeError {
    let (code, detail) = lovelyhawk_core::database_password::public_reason(&error);
    MySqlRuntimeError::Rejected(code, detail)
}

fn new_handle() -> String {
    Uuid::new_v4().to_string()
}

fn profile_dto(handle: &str, snapshot: &DatabaseProfileSnapshot) -> ProfileDto {
    let view = snapshot.view();
    let config = &view.config;
    let tls = config.mysql_tls.clone().unwrap_or_default();
    let username = config.connection.username.clone().unwrap_or_default();
    ProfileDto {
        profile_handle: handle.into(),
        name: config.name.clone(),
        host: config.connection.host.clone(),
        port: config.connection.port,
        database: config.connection.database.clone().unwrap_or_default(),
        username,
        tls_mode: tls.mode,
        has_ca: tls.ca_certificate_pem.is_some(),
        has_password: view.has_password,
        unassigned: config.ssh_connection_id.is_none(),
    }
}

impl MySqlRuntimeApi {
    pub(crate) fn new(services: BackendServices, ssh: Arc<SshApi>) -> Self {
        Self {
            services,
            ssh,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn close_binding(&self, binding: &str) {
        self.entries.lock().remove(binding);
    }

    fn capture(&self, binding: &str) -> Result<(Scope, BoundSshSession)> {
        handle(binding)?;
        let session = self
            .ssh
            .binding_session_clone(binding)
            .map_err(|_| MySqlRuntimeError::Stale)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| MySqlRuntimeError::Stale)?;
        Ok((
            Scope {
                binding: binding.into(),
                session: session.session_id().into(),
                connection: session.connection_id().into(),
                target: session.target().clone(),
            },
            session,
        ))
    }

    fn validate(&self, scope: &Scope) -> Result<()> {
        if self.capture(&scope.binding)?.0 == *scope {
            Ok(())
        } else {
            Err(MySqlRuntimeError::Stale)
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock()
    }

    fn with_entry<T>(
        &self,
        scope: &Scope,
        work: impl FnOnce(&mut Entry) -> Result<T>,
    ) -> Result<T> {
        self.validate(scope)?;
        let mut entries = self.entries();
        entries.retain(|_, entry| {
            entry.deleting || entry.password_busy || entry.touched.elapsed() < TTL
        });
        let entry = entries
            .get_mut(&scope.binding)
            .filter(|entry| entry.scope == *scope)
            .ok_or(MySqlRuntimeError::Stale)?;
        entry.touched = Instant::now();
        work(entry)
    }

    fn profile(&self, entry: &Entry, handle: &str) -> Result<DatabaseProfileSnapshot> {
        entry
            .profiles
            .get(handle)
            .cloned()
            .ok_or(MySqlRuntimeError::Stale)
    }

    fn idle(entry: &Entry) -> Result<()> {
        if entry.password_busy || entry.deleting || entry.privilege_busy {
            return Err(MySqlRuntimeError::Busy);
        }
        Ok(())
    }

    /// Re-issue a fresh handle for a profile whose stored secret changed.
    fn refresh_profile(
        &self,
        scope: &Scope,
        profile_id: &str,
        old_handle: &str,
    ) -> Result<Option<ProfileDto>> {
        let snapshot = self
            .services
            .database()
            .profile_snapshots()
            .map_err(|_| MySqlRuntimeError::Store)?
            .into_iter()
            .find(|snapshot| snapshot.view().config.id == profile_id)
            .ok_or(MySqlRuntimeError::Stale)?;
        self.with_entry(scope, |entry| {
            entry.profiles.remove(old_handle);
            let id = new_handle();
            let dto = profile_dto(&id, &snapshot);
            entry.profiles.insert(id, snapshot);
            Ok(Some(dto))
        })
    }

    pub(crate) async fn dispatch(&self, request: MySqlRuntimeRequest) -> Value {
        let action = action_name(&request);
        match self.dispatch_inner(request).await {
            Ok(value) => value,
            Err(error) => {
                let (code, detail) = match error {
                    MySqlRuntimeError::Rejected(code, detail) => (code, detail),
                    MySqlRuntimeError::Invalid => {
                        ("invalid-params", "请求内容不符合要求".to_owned())
                    }
                    MySqlRuntimeError::Stale => (
                        "stale",
                        "连接、配置或计划已变化或过期，请刷新后重试。".to_owned(),
                    ),
                    MySqlRuntimeError::Busy => ("busy", "上一个操作尚未结束，请稍候。".to_owned()),
                    MySqlRuntimeError::Capacity => (
                        "capacity",
                        "打开的连接页过多，请先关闭不需要的。".to_owned(),
                    ),
                    MySqlRuntimeError::Store => ("store", "本机配置存储暂时不可用。".to_owned()),
                };
                json!({"kind":"rejected", "action":action, "code":code, "detail":detail})
            }
        }
    }

    async fn dispatch_inner(&self, request: MySqlRuntimeRequest) -> Result<Value> {
        use MySqlRuntimeRequest::*;
        let binding = match &request {
            List { binding_handle }
            | Save { binding_handle, .. }
            | PlanDelete { binding_handle, .. }
            | Inspect { binding_handle, .. }
            | Delete { binding_handle, .. }
            | PlanPassword { binding_handle, .. }
            | ExecutePassword { binding_handle, .. }
            | PlanPasswordRestore { binding_handle, .. }
            | ExecutePasswordRestore { binding_handle, .. }
            | Privileges { binding_handle, .. }
            | PlanPrivileges { binding_handle, .. }
            | ExecutePrivileges { binding_handle, .. }
            | UndoPrivileges { binding_handle, .. } => binding_handle,
        };
        let (scope, session) = self.capture(binding)?;
        let response = match request {
            List { .. } => {
                let snapshots = self
                    .services
                    .database()
                    .profile_snapshots()
                    .map_err(|_| MySqlRuntimeError::Store)?;
                self.validate(&scope)?;
                let mut entries = self.entries();
                entries.retain(|_, entry| {
                    entry.deleting || entry.password_busy || entry.touched.elapsed() < TTL
                });
                if entries
                    .get(&scope.binding)
                    .is_some_and(|entry| entry.scope != scope)
                {
                    entries.remove(&scope.binding);
                }
                if !entries.contains_key(&scope.binding) && entries.len() >= MAX_BINDINGS {
                    return Err(MySqlRuntimeError::Capacity);
                }
                let entry = entries
                    .entry(scope.binding.clone())
                    .or_insert_with(|| Entry {
                        scope: scope.clone(),
                        touched: Instant::now(),
                        profiles: HashMap::new(),
                        delete: None,
                        deleting: false,
                        password_plan: None,
                        restore_plan: None,
                        restore: None,
                        password_busy: false,
                        privilege_plan: None,
                        privilege_undo: None,
                        privilege_busy: false,
                    });
                Self::idle(entry)?;
                let mut refreshed = HashMap::new();
                let mut profiles = Vec::new();
                for snapshot in snapshots.into_iter().filter(|s| {
                    s.view().config.connection.engine == DatabaseEngine::Mysql
                        && s.view()
                            .config
                            .ssh_connection_id
                            .as_ref()
                            .is_none_or(|owner| owner == &scope.connection)
                }) {
                    let id = entry
                        .profiles
                        .iter()
                        .find(|(_, old)| old.same_revision(&snapshot))
                        .map(|(id, _)| id.clone())
                        .unwrap_or_else(new_handle);
                    profiles.push(profile_dto(&id, &snapshot));
                    refreshed.insert(id, snapshot);
                }
                entry.profiles = refreshed;
                entry.touched = Instant::now();
                json!({"kind":"profiles", "profiles":profiles})
            }
            Save {
                profile_handle,
                profile,
                password,
                ..
            } => self.with_entry(&scope, |entry| {
                Self::idle(entry)?;
                if !text(&profile.name, 256, false)
                    || !text(&profile.host, 253, false)
                    || !profile
                        .host
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._:[]-".contains(&c))
                    || !text(&profile.username, 128, false)
                    || !text(&profile.database, 128, true)
                    || profile.port == 0
                {
                    return Err(MySqlRuntimeError::Invalid);
                }
                let expected = profile_handle
                    .as_deref()
                    .map(|id| self.profile(entry, id))
                    .transpose()?;
                let mut config = expected
                    .as_ref()
                    .map(|s| s.view().config.clone())
                    .unwrap_or_else(|| {
                        DatabaseProfileConfig::new(&profile.name, DatabaseEngine::Mysql)
                    });
                config.name = profile.name;
                config.connection.host = profile.host;
                config.connection.port = profile.port;
                config.connection.username = Some(profile.username);
                config.connection.database =
                    (!profile.database.is_empty()).then_some(profile.database);
                config.mysql_tls = Some(MySqlTlsSettings {
                    mode: profile.tls_mode,
                    ca_certificate_pem: profile.ca_pem,
                });
                config.ssh_connection_id = Some(scope.connection.clone());
                config
                    .validate()
                    .map_err(|_| MySqlRuntimeError::Invalid)?;
                let password = match password {
                    PasswordChange::Keep => DatabaseSecretChange::Keep,
                    PasswordChange::Remove => DatabaseSecretChange::Remove,
                    PasswordChange::Replace { value } => DatabaseSecretChange::Replace(value),
                };
                let saved = self
                    .services
                    .database()
                    .save_profile_if_unchanged(
                        config,
                        DatabaseProfileChanges { password },
                        expected.as_ref(),
                    )
                    .map_err(|_| MySqlRuntimeError::Store)?;
                if let Some(old) = profile_handle {
                    entry.profiles.remove(&old);
                }
                let id = new_handle();
                let dto = profile_dto(&id, &saved);
                entry.profiles.insert(id, saved);
                Ok(json!({"kind":"saved", "profile":dto}))
            })?,
            Inspect { profile_handle, .. } => {
                let snapshot = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    self.profile(entry, &profile_handle)
                })?;
                let review = self
                    .services
                    .database()
                    .mysql_instance_review(&session, &snapshot)
                    .await
                    .map_err(core_error)?;
                let view = serde_json::to_value(&review).map_err(|_| MySqlRuntimeError::Store)?;
                self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    entry.touched = Instant::now();
                    Ok(json!({"kind":"review","review":view}))
                })?
            }
            PlanDelete { profile_handle, .. } => self.with_entry(&scope, |entry| {
                Self::idle(entry)?;
                let snapshot = self.profile(entry, &profile_handle)?;
                let core = self
                    .services
                    .database()
                    .plan_delete_profile_snapshot(&snapshot)
                    .map_err(|_| MySqlRuntimeError::Stale)?;
                let profile = profile_dto(&profile_handle, &snapshot);
                let id = new_handle();
                let response =
                    json!({"kind":"delete-plan","planHandle":id,"profile":profile,"expiresInMs":120000});
                entry.delete = Some(DeletePlan {
                    handle: id,
                    profile,
                    core,
                });
                Ok(response)
            })?,
            Delete { plan_handle, .. } => {
                handle(&plan_handle)?;
                let plan = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    if entry
                        .delete
                        .as_ref()
                        .is_none_or(|plan| plan.handle != plan_handle)
                    {
                        return Err(MySqlRuntimeError::Stale);
                    }
                    entry.deleting = true;
                    Ok(entry.delete.take().expect("checked plan"))
                })?;
                let _lease = PasswordLease {
                    entries: self.entries.clone(),
                    scope: scope.clone(),
                };
                let confirmation = DangerousConfirmation::approve(plan.core.definition());
                let result = self
                    .services
                    .database()
                    .execute_delete_profile(
                        plan.core,
                        confirmation,
                        self.services.operation_journal(),
                    )
                    .await;
                let verified = result.is_ok_and(|outcome| outcome.verification.passed);
                self.with_entry(&scope, |entry| {
                    entry.deleting = false;
                    entry.profiles.remove(&plan.profile.profile_handle);
                    Ok(())
                })?;
                json!({"kind":"deleted","planHandle":plan_handle,"profileHandle":plan.profile.profile_handle,"verified":verified,
                    "detail":if verified { "已删除本机保存的数据库连接并核实结果。" } else { "删除状态尚未确认，请刷新连接列表；不要重复使用原确认。" }})
            }
            PlanPassword {
                profile_handle,
                account,
                password,
                update_saved_password,
                ..
            } => {
                let account = MySqlAccount::new(&account.user, &account.host)
                    .map_err(|_| MySqlRuntimeError::Invalid)?;
                let snapshot = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    self.profile(entry, &profile_handle)
                })?;
                let plan = self
                    .services
                    .database()
                    .plan_mysql_password(
                        &session,
                        &snapshot,
                        account,
                        password,
                        update_saved_password,
                    )
                    .await
                    .map_err(core_error)?;
                let view =
                    serde_json::to_value(&plan.view).map_err(|_| MySqlRuntimeError::Store)?;
                self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    let id = new_handle();
                    entry.password_plan = Some(PasswordPlan {
                        handle: id.clone(),
                        core: plan,
                        profile_id: snapshot.view().config.id.clone(),
                        profile_handle: profile_handle.clone(),
                    });
                    Ok(json!({"kind":"password-plan","planHandle":id,"expiresInMs":120000,"plan":view}))
                })?
            }
            ExecutePassword { plan_handle, .. } => {
                handle(&plan_handle)?;
                let plan = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    if entry
                        .password_plan
                        .as_ref()
                        .is_none_or(|plan| plan.handle != plan_handle)
                    {
                        return Err(MySqlRuntimeError::Stale);
                    }
                    entry.password_busy = true;
                    Ok(entry.password_plan.take().expect("checked plan"))
                })?;
                let _lease = PasswordLease {
                    entries: self.entries.clone(),
                    scope: scope.clone(),
                };
                let confirmation = DangerousConfirmation::approve(plan.core.definition());
                let execution = match self
                    .services
                    .database()
                    .execute_mysql_password(
                        &session,
                        plan.core,
                        confirmation,
                        self.services.operation_journal(),
                    )
                    .await
                {
                    Ok(execution) => execution,
                    Err(error) => {
                        let detail = error.to_string();
                        let code = if detail.contains("未确认") {
                            "unknown-state"
                        } else if detail.contains("已变化") || detail.contains("过期") {
                            "stale"
                        } else {
                            "rejected"
                        };
                        return Ok(
                            json!({"kind":"rejected","action":"execute-password","code":code,"detail":detail}),
                        );
                    }
                };
                let outcome = execution.outcome;
                // The change already committed remotely; bookkeeping below is
                // best-effort and must not lose the outcome.
                let (restore_handle, restore_unavailable) = match execution.restore_token {
                    Some(token) => {
                        let handle = new_handle();
                        match self.with_entry(&scope, |entry| {
                            entry.restore = Some(RestoreSlot {
                                handle: handle.clone(),
                                token,
                            });
                            Ok(())
                        }) {
                            Ok(_) => (Some(handle), false),
                            Err(_) => (None, true),
                        }
                    }
                    None => (None, false),
                };
                let profile = if outcome.saved_password == SavedPasswordUpdate::Updated {
                    self.refresh_profile(&scope, &plan.profile_id, &plan.profile_handle)
                        .unwrap_or_default()
                } else {
                    None
                };
                let profile = serde_json::to_value(&profile).unwrap_or(Value::Null);
                let (state, reason) = match outcome.verification {
                    MySqlPasswordVerification::Passed => ("passed", None),
                    MySqlPasswordVerification::Rejected => ("rejected", None),
                    MySqlPasswordVerification::Unverifiable => {
                        ("unverifiable", Some("path"))
                    }
                };
                json!({"kind":"password-result","result":{
                    "verification":{"state":state,"reason":reason},
                    "savedPassword":outcome.saved_password,
                    "restorable":outcome.restorable,
                    "journalRecorded":outcome.journal_recorded,
                    "restoreHandle":restore_handle,
                    "restoreUnavailable":restore_unavailable,
                    "profile":profile,
                }})
            }
            PlanPasswordRestore {
                restore_handle,
                profile_handle,
                ..
            } => {
                handle(&restore_handle)?;
                let (token, snapshot) = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    if entry
                        .restore
                        .as_ref()
                        .is_none_or(|slot| slot.handle != restore_handle)
                    {
                        return Err(MySqlRuntimeError::Stale);
                    }
                    let snapshot = self.profile(entry, &profile_handle)?;
                    Ok((entry.restore.take().expect("checked restore").token, snapshot))
                })?;
                let plan = self
                    .services
                    .database()
                    .plan_mysql_password_restore(&session, &snapshot, token)
                    .await
                    .map_err(|error| {
                        let (_, detail) = lovelyhawk_core::database_password::public_reason(&error);
                        MySqlRuntimeError::Rejected(
                            "stale",
                            format!("{detail} 恢复令牌只能使用一次，旧口令已无法自动放回。"),
                        )
                    })?;
                let view =
                    serde_json::to_value(&plan.view).map_err(|_| MySqlRuntimeError::Store)?;
                self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    let id = new_handle();
                    entry.restore_plan = Some(RestorePlan {
                        handle: id.clone(),
                        core: plan,
                        profile_id: snapshot.view().config.id.clone(),
                        profile_handle: profile_handle.clone(),
                    });
                    Ok(json!({"kind":"password-restore-plan","planHandle":id,"expiresInMs":120000,"plan":view}))
                })?
            }
            ExecutePasswordRestore { plan_handle, .. } => {
                handle(&plan_handle)?;
                let plan = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    if entry
                        .restore_plan
                        .as_ref()
                        .is_none_or(|plan| plan.handle != plan_handle)
                    {
                        return Err(MySqlRuntimeError::Stale);
                    }
                    entry.password_busy = true;
                    Ok(entry.restore_plan.take().expect("checked plan"))
                })?;
                let _lease = PasswordLease {
                    entries: self.entries.clone(),
                    scope: scope.clone(),
                };
                let confirmation = DangerousConfirmation::approve(plan.core.definition());
                let outcome = match self
                    .services
                    .database()
                    .execute_mysql_password_restore(
                        &session,
                        plan.core,
                        confirmation,
                        self.services.operation_journal(),
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let detail = error.to_string();
                        let code = if detail.contains("未确认") {
                            "unknown-state"
                        } else if detail.contains("已变化") || detail.contains("过期") {
                            "stale"
                        } else {
                            "rejected"
                        };
                        return Ok(
                            json!({"kind":"rejected","action":"execute-password-restore","code":code,"detail":detail}),
                        );
                    }
                };
                let profile = if outcome.saved_password_restored {
                    self.refresh_profile(&scope, &plan.profile_id, &plan.profile_handle)
                        .unwrap_or_default()
                } else {
                    None
                };
                let profile = serde_json::to_value(&profile).unwrap_or(Value::Null);
                json!({"kind":"password-restore-result","result":{
                    "verified":outcome.verified,
                    "savedPasswordRestored":outcome.saved_password_restored,
                    "journalRecorded":outcome.journal_recorded,
                    "profile":profile,
                }})
            }
            Privileges {
                profile_handle,
                account,
                ..
            } => {
                let account = MySqlAccount::new(&account.user, &account.host)
                    .map_err(|_| MySqlRuntimeError::Invalid)?;
                let snapshot = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    self.profile(entry, &profile_handle)
                })?;
                let (read, _profile_id) = self
                    .services
                    .database()
                    .mysql_privilege_review(&session, &snapshot, account)
                    .await
                    .map_err(core_error)?;
                let rows = mysql_privilege::parse_show_grants(&read.grant_lines);
                let dto_rows: Vec<Value> = rows
                    .iter()
                    .enumerate()
                    .map(|(index, row)| {
                        let (kind, db, table) = match &row.scope {
                            GrantScope::Global => ("global", None, None),
                            GrantScope::Database(db) => ("database", Some(db.clone()), None),
                            GrantScope::Table(db, table) => {
                                ("table", Some(db.clone()), Some(table.clone()))
                            }
                            GrantScope::Other => ("other", None, None),
                        };
                        json!({"row":index,"raw":row.raw,"parseable":row.parseable,
                            "scope":{"kind":kind,"database":db,"table":table},
                            "privileges":row.privileges,
                            "members":row.members(),
                            "allPrivileges":row.all_privileges,
                            "grantOption":row.grant_option})
                    })
                    .collect();
                self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    entry.touched = Instant::now();
                    Ok(())
                })?;
                json!({"kind":"privileges","review":{
                    "product":match read.product {
                        lovelyhawk_core::mysql_password::MySqlProduct::MySql => "MySQL",
                        lovelyhawk_core::mysql_password::MySqlProduct::MariaDb => "MariaDB",
                    },
                    "serverVersion":read.server_version,
                    "connecting":{"user":read.connecting.user,"host":read.connecting.host},
                    "rows":dto_rows,
                    "schemas":read.schemas,
                    "tables":read.tables.iter()
                        .map(|(db, table)| json!({"database":db,"table":table}))
                        .collect::<Vec<Value>>(),
                }})
            }
            PlanPrivileges {
                profile_handle,
                account,
                revokes,
                grants,
                ..
            } => {
                let account = MySqlAccount::new(&account.user, &account.host)
                    .map_err(|_| MySqlRuntimeError::Invalid)?;
                if revokes.len() > 200
                    || grants.len() > 200
                    || revokes.iter().any(|row| row.privileges.len() > 64)
                    || grants.iter().any(|row| row.privileges.len() > 64)
                {
                    return Err(MySqlRuntimeError::Invalid);
                }
                let snapshot = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    self.profile(entry, &profile_handle)
                })?;
                let revoke_choices: Vec<mysql_privilege::RevokeChoice> = revokes
                    .iter()
                    .map(|row| mysql_privilege::RevokeChoice {
                        row: row.row,
                        privileges: row.privileges.clone(),
                    })
                    .collect();
                let add_choices: Vec<mysql_privilege::AddChoice> = grants
                    .iter()
                    .map(|row| mysql_privilege::AddChoice {
                        scope: match &row.table {
                            Some(table) => GrantScope::Table(
                                row.database.clone(),
                                table.clone(),
                            ),
                            None => GrantScope::Database(row.database.clone()),
                        },
                        privileges: row.privileges.clone(),
                    })
                    .collect();
                let plan = self
                    .services
                    .database()
                    .plan_mysql_privileges(&session, &snapshot, account, revoke_choices, add_choices)
                    .await
                    .map_err(core_error)?;
                let view =
                    serde_json::to_value(&plan.view).map_err(|_| MySqlRuntimeError::Store)?;
                self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    let id = new_handle();
                    entry.privilege_plan = Some(PrivilegePlanSlot {
                        handle: id.clone(),
                        profile_handle: profile_handle.clone(),
                        plan,
                    });
                    Ok(json!({"kind":"privilege-plan","planHandle":id,"expiresInMs":120000,"plan":view}))
                })?
            }
            ExecutePrivileges { plan_handle, .. } => {
                handle(&plan_handle)?;
                let slot = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    if entry
                        .privilege_plan
                        .as_ref()
                        .is_none_or(|plan| plan.handle != plan_handle)
                    {
                        return Err(MySqlRuntimeError::Stale);
                    }
                    entry.privilege_busy = true;
                    Ok(entry.privilege_plan.take().expect("checked plan"))
                })?;
                let _lease = PasswordLease {
                    entries: self.entries.clone(),
                    scope: scope.clone(),
                };
                let snapshot = self.with_entry(&scope, |entry| {
                    self.profile(entry, &slot.profile_handle)
                })?;
                let (receipt, outcome) = match self
                    .services
                    .database()
                    .execute_mysql_privileges(&session, &snapshot, &slot.plan)
                    .await
                {
                    Ok(pair) => pair,
                    Err(error) => {
                        let (code, detail) =
                            lovelyhawk_core::database_password::public_reason(&error);
                        return Ok(json!({"kind":"rejected","action":"execute-privileges","code":code,"detail":detail}));
                    }
                };
                let undo_handle = new_handle();
                self.with_entry(&scope, |entry| {
                    entry.privilege_undo = Some(PrivilegeUndoSlot {
                        handle: undo_handle.clone(),
                        profile_handle: slot.profile_handle.clone(),
                        plan: slot.plan,
                        applied_lines: outcome.after_lines.clone(),
                        applied: outcome.applied,
                        at: Instant::now(),
                    });
                    Ok(())
                })?;
                let receipt = serde_json::to_value(&receipt)
                    .map_err(|_| MySqlRuntimeError::Store)?;
                json!({"kind":"privilege-result","receipt":receipt,"undoHandle":undo_handle})
            }
            UndoPrivileges { plan_handle, .. } => {
                handle(&plan_handle)?;
                let slot = self.with_entry(&scope, |entry| {
                    Self::idle(entry)?;
                    match &entry.privilege_undo {
                        Some(undo) if undo.handle == plan_handle => {
                            if undo.at.elapsed() > UNDO_TTL {
                                entry.privilege_undo = None;
                                return Err(MySqlRuntimeError::Stale);
                            }
                        }
                        _ => return Err(MySqlRuntimeError::Stale),
                    }
                    entry.privilege_busy = true;
                    Ok(entry.privilege_undo.take().expect("checked undo"))
                })?;
                let _lease = PasswordLease {
                    entries: self.entries.clone(),
                    scope: scope.clone(),
                };
                let snapshot = self.with_entry(&scope, |entry| {
                    self.profile(entry, &slot.profile_handle)
                })?;
                let receipt = match self
                    .services
                    .database()
                    .undo_mysql_privileges(
                        &session,
                        &snapshot,
                        &slot.plan,
                        &slot.applied_lines,
                        slot.applied,
                    )
                    .await
                {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        let (code, detail) =
                            lovelyhawk_core::database_password::public_reason(&error);
                        return Ok(json!({"kind":"rejected","action":"undo-privileges","code":code,"detail":detail}));
                    }
                };
                let receipt = serde_json::to_value(&receipt)
                    .map_err(|_| MySqlRuntimeError::Store)?;
                json!({"kind":"privilege-result","receipt":receipt,"undoHandle":Value::Null})
            }
        };
        Ok(response)
    }
}

fn read_password<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<SecretValue, D::Error> {
    let value = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
    if value.is_empty() || value.len() > 16384 || value.contains('\0') {
        return Err(serde::de::Error::custom("invalid database credential"));
    }
    Ok(SecretValue::new(value.to_string()))
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

/// Clears `password_busy` if the holder's scope is still live when the
/// in-flight call returns; a stale scope keeps the entry dropped instead.
struct PasswordLease {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    scope: Scope,
}

impl Drop for PasswordLease {
    fn drop(&mut self) {
        if let Some(entry) = self.entries.lock().get_mut(&self.scope.binding) {
            entry.password_busy = false;
            entry.privilege_busy = false;
        }
    }
}
