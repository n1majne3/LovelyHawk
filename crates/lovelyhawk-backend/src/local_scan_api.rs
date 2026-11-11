//! Fetching target content into the local quarantine area and starting a
//! configured local engine against it.
//!
//! `program` inside `configure` arrives only through the host's native file
//! dialog — a page never sends one. Every later action names a stored fetch
//! id, not a local path, and resolves through this registry against the
//! binding the fetch was minted under.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    file_evidence::FileEvidenceProgress,
    local_scan::{
        FETCH_KIND_REFUSAL, FETCH_SIZE_REFUSAL, FETCH_TOOLS_REFUSAL, FetchKind, LocalScanEngine,
        LocalScanEngineKind, LocalScanManifest, LocalScanScope, create_fetch_staging,
        engine_launch, extract_fetch_archive, fetch_bundle_command, fetch_probe_command,
        fetch_root, parse_fetch_bundle, parse_fetch_probe, validate_engine, write_manifest,
    },
    sftp::RemotePath,
    ssh::SshCommandOutput,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    emergency_path_api::{EmergencyPathApi, PathScope},
    ssh_api::SshApi,
};

const MAX_FETCHES: usize = 8;
const FETCH_TTL: Duration = Duration::from_secs(30 * 60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const BUNDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_RUN_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RUN_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ENTRIES_DISPLAY: usize = 200;

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum LocalScanRequest {
    Engines {},
    Configure {
        name: String,
        kind: String,
        #[serde(default)]
        arguments: Vec<String>,
        /// Absolute program path — host dialog input only.
        program: String,
    },
    RemoveEngine {
        engine_id: String,
    },
    Fetch {
        binding_handle: String,
        path_handle: String,
        scope: String,
    },
    Inspect {
        binding_handle: String,
        fetch_id: String,
    },
    Run {
        binding_handle: String,
        fetch_id: String,
        engine_id: String,
    },
    Reveal {
        binding_handle: String,
        fetch_id: String,
    },
    Discard {
        binding_handle: String,
        fetch_id: String,
    },
}

#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(crate) enum LocalScanResponse {
    Engines {
        engines: Vec<EngineDto>,
    },
    Fetch {
        fetch: FetchDto,
    },
    Run {
        state: String,
        engine_name: String,
        exit_code: Option<i32>,
        output: Option<String>,
        detail: String,
    },
    Done {
        detail: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EngineDto {
    id: String,
    name: String,
    kind: String,
    program_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FetchDto {
    fetch_id: String,
    path: String,
    source_kind: String,
    scope: String,
    files: usize,
    directories: usize,
    bytes: u64,
    skipped: usize,
    skipped_reasons: Vec<String>,
    truncated: bool,
    archive_sha256: String,
    archive_bytes: u64,
    transport: String,
    staging_directory: String,
    entries: Vec<String>,
    fetched_at: String,
    expires_in_seconds: u64,
}

struct FetchEntry {
    scope: PathScope,
    dir: PathBuf,
    content_dir: PathBuf,
    created: Instant,
}

#[derive(Clone)]
pub(crate) struct LocalScanApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    paths: EmergencyPathApi,
    fetches: Arc<Mutex<HashMap<String, FetchEntry>>>,
}
impl std::fmt::Debug for LocalScanApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalScanApi")
            .field("fetches", &self.fetches.lock().len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum LocalScanError {
    Invalid,
    Stale,
    Capacity,
    Tools,
    Kind,
    Size,
    Engine,
    Launch,
    Unavailable,
}

impl LocalScanApi {
    pub(crate) fn new(
        services: BackendServices,
        ssh_api: Arc<SshApi>,
        paths: EmergencyPathApi,
    ) -> Self {
        Self {
            services,
            ssh_api,
            paths,
            fetches: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn close_binding(&self, binding: &str) {
        let mut fetches = self.fetches.lock();
        let stale: Vec<String> = fetches
            .iter()
            .filter(|(_, entry)| entry.scope.binding_handle == binding)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(entry) = fetches.remove(&id) {
                let _ = std::fs::remove_dir_all(&entry.dir);
            }
        }
    }

    pub(crate) async fn dispatch(
        &self,
        request: LocalScanRequest,
    ) -> Result<LocalScanResponse, LocalScanError> {
        self.prune();
        match request {
            LocalScanRequest::Engines {} => self.engines(),
            LocalScanRequest::Configure {
                name,
                kind,
                arguments,
                program,
            } => self.configure(&name, &kind, arguments, &program),
            LocalScanRequest::RemoveEngine { engine_id } => self.remove_engine(&engine_id),
            LocalScanRequest::Fetch {
                binding_handle,
                path_handle,
                scope,
            } => self.fetch(&binding_handle, &path_handle, &scope).await,
            LocalScanRequest::Inspect {
                binding_handle,
                fetch_id,
            } => self.inspect(&binding_handle, &fetch_id),
            LocalScanRequest::Run {
                binding_handle,
                fetch_id,
                engine_id,
            } => self.run(&binding_handle, &fetch_id, &engine_id).await,
            LocalScanRequest::Reveal {
                binding_handle,
                fetch_id,
            } => self.reveal(&binding_handle, &fetch_id),
            LocalScanRequest::Discard {
                binding_handle,
                fetch_id,
            } => self.discard(&binding_handle, &fetch_id),
        }
    }

    fn prune(&self) {
        let mut fetches = self.fetches.lock();
        let stale: Vec<String> = fetches
            .iter()
            .filter(|(_, entry)| entry.created.elapsed() > FETCH_TTL)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(entry) = fetches.remove(&id) {
                let _ = std::fs::remove_dir_all(&entry.dir);
            }
        }
    }

    fn live_entry(
        &self,
        binding: &str,
        fetch_id: &str,
    ) -> Result<(PathScope, PathBuf, PathBuf), LocalScanError> {
        if !valid_field(fetch_id, 128) {
            return Err(LocalScanError::Invalid);
        }
        let fetches = self.fetches.lock();
        let entry = fetches
            .get(fetch_id)
            .filter(|entry| entry.scope.binding_handle == binding)
            .ok_or(LocalScanError::Stale)?;
        self.paths
            .validate_binding(&entry.scope)
            .map_err(|_| LocalScanError::Stale)?;
        if !lovelyhawk_core::local_scan::is_fetch_staging(self.services.store(), &entry.dir) {
            return Err(LocalScanError::Unavailable);
        }
        Ok((
            entry.scope.clone(),
            entry.dir.clone(),
            entry.content_dir.clone(),
        ))
    }

    fn engines(&self) -> Result<LocalScanResponse, LocalScanError> {
        let settings = self
            .services
            .settings()
            .load()
            .map_err(|_| LocalScanError::Unavailable)?;
        let engines = settings
            .local_scan
            .engines
            .iter()
            .map(|engine| EngineDto {
                id: engine.id.clone(),
                name: engine.name.clone(),
                kind: engine.kind.as_str().to_owned(),
                program_name: Path::new(&engine.program)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| engine.program.clone()),
            })
            .collect();
        Ok(LocalScanResponse::Engines { engines })
    }

    fn configure(
        &self,
        name: &str,
        kind: &str,
        arguments: Vec<String>,
        program: &str,
    ) -> Result<LocalScanResponse, LocalScanError> {
        let Some(kind) = LocalScanEngineKind::parse(kind) else {
            return Err(LocalScanError::Invalid);
        };
        if !valid_field(name, 64) || !valid_field(program, 1024) {
            return Err(LocalScanError::Invalid);
        }
        let program_path = Path::new(program);
        if !program_path.is_absolute() || !program_path.is_file() {
            return Err(LocalScanError::Engine);
        }
        self.services
            .settings()
            .update(|settings| {
                // Replace a same-named engine or append a new one; the id is
                // stable for the page, never derived from the local path.
                let id = settings
                    .local_scan
                    .engines
                    .iter()
                    .find(|engine| engine.name == name)
                    .map(|engine| engine.id.clone())
                    .unwrap_or_else(|| {
                        format!("eng-{}", &Uuid::new_v4().simple().to_string()[..8])
                    });
                let engine = LocalScanEngine {
                    id: id.clone(),
                    name: name.to_owned(),
                    kind,
                    program: program.to_owned(),
                    arguments,
                };
                validate_engine(&engine)?;
                settings
                    .local_scan
                    .engines
                    .retain(|stored| stored.id != id && stored.name != name);
                settings.local_scan.engines.push(engine);
                Ok(())
            })
            .map_err(|_| LocalScanError::Engine)?;
        self.engines()
    }

    fn remove_engine(&self, engine_id: &str) -> Result<LocalScanResponse, LocalScanError> {
        if !valid_field(engine_id, 64) {
            return Err(LocalScanError::Invalid);
        }
        self.services
            .settings()
            .update(|settings| {
                settings
                    .local_scan
                    .engines
                    .retain(|engine| engine.id != engine_id);
                Ok(())
            })
            .map_err(|_| LocalScanError::Unavailable)?;
        self.engines()
    }

    async fn fetch(
        &self,
        binding: &str,
        path_handle: &str,
        scope_value: &str,
    ) -> Result<LocalScanResponse, LocalScanError> {
        let Some(scope) = LocalScanScope::parse(scope_value) else {
            return Err(LocalScanError::Invalid);
        };
        let (path_scope, path) = self
            .paths
            .resolve_evidence_path(binding, path_handle)
            .map_err(|_| LocalScanError::Stale)?;
        let root = fetch_root(&path, scope).map_err(local_scan_core_failure)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding)
            .map_err(|_| LocalScanError::Stale)?;
        self.paths
            .validate_binding(&path_scope)
            .map_err(|_| LocalScanError::Stale)?;

        let probe = self
            .exec(&session, fetch_probe_command(&root), PROBE_TIMEOUT)
            .await?;
        let probe = parse_fetch_probe(&probe.output);
        if !probe.tar || (probe.kind == FetchKind::Directory && !probe.find) {
            return Err(LocalScanError::Tools);
        }
        if probe.kind == FetchKind::Other {
            return Err(LocalScanError::Kind);
        }
        if let Some(size) = probe.size
            && probe.kind == FetchKind::File
            && size > lovelyhawk_core::local_scan::MAX_FETCH_ARCHIVE_BYTES
        {
            return Err(LocalScanError::Size);
        }

        let bundled = self
            .exec(
                &session,
                fetch_bundle_command(&root, probe.kind),
                BUNDLE_TIMEOUT,
            )
            .await?;
        let bundle = parse_fetch_bundle(&bundled.output).map_err(local_scan_core_failure)?;
        if bundle.bytes > lovelyhawk_core::local_scan::MAX_FETCH_ARCHIVE_BYTES {
            self.cleanup_remote(&session, &bundle.archive).await;
            return Err(LocalScanError::Size);
        }
        self.paths
            .validate_binding(&path_scope)
            .map_err(|_| LocalScanError::Stale)?;

        let staging =
            create_fetch_staging(self.services.store()).map_err(|_| LocalScanError::Unavailable)?;
        let archive_local = staging.dir.join("bundle.tar");
        let result = self
            .download_archive(&path_scope, &bundle.archive, &archive_local)
            .await;
        self.cleanup_remote(&session, &bundle.archive).await;
        let proof = match result {
            Ok(proof) => proof,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging.dir);
                return Err(error);
            }
        };

        let report = match extract_fetch_archive(&archive_local, &staging.content_dir) {
            Ok(report) => report,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&staging.dir);
                return Err(LocalScanError::Unavailable);
            }
        };
        let _ = std::fs::remove_file(&archive_local);

        let target_label = self.target_label(&path_scope).await;
        let mut limitations = vec![
            "取回内容按不可信来源隔离存放：去除执行权限并标记为来自网络；取回本身不代表文件安全。".to_owned(),
            "远端 find 只覆盖普通文件与目录，符号链接、套接字与设备不会取回；超出边界的成员已跳过。".to_owned(),
            "本机安全软件会实时检查取回内容，可能拦截或锁定命中文件——这是取回活动的固有面，不是错误。".to_owned(),
        ];
        if bundle.truncated {
            limitations.push(format!(
                "目录成员数超过 {} 上限，取回内容不完整。",
                lovelyhawk_core::local_scan::MAX_FETCH_ENTRIES
            ));
        }
        if proof.transport == "scp" {
            limitations.push("目标缺少 SFTP 子系统，本次经 SCP 取回。".to_owned());
        }
        let fetched_at = proof.completed_at.to_rfc3339();
        let manifest = LocalScanManifest {
            version: 1,
            source_path: path.as_str().to_owned(),
            source_kind: match probe.kind {
                FetchKind::File => "file",
                FetchKind::Directory => "directory",
                FetchKind::Other => "other",
            }
            .to_owned(),
            scope: scope.as_str().to_owned(),
            target_label: target_label.clone(),
            fetched_at: fetched_at.clone(),
            transport: proof.transport.clone(),
            archive_sha256: proof.sha256.clone(),
            archive_bytes: bundle.bytes,
            files: report.files,
            directories: report.directories,
            bytes: report.bytes,
            skipped: report.skipped,
            truncated: bundle.truncated,
            entries: report.entries.clone(),
            limitations,
        };
        if write_manifest(&staging, &manifest).is_err() {
            let _ = std::fs::remove_dir_all(&staging.dir);
            return Err(LocalScanError::Unavailable);
        }

        let fetch_id = Uuid::new_v4().to_string();
        let dto = FetchDto {
            fetch_id: fetch_id.clone(),
            path: path.as_str().to_owned(),
            source_kind: manifest.source_kind.clone(),
            scope: manifest.scope.clone(),
            files: report.files,
            directories: report.directories,
            bytes: report.bytes,
            skipped: report.skipped,
            skipped_reasons: report.skipped_reasons.clone(),
            truncated: bundle.truncated,
            archive_sha256: proof.sha256,
            archive_bytes: bundle.bytes,
            transport: proof.transport,
            staging_directory: staging.content_dir.to_string_lossy().into_owned(),
            entries: report
                .entries
                .into_iter()
                .take(MAX_ENTRIES_DISPLAY)
                .collect(),
            fetched_at,
            expires_in_seconds: FETCH_TTL.as_secs(),
        };
        let mut fetches = self.fetches.lock();
        if fetches.len() >= MAX_FETCHES {
            // Make room by dropping this binding's oldest fetch, or refuse.
            let oldest = fetches
                .iter()
                .filter(|(_, entry)| entry.scope.binding_handle == binding)
                .min_by_key(|(_, entry)| entry.created)
                .map(|(id, _)| id.clone());
            match oldest {
                Some(id) => {
                    if let Some(entry) = fetches.remove(&id) {
                        let _ = std::fs::remove_dir_all(&entry.dir);
                    }
                }
                None => {
                    drop(fetches);
                    let _ = std::fs::remove_dir_all(&staging.dir);
                    return Err(LocalScanError::Capacity);
                }
            }
        }
        fetches.insert(
            fetch_id,
            FetchEntry {
                scope: path_scope,
                dir: staging.dir,
                content_dir: staging.content_dir,
                created: Instant::now(),
            },
        );
        Ok(LocalScanResponse::Fetch { fetch: dto })
    }

    fn inspect(&self, binding: &str, fetch_id: &str) -> Result<LocalScanResponse, LocalScanError> {
        let (_, dir, content_dir) = self.live_entry(binding, fetch_id)?;
        let manifest = lovelyhawk_core::local_scan::read_manifest(&dir)
            .map_err(|_| LocalScanError::Unavailable)?;
        let remaining = {
            let fetches = self.fetches.lock();
            fetches
                .get(fetch_id)
                .map(|entry| {
                    FETCH_TTL
                        .as_secs()
                        .saturating_sub(entry.created.elapsed().as_secs())
                })
                .unwrap_or(0)
        };
        let dto = FetchDto {
            fetch_id: fetch_id.to_owned(),
            path: manifest.source_path.clone(),
            source_kind: manifest.source_kind.clone(),
            scope: manifest.scope.clone(),
            files: manifest.files,
            directories: manifest.directories,
            bytes: manifest.bytes,
            skipped: manifest.skipped,
            skipped_reasons: manifest.limitations.clone(),
            truncated: manifest.truncated,
            archive_sha256: manifest.archive_sha256.clone(),
            archive_bytes: manifest.archive_bytes,
            transport: manifest.transport.clone(),
            staging_directory: content_dir.to_string_lossy().into_owned(),
            entries: manifest.entries.clone(),
            fetched_at: manifest.fetched_at.clone(),
            expires_in_seconds: remaining,
        };
        Ok(LocalScanResponse::Fetch { fetch: dto })
    }

    async fn run(
        &self,
        binding: &str,
        fetch_id: &str,
        engine_id: &str,
    ) -> Result<LocalScanResponse, LocalScanError> {
        if !valid_field(engine_id, 64) {
            return Err(LocalScanError::Invalid);
        }
        let (_, _, content_dir) = self.live_entry(binding, fetch_id)?;
        let settings = self
            .services
            .settings()
            .load()
            .map_err(|_| LocalScanError::Unavailable)?;
        let engine = settings
            .local_scan
            .engines
            .into_iter()
            .find(|engine| engine.id == engine_id)
            .ok_or(LocalScanError::Engine)?;
        let (program, argv) =
            engine_launch(&engine, &content_dir).map_err(|_| LocalScanError::Engine)?;
        match engine.kind {
            LocalScanEngineKind::Gui => {
                let mut command = std::process::Command::new(&program);
                command.args(&argv).current_dir(&content_dir);
                match command.spawn() {
                    Ok(_) => Ok(LocalScanResponse::Run {
                        state: "launched".to_owned(),
                        engine_name: engine.name.clone(),
                        exit_code: None,
                        output: None,
                        detail: format!(
                            "已启动 {}；请在引擎窗口中选择目录 {}",
                            engine.name,
                            content_dir.display()
                        ),
                    }),
                    Err(_) => Err(LocalScanError::Launch),
                }
            }
            LocalScanEngineKind::Cli => {
                let output = tokio::time::timeout(
                    CLI_RUN_TIMEOUT,
                    tokio::process::Command::new(&program)
                        .args(&argv)
                        .current_dir(&content_dir)
                        .output(),
                )
                .await;
                let output = match output {
                    Ok(Ok(output)) => output,
                    _ => return Err(LocalScanError::Launch),
                };
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(LocalScanResponse::Run {
                    state: "finished".to_owned(),
                    engine_name: engine.name.clone(),
                    exit_code: output.status.code(),
                    output: Some(bounded_output(&text)),
                    detail: format!(
                        "{} 已退出，退出码 {:?}；输出已截断到 {} 字节",
                        engine.name,
                        output.status.code(),
                        MAX_RUN_OUTPUT_BYTES
                    ),
                })
            }
        }
    }

    fn reveal(&self, binding: &str, fetch_id: &str) -> Result<LocalScanResponse, LocalScanError> {
        let (_, _, content_dir) = self.live_entry(binding, fetch_id)?;
        let opened = open_in_file_manager(&content_dir);
        if opened {
            Ok(LocalScanResponse::Done {
                detail: format!("已在文件管理器中打开 {}", content_dir.display()),
            })
        } else {
            Err(LocalScanError::Unavailable)
        }
    }

    fn discard(&self, binding: &str, fetch_id: &str) -> Result<LocalScanResponse, LocalScanError> {
        let _ = self.live_entry(binding, fetch_id)?;
        let entry = self.fetches.lock().remove(fetch_id);
        if let Some(entry) = entry {
            let _ = std::fs::remove_dir_all(&entry.dir);
        }
        Ok(LocalScanResponse::Done {
            detail: "已删除本次取回的本地副本。".to_owned(),
        })
    }

    async fn exec(
        &self,
        session: &lovelyhawk_core::ssh::BoundSshSession,
        command: String,
        timeout: Duration,
    ) -> Result<SshCommandOutput, LocalScanError> {
        let output = self
            .services
            .ssh()
            .execute_bound(session, command, timeout)
            .await
            .map_err(|_| LocalScanError::Unavailable)?;
        if output.timed_out {
            return Err(LocalScanError::Unavailable);
        }
        Ok(output)
    }

    async fn cleanup_remote(
        &self,
        session: &lovelyhawk_core::ssh::BoundSshSession,
        archive: &RemotePath,
    ) {
        let _ = self
            .services
            .ssh()
            .execute_bound(
                session,
                format!(
                    "rm -f -- {}",
                    lovelyhawk_core::shell_escape::shq(archive.as_str())
                ),
                CLEANUP_TIMEOUT,
            )
            .await;
    }

    async fn download_archive(
        &self,
        scope: &PathScope,
        archive: &RemotePath,
        local: &Path,
    ) -> Result<lovelyhawk_core::file_evidence::FileEvidenceReadProof, LocalScanError> {
        let session = self
            .paths
            .bind_sftp(scope)
            .await
            .map_err(|_| LocalScanError::Stale)?;
        // Read+write: the collector rewinds and re-hashes the saved bytes as
        // its final consistency check, so a write-only handle fails.
        let mut open = std::fs::OpenOptions::new();
        open.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let destination = open.open(local).map_err(|_| LocalScanError::Unavailable)?;
        let result = tokio::time::timeout(
            DOWNLOAD_TIMEOUT,
            self.services.sftp().collect_file_evidence(
                &session,
                archive,
                destination,
                FileEvidenceProgress::default(),
            ),
        )
        .await;
        match result {
            Ok(Ok(proof)) => Ok(proof),
            _ => {
                let _ = std::fs::remove_file(local);
                Err(LocalScanError::Unavailable)
            }
        }
    }

    async fn target_label(&self, scope: &PathScope) -> String {
        let status = self
            .services
            .ssh()
            .list_sessions()
            .await
            .ok()
            .and_then(|sessions| {
                sessions.into_iter().find(|s| {
                    s.session_id == scope.session_id && s.connection_id == scope.connection_id
                })
            });
        match status {
            Some(status) => format!("{}@{}:{}", status.username, status.host, status.port),
            None => "未知目标".to_owned(),
        }
    }
}

fn valid_field(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn bounded_output(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_RUN_OUTPUT_BYTES));
    for character in text.chars() {
        if out.len() >= MAX_RUN_OUTPUT_BYTES {
            break;
        }
        if character.is_control() && !matches!(character, '\n' | '\t' | '\r') {
            out.push(char::REPLACEMENT_CHARACTER);
        } else {
            out.push(character);
        }
    }
    out
}

#[cfg(windows)]
fn open_in_file_manager(path: &Path) -> bool {
    std::process::Command::new("explorer.exe")
        .arg(path)
        .spawn()
        .is_ok()
}

#[cfg(not(windows))]
fn open_in_file_manager(path: &Path) -> bool {
    std::process::Command::new("xdg-open")
        .arg(path)
        .spawn()
        .is_ok()
}

fn local_scan_core_failure(error: CoreError) -> LocalScanError {
    match &error {
        CoreError::Validation { subject, .. } => match *subject {
            FETCH_TOOLS_REFUSAL => LocalScanError::Tools,
            FETCH_KIND_REFUSAL => LocalScanError::Kind,
            FETCH_SIZE_REFUSAL => LocalScanError::Size,
            _ => LocalScanError::Unavailable,
        },
        _ => LocalScanError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_output_strips_controls_and_caps() {
        let out = bounded_output("ok\u{7}\nline");
        assert_eq!(out, "ok\u{FFFD}\nline");
        let long = "x".repeat(MAX_RUN_OUTPUT_BYTES + 10);
        assert_eq!(bounded_output(&long).len(), MAX_RUN_OUTPUT_BYTES);
    }
}
