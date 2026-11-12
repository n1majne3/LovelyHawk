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
    docker::ContainerIdentity,
    file_evidence::FileEvidenceProgress,
    local_scan::{
        EngineMention, FETCH_KIND_REFUSAL, FETCH_SIZE_REFUSAL, FETCH_TOOLS_REFUSAL, FetchKind,
        FetchRoot, LocalScanEngine, LocalScanEngineKind, LocalScanManifest, LocalScanScope,
        container_fetch_bundle_command, create_fetch_staging, engine_launch, extract_fetch_archive,
        fetch_bundle_command, fetch_probe_command, fetch_root, manifest_member_remote,
        parse_fetch_bundle, parse_fetch_probe, read_manifest, scan_engine_mentions,
        validate_engine, write_manifest,
    },
    sftp::RemotePath,
    ssh::SshCommandOutput,
    target::TargetGuard,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    docker_read_api::DockerReadApi,
    emergency_path_api::{EmergencyPathApi, PathOfferSource, PathScope},
    sftp_browser_api::SftpBrowserApi,
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
    FetchBrowser {
        binding_handle: String,
        browser_handle: String,
        entry_handle: String,
        scope: String,
    },
    FetchContainer {
        binding_handle: String,
        snapshot_handle: String,
        container_handle: String,
        path: String,
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
        fetch: Box<FetchDto>,
    },
    Run {
        state: String,
        engine_name: String,
        exit_code: Option<i32>,
        output: Option<String>,
        hits: Vec<EngineHitDto>,
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

/// One fetched member a CLI engine named in its output, mapped back to the
/// remote path through the fetch manifest. `pathHandle` is minted only for
/// host-origin fetches; container hits stay display-only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EngineHitDto {
    remote_path: String,
    member: String,
    line: String,
    path_handle: Option<String>,
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
    /// `host` or `container`: where the fetched bytes came from.
    origin: String,
    /// Who the content came from when it was not the host; empty for `host`.
    origin_label: String,
}

/// Who a fetch belongs to: the binding plus the session, connection and
/// target identity it was minted under. Every fetch source mints the same
/// owner, so later actions resolve identically no matter where the path came
/// from.
#[derive(Clone, PartialEq, Eq)]
struct FetchOwner {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl FetchOwner {
    fn to_path_scope(&self) -> PathScope {
        PathScope {
            binding_handle: self.binding_handle.clone(),
            session_id: self.session_id.clone(),
            connection_id: self.connection_id.clone(),
            target: self.target.clone(),
        }
    }
}

struct FetchEntry {
    owner: FetchOwner,
    dir: PathBuf,
    content_dir: PathBuf,
    created: Instant,
}

#[derive(Clone)]
pub(crate) struct LocalScanApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    paths: EmergencyPathApi,
    sftp_browser: SftpBrowserApi,
    docker_read: Arc<DockerReadApi>,
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
        sftp_browser: SftpBrowserApi,
        docker_read: Arc<DockerReadApi>,
    ) -> Self {
        Self {
            services,
            ssh_api,
            paths,
            sftp_browser,
            docker_read,
            fetches: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn close_binding(&self, binding: &str) {
        let mut fetches = self.fetches.lock();
        let stale: Vec<String> = fetches
            .iter()
            .filter(|(_, entry)| entry.owner.binding_handle == binding)
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
            LocalScanRequest::FetchBrowser {
                binding_handle,
                browser_handle,
                entry_handle,
                scope,
            } => {
                self.fetch_browser(&binding_handle, &browser_handle, &entry_handle, &scope)
                    .await
            }
            LocalScanRequest::FetchContainer {
                binding_handle,
                snapshot_handle,
                container_handle,
                path,
                scope,
            } => {
                self.fetch_container(
                    &binding_handle,
                    &snapshot_handle,
                    &container_handle,
                    &path,
                    &scope,
                )
                .await
            }
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

    /// Who the binding currently is, minted the same way for every fetch
    /// source. The comparison on `validate_owner` is exact, so a reconnect or
    /// a new session under the same binding ends the fetch.
    fn capture_owner(&self, binding: &str) -> Result<FetchOwner, LocalScanError> {
        if !valid_field(binding, 128) {
            return Err(LocalScanError::Invalid);
        }
        let session = self
            .ssh_api
            .binding_session_clone(binding)
            .map_err(|_| LocalScanError::Stale)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| LocalScanError::Stale)?;
        Ok(FetchOwner {
            binding_handle: binding.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        })
    }

    fn validate_owner(&self, owner: &FetchOwner) -> Result<(), LocalScanError> {
        if &self.capture_owner(&owner.binding_handle)? != owner {
            return Err(LocalScanError::Stale);
        }
        Ok(())
    }

    fn live_entry(
        &self,
        binding: &str,
        fetch_id: &str,
    ) -> Result<(FetchOwner, PathBuf, PathBuf), LocalScanError> {
        if !valid_field(fetch_id, 128) {
            return Err(LocalScanError::Invalid);
        }
        let fetches = self.fetches.lock();
        let entry = fetches
            .get(fetch_id)
            .filter(|entry| entry.owner.binding_handle == binding)
            .ok_or(LocalScanError::Stale)?;
        self.validate_owner(&entry.owner)?;
        if !lovelyhawk_core::local_scan::is_fetch_staging(self.services.store(), &entry.dir) {
            return Err(LocalScanError::Unavailable);
        }
        Ok((
            entry.owner.clone(),
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

    /// A path offered beside command output on the target's own filesystem.
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
        let owner = self.capture_owner(binding)?;
        self.paths
            .validate_binding(&path_scope)
            .map_err(|_| LocalScanError::Stale)?;
        self.fetch_pipeline(
            owner,
            scope,
            path.as_str().to_owned(),
            FetchSource::Host { root },
            "host",
        )
        .await
    }

    /// A file or directory entry an SFTP browser already offered.
    async fn fetch_browser(
        &self,
        binding: &str,
        browser_handle: &str,
        entry_handle: &str,
        scope_value: &str,
    ) -> Result<LocalScanResponse, LocalScanError> {
        let Some(scope) = LocalScanScope::parse(scope_value) else {
            return Err(LocalScanError::Invalid);
        };
        let path = self
            .sftp_browser
            .path_for_fetch(binding, browser_handle, entry_handle)
            .map_err(|_| LocalScanError::Stale)?;
        let root = fetch_root(&path, scope).map_err(local_scan_core_failure)?;
        let owner = self.capture_owner(binding)?;
        self.fetch_pipeline(
            owner,
            scope,
            path.as_str().to_owned(),
            FetchSource::Host { root },
            "host",
        )
        .await
    }

    /// A path inside a listed container, copied out through its runtime.
    async fn fetch_container(
        &self,
        binding: &str,
        snapshot_handle: &str,
        container_handle: &str,
        path: &str,
        scope_value: &str,
    ) -> Result<LocalScanResponse, LocalScanError> {
        let Some(scope) = LocalScanScope::parse(scope_value) else {
            return Err(LocalScanError::Invalid);
        };
        let path = container_fetch_path(path)?;
        let (_session, identity) = self
            .docker_read
            .resolve_container_for_mutation(binding, snapshot_handle, container_handle)
            .map_err(|_| LocalScanError::Stale)?;
        // The scope's directory means the directory holding the path, asked
        // of the container path exactly as of a host path.
        let root = fetch_root(&path, scope).map_err(local_scan_core_failure)?;
        let owner = self.capture_owner(binding)?;
        self.fetch_pipeline(
            owner,
            scope,
            path.as_str().to_owned(),
            FetchSource::Container {
                root,
                identity,
                snapshot_handle: snapshot_handle.to_owned(),
                container_handle: container_handle.to_owned(),
            },
            "container",
        )
        .await
    }

    /// Stage on the target, download, extract, manifest and register — the
    /// tail every fetch source shares once it has resolved where the bytes
    /// come from.
    async fn fetch_pipeline(
        &self,
        owner: FetchOwner,
        scope: LocalScanScope,
        display_path: String,
        source: FetchSource,
        origin: &str,
    ) -> Result<LocalScanResponse, LocalScanError> {
        let session = self
            .ssh_api
            .binding_session_clone(&owner.binding_handle)
            .map_err(|_| LocalScanError::Stale)?;
        self.validate_owner(&owner)?;

        let (bundle_command, probed_kind) = match &source {
            FetchSource::Host { root } => {
                let probe = self
                    .exec(&session, fetch_probe_command(root), PROBE_TIMEOUT)
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
                (fetch_bundle_command(root, probe.kind), Some(probe.kind))
            }
            FetchSource::Container { root, identity, .. } => {
                (container_fetch_bundle_command(identity, root), None)
            }
        };

        let bundled = self.exec(&session, bundle_command, BUNDLE_TIMEOUT).await?;
        let bundle = parse_fetch_bundle(&bundled.output).map_err(local_scan_core_failure)?;
        if bundle.bytes > lovelyhawk_core::local_scan::MAX_FETCH_ARCHIVE_BYTES {
            self.cleanup_remote(&session, &bundle.archive).await;
            return Err(LocalScanError::Size);
        }
        self.validate_owner(&owner)?;
        // The container the bytes came out of is re-resolved after the remote
        // steps, like every other mutation path: a snapshot that moved on
        // since the handle resolved means these bytes are nobody's.
        let origin_label = match &source {
            FetchSource::Host { .. } => String::new(),
            FetchSource::Container {
                identity,
                snapshot_handle,
                container_handle,
                ..
            } => {
                let (_session, again) = self
                    .docker_read
                    .resolve_container_for_mutation(
                        &owner.binding_handle,
                        snapshot_handle,
                        container_handle,
                    )
                    .map_err(|_| LocalScanError::Stale)?;
                if &again != identity {
                    self.cleanup_remote(&session, &bundle.archive).await;
                    return Err(LocalScanError::Stale);
                }
                let name = self
                    .services
                    .docker()
                    .inspect(&session, identity)
                    .await
                    .map(|inspection| inspection.name)
                    .unwrap_or_else(|_| identity.short_id().to_owned());
                format!(
                    "{}（{}，{}）",
                    name,
                    identity.short_id(),
                    identity.runtime().label().to_lowercase()
                )
            }
        };

        let staging =
            create_fetch_staging(self.services.store()).map_err(|_| LocalScanError::Unavailable)?;
        let archive_local = staging.dir.join("bundle.tar");
        let result = self
            .download_archive(&owner.to_path_scope(), &bundle.archive, &archive_local)
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

        let source_kind = match probed_kind {
            Some(FetchKind::File) => "file".to_owned(),
            Some(FetchKind::Directory) => "directory".to_owned(),
            Some(FetchKind::Other) | None => {
                // A container bundle's kind was never probed: it is what the
                // archive's single top-level member turned out to be.
                top_level_kind(&staging.content_dir)
            }
        };

        let target_label = self.target_label(&owner.to_path_scope()).await;
        let mut limitations = vec![
            "取回内容按不可信来源隔离存放：去除执行权限并标记为来自网络；取回本身不代表文件安全。"
                .to_owned(),
        ];
        match &source {
            FetchSource::Host { .. } => limitations.push(
                "远端 find 只覆盖普通文件与目录，符号链接、套接字与设备不会取回；超出边界的成员已跳过。".to_owned(),
            ),
            FetchSource::Container { .. } => limitations.push(
                "经容器运行时 cp 从容器文件系统取回；符号链接不会跟随，取回的是容器当前文件系统，不等于镜像原始内容。".to_owned(),
            ),
        }
        limitations.push(
            "本机安全软件会实时检查取回内容，可能拦截或锁定命中文件——这是取回活动的固有面，不是错误。".to_owned(),
        );
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
            source_path: display_path.clone(),
            origin: origin.to_owned(),
            origin_label: origin_label.clone(),
            source_kind: source_kind.clone(),
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
            path: display_path,
            source_kind,
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
            origin: manifest.origin.clone(),
            origin_label,
        };
        let mut fetches = self.fetches.lock();
        if fetches.len() >= MAX_FETCHES {
            // Make room by dropping this binding's oldest fetch, or refuse.
            let oldest = fetches
                .iter()
                .filter(|(_, entry)| entry.owner.binding_handle == owner.binding_handle)
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
                owner,
                dir: staging.dir,
                content_dir: staging.content_dir,
                created: Instant::now(),
            },
        );
        Ok(LocalScanResponse::Fetch {
            fetch: Box::new(dto),
        })
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
            origin: manifest.origin.clone(),
            origin_label: manifest.origin_label.clone(),
        };
        Ok(LocalScanResponse::Fetch {
            fetch: Box::new(dto),
        })
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
        let (owner, dir, content_dir) = self.live_entry(binding, fetch_id)?;
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
                        hits: Vec::new(),
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
                let text = bounded_output(&text);
                let hits = self.engine_hits(&owner, &dir, &content_dir, &text);
                Ok(LocalScanResponse::Run {
                    state: "finished".to_owned(),
                    engine_name: engine.name.clone(),
                    exit_code: output.status.code(),
                    output: Some(text),
                    hits,
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

    /// Maps engine-named members of this fetch's staging tree back to remote
    /// paths through the manifest, minting a path handle per hit for
    /// host-origin fetches. Raw output text never supplies a path by itself:
    /// a token only counts when `scan_engine_mentions` resolved it to a real
    /// member of the extraction dir, and the remote path only ever comes
    /// from the manifest's recorded source and scope.
    fn engine_hits(
        &self,
        owner: &FetchOwner,
        dir: &Path,
        content_dir: &Path,
        output: &str,
    ) -> Vec<EngineHitDto> {
        let Ok(manifest) = read_manifest(dir) else {
            return Vec::new();
        };
        let pairs: Vec<(EngineMention, String)> = scan_engine_mentions(output, content_dir)
            .into_iter()
            .filter_map(|mention| {
                manifest_member_remote(&manifest, &mention.member).map(|remote| (mention, remote))
            })
            .collect();
        let remotes: Vec<String> = pairs.iter().map(|(_, remote)| remote.clone()).collect();
        let handles = if manifest.origin == "host" {
            self.paths
                .offer_paths(&owner.to_path_scope(), PathOfferSource::LocalScan, &remotes)
        } else {
            vec![None; remotes.len()]
        };
        pairs
            .into_iter()
            .zip(handles)
            .map(|((mention, remote), path_handle)| EngineHitDto {
                remote_path: remote,
                member: mention.member,
                line: mention.line,
                path_handle,
            })
            .collect()
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

/// Where the bundle bytes come from once a fetch source has resolved: the
/// target's own filesystem packed by tar, or a container path streamed out
/// by `runtime cp`.
enum FetchSource {
    Host {
        root: FetchRoot,
    },
    Container {
        root: FetchRoot,
        identity: ContainerIdentity,
        snapshot_handle: String,
        container_handle: String,
    },
}

/// What the single top-level member of an extracted bundle turned out to be.
///
/// Container bundles are never probed, so their kind is read off the staged
/// tree: one directory member is a directory fetch, everything else a file.
fn top_level_kind(content_dir: &Path) -> String {
    let mut top = match std::fs::read_dir(content_dir) {
        Ok(top) => top,
        Err(_) => return "file".to_owned(),
    };
    match (top.next(), top.next()) {
        (Some(Ok(entry)), None) if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) => {
            "directory".to_owned()
        }
        _ => "file".to_owned(),
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

/// A container path is the same shape `exec_directory_path` demands:
/// absolute, bounded, never `/`, and `RemotePath` refuses `.`/`..`/empty
/// components and non-absolute input — nothing becomes `cp` operand text.
fn container_fetch_path(path: &str) -> Result<RemotePath, LocalScanError> {
    if !valid_field(path, 4096) || path == "/" {
        return Err(LocalScanError::Invalid);
    }
    RemotePath::new(path.to_owned()).map_err(|_| LocalScanError::Invalid)
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

    #[test]
    fn request_shapes_are_exact_for_every_fetch_source() {
        let browser: LocalScanRequest = serde_json::from_str(
            r#"{"action":"fetch-browser","bindingHandle":"b","browserHandle":"w","entryHandle":"e","scope":"directory"}"#,
        )
        .unwrap();
        assert!(matches!(
            browser,
            LocalScanRequest::FetchBrowser {
                scope,
                ..
            } if scope == "directory"
        ));
        let container: LocalScanRequest = serde_json::from_str(
            r#"{"action":"fetch-container","bindingHandle":"b","snapshotHandle":"s","containerHandle":"c","path":"/var/www","scope":"file"}"#,
        )
        .unwrap();
        assert!(matches!(
            container,
            LocalScanRequest::FetchContainer { path, .. } if path == "/var/www"
        ));
        for bad in [
            // Unknown keys never sneak a path or a second target past the shape.
            r#"{"action":"fetch-browser","bindingHandle":"b","browserHandle":"w","entryHandle":"e","scope":"file","path":"/etc"}"#,
            r#"{"action":"fetch-container","bindingHandle":"b","snapshotHandle":"s","containerHandle":"c","path":"/x","scope":"file","entryHandle":"e"}"#,
            r#"{"action":"fetch-browser","bindingHandle":"b","browserHandle":"w","scope":"file"}"#,
            r#"{"action":"fetch-container","bindingHandle":"b","snapshotHandle":"s","containerHandle":"c","scope":"file"}"#,
        ] {
            assert!(
                serde_json::from_str::<LocalScanRequest>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn container_fetch_path_refuses_traversal_relative_and_root() {
        for bad in [
            "/var/../etc",
            "var/www",
            "/",
            "./x",
            "/a//b",
            "/a/./b",
            "relative/../path",
            "",
        ] {
            assert!(
                matches!(container_fetch_path(bad), Err(LocalScanError::Invalid)),
                "{bad}"
            );
        }
        for good in ["/var/www", "/etc/nginx/nginx.conf", "/var/www/has space/x"] {
            assert!(container_fetch_path(good).is_ok(), "{good}");
        }
    }
}
