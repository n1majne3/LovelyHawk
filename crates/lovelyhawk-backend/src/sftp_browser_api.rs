//! Read-only, capability-based SFTP browser boundary for the desktop app.
//!
//! Remote paths, target identity, raw session data, and SFTP requests remain
//! sidecar-owned. The renderer can only traverse or preview entries that were
//! returned as binding- and browser-scoped opaque capabilities.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    connections::ConnectionConfig,
    local_pack::DIRECTORY_UPLOAD_TAR_OVERHEAD_BYTES,
    operations::{DangerousConfirmation, OperationState, VerificationResult},
    path_guard::PathGuard,
    sftp::{
        ArchiveFormat, BoundSftpSession, MAX_ARCHIVE_DOWNLOAD_BYTES, MAX_ARCHIVE_DOWNLOAD_FILES,
        MAX_DIRECTORY_ENTRIES, RemotePath, SftpDownloadOptions, SftpEntry, SftpFileKind,
        SftpMutation, SftpPlannedOperation, SftpService, SftpTransferCancel, SftpTransport,
    },
    ssh::{BoundSshSession, SFTP_HANDSHAKE_OPERATION, SshConnectAuthorization},
    target::{TargetContext, TargetGuard, TargetIdentity},
};
use serde::Serialize;
use tokio::time::timeout;
use uuid::Uuid;

use crate::ssh_api::SshApi;

const MAX_HANDLE_BYTES: usize = 128;
const MAX_DISPLAYED_ENTRIES: usize = 128;
// Entry names and directory labels cross the boundary through the same
// normaliser, so they share one ceiling.
const MAX_ENTRY_NAME_BYTES: usize = 256;
const MAX_NAVIGATION_DEPTH: usize = 64;
const MAX_BROWSERS: usize = 4;
const MAX_EDITOR_BROWSERS: usize = 16;
const MAX_BROWSER_BYTES: usize = 1024 * 1024;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_OPENS: usize = 2;
const MAX_ACTIVE_OPERATIONS: usize = 4;
const MAX_CORE_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEXT_LINES: usize = 2_000;
const MAX_TEXT_LINE_BYTES: usize = 4 * 1024;
const MAX_TEXT_BYTES: usize = 256 * 1024;
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_TEXT_RESPONSE_BYTES: usize = 384 * 1024;
const BROWSER_TTL: Duration = Duration::from_secs(5 * 60);
const BIND_DEADLINE: Duration = Duration::from_secs(15);
const LIST_DEADLINE: Duration = Duration::from_secs(20);
const READ_DEADLINE: Duration = Duration::from_secs(20);
const TRANSFER_DEADLINE: Duration = Duration::from_secs(180);
const EXECUTE_DEADLINE: Duration = Duration::from_secs(90);
const PLAN_TTL: Duration = Duration::from_secs(2 * 60);
const MAX_PLANS: usize = 8;
/// How long a verified, reversible operation stays available to undo. The
/// file manager tells the operator this window (SftpOperationDialog.tsx).
const UNDO_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_DONE: usize = 16;
/// How long a cancelled transfer gets to remove what it had written.
const TRANSFER_CANCEL_GRACE: Duration = Duration::from_secs(15);
const MAX_STAGED_UPLOADS: usize = 8;
const MAX_PLAN_TEXT_BYTES: usize = 1024;
const MAX_ENTRY_NAME_INPUT: usize = 255;
const MAX_ARCHIVE_SOURCES: usize = 64;
const MAX_STAGED_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
// Names and file text cross the boundary as the target has them. Blanking a
// file called "secret_key" or a config line containing "password=" removes the
// very thing the operator opened the browser to look at.
const ROOT_LABEL: &str = "根目录";

#[derive(Clone)]
pub(crate) struct SftpBrowserApi {
    services: BackendServices,
    ssh_api: Arc<SshApi>,
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    /// Owns which local paths a transfer may touch; the renderer never sees one.
    paths: Arc<PathGuard>,
}

impl fmt::Debug for SftpBrowserApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (browsers, bytes, opens, operations) = self
            .registry
            .lock()
            .map(|registry| {
                (
                    registry.browsers.len(),
                    registry.total_bytes(),
                    registry.active_open_bindings.len(),
                    registry.active_operations.len(),
                )
            })
            .unwrap_or_default();
        formatter
            .debug_struct("SftpBrowserApi")
            .field("browser_count", &browsers)
            .field("registry_bytes", &bytes)
            .field("active_opens", &opens)
            .field("active_operations", &operations)
            .finish()
    }
}

impl SftpBrowserApi {
    pub(crate) fn new(services: BackendServices, ssh_api: Arc<SshApi>) -> Self {
        let staging = services.store().root().join("sftp-staging");
        let paths = PathGuard::new(staging, [])
            .expect("the portable store root is always writable at startup");
        Self {
            services,
            ssh_api,
            registry: Arc::new(Mutex::new(SftpBrowserRegistry::default())),
            paths: Arc::new(paths),
        }
    }

    /// Copies one remote file to a local path the operator picked in the save
    /// dialog. The path arrives from main, never from the renderer, and the
    /// core refuses anything outside what a save dialog can produce.
    pub(crate) async fn download_entry(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        file_handle: &str,
        local_path: &Path,
    ) -> Result<SftpTransferDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(file_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) =
            self.begin_operation(&scope, browser_handle, file_handle, EntryAction::Preview)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        let cancel = SftpTransferCancel::new();
        let _transfer = self.register_transfer(&scope, browser_handle, &cancel)?;
        let (sftp, source) = (self.services.sftp(), &access.node.path);
        let download = sftp.download_new(&session, &self.paths, source, local_path, &cancel);
        let receipt = run_transfer(download, &cancel, TRANSFER_DEADLINE)
            .await?
            .map_err(|error| {
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error) {
                    SftpBrowserApiError::Cancelled
                } else {
                    error.into()
                }
            })?;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.verify_operation(&access)?;
        Ok(SftpTransferDto {
            browser_handle: access.browser_handle.clone(),
            file_handle: access.node.handle.clone(),
            bytes: receipt.bytes.to_string(),
        })
    }

    /// Packs a whole directory into a remote tar, downloads it to the
    /// host-chosen local path, and always removes the remote temp archive —
    /// on success, on refusal, on failure and on cancel. Over-cap trees are
    /// refused with the counted numbers, and an optional hardened extraction
    /// can land the members in a chosen empty folder.
    pub(crate) async fn download_directory(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        directory_handle: &str,
        local_path: &Path,
        extract_to: Option<&Path>,
    ) -> Result<SftpDirectoryDownloadDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(directory_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) = self.begin_operation(
            &scope,
            browser_handle,
            directory_handle,
            EntryAction::Browse,
        )?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        if self.sftp_degraded(&session).await? {
            return Err(SftpBrowserApiError::SubsystemUnavailable);
        }
        let directory = access.node.path.clone();
        let parent = directory
            .parent()
            .map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let preflight = timeout(
            LIST_DEADLINE,
            self.services
                .sftp()
                .directory_archive_preflight(&session, &directory),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        if preflight.files > MAX_ARCHIVE_DOWNLOAD_FILES
            || preflight.bytes > MAX_ARCHIVE_DOWNLOAD_BYTES
        {
            return Ok(SftpDirectoryDownloadDto {
                browser_handle: browser_handle.to_owned(),
                state: "refused-over-cap".to_owned(),
                file_count: preflight.files.to_string(),
                total_bytes: preflight.bytes.to_string(),
                archive_bytes: None,
                extracted_entries: None,
                detail: format!(
                    "目录超出打包上限：共 {} 个文件{}；上限为 {} 个文件或 {} 字节。",
                    preflight.files,
                    if preflight.files > MAX_ARCHIVE_DOWNLOAD_FILES {
                        "（超出文件数上限，字节数未统计）".to_owned()
                    } else {
                        format!("、{} 字节", preflight.bytes)
                    },
                    MAX_ARCHIVE_DOWNLOAD_FILES,
                    MAX_ARCHIVE_DOWNLOAD_BYTES
                ),
            });
        }
        // Cancel is wired before packing so a stop during the archive phase
        // still aborts the download below — the trap and restore then clear
        // every remote temporary either way.
        let cancel = SftpTransferCancel::new();
        let _transfer = self.register_transfer(&scope, browser_handle, &cancel)?;
        let temporary = parent
            .child(&format!(
                ".lovelyres-download-{}.tar",
                Uuid::new_v4().simple()
            ))
            .map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let mut operation = self
            .services
            .sftp()
            .plan(
                &session,
                SftpMutation::CreateArchive {
                    sources: vec![directory],
                    destination: temporary.clone(),
                    format: ArchiveFormat::Tar,
                },
            )
            .map_err(|_| SftpBrowserApiError::InvalidListing)?;
        operation
            .confirm(DangerousConfirmation::approve(operation.definition()))
            .map_err(|_| SftpBrowserApiError::Busy)?;
        let verification = match operation.execute_and_verify().await {
            Ok(verification) => verification,
            Err(error) => {
                let _ = operation.restore().await;
                return Err(error.into());
            }
        };
        if !verification.passed {
            let _ = operation.restore().await;
            return Err(SftpBrowserApiError::Core);
        }
        if cancel.is_cancelled() {
            // The archive finished after the operator asked to stop: it goes
            // back away and nothing is downloaded.
            let _ = operation.restore().await;
            return Err(SftpBrowserApiError::Cancelled);
        }
        let outcome = run_transfer(
            self.services.sftp().download_new(
                &session,
                &self.paths,
                &temporary,
                local_path,
                &cancel,
            ),
            &cancel,
            TRANSFER_DEADLINE,
        )
        .await;
        // Whatever the transfer did, the remote temp archive goes away.
        let cleaned = operation.restore().await.is_ok();
        let receipt = match outcome {
            Err(error) => return Err(error),
            Ok(Err(error)) => {
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error) {
                    return Err(SftpBrowserApiError::Cancelled);
                }
                return Err(error.into());
            }
            Ok(Ok(receipt)) => receipt,
        };
        let mut detail =
            "目录已打包为 tar 下载；符号链接在包中保持为链接条目，不会跟随成普通文件。".to_owned();
        let mut extracted_entries = None;
        if let Some(target) = extract_to {
            let empty = target
                .is_dir()
                .then(|| std::fs::read_dir(target).map(|mut it| it.next().is_none()))
                .and_then(|result| result.ok())
                .unwrap_or(false);
            if !empty {
                if cleaned {
                    detail.push_str("远端临时包已删除。");
                } else {
                    detail.push_str("远端临时包可能未删除，请核对。");
                }
                return Ok(SftpDirectoryDownloadDto {
                    browser_handle: browser_handle.to_owned(),
                    state: "extract-refused".to_owned(),
                    file_count: preflight.files.to_string(),
                    total_bytes: preflight.bytes.to_string(),
                    archive_bytes: Some(receipt.bytes.to_string()),
                    extracted_entries: None,
                    detail: format!("{detail}所选本机文件夹不存在、不是文件夹或不是空文件夹。"),
                });
            }
            match lovelyhawk_core::local_scan::extract_fetch_archive(local_path, target) {
                Ok(report) => {
                    extracted_entries = Some(report.files.to_string());
                    if report.skipped > 0 {
                        detail.push_str(&format!(
                            "解压时跳过 {} 个不安全成员（如链接或越界路径）。",
                            report.skipped
                        ));
                    }
                }
                Err(error) => {
                    return Ok(SftpDirectoryDownloadDto {
                        browser_handle: browser_handle.to_owned(),
                        state: "extract-failed".to_owned(),
                        file_count: preflight.files.to_string(),
                        total_bytes: preflight.bytes.to_string(),
                        archive_bytes: Some(receipt.bytes.to_string()),
                        extracted_entries: None,
                        detail: format!("{detail}解压失败：{error}"),
                    });
                }
            }
        }
        if cleaned {
            detail.push_str("远端临时包已删除。");
        } else {
            detail.push_str("远端临时包可能未删除，请核对。");
        }
        Ok(SftpDirectoryDownloadDto {
            browser_handle: browser_handle.to_owned(),
            state: "done".to_owned(),
            file_count: preflight.files.to_string(),
            total_bytes: preflight.bytes.to_string(),
            archive_bytes: Some(receipt.bytes.to_string()),
            extracted_entries,
            detail,
        })
    }

    /// Copies a packed local directory archive (built by the host from a
    /// native folder dialog) into core-managed staging. The folder name the
    /// target will see is bound to the staged handle here, and the file is
    /// removed on confirmation, discard or expiry.
    pub(crate) fn stage_directory_upload(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        local_path: &Path,
        name: &str,
    ) -> Result<SftpDirectoryUploadStageDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        {
            let registry = self.lock_registry()?;
            if !registry.browsers.contains_key(browser_handle) {
                return Err(SftpBrowserApiError::BrowserStale);
            }
        }
        let display_name = validated_entry_name(name)?;
        let metadata =
            std::fs::metadata(local_path).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let maximum = MAX_ARCHIVE_DOWNLOAD_BYTES + DIRECTORY_UPLOAD_TAR_OVERHEAD_BYTES;
        if !metadata.is_file() || metadata.len() > maximum {
            return Err(SftpBrowserApiError::Capacity);
        }
        let staged = self
            .paths
            .stage_native_selected_upload(local_path, maximum)
            .map_err(|_| SftpBrowserApiError::Capacity)?;
        let staged_handle = Uuid::new_v4().to_string();
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_directory_upload(
            staged_handle.clone(),
            PendingDirectoryUpload {
                binding_handle: scope.binding_handle.clone(),
                path: staged,
                name: display_name.clone(),
                expires_at: now + PLAN_TTL,
            },
        )?;
        Ok(SftpDirectoryUploadStageDto {
            staged_handle,
            name: display_name,
            bytes: metadata.len().to_string(),
        })
    }

    /// Drops a packed directory archive the operator declined to upload.
    pub(crate) fn discard_directory_upload(
        &self,
        binding_handle: &str,
        staged_handle: &str,
    ) -> Result<SftpDirectoryUploadDiscardDto, SftpBrowserApiError> {
        validate_handle(staged_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        Ok(SftpDirectoryUploadDiscardDto {
            discarded: registry.discard_directory_upload(&scope, staged_handle),
        })
    }

    /// Uploads a staged directory archive to a remote temp path, extracts it
    /// under `<current dir>/<folder name>` and removes both temps on every
    /// outcome. The extraction plan is kept in the done registry so the
    /// existing undo flow removes the extracted tree again after verifying it
    /// has not changed.
    pub(crate) async fn upload_directory(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        directory_handle: &str,
        staged_handle: &str,
    ) -> Result<SftpDirectoryUploadDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(directory_handle)?;
        validate_handle(staged_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) = self.begin_operation(
            &scope,
            browser_handle,
            directory_handle,
            EntryAction::Browse,
        )?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        if self.sftp_degraded(&session).await? {
            return Err(SftpBrowserApiError::SubsystemUnavailable);
        }
        let staged = {
            let mut registry = self.lock_registry()?;
            registry.take_directory_upload(&scope, staged_handle, Instant::now())?
        };
        // The local staged archive goes away on every outcome — the upload
        // operation also removes it when it runs, and this guard covers every
        // earlier exit.
        struct StagedFile(Option<PathBuf>);
        impl Drop for StagedFile {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let _staged_file = StagedFile(Some(staged.path.clone()));
        let parent = access.node.path.clone();
        let destination = parent
            .child(&staged.name)
            .map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let temporary = parent
            .child(&format!(
                ".lovelyhawk-upload-{}.tar",
                Uuid::new_v4().simple()
            ))
            .map_err(|_| SftpBrowserApiError::InvalidListing)?;

        // Refuse the destination up front so the message names what happened;
        // plan_extract re-checks right before writing and closes the race.
        let taken = self
            .services
            .sftp()
            .metadata(&session, &destination, false)
            .await
            .is_ok();
        if taken {
            return Ok(SftpDirectoryUploadDto {
                browser_handle: browser_handle.to_owned(),
                state: "refused-destination".to_owned(),
                detail: "目标位置已存在同名文件夹或文件，未写入任何内容。请先改名或移走。"
                    .to_owned(),
                plan_handle: None,
                undoable: false,
            });
        }

        let mut upload = self
            .services
            .sftp()
            .plan_upload(&session, &self.paths, &staged.path, temporary.clone())
            .map_err(|_| SftpBrowserApiError::InvalidListing)?;
        upload
            .confirm(DangerousConfirmation::approve(upload.definition()))
            .map_err(|_| SftpBrowserApiError::Busy)?;
        let cancel = upload.transfer_cancel();
        let _transfer = self.register_transfer(&scope, browser_handle, &cancel)?;
        let outcome = run_transfer(upload.execute_and_verify(), &cancel, TRANSFER_DEADLINE).await;
        self.validate_binding(&scope)?;
        match outcome {
            Err(error) => return Err(error),
            Ok(Err(error)) => {
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error) {
                    return Ok(SftpDirectoryUploadDto {
                        browser_handle: browser_handle.to_owned(),
                        state: "cancelled".to_owned(),
                        detail: "上传已取消，没有内容写到目标机。".to_owned(),
                        plan_handle: None,
                        undoable: false,
                    });
                }
                let _ = upload.restore().await;
                return Ok(SftpDirectoryUploadDto {
                    browser_handle: browser_handle.to_owned(),
                    state: "failed".to_owned(),
                    detail: lovelyhawk_core::sftp::operation_failure_advice(&error)
                        .unwrap_or("上传没有完成，目标机上未保留临时包。")
                        .to_owned(),
                    plan_handle: None,
                    undoable: false,
                });
            }
            Ok(Ok(verification)) if !verification.passed => {
                let _ = upload.restore().await;
                return Ok(SftpDirectoryUploadDto {
                    browser_handle: browser_handle.to_owned(),
                    state: "failed".to_owned(),
                    detail: "上传后核对不一致，临时包已删除，目标机未写入目录。".to_owned(),
                    plan_handle: None,
                    undoable: false,
                });
            }
            Ok(Ok(_)) => {}
        }
        if cancel.is_cancelled() {
            let _ = upload.restore().await;
            return Ok(SftpDirectoryUploadDto {
                browser_handle: browser_handle.to_owned(),
                state: "cancelled".to_owned(),
                detail: "上传已取消，远端临时包已删除。".to_owned(),
                plan_handle: None,
                undoable: false,
            });
        }

        let mut extract = match self
            .services
            .sftp()
            .plan_extract(&session, temporary.clone(), destination.clone())
            .await
        {
            Ok(plan) => plan,
            Err(error) => {
                let _ = upload.restore().await;
                let taken = error.to_string().contains("already exists")
                    || error.to_string().contains("存在");
                return Ok(SftpDirectoryUploadDto {
                    browser_handle: browser_handle.to_owned(),
                    state: if taken {
                        "refused-destination"
                    } else {
                        "failed"
                    }
                    .to_owned(),
                    detail: if taken {
                        "目标位置已存在同名文件夹或文件，未写入任何内容；远端临时包已删除。"
                            .to_owned()
                    } else {
                        format!(
                            "远端解包计划被拒绝：{}；远端临时包已删除。",
                            lovelyhawk_core::sftp::operation_failure_advice(&error)
                                .unwrap_or("请核对目标机状态")
                        )
                    },
                    plan_handle: None,
                    undoable: false,
                });
            }
        };
        extract
            .confirm(DangerousConfirmation::approve(extract.definition()))
            .map_err(|_| SftpBrowserApiError::Busy)?;
        let verification = match extract.execute_and_verify().await {
            Ok(verification) => verification,
            Err(error) => {
                let _ = upload.restore().await;
                return Ok(SftpDirectoryUploadDto {
                    browser_handle: browser_handle.to_owned(),
                    state: "failed".to_owned(),
                    detail: format!(
                        "远端解包失败：{}；远端临时包已删除。",
                        lovelyhawk_core::sftp::operation_failure_advice(&error)
                            .unwrap_or("请核对目标机状态")
                    ),
                    plan_handle: None,
                    undoable: false,
                });
            }
        };
        self.validate_binding(&scope)?;
        if !verification.passed {
            let _ = upload.restore().await;
            return Ok(SftpDirectoryUploadDto {
                browser_handle: browser_handle.to_owned(),
                state: "failed".to_owned(),
                detail: "远端解包后的核对未通过，已清理；请检查目标机状态。".to_owned(),
                plan_handle: None,
                undoable: false,
            });
        }

        // Extraction verified: the remote temp archive goes away and the
        // extraction plan becomes the undoable done entry.
        let temp_removed = upload.restore().await.is_ok();
        let plan_handle = Uuid::new_v4().to_string();
        let entry = PlannedEntry {
            plan_handle: plan_handle.clone(),
            browser_handle: browser_handle.to_owned(),
            browser_token: access.browser_token,
            scope: scope.clone(),
            kind: "upload-directory".to_owned(),
            operation: extract,
            expires_at: Instant::now() + PLAN_TTL,
        };
        let undoable = self.lock_registry()?.store_done(entry);
        let mut detail = "目录已上传并在目标机解包核对完成。".to_owned();
        if temp_removed {
            detail.push_str("远端临时包已删除。");
        } else {
            detail.push_str("远端临时包可能未删除，请核对。");
        }
        if undoable {
            detail.push_str("如需回退，可撤销这次上传，解出的文件夹会在核对未变后整个删除。");
        }
        Ok(SftpDirectoryUploadDto {
            browser_handle: browser_handle.to_owned(),
            state: "done".to_owned(),
            detail,
            plan_handle: if undoable { Some(plan_handle) } else { None },
            undoable,
        })
    }

    pub(crate) async fn open_sftp_browser(
        &self,
        binding_handle: &str,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.begin_open(&scope)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        let degraded_sftp = self.sftp_degraded(&session).await?;
        let root = RemotePath::new("/").map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let entries = timeout(LIST_DEADLINE, self.services.sftp().list(&session, &root))
            .await
            .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;

        let now = Instant::now();
        let (mut browser, mut dto) = BrowserSnapshot::from_root(scope.clone(), entries, now)?;
        browser.degraded_sftp = degraded_sftp;
        dto.degraded_sftp = degraded_sftp;
        ensure_serialized_bound(&dto, MAX_DIRECTORY_RESPONSE_BYTES)?;
        let browser_handle = browser.browser_handle.clone();
        let browser_token = browser.token;
        let directory_handle = browser.root_handle.clone();
        let revision = browser.revision;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.replace(browser)?;
        drop(registry);

        self.validate_binding(&scope)?;
        self.verify_directory_response(
            &scope,
            &browser_handle,
            browser_token,
            &directory_handle,
            revision,
        )?;
        Ok(dto)
    }

    /// True when the target has no SFTP subsystem and file features run
    /// through the exec/SCP fallback instead.
    async fn sftp_degraded(&self, session: &BoundSftpSession) -> Result<bool, SftpBrowserApiError> {
        Ok(matches!(
            timeout(LIST_DEADLINE, self.services.sftp().transport(session))
                .await
                .map_err(|_| SftpBrowserApiError::Deadline)??,
            SftpTransport::ExecFallback
        ))
    }

    /// Used only after a domain snapshot authorizes this exact file. It creates
    /// a separate capability so opening/browsing the terminal cannot invalidate
    /// an editor's draft, and does not give the page a path-based browser API.
    pub(crate) async fn open_editor_file(
        &self,
        binding_handle: &str,
        path: RemotePath,
    ) -> Result<SftpEditorFileDto, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let _permit = self.begin_open(&scope)?;
        {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            if let Some(browser) = registry.browsers.values_mut().find(|browser| {
                browser.editor_only
                    && browser.scope == scope
                    && browser
                        .nodes
                        .values()
                        .any(|node| node.action == EntryAction::Preview && node.path == path)
            }) {
                browser.expires_at = now + BROWSER_TTL;
                browser.last_used_at = now;
                let node = browser
                    .nodes
                    .values()
                    .find(|node| node.action == EntryAction::Preview && node.path == path)
                    .ok_or(SftpBrowserApiError::EntryUnavailable)?;
                return Ok(SftpEditorFileDto {
                    browser_handle: browser.browser_handle.clone(),
                    entry_handle: node.handle.clone(),
                    name: node.display_name.clone(),
                });
            }
        }
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        let metadata = timeout(
            READ_DEADLINE,
            self.services.sftp().metadata(&session, &path, false),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        if metadata.kind != SftpFileKind::File {
            return Err(SftpBrowserApiError::EntryUnavailable);
        }
        let (parent, name) = path
            .as_str()
            .rsplit_once('/')
            .ok_or(SftpBrowserApiError::EntryUnavailable)?;
        let parent = RemotePath::new(if parent.is_empty() { "/" } else { parent })
            .map_err(|_| SftpBrowserApiError::EntryUnavailable)?;
        let name = name.to_owned();
        let degraded_sftp = self.sftp_degraded(&session).await?;
        let now = Instant::now();
        let (mut browser, dto) = BrowserSnapshot::from_directory(
            scope.clone(),
            parent,
            vec![SftpEntry {
                name,
                path,
                metadata,
            }],
            now,
        )?;
        browser.editor_only = true;
        browser.degraded_sftp = degraded_sftp;
        let entry = dto
            .entries
            .first()
            .filter(|entry| !entry.name_truncated)
            .ok_or(SftpBrowserApiError::EntryUnavailable)?;
        let result = SftpEditorFileDto {
            browser_handle: dto.browser_handle,
            entry_handle: entry.entry_handle.clone(),
            name: entry.name.clone(),
        };
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.lock_registry()?.replace(browser)?;
        self.validate_binding(&scope)?;
        Ok(result)
    }

    pub(crate) async fn list_sftp_directory(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        directory_handle: &str,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(directory_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) = self.begin_operation(
            &scope,
            browser_handle,
            directory_handle,
            EntryAction::Browse,
        )?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        let degraded_sftp = self.sftp_degraded(&session).await?;
        let entries = timeout(
            LIST_DEADLINE,
            self.services.sftp().list(&session, &access.node.path),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.verify_operation(&access)?;

        let receipt = {
            let mut registry = self.lock_registry()?;
            registry.apply_listing(&access, entries, degraded_sftp, Instant::now())?
        };
        if ensure_serialized_bound(&receipt.dto, MAX_DIRECTORY_RESPONSE_BYTES).is_err() {
            self.invalidate_browser(&access.browser_handle);
            return Err(SftpBrowserApiError::Capacity);
        }
        self.validate_binding(&scope)?;
        self.verify_directory_response(
            &scope,
            &receipt.browser_handle,
            receipt.browser_token,
            &receipt.directory_handle,
            receipt.revision,
        )?;
        Ok(receipt.dto)
    }

    pub(crate) async fn read_sftp_text(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        file_handle: &str,
    ) -> Result<SftpTextPreviewDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(file_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (access, _permit) =
            self.begin_operation(&scope, browser_handle, file_handle, EntryAction::Preview)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        let source = timeout(
            READ_DEADLINE,
            self.services.sftp().read_text(&session, &access.node.path),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;
        self.verify_operation(&access)?;

        let projected = project_text(&source)?;
        let dto = SftpTextPreviewDto {
            browser_handle: access.browser_handle.clone(),
            file_handle: access.node.handle.clone(),
            text: projected.text,
            observed_line_count: projected.observed_line_count,
            displayed_line_count: projected.displayed_line_count,
            truncated: projected.truncated,
            // Over `source`, the whole file, not over the projection handed
            // back. A hash of what was displayed would happily authorise
            // writing a truncated file over a complete one.
            sha256: hex_digest(source.as_bytes()),
            exact: projected.exact,
        };
        ensure_serialized_bound(&dto, MAX_TEXT_RESPONSE_BYTES)?;
        self.validate_binding(&scope)?;
        self.verify_operation(&access)?;
        Ok(dto)
    }

    fn capture_binding(
        &self,
        binding_handle: &str,
    ) -> Result<(BoundSshSession, BindingScope), SftpBrowserApiError> {
        validate_handle(binding_handle)?;
        let session = self
            .ssh_api
            .binding_session_clone(binding_handle)
            .map_err(|_| SftpBrowserApiError::BindingUnavailable)?;
        self.services
            .target()
            .validate(session.target())
            .map_err(|_| SftpBrowserApiError::BindingUnavailable)?;
        let scope = BindingScope::from_session(binding_handle, &session);
        Ok((session, scope))
    }

    async fn bind_sftp(
        &self,
        scope: &BindingScope,
    ) -> Result<BoundSftpSession, SftpBrowserApiError> {
        self.validate_binding(scope)?;
        let session = timeout(
            BIND_DEADLINE,
            self.services
                .sftp()
                .bind_session(scope.target.clone(), &scope.session_id),
        )
        .await
        .map_err(|_| SftpBrowserApiError::Deadline)??;
        self.validate_binding(scope)?;
        validate_sftp_session(scope, &session)?;
        Ok(session)
    }

    fn validate_binding(&self, expected: &BindingScope) -> Result<(), SftpBrowserApiError> {
        let (_, current) = self.capture_binding(&expected.binding_handle)?;
        if &current != expected {
            return Err(SftpBrowserApiError::BindingUnavailable);
        }
        Ok(())
    }

    fn begin_open(&self, scope: &BindingScope) -> Result<OpenPermit, SftpBrowserApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        registry.begin_open(scope)?;
        Ok(OpenPermit {
            registry: Arc::clone(&self.registry),
            binding_handle: scope.binding_handle.clone(),
        })
    }

    fn begin_operation(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        entry_handle: &str,
        required_action: EntryAction,
    ) -> Result<(OperationAccess, OperationPermit), SftpBrowserApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let access = registry.begin_operation(
            scope,
            browser_handle,
            entry_handle,
            required_action,
            Instant::now(),
        )?;
        let permit = OperationPermit {
            registry: Arc::clone(&self.registry),
            operation_token: access.operation_token,
        };
        Ok((access, permit))
    }

    fn verify_operation(&self, access: &OperationAccess) -> Result<(), SftpBrowserApiError> {
        self.lock_registry()?
            .verify_operation(access, Instant::now())
    }

    fn verify_directory_response(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        browser_token: Uuid,
        directory_handle: &str,
        revision: u64,
    ) -> Result<(), SftpBrowserApiError> {
        self.lock_registry()?.verify_directory_response(
            scope,
            browser_handle,
            browser_token,
            directory_handle,
            revision,
            Instant::now(),
        )
    }

    /// The path of a directory this browser listed, for a terminal to start in.
    /// Only a directory the browser offered as one to open qualifies; a file, a
    /// link or a handle from another target does not.
    pub(crate) fn directory_for_terminal(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        directory_handle: &str,
    ) -> Result<RemotePath, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(directory_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        self.lock_registry()?.directory_for_terminal(
            &scope,
            browser_handle,
            directory_handle,
            Instant::now(),
        )
    }

    /// The path of an entry this browser offered, for a local-scan fetch.
    /// A directory offered to open (Browse, including the browser's current
    /// or root directory) and a regular file offered to preview qualify; a
    /// symlink or anything else, a handle from another target, and an expired
    /// browser do not.
    pub(crate) fn path_for_fetch(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        entry_handle: &str,
    ) -> Result<RemotePath, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(entry_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        self.lock_registry()?
            .path_for_fetch(&scope, browser_handle, entry_handle, Instant::now())
    }

    /// Drops every browser that belonged to a target that is going away.
    pub(crate) fn close_binding(&self, binding_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry
                .browsers
                .retain(|_, browser| browser.scope.binding_handle != binding_handle);
            registry.active_open_bindings.remove(binding_handle);
            registry
                .active_operations
                .retain(|_, operation| operation.binding_handle != binding_handle);
            registry
                .plans
                .retain(|_, entry| entry.scope.binding_handle != binding_handle);
            registry
                .done
                .retain(|_, entry| entry.scope.binding_handle != binding_handle);
            // A transfer for a target going away stops and cleans up what it
            // can; its own registration leaves when it answers.
            for transfer in registry.transfers.values() {
                if transfer.binding_handle == binding_handle {
                    transfer.cancel.cancel();
                }
            }
            registry.staged.retain(|_, staged| {
                if staged.binding_handle != binding_handle {
                    return true;
                }
                let _ = std::fs::remove_file(&staged.path);
                false
            });
            // Queues are binding-scoped: a target going away cancels every
            // item and drops the queue (Drop also frees unconsumed staging).
            let mut dead_queues = Vec::new();
            registry.queues.retain(|_, queue| {
                if queue.scope.binding_handle == binding_handle {
                    dead_queues.push(Arc::clone(queue));
                    false
                } else {
                    true
                }
            });
            for queue in dead_queues {
                queue.cancel_all();
            }
            // Relays are scoped to the source binding; losing it throws the
            // switch on both legs and drops the entry.
            registry.relays.retain(|_, relay| {
                if relay.scope.binding_handle == binding_handle {
                    relay.cancel.cancel();
                    false
                } else {
                    true
                }
            });
        }
    }

    fn invalidate_browser(&self, browser_handle: &str) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.browsers.remove(browser_handle);
            if let Some(queue) = registry.queues.remove(browser_handle) {
                queue.cancel_all();
            }
            registry.relays.retain(|_, relay| {
                if relay.browser_handle == browser_handle {
                    relay.cancel.cancel();
                    false
                } else {
                    true
                }
            });
        }
    }

    fn lock_registry(&self) -> Result<MutexGuard<'_, SftpBrowserRegistry>, SftpBrowserApiError> {
        self.registry
            .lock()
            .map_err(|_| SftpBrowserApiError::RegistryUnavailable)
    }
}

pub(crate) enum SftpBrowserApiError {
    Core,
    BindingUnavailable,
    InvalidHandle,
    BrowserStale,
    EntryUnavailable,
    InvalidListing,
    InvalidText,
    Busy,
    Capacity,
    Deadline,
    RegistryUnavailable,
    /// The operator stopped a transfer; what it had written was removed.
    Cancelled,
    /// The server took the SFTP request and never finished the handshake.
    SubsystemUnavailable,
}

impl fmt::Debug for SftpBrowserApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core([REDACTED])",
            Self::BindingUnavailable => "BindingUnavailable",
            Self::InvalidHandle => "InvalidHandle",
            Self::BrowserStale => "BrowserStale",
            Self::EntryUnavailable => "EntryUnavailable",
            Self::InvalidListing => "InvalidListing",
            Self::InvalidText => "InvalidText",
            Self::Busy => "Busy",
            Self::Capacity => "Capacity",
            Self::Deadline => "Deadline",
            Self::RegistryUnavailable => "RegistryUnavailable",
            Self::Cancelled => "Cancelled",
            Self::SubsystemUnavailable => "SubsystemUnavailable",
        })
    }
}

impl fmt::Display for SftpBrowserApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core => "the SFTP browser operation failed",
            Self::BindingUnavailable => "the SSH binding is missing or stale",
            Self::InvalidHandle => "the SFTP browser capability is invalid",
            Self::BrowserStale => "the SFTP browser capability is missing or stale",
            Self::EntryUnavailable => "the selected SFTP entry cannot be opened",
            Self::InvalidListing => "the SFTP directory result was rejected",
            Self::InvalidText => "the SFTP text result was rejected",
            Self::Busy => "the SFTP browser boundary is busy",
            Self::Capacity => "the SFTP browser boundary reached its capacity",
            Self::Deadline => "the SFTP browser operation exceeded its deadline",
            Self::RegistryUnavailable => "the SFTP browser registry is unavailable",
            Self::Cancelled => "the transfer was cancelled and nothing partial was kept",
            Self::SubsystemUnavailable => "the target did not complete the SFTP handshake",
        })
    }
}

impl std::error::Error for SftpBrowserApiError {}

impl From<CoreError> for SftpBrowserApiError {
    fn from(error: CoreError) -> Self {
        // The renderer only ever sees a fixed message, so without this the
        // reason a page failed is lost before anyone can read it.
        tracing::warn!(operation = "SftpBrowser", error = %error, "core operation failed");
        // A host that went away is not a failure of this feature. One lost
        // connection reported once beats a dozen features each announcing
        // their own breakage.
        if matches!(error, CoreError::SshDisconnected { .. }) {
            return Self::BindingUnavailable;
        }
        // Worth its own answer: "this target does not offer SFTP" is something
        // an operator can act on, and it is nothing like "the browser broke".
        // The exec/SCP fallback surfaces the absent subsystem under the
        // request operation name for everything it cannot answer.
        if matches!(
            &error,
            CoreError::Ssh { operation, .. }
                if *operation == SFTP_HANDSHAKE_OPERATION
                    || *operation == "request SFTP subsystem"
        ) {
            return Self::SubsystemUnavailable;
        }
        Self::Core
    }
}

#[derive(Clone, PartialEq, Eq)]
struct BindingScope {
    binding_handle: String,
    session_id: String,
    connection_id: String,
    target: TargetGuard,
}

impl BindingScope {
    fn from_session(binding_handle: &str, session: &BoundSshSession) -> Self {
        Self {
            binding_handle: binding_handle.to_owned(),
            session_id: session.session_id().to_owned(),
            connection_id: session.connection_id().to_owned(),
            target: session.target().clone(),
        }
    }

    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.binding_handle.len())
            .saturating_add(self.session_id.len())
            .saturating_add(self.connection_id.len())
            .saturating_add(self.target.identity.as_str().len())
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SftpBrowserEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SftpBrowserEntryAction {
    Browse,
    Preview,
    None,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpDirectoryDto {
    pub(crate) browser_handle: String,
    pub(crate) directory_handle: String,
    pub(crate) parent_directory_handle: Option<String>,
    pub(crate) directory_label: String,
    pub(crate) directory_label_truncated: bool,
    pub(crate) expires_in_seconds: u64,
    pub(crate) observed_entry_count: u32,
    pub(crate) displayed_entry_count: u32,
    pub(crate) truncated: bool,
    pub(crate) entries: Vec<SftpBrowserEntryDto>,
    /// True when the target has no SFTP subsystem and this listing was read
    /// through the exec/SCP fallback: read-only browsing plus plain transfers,
    /// no rename, chmod, delete or recursive operations.
    pub(crate) degraded_sftp: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpBrowserEntryDto {
    pub(crate) entry_handle: String,
    pub(crate) name: String,
    pub(crate) name_truncated: bool,
    pub(crate) kind: SftpBrowserEntryKind,
    pub(crate) action: SftpBrowserEntryAction,
    pub(crate) size_bytes: String,
    pub(crate) modified_at: Option<String>,
    /// The permission bits as four octal digits, when the server reports them.
    pub(crate) mode: Option<String>,
    /// Numeric owner and group. Names need a passwd lookup this slice does not
    /// make, so the numbers are reported as they arrive.
    pub(crate) owner_id: Option<u32>,
    pub(crate) group_id: Option<u32>,
}

/// A packed local folder accepted into managed staging; the preview on the
/// page shows name/bytes before the operator confirms.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpDirectoryUploadStageDto {
    pub(crate) staged_handle: String,
    pub(crate) name: String,
    pub(crate) bytes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpDirectoryUploadDiscardDto {
    pub(crate) discarded: bool,
}

/// What a directory upload did: extracted and verified, refused, failed or
/// cancelled — plus the undo handle when the tree can still be removed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpDirectoryUploadDto {
    pub(crate) browser_handle: String,
    pub(crate) state: String,
    pub(crate) detail: String,
    pub(crate) plan_handle: Option<String>,
    pub(crate) undoable: bool,
}

/// The result of a whole-directory download. `state` is one of
/// `refused-over-cap`, `extract-refused`, `extract-failed` or `done`; the
/// counts are always the preflight numbers, `archiveBytes` is the tar's size
/// once it existed, and `extractedEntries` counts unpacked files when the
/// optional extraction ran.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpDirectoryDownloadDto {
    pub(crate) browser_handle: String,
    pub(crate) state: String,
    pub(crate) file_count: String,
    pub(crate) total_bytes: String,
    pub(crate) archive_bytes: Option<String>,
    pub(crate) extracted_entries: Option<String>,
    pub(crate) detail: String,
}

/// What a finished transfer moved, in capability terms only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpTransferDto {
    pub(crate) browser_handle: String,
    pub(crate) file_handle: String,
    /// A byte count as a decimal string, because it can exceed 2^53.
    pub(crate) bytes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpTextPreviewDto {
    pub(crate) browser_handle: String,
    pub(crate) file_handle: String,
    pub(crate) text: String,
    pub(crate) observed_line_count: u32,
    pub(crate) displayed_line_count: u32,
    pub(crate) truncated: bool,
    /// Of the file as read, not of the text that was handed back.
    ///
    /// The editor sends this back when it saves, and the write only lands if
    /// the file on the target still hashes to it — so an edit begun before
    /// somebody else changed the file is refused rather than silently
    /// overwriting their change. It is also why the two must not be confused:
    /// when `truncated` is true this is still the whole file's hash, and the
    /// text is not the whole file, so saving is refused outright.
    pub(crate) sha256: String,
    /// Whether the text above is the file byte for byte. False means the
    /// projection changed something — a line ending, a control character, a
    /// dropped tail — and the editor refuses to save, because saving would
    /// write the change the projection made rather than the one the operator
    /// made.
    pub(crate) exact: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryAction {
    Browse,
    Preview,
    None,
}

impl EntryAction {
    const fn dto(self) -> SftpBrowserEntryAction {
        match self {
            Self::Browse => SftpBrowserEntryAction::Browse,
            Self::Preview => SftpBrowserEntryAction::Preview,
            Self::None => SftpBrowserEntryAction::None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StoredNode {
    handle: String,
    path: RemotePath,
    kind: SftpBrowserEntryKind,
    action: EntryAction,
    parent_handle: Option<String>,
    depth: usize,
    display_name: String,
    name_truncated: bool,
    size_bytes: String,
    modified_at: Option<String>,
    mode: Option<String>,
    owner_id: Option<u32>,
    group_id: Option<u32>,
}

/// The permission bits an operator reads and types, as four octal digits.
/// Only the low twelve bits mean anything here: the file type lives in the
/// kind, and reporting it twice would just invite a wrong chmod.
fn octal_mode(permissions: u32) -> String {
    format!("{:04o}", permissions & 0o7777)
}

impl StoredNode {
    fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.handle.len())
            .saturating_add(self.path.as_str().len())
            .saturating_add(self.parent_handle.as_ref().map_or(0, String::len))
            .saturating_add(self.display_name.len())
            .saturating_add(self.size_bytes.len())
            .saturating_add(self.modified_at.as_ref().map_or(0, String::len))
            .saturating_add(self.mode.as_ref().map_or(0, String::len))
    }

    fn dto(&self) -> SftpBrowserEntryDto {
        SftpBrowserEntryDto {
            entry_handle: self.handle.clone(),
            name: self.display_name.clone(),
            name_truncated: self.name_truncated,
            kind: self.kind,
            action: self.action.dto(),
            size_bytes: self.size_bytes.clone(),
            modified_at: self.modified_at.clone(),
            mode: self.mode.clone(),
            owner_id: self.owner_id,
            group_id: self.group_id,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpEditorFileDto {
    browser_handle: String,
    entry_handle: String,
    name: String,
}

#[derive(Clone)]
struct BrowserSnapshot {
    browser_handle: String,
    token: Uuid,
    scope: BindingScope,
    root_handle: String,
    nodes: HashMap<String, StoredNode>,
    revision: u64,
    expires_at: Instant,
    last_used_at: Instant,
    stored_bytes: usize,
    editor_only: bool,
    degraded_sftp: bool,
}

impl BrowserSnapshot {
    fn from_root(
        scope: BindingScope,
        entries: Vec<SftpEntry>,
        now: Instant,
    ) -> Result<(Self, SftpDirectoryDto), SftpBrowserApiError> {
        Self::from_directory(
            scope,
            RemotePath::new("/").map_err(|_| SftpBrowserApiError::InvalidListing)?,
            entries,
            now,
        )
    }

    fn from_directory(
        scope: BindingScope,
        root_path: RemotePath,
        entries: Vec<SftpEntry>,
        now: Instant,
    ) -> Result<(Self, SftpDirectoryDto), SftpBrowserApiError> {
        let browser_handle = Uuid::new_v4().to_string();
        let root_handle = Uuid::new_v4().to_string();
        let root = StoredNode {
            handle: root_handle.clone(),
            path: root_path,
            kind: SftpBrowserEntryKind::Directory,
            action: EntryAction::Browse,
            parent_handle: None,
            depth: 0,
            display_name: ROOT_LABEL.to_owned(),
            name_truncated: false,
            size_bytes: "0".to_owned(),
            modified_at: None,
            mode: None,
            owner_id: None,
            group_id: None,
        };
        let mut nodes = HashMap::new();
        nodes.insert(root_handle.clone(), root);
        let mut browser = Self {
            browser_handle,
            token: Uuid::new_v4(),
            scope,
            root_handle: root_handle.clone(),
            nodes,
            revision: 0,
            expires_at: now + BROWSER_TTL,
            last_used_at: now,
            stored_bytes: 0,
            editor_only: false,
            degraded_sftp: false,
        };
        let dto = browser.refresh_directory(&root_handle, entries, now)?;
        Ok((browser, dto))
    }

    fn refresh_directory(
        &mut self,
        directory_handle: &str,
        mut entries: Vec<SftpEntry>,
        now: Instant,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            return Err(SftpBrowserApiError::InvalidListing);
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        if entries.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(SftpBrowserApiError::InvalidListing);
        }
        entries.sort_by(|left, right| {
            entry_kind(left.metadata.kind)
                .cmp(&entry_kind(right.metadata.kind))
                .then_with(|| left.name.cmp(&right.name))
        });

        let directory = self
            .nodes
            .get(directory_handle)
            .cloned()
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if directory.action != EntryAction::Browse {
            return Err(SftpBrowserApiError::EntryUnavailable);
        }
        let old_children = self
            .nodes
            .values()
            .filter(|node| node.parent_handle.as_deref() == Some(directory_handle))
            .map(|node| (node.path.clone(), node.clone()))
            .collect::<HashMap<_, _>>();
        let observed_entry_count =
            u32::try_from(entries.len()).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let truncated = entries.len() > MAX_DISPLAYED_ENTRIES;
        let mut projected = Vec::with_capacity(entries.len().min(MAX_DISPLAYED_ENTRIES));
        for entry in entries.into_iter().take(MAX_DISPLAYED_ENTRIES) {
            let kind = entry_kind(entry.metadata.kind);
            let depth = directory.depth.saturating_add(1);
            let action = match kind {
                SftpBrowserEntryKind::Directory if depth <= MAX_NAVIGATION_DEPTH => {
                    EntryAction::Browse
                }
                SftpBrowserEntryKind::File => EntryAction::Preview,
                _ => EntryAction::None,
            };
            let (display_name, name_truncated) = project_name(&entry.name);
            let existing = old_children
                .get(&entry.path)
                .filter(|node| node.kind == kind);
            projected.push(StoredNode {
                handle: existing
                    .map(|node| node.handle.clone())
                    .unwrap_or_else(|| Uuid::new_v4().to_string()),
                path: RemotePath::new(entry.path.as_str().to_owned())
                    .map_err(|_| SftpBrowserApiError::InvalidListing)?,
                kind,
                action,
                parent_handle: Some(directory_handle.to_owned()),
                depth,
                display_name,
                name_truncated,
                size_bytes: entry.metadata.size.to_string(),
                modified_at: entry.metadata.modified_at.map(|value| value.to_rfc3339()),
                mode: entry.metadata.permissions.map(octal_mode),
                owner_id: entry.metadata.uid,
                group_id: entry.metadata.gid,
            });
        }

        let mut retained = HashMap::new();
        let mut cursor = Some(directory_handle.to_owned());
        while let Some(handle) = cursor {
            let node = self
                .nodes
                .get(&handle)
                .cloned()
                .ok_or(SftpBrowserApiError::BrowserStale)?;
            cursor = node.parent_handle.clone();
            retained.insert(handle, node);
        }
        for node in projected {
            retained.insert(node.handle.clone(), node);
        }
        self.nodes = retained;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(SftpBrowserApiError::Capacity)?;
        self.last_used_at = now;
        // Browsing keeps the browser open, as running checks keeps the command
        // list open: with a fixed five minutes from opening, every listing after
        // that failed and only reopening the window brought the files back. A
        // browser nobody lists from still closes on time, and every operation
        // checks the target binding regardless.
        self.expires_at = now + BROWSER_TTL;
        self.stored_bytes = self.estimated_bytes();
        if self.stored_bytes > MAX_BROWSER_BYTES
            || self.nodes.len() > MAX_NAVIGATION_DEPTH + 1 + MAX_DISPLAYED_ENTRIES
        {
            return Err(SftpBrowserApiError::Capacity);
        }
        self.directory_dto(directory_handle, observed_entry_count, truncated, now)
    }

    fn directory_dto(
        &self,
        directory_handle: &str,
        observed_entry_count: u32,
        truncated: bool,
        now: Instant,
    ) -> Result<SftpDirectoryDto, SftpBrowserApiError> {
        let directory = self
            .nodes
            .get(directory_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let mut entries = self
            .nodes
            .values()
            .filter(|node| node.parent_handle.as_deref() == Some(directory_handle))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.display_name.cmp(&right.display_name))
                .then_with(|| left.handle.cmp(&right.handle))
        });
        let displayed_entry_count =
            u32::try_from(entries.len()).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        Ok(SftpDirectoryDto {
            browser_handle: self.browser_handle.clone(),
            directory_handle: directory.handle.clone(),
            parent_directory_handle: directory.parent_handle.clone(),
            directory_label: directory.display_name.clone(),
            directory_label_truncated: directory.name_truncated,
            expires_in_seconds: remaining_seconds(self.expires_at, now)?,
            observed_entry_count,
            displayed_entry_count,
            truncated,
            degraded_sftp: self.degraded_sftp,
            entries: entries.into_iter().map(StoredNode::dto).collect(),
        })
    }

    fn estimated_bytes(&self) -> usize {
        self.scope
            .estimated_bytes()
            .saturating_add(std::mem::size_of::<Self>())
            .saturating_add(self.browser_handle.len())
            .saturating_add(self.root_handle.len())
            .saturating_add(
                self.nodes
                    .iter()
                    .map(|(handle, node)| {
                        node.estimated_bytes()
                            .saturating_add(handle.len())
                            .saturating_add(128)
                    })
                    .fold(0usize, usize::saturating_add),
            )
    }

    fn registry_bytes(&self) -> usize {
        self.stored_bytes
            .saturating_add(self.browser_handle.len())
            .saturating_add(128)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct OperationAccess {
    browser_handle: String,
    browser_token: Uuid,
    operation_token: Uuid,
    scope: BindingScope,
    node: StoredNode,
    required_action: EntryAction,
}

struct ActiveOperation {
    browser_handle: String,
    browser_token: Uuid,
    binding_handle: String,
}

struct DirectoryReceipt {
    dto: SftpDirectoryDto,
    browser_handle: String,
    browser_token: Uuid,
    directory_handle: String,
    revision: u64,
}

#[derive(Default)]
struct SftpBrowserRegistry {
    browsers: HashMap<String, BrowserSnapshot>,
    active_open_bindings: HashSet<String>,
    active_operations: HashMap<Uuid, ActiveOperation>,
    plans: HashMap<String, PlannedEntry>,
    /// Verified operations that can still be undone, once each.
    done: HashMap<String, PlannedEntry>,
    staged: HashMap<String, StagedUpload>,
    /// Packed local folders waiting for the operator's upload confirmation.
    directory_uploads: HashMap<String, PendingDirectoryUpload>,
    /// Uploads and downloads copying right now.
    transfers: HashMap<Uuid, ActiveTransfer>,
    /// One batch transfer queue per browser window.
    queues: HashMap<String, Arc<TransferQueue>>,
    /// File relays in flight, keyed by their opaque handle.
    relays: HashMap<String, Arc<Relay>>,
}

impl SftpBrowserRegistry {
    /// Queue items don't take an operation permit — two run at once, which a
    /// single permit cannot express — so they validate browser, scope and
    /// node freshness directly here instead.
    fn queue_entry(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        entry_handle: &str,
        required_action: EntryAction,
        now: Instant,
    ) -> Result<StoredNode, SftpBrowserApiError> {
        let browser = self
            .browsers
            .get(browser_handle)
            .filter(|browser| &browser.scope == scope && browser.expires_at > now)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        browser
            .nodes
            .get(entry_handle)
            .filter(|node| node.action == required_action)
            .cloned()
            .ok_or(SftpBrowserApiError::EntryUnavailable)
    }

    /// Throws the switch of every transfer this browser has running, and only
    /// those: another window's browser, or another target's, keeps copying.
    fn cancel_transfers(&self, binding_handle: &str, browser_handle: &str) -> u32 {
        let mut cancelled = 0_u32;
        for transfer in self.transfers.values() {
            if transfer.binding_handle == binding_handle
                && transfer.browser_handle == browser_handle
            {
                transfer.cancel.cancel();
                cancelled = cancelled.saturating_add(1);
            }
        }
        cancelled
    }

    /// Holds a finished operation for its undo window. Full means no undo is
    /// offered for this one, rather than silently dropping an older offer.
    fn store_done(&mut self, entry: PlannedEntry) -> bool {
        if self.done.len() >= MAX_DONE {
            return false;
        }
        self.done.insert(entry.plan_handle.clone(), entry);
        true
    }

    /// An undo answers only the target it was done on, and only once.
    fn take_done(
        &mut self,
        scope: &BindingScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<PlannedEntry, SftpBrowserApiError> {
        if !self
            .done
            .get(plan_handle)
            .is_some_and(|entry| &entry.scope == scope && entry.expires_at > now)
        {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        self.done
            .remove(plan_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)
    }

    fn store_plan(&mut self, entry: PlannedEntry) -> Result<(), SftpBrowserApiError> {
        if self.plans.len() >= MAX_PLANS {
            return Err(SftpBrowserApiError::Capacity);
        }
        self.plans.insert(entry.plan_handle.clone(), entry);
        Ok(())
    }

    fn store_staged(
        &mut self,
        handle: String,
        staged: StagedUpload,
    ) -> Result<(), SftpBrowserApiError> {
        if self.staged.len() >= MAX_STAGED_UPLOADS {
            return Err(SftpBrowserApiError::Capacity);
        }
        self.staged.insert(handle, staged);
        Ok(())
    }

    fn store_directory_upload(
        &mut self,
        handle: String,
        pending: PendingDirectoryUpload,
    ) -> Result<(), SftpBrowserApiError> {
        if self.directory_uploads.len() >= MAX_STAGED_UPLOADS {
            return Err(SftpBrowserApiError::Capacity);
        }
        self.directory_uploads.insert(handle, pending);
        Ok(())
    }

    /// A prepared directory upload answers only its binding, and only once.
    fn take_directory_upload(
        &mut self,
        scope: &BindingScope,
        staged_handle: &str,
        now: Instant,
    ) -> Result<PendingDirectoryUpload, SftpBrowserApiError> {
        let valid = self
            .directory_uploads
            .get(staged_handle)
            .is_some_and(|pending| {
                pending.binding_handle == scope.binding_handle && pending.expires_at > now
            });
        if !valid {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        self.directory_uploads
            .remove(staged_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)
    }

    /// Drops a prepared archive the operator declined, removing its file.
    fn discard_directory_upload(&mut self, scope: &BindingScope, staged_handle: &str) -> bool {
        let owned = self
            .directory_uploads
            .get(staged_handle)
            .is_some_and(|pending| pending.binding_handle == scope.binding_handle);
        if !owned {
            return false;
        }
        if let Some(pending) = self.directory_uploads.remove(staged_handle) {
            let _ = std::fs::remove_file(&pending.path);
        }
        true
    }

    /// A plan only answers the target and browser it was built against.
    fn plan_mut(
        &mut self,
        scope: &BindingScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<&mut PlannedEntry, SftpBrowserApiError> {
        let browsers = &self.browsers;
        self.plans
            .get_mut(plan_handle)
            .filter(|entry| &entry.scope == scope && entry.expires_at > now)
            .filter(|entry| {
                browsers
                    .get(&entry.browser_handle)
                    .is_some_and(|browser| browser.token == entry.browser_token)
            })
            .ok_or(SftpBrowserApiError::BrowserStale)
    }

    /// Executing consumes the plan, so it can never run a second time.
    fn take_confirmed_plan(
        &mut self,
        scope: &BindingScope,
        plan_handle: &str,
        now: Instant,
    ) -> Result<PlannedEntry, SftpBrowserApiError> {
        self.plan_mut(scope, plan_handle, now)?;
        let entry = self
            .plans
            .remove(plan_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if entry.operation.state() != OperationState::Confirmed {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        Ok(entry)
    }

    fn drop_plan(&mut self, scope: &BindingScope, plan_handle: &str) {
        if self
            .plans
            .get(plan_handle)
            .is_some_and(|entry| &entry.scope == scope)
        {
            self.plans.remove(plan_handle);
        }
    }

    fn prune_operations(&mut self, now: Instant) {
        self.plans.retain(|_, entry| entry.expires_at > now);
        self.done.retain(|_, entry| entry.expires_at > now);
        self.staged.retain(|_, staged| {
            if staged.expires_at > now {
                return true;
            }
            let _ = std::fs::remove_file(&staged.path);
            false
        });
        self.directory_uploads.retain(|_, pending| {
            if pending.expires_at > now {
                return true;
            }
            let _ = std::fs::remove_file(&pending.path);
            false
        });
    }
}

impl SftpBrowserRegistry {
    fn total_bytes(&self) -> usize {
        let browsers = self
            .browsers
            .values()
            .map(BrowserSnapshot::registry_bytes)
            .fold(0usize, usize::saturating_add);
        let opens = self
            .active_open_bindings
            .iter()
            .fold(0usize, |total, binding| {
                total.saturating_add(binding.len()).saturating_add(64)
            });
        let operations = self
            .active_operations
            .values()
            .fold(0usize, |total, operation| {
                total
                    .saturating_add(std::mem::size_of::<ActiveOperation>())
                    .saturating_add(operation.browser_handle.len())
                    .saturating_add(operation.binding_handle.len())
                    .saturating_add(64)
            });
        browsers.saturating_add(opens).saturating_add(operations)
    }

    fn begin_open(&mut self, scope: &BindingScope) -> Result<(), SftpBrowserApiError> {
        if self.active_open_bindings.len() >= MAX_ACTIVE_OPENS
            || self.active_open_bindings.contains(&scope.binding_handle)
            || self
                .active_operations
                .values()
                .any(|operation| operation.binding_handle == scope.binding_handle)
        {
            return Err(SftpBrowserApiError::Busy);
        }
        self.active_open_bindings
            .insert(scope.binding_handle.clone());
        Ok(())
    }

    fn finish_open(&mut self, binding_handle: &str) {
        self.active_open_bindings.remove(binding_handle);
    }

    fn replace(&mut self, browser: BrowserSnapshot) -> Result<(), SftpBrowserApiError> {
        if browser.stored_bytes > MAX_BROWSER_BYTES || browser.registry_bytes() > MAX_REGISTRY_BYTES
        {
            return Err(SftpBrowserApiError::Capacity);
        }
        let binding_handle = browser.scope.binding_handle.clone();
        if browser.editor_only {
            if self
                .browsers
                .values()
                .filter(|stored| stored.editor_only)
                .count()
                >= MAX_EDITOR_BROWSERS
                || self.total_bytes().saturating_add(browser.registry_bytes()) > MAX_REGISTRY_BYTES
            {
                return Err(SftpBrowserApiError::Capacity);
            }
            self.browsers
                .insert(browser.browser_handle.clone(), browser);
            return Ok(());
        }
        self.browsers.retain(|_, stored| {
            stored.editor_only || stored.scope.binding_handle != binding_handle
        });
        while self
            .browsers
            .values()
            .filter(|stored| !stored.editor_only)
            .count()
            >= MAX_BROWSERS
            || self.total_bytes().saturating_add(browser.registry_bytes()) > MAX_REGISTRY_BYTES
        {
            let Some(handle) = self
                .browsers
                .iter()
                .filter(|(handle, stored)| !stored.editor_only && !self.browser_is_active(handle))
                .min_by_key(|(_, stored)| stored.last_used_at)
                .map(|(handle, _)| handle.clone())
            else {
                return Err(SftpBrowserApiError::Capacity);
            };
            self.browsers.remove(&handle);
        }
        self.browsers
            .insert(browser.browser_handle.clone(), browser);
        Ok(())
    }

    fn begin_operation(
        &mut self,
        scope: &BindingScope,
        browser_handle: &str,
        entry_handle: &str,
        required_action: EntryAction,
        now: Instant,
    ) -> Result<OperationAccess, SftpBrowserApiError> {
        if self.active_operations.len() >= MAX_ACTIVE_OPERATIONS
            || self.active_open_bindings.contains(&scope.binding_handle)
            || self
                .active_operations
                .values()
                .any(|operation| operation.browser_handle == browser_handle)
        {
            return Err(SftpBrowserApiError::Busy);
        }
        let browser = self
            .browsers
            .get(browser_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if &browser.scope != scope || browser.expires_at <= now {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        let node = browser
            .nodes
            .get(entry_handle)
            .filter(|node| node.action == required_action)
            .cloned()
            .ok_or(SftpBrowserApiError::EntryUnavailable)?;
        let operation_token = Uuid::new_v4();
        let access = OperationAccess {
            browser_handle: browser_handle.to_owned(),
            browser_token: browser.token,
            operation_token,
            scope: scope.clone(),
            node,
            required_action,
        };
        self.active_operations.insert(
            operation_token,
            ActiveOperation {
                browser_handle: browser_handle.to_owned(),
                browser_token: browser.token,
                binding_handle: scope.binding_handle.clone(),
            },
        );
        Ok(access)
    }

    fn verify_operation(
        &self,
        access: &OperationAccess,
        now: Instant,
    ) -> Result<(), SftpBrowserApiError> {
        let active = self
            .active_operations
            .get(&access.operation_token)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let browser = self
            .browsers
            .get(&access.browser_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if active.browser_handle != access.browser_handle
            || active.browser_token != access.browser_token
            || active.binding_handle != access.scope.binding_handle
            || browser.token != access.browser_token
            || browser.scope != access.scope
            || browser.expires_at <= now
            || browser.nodes.get(&access.node.handle) != Some(&access.node)
            || access.node.action != access.required_action
        {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        Ok(())
    }

    fn apply_listing(
        &mut self,
        access: &OperationAccess,
        entries: Vec<SftpEntry>,
        degraded_sftp: bool,
        now: Instant,
    ) -> Result<DirectoryReceipt, SftpBrowserApiError> {
        self.verify_operation(access, now)?;
        let current = self
            .browsers
            .get(&access.browser_handle)
            .cloned()
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let mut candidate = current.clone();
        candidate.degraded_sftp = degraded_sftp;
        let dto = candidate.refresh_directory(&access.node.handle, entries, now)?;
        let projected_total = self
            .total_bytes()
            .saturating_sub(current.registry_bytes())
            .saturating_add(candidate.registry_bytes());
        if candidate.stored_bytes > MAX_BROWSER_BYTES || projected_total > MAX_REGISTRY_BYTES {
            return Err(SftpBrowserApiError::Capacity);
        }
        let revision = candidate.revision;
        self.browsers
            .insert(access.browser_handle.clone(), candidate);
        Ok(DirectoryReceipt {
            dto,
            browser_handle: access.browser_handle.clone(),
            browser_token: access.browser_token,
            directory_handle: access.node.handle.clone(),
            revision,
        })
    }

    fn verify_directory_response(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        browser_token: Uuid,
        directory_handle: &str,
        revision: u64,
        now: Instant,
    ) -> Result<(), SftpBrowserApiError> {
        let browser = self
            .browsers
            .get(browser_handle)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        if browser.token != browser_token
            || &browser.scope != scope
            || browser.revision != revision
            || browser.expires_at <= now
            || browser
                .nodes
                .get(directory_handle)
                .is_none_or(|node| node.action != EntryAction::Browse)
        {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        Ok(())
    }

    /// A lookup, not an operation: it holds no slot, so a listing in progress
    /// does not refuse it.
    fn directory_for_terminal(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        directory_handle: &str,
        now: Instant,
    ) -> Result<RemotePath, SftpBrowserApiError> {
        let browser = self
            .browsers
            .get(browser_handle)
            .filter(|browser| &browser.scope == scope && browser.expires_at > now)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let node = browser
            .nodes
            .get(directory_handle)
            .filter(|node| {
                node.action == EntryAction::Browse && node.kind == SftpBrowserEntryKind::Directory
            })
            .ok_or(SftpBrowserApiError::EntryUnavailable)?;
        Ok(node.path.clone())
    }

    /// Same lookup shape as `directory_for_terminal`: no operation slot, so a
    /// listing in progress does not refuse a fetch. A directory the browser
    /// offers to open and a regular file it offers to preview both qualify;
    /// anything else cannot be packed and is refused here rather than on the
    /// target.
    fn path_for_fetch(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        entry_handle: &str,
        now: Instant,
    ) -> Result<RemotePath, SftpBrowserApiError> {
        let browser = self
            .browsers
            .get(browser_handle)
            .filter(|browser| &browser.scope == scope && browser.expires_at > now)
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let node = browser
            .nodes
            .get(entry_handle)
            .ok_or(SftpBrowserApiError::EntryUnavailable)?;
        let qualifies = matches!(
            (node.action, node.kind),
            (EntryAction::Browse, SftpBrowserEntryKind::Directory)
                | (EntryAction::Preview, SftpBrowserEntryKind::File)
        );
        if !qualifies {
            return Err(SftpBrowserApiError::EntryUnavailable);
        }
        Ok(node.path.clone())
    }

    fn finish_operation(&mut self, operation_token: Uuid) {
        self.active_operations.remove(&operation_token);
    }

    fn prune(&mut self, now: Instant) {
        let mut active = self
            .active_operations
            .values()
            .map(|operation| operation.browser_handle.as_str())
            .collect::<HashSet<_>>();
        // A browser whose queue still has pending or running work stays
        // alive past its TTL; the queue's item validation decides staleness.
        for (handle, queue) in &self.queues {
            let pending = queue
                .items
                .lock()
                .map(|items| {
                    items.iter().any(|item| {
                        matches!(item.state, QueueItemState::Queued | QueueItemState::Running)
                    })
                })
                .unwrap_or(false);
            if pending {
                active.insert(handle.as_str());
            }
        }
        for relay in self.relays.values() {
            let running = relay
                .state
                .lock()
                .map(|state| state.status == RelayStatus::Running)
                .unwrap_or(false);
            if running {
                active.insert(relay.browser_handle.as_str());
            }
        }
        self.browsers
            .retain(|handle, browser| browser.expires_at > now || active.contains(handle.as_str()));
        self.prune_operations(now);
    }

    fn browser_is_active(&self, browser_handle: &str) -> bool {
        self.active_operations
            .values()
            .any(|operation| operation.browser_handle == browser_handle)
    }
}

struct OpenPermit {
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    binding_handle: String,
}

impl Drop for OpenPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_open(&self.binding_handle);
        }
    }
}

/// An upload or download that is copying now, and the switch that stops it.
struct ActiveTransfer {
    binding_handle: String,
    browser_handle: String,
    cancel: SftpTransferCancel,
}

/// Holds a transfer's place in the registry for exactly as long as it runs.
struct TransferRegistration {
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    token: Uuid,
}

impl Drop for TransferRegistration {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.transfers.remove(&self.token);
        }
    }
}

/// Runs a transfer to its deadline. At the deadline it is cancelled rather
/// than dropped, and given a moment to remove what it wrote: dropping it
/// would stop the copy before its own clean-up could run.
async fn run_transfer<T>(
    transfer: impl std::future::Future<Output = T>,
    cancel: &SftpTransferCancel,
    deadline: Duration,
) -> Result<T, SftpBrowserApiError> {
    tokio::pin!(transfer);
    match timeout(deadline, &mut transfer).await {
        Ok(result) => Ok(result),
        Err(_) => {
            cancel.cancel();
            let _ = timeout(TRANSFER_CANCEL_GRACE, &mut transfer).await;
            Err(SftpBrowserApiError::Deadline)
        }
    }
}

struct OperationPermit {
    registry: Arc<Mutex<SftpBrowserRegistry>>,
    operation_token: Uuid,
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_operation(self.operation_token);
        }
    }
}

struct ProjectedText {
    text: String,
    observed_line_count: u32,
    displayed_line_count: u32,
    truncated: bool,
    /// Whether this text is the file, byte for byte.
    ///
    /// The projection splits on lines and rejoins with `\n`, which was fine
    /// while it only fed a preview and is not fine now that it feeds an
    /// editor: a file ending in a newline came back without one, and a file
    /// with CRLF endings came back with LF. Saving either would have quietly
    /// rewritten the file for no reason the operator asked for — on a sudoers
    /// file or a shell script that is a real change.
    ///
    /// Computed by comparison rather than by tracking each transformation, so
    /// it cannot drift from what the projection actually did.
    exact: bool,
}

/// Lowercase hex, the form the core's own compare-and-write expects.
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn project_text(source: &str) -> Result<ProjectedText, SftpBrowserApiError> {
    if source.len() > MAX_CORE_TEXT_BYTES {
        return Err(SftpBrowserApiError::InvalidText);
    }
    let observed = source.lines().count();
    let observed_line_count =
        u32::try_from(observed).map_err(|_| SftpBrowserApiError::InvalidText)?;
    let mut lines = Vec::with_capacity(observed.min(MAX_TEXT_LINES));
    let mut bytes = 0usize;
    let mut truncated = false;
    for line in source.lines() {
        if lines.len() >= MAX_TEXT_LINES {
            truncated = true;
            break;
        }
        // Only control characters and the per-line ceiling are applied.
        let (projected, line_truncated) = normalize_plain_text(line, MAX_TEXT_LINE_BYTES);
        let separator = usize::from(!lines.is_empty());
        if bytes
            .saturating_add(separator)
            .saturating_add(projected.len())
            > MAX_TEXT_BYTES
        {
            truncated = true;
            break;
        }
        bytes = bytes
            .saturating_add(separator)
            .saturating_add(projected.len());
        truncated |= line_truncated;
        lines.push(projected);
    }
    truncated |= observed > lines.len();
    let mut text = lines.join("\n");
    // Put back the final newline the split removed. Most text files on a Unix
    // host end with one, and an editor that drops it changes every file it
    // opens.
    if !truncated && source.ends_with('\n') {
        text.push('\n');
    }
    let exact = !truncated && text == source;
    Ok(ProjectedText {
        observed_line_count,
        displayed_line_count: u32::try_from(lines.len())
            .map_err(|_| SftpBrowserApiError::InvalidText)?,
        truncated,
        exact,
        text,
    })
}

fn project_name(value: &str) -> (String, bool) {
    normalize_plain_text(value, MAX_ENTRY_NAME_BYTES)
}

fn normalize_plain_text(value: &str, maximum_bytes: usize) -> (String, bool) {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    let mut truncated = false;
    for character in value.chars() {
        let replacement = if character == '\t' || !character.is_control() {
            character
        } else {
            '\u{fffd}'
        };
        if output.len().saturating_add(replacement.len_utf8()) > maximum_bytes {
            truncated = true;
            break;
        }
        output.push(replacement);
    }
    (output, truncated)
}

const fn entry_kind(value: SftpFileKind) -> SftpBrowserEntryKind {
    match value {
        SftpFileKind::Directory => SftpBrowserEntryKind::Directory,
        SftpFileKind::File => SftpBrowserEntryKind::File,
        SftpFileKind::Symlink => SftpBrowserEntryKind::Symlink,
        SftpFileKind::Other => SftpBrowserEntryKind::Other,
    }
}

fn validate_sftp_session(
    scope: &BindingScope,
    session: &BoundSftpSession,
) -> Result<(), SftpBrowserApiError> {
    if session.session_id() != scope.session_id
        || session.connection_id() != scope.connection_id
        || session.target() != &scope.target
    {
        return Err(SftpBrowserApiError::BindingUnavailable);
    }
    Ok(())
}

fn validate_handle(value: &str) -> Result<(), SftpBrowserApiError> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SftpBrowserApiError::InvalidHandle);
    }
    Ok(())
}

fn remaining_seconds(expires_at: Instant, now: Instant) -> Result<u64, SftpBrowserApiError> {
    if expires_at <= now {
        return Err(SftpBrowserApiError::BrowserStale);
    }
    Ok(expires_at
        .saturating_duration_since(now)
        .as_secs()
        .saturating_add(1)
        .min(BROWSER_TTL.as_secs()))
}

fn ensure_serialized_bound<T: Serialize>(
    value: &T,
    maximum_bytes: usize,
) -> Result<(), SftpBrowserApiError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SftpBrowserApiError::InvalidListing)?;
    if bytes.len() > maximum_bytes {
        return Err(SftpBrowserApiError::Capacity);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Write operations
//
// Every change to a target goes through the core's plan → confirm → execute →
// verify pipeline, and nothing here can shortcut it. The renderer names an
// entry by an opaque capability this registry issued; it never names a path, a
// mode, or a target. A plan is single use, bound to the browser it came from,
// and expires with it. When verification fails the operation is restored from
// the backup the core took, and the receipt says so.
// ---------------------------------------------------------------------------

/// What the renderer asked for, in capability terms only.
#[derive(Debug)]
pub(crate) enum SftpOperationRequest {
    CreateDirectory {
        directory_handle: String,
        name: String,
    },
    Rename {
        entry_handle: String,
        name: String,
    },
    Chmod {
        entry_handle: String,
        mode: u32,
    },
    Remove {
        entry_handle: String,
    },
    Archive {
        entry_handles: Vec<String>,
        name: String,
        format: String,
    },
    Upload {
        directory_handle: String,
        staged_handle: String,
        name: String,
    },
    /// Write edited text back over a file the operator opened.
    ///
    /// `expected_sha256` is the hash the read handed out. The core's
    /// compare-and-write refuses if the file no longer hashes to it, so an
    /// edit that began before somebody else changed the file fails loudly
    /// instead of quietly discarding their work.
    WriteText {
        entry_handle: String,
        text: String,
        expected_sha256: String,
    },
}

impl SftpOperationRequest {
    fn kind(&self) -> &'static str {
        match self {
            Self::CreateDirectory { .. } => "create-directory",
            Self::Rename { .. } => "rename",
            Self::Chmod { .. } => "chmod",
            Self::Remove { .. } => "remove",
            Self::Archive { .. } => "archive",
            Self::Upload { .. } => "upload",
            Self::WriteText { .. } => "write-text",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpOperationPlanDto {
    pub(crate) plan_handle: String,
    pub(crate) browser_handle: String,
    pub(crate) kind: String,
    pub(crate) summary: String,
    pub(crate) dangerous: bool,
    pub(crate) restore_description: Option<String>,
    pub(crate) state: String,
    pub(crate) expires_in_seconds: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpOperationReceiptDto {
    pub(crate) plan_handle: String,
    pub(crate) kind: String,
    pub(crate) passed: bool,
    pub(crate) detail: String,
    pub(crate) restored: bool,
    /// Verified and of a kind that can be put back: the window may offer an
    /// undo for [`UNDO_TTL`].
    pub(crate) undoable: bool,
    /// The operator stopped the upload; what it had written was removed.
    pub(crate) cancelled: bool,
}

/// One queue item as the page shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpQueueItemDto {
    pub item_id: u64,
    pub name: String,
    /// queued | running | done | failed | cancelled.
    pub state: String,
    pub done_bytes: String,
    pub total_bytes: String,
    /// Reason for failed items, or the integrity/resume note for done ones.
    pub detail: String,
}

/// A browser window's batch transfer queue.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpTransferQueueDto {
    pub active: bool,
    /// True when the target has no SFTP: items run one at a time through SCP
    /// and downloads cannot resume.
    pub degraded: bool,
    pub items: Vec<SftpQueueItemDto>,
}

/// How many running transfers a cancel reached; zero when none was running.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpTransferCancelDto {
    pub(crate) cancelled: u32,
}

/// One saved connection the relay dialog may offer, minus the binding this
/// browser is attached to.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpRelayTargetDto {
    pub connection_id: String,
    /// Display label plus host identity, e.g. "web-a（root@10.0.0.2:22）".
    pub label: String,
}

/// A file relay between two SSH targets through a managed host temp file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpRelayDto {
    pub relay_handle: String,
    /// running | done | failed | cancelled.
    pub state: String,
    /// download | upload, empty before the first leg starts.
    pub leg: String,
    pub done_bytes: String,
    pub total_bytes: String,
    /// Reason for a failed relay; the verification note for a done one.
    pub detail: String,
}

/// What an undo did: put back and read back, or refused with the reason.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpOperationUndoDto {
    pub(crate) plan_handle: String,
    pub(crate) kind: String,
    pub(crate) undone: bool,
    pub(crate) detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SftpStagedUploadDto {
    pub(crate) staged_handle: String,
    pub(crate) name: String,
    pub(crate) bytes: String,
}

struct PlannedEntry {
    plan_handle: String,
    browser_handle: String,
    browser_token: Uuid,
    scope: BindingScope,
    kind: String,
    operation: SftpPlannedOperation,
    expires_at: Instant,
}

#[derive(Clone)]
struct StagedUpload {
    binding_handle: String,
    path: PathBuf,
    expires_at: Instant,
}

/// The most items one browser's transfer queue may hold.
const MAX_QUEUE_ITEMS: usize = 64;
const MAX_RELAY_TARGETS: usize = 32;

/// What the page sends for each host-picked file in a queue upload.
#[derive(Debug, Clone)]
pub(crate) struct SftpQueuedUpload {
    pub staged_handle: String,
    pub name: String,
}

#[derive(Clone)]
enum QueueItemKind {
    Download {
        remote_path: RemotePath,
        local_dir: PathBuf,
    },
    Upload {
        staged_path: PathBuf,
        dest_dir: RemotePath,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueItemState {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
}

struct QueueItem {
    id: u64,
    name: String,
    kind: QueueItemKind,
    state: QueueItemState,
    done_bytes: u64,
    total_bytes: u64,
    detail: String,
    cancel: Option<SftpTransferCancel>,
    /// The `.part` a running download writes; polling its length is the
    /// progress number the page shows.
    part_path: Option<PathBuf>,
    /// The remote file a running upload grows; polling its size is the
    /// progress number the page shows.
    remote_dest: Option<RemotePath>,
}

/// One browser window's batch transfer queue. Bound to the binding it was
/// created under; a target switch drops it via `close_binding`/`ensure_queue`.
struct TransferQueue {
    scope: BindingScope,
    browser_handle: String,
    degraded: bool,
    rate_limit_bytes_per_second: std::sync::atomic::AtomicU64,
    items: Mutex<Vec<QueueItem>>,
    runner: Mutex<Option<tokio::task::JoinHandle<()>>>,
    next_item_id: std::sync::atomic::AtomicU64,
}

/// Queued items turn cancelled; running ones get their switch thrown.
fn cancel_queue_items(items: &Mutex<Vec<QueueItem>>) -> u32 {
    let mut cancelled = 0_u32;
    if let Ok(mut items) = items.lock() {
        for item in items.iter_mut() {
            match item.state {
                QueueItemState::Queued => {
                    item.state = QueueItemState::Cancelled;
                    item.detail = "已取消。".to_owned();
                    cancelled = cancelled.saturating_add(1);
                }
                QueueItemState::Running => {
                    if let Some(cancel) = &item.cancel {
                        cancel.cancel();
                    }
                    cancelled = cancelled.saturating_add(1);
                }
                _ => {}
            }
        }
    }
    cancelled
}

impl TransferQueue {
    fn cancel_all(&self) -> u32 {
        cancel_queue_items(&self.items)
    }
}

impl Drop for TransferQueue {
    fn drop(&mut self) {
        self.cancel_all();
        if let Ok(items) = self.items.lock() {
            for item in items.iter() {
                // A staged upload the item never consumed would otherwise
                // sit in managed staging until its TTL; remove it now.
                if let QueueItemKind::Upload { staged_path, .. } = &item.kind
                    && item.state != QueueItemState::Done
                {
                    let _ = std::fs::remove_file(staged_path);
                }
            }
        }
    }
}

fn queue_item_update(queue: &Arc<TransferQueue>, id: u64, update: impl FnOnce(&mut QueueItem)) {
    if let Ok(mut items) = queue.items.lock()
        && let Some(item) = items.iter_mut().find(|item| item.id == id)
    {
        update(item);
    }
}

/// Which side of a relay is copying; the progress line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayLeg {
    Download,
    Upload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayStatus {
    Running,
    Done,
    Failed,
    Cancelled,
}

enum RelayOutcome {
    Done,
    Failed(String),
    Cancelled,
}

struct RelayState {
    status: RelayStatus,
    leg: Option<RelayLeg>,
    done_bytes: u64,
    total_bytes: u64,
    detail: String,
}

/// A single-file relay between the browser's binding and a saved peer
/// connection. LovelyHawk keeps exactly one SSH binding at a time, so the
/// peer side is not a binding: the relay establishes its own session for the
/// transfer and tears it down on every outcome. The peer guard lives in a
/// private target context, so a relay can never disturb the active target
/// epoch — and the active epoch can never validate the peer.
struct Relay {
    scope: BindingScope,
    browser_handle: String,
    cancel: SftpTransferCancel,
    state: Mutex<RelayState>,
    /// The managed temp file the first leg writes; its length is the
    /// download progress number.
    temp_path: Mutex<Option<PathBuf>>,
    /// The remote destination the second leg grows; its size is the upload
    /// progress number, read through the peer session pair stored here.
    remote_dest: Mutex<Option<RemotePath>>,
    peer: Mutex<Option<(SftpService, BoundSftpSession)>>,
}

/// The peer-side paths the second leg checks and writes: the directory the
/// operator picked and the exact file inside it.
struct RelayDestination {
    dir: RemotePath,
    remote: RemotePath,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The managed temp file a relay leaves behind on no outcome at all.
struct RelayTempFile(PathBuf);

impl Drop for RelayTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn relay_target_label(config: &ConnectionConfig) -> String {
    let host = if config.host.contains(':') {
        format!("[{}]", config.host)
    } else {
        config.host.clone()
    };
    let identity = format!("{}@{}:{}", config.username, host, config.port);
    if config.name.is_empty() {
        identity
    } else {
        format!("{}（{}）", config.name, identity)
    }
}

/// The `.part` sidecar: the remote size and mtime the partial was taken
/// under, so a retry can tell "resume" apart from "the file changed".
#[derive(serde::Serialize, serde::Deserialize)]
struct PartMeta {
    size: u64,
    mtime_epoch: Option<i64>,
}

fn read_part_meta(path: &Path) -> Option<PartMeta> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_part_meta(path: &Path, size: u64, mtime_epoch: Option<i64>) {
    if let Ok(text) = serde_json::to_string(&PartMeta { size, mtime_epoch }) {
        let _ = std::fs::write(path, text);
    }
}

fn local_file_sha256(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// A remote entry name turned into a safe local file name: separators,
/// control characters and Windows-reserved forms are replaced, never
/// followed or interpreted.
fn sanitize_local_name(name: &str) -> Result<String, SftpBrowserApiError> {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|character| match character {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']).to_owned();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if cleaned.is_empty()
        || cleaned.len() > MAX_ENTRY_NAME_INPUT
        || cleaned == "."
        || cleaned == ".."
        || RESERVED.contains(&cleaned.to_ascii_uppercase().as_str())
    {
        return Err(SftpBrowserApiError::InvalidHandle);
    }
    Ok(cleaned)
}

/// A packed local directory archive held in managed staging while the page
/// shows its preview; the name is bound here so a later call cannot swap it.
struct PendingDirectoryUpload {
    binding_handle: String,
    path: PathBuf,
    name: String,
    expires_at: Instant,
}

impl SftpBrowserApi {
    /// Builds a plan the operator can read before anything is touched.
    pub(crate) async fn plan_operation(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        request: SftpOperationRequest,
    ) -> Result<SftpOperationPlanDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        let kind = request.kind().to_owned();
        let (_, scope) = self.capture_binding(binding_handle)?;
        let (browser_token, mutation) = self.build_mutation(&scope, browser_handle, &request)?;
        let session = self.bind_sftp(&scope).await?;
        self.validate_binding(&scope)?;
        let planned = match mutation {
            PlannedMutation::Remote(mutation) => self
                .services
                .sftp()
                .plan(&session, mutation)
                .map_err(|_| SftpBrowserApiError::InvalidListing)?,
            PlannedMutation::Upload {
                staged_path,
                destination,
            } => self
                .services
                .sftp()
                .plan_upload(&session, &self.paths, &staged_path, destination)
                .map_err(|_| SftpBrowserApiError::InvalidListing)?,
        };
        self.validate_binding(&scope)?;
        validate_sftp_session(&scope, &session)?;

        let now = Instant::now();
        let plan_handle = Uuid::new_v4().to_string();
        let entry = PlannedEntry {
            plan_handle: plan_handle.clone(),
            browser_handle: browser_handle.to_owned(),
            browser_token,
            scope: scope.clone(),
            kind: kind.clone(),
            operation: planned,
            expires_at: now + PLAN_TTL,
        };
        let dto = plan_dto(&entry, now)?;
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_plan(entry)?;
        Ok(dto)
    }

    /// Records the operator's approval; nothing runs until this happened.
    pub(crate) fn confirm_operation(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SftpOperationPlanDto, SftpBrowserApiError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        let entry = registry.plan_mut(&scope, plan_handle, now)?;
        let confirmation = DangerousConfirmation::approve(entry.operation.definition());
        entry
            .operation
            .confirm(confirmation)
            .map_err(|_| SftpBrowserApiError::BrowserStale)?;
        plan_dto(entry, now)
    }

    /// Runs the confirmed plan once, verifies it, and restores on failure.
    pub(crate) async fn execute_operation(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SftpOperationReceiptDto, SftpBrowserApiError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        // The plan leaves the registry before the await, so the lock is never
        // held across it and the plan can never run twice.
        let mut entry = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_confirmed_plan(&scope, plan_handle, now)?
        };
        // An upload copies bytes for a while; the operator may stop it from
        // the window, and at the deadline it is cancelled rather than dropped.
        let cancel = entry.operation.transfer_cancel();
        let _transfer = self.register_transfer(&scope, &entry.browser_handle, &cancel)?;
        let outcome = run_transfer(
            entry.operation.execute_and_verify(),
            &cancel,
            EXECUTE_DEADLINE,
        )
        .await;
        self.validate_binding(&scope)?;
        let verification = match outcome {
            Err(error) => return Err(error),
            Ok(Err(error)) if lovelyhawk_core::sftp::is_transfer_cancelled(&error) => {
                // The copy removed what it wrote; there is nothing to restore.
                return Ok(SftpOperationReceiptDto {
                    plan_handle: entry.plan_handle,
                    kind: entry.kind,
                    passed: false,
                    detail: lovelyhawk_core::sftp::operation_failure_advice(&error)
                        .unwrap_or("传输已取消。")
                        .to_owned(),
                    restored: false,
                    undoable: false,
                    cancelled: true,
                });
            }
            Ok(Err(error)) => {
                // The core reads the failure and hands back one of its own
                // sentences, or nothing. Nothing the machine wrote reaches the
                // window either way — but when the core recognises the trouble,
                // saying so beats "操作未能完成" by the whole next step.
                let advice = lovelyhawk_core::sftp::operation_failure_advice(&error);
                let restored = entry.operation.restore().await.is_ok();
                return Ok(SftpOperationReceiptDto {
                    plan_handle: entry.plan_handle,
                    kind: entry.kind,
                    passed: false,
                    detail: advice.unwrap_or("操作未能完成。").to_owned(),
                    restored,
                    undoable: false,
                    cancelled: false,
                });
            }
            Ok(Ok(verification)) => verification,
        };
        let restored = if verification.passed {
            false
        } else {
            entry.operation.restore().await.is_ok()
        };
        let mut receipt = SftpOperationReceiptDto {
            plan_handle: entry.plan_handle.clone(),
            kind: entry.kind.clone(),
            passed: verification.passed,
            detail: bounded_detail(&verification.detail),
            restored,
            undoable: false,
            cancelled: false,
        };
        if verification.passed && entry.operation.can_undo() {
            entry.expires_at = Instant::now() + UNDO_TTL;
            receipt.undoable = self.lock_registry()?.store_done(entry);
        }
        Ok(receipt)
    }

    /// Puts a finished operation back, once, while the target still shows
    /// exactly what the operation left; the core refuses otherwise and reads
    /// the restore back.
    pub(crate) async fn undo_operation(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<SftpOperationUndoDto, SftpBrowserApiError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut entry = {
            let now = Instant::now();
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            registry.take_done(&scope, plan_handle, now)?
        };
        let outcome = timeout(EXECUTE_DEADLINE, entry.operation.undo()).await;
        self.validate_binding(&scope)?;
        match outcome {
            Err(_) => Err(SftpBrowserApiError::Deadline),
            Ok(Ok(detail)) => Ok(SftpOperationUndoDto {
                plan_handle: entry.plan_handle,
                kind: entry.kind,
                undone: true,
                detail: bounded_detail(&detail),
            }),
            Ok(Err(error)) => Ok(SftpOperationUndoDto {
                plan_handle: entry.plan_handle,
                kind: entry.kind,
                undone: false,
                detail: lovelyhawk_core::sftp::operation_failure_advice(&error)
                    .unwrap_or("撤销没有完成，请在目标机上检查现在的状态。")
                    .to_owned(),
            }),
        }
    }

    /// Stops every upload and download this browser has copying now. Each one
    /// removes what it wrote before it answers its own caller; this only
    /// throws the switch and says how many there were.
    pub(crate) fn cancel_transfers(
        &self,
        binding_handle: &str,
        browser_handle: &str,
    ) -> Result<SftpTransferCancelDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let cancelled = self
            .lock_registry()?
            .cancel_transfers(&scope.binding_handle, browser_handle);
        Ok(SftpTransferCancelDto { cancelled })
    }

    fn register_transfer(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        cancel: &SftpTransferCancel,
    ) -> Result<TransferRegistration, SftpBrowserApiError> {
        let token = Uuid::new_v4();
        self.lock_registry()?.transfers.insert(
            token,
            ActiveTransfer {
                binding_handle: scope.binding_handle.clone(),
                browser_handle: browser_handle.to_owned(),
                cancel: cancel.clone(),
            },
        );
        Ok(TransferRegistration {
            registry: Arc::clone(&self.registry),
            token,
        })
    }

    /// Enqueues downloads of the selected files into one host-chosen folder.
    /// The queue lives on the browser; every item writes `<name>.part` and
    /// only renames to the real name once complete, so a retry can resume.
    pub(crate) async fn queue_download(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        file_handles: &[String],
        local_dir: &Path,
        rate_limit_kib: u64,
    ) -> Result<SftpTransferQueueDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        if file_handles.is_empty() || file_handles.len() > MAX_QUEUE_ITEMS {
            return Err(SftpBrowserApiError::InvalidHandle);
        }
        if !local_dir.is_dir() {
            return Err(SftpBrowserApiError::InvalidHandle);
        }
        let (_, scope) = self.capture_binding(binding_handle)?;
        let session = self.bind_sftp(&scope).await?;
        let degraded = self.sftp_degraded(&session).await?;
        let nodes = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            let mut nodes = Vec::with_capacity(file_handles.len());
            for handle in file_handles {
                validate_handle(handle)?;
                let node = registry.queue_entry(
                    &scope,
                    browser_handle,
                    handle,
                    EntryAction::Preview,
                    Instant::now(),
                )?;
                if node.kind != SftpBrowserEntryKind::File {
                    return Err(SftpBrowserApiError::EntryUnavailable);
                }
                let local_name = sanitize_local_name(&node.display_name)?;
                nodes.push((local_name, node.path.clone()));
            }
            nodes
        };
        let queue = self.ensure_queue(&scope, browser_handle, degraded, Some(rate_limit_kib))?;
        {
            let mut items = queue
                .items
                .lock()
                .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
            if items.len() + nodes.len() > MAX_QUEUE_ITEMS {
                return Err(SftpBrowserApiError::Capacity);
            }
            for (local_name, remote_path) in nodes {
                let id = queue
                    .next_item_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                items.push(QueueItem {
                    id,
                    name: local_name,
                    kind: QueueItemKind::Download {
                        remote_path,
                        local_dir: local_dir.to_path_buf(),
                    },
                    state: QueueItemState::Queued,
                    done_bytes: 0,
                    total_bytes: 0,
                    detail: String::new(),
                    cancel: None,
                    part_path: None,
                    remote_dest: None,
                });
            }
        }
        self.spawn_queue_runner(&queue);
        self.queue_snapshot(&queue).await
    }

    /// Enqueues staged host files for upload into the given remote directory.
    pub(crate) async fn queue_upload(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        directory_handle: &str,
        staged: &[SftpQueuedUpload],
    ) -> Result<SftpTransferQueueDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        validate_handle(directory_handle)?;
        if staged.is_empty() || staged.len() > MAX_QUEUE_ITEMS {
            return Err(SftpBrowserApiError::InvalidHandle);
        }
        let (_, scope) = self.capture_binding(binding_handle)?;
        let session = self.bind_sftp(&scope).await?;
        let degraded = self.sftp_degraded(&session).await?;
        let now = Instant::now();
        let mut claimed = Vec::with_capacity(staged.len());
        {
            let mut registry = self.lock_registry()?;
            registry.prune(now);
            let directory = registry
                .queue_entry(
                    &scope,
                    browser_handle,
                    directory_handle,
                    EntryAction::Browse,
                    now,
                )
                .and_then(|node| {
                    (node.kind == SftpBrowserEntryKind::Directory)
                        .then(|| node.path.clone())
                        .ok_or(SftpBrowserApiError::EntryUnavailable)
                })?;
            for item in staged {
                validate_handle(&item.staged_handle)?;
                let name = validated_entry_name(&item.name)?;
                let staged_upload = registry
                    .staged
                    .get(&item.staged_handle)
                    .filter(|entry| {
                        entry.binding_handle == scope.binding_handle && entry.expires_at > now
                    })
                    .cloned()
                    .ok_or(SftpBrowserApiError::EntryUnavailable)?;
                registry.staged.remove(&item.staged_handle);
                claimed.push((name, staged_upload.path, directory.clone()));
            }
        }
        let queue = self.ensure_queue(&scope, browser_handle, degraded, None)?;
        {
            let mut items = queue
                .items
                .lock()
                .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
            if items.len() + claimed.len() > MAX_QUEUE_ITEMS {
                return Err(SftpBrowserApiError::Capacity);
            }
            for (name, staged_path, dest_dir) in claimed {
                let id = queue
                    .next_item_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                items.push(QueueItem {
                    id,
                    name,
                    kind: QueueItemKind::Upload {
                        staged_path,
                        dest_dir,
                    },
                    state: QueueItemState::Queued,
                    done_bytes: 0,
                    total_bytes: 0,
                    detail: String::new(),
                    cancel: None,
                    part_path: None,
                    remote_dest: None,
                });
            }
        }
        self.spawn_queue_runner(&queue);
        self.queue_snapshot(&queue).await
    }

    /// Live queue state for the page; `None` when this browser has no queue
    /// (yet, or after the target changed and it was invalidated).
    pub(crate) async fn queue_poll(
        &self,
        binding_handle: &str,
        browser_handle: &str,
    ) -> Result<Option<SftpTransferQueueDto>, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let queue = self
            .lock_registry()?
            .queues
            .get(browser_handle)
            .filter(|queue| queue.scope == scope)
            .cloned();
        let Some(queue) = queue else {
            return Ok(None);
        };
        self.queue_snapshot(&queue).await.map(Some)
    }

    /// Cancels every item: queued ones turn cancelled at once, running ones
    /// get their transfer switch thrown and land cancelled when they answer.
    pub(crate) fn queue_cancel_all(
        &self,
        binding_handle: &str,
        browser_handle: &str,
    ) -> Result<SftpTransferCancelDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let queue = self
            .lock_registry()?
            .queues
            .get(browser_handle)
            .filter(|queue| queue.scope == scope)
            .cloned()
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        Ok(SftpTransferCancelDto {
            cancelled: queue.cancel_all(),
        })
    }

    /// Requeues one failed or cancelled item.
    pub(crate) async fn queue_retry(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        item_id: u64,
    ) -> Result<SftpTransferQueueDto, SftpBrowserApiError> {
        validate_handle(browser_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let queue = self
            .lock_registry()?
            .queues
            .get(browser_handle)
            .filter(|queue| queue.scope == scope)
            .cloned()
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        {
            let mut items = queue
                .items
                .lock()
                .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
            let item = items
                .iter_mut()
                .find(|item| item.id == item_id)
                .ok_or(SftpBrowserApiError::EntryUnavailable)?;
            match item.state {
                QueueItemState::Failed | QueueItemState::Cancelled => {
                    item.state = QueueItemState::Queued;
                    item.done_bytes = 0;
                    item.detail = String::new();
                    item.cancel = None;
                }
                _ => return Err(SftpBrowserApiError::Busy),
            }
        }
        self.spawn_queue_runner(&queue);
        self.queue_snapshot(&queue).await
    }

    /// One queue per browser window. A queue created under another binding is
    /// stale — it is dropped here and a fresh one replaces it.
    fn ensure_queue(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        degraded: bool,
        rate_limit_kib: Option<u64>,
    ) -> Result<Arc<TransferQueue>, SftpBrowserApiError> {
        let mut registry = self.lock_registry()?;
        if let Some(existing) = registry.queues.get(browser_handle) {
            if &existing.scope == scope && existing.degraded == degraded {
                if let Some(kib) = rate_limit_kib {
                    existing.rate_limit_bytes_per_second.store(
                        kib.saturating_mul(1024),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                return Ok(Arc::clone(existing));
            }
            let stale = Arc::clone(existing);
            registry.queues.remove(browser_handle);
            stale.cancel_all();
        }
        let queue = Arc::new(TransferQueue {
            scope: scope.clone(),
            browser_handle: browser_handle.to_owned(),
            degraded,
            rate_limit_bytes_per_second: std::sync::atomic::AtomicU64::new(
                rate_limit_kib.unwrap_or(0).saturating_mul(1024),
            ),
            items: Mutex::new(Vec::new()),
            runner: Mutex::new(None),
            next_item_id: std::sync::atomic::AtomicU64::new(1),
        });
        registry
            .queues
            .insert(browser_handle.to_owned(), Arc::clone(&queue));
        Ok(queue)
    }

    fn spawn_queue_runner(&self, queue: &Arc<TransferQueue>) {
        let Ok(mut slot) = queue.runner.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let api = self.cloned_for_task();
        let queue = Arc::clone(queue);
        *slot = Some(tokio::spawn(async move { api.run_queue(queue).await }));
    }

    fn cloned_for_task(&self) -> Self {
        Self {
            services: self.services.clone(),
            ssh_api: Arc::clone(&self.ssh_api),
            registry: Arc::clone(&self.registry),
            paths: Arc::clone(&self.paths),
        }
    }

    /// Drains queued items, at most two running at once — one for degraded
    /// targets, where SCP transfers are serialized.
    async fn run_queue(&self, queue: Arc<TransferQueue>) {
        let limit = if queue.degraded { 1 } else { 2 };
        let mut set = tokio::task::JoinSet::new();
        loop {
            while set.len() < limit {
                let claimed = {
                    let Ok(mut items) = queue.items.lock() else {
                        break;
                    };
                    items
                        .iter_mut()
                        .find(|item| item.state == QueueItemState::Queued)
                        .map(|item| {
                            item.state = QueueItemState::Running;
                            let cancel = SftpTransferCancel::new();
                            item.cancel = Some(cancel.clone());
                            (item.id, item.name.clone(), item.kind.clone(), cancel)
                        })
                };
                let Some((id, name, kind, cancel)) = claimed else {
                    break;
                };
                let api = self.cloned_for_task();
                let queue = Arc::clone(&queue);
                set.spawn(async move {
                    match kind {
                        QueueItemKind::Download {
                            remote_path,
                            local_dir,
                        } => {
                            api.run_download_item(&queue, id, name, remote_path, local_dir, cancel)
                                .await;
                        }
                        QueueItemKind::Upload {
                            staged_path,
                            dest_dir,
                        } => {
                            api.run_upload_item(&queue, id, name, staged_path, dest_dir, cancel)
                                .await;
                        }
                    }
                });
            }
            if set.is_empty() {
                break;
            }
            let _ = set.join_next().await;
        }
        // Let a retry or a new enqueue start a fresh runner once this one is
        // fully drained; recheck because a retry may have slipped in while
        // the last item finished.
        if let Ok(mut slot) = queue.runner.lock() {
            *slot = None;
        }
        let pending = queue
            .items
            .lock()
            .map(|items| {
                items
                    .iter()
                    .any(|item| item.state == QueueItemState::Queued)
            })
            .unwrap_or(false);
        if pending {
            self.spawn_queue_runner(&queue);
        }
    }

    /// `.part` download item: resumes when the recorded remote size and mtime
    /// still match, restarts otherwise, verifies the remote SHA-256 when the
    /// target offers one, and renames to the real name only when whole.
    async fn run_download_item(
        &self,
        queue: &Arc<TransferQueue>,
        id: u64,
        name: String,
        remote_path: RemotePath,
        local_dir: PathBuf,
        cancel: SftpTransferCancel,
    ) {
        let finish = |state: QueueItemState, detail: String| {
            queue_item_update(queue, id, |item| {
                item.state = state;
                item.detail = detail;
                item.cancel = None;
            });
        };
        if self.validate_binding(&queue.scope).is_err() {
            finish(QueueItemState::Failed, "连接已失效，未能下载。".to_owned());
            return;
        }
        let session = match self.bind_sftp(&queue.scope).await {
            Ok(session) => session,
            Err(_) => {
                finish(QueueItemState::Failed, "无法连接目标机。".to_owned());
                return;
            }
        };
        let metadata = match timeout(
            READ_DEADLINE,
            self.services.sftp().metadata(&session, &remote_path, false),
        )
        .await
        {
            Ok(Ok(metadata)) => metadata,
            Ok(Err(error)) => {
                finish(
                    QueueItemState::Failed,
                    format!("读取远端文件信息失败：{error}"),
                );
                return;
            }
            Err(_) => {
                finish(QueueItemState::Failed, "读取远端文件信息超时。".to_owned());
                return;
            }
        };
        if metadata.kind != SftpFileKind::File {
            finish(QueueItemState::Failed, "远端对象不是普通文件。".to_owned());
            return;
        }
        queue_item_update(queue, id, |item| {
            item.total_bytes = metadata.size;
        });
        let part = local_dir.join(format!("{name}.part"));
        let destination = local_dir.join(&name);
        let sidecar = local_dir.join(format!("{name}.part.lhmeta"));
        if destination.exists() {
            finish(
                QueueItemState::Failed,
                "本机已有同名文件，未覆盖。".to_owned(),
            );
            return;
        }
        let mut detail = String::new();
        let mut resume_from = 0_u64;
        if queue.degraded {
            if part.exists() {
                let _ = std::fs::remove_file(&part);
            }
            detail = "SCP 通道无法续传，将从头重新下载。".to_owned();
        } else if let Some(recorded) = read_part_meta(&sidecar) {
            let same_file = recorded.size == metadata.size
                && recorded.mtime_epoch == metadata.modified_at.map(|mtime| mtime.timestamp());
            let part_len = std::fs::metadata(&part).ok().map(|meta| meta.len());
            match (same_file, part_len) {
                (true, Some(len)) if len <= metadata.size => {
                    resume_from = len;
                    if len > 0 {
                        detail = format!("从 {len} 字节处续传。");
                    }
                }
                (true, _) => {
                    resume_from = 0;
                }
                (false, _) => {
                    let _ = std::fs::remove_file(&part);
                    detail = "远端文件已变化，从头重新下载。".to_owned();
                }
            }
        } else if part.exists() {
            let _ = std::fs::remove_file(&part);
        }
        write_part_meta(
            &sidecar,
            metadata.size,
            metadata.modified_at.map(|mtime| mtime.timestamp()),
        );
        queue_item_update(queue, id, |item| {
            item.part_path = Some(part.clone());
            item.done_bytes = resume_from;
        });
        let _registration =
            match self.register_transfer(&queue.scope, &queue.browser_handle, &cancel) {
                Ok(registration) => registration,
                Err(_) => {
                    finish(QueueItemState::Failed, "无法登记传输任务。".to_owned());
                    return;
                }
            };
        let rate = queue
            .rate_limit_bytes_per_second
            .load(std::sync::atomic::Ordering::Relaxed);
        let outcome = run_transfer(
            self.services.sftp().download_with_options(
                &session,
                &self.paths,
                &remote_path,
                &part,
                SftpDownloadOptions {
                    resume_from,
                    rate_limit_bytes_per_second: rate,
                    keep_partial: true,
                },
                &cancel,
            ),
            &cancel,
            TRANSFER_DEADLINE,
        )
        .await;
        let result = match outcome {
            Err(error) => {
                finish(QueueItemState::Failed, format!("下载未完成：{error}"));
                return;
            }
            Ok(Err(error)) => {
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error) {
                    finish(QueueItemState::Cancelled, "已取消。".to_owned());
                } else {
                    finish(QueueItemState::Failed, format!("下载未完成：{error}"));
                }
                return;
            }
            Ok(Ok(receipt)) => receipt,
        };
        let _ = result;
        if self.validate_binding(&queue.scope).is_err() {
            finish(
                QueueItemState::Failed,
                "连接已失效，结果未保存。".to_owned(),
            );
            return;
        }
        match self
            .services
            .sftp()
            .remote_sha256(&session, &remote_path)
            .await
        {
            Ok(Some(expected)) => match local_file_sha256(&part) {
                Ok(actual) if actual.eq_ignore_ascii_case(&expected) => {
                    if !detail.is_empty() {
                        detail.push(' ');
                    }
                    detail.push_str("已核对完整性");
                }
                Ok(_) => {
                    finish(
                        QueueItemState::Failed,
                        "完整性校验不一致，保留 .part 文件供排查。".to_owned(),
                    );
                    return;
                }
                Err(_) => {
                    finish(
                        QueueItemState::Failed,
                        "无法读取本机文件核对完整性。".to_owned(),
                    );
                    return;
                }
            },
            Ok(None) => {
                if !detail.is_empty() {
                    detail.push(' ');
                }
                detail.push_str("未核对完整性");
            }
            Err(_) => {
                if !detail.is_empty() {
                    detail.push(' ');
                }
                detail.push_str("未能核对完整性");
            }
        }
        if destination.exists() {
            finish(
                QueueItemState::Failed,
                "本机已有同名文件，未覆盖；内容留在 .part 文件中。".to_owned(),
            );
            return;
        }
        if std::fs::rename(&part, &destination).is_err() {
            finish(
                QueueItemState::Failed,
                "无法把 .part 改名为最终文件名。".to_owned(),
            );
            return;
        }
        let _ = std::fs::remove_file(&sidecar);
        queue_item_update(queue, id, |item| {
            item.part_path = None;
            item.done_bytes = item.total_bytes;
        });
        finish(QueueItemState::Done, detail);
    }

    /// Upload item: the staged file goes through the same plan → confirm →
    /// execute-and-verify path a single upload takes, with the item's own
    /// cancel switch wired to the operation's transfer switch.
    async fn run_upload_item(
        &self,
        queue: &Arc<TransferQueue>,
        id: u64,
        name: String,
        staged_path: PathBuf,
        dest_dir: RemotePath,
        cancel: SftpTransferCancel,
    ) {
        let finish = |state: QueueItemState, detail: String| {
            queue_item_update(queue, id, |item| {
                item.state = state;
                item.detail = detail;
                item.cancel = None;
            });
        };
        if self.validate_binding(&queue.scope).is_err() {
            finish(QueueItemState::Failed, "连接已失效，未能上传。".to_owned());
            return;
        }
        let session = match self.bind_sftp(&queue.scope).await {
            Ok(session) => session,
            Err(_) => {
                finish(QueueItemState::Failed, "无法连接目标机。".to_owned());
                return;
            }
        };
        let destination = match dest_dir.child(&name) {
            Ok(path) => path,
            Err(_) => {
                finish(QueueItemState::Failed, "远端目标路径无效。".to_owned());
                return;
            }
        };
        if let Ok(meta) = std::fs::metadata(&staged_path) {
            queue_item_update(queue, id, |item| {
                item.total_bytes = meta.len();
            });
        }
        let mut upload = match self.services.sftp().plan_upload(
            &session,
            &self.paths,
            &staged_path,
            destination.clone(),
        ) {
            Ok(upload) => upload,
            Err(error) => {
                finish(QueueItemState::Failed, format!("上传被拒绝：{error}"));
                return;
            }
        };
        if upload
            .confirm(DangerousConfirmation::approve(upload.definition()))
            .is_err()
        {
            finish(QueueItemState::Failed, "上传计划未能确认。".to_owned());
            return;
        }
        let op_cancel = upload.transfer_cancel();
        queue_item_update(queue, id, |item| {
            item.remote_dest = Some(destination.clone());
        });
        let _registration =
            match self.register_transfer(&queue.scope, &queue.browser_handle, &cancel) {
                Ok(registration) => registration,
                Err(_) => {
                    finish(QueueItemState::Failed, "无法登记传输任务。".to_owned());
                    return;
                }
            };
        enum UploadOutcome {
            CancelledByItem,
            Finished(Result<Result<VerificationResult, CoreError>, SftpBrowserApiError>),
        }
        let outcome = tokio::select! {
            () = cancel.cancelled() => {
                op_cancel.cancel();
                UploadOutcome::CancelledByItem
            }
            result = run_transfer(upload.execute_and_verify(), &op_cancel, TRANSFER_DEADLINE) => {
                UploadOutcome::Finished(result)
            }
        };
        match outcome {
            UploadOutcome::CancelledByItem => {
                let _ = upload.restore().await;
                finish(QueueItemState::Cancelled, "已取消。".to_owned());
            }
            UploadOutcome::Finished(Err(error)) => {
                let _ = upload.restore().await;
                finish(QueueItemState::Failed, format!("上传未完成：{error}"));
            }
            UploadOutcome::Finished(Ok(Err(error))) => {
                let _ = upload.restore().await;
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error) {
                    finish(QueueItemState::Cancelled, "已取消。".to_owned());
                } else {
                    finish(QueueItemState::Failed, format!("上传未完成：{error}"));
                }
            }
            UploadOutcome::Finished(Ok(Ok(verification))) => {
                if self.validate_binding(&queue.scope).is_err() {
                    finish(
                        QueueItemState::Failed,
                        "连接已失效，结果未保存。".to_owned(),
                    );
                    return;
                }
                if verification.passed {
                    queue_item_update(queue, id, |item| {
                        item.done_bytes = item.total_bytes;
                    });
                    finish(QueueItemState::Done, String::new());
                } else {
                    let _ = upload.restore().await;
                    finish(
                        QueueItemState::Failed,
                        format!("上传结果未能核实：{}", verification.detail),
                    );
                }
            }
        }
    }

    /// Current queue state; running items report live bytes — downloads from
    /// the `.part` file length, uploads from the remote file's growth.
    async fn queue_snapshot(
        &self,
        queue: &Arc<TransferQueue>,
    ) -> Result<SftpTransferQueueDto, SftpBrowserApiError> {
        let mut upload_stats: Vec<(u64, RemotePath)> = Vec::new();
        {
            let mut items = queue
                .items
                .lock()
                .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
            for item in items.iter_mut() {
                if item.state != QueueItemState::Running {
                    continue;
                }
                match &item.kind {
                    QueueItemKind::Download { .. } => {
                        if let Some(part) = &item.part_path
                            && let Ok(meta) = std::fs::metadata(part)
                        {
                            item.done_bytes = if item.total_bytes > 0 {
                                meta.len().min(item.total_bytes)
                            } else {
                                meta.len()
                            };
                        }
                    }
                    QueueItemKind::Upload { .. } => {
                        if let Some(dest) = &item.remote_dest {
                            upload_stats.push((item.id, dest.clone()));
                        }
                    }
                }
            }
        }
        if !upload_stats.is_empty()
            && let Ok(session) = self.bind_sftp(&queue.scope).await
        {
            for (id, path) in upload_stats {
                if let Ok(Ok(meta)) = timeout(
                    LIST_DEADLINE,
                    self.services.sftp().metadata(&session, &path, false),
                )
                .await
                {
                    queue_item_update(queue, id, |item| {
                        item.done_bytes = if item.total_bytes > 0 {
                            meta.size.min(item.total_bytes)
                        } else {
                            meta.size
                        };
                    });
                }
            }
        }
        let (active, items) = {
            let items = queue
                .items
                .lock()
                .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
            (
                items.iter().any(|item| {
                    matches!(item.state, QueueItemState::Queued | QueueItemState::Running)
                }),
                items
                    .iter()
                    .map(|item| SftpQueueItemDto {
                        item_id: item.id,
                        name: item.name.clone(),
                        state: match item.state {
                            QueueItemState::Queued => "queued",
                            QueueItemState::Running => "running",
                            QueueItemState::Done => "done",
                            QueueItemState::Failed => "failed",
                            QueueItemState::Cancelled => "cancelled",
                        }
                        .to_owned(),
                        done_bytes: item.done_bytes.to_string(),
                        total_bytes: item.total_bytes.to_string(),
                        detail: item.detail.clone(),
                    })
                    .collect(),
            )
        };
        Ok(SftpTransferQueueDto {
            active,
            degraded: queue.degraded,
            items,
        })
    }

    /// The browser must exist and belong to this scope for the relay entry
    /// point to be callable at all.
    fn require_browser(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
    ) -> Result<(), SftpBrowserApiError> {
        let mut registry = self.lock_registry()?;
        registry.prune(Instant::now());
        let live = registry
            .browsers
            .get(browser_handle)
            .is_some_and(|browser| &browser.scope == scope);
        if !live {
            return Err(SftpBrowserApiError::BrowserStale);
        }
        Ok(())
    }

    /// Other saved connections this browser's file could be relayed to. The
    /// peer is a connection record, not a live binding — only one binding
    /// ever exists — so the relay opens the peer session itself.
    pub(crate) fn relay_targets(
        &self,
        binding_handle: &str,
        browser_handle: &str,
    ) -> Result<Vec<SftpRelayTargetDto>, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        self.require_browser(&scope, browser_handle)?;
        let views = self
            .services
            .connections()
            .list()
            .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
        let mut targets = views
            .into_iter()
            .filter(|view| view.config.id != scope.connection_id)
            .map(|view| SftpRelayTargetDto {
                connection_id: view.config.id.clone(),
                label: relay_target_label(&view.config),
            })
            .collect::<Vec<_>>();
        targets.sort_by(|a, b| a.label.cmp(&b.label));
        targets.truncate(MAX_RELAY_TARGETS);
        Ok(targets)
    }

    /// Starts a single-file relay: download through this browser's binding
    /// into a managed temp file, then upload to the destination on a session
    /// the relay opens against the chosen connection. EXCLUDE semantics: an
    /// existing destination refuses before any byte moves.
    pub(crate) async fn relay_start(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        file_handle: &str,
        connection_id: &str,
        dest_dir: &str,
    ) -> Result<SftpRelayDto, SftpBrowserApiError> {
        validate_handle(file_handle)?;
        if connection_id.is_empty() || connection_id.len() > 256 {
            return Err(SftpBrowserApiError::InvalidHandle);
        }
        let dest_dir = RemotePath::new(dest_dir).map_err(|_| SftpBrowserApiError::InvalidHandle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        if connection_id == scope.connection_id {
            return Err(SftpBrowserApiError::InvalidHandle);
        }
        let node = {
            let mut registry = self.lock_registry()?;
            registry.prune(Instant::now());
            registry.queue_entry(
                &scope,
                browser_handle,
                file_handle,
                EntryAction::Preview,
                Instant::now(),
            )?
        };
        if node.kind != SftpBrowserEntryKind::File {
            return Err(SftpBrowserApiError::EntryUnavailable);
        }
        let remote_dest = dest_dir
            .child(&node.display_name)
            .map_err(|_| SftpBrowserApiError::InvalidHandle)?;
        let total_bytes = node.size_bytes.parse::<u64>().unwrap_or(0);
        let relay_handle = Uuid::new_v4().to_string();
        let relay = Arc::new(Relay {
            scope,
            browser_handle: browser_handle.to_owned(),
            cancel: SftpTransferCancel::new(),
            state: Mutex::new(RelayState {
                status: RelayStatus::Running,
                leg: None,
                done_bytes: 0,
                total_bytes,
                detail: String::new(),
            }),
            temp_path: Mutex::new(None),
            remote_dest: Mutex::new(None),
            peer: Mutex::new(None),
        });
        {
            let mut registry = self.lock_registry()?;
            registry
                .relays
                .insert(relay_handle.clone(), Arc::clone(&relay));
        }
        let api = self.cloned_for_task();
        let task_relay = Arc::clone(&relay);
        let connection_id = connection_id.to_owned();
        tokio::spawn(async move {
            api.run_relay(task_relay, node.path, connection_id, dest_dir, remote_dest)
                .await;
        });
        self.relay_snapshot(&relay_handle, &relay).await
    }

    /// Finds a relay only when the caller holds the exact binding and
    /// browser it was started under.
    fn relay_lookup(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        relay_handle: &str,
    ) -> Result<Option<Arc<Relay>>, SftpBrowserApiError> {
        let relay = {
            let registry = self.lock_registry()?;
            registry.relays.get(relay_handle).map(Arc::clone)
        };
        match relay {
            Some(relay) if relay.scope == *scope && relay.browser_handle == browser_handle => {
                Ok(Some(relay))
            }
            _ => Ok(None),
        }
    }

    /// Polls one relay; the handle answers only on the binding and browser
    /// that started it.
    pub(crate) async fn relay_poll(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        relay_handle: &str,
    ) -> Result<Option<SftpRelayDto>, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        match self.relay_lookup(&scope, browser_handle, relay_handle)? {
            Some(relay) => self.relay_snapshot(relay_handle, &relay).await.map(Some),
            None => Ok(None),
        }
    }

    /// Throws the switch on both legs of one relay.
    pub(crate) async fn relay_cancel(
        &self,
        binding_handle: &str,
        browser_handle: &str,
        relay_handle: &str,
    ) -> Result<Option<SftpRelayDto>, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        match self.relay_lookup(&scope, browser_handle, relay_handle)? {
            Some(relay) => {
                relay.cancel.cancel();
                self.relay_snapshot(relay_handle, &relay).await.map(Some)
            }
            None => Ok(None),
        }
    }

    /// Builds the public state, refreshing the progress number from wherever
    /// the active leg is writing.
    async fn relay_snapshot(
        &self,
        relay_handle: &str,
        relay: &Arc<Relay>,
    ) -> Result<SftpRelayDto, SftpBrowserApiError> {
        let (status, leg, mut done_bytes, total_bytes, detail) = {
            let state = relay
                .state
                .lock()
                .map_err(|_| SftpBrowserApiError::RegistryUnavailable)?;
            (
                state.status,
                state.leg,
                state.done_bytes,
                state.total_bytes,
                state.detail.clone(),
            )
        };
        if status == RelayStatus::Running {
            match leg {
                Some(RelayLeg::Download) => {
                    if let Ok(temp) = relay.temp_path.lock()
                        && let Some(path) = temp.as_ref()
                        && let Ok(meta) = std::fs::metadata(path)
                    {
                        done_bytes = if total_bytes > 0 {
                            meta.len().min(total_bytes)
                        } else {
                            meta.len()
                        };
                    }
                }
                Some(RelayLeg::Upload) => {
                    let peer = relay.peer.lock().ok().and_then(|peer| peer.clone());
                    let dest = relay.remote_dest.lock().ok().and_then(|dest| dest.clone());
                    if let (Some((peer_sftp, peer_session)), Some(dest)) = (peer, dest)
                        && let Ok(Ok(meta)) = timeout(
                            LIST_DEADLINE,
                            peer_sftp.metadata(&peer_session, &dest, false),
                        )
                        .await
                    {
                        done_bytes = if total_bytes > 0 {
                            meta.size.min(total_bytes)
                        } else {
                            meta.size
                        };
                    }
                }
                None => {}
            }
        }
        Ok(SftpRelayDto {
            relay_handle: relay_handle.to_owned(),
            state: match status {
                RelayStatus::Running => "running",
                RelayStatus::Done => "done",
                RelayStatus::Failed => "failed",
                RelayStatus::Cancelled => "cancelled",
            }
            .to_owned(),
            leg: match leg {
                Some(RelayLeg::Download) => "download",
                Some(RelayLeg::Upload) => "upload",
                None => "",
            }
            .to_owned(),
            done_bytes: done_bytes.to_string(),
            total_bytes: total_bytes.to_string(),
            detail,
        })
    }

    /// The relay's whole lifecycle: peer session up, directory and EXCLUDE
    /// checks, both legs, then teardown of the temp file and the peer
    /// session on every outcome.
    async fn run_relay(
        &self,
        relay: Arc<Relay>,
        source: RemotePath,
        connection_id: String,
        dest_dir: RemotePath,
        remote_dest: RemotePath,
    ) {
        let finish = |status: RelayStatus, detail: String| {
            if let Ok(mut state) = relay.state.lock() {
                state.status = status;
                state.detail = detail;
            }
        };
        if self.validate_binding(&relay.scope).is_err() {
            finish(RelayStatus::Failed, "当前连接已失效，未能发送。".to_owned());
            return;
        }
        let a_session = match self.bind_sftp(&relay.scope).await {
            Ok(session) => session,
            Err(_) => {
                finish(RelayStatus::Failed, "无法连接当前主机。".to_owned());
                return;
            }
        };
        // The peer session is opened by the relay itself. A host key the
        // operator never confirmed refuses loudly instead of silently
        // trusting on first use.
        let status_b = match self
            .services
            .ssh()
            .connect_authorized(&connection_id, SshConnectAuthorization::default())
            .await
        {
            Ok(status) => status,
            Err(CoreError::SshHostKeyConfirmationRequired { .. }) => {
                finish(
                    RelayStatus::Failed,
                    "目标主机的密钥尚未确认过：请先在主界面连接该主机一次。".to_owned(),
                );
                return;
            }
            Err(_) => {
                finish(RelayStatus::Failed, "无法连接目标主机。".to_owned());
                return;
            }
        };
        let peer_session_id = status_b.session_id.clone();
        let outcome = self
            .relay_transfer(
                &relay,
                &a_session,
                &source,
                &connection_id,
                &peer_session_id,
                &RelayDestination {
                    dir: dest_dir,
                    remote: remote_dest,
                },
            )
            .await;
        let _ = self.services.ssh().disconnect(&peer_session_id).await;
        match outcome {
            RelayOutcome::Done => finish(RelayStatus::Done, "已送达并通过完整性核对。".to_owned()),
            RelayOutcome::Failed(detail) => finish(RelayStatus::Failed, detail),
            RelayOutcome::Cancelled => finish(RelayStatus::Cancelled, "已取消。".to_owned()),
        }
    }

    async fn relay_transfer(
        &self,
        relay: &Arc<Relay>,
        a_session: &BoundSftpSession,
        source: &RemotePath,
        connection_id: &str,
        peer_session_id: &str,
        destination: &RelayDestination,
    ) -> RelayOutcome {
        // The peer guard lives in a target context nothing else shares, so
        // the active target epoch is untouched while every peer operation is
        // still epoch-validated internally.
        let peer_target = Arc::new(TargetContext::new());
        let identity = match TargetIdentity::new(connection_id.to_owned()) {
            Ok(identity) => identity,
            Err(_) => return RelayOutcome::Failed("目标身份无效。".to_owned()),
        };
        let guard = match peer_target.activate(identity) {
            Ok(guard) => guard,
            Err(_) => return RelayOutcome::Failed("无法登记目标身份。".to_owned()),
        };
        let peer_sftp = SftpService::new(
            self.services.ssh().clone(),
            peer_target,
            self.services.operation_journal().clone(),
        );
        let b_session = match peer_sftp.bind_session(guard, peer_session_id).await {
            Ok(session) => session,
            Err(_) => return RelayOutcome::Failed("无法建立目标主机的文件会话。".to_owned()),
        };
        if let Ok(mut peer) = relay.peer.lock() {
            *peer = Some((peer_sftp.clone(), b_session.clone()));
        }
        match timeout(
            LIST_DEADLINE,
            peer_sftp.metadata(&b_session, &destination.dir, false),
        )
        .await
        {
            Ok(Ok(meta)) if meta.kind == SftpFileKind::Directory => {}
            Ok(Ok(_)) => {
                return RelayOutcome::Failed("目标路径不是目录。".to_owned());
            }
            _ => {
                return RelayOutcome::Failed("目标目录不存在或无法读取。".to_owned());
            }
        }
        // EXCLUDE: anything answering metadata under the destination name
        // refuses the relay before a byte moves; the upload mutation itself
        // refuses a name that appears after this check.
        if let Ok(Ok(_)) = timeout(
            LIST_DEADLINE,
            peer_sftp.metadata(&b_session, &destination.remote, false),
        )
        .await
        {
            return RelayOutcome::Failed("目标目录已有同名文件，未覆盖。".to_owned());
        }
        let temp = self
            .paths
            .managed_upload_root()
            .join(format!("lovelyhawk-relay-{}", Uuid::new_v4().simple()));
        if let Ok(mut temp_path) = relay.temp_path.lock() {
            *temp_path = Some(temp.clone());
        }
        let _temp = RelayTempFile(temp.clone());
        if let Ok(mut state) = relay.state.lock() {
            state.leg = Some(RelayLeg::Download);
            state.done_bytes = 0;
        }
        let download = self.services.sftp().download_with_options(
            a_session,
            &self.paths,
            source,
            &temp,
            SftpDownloadOptions {
                resume_from: 0,
                rate_limit_bytes_per_second: 0,
                keep_partial: false,
            },
            &relay.cancel,
        );
        match run_transfer(download, &relay.cancel, TRANSFER_DEADLINE).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error)
                    || relay.cancel.is_cancelled()
                {
                    return RelayOutcome::Cancelled;
                }
                return RelayOutcome::Failed("下载阶段失败，未送达。".to_owned());
            }
            Err(_) => {
                if relay.cancel.is_cancelled() {
                    return RelayOutcome::Cancelled;
                }
                return RelayOutcome::Failed("下载阶段超时或已中断。".to_owned());
            }
        }
        if let Ok(mut state) = relay.state.lock() {
            state.leg = Some(RelayLeg::Upload);
            state.done_bytes = 0;
        }
        if let Ok(mut dest) = relay.remote_dest.lock() {
            *dest = Some(destination.remote.clone());
        }
        let mut upload =
            match peer_sftp.plan_upload(&b_session, &self.paths, &temp, destination.remote.clone())
            {
                Ok(upload) => upload,
                Err(_) => {
                    return RelayOutcome::Failed("目标主机拒绝了这次上传。".to_owned());
                }
            };
        if upload
            .confirm(DangerousConfirmation::approve(upload.definition()))
            .is_err()
        {
            return RelayOutcome::Failed("上传计划未能确认。".to_owned());
        }
        let op_cancel = upload.transfer_cancel();
        enum LegOutcome {
            CancelledByOperator,
            Finished(Result<Result<VerificationResult, CoreError>, SftpBrowserApiError>),
        }
        let outcome = tokio::select! {
            () = relay.cancel.cancelled() => {
                op_cancel.cancel();
                LegOutcome::CancelledByOperator
            }
            result = run_transfer(upload.execute_and_verify(), &op_cancel, TRANSFER_DEADLINE) => {
                LegOutcome::Finished(result)
            }
        };
        match outcome {
            LegOutcome::CancelledByOperator => RelayOutcome::Cancelled,
            LegOutcome::Finished(Ok(Ok(_))) => RelayOutcome::Done,
            LegOutcome::Finished(Ok(Err(error))) => {
                if lovelyhawk_core::sftp::is_transfer_cancelled(&error)
                    || relay.cancel.is_cancelled()
                {
                    RelayOutcome::Cancelled
                } else {
                    RelayOutcome::Failed("上传阶段未完成，目标文件未写入。".to_owned())
                }
            }
            LegOutcome::Finished(Err(_)) => {
                if relay.cancel.is_cancelled() {
                    RelayOutcome::Cancelled
                } else {
                    RelayOutcome::Failed("上传阶段超时或已中断。".to_owned())
                }
            }
        }
    }

    /// Drops a plan the operator decided against.
    pub(crate) fn cancel_operation(
        &self,
        binding_handle: &str,
        plan_handle: &str,
    ) -> Result<(), SftpBrowserApiError> {
        validate_handle(plan_handle)?;
        let (_, scope) = self.capture_binding(binding_handle)?;
        let mut registry = self.lock_registry()?;
        registry.drop_plan(&scope, plan_handle);
        Ok(())
    }

    /// Copies a local file the operator picked into the core-managed staging
    /// area, so an upload plan can only ever name a staged file.
    pub(crate) fn stage_upload(
        &self,
        binding_handle: &str,
        local_path: &Path,
        name: &str,
    ) -> Result<SftpStagedUploadDto, SftpBrowserApiError> {
        let (_, scope) = self.capture_binding(binding_handle)?;
        let display_name = validated_entry_name(name)?;
        let metadata =
            std::fs::metadata(local_path).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        if !metadata.is_file() || metadata.len() > MAX_STAGED_UPLOAD_BYTES {
            return Err(SftpBrowserApiError::Capacity);
        }
        let bytes = std::fs::read(local_path).map_err(|_| SftpBrowserApiError::InvalidListing)?;
        let staged = self
            .paths
            .stage_upload(&bytes)
            .map_err(|_| SftpBrowserApiError::Capacity)?;
        let staged_handle = Uuid::new_v4().to_string();
        let now = Instant::now();
        let mut registry = self.lock_registry()?;
        registry.prune(now);
        registry.store_staged(
            staged_handle.clone(),
            StagedUpload {
                binding_handle: scope.binding_handle.clone(),
                path: staged,
                expires_at: now + PLAN_TTL,
            },
        )?;
        Ok(SftpStagedUploadDto {
            staged_handle,
            name: display_name,
            bytes: metadata.len().to_string(),
        })
    }

    /// Turns capabilities into the one mutation the core will accept.
    fn build_mutation(
        &self,
        scope: &BindingScope,
        browser_handle: &str,
        request: &SftpOperationRequest,
    ) -> Result<(Uuid, PlannedMutation), SftpBrowserApiError> {
        let registry = self.lock_registry()?;
        let browser = registry
            .browsers
            .get(browser_handle)
            .filter(|browser| &browser.scope == scope && browser.expires_at > Instant::now())
            .ok_or(SftpBrowserApiError::BrowserStale)?;
        let node = |handle: &str| -> Result<StoredNode, SftpBrowserApiError> {
            browser
                .nodes
                .get(handle)
                .cloned()
                .ok_or(SftpBrowserApiError::EntryUnavailable)
        };
        let mutation = match request {
            SftpOperationRequest::CreateDirectory {
                directory_handle,
                name,
            } => {
                let parent = node(directory_handle)?;
                if parent.kind != SftpBrowserEntryKind::Directory {
                    return Err(SftpBrowserApiError::EntryUnavailable);
                }
                PlannedMutation::Remote(SftpMutation::CreateDirectory {
                    path: child_path(&parent.path, name)?,
                })
            }
            SftpOperationRequest::Rename { entry_handle, name } => {
                let entry = node(entry_handle)?;
                let parent = entry
                    .path
                    .parent()
                    .map_err(|_| SftpBrowserApiError::EntryUnavailable)?;
                PlannedMutation::Remote(SftpMutation::Rename {
                    from: entry.path.clone(),
                    to: child_path(&parent, name)?,
                })
            }
            SftpOperationRequest::Chmod { entry_handle, mode } => {
                if *mode > 0o7777 {
                    return Err(SftpBrowserApiError::InvalidHandle);
                }
                PlannedMutation::Remote(SftpMutation::Chmod {
                    path: node(entry_handle)?.path,
                    mode: *mode,
                })
            }
            SftpOperationRequest::Remove { entry_handle } => {
                PlannedMutation::Remote(SftpMutation::Remove {
                    path: node(entry_handle)?.path,
                })
            }
            SftpOperationRequest::WriteText {
                entry_handle,
                text,
                expected_sha256,
            } => {
                // Same ceiling the read side uses. A file too large to have
                // been read whole is a file that must not be written back.
                if text.len() > MAX_CORE_TEXT_BYTES {
                    return Err(SftpBrowserApiError::InvalidHandle);
                }
                if expected_sha256.len() != 64
                    || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(SftpBrowserApiError::InvalidHandle);
                }
                let target = node(entry_handle)?;
                PlannedMutation::Remote(SftpMutation::AtomicWriteIfMatch {
                    // Canonical path checked as well as the hash: a symlink
                    // swapped under the editor would otherwise land the write
                    // somewhere the operator never opened.
                    expected_canonical_path: Some(target.path.clone()),
                    backup_directory: target.path.parent().ok(),
                    path: target.path,
                    expected_sha256: expected_sha256.to_ascii_lowercase(),
                    content: text.clone().into_bytes(),
                })
            }
            SftpOperationRequest::Archive {
                entry_handles,
                name,
                format,
            } => {
                if entry_handles.is_empty() || entry_handles.len() > MAX_ARCHIVE_SOURCES {
                    return Err(SftpBrowserApiError::InvalidHandle);
                }
                let mut sources = Vec::with_capacity(entry_handles.len());
                for handle in entry_handles {
                    sources.push(node(handle)?.path);
                }
                let parent = sources[0]
                    .parent()
                    .map_err(|_| SftpBrowserApiError::EntryUnavailable)?;
                PlannedMutation::Remote(SftpMutation::CreateArchive {
                    destination: child_path(&parent, name)?,
                    sources,
                    format: archive_format(format)?,
                })
            }
            SftpOperationRequest::Upload {
                directory_handle,
                staged_handle,
                name,
            } => {
                let parent = node(directory_handle)?;
                if parent.kind != SftpBrowserEntryKind::Directory {
                    return Err(SftpBrowserApiError::EntryUnavailable);
                }
                let staged = registry
                    .staged
                    .get(staged_handle)
                    .filter(|staged| staged.binding_handle == scope.binding_handle)
                    .filter(|staged| staged.expires_at > Instant::now())
                    .ok_or(SftpBrowserApiError::EntryUnavailable)?;
                PlannedMutation::Upload {
                    staged_path: staged.path.clone(),
                    destination: child_path(&parent.path, name)?,
                }
            }
        };
        Ok((browser.token, mutation))
    }
}

enum PlannedMutation {
    Remote(SftpMutation),
    Upload {
        staged_path: PathBuf,
        destination: RemotePath,
    },
}

fn plan_dto(
    entry: &PlannedEntry,
    now: Instant,
) -> Result<SftpOperationPlanDto, SftpBrowserApiError> {
    let definition = entry.operation.definition();
    let remaining = entry.expires_at.saturating_duration_since(now).as_secs();
    Ok(SftpOperationPlanDto {
        plan_handle: entry.plan_handle.clone(),
        browser_handle: entry.browser_handle.clone(),
        kind: entry.kind.clone(),
        summary: bounded_detail(&definition.summary),
        dangerous: definition.dangerous,
        restore_description: definition
            .restore_description
            .as_deref()
            .map(bounded_detail),
        state: match entry.operation.state() {
            OperationState::Planned => "planned".to_owned(),
            OperationState::Confirmed => "confirmed".to_owned(),
            _ => "spent".to_owned(),
        },
        expires_in_seconds: u32::try_from(remaining.max(1))
            .map_err(|_| SftpBrowserApiError::InvalidListing)?,
    })
}

/// Plan text is written by the core, but it still crosses a boundary: keep it
/// one line and bounded so it can be drawn in a dialog.
fn bounded_detail(value: &str) -> String {
    let (text, _) = normalize_plain_text(value, MAX_PLAN_TEXT_BYTES);
    text
}

fn child_path(parent: &RemotePath, name: &str) -> Result<RemotePath, SftpBrowserApiError> {
    let name = validated_entry_name(name)?;
    parent
        .child(&name)
        .map_err(|_| SftpBrowserApiError::InvalidHandle)
}

fn validated_entry_name(value: &str) -> Result<String, SftpBrowserApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_ENTRY_NAME_INPUT
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(|character| character.is_control())
    {
        return Err(SftpBrowserApiError::InvalidHandle);
    }
    Ok(trimmed.to_owned())
}

fn archive_format(value: &str) -> Result<ArchiveFormat, SftpBrowserApiError> {
    match value {
        "tar" => Ok(ArchiveFormat::Tar),
        "tar-gzip" => Ok(ArchiveFormat::TarGzip),
        "tar-zstd" => Ok(ArchiveFormat::TarZstd),
        _ => Err(SftpBrowserApiError::InvalidHandle),
    }
}

#[cfg(test)]
mod tests {
    use lovelyhawk_core::{
        sftp::SftpMetadata,
        target::{TargetContext, TargetIdentity},
    };

    use super::*;

    fn scope(binding: &str, identity: &str, generation: usize) -> BindingScope {
        let target = TargetContext::new();
        let mut guard = target
            .activate(TargetIdentity::new(identity).unwrap())
            .unwrap();
        for _ in 0..generation {
            guard = target
                .activate(TargetIdentity::new(identity).unwrap())
                .unwrap();
        }
        BindingScope {
            binding_handle: binding.to_owned(),
            session_id: format!("session-{identity}"),
            connection_id: identity.to_owned(),
            target: guard,
        }
    }

    fn entry(parent: &str, name: &str, kind: SftpFileKind) -> SftpEntry {
        let parent = RemotePath::new(parent).unwrap();
        SftpEntry {
            name: name.to_owned(),
            path: parent.child(name).unwrap(),
            metadata: SftpMetadata {
                size: 42,
                permissions: Some(0o640),
                uid: Some(1000),
                gid: Some(1000),
                modified_at: None,
                kind,
            },
        }
    }

    #[test]
    fn root_listing_maps_paths_and_entry_types_to_opaque_capabilities() {
        let private_scope = scope("binding-private", "target-private", 0);
        let (browser, dto) = BrowserSnapshot::from_root(
            private_scope,
            vec![
                entry("/", "etc", SftpFileKind::Directory),
                entry("/", "evidence.txt", SftpFileKind::File),
                entry("/", "latest", SftpFileKind::Symlink),
                entry("/", "socket", SftpFileKind::Other),
            ],
            Instant::now(),
        )
        .unwrap();
        assert_eq!(dto.directory_label, ROOT_LABEL);
        assert!(dto.parent_directory_handle.is_none());
        assert_eq!(dto.displayed_entry_count, 4);
        assert_eq!(dto.observed_entry_count, 4);
        assert!(!dto.truncated);
        assert_eq!(browser.nodes.len(), 5);
        assert!(dto.entries.iter().any(|entry| {
            entry.name == "etc" && entry.action == SftpBrowserEntryAction::Browse
        }));
        assert!(dto.entries.iter().any(|entry| {
            entry.name == "evidence.txt" && entry.action == SftpBrowserEntryAction::Preview
        }));
        assert!(
            dto.entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.kind,
                        SftpBrowserEntryKind::Symlink | SftpBrowserEntryKind::Other
                    )
                })
                .all(|entry| entry.action == SftpBrowserEntryAction::None)
        );
        let encoded = serde_json::to_string(&dto).unwrap();
        for forbidden in [
            "binding-private",
            "target-private",
            "session-target-private",
            "remotePath",
            "sessionId",
            "connectionId",
            "fingerprint",
            "permissions",
            "uid",
            "gid",
            "\"/etc\"",
        ] {
            assert!(!encoded.contains(forbidden), "encoded {forbidden}");
        }
        assert!(encoded.len() <= MAX_DIRECTORY_RESPONSE_BYTES);
    }

    #[test]
    fn listing_keeps_the_browser_open_but_one_left_alone_still_closes() {
        let opened = Instant::now();
        let owner = scope("binding-one", "target-one", 0);
        let listing = || vec![entry("/", "etc", SftpFileKind::Directory)];
        let (mut browser, dto) =
            BrowserSnapshot::from_root(owner.clone(), listing(), opened).unwrap();
        assert_eq!(dto.expires_in_seconds, BROWSER_TTL.as_secs());
        let root = browser.root_handle.clone();
        let handle = browser.browser_handle.clone();

        // Four minutes in, listing again starts the five minutes over.
        let relisted_at = opened + Duration::from_secs(240);
        let relisted = browser
            .refresh_directory(&root, listing(), relisted_at)
            .unwrap();
        assert_eq!(relisted.expires_in_seconds, BROWSER_TTL.as_secs());

        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();
        // Past five minutes from opening, a browser in use is still there…
        assert!(
            registry
                .directory_for_terminal(&owner, &handle, &root, opened + BROWSER_TTL)
                .is_ok()
        );
        // …and five minutes after the last listing it has closed.
        assert!(matches!(
            registry.directory_for_terminal(&owner, &handle, &root, relisted_at + BROWSER_TTL),
            Err(SftpBrowserApiError::BrowserStale)
        ));
    }

    #[test]
    fn a_terminal_starts_only_in_a_listed_directory_of_the_same_target() {
        let now = Instant::now();
        let owner = scope("binding-one", "target-one", 0);
        let (browser, dto) = BrowserSnapshot::from_root(
            owner.clone(),
            vec![
                entry("/", "it's a dir; touch PWNED", SftpFileKind::Directory),
                entry("/", "notes.txt", SftpFileKind::File),
                entry("/", "link", SftpFileKind::Symlink),
            ],
            now,
        )
        .unwrap();
        let browser_handle = browser.browser_handle.clone();
        let root = browser.root_handle.clone();
        let handle_of = |name: &str| {
            dto.entries
                .iter()
                .find(|entry| entry.name == name)
                .unwrap()
                .entry_handle
                .clone()
        };
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();

        let path = registry
            .directory_for_terminal(
                &owner,
                &browser_handle,
                &handle_of("it's a dir; touch PWNED"),
                now,
            )
            .unwrap();
        // Handed on as a path, for core to quote, never as shell text.
        assert_eq!(path.as_str(), "/it's a dir; touch PWNED");
        let root_path = registry
            .directory_for_terminal(&owner, &browser_handle, &root, now)
            .unwrap();
        assert_eq!(root_path.as_str(), "/");

        for refused in [
            handle_of("notes.txt"),
            handle_of("link"),
            "unknown".to_owned(),
        ] {
            assert!(matches!(
                registry.directory_for_terminal(&owner, &browser_handle, &refused, now),
                Err(SftpBrowserApiError::EntryUnavailable)
            ));
        }
        let other_target = scope("binding-one", "target-two", 0);
        assert!(matches!(
            registry.directory_for_terminal(&other_target, &browser_handle, &root, now),
            Err(SftpBrowserApiError::BrowserStale)
        ));
        let reconnected = scope("binding-one", "target-one", 1);
        assert!(matches!(
            registry.directory_for_terminal(&reconnected, &browser_handle, &root, now),
            Err(SftpBrowserApiError::BrowserStale)
        ));
        assert!(matches!(
            registry.directory_for_terminal(&owner, &browser_handle, &root, now + BROWSER_TTL),
            Err(SftpBrowserApiError::BrowserStale)
        ));
    }

    #[test]
    fn a_fetch_resolves_only_listed_files_and_directories_of_the_same_target() {
        let now = Instant::now();
        let owner = scope("binding-one", "target-one", 0);
        let (browser, dto) = BrowserSnapshot::from_root(
            owner.clone(),
            vec![
                entry("/", "etc", SftpFileKind::Directory),
                entry("/", "notes.txt", SftpFileKind::File),
                entry("/", "link", SftpFileKind::Symlink),
                entry("/", "fifo", SftpFileKind::Other),
            ],
            now,
        )
        .unwrap();
        let browser_handle = browser.browser_handle.clone();
        let root = browser.root_handle.clone();
        let handle_of = |name: &str| {
            dto.entries
                .iter()
                .find(|entry| entry.name == name)
                .unwrap()
                .entry_handle
                .clone()
        };
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();

        // A directory offered to open and a regular file offered to preview
        // both qualify, as does the browser's current directory itself.
        assert_eq!(
            registry
                .path_for_fetch(&owner, &browser_handle, &handle_of("etc"), now)
                .unwrap()
                .as_str(),
            "/etc"
        );
        assert_eq!(
            registry
                .path_for_fetch(&owner, &browser_handle, &handle_of("notes.txt"), now)
                .unwrap()
                .as_str(),
            "/notes.txt"
        );
        assert_eq!(
            registry
                .path_for_fetch(&owner, &browser_handle, &root, now)
                .unwrap()
                .as_str(),
            "/"
        );
        // Anything that cannot be packed is refused here, not on the target.
        for refused in [handle_of("link"), handle_of("fifo"), "unknown".to_owned()] {
            assert!(matches!(
                registry.path_for_fetch(&owner, &browser_handle, &refused, now),
                Err(SftpBrowserApiError::EntryUnavailable)
            ));
        }
        // Another target's scope, another session of the same binding, and an
        // expired browser all resolve to nothing.
        let other_target = scope("binding-one", "target-two", 0);
        assert!(matches!(
            registry.path_for_fetch(&other_target, &browser_handle, &root, now),
            Err(SftpBrowserApiError::BrowserStale)
        ));
        let reconnected = scope("binding-one", "target-one", 1);
        assert!(matches!(
            registry.path_for_fetch(&reconnected, &browser_handle, &root, now),
            Err(SftpBrowserApiError::BrowserStale)
        ));
        assert!(matches!(
            registry.path_for_fetch(&owner, &browser_handle, &root, now + BROWSER_TTL),
            Err(SftpBrowserApiError::BrowserStale)
        ));
    }

    #[test]
    fn registry_scopes_handles_rotates_on_open_and_rejects_symlink_actions() {
        let now = Instant::now();
        let original_scope = scope("binding-one", "target-one", 0);
        let (first, first_dto) = BrowserSnapshot::from_root(
            original_scope.clone(),
            vec![
                entry("/", "dir", SftpFileKind::Directory),
                entry("/", "link", SftpFileKind::Symlink),
            ],
            now,
        )
        .unwrap();
        let first_handle = first.browser_handle.clone();
        let directory = first_dto
            .entries
            .iter()
            .find(|entry| entry.name == "dir")
            .unwrap()
            .entry_handle
            .clone();
        let symlink = first_dto
            .entries
            .iter()
            .find(|entry| entry.name == "link")
            .unwrap()
            .entry_handle
            .clone();
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(first).unwrap();
        let access = registry
            .begin_operation(
                &original_scope,
                &first_handle,
                &directory,
                EntryAction::Browse,
                now,
            )
            .unwrap();
        assert!(matches!(
            registry.begin_operation(
                &original_scope,
                &first_handle,
                &directory,
                EntryAction::Browse,
                now,
            ),
            Err(SftpBrowserApiError::Busy)
        ));
        registry.finish_operation(access.operation_token);
        assert!(matches!(
            registry.begin_operation(
                &original_scope,
                &first_handle,
                &symlink,
                EntryAction::Browse,
                now,
            ),
            Err(SftpBrowserApiError::EntryUnavailable)
        ));

        let changed_generation = scope("binding-one", "target-one", 1);
        assert!(matches!(
            registry.begin_operation(
                &changed_generation,
                &first_handle,
                &directory,
                EntryAction::Browse,
                now,
            ),
            Err(SftpBrowserApiError::BrowserStale)
        ));
        let (replacement, _) =
            BrowserSnapshot::from_root(original_scope, Vec::new(), now + Duration::from_millis(1))
                .unwrap();
        let replacement_handle = replacement.browser_handle.clone();
        registry.replace(replacement).unwrap();
        assert!(!registry.browsers.contains_key(&first_handle));
        assert!(registry.browsers.contains_key(&replacement_handle));
    }

    #[test]
    fn directory_refresh_preserves_matching_handles_and_computes_parent_in_registry() {
        let now = Instant::now();
        let private_scope = scope("binding-one", "target-one", 0);
        let (browser, root_dto) = BrowserSnapshot::from_root(
            private_scope.clone(),
            vec![entry("/", "etc", SftpFileKind::Directory)],
            now,
        )
        .unwrap();
        let browser_handle = browser.browser_handle.clone();
        let directory_handle = root_dto.entries[0].entry_handle.clone();
        let root_handle = root_dto.directory_handle.clone();
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();
        let access = registry
            .begin_operation(
                &private_scope,
                &browser_handle,
                &directory_handle,
                EntryAction::Browse,
                now,
            )
            .unwrap();
        let receipt = registry
            .apply_listing(
                &access,
                vec![entry("/etc", "config", SftpFileKind::File)],
                false,
                now + Duration::from_millis(1),
            )
            .unwrap();
        assert_eq!(receipt.dto.parent_directory_handle, Some(root_handle));
        assert_eq!(receipt.dto.directory_label, "etc");
        let file_handle = receipt.dto.entries[0].entry_handle.clone();
        registry.finish_operation(access.operation_token);

        let access = registry
            .begin_operation(
                &private_scope,
                &browser_handle,
                &directory_handle,
                EntryAction::Browse,
                now + Duration::from_millis(2),
            )
            .unwrap();
        let refreshed = registry
            .apply_listing(
                &access,
                vec![entry("/etc", "config", SftpFileKind::File)],
                false,
                now + Duration::from_millis(3),
            )
            .unwrap();
        assert_eq!(refreshed.dto.entries[0].entry_handle, file_handle);
        registry.finish_operation(access.operation_token);
    }

    #[test]
    fn listing_and_registry_are_entry_ttl_memory_and_capacity_bounded() {
        let now = Instant::now();
        let entries = (0..MAX_DISPLAYED_ENTRIES + 20)
            .map(|index| entry("/", &format!("item-{index:03}"), SftpFileKind::File))
            .collect();
        let (mut browser, dto) =
            BrowserSnapshot::from_root(scope("binding", "target", 0), entries, now).unwrap();
        assert_eq!(dto.displayed_entry_count, MAX_DISPLAYED_ENTRIES as u32);
        assert_eq!(
            dto.observed_entry_count,
            (MAX_DISPLAYED_ENTRIES + 20) as u32
        );
        assert!(dto.truncated);
        assert!(browser.stored_bytes <= MAX_BROWSER_BYTES);
        assert!(browser.nodes.len() <= MAX_NAVIGATION_DEPTH + 1 + MAX_DISPLAYED_ENTRIES);
        browser.expires_at = now;
        let mut registry = SftpBrowserRegistry::default();
        registry.replace(browser).unwrap();
        registry.prune(now);
        assert!(registry.browsers.is_empty());

        for index in 0..MAX_BROWSERS + 1 {
            let (browser, _) = BrowserSnapshot::from_root(
                scope(&format!("binding-{index}"), &format!("target-{index}"), 0),
                Vec::new(),
                now + Duration::from_millis(index as u64),
            )
            .unwrap();
            registry.replace(browser).unwrap();
        }
        assert_eq!(registry.browsers.len(), MAX_BROWSERS);
        assert!(registry.total_bytes() <= MAX_REGISTRY_BYTES);
    }

    #[test]
    fn opening_a_terminal_browser_preserves_inventory_editors_and_bounds_them() {
        let now = Instant::now();
        let private_scope = scope("binding", "target", 0);
        let mut registry = SftpBrowserRegistry::default();
        let mut first = None;
        for index in 0..=MAX_EDITOR_BROWSERS {
            let (mut browser, dto) = BrowserSnapshot::from_directory(
                private_scope.clone(),
                RemotePath::new("/root").unwrap(),
                vec![entry("/root", &format!("file-{index}"), SftpFileKind::File)],
                now,
            )
            .unwrap();
            browser.editor_only = true;
            if index == MAX_EDITOR_BROWSERS {
                assert!(matches!(
                    registry.replace(browser),
                    Err(SftpBrowserApiError::Capacity)
                ));
            } else {
                registry.replace(browser).unwrap();
                if first.is_none() {
                    first = Some(dto);
                }
            }
        }
        for _ in 0..2 {
            let (browser, _) =
                BrowserSnapshot::from_root(private_scope.clone(), Vec::new(), now).unwrap();
            registry.replace(browser).unwrap();
        }
        assert_eq!(registry.browsers.len(), MAX_EDITOR_BROWSERS + 1);
        let first = first.unwrap();
        let access = registry
            .begin_operation(
                &private_scope,
                &first.browser_handle,
                &first.entries[0].entry_handle,
                EntryAction::Preview,
                now,
            )
            .unwrap();
        assert_eq!(access.node.path.as_str(), "/root/file-0");
        registry.finish_operation(access.operation_token);
        assert!(
            registry
                .begin_operation(
                    &scope("other", "target", 0),
                    &first.browser_handle,
                    &first.entries[0].entry_handle,
                    EntryAction::Preview,
                    now
                )
                .is_err()
        );
    }

    #[test]
    fn hostile_names_are_plain_bounded_and_credential_like_names_are_redacted() {
        let long_name = format!("{}{}", "界".repeat(100), "tail");
        let (_, dto) = BrowserSnapshot::from_root(
            scope("binding", "target", 0),
            vec![
                entry(
                    "/",
                    "<script>steal()<img src=x onerror=steal()>",
                    SftpFileKind::File,
                ),
                entry("/", "password=do-not-render", SftpFileKind::File),
                entry("/", &long_name, SftpFileKind::File),
            ],
            Instant::now(),
        )
        .unwrap();
        assert!(
            dto.entries
                .iter()
                .any(|entry| entry.name.contains("<script>"))
        );
        // A name that merely looks credential-shaped is still the operator's
        // evidence, so it crosses as written.
        assert!(
            serde_json::to_string(&dto)
                .unwrap()
                .contains("do-not-render")
        );
        let truncated = dto
            .entries
            .iter()
            .find(|entry| entry.name_truncated)
            .unwrap();
        assert!(truncated.name.len() <= MAX_ENTRY_NAME_BYTES);
    }

    #[test]
    fn text_preview_crosses_verbatim_within_line_byte_and_control_bounds() {
        let hostile = [
            "</pre><script>steal()</script><img src=x onerror=steal()>",
            "password=keep-this-visible",
            "root:$6$salt$hash:19000:0:99999:7:::",
            "plain\u{0007}control",
            &"x".repeat(MAX_TEXT_LINE_BYTES + 20),
        ]
        .join("\n");
        let projected = project_text(&hostile).unwrap();
        // Markup stays inert text; the rest is what the file actually holds.
        assert!(projected.text.contains("</pre><script>steal()</script>"));
        assert!(projected.text.contains("password=keep-this-visible"));
        assert!(projected.text.contains("root:$6$salt$hash"));
        // Only control characters are normalised, because they break rendering.
        assert!(projected.text.contains("plain\u{fffd}control"));
        assert!(projected.truncated);
        assert!(projected.displayed_line_count <= MAX_TEXT_LINES as u32);
        assert!(projected.text.len() <= MAX_TEXT_BYTES);
        assert!(
            projected
                .text
                .lines()
                .all(|line| line.len() <= MAX_TEXT_LINE_BYTES)
        );
    }

    #[test]
    fn text_preview_many_lines_and_serialized_escaping_stay_bounded() {
        let source = (0..MAX_TEXT_LINES + 200)
            .map(|index| format!("<line-{index}>\\\""))
            .collect::<Vec<_>>()
            .join("\n");
        let projected = project_text(&source).unwrap();
        assert_eq!(projected.displayed_line_count, MAX_TEXT_LINES as u32);
        assert!(projected.truncated);
        let dto = SftpTextPreviewDto {
            browser_handle: "opaque-browser".to_owned(),
            file_handle: "opaque-file".to_owned(),
            text: projected.text,
            observed_line_count: projected.observed_line_count,
            displayed_line_count: projected.displayed_line_count,
            truncated: projected.truncated,
            sha256: hex_digest(source.as_bytes()),
            exact: projected.exact,
        };
        ensure_serialized_bound(&dto, MAX_TEXT_RESPONSE_BYTES).unwrap();
    }

    /// What comes back is the file, or it is marked as not the file.
    ///
    /// The projection splits on lines and rejoins with `\n`. That was fine
    /// while it fed a preview and became a data-loss bug the moment it fed an
    /// editor: a file ending in a newline read back without one, so opening it
    /// and saving without typing anything would have removed the newline, and
    /// a CRLF file would have been converted to LF. `exact` is what the editor
    /// checks before it offers to save at all.
    #[test]
    fn the_projection_is_either_the_file_or_says_it_is_not() {
        for faithful in [
            "one\ntwo\nthree\n",
            "one\ntwo\nthree",
            "",
            "\n",
            "single line",
            "trailing blank\n\n",
        ] {
            let projected = project_text(faithful).unwrap();
            assert!(projected.exact, "{faithful:?} should round-trip");
            assert_eq!(projected.text, faithful, "{faithful:?} came back changed");
        }

        // CRLF: Rust's `lines()` eats the carriage return, so the text is a
        // different file. It is still shown — it is just not writable.
        let crlf = project_text("one\r\ntwo\r\n").unwrap();
        assert!(!crlf.exact);
        assert_eq!(crlf.text, "one\ntwo\n");

        // A control character the projection strips is the same story.
        let control = project_text("before\u{0}after\n").unwrap();
        assert!(!control.exact);

        // And a file too long to have been read whole is never exact, because
        // what came back is missing its tail.
        let long = (0..MAX_TEXT_LINES + 5)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let truncated = project_text(&long).unwrap();
        assert!(truncated.truncated);
        assert!(!truncated.exact);
    }

    /// The hash is of the whole file, never of the text that was handed back.
    ///
    /// It authorises a write, so hashing the projection would let a truncated
    /// read authorise replacing a complete file with the part that fitted.
    #[test]
    fn the_read_hash_covers_the_whole_file_not_the_projection() {
        let source = (0..MAX_TEXT_LINES + 50)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let projected = project_text(&source).unwrap();
        assert!(projected.truncated);
        assert_ne!(projected.text, source);
        assert_eq!(hex_digest(source.as_bytes()).len(), 64);
        assert_ne!(
            hex_digest(source.as_bytes()),
            hex_digest(projected.text.as_bytes()),
        );
        // Lowercase hex, which is what the core's compare-and-write expects.
        assert!(
            hex_digest(source.as_bytes())
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn duplicate_paths_invalid_handles_and_public_errors_fail_closed() {
        let duplicate = entry("/", "same", SftpFileKind::File);
        assert!(
            BrowserSnapshot::from_root(
                scope("binding", "target", 0),
                vec![duplicate.clone(), duplicate],
                Instant::now(),
            )
            .is_err()
        );
        for invalid in [
            "",
            "space value",
            "slash/value",
            "control\n",
            &"x".repeat(129),
        ] {
            assert!(validate_handle(invalid).is_err());
        }
        assert!(validate_handle("opaque-123-ABC").is_ok());
        let error = SftpBrowserApiError::Core;
        assert_eq!(error.to_string(), "the SFTP browser operation failed");
        assert!(!format!("{error:?}").contains("secret"));
    }

    /// Names come from the operator, so they are the one free-form input the
    /// pipeline accepts. Anything that could escape a directory is refused
    /// before the core builds a path from it.
    #[test]
    fn entry_names_refuse_traversal_separators_and_control_characters() {
        for accepted in ["report.txt", "归档 2026", "a-b_c.tar.gz", " spaced "] {
            assert!(validated_entry_name(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "",
            "   ",
            ".",
            "..",
            "a/b",
            "a\\b",
            "tab\tname",
            &"x".repeat(MAX_ENTRY_NAME_INPUT + 1),
        ] {
            assert!(validated_entry_name(refused).is_err(), "{refused:?}");
        }
        assert_eq!(validated_entry_name(" spaced ").unwrap(), "spaced");
    }

    #[test]
    fn archive_formats_are_a_closed_set() {
        assert!(archive_format("tar").is_ok());
        assert!(archive_format("tar-gzip").is_ok());
        assert!(archive_format("tar-zstd").is_ok());
        for refused in ["zip", "", "tar; rm -rf /", "TAR"] {
            assert!(archive_format(refused).is_err(), "{refused}");
        }
    }

    /// Queue downloads write `<name>.part` on the host; a remote name can be
    /// anything the server sent, so it is sanitized to a plain local name —
    /// separators, control characters and Windows-reserved forms never reach
    /// the filesystem.
    #[test]
    fn queue_local_names_are_sanitized() {
        assert_eq!(sanitize_local_name("report.tar").unwrap(), "report.tar");
        assert_eq!(sanitize_local_name("a/b\\c:d").unwrap(), "a_b_c_d");
        assert_eq!(sanitize_local_name("name\tevil").unwrap(), "name_evil");
        assert_eq!(sanitize_local_name("trail.").unwrap(), "trail");
        for refused in ["", "   ", ".", "..", "...", "CON", "nul", "LPT3"] {
            assert!(sanitize_local_name(refused).is_err(), "{refused:?}");
        }
    }

    /// The `.part` sidecar is the only thing a retry trusts: it round-trips
    /// size and mtime and unreadable content counts as "no resume data".
    #[test]
    fn part_meta_round_trips_and_rejects_garbage() {
        let directory =
            std::env::temp_dir().join(format!("lh-part-meta-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&directory).unwrap();
        let sidecar = directory.join("f.part.lhmeta");
        assert!(read_part_meta(&sidecar).is_none());
        write_part_meta(&sidecar, 42, Some(1_700_000_000));
        let meta = read_part_meta(&sidecar).expect("written sidecar parses");
        assert_eq!(meta.size, 42);
        assert_eq!(meta.mtime_epoch, Some(1_700_000_000));
        write_part_meta(&sidecar, 7, None);
        let meta = read_part_meta(&sidecar).expect("rewritten sidecar parses");
        assert_eq!(meta.mtime_epoch, None);
        std::fs::write(&sidecar, b"not json").unwrap();
        assert!(read_part_meta(&sidecar).is_none());
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Cancel-all flips queued items to cancelled and throws the switch of
    /// running ones; finished items are left alone.
    #[test]
    fn queue_cancel_all_marks_pending_items() {
        let make = |id, state| QueueItem {
            id,
            name: "n".to_owned(),
            kind: QueueItemKind::Download {
                remote_path: RemotePath::new("/f").unwrap(),
                local_dir: PathBuf::from("/tmp"),
            },
            state,
            done_bytes: 0,
            total_bytes: 0,
            detail: String::new(),
            cancel: None,
            part_path: None,
            remote_dest: None,
        };
        let running_cancel = SftpTransferCancel::new();
        let items = Mutex::new(vec![
            make(1, QueueItemState::Queued),
            {
                let mut running = make(2, QueueItemState::Running);
                running.cancel = Some(running_cancel.clone());
                running
            },
            make(3, QueueItemState::Done),
        ]);
        assert_eq!(cancel_queue_items(&items), 2);
        assert!(running_cancel.is_cancelled());
        let items = items.lock().unwrap();
        assert!(matches!(items[0].state, QueueItemState::Cancelled));
        assert!(matches!(items[1].state, QueueItemState::Running));
        assert!(matches!(items[2].state, QueueItemState::Done));
    }

    /// The download result crosses as exact camelCase fields with the
    /// preflight counts always present so a refusal can show its numbers.
    #[test]
    fn directory_download_dto_serializes_exact_fields() {
        let dto = SftpDirectoryDownloadDto {
            browser_handle: "opaque-browser".to_owned(),
            state: "refused-over-cap".to_owned(),
            file_count: "21000".to_owned(),
            total_bytes: "0".to_owned(),
            archive_bytes: None,
            extracted_entries: None,
            detail: "目录超出打包上限".to_owned(),
        };
        let value = serde_json::to_value(&dto).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 7);
        for key in [
            "browserHandle",
            "state",
            "fileCount",
            "totalBytes",
            "archiveBytes",
            "extractedEntries",
            "detail",
        ] {
            assert!(object.contains_key(key), "{key}");
        }
        assert_eq!(value["state"], "refused-over-cap");
        assert!(value["archiveBytes"].is_null());
        // No local or remote path ever crosses on the receipt.
        let encoded = serde_json::to_string(&dto).unwrap();
        for forbidden in ["localPath", "remotePath", "extractTo", "path"] {
            assert!(!encoded.contains(forbidden), "{forbidden}");
        }
    }

    /// The upload receipt crosses as exact camelCase fields; the undo handle
    /// only exists while the upload is still undoable, and no local or remote
    /// path ever crosses on it.
    #[test]
    fn directory_upload_dto_serializes_exact_fields() {
        let dto = SftpDirectoryUploadDto {
            browser_handle: "opaque-browser".to_owned(),
            state: "done".to_owned(),
            detail: "目录已上传并在目标机解包核对完成。".to_owned(),
            plan_handle: Some(Uuid::new_v4().to_string()),
            undoable: true,
        };
        let value = serde_json::to_value(&dto).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 5);
        for key in ["browserHandle", "state", "detail", "planHandle", "undoable"] {
            assert!(object.contains_key(key), "{key}");
        }
        let encoded = serde_json::to_string(&dto).unwrap();
        for forbidden in [
            "localPath",
            "remotePath",
            "stagedPath",
            "path\":",
            "fileCount",
        ] {
            assert!(!encoded.contains(forbidden), "{forbidden}");
        }
        // A refused upload never advertises an undo handle.
        let refused = SftpDirectoryUploadDto {
            browser_handle: "opaque-browser".to_owned(),
            state: "refused-destination".to_owned(),
            detail: "目标位置已存在同名文件夹。".to_owned(),
            plan_handle: None,
            undoable: false,
        };
        assert!(serde_json::to_value(&refused).unwrap()["planHandle"].is_null());
    }

    /// A prepared archive is single use and belongs to its binding only;
    /// discarding it removes the staged file.
    #[test]
    fn directory_upload_staging_is_single_use_and_scoped() {
        let mut registry = SftpBrowserRegistry::default();
        let scope_a = scope("binding-a", "a@10.0.0.1", 0);
        let other = scope("binding-b", "b@10.0.0.2", 0);
        let staged = std::env::temp_dir().join(format!("lh-staged-{}", Uuid::new_v4()));
        std::fs::write(&staged, b"tar").unwrap();
        let now = Instant::now();
        registry
            .store_directory_upload(
                "staged-1".to_owned(),
                PendingDirectoryUpload {
                    binding_handle: scope_a.binding_handle.clone(),
                    path: staged.clone(),
                    name: "site".to_owned(),
                    expires_at: now + PLAN_TTL,
                },
            )
            .unwrap();
        assert!(
            registry
                .take_directory_upload(&other, "staged-1", now)
                .is_err()
        );
        let pending = registry
            .take_directory_upload(&scope_a, "staged-1", now)
            .unwrap();
        assert_eq!(pending.name, "site");
        assert!(
            registry
                .take_directory_upload(&scope_a, "staged-1", now)
                .is_err()
        );
        std::fs::remove_file(&staged).unwrap();

        let gone = std::env::temp_dir().join(format!("lh-staged-{}", Uuid::new_v4()));
        std::fs::write(&gone, b"tar").unwrap();
        registry
            .store_directory_upload(
                "staged-2".to_owned(),
                PendingDirectoryUpload {
                    binding_handle: scope_a.binding_handle.clone(),
                    path: gone.clone(),
                    name: "site".to_owned(),
                    expires_at: now + PLAN_TTL,
                },
            )
            .unwrap();
        assert!(!registry.discard_directory_upload(&other, "staged-2"));
        assert!(gone.exists());
        assert!(registry.discard_directory_upload(&scope_a, "staged-2"));
        assert!(!gone.exists());
    }

    /// A plan is single use and belongs to one target and one browser.
    #[test]
    fn plans_are_scoped_single_use_and_expire() {
        let mut registry = SftpBrowserRegistry::default();
        let owner = scope("binding-one", "identity-one", 0);
        let other = scope("binding-two", "identity-two", 0);
        let now = Instant::now();

        // Without a live browser behind it, a plan answers nobody.
        assert!(registry.plan_mut(&owner, "missing-plan", now).is_err());
        assert!(
            registry
                .take_confirmed_plan(&owner, "missing-plan", now)
                .is_err()
        );

        // Dropping is scoped too: another target cannot release this plan.
        registry.drop_plan(&other, "missing-plan");
        assert!(registry.plans.is_empty());

        // An undo nobody holds is refused, not invented.
        assert!(registry.take_done(&owner, "missing-plan", now).is_err());
        assert!(registry.done.is_empty());
    }

    /// A cancel reaches the transfers of the browser it names and no others.
    #[test]
    fn cancelling_stops_only_this_browsers_transfers() {
        let mut registry = SftpBrowserRegistry::default();
        let mine = SftpTransferCancel::new();
        let other_window = SftpTransferCancel::new();
        let other_target = SftpTransferCancel::new();
        for (binding, browser, cancel) in [
            ("binding-one", "browser-one", &mine),
            ("binding-one", "browser-two", &other_window),
            ("binding-two", "browser-one", &other_target),
        ] {
            registry.transfers.insert(
                Uuid::new_v4(),
                ActiveTransfer {
                    binding_handle: binding.to_owned(),
                    browser_handle: browser.to_owned(),
                    cancel: cancel.clone(),
                },
            );
        }
        assert_eq!(registry.cancel_transfers("binding-one", "browser-one"), 1);
        assert!(mine.is_cancelled());
        assert!(!other_window.is_cancelled());
        assert!(!other_target.is_cancelled());
        // Nothing running for a browser is an answer, not an error.
        assert_eq!(registry.cancel_transfers("binding-one", "browser-three"), 0);
    }

    /// A transfer at its deadline is cancelled, not dropped, so its own
    /// clean-up gets to run before the deadline is reported.
    #[tokio::test]
    async fn a_transfer_at_its_deadline_is_cancelled_and_finishes_cleaning_up() {
        let cancel = SftpTransferCancel::new();
        let watched = cancel.clone();
        let cleaned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleaned_by_transfer = Arc::clone(&cleaned);
        let transfer = async move {
            while !watched.is_cancelled() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            cleaned_by_transfer.store(true, std::sync::atomic::Ordering::SeqCst);
        };
        let outcome = run_transfer(transfer, &cancel, Duration::from_millis(30)).await;
        assert!(matches!(outcome, Err(SftpBrowserApiError::Deadline)));
        assert!(cancel.is_cancelled());
        assert!(cleaned.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// The window offers an undo only for what the backend holds, and says how
    /// long for; the two must agree.
    #[test]
    fn the_undo_window_is_the_one_the_file_manager_states() {
        assert_eq!(UNDO_TTL, Duration::from_secs(10 * 60));
    }

    #[test]
    fn plan_text_stays_one_bounded_line() {
        let noisy = [
            "summary\u{7}with control\n",
            &"x".repeat(MAX_PLAN_TEXT_BYTES),
        ]
        .concat();
        let bounded = bounded_detail(&noisy);
        assert!(bounded.len() <= MAX_PLAN_TEXT_BYTES);
        assert!(!bounded.contains('\u{7}'));
    }

    /// The pipeline reaches a target through the core's planning surface and
    /// nothing else. Reading is direct; every change is a plan the operator
    /// confirms, so no call here changes a target on its own.
    #[test]
    fn production_source_uses_only_the_closed_core_sftp_surface() {
        let source = include_str!("sftp_browser_api.rs");
        let whole = source.split("#[cfg(test)]").next().unwrap();
        // Local upload sizing and the inventory-authorized, non-following core
        // lstat are the only metadata calls. There is no page-supplied path API.
        let editor_stat = "self.services.sftp().metadata(&session, &path, false)";
        // The directory-upload destination is statted up front so a refusal
        // can say the name is taken; plan_extract re-checks before writing.
        let upload_stat = ".metadata(&session, &destination, false)";
        assert!(whole.contains(editor_stat));
        assert!(whole.contains(upload_stat));
        assert!(whole.contains("metadata.kind != SftpFileKind::File"));
        let production = whole
            .replace("std::fs::metadata(local_path)", "")
            .replace(editor_stat, "")
            .replace(upload_stat, "")
            // The queue stats each download source once for the resume
            // decision, and each running upload's remote file for progress.
            .replace(".metadata(&session, &remote_path, false)", "")
            .replace(".metadata(&session, &path, false)", "")
            // Local `.part`/staged sizing for progress and the upload total.
            .replace("std::fs::metadata(&part)", "")
            .replace("std::fs::metadata(part)", "")
            .replace("std::fs::metadata(&staged_path)", "")
            // The relay stats its host temp for download progress, and asks
            // the peer for the destination directory, the EXCLUDE check and
            // upload progress — all through the peer's own core service.
            .replace("std::fs::metadata(path)", "")
            .replace(".metadata(&peer_session, &dest, false)", "")
            .replace(".metadata(&b_session, &destination.dir, false)", "")
            .replace(".metadata(&b_session, &destination.remote, false)", "");
        assert!(production.contains(".sftp()\n                .bind_session("));
        assert!(production.contains("self.services.sftp().list("));
        assert!(production.contains("self.services.sftp().read_text("));
        assert!(production.contains("RemotePath::new(\"/\")"));
        // The one transfer that exists goes through the core call that checks
        // the local target against the path guard.
        assert!(production.contains(".download_new(&session, &self.paths,"));
        assert!(production.contains("&self.paths,"));
        // A change is planned, approved, executed and verified as four steps,
        // with the restore path written down next to them.
        for step in [
            ".plan(&session, mutation)",
            ".plan_upload(&session, &self.paths, &staged_path, destination)",
            ".plan_upload(&session, &self.paths, &staged.path, temporary.clone())",
            ".plan_extract(&session, temporary.clone(), destination.clone())",
            "DangerousConfirmation::approve(",
            ".execute_and_verify()",
            ".restore()",
        ] {
            assert!(production.contains(step), "production is missing {step}");
        }
        for forbidden in [
            [".ssh()", ".sftp("].concat(),
            ["open_directory", "_terminal"].concat(),
            ["read", "_file("].concat(),
            ["canonical", "ize"].concat(),
            ["metadata", "("].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "production contains {forbidden}"
            );
        }
    }
}
