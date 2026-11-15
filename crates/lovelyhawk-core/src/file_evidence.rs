//! Bounded collection of original file bytes. The manifest records observations,
//! not a claim that an untrusted SFTP server provided an atomic filesystem snapshot.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use russh_sftp::client::{SftpSession, fs::Metadata};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{CoreError, CoreResult};

pub const FILE_EVIDENCE_LIMITATIONS: &str = "通过 SFTP 两次读取远端文件，并回读本地副本核对 SHA-256；检查采集前后的路径、大小、权限、属主和修改时间。读取可能改变访问时间并增加磁盘与网络负载。SFTP 不提供原子快照、可信 inode 或持续不变证明；不能据此排除两次观测之间的变化或不可信服务器伪造。";

/// Same guarantees as [`FILE_EVIDENCE_LIMITATIONS`], phrased for the classic
/// scp protocol used when the target exposes no `Subsystem sftp`. The
/// transport changes, the double-read verification does not.
pub const FILE_EVIDENCE_LIMITATIONS_SCP: &str = "远端无 SFTP 子系统，经 exec 通道上的经典 SCP 协议两次读取远端文件，并回读本地副本核对 SHA-256；检查采集前后的路径、大小、权限、属主和修改时间。读取可能改变访问时间并增加磁盘与网络负载。exec/SCP 不提供原子快照、可信 inode 或持续不变证明；不能据此排除两次观测之间的变化或不可信服务器伪造。";

/// Directory selected through a native dialog, with fresh names and no overwrite
/// or recursive cleanup. Cancelled captures deliberately retain labelled partial
/// bytes: absence of manifest.json means they have not passed collection checks.
#[derive(Debug)]
pub struct FileEvidenceBundle {
    directory: std::path::PathBuf,
    folder_name: String,
    sample_file: &'static str,
    destination: Option<std::fs::File>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvidenceSource {
    target: crate::target::TargetGuard,
    session_id: String,
    host: String,
    port: u16,
    username: String,
    host_key_fingerprint: String,
}

impl FileEvidenceSource {
    pub fn from_session(
        session: &crate::sftp::BoundSftpSession,
        status: &crate::ssh::SshConnectionStatus,
    ) -> CoreResult<Self> {
        if session.session_id() != status.session_id
            || session.connection_id() != status.connection_id
        {
            return Err(invalid("source session does not match the selected target"));
        }
        Ok(Self {
            target: session.target().clone(),
            session_id: status.session_id.clone(),
            host: status.host.clone(),
            port: status.port,
            username: status.username.clone(),
            host_key_fingerprint: status.host_key_fingerprint.clone(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEvidenceManifest {
    pub schema: String,
    pub sample_file: String,
    pub case_id: String,
    pub source: FileEvidenceSource,
    pub observation: FileEvidenceReadProof,
    pub limitations: String,
    /// Present only for a packet capture kept as evidence; file evidence from
    /// earlier versions has no such field and still reads the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<crate::packet_capture::PcapEvidenceContext>,
    /// Present only for a file copied out of a Kubernetes pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<crate::kubernetes::PodFileEvidenceContext>,
}

impl FileEvidenceBundle {
    pub fn create(
        paths: &crate::path_guard::PathGuard,
        selected_parent: &std::path::Path,
    ) -> CoreResult<Self> {
        Self::create_with_sample(paths, selected_parent, "sample.bin")
    }

    /// The same bundle with the bytes under a name a viewer recognises, such
    /// as `capture.pcap` for a packet capture.
    pub fn create_with_sample(
        paths: &crate::path_guard::PathGuard,
        selected_parent: &std::path::Path,
        sample_file: &'static str,
    ) -> CoreResult<Self> {
        if sample_file.is_empty()
            || sample_file.len() > 64
            || sample_file.starts_with('.')
            || matches!(sample_file, "README.txt" | "manifest.json")
            || !sample_file
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(invalid("evidence sample name must be a plain file name"));
        }
        let parent = paths.ensure_safe_download_target(selected_parent)?;
        if !parent.is_dir() {
            return Err(invalid("select an existing evidence destination directory"));
        }
        let folder_name = format!("LovelyHawk-evidence-{}", uuid::Uuid::new_v4());
        let directory = parent.join(&folder_name);
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&directory)
            .map_err(|e| CoreError::io("create evidence directory", &directory, e))?;
        // Resolve the newly created directory and reject any redirect before each
        // subsequent file creation. Never remove by a possibly-replaced path.
        let mut bundle = Self {
            directory,
            folder_name,
            sample_file,
            destination: None,
        };
        bundle.require_directory()?;
        bundle.write_new("README.txt", format!("原始字节保存在 {sample_file}。只有同目录 manifest.json 能完整解析且样本摘要匹配时，才表示采集校验已完成。取消、断连或失败可能留下不完整文件；请勿将其当作已完成证据。即使采集完成，也应在隔离的分析环境中查看，不能直接执行样本。\n").as_bytes())?;
        bundle.require_directory()?;
        bundle.destination = Some(new_file(&bundle.directory.join(sample_file))?);
        Ok(bundle)
    }

    pub fn folder_name(&self) -> &str {
        &self.folder_name
    }
    pub fn sample_locator(&self) -> String {
        format!("{}/{}", self.folder_name, self.sample_file)
    }

    pub fn take_destination(&mut self) -> CoreResult<std::fs::File> {
        self.destination
            .take()
            .ok_or_else(|| invalid("evidence destination was already consumed"))
    }

    pub fn finish(
        &self,
        source: FileEvidenceSource,
        case_id: &str,
        proof: FileEvidenceReadProof,
    ) -> CoreResult<FileEvidenceManifest> {
        self.finish_with_capture(source, case_id, proof, None)
    }

    pub fn finish_with_capture(
        &self,
        source: FileEvidenceSource,
        case_id: &str,
        proof: FileEvidenceReadProof,
        capture: Option<crate::packet_capture::PcapEvidenceContext>,
    ) -> CoreResult<FileEvidenceManifest> {
        self.write_manifest(source, case_id, proof, capture, None)
    }

    /// A file copied out of a pod: the manifest says which pod, container and
    /// path, and the digests taken inside the pod.
    pub fn finish_with_pod_file(
        &self,
        source: FileEvidenceSource,
        case_id: &str,
        proof: FileEvidenceReadProof,
        pod: crate::kubernetes::PodFileEvidenceContext,
    ) -> CoreResult<FileEvidenceManifest> {
        self.write_manifest(source, case_id, proof, None, Some(pod))
    }

    fn write_manifest(
        &self,
        source: FileEvidenceSource,
        case_id: &str,
        proof: FileEvidenceReadProof,
        capture: Option<crate::packet_capture::PcapEvidenceContext>,
        pod: Option<crate::kubernetes::PodFileEvidenceContext>,
    ) -> CoreResult<FileEvidenceManifest> {
        if self.destination.is_some() {
            return Err(invalid("evidence collection has not started"));
        }
        let manifest = FileEvidenceManifest {
            schema: "lovelyres-file-evidence/v1".to_owned(),
            sample_file: self.sample_file.to_owned(),
            case_id: case_id.to_owned(),
            source,
            limitations: match proof.transport.as_str() {
                "scp" => FILE_EVIDENCE_LIMITATIONS_SCP.to_owned(),
                _ => FILE_EVIDENCE_LIMITATIONS.to_owned(),
            },
            observation: proof,
            capture,
            pod,
        };
        let encoded = serde_json::to_vec_pretty(&manifest).map_err(|source| CoreError::Encode {
            subject: "file evidence manifest",
            source,
        })?;
        // create_new works on native exports including FAT/exFAT media. An
        // interrupted write is not a valid complete JSON manifest; the receipt is
        // returned only after sync_all, and README requires parsing plus digest verification.
        self.write_new("manifest.json", &encoded)?;
        Ok(manifest)
    }

    fn require_directory(&self) -> CoreResult<()> {
        let metadata = std::fs::symlink_metadata(&self.directory)
            .map_err(|e| CoreError::io("inspect evidence directory", &self.directory, e))?;
        let resolved = std::fs::canonicalize(&self.directory)
            .map_err(|e| CoreError::io("resolve evidence directory", &self.directory, e))?;
        if !metadata.is_dir() || metadata.is_symlink() || resolved != self.directory {
            return Err(invalid("evidence directory was redirected"));
        }
        Ok(())
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> CoreResult<()> {
        use std::io::Write;
        self.require_directory()?;
        let path = self.directory.join(name);
        let mut file = new_file(&path)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| CoreError::io("write evidence manifest", path, e))
    }
}

fn new_file(path: &std::path::Path) -> CoreResult<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| CoreError::io("create evidence file", path, e))
}

pub const MAX_FILE_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
pub const FILE_EVIDENCE_DEADLINE: Duration = Duration::from_secs(15 * 60);
const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub struct FileEvidenceProgress {
    copied: Arc<AtomicU64>,
    verified: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

impl FileEvidenceProgress {
    pub fn copied_bytes(&self) -> u64 {
        self.copied.load(Ordering::SeqCst)
    }
    pub fn verified_bytes(&self) -> u64 {
        self.verified.load(Ordering::SeqCst)
    }
    pub fn total_bytes(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvidenceMetadata {
    pub bytes: u64,
    pub mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub modified_unix_seconds: Option<u32>,
    pub accessed_unix_seconds: Option<u32>,
}

impl FileEvidenceMetadata {
    fn from_remote(value: &Metadata) -> CoreResult<Self> {
        if value.permissions.map(|mode| mode & 0o170000) != Some(0o100000) {
            return Err(invalid(
                "source must be a regular file, not a symbolic link or device",
            ));
        }
        let bytes = value
            .size
            .ok_or_else(|| invalid("source size is unavailable"))?;
        if bytes > MAX_FILE_EVIDENCE_BYTES {
            return Err(invalid("source exceeds the 512 MiB collection limit"));
        }
        Ok(Self {
            bytes,
            mode: value
                .permissions
                .ok_or_else(|| invalid("source type is unavailable"))?,
            uid: value.uid,
            gid: value.gid,
            modified_unix_seconds: value.mtime,
            accessed_unix_seconds: value.atime,
        })
    }

    fn from_scp_stat(stat: &crate::scp::ScpRemoteStat) -> CoreResult<Self> {
        if stat.mode & 0o170000 != 0o100000 {
            return Err(invalid(
                "source must be a regular file, not a symbolic link or device",
            ));
        }
        if stat.size > MAX_FILE_EVIDENCE_BYTES {
            return Err(invalid("source exceeds the 512 MiB collection limit"));
        }
        Ok(Self {
            bytes: stat.size,
            mode: stat.mode,
            uid: Some(stat.uid),
            gid: Some(stat.gid),
            modified_unix_seconds: Some(stat.mtime),
            accessed_unix_seconds: Some(stat.atime),
        })
    }

    fn require_same(&self, current: &Metadata) -> CoreResult<()> {
        let current = Self::from_remote(current)?;
        self.require_same_metadata(&current)
    }

    fn require_same_scp(&self, current: &crate::scp::ScpRemoteStat) -> CoreResult<()> {
        let current = Self::from_scp_stat(current)?;
        self.require_same_metadata(&current)
    }

    fn require_same_metadata(&self, current: &Self) -> CoreResult<()> {
        let mut current = current.to_owned();
        // Reading the source may legitimately change atime. Preserve its original
        // observation separately instead of changing it back on the target.
        current.accessed_unix_seconds = self.accessed_unix_seconds;
        if &current != self {
            return Err(invalid("source metadata changed during collection"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvidenceReadProof {
    pub remote_path: String,
    pub canonical_path: String,
    pub metadata: FileEvidenceMetadata,
    pub final_accessed_unix_seconds: Option<u32>,
    pub sha256: String,
    pub bytes: u64,
    /// How the bytes left the target: "sftp" normally, "scp" when the host
    /// had no SFTP subsystem and the classic protocol carried the file.
    #[serde(default = "default_evidence_transport")]
    pub transport: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

fn default_evidence_transport() -> String {
    "sftp".to_owned()
}

pub(crate) async fn collect_sftp_file(
    sftp: &SftpSession,
    path: &str,
    destination: std::fs::File,
    progress: FileEvidenceProgress,
) -> CoreResult<FileEvidenceReadProof> {
    let started_at = chrono::Utc::now();
    let canonical_path = sftp.canonicalize(path).await.map_err(remote_error)?;
    // Reject symlinked ancestors too: an observation cannot authorize following a
    // different path later. The canonical path is also checked after both reads.
    if canonical_path != path {
        return Err(invalid(
            "source path must be canonical without symbolic links",
        ));
    }
    let before = sftp.symlink_metadata(path).await.map_err(remote_error)?;
    let metadata = FileEvidenceMetadata::from_remote(&before)?;
    progress.total.store(metadata.bytes, Ordering::SeqCst);
    let mut source = sftp.open(path).await.map_err(remote_error)?;
    metadata.require_same(&source.metadata().await.map_err(remote_error)?)?;
    let mut local = tokio::fs::File::from_std(destination);
    let (bytes, sha256) =
        copy_and_hash(&mut source, &mut local, metadata.bytes, &progress.copied).await?;
    metadata.require_same(&source.metadata().await.map_err(remote_error)?)?;
    source.close().await.map_err(remote_error)?;
    local.sync_all().await.map_err(remote_error)?;

    // Reopen the named path for the independent read. This catches replacement of
    // the path while the first handle continued reading an unlinked old file.
    metadata.require_same(&sftp.symlink_metadata(path).await.map_err(remote_error)?)?;
    let mut verification = sftp.open(path).await.map_err(remote_error)?;
    metadata.require_same(&verification.metadata().await.map_err(remote_error)?)?;
    let (_, verification_sha256) = copy_and_hash(
        &mut verification,
        &mut tokio::io::sink(),
        metadata.bytes,
        &progress.verified,
    )
    .await?;
    metadata.require_same(&verification.metadata().await.map_err(remote_error)?)?;
    verification.close().await.map_err(remote_error)?;
    let after = sftp.symlink_metadata(path).await.map_err(remote_error)?;
    metadata.require_same(&after)?;
    if sftp.canonicalize(path).await.map_err(remote_error)? != canonical_path {
        return Err(invalid("source canonical path changed during collection"));
    }
    if sha256 != verification_sha256 {
        return Err(invalid("source content changed between the two reads"));
    }
    local.rewind().await.map_err(remote_error)?;
    let (_, local_sha256) = copy_and_hash(
        &mut local,
        &mut tokio::io::sink(),
        metadata.bytes,
        &AtomicU64::new(0),
    )
    .await?;
    if local_sha256 != sha256 {
        return Err(invalid("saved bytes did not match the collected content"));
    }
    Ok(FileEvidenceReadProof {
        remote_path: path.to_owned(),
        canonical_path,
        metadata,
        final_accessed_unix_seconds: after.atime,
        sha256,
        bytes,
        transport: "sftp".to_owned(),
        started_at,
        completed_at: chrono::Utc::now(),
    })
}

/// Collect over the classic scp protocol instead of SFTP: the target has no
/// `Subsystem sftp`, so metadata comes from a bounded `stat`/`readlink` probe
/// and each of the two reads is its own `scp -f` exec channel. The checks are
/// the same as [`collect_sftp_file`] — canonical path equality, stat equality
/// around both reads, and byte equality across them.
pub(crate) async fn collect_scp_file<E, EF, O, OF, I>(
    exec: &E,
    open_io: &O,
    path: &str,
    destination: std::fs::File,
    progress: FileEvidenceProgress,
) -> CoreResult<FileEvidenceReadProof>
where
    E: Fn(String) -> EF,
    EF: std::future::Future<Output = CoreResult<String>>,
    O: Fn() -> OF,
    OF: std::future::Future<Output = CoreResult<I>>,
    I: crate::scp::ScpIo,
{
    let started_at = chrono::Utc::now();
    let stat = scp_remote_stat(exec, path).await?;
    if stat.canonical_path.is_empty() {
        return Err(invalid("source canonical path is unavailable"));
    }
    if stat.canonical_path != path {
        return Err(invalid(
            "source path must be canonical without symbolic links",
        ));
    }
    let metadata = FileEvidenceMetadata::from_scp_stat(&stat)?;
    progress.total.store(metadata.bytes, Ordering::SeqCst);

    let mut local = tokio::fs::File::from_std(destination);
    let mut first_io = open_io().await?;
    let mut first = EvidenceScpSink::new(Some(&mut local), &progress.copied);
    let header =
        crate::scp::run_scp_download(&mut first_io, &mut first, metadata.bytes, &|| false).await?;
    if header.bytes != metadata.bytes {
        return Err(invalid("source size changed between stat and collection"));
    }
    let sha256 = first.digest();
    local.sync_all().await.map_err(remote_error)?;

    metadata.require_same_scp(&scp_remote_stat(exec, path).await?)?;
    let mut second_io = open_io().await?;
    let mut second = EvidenceScpSink::new(None, &progress.verified);
    crate::scp::run_scp_download(&mut second_io, &mut second, metadata.bytes, &|| false).await?;
    let second_sha256 = second.digest();
    let after = scp_remote_stat(exec, path).await?;
    metadata.require_same_scp(&after)?;
    if after.canonical_path != stat.canonical_path {
        return Err(invalid("source canonical path changed during collection"));
    }
    if sha256 != second_sha256 {
        return Err(invalid("source content changed between the two reads"));
    }
    local.rewind().await.map_err(remote_error)?;
    let (_, local_sha256) = copy_and_hash(
        &mut local,
        &mut tokio::io::sink(),
        metadata.bytes,
        &AtomicU64::new(0),
    )
    .await?;
    if local_sha256 != sha256 {
        return Err(invalid("saved bytes did not match the collected content"));
    }
    Ok(FileEvidenceReadProof {
        remote_path: path.to_owned(),
        canonical_path: stat.canonical_path,
        metadata,
        final_accessed_unix_seconds: Some(after.atime),
        sha256,
        bytes: header.bytes,
        transport: "scp".to_owned(),
        started_at,
        completed_at: chrono::Utc::now(),
    })
}

async fn scp_remote_stat<E, EF>(exec: &E, path: &str) -> CoreResult<crate::scp::ScpRemoteStat>
where
    E: Fn(String) -> EF,
    EF: std::future::Future<Output = CoreResult<String>>,
{
    let output = exec(crate::scp::scp_stat_command(path)).await?;
    crate::scp::parse_scp_stat(&output, path)
}

/// Streams scp payload bytes into the evidence file and/or just the digest,
/// reporting progress exactly like the SFTP copies do.
struct EvidenceScpSink<'a> {
    file: Option<&'a mut tokio::fs::File>,
    digest: Sha256,
    progress: &'a AtomicU64,
    written: u64,
}

impl<'a> EvidenceScpSink<'a> {
    fn new(file: Option<&'a mut tokio::fs::File>, progress: &'a AtomicU64) -> Self {
        Self {
            file,
            digest: Sha256::new(),
            progress,
            written: 0,
        }
    }

    fn digest(self) -> String {
        format!("{:x}", self.digest.finalize())
    }
}

impl crate::scp::ScpSink for EvidenceScpSink<'_> {
    async fn write(&mut self, bytes: &[u8]) -> CoreResult<()> {
        if let Some(file) = self.file.as_deref_mut() {
            file.write_all(bytes).await.map_err(remote_error)?;
        }
        self.digest.update(bytes);
        self.written += bytes.len() as u64;
        self.progress.store(self.written, Ordering::SeqCst);
        Ok(())
    }

    async fn finish(&mut self) -> CoreResult<()> {
        if let Some(file) = self.file.as_deref_mut() {
            file.flush().await.map_err(remote_error)?;
        }
        Ok(())
    }
}

async fn copy_and_hash(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    expected: u64,
    progress: &AtomicU64,
) -> CoreResult<(u64, String)> {
    if expected > MAX_FILE_EVIDENCE_BYTES {
        return Err(invalid("file exceeds collection limit"));
    }
    let mut buffer = Zeroizing::new(vec![0_u8; BUFFER_BYTES]);
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    loop {
        // Read at most one extra byte to detect growth, without writing that byte.
        let limit = (expected.saturating_sub(count) + 1).min(BUFFER_BYTES as u64) as usize;
        let read = reader
            .read(&mut buffer[..limit])
            .await
            .map_err(remote_error)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > expected {
            return Err(invalid("source grew during collection"));
        }
        writer
            .write_all(&buffer[..read])
            .await
            .map_err(remote_error)?;
        digest.update(&buffer[..read]);
        progress.store(count, Ordering::SeqCst);
    }
    if count != expected {
        return Err(invalid("source shrank during collection"));
    }
    writer.flush().await.map_err(remote_error)?;
    Ok((count, format!("{:x}", digest.finalize())))
}

fn invalid(message: &'static str) -> CoreError {
    CoreError::validation("file evidence", message)
}
fn remote_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::ssh("collect file evidence", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::FileAttributes;

    #[tokio::test]
    async fn streams_binary_bytes_without_text_conversion_and_hashes_empty_file() {
        let content = (0..=255_u8)
            .cycle()
            .take(BUFFER_BYTES * 3 + 17)
            .collect::<Vec<_>>();
        let mut result = Vec::new();
        let progress = AtomicU64::new(0);
        let (bytes, digest) = copy_and_hash(
            &mut content.as_slice(),
            &mut result,
            content.len() as u64,
            &progress,
        )
        .await
        .unwrap();
        assert_eq!(result, content);
        assert_eq!(bytes, content.len() as u64);
        assert_eq!(digest, format!("{:x}", Sha256::digest(&content)));
        assert_eq!(progress.load(Ordering::Relaxed), bytes);
        let (_, empty) = copy_and_hash(&mut &b""[..], &mut tokio::io::sink(), 0, &progress)
            .await
            .unwrap();
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn rejects_growth_shrink_and_over_limit_without_publishing_extra_bytes() {
        let progress = AtomicU64::new(0);
        for (input, expected) in [
            (&b"abcd"[..], 3),
            (&b"ab"[..], 3),
            (&b""[..], MAX_FILE_EVIDENCE_BYTES + 1),
        ] {
            let mut output = Vec::new();
            assert!(
                copy_and_hash(&mut &input[..], &mut output, expected, &progress)
                    .await
                    .is_err()
            );
            assert!(output.len() as u64 <= expected);
        }
    }

    fn metadata() -> FileAttributes {
        FileAttributes {
            size: Some(3),
            permissions: Some(0o100644),
            uid: Some(1000),
            gid: Some(1000),
            mtime: Some(12),
            atime: Some(11),
            ..FileAttributes::default()
        }
    }

    #[test]
    fn a_packet_capture_keeps_its_own_file_name_and_says_what_it_captured() {
        let root =
            std::env::temp_dir().join(format!("lovelyhawk-evidence-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let parent = std::fs::canonicalize(&root).unwrap();
        let paths = crate::path_guard::PathGuard::new(parent.join("uploads"), []).unwrap();
        for bad in [
            "",
            "../x.pcap",
            "a/b.pcap",
            ".hidden",
            "manifest.json",
            "README.txt",
            "x y.pcap",
        ] {
            assert!(
                FileEvidenceBundle::create_with_sample(&paths, &parent, bad).is_err(),
                "{bad}"
            );
        }
        let mut bundle =
            FileEvidenceBundle::create_with_sample(&paths, &parent, "capture.pcap").unwrap();
        let folder = parent.join(bundle.folder_name());
        assert_eq!(
            bundle.sample_locator(),
            format!("{}/capture.pcap", bundle.folder_name())
        );
        assert!(folder.join("capture.pcap").is_file());
        assert!(!folder.join("sample.bin").exists());
        assert!(
            std::fs::read_to_string(folder.join("README.txt"))
                .unwrap()
                .contains("原始字节保存在 capture.pcap")
        );
        drop(bundle.take_destination().unwrap());

        let source: FileEvidenceSource = serde_json::from_value(serde_json::json!({
            "target": { "identity": "connection-1", "generation": 3 },
            "session_id": "session-1",
            "host": "192.0.2.10",
            "port": 22,
            "username": "root",
            "host_key_fingerprint": "SHA256:fixture"
        }))
        .unwrap();
        let now = chrono::Utc::now();
        let proof = FileEvidenceReadProof {
            remote_path: "/tmp/lovelyres-pcap-123e4567-e89b-12d3-a456-426614174000.pcap".to_owned(),
            canonical_path: "/tmp/lovelyres-pcap-123e4567-e89b-12d3-a456-426614174000.pcap"
                .to_owned(),
            metadata: FileEvidenceMetadata::from_remote(&metadata()).unwrap(),
            final_accessed_unix_seconds: None,
            sha256: "ab".repeat(32),
            bytes: 3,
            transport: "sftp".to_owned(),
            started_at: now,
            completed_at: now,
        };
        let capture = crate::packet_capture::PcapEvidenceContext {
            tool: "tcpdump".to_owned(),
            interface: "eth0".to_owned(),
            filter: Some("icmp".to_owned()),
            packet_limit: Some(6),
            duration_seconds: 20,
            capture_started_at: now,
            capture_finished_at: now,
            target_bytes: 3,
            target_sha256: "ab".repeat(32),
            target_temporary_path: proof.remote_path.clone(),
            target_temporary_removed: true,
            live_capture: false,
            limitations: crate::packet_capture::PCAP_EVIDENCE_LIMITATIONS.to_owned(),
        };
        let manifest = bundle
            .finish_with_capture(source.clone(), "case-1", proof.clone(), Some(capture))
            .unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(written["sample_file"], "capture.pcap");
        assert_eq!(written["capture"]["interface"], "eth0");
        assert_eq!(written["capture"]["target_temporary_removed"], true);
        assert_eq!(manifest.sample_file, "capture.pcap");

        // Ordinary file evidence writes the manifest it always wrote.
        let mut plain = FileEvidenceBundle::create(&paths, &parent).unwrap();
        drop(plain.take_destination().unwrap());
        plain.finish(source, "case-1", proof).unwrap();
        let written: serde_json::Value = serde_json::from_slice(
            &std::fs::read(parent.join(plain.folder_name()).join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written["sample_file"], "sample.bin");
        assert!(written.get("capture").is_none());
        assert!(written.get("pod").is_none());

        // A pod file names its pod, container and path, and nothing of a capture.
        let mut pod_bundle =
            FileEvidenceBundle::create_with_sample(&paths, &parent, "pod-file.bin").unwrap();
        drop(pod_bundle.take_destination().unwrap());
        let pod = crate::kubernetes::PodFileEvidenceContext {
            tool: "kubectl exec cat".to_owned(),
            kube_context: "viewer@lab".to_owned(),
            namespace: "payments".to_owned(),
            pod: "ledger-0".to_owned(),
            pod_uid: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
            container: Some("app".to_owned()),
            path: "/etc/ledger.conf".to_owned(),
            copied_at: now,
            pod_bytes: 3,
            pod_sha256: "ab".repeat(32),
            host_temporary_path: "/tmp/lovelyhawk-podfile-123e4567-e89b-12d3-a456-426614174000.bin"
                .to_owned(),
            host_temporary_removed: true,
            limitations: crate::kubernetes::POD_FILE_EVIDENCE_LIMITATIONS.to_owned(),
        };
        let manifest = pod_bundle
            .finish_with_pod_file(source_for_pod(), "case-1", proof_for_pod(now), pod)
            .unwrap();
        let written: serde_json::Value = serde_json::from_slice(
            &std::fs::read(parent.join(pod_bundle.folder_name()).join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written["sample_file"], "pod-file.bin");
        assert_eq!(written["pod"]["namespace"], "payments");
        assert_eq!(written["pod"]["container"], "app");
        assert_eq!(written["pod"]["pod_sha256"], "ab".repeat(32));
        assert!(written.get("capture").is_none());
        assert_eq!(manifest.pod.unwrap().pod, "ledger-0");
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn source_for_pod() -> FileEvidenceSource {
        serde_json::from_value(serde_json::json!({
            "target": { "identity": "connection-1", "generation": 3 },
            "session_id": "session-1",
            "host": "192.0.2.10",
            "port": 22,
            "username": "root",
            "host_key_fingerprint": "SHA256:fixture"
        }))
        .unwrap()
    }

    fn proof_for_pod(now: chrono::DateTime<chrono::Utc>) -> FileEvidenceReadProof {
        let path = "/tmp/lovelyhawk-podfile-123e4567-e89b-12d3-a456-426614174000.bin";
        FileEvidenceReadProof {
            remote_path: path.to_owned(),
            canonical_path: path.to_owned(),
            metadata: FileEvidenceMetadata::from_remote(&metadata()).unwrap(),
            final_accessed_unix_seconds: None,
            sha256: "ab".repeat(32),
            bytes: 3,
            transport: "sftp".to_owned(),
            started_at: now,
            completed_at: now,
        }
    }

    #[test]
    fn consistency_preserves_original_atime_but_rejects_other_changes_and_missing_size() {
        let initial = metadata();
        let observation = FileEvidenceMetadata::from_remote(&initial).unwrap();
        let mut accessed = initial.clone();
        accessed.atime = Some(42);
        observation.require_same(&accessed).unwrap();
        assert_eq!(observation.accessed_unix_seconds, Some(11));
        for field in ["size", "mode", "uid", "gid", "mtime"] {
            let mut changed = initial.clone();
            match field {
                "size" => changed.size = Some(4),
                "mode" => changed.permissions = Some(0o100600),
                "uid" => changed.uid = None,
                "gid" => changed.gid = Some(2),
                _ => changed.mtime = Some(13),
            }
            assert!(observation.require_same(&changed).is_err(), "{field}");
        }
        let mut missing = initial.clone();
        missing.size = None;
        assert!(FileEvidenceMetadata::from_remote(&missing).is_err());
        for mode in [0o120777, 0o040755, 0o020666, 0o010600, 0o140666] {
            let mut invalid = initial.clone();
            invalid.permissions = Some(mode);
            assert!(FileEvidenceMetadata::from_remote(&invalid).is_err());
        }
    }
}
