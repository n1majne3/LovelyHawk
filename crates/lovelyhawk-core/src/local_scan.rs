//! Fetching target content into a local quarantine area for a local scan
//! engine, the "D盾扫 www" workflow made bounded and auditable.
//!
//! The remote side packs one bounded file set into a plain tar inside the
//! target's own temp space; the download reuses the evidence transport (SFTP,
//! or classic SCP where the subsystem is missing) so the archive gets the
//! same double-read and digest checks evidence does. Extraction on this side
//! is a fixed parser that writes only regular files below a fresh directory,
//! never reproduces remote modes, marks every file as downloaded content, and
//! skips anything that is not a plain file or directory.
//!
//! A configured engine is then launched against the staged copy. Launching a
//! GUI engine and revealing the folder are the only effects this module has
//! on the local machine; nothing fetched is ever executed.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, CoreResult, PortableStore, sftp::RemotePath, shell_escape::shq};

/// Largest archive the remote may hand back before the download is refused.
pub const MAX_FETCH_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
/// Most members one remote file set may contain.
pub const MAX_FETCH_ENTRIES: usize = 20_000;
/// Largest single member the remote `find` filter keeps. The local extractor
/// enforces the same ceiling again in case the remote side lied.
pub const MAX_FETCH_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Largest total the extractor will write; archives can expand far beyond
/// their packed size, so the extracted sum is bounded on its own.
pub const MAX_FETCH_EXTRACT_BYTES: u64 = 1024 * 1024 * 1024;
/// Deepest `find` descent below the fetched directory.
pub const FETCH_FIND_DEPTH: u32 = 16;
/// Most engines one settings file may carry.
pub const MAX_LOCAL_SCAN_ENGINES: usize = 8;
/// Most entries a fetch manifest keeps for display.
pub const MAX_FETCH_LIST_ENTRIES: usize = 400;

const MAX_MEMBER_COMPONENTS: usize = 32;
const MAX_MEMBER_COMPONENT_BYTES: usize = 240;
const MAX_MEMBER_PATH_BYTES: usize = 1024;
const MAX_SKIP_REASONS: usize = 8;

/// Refusal subjects the backend translates into page wording.
pub const FETCH_TOOLS_REFUSAL: &str = "local-scan tools";
pub const FETCH_KIND_REFUSAL: &str = "local-scan kind";
pub const FETCH_SIZE_REFUSAL: &str = "local-scan size";

/// What part of the offered path the fetch covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalScanScope {
    /// The offered path itself, file or directory.
    Path,
    /// The directory that contains the offered path.
    Parent,
}

impl LocalScanScope {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "file" => Some(Self::Path),
            "directory" => Some(Self::Parent),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Path => "file",
            Self::Parent => "directory",
        }
    }
}

/// The remote root a scope resolves to: the directory `tar -C` starts in and
/// the single top member it packs, so extracted content always sits under one
/// folder named like the remote file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRoot {
    pub remote: RemotePath,
    pub base: String,
    pub directory_side: RemotePath,
}

pub fn fetch_root(path: &RemotePath, scope: LocalScanScope) -> CoreResult<FetchRoot> {
    let remote = match scope {
        LocalScanScope::Path => path.clone(),
        LocalScanScope::Parent => path.parent().map_err(|_| {
            CoreError::validation(
                FETCH_KIND_REFUSAL,
                "该路径没有可取的所在目录；改为只取回该路径本身",
            )
        })?,
    };
    let base = remote
        .file_name()
        .map_err(|_| CoreError::validation(FETCH_KIND_REFUSAL, "无法确定要取回的顶层名称"))?
        .to_owned();
    let directory_side = remote
        .parent()
        .map_err(|_| CoreError::validation(FETCH_KIND_REFUSAL, "无法确定取回命令的工作目录"))?;
    Ok(FetchRoot {
        remote,
        base,
        directory_side,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchProbe {
    pub tar: bool,
    pub find: bool,
    pub kind: FetchKind,
    /// Reported size for a regular file; `None` for anything else.
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchKind {
    File,
    Directory,
    /// A symlink, socket, device or anything else that cannot be packed.
    Other,
}

/// Fixed-shape probe. Markers keep the output parseable beside locale noise.
pub fn fetch_probe_command(root: &FetchRoot) -> String {
    format!(
        "command -v tar >/dev/null 2>&1 && echo LH_TAR=1 || echo LH_TAR=0; \
         command -v find >/dev/null 2>&1 && echo LH_FIND=1 || echo LH_FIND=0; \
         if [ -f {root} ]; then echo LH_KIND=file; stat -c 'LH_SIZE=%s' -- {root} 2>/dev/null; \
         elif [ -d {root} ]; then echo LH_KIND=directory; else echo LH_KIND=other; fi",
        root = shq(root.remote.as_str()),
    )
}

pub fn parse_fetch_probe(output: &str) -> FetchProbe {
    let mut probe = FetchProbe {
        tar: false,
        find: false,
        kind: FetchKind::Other,
        size: None,
    };
    for line in output.lines() {
        match line.trim() {
            "LH_TAR=1" => probe.tar = true,
            "LH_FIND=1" => probe.find = true,
            "LH_KIND=file" => probe.kind = FetchKind::File,
            "LH_KIND=directory" => probe.kind = FetchKind::Directory,
            "LH_KIND=other" => probe.kind = FetchKind::Other,
            line => {
                if let Some(size) = line.strip_prefix("LH_SIZE=") {
                    probe.size = size.trim().parse::<u64>().ok();
                }
            }
        }
    }
    probe
}

/// Packs the fetch root into one tar under the target's temp space.
///
/// The member list is always relative to `directory_side` and always starts
/// at `base`, so an archive member can never step out of the one folder the
/// operator asked about. `find` emits only directories and regular files at
/// most `MAX_FETCH_FILE_BYTES` large, bounded to `MAX_FETCH_ENTRIES`; a
/// `LH_TRUNCATED` marker follows when the set was clipped.
pub fn fetch_bundle_command(root: &FetchRoot, kind: FetchKind) -> String {
    let tmp = "$(mktemp /tmp/lh-fetch-XXXXXX.tar)";
    let list = match kind {
        FetchKind::File => format!("printf '%s\\n' {}", shq(&root.base)),
        FetchKind::Directory | FetchKind::Other => format!(
            "find {base} -xdev -maxdepth {depth} \\( -type d -o -type f -size -{kib}k \\) 2>/dev/null",
            base = shq(&root.base),
            depth = FETCH_FIND_DEPTH,
            kib = MAX_FETCH_FILE_BYTES / 1024,
        ),
    };
    format!(
        "set -eu; cd {dir}; LH_TMP={tmp}; export LH_TMP; \
         {list} > \"$LH_TMP.list\" 2>/dev/null || true; \
         LH_N=$(wc -l < \"$LH_TMP.list\" 2>/dev/null || echo 0); \
         if [ \"$LH_N\" -gt {max} ]; then head -n {max} \"$LH_TMP.list\" > \"$LH_TMP.list.h\" && mv \"$LH_TMP.list.h\" \"$LH_TMP.list\"; echo LH_TRUNCATED=1; fi; \
         tar -cf \"$LH_TMP\" -T \"$LH_TMP.list\" 2>/dev/null; \
         LH_RC=$?; rm -f \"$LH_TMP.list\"; \
         if [ \"$LH_RC\" -ne 0 ]; then rm -f \"$LH_TMP\"; echo LH_FAILED=1; exit \"$LH_RC\"; fi; \
         echo LH_ARCHIVE=\"$LH_TMP\"; \
         stat -c 'LH_BYTES=%s' -- \"$LH_TMP\" 2>/dev/null || stat -f '%z' -- \"$LH_TMP\"; \
         echo LH_COUNT=$LH_N",
        dir = shq(root.directory_side.as_str()),
        tmp = tmp,
        list = list,
        max = MAX_FETCH_ENTRIES,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchBundleResult {
    pub archive: RemotePath,
    pub bytes: u64,
    pub members: usize,
    pub truncated: bool,
}

pub fn parse_fetch_bundle(output: &str) -> CoreResult<FetchBundleResult> {
    if output.lines().any(|line| line.trim() == "LH_FAILED=1") {
        return Err(CoreError::validation(
            "local scan bundle",
            "目标机打包失败：tar 未接受成员清单",
        ));
    }
    let mut archive = None;
    let mut bytes = None;
    let mut members = 0_usize;
    let mut truncated = false;
    for line in output.lines() {
        let line = line.trim();
        if let Some(path) = line.strip_prefix("LH_ARCHIVE=") {
            archive = Some(path.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("LH_BYTES=") {
            bytes = value.trim().parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("LH_COUNT=") {
            members = value.trim().parse::<usize>().ok().unwrap_or(0);
        } else if line == "LH_TRUNCATED=1" {
            truncated = true;
        }
    }
    let archive = archive
        .ok_or_else(|| CoreError::validation("local scan bundle", "目标机没有产出取回包"))?;
    let archive = RemotePath::new(archive)
        .map_err(|_| CoreError::validation("local scan bundle", "目标机产出包的路径无效"))?;
    // mktemp names every archive lh-fetch-XXXXXX.tar under /tmp.
    let name_ok = archive
        .as_str()
        .rsplit('/')
        .next()
        .is_some_and(|name| name.starts_with("lh-fetch-") && name.ends_with(".tar"));
    if !name_ok {
        return Err(CoreError::validation(
            "local scan bundle",
            "目标机产出包的路径无效",
        ));
    }
    let bytes =
        bytes.ok_or_else(|| CoreError::validation("local scan bundle", "无法取得取回包的大小"))?;
    if bytes == 0 || bytes > MAX_FETCH_ARCHIVE_BYTES {
        return Err(CoreError::validation(
            FETCH_SIZE_REFUSAL,
            format!("取回包 {} 字节超出上限；请缩小目录或改用文件留证", bytes),
        ));
    }
    Ok(FetchBundleResult {
        archive,
        bytes,
        members,
        truncated,
    })
}

/// One staging area: `content/` holds the untrusted tree, `manifest.json`
/// records what it claims to be, `bundle.tar` is removed once extracted.
#[derive(Debug)]
pub struct FetchStaging {
    pub id: String,
    pub dir: PathBuf,
    pub content_dir: PathBuf,
}

pub fn local_scan_root(store: &PortableStore) -> PathBuf {
    store.temp_dir().join("local-scan")
}

pub fn create_fetch_staging(store: &PortableStore) -> CoreResult<FetchStaging> {
    let root = local_scan_root(store);
    let id = Uuid::new_v4().to_string();
    let dir = root.join(&id);
    let content_dir = dir.join("content");
    fs::create_dir_all(&content_dir)
        .map_err(|source| CoreError::io("create local scan staging", &content_dir, source))?;
    Ok(FetchStaging {
        id,
        dir,
        content_dir,
    })
}

/// Whether `dir` is a fetch staging directory this store created.
///
/// `reveal` and `run` resolve the directory only through a stored fetch id —
/// this check is the second line for anything that slipped the registry.
pub fn is_fetch_staging(store: &PortableStore, dir: &Path) -> bool {
    let root = local_scan_root(store);
    let (Ok(root), Ok(dir)) = (fs::canonicalize(&root), fs::canonicalize(dir)) else {
        return false;
    };
    dir.starts_with(&root) && dir != root && dir.join("manifest.json").is_file()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanManifest {
    pub version: u32,
    pub source_path: String,
    pub source_kind: String,
    pub scope: String,
    pub target_label: String,
    pub fetched_at: String,
    pub transport: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub files: usize,
    #[serde(default)]
    pub directories: usize,
    pub bytes: u64,
    pub skipped: usize,
    pub truncated: bool,
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

pub fn write_manifest(staging: &FetchStaging, manifest: &LocalScanManifest) -> CoreResult<()> {
    let path = staging.dir.join("manifest.json");
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|source| CoreError::Encode {
        subject: "local scan manifest",
        source,
    })?;
    fs::write(&path, bytes)
        .map_err(|source| CoreError::io("write local scan manifest", &path, source))
}

pub fn read_manifest(dir: &Path) -> CoreResult<LocalScanManifest> {
    let bytes = fs::read(dir.join("manifest.json"))
        .map_err(|source| CoreError::io("read local scan manifest", dir, source))?;
    serde_json::from_slice(&bytes).map_err(|source| CoreError::Decode {
        subject: "local scan manifest",
        source,
    })
}

#[derive(Debug, Clone, Default)]
pub struct FetchExtractReport {
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
    pub skipped: usize,
    /// Bounded sample of why members were refused; never full attacker text.
    pub skipped_reasons: Vec<String>,
    /// Relative display paths of the first `MAX_FETCH_LIST_ENTRIES` files.
    pub entries: Vec<String>,
}

/// Extracts a tar archive into `content`, writing only regular files.
///
/// Every member is checked like an untrusted name: no absolute paths, parent
/// steps, separators, control characters, reserved or trailing-punctuation
/// names and nothing that is not a file or directory survives. Modes are
/// never reproduced — extracted files land without execute permission — and
/// on Windows each file carries a Mark-of-the-Web zone identifier so the
/// shell treats it as downloaded content.
pub fn extract_fetch_archive(archive: &Path, content: &Path) -> CoreResult<FetchExtractReport> {
    let mut reader = TarReader::open(archive)?;
    let mut report = FetchExtractReport::default();
    // GNU `L` long names and pax `x` `path=` records both apply to the entry
    // that follows them, so one pending slot covers either producer.
    let mut pending_name: Option<String> = None;
    while let Some(header) = reader.next_header()? {
        match header.kind {
            TarKind::File => {
                let name = match member_name(&header, pending_name.take()) {
                    Ok(name) => name,
                    Err(reason) => {
                        reader.skip(header.size)?;
                        skip(&mut report, reason);
                        continue;
                    }
                };
                let Some(dest) = safe_member_path(content, &name) else {
                    reader.skip(header.size)?;
                    skip(&mut report, "成员路径不安全");
                    continue;
                };
                if header.size > MAX_FETCH_FILE_BYTES {
                    reader.skip(header.size)?;
                    skip(&mut report, "成员超出单文件上限");
                    continue;
                }
                if report.files >= MAX_FETCH_ENTRIES {
                    reader.skip(header.size)?;
                    skip(&mut report, "成员数量超出上限");
                    continue;
                }
                if report.bytes.saturating_add(header.size) > MAX_FETCH_EXTRACT_BYTES {
                    reader.skip(header.size)?;
                    skip(&mut report, "解压总量超出上限");
                    continue;
                }
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent).map_err(|source| {
                        CoreError::io("create fetched directory", parent, source)
                    })?;
                }
                let mut file = match OpenOptions::new().create_new(true).write(true).open(&dest) {
                    Ok(file) => file,
                    Err(_) => {
                        reader.skip(header.size)?;
                        skip(&mut report, "成员名冲突");
                        continue;
                    }
                };
                let copied = std::io::copy(&mut reader.by_ref().take(header.size), &mut file)
                    .map_err(|source| CoreError::io("write fetched file", &dest, source))?;
                file.sync_all()
                    .map_err(|source| CoreError::io("sync fetched file", &dest, source))?;
                if copied != header.size {
                    let _ = fs::remove_file(&dest);
                    return Err(CoreError::validation(
                        "local scan extract",
                        "成员内容不完整，已丢弃该文件",
                    ));
                }
                mark_downloaded(&dest);
                report.files += 1;
                report.bytes += copied;
                if report.entries.len() < MAX_FETCH_LIST_ENTRIES {
                    report.entries.push(name);
                }
            }
            TarKind::Directory => {
                if let Ok(name) = member_name(&header, pending_name.take())
                    && let Some(dest) = safe_member_path(content, &name)
                {
                    fs::create_dir_all(&dest).map_err(|source| {
                        CoreError::io("create fetched directory", &dest, source)
                    })?;
                    report.directories += 1;
                }
                reader.skip(header.size)?;
            }
            TarKind::LongName => {
                pending_name = Some(reader.take_string(header.size)?);
            }
            TarKind::Pax => {
                pending_name = reader.take_pax_path(header.size)?.or(pending_name.take());
            }
            TarKind::LongLink | TarKind::Skip => {
                // Links, devices and anything else never land; the pending
                // name stays because a `K`/`x` header still belongs to the
                // next real member.
                reader.skip(header.size)?;
                if matches!(header.typeflag, b'1' | b'2' | b'3' | b'4' | b'6' | b'7') {
                    skip(&mut report, "仅保留普通文件与目录");
                }
            }
        }
    }
    Ok(report)
}

fn skip(report: &mut FetchExtractReport, reason: &'static str) {
    report.skipped += 1;
    if report.skipped_reasons.len() < MAX_SKIP_REASONS
        && !report.skipped_reasons.iter().any(|seen| seen == reason)
    {
        report.skipped_reasons.push(reason.to_owned());
    }
}

#[cfg(windows)]
fn mark_downloaded(path: &Path) {
    let zone = format!("{}:Zone.Identifier", path.display());
    let _ = fs::write(zone, "[ZoneTransfer]\r\nZoneId=3\r\n");
}

#[cfg(not(windows))]
fn mark_downloaded(_path: &Path) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TarKind {
    File,
    Directory,
    LongName,
    LongLink,
    Pax,
    Skip,
}

struct TarHeader {
    kind: TarKind,
    size: u64,
    name: String,
    prefix: String,
    typeflag: u8,
}

struct TarReader {
    inner: fs::File,
    /// Bytes left in the current member's data.
    remaining: u64,
    /// Padding owed once `remaining` reaches zero.
    pad: u64,
}

impl TarReader {
    fn open(path: &Path) -> CoreResult<Self> {
        let inner = fs::File::open(path)
            .map_err(|source| CoreError::io("open fetched archive", path, source))?;
        Ok(Self {
            inner,
            remaining: 0,
            pad: 0,
        })
    }

    fn next_header(&mut self) -> CoreResult<Option<TarHeader>> {
        // A caller that left member data unread still owes it before the pad.
        let owed = self.remaining.saturating_add(self.pad);
        self.remaining = 0;
        self.pad = 0;
        self.drain(owed)?;
        let mut block = [0_u8; 512];
        match self.inner.read(&mut block) {
            Ok(0) => return Ok(None),
            Ok(n) if n < 512 => {
                return Err(CoreError::validation(
                    "local scan extract",
                    "取回包在块边界前结束",
                ));
            }
            Ok(_) => {}
            Err(source) => {
                return Err(CoreError::io(
                    "read fetched archive",
                    Path::new("tar"),
                    source,
                ));
            }
        }
        if block.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        let name = tar_string(&block[0..100]);
        let size = tar_octal(&block[124..136])?;
        let typeflag = block[156];
        let prefix = if &block[257..262] == b"ustar" {
            tar_string(&block[345..500])
        } else {
            String::new()
        };
        let kind = match typeflag {
            b'0' | 0 | b'7' => TarKind::File,
            b'5' => TarKind::Directory,
            b'L' => TarKind::LongName,
            b'K' => TarKind::LongLink,
            b'x' => TarKind::Pax,
            _ => TarKind::Skip,
        };
        self.remaining = size;
        self.pad = (512 - size % 512) % 512;
        Ok(Some(TarHeader {
            kind,
            size,
            name,
            prefix,
            typeflag,
        }))
    }

    fn skip(&mut self, size: u64) -> CoreResult<()> {
        self.drain(size)?;
        self.remaining = 0;
        Ok(())
    }

    fn drain(&mut self, bytes: u64) -> CoreResult<()> {
        let mut left = bytes;
        let mut scratch = [0_u8; 8192];
        while left > 0 {
            let step = left.min(scratch.len() as u64) as usize;
            let read = self
                .inner
                .read(&mut scratch[..step])
                .map_err(|source| CoreError::io("skip fetched member", Path::new("tar"), source))?;
            if read == 0 {
                return Err(CoreError::validation(
                    "local scan extract",
                    "取回包内容不完整",
                ));
            }
            left -= read as u64;
        }
        Ok(())
    }

    fn take_string(&mut self, size: u64) -> CoreResult<String> {
        if size > 4096 {
            self.skip(size)?;
            return Ok(String::new());
        }
        let mut buffer = vec![0_u8; size as usize];
        self.inner
            .read_exact(&mut buffer)
            .map_err(|source| CoreError::io("read long member name", Path::new("tar"), source))?;
        self.remaining = 0;
        Ok(String::from_utf8_lossy(&buffer)
            .trim_end_matches('\0')
            .to_owned())
    }

    fn take_pax_path(&mut self, size: u64) -> CoreResult<Option<String>> {
        if size > 8192 {
            self.skip(size)?;
            return Ok(None);
        }
        let data = self.take_string(size)?;
        // Records are `<len> <key>=<value>\n`; only `path` matters here.
        for record in data.split('\n') {
            if let Some((_, value)) = record.split_once(' ')
                && let Some((key, value)) = value.split_once('=')
                && key == "path"
            {
                return Ok(Some(value.to_owned()));
            }
        }
        Ok(None)
    }
}

impl Read for TarReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let wanted = (buffer.len() as u64).min(self.remaining) as usize;
        let read = self.inner.read(&mut buffer[..wanted])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn tar_string(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn tar_octal(field: &[u8]) -> CoreResult<u64> {
    // GNU tar writes base-256 for sizes past the octal range.
    if field[0] & 0x80 != 0 {
        let mut value = (field[0] & 0x7f) as u64;
        for byte in &field[1..12] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(*byte as u64))
                .ok_or_else(|| CoreError::validation("local scan extract", "成员大小无法表示"))?;
        }
        return Ok(value);
    }
    let text = tar_string(field);
    let text = text.trim_end_matches([' ', '\0']);
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text.trim_start_matches(' '), 8)
        .map_err(|_| CoreError::validation("local scan extract", "成员大小字段无法解析"))
}

fn member_name(header: &TarHeader, pending: Option<String>) -> Result<String, &'static str> {
    let name = pending.unwrap_or_else(|| match header.prefix.as_str() {
        "" => header.name.clone(),
        prefix => format!("{prefix}/{}", header.name),
    });
    if name.is_empty() || name.len() > MAX_MEMBER_PATH_BYTES {
        return Err("成员名无效");
    }
    Ok(name)
}

/// The local side of member-name safety: a member must reduce to a plain
/// relative path of acceptable components.
fn safe_member_path(root: &Path, name: &str) -> Option<PathBuf> {
    let name = name.trim_end_matches('/');
    if name.is_empty() || name.starts_with('/') || name.starts_with('\\') {
        return None;
    }
    let mut dest = root.to_path_buf();
    let mut components = 0_usize;
    for part in name.split('/') {
        components += 1;
        if components > MAX_MEMBER_COMPONENTS || !safe_component(part) {
            return None;
        }
        dest.push(part);
    }
    Some(dest)
}

fn safe_component(part: &str) -> bool {
    if part.is_empty()
        || part == "."
        || part == ".."
        || part.len() > MAX_MEMBER_COMPONENT_BYTES
        || part.ends_with(['.', ' '])
    {
        return false;
    }
    if part
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\'))
    {
        return false;
    }
    let stem = part.split('.').next().unwrap_or(part).to_ascii_lowercase();
    !(matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0'))
}

/// How a configured engine is started against a staging directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalScanEngineKind {
    /// A windowed tool (D盾 style); we launch it and the operator drives it.
    Gui,
    /// A command-line scanner whose output we can capture and show.
    Cli,
}

impl LocalScanEngineKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "gui" => Some(Self::Gui),
            "cli" => Some(Self::Cli),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::Cli => "cli",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanEngine {
    pub id: String,
    pub name: String,
    pub kind: LocalScanEngineKind,
    /// Absolute local program path; only ever set by the native file dialog.
    pub program: String,
    /// Fixed argument list; `{dir}` is replaced by the staging directory.
    #[serde(default)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanSettings {
    #[serde(default)]
    pub engines: Vec<LocalScanEngine>,
}

pub fn validate_engine(engine: &LocalScanEngine) -> CoreResult<()> {
    if engine.id.is_empty()
        || engine.id.len() > 64
        || !engine
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(CoreError::validation(
            "local scan engine id",
            "must be 1..=64 ASCII letters, digits, dots, underscores or hyphens",
        ));
    }
    if engine.name.trim().is_empty()
        || engine.name.len() > 64
        || engine.name.chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "local scan engine name",
            "must be 1..=64 characters without control characters",
        ));
    }
    let program = Path::new(&engine.program);
    if !program.is_absolute()
        || engine.program.len() > 1024
        || engine.program.chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "local scan engine program",
            "must be an absolute local path",
        ));
    }
    if engine.arguments.len() > 16
        || engine
            .arguments
            .iter()
            .any(|arg| arg.len() > 512 || arg.chars().any(char::is_control))
    {
        return Err(CoreError::validation(
            "local scan engine arguments",
            "must be at most 16 bounded arguments",
        ));
    }
    Ok(())
}

impl LocalScanSettings {
    pub fn validate(&self) -> CoreResult<()> {
        if self.engines.len() > MAX_LOCAL_SCAN_ENGINES {
            return Err(CoreError::validation(
                "local scan engines",
                format!("must contain at most {MAX_LOCAL_SCAN_ENGINES} engines"),
            ));
        }
        let mut ids = BTreeSet::new();
        for engine in &self.engines {
            validate_engine(engine)?;
            if !ids.insert(engine.id.as_str()) {
                return Err(CoreError::validation(
                    "local scan engine id",
                    "must be unique",
                ));
            }
        }
        Ok(())
    }
}

/// The argv a launch passes: `{dir}` becomes the staging directory, and a
/// list without the placeholder gets the directory appended — a GUI engine
/// that ignores arguments still opens, a CLI engine always sees the folder.
pub fn engine_launch(
    engine: &LocalScanEngine,
    content_dir: &Path,
) -> CoreResult<(PathBuf, Vec<String>)> {
    let program = Path::new(&engine.program);
    if !program.is_absolute() || !program.is_file() {
        return Err(CoreError::validation(
            "local scan engine",
            "引擎程序不存在或不是文件，请重新配置",
        ));
    }
    let dir = content_dir.to_string_lossy().into_owned();
    let mut argv: Vec<String> = engine
        .arguments
        .iter()
        .map(|arg| arg.replace("{dir}", &dir))
        .collect();
    if !engine.arguments.iter().any(|arg| arg.contains("{dir}")) {
        argv.push(dir);
    }
    Ok((program.to_path_buf(), argv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_resolves_path_and_parent_roots() {
        let path = RemotePath::new("/var/www/html/up.php".to_owned()).unwrap();
        let file = fetch_root(&path, LocalScanScope::Path).unwrap();
        assert_eq!(file.base, "up.php");
        assert_eq!(file.directory_side.as_str(), "/var/www/html");
        let parent = fetch_root(&path, LocalScanScope::Parent).unwrap();
        assert_eq!(parent.base, "html");
        assert_eq!(parent.directory_side.as_str(), "/var/www");
    }

    #[test]
    fn probe_parses_kind_and_tools() {
        let probe = parse_fetch_probe("LH_TAR=1\nLH_FIND=1\nLH_KIND=directory\n");
        assert!(probe.tar && probe.find);
        assert_eq!(probe.kind, FetchKind::Directory);
        let file = parse_fetch_probe("LH_TAR=1\nLH_FIND=0\nLH_KIND=file\nLH_SIZE=42\n");
        assert_eq!(file.kind, FetchKind::File);
        assert_eq!(file.size, Some(42));
    }

    #[test]
    fn bundle_result_refuses_oversized_or_missing_archives() {
        assert!(parse_fetch_bundle("LH_FAILED=1\n").is_err());
        assert!(parse_fetch_bundle("LH_BYTES=10\n").is_err());
        let ok = parse_fetch_bundle(
            "LH_ARCHIVE=/tmp/lh-fetch-a1b2c3.tar\nLH_BYTES=100\nLH_COUNT=3\nLH_TRUNCATED=1\n",
        )
        .unwrap();
        assert_eq!(ok.bytes, 100);
        assert!(ok.truncated);
        let too_big = parse_fetch_bundle(&format!(
            "LH_ARCHIVE=/tmp/lh-fetch-x.tar\nLH_BYTES={}\n",
            MAX_FETCH_ARCHIVE_BYTES + 1
        ));
        assert!(too_big.is_err());
    }

    /// A minimal tar writer for tests: ustar headers, no compression.
    fn tar_entry(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
        let mut block = [0_u8; 512];
        let name_bytes = name.as_bytes();
        block[..name_bytes.len().min(100)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
        block[100..108].copy_from_slice(b"0000644\0");
        block[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        block[156] = kind;
        block[257..263].copy_from_slice(b"ustar\0");
        let mut out = block.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    fn stage() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("lh-scan-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let content = dir.join("content");
        fs::create_dir_all(&content).unwrap();
        (dir, content)
    }

    #[test]
    fn extractor_writes_plain_files_and_refuses_traversal() {
        let (dir, content) = stage();
        let archive = dir.join("a.tar");
        let mut bytes = tar_entry("site/index.php", b'0', b"<?php echo 1;");
        bytes.extend(tar_entry("site/", b'5', b""));
        bytes.extend(tar_entry("../escape.php", b'0', b"evil"));
        bytes.extend(tar_entry("/abs.php", b'0', b"evil"));
        bytes.extend(tar_entry("site/link", b'2', b"/etc/passwd"));
        bytes.extend(tar_entry("site/evil.sh", b'0', b"#!/bin/sh"));
        bytes.extend(tar_entry("con.php", b'0', b"evil"));
        fs::write(&archive, &bytes).unwrap();
        let report = extract_fetch_archive(&archive, &content).unwrap();
        assert_eq!(report.files, 2);
        assert_eq!(report.skipped, 4, "{:?}", report.skipped_reasons);
        assert!(content.join("site/index.php").is_file());
        assert!(content.join("site/evil.sh").is_file());
        assert!(!content.join("escape.php").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(content.join("site/evil.sh"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0, "extracted file must not be executable");
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extractor_honours_gnu_long_names_and_pax_paths() {
        let (dir, content) = stage();
        let archive = dir.join("a.tar");
        let long = format!("deep/{}/file.php", "x".repeat(120));
        let mut bytes = tar_entry("././@LongLink", b'L', long.as_bytes());
        bytes.extend(tar_entry("truncated", b'0', b"body"));
        fs::write(&archive, &bytes).unwrap();
        let report = extract_fetch_archive(&archive, &content).unwrap();
        assert_eq!(report.files, 1);
        assert!(content.join(&long).is_file());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn member_names_reject_every_step_out() {
        let content = Path::new("/tmp/content");
        assert!(safe_member_path(content, "a/b.php").is_some());
        for bad in [
            "/a", "../a", "a/../b", "a\\b", "con", "COM1.txt", "a:b", "x.", "x ", "", "a//b",
        ] {
            assert!(safe_member_path(content, bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn engine_argv_substitutes_the_directory_once() {
        let engine = LocalScanEngine {
            id: "dshield".to_owned(),
            name: "D盾".to_owned(),
            kind: LocalScanEngineKind::Gui,
            program: "C:\\tools\\d.exe".to_owned(),
            arguments: vec!["-scan".to_owned(), "{dir}".to_owned()],
        };
        let dir = Path::new("C:\\stage\\content");
        // is_file() fails for a path that does not exist, so test the argv
        // shape through a program that does exist.
        let real = LocalScanEngine {
            program: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            ..engine.clone()
        };
        let (_, argv) = engine_launch(&real, dir).unwrap();
        assert_eq!(
            argv,
            vec!["-scan".to_owned(), dir.to_string_lossy().into_owned()]
        );
        let bare = LocalScanEngine {
            arguments: vec![],
            ..engine
        };
        let real = LocalScanEngine {
            program: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            ..bare
        };
        let (_, argv) = engine_launch(&real, dir).unwrap();
        assert_eq!(argv, vec![dir.to_string_lossy().into_owned()]);
    }
}
