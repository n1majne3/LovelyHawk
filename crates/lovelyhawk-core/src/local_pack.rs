//! Builds a tar archive out of a local directory so it can be uploaded to a
//! target and extracted there as one verified operation.
//!
//! The walker refuses symbolic links, junctions and reparse points rather than
//! following them, never leaves the picked directory, and stops with counted
//! numbers when the file count or byte budget is exceeded — before a single
//! byte is written to the archive.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, CoreResult};

/// Files allowed in one directory upload, before tar overhead.
pub const MAX_DIRECTORY_UPLOAD_FILES: u64 = 20_000;
/// Bytes of file content allowed in one directory upload, before tar overhead.
pub const MAX_DIRECTORY_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;
/// Room added on top of the content budget for tar headers and padding when a
/// staged archive is size-checked.
pub const DIRECTORY_UPLOAD_TAR_OVERHEAD_BYTES: u64 = 64 * 1024 * 1024;

/// What a finished pack produced; the page shows these numbers before asking
/// the operator to confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPackReport {
    pub files: u64,
    pub bytes: u64,
    /// The picked folder's name — the remote destination takes it, and it is
    /// already checked to be a single safe path component.
    pub name: String,
}

/// Budgets a pack run enforces. Production callers use [`LocalPackLimits::production`];
/// tests shrink them instead of creating twenty thousand files.
#[derive(Debug, Clone, Copy)]
pub struct LocalPackLimits {
    pub max_files: u64,
    pub max_bytes: u64,
}

impl LocalPackLimits {
    pub const fn production() -> Self {
        Self {
            max_files: MAX_DIRECTORY_UPLOAD_FILES,
            max_bytes: MAX_DIRECTORY_UPLOAD_BYTES,
        }
    }
}

#[derive(Debug)]
struct PackEntry {
    /// Absolute local source; for directories this is where children came from.
    source: PathBuf,
    /// Member path inside the tar, relative to the archive root.
    member: String,
    size: u64,
    is_dir: bool,
}

/// Packs `source` into a POSIX ustar archive at `destination`. Members are
/// relative paths — the remote extraction creates `<cwd>/<name>` itself and
/// lands the members inside it.
pub fn pack_local_directory(source: &Path, destination: &Path) -> CoreResult<LocalPackReport> {
    pack_local_directory_with_limits(source, destination, LocalPackLimits::production())
}

pub fn pack_local_directory_with_limits(
    source: &Path,
    destination: &Path,
    limits: LocalPackLimits,
) -> CoreResult<LocalPackReport> {
    if !source.is_absolute() {
        return Err(CoreError::validation(
            "directory upload source",
            "本机目录必须是本机对话框返回的绝对路径。",
        ));
    }
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| CoreError::io("inspect directory upload source", source, error))?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(CoreError::validation(
            "directory upload source",
            "所选位置不是一个普通的本机文件夹。",
        ));
    }
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::validation("directory upload name", "文件夹名称无法识别。"))?;
    if !safe_component(name) {
        return Err(CoreError::validation(
            "directory upload name",
            "文件夹名称含有目标机不安全接受的字符，请先改名。",
        ));
    }

    let mut entries = Vec::new();
    let mut files: u64 = 0;
    let mut bytes: u64 = 0;
    collect(source, "", &mut entries, &mut files, &mut bytes, limits)?;
    if entries.is_empty() {
        return Err(CoreError::validation(
            "directory upload source",
            "所选文件夹是空的，没有可上传的内容。",
        ));
    }
    if files > limits.max_files {
        return Err(CoreError::validation(
            "directory upload budget",
            format!(
                "本机目录内有 {files} 个文件，超过单次上传上限 {} 个。",
                limits.max_files
            ),
        ));
    }
    if bytes > limits.max_bytes {
        return Err(CoreError::validation(
            "directory upload budget",
            format!(
                "本机目录内容共 {bytes} 字节，超过单次上传上限 {} 字节。",
                limits.max_bytes
            ),
        ));
    }

    let file = File::create(destination)
        .map_err(|source| CoreError::io("create directory upload archive", destination, source))?;
    let mut writer = BufWriter::new(file);
    for entry in &entries {
        if entry.is_dir {
            write_header(&mut writer, &entry.member, 0o755, 0, b'5')
        } else {
            write_header(&mut writer, &entry.member, 0o644, entry.size, b'0')
        }
        .map_err(|source| CoreError::io("write directory upload archive", destination, source))?;
        if entry.is_dir {
            continue;
        }
        let mut input = File::open(&entry.source)
            .map_err(|source| CoreError::io("read packed file", &entry.source, source))?;
        std::io::copy(&mut input, &mut writer).map_err(|source| {
            CoreError::io("write directory upload archive", destination, source)
        })?;
        write_padding(&mut writer, entry.size).map_err(|source| {
            CoreError::io("write directory upload archive", destination, source)
        })?;
    }
    writer
        .write_all(&[0u8; 1024])
        .and_then(|_| writer.flush())
        .map_err(|source| CoreError::io("finish directory upload archive", destination, source))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|source| CoreError::io("sync directory upload archive", destination, source))?;
    Ok(LocalPackReport {
        files,
        bytes,
        name: name.to_owned(),
    })
}

fn collect(
    directory: &Path,
    prefix: &str,
    entries: &mut Vec<PackEntry>,
    files: &mut u64,
    bytes: &mut u64,
    limits: LocalPackLimits,
) -> CoreResult<()> {
    // Collect before recursing so a single read_dir failure does not leave the
    // member order dependent on which directory happened to be read first.
    let mut children: Vec<(PathBuf, String, fs::Metadata)> = Vec::new();
    for child in fs::read_dir(directory)
        .map_err(|source| CoreError::io("list directory upload source", directory, source))?
    {
        let child = child
            .map_err(|source| CoreError::io("list directory upload source", directory, source))?;
        // symlink_metadata: a link is refused at its own entry, never opened.
        let metadata = fs::symlink_metadata(child.path()).map_err(|source| {
            CoreError::io("inspect directory upload entry", child.path(), source)
        })?;
        let name = child.file_name();
        let name = name.to_str().ok_or_else(|| {
            CoreError::validation(
                "directory upload name",
                "目录内有名称无法识别的条目，请先改名。",
            )
        })?;
        if !safe_component(name) {
            return Err(CoreError::validation(
                "directory upload name",
                format!("目录内条目 {name:?} 的名称含有不安全字符，请先改名。"),
            ));
        }
        if is_link_or_reparse(&metadata) {
            return Err(CoreError::validation(
                "directory upload link",
                format!(
                    "目录内有链接或重解析点（{name}）。为保护目标机，目录上传不接受链接、交接点或重解析点，也不会跟随它们。"
                ),
            ));
        }
        children.push((child.path(), name.to_owned(), metadata));
    }
    children.sort_by(|left, right| left.1.cmp(&right.1));
    for (path, name, metadata) in children {
        let member = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if metadata.is_dir() {
            entries.push(PackEntry {
                source: path.clone(),
                member: member.clone(),
                size: 0,
                is_dir: true,
            });
            collect(&path, &member, entries, files, bytes, limits)?;
        } else if metadata.is_file() {
            *files += 1;
            *bytes += metadata.len();
            if *files > limits.max_files {
                return Err(CoreError::validation(
                    "directory upload budget",
                    format!(
                        "本机目录内文件数超过单次上传上限 {} 个（已统计到 {files} 个）。",
                        limits.max_files
                    ),
                ));
            }
            if *bytes > limits.max_bytes {
                return Err(CoreError::validation(
                    "directory upload budget",
                    format!(
                        "本机目录内容超过单次上传上限 {} 字节（已统计到 {bytes} 字节）。",
                        limits.max_bytes
                    ),
                ));
            }
            entries.push(PackEntry {
                source: path,
                member,
                size: metadata.len(),
                is_dir: false,
            });
        } else {
            return Err(CoreError::validation(
                "directory upload entry",
                format!("目录内有不是普通文件或文件夹的条目（{name}），无法上传。"),
            ));
        }
    }
    Ok(())
}

/// One safe path component for a tar member: no separators, no control
/// characters, no dot-only names, and short enough for a ustar header.
fn safe_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && name
            .chars()
            .all(|character| !character.is_control() && character != '/' && character != '\\')
}

/// Whether this filesystem entry is a link or a reparse point — both are
/// refused, never followed.
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Writes one POSIX ustar header. Member paths longer than 100 bytes are split
/// across `name`/`prefix`; anything that cannot be split is refused.
fn write_header<W: Write>(
    writer: &mut W,
    path: &str,
    mode: u64,
    size: u64,
    typeflag: u8,
) -> std::io::Result<()> {
    let mut header = [0u8; 512];
    let (name, prefix) = split_member_path(path).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("tar member path too long: {path}"),
        )
    })?;
    header[..name.len()].copy_from_slice(name.as_bytes());
    if let Some(prefix) = prefix {
        header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    }
    write_octal(&mut header[100..108], mode);
    write_octal(&mut header[108..116], 0); // uid
    write_octal(&mut header[116..124], 0); // gid
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 0); // mtime: the plan binds sizes, not times
    header[156] = typeflag;
    header[257..262].copy_from_slice(b"ustar");
    header[262] = 0;
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let encoded = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(encoded.as_bytes());
    writer.write_all(&header)
}

fn split_member_path(path: &str) -> Option<(&str, Option<&str>)> {
    if path.len() <= 100 {
        return Some((path, None));
    }
    if path.len() > 255 {
        return None;
    }
    // ustar splits at a '/': prefix up to 155 bytes, name up to 100.
    for (index, _) in path.match_indices('/').rev() {
        let (prefix, remainder) = path.split_at(index);
        let name = &remainder[1..];
        if prefix.len() <= 155 && name.len() <= 100 && !name.is_empty() {
            return Some((name, Some(prefix)));
        }
    }
    None
}

fn write_octal(field: &mut [u8], value: u64) {
    let encoded = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(encoded.as_bytes());
}

fn write_padding<W: Write>(writer: &mut W, size: u64) -> std::io::Result<()> {
    let padding = (512 - size % 512) % 512;
    writer.write_all(&vec![0u8; padding as usize])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_scan::extract_fetch_archive;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("lh-pack-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn nested_tree_round_trips_through_the_hardened_unpacker() {
        let root = temp_root("tree");
        let source = root.join("site");
        std::fs::create_dir_all(source.join("a/b")).unwrap();
        std::fs::write(source.join("index.html"), b"<h1>ok</h1>").unwrap();
        std::fs::write(source.join("a/b/deep.bin"), [7u8; 900]).unwrap();
        let tar = root.join("out.tar");
        let report = pack_local_directory(&source, &tar).unwrap();
        assert_eq!(report.files, 2);
        assert_eq!(report.bytes, 911);
        assert_eq!(report.name, "site");

        let staged = root.join("staged");
        let out = root.join("extracted");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::copy(&tar, staged.join("dir.tar")).unwrap();
        let extraction = extract_fetch_archive(&staged.join("dir.tar"), &out).unwrap();
        assert_eq!(extraction.files, 2);
        assert_eq!(
            std::fs::read(out.join("index.html")).unwrap(),
            b"<h1>ok</h1>"
        );
        assert_eq!(std::fs::read(out.join("a/b/deep.bin")).unwrap().len(), 900);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn symlinks_are_refused_and_never_followed() {
        let root = temp_root("link");
        let source = root.join("data");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("real.txt"), b"real").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hostname", source.join("link")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(root.join("outside.txt"), source.join("link"))
            .unwrap_or_else(|_| {
                std::fs::write(root.join("outside.txt"), b"x").unwrap();
                std::os::windows::fs::symlink_file(root.join("outside.txt"), source.join("link"))
                    .unwrap()
            });
        std::fs::write(root.join("outside.txt"), b"secret").unwrap();
        let error = pack_local_directory(&source, &root.join("out.tar")).unwrap_err();
        assert!(error.to_string().contains("链接") || error.to_string().contains("重解析"));
        assert!(!root.join("out.tar").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn file_and_byte_budgets_refuse_with_counts() {
        let root = temp_root("cap");
        let source = root.join("many");
        std::fs::create_dir_all(&source).unwrap();
        for index in 0..4 {
            std::fs::write(source.join(format!("f{index}")), [0u8; 10]).unwrap();
        }
        let limits = LocalPackLimits {
            max_files: 3,
            max_bytes: 1_000,
        };
        let error =
            pack_local_directory_with_limits(&source, &root.join("a.tar"), limits).unwrap_err();
        assert!(error.to_string().contains('4'));
        let limits = LocalPackLimits {
            max_files: 100,
            max_bytes: 25,
        };
        let error =
            pack_local_directory_with_limits(&source, &root.join("b.tar"), limits).unwrap_err();
        assert!(error.to_string().contains("字节"), "{error}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_refused_on_windows() {
        let root = temp_root("junction");
        let source = root.join("data");
        let target = root.join("elsewhere");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &source.join("junction").to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .status()
            .unwrap();
        if !status.success() {
            // The test box cannot create junctions; nothing more to prove.
            return;
        }
        let error = pack_local_directory(&source, &root.join("out.tar")).unwrap_err();
        assert!(error.to_string().contains("链接") || error.to_string().contains("重解析"));
        assert!(!root.join("out.tar").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn long_member_paths_split_across_ustar_fields() {
        let deep = format!("{}/{}", "p".repeat(120), "n".repeat(90));
        let (name, prefix) = split_member_path(&deep).unwrap();
        assert_eq!(name.len(), 90);
        assert_eq!(prefix.unwrap().len(), 120);
        assert!(split_member_path(&"x".repeat(300)).is_none());
    }
}
