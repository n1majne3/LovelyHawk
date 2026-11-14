//! Deleting lines from a file a read-only run already named — the "remove it,
//! do not comment it" half of the roadmap's line-level cleanup item.
//!
//! A comment keeps the line on the machine, which is the right call when the
//! operator wants the original text back at a glance. Sometimes the answer has
//! to be that the line is gone: persistence dropped into a crontab or an init
//! script is live again the moment somebody un-comments it. Deleting goes
//! through the same guarded SFTP atomic replace the other managed edits use —
//! the whole file is backed up beside the original first, the replace refuses
//! a file that moved since the preview, verification is an independent
//! re-read of the bytes that remain, and undo puts the backup back only while
//! the file is still exactly what the delete left.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::error::{CoreError, CoreResult};
use crate::operations::{DangerousConfirmation, OperationPlan, OperationState, VerificationResult};
use crate::sftp::{
    BoundSftpSession, MAX_EDIT_BYTES, RemotePath, SftpFileKind, SftpMutation, SftpPlannedOperation,
    content_sha256,
};
use crate::shell_escape::{is_valid_username, shq};
use crate::ssh::BoundSshSession;
use crate::system_info::{SystemInfoService, is_valid_safe_basename};

/// Refusal subjects the backend maps to operator-facing codes.
pub const LINE_DELETE_LOCATION_REFUSAL: &str = "line delete location";
pub const LINE_DELETE_KIND_REFUSAL: &str = "line delete kind";
pub const LINE_DELETE_SIZE_REFUSAL: &str = "line delete size";
pub const LINE_DELETE_RANGE_REFUSAL: &str = "line delete range";
pub const LINE_DELETE_STALE_REFUSAL: &str = "line delete stale";
pub const LINE_DELETE_SYNTAX_REFUSAL: &str = "line delete syntax";

/// A chosen range never removes more lines than a person can read in the
/// plan before confirming it.
pub const MAX_DELETE_LINES: u32 = 200;
/// The preview caps what crosses to the page, not what may be deleted.
const MAX_PREVIEW_LINES: usize = 5_000;
/// A line longer than this still exists; only its display is clipped.
const MAX_PREVIEW_LINE_CHARS: usize = 512;
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(15);

/// Whether `path` is one of the managed files a line may be deleted from.
///
/// The list is closed: startup files, cron's own files and the init scripts
/// the cleanup workflow names. Anything else — web roots, libraries, random
/// text — keeps the existing comment/edit flows instead.
pub fn line_delete_path_allowed(path: &RemotePath) -> bool {
    let value = path.as_str();
    if matches!(
        value,
        "/etc/crontab"
            | "/etc/profile"
            | "/etc/bash.bashrc"
            | "/etc/bashrc"
            | "/etc/rc.local"
            | "/etc/rc.d/rc.local"
            | "/etc/inetd.conf"
            | "/etc/modules"
    ) {
        return true;
    }
    if let Some(name) = value.strip_prefix("/etc/modules-load.d/") {
        return name.ends_with(".conf") && is_valid_safe_basename(name) && !name.starts_with('.');
    }
    if let Some(name) = value.strip_prefix("/etc/cron.d/") {
        return is_valid_safe_basename(name) && !name.starts_with('.');
    }
    if let Some(name) = value.strip_prefix("/etc/profile.d/") {
        return name.ends_with(".sh") && is_valid_safe_basename(name) && !name.starts_with('.');
    }
    for prefix in [
        "/var/spool/cron/crontabs/",
        "/var/spool/cron/tabs/",
        "/var/spool/cron/",
    ] {
        if let Some(user) = value.strip_prefix(prefix) {
            return is_valid_username(user);
        }
    }
    if matches!(
        value,
        "/root/.bashrc"
            | "/root/.profile"
            | "/root/.bash_profile"
            | "/root/.vimrc"
            | "/root/.exrc"
            | "/root/.nanorc"
            | "/root/.emacs"
            | "/etc/vim/vimrc"
            | "/etc/vim/vimrc.local"
            | "/etc/vimrc"
    ) {
        return true;
    }
    if let Some(rest) = value.strip_prefix("/home/") {
        return rest.split_once('/').is_some_and(|(user, file)| {
            is_valid_username(user)
                && matches!(
                    file,
                    ".bashrc"
                        | ".profile"
                        | ".bash_profile"
                        | ".vimrc"
                        | ".exrc"
                        | ".nanorc"
                        | ".emacs"
                )
        });
    }
    if let Some(name) = value.strip_prefix("/etc/init.d/") {
        return is_valid_safe_basename(name) && !name.starts_with('.');
    }
    false
}

/// The paths whose deletion can break a boot script's syntax: init.d scripts
/// and rc.local run under `sh`, so a broken remainder is a boot-time problem.
fn line_delete_needs_syntax_check(path: &RemotePath) -> bool {
    let value = path.as_str();
    value == "/etc/rc.local"
        || value == "/etc/rc.d/rc.local"
        || value
            .strip_prefix("/etc/init.d/")
            .is_some_and(|name| is_valid_safe_basename(name) && !name.starts_with('.'))
}

/// One numbered, display-safe line of a preview or a removal list. `text` is
/// lossy UTF-8 with control characters flattened to spaces — what the page
/// draws is always plain text, never terminal bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewLine {
    pub number: u32,
    pub text: String,
    pub clipped: bool,
}

/// What the operator looked at when they chose lines: the file's digest at
/// that moment and the numbered, sanitized lines. `sha256` stays behind the
/// boundary; the plan binds it so a file that moved is refused rather than
/// edited blind.
#[derive(Debug, Clone)]
pub struct LinePreview {
    pub sha256: String,
    pub total_lines: u32,
    pub lines: Vec<PreviewLine>,
    /// The file has more lines than `lines` carries.
    pub truncated: bool,
}

pub fn preview_lines(content: &[u8]) -> LinePreview {
    let chunks: Vec<&[u8]> = content.split_inclusive(|byte| *byte == b'\n').collect();
    let total_lines = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
    let lines = chunks
        .iter()
        .take(MAX_PREVIEW_LINES)
        .enumerate()
        .map(|(index, chunk)| {
            let body = chunk.strip_suffix(b"\n").unwrap_or(chunk);
            let (text, clipped) = sanitize_preview_line(body);
            PreviewLine {
                number: index as u32 + 1,
                text,
                clipped,
            }
        })
        .collect();
    LinePreview {
        sha256: content_sha256(content),
        total_lines,
        lines,
        truncated: chunks.len() > MAX_PREVIEW_LINES,
    }
}

fn sanitize_preview_line(body: &[u8]) -> (String, bool) {
    let mut text = String::with_capacity(body.len().min(MAX_PREVIEW_LINE_CHARS));
    let mut clipped = false;
    for (count, character) in String::from_utf8_lossy(body).chars().enumerate() {
        if count >= MAX_PREVIEW_LINE_CHARS {
            clipped = true;
            break;
        }
        text.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    (text, clipped)
}

/// The bytes a delete produces and the bytes it took out — never routed
/// through `String`, so encodings and line endings the delete did not touch
/// survive byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineDeletion {
    pub replacement: Vec<u8>,
    pub removed: Vec<u8>,
}

/// Removes `first..=last` (1-based, inclusive) from `content`.
///
/// A trailing line without its newline is still a line, and deleting it does
/// not eat the newline that ended the one before.
pub fn delete_line_range(content: &[u8], first: u32, last: u32) -> CoreResult<LineDeletion> {
    let lines: Vec<&[u8]> = content.split_inclusive(|byte| *byte == b'\n').collect();
    let total = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    if first == 0 || last < first {
        return Err(CoreError::validation(
            LINE_DELETE_RANGE_REFUSAL,
            "行号范围无效",
        ));
    }
    if last - first + 1 > MAX_DELETE_LINES {
        return Err(CoreError::validation(
            LINE_DELETE_RANGE_REFUSAL,
            format!("一次最多删除 {MAX_DELETE_LINES} 行"),
        ));
    }
    if last > total {
        return Err(CoreError::validation(
            LINE_DELETE_RANGE_REFUSAL,
            "行号超出文件行数",
        ));
    }
    let start = usize::try_from(first - 1).unwrap_or(usize::MAX);
    let end = usize::try_from(last - 1).unwrap_or(usize::MAX);
    let mut replacement = Vec::with_capacity(content.len());
    let mut removed = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if (start..=end).contains(&index) {
            removed.extend_from_slice(line);
        } else {
            replacement.extend_from_slice(line);
        }
    }
    if removed.is_empty() {
        return Err(CoreError::validation(
            LINE_DELETE_RANGE_REFUSAL,
            "所选范围没有可删除的内容",
        ));
    }
    Ok(LineDeletion {
        replacement,
        removed,
    })
}

/// Whether the post-delete `sh -n` check applies, and whether the original
/// file passed it. When the original already fails — or `sh` is not there to
/// ask — the delete is still allowed; the plan and the outcome just say the
/// check never ran, with the reason.
#[derive(Debug)]
enum SyntaxGate {
    /// Not an init script or rc.local; nothing is checked.
    NotApplicable,
    /// The original passed `sh -n`; the post-delete file must too.
    Enforced,
    /// Not enforced, with the reason shown to the operator.
    Skipped(&'static str),
}

fn sh_command_failed(subject: &'static str, output: &crate::ssh::SshCommandOutput) -> CoreError {
    CoreError::Validation {
        subject,
        message: format!(
            "failed (exit={:?}, timed_out={})",
            output.exit_code, output.timed_out
        ),
    }
}

impl SystemInfoService {
    /// Describe deleting `first..=last` from `path`, bound to the digest of
    /// the preview the operator looked at.
    ///
    /// The allow-list, the file kind and size, and the digest are all checked
    /// here; the write itself re-checks the digest before replacing, so a
    /// file that moved between preview and execution is never touched.
    pub async fn plan_line_delete(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
        first: u32,
        last: u32,
        expected_sha256: &str,
    ) -> CoreResult<LineDeleteOperation> {
        self.target.validate(session.target())?;
        if !line_delete_path_allowed(path) {
            return Err(CoreError::validation(
                LINE_DELETE_LOCATION_REFUSAL,
                "该位置不在行级删除纳管的启动与计划任务文件范围内",
            ));
        }
        let bound = self
            .sftp
            .bind_session(session.target().clone(), session.session_id())
            .await?;
        let metadata =
            self.sftp.metadata(&bound, path, false).await.map_err(|_| {
                CoreError::validation(LINE_DELETE_KIND_REFUSAL, "无法读取该文件的属性")
            })?;
        if metadata.kind != SftpFileKind::File {
            return Err(CoreError::validation(
                LINE_DELETE_KIND_REFUSAL,
                "只能删除普通文件中的行；符号链接、目录与其他类型不支持",
            ));
        }
        if metadata.size == 0 || metadata.size > MAX_EDIT_BYTES {
            return Err(CoreError::validation(
                LINE_DELETE_SIZE_REFUSAL,
                format!("文件为空，或超过 {MAX_EDIT_BYTES} 字节的托管编辑上限"),
            ));
        }
        let content = self.sftp.read_file(&bound, path).await?;
        let original_sha256 = content_sha256(&content);
        if original_sha256 != expected_sha256 {
            return Err(CoreError::validation(
                LINE_DELETE_STALE_REFUSAL,
                "file content changed after the preview; nothing was planned",
            ));
        }
        let deletion = delete_line_range(&content, first, last)?;
        let deleted_sha256 = content_sha256(&deletion.replacement);
        let removed_lines = preview_removed(&deletion.removed, first);
        let syntax = self.syntax_probe(session, path).await?;
        self.target.validate(session.target())?;

        let count = last - first + 1;
        let range = if first == last {
            format!("第 {first} 行")
        } else {
            format!("第 {first}–{last} 行")
        };
        let syntax_note = match &syntax {
            SyntaxGate::NotApplicable => String::new(),
            SyntaxGate::Enforced => {
                "写入后会用 sh -n 对该文件做语法检查，不通过就自动放回原文件。".to_owned()
            }
            SyntaxGate::Skipped(reason) => format!("未做语法检查：{reason}。"),
        };
        // Editing inetd.conf alone does not drop the listener: the daemon
        // has to re-read it, and reloading is not implemented here.
        let reload_note = if path.as_str() == "/etc/inetd.conf" {
            "inetd 需重新加载后才生效，本工具尚不执行重载。"
        } else {
            ""
        };
        let summary = format!(
            "删除 {} {range}（共 {count} 行，原文件 SHA-256 {original_sha256}）。写入前先把整份文件备份到同目录的 .lovelyres-backups/，文件若在预览后变化则拒绝写入；这是彻底删除而不是注释，文件中不再保留该行原文。{syntax_note}{reload_note}",
            path.as_str(),
        );
        let operation = self.sftp.plan_described(
            &bound,
            SftpMutation::AtomicWriteIfMatch {
                path: path.clone(),
                expected_sha256: original_sha256.clone(),
                expected_canonical_path: None,
                backup_directory: None,
                content: deletion.replacement,
            },
            summary,
            Some(format!(
                "在文件仍是删除后内容的前提下，把删除前的完整文件从备份放回 {}",
                path.as_str()
            )),
            BTreeMap::from([
                ("source".to_owned(), "line-delete".to_owned()),
                ("first-line".to_owned(), first.to_string()),
                ("last-line".to_owned(), last.to_string()),
                (
                    "removed-sha256".to_owned(),
                    content_sha256(&deletion.removed),
                ),
            ]),
        )?;
        Ok(LineDeleteOperation {
            inner: operation,
            service: self.clone(),
            session: session.clone(),
            sftp: bound,
            path: path.clone(),
            original_sha256,
            deleted_sha256,
            removed_lines,
            syntax,
        })
    }

    /// What `sh -n` says about the original file, when this path is one the
    /// post-delete check applies to.
    async fn syntax_probe(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
    ) -> CoreResult<SyntaxGate> {
        if !line_delete_needs_syntax_check(path) {
            return Ok(SyntaxGate::NotApplicable);
        }
        let check = format!(
            "command -v sh >/dev/null 2>&1 && sh -n {}",
            shq(path.as_str())
        );
        let output = self
            .ssh
            .execute_bound(session, check, PROBE_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(sh_command_failed("syntax check probe", &output));
        }
        if output.exit_code == Some(0) {
            return Ok(SyntaxGate::Enforced);
        }
        // The check failing for the *original* is not a reason to block the
        // edit — only the reason there is nothing meaningful to enforce. Say
        // which of the two it was so the plan text stays honest.
        let sh = self
            .ssh
            .execute_bound(session, "command -v sh".to_owned(), PROBE_TIMEOUT)
            .await?;
        Ok(if !sh.timed_out && sh.exit_code == Some(0) {
            SyntaxGate::Skipped("原文件本身未通过 sh -n 语法检查")
        } else {
            SyntaxGate::Skipped("目标机没有可用的 sh")
        })
    }
}

/// The stored operation the backend registry holds between plan and undo.
#[derive(Debug)]
pub struct LineDeleteOperation {
    inner: SftpPlannedOperation,
    service: SystemInfoService,
    session: BoundSshSession,
    sftp: BoundSftpSession,
    path: RemotePath,
    original_sha256: String,
    /// The digest the file must still have for undo to put anything back.
    deleted_sha256: String,
    removed_lines: Vec<PreviewLine>,
    syntax: SyntaxGate,
}

impl LineDeleteOperation {
    pub fn definition(&self) -> &OperationPlan {
        self.inner.definition()
    }

    pub fn state(&self) -> OperationState {
        self.inner.state()
    }

    /// The exact lines the delete takes out, display-sanitized the same way
    /// the preview was, so the confirmation lists everything that will go.
    pub fn removed_lines(&self) -> &[PreviewLine] {
        &self.removed_lines
    }

    pub fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        self.inner.confirm(confirmation)
    }

    pub async fn execute_and_verify(&mut self) -> CoreResult<VerificationResult> {
        let mut verification = self.inner.execute_and_verify().await?;
        self.service
            .target
            .validate(&self.inner.definition().target)?;
        if !verification.passed {
            return Ok(verification);
        }
        match &self.syntax {
            SyntaxGate::NotApplicable => {}
            SyntaxGate::Skipped(reason) => {
                verification
                    .detail
                    .push_str(&format!(" 未做语法检查：{reason}。"));
            }
            SyntaxGate::Enforced => {
                let outcome = self
                    .service
                    .ssh
                    .execute_bound(
                        &self.session,
                        format!("sh -n {}", shq(self.path.as_str())),
                        EXECUTE_TIMEOUT,
                    )
                    .await;
                // A dead channel must not leave the file half-committed:
                // put the original back best-effort and say what could
                // not be verified.
                let detail = match &outcome {
                    Ok(output) if output.timed_out || output.exit_code != Some(0) => {
                        "post-delete `sh -n` check failed"
                    }
                    Ok(_) => {
                        verification.detail.push_str(" sh -n 语法检查通过。");
                        return Ok(verification);
                    }
                    Err(_) => "post-delete `sh -n` check could not run",
                };
                return match self.inner.restore().await {
                    Ok(()) => Err(CoreError::validation(
                        LINE_DELETE_SYNTAX_REFUSAL,
                        format!("{detail}; original bytes were put back"),
                    )),
                    Err(restore_error) => Err(CoreError::validation(
                        LINE_DELETE_SYNTAX_REFUSAL,
                        format!("{detail}; automatic restore also failed: {restore_error}"),
                    )),
                };
            }
        }
        Ok(verification)
    }

    pub async fn restore(&mut self) -> CoreResult<()> {
        self.inner.restore().await
    }

    /// A verified delete is undoable until the file moves on: the undo first
    /// re-reads it, so a later change is never overwritten by the backup.
    pub fn can_undo(&self) -> bool {
        self.inner.state() == OperationState::Verified
    }

    pub async fn undo(&mut self) -> CoreResult<String> {
        if !self.can_undo() {
            return Err(CoreError::validation(
                "undo",
                "only a completed, verified line deletion can be undone",
            ));
        }
        self.service
            .target
            .validate(&self.inner.definition().target)?;
        let current = self.service.sftp.read_file(&self.sftp, &self.path).await?;
        if content_sha256(&current) != self.deleted_sha256 {
            return Err(CoreError::validation(
                "undo target",
                "target changed after the operation; nothing was undone",
            ));
        }
        self.inner.restore().await?;
        let restored = self.service.sftp.read_file(&self.sftp, &self.path).await?;
        if content_sha256(&restored) == self.original_sha256 {
            Ok(format!(
                "回读：{} 已放回删除前的完整文件，逐字节一致。",
                self.path.as_str()
            ))
        } else {
            Err(CoreError::validation(
                "line delete restore check",
                "放回后复核不一致，请人工检查目标文件与备份",
            ))
        }
    }
}

/// The removed bytes as numbered, display-safe lines — exactly the slice of
/// the preview that will be gone.
fn preview_removed(removed: &[u8], first: u32) -> Vec<PreviewLine> {
    removed
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, chunk)| {
            let body = chunk.strip_suffix(b"\n").unwrap_or(chunk);
            let (text, clipped) = sanitize_preview_line(body);
            PreviewLine {
                number: first + index as u32,
                text,
                clipped,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RemotePath {
        RemotePath::new(value).unwrap()
    }

    #[test]
    fn allow_list_accepts_the_managed_files() {
        for value in [
            "/etc/crontab",
            "/etc/cron.d/lovelyres-backdoor",
            "/etc/cron.d/0hourly",
            "/var/spool/cron/root",
            "/var/spool/cron/crontabs/alice",
            "/var/spool/cron/tabs/alice",
            "/etc/profile",
            "/etc/profile.d/java.sh",
            "/etc/bash.bashrc",
            "/etc/bashrc",
            "/root/.bashrc",
            "/root/.profile",
            "/root/.bash_profile",
            "/home/alice/.bashrc",
            "/home/bob-1/.profile",
            "/home/_svc/.bash_profile",
            "/etc/rc.local",
            "/etc/rc.d/rc.local",
            "/etc/init.d/ssh",
            "/etc/init.d/cron",
            "/root/.vimrc",
            "/root/.exrc",
            "/root/.nanorc",
            "/root/.emacs",
            "/home/alice/.vimrc",
            "/home/bob-1/.nanorc",
            "/etc/vim/vimrc",
            "/etc/vim/vimrc.local",
            "/etc/vimrc",
            "/etc/inetd.conf",
            "/etc/modules",
            "/etc/modules-load.d/blacklist.conf",
        ] {
            assert!(line_delete_path_allowed(&path(value)), "{value}");
        }
    }

    #[test]
    fn allow_list_rejects_everything_else() {
        for value in [
            "/etc/crontab.bak",
            "/etc/cron.d/.hidden",
            "/var/spool/cron/root/extra",
            "/var/spool/cron/.ssh",
            "/etc/profile.d/not-a-script.conf",
            "/etc/profile.d/.hidden.sh",
            "/home/a/b/.bashrc",
            "/home/alice/.zshrc",
            "/root/.zshrc",
            "/root/.vim/plugin/evil.vim",
            "/home/alice/.emacs.d/init.el",
            "/home/alice/.config/nvim/init.vim",
            "/etc/virc",
            "/etc/nanorc",
            "/etc/init.d/.hidden",
            "/etc/modules-load.d/.hidden.conf",
            "/etc/modules-load.d/noext",
            "/etc/xinetd.d/echo",
            "/usr/bin/something",
            "/etc/passwd",
            "/tmp/payload",
            "/var/www/html/shell.php",
        ] {
            assert!(!line_delete_path_allowed(&path(value)), "{value}");
        }
        // A basename slot only ever sees safe characters; anything else means
        // the path never parses into the allow-list shape — most of these do
        // not even make it through RemotePath.
        for value in [
            "/etc/cron.d/x;rm",
            "/etc/init.d/x$(id)",
            "/home/a b/.bashrc",
            "/etc/cron.d/x y",
        ] {
            if let Ok(remote) = RemotePath::new(value) {
                assert!(!line_delete_path_allowed(&remote), "{value}");
            }
        }
    }

    #[test]
    fn delete_removes_exactly_the_range() {
        let content = b"one\ntwo\nthree\nfour\n";
        let deletion = delete_line_range(content, 2, 3).unwrap();
        assert_eq!(deletion.replacement, b"one\nfour\n");
        assert_eq!(deletion.removed, b"two\nthree\n");
    }

    #[test]
    fn delete_handles_first_and_last_lines() {
        let deletion = delete_line_range(b"a\nb\nc\n", 1, 1).unwrap();
        assert_eq!(deletion.replacement, b"b\nc\n");
        let deletion = delete_line_range(b"a\nb\nc\n", 3, 3).unwrap();
        assert_eq!(deletion.replacement, b"a\nb\n");
    }

    #[test]
    fn delete_last_line_without_newline_keeps_the_previous_one() {
        let deletion = delete_line_range(b"a\nb", 2, 2).unwrap();
        assert_eq!(deletion.replacement, b"a\n");
        assert_eq!(deletion.removed, b"b");
        let deletion = delete_line_range(b"a\nb", 1, 2).unwrap();
        assert_eq!(deletion.replacement, b"");
        let deletion = delete_line_range(b"a\nb\r\n", 2, 2).unwrap();
        // The previous line's own CRLF is untouched; the removed line keeps
        // its bytes in the removed set.
        assert_eq!(deletion.replacement, b"a\n");
        assert_eq!(deletion.removed, b"b\r\n");
    }

    #[test]
    fn delete_preserves_untouched_bytes() {
        let content = b"one\r\nt\xffw\x80o\r\nthree\n";
        let deletion = delete_line_range(content, 2, 2).unwrap();
        assert_eq!(deletion.replacement, b"one\r\nthree\n");
        assert_eq!(deletion.removed, b"t\xffw\x80o\r\n");
    }

    #[test]
    fn delete_refuses_out_of_range_ranges() {
        let content = b"one\ntwo\n";
        for (first, last) in [(0, 1), (3, 2), (3, 3), (1, 5)] {
            assert!(
                delete_line_range(content, first, last).is_err(),
                "{first}..{last}"
            );
        }
        // Empty files have no line 1 to delete.
        assert!(delete_line_range(b"", 1, 1).is_err());
        // More than the cap in one go.
        let content = b"x\n".repeat(MAX_DELETE_LINES as usize + 1);
        assert!(delete_line_range(&content, 1, MAX_DELETE_LINES + 1).is_err());
        assert!(delete_line_range(&content, 1, MAX_DELETE_LINES).is_ok());
    }

    #[test]
    fn preview_sanitizes_and_clips() {
        let content = b"clean\nesc\x1b[31m line\ttab\nvery long line\n";
        let preview = preview_lines(content);
        assert_eq!(preview.total_lines, 3);
        assert!(!preview.truncated);
        assert_eq!(preview.lines[0].text, "clean");
        assert_eq!(preview.lines[1].text, "esc [31m line tab");
        assert_eq!(preview.lines[2].text, "very long line");
    }

    #[test]
    fn preview_clips_long_lines_and_marks_them() {
        let long = "x".repeat(MAX_PREVIEW_LINE_CHARS + 40);
        let content = format!("{long}\nshort\n").into_bytes();
        let preview = preview_lines(&content);
        assert!(preview.lines[0].clipped);
        assert_eq!(
            preview.lines[0].text.chars().count(),
            MAX_PREVIEW_LINE_CHARS
        );
        assert!(!preview.lines[1].clipped);
    }

    #[test]
    fn preview_marks_files_past_the_line_cap() {
        let content = b"a\n".repeat(MAX_PREVIEW_LINES + 3);
        let preview = preview_lines(&content);
        assert!(preview.truncated);
        assert_eq!(preview.lines.len(), MAX_PREVIEW_LINES);
        assert_eq!(preview.total_lines, MAX_PREVIEW_LINES as u32 + 3);
    }

    #[test]
    fn preview_counts_a_final_line_without_newline() {
        let preview = preview_lines(b"one\ntwo");
        assert_eq!(preview.total_lines, 2);
        assert_eq!(preview.lines[1].text, "two");
    }
}
