//! Classic SCP fallback for targets that run no `Subsystem sftp` line.
//!
//! When the subsystem handshake fails, the transfer requests that only need
//! bytes — download, upload, evidence collection — degrade to the wire
//! protocol every remote `scp -f` / `scp -t` still speaks: one `C` header,
//! the payload, and NUL acknowledgements. Everything else (listing, rename,
//! chmod, atomic write) keeps reporting the subsystem gap instead of being
//! re-implemented over shell commands with different semantics.
//!
//! The remote command is a shell line, so the path reaches `scp` through
//! [`shq`]; the wire side is a strict state machine, not text scraping:
//! anything the remote emits that is not a `T`, `C`, `D`, `E`, or a numbered
//! error record aborts the transfer.

use std::collections::VecDeque;

use crate::shell_escape::shq;
use crate::{CoreError, CoreResult};

/// The operation tag every SCP failure carries; "request SFTP subsystem" and
/// `SFTP_HANDSHAKE_OPERATION` in ssh.rs name the failure that triggers the
/// fallback, this names the fallback itself.
pub(crate) const SCP_TRANSFER_OPERATION: &str = "classic SCP transfer";

const MAX_SCP_LINE_BYTES: usize = 8 * 1024;
const MAX_SCP_NAME_BYTES: usize = 255;
const STDERR_TAIL_BYTES: usize = 4 * 1024;

/// What the remote scp process may send down an exec channel.
pub(crate) enum ScpIoEvent {
    Data(Vec<u8>),
    Stderr(Vec<u8>),
    /// The channel ended (remote exited); `exit_status` carries the code if
    /// the peer reported one before closing.
    Eof,
}

/// The bidirectional slice of an exec channel the protocol drives. Kept as a
/// trait so the state machine is unit-tested against scripted peers instead
/// of a live SSH session.
pub(crate) trait ScpIo {
    async fn next(&mut self) -> CoreResult<ScpIoEvent>;
    async fn write(&mut self, bytes: &[u8]) -> CoreResult<()>;
    /// EOF on the remote's stdin: after an upload's last record the remote
    /// `scp -t` exits once stdin ends, so the channel must half-close.
    async fn send_eof(&mut self) -> CoreResult<()>;
    /// Exit status the peer reported, once it did.
    fn exit_status(&self) -> Option<u32>;
}

/// Where downloaded bytes go; the caller decides whether they land in a
/// file, a hasher, or both.
pub(crate) trait ScpSink {
    async fn write(&mut self, bytes: &[u8]) -> CoreResult<()>;
    async fn finish(&mut self) -> CoreResult<()>;
}

impl ScpSink for Vec<u8> {
    async fn write(&mut self, bytes: &[u8]) -> CoreResult<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
    async fn finish(&mut self) -> CoreResult<()> {
        Ok(())
    }
}

/// The `C` record the remote advertised, checked but not trusted: `name` is
/// informational only (the caller chooses the local name it writes to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScpFileHeader {
    pub mode: u32,
    pub bytes: u64,
    pub name: String,
}

fn scp_error(message: impl Into<String>) -> CoreError {
    CoreError::ssh(SCP_TRANSFER_OPERATION, message)
}

/// The command line that asks the remote scp to source one file. `--` keeps
/// dash-leading absolute paths literal; `shq` keeps everything else literal.
/// `program` is the binary the availability probe found.
pub(crate) fn scp_source_command(program: &str, path: &str) -> String {
    format!("{} -qf -- {}", shq(program), shq(path))
}

/// The command line that asks the remote scp to accept one file into `dir`.
/// The caller guarantees `dir` is a directory and the file name travels in
/// the `C` record, so a dash-or-space containing directory stays exact.
pub(crate) fn scp_sink_command(program: &str, directory: &str) -> String {
    format!("{} -qt -- {}", shq(program), shq(directory))
}

/// Whether the remote offers an `scp` binary at all; the answer is the
/// absolute path to run, or empty when neither PATH nor the usual locations
/// have one.
pub(crate) fn scp_probe_command() -> &'static str {
    "for c in scp /usr/bin/scp /usr/local/bin/scp /bin/scp /usr/libexec/scp; do if command -v \"$c\" >/dev/null 2>&1 || [ -x \"$c\" ]; then command -v \"$c\" 2>/dev/null || echo \"$c\"; break; fi; done"
}

/// What [`scp_probe_command`] printed, reduced to the one safe thing it may
/// be: a single line naming `scp` or an absolute path ending in `scp`. The
/// remote writes this text, so it is a whitelist, never trusted structure.
pub(crate) fn parse_scp_probe(output: &str) -> Option<String> {
    let line = output.trim().lines().next()?.trim();
    let plausible = line == "scp"
        || (line.starts_with('/')
            && line.ends_with("/scp")
            && line.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.')
            }));
    plausible.then(|| line.to_owned())
}

/// Metadata one `stat`/`readlink` probe returns when SFTP is absent; the
/// fields mirror what evidence collection reads off an SFTP handle so the
/// same change-detection checks apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScpRemoteStat {
    pub canonical_path: String,
    pub kind: ScpRemoteKind,
    /// Raw mode including the type bits, matching `Metadata::permissions`.
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub atime: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScpRemoteKind {
    Regular,
    Directory,
    Symlink,
    Other,
    /// `stat` itself failed (missing tool, permission denied); a gap, not a
    /// negative answer.
    Unknown,
}

/// One probe: canonical path, then type, then the raw-mode stat line.
/// `%f` is mode in hex on both GNU coreutils and busybox stat.
pub(crate) fn scp_stat_command(path: &str) -> String {
    let quoted = shq(path);
    format!(
        "c=$(readlink -f -- {quoted} 2>/dev/null) && echo \"LH_CANON $c\" || echo LH_CANON unavailable; \
         if [ -L {quoted} ]; then echo LH_TYPE symlink; \
         elif [ -f {quoted} ]; then echo LH_TYPE regular; \
         elif [ -d {quoted} ]; then echo LH_TYPE directory; \
         else echo LH_TYPE other; fi; \
         stat -c 'LH_ST %f %s %u %g %Y %X' -- {quoted} 2>/dev/null || echo LH_ST unavailable"
    )
}

pub(crate) fn parse_scp_stat(output: &str, path: &str) -> CoreResult<ScpRemoteStat> {
    let mut canonical_path = None;
    let mut kind = None;
    let mut stat_fields = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("LH_CANON ") {
            let value = value.trim();
            canonical_path = (value != "unavailable").then(|| value.to_owned());
        } else if let Some(value) = line.strip_prefix("LH_TYPE ") {
            kind = Some(match value.trim() {
                "regular" => ScpRemoteKind::Regular,
                "directory" => ScpRemoteKind::Directory,
                "symlink" => ScpRemoteKind::Symlink,
                "other" => ScpRemoteKind::Other,
                _ => ScpRemoteKind::Unknown,
            });
        } else if let Some(value) = line.strip_prefix("LH_ST ") {
            stat_fields = Some(value.trim().to_owned());
        }
    }
    let Some(fields) = stat_fields else {
        return Err(scp_error("could not stat the remote path"));
    };
    if fields == "unavailable" {
        return Ok(ScpRemoteStat {
            canonical_path: canonical_path.unwrap_or_default(),
            kind: kind.unwrap_or(ScpRemoteKind::Unknown),
            mode: 0,
            size: 0,
            uid: 0,
            gid: 0,
            mtime: 0,
            atime: 0,
        });
    }
    let fields: Vec<&str> = fields.split_whitespace().collect();
    if fields.len() != 6 {
        return Err(scp_error("unrecognised stat output from the target"));
    }
    let mode = u32::from_str_radix(fields[0], 16)
        .map_err(|_| scp_error("unrecognised stat output from the target"))?;
    let number = |index: usize| -> CoreResult<u64> {
        fields[index]
            .parse::<u64>()
            .map_err(|_| scp_error("unrecognised stat output from the target"))
    };
    Ok(ScpRemoteStat {
        canonical_path: canonical_path.unwrap_or_else(|| path.to_owned()),
        kind: kind.unwrap_or(ScpRemoteKind::Unknown),
        mode,
        size: number(1)?,
        uid: number(2)? as u32,
        gid: number(3)? as u32,
        mtime: number(4)? as u32,
        atime: number(5)? as u32,
    })
}

/// Streamed decode of the source side of the wire. Keeps at most one SSH
/// chunk resident beyond the small line buffer — a 512 MiB file never sits
/// in memory.
struct Wire<'a, I: ScpIo> {
    io: &'a mut I,
    pending: VecDeque<u8>,
    stderr_tail: Vec<u8>,
    eof: bool,
}

impl<'a, I: ScpIo> Wire<'a, I> {
    fn new(io: &'a mut I) -> Self {
        Self {
            io,
            pending: VecDeque::new(),
            stderr_tail: Vec::new(),
            eof: false,
        }
    }

    async fn fill(&mut self) -> CoreResult<()> {
        while self.pending.is_empty() && !self.eof {
            match self.io.next().await? {
                ScpIoEvent::Data(bytes) => self.pending.extend(bytes),
                ScpIoEvent::Stderr(bytes) => {
                    self.stderr_tail.extend_from_slice(&bytes);
                    if self.stderr_tail.len() > STDERR_TAIL_BYTES {
                        let keep = self
                            .stderr_tail
                            .split_off(self.stderr_tail.len() - STDERR_TAIL_BYTES);
                        self.stderr_tail = keep;
                    }
                }
                ScpIoEvent::Eof => self.eof = true,
            }
        }
        Ok(())
    }

    async fn byte(&mut self) -> CoreResult<Option<u8>> {
        self.fill().await?;
        Ok(self.pending.pop_front())
    }

    async fn line(&mut self) -> CoreResult<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            match self.byte().await? {
                Some(b'\n') => return Ok(line),
                Some(byte) => {
                    line.push(byte);
                    if line.len() > MAX_SCP_LINE_BYTES {
                        return Err(scp_error("remote sent an unterminated control record"));
                    }
                }
                None => {
                    return Err(scp_error(match self.stderr_tail.is_empty() {
                        true => "remote closed the channel mid-transfer".to_owned(),
                        false => format!(
                            "remote closed the channel mid-transfer: {}",
                            String::from_utf8_lossy(&self.stderr_tail).trim_end()
                        ),
                    }));
                }
            }
        }
    }

    async fn ack(&mut self) -> CoreResult<()> {
        self.io.write(&[0]).await
    }

    /// Read the peer's answer to a record: `\0` continue, `\x01`/`\x02`
    /// followed by a line is the remote's own error message.
    async fn expect_ack(&mut self) -> CoreResult<()> {
        match self.byte().await? {
            Some(0) => Ok(()),
            Some(1 | 2) => {
                let message = self.line().await?;
                Err(scp_error(format!(
                    "remote refused the transfer: {}",
                    String::from_utf8_lossy(&message)
                )))
            }
            Some(other) => Err(scp_error(format!(
                "remote answered with an unexpected byte {other:#04x}"
            ))),
            None => Err(scp_error("remote closed the channel before answering")),
        }
    }

    async fn drain_closed(&mut self) -> CoreResult<()> {
        self.pending.clear();
        while !self.eof {
            self.fill().await?;
            self.pending.clear();
        }
        match self.io.exit_status() {
            Some(0) | None => Ok(()),
            Some(code) => Err(scp_error(format!(
                "remote scp exited with status {code}{}",
                match self.stderr_tail.is_empty() {
                    true => String::new(),
                    false => format!(
                        ": {}",
                        String::from_utf8_lossy(&self.stderr_tail).trim_end()
                    ),
                }
            ))),
        }
    }
}

fn parse_scp_number(text: &str) -> CoreResult<u64> {
    text.parse::<u64>()
        .map_err(|_| scp_error("remote sent a malformed numeric field"))
}

/// Parse one `C`/`D`/`T` record body. For `C`/`D`: `mode size name`, where
/// the name may itself contain spaces. For `T`: four numbers we do not use
/// but still validate are numbers.
fn parse_file_record(line: &[u8], marker: u8) -> CoreResult<ScpFileHeader> {
    let text = String::from_utf8_lossy(line);
    let mut parts = text.splitn(3, ' ');
    let mode_text = parts.next().unwrap_or_default();
    let size_text = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if mode_text.len() != 4 || !mode_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(scp_error("remote sent a malformed mode field"));
    }
    let mode = u32::from_str_radix(mode_text, 8)
        .map_err(|_| scp_error("remote sent a malformed mode field"))?;
    let bytes = parse_scp_number(size_text)?;
    if name.is_empty()
        || name.len() > MAX_SCP_NAME_BYTES
        || name == "."
        || name == ".."
        || name.contains('/')
    {
        return Err(scp_error(format!(
            "remote sent an unsafe file name in the {} record",
            marker as char
        )));
    }
    Ok(ScpFileHeader {
        mode,
        bytes,
        name: name.to_owned(),
    })
}

/// One single-file `scp -f` transfer: acknowledge the banner, read `T`/`C`
/// records, stream exactly the advertised bytes to `sink`, acknowledge the
/// payload, then drain the channel and insist the remote exited 0.
/// `is_cancelled` is polled between chunks so a cancelled transfer dies
/// with the channel instead of finishing silently.
pub(crate) async fn run_scp_download<I, S>(
    io: &mut I,
    sink: &mut S,
    maximum_bytes: u64,
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> CoreResult<ScpFileHeader>
where
    I: ScpIo,
    S: ScpSink,
{
    let mut wire = Wire::new(io);
    wire.ack().await?;
    let header = loop {
        let Some(marker) = wire.byte().await? else {
            return Err(scp_error(match wire.stderr_tail.is_empty() {
                true => "remote scp produced no file record".to_owned(),
                false => format!(
                    "remote scp produced no file record: {}",
                    String::from_utf8_lossy(&wire.stderr_tail).trim_end()
                ),
            }));
        };
        match marker {
            1 | 2 => {
                let message = wire.line().await?;
                return Err(scp_error(format!(
                    "remote refused the transfer: {}",
                    String::from_utf8_lossy(&message)
                )));
            }
            b'T' => {
                let line = wire.line().await?;
                let text = String::from_utf8_lossy(&line);
                let numbers: Vec<&str> = text.split_whitespace().collect();
                if numbers.len() != 4 || numbers.iter().any(|n| parse_scp_number(n).is_err()) {
                    return Err(scp_error("remote sent a malformed time record"));
                }
                wire.ack().await?;
            }
            b'C' => {
                let header = parse_file_record(&wire.line().await?, b'C')?;
                if header.bytes > maximum_bytes {
                    return Err(scp_error(format!(
                        "remote file exceeds the {maximum_bytes}-byte transfer limit"
                    )));
                }
                wire.ack().await?;
                break header;
            }
            b'D' => {
                let _ = wire.line().await?;
                return Err(scp_error("remote path is a directory, not a file"));
            }
            other => {
                return Err(scp_error(format!(
                    "remote sent an unexpected record byte {other:#04x}"
                )));
            }
        }
    };

    let mut remaining = header.bytes;
    while remaining > 0 {
        if is_cancelled() {
            return Err(CoreError::validation("SCP transfer", "transfer cancelled"));
        }
        wire.fill().await?;
        if wire.pending.is_empty() {
            return Err(scp_error("remote ended the file payload early"));
        }
        let take = remaining.min(wire.pending.len() as u64) as usize;
        let chunk: Vec<u8> = wire.pending.drain(..take).collect();
        sink.write(&chunk).await?;
        remaining -= take as u64;
    }
    // The byte after the payload must be the remote's own NUL.
    match wire.byte().await? {
        Some(0) => {}
        Some(other) => {
            return Err(scp_error(format!(
                "remote sent an unexpected byte {other:#04x} after the payload"
            )));
        }
        None => return Err(scp_error("remote closed the channel inside the payload")),
    }
    wire.ack().await?;
    sink.finish().await?;
    wire.drain_closed().await?;
    Ok(header)
}

/// One single-file `scp -t` transfer: wait for the banner, offer the `C`
/// record, stream the payload, then wait for the remote's own NUL and a
/// clean exit. `header.name` is the file name the remote writes inside the
/// directory it was started on — never a path.
pub(crate) async fn run_scp_upload<I, R>(
    io: &mut I,
    header: &ScpFileHeader,
    source: &mut R,
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> CoreResult<()>
where
    I: ScpIo,
    R: tokio::io::AsyncRead + Unpin,
{
    let mut wire = Wire::new(io);
    wire.expect_ack().await?;
    wire.io
        .write(format!("C{:04o} {} {}\n", header.mode, header.bytes, header.name).as_bytes())
        .await?;
    wire.expect_ack().await?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut sent = 0_u64;
    loop {
        if is_cancelled() {
            return Err(CoreError::validation("SCP transfer", "transfer cancelled"));
        }
        use tokio::io::AsyncReadExt;
        let read = source
            .read(&mut buffer)
            .await
            .map_err(|error| scp_error(format!("could not read the staged upload: {error}")))?;
        if read == 0 {
            break;
        }
        wire.io.write(&buffer[..read]).await?;
        sent += read as u64;
        if sent > header.bytes {
            return Err(scp_error("staged upload grew past its announced size"));
        }
    }
    if sent != header.bytes {
        return Err(scp_error("staged upload shrank below its announced size"));
    }
    wire.ack().await?;
    wire.expect_ack().await?;
    // `scp -t` exits once stdin ends; without the half-close it would sit
    // waiting for another record.
    wire.io.send_eof().await?;
    wire.drain_closed().await?;
    Ok(())
}

/// The base name a remote path must reduce to for an upload `C` record.
/// Returns the pair `(directory, file-name)` the sink command and record
/// need; the workspace only ever stages absolute paths, so anything else —
/// including a trailing slash that meant a directory — is refused.
pub(crate) fn scp_upload_target(path: &str) -> CoreResult<(String, String)> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\0')
        || path.contains('\n')
    {
        return Err(scp_error("upload target is not a usable remote path"));
    }
    let (directory, name) = match path.rfind('/') {
        Some(0) => ("/".to_owned(), &path[1..]),
        Some(index) => (path[..index].to_owned(), &path[index + 1..]),
        None => unreachable!("absolute path always contains a slash"),
    };
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_SCP_NAME_BYTES
        || name.contains('/')
    {
        return Err(scp_error(
            "upload target must name a file inside a directory",
        ));
    }
    Ok((directory, name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque as Queue;

    /// A scripted remote peer: replays output bytes, records what we wrote.
    struct FakeIo {
        incoming: Queue<ScpIoEvent>,
        written: Vec<u8>,
        exit: Option<u32>,
    }

    impl FakeIo {
        fn download(bytes: &[u8]) -> Self {
            Self {
                incoming: Queue::from([ScpIoEvent::Data(bytes.to_vec()), ScpIoEvent::Eof]),
                written: Vec::new(),
                exit: Some(0),
            }
        }
    }

    impl ScpIo for FakeIo {
        async fn next(&mut self) -> CoreResult<ScpIoEvent> {
            Ok(self.incoming.pop_front().unwrap_or(ScpIoEvent::Eof))
        }
        async fn write(&mut self, bytes: &[u8]) -> CoreResult<()> {
            self.written.extend_from_slice(bytes);
            Ok(())
        }
        async fn send_eof(&mut self) -> CoreResult<()> {
            Ok(())
        }
        fn exit_status(&self) -> Option<u32> {
            self.exit
        }
    }

    fn never() -> bool {
        false
    }

    #[tokio::test]
    async fn download_reads_header_payload_and_acks_each_step() {
        let payload = b"hello evidence";
        let mut wire_bytes = Vec::new();
        wire_bytes.extend_from_slice(b"T1700000000 0 1700000000 0\n");
        wire_bytes.extend_from_slice(b"C0644 14 shell.php\n");
        wire_bytes.extend_from_slice(payload);
        wire_bytes.push(0);
        let mut io = FakeIo::download(&wire_bytes);
        let mut sink = Vec::new();
        let header = run_scp_download(&mut io, &mut sink, 1024, &never)
            .await
            .unwrap();
        assert_eq!(header.mode, 0o644);
        assert_eq!(header.bytes, 14);
        assert_eq!(header.name, "shell.php");
        assert_eq!(sink, payload);
        // Start ack, T ack, C ack, payload ack.
        assert_eq!(io.written, vec![0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn download_without_times_record_still_completes() {
        let mut wire_bytes = Vec::new();
        wire_bytes.extend_from_slice(b"C0600 3 a.php\n");
        wire_bytes.extend_from_slice(b"abc");
        wire_bytes.push(0);
        let mut io = FakeIo::download(&wire_bytes);
        let mut sink = Vec::new();
        let header = run_scp_download(&mut io, &mut sink, 1024, &never)
            .await
            .unwrap();
        assert_eq!(header.mode, 0o600);
        assert_eq!(sink, b"abc");
    }

    #[tokio::test]
    async fn download_surfaces_remote_error_and_stderr() {
        let mut io = FakeIo {
            incoming: Queue::from([
                ScpIoEvent::Data(vec![1]),
                ScpIoEvent::Data(b"scp: /x: Permission denied\n".to_vec()),
                ScpIoEvent::Eof,
            ]),
            written: Vec::new(),
            exit: Some(1),
        };
        let mut sink = Vec::new();
        let error = run_scp_download(&mut io, &mut sink, 1024, &never)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Permission denied"));
    }

    #[tokio::test]
    async fn download_rejects_directories_and_size_over_limit() {
        let mut io = FakeIo::download(b"D0755 0 dir\n");
        let mut sink = Vec::new();
        assert!(
            run_scp_download(&mut io, &mut sink, 1024, &never)
                .await
                .unwrap_err()
                .to_string()
                .contains("directory")
        );

        let mut io = FakeIo::download(b"C0644 4096 big.bin\n");
        let mut sink = Vec::new();
        assert!(
            run_scp_download(&mut io, &mut sink, 1024, &never)
                .await
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
    }

    #[tokio::test]
    async fn download_refuses_unsafe_names_and_early_close() {
        for line in [
            b"C0644 1 ../escape\n".as_slice(),
            b"C0644 1 a/b\n".as_slice(),
        ] {
            let mut io = FakeIo::download(line);
            let mut sink = Vec::new();
            assert!(
                run_scp_download(&mut io, &mut sink, 1024, &never)
                    .await
                    .is_err()
            );
        }
        // Payload advertised more than the channel delivers.
        let mut io = FakeIo::download(b"C0644 100 f\nabc");
        let mut sink = Vec::new();
        assert!(
            run_scp_download(&mut io, &mut sink, 1024, &never)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancelled_download_stops_before_finishing() {
        let mut wire_bytes = Vec::new();
        wire_bytes.extend_from_slice(b"C0644 10 f\n");
        wire_bytes.extend_from_slice(b"0123456789");
        wire_bytes.push(0);
        let mut io = FakeIo::download(&wire_bytes);
        let mut sink = Vec::new();
        let cancel = || true;
        assert!(matches!(
            run_scp_download(&mut io, &mut sink, 1024, &cancel).await,
            Err(CoreError::Validation { .. })
        ));
    }

    #[tokio::test]
    async fn upload_emits_record_payload_and_waits_for_acks() {
        // The remote answers \0 to the banner, \0 to the C record, \0 to the
        // payload terminator — staged as Data events.
        let mut io = FakeIo {
            incoming: Queue::from([
                ScpIoEvent::Data(vec![0]),
                ScpIoEvent::Data(vec![0]),
                ScpIoEvent::Data(vec![0]),
                ScpIoEvent::Eof,
            ]),
            written: Vec::new(),
            exit: Some(0),
        };
        let header = ScpFileHeader {
            mode: 0o644,
            bytes: 5,
            name: "note.txt".to_owned(),
        };
        let mut source: &[u8] = b"abcde";
        run_scp_upload(&mut io, &header, &mut source, &never)
            .await
            .unwrap();
        let mut expected = b"C0644 5 note.txt\n".to_vec();
        expected.extend_from_slice(b"abcde");
        expected.push(0);
        assert_eq!(io.written, expected);
    }

    #[tokio::test]
    async fn upload_aborts_on_remote_refusal() {
        let mut io = FakeIo {
            incoming: Queue::from([
                ScpIoEvent::Data(vec![0]),
                ScpIoEvent::Data(vec![2]),
                ScpIoEvent::Data(b"scp: permission denied\n".to_vec()),
                ScpIoEvent::Eof,
            ]),
            written: Vec::new(),
            exit: Some(1),
        };
        let header = ScpFileHeader {
            mode: 0o644,
            bytes: 1,
            name: "x".to_owned(),
        };
        let mut source: &[u8] = b"x";
        assert!(
            run_scp_upload(&mut io, &header, &mut source, &never)
                .await
                .unwrap_err()
                .to_string()
                .contains("permission denied")
        );
    }

    #[test]
    fn upload_target_splits_directory_and_name_safely() {
        assert_eq!(
            scp_upload_target("/var/www/html/pic.jpg").unwrap(),
            ("/var/www/html".to_owned(), "pic.jpg".to_owned())
        );
        assert_eq!(
            scp_upload_target("/x").unwrap(),
            ("/".to_owned(), "x".to_owned())
        );
        for bad in ["/dir/", "rel/file", "/dir/\n", "/dir/..", "/dir/."] {
            assert!(scp_upload_target(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn stat_probe_parses_type_and_mode_fields() {
        let stat = parse_scp_stat(
            "LH_CANON /var/www/html/shell.php\nLH_TYPE regular\nLH_ST 81a4 2048 33 33 1700000001 1700000002\n",
            "/var/www/html/shell.php",
        )
        .unwrap();
        assert_eq!(stat.kind, ScpRemoteKind::Regular);
        assert_eq!(stat.mode, 0x81a4);
        assert_eq!(stat.size, 2048);
        assert_eq!(stat.uid, 33);
        assert_eq!(stat.mtime, 1700000001);
        assert_eq!(stat.canonical_path, "/var/www/html/shell.php");
    }

    #[test]
    fn stat_probe_reports_unknown_instead_of_guessing() {
        let stat = parse_scp_stat(
            "LH_CANON unavailable\nLH_TYPE other\nLH_ST unavailable\n",
            "/x",
        )
        .unwrap();
        assert_eq!(stat.kind, ScpRemoteKind::Other);
        assert!(stat.canonical_path.is_empty());
        let missing = parse_scp_stat("LH_TYPE regular\n", "/x").unwrap_err();
        assert!(missing.to_string().contains("stat"));
    }

    #[test]
    fn wire_names_and_commands_stay_quoted() {
        assert_eq!(
            scp_source_command("scp", "/var/www/it's a.php"),
            "'scp' -qf -- '/var/www/it'\\''s a.php'"
        );
        assert!(scp_sink_command("scp", "/a b").ends_with("'/a b'"));
        assert_eq!(
            scp_source_command("/usr/bin/scp", "/x"),
            "'/usr/bin/scp' -qf -- '/x'"
        );
    }

    #[test]
    fn probe_output_is_whitelisted_to_a_binary_path() {
        assert_eq!(
            parse_scp_probe("/usr/bin/scp\n"),
            Some("/usr/bin/scp".to_owned())
        );
        assert_eq!(parse_scp_probe("scp"), Some("scp".to_owned()));
        assert_eq!(parse_scp_probe(""), None);
        assert_eq!(parse_scp_probe("scp; rm -rf /"), None);
        assert_eq!(parse_scp_probe("/usr/bin/scp -v"), None);
    }
}
