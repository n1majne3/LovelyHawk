//! Minimal MySQL / MariaDB client protocol over an arbitrary async stream.
//!
//! The stream is supplied by the caller (an SSH `direct-tcpip` channel, or the
//! TLS session negotiated on top of it mid-handshake). Only the reviewed
//! handshake, two authentication plugins, `COM_QUERY` text results and
//! OK/ERR/EOF packets are implemented — no prepared statements, no LOCAL
//! INFILE, no multi-statement, no compression.
//!
//! Bounds: every packet payload is capped (`MAX_PACKET_BYTES`), the whole
//! connection carries a finite read/write budget, result sets are capped in
//! columns and rows by the caller, and sequence ids must advance exactly.
//! `DEPRECATE_EOF` is deliberately not set: the classic `0xfe` EOF terminator
//! is unambiguous under the packet cap, while the OK-as-terminator form could
//! be mistaken for a row whose first column is an empty string.

use sha1::{Digest as _, Sha1};
use sha2::{Digest, Sha256};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::crypto::SecretValue;
use crate::error::{CoreError, CoreResult};

pub(crate) const MAX_PACKET_BYTES: usize = 1024 * 1024;
const MAX_READ_BUDGET: usize = 16 * 1024 * 1024;
const MAX_WRITE_BUDGET: usize = 1024 * 1024;
const MAX_AUTH_PLUGIN_LEN: usize = 64;
const MAX_SALT_BYTES: usize = 64;
const MAX_COLUMNS: usize = 64;
const CHARSET_UTF8MB4: u8 = 45;

// Client capability bits (only the ones this driver can request or inspect).
const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

const COM_QUERY: u8 = 0x03;
const COM_QUIT: u8 = 0x01;

const AUTH_NATIVE: &str = "mysql_native_password";
const AUTH_CACHING_SHA2: &str = "caching_sha2_password";

fn invalid(reason: &'static str) -> CoreError {
    CoreError::validation("MySQL wire", reason)
}

/// The stream contract a MySQL session needs: an SSH channel or the TLS
/// session built on it. Boxed so both forms share one code path.
pub(crate) trait MysqlStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> MysqlStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Closed connect-failure classes, mirroring the PostgreSQL native classes so
/// the password-change layer can tell "rejected credentials" apart from "the
/// attempt could not run".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MysqlConnectClass {
    Authentication,
    AccessRule,
    Timeout,
    Other,
}

#[derive(Debug)]
pub(crate) struct MysqlConnectError {
    pub(crate) class: MysqlConnectClass,
    error: CoreError,
}

impl MysqlConnectError {
    fn new(class: MysqlConnectClass, reason: &'static str) -> Self {
        Self {
            class,
            error: invalid(reason),
        }
    }
}

impl From<MysqlConnectError> for CoreError {
    fn from(error: MysqlConnectError) -> Self {
        error.error
    }
}

/// What the server advertised in its HandshakeV10 greeting.
#[derive(Debug, Clone)]
pub(crate) struct ServerGreeting {
    pub(crate) server_version: String,
    pub(crate) connection_id: u32,
    pub(crate) capabilities: u32,
    salt: Vec<u8>,
    auth_plugin: String,
}

pub(crate) struct MysqlConnection {
    stream: Box<dyn MysqlStream>,
    read_left: usize,
    write_left: usize,
    /// Set by the caller that knows whether the stream was TLS-upgraded; the
    /// wire layer only uses it for the caching_sha2 full-auth plaintext rule.
    is_tls: bool,
}

/// Unboxed packet I/O used by the handshake before the stream's final type is
/// known (TLS upgrade consumes the raw stream by value).
struct PacketIo<'a, S> {
    stream: &'a mut S,
    read_left: usize,
    write_left: usize,
}

impl<'a, S: MysqlStream> PacketIo<'a, S> {
    fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            read_left: MAX_READ_BUDGET,
            write_left: MAX_WRITE_BUDGET,
        }
    }
    async fn read_packet(&mut self, expected_seq: u8) -> CoreResult<Zeroizing<Vec<u8>>> {
        let mut header = [0_u8; 4];
        read_budgeted(&mut self.stream, &mut self.read_left, &mut header).await?;
        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
        if header[3] != expected_seq {
            return Err(invalid("数据库返回的报文序号不连续"));
        }
        if length > MAX_PACKET_BYTES || length == 0 {
            return Err(invalid("数据库返回的报文长度超出支持范围"));
        }
        let mut payload = Zeroizing::new(vec![0_u8; length]);
        read_budgeted(&mut self.stream, &mut self.read_left, &mut payload).await?;
        Ok(payload)
    }
    async fn write_packet(&mut self, seq: u8, payload: &[u8]) -> CoreResult<()> {
        write_packet(&mut self.stream, &mut self.write_left, seq, payload).await
    }
}

async fn read_budgeted<S: MysqlStream>(
    stream: &mut S,
    budget: &mut usize,
    out: &mut [u8],
) -> CoreResult<()> {
    if out.len() > *budget {
        return Err(invalid("数据库读取总量超过本次连接上限"));
    }
    *budget -= out.len();
    stream
        .read_exact(out)
        .await
        .map_err(|_| invalid("数据库连接中断或返回了截断的报文"))?;
    Ok(())
}

async fn write_packet<S: MysqlStream>(
    stream: &mut S,
    budget: &mut usize,
    seq: u8,
    payload: &[u8],
) -> CoreResult<()> {
    if payload.len() > MAX_PACKET_BYTES || payload.len() + 4 > *budget {
        return Err(invalid("发送给数据库的报文超过本次连接上限"));
    }
    *budget -= payload.len() + 4;
    let length = (payload.len() as u32).to_le_bytes();
    stream
        .write_all(&[length[0], length[1], length[2], seq])
        .await
        .map_err(|_| invalid("数据库连接写入失败"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|_| invalid("数据库连接写入失败"))
}

impl fmt::Debug for MysqlConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MysqlConnection")
            .field("read_left", &self.read_left)
            .field("tls", &self.is_tls)
            .finish_non_exhaustive()
    }
}

/// A text-protocol result set. Values stay bytes; callers decode.
#[derive(Debug)]
pub(crate) enum QueryResult {
    Rows(Vec<Vec<Option<Vec<u8>>>>),
    Ok { affected_rows: u64 },
}

impl MysqlConnection {
    fn new(stream: Box<dyn MysqlStream>, is_tls: bool) -> Self {
        Self {
            stream,
            read_left: MAX_READ_BUDGET,
            write_left: MAX_WRITE_BUDGET,
            is_tls,
        }
    }

    async fn read_packet(&mut self, expected_seq: u8) -> CoreResult<Zeroizing<Vec<u8>>> {
        let mut header = [0_u8; 4];
        read_budgeted(&mut self.stream, &mut self.read_left, &mut header).await?;
        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
        if header[3] != expected_seq {
            return Err(invalid("数据库返回的报文序号不连续"));
        }
        if length > MAX_PACKET_BYTES || length == 0 {
            return Err(invalid("数据库返回的报文长度超出支持范围"));
        }
        let mut payload = Zeroizing::new(vec![0_u8; length]);
        read_budgeted(&mut self.stream, &mut self.read_left, &mut payload).await?;
        Ok(payload)
    }

    async fn write_packet(&mut self, seq: u8, payload: &[u8]) -> CoreResult<()> {
        write_packet(&mut self.stream, &mut self.write_left, seq, payload).await
    }

    /// A polite close; errors are ignored because the channel is going away.
    pub(crate) async fn quit(&mut self) {
        self.write_left = self.write_left.max(5);
        let _ = self.write_packet(0, &[COM_QUIT]).await;
        let _ = self.stream.shutdown().await;
    }

    /// Run one text-protocol statement. `Err` packets map to a closed error
    /// carrying the numeric code and SQLSTATE class so callers can map
    /// privilege/policy failures without seeing server prose.
    pub(crate) async fn query(&mut self, sql: &[u8]) -> CoreResult<QueryResult> {
        self.write_packet(0, &[&[COM_QUERY], sql].concat()).await?;
        let first = self.read_packet(1).await?;
        match first[0] {
            0xff => Err(err_packet(&first)),
            0xfb => Err(invalid("数据库要求本机文件读取，已拒绝")),
            0x00 => Ok(QueryResult::Ok {
                affected_rows: lenenc_int(&first[1..]).0,
            }),
            _ => {
                let (columns, _) = lenenc_int(&first);
                if columns == 0 || columns > MAX_COLUMNS as u64 {
                    return Err(invalid("数据库返回的列数超出支持范围"));
                }
                for index in 0..columns {
                    let seq = 2_u8.wrapping_add(index as u8);
                    let column = self.read_packet(seq).await?;
                    if column.first() == Some(&0xff) {
                        return Err(err_packet(&column));
                    }
                }
                // Column-definition terminator (classic EOF because
                // DEPRECATE_EOF is not negotiated).
                let seq = 2_u8.wrapping_add(columns as u8);
                self.expect_eof(seq).await?;
                let mut rows = Vec::new();
                loop {
                    let seq = seq.wrapping_add(1).wrapping_add(rows.len() as u8);
                    let packet = self.read_packet(seq).await?;
                    match packet.first() {
                        Some(0xff) => return Err(err_packet(&packet)),
                        Some(0xfe) if packet.len() < 9 => {
                            return Ok(QueryResult::Rows(rows));
                        }
                        _ => rows.push(parse_row(&packet, columns as usize)?),
                    }
                }
            }
        }
    }

    async fn expect_eof(&mut self, seq: u8) -> CoreResult<()> {
        let packet = self.read_packet(seq).await?;
        match packet.first() {
            Some(0xff) => Err(err_packet(&packet)),
            Some(0xfe) if packet.len() < 9 => Ok(()),
            _ => Err(invalid("数据库结果集格式不符合约定")),
        }
    }
}

fn lenenc_int(bytes: &[u8]) -> (u64, usize) {
    match bytes.first() {
        Some(0xfb) => (u64::MAX, 1), // NULL marker; callers never feed rows here
        Some(0xfc) if bytes.len() >= 3 => (u16::from_le_bytes([bytes[1], bytes[2]]) as u64, 3),
        Some(0xfd) if bytes.len() >= 4 => {
            let value = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], 0]);
            (value as u64, 4)
        }
        Some(0xfe) if bytes.len() >= 9 => (
            u64::from_le_bytes(bytes[1..9].try_into().expect("8 lenenc bytes")),
            9,
        ),
        Some(value @ 0..=0xfa) => (*value as u64, 1),
        _ => (u64::MAX, 0),
    }
}

fn parse_row(packet: &[u8], columns: usize) -> CoreResult<Vec<Option<Vec<u8>>>> {
    let mut row = Vec::with_capacity(columns);
    let mut offset = 0_usize;
    for _ in 0..columns {
        if offset >= packet.len() {
            return Err(invalid("数据库结果行缺少列值"));
        }
        if packet[offset] == 0xfb {
            row.push(None);
            offset += 1;
            continue;
        }
        let (length, marker) = lenenc_int(&packet[offset..]);
        if marker == 0 || length == u64::MAX {
            return Err(invalid("数据库结果行的列长度编码无效"));
        }
        offset += marker;
        let end = offset
            .checked_add(length as usize)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| invalid("数据库结果行的列长度越界"))?;
        row.push(Some(packet[offset..end].to_vec()));
        offset = end;
    }
    if offset != packet.len() {
        return Err(invalid("数据库结果行包含多余字节"));
    }
    Ok(row)
}

/// `0xff` ERR packet → a closed error carrying errno + sqlstate only.
fn err_packet(packet: &[u8]) -> CoreError {
    if packet.len() < 3 || packet[0] != 0xff {
        return invalid("数据库返回了无法识别的错误报文");
    }
    let errno = u16::from_le_bytes([packet[1], packet[2]]);
    let sqlstate = if packet.len() >= 9 && packet[3] == b'#' {
        String::from_utf8_lossy(&packet[4..9]).into_owned()
    } else {
        String::new()
    };
    CoreError::validation(
        "MySQL server error",
        format!(
            "数据库拒绝了请求（错误号 {errno}{}）",
            sqlstate_label(&sqlstate)
        ),
    )
}

fn sqlstate_label(sqlstate: &str) -> String {
    if sqlstate.is_empty() {
        return String::new();
    }
    format!("，SQLSTATE {sqlstate}")
}

/// Parse the server greeting. Returns an authentication-class error when the
/// server answered with an ERR packet (e.g. host not allowed to connect).
fn parse_greeting(packet: &[u8]) -> Result<ServerGreeting, MysqlConnectError> {
    if packet.first() == Some(&0xff) {
        let errno = if packet.len() >= 3 {
            u16::from_le_bytes([packet[1], packet[2]])
        } else {
            0
        };
        // 1130/1129/1043 style rejections mean the account's host rule refuses
        // this path entirely; everything else is a plain connect failure.
        let class = if matches!(errno, 1043 | 1129 | 1130 | 1135) {
            MysqlConnectClass::AccessRule
        } else {
            MysqlConnectClass::Other
        };
        return Err(MysqlConnectError {
            class,
            error: invalid("数据库拒绝了来自当前连接路径的连接"),
        });
    }
    let mut cursor = 0_usize;
    let take = |cursor: &mut usize, count: usize| -> Result<&[u8], MysqlConnectError> {
        let slice = packet.get(*cursor..*cursor + count).ok_or_else(|| {
            MysqlConnectError::new(MysqlConnectClass::Other, "数据库握手报文被截断")
        })?;
        *cursor += count;
        Ok(slice)
    };
    if take(&mut cursor, 1)?[0] != 0x0a {
        return Err(MysqlConnectError::new(
            MysqlConnectClass::Other,
            "数据库握手协议版本不受支持",
        ));
    }
    let version_end = packet
        .iter()
        .skip(cursor)
        .position(|byte| *byte == 0)
        .map(|offset| cursor + offset)
        .ok_or_else(|| {
            MysqlConnectError::new(MysqlConnectClass::Other, "数据库握手缺少版本信息")
        })?;
    let server_version = std::str::from_utf8(&packet[cursor..version_end])
        .map_err(|_| MysqlConnectError::new(MysqlConnectClass::Other, "数据库版本信息无法解码"))?
        .to_owned();
    cursor = version_end + 1;
    let connection_id = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().expect("4 bytes"));
    let mut salt = take(&mut cursor, 8)?.to_vec();
    take(&mut cursor, 1)?; // filler
    let lower = u16::from_le_bytes(take(&mut cursor, 2)?.try_into().expect("2 bytes"));
    let mut capabilities = lower as u32;
    let mut auth_plugin = String::new();
    if cursor < packet.len() {
        take(&mut cursor, 1)?; // charset
        take(&mut cursor, 2)?; // status
        let upper = u16::from_le_bytes(take(&mut cursor, 2)?.try_into().expect("2 bytes"));
        capabilities |= (upper as u32) << 16;
        let auth_len = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
            take(&mut cursor, 1)?[0] as usize
        } else {
            take(&mut cursor, 1)?[0];
            21
        };
        take(&mut cursor, 10)?; // reserved
        let part2_len = auth_len.saturating_sub(8).max(13).min(MAX_SALT_BYTES);
        if let Some(part2) = packet.get(cursor..cursor + part2_len) {
            let usable = part2
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(part2.len());
            salt.extend_from_slice(&part2[..usable.min(part2_len.saturating_sub(1).max(1))]);
            cursor += part2_len.min(packet.len().saturating_sub(cursor));
        }
        if capabilities & CLIENT_PLUGIN_AUTH != 0 && cursor < packet.len() {
            let name_end = packet
                .iter()
                .skip(cursor)
                .position(|byte| *byte == 0)
                .map(|offset| cursor + offset)
                .unwrap_or(packet.len());
            if name_end - cursor > MAX_AUTH_PLUGIN_LEN {
                return Err(MysqlConnectError::new(
                    MysqlConnectClass::Other,
                    "数据库声明的认证方式名称过长",
                ));
            }
            auth_plugin = std::str::from_utf8(&packet[cursor..name_end])
                .unwrap_or("")
                .to_owned();
        }
    }
    salt.truncate(MAX_SALT_BYTES);
    salt.retain(|byte| *byte != 0);
    if capabilities & CLIENT_PROTOCOL_41 == 0 || salt.len() < 8 {
        return Err(MysqlConnectError::new(
            MysqlConnectClass::Other,
            "数据库握手缺少所需的能力位或随机数",
        ));
    }
    Ok(ServerGreeting {
        server_version,
        connection_id,
        capabilities,
        salt,
        auth_plugin,
    })
}

/// Scramble for `mysql_native_password`:
/// `SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))`.
fn native_token(password: &[u8], salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = Sha1::digest(password);
    let stage2 = Sha1::digest(stage1);
    let mut hasher = Sha1::new();
    hasher.update(salt);
    hasher.update(stage2);
    let stage3 = hasher.finalize();
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// Scramble for `caching_sha2_password`:
/// `SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + salt)`.
fn caching_sha2_token(password: &[u8], salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = Sha256::digest(password);
    let stage2 = Sha256::digest(stage1);
    let mut hasher = Sha256::new();
    hasher.update(stage2);
    hasher.update(salt);
    let stage3 = hasher.finalize();
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn auth_token(plugin: &str, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, MysqlConnectError> {
    match plugin {
        AUTH_NATIVE => Ok(native_token(password, salt)),
        AUTH_CACHING_SHA2 => Ok(caching_sha2_token(password, salt)),
        _ => Err(MysqlConnectError::new(
            MysqlConnectClass::Other,
            "数据库要求的认证插件不受支持，请改用 mysql_native_password 或 caching_sha2_password",
        )),
    }
}

/// Build the HandshakeResponse41 payload.
fn handshake_response(
    capabilities: u32,
    username: &str,
    token: &[u8],
    database: Option<&str>,
    plugin: &str,
    ssl: bool,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(64 + username.len() + token.len());
    response.extend_from_slice(&capabilities.to_le_bytes());
    response.extend_from_slice(&(MAX_PACKET_BYTES as u32).to_le_bytes());
    response.push(CHARSET_UTF8MB4);
    response.extend_from_slice(&[0_u8; 23]);
    if !ssl {
        response.extend_from_slice(username.as_bytes());
        response.push(0);
        response.push(token.len() as u8);
        response.extend_from_slice(token);
        if let Some(name) = database {
            response.extend_from_slice(name.as_bytes());
            response.push(0);
        }
        response.extend_from_slice(plugin.as_bytes());
        response.push(0);
    }
    response
}

/// Which TLS behaviour the caller asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MysqlTlsMode {
    /// Require TLS and verify the certificate against the endpoint host.
    VerifyFull,
    /// No database TLS; the SSH channel is the protection (loopback only).
    SshLoopback,
}

/// Performs the whole login on `stream`: greeting → optional TLS upgrade →
/// HandshakeResponse41 → authentication exchange. `upgrade` is invoked with
/// the raw stream when TLS is required and must return the established TLS
/// session boxed as a `MysqlStream`.
pub(crate) async fn connect<S, F, Fut>(
    stream: S,
    host: &str,
    username: &str,
    password: Option<&SecretValue>,
    database: Option<&str>,
    tls: MysqlTlsMode,
    upgrade: F,
) -> Result<MysqlConnection, MysqlConnectError>
where
    S: MysqlStream + 'static,
    F: FnOnce(S) -> Fut,
    Fut: std::future::Future<Output = Result<Box<dyn MysqlStream>, MysqlConnectError>>,
{
    let mut stream = stream;
    let greeting = {
        let mut io = PacketIo::new(&mut stream);
        let packet = io.read_packet(0).await.map_err(|error| MysqlConnectError {
            class: MysqlConnectClass::Other,
            error,
        })?;
        let greeting = parse_greeting(&packet)?;
        let mut capabilities = CLIENT_LONG_PASSWORD
            | CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_TRANSACTIONS;
        if database.is_some() {
            capabilities |= CLIENT_CONNECT_WITH_DB;
        }
        if tls == MysqlTlsMode::VerifyFull {
            if greeting.capabilities & CLIENT_SSL == 0 {
                return Err(MysqlConnectError::new(
                    MysqlConnectClass::Other,
                    "数据库不支持 TLS，无法按所选安全模式连接",
                ));
            }
            // The SSL request shares the HandshakeResponse41 head; the
            // response itself continues the sequence on the TLS channel.
            io.write_packet(
                1,
                &handshake_response(capabilities | CLIENT_SSL, "", &[], None, "", true),
            )
            .await
            .map_err(|error| MysqlConnectError {
                class: MysqlConnectClass::Other,
                error,
            })?;
        }
        (greeting, capabilities)
    };

    let _ = host;
    let (greeting, capabilities) = greeting;
    let plugin = if greeting.auth_plugin.is_empty() {
        AUTH_NATIVE
    } else {
        greeting.auth_plugin.as_str()
    };
    let password_bytes = Zeroizing::new(
        password
            .map(|value| value.expose().as_bytes().to_vec())
            .unwrap_or_default(),
    );
    let token = auth_token(plugin, &password_bytes, &greeting.salt)?;
    let (boxed, is_tls, seq): (Box<dyn MysqlStream>, bool, u8) = match tls {
        MysqlTlsMode::VerifyFull => (upgrade(stream).await?, true, 2),
        MysqlTlsMode::SshLoopback => (Box::new(stream), false, 1),
    };
    let mut connection = MysqlConnection::new(boxed, is_tls);
    connection
        .write_packet(
            seq,
            &handshake_response(capabilities, username, &token, database, plugin, false),
        )
        .await
        .map_err(|error| MysqlConnectError {
            class: MysqlConnectClass::Other,
            error,
        })?;
    finish_auth(&mut connection, &password_bytes, seq + 1).await?;
    Ok(connection)
}

/// Drive the authentication exchange to the final OK: plugin switches,
/// caching_sha2 fast/full rounds, and the refusal of insecure full auth.
async fn finish_auth(
    connection: &mut MysqlConnection,
    password: &[u8],
    mut seq: u8,
) -> Result<(), MysqlConnectError> {
    for _ in 0..4 {
        let packet = connection
            .read_packet(seq)
            .await
            .map_err(|error| MysqlConnectError {
                class: MysqlConnectClass::Other,
                error,
            })?;
        match packet.first() {
            Some(0x00) => return Ok(()),
            Some(0xff) => {
                let errno = if packet.len() >= 3 {
                    u16::from_le_bytes([packet[1], packet[2]])
                } else {
                    0
                };
                let class = match errno {
                    1045 => MysqlConnectClass::Authentication,
                    1130 | 1129 | 1044 | 1043 => MysqlConnectClass::AccessRule,
                    _ => MysqlConnectClass::Other,
                };
                return Err(MysqlConnectError {
                    class,
                    error: invalid("数据库拒绝了登录，请核对账号、口令与访问来源"),
                });
            }
            Some(0x01) => {
                // caching_sha2_password AuthMoreData.
                let Some(&step) = packet.get(1) else {
                    return Err(MysqlConnectError::new(
                        MysqlConnectClass::Other,
                        "数据库认证附加报文缺少步骤标识",
                    ));
                };
                match step {
                    // Fast path accepted; the real OK follows.
                    0x03 => {
                        seq = seq.wrapping_add(1);
                        continue;
                    }
                    // Full auth: send the password only over a secured link.
                    0x04 => {
                        if !connection.is_tls() {
                            return Err(MysqlConnectError::new(
                                MysqlConnectClass::Other,
                                "数据库要求完整口令认证；未加密连接不发送明文，请启用数据库 TLS",
                            ));
                        }
                        seq = seq.wrapping_add(1);
                        let mut clear = Zeroizing::new(password.to_vec());
                        clear.push(0);
                        connection
                            .write_packet(seq, &clear)
                            .await
                            .map_err(|error| MysqlConnectError {
                                class: MysqlConnectClass::Other,
                                error,
                            })?;
                        seq = seq.wrapping_add(1);
                        continue;
                    }
                    _ => {
                        return Err(MysqlConnectError::new(
                            MysqlConnectClass::Other,
                            "数据库要求的认证步骤不受支持",
                        ));
                    }
                }
            }
            Some(0xfe) if packet.len() > 1 => {
                // AuthSwitchRequest: plugin name NUL + new salt.
                let name_end = packet
                    .iter()
                    .skip(1)
                    .position(|byte| *byte == 0)
                    .map(|offset| offset + 1)
                    .ok_or_else(|| {
                        MysqlConnectError::new(
                            MysqlConnectClass::Other,
                            "数据库认证切换报文缺少插件名",
                        )
                    })?;
                if name_end - 1 > MAX_AUTH_PLUGIN_LEN {
                    return Err(MysqlConnectError::new(
                        MysqlConnectClass::Other,
                        "数据库要求切换的认证插件名称过长",
                    ));
                }
                let current_plugin = std::str::from_utf8(&packet[1..name_end])
                    .map_err(|_| {
                        MysqlConnectError::new(
                            MysqlConnectClass::Other,
                            "数据库要求切换的认证插件无法解码",
                        )
                    })?
                    .to_owned();
                let salt: Vec<u8> = packet[name_end + 1..]
                    .iter()
                    .copied()
                    .filter(|byte| *byte != 0)
                    .take(MAX_SALT_BYTES)
                    .collect();
                if salt.len() < 8 {
                    return Err(MysqlConnectError::new(
                        MysqlConnectClass::Other,
                        "数据库认证切换缺少有效随机数",
                    ));
                }
                let token = auth_token(&current_plugin, password, &salt)?;
                seq = seq.wrapping_add(1);
                connection
                    .write_packet(seq, &token)
                    .await
                    .map_err(|error| MysqlConnectError {
                        class: MysqlConnectClass::Other,
                        error,
                    })?;
                seq = seq.wrapping_add(1);
                continue;
            }
            _ => {
                return Err(MysqlConnectError::new(
                    MysqlConnectClass::Other,
                    "数据库认证阶段返回了无法识别的报文",
                ));
            }
        }
    }
    Err(MysqlConnectError::new(
        MysqlConnectClass::Other,
        "数据库认证交换超过轮次上限",
    ))
}

impl MysqlConnection {
    /// Whether this session runs inside a negotiated TLS stream. The wire
    /// layer only decides the full-auth plaintext policy from it.
    pub(crate) fn is_tls(&self) -> bool {
        self.is_tls
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(payload.len() + 4);
        let length = (payload.len() as u32).to_le_bytes();
        bytes.extend_from_slice(&length[..3]);
        bytes.push(seq);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn native_token_matches_reference_vector() {
        // Reference: mysql_native_password for "secret" with a fixed salt,
        // recomputed step by step (documented formula, not a magic constant).
        let password = b"secret";
        let salt = b"12345678901234567890";
        let stage1 = Sha1::digest(password);
        let stage2 = Sha1::digest(stage1);
        let mut hasher = Sha1::new();
        hasher.update(salt);
        hasher.update(stage2);
        let stage3 = hasher.finalize();
        let expected: Vec<u8> = stage1
            .iter()
            .zip(stage3.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(native_token(password, salt), expected);
        assert_eq!(native_token(password, salt).len(), 20);
        assert!(native_token(b"", salt).is_empty());
    }

    #[test]
    fn caching_sha2_token_matches_reference_formula() {
        let password = b"secret";
        let salt = b"12345678901234567890";
        let stage1 = Sha256::digest(password);
        let stage2 = Sha256::digest(stage1);
        let mut hasher = Sha256::new();
        hasher.update(stage2);
        hasher.update(salt);
        let stage3 = hasher.finalize();
        let expected: Vec<u8> = stage1
            .iter()
            .zip(stage3.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(caching_sha2_token(password, salt), expected);
        assert_eq!(caching_sha2_token(password, salt).len(), 32);
        assert!(caching_sha2_token(b"", salt).is_empty());
    }

    #[test]
    fn greeting_parses_mysql8_layout() {
        let mut payload = vec![0x0a];
        payload.extend_from_slice(b"8.0.36\0");
        payload.extend_from_slice(&42_u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0);
        payload.extend_from_slice(&0xf7ff_u16.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&0x0002_u16.to_le_bytes());
        payload.extend_from_slice(&0xdfff_u16.to_le_bytes());
        payload.push(21);
        payload.extend_from_slice(&[0_u8; 10]);
        payload.extend_from_slice(b"901234567890\0");
        payload.extend_from_slice(b"caching_sha2_password\0");
        let greeting = parse_greeting(&payload).expect("greeting");
        assert_eq!(greeting.server_version, "8.0.36");
        assert_eq!(greeting.connection_id, 42);
        assert_eq!(greeting.auth_plugin, "caching_sha2_password");
        assert_eq!(greeting.salt.len(), 20);
    }

    #[test]
    fn greeting_err_packet_maps_host_refusals() {
        let mut payload = vec![0xff];
        payload.extend_from_slice(&1130_u16.to_le_bytes());
        payload.extend_from_slice(b"#HY000");
        payload.extend_from_slice(b"Host 'x' is not allowed");
        let error = parse_greeting(&payload).unwrap_err();
        assert_eq!(error.class, MysqlConnectClass::AccessRule);
    }

    #[test]
    fn lenenc_and_row_parsing_are_exact() {
        assert_eq!(lenenc_int(&[0xfa]), (250, 1));
        assert_eq!(lenenc_int(&[0xfc, 0x00, 0x01]), (256, 3));
        assert_eq!(lenenc_int(&[0xfd, 0x00, 0x00, 0x01]), (65536, 4));
        let row = [0x03, b'a', b'b', b'c', 0xfb, 0x02, b'o', b'k'];
        assert_eq!(
            parse_row(&row, 3).unwrap(),
            vec![Some(b"abc".to_vec()), None, Some(b"ok".to_vec()),]
        );
        assert!(parse_row(&row[..6], 3).is_err());
        assert!(parse_row(&[0x05, b'a'], 1).is_err());
    }

    #[tokio::test]
    async fn err_packet_carries_errno_and_sqlstate_not_prose() {
        let mut payload = vec![0xff];
        payload.extend_from_slice(&1045_u16.to_le_bytes());
        payload.extend_from_slice(b"#28000");
        payload.extend_from_slice(b"Access denied for user 'root'@'localhost'");
        let error = err_packet(&payload);
        let text = format!("{error}");
        assert!(text.contains("1045"), "{text}");
        assert!(text.contains("28000"), "{text}");
        assert!(!text.contains("Access denied"), "{text}");
    }

    #[tokio::test]
    async fn read_packet_enforces_sequence_and_budget() {
        let (client, mut server) = duplex(256);
        server.write_all(&packet(0, b"hello")).await.unwrap();
        server.write_all(&packet(7, b"world")).await.unwrap();
        let mut connection = MysqlConnection::new(Box::new(client), false);
        assert_eq!(&*connection.read_packet(0).await.unwrap(), b"hello");
        assert!(connection.read_packet(1).await.is_err());
    }
}
