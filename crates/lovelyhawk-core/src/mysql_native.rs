//! Native MySQL / MariaDB sessions over an already authenticated SSH stream.
//!
//! Mirrors the PostgreSQL native layer: the SSH actor hands us a stream and we
//! run the reviewed handshake on it (see `mysql_wire`). TLS policy is identical
//! in spirit: `VerifyFull` negotiates database TLS and verifies the
//! certificate against the endpoint host, optionally with one operator-
//! supplied CA; `SshLoopback` requires a literal loopback destination and
//! sends no plaintext password (caching_sha2 full auth is refused upstream).

use native_tls::{Certificate, Protocol};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    CoreError, CoreResult,
    crypto::SecretValue,
    database::{DatabaseConnection, DatabaseEngine},
    mysql_wire::{
        self, MysqlConnectClass, MysqlConnectError, MysqlConnection, MysqlTlsMode, QueryResult,
    },
};

pub(crate) const MYSQL_NATIVE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CA_BYTES: usize = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MySqlTlsMode {
    #[default]
    VerifyFull,
    /// Requires an explicit literal loopback destination behind the SSH host.
    SshLoopback,
}

impl From<MySqlTlsMode> for MysqlTlsMode {
    fn from(mode: MySqlTlsMode) -> Self {
        match mode {
            MySqlTlsMode::VerifyFull => MysqlTlsMode::VerifyFull,
            MySqlTlsMode::SshLoopback => MysqlTlsMode::SshLoopback,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MySqlTlsSettings {
    #[serde(default)]
    pub mode: MySqlTlsMode,
    /// One public CA certificate. Private keys and extra PEM blocks are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_pem: Option<String>,
}

fn invalid(reason: &'static str) -> CoreError {
    CoreError::validation("MySQL native transport", reason)
}

fn endpoint_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}

fn parse_ca(pem: &str) -> CoreResult<Certificate> {
    if pem.len() > MAX_CA_BYTES {
        return Err(invalid("请提供一份不超过 64 KiB 的 PEM 格式 CA 证书"));
    }
    let pem = pem.trim();
    if !pem.starts_with("-----BEGIN CERTIFICATE-----")
        || !pem.ends_with("-----END CERTIFICATE-----")
        || pem.matches("-----BEGIN ").count() != 1
        || pem.matches("-----END ").count() != 1
        || pem.contains("PRIVATE KEY")
    {
        return Err(invalid("请提供一份不超过 64 KiB 的 PEM 格式 CA 证书"));
    }
    Certificate::from_pem(pem.as_bytes()).map_err(|_| invalid("CA 证书无法解析"))
}

impl MySqlTlsSettings {
    pub fn validate(&self, connection: &DatabaseConnection) -> CoreResult<()> {
        connection.validate()?;
        let host = endpoint_host(&connection.host);
        if host.is_empty()
            || host.contains(['[', ']'])
            || ((connection.host.starts_with('[') || connection.host.ends_with(']'))
                && host.parse::<std::net::Ipv6Addr>().is_err())
        {
            return Err(invalid("请填写有效的数据库主机名或 IP 地址"));
        }
        if connection.engine != DatabaseEngine::Mysql {
            return Err(invalid("TLS 配置只适用于 MySQL / MariaDB 连接"));
        }
        if self.mode == MySqlTlsMode::SshLoopback {
            if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
                return Err(invalid(
                    "仅使用 SSH 保护时，数据库必须位于该 SSH 主机的回环 IP 地址",
                ));
            }
            if self.ca_certificate_pem.is_some() {
                return Err(invalid("未启用数据库 TLS 时不能配置 CA 证书"));
            }
        }
        if let Some(pem) = &self.ca_certificate_pem {
            parse_ca(pem)?;
        }
        Ok(())
    }
}

pub(crate) struct MySqlRuntimeRequest {
    pub(crate) connection: DatabaseConnection,
    pub(crate) tls: MySqlTlsSettings,
    pub(crate) password: Option<SecretValue>,
}

impl fmt::Debug for MySqlRuntimeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlRuntimeRequest")
            .field("tls_mode", &self.tls.mode)
            .finish_non_exhaustive()
    }
}

impl MySqlRuntimeRequest {
    pub(crate) fn new(
        connection: DatabaseConnection,
        tls: MySqlTlsSettings,
        password: Option<SecretValue>,
    ) -> CoreResult<Self> {
        tls.validate(&connection)?;
        if connection
            .username
            .as_deref()
            .is_none_or(|name| name.is_empty() || name.contains('\0') || name.len() > 128)
        {
            return Err(invalid("请填写有效的 MySQL 用户名"));
        }
        if connection
            .database
            .as_deref()
            .is_some_and(|name| name.is_empty() || name.contains('\0') || name.len() > 128)
        {
            return Err(invalid("数据库名称包含不支持的字符"));
        }
        if password.as_ref().is_some_and(|value| {
            value.expose().len() > MAX_PASSWORD_BYTES || value.expose().contains('\0')
        }) {
            return Err(invalid("数据库口令超过长度限制或包含不支持的字符"));
        }
        Ok(Self {
            connection,
            tls,
            password,
        })
    }

    pub(crate) fn host(&self) -> &str {
        endpoint_host(&self.connection.host)
    }
    pub(crate) fn port(&self) -> u16 {
        self.connection.port
    }

    /// Same endpoint under another account's credentials — used by the
    /// password-change login verification.
    pub(crate) fn for_user(
        &self,
        username: &str,
        password: Option<SecretValue>,
    ) -> CoreResult<Self> {
        let mut connection = self.connection.clone();
        connection.username = Some(username.to_owned());
        Self::new(connection, self.tls.clone(), password)
    }
}

/// One authenticated MySQL session. The boxed stream keeps the SSH channel
/// and any TLS session alive; dropping it closes both.
pub(crate) struct MySqlSession {
    inner: MysqlConnection,
}

impl fmt::Debug for MySqlSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlSession").finish_non_exhaustive()
    }
}

impl MySqlSession {
    pub(crate) async fn query(&mut self, sql: &[u8]) -> CoreResult<QueryResult> {
        self.inner.query(sql).await
    }

    /// Convenience for fixed-column text queries: every cell decoded as UTF-8.
    pub(crate) async fn query_rows(
        &mut self,
        sql: &[u8],
        columns: usize,
        maximum_rows: usize,
    ) -> CoreResult<Vec<Vec<Option<String>>>> {
        match self.query(sql).await? {
            QueryResult::Ok { .. } => Err(invalid("数据库检查语句没有返回结果集")),
            QueryResult::Rows(rows) => {
                if rows.len() > maximum_rows {
                    return Err(invalid("数据库检查结果超过读取上限"));
                }
                rows.into_iter()
                    .map(|row| {
                        if row.len() != columns {
                            return Err(invalid("数据库检查结果列数不符合约定"));
                        }
                        row.into_iter()
                            .map(|cell| {
                                cell.map(|bytes| {
                                    String::from_utf8(bytes)
                                        .map_err(|_| invalid("数据库检查返回了无法解码的字段"))
                                })
                                .transpose()
                            })
                            .collect()
                    })
                    .collect()
            }
        }
    }

    pub(crate) async fn quit(mut self) {
        self.inner.quit().await;
    }
}

/// Connect one reviewed session over the supplied stream. `stream` is the SSH
/// `direct-tcpip` channel to the database endpoint; when TLS is required the
/// native-tls upgrade happens inside the MySQL handshake itself.
pub(crate) async fn connect<S>(
    stream: S,
    request: MySqlRuntimeRequest,
) -> Result<MySqlSession, MysqlConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = request.host().to_owned();
    let mode = request.tls.mode;
    let tls_connector = match mode {
        MySqlTlsMode::VerifyFull => {
            let mut builder = native_tls::TlsConnector::builder();
            builder.min_protocol_version(Some(Protocol::Tlsv12));
            if let Some(pem) = &request.tls.ca_certificate_pem {
                builder.add_root_certificate(parse_ca(pem).map_err(|error| {
                    MysqlConnectError::classified(MysqlConnectClass::Other, error)
                })?);
            }
            Some(
                builder
                    .build()
                    .map_err(|_| {
                        MysqlConnectError::classified(
                            MysqlConnectClass::Other,
                            invalid("无法建立数据库 TLS 验证器"),
                        )
                    })
                    .map(tokio_native_tls::TlsConnector::from)?,
            )
        }
        MySqlTlsMode::SshLoopback => None,
    };
    let upgrade_host = host.clone();
    let upgrade = move |raw: S| {
        let connector = tls_connector.expect("TLS mode supplies a connector");
        let host = upgrade_host;
        async move {
            let tls = tokio::time::timeout(MYSQL_NATIVE_TIMEOUT, connector.connect(&host, raw))
                .await
                .map_err(|_| {
                    MysqlConnectError::classified(
                        MysqlConnectClass::Timeout,
                        invalid("数据库 TLS 握手超时"),
                    )
                })?
                .map_err(|_| {
                    MysqlConnectError::classified(
                        MysqlConnectClass::Other,
                        invalid("数据库 TLS 证书或握手未通过验证"),
                    )
                })?;
            Ok(Box::new(tls) as Box<dyn mysql_wire::MysqlStream>)
        }
    };
    let session = tokio::time::timeout(
        MYSQL_NATIVE_TIMEOUT,
        mysql_wire::connect(
            stream,
            &host,
            request.connection.username.as_deref().expect("validated"),
            request.password.as_ref(),
            request.connection.database.as_deref(),
            mode.into(),
            upgrade,
        ),
    )
    .await
    .map_err(|_| {
        MysqlConnectError::classified(MysqlConnectClass::Timeout, invalid("数据库连接或认证超时"))
    })??;
    Ok(MySqlSession { inner: session })
}
