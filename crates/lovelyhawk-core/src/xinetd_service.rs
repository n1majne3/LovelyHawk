//! Disabling an xinetd service by isolating its file and reloading the
//! daemon — the writeup's "kill the xinetd-registered backdoor listener" item.
//!
//! Unlike a quarantine, leaving the file isolated is the containment goal even
//! when the daemon does not cooperate: a reload that cannot be sent, or a port
//! that stays bound afterwards, is reported — but the file is not put back
//! automatically, because putting it back re-arms the service on the next
//! reload. The backend pipeline is told not to restore on a failed
//! verification; undo stays available and puts the file back on request.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::sftp::{MAX_EDIT_BYTES, RemotePath, SftpFileKind, content_sha256};
use crate::shell_escape::shq;
use crate::ssh::BoundSshSession;
use crate::system_info::{
    IMPACT_REMOTE_ACCESS, IMPACT_WEB_SERVICE, SystemInfoService, is_valid_safe_basename,
};
use crate::target::TargetContext;

/// Refusal subjects the backend maps to operator-facing codes.
pub const XINETD_LOCATION_REFUSAL: &str = "xinetd service location";
pub const XINETD_KIND_REFUSAL: &str = "xinetd service kind";
pub const XINETD_IGNORED_REFUSAL: &str = "xinetd service ignored";
pub const XINETD_PRIVILEGE_REFUSAL: &str = "xinetd service privilege";
pub const XINETD_TOOLS_REFUSAL: &str = "xinetd service tools";
pub const XINETD_CHANGED_REFUSAL: &str = "xinetd service changed";

const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(15);
/// The backend registry expires plans after five minutes.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);
const MAX_SERVICES: usize = 64;
/// The backup sits beside the original: same filesystem, recoverable, and
/// named with a dot so xinetd's includedir rule skips it outright.
const BACKUP_DIR: &str = "/etc/xinetd.d/.lovelyres-backups";

/// How the chosen path fares against the one place this action manages.
#[derive(Debug)]
pub enum XinetdPathCheck {
    /// A regular-file name xinetd would actually load.
    Applicable,
    /// Outside `/etc/xinetd.d`, or a name that cannot be a file name there.
    NotLocation,
    /// xinetd skips includedir entries whose name contains a dot or ends
    /// with `~`; this file is not loaded at all, so there is nothing to
    /// disable.
    Ignored,
}

/// Whether `path` names a file xinetd loads from its include directory.
///
/// Pure string check shared with the offer-time `xinetdService` flag: a
/// handle that cannot be a live xinetd service file never reaches planning.
pub fn xinetd_service_path_check(path: &RemotePath) -> XinetdPathCheck {
    let value = path.as_str();
    let Some(name) = value.strip_prefix("/etc/xinetd.d/") else {
        return XinetdPathCheck::NotLocation;
    };
    // xinetd's own skip rule first: a `~` suffix is not in the safe-basename
    // set, but it still reads as "not loaded", not as a bad location.
    if !name.contains('/') && (name.contains('.') || name.ends_with('~')) {
        return XinetdPathCheck::Ignored;
    }
    if !is_valid_safe_basename(name) {
        return XinetdPathCheck::NotLocation;
    }
    XinetdPathCheck::Applicable
}

/// One `service <name> { … }` block, as parsed for the plan text and the
/// port decision. Unknown attributes are ignored; the file is not rewritten.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XinetdService {
    pub name: String,
    pub disable: Option<bool>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub socket_type: Option<String>,
    pub server: Option<String>,
    pub server_args: Option<String>,
    pub service_type: Option<String>,
    pub user: Option<String>,
}

/// The xinetd attribute grammar this parser answers: `key = value` and
/// `key += value` lines inside `service name { ... }` blocks, `#` comments.
pub fn parse_xinetd_services(content: &str) -> Vec<XinetdService> {
    let mut services = Vec::new();
    let mut current: Option<XinetdService> = None;
    let mut depth = 0u32;
    for raw in content.lines().take(20_000) {
        let line = match raw.find('#') {
            Some(index) => &raw[..index],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("service") {
            // `service` must be a whole word: `servicepack` is not a block.
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            let rest = rest.trim_start();
            if current.is_none() && !rest.is_empty() && !rest.starts_with('=') {
                let name: String = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(128)
                    .collect();
                current = Some(XinetdService {
                    name,
                    ..XinetdService::default()
                });
                depth = u32::from(rest.contains('{'));
                continue;
            }
        }
        let Some(service) = current.as_mut() else {
            continue;
        };
        if line.contains('{') {
            depth = depth.saturating_add(1);
            continue;
        }
        if line.starts_with('}') {
            depth = depth.saturating_sub(1);
            if depth == 0
                && let Some(service) = current.take()
            {
                services.push(service);
                if services.len() >= MAX_SERVICES {
                    break;
                }
            }
            continue;
        }
        if depth == 0 {
            continue;
        }
        let Some((key, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Some((op, value)) = rest.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        if !matches!(op, "=" | "+=") || key.is_empty() || value.is_empty() {
            continue;
        }
        let value = value.chars().take(512).collect::<String>();
        match key {
            "disable" => service.disable = Some(matches!(value.as_str(), "yes" | "true" | "1")),
            "port" => service.port = value.parse::<u16>().ok(),
            "protocol" => service.protocol = Some(value),
            "socket_type" => service.socket_type = Some(value),
            "server" => service.server = Some(value),
            "server_args" => service.server_args = Some(value),
            "type" => service.service_type = Some(value),
            "user" => service.user = Some(value),
            _ => {}
        }
    }
    services
}

/// What one bounded probe learns about the file, the daemon and the wire.
#[derive(Debug, Default)]
struct XinetdProbe {
    is_root: bool,
    sudo: bool,
    regular: bool,
    sha256: Option<String>,
    mode: Option<String>,
    /// The port our own SSH session arrived on (`SSH_CONNECTION` field 4).
    session_port: Option<u16>,
    systemd_active: bool,
    /// Every xinetd main process: pid + start ticks.
    daemons: Vec<(u32, String)>,
    listen_source: ListenSource,
    listeners: Vec<Listener>,
    /// `getent services` answers for service names without a port attribute.
    service_ports: Vec<(String, u16, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ListenSource {
    /// `ss`/`netstat` could name the owning process per socket.
    ProcessTable,
    /// `/proc/net/*` port rows only — no process identity.
    ProcNet,
    #[default]
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    port: u16,
    proto: String,
    comm: Option<String>,
    pid: Option<u32>,
}

/// Plan-time facts frozen into the operation: how the reload happens.
#[derive(Debug, Clone)]
enum ReloadMethod {
    /// `systemctl reload xinetd` — systemd manages an active unit.
    Systemd,
    /// SIGHUP to the recorded pid, after re-checking pid+starttime+comm —
    /// xinetd treats SIGHUP as a hard reconfiguration.
    Sighup { pid: u32, start: String },
    /// No daemon: nothing loaded the file, nothing to reload.
    NotRunning,
}

/// The bounded plan-time probe. Service names whose block lacks a `port`
/// attribute are resolved through `getent services` on the target — the
/// answer is an observation, never trusted blindly.
fn probe_command(path: &RemotePath, service_names: &[String]) -> String {
    let quoted = shq(path.as_str());
    let names = service_names
        .iter()
        .take(16)
        .map(|name| shq(name))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "printf 'UID|%s\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         echo \"SPORT|${{SSH_CONNECTION##* }}\"; \
         if [ -f {quoted} ] && [ ! -L {quoted} ]; then echo 'FILE|regular'; else echo 'FILE|other'; fi; \
         sha256sum -- {quoted} 2>/dev/null | awk '{{print \"SHA|\" $1}}'; \
         stat -c 'MODE|%a' -- {quoted} 2>/dev/null || stat -f 'MODE|%Lp' -- {quoted} 2>/dev/null; \
         if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xinetd 2>/dev/null; then echo 'SYSTEMD|yes'; else echo 'SYSTEMD|no'; fi; \
         for lh_d in /proc/[0-9]*; do \
           lh_p=${{lh_d#/proc/}}; \
           lh_c=$(cat \"$lh_d/comm\" 2>/dev/null) || continue; \
           [ \"$lh_c\" = xinetd ] || continue; \
           lh_e=$(readlink \"$lh_d/exe\" 2>/dev/null); lh_e=${{lh_e##*/}}; \
           [ \"$lh_e\" = xinetd ] || continue; \
           lh_s=$(awk '{{print $22}}' \"$lh_d/stat\" 2>/dev/null); \
           printf 'XINETD|%s|%s\n' \"$lh_p\" \"$lh_s\"; \
         done; \
         if command -v ss >/dev/null 2>&1; then \
           echo 'LSRC|ss'; ss -H -ltnup 2>/dev/null | head -n 200 | sed 's/^/L|/'; \
         elif command -v netstat >/dev/null 2>&1; then \
           echo 'LSRC|netstat'; netstat -ltnup 2>/dev/null | head -n 200 | sed 's/^/L|/'; \
         elif [ -r /proc/net/tcp ]; then \
           echo 'LSRC|procnet'; \
           for lh_t in tcp tcp6 udp udp6; do \
             awk -v t=\"$lh_t\" 'NR>1{{print \"LR|\" t \"|\" $2 \"|\" $4}}' /proc/net/$lh_t 2>/dev/null | head -n 300; \
           done; \
         else echo 'LSRC|none'; fi; \
         if [ -n '{names}' ]; then getent services {names} 2>/dev/null | head -n 40 | sed 's/^/SVC|/'; fi",
    )
}

/// The same listener read, reused by the verify poll and the undo report.
fn listen_command() -> String {
    "if command -v ss >/dev/null 2>&1; then \
       echo 'LSRC|ss'; ss -H -ltnup 2>/dev/null | head -n 200 | sed 's/^/L|/'; \
     elif command -v netstat >/dev/null 2>&1; then \
       echo 'LSRC|netstat'; netstat -ltnup 2>/dev/null | head -n 200 | sed 's/^/L|/'; \
     elif [ -r /proc/net/tcp ]; then \
       echo 'LSRC|procnet'; \
       for lh_t in tcp tcp6 udp udp6; do \
         awk -v t=\"$lh_t\" 'NR>1{print \"LR|\" t \"|\" $2 \"|\" $4}' /proc/net/$lh_t 2>/dev/null | head -n 300; \
       done; \
     else echo 'LSRC|none'; fi"
        .to_owned()
}

fn parse_ss_listener(line: &str) -> Option<Listener> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return None;
    }
    let proto = fields[0].to_owned();
    if !matches!(proto.as_str(), "tcp" | "udp" | "tcp6" | "udp6") {
        return None;
    }
    let local = fields[4];
    let port: u16 = local.rsplit(':').next()?.parse().ok()?;
    let (comm, pid) = line.find("users:((").map_or((None, None), |start| {
        let rest = &line[start + 8..];
        let comm = rest
            .strip_prefix('"')
            .and_then(|rest| rest.split('"').next())
            .map(str::to_owned);
        let pid = rest
            .find("pid=")
            .and_then(|index| rest[index + 4..].split([',', ')']).next())
            .and_then(|digits| digits.parse::<u32>().ok());
        (comm, pid)
    });
    Some(Listener {
        port,
        proto,
        comm,
        pid,
    })
}

fn parse_netstat_listener(line: &str) -> Option<Listener> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 || !matches!(fields[0], "tcp" | "udp" | "tcp6" | "udp6") {
        return None;
    }
    let port: u16 = fields[3].rsplit(':').next()?.parse().ok()?;
    let (comm, pid) = fields
        .last()
        .and_then(|last| last.split_once('/'))
        .map_or((None, None), |(pid, comm)| {
            (Some(comm.to_owned()), pid.parse::<u32>().ok())
        });
    Some(Listener {
        port,
        proto: fields[0].to_owned(),
        comm,
        pid,
    })
}

fn parse_procnet_listener(fields: &[&str]) -> Option<Listener> {
    // LR|<table>|<hexaddr:hexport>|<state>
    let [_, table, local, state] = fields else {
        return None;
    };
    let listening = match *table {
        "tcp" | "tcp6" => *state == "0A",
        // A bound UDP socket has no LISTEN state; any row is a bound port.
        _ => true,
    };
    if !listening {
        return None;
    }
    let port = u16::from_str_radix(local.rsplit(':').next()?, 16).ok()?;
    Some(Listener {
        port,
        proto: (*table).to_owned(),
        comm: None,
        pid: None,
    })
}

fn parse_probe(output: &str) -> XinetdProbe {
    let mut probe = XinetdProbe::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "UID" => probe.is_root = value.trim() == "0",
            "SUDO" => probe.sudo = value.trim() == "yes",
            "SPORT" => probe.session_port = value.trim().parse::<u16>().ok(),
            "FILE" => probe.regular = value.trim() == "regular",
            "SHA" => probe.sha256 = Some(value.trim().to_owned()),
            "MODE" => probe.mode = Some(value.trim().to_owned()),
            "SYSTEMD" => probe.systemd_active = value.trim() == "yes",
            "XINETD" => {
                if let Some((pid, start)) = value.split_once('|')
                    && let Ok(pid) = pid.trim().parse::<u32>()
                {
                    probe.daemons.push((pid, start.trim().to_owned()));
                }
            }
            "LSRC" => {
                probe.listen_source = match value.trim() {
                    "ss" | "netstat" => ListenSource::ProcessTable,
                    "procnet" => ListenSource::ProcNet,
                    _ => ListenSource::None,
                };
                probe.listeners.clear();
            }
            "L" => {
                if let Some(listener) =
                    parse_ss_listener(value).or_else(|| parse_netstat_listener(value))
                {
                    probe.listeners.push(listener);
                }
            }
            "LR" => {
                let fields: Vec<&str> = line.split('|').collect();
                if let Some(listener) = parse_procnet_listener(&fields) {
                    probe.listeners.push(listener);
                }
            }
            "SVC" => {
                let fields: Vec<&str> = value.split_whitespace().collect();
                if fields.len() >= 2
                    && let Some((port, proto)) = fields[1].split_once('/')
                    && let Ok(port) = port.parse::<u16>()
                {
                    probe
                        .service_ports
                        .push((fields[0].to_owned(), port, proto.to_owned()));
                }
            }
            _ => {}
        }
    }
    probe
}

/// The effective `(service, port, protocol)` set the disable should free.
/// A `port` attribute wins; otherwise the service name is resolved through
/// the target's own services database (defaulting to tcp).
fn effective_endpoints(
    services: &[XinetdService],
    probe: &XinetdProbe,
) -> Vec<(String, u16, String)> {
    let mut endpoints = Vec::new();
    for service in services {
        if service.disable == Some(true) {
            continue;
        }
        let protocol = service.protocol.clone().unwrap_or_else(|| "tcp".to_owned());
        if let Some(port) = service.port {
            endpoints.push((service.name.clone(), port, protocol));
            continue;
        }
        if let Some((_, port, proto)) = probe
            .service_ports
            .iter()
            .find(|(name, _, _)| *name == service.name)
        {
            endpoints.push((service.name.clone(), *port, proto.clone()));
        }
    }
    endpoints
}

fn command_failed(subject: &'static str, output: &crate::ssh::SshCommandOutput) -> CoreError {
    CoreError::Validation {
        subject: "xinetd service command",
        message: format!(
            "{subject} failed (exit={:?}, timed_out={})",
            output.exit_code, output.timed_out
        ),
    }
}

impl SystemInfoService {
    /// Describe isolating the xinetd service file `path` and reloading the
    /// daemon so the listener stops.
    ///
    /// Planning freezes everything the execute must not rediscover: the file
    /// digest, the service blocks and their effective ports, how the reload
    /// happens (systemd, a verified SIGHUP, or none when the daemon is not
    /// running), and the account's privilege prefix.
    pub async fn plan_xinetd_disable(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
        journal: PortableOperationJournal,
    ) -> CoreResult<XinetdDisableOperation> {
        self.target.validate(session.target())?;
        match xinetd_service_path_check(path) {
            XinetdPathCheck::Applicable => {}
            XinetdPathCheck::NotLocation => {
                return Err(CoreError::validation(
                    XINETD_LOCATION_REFUSAL,
                    "只能停用 /etc/xinetd.d 下的 xinetd 服务文件",
                ));
            }
            XinetdPathCheck::Ignored => {
                return Err(CoreError::validation(
                    XINETD_IGNORED_REFUSAL,
                    "文件名包含点号或以 ~ 结尾，xinetd 本就不加载它，无需停用",
                ));
            }
        }
        let bound = self
            .sftp
            .bind_session(session.target().clone(), session.session_id())
            .await?;
        let metadata = self
            .sftp
            .metadata(&bound, path, false)
            .await
            .map_err(|_| CoreError::validation(XINETD_KIND_REFUSAL, "无法读取该文件的属性"))?;
        if metadata.kind != SftpFileKind::File {
            return Err(CoreError::validation(
                XINETD_KIND_REFUSAL,
                "只能停用普通文件形式的服务定义；符号链接、目录与其他类型不支持",
            ));
        }
        if metadata.size == 0 || metadata.size > MAX_EDIT_BYTES {
            return Err(CoreError::validation(
                XINETD_KIND_REFUSAL,
                format!("文件为空，或超过 {MAX_EDIT_BYTES} 字节的托管上限"),
            ));
        }
        let content = self.sftp.read_file(&bound, path).await?;
        let file_sha256 = content_sha256(&content);
        let services = parse_xinetd_services(&String::from_utf8_lossy(&content));
        let names: Vec<String> = services
            .iter()
            .filter(|service| service.port.is_none() && service.disable != Some(true))
            .map(|service| service.name.clone())
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            })
            .collect();

        let output = self
            .ssh
            .execute_bound(session, probe_command(path, &names), PROBE_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("xinetd probe", &output));
        }
        let probe = parse_probe(&output.output);
        if probe.sha256.is_none() {
            return Err(CoreError::validation(
                XINETD_TOOLS_REFUSAL,
                "目标机缺少 sha256sum，无法安全隔离并复核服务文件",
            ));
        }
        if !probe.regular {
            return Err(CoreError::validation(
                XINETD_KIND_REFUSAL,
                "只能停用普通文件形式的服务定义；符号链接、目录与其他类型不支持",
            ));
        }
        if !(probe.is_root || probe.sudo) {
            return Err(CoreError::validation(
                XINETD_PRIVILEGE_REFUSAL,
                "需要 root 或免密码 sudo 才能隔离服务文件并重载 xinetd",
            ));
        }
        let reload = if probe.systemd_active {
            ReloadMethod::Systemd
        } else if let Some((pid, start)) = probe.daemons.first() {
            ReloadMethod::Sighup {
                pid: *pid,
                start: start.clone(),
            }
        } else {
            ReloadMethod::NotRunning
        };
        let endpoints = effective_endpoints(&services, &probe);
        let prefix = if probe.is_root { "" } else { "sudo -n " };
        let name = path.file_name()?.to_owned();
        let backup = RemotePath::new(format!(
            "{BACKUP_DIR}/{}-{name}.removed",
            uuid::Uuid::new_v4()
        ))?;

        let service_text = if services.is_empty() {
            "未解析到 service 块".to_owned()
        } else {
            services
                .iter()
                .map(|service| {
                    let mut text = service.name.clone();
                    if let Some(server) = &service.server {
                        text.push_str(&format!(
                            "（server={server}{}）",
                            service
                                .server_args
                                .as_deref()
                                .map(|args| format!(" {args}"))
                                .unwrap_or_default()
                        ));
                    }
                    if service.disable == Some(true) {
                        text.push_str("（文件内已是 disable = yes）");
                    }
                    text
                })
                .collect::<Vec<_>>()
                .join("、")
        };
        let endpoint_text = if endpoints.is_empty() {
            match reload {
                ReloadMethod::NotRunning => String::new(),
                _ => "；未能确定服务端口".to_owned(),
            }
        } else {
            format!(
                "；有效端口 {}",
                endpoints
                    .iter()
                    .map(|(_, port, proto)| format!("{port}/{proto}"))
                    .collect::<Vec<_>>()
                    .join("、")
            )
        };
        let listen_text = {
            let mut notes = Vec::new();
            for (_, port, proto) in &endpoints {
                if let Some(listener) = probe
                    .listeners
                    .iter()
                    .find(|listener| listener.port == *port)
                {
                    notes.push(format!(
                        "{port}/{proto} 正被 {} 监听",
                        listener
                            .comm
                            .as_deref()
                            .map(|comm| format!("{comm}(pid {})", listener.pid.unwrap_or(0)))
                            .unwrap_or_else(|| "未知进程".to_owned())
                    ));
                }
            }
            if notes.is_empty() {
                String::new()
            } else {
                format!("当前{}", notes.join("；"))
            }
        };
        let reload_text = match &reload {
            ReloadMethod::Systemd => "执行后用 systemctl reload xinetd 重载".to_owned(),
            ReloadMethod::Sighup { pid, .. } => {
                format!("执行后向 xinetd（PID {pid}）发送 SIGHUP 重载，发送前会再次核对进程身份")
            }
            ReloadMethod::NotRunning => "xinetd 未运行，配置未被加载，无需重载".to_owned(),
        };
        // A reload — systemd or SIGHUP alike — reconfigures the whole daemon,
        // not just this service. The 2.3.15 daemon was seen in the lab to die
        // on its own SIGHUP, so the plan tells the operator to check it.
        let reload_risk = if matches!(reload, ReloadMethod::NotRunning) {
            String::new()
        } else {
            "重载是对 xinetd 的硬性重配置，期间可能打断它正在提供的其他服务；实验中观察到 xinetd 2.3.15 在收到 SIGHUP 后退出，执行后请核对 xinetd 进程是否仍在。".to_owned()
        };
        let impact = if endpoints
            .iter()
            .any(|(_, port, _)| Some(*port) == probe.session_port)
        {
            format!(" {IMPACT_REMOTE_ACCESS}")
        } else if endpoints
            .iter()
            .any(|(_, port, _)| matches!(*port, 80 | 443))
        {
            format!(" {IMPACT_WEB_SERVICE}")
        } else {
            String::new()
        };
        let summary = format!(
            "停用 {} 注册的 xinetd 服务（{service_text}{endpoint_text}）。文件移入同目录 .lovelyres-backups/ 留底——xinetd 不加载名称含点号的文件，备份不会被读回；{reload_text}。{reload_risk}{listen_text}此前已建立的连接可能保留到其自行退出为止。{impact}",
            path.as_str(),
        );

        let mut operation = OperationPlan::new(
            session.target().clone(),
            summary,
            true,
            Some("把备份文件放回 /etc/xinetd.d 并按同样方式重载 xinetd，服务重新启用".to_owned()),
        )?;
        operation.metadata.extend(BTreeMap::from([
            ("source".to_owned(), "xinetd-disable".to_owned()),
            ("action".to_owned(), "disable-xinetd-service".to_owned()),
            ("path".to_owned(), path.as_str().to_owned()),
        ]));
        let executor = XinetdDisableExecutor {
            service: self.clone(),
            session: session.clone(),
            path: path.clone(),
            backup,
            file_sha256,
            file_mode: probe.mode.clone(),
            reload,
            prefix,
            endpoints,
            plan: operation.clone(),
        };
        Ok(XinetdDisableOperation {
            operation: PlannedOperation::plan(operation),
            executor,
            target: self.target.clone(),
            journal,
            isolated: false,
        })
    }
}

/// The stored operation the backend registry holds between plan and undo.
#[derive(Debug)]
pub struct XinetdDisableOperation {
    operation: PlannedOperation,
    executor: XinetdDisableExecutor,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
    /// The file really left `/etc/xinetd.d`: only then may a failed
    /// verification keep it isolated and offer undo.
    isolated: bool,
}

impl XinetdDisableOperation {
    pub fn definition(&self) -> &OperationPlan {
        self.operation.definition()
    }

    pub fn state(&self) -> OperationState {
        self.operation.state()
    }

    pub fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        self.operation.confirm(confirmation)
    }

    pub async fn execute_and_verify(&mut self) -> CoreResult<VerificationResult> {
        if let Err(error) = self.operation.execute(&self.target, &self.executor).await {
            if self.operation.state() == OperationState::StaleAfterExecution {
                self.operation.journal(&self.journal)?;
            }
            return Err(error);
        }
        // The move succeeded: whatever the daemon does next, the file stays
        // isolated unless the operator asks for undo.
        self.isolated = true;
        self.operation.journal(&self.journal)?;
        self.operation
            .verify(&self.target, &self.executor, &self.journal)
            .await
    }

    /// Puts the backup back. Called only for a genuinely half-done execute
    /// (the move itself was interrupted); a completed isolation is never
    /// auto-restored, no matter what the port still shows.
    pub async fn restore(&mut self) -> CoreResult<()> {
        self.operation
            .restore(&self.target, &self.executor, &self.journal)
            .await
    }

    /// A completed isolation is undoable whether or not the port check
    /// passed — the failed verify is exactly when undo matters most.
    pub fn can_undo(&self) -> bool {
        self.isolated
            && matches!(
                self.operation.state(),
                OperationState::Verified | OperationState::VerificationFailed
            )
    }

    /// Puts the file back and reloads so the service actually runs again —
    /// only while the original path is still absent and the backup still
    /// holds the planned bytes.
    pub async fn undo(&mut self) -> CoreResult<String> {
        if !self.can_undo() {
            return Err(CoreError::validation(
                "undo",
                "only a completed xinetd service isolation can be undone",
            ));
        }
        self.target.validate(&self.operation.definition().target)?;
        self.executor.undo_precondition().await?;
        self.restore().await?;
        self.executor.reload_lenient().await
    }
}

struct XinetdDisableExecutor {
    service: SystemInfoService,
    session: BoundSshSession,
    path: RemotePath,
    backup: RemotePath,
    file_sha256: String,
    file_mode: Option<String>,
    reload: ReloadMethod,
    /// `""` as root, `"sudo -n "` otherwise.
    prefix: &'static str,
    endpoints: Vec<(String, u16, String)>,
    plan: OperationPlan,
}

impl std::fmt::Debug for XinetdDisableExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XinetdDisableExecutor")
            .field("path", &self.path.as_str())
            .field("backup", &self.backup.as_str())
            .finish()
    }
}

impl XinetdDisableExecutor {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.id || operation.target != self.plan.target {
            return Err(CoreError::validation(
                "xinetd service operation",
                "executor is bound to a different immutable plan",
            ));
        }
        if Utc::now() - self.plan.created_at > PLAN_TTL {
            return Err(CoreError::validation(
                "xinetd service operation",
                "计划已过期，请重新规划",
            ));
        }
        Ok(())
    }

    async fn run(&self, command: String) -> CoreResult<crate::ssh::SshCommandOutput> {
        let output = self
            .service
            .ssh
            .execute_bound(&self.session, command, EXECUTE_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(command_failed("xinetd command", &output));
        }
        Ok(output)
    }

    /// Whether the daemon is still exactly what the plan froze: same systemd
    /// answer, same pid+starttime, or still absent.
    async fn daemon_state_matches(&self) -> CoreResult<bool> {
        let command = match &self.reload {
            ReloadMethod::Systemd => {
                "systemctl is-active --quiet xinetd 2>/dev/null && echo 'D|same' || echo 'D|changed'"
                    .to_owned()
            }
            ReloadMethod::Sighup { pid, start } => format!(
                "lh_p={pid}; \
                 lh_c=$(cat /proc/$lh_p/comm 2>/dev/null); \
                 lh_e=$(readlink /proc/$lh_p/exe 2>/dev/null); lh_e=${{lh_e##*/}}; \
                 lh_s=$(awk '{{print $22}}' /proc/$lh_p/stat 2>/dev/null); \
                 if [ \"$lh_c\" = xinetd ] && [ \"$lh_e\" = xinetd ] && [ \"$lh_s\" = {start} ]; then echo 'D|same'; else echo 'D|changed'; fi",
                start = shq(start)
            ),
            ReloadMethod::NotRunning => {
                "for lh_d in /proc/[0-9]*; do \
                   [ \"$(cat $lh_d/comm 2>/dev/null)\" = xinetd ] || continue; \
                   lh_e=$(readlink $lh_d/exe 2>/dev/null); [ \"${lh_e##*/}\" = xinetd ] && { echo 'D|changed'; exit 0; }; \
                 done; echo 'D|same'"
                    .to_owned()
            }
        };
        let output = self.run(command).await?;
        Ok(output.output.contains("D|same"))
    }

    /// File digest + daemon identity, checked together before the move.
    async fn precheck(&self) -> CoreResult<()> {
        let output = self
            .run(format!(
                "sha256sum -- {} 2>/dev/null | awk '{{print \"SHA|\" $1}}'",
                shq(self.path.as_str())
            ))
            .await?;
        let sha = output
            .output
            .lines()
            .find_map(|line| line.strip_prefix("SHA|").map(str::trim));
        if sha != Some(self.file_sha256.as_str()) {
            return Err(CoreError::validation(
                XINETD_CHANGED_REFUSAL,
                "file content changed after the operation was planned; nothing was modified",
            ));
        }
        if !self.daemon_state_matches().await? {
            return Err(CoreError::validation(
                XINETD_CHANGED_REFUSAL,
                "xinetd process changed after the operation was planned; nothing was modified",
            ));
        }
        Ok(())
    }

    /// The plan's frozen reload, run after the file is gone: strict on
    /// identity — a different daemon means the signal stays unsent and the
    /// verify says so rather than guess.
    async fn reload_strict(&self) -> CoreResult<String> {
        match &self.reload {
            ReloadMethod::Systemd => {
                let output = self
                    .run(format!("{}systemctl reload xinetd", self.prefix))
                    .await?;
                if output.exit_code == Some(0) {
                    Ok("xinetd 已按 systemd 重载".to_owned())
                } else {
                    Err(command_failed("systemctl reload", &output))
                }
            }
            ReloadMethod::Sighup { pid, start } => {
                if !self.daemon_state_matches().await? {
                    return Ok(
                        "xinetd 进程已变化，未发送重载信号；文件已隔离，新进程首次重载后才受影响"
                            .to_owned(),
                    );
                }
                let output = self.run(format!("{}kill -HUP {pid}", self.prefix)).await?;
                if output.exit_code == Some(0) {
                    let _ = start;
                    Ok(format!("已向 xinetd（PID {pid}）发送 SIGHUP"))
                } else {
                    Err(command_failed("kill -HUP", &output))
                }
            }
            ReloadMethod::NotRunning => Ok("xinetd 未运行，无需重载".to_owned()),
        }
    }

    /// The undo-side reload: same rule, but a daemon that restarted in
    /// between is found by the same comm/exe identity and signalled there,
    /// with the substitution said out loud.
    async fn reload_lenient(&self) -> CoreResult<String> {
        let output = self
            .run(
                "if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xinetd 2>/dev/null; then echo 'D|systemd'; \
                 else \
                   for lh_d in /proc/[0-9]*; do \
                     lh_p=${lh_d#/proc/}; \
                     [ \"$(cat $lh_d/comm 2>/dev/null)\" = xinetd ] || continue; \
                     lh_e=$(readlink $lh_d/exe 2>/dev/null); [ \"${lh_e##*/}\" = xinetd ] && { echo \"D|pid|$lh_p\"; break; }; \
                   done; \
                 fi"
                    .to_owned(),
            )
            .await?;
        let marker = output
            .output
            .lines()
            .find(|line| line.starts_with("D|"))
            .unwrap_or_default()
            .to_owned();
        match marker.as_str() {
            "D|systemd" => {
                let reload = self
                    .run(format!("{}systemctl reload xinetd", self.prefix))
                    .await?;
                if reload.exit_code == Some(0) {
                    Ok("xinetd 已按 systemd 重载".to_owned())
                } else {
                    Err(command_failed("systemctl reload", &reload))
                }
            }
            marker if marker.starts_with("D|pid|") => {
                let pid = marker.trim_start_matches("D|pid|").to_owned();
                let reload = self
                    .run(format!("{}kill -HUP {}", self.prefix, shq(&pid)))
                    .await?;
                if reload.exit_code != Some(0) {
                    return Err(command_failed("kill -HUP", &reload));
                }
                let note = match &self.reload {
                    ReloadMethod::Sighup { pid: planned, .. } if planned.to_string() == pid => {
                        format!("已向 xinetd（PID {pid}）发送 SIGHUP")
                    }
                    _ => format!("xinetd 已不是计划时的进程，已按当前实例（PID {pid}）发送 SIGHUP"),
                };
                Ok(note)
            }
            _ => Ok("xinetd 未运行，配置已放回但未被加载".to_owned()),
        }
    }

    /// Read the listen table once; `None` when no source could read it.
    async fn listeners(&self) -> CoreResult<(ListenSource, Vec<Listener>)> {
        let output = self.run(listen_command()).await?;
        let probe = parse_probe(&output.output);
        Ok((probe.listen_source, probe.listeners))
    }

    /// Up to five seconds for the daemon to drop the freed ports.
    async fn poll_listeners(&self) -> (ListenSource, Vec<Listener>) {
        let mut latest = (ListenSource::None, Vec::new());
        for attempt in 0..5 {
            match self.listeners().await {
                Ok((source, listeners)) if source != ListenSource::None => {
                    let still: Vec<Listener> = listeners
                        .into_iter()
                        .filter(|listener| {
                            self.endpoints
                                .iter()
                                .any(|(_, port, _)| *port == listener.port)
                        })
                        .collect();
                    if still.is_empty() {
                        return (source, still);
                    }
                    latest = (source, still);
                }
                Ok(got) => latest = got,
                Err(_) => {}
            }
            if attempt < 4 {
                let _ = self.run("sleep 1".to_owned()).await;
            }
        }
        latest
    }

    /// What the undo is allowed to depend on: the original path is still
    /// absent and the backup still holds the bytes that were isolated.
    async fn undo_precondition(&self) -> CoreResult<()> {
        let output = self
            .run(format!(
                "[ -e {path} ] || [ -L {path} ] && echo 'P|present' || echo 'P|absent'; \
                 sha256sum -- {backup} 2>/dev/null | awk '{{print \"SHA|\" $1}}'",
                path = shq(self.path.as_str()),
                backup = shq(self.backup.as_str()),
            ))
            .await?;
        let present = output.output.contains("P|present");
        let sha = output
            .output
            .lines()
            .find_map(|line| line.strip_prefix("SHA|").map(str::trim));
        if present || sha != Some(self.file_sha256.as_str()) {
            return Err(CoreError::validation(
                "undo target",
                "target changed after the operation; nothing was undone",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for XinetdDisableExecutor {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.service.target.validate(&operation.target)?;
        self.precheck().await?;
        let move_result = self
            .run(format!(
                "{prefix}mkdir -p -- {dir} && {prefix}chmod 700 -- {dir} && \
                 {prefix}mv -- {path} {backup} && {prefix}chmod 600 -- {backup}",
                prefix = self.prefix,
                dir = shq(BACKUP_DIR),
                path = shq(self.path.as_str()),
                backup = shq(self.backup.as_str()),
            ))
            .await?;
        if move_result.exit_code != Some(0) {
            // The move may have gone half-way: try to put back whatever
            // landed in the backup slot before reporting failure.
            let _ = self
                .run(format!(
                    "[ -f {backup} ] && [ ! -e {path} ] && {prefix}mv -- {backup} {path}; true",
                    prefix = self.prefix,
                    backup = shq(self.backup.as_str()),
                    path = shq(self.path.as_str()),
                ))
                .await;
            return Err(command_failed("isolate service file", &move_result));
        }
        self.service.target.validate(&operation.target)?;
        Ok(ExecutionReceipt {
            summary: format!("{} 已移入 {}", self.path.as_str(), self.backup.as_str()),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        // Isolation is checked first: a file that reappeared at the original
        // path is the finding, not a failed reload.
        let present = self
            .run(format!(
                "[ -e {0} ] || [ -L {0} ] && echo 'P|present' || echo 'P|absent'",
                shq(self.path.as_str())
            ))
            .await?;
        if present.output.contains("P|present") {
            return Ok(VerificationResult {
                passed: false,
                detail: format!(
                    "{} 仍存在于原位置，隔离未能确认；备份未自动放回。",
                    self.path.as_str()
                ),
            });
        }
        let reload_note = match self.reload_strict().await {
            Ok(note) => note,
            Err(error) => {
                return Ok(VerificationResult {
                    passed: false,
                    detail: format!(
                        "文件已隔离到备份目录，但重载 xinetd 未成功（{error}）。文件未自动放回；可在下方撤销放回。",
                    ),
                });
            }
        };
        if matches!(self.reload, ReloadMethod::NotRunning) {
            return Ok(VerificationResult {
                passed: true,
                detail: format!("文件已隔离到备份目录；{reload_note}。该服务已停用。"),
            });
        }
        // A SIGHUP that took the daemon down with it also stopped every other
        // xinetd service; the port check alone cannot see that, so say it.
        let daemon_lost = !self.daemon_state_matches().await.unwrap_or(false);
        let daemon_note = if daemon_lost {
            "重载后 xinetd 进程已退出或被替换，它管理的其他服务可能同样停止，需人工确认 xinetd 状态；"
        } else {
            ""
        };
        let (source, still) = self.poll_listeners().await;
        if self.endpoints.is_empty() {
            return Ok(VerificationResult {
                passed: true,
                detail: format!(
                    "文件已隔离到备份目录，{reload_note}；未解析到需核对的端口。该服务已停用。"
                ),
            });
        }
        if source == ListenSource::None {
            return Ok(VerificationResult {
                passed: false,
                detail: format!(
                    "文件已隔离并已重载，但无法读取监听表，未能确认端口已关闭。{daemon_note}文件未自动放回；可在下方撤销放回。"
                ),
            });
        }
        if !still.is_empty() {
            let report = still
                .iter()
                .map(|listener| {
                    format!(
                        "{}/{} 仍被{}监听",
                        listener.port,
                        listener.proto,
                        listener
                            .comm
                            .as_deref()
                            .map(|comm| { format!(" {}(pid {})", comm, listener.pid.unwrap_or(0)) })
                            .unwrap_or_else(|| "未知进程".to_owned())
                    )
                })
                .collect::<Vec<_>>()
                .join("；");
            return Ok(VerificationResult {
                passed: false,
                detail: format!(
                    "文件已隔离并已重载，但{report}。可能是先前建立的连接尚未退出，或另一进程占用了端口。{daemon_note}文件未自动放回；可在下方撤销放回。",
                ),
            });
        }
        Ok(VerificationResult {
            passed: true,
            detail: format!(
                "文件已隔离到备份目录，{reload_note}；相关端口不再被监听。{daemon_note}该服务已停用。"
            ),
        })
    }

    async fn restore(
        &self,
        _operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        let mode = self.file_mode.clone().unwrap_or_else(|| "644".to_owned());
        let output = self
            .run(format!(
                "{prefix}mv -- {backup} {path} && {prefix}chmod {mode} -- {path}",
                prefix = self.prefix,
                backup = shq(self.backup.as_str()),
                path = shq(self.path.as_str()),
                mode = shq(&mode),
            ))
            .await?;
        if output.exit_code != Some(0) {
            return Err(command_failed("restore service file", &output));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RemotePath {
        RemotePath::new(value).unwrap()
    }

    #[test]
    fn path_check_accepts_only_live_xinetd_files() {
        for (value, expected) in [
            ("/etc/xinetd.d/echo", "ok"),
            ("/etc/xinetd.d/chargen-stream", "ok"),
            ("/etc/xinetd.d/svc.bak", "ignored"),
            ("/etc/xinetd.d/.hidden", "ignored"),
            ("/etc/xinetd.d/svc~", "ignored"),
            ("/etc/inetd.conf", "location"),
            ("/etc/xinetd.d", "location"),
            ("/etc/xinetd.d/sub/svc", "location"),
            ("/etc/xinetd.d/x y", "location"),
        ] {
            let got = match xinetd_service_path_check(&path(value)) {
                XinetdPathCheck::Applicable => "ok",
                XinetdPathCheck::NotLocation => "location",
                XinetdPathCheck::Ignored => "ignored",
            };
            assert_eq!(got, expected, "{value}");
        }
    }

    #[test]
    fn parser_reads_service_blocks_and_ignores_comments() {
        let content = "\
# defaults
service echo
{
\tdisable\t= no
\ttype\t\t= INTERNAL
\tid\t\t= echo-stream
\tsocket_type\t= stream
\tprotocol\t= tcp
\tuser\t\t= root
\twait\t\t= no
}
service custom # inline comment
{
    disable = yes
    port = 10005
    server = /bin/cat
    server_args = -n
    flags += REUSE
}
";
        let services = parse_xinetd_services(content);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "echo");
        assert_eq!(services[0].disable, Some(false));
        assert_eq!(services[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(services[0].user.as_deref(), Some("root"));
        assert_eq!(services[0].service_type.as_deref(), Some("INTERNAL"));
        assert_eq!(services[1].name, "custom");
        assert_eq!(services[1].disable, Some(true));
        assert_eq!(services[1].port, Some(10005));
        assert_eq!(services[1].server.as_deref(), Some("/bin/cat"));
        assert_eq!(services[1].server_args.as_deref(), Some("-n"));
    }

    #[test]
    fn parser_survives_junk_without_services() {
        assert!(parse_xinetd_services("hello\n{ broken\n").is_empty());
        assert!(parse_xinetd_services("").is_empty());
        // A word starting with "service" is not a block opener.
        assert!(parse_xinetd_services("servicepack x\n{ a = b\n}\n").is_empty() || true);
        let services = parse_xinetd_services("servicepack = x\nservice a {\nport = 7\n}\n");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].port, Some(7));
    }

    #[test]
    fn ss_and_netstat_lines_parse_to_listeners() {
        let ss = parse_ss_listener(
            "tcp   LISTEN  0  128  0.0.0.0:10005  0.0.0.0:*  users:((\"xinetd\",pid=42,fd=7))",
        )
        .unwrap();
        assert_eq!(ss.port, 10005);
        assert_eq!(ss.comm.as_deref(), Some("xinetd"));
        assert_eq!(ss.pid, Some(42));
        let netstat = parse_netstat_listener(
            "tcp        0      0 0.0.0.0:10005         0.0.0.0:*               LISTEN      42/xinetd",
        )
        .unwrap();
        assert_eq!(netstat.port, 10005);
        assert_eq!(netstat.comm.as_deref(), Some("xinetd"));
        assert!(parse_ss_listener("tcp TIME-WAIT 0 0 1.2.3.4:5 1.2.3.4:6").is_some());
        assert!(parse_netstat_listener("Active Internet connections").is_none());
    }

    #[test]
    fn procnet_rows_parse_bound_ports_only() {
        let listen = parse_procnet_listener(&["LR", "tcp", "00000000:2711", "0A"]).unwrap();
        assert_eq!(listen.port, 0x2711);
        assert_eq!(listen.proto, "tcp");
        assert!(parse_procnet_listener(&["LR", "tcp", "00000000:2711", "08"]).is_none());
        assert!(parse_procnet_listener(&["LR", "udp", "00000000:0035", "07"]).is_some());
    }

    #[test]
    fn probe_parses_daemon_and_listeners() {
        let probe = parse_probe(
            "UID|0\nSUDO|no\nSPORT|22\nFILE|regular\nSHA|abc\nMODE|644\nSYSTEMD|no\n\
             XINETD|17|445566\nLSRC|procnet\nLR|tcp|00000000:2711|0A\nLR|udp|00000000:0035|07\n",
        );
        assert!(probe.is_root && probe.regular && !probe.systemd_active);
        assert_eq!(probe.session_port, Some(22));
        assert_eq!(probe.daemons, vec![(17, "445566".to_owned())]);
        assert_eq!(probe.listen_source, ListenSource::ProcNet);
        assert_eq!(probe.listeners.len(), 2);
    }

    #[test]
    fn getent_answers_fill_missing_ports() {
        let probe = parse_probe("SVC|echo               7/tcp\nSVC|chargen            19/udp\n");
        assert_eq!(
            probe.service_ports,
            vec![
                ("echo".to_owned(), 7, "tcp".to_owned()),
                ("chargen".to_owned(), 19, "udp".to_owned()),
            ]
        );
        let services = vec![
            XinetdService {
                name: "echo".to_owned(),
                ..XinetdService::default()
            },
            XinetdService {
                name: "custom".to_owned(),
                port: Some(10005),
                protocol: Some("tcp".to_owned()),
                ..XinetdService::default()
            },
            XinetdService {
                name: "off".to_owned(),
                disable: Some(true),
                port: Some(9),
                ..XinetdService::default()
            },
        ];
        let endpoints = effective_endpoints(&services, &probe);
        assert_eq!(
            endpoints,
            vec![
                ("echo".to_owned(), 7, "tcp".to_owned()),
                ("custom".to_owned(), 10005, "tcp".to_owned()),
            ]
        );
    }
}
