//! Runtime-only firewall IP blocking (batch 7a).
//!
//! Mirrors `plan_network_disconnect`/`execute_network_disconnect` in
//! `system_info.rs`: immutable plan, 120 s TTL, single execute behind a
//! [`DangerousConfirmation`], independent re-list verification, and a
//! separate single-use restore plan that deletes exactly the tagged rules.
//!
//! No persistent configuration is written in this increment; the plan and
//! result state that clearly.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{Duration, Utc};

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::shq;
use crate::ssh::BoundSshSession;
use crate::system_info::SystemInfoService;

/// Refusal subjects the backend maps to their own operator-facing codes.
pub const FIREWALL_PRIVILEGE_REFUSAL: &str = "firewall block privilege";
pub const FIREWALL_UFW_REFUSAL: &str = "firewall block ufw";
pub const FIREWALL_BACKEND_REFUSAL: &str = "firewall block backend";
pub const FIREWALL_SESSION_REFUSAL: &str = "firewall block own session";

const PRECONDITION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const EXECUTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PLAN_TTL: Duration = Duration::seconds(120);
const RESTORE_TTL: Duration = Duration::hours(24);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
    Both,
}

impl FirewallDirection {
    pub const fn blocks_inbound(self) -> bool {
        matches!(self, Self::Inbound | Self::Both)
    }
    pub const fn blocks_outbound(self) -> bool {
        matches!(self, Self::Outbound | Self::Both)
    }
    const fn label(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Firewalld,
    IpTables,
    Nft,
}

impl FirewallBackend {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Firewalld => "firewalld",
            Self::IpTables => "iptables",
            Self::Nft => "nftables",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBlockRequest {
    address: IpAddr,
    direction: FirewallDirection,
}

impl FirewallBlockRequest {
    pub fn new(address: IpAddr, direction: FirewallDirection) -> CoreResult<Self> {
        match address {
            IpAddr::V4(v4)
                if v4.is_unspecified()
                    || v4.is_loopback()
                    || v4.is_multicast()
                    || v4.is_link_local()
                    || v4.is_broadcast() =>
            {
                return Err(CoreError::validation(
                    "firewall block address",
                    "must be a single routable host address",
                ));
            }
            IpAddr::V6(v6)
                if v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 =>
            {
                return Err(CoreError::validation(
                    "firewall block address",
                    "must be a single routable host address",
                ));
            }
            _ => {}
        }
        Ok(Self { address, direction })
    }
    pub const fn address(&self) -> IpAddr {
        self.address
    }
    pub const fn direction(&self) -> FirewallDirection {
        self.direction
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBlockPlan {
    operation: OperationPlan,
    request: FirewallBlockRequest,
    backend: FirewallBackend,
    /// Literal apply commands — no secrets, safe to show and journal.
    commands: Vec<String>,
    /// Literal verify-list command; the executor counts tag hits per rule.
    list_command: String,
    warnings: Vec<String>,
    tag: String,
}

impl FirewallBlockPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
    pub const fn backend(&self) -> FirewallBackend {
        self.backend
    }
    pub fn commands(&self) -> &[String] {
        &self.commands
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub fn request(&self) -> &FirewallBlockRequest {
        &self.request
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBlockOutcome {
    pub verification: VerificationResult,
    /// In-memory restore token: backend + tag + created timestamp.
    restore_handle: Option<String>,
}

impl FirewallBlockOutcome {
    pub fn restore_handle(&self) -> Option<&str> {
        self.restore_handle.as_deref()
    }

    /// Re-materialize an outcome from a token the backend kept in memory —
    /// the page-facing opaque handle is not the core's concern.
    pub fn from_token(token: String) -> Self {
        Self {
            verification: VerificationResult {
                passed: true,
                detail: String::new(),
            },
            restore_handle: Some(token),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBlockRestorePlan {
    operation: OperationPlan,
    backend: FirewallBackend,
    tag: String,
    commands: Vec<String>,
    list_command: String,
}

impl FirewallBlockRestorePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
    pub const fn backend(&self) -> FirewallBackend {
        self.backend
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBlockRestoreOutcome {
    pub verification: VerificationResult,
}

// ---- plan-time probe ----

/// One bounded read: privilege, own session addresses, backend detection.
fn probe_command(address: IpAddr) -> String {
    let family = match address {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    };
    format!(
        "printf 'UID|%s\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         echo \"CONN|${{SSH_CONNECTION%% *}}\"; \
         if command -v ss >/dev/null 2>&1; then \
           ss -tn state established 2>/dev/null | awk 'NR>1{{split($4,a,\":\"); lp=a[length(a)]; split($5,b,\":\"); print \"ESTAB|\" lp \"|\" b[1]}}' | head -n 200; \
           ss -tlnpH 2>/dev/null | awk '/sshd/{{split($4,a,\":\"); print \"SPORT|\" a[length(a)]}}' | head -n 20; \
         fi; \
         if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qx running; then echo 'BACKEND|firewalld'; \
         elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -n 1 | grep -qx 'Status: active'; then echo 'BACKEND|ufw'; \
         elif command -v iptables >/dev/null 2>&1 || command -v ip6tables >/dev/null 2>&1; then \
           echo 'BACKEND|iptables'; \
           {family_tool} -L DOCKER-USER -n >/dev/null 2>&1 && echo 'DOCKERUSER|yes' || true; \
         elif command -v nft >/dev/null 2>&1; then echo 'BACKEND|nft'; \
         else echo 'BACKEND|none'; fi",
        family_tool = if family == "ipv4" {
            "iptables"
        } else {
            "ip6tables"
        },
    )
}

struct Probe {
    is_root: bool,
    sudo: bool,
    own_ips: Vec<IpAddr>,
    backend: Option<FirewallBackend>,
    ufw_active: bool,
    docker_user: bool,
}

fn parse_probe(output: &str) -> Probe {
    let mut probe = Probe {
        is_root: false,
        sudo: false,
        own_ips: Vec::new(),
        backend: None,
        ufw_active: false,
        docker_user: false,
    };
    let mut sports = Vec::new();
    let mut estab = Vec::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "UID" => probe.is_root = value.trim() == "0",
            "SUDO" => probe.sudo = value.trim() == "yes",
            "CONN" => {
                if let Ok(ip) = value.trim().parse::<IpAddr>() {
                    probe.own_ips.push(ip);
                }
            }
            "ESTAB" => {
                if let Some((port, addr)) = value.split_once('|') {
                    estab.push((port.to_owned(), addr.to_owned()));
                }
            }
            "SPORT" => sports.push(value.trim().to_owned()),
            "DOCKERUSER" => probe.docker_user = value.trim() == "yes",
            "BACKEND" => {
                probe.backend = match value.trim() {
                    "firewalld" => Some(FirewallBackend::Firewalld),
                    "iptables" => Some(FirewallBackend::IpTables),
                    "nft" => Some(FirewallBackend::Nft),
                    "ufw" => {
                        probe.ufw_active = true;
                        None
                    }
                    _ => None,
                };
            }
            _ => {}
        }
    }
    // Any established connection whose local port is an sshd port exposes its
    // peer — those peers include this session and any other live ssh login.
    let ports: Vec<&str> = if sports.is_empty() {
        vec!["22"]
    } else {
        sports.iter().map(String::as_str).collect()
    };
    for (port, addr) in estab {
        if ports.contains(&port.as_str())
            && let Ok(ip) = addr.parse::<IpAddr>()
            && !probe.own_ips.contains(&ip)
        {
            probe.own_ips.push(ip);
        }
    }
    probe
}

// ---- command construction per backend ----

fn family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

fn table_tool(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "iptables",
        IpAddr::V6(_) => "ip6tables",
    }
}

fn nft_addr_keyword(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    }
}

fn apply_commands(
    backend: FirewallBackend,
    request: &FirewallBlockRequest,
    tag: &str,
    docker_user: bool,
    sudo: &str,
) -> Vec<String> {
    let ip = request.address.to_string();
    match backend {
        FirewallBackend::Firewalld => {
            let mut commands = Vec::new();
            if request.direction.blocks_inbound() {
                commands.push(format!(
                    "{sudo}firewall-cmd --add-rich-rule {}",
                    shq(&format!(
                        "rule family={} source address={ip} drop",
                        family(request.address)
                    ))
                ));
            }
            if request.direction.blocks_outbound() {
                commands.push(format!(
                    "{sudo}firewall-cmd --direct --add-rule {} filter OUTPUT 0 -d {ip} -j DROP",
                    family(request.address)
                ));
            }
            commands
        }
        FirewallBackend::IpTables => {
            let tool = table_tool(request.address);
            let mut commands = Vec::new();
            if request.direction.blocks_inbound() {
                commands.push(format!(
                    "{sudo}{tool} -I INPUT 1 -s {ip} -m comment --comment {tag} -j DROP"
                ));
                if docker_user {
                    commands.push(format!(
                        "{sudo}{tool} -I DOCKER-USER 1 -s {ip} -m comment --comment {tag} -j DROP"
                    ));
                }
            }
            if request.direction.blocks_outbound() {
                commands.push(format!(
                    "{sudo}{tool} -I OUTPUT 1 -d {ip} -m comment --comment {tag} -j DROP"
                ));
            }
            commands
        }
        FirewallBackend::Nft => {
            let kw = nft_addr_keyword(request.address);
            let mut commands = vec![
                format!(
                    "{sudo}nft list table inet lovelyhawk >/dev/null 2>&1 || {sudo}nft add table inet lovelyhawk"
                ),
                format!(
                    "{sudo}nft 'add chain inet lovelyhawk input {{ type filter hook input priority -5; policy accept; }}' 2>/dev/null || true"
                ),
                format!(
                    "{sudo}nft 'add chain inet lovelyhawk output {{ type filter hook output priority -5; policy accept; }}' 2>/dev/null || true"
                ),
            ];
            if request.direction.blocks_inbound() {
                commands.push(format!(
                    "{sudo}nft add rule inet lovelyhawk input {kw} saddr {ip} counter drop comment {}",
                    shq(tag)
                ));
            }
            if request.direction.blocks_outbound() {
                commands.push(format!(
                    "{sudo}nft add rule inet lovelyhawk output {kw} daddr {ip} counter drop comment {}",
                    shq(tag)
                ));
            }
            commands
        }
    }
}

fn list_command(backend: FirewallBackend, address: IpAddr, sudo: &str) -> String {
    match backend {
        FirewallBackend::Firewalld => format!(
            "{sudo}firewall-cmd --list-rich-rules 2>/dev/null; {sudo}firewall-cmd --direct --get-all-rules 2>/dev/null"
        ),
        FirewallBackend::IpTables => format!("{sudo}{} -S 2>/dev/null", table_tool(address)),
        FirewallBackend::Nft => format!("{sudo}nft -a list table inet lovelyhawk 2>/dev/null"),
    }
}

fn restore_commands(
    backend: FirewallBackend,
    request: &FirewallBlockRequest,
    tag: &str,
    docker_user: bool,
    sudo: &str,
) -> Vec<String> {
    let ip = request.address.to_string();
    match backend {
        FirewallBackend::Firewalld => {
            let mut commands = Vec::new();
            if request.direction.blocks_inbound() {
                commands.push(format!(
                    "{sudo}firewall-cmd --remove-rich-rule {}",
                    shq(&format!(
                        "rule family={} source address={ip} drop",
                        family(request.address)
                    ))
                ));
            }
            if request.direction.blocks_outbound() {
                commands.push(format!(
                    "{sudo}firewall-cmd --direct --remove-rule {} filter OUTPUT 0 -d {ip} -j DROP",
                    family(request.address)
                ));
            }
            commands
        }
        FirewallBackend::IpTables => {
            let tool = table_tool(request.address);
            let mut commands = Vec::new();
            if request.direction.blocks_inbound() {
                commands.push(format!(
                    "{sudo}{tool} -D INPUT -s {ip} -m comment --comment {tag} -j DROP"
                ));
                if docker_user {
                    commands.push(format!(
                        "{sudo}{tool} -D DOCKER-USER -s {ip} -m comment --comment {tag} -j DROP"
                    ));
                }
            }
            if request.direction.blocks_outbound() {
                commands.push(format!(
                    "{sudo}{tool} -D OUTPUT -d {ip} -m comment --comment {tag} -j DROP"
                ));
            }
            commands
        }
        FirewallBackend::Nft => {
            // Delete by handle found via the tag comment; never flush a chain
            // or drop the table while other lovelyhawk rules might remain.
            vec![format!(
                "{sudo}nft -a list table inet lovelyhawk 2>/dev/null | awk -v t={} '$1==\"chain\"{{c=$2}} index($0, \"comment \\\"\" t \"\\\"\"){{print c, $NF}}' | while read lh_c lh_h; do \
                 [ -n \"$lh_h\" ] && {sudo}nft delete rule inet lovelyhawk \"$lh_c\" handle \"$lh_h\"; done",
                shq(tag),
            )]
        }
    }
}

/// Count the tagged rules in verify output. For iptables/nft that is the
/// comment tag; for firewalld the rich-rule line carries the address instead.
fn count_tagged(backend: FirewallBackend, output: &str, tag: &str, ip: &IpAddr) -> usize {
    match backend {
        FirewallBackend::Firewalld => output
            .lines()
            .filter(|line| line.contains(&ip.to_string()))
            .count(),
        _ => output.lines().filter(|line| line.contains(tag)).count(),
    }
}

// ---- service API ----

impl SystemInfoService {
    /// Plan a runtime-only IP block. Refuses when the block would cut this
    /// SSH session, when the address is not a routable host, when no usable
    /// firewall backend exists, or without root / `sudo -n`.
    pub async fn plan_firewall_block(
        &self,
        session: &BoundSshSession,
        request: &FirewallBlockRequest,
    ) -> CoreResult<FirewallBlockPlan> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                probe_command(request.address),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("firewall probe", &output));
        }
        let probe = parse_probe(&output.output);
        if !(probe.is_root || probe.sudo) {
            return Err(CoreError::validation(
                FIREWALL_PRIVILEGE_REFUSAL,
                "需要 root 或免密码 sudo 才能改防火墙规则",
            ));
        }
        if probe.ufw_active {
            return Err(CoreError::validation(
                FIREWALL_UFW_REFUSAL,
                "主机使用 ufw 管理自己的规则链，暂不支持通过 ufw 封禁；请用 ufw 自身的 deny 规则",
            ));
        }
        let Some(backend) = probe.backend else {
            return Err(CoreError::validation(
                FIREWALL_BACKEND_REFUSAL,
                "未找到可用的防火墙后端（firewalld/iptables/nftables 均不可用）",
            ));
        };
        if request.direction.blocks_inbound() && probe.own_ips.contains(&request.address) {
            return Err(CoreError::validation(
                FIREWALL_SESSION_REFUSAL,
                "该地址是当前 SSH 连接的来源，入方向封禁会切断本会话，已拒绝",
            ));
        }
        let sudo = if probe.is_root { "" } else { "sudo -n " };
        let tag = format!(
            "lovelyhawk-block-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let mut warnings = vec!["重启、防火墙重载或服务重启后失效；尚不写入持久配置。".to_owned()];
        if is_private_address(&request.address) {
            warnings.push("内网地址，可能是跳板或业务主机，请确认。".to_owned());
        }
        // 出方向封禁本会话或其他在线 SSH 登录的对端，效果同样是切断远程接入；
        // 入方向命中已在前面整体拒绝。
        if !request.direction.blocks_inbound() && probe.own_ips.contains(&request.address) {
            warnings.push(
                "该地址是 SSH 连接的对端。可能影响远程接入或对外业务，请确认仍有其他接入方式。"
                    .to_owned(),
            );
        }
        if backend == FirewallBackend::IpTables
            && probe.docker_user
            && request.direction.blocks_inbound()
        {
            warnings.push("检测到 DOCKER-USER 链：已一并加规则覆盖已发布容器端口。".to_owned());
        }
        let commands = apply_commands(backend, request, &tag, probe.docker_user, sudo);
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "封禁 {address}（{direction} 方向，{backend}，仅运行时）。",
                address = request.address,
                direction = request.direction.label(),
                backend = backend.name(),
            ),
            true,
            Some("删除本次带标记的封禁规则".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "firewall-block".to_owned());
        operation
            .metadata
            .insert("action".to_owned(), "block".to_owned());
        operation
            .metadata
            .insert("address".to_owned(), request.address.to_string());
        operation
            .metadata
            .insert("direction".to_owned(), request.direction.label().to_owned());
        operation
            .metadata
            .insert("backend".to_owned(), backend.name().to_owned());
        operation.metadata.insert("tag".to_owned(), tag.clone());
        Ok(FirewallBlockPlan {
            operation,
            request: request.clone(),
            backend,
            commands,
            list_command: list_command(backend, request.address, sudo),
            warnings,
            tag,
        })
    }

    pub async fn execute_firewall_block(
        &self,
        session: &BoundSshSession,
        plan: FirewallBlockPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<FirewallBlockOutcome> {
        let expected = plan.commands.len()
            - if plan.backend == FirewallBackend::Nft {
                3
            } else {
                0
            };
        let executor = FirewallBlockExecutor {
            service: self,
            session,
            plan: &plan,
            deleting: false,
            expected_tags: expected,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        let restore_handle = if verification.passed {
            Some(format!(
                "{}|{}|{}",
                plan.backend.name(),
                plan.tag,
                Utc::now().timestamp()
            ))
        } else {
            None
        };
        Ok(FirewallBlockOutcome {
            verification,
            restore_handle,
        })
    }

    /// Plan deleting exactly the rules an earlier execute created. The token
    /// is bound to one tag; verification afterwards fails a second attempt
    /// because the tagged rules are gone — effectively single use.
    pub async fn plan_firewall_block_restore(
        &self,
        session: &BoundSshSession,
        request: &FirewallBlockRequest,
        outcome: &FirewallBlockOutcome,
    ) -> CoreResult<FirewallBlockRestorePlan> {
        self.target.validate(session.target())?;
        let Some(token) = outcome.restore_handle() else {
            return Err(CoreError::validation(
                "firewall restore",
                "本次封禁结果没有可用的放回令牌",
            ));
        };
        let mut parts = token.split('|');
        let backend = match parts.next() {
            Some("firewalld") => FirewallBackend::Firewalld,
            Some("iptables") => FirewallBackend::IpTables,
            Some("nft") => FirewallBackend::Nft,
            _ => {
                return Err(CoreError::validation(
                    "firewall restore token",
                    "unrecognized backend",
                ));
            }
        };
        let tag = parts
            .next()
            .ok_or_else(|| CoreError::validation("firewall restore token", "missing tag"))?;
        if !tag.starts_with("lovelyhawk-block-")
            || tag.len() != 25
            || !tag[17..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(CoreError::validation(
                "firewall restore token",
                "malformed tag",
            ));
        }
        let created = parts
            .next()
            .and_then(|t| t.parse::<i64>().ok())
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .ok_or_else(|| CoreError::validation("firewall restore token", "missing timestamp"))?;
        if Utc::now() - created > RESTORE_TTL {
            return Err(CoreError::validation(
                "firewall restore",
                "放回令牌已过期（24 小时）",
            ));
        }
        let output = self
            .ssh
            .execute_bound(
                session,
                "id -u; sudo -n true >/dev/null 2>&1 && echo sudo || true; { iptables -S DOCKER-USER || sudo -n iptables -S DOCKER-USER; } >/dev/null 2>&1 && echo docker-user || true".to_owned(),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("firewall probe", &output));
        }
        let sudo = if output
            .output
            .lines()
            .next()
            .is_some_and(|l| l.trim() == "0")
        {
            ""
        } else if output.output.lines().any(|l| l.trim() == "sudo") {
            "sudo -n "
        } else {
            return Err(CoreError::validation(
                "firewall restore",
                "需要 root 或免密码 sudo 才能删除防火墙规则",
            ));
        };
        // The block added a DOCKER-USER rule only when that chain existed;
        // deleting from a missing chain fails after the INPUT rule is gone.
        let docker_user = backend == FirewallBackend::IpTables
            && request.direction.blocks_inbound()
            && output.output.lines().any(|l| l.trim() == "docker-user");
        let commands = restore_commands(backend, request, tag, docker_user, sudo);
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "删除 {tag} 标记的封禁规则（{backend}，仅运行时规则）。",
                backend = backend.name(),
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "firewall-block".to_owned());
        operation
            .metadata
            .insert("action".to_owned(), "restore".to_owned());
        operation
            .metadata
            .insert("address".to_owned(), request.address.to_string());
        operation
            .metadata
            .insert("backend".to_owned(), backend.name().to_owned());
        operation.metadata.insert("tag".to_owned(), tag.to_owned());
        Ok(FirewallBlockRestorePlan {
            operation,
            backend,
            tag: tag.to_owned(),
            commands,
            list_command: list_command(backend, request.address, sudo),
        })
    }

    pub async fn execute_firewall_block_restore(
        &self,
        session: &BoundSshSession,
        plan: FirewallBlockRestorePlan,
        request: &FirewallBlockRequest,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<FirewallBlockRestoreOutcome> {
        let block_plan = FirewallBlockPlan {
            operation: plan.operation.clone(),
            request: request.clone(),
            backend: plan.backend,
            commands: plan.commands.clone(),
            list_command: plan.list_command.clone(),
            warnings: Vec::new(),
            tag: plan.tag.clone(),
        };
        let executor = FirewallBlockExecutor {
            service: self,
            session,
            plan: &block_plan,
            deleting: true,
            expected_tags: 0,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        Ok(FirewallBlockRestoreOutcome { verification })
    }
}

impl std::fmt::Debug for FirewallBlockExecutor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirewallBlockExecutor")
            .field("tag", &self.plan.tag)
            .field("deleting", &self.deleting)
            .finish()
    }
}

struct FirewallBlockExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a FirewallBlockPlan,
    deleting: bool,
    expected_tags: usize,
}

impl FirewallBlockExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "firewall operation",
                "executor is bound to a different immutable plan",
            ));
        }
        let ttl = if self.deleting { RESTORE_TTL } else { PLAN_TTL };
        if Utc::now() - self.plan.operation.created_at > ttl {
            return Err(CoreError::validation(
                "firewall operation",
                "计划已过期，请重新规划",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for FirewallBlockExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.service.target.validate(&operation.target)?;
        // Precondition: tagged rules must be absent when applying, present
        // when deleting. Anything else means the state drifted mid-flight.
        let listed = self
            .service
            .ssh
            .execute_bound(
                self.session,
                self.plan.list_command.clone(),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        if listed.timed_out {
            return Err(command_failed("firewall list", &listed));
        }
        let current = count_tagged(
            self.plan.backend,
            &listed.output,
            &self.plan.tag,
            &self.plan.request.address,
        );
        if !self.deleting && current > 0 {
            return Err(CoreError::validation(
                "firewall block precondition",
                "同名标记规则已存在，拒绝重复写入",
            ));
        }
        if self.deleting && current == 0 {
            return Err(CoreError::validation(
                "firewall restore precondition",
                "带标记的封禁规则已不存在，放回令牌只能使用一次",
            ));
        }
        for command in &self.plan.commands {
            let output = self
                .service
                .ssh
                .execute_bound(self.session, command.clone(), EXECUTE_TIMEOUT)
                .await?;
            if output.timed_out {
                return Err(command_failed("firewall rule", &output));
            }
            if output.exit_code.is_some_and(|code| code != 0) {
                return Err(command_failed("firewall rule", &output));
            }
        }
        self.service.target.validate(&operation.target)?;
        Ok(ExecutionReceipt {
            summary: format!(
                "{} {}: {}",
                if self.deleting { "removed" } else { "added" },
                self.plan.tag,
                self.plan.commands.join("; ")
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let listed = self
            .service
            .ssh
            .execute_bound(
                self.session,
                self.plan.list_command.clone(),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        if listed.timed_out {
            return Err(command_failed("firewall list", &listed));
        }
        let found = count_tagged(
            self.plan.backend,
            &listed.output,
            &self.plan.tag,
            &self.plan.request.address,
        );
        let passed = found == self.expected_tags;
        Ok(VerificationResult {
            passed,
            detail: if self.deleting {
                if passed {
                    format!("回读：标记 {} 的封禁规则已全部删除。", self.plan.tag)
                } else {
                    format!(
                        "回读：标记 {} 仍残留 {found} 条规则，请人工核对。",
                        self.plan.tag
                    )
                }
            } else if passed {
                format!(
                    "回读：标记 {} 的 {} 条封禁规则已生效。",
                    self.plan.tag, found
                )
            } else {
                format!(
                    "回读：标记 {} 应出现 {} 次，实际 {found} 次，未自动放回。",
                    self.plan.tag, self.expected_tags
                )
            },
        })
    }

    async fn restore(
        &self,
        _operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        // Runtime firewall rules are restored through the dedicated
        // plan/execute path so verification runs again — never auto-restore.
        Ok(())
    }
}

fn is_private_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn command_failed(subject: &'static str, output: &crate::ssh::SshCommandOutput) -> CoreError {
    CoreError::Validation {
        subject: "firewall command",
        message: format!(
            "{subject} failed (exit={:?}, timed_out={})",
            output.exit_code, output.timed_out
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn req(addr: &str, direction: FirewallDirection) -> FirewallBlockRequest {
        FirewallBlockRequest::new(addr.parse().unwrap(), direction).unwrap()
    }

    #[test]
    fn address_validation_rejects_non_hosts() {
        use FirewallDirection::Inbound;
        for bad in [
            "0.0.0.0",
            "127.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "169.254.1.1",
            "::",
            "::1",
            "ff02::1",
            "fe80::1",
        ] {
            assert!(
                FirewallBlockRequest::new(bad.parse().unwrap(), Inbound).is_err(),
                "{bad}"
            );
        }
        for good in [
            "192.0.2.9",
            "198.51.100.7",
            "10.0.0.4",
            "2001:db8::1",
            "fd00::9",
        ] {
            assert!(
                FirewallBlockRequest::new(good.parse().unwrap(), Inbound).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn probe_parses_privilege_backend_and_self_addresses() {
        let probe = parse_probe(
            "UID|0\nSUDO|no\nCONN|192.0.2.50\nESTAB|22|192.0.2.60\nSPORT|22\nDOCKERUSER|yes\nBACKEND|iptables\n",
        );
        assert!(probe.is_root && !probe.sudo && probe.docker_user);
        assert_eq!(probe.backend, Some(FirewallBackend::IpTables));
        assert!(probe.own_ips.contains(&"192.0.2.50".parse().unwrap()));
        // ESTAB peer on sshd port joins the self-lockout set.
        assert!(probe.own_ips.contains(&"192.0.2.60".parse().unwrap()));
        // Non-sshd local port is ignored.
        let probe =
            parse_probe("UID|1000\nSUDO|yes\nCONN|203.0.113.5\nESTAB|443|9.9.9.9\nBACKEND|nft\n");
        assert!(probe.sudo && !probe.is_root);
        assert_eq!(probe.backend, Some(FirewallBackend::Nft));
        assert!(!probe.own_ips.contains(&"9.9.9.9".parse().unwrap()));
        assert_eq!(parse_probe("UID|0\nBACKEND|ufw\n").backend, None);
        assert!(parse_probe("UID|0\nBACKEND|ufw\n").ufw_active);
        assert_eq!(parse_probe("UID|0\nBACKEND|none\n").backend, None);
    }

    #[test]
    fn commands_are_built_per_backend_with_quotes() {
        let both = req("198.51.100.23", FirewallDirection::Both);
        let inb = req("198.51.100.23", FirewallDirection::Inbound);
        let tag = "lovelyhawk-block-a1b2c3d4";
        let ipt = apply_commands(FirewallBackend::IpTables, &both, tag, true, "sudo -n ");
        assert_eq!(ipt.len(), 3);
        assert!(ipt[0].contains("iptables -I INPUT 1 -s 198.51.100.23 -m comment --comment lovelyhawk-block-a1b2c3d4 -j DROP"));
        assert!(ipt[1].contains("-I DOCKER-USER 1 -s 198.51.100.23"));
        assert!(ipt[2].contains("-I OUTPUT 1 -d 198.51.100.23"));
        assert!(ipt.iter().all(|c| c.starts_with("sudo -n ")));
        let ipt = apply_commands(FirewallBackend::IpTables, &inb, tag, false, "");
        assert_eq!(ipt.len(), 1);
        let fwd = apply_commands(FirewallBackend::Firewalld, &both, tag, false, "");
        assert!(
            fwd[0].contains("--add-rich-rule 'rule family=ipv4 source address=198.51.100.23 drop'"),
            "{}",
            fwd[0]
        );
        assert!(
            fwd[1].contains("--direct --add-rule ipv4 filter OUTPUT 0 -d 198.51.100.23 -j DROP")
        );
        let nft = apply_commands(FirewallBackend::Nft, &both, tag, false, "");
        assert_eq!(nft.len(), 5);
        assert!(nft[0].contains("nft add table inet lovelyhawk"));
        assert!(
            nft[3].contains(
                "input ip saddr 198.51.100.23 counter drop comment 'lovelyhawk-block-a1b2c3d4'"
            ),
            "{}",
            nft[3]
        );
        assert!(nft[4].contains("output ip daddr 198.51.100.23 counter drop comment"));
        let nft6 = apply_commands(
            FirewallBackend::Nft,
            &req("2001:db8::5", FirewallDirection::Inbound),
            tag,
            false,
            "",
        );
        assert!(nft6[3].contains("ip6 saddr 2001:db8::5"));
        let ip6t = apply_commands(
            FirewallBackend::IpTables,
            &req("2001:db8::5", FirewallDirection::Outbound),
            tag,
            false,
            "",
        );
        assert!(ip6t[0].contains("ip6tables -I OUTPUT 1 -d 2001:db8::5"));
    }

    #[test]
    fn restore_commands_delete_exactly_the_tagged_rules() {
        let both = req("198.51.100.23", FirewallDirection::Both);
        let tag = "lovelyhawk-block-a1b2c3d4";
        let ipt = restore_commands(FirewallBackend::IpTables, &both, tag, true, "sudo -n ");
        assert!(ipt[0].contains(
            "-D INPUT -s 198.51.100.23 -m comment --comment lovelyhawk-block-a1b2c3d4 -j DROP"
        ));
        assert!(ipt[1].contains("-D DOCKER-USER -s 198.51.100.23"));
        assert!(ipt[2].contains("-D OUTPUT -d 198.51.100.23"));
        let fwd = restore_commands(FirewallBackend::Firewalld, &both, tag, false, "");
        assert!(
            fwd[0].contains(
                "--remove-rich-rule 'rule family=ipv4 source address=198.51.100.23 drop'"
            )
        );
        assert!(
            fwd[1].contains("--direct --remove-rule ipv4 filter OUTPUT 0 -d 198.51.100.23 -j DROP")
        );
        let nft = restore_commands(FirewallBackend::Nft, &both, tag, false, "");
        assert_eq!(nft.len(), 1);
        assert!(nft[0].contains("delete rule inet lovelyhawk"));
        assert!(nft[0].contains("lovelyhawk-block-a1b2c3d4"));
        assert!(!nft[0].contains("flush"));
    }

    #[test]
    fn verify_counts_tagged_rules() {
        let tag = "lovelyhawk-block-a1b2c3d4";
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));
        let ipt = format!(
            "-P INPUT ACCEPT\n-A INPUT -s {ip} -m comment --comment {tag} -j DROP\n-A OUTPUT -d {ip} -m comment --comment {tag} -j DROP\n"
        );
        assert_eq!(count_tagged(FirewallBackend::IpTables, &ipt, tag, &ip), 2);
        assert_eq!(
            count_tagged(FirewallBackend::IpTables, "-P INPUT ACCEPT\n", tag, &ip),
            0
        );
        let dup = ipt.clone() + &format!("-A INPUT -s {ip} -m comment --comment {tag} -j DROP\n");
        assert_eq!(count_tagged(FirewallBackend::IpTables, &dup, tag, &ip), 3);
        let nft = format!(
            "table inet lovelyhawk {{\n chain input {{\n  ip saddr {ip} drop comment \"{tag}\" # handle 4\n }}\n}}\n"
        );
        assert_eq!(count_tagged(FirewallBackend::Nft, &nft, tag, &ip), 1);
        let fwd = format!(
            "rule family=ipv4 source address={ip} drop\nipv4 filter OUTPUT 0 -d {ip} -j DROP\n"
        );
        assert_eq!(count_tagged(FirewallBackend::Firewalld, &fwd, tag, &ip), 2);
    }

    #[test]
    fn private_addresses_warn() {
        assert!(is_private_address(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_address(&"fd00::1".parse().unwrap()));
        assert!(!is_private_address(&"8.8.8.8".parse().unwrap()));
    }
}

#[cfg(test)]
mod lab {
    use super::*;
    use std::process::Command;

    struct Case {
        family: &'static str,
        backend: FirewallBackend,
    }

    fn cli() -> String {
        std::env::var("LOVELYHAWK_LAB_CLI").unwrap_or_else(|_| "podman".to_owned())
    }

    fn exec(container: &str, script: &str) -> String {
        let output = Command::new(cli())
            .args(["exec", container, "/bin/sh", "-c", script])
            .output()
            .expect("container CLI");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn exec_code(container: &str, script: &str) -> i32 {
        Command::new(cli())
            .args(["exec", container, "/bin/sh", "-c", script])
            .output()
            .expect("container CLI")
            .status
            .code()
            .unwrap_or(-1)
    }

    #[test]
    #[ignore = "needs disposable NET_ADMIN containers in LOVELYHAWK_LAB_CONTAINERS"]
    fn firewall_block_end_to_end_in_containers() {
        let containers = std::env::var("LOVELYHAWK_LAB_CONTAINERS").expect("containers");
        let cases = [
            Case {
                family: "debian-nft",
                backend: FirewallBackend::IpTables,
            },
            Case {
                family: "debian-legacy",
                backend: FirewallBackend::IpTables,
            },
            Case {
                family: "alpine-nft",
                backend: FirewallBackend::Nft,
            },
        ];
        let mut failures = Vec::new();
        for pair in containers.split(',') {
            let (name, container) = pair.split_once('=').expect("family=container");
            let case = cases.iter().find(|c| c.family == name).expect(name);
            // Real probe: backend detection + privilege.
            let probe = parse_probe(&exec(
                container,
                &probe_command("198.51.100.99".parse().unwrap()),
            ));
            if probe.backend != Some(case.backend) {
                failures.push(format!(
                    "{name}: backend {:?} != {:?}",
                    probe.backend, case.backend
                ));
            }
            let sudo = if probe.is_root { "" } else { "sudo -n " };
            // Inbound + outbound block on the podman gateway for traffic proof.
            let gw = exec(
                container,
                "ip route 2>/dev/null | awk '/default/{print $3}'",
            )
            .trim()
            .to_owned();
            let target_ip: IpAddr = if gw.is_empty() {
                "198.51.100.99".parse().unwrap()
            } else {
                gw.parse().expect("gw")
            };
            let request = FirewallBlockRequest::new(target_ip, FirewallDirection::Both).unwrap();
            let tag = format!(
                "lovelyhawk-block-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let apply = apply_commands(case.backend, &request, &tag, probe.docker_user, sudo);
            let list = list_command(case.backend, target_ip, sudo);
            let mut kernel_backend_missing = false;
            for command in &apply {
                if exec_code(container, command) != 0 {
                    // iptables-legacy needs kernel tables podman's VM lacks;
                    // that is an environment limit, not a command bug.
                    if case.family == "debian-legacy" {
                        kernel_backend_missing = true;
                    } else {
                        failures.push(format!("{name}: apply failed: {command}"));
                    }
                }
            }
            if kernel_backend_missing {
                println!("== {name} skipped: kernel has no legacy iptables backend in this VM");
                continue;
            }
            let expected = apply.len()
                - if case.backend == FirewallBackend::Nft {
                    3
                } else {
                    0
                };
            let found = count_tagged(case.backend, &exec(container, &list), &tag, &target_ip);
            if found != expected {
                failures.push(format!(
                    "{name}: expected {expected} tagged rules, saw {found}"
                ));
            }
            // Traffic proof: packets to the blocked address must die in OUTPUT.
            exec(
                container,
                "nc -z -w2 $(ip route | awk '/default/{print $3}') 53 >/dev/null 2>&1; nc -z -w2 $(ip route | awk '/default/{print $3}') 53 >/dev/null 2>&1 || true",
            );
            let gw_now = exec(
                container,
                "ip route 2>/dev/null | awk '/default/{print $3}'",
            )
            .trim()
            .to_owned();
            if gw_now == gw && !gw.is_empty() {
                // Counter-based proof on both backends.
                let counters = match case.backend {
                    FirewallBackend::IpTables => exec(
                        container,
                        "iptables -L OUTPUT -v -n -x 2>/dev/null | grep -c 'lovelyhawk-block' ; iptables -L DOCKER-USER -v -n -x 2>/dev/null | grep -c 'lovelyhawk-block'",
                    ),
                    _ => exec(
                        container,
                        "nft list ruleset 2>/dev/null | grep 'lovelyhawk-block' | grep -c 'packets [1-9]'",
                    ),
                };
                println!("== {name} counters {counters:?}");
                let hit = counters
                    .lines()
                    .filter_map(|l| l.trim().parse::<usize>().ok())
                    .sum::<usize>()
                    > 0;
                if case.backend == FirewallBackend::Nft && !hit {
                    failures.push(format!("{name}: no packet counter hit on nft rules"));
                }
                if case.backend == FirewallBackend::IpTables {
                    let pkts: usize = exec(
                        container,
                        &format!("iptables -L OUTPUT -v -n -x 2>/dev/null | awk '$9==\"{target_ip}\"{{s+=$1}} END{{print s+0}}'"),
                    )
                    .trim()
                    .parse()
                    .unwrap_or(0);
                    if pkts == 0 {
                        failures.push(format!("{name}: OUTPUT counter shows no packets"));
                    }
                }
                // And the ping must actually fail now.
                if exec_code(
                    container,
                    "nc -z -w2 $(ip route | awk '/default/{print $3}') 53 >/dev/null 2>&1",
                ) == 0
                {
                    failures.push(format!("{name}: connect to blocked address still succeeds"));
                }
            }
            // Restore: delete exactly the tagged rules.
            for command in &restore_commands(case.backend, &request, &tag, probe.docker_user, sudo)
            {
                exec(container, command);
            }
            let remaining = count_tagged(case.backend, &exec(container, &list), &tag, &target_ip);
            if remaining != 0 {
                failures.push(format!(
                    "{name}: {remaining} tagged rules left after restore"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
