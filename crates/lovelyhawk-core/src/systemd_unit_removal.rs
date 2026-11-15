//! Removing a malicious systemd unit — the `service.remove-unit` row action
//! on the service and autostart inventories.
//!
//! The unit's fragment file, its drop-in directory and its enablement links
//! are moved into a backup tree rather than commented out, so nothing is
//! left for a reload or boot to resurrect. The probe/plan/execute/verify
//! lifecycle re-reads every identity field before acting, and undo puts the
//! moved pieces back for a ten-minute window.

use std::time::Duration;

use async_trait::async_trait;

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::shq;
use crate::ssh::{BoundSshSession, SshCommandOutput};
use crate::system_info::{SystemInfoService, PRECONDITION_TIMEOUT};

/// Refusal subjects the backend maps to operator-facing codes.
pub const UNIT_NOT_LOADED_REFUSAL: &str = "systemd unit not loaded";
pub const UNIT_LOCATION_REFUSAL: &str = "systemd unit location";
pub const UNIT_PACKAGE_REFUSAL: &str = "systemd unit package";
pub const UNIT_PRIVILEGE_REFUSAL: &str = "systemd unit privilege";
pub const UNIT_TOOLS_REFUSAL: &str = "systemd unit tools";
pub const UNIT_CHANGED_REFUSAL: &str = "systemd unit changed";
pub const UNIT_PROBE_REFUSAL: &str = "systemd unit probe";
pub const UNIT_UNDO_REFUSAL: &str = "systemd unit undo";

const EXECUTE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DROPINS: usize = 32;
const MAX_LINKS: usize = 32;
/// Unit files an operator placed directly, which this action may remove.
/// Anything living under package or runtime trees is refused instead.
const LOCAL_DIRS: [&str; 2] = ["/etc/systemd/system/", "/usr/local/lib/systemd/system/"];
const BACKUP_ROOT: &str = "/var/lib/lovelyres-unit-backups";

/// Unit types this action answers and the characters a unit name may carry.
fn is_removable_unit_name(value: &str) -> bool {
    let Some(stem) = value
        .strip_suffix(".service")
        .or_else(|| value.strip_suffix(".timer"))
        .or_else(|| value.strip_suffix(".socket"))
        .or_else(|| value.strip_suffix(".path"))
    else {
        return false;
    };
    !stem.is_empty()
        && stem.len() <= 200
        && stem.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':' | b'\\')
        })
        && !stem.contains("..")
}

/// A service or autostart row resolved to the unit it names.
#[derive(Debug, Clone)]
pub struct SystemdUnitRemovalRequest {
    pub row_id: String,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropIn {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableLink {
    path: String,
    target: String,
}

/// Every fact the plan and the just-before-execution re-check are bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSnapshot {
    pub unit: String,
    pub fragment_path: String,
    pub fragment_sha256: String,
    pub owner: String,
    pub mode: String,
    pub dropins: Vec<DropIn>,
    pub links: Vec<EnableLink>,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    /// The unit's main process and its /proc/<pid>/stat start time, so a pid
    /// reuse cannot make an old process look like the one we saw.
    pub main_pid: Option<u32>,
    pub main_pid_start: Option<String>,
    pub triggered_by: Vec<String>,
    pub exec_start: Option<String>,
}

/// The confirmed, target-bound description of one unit removal.
#[derive(Debug)]
pub struct SystemdUnitRemovalPlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: UnitSnapshot,
    /// `sudo -n ` when the session is not root.
    prefix: &'static str,
}

impl SystemdUnitRemovalPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }
}

/// What a completed removal reports back, plus the undo handle.
#[derive(Debug)]
pub struct SystemdUnitRemovalOutcome {
    pub unit: String,
    pub verification: VerificationResult,
    /// `Some` when the removal verified and its pieces sit in the backup
    /// tree: the backend keeps this so the receipt can offer to put them
    /// back for a bounded window.
    pub undo: Option<SystemdUnitRemovalUndo>,
}

/// The closed description of one undo: the snapshot the removal was built on
/// and where its pieces were moved to.
#[derive(Debug, Clone)]
pub struct SystemdUnitRemovalUndo {
    snapshot: UnitSnapshot,
    backup_dir: String,
    prefix: &'static str,
}

#[derive(Debug, Default)]
struct UnitProbe {
    is_root: bool,
    sudo: bool,
    systemctl: bool,
    show: Option<std::collections::BTreeMap<String, String>>,
    file_kind: Option<String>,
    sha256: Option<String>,
    owner: Option<String>,
    mode: Option<String>,
    package_owned: Option<bool>,
    dropins: Option<Vec<DropIn>>,
    links: Option<Vec<EnableLink>>,
    main_pid_start: Option<String>,
    /// The probe hit a field it could not read at all.
    unreadable: bool,
}

fn probe_command(unit: &str) -> String {
    let u = shq(unit);
    format!(
        "u={u}; \
         printf 'UID|%s\n' \"$(id -u)\"; \
         sudo -n true >/dev/null 2>&1 && echo 'SUDO|yes' || echo 'SUDO|no'; \
         command -v systemctl >/dev/null 2>&1 && echo 'SYSTEMCTL|yes' || echo 'SYSTEMCTL|no'; \
         systemctl show --no-pager -p FragmentPath,DropInPaths,LoadState,ActiveState,SubState,UnitFileState,MainPID,TriggeredBy,Triggers,ExecStart -- \"$u\" 2>/dev/null | sed 's/^/SHOW|/' ; \
         fp=\"$(systemctl show --no-pager -p FragmentPath --value -- \"$u\" 2>/dev/null)\"; \
         if [ -n \"$fp\" ]; then \
         if [ -L \"$fp\" ]; then echo 'FILE|symlink'; elif [ -f \"$fp\" ]; then echo 'FILE|regular'; elif [ -e \"$fp\" ]; then echo 'FILE|other'; else echo 'FILE|missing'; fi; \
         sha256sum -- \"$fp\" 2>/dev/null | awk '{{print \"SHA|\" $1}}'; \
         stat -c 'OWNER|%u:%g' -- \"$fp\" 2>/dev/null || echo 'OWNER|unreadable'; \
         stat -c 'MODE|%a' -- \"$fp\" 2>/dev/null || echo 'MODE|unreadable'; \
         {{ command -v dpkg >/dev/null 2>&1 && dpkg -S -- \"$fp\" >/dev/null 2>&1; }} && echo 'PKG|yes' || \
         {{ command -v rpm >/dev/null 2>&1 && rpm -qf -- \"$fp\" >/dev/null 2>&1; }} && echo 'PKG|yes' || echo 'PKG|no'; \
         fi; \
         dd=\"/etc/systemd/system/$u.d\"; \
         if [ -d \"$dd\" ]; then for f in \"$dd\"/*; do [ -f \"$f\" ] || continue; \
         printf 'DROPIN|%s|%s\n' \"$f\" \"$(sha256sum -- \"$f\" 2>/dev/null | awk '{{print $1}}')\"; done; \
         else echo 'DROPIN|none|none'; fi; \
         for d in /etc/systemd/system/*.wants /etc/systemd/system/*.requires /etc/systemd/system/*.upholds; do \
         [ -L \"$d/$u\" ] && printf 'LINK|%s|%s\n' \"$d/$u\" \"$(readlink \"$d/$u\")\"; done; echo 'LINKSEND|end'; \
         pid=\"$(systemctl show --no-pager -p MainPID --value -- \"$u\" 2>/dev/null)\"; \
         if [ -n \"$pid\" ] && [ \"$pid\" != \"0\" ]; then printf 'START|%s\n' \"$(awk '{{print $22}}' \"/proc/$pid/stat\" 2>/dev/null)\"; fi"
    )
}

fn parse_probe(output: &str) -> UnitProbe {
    let mut probe = UnitProbe::default();
    let mut dropins = Vec::new();
    let mut links = Vec::new();
    let mut saw_dropin_marker = false;
    let mut saw_links_end = false;
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "UID" => probe.is_root = value.trim() == "0",
            "SUDO" => probe.sudo = value.trim() == "yes",
            "SYSTEMCTL" => probe.systemctl = value.trim() == "yes",
            "SHOW" => {
                if let Some((name, field)) = value.split_once('=') {
                    probe
                        .show
                        .get_or_insert_with(std::collections::BTreeMap::new)
                        .insert(name.to_owned(), field.to_owned());
                }
            }
            "FILE" => probe.file_kind = Some(value.trim().to_owned()),
            "SHA" => probe.sha256 = Some(value.trim().to_owned()),
            "OWNER" => {
                if value.trim() == "unreadable" {
                    probe.unreadable = true;
                } else {
                    probe.owner = Some(value.trim().to_owned());
                }
            }
            "MODE" => {
                if value.trim() == "unreadable" {
                    probe.unreadable = true;
                } else {
                    probe.mode = Some(value.trim().to_owned());
                }
            }
            "PKG" => probe.package_owned = Some(value.trim() == "yes"),
            "DROPIN" => {
                saw_dropin_marker = true;
                let mut parts = value.split('|');
                if let (Some(path), Some(sha)) = (parts.next(), parts.next())
                    && path != "none"
                {
                    dropins.push(DropIn {
                        path: path.to_owned(),
                        sha256: sha.trim().to_owned(),
                    });
                }
            }
            "LINK" => {
                let mut parts = value.split('|');
                if let (Some(path), Some(target)) = (parts.next(), parts.next()) {
                    links.push(EnableLink {
                        path: path.to_owned(),
                        target: target.to_owned(),
                    });
                }
            }
            "LINKSEND" => saw_links_end = true,
            "START" => probe.main_pid_start = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    if saw_dropin_marker {
        probe.dropins = Some(dropins);
    }
    if saw_links_end {
        probe.links = Some(links);
    }
    probe
}

fn fragment_is_local(path: &str, unit: &str) -> bool {
    LOCAL_DIRS
        .iter()
        .any(|dir| *path == format!("{dir}{unit}"))
}

/// A digest the probe read must be a real sha256 before it can go anywhere
/// near a shell command line — the value is remote-controlled text.
fn is_hex_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn refusal(subject: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::validation(subject, message)
}

impl SystemInfoService {
    /// Describe moving one unit's files out of the unit search path.
    ///
    /// The probe reads systemctl's own answer plus the fragment, drop-ins and
    /// enablement links once, and refuses anything this action could not put
    /// back faithfully: package-owned or vendor-tree fragments, symlinks,
    /// masked or never-loaded units.
    pub async fn plan_systemd_unit_removal(
        &self,
        session: &BoundSshSession,
        request: &SystemdUnitRemovalRequest,
    ) -> CoreResult<SystemdUnitRemovalPlan> {
        self.target.validate(session.target())?;
        if !is_removable_unit_name(&request.unit) {
            return Err(refusal(
                UNIT_NOT_LOADED_REFUSAL,
                "单元名不是可处理的 service/timer/socket/path 形式",
            ));
        }
        let output = self
            .ssh
            .execute_bound(session, probe_command(&request.unit), PRECONDITION_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(refusal(UNIT_PROBE_REFUSAL, "systemd unit probe timed out"));
        }
        let probe = parse_probe(&output.output);
        if !probe.systemctl {
            return Err(refusal(
                UNIT_TOOLS_REFUSAL,
                "目标机没有可用的 systemctl，无法确认选中的是哪个单元文件",
            ));
        }
        if !(probe.is_root || probe.sudo) {
            return Err(refusal(
                UNIT_PRIVILEGE_REFUSAL,
                "移除 systemd 单元需要 root 或免密码 sudo",
            ));
        }
        let show = probe.show.ok_or_else(|| {
            refusal(UNIT_PROBE_REFUSAL, "systemctl show 没有返回可解析的单元信息")
        })?;
        let load_state = show.get("LoadState").cloned().unwrap_or_default();
        let fragment_path = show.get("FragmentPath").cloned().unwrap_or_default();
        if load_state != "loaded" || fragment_path.is_empty() {
            return Err(refusal(
                UNIT_NOT_LOADED_REFUSAL,
                format!("这个单元当前未加载（LoadState={}），没有可移除的单元文件", if load_state.is_empty() { "未知".to_owned() } else { load_state }),
            ));
        }
        if !fragment_is_local(&fragment_path, &request.unit) {
            return Err(refusal(
                UNIT_LOCATION_REFUSAL,
                "这个单元文件来自软件包或运行时位置，请改用禁用或屏蔽；这里只移除管理员直接放在 /etc/systemd/system 或 /usr/local/lib/systemd/system 的单元",
            ));
        }
        match probe.file_kind.as_deref() {
            Some("regular") => {}
            Some("symlink") | Some("missing") => {
                return Err(refusal(
                    UNIT_NOT_LOADED_REFUSAL,
                    "这个单元是符号链接或已被屏蔽（masked），没有可移除的本地单元文件",
                ));
            }
            _ => {
                return Err(refusal(
                    UNIT_PROBE_REFUSAL,
                    "单元文件类型读不回来或不是普通文件，未敢移除",
                ));
            }
        }
        if probe.package_owned == Some(true) {
            return Err(refusal(
                UNIT_PACKAGE_REFUSAL,
                "这个单元文件属于软件包，删除会破坏软件包完整性，请改用禁用或屏蔽",
            ));
        }
        // A probe that read back only part of itself must not become a plan:
        // missing sections would silently drop pieces the removal then never
        // moves, and a digest that is not a real sha256 cannot go on a shell
        // line in the undo guard.
        if probe.unreadable
            || probe.package_owned.is_none()
            || probe.sha256.as_deref().is_none_or(|sha| !is_hex_sha(sha))
            || probe.owner.is_none()
            || probe.mode.is_none()
            || probe.dropins.is_none()
            || probe.links.is_none()
            || probe
                .dropins
                .as_deref()
                .is_some_and(|list| list.iter().any(|dropin| !is_hex_sha(&dropin.sha256)))
        {
            return Err(refusal(
                UNIT_PROBE_REFUSAL,
                "单元文件的摘要、属主、权限或附属清单读不回来或格式异常，无法安全移除",
            ));
        }
        let dropins = probe.dropins.unwrap_or_default();
        let links = probe.links.unwrap_or_default();
        if dropins.len() > MAX_DROPINS || links.len() > MAX_LINKS {
            return Err(refusal(
                UNIT_PROBE_REFUSAL,
                "这个单元的 drop-in 或启用链接数量超出上限，请手工处理",
            ));
        }
        let main_pid: Option<u32> = show
            .get("MainPID")
            .and_then(|value| value.parse().ok())
            .filter(|pid| *pid != 0);
        let exec_start = show
            .get("ExecStart")
            .map(|value| value.chars().take(200).collect());
        let snapshot = UnitSnapshot {
            unit: request.unit.clone(),
            fragment_path,
            fragment_sha256: probe.sha256.unwrap_or_default(),
            owner: probe.owner.unwrap_or_default(),
            mode: probe.mode.unwrap_or_default(),
            dropins,
            links,
            load_state,
            active_state: show.get("ActiveState").cloned().unwrap_or_default(),
            sub_state: show.get("SubState").cloned().unwrap_or_default(),
            unit_file_state: show.get("UnitFileState").cloned().unwrap_or_default(),
            main_pid,
            main_pid_start: if main_pid.is_some() {
                probe.main_pid_start
            } else {
                None
            },
            triggered_by: show
                .get("TriggeredBy")
                .map(|value| value.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            exec_start,
        };
        let running_note = if snapshot.active_state == "active" {
            format!("服务当前在运行（{} / {}），执行时先停止。", snapshot.active_state, snapshot.sub_state)
        } else {
            format!("服务当前未在运行（{} / {}）。", snapshot.active_state, snapshot.sub_state)
        };
        let dropins_note = if snapshot.dropins.is_empty() {
            "无 drop-in 目录".to_owned()
        } else {
            format!("附带 {} 个 drop-in 文件", snapshot.dropins.len())
        };
        let links_note = if snapshot.links.is_empty() {
            "无开机自启链接".to_owned()
        } else {
            format!("移除 {} 个启用链接", snapshot.links.len())
        };
        let trigger_note = if snapshot.triggered_by.is_empty() {
            String::new()
        } else {
            format!(
                "它由 {} 触发，触发器仍会保留，请另行处理。",
                snapshot.triggered_by.join(" ")
            )
        };
        let exec_note = match &snapshot.exec_start {
            Some(command) => format!("它启动的程序（{}）不会被删除，需要另行处置。", command),
            None => String::new(),
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "移除 systemd 单元 {}：把单元文件 {}（{}{}，{}）移入备份目录（不是注释或禁用，文件整体移出单元搜索路径），随后让 systemd 重读单元表。{}{}{}{}{}文件备份在 {}/<计划编号>/ 下，10 分钟内可从回执撤销。",
                snapshot.unit,
                snapshot.fragment_path,
                snapshot.owner,
                snapshot.mode,
                snapshot.unit_file_state,
                running_note,
                dropins_note,
                links_note,
                trigger_note,
                exec_note,
                BACKUP_ROOT,
            ),
            true,
            Some("把移走的单元文件、drop-in 与启用链接全部放回原位置".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-service-remove".to_owned());
        operation
            .metadata
            .insert("unit".to_owned(), snapshot.unit.clone());
        operation
            .metadata
            .insert("fragment".to_owned(), snapshot.fragment_path.clone());
        Ok(SystemdUnitRemovalPlan {
            operation,
            row_id: request.row_id.clone(),
            snapshot,
            prefix: if probe.is_root { "" } else { "sudo -n " },
        })
    }

    pub async fn execute_systemd_unit_removal(
        &self,
        session: &BoundSshSession,
        plan: SystemdUnitRemovalPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<SystemdUnitRemovalOutcome> {
        let executor = UnitRemovalExecutor {
            service: self,
            session,
            plan: &plan,
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
        // Leaving the unit removed is the containment goal: a verification
        // read that fails is reported, not silently undone — the operator's
        // undo button is the way back, same as the xinetd isolation.
        let verification = operation.verify(&self.target, &executor, journal).await?;
        let undo = verification.passed.then(|| SystemdUnitRemovalUndo {
            snapshot: plan.snapshot.clone(),
            backup_dir: format!("{BACKUP_ROOT}/{}", plan.operation.id),
            prefix: plan.prefix,
        });
        Ok(SystemdUnitRemovalOutcome {
            unit: plan.snapshot.unit,
            verification,
            undo,
        })
    }
}

impl SystemdUnitRemovalUndo {
    /// Put the removed pieces back. Refuses when anything the removal left
    /// has since been recreated or the backup no longer matches, so an undo
    /// never overwrites newer work.
    pub async fn undo(
        &self,
        service: &SystemInfoService,
        session: &BoundSshSession,
    ) -> CoreResult<String> {
        service.target.validate(session.target())?;
        // Every original path must still be empty and every backup file must
        // still carry the recorded digest before anything moves back.
        let mut guards = String::from("set -e; ");
        for path in self.restore_paths() {
            guards.push_str(&format!(
                "[ ! -e {} ] || exit 41; ",
                shq(&path)
            ));
        }
        guards.push_str(&format!("cd {}", shq(&self.backup_dir)));
        for (backup, sha) in self.backup_files() {
            guards.push_str(&format!(
                "; echo '{}  {}' | {}sha256sum -c --status - || exit 42",
                sha,
                shq(&backup),
                self.prefix
            ));
        }
        let output = service
            .ssh
            .execute_bound(session, format!("{}{}", self.prefix, guards), EXECUTE_TIMEOUT)
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(refusal(
                UNIT_UNDO_REFUSAL,
                format!(
                    "原位置已被重新占用或备份内容变了（exit={:?}），没有放回原文件",
                    output.exit_code
                ),
            ));
        }
        // Move back, preserving what the removal preserved.
        let mut restore = format!("{}set -e; ", self.prefix);
        restore.push_str(&format!(
            "mv -- {}/fragment/{} {}; ",
            shq(&self.backup_dir),
            shq(
                self.snapshot
                    .fragment_path
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
            ),
            shq(&self.snapshot.fragment_path)
        ));
        let dropin_dir = format!("/etc/systemd/system/{}.d", self.snapshot.unit);
        if !self.snapshot.dropins.is_empty() {
            restore.push_str(&format!(
                "mv -- {}/dropins {}; ",
                shq(&self.backup_dir),
                shq(&dropin_dir)
            ));
        }
        for link in &self.snapshot.links {
            let group = link
                .path
                .rsplit('/')
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            restore.push_str(&format!(
                "install -d -m 755 {}; mv -- {}/links/{}/{} {}; ",
                shq(&link
                    .path
                    .rsplit('/')
                    .nth(1)
                    .map(|group| format!("/etc/systemd/system/{group}"))
                    .unwrap_or_default()),
                shq(&self.backup_dir),
                shq(&group),
                shq(&self.snapshot.unit),
                shq(&link.path)
            ));
        }
        restore.push_str(&format!("{}systemctl daemon-reload", self.prefix));
        let output = service
            .ssh
            .execute_bound(session, restore, EXECUTE_TIMEOUT)
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(refusal(
                UNIT_UNDO_REFUSAL,
                "放回单元文件时出错，备份目录仍保留，请手工核对",
            ));
        }
        // Independent re-read: systemd must list the unit as loaded again
        // with the unit-file state the plan recorded. The service itself is
        // deliberately not restarted.
        let output = service
            .ssh
            .execute_bound(
                session,
                format!(
                    "u={}; {}systemctl show --no-pager -p LoadState,UnitFileState -- \"$u\"",
                    shq(&self.snapshot.unit),
                    self.prefix
                ),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        let text = output.output;
        let loaded = text.contains("LoadState=loaded");
        let state_back = self.snapshot.unit_file_state.is_empty()
            || text.contains(&format!("UnitFileState={}", self.snapshot.unit_file_state));
        if output.timed_out || !loaded || !state_back {
            return Err(refusal(
                UNIT_UNDO_REFUSAL,
                "文件已放回但 systemd 回读不一致，请手工核对单元状态",
            ));
        }
        Ok(format!(
            "回读：{} 已恢复为 loaded / {}；服务未自动启动，需要时请手工启动。",
            self.snapshot.unit, self.snapshot.unit_file_state
        ))
    }

    fn restore_paths(&self) -> Vec<String> {
        let mut paths = vec![self.snapshot.fragment_path.clone()];
        if !self.snapshot.dropins.is_empty() {
            paths.push(format!("/etc/systemd/system/{}.d", self.snapshot.unit));
        }
        paths.extend(self.snapshot.links.iter().map(|link| link.path.clone()));
        paths
    }

    fn backup_files(&self) -> Vec<(String, String)> {
        let mut files = vec![(
            format!(
                "fragment/{}",
                self.snapshot
                    .fragment_path
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
            ),
            self.snapshot.fragment_sha256.clone(),
        )];
        for dropin in &self.snapshot.dropins {
            let name = dropin.path.rsplit('/').next().unwrap_or_default();
            files.push((format!("dropins/{name}"), dropin.sha256.clone()));
        }
        files
    }
}

#[derive(Debug)]
struct UnitRemovalExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a SystemdUnitRemovalPlan,
}

impl UnitRemovalExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(refusal(
                "systemd unit removal operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn re_probe(&self) -> CoreResult<UnitSnapshot> {
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                probe_command(&self.plan.snapshot.unit),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        if output.timed_out {
            return Err(refusal(UNIT_PROBE_REFUSAL, "systemd unit re-probe timed out"));
        }
        let probe = parse_probe(&output.output);
        let show = probe.show.ok_or_else(|| {
            refusal(UNIT_PROBE_REFUSAL, "systemctl show 没有返回可解析的单元信息")
        })?;
        let main_pid: Option<u32> = show
            .get("MainPID")
            .and_then(|value| value.parse().ok())
            .filter(|pid| *pid != 0);
        Ok(UnitSnapshot {
            unit: self.plan.snapshot.unit.clone(),
            fragment_path: show.get("FragmentPath").cloned().unwrap_or_default(),
            fragment_sha256: probe.sha256.unwrap_or_default(),
            owner: probe.owner.unwrap_or_default(),
            mode: probe.mode.unwrap_or_default(),
            dropins: probe.dropins.unwrap_or_default(),
            links: probe.links.unwrap_or_default(),
            load_state: show.get("LoadState").cloned().unwrap_or_default(),
            active_state: show.get("ActiveState").cloned().unwrap_or_default(),
            sub_state: show.get("SubState").cloned().unwrap_or_default(),
            unit_file_state: show.get("UnitFileState").cloned().unwrap_or_default(),
            main_pid,
            main_pid_start: if main_pid.is_some() {
                probe.main_pid_start
            } else {
                None
            },
            triggered_by: show
                .get("TriggeredBy")
                .map(|value| value.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            exec_start: show
                .get("ExecStart")
                .map(|value| value.chars().take(200).collect()),
        })
    }
}

#[async_trait]
impl OperationExecutor for UnitRemovalExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self.re_probe().await?;
        if observed != self.plan.snapshot {
            return Err(refusal(
                UNIT_CHANGED_REFUSAL,
                "这个 systemd 单元在确认之后变了（文件、链接或运行状态），这次没有移除",
            ));
        }
        self.service.target.validate(&operation.target)?;
        let unit = shq(&self.plan.snapshot.unit);
        let backup = format!("{BACKUP_ROOT}/{}", self.plan.operation.id);
        let prefix = self.plan.prefix;
        let mut script = String::from("set -e; ");
        if self.plan.snapshot.active_state == "active" {
            script.push_str(&format!("{prefix}systemctl stop -- {unit}; "));
        }
        script.push_str(&format!("{prefix}install -d -m 700 {backup_dir}/fragment {backup_dir}/links; ", backup_dir = shq(&backup)));
        if !self.plan.snapshot.dropins.is_empty() {
            script.push_str(&format!(
                "{prefix}mv -- {dropin_dir} {backup_dir}/dropins; ",
                dropin_dir = shq(&format!("/etc/systemd/system/{}.d", self.plan.snapshot.unit)),
                backup_dir = shq(&backup)
            ));
        }
        let fragment_name = self
            .plan
            .snapshot
            .fragment_path
            .rsplit('/')
            .next()
            .unwrap_or_default();
        script.push_str(&format!(
            "{prefix}mv -- {} {}/fragment/{}; ",
            shq(&self.plan.snapshot.fragment_path),
            shq(&backup),
            shq(fragment_name)
        ));
        for link in &self.plan.snapshot.links {
            let group = link.path.rsplit('/').nth(1).unwrap_or_default();
            script.push_str(&format!(
                "{prefix}install -d -m 700 {}/links/{}; {prefix}mv -- {} {}/links/{}/; ",
                shq(&backup),
                shq(group),
                shq(&link.path),
                shq(&backup),
                shq(group)
            ));
        }
        // The manifest records where every piece came from and what digest it
        // carried, so undo can prove nothing else wrote over the backup.
        script.push_str(&format!(
            "{{ printf 'fragment %s %s\\n' {} {}; printf 'unit %s\\n' {}; ",
            shq(&self.plan.snapshot.fragment_path),
            shq(&self.plan.snapshot.fragment_sha256),
            unit
        ));
        for link in &self.plan.snapshot.links {
            script.push_str(&format!("printf 'link %s %s\\n' {} {}; ", shq(&link.path), shq(&link.target)));
        }
        for dropin in &self.plan.snapshot.dropins {
            script.push_str(&format!("printf 'dropin %s %s\\n' {} {}; ", shq(&dropin.path), shq(&dropin.sha256)));
        }
        script.push_str(&format!("}} > {}/manifest.txt; ", shq(&backup)));
        script.push_str(&format!("{prefix}systemctl daemon-reload; {prefix}systemctl reset-failed -- {unit} 2>/dev/null || true"));
        let output: SshCommandOutput = self
            .service
            .ssh
            .execute_bound(self.session, script, EXECUTE_TIMEOUT)
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(refusal(
                "systemd unit removal command",
                format!(
                    "移除脚本没有完成（exit={:?}, timed_out={}），单元文件可能处于半移动状态，请手工核对 {}",
                    output.exit_code, output.timed_out, backup
                ),
            ));
        }
        Ok(ExecutionReceipt {
            summary: format!(
                "单元文件 {} 及其 drop-in、启用链接已移入 {}",
                self.plan.snapshot.fragment_path, backup
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
        let unit = shq(&self.plan.snapshot.unit);
        let mut checks = format!(
            "{prefix}systemctl show --no-pager -p LoadState -- {unit} 2>/dev/null | sed 's/^/LOAD|/'; ",
            prefix = self.plan.prefix
        );
        checks.push_str(&format!(
            "[ -e {} ] && echo 'FRAG|present' || echo 'FRAG|absent'; ",
            shq(&self.plan.snapshot.fragment_path)
        ));
        for link in &self.plan.snapshot.links {
            checks.push_str(&format!(
                "[ -e {} ] || [ -L {} ] && echo 'LINK|present' || true; ",
                shq(&link.path),
                shq(&link.path)
            ));
        }
        checks.push_str("echo 'LINKDONE|end'; ");
        if let Some(pid) = self.plan.snapshot.main_pid {
            checks.push_str(&format!(
                "printf 'PID|%s\\n' \"$(awk '{{print $22}}' /proc/{pid}/stat 2>/dev/null)\"; "
            ));
        }
        let output = self
            .service
            .ssh
            .execute_bound(self.session, checks, PRECONDITION_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(refusal(UNIT_PROBE_REFUSAL, "verification probe timed out"));
        }
        let mut load_not_found = false;
        let mut frag_absent = false;
        let mut links_absent = true;
        let mut pid_gone = true;
        for line in output.output.lines() {
            if let Some(rest) = line.strip_prefix("LOAD|") {
                load_not_found = rest.contains("LoadState=not-found")
                    || rest.contains("LoadState=masked")
                    || rest.trim().is_empty();
            } else if line == "FRAG|absent" {
                frag_absent = true;
            } else if line.starts_with("LINK|present") {
                links_absent = false;
            } else if let Some(start) = line.strip_prefix("PID|") {
                // The recorded start time must be gone: a pid reuse with a
                // different start time counts as gone, the same value does not.
                pid_gone = start.trim().is_empty()
                    || Some(start.trim().to_owned()) != self.plan.snapshot.main_pid_start;
            }
        }
        let passed = load_not_found && frag_absent && links_absent && pid_gone;
        let detail = if passed {
            format!(
                "回读：{} 已不在 systemd 单元表（LoadState=not-found），单元文件与启用链接都已移出，原进程已结束。",
                self.plan.snapshot.unit
            )
        } else {
            let mut parts = Vec::new();
            if !load_not_found {
                parts.push("仍在 systemd 单元表中");
            }
            if !frag_absent {
                parts.push("单元文件仍在原位置");
            }
            if !links_absent {
                parts.push("仍有启用链接存在");
            }
            if !pid_gone {
                parts.push("原主进程仍在运行");
            }
            format!("回读：{} 未完全移除（{}）。", self.plan.snapshot.unit, parts.join("，"))
        };
        Ok(VerificationResult { passed, detail })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(refusal(
            "systemd unit removal restore",
            "unit removal stays out until the operator undoes it",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn show_block() -> String {
        "SHOW|FragmentPath=/etc/systemd/system/lh-beacon.service\n\
         SHOW|DropInPaths=/etc/systemd/system/lh-beacon.service.d/override.conf\n\
         SHOW|LoadState=loaded\nSHOW|ActiveState=active\nSHOW|SubState=running\n\
         SHOW|UnitFileState=enabled\nSHOW|MainPID=4242\nSHOW|TriggeredBy=lh-beacon.timer\n\
         SHOW|Triggers=\nSHOW|ExecStart={ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 3600 ; }\n"
            .to_owned()
    }

    fn probe_output() -> String {
        format!(
            "UID|0\nSUDO|no\nSYSTEMCTL|yes\n{show}\
             FILE|regular\nSHA|abc123\nOWNER|0:0\nMODE|644\nPKG|no\n\
             DROPIN|/etc/systemd/system/lh-beacon.service.d/override.conf|def456\n\
             LINK|/etc/systemd/system/multi-user.target.wants/lh-beacon.service|/etc/systemd/system/lh-beacon.service\n\
             LINKSEND|end\nSTART|987654\n",
            show = show_block()
        )
    }

    #[test]
    fn unit_names_accept_managed_types_only() {
        for name in [
            "lh-beacon.service",
            "backup.timer",
            "watcher.socket",
            "scan.path",
            "evil@inst.service",
        ] {
            assert!(is_removable_unit_name(name), "{name}");
        }
        for name in [
            "", "lh-beacon", "x.target", "x.mount", "../x.service", "x\x00.service",
            "x y.service",
        ] {
            assert!(!is_removable_unit_name(name), "{name}");
        }
    }

    #[test]
    fn fragment_location_only_allows_operator_dirs() {
        assert!(fragment_is_local(
            "/etc/systemd/system/lh-beacon.service",
            "lh-beacon.service"
        ));
        assert!(fragment_is_local(
            "/usr/local/lib/systemd/system/lh-beacon.service",
            "lh-beacon.service"
        ));
        for path in [
            "/usr/lib/systemd/system/lh-beacon.service",
            "/lib/systemd/system/lh-beacon.service",
            "/run/systemd/system/lh-beacon.service",
            "/etc/systemd/system/subdir/lh-beacon.service",
            "/etc/systemd/system/other.service",
        ] {
            assert!(!fragment_is_local(path, "lh-beacon.service"), "{path}");
        }
    }

    #[test]
    fn probe_parses_a_complete_removable_unit() {
        let probe = parse_probe(&probe_output());
        assert!(probe.is_root && !probe.sudo && probe.systemctl);
        let show = probe.show.expect("systemctl show parsed");
        assert_eq!(
            show.get("FragmentPath").map(String::as_str),
            Some("/etc/systemd/system/lh-beacon.service")
        );
        assert_eq!(show.get("LoadState").map(String::as_str), Some("loaded"));
        assert_eq!(show.get("MainPID").map(String::as_str), Some("4242"));
        assert_eq!(
            show.get("TriggeredBy").map(String::as_str),
            Some("lh-beacon.timer")
        );
        assert_eq!(probe.file_kind.as_deref(), Some("regular"));
        assert_eq!(probe.sha256.as_deref(), Some("abc123"));
        assert_eq!(probe.owner.as_deref(), Some("0:0"));
        assert_eq!(probe.mode.as_deref(), Some("644"));
        assert_eq!(probe.package_owned, Some(false));
        assert_eq!(
            probe.dropins,
            Some(vec![DropIn {
                path: "/etc/systemd/system/lh-beacon.service.d/override.conf".to_owned(),
                sha256: "def456".to_owned(),
            }])
        );
        assert_eq!(
            probe.links,
            Some(vec![EnableLink {
                path: "/etc/systemd/system/multi-user.target.wants/lh-beacon.service".to_owned(),
                target: "/etc/systemd/system/lh-beacon.service".to_owned(),
            }])
        );
        assert_eq!(probe.main_pid_start.as_deref(), Some("987654"));
    }

    #[test]
    fn probe_marks_missing_fields_as_none_not_empty() {
        let probe = parse_probe("UID|0\nSUDO|no\nSYSTEMCTL|yes\n");
        assert!(probe.show.is_none());
        assert!(probe.file_kind.is_none());
        assert!(probe.dropins.is_none());
        assert!(probe.links.is_none());
        assert!(probe.package_owned.is_none());
    }

    #[test]
    fn probe_command_quotes_and_bounds_every_read() {
        let command = probe_command("weird'unit.service");
        assert!(command.contains("u='weird'\\''unit.service'"));
        assert!(command.contains("systemctl show --no-pager"));
        assert!(command.contains("/etc/systemd/system/$u.d"));
        assert!(command.contains("dpkg -S -- \"$fp\""));
        assert!(command.contains("readlink \"$d/$u\""));
    }

    #[test]
    fn probe_flags_unreadable_fields_and_package_ownership() {
        let probe = parse_probe(
            "UID|1000\nSUDO|yes\nSYSTEMCTL|yes\nFILE|regular\nSHA|abc\n\
             OWNER|unreadable\nMODE|unreadable\nPKG|yes\n\
             DROPIN|none|none\nLINKSEND|end\n",
        );
        assert!(!probe.is_root && probe.sudo);
        assert!(probe.unreadable);
        assert!(probe.owner.is_none() && probe.mode.is_none());
        assert_eq!(probe.package_owned, Some(true));
        // The no-drop-in marker still proves the drop-in section ran.
        assert_eq!(probe.dropins, Some(Vec::new()));
    }

    #[test]
    fn probe_marks_a_masked_or_symlinked_fragment() {
        for kind in ["symlink", "missing", "other"] {
            let probe = parse_probe(&format!("FILE|{kind}\nLINKSEND|end\n"));
            assert_eq!(probe.file_kind.as_deref(), Some(kind));
        }
    }

    #[test]
    fn probe_without_links_end_keeps_links_unknown() {
        // Output that stops before the link scan finished must read as
        // unknown, never as "no links": planning on a truncated list would
        // leave enablement links behind.
        let probe = parse_probe("UID|0\nLINK|/etc/systemd/system/a.wants/x.service|/x\n");
        assert!(probe.links.is_none());
        assert!(probe.dropins.is_none());
    }

    #[test]
    fn digests_must_be_real_sha256_before_they_touch_a_command() {
        assert!(is_hex_sha(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ));
        for bad in [
            "",
            "abc",
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
            "'; rm -rf / #padding-to-sixty-four-chars-0123456789abcdef",
            &"a".repeat(63),
            &"a".repeat(65),
        ] {
            assert!(!is_hex_sha(bad), "{bad}");
        }
    }

    #[test]
    fn undo_guard_paths_cover_every_moved_piece() {
        let snapshot = UnitSnapshot {
            unit: "lh-beacon.service".to_owned(),
            fragment_path: "/etc/systemd/system/lh-beacon.service".to_owned(),
            fragment_sha256: "a".repeat(64),
            owner: "0:0".to_owned(),
            mode: "644".to_owned(),
            dropins: vec![DropIn {
                path: "/etc/systemd/system/lh-beacon.service.d/override.conf".to_owned(),
                sha256: "b".repeat(64),
            }],
            links: vec![EnableLink {
                path: "/etc/systemd/system/multi-user.target.wants/lh-beacon.service".to_owned(),
                target: "/etc/systemd/system/lh-beacon.service".to_owned(),
            }],
            load_state: "loaded".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            unit_file_state: "enabled".to_owned(),
            main_pid: Some(4242),
            main_pid_start: Some("987654".to_owned()),
            triggered_by: vec![],
            exec_start: None,
        };
        let undo = SystemdUnitRemovalUndo {
            snapshot,
            backup_dir: format!("{BACKUP_ROOT}/plan-1"),
            prefix: "sudo -n ",
        };
        let paths = undo.restore_paths();
        assert!(paths.contains(&"/etc/systemd/system/lh-beacon.service".to_owned()));
        assert!(paths.contains(&"/etc/systemd/system/lh-beacon.service.d".to_owned()));
        assert!(
            paths.contains(
                &"/etc/systemd/system/multi-user.target.wants/lh-beacon.service".to_owned()
            )
        );
        let files = undo.backup_files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "fragment/lh-beacon.service");
        assert_eq!(files[1].0, "dropins/override.conf");
    }
}
