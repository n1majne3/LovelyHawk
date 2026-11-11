//! Restoring a system command from the backup residue left beside it — the
//! guided half of the roadmap's "trojaned command" repair item.
//!
//! A workbench check names residue such as `/bin/ls.bak` or `/usr/bin/lsd`
//! next to the command it shadows; this plans writing the residue back over
//! the command in place. Everything runs over the bound SSH channel the
//! workbench reads through (SFTP is not required): the plan snapshots the
//! digests of the command and the residue, execution refuses when either
//! moved, the replaced bytes are quarantined alongside for undo, and
//! verification re-reads all three. Package verification and a bounded
//! `--version` run are reported as observations, not gates — residue may
//! legitimately differ from the installed package, and a file that runs is
//! not thereby trusted.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan, OperationState,
    PlannedOperation, PortableOperationJournal, VerificationResult,
};
use crate::sftp::RemotePath;
use crate::shell_escape::shq;
use crate::ssh::BoundSshSession;
use crate::system_info::SystemInfoService;
use crate::target::TargetContext;

/// Refusal subjects the backend maps to operator-facing codes.
pub const RESTORE_TOOLS_REFUSAL: &str = "command restore tools";
pub const RESTORE_PRIVILEGE_REFUSAL: &str = "command restore privilege";
pub const RESTORE_KIND_REFUSAL: &str = "command restore kind";
pub const RESTORE_LOCATION_REFUSAL: &str = "command restore location";
pub const RESTORE_EMPTY_REFUSAL: &str = "command restore empty";
pub const RESTORE_AMBIGUOUS_REFUSAL: &str = "command restore ambiguous";
pub const RESTORE_CHANGED_REFUSAL: &str = "command restore changed";

const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(15);
/// The restored bytes are run only to see whether they run at all; a hang is
/// reported, not waited on.
const FUNCTIONAL_TIMEOUT: Duration = Duration::from_secs(8);
/// The backend registry expires plans after five minutes; the executor keeps
/// the same ceiling so a plan held elsewhere cannot run later either.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);

/// Only a file that lives directly in a system command directory may be
/// restored this way; residue anywhere else is an operator decision, not a
/// menu item's.
const SYSTEM_BIN_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Names the workbench also flags: planted copies of a command under a
/// `name+d` spelling. They are weaker evidence than an explicit backup, so
/// they restore only when no explicit backup exists.
const D_VARIANTS: &[(&str, &str)] = &[
    ("ps", "psd"),
    ("ls", "lsd"),
    ("netstat", "netstatd"),
    ("top", "topd"),
];

/// Whether a candidate is an explicit backup spelling (`ls.bak`, `ls.orig`,
/// `ls.old`, `ls~`, `.ls`) or one of the known `d`-suffixed planted copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidueKind {
    Backup,
    Variant,
}

impl ResidueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backup => "backup",
            Self::Variant => "variant",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "backup" => Some(Self::Backup),
            "variant" => Some(Self::Variant),
            _ => None,
        }
    }
}

/// A regular file beside the command that could be its replacement, as the
/// probe measured it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidueCandidate {
    path: RemotePath,
    sha256: String,
    size: u64,
    kind: ResidueKind,
}

impl ResidueCandidate {
    pub fn path(&self) -> &RemotePath {
        &self.path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn kind(&self) -> ResidueKind {
        self.kind
    }
}

/// Which package manager named the command's owner, and the name it gave.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandPackage {
    name: String,
    tool: PackageTool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageTool {
    Dpkg,
    Rpm,
}

impl CommandPackage {
    /// `dpkg --verify` takes one package name; a `pkg1, pkg2` ownership line
    /// verifies its first owner.
    fn verify_name(&self) -> &str {
        self.name
            .split(',')
            .next()
            .map(str::trim)
            .unwrap_or(&self.name)
    }
}

/// What one bounded probe learns about the command, its owner and the
/// residue that could restore it.
#[derive(Debug, Default)]
struct RestoreProbe {
    is_root: bool,
    sudo: bool,
    sha256sum: bool,
    regular: bool,
    sha256: Option<String>,
    package: Option<CommandPackage>,
    candidates: Vec<ResidueCandidate>,
}

/// Each candidate goes to the host as one `kind|path` word. `|` cannot
/// appear inside a kind, and splitting at the first `|` keeps any `|` inside
/// a hostile path intact.
fn probe_command(path: &RemotePath, candidates: &[(RemotePath, ResidueKind)]) -> String {
    let quoted = shq(path.as_str());
    let specs = candidates
        .iter()
        .map(|(candidate, kind)| shq(&format!("{}|{}", kind.as_str(), candidate.as_str())))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "printf 'UID|%s\n' \"$(id -u)\"; \
         if sudo -n true >/dev/null 2>&1; then echo 'SUDO|yes'; else echo 'SUDO|no'; fi; \
         lh_p=; [ \"$(id -u)\" = '0' ] || {{ sudo -n true >/dev/null 2>&1 && lh_p='sudo -n '; }}; \
         command -v sha256sum >/dev/null 2>&1 && echo 'SHA256SUM|yes' || echo 'SHA256SUM|no'; \
         if [ -f {quoted} ] && [ ! -L {quoted} ]; then echo 'FILE|regular'; else echo 'FILE|other'; fi; \
         ${{lh_p}}sha256sum -- {quoted} 2>/dev/null | awk '{{print \"SHA|\" $1}}'; \
         if command -v dpkg >/dev/null 2>&1; then \
             lh_t={quoted}; lh_a=; case \"$lh_t\" in /usr/bin/*|/usr/sbin/*) lh_a=\"${{lh_t#/usr}}\";; /bin/*|/sbin/*) lh_a=\"/usr$lh_t\";; esac; \
             for lh_q in \"$lh_t\" \"$lh_a\"; do \
                 [ -n \"$lh_q\" ] || continue; \
                 lh_o=$(dpkg -S \"$lh_q\" 2>/dev/null | awk -v q=\"$lh_q\" 'index($0,\": \"){{p=substr($0,index($0,\": \")+2); if(p==q){{sub(/: .*/,\"\",$0); print; exit}}}}'); \
                 if [ -n \"$lh_q\" ] && [ -n \"$lh_o\" ]; then printf 'PKG|dpkg|%s\n' \"$lh_o\"; break; fi; \
             done; \
         fi; \
         lh_rpm=$(LC_ALL=C rpm -q -f {quoted} --qf '%{{NAME}}\\n' 2>/dev/null | head -n 1); \
         case \"$lh_rpm\" in ''|*not\\ owned*) ;; *) printf 'PKG|rpm|%s\n' \"$lh_rpm\" ;; esac; \
         for lh_spec in {specs}; do \
             lh_k=${{lh_spec%%|*}}; lh_c=${{lh_spec#*|}}; \
             [ -f \"$lh_c\" ] && [ ! -L \"$lh_c\" ] || continue; \
             lh_h=$(${{lh_p}}sha256sum -- \"$lh_c\" 2>/dev/null | awk '{{print $1}}'); \
             [ -n \"$lh_h\" ] || continue; \
             lh_s=$(${{lh_p}}wc -c -- \"$lh_c\" 2>/dev/null | awk '{{print $1}}'); \
             printf 'CAND|%s|%s|%s|%s\n' \"$lh_k\" \"$lh_s\" \"$lh_h\" \"$lh_c\"; \
         done; \
         true"
    )
}

/// Every residue spelling probed beside `name`, in the order they are
/// preferred. `dir.child` cannot fail on names a valid `file_name` produces,
/// but a refused component simply is not offered.
fn residue_candidates(dir: &RemotePath, name: &str) -> Vec<(RemotePath, ResidueKind)> {
    let mut names: Vec<(String, ResidueKind)> = vec![
        (format!("{name}.bak"), ResidueKind::Backup),
        (format!("{name}.orig"), ResidueKind::Backup),
        (format!("{name}.old"), ResidueKind::Backup),
        (format!("{name}~"), ResidueKind::Backup),
        (format!(".{name}"), ResidueKind::Backup),
        // dpkg's own residue from interrupted or diverted package writes;
        // `.dpkg-tmp`/`.dpkg-remove` are deliberately not offered — they are
        // incomplete states, not content to put back.
        (format!("{name}.dpkg-old"), ResidueKind::Backup),
        (format!("{name}.dpkg-new"), ResidueKind::Backup),
        (format!("{name}.dpkg-bak"), ResidueKind::Backup),
    ];
    if let Some((_, variant)) = D_VARIANTS.iter().find(|(base, _)| *base == name) {
        names.push(((*variant).to_owned(), ResidueKind::Variant));
    }
    names
        .into_iter()
        .filter_map(|(candidate, kind)| dir.child(&candidate).ok().map(|path| (path, kind)))
        .collect()
}

fn parse_probe(output: &str, asked: &[(RemotePath, ResidueKind)]) -> RestoreProbe {
    let mut probe = RestoreProbe::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('|') else {
            continue;
        };
        match key {
            "UID" => probe.is_root = value.trim() == "0",
            "SUDO" => probe.sudo = value.trim() == "yes",
            "SHA256SUM" => probe.sha256sum = value.trim() == "yes",
            "FILE" => probe.regular = value.trim() == "regular",
            "SHA" => probe.sha256 = Some(value.trim().to_owned()),
            "PKG" if probe.package.is_none() => {
                let mut parts = value.splitn(2, '|');
                let tool = match parts.next() {
                    Some("dpkg") => Some(PackageTool::Dpkg),
                    Some("rpm") => Some(PackageTool::Rpm),
                    _ => None,
                };
                if let (Some(tool), Some(name)) = (tool, parts.next().map(str::trim))
                    && !name.is_empty()
                    && name.len() <= 128
                {
                    probe.package = Some(CommandPackage {
                        name: name.to_owned(),
                        tool,
                    });
                }
            }
            "CAND" => {
                let mut parts = value.splitn(4, '|');
                if let (Some(kind), Some(size), Some(sha256), Some(path)) = (
                    parts.next().and_then(ResidueKind::parse),
                    parts.next(),
                    parts.next().map(str::trim),
                    parts.next().map(str::trim),
                ) && !sha256.is_empty()
                    // The host answers under our markers but is not trusted:
                    // only a file actually asked about may become a source.
                    && let Some((asked_path, _)) = asked.iter().find(|(asked_path, asked_kind)| {
                        asked_path.as_str() == path && *asked_kind == kind
                    })
                    && !probe.candidates.iter().any(|candidate| {
                        candidate.path.as_str() == asked_path.as_str()
                    })
                {
                    probe.candidates.push(ResidueCandidate {
                        path: asked_path.clone(),
                        sha256: sha256.to_owned(),
                        size: size.trim().parse().unwrap_or(0),
                        kind,
                    });
                }
            }
            _ => {}
        }
    }
    probe
}

/// Deterministic pick: an explicit backup always beats a `d`-variant, and
/// more than one explicit backup is a refusal — a wrong pick is worse. An
/// empty winner is refused too: zero bytes would verify cleanly after the
/// write while leaving the command useless.
fn choose_source(candidates: &[ResidueCandidate]) -> CoreResult<&ResidueCandidate> {
    let mut backups = candidates
        .iter()
        .filter(|candidate| candidate.kind == ResidueKind::Backup);
    let picked = match (backups.next(), backups.next()) {
        (Some(_), Some(_)) => return Err(ambiguous(candidates)),
        (Some(only), None) => only,
        (None, _) => {
            let mut variants = candidates
                .iter()
                .filter(|candidate| candidate.kind == ResidueKind::Variant);
            match (variants.next(), variants.next()) {
                (Some(only), None) => only,
                _ => return Err(ambiguous(candidates)),
            }
        }
    };
    if picked.size == 0 {
        return Err(CoreError::validation(
            RESTORE_EMPTY_REFUSAL,
            "找到的备份残留是空文件，不能据此恢复",
        ));
    }
    Ok(picked)
}

fn ambiguous(candidates: &[ResidueCandidate]) -> CoreError {
    let list = candidates
        .iter()
        .map(|candidate| candidate.path.as_str())
        .collect::<Vec<_>>()
        .join("、");
    CoreError::validation(
        RESTORE_AMBIGUOUS_REFUSAL,
        format!("同目录下有多个备份残留：{list}，无法自动判断来源，请人工核实后再恢复"),
    )
}

/// The same reads run before the write, during undo, and at verification:
/// the command's digest, the residue's digest, the quarantine copy's digest
/// and whether that path exists at all.
fn state_command(
    prefix: &str,
    target: &RemotePath,
    source: &RemotePath,
    quarantine: &RemotePath,
) -> String {
    format!(
        "{prefix}sha256sum -- {t} 2>/dev/null | awk '{{print \"SHA|\" $1}}'; \
         {prefix}sha256sum -- {s} 2>/dev/null | awk '{{print \"SHASRC|\" $1}}'; \
         {prefix}sha256sum -- {q} 2>/dev/null | awk '{{print \"SHAQ|\" $1}}'; \
         [ -e {q} ] && echo 'QE|yes' || echo 'QE|no'",
        t = shq(target.as_str()),
        s = shq(source.as_str()),
        q = shq(quarantine.as_str()),
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RestoreState {
    target_sha256: Option<String>,
    source_sha256: Option<String>,
    quarantine_sha256: Option<String>,
    quarantine_exists: bool,
}

fn parse_state(output: &str) -> RestoreState {
    let mut state = RestoreState::default();
    for line in output.lines() {
        if let Some(sha) = marker(line, "SHA|") {
            state.target_sha256 = Some(sha.to_owned());
        } else if let Some(sha) = marker(line, "SHASRC|") {
            state.source_sha256 = Some(sha.to_owned());
        } else if let Some(sha) = marker(line, "SHAQ|") {
            state.quarantine_sha256 = Some(sha.to_owned());
        } else if line.trim() == "QE|yes" {
            state.quarantine_exists = true;
        }
    }
    state
}

fn marker<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.strip_prefix(name).map(str::trim)
}

/// Refuses before anything is written when the command, the residue, or the
/// quarantine slot moved since the plan was read. The message deliberately
/// carries the changed-after-planning wording the boundary recognises, so
/// the receipt says "untouched" rather than "could not restore".
fn expect_planned_state(
    state: &RestoreState,
    target_sha256: &str,
    source_sha256: &str,
) -> CoreResult<()> {
    if state.target_sha256.as_deref() != Some(target_sha256) {
        return Err(CoreError::validation(
            RESTORE_CHANGED_REFUSAL,
            "file content changed after the operation was planned; nothing was modified",
        ));
    }
    if state.source_sha256.as_deref() != Some(source_sha256) {
        return Err(CoreError::validation(
            RESTORE_CHANGED_REFUSAL,
            "residue file content changed after the operation was planned; nothing was modified",
        ));
    }
    if state.quarantine_exists {
        return Err(CoreError::validation(
            RESTORE_CHANGED_REFUSAL,
            "file content changed after the operation was planned; the quarantine path appeared; nothing was modified",
        ));
    }
    Ok(())
}

/// What restore does next given the current digests.
#[derive(Debug, PartialEq, Eq)]
enum RestoreStep {
    /// The command already carries the pre-operation bytes; only our copy
    /// may still need removing.
    AlreadyOriginal,
    /// The command still carries the restored bytes and the quarantine copy
    /// still proves the original; put it back, then remove the copy.
    PutBack,
    Refuse(&'static str),
}

fn restore_decision(state: &RestoreState, target_sha256: &str, source_sha256: &str) -> RestoreStep {
    if state.target_sha256.as_deref() == Some(target_sha256) {
        return RestoreStep::AlreadyOriginal;
    }
    if state.target_sha256.as_deref() != Some(source_sha256) {
        return RestoreStep::Refuse("target changed after the operation; nothing was undone");
    }
    if !state.quarantine_exists || state.quarantine_sha256.as_deref() != Some(target_sha256) {
        return RestoreStep::Refuse(
            "the quarantine copy needed to put the command back is missing or changed",
        );
    }
    RestoreStep::PutBack
}

/// `cat`, never `cp`: a trojaned `cp` is part of the threat model, and
/// truncating in place keeps the file's inode, owner and mode. The whole
/// script runs under the privilege prefix so the redirection gets it too.
fn quarantine_script(target: &RemotePath, quarantine: &RemotePath) -> String {
    format!(
        "cat -- {t} > {q} && chmod 600 {q} && sha256sum -- {q} | awk '{{print \"QSHA|\" $1}}'",
        t = shq(target.as_str()),
        q = shq(quarantine.as_str()),
    )
}

fn replace_script(source: &RemotePath, target: &RemotePath) -> String {
    format!(
        "cat -- {s} > {t} && sha256sum -- {t} | awk '{{print \"TSHA|\" $1}}'",
        s = shq(source.as_str()),
        t = shq(target.as_str()),
    )
}

fn put_back_script(quarantine: &RemotePath, target: &RemotePath) -> String {
    format!(
        "cat -- {q} > {t} && sha256sum -- {t} | awk '{{print \"TSHA|\" $1}}'",
        q = shq(quarantine.as_str()),
        t = shq(target.as_str()),
    )
}

fn privileged_script(prefix: &str, script: String) -> String {
    format!("{prefix}sh -c {}", shq(&script))
}

fn remove_quarantine_command(prefix: &str, quarantine: &RemotePath) -> String {
    format!("{prefix}rm -f -- {}", shq(quarantine.as_str()))
}

/// The package manager's own answer about the file, kept as text the
/// operator reads. A differing residue is legitimate — this is an
/// observation, never a gate.
fn package_verify_command(package: &CommandPackage, target: &RemotePath) -> String {
    let quoted_name = shq(package.verify_name());
    let quoted_target = shq(target.as_str());
    // dpkg's records predate usrmerge: the verify listing spells /bin/ls
    // while the operator's path is /usr/bin/ls. Match either spelling.
    let twin = format!(
        "lh_t={quoted_target}; lh_a=; case \"$lh_t\" in /usr/bin/*|/usr/sbin/*) lh_a=\"${{lh_t#/usr}}\";; /bin/*|/sbin/*) lh_a=\"/usr$lh_t\";; esac; "
    );
    match package.tool {
        PackageTool::Dpkg => format!(
            "{twin}dpkg --verify {quoted_name} 2>&1 | while IFS= read -r lh_l; do \
                 case \"${{lh_l##* }}\" in \"$lh_t\"|\"$lh_a\") printf 'PKGV|%s\n' \"$lh_l\";; esac; \
             done | head -n 4"
        ),
        PackageTool::Rpm => format!(
            "LC_ALL=C rpm -Vf {quoted_target} 2>&1 | while IFS= read -r lh_l; do \
                 [ \"${{lh_l##* }}\" = {quoted_target} ] && printf 'PKGV|%s\n' \"$lh_l\"; \
             done | head -n 4"
        ),
    }
}

/// Whether the restored bytes run at all. Runs unprivileged on purpose:
/// privilege must never be lent to a file we only just stopped distrusting.
/// Output is bounded and the exit code comes back as a marked line.
fn functional_command(target: &RemotePath) -> String {
    format!(
        "{{ {t} --version 2>&1; printf 'FUNCRC|%s\n' \"$?\"; }} | head -c 4096",
        t = shq(target.as_str()),
    )
}

fn ensure_plan(plan: &OperationPlan, operation: &OperationPlan) -> CoreResult<()> {
    if operation.id != plan.id || operation.target != plan.target {
        return Err(CoreError::validation(
            "command restore operation",
            "executor is bound to a different immutable plan",
        ));
    }
    if Utc::now() - plan.created_at > PLAN_TTL {
        return Err(CoreError::validation(
            "command restore operation",
            "计划已过期，请重新规划",
        ));
    }
    Ok(())
}

impl SystemInfoService {
    /// Describe writing the chosen residue over `path`, keeping the current
    /// bytes beside it for one undo.
    ///
    /// Refuses before planning when `path` is not directly inside a system
    /// command directory, when it is not a plain regular file, when the
    /// account cannot write it, when `sha256sum` is missing, when no residue
    /// exists, or when several explicit backups make the pick ambiguous.
    pub async fn plan_command_restore(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
        journal: PortableOperationJournal,
    ) -> CoreResult<CommandRestoreOperation> {
        self.target.validate(session.target())?;
        let dir = path.parent().map_err(|_| {
            CoreError::validation(RESTORE_LOCATION_REFUSAL, "只能恢复系统命令目录里的命令")
        })?;
        if !SYSTEM_BIN_DIRS.contains(&dir.as_str()) {
            return Err(CoreError::validation(
                RESTORE_LOCATION_REFUSAL,
                format!(
                    "只能恢复系统命令目录（{}）里的命令，{dir} 不在范围内",
                    SYSTEM_BIN_DIRS.join(" "),
                    dir = dir.as_str()
                ),
            ));
        }
        let name = path.file_name().map_err(|_| {
            CoreError::validation(RESTORE_LOCATION_REFUSAL, "只能恢复系统命令目录里的命令")
        })?;
        let asked = residue_candidates(&dir, name);
        let output = self
            .ssh
            .execute_bound(session, probe_command(path, &asked), PROBE_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("command restore probe", &output));
        }
        let probe = parse_probe(&output.output, &asked);
        if !probe.sha256sum {
            return Err(CoreError::validation(
                RESTORE_TOOLS_REFUSAL,
                "目标机缺少 sha256sum，无法安全核对写回的内容",
            ));
        }
        if !probe.regular {
            return Err(CoreError::validation(
                RESTORE_KIND_REFUSAL,
                "只能恢复普通文件；符号链接、目录与其他类型不支持",
            ));
        }
        if probe.sha256.is_none() {
            return Err(CoreError::validation(
                RESTORE_TOOLS_REFUSAL,
                "无法取得目标文件的摘要，无法安全核对写回的内容",
            ));
        }
        if !(probe.is_root || probe.sudo) {
            return Err(CoreError::validation(
                RESTORE_PRIVILEGE_REFUSAL,
                "需要 root 或免密码 sudo 才能写回系统命令",
            ));
        }
        if probe.candidates.is_empty() {
            return Err(CoreError::validation(
                RESTORE_EMPTY_REFUSAL,
                "同目录下没有找到可用于恢复的备份残留",
            ));
        }
        let source = choose_source(&probe.candidates)?;
        let prefix = if probe.is_root { "" } else { "sudo -n " };
        // The quarantine path gets its own id; embedding the plan id would
        // mean writing the summary after the plan exists, and the link lives
        // in metadata anyway.
        let quarantine =
            RemotePath::new(format!("{}.lh-replaced-{}", path.as_str(), Uuid::new_v4())).map_err(
                |_| CoreError::validation("command restore quarantine", "invalid quarantine path"),
            )?;
        let package_label = probe
            .package
            .as_ref()
            .map(|package| format!("，包归属 {name}", name = package.name))
            .unwrap_or_default();
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "用残留 {source} 的内容写回 {target}{package_label}；当前内容留底为 {quarantine}（仅属主可读）。写回后做软件包校验并试跑一次；能运行不代表可信。",
                source = source.path.as_str(),
                target = path.as_str(),
                quarantine = quarantine.as_str(),
            ),
            true,
            Some(format!(
                "把留底的内容写回 {target}，并删除该留底",
                target = path.as_str()
            )),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "command-restore".to_owned());
        operation
            .metadata
            .insert("action".to_owned(), "restore-residue".to_owned());
        operation
            .metadata
            .insert("path".to_owned(), path.as_str().to_owned());
        operation.metadata.insert(
            "target-sha256".to_owned(),
            probe.sha256.clone().unwrap_or_default(),
        );
        operation
            .metadata
            .insert("source-path".to_owned(), source.path.as_str().to_owned());
        operation
            .metadata
            .insert("source-sha256".to_owned(), source.sha256.clone());
        operation
            .metadata
            .insert("quarantine-path".to_owned(), quarantine.as_str().to_owned());
        if let Some(package) = &probe.package {
            operation
                .metadata
                .insert("package".to_owned(), package.name.clone());
        }
        let executor = CommandRestoreExecutor {
            service: self.clone(),
            session: session.clone(),
            target: path.clone(),
            target_sha256: probe.sha256.unwrap_or_default(),
            source: source.clone(),
            quarantine,
            package: probe.package,
            prefix,
            plan: operation.clone(),
            candidates: probe.candidates,
        };
        Ok(CommandRestoreOperation {
            operation: PlannedOperation::plan(operation),
            executor,
            target: self.target.clone(),
            journal,
        })
    }
}

/// The stored operation the backend registry holds between plan and undo.
#[derive(Debug)]
pub struct CommandRestoreOperation {
    operation: PlannedOperation,
    executor: CommandRestoreExecutor,
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
}

impl CommandRestoreOperation {
    pub fn definition(&self) -> &OperationPlan {
        self.operation.definition()
    }

    pub fn state(&self) -> OperationState {
        self.operation.state()
    }

    /// The residue file the plan will write over the command.
    pub fn source(&self) -> &ResidueCandidate {
        &self.executor.source
    }

    /// Every regular-file candidate the probe saw beside the command.
    pub fn candidates(&self) -> &[ResidueCandidate] {
        &self.executor.candidates
    }

    /// The owning package name, when dpkg or rpm could name one.
    pub fn package_name(&self) -> Option<&str> {
        self.executor
            .package
            .as_ref()
            .map(|package| package.name.as_str())
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
        self.operation.journal(&self.journal)?;
        self.operation
            .verify(&self.target, &self.executor, &self.journal)
            .await
    }

    pub async fn restore(&mut self) -> CoreResult<()> {
        self.operation
            .restore(&self.target, &self.executor, &self.journal)
            .await
    }

    /// A verified restore is undoable until the command moves on: undo first
    /// re-runs this operation's own check, so a later change is never
    /// overwritten.
    pub fn can_undo(&self) -> bool {
        self.operation.state() == OperationState::Verified
    }

    pub async fn undo(&mut self) -> CoreResult<String> {
        if !self.can_undo() {
            return Err(CoreError::validation(
                "undo",
                "only a completed, verified operation of an undoable kind can be undone",
            ));
        }
        self.target.validate(&self.operation.definition().target)?;
        let receipt = self.operation.execution_receipt()?.clone();
        let still = self
            .executor
            .verify(self.operation.definition(), &receipt)
            .await?;
        if !still.passed {
            return Err(CoreError::validation(
                "undo target",
                "target changed after the operation; nothing was undone",
            ));
        }
        self.restore().await?;
        self.executor.confirm_restored().await
    }
}

struct CommandRestoreExecutor {
    service: SystemInfoService,
    session: BoundSshSession,
    target: RemotePath,
    target_sha256: String,
    source: ResidueCandidate,
    quarantine: RemotePath,
    package: Option<CommandPackage>,
    /// `""` as root, `"sudo -n "` otherwise.
    prefix: &'static str,
    plan: OperationPlan,
    candidates: Vec<ResidueCandidate>,
}

impl CommandRestoreExecutor {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        ensure_plan(&self.plan, operation)
    }

    async fn read_state(&self) -> CoreResult<RestoreState> {
        let output = self
            .service
            .ssh
            .execute_bound(
                &self.session,
                state_command(
                    self.prefix,
                    &self.target,
                    &self.source.path,
                    &self.quarantine,
                ),
                PROBE_TIMEOUT,
            )
            .await?;
        if output.timed_out {
            return Err(command_failed("command restore read", &output));
        }
        Ok(parse_state(&output.output))
    }

    async fn run(&self, command: String) -> CoreResult<crate::ssh::SshCommandOutput> {
        let output = self
            .service
            .ssh
            .execute_bound(&self.session, command, EXECUTE_TIMEOUT)
            .await?;
        if output.timed_out {
            return Err(command_failed("command restore command", &output));
        }
        Ok(output)
    }

    async fn observations(&self) -> String {
        let package_note = match &self.package {
            Some(package) => {
                match self
                    .run(package_verify_command(package, &self.target))
                    .await
                {
                    Ok(output) => {
                        let lines = output
                            .output
                            .lines()
                            .filter_map(|line| marker(line, "PKGV|"))
                            .collect::<Vec<_>>();
                        if lines.is_empty() && output.exit_code != Some(0) {
                            format!("包校验未执行成功（退出码 {:?}）", output.exit_code)
                        } else if lines.is_empty() {
                            "包校验：该文件未见差异".to_owned()
                        } else {
                            format!("包校验：{}", lines.join("；"))
                        }
                    }
                    Err(_) => "包校验未执行成功".to_owned(),
                }
            }
            None => "未识别包归属，未做包校验".to_owned(),
        };
        let functional_note = match self
            .service
            .ssh
            .execute_bound(
                &self.session,
                functional_command(&self.target),
                FUNCTIONAL_TIMEOUT,
            )
            .await
        {
            Ok(output) if output.timed_out => "试跑：限时内未取得结果".to_owned(),
            Ok(output) => {
                let mut exit = None;
                let mut first = None;
                for line in output.output.lines() {
                    if let Some(code) = marker(line, "FUNCRC|") {
                        exit = Some(code.to_owned());
                    } else if first.is_none() {
                        first = Some(line.chars().take(120).collect::<String>());
                    }
                }
                match (exit.as_deref(), first) {
                    (Some(code), Some(line)) => format!("试跑：退出码 {code}（{line}）"),
                    (Some(code), None) => format!("试跑：退出码 {code}，无输出"),
                    (None, Some(line)) => format!("试跑：退出码未取得，首行 {line}"),
                    (None, None) => "试跑：无输出，退出码未取得".to_owned(),
                }
            }
            Err(_) => "试跑：未能执行".to_owned(),
        };
        format!("{package_note}；{functional_note}；能运行不代表可信")
    }

    async fn confirm_restored(&self) -> CoreResult<String> {
        let state = self.read_state().await?;
        if state.target_sha256.as_deref() == Some(self.target_sha256.as_str())
            && !state.quarantine_exists
        {
            Ok(format!(
                "回读：{} 已放回操作前的内容，留底已删除。",
                self.target.as_str()
            ))
        } else {
            Err(CoreError::validation(
                "command restore check",
                "放回后复核不一致，请人工检查该命令的内容与同目录留底",
            ))
        }
    }
}

impl std::fmt::Debug for CommandRestoreExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandRestoreExecutor")
            .field("target", &self.target.as_str())
            .field("source", &self.source.path.as_str())
            .finish()
    }
}

#[async_trait]
impl OperationExecutor for CommandRestoreExecutor {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        self.service.target.validate(&operation.target)?;
        let state = self.read_state().await?;
        expect_planned_state(&state, &self.target_sha256, &self.source.sha256)?;

        // Quarantine the current bytes first; a write that cannot prove its
        // safety net stops before touching the command. The command itself
        // was never written, which the message says so the receipt reads
        // "left alone" rather than "could not restore".
        let output = self
            .run(privileged_script(
                self.prefix,
                quarantine_script(&self.target, &self.quarantine),
            ))
            .await?;
        let quarantine_sha = output
            .output
            .lines()
            .rev()
            .find_map(|line| marker(line, "QSHA|").map(str::to_owned));
        if output.exit_code != Some(0)
            || quarantine_sha.as_deref() != Some(self.target_sha256.as_str())
        {
            let _ = self
                .run(remove_quarantine_command(self.prefix, &self.quarantine))
                .await;
            return Err(CoreError::validation(
                "command restore quarantine",
                "could not stage the safety copy; nothing was modified",
            ));
        }

        let output = self
            .run(privileged_script(
                self.prefix,
                replace_script(&self.source.path, &self.target),
            ))
            .await?;
        let replaced_sha = output
            .output
            .lines()
            .rev()
            .find_map(|line| marker(line, "TSHA|").map(str::to_owned));
        if output.exit_code != Some(0)
            || replaced_sha.as_deref() != Some(self.source.sha256.as_str())
        {
            // The command may hold anything now; put the quarantined bytes
            // back and report whether that was verified.
            let back = self
                .run(privileged_script(
                    self.prefix,
                    put_back_script(&self.quarantine, &self.target),
                ))
                .await?;
            let restored = back
                .output
                .lines()
                .rev()
                .find_map(|line| marker(line, "TSHA|").map(str::to_owned))
                .as_deref()
                == Some(self.target_sha256.as_str());
            return Err(CoreError::validation(
                "command restore replace",
                if restored {
                    "restore write check failed; original bytes were put back"
                } else {
                    "restore write check failed; original bytes could not be verified"
                },
            ));
        }

        let observations = self.observations().await;
        self.service.target.validate(&operation.target)?;
        Ok(ExecutionReceipt {
            summary: format!(
                "用 {} 的内容写回 {}（原内容留底 {}）",
                self.source.path.as_str(),
                self.target.as_str(),
                self.quarantine.as_str()
            ),
            restore_token: Some(observations),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let state = self.read_state().await?;
        let replaced = state.target_sha256.as_deref() == Some(self.source.sha256.as_str());
        let quarantined = state.quarantine_sha256.as_deref() == Some(self.target_sha256.as_str());
        let passed = replaced && quarantined;
        let observations = receipt.restore_token.as_deref().unwrap_or_default();
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "回读：{} 已与 {} 的内容一致；原内容留底在 {}。{}",
                    self.target.as_str(),
                    self.source.path.as_str(),
                    self.quarantine.as_str(),
                    observations
                )
            } else if !replaced {
                format!(
                    "回读：{} 的摘要在写回后又有变化，未自动放回。{}",
                    self.target.as_str(),
                    observations
                )
            } else {
                format!(
                    "回读：留底 {} 缺失或内容不符，未自动放回。{}",
                    self.quarantine.as_str(),
                    observations
                )
            },
        })
    }

    async fn restore(
        &self,
        _operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        let state = self.read_state().await?;
        match restore_decision(&state, &self.target_sha256, &self.source.sha256) {
            RestoreStep::Refuse(message) => {
                Err(CoreError::validation("command restore undo", message))
            }
            RestoreStep::AlreadyOriginal => {
                if state.quarantine_exists {
                    let output = self
                        .run(remove_quarantine_command(self.prefix, &self.quarantine))
                        .await?;
                    if output.exit_code != Some(0) {
                        return Err(command_failed("command restore cleanup", &output));
                    }
                }
                Ok(())
            }
            RestoreStep::PutBack => {
                let output = self
                    .run(privileged_script(
                        self.prefix,
                        put_back_script(&self.quarantine, &self.target),
                    ))
                    .await?;
                let restored = output
                    .output
                    .lines()
                    .rev()
                    .find_map(|line| marker(line, "TSHA|").map(str::to_owned))
                    .as_deref()
                    == Some(self.target_sha256.as_str());
                if output.exit_code != Some(0) || !restored {
                    return Err(CoreError::validation(
                        "command restore put-back",
                        "the target was not put back as it was before the operation",
                    ));
                }
                let output = self
                    .run(remove_quarantine_command(self.prefix, &self.quarantine))
                    .await?;
                if output.exit_code != Some(0) {
                    return Err(command_failed("command restore cleanup", &output));
                }
                Ok(())
            }
        }
    }
}

fn command_failed(subject: &'static str, output: &crate::ssh::SshCommandOutput) -> CoreError {
    CoreError::Validation {
        subject: "command restore command",
        message: format!(
            "{subject} failed (exit={:?}, timed_out={})",
            output.exit_code, output.timed_out
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::TargetIdentity;

    fn path(value: &str) -> RemotePath {
        RemotePath::new(value).unwrap()
    }

    fn candidate(path: &str, sha: &str, kind: ResidueKind) -> ResidueCandidate {
        ResidueCandidate {
            path: RemotePath::new(path).unwrap(),
            sha256: sha.to_owned(),
            size: 100,
            kind,
        }
    }

    fn state(target: &str, source: &str, quarantine: &str, exists: bool) -> RestoreState {
        RestoreState {
            target_sha256: Some(target.to_owned()),
            source_sha256: Some(source.to_owned()),
            quarantine_sha256: if quarantine.is_empty() {
                None
            } else {
                Some(quarantine.to_owned())
            },
            quarantine_exists: exists,
        }
    }

    #[test]
    fn probe_collects_privilege_tools_kind_digest_package_and_candidates() {
        let dir = path("/bin");
        let asked = residue_candidates(&dir, "ls");
        let probe = parse_probe(
            "UID|0\nSUDO|no\nSHA256SUM|yes\nFILE|regular\nSHA|abc123\n\
             PKG|dpkg|coreutils\n\
             CAND|backup|  4096|deadbeef|/bin/ls.bak\n\
             CAND|variant|2048|cafe|/bin/lsd\n",
            &asked,
        );
        assert!(probe.is_root && !probe.sudo && probe.regular && probe.sha256sum);
        assert_eq!(probe.sha256.as_deref(), Some("abc123"));
        assert_eq!(
            probe.package.as_ref().map(|package| package.name.as_str()),
            Some("coreutils")
        );
        assert_eq!(probe.candidates.len(), 2);
        assert_eq!(probe.candidates[0].path.as_str(), "/bin/ls.bak");
        assert_eq!(probe.candidates[0].size, 4096);
        assert_eq!(probe.candidates[0].kind, ResidueKind::Backup);
        assert_eq!(probe.candidates[1].kind, ResidueKind::Variant);
    }

    #[test]
    fn probe_takes_the_first_package_answer_and_accepts_rpm() {
        let dir = path("/usr/bin");
        let asked = residue_candidates(&dir, "ps");
        let probe = parse_probe(
            "UID|1000\nSUDO|yes\nSHA256SUM|yes\nFILE|regular\nSHA|s\n\
             PKG|dpkg|procps-ng\nPKG|rpm|ignored\n",
            &asked,
        );
        assert_eq!(
            probe.package.as_ref().map(|package| package.name.as_str()),
            Some("procps-ng")
        );
        assert_eq!(
            probe.package.as_ref().map(|package| package.tool),
            Some(PackageTool::Dpkg)
        );
        let probe = parse_probe(
            "UID|0\nSHA256SUM|yes\nFILE|regular\nSHA|s\nPKG|rpm|procps-ng\n",
            &asked,
        );
        assert_eq!(
            probe.package.as_ref().map(|package| package.tool),
            Some(PackageTool::Rpm)
        );
    }

    #[test]
    fn probe_ignores_candidates_it_never_asked_about() {
        let dir = path("/bin");
        let asked = residue_candidates(&dir, "ls");
        // A hostile answer naming files outside the residue set contributes
        // nothing: only the asked spelling may ever become the source.
        let probe = parse_probe(
            "SHA256SUM|yes\nFILE|regular\nSHA|s\n\
             CAND|backup|1|dead|/etc/passwd\n\
             CAND|backup|1|dead|/bin/sh.bak\n\
             CAND|backup|1|dead|/bin/ls.bak\nCAND|backup|2|dead|/bin/ls.bak\n",
            &asked,
        );
        assert_eq!(probe.candidates.len(), 1);
        assert_eq!(probe.candidates[0].path.as_str(), "/bin/ls.bak");
        // The first answer wins on a repeated line.
        assert_eq!(probe.candidates[0].size, 1);
    }

    #[test]
    fn residue_names_cover_backups_then_the_known_variant() {
        let names = residue_candidates(&path("/usr/bin"), "ps")
            .into_iter()
            .map(|(candidate, kind)| (candidate.as_str().to_owned(), kind))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("/usr/bin/ps.bak".to_owned(), ResidueKind::Backup),
                ("/usr/bin/ps.orig".to_owned(), ResidueKind::Backup),
                ("/usr/bin/ps.old".to_owned(), ResidueKind::Backup),
                ("/usr/bin/ps~".to_owned(), ResidueKind::Backup),
                ("/usr/bin/.ps".to_owned(), ResidueKind::Backup),
                ("/usr/bin/ps.dpkg-old".to_owned(), ResidueKind::Backup),
                ("/usr/bin/ps.dpkg-new".to_owned(), ResidueKind::Backup),
                ("/usr/bin/ps.dpkg-bak".to_owned(), ResidueKind::Backup),
                ("/usr/bin/psd".to_owned(), ResidueKind::Variant),
            ]
        );
        // Unknown names get no variant candidate.
        let names = residue_candidates(&path("/bin"), "cat");
        assert_eq!(names.len(), 8);
        assert!(names.iter().all(|(_, kind)| *kind == ResidueKind::Backup));
    }

    #[test]
    fn choose_source_prefers_one_explicit_backup_over_a_variant() {
        let backup = candidate("/bin/ls.bak", "b", ResidueKind::Backup);
        let variant = candidate("/bin/lsd", "v", ResidueKind::Variant);
        assert_eq!(
            choose_source(&[backup, variant.clone()])
                .unwrap()
                .path
                .as_str(),
            "/bin/ls.bak"
        );
        assert_eq!(choose_source(&[variant]).unwrap().path.as_str(), "/bin/lsd");
    }

    #[test]
    fn choose_source_refuses_two_explicit_backups() {
        let candidates = vec![
            candidate("/bin/ls.bak", "a", ResidueKind::Backup),
            candidate("/bin/ls.old", "b", ResidueKind::Backup),
            candidate("/bin/lsd", "c", ResidueKind::Variant),
        ];
        match choose_source(&candidates).unwrap_err() {
            CoreError::Validation { subject, message } => {
                assert_eq!(subject, RESTORE_AMBIGUOUS_REFUSAL);
                assert!(message.contains("/bin/ls.bak") && message.contains("/bin/ls.old"));
            }
            _ => panic!("expected a validation refusal"),
        }
    }

    #[test]
    fn choose_source_refuses_an_empty_winner() {
        let mut empty = candidate("/bin/ls.bak", "e3b0", ResidueKind::Backup);
        empty.size = 0;
        match choose_source(&[empty.clone()]).unwrap_err() {
            CoreError::Validation { subject, .. } => {
                assert_eq!(subject, RESTORE_EMPTY_REFUSAL);
            }
            _ => panic!("expected a validation refusal"),
        }
        // Emptiness loses to nothing else either: two backups, one empty,
        // still read as ambiguous rather than silently skipping it.
        assert!(matches!(
            choose_source(&[empty, candidate("/bin/ls.old", "b", ResidueKind::Backup)]),
            Err(CoreError::Validation { subject, .. }) if subject == RESTORE_AMBIGUOUS_REFUSAL
        ));
    }

    #[test]
    fn planned_state_refuses_target_source_and_quarantine_changes() {
        assert!(expect_planned_state(&state("t", "s", "", false), "t", "s").is_ok());
        for changed in [
            state("moved", "s", "", false),
            state("t", "moved", "", false),
            state("t", "s", "", true),
        ] {
            match expect_planned_state(&changed, "t", "s").unwrap_err() {
                CoreError::Validation { subject, message } => {
                    assert_eq!(subject, RESTORE_CHANGED_REFUSAL);
                    // The receipt must read as untouched, not unrestorable.
                    assert!(
                        message.contains("file content changed after the operation was planned")
                    );
                }
                _ => panic!("expected a validation refusal"),
            }
        }
    }

    #[test]
    fn restore_decision_covers_each_post_state() {
        // The command already carries the original bytes: nothing to put back.
        assert_eq!(
            restore_decision(&state("t", "s", "", false), "t", "s"),
            RestoreStep::AlreadyOriginal
        );
        // It holds the restored bytes and the quarantine copy is intact.
        assert_eq!(
            restore_decision(&state("s", "s", "t", true), "t", "s"),
            RestoreStep::PutBack
        );
        // The command moved after the operation: refuse rather than clobber.
        assert!(matches!(
            restore_decision(&state("other", "s", "t", true), "t", "s"),
            RestoreStep::Refuse(_)
        ));
        // The copy needed to put bytes back is gone or wrong.
        assert!(matches!(
            restore_decision(&state("s", "s", "", false), "t", "s"),
            RestoreStep::Refuse(_)
        ));
        assert!(matches!(
            restore_decision(&state("s", "s", "wrong", true), "t", "s"),
            RestoreStep::Refuse(_)
        ));
    }

    #[test]
    fn state_parse_reads_every_marker() {
        let parsed = parse_state("SHA|t1\nSHASRC|s1\nSHAQ|q1\nQE|yes\nSHA|t2\n");
        assert_eq!(parsed.target_sha256.as_deref(), Some("t2"));
        assert_eq!(parsed.source_sha256.as_deref(), Some("s1"));
        assert_eq!(parsed.quarantine_sha256.as_deref(), Some("q1"));
        assert!(parsed.quarantine_exists);
        assert!(!parse_state("SHA|t\nQE|no\n").quarantine_exists);
    }

    #[test]
    fn write_scripts_truncate_in_place_and_mark_their_proof() {
        let script = quarantine_script(&path("/bin/ls"), &path("/bin/ls.lh-replaced-x"));
        assert!(script.contains("cat -- '/bin/ls' > '/bin/ls.lh-replaced-x'"));
        assert!(script.contains("chmod 600 '/bin/ls.lh-replaced-x'"));
        assert!(script.contains("QSHA|"));
        let script = replace_script(&path("/bin/ls.bak"), &path("/bin/ls"));
        assert!(script.contains("cat -- '/bin/ls.bak' > '/bin/ls'"));
        assert!(script.contains("TSHA|"));
        let script = put_back_script(&path("/bin/ls.lh-replaced-x"), &path("/bin/ls"));
        assert!(script.contains("cat -- '/bin/ls.lh-replaced-x' > '/bin/ls'"));
        // A sudo run wraps the whole script so the redirection gets privilege.
        let command = privileged_script("sudo -n ", script);
        assert!(command.starts_with("sudo -n sh -c "));
        assert!(
            remove_quarantine_command("sudo -n ", &path("/bin/ls.x"))
                .starts_with("sudo -n rm -f -- '/bin/ls.x'")
        );
    }

    #[test]
    fn probe_command_quotes_everything_and_names_each_candidate() {
        let dir = path("/usr/bin");
        let command = probe_command(&path("/usr/bin/ps"), &residue_candidates(&dir, "ps"));
        assert!(command.contains("sha256sum -- '/usr/bin/ps'"));
        // usrmerge: dpkg may only know the /bin spelling, so both go out.
        assert!(command.contains("lh_t='/usr/bin/ps'"));
        assert!(command.contains("dpkg -S \"$lh_q\""));
        assert!(command.contains("'backup|/usr/bin/ps.bak'"));
        assert!(command.contains("'variant|/usr/bin/psd'"));
        // The functional probe never runs under privilege, and stays bounded.
        let command = functional_command(&path("/usr/bin/ps"));
        assert!(command.contains("'/usr/bin/ps' --version"));
        assert!(command.contains("head -c 4096"));
        assert!(
            package_verify_command(
                &CommandPackage {
                    name: "coreutils".to_owned(),
                    tool: PackageTool::Dpkg,
                },
                &path("/usr/bin/ps"),
            )
            .contains("dpkg --verify 'coreutils'")
        );
    }

    #[test]
    fn plan_binding_refuses_a_different_or_expired_plan() {
        let target = TargetContext::new();
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let plan = OperationPlan::new(guard, "restore", true, Some("put back".to_owned())).unwrap();
        assert!(ensure_plan(&plan, &plan).is_ok());
        let other = OperationPlan::new(
            target.current_guard().unwrap(),
            "restore",
            true,
            Some("put back".to_owned()),
        )
        .unwrap();
        assert!(ensure_plan(&plan, &other).is_err());
        let mut expired = plan.clone();
        expired.created_at = Utc::now() - chrono::Duration::minutes(6);
        assert!(ensure_plan(&expired, &expired).is_err());
    }
}
