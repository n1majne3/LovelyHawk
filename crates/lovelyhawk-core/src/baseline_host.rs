//! Attribute-only authentication repairs and a closed set of audit watches.
//! These use the baseline's existing confirmation, journal and history; neither
//! the account files nor arbitrary audit commands are exposed to the page.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub(super) const PERMISSION_SAFE: &str = "权限符合策略";
pub(super) const AUDIT_READY: &str = "规则已保存并载入";
pub(super) fn is_attribute_label(value: &str) -> bool {
    let Some((mode, rest)) = value
        .strip_prefix("权限 ")
        .and_then(|s| s.split_once("，属主 UID "))
    else {
        return false;
    };
    let Some((uid, gid)) = rest.split_once("，属组 GID ") else {
        return false;
    };
    mode.len() == 4
        && mode.bytes().all(|b| matches!(b, b'0'..=b'7'))
        && [uid, gid].iter().all(|id| {
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && id.parse::<u32>().is_ok()
        })
}
const AUTH_FILES: [&str; 4] = ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"];
const AUDIT_FILE: &str = "/etc/audit/rules.d/70-lovelyhawk-auth.rules";
const AUDIT_KEY: &str = "lovelyhawk_auth";

pub(super) const fn permission_definition(
    id: &'static str,
    file: &'static str,
    title: &'static str,
) -> BaselineDefinition {
    BaselineDefinition {
        id,
        file,
        title,
        category: BaselineCategory::FilePermissions,
        component: BaselineComponent::System,
        risk: BaselineRisk::High,
        description: "检查普通文件的属主、属组、权限与 ACL。保留 root/shadow 组的现有用途，只移除多余权限；未知属组或扩展 ACL 须人工核对。读取摘要可能更新访问时间，不显示账号或口令正文。",
        recommendation: PERMISSION_SAFE,
        value_kind: BaselineValueKind::Choice(&[PERMISSION_SAFE]),
        reading: Reading::HostState,
        implicit: None,
        key: "auth_permissions",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    }
}

pub(super) const AUDIT_DEFINITION: BaselineDefinition = BaselineDefinition {
    id: "logging-auth-file-watches",
    file: AUDIT_FILE,
    title: "认证文件的 auditd 监控",
    category: BaselineCategory::Logging,
    component: BaselineComponent::System,
    risk: BaselineRisk::High,
    description: "记录 passwd、group、shadow、gshadow 的写入和属性变化。分别核对受管规则片段与内核运行规则；不会安装或启动 auditd、清空其他规则或重载整个规则集。规则存在不证明事件已落盘，也不证明重启后会自动加载。",
    recommendation: AUDIT_READY,
    value_kind: BaselineValueKind::Choice(&[AUDIT_READY]),
    reading: Reading::HostState,
    implicit: None,
    key: "auth_watches",
    format: FileFormat::Whitespace,
    reload: ReloadGroup::None,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Guard {
    Permissions {
        before: BaselineBackupEvidence,
        desired_mode: u32,
        desired_gid: u32,
        group_hash: String,
    },
    Audit {
        before: BaselineBackupEvidence,
        boot: String,
        daemon_pid: u32,
        watched_hash: String,
        runtime_before: String,
        runtime_after: String,
    },
    /// Appending `Subsystem sftp internal-sftp` to sshd_config when `sshd -T`
    /// reports no effective sftp subsystem. The write prepends a global line
    /// so no `Match` block is touched, keeps the original inode, and restores
    /// by copying the verified backup back over the same file.
    Sftp {
        before: BaselineBackupEvidence,
        state_before: String,
    },
}

#[derive(Debug, Clone)]
struct PermissionProbe {
    file: BaselineBackupEvidence,
    root_gid: u32,
    shadow_gid: Option<u32>,
    group_hash: String,
}
#[derive(Debug, Clone)]
struct AuditProbe {
    file: BaselineBackupEvidence,
    boot: String,
    daemon_pid: u32,
    watched_hash: String,
    rules: String,
}

// All files are fixed by the catalogue. The caller's environment cannot choose
// programs. Extended ACLs require a separate policy, so refuse them instead of
// interpreting mode bits as the whole access decision.
const PROBE: &str = r#"
PATH=/usr/sbin:/usr/bin:/sbin:/bin; LC_ALL=C; export PATH LC_ALL
lh_path() {
  lh_p=$1
  while [ "$lh_p" != / ]; do
    [ ! -L "$lh_p" ] || return 1
    lh_p=${lh_p%/*}; [ -n "$lh_p" ] || lh_p=/
  done
}
lh_hash() { lh_h=$(sha256sum -- "$1") || return 1; printf '%s' "${lh_h%% *}"; }
lh_safe_dir() {
  lh_parent=$1
  while [ "$lh_parent" != / ]; do
    lh_path "$lh_parent" || return 1
    if [ -e "$lh_parent" ]; then
      [ -d "$lh_parent" ] && [ "$(stat -c %u -- "$lh_parent")" = 0 ] || return 1
      lh_mode=$(stat -c %a -- "$lh_parent") || return 1
      [ "$((0$lh_mode & 022))" = 0 ] || return 1
    fi
    lh_parent=${lh_parent%/*}; [ -n "$lh_parent" ] || lh_parent=/
  done
}
lh_file() {
  lh_path "$1" && [ -f "$1" ] && [ -r "$1" ] || return 1
  [ "$(stat -c %h -- "$1")" = 1 ] || return 1
  [ "$(stat -c %s -- "$1")" -le 1048576 ] || return 1
  lh_attrs=$(stat -c '%a:%u:%g:%d:%i:%h' -- "$1") || return 1
  lh_digest=$(lh_hash "$1") || return 1
  [ "$(stat -c '%a:%u:%g:%d:%i:%h' -- "$1")" = "$lh_attrs" ] || return 1
}
lh_perm() {
  lh_f=$1
  for lh_tool in stat sha256sum awk getfacl; do command -v "$lh_tool" >/dev/null 2>&1 || return 1; done
  lh_file "$lh_f" || return 1
  lh_a=$lh_attrs lh_d=$lh_digest
  lh_acl=$(getfacl -cp -- "$lh_f" 2>/dev/null) || return 1
  printf '%s\n' "$lh_acl" | awk '
    /^user::[rwx-][rwx-][rwx-]$/ {u++; next}
    /^group::[rwx-][rwx-][rwx-]$/ {g++; next}
    /^other::[rwx-][rwx-][rwx-]$/ {o++; next}
    /^$/ {next} {bad=1} END {exit !(u==1 && g==1 && o==1 && !bad)}' || return 1
  lh_file /etc/group || return 1
  lh_g=$lh_digest
  lh_groups=$(awk -F: '$1=="root" {r++; rg=$3} $1=="shadow" {s++; sg=$3} END {if(r!=1 || s>1) exit 1; print rg "|" (s==1 ? sg : "-")}' /etc/group) || return 1
  [ "$(lh_hash /etc/group)" = "$lh_g" ] || return 1
  [ "$(stat -c '%a:%u:%g:%d:%i:%h' -- "$lh_f")" = "$lh_a" ] || return 1
  printf 'PERM|%s|%s|%s|%s|%s\n' "$lh_f" "$lh_a" "$lh_d" "$lh_groups" "$lh_g"
}
lh_audit() {
  for lh_tool in auditctl stat sha256sum base64 head wc sort tr awk uname systemd-detect-virt; do command -v "$lh_tool" >/dev/null 2>&1 || return 1; done
  # A container shares its kernel's audit subsystem; it is not a host target.
  [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ] && [ ! -e /.containerenv ] || return 1
  lh_virt_status=0
  lh_virt=$(systemd-detect-virt --container 2>/dev/null) || lh_virt_status=$?
  [ "$lh_virt_status" = 1 ] && [ "$lh_virt" = none ] || return 1
  case "$(uname -r)" in *[Mm]icrosoft*|*WSL*) return 1;; esac
  lh_path /etc/audit/rules.d && [ -d /etc/audit/rules.d ] || return 1
  lh_status=$(auditctl -s 2>/dev/null) || return 1
  lh_enabled=$(printf '%s\n' "$lh_status" | awk '$1=="enabled" {print $2}')
  lh_pid=$(printf '%s\n' "$lh_status" | awk '$1=="pid" {print $2}')
  [ "$lh_enabled" = 1 ] && [ "${lh_pid:-0}" -gt 0 ] || return 1
  lh_boot=$(head -c 64 /proc/sys/kernel/random/boot_id) || return 1
  lh_objects=$(for lh_watch in /etc/passwd /etc/group /etc/shadow /etc/gshadow; do
    lh_path "$lh_watch" && [ -f "$lh_watch" ] && [ "$(stat -c %h -- "$lh_watch")" = 1 ] || exit 1
    stat -c '%d:%i' -- "$lh_watch" || exit 1
  done) || return 1
  lh_watched=$(printf '%s' "$lh_objects" | sha256sum); lh_watched=${lh_watched%% *}
  lh_rules=$({ auditctl -l 2>/dev/null; printf '\nLH_AUDIT_STATUS:%s' "$?"; } | head -c 65537)
  [ "${#lh_rules}" -lt 65536 ] || return 1
  lh_end=${lh_rules##*'
LH_AUDIT_STATUS:'}; [ "$lh_end" = 0 ] || return 1
  lh_rules=${lh_rules%'
LH_AUDIT_STATUS:'*}
  lh_rule_data=$(printf '%s' "$lh_rules" | base64 | tr -d '\n')
  lh_f=/etc/audit/rules.d/70-lovelyhawk-auth.rules
  lh_path "$lh_f" || return 1
  if [ -e "$lh_f" ]; then
    lh_file "$lh_f" || return 1
    lh_fa=$lh_attrs lh_fd=$lh_digest
  else lh_fa=- lh_fd=-; fi
  printf 'AUDIT|%s|%s|%s|%s|%s|%s\n' "$lh_fa" "$lh_fd" "$lh_boot" "$lh_pid" "$lh_rule_data" "$lh_watched"
}
lh_sshd() {
  lh_t=$(sshd -T 2>/dev/null) || return 1
  printf '%s\n' "$lh_t" | awk '$1~/^(ciphers|macs|kexalgorithms|subsystem|allowusers|allowgroups)$/{print "SSHD|"$0}' | head -n 40
  echo SSHD_OK
}
lh_tmout() {
  command -v awk >/dev/null 2>&1 || return 1
  cat /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/bash.bashrc 2>/dev/null |
    awk -F= '/^[ 	]*(#|$)/{next} /(^|[ 	;])(export[ 	]+|readonly[ 	]+)?TMOUT=/ {gsub(/[ 	;]/,"",$2); if ($2 ~ /^[0-9]+$/) v=$2; else v="x"} END{print "TMOUT|" (v==""?"unset":v); print "TMOUT_OK"}'
}
lh_pwhist() {
  command -v awk >/dev/null 2>&1 || return 1
  cat /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | awk '
    /^[ 	]*(#|$)/{next}
    $1=="password" && /pam_pwhistory[.]so/{ph=1}
    $1=="password" && /(pam_pwhistory|pam_unix)[.]so/ && match($0,/remember=[0-9]+/){print "PWHIST|pam:" substr($0,RSTART+9,RLENGTH-9)}
    END{if(ph) print "PWHIST|uses-pwhistory"}'
  if [ -r /etc/security/pwhistory.conf ]; then
    awk '/^[ 	]*(#|$)/{next} match($0,/remember[ 	]*=[ 	]*[0-9]+/){v=substr($0,RSTART,RLENGTH); gsub(/[ 	]/,"",v); sub(/remember=/,"",v); print "PWHIST|conf:" v}' /etc/security/pwhistory.conf
  fi
  echo PWHIST_OK
}
lh_wheel() {
  [ -f /etc/pam.d/su ] && [ -r /etc/pam.d/su ] || return 1
  command -v awk >/dev/null 2>&1 || return 1
  awk '/^[ 	]*(#|$)/{next} $1=="auth" && $2=="required" && /pam_wheel[.]so/{print "WHEEL|required"; found=1} END{if(!found) print "WHEEL|unset"; print "WHEEL_OK"}' /etc/pam.d/su
}
lh_dormant() {
  command -v lastlog >/dev/null 2>&1 || return 1
  command -v awk >/dev/null 2>&1 || return 1
  for lh_u in $(awk -F: '$7!~/\/(nologin|false|sync|shutdown|halt)$/{print $1}' /etc/passwd 2>/dev/null); do
    lastlog -b 90 -u "$lh_u" 2>/dev/null | tail -n 1
  done | awk 'NF && $1!="Username" {print "DORMANT|"$1; n++} END{print "DORMANT_N|" (n+0); print "DORMANT_OK"}'
}
lh_sudolog() {
  command -v awk >/dev/null 2>&1 || return 1
  command -v cat >/dev/null 2>&1 || return 1
  lh_s=''
  [ -r /etc/sudoers ] && lh_s=$(cat /etc/sudoers)
  for lh_f in /etc/sudoers.d/*; do
    [ -r "$lh_f" ] && lh_s="$lh_s
$(cat "$lh_f")"
  done
  [ -n "$lh_s" ] || return 1
  printf '%s
' "$lh_s" | awk '
    /^[ 	]*(#|$)/{next}
    /(^|[ 	:,])Defaults/ {
      if ($0 ~ /logfile[ 	]*=/) f=1
      if ($0 ~ /(^|[ 	,])(log_output|log_input|iolog_dir)([ 	,=]|$)/) f=1
      if ($0 ~ /!logfile|!log_output|!log_input/) f=0
      if ($0 ~ /!syslog/) n=1
    }
    END {
      if (f) { print "SUDOLOG|enabled"; print "SUDOLOG_OK" }
      else if (!n) { print "SUDOLOG|syslog-only"; print "SUDOLOG_OK" }
      else { print "SUDOLOG|unset"; print "SUDOLOG_OK" }
    }'
}
lh_apache() {
  for lh_t in awk cat head ps; do command -v "$lh_t" >/dev/null 2>&1 || return 1; done
  lh_confs=''
  for lh_f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache2/conf/httpd.conf \
    /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf \
    /etc/apache2/mods-enabled/*.conf /usr/local/apache2/conf/extra/*.conf; do
    [ -r "$lh_f" ] && lh_confs="$lh_confs $lh_f"
  done
  lh_modbin=''
  for lh_c in apachectl apache2ctl httpd apache2; do
    command -v "$lh_c" >/dev/null 2>&1 && { lh_modbin=$lh_c; break; }
  done
  [ -n "$lh_confs$lh_modbin" ] || { printf 'APACHE|ABSENT\n'; return 0; }
  # Debian/RHEL write `User ${APACHE_RUN_USER}`; the value lives in envvars
  # files, so read those too or the directive cannot be judged.
  lh_envs=''
  for lh_e in /etc/apache2/envvars /etc/sysconfig/httpd /etc/default/apache2 /etc/httpd/envvars; do
    [ -r "$lh_e" ] && lh_envs="$lh_envs $lh_e"
  done
  if [ -n "$lh_confs" ]; then
    cat $lh_confs 2>/dev/null | head -c 524288 | awk -v envtext="$(cat $lh_envs 2>/dev/null)" '
      BEGIN {
        en = split(envtext, EL, "\n")
        for (i = 1; i <= en; i++) {
          s = EL[i]
          sub(/^[ \t]*export[ \t]+/, "", s); sub(/^[ \t]+/, "", s)
          eq = index(s, "=")
          if (eq < 2) continue
          nm = substr(s, 1, eq - 1); vv = substr(s, eq + 1)
          gsub(/[ \t]+/, "", nm); sub(/[ \t]*#.*$/, "", vv)
          gsub(/^[ \t]+|[ \t]+$/, "", vv)
          sub(/^"/, "", vv); sub(/"$/, "", vv); sub(/^\47/, "", vv); sub(/\47$/, "", vv)
          if (nm ~ /^[A-Za-z_][A-Za-z0-9_]*$/) env[nm] = vv
        }
      }
      function resolve(vv,   nm, z) {
        for (z = 0; z < 8; z++) {
          if (!match(vv, /[$][{]?[A-Za-z_][A-Za-z0-9_]*[}]?/)) return vv
          nm = substr(vv, RSTART, RLENGTH)
          gsub(/[$}{]/, "", nm)
          if (!(nm in env)) return "unresolved"
          vv = substr(vv, 1, RSTART - 1) env[nm] substr(vv, RSTART + RLENGTH)
        }
        return "unresolved"
      }
      /^[ \t]*(#|$)/ { next }
      {
        low = tolower($0)
        if (low ~ /<[ \t]*location/) { inloc = 1; rst = 0; hnd = 0; next }
        if (inloc && low ~ /<\/[ \t]*location/) { if (hnd && !rst) st = "exposed"; inloc = 0; next }
        if (inloc && low ~ /sethandler[ \t]+server-(status|info)/) hnd = 1
        if (inloc && low ~ /require|allow[ \t]+from|order[ \t]|deny[ \t]+from/) rst = 1
        k = tolower($1)
        if (k == "options") {
          seen = 1; grant = 0; deny = 0; none = 0
          for (i = 2; i <= NF; i++) {
            w = tolower($i); gsub(/["\47]/, "", w)
            if (w == "none") none = 1
            else if (w == "all" || w == "+all" || w == "indexes" || w == "+indexes") grant = 1
            else if (w == "-indexes" || w == "-all") deny = 1
          }
          if (grant && !deny && !none) idx_on = 1
          next
        }
        if (k == "user") usr = resolve($2)
        else if (k == "timeout" && $2 ~ /^[0-9]+$/) tmo = $2
        else if (k == "limitrequestbody") lrb = 1
        else if (!inloc && low ~ /sethandler[ \t]+server-(status|info)/) st = "exposed"
      }
      END {
        if (idx_on) print "APACHE|indexes|on"
        else if (seen) print "APACHE|indexes|off"
        else print "APACHE|indexes|unset"
        print "APACHE|status|" (st == "" ? "off" : st)
        print "APACHE|usr|" (usr == "" ? "unset" : usr)
        if (tmo != "") print "APACHE|tmo|" tmo
        if (lrb) print "APACHE|lrb|set"
      }'
  else
    printf 'APACHE|indexes|unverified\nAPACHE|status|unverified\nAPACHE|usr|unverified\n'
  fi
  ps -eo uid,ppid,comm 2>/dev/null | awk '
    $3 ~ /^(httpd|apache2)$/ {
      if ($2 == 1) master = NR
      else if ($1 == 0) w0 = 1
    }
    END { if (w0) print "APACHE|worker0|1" }'
  lh_mods=''
  if [ -n "$lh_modbin" ]; then
    lh_mods=$("$lh_modbin" -M 2>/dev/null | awk '{print tolower($1)}')
  fi
  if [ -z "$lh_mods" ] && [ -n "$lh_confs" ]; then
    lh_mods=$(cat $lh_confs 2>/dev/null | awk 'tolower($1)=="loadmodule"{print tolower($2)}')
  fi
  if [ -z "$lh_mods" ]; then
    printf 'APACHE|mods|unverified\nAPACHE_OK\n'; return 0
  fi
  printf '%s\n' "$lh_mods" | awk '
    /^(autoindex|status|info|userdir|cgi|cgid|asis|dav|dav_fs|dav_lock|proxy_ftp)(_module)?$/ {
      sub(/_module$/, ""); risky = risky (risky ? "," : "") $0; r = 1
    }
    END { print "APACHE|mods|" (r ? risky : "none") }'
  printf 'APACHE_OK\n'
}
lh_tomcat() {
  for lh_t in awk cat ps grep; do command -v "$lh_t" >/dev/null 2>&1 || return 1; done
  lh_home=''
  for lh_d in /usr/local/tomcat /opt/tomcat /opt/tomcat* /etc/tomcat /etc/tomcat* /var/lib/tomcat* /usr/share/tomcat*; do
    if [ -d "$lh_d" ] && { [ -r "$lh_d/conf/server.xml" ] || [ -d "$lh_d/webapps" ]; }; then
      lh_home=$lh_d; break
    fi
  done
  [ -n "$lh_home" ] || { printf 'TOMCAT|ABSENT\n'; return 0; }
  lh_conf=$lh_home/conf
  lh_web=$lh_home/webapps
  # manager/host-manager deploy two ways: a webapps/<name> dir or an external
  # $conf/Catalina/localhost/<name>.xml descriptor whose docBase may live
  # outside webapps (Debian tomcat10-admin). A descriptor overrides the app's
  # own META-INF/context.xml, so it is the only restriction source then.
  # An unreadable deployment channel is a gap, not proof of absence.
  lh_mgr_bad=0 lh_mgr_gap=0
  for lh_xd in "$lh_conf" "$lh_conf/Catalina/localhost" "$lh_web"; do
    [ -d "$lh_xd" ] || continue
    [ -r "$lh_xd" ] && [ -x "$lh_xd" ] || lh_mgr_gap=1
  done
  for lh_base in manager host-manager; do
    lh_cx="$lh_conf/Catalina/localhost/$lh_base.xml"
    lh_deployed=0 lh_restricted=0
    if [ -r "$lh_cx" ]; then
      lh_deployed=1
      grep -qE 'RemoteAddrValve|RemoteCIDRValve|allow="127\.|allow="::1' "$lh_cx" 2>/dev/null && lh_restricted=1
    elif [ -d "$lh_web/$lh_base" ]; then
      lh_deployed=1
      if [ -r "$lh_web/$lh_base/META-INF/context.xml" ] && grep -qE 'RemoteAddrValve|RemoteCIDRValve|allow="127\.|allow="::1' "$lh_web/$lh_base/META-INF/context.xml" 2>/dev/null; then
        lh_restricted=1
      fi
    fi
    if [ "$lh_deployed" = 1 ] && [ "$lh_restricted" = 0 ]; then lh_mgr_bad=1; fi
  done
  # A confirmed exposure outranks an enumeration gap; a gap alone is never safe.
  if [ "$lh_mgr_bad" = 1 ]; then printf 'TOMCAT|mgr|exposed\n'
  elif [ "$lh_mgr_gap" = 1 ]; then printf 'TOMCAT|mgr|unverified\n'
  else printf 'TOMCAT|mgr|safe\n'; fi
  if [ -r "$lh_conf/server.xml" ]; then
    awk '
      {
        # XML comments may span lines; a commented connector is no connector.
        s = $0
        while (length(s) > 0) {
          if (cmt) { e = index(s, "-->"); if (e == 0) { s = ""; break }; s = substr(s, e + 3); cmt = 0; continue }
          c = index(s, "<!--"); if (c == 0) break
          e = index(substr(s, c + 4), "-->")
          if (e == 0) { s = substr(s, 1, c - 1); cmt = 1; break }
          s = substr(s, 1, c - 1) substr(s, c + 4 + e + 2)
        }
        line = s
      }
      line ~ /<[Cc]onnector/ || buf != "" { buf = buf " " line; if (line !~ />/) next }
      { if (buf != "") { l = buf; buf = "" } else l = line
        if (tolower(l) ~ /protocol[^>]*ajp/) {
          ajp = "open"
          if (l ~ /secretRequired="true"/ || l ~ /secret="[^"]+"/) ajp = "secured"
        } }
      END { print "TOMCAT|ajp|" (ajp == "open" ? "open" : "secured") }' "$lh_conf/server.xml"
  else
    printf 'TOMCAT|ajp|unverified\n'
  fi
  # comm narrows to real launchers; args must still name catalina/tomcat so an
  # unrelated java process is not attributed to this instance. The lh_tomcat
  # token excludes this probe's own argv, which embeds the script text.
  ps -eo uid,comm,args 2>/dev/null | awk '
    ($2 == "java" || $2 == "jsvc") && $0 ~ /catalina|tomcat/ && $0 !~ /lh_tomcat/ {
      seen = 1
      if ($1 == 0) root = 1
    }
    END {
      if (root) print "TOMCAT|usr|root"
      else if (seen) print "TOMCAT|usr|non-root"
      else print "TOMCAT|usr|unknown"
    }'
  if [ -r "$lh_conf/web.xml" ]; then
    awk '
      {
        # Commented-out parameters must not answer for the live config.
        s = $0
        while (length(s) > 0) {
          if (cmt) { e = index(s, "-->"); if (e == 0) { s = ""; break }; s = substr(s, e + 3); cmt = 0; continue }
          c = index(s, "<!--"); if (c == 0) break
          e = index(substr(s, c + 4), "-->")
          if (e == 0) { s = substr(s, 1, c - 1); cmt = 1; break }
          s = substr(s, 1, c - 1) substr(s, c + 4 + e + 2)
        }
        line = s
      }
      line ~ /init-param/ { inp = 1; nm = ""; vl = "" }
      inp && line ~ /<param-name>/ { t = line; gsub(/.*<param-name>|<\/param-name>.*/, "", t); nm = t }
      inp && line ~ /<param-value>/ { t = line; gsub(/.*<param-value>|<\/param-value>.*/, "", t); vl = t;
        if (nm ~ /listings/) lst = (vl ~ /true/ ? "true" : "false"); inp = 0 }
      line ~ /<session-timeout>/ { t = line; gsub(/.*<session-timeout>|<\/session-timeout>.*/, "", t); ses = t }
      END {
        print "TOMCAT|lst|" (lst == "" ? "false" : lst)
        print "TOMCAT|ses|" (ses ~ /^[0-9]+$/ ? ses : "30")
      }' "$lh_conf/web.xml"
  else
    printf 'TOMCAT|lst|unverified\nTOMCAT|ses|unverified\n'
  fi
  printf 'TOMCAT_OK\n'
}
lh_sftp() {
  lh_file /etc/ssh/sshd_config || return 1
  lh_a=$lh_attrs lh_d=$lh_digest
  command -v sshd >/dev/null 2>&1 || return 1
  lh_t=$(sshd -T 2>/dev/null) || return 1
  lh_state=absent
  printf '%s\n' "$lh_t" | awk '$1=="subsystem" && $2=="sftp"{f=1} END{exit !f}' && lh_state=present
  printf 'SFTP|%s|%s|%s\n' "$lh_state" "$lh_a" "$lh_d"
}
lh_sftp_state() {
  command -v sshd >/dev/null 2>&1 || return 1
  lh_t=$(sshd -T 2>/dev/null) || return 1
  printf '%s\n' "$lh_t" | awk '$1=="subsystem" && $2=="sftp"{f=1} END{if(f) print "present"; else print "absent"}'
}
"#;

fn error(message: impl Into<String>) -> CoreError {
    CoreError::validation("authentication baseline", message)
}
fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn attributes(file: &BaselineBackupEvidence) -> CoreResult<Vec<u64>> {
    validate_applied_files(std::slice::from_ref(&file.file), std::slice::from_ref(file))?;
    file.attributes
        .as_ref()
        .ok_or_else(|| error("missing attributes"))?
        .split(':')
        .enumerate()
        .map(|(i, value)| {
            if i == 0 {
                u64::from_str_radix(value, 8)
            } else {
                value.parse()
            }
            .map_err(|_| error("invalid attributes"))
        })
        .collect()
}
fn evidence(file: &str, attrs: &str, hash: &str) -> CoreResult<BaselineBackupEvidence> {
    let item = BaselineBackupEvidence {
        file: file.to_owned(),
        attributes: (attrs != "-").then(|| attrs.to_owned()),
        sha256: (hash != "-").then(|| hash.to_owned()),
    };
    validate_backups(&[file.to_owned()], std::slice::from_ref(&item))?;
    if item.sha256.is_some() != item.attributes.is_some() {
        return Err(error("incomplete file state"));
    }
    Ok(item)
}
fn parse_permission(line: &str) -> CoreResult<PermissionProbe> {
    let p: Vec<_> = line.split('|').collect();
    if p.len() != 7 || p[0] != "PERM" || !AUTH_FILES.contains(&p[1]) || !digest(p[6]) {
        return Err(error("invalid permission observation"));
    }
    let result = PermissionProbe {
        file: evidence(p[1], p[2], p[3])?,
        root_gid: p[4].parse().map_err(|_| error("root group unavailable"))?,
        shadow_gid: if p[5] == "-" {
            None
        } else {
            Some(
                p[5].parse()
                    .map_err(|_| error("shadow group unavailable"))?,
            )
        },
        group_hash: p[6].to_owned(),
    };
    attributes(&result.file)?;
    Ok(result)
}

fn permission_policy(probe: &PermissionProbe) -> CoreResult<(u32, u32)> {
    let a = attributes(&probe.file)?;
    let gid = u32::try_from(a[2]).map_err(|_| error("invalid gid"))?;
    let secret = matches!(probe.file.file.as_str(), "/etc/shadow" | "/etc/gshadow");
    let (mask, wanted_gid) = if !secret {
        (0o644, probe.root_gid)
    } else if gid == probe.root_gid {
        (0o600, gid)
    } else if Some(gid) == probe.shadow_gid {
        (0o640, gid)
    } else {
        return Err(error(
            "口令文件属于未知用户组，请核对本机认证程序的访问需求后处理。",
        ));
    };
    Ok((a[0] as u32 & mask, wanted_gid))
}
fn wanted_rules() -> Vec<String> {
    AUTH_FILES
        .iter()
        .map(|file| format!("-w {file} -p wa -k {AUDIT_KEY}"))
        .collect()
}
fn rules_file() -> String {
    format!(
        "# LovelyHawk authentication watches v1\n{}\n",
        wanted_rules().join("\n")
    )
}
fn canonical_rules(raw: &str) -> CoreResult<String> {
    if raw.len() > 65536
        || raw
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(error("audit rule output exceeded bounds"));
    }
    let mut lines: Vec<_> = raw
        .lines()
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty() && s != "No rules")
        .collect();
    if lines.len() > 1024 {
        return Err(error("too many audit rules"));
    }
    lines.sort();
    if lines.windows(2).any(|p| p[0] == p[1]) {
        return Err(error("duplicate audit rules require review"));
    }
    Ok(lines.join("\n"))
}
fn parse_audit(line: &str) -> CoreResult<AuditProbe> {
    let p: Vec<_> = line.split('|').collect();
    if p.len() != 7 || p[0] != "AUDIT" || Uuid::parse_str(p[3]).is_err() || !digest(p[6]) {
        return Err(error("audit status unavailable"));
    }
    let daemon_pid = p[4]
        .parse::<u32>()
        .map_err(|_| error("audit daemon unavailable"))?;
    if daemon_pid == 0 {
        return Err(error("audit daemon not running"));
    }
    let raw = String::from_utf8(
        STANDARD
            .decode(p[5])
            .map_err(|_| error("invalid audit encoding"))?,
    )
    .map_err(|_| error("invalid audit output"))?;
    Ok(AuditProbe {
        file: evidence(AUDIT_FILE, p[1], p[2])?,
        boot: p[3].to_owned(),
        daemon_pid,
        watched_hash: p[6].to_owned(),
        rules: canonical_rules(&raw)?,
    })
}
fn audit_policy(probe: &AuditProbe) -> CoreResult<String> {
    if let Some(hash) = &probe.file.sha256 {
        let a = attributes(&probe.file)?;
        if *hash != sha256_hex(rules_file()) || a[0] != 0o600 || a[1] != 0 || a[2] != 0 {
            return Err(error("同名 auditd 文件不是完整的受管规则，拒绝覆盖。"));
        }
    }
    let wanted = wanted_rules();
    let mut rules: BTreeSet<String> = probe.rules.lines().map(str::to_owned).collect();
    for rule in &rules {
        if wanted.contains(rule) {
            continue;
        }
        if rule.contains(AUDIT_KEY)
            || rule.contains("never")
            || rule.contains("exclude")
            || rule.contains("task")
            || AUTH_FILES.iter().any(|p| rule.contains(p))
            || rule.contains("dir=/etc")
            || rule.contains("dir=/ ")
            || rule.ends_with("dir=/")
            || rule.starts_with("-w /etc ")
            || rule.starts_with("-w / ")
        {
            return Err(error(
                "已有重叠或排除审计规则，需先核对其覆盖范围；没有添加重复监控。",
            ));
        }
    }
    rules.extend(wanted);
    Ok(rules.into_iter().collect::<Vec<_>>().join("\n"))
}

pub(super) fn scan_item(definition: &BaselineDefinition) -> String {
    // A self-contained placeholder row: the host observation replaces it, and
    // an empty source defaults to the check's primary file.
    format!(
        "printf 'ITEM=%s\\t__unverified__\\t%s\\n' {} {}; ",
        shq(definition.id),
        shq(definition.file)
    )
}
async fn run(
    service: &BaselineService,
    session: &BoundSshSession,
    body: &str,
) -> CoreResult<String> {
    let result = successful_output(
        "认证文件与审计状态核对",
        service
            .ssh
            .execute_bound(session, format!("{PROBE}\n{body}"), COMMAND_TIMEOUT)
            .await?,
    )?;
    service.target.validate(session.target())?;
    if result.len() > 128 * 1024 {
        return Err(error("host observation exceeded bounds"));
    }
    Ok(result)
}
pub(super) fn scan_script() -> String {
    format!(
        "\n{PROBE}\nfor lh_target in {}; do (lh_perm \"$lh_target\") 2>/dev/null || printf 'GAP|%s\\n' \"$lh_target\"; done; (lh_audit) 2>/dev/null || printf 'GAP|audit\\n'; (lh_sshd) 2>/dev/null || printf 'GAP|sshd\\n'; (lh_tmout) 2>/dev/null || printf 'GAP|tmout\\n'; (lh_pwhist) 2>/dev/null || printf 'GAP|pwhist\\n'; (lh_wheel) 2>/dev/null || printf 'GAP|wheel\\n'; (lh_dormant) 2>/dev/null || printf 'GAP|dormant\\n'; (lh_apache) 2>/dev/null || printf 'GAP|apache\\n'; (lh_tomcat) 2>/dev/null || printf 'GAP|tomcat\\n'",
        AUTH_FILES
            .iter()
            .map(|p| shq(p))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
pub(super) const SSH_WEAK_NONE: &str = "none";
pub(super) const SSH_SFTP_ENABLED: &str = "enabled";
pub(super) const SSH_LOGIN_RESTRICTED: &str = "restricted";
const SSH_WEAK: &[(&str, &str)] = &[
    ("ciphers", "aes128-cbc"),
    ("ciphers", "aes192-cbc"),
    ("ciphers", "aes256-cbc"),
    ("ciphers", "3des-cbc"),
    ("ciphers", "arcfour"),
    ("ciphers", "arcfour128"),
    ("ciphers", "arcfour256"),
    ("ciphers", "blowfish-cbc"),
    ("ciphers", "cast128-cbc"),
    ("ciphers", "rijndael-cbc@lysator.liu.se"),
    ("macs", "hmac-md5"),
    ("macs", "hmac-md5-96"),
    ("macs", "hmac-md5-etm@openssh.com"),
    ("macs", "hmac-sha1"),
    ("macs", "hmac-sha1-etm@openssh.com"),
    ("macs", "hmac-sha1-96"),
    ("macs", "umac-64@openssh.com"),
    ("macs", "umac-64-etm@openssh.com"),
    ("macs", "hmac-ripemd160"),
    ("macs", "hmac-ripemd160-etm@openssh.com"),
    ("macs", "hmac-ripemd160@openssh.com"),
    ("kexalgorithms", "diffie-hellman-group1-sha1"),
    ("kexalgorithms", "diffie-hellman-group14-sha1"),
    ("kexalgorithms", "diffie-hellman-group-exchange-sha1"),
    ("kexalgorithms", "gss-g1-sha1-"),
    ("kexalgorithms", "gss-g14-sha1-"),
    ("kexalgorithms", "gss-group1-sha1-"),
    ("kexalgorithms", "gss-group14-sha1-"),
];

fn sshd_observed(item_id: &str, output: &str) -> BaselineObservedValue {
    let mut ciphers = "";
    let mut macs = "";
    let mut kex = "";
    let mut sftp = false;
    let mut acl = false;
    if !output.lines().any(|line| line == "SSHD_OK") {
        return BaselineObservedValue::Unverified;
    }
    for line in output.lines().filter_map(|l| l.strip_prefix("SSHD|")) {
        let mut parts = line.splitn(2, ' ');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("").trim();
        match key {
            "ciphers" => ciphers = value,
            "macs" => macs = value,
            "kexalgorithms" => kex = value,
            "subsystem" => {
                if value.split_whitespace().next() == Some("sftp") {
                    sftp = true;
                }
            }
            "allowusers" | "allowgroups" => acl = true,
            _ => {}
        }
    }
    // Observed values stay inert ASCII tokens (see `validate_observed`);
    // algorithm names are public and already in that alphabet.
    let token = |value: &str| BaselineObservedValue::Value(value.to_owned());
    match item_id {
        "ssh-weak-algorithms" => {
            let weak: Vec<&str> = [("ciphers", ciphers), ("macs", macs), ("kexalgorithms", kex)]
                .iter()
                .flat_map(|(section, list)| {
                    list.split(',').filter(move |name| {
                        !name.is_empty()
                            && SSH_WEAK.iter().any(|(k, weak)| {
                                k == section
                                    && if weak.ends_with('-') {
                                        name.starts_with(weak)
                                    } else {
                                        weak == name
                                    }
                            })
                    })
                })
                .collect();
            if weak.is_empty() {
                return token(SSH_WEAK_NONE);
            }
            let mut value = String::new();
            for (index, name) in weak.iter().enumerate() {
                let next = if value.is_empty() {
                    name.len()
                } else {
                    value.len() + 1 + name.len()
                };
                let rest = format!(",+{}", weak.len() - index);
                if next + rest.len() > 64 {
                    value.push_str(&rest);
                    break;
                }
                if !value.is_empty() {
                    value.push(',');
                }
                value.push_str(name);
            }
            token(&value)
        }
        "ssh-sftp-subsystem" => token(if sftp { SSH_SFTP_ENABLED } else { "absent" }),
        "ssh-login-restriction" => token(if acl {
            SSH_LOGIN_RESTRICTED
        } else {
            "unrestricted"
        }),
        _ => BaselineObservedValue::Unverified,
    }
}

fn tmout_observed(output: &str) -> BaselineObservedValue {
    if !output.lines().any(|line| line == "TMOUT_OK") {
        return BaselineObservedValue::Unverified;
    }
    let value = output
        .lines()
        .filter_map(|line| line.strip_prefix("TMOUT|"))
        .next()
        .unwrap_or("unset");
    match value.parse::<u32>() {
        Ok(n) if (1..=900).contains(&n) => BaselineObservedValue::Value("within-900".to_owned()),
        Ok(n) => BaselineObservedValue::Value(n.to_string()),
        Err(_) => BaselineObservedValue::Value("unset".to_owned()),
    }
}

fn pwhist_observed(output: &str) -> BaselineObservedValue {
    if !output.lines().any(|line| line == "PWHIST_OK") {
        return BaselineObservedValue::Unverified;
    }
    let uses_pwhistory = output.lines().any(|line| line == "PWHIST|uses-pwhistory");
    let mut best: Option<u32> = None;
    for line in output
        .lines()
        .filter_map(|line| line.strip_prefix("PWHIST|"))
    {
        let Some((kind, number)) = line.split_once(':') else {
            continue;
        };
        if kind == "conf" && !uses_pwhistory {
            continue;
        }
        if matches!(kind, "pam" | "conf")
            && let Ok(n) = number.parse::<u32>()
        {
            best = Some(best.map_or(n, |b| b.max(n)));
        }
    }
    match best {
        Some(n) if n >= 5 => BaselineObservedValue::Value("ge-5".to_owned()),
        Some(n) => BaselineObservedValue::Value(n.to_string()),
        None => BaselineObservedValue::Value("unset".to_owned()),
    }
}

fn wheel_observed(output: &str) -> BaselineObservedValue {
    if !output.lines().any(|line| line == "WHEEL_OK") {
        return BaselineObservedValue::Unverified;
    }
    BaselineObservedValue::Value(
        if output.lines().any(|line| line == "WHEEL|required") {
            "required"
        } else {
            "unset"
        }
        .to_owned(),
    )
}

fn dormant_observed(output: &str) -> BaselineObservedValue {
    if !output.lines().any(|line| line == "DORMANT_OK") {
        return BaselineObservedValue::Unverified;
    }
    let names: Vec<&str> = output
        .lines()
        .filter_map(|line| line.strip_prefix("DORMANT|"))
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
        .take(20)
        .collect();
    let total = output
        .lines()
        .filter_map(|line| line.strip_prefix("DORMANT_N|"))
        .next()
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(names.len());
    if total == 0 {
        return BaselineObservedValue::Value("none".to_owned());
    }
    let mut label = String::new();
    let mut shown = 0usize;
    for name in &names {
        let extra = if total.saturating_sub(shown) > 1 {
            4
        } else {
            0
        };
        if label.len() + name.len() + extra > 60 && !label.is_empty() {
            break;
        }
        if !label.is_empty() {
            label.push(',');
        }
        label.push_str(name);
        shown += 1;
    }
    if total > shown {
        if !label.is_empty() {
            label.push(',');
        }
        label.push('+');
        label.push_str(&(total - shown).to_string());
    }
    BaselineObservedValue::Value(if label.is_empty() {
        format!("+{total}")
    } else {
        label
    })
}

/// `SUDOLOG|enabled`, `SUDOLOG|syslog-only`, or `SUDOLOG|unset`; unreadable
/// sudoers keeps the check explicitly undecidable rather than clean.
fn sudolog_observed(output: &str) -> BaselineObservedValue {
    if !output.lines().any(|line| line == "SUDOLOG_OK") {
        return BaselineObservedValue::Unverified;
    }
    match output
        .lines()
        .filter_map(|line| line.strip_prefix("SUDOLOG|"))
        .next()
    {
        Some("enabled") => BaselineObservedValue::Value("enabled".to_owned()),
        Some("syslog-only") => BaselineObservedValue::Value("syslog-only".to_owned()),
        _ => BaselineObservedValue::Value("unset".to_owned()),
    }
}

/// `APACHE|<key>|<value>` rows; `APACHE|ABSENT` means the component is not on
/// the host at all, and a missing `APACHE_OK` keeps every check undecidable.
fn apache_observed(item_id: &str, output: &str) -> BaselineObservedValue {
    if output.lines().any(|line| line == "APACHE|ABSENT") {
        return BaselineObservedValue::NotInstalled;
    }
    if !output.lines().any(|line| line == "APACHE_OK") {
        return BaselineObservedValue::Unverified;
    }
    let get = |key: &str| {
        output
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("APACHE|{key}|")))
            .next()
            .unwrap_or("")
    };
    let v = |s: &str| BaselineObservedValue::Value(s.to_owned());
    match item_id {
        "apache-options-indexes" => match get("indexes") {
            "on" => v("on"),
            "off" => v("off"),
            _ => v("unset"),
        },
        "apache-status-info" => match get("status") {
            "exposed" => v("exposed"),
            "unverified" => BaselineObservedValue::Unverified,
            _ => v("off"),
        },
        "apache-run-user" => {
            if get("worker0") == "1" {
                v("root-worker")
            } else {
                match get("usr") {
                    "unverified" | "unresolved" => BaselineObservedValue::Unverified,
                    "root" => v("root"),
                    "" | "unset" => v("unset"),
                    _ => v("non-root"),
                }
            }
        }
        "apache-timeout" => match get("tmo").parse::<u64>() {
            Ok(n) if n <= 300 => v("within-300"),
            Ok(n) => v(&n.to_string()),
            _ => v("within-300"),
        },
        "apache-limit-request-body" => v(if get("lrb") == "set" {
            "configured"
        } else {
            "unset"
        }),
        "apache-modules-minimal" => match get("mods") {
            "unverified" | "" => BaselineObservedValue::Unverified,
            m => v(m),
        },
        _ => BaselineObservedValue::Unverified,
    }
}

/// `TOMCAT|<key>|<value>` rows, same contract as `APACHE|*`.
fn tomcat_observed(item_id: &str, output: &str) -> BaselineObservedValue {
    if output.lines().any(|line| line == "TOMCAT|ABSENT") {
        return BaselineObservedValue::NotInstalled;
    }
    if !output.lines().any(|line| line == "TOMCAT_OK") {
        return BaselineObservedValue::Unverified;
    }
    let get = |key: &str| {
        output
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("TOMCAT|{key}|")))
            .next()
            .unwrap_or("")
    };
    let v = |s: &str| BaselineObservedValue::Value(s.to_owned());
    match item_id {
        "tomcat-manager-access" => match get("mgr") {
            "exposed" => v("exposed"),
            "unverified" => BaselineObservedValue::Unverified,
            _ => v("safe"),
        },
        "tomcat-ajp-secret" => match get("ajp") {
            "open" => v("open"),
            "unverified" => BaselineObservedValue::Unverified,
            _ => v("secured"),
        },
        "tomcat-run-user" => match get("usr") {
            "root" => v("root"),
            "non-root" => v("non-root"),
            _ => BaselineObservedValue::Unverified,
        },
        "tomcat-listings-off" => match get("lst") {
            "true" => v("true"),
            "unverified" => BaselineObservedValue::Unverified,
            _ => v("false"),
        },
        "tomcat-session-timeout" => match get("ses").parse::<u64>() {
            Ok(n) if n <= 30 => v("within-30"),
            Ok(n) => v(&n.to_string()),
            _ => match get("ses") {
                "unverified" => BaselineObservedValue::Unverified,
                _ => v("within-30"),
            },
        },
        _ => BaselineObservedValue::Unverified,
    }
}
pub(super) fn scan_from_output(output: &str) -> CoreResult<Vec<BaselineStatus>> {
    BASELINE_CATALOG
        .iter()
        .filter(|d| matches!(d.reading, Reading::HostState))
        .map(|d| {
            let observed = if d.id.starts_with("ssh-") && d.file == "/etc/ssh/sshd_config" {
                Some(sshd_observed(d.id, output))
            } else if d.id == "session-idle-timeout" {
                Some(tmout_observed(output))
            } else if d.id == "password-history" {
                Some(pwhist_observed(output))
            } else if d.id == "su-wheel-restriction" {
                Some(wheel_observed(output))
            } else if d.id == "dormant-login-accounts" {
                Some(dormant_observed(output))
            } else if d.id == "sudo-operation-log" {
                Some(sudolog_observed(output))
            } else if d.id.starts_with("apache-") {
                Some(apache_observed(d.id, output))
            } else if d.id.starts_with("tomcat-") {
                Some(tomcat_observed(d.id, output))
            } else if d.file == AUDIT_FILE {
                output
                    .lines()
                    .find(|s| s.starts_with("AUDIT|"))
                    .and_then(|line| parse_audit(line).ok())
                    .and_then(|probe| {
                        audit_policy(&probe).ok().map(|wanted| {
                            if probe.rules == wanted && probe.file.sha256.is_some() {
                                BaselineObservedValue::Value(AUDIT_READY.to_owned())
                            } else {
                                BaselineObservedValue::Value(
                                    if probe.file.sha256.is_some() {
                                        "persistent-only"
                                    } else if probe
                                        .rules
                                        .lines()
                                        .any(|line| line.contains(AUDIT_KEY))
                                    {
                                        "runtime-only"
                                    } else {
                                        "not-configured"
                                    }
                                    .to_owned(),
                                )
                            }
                        })
                    })
            } else {
                output
                    .lines()
                    .find(|s| s.starts_with(&format!("PERM|{}|", d.file)))
                    .and_then(|line| parse_permission(line).ok())
                    .and_then(|probe| {
                        permission_policy(&probe).ok().and_then(|(mode, gid)| {
                            attributes(&probe.file).ok().map(|a| {
                                BaselineObservedValue::Value(
                                    if a[0] == u64::from(mode)
                                        && a[1] == 0
                                        && a[2] == u64::from(gid)
                                    {
                                        PERMISSION_SAFE.to_owned()
                                    } else {
                                        format!(
                                            "权限 {:04o}，属主 UID {}，属组 GID {}",
                                            a[0], a[1], a[2]
                                        )
                                    },
                                )
                            })
                        })
                    })
            }
            .unwrap_or(BaselineObservedValue::Unverified);
            Ok(BaselineStatus {
                item_id: d.id.to_owned(),
                compliant: observed == BaselineObservedValue::Value(d.recommendation.to_owned()),
                observed,
                source_file: d.file.to_owned(),
            })
        })
        .collect()
}
pub(super) async fn capture(
    service: &BaselineService,
    session: &BoundSshSession,
    definition: &BaselineDefinition,
) -> CoreResult<Guard> {
    capture_state(service, session, definition, true).await
}

async fn capture_state(
    service: &BaselineService,
    session: &BoundSshSession,
    definition: &BaselineDefinition,
    require_root: bool,
) -> CoreResult<Guard> {
    let permission = if require_root {
        "[ \"$(id -u)\" = 0 ]"
    } else {
        "true"
    };
    if definition.id == "ssh-sftp-subsystem" {
        let output = run(service, session, &format!("{permission} && lh_sftp")).await?;
        let guard = parse_sftp(output.trim(), definition.file)?;
        guard.validate(definition)?;
        Ok(guard)
    } else if definition.file == AUDIT_FILE {
        let output = run(service, session, &format!("{permission} && lh_audit")).await?;
        let probe = parse_audit(output.trim())?;
        let after = audit_policy(&probe)?;
        let guard = Guard::Audit {
            before: probe.file,
            boot: probe.boot,
            daemon_pid: probe.daemon_pid,
            watched_hash: probe.watched_hash,
            runtime_before: probe.rules,
            runtime_after: after,
        };
        guard.validate(definition)?;
        Ok(guard)
    } else {
        let output = run(
            service,
            session,
            &format!("{permission} && lh_perm {}", shq(definition.file)),
        )
        .await?;
        let probe = parse_permission(output.trim())?;
        let (desired_mode, desired_gid) = permission_policy(&probe)?;
        Ok(Guard::Permissions {
            before: probe.file,
            desired_mode,
            desired_gid,
            group_hash: probe.group_hash,
        })
    }
}
pub(super) async fn read_view(
    service: &BaselineService,
    session: &BoundSshSession,
    definition: &BaselineDefinition,
) -> CoreResult<BaselineFileView> {
    let text = match capture_state(service, session, definition, false).await {
        Ok(Guard::Permissions {
            before,
            desired_mode,
            desired_gid,
            ..
        }) => {
            let a = attributes(&before)?;
            format!(
                "当前权限 {:04o}，属主 UID {}，属组 GID {}。\n策略目标：权限 {desired_mode:04o}，属主 UID 0，属组 GID {desired_gid}。\n已核对普通文件、内容摘要、身份及基础 ACL；正文不返回页面。需要修改时先查看具体计划并确认。",
                a[0], a[1], a[2]
            )
        }
        Ok(Guard::Sftp {
            before,
            state_before,
        }) => {
            format!(
                "sshd -T 生效 sftp 子系统：{state_before}。\n{}文件身份已核对；可经确认写入 Subsystem sftp internal-sftp（不依赖外部 sftp-server），经 sshd -t 校验后重载，失败可独立放回。\n不改动 Match 块；生效值来自其他位置时不提供写入。",
                if before.sha256.is_some() {
                    "sshd_config 完整摘要与"
                } else {
                    "sshd_config "
                }
            )
        }
        Ok(Guard::Audit {
            before,
            runtime_before,
            ..
        }) => {
            let count = wanted_rules()
                .iter()
                .filter(|rule| runtime_before.lines().any(|line| line == rule.as_str()))
                .count();
            format!(
                "本工具规则片段：{}。\n运行中匹配的认证文件监控：{count} / 4。\n未核实事件落盘或重启自动加载；当前核对未执行修改。\n{}",
                if before.sha256.is_some() {
                    "已保存并核对"
                } else {
                    "尚未保存"
                },
                wanted_rules().join("\n")
            )
        }
        Err(_) => {
            if definition.file == AUDIT_FILE {
                "无法核实 auditd：可能未安装、未运行、规则已锁定、权限不足、处于容器/WSL，或存在重叠规则及非受管文件。请在真实主机核对 auditctl -s、auditctl -l 和规则文件；未执行修改。".to_owned()
            } else {
                "无法核实文件属性、完整摘要或 ACL：可能缺少 getfacl/stat/sha256sum、权限不足、存在扩展 ACL、未知属组、链接或文件在读取时变化。仅支持本次能完整核实的普通文件；账号和口令正文不会返回页面。".to_owned()
            }
        }
    };
    Ok(BaselineFileView {
        path: definition.file.to_owned(),
        key: if definition.file == AUDIT_FILE {
            "认证文件监控"
        } else if definition.id == "ssh-sftp-subsystem" {
            "SFTP 子系统"
        } else {
            "文件属主与权限"
        },
        exists: !text.starts_with("无法核实"),
        text,
        mentions: Vec::new(),
        truncated: false,
    })
}

impl Guard {
    fn before(&self) -> &BaselineBackupEvidence {
        match self {
            Self::Permissions { before, .. }
            | Self::Audit { before, .. }
            | Self::Sftp { before, .. } => before,
        }
    }
    pub(super) fn validate(&self, definition: &BaselineDefinition) -> CoreResult<()> {
        if self.before().file != definition.file {
            return Err(error("guard does not match the selected file"));
        }
        validate_backups(
            &[definition.file.to_owned()],
            std::slice::from_ref(self.before()),
        )?;
        match self {
            Self::Permissions {
                before,
                desired_mode,
                desired_gid: _,
                group_hash,
            } => {
                if !AUTH_FILES.contains(&definition.file)
                    || *desired_mode > 0o644
                    || !digest(group_hash)
                {
                    return Err(error("invalid permission plan"));
                }
                let a = attributes(before)?;
                if u64::from(*desired_mode) & !a[0] != 0 {
                    return Err(error("permission repair cannot add access"));
                }
            }
            Self::Audit {
                before,
                boot,
                daemon_pid,
                watched_hash,
                runtime_before,
                runtime_after,
            } => {
                if definition.file != AUDIT_FILE
                    || Uuid::parse_str(boot).is_err()
                    || *daemon_pid == 0
                    || !digest(watched_hash)
                    || canonical_rules(runtime_before)? != *runtime_before
                {
                    return Err(error("invalid audit plan"));
                }
                let probe = AuditProbe {
                    file: before.clone(),
                    boot: boot.clone(),
                    daemon_pid: *daemon_pid,
                    watched_hash: watched_hash.clone(),
                    rules: runtime_before.clone(),
                };
                if audit_policy(&probe)? != *runtime_after {
                    return Err(error("audit plan changed"));
                }
            }
            Self::Sftp {
                before,
                state_before,
            } => {
                // The only writable transition is absent -> internal-sftp.
                // If sshd -T already reports an effective Subsystem sftp line
                // (from any file sshd reads), no write is offered.
                if definition.id != "ssh-sftp-subsystem"
                    || definition.file != before.file
                    || state_before != "absent"
                    || before.sha256.is_none()
                {
                    return Err(error("invalid sftp plan"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn summary(&self, file: &str) -> CoreResult<String> {
        match self {
            Self::Permissions {
                before,
                desired_mode,
                desired_gid,
                ..
            } => {
                let a = attributes(before)?;
                Ok(format!(
                    "仅修改 {file} 的属性：权限 {:04o} → {desired_mode:04o}，UID {} → 0，GID {} → {desired_gid}。保留文件正文及 inode，先在受管私有目录备份；权限立即生效，依赖多余权限的程序可能无法再访问。放回前核对完整内容与身份，只放回原权限和属主，不覆盖后来修改的正文。",
                    a[0], a[1], a[2]
                ))
            }
            Self::Sftp { .. } => Ok(format!(
                "在 {file} 开头追加全局指令 Subsystem sftp internal-sftp：不依赖外部 sftp-server 二进制，不改动 Match 块与已有内容，写入后经 sshd -t 校验并重载 sshd。先在受管私有目录备份完整文件；新连接即可使用 SFTP/本工作台文件管理，进行中的会话不受影响。放回前核对备份摘要，把原文件内容写回同一 inode 并重载；遇到后续变化即停止。",
            )),
            Self::Audit { runtime_before, .. } => Ok(format!(
                "为 /etc/passwd、/etc/group、/etc/shadow、/etc/gshadow 增加写入及属性变化监控。规则片段：{file}（root:root，0600）；运行中只添加缺失的 {} 条本工具规则，不重载其他规则或重启服务。会增加审计事件量。保存片段不证明启动加载，规则存在不证明日志成功落盘，须独立产生测试事件并检查留存。恢复只撤销本次新增规则并放回原片段，遇到后续变化即停止。\n{}",
                wanted_rules()
                    .iter()
                    .filter(|rule| !runtime_before.lines().any(|line| line == rule.as_str()))
                    .count(),
                wanted_rules().join("\n")
            )),
        }
    }
}

fn guard_assertion(guard: &Guard, restored: bool) -> CoreResult<String> {
    let before = guard.before();
    match guard {
        Guard::Permissions {
            desired_mode,
            desired_gid,
            group_hash,
            ..
        } => {
            let mut expected = before.clone();
            if !restored {
                let a = attributes(before)?;
                expected.attributes = Some(format!(
                    "{desired_mode:o}:0:{desired_gid}:{}:{}:1",
                    a[3], a[4]
                ));
            }
            Ok(format!(
                "{} [ \"$(lh_hash /etc/group)\" = {} ] || exit 42; lh_perm {} >/dev/null || exit 42; ",
                assert_file_evidence(&expected),
                shq(group_hash),
                shq(&before.file)
            ))
        }
        Guard::Audit {
            boot,
            daemon_pid,
            watched_hash,
            runtime_before,
            runtime_after,
            ..
        } => {
            let runtime = if restored {
                runtime_before
            } else {
                runtime_after
            };
            // Reuse the same bounded parser on the target. Normalized rule order
            // is irrelevant; all unrelated rules must still match the plan.
            Ok(format!(
                "lh_audit >/dev/null || exit 42; [ \"$lh_boot\" = {} ] && [ \"$lh_pid\" = {} ] && [ \"$lh_watched\" = {} ] || exit 42; lh_normal=$(printf '%s\\n' \"$lh_rules\" | awk 'NF && $0 != \"No rules\" {{$1=$1; print}}' | LC_ALL=C sort); [ \"$lh_normal\" = {} ] || exit 42; ",
                shq(boot),
                shq(&daemon_pid.to_string()),
                shq(watched_hash),
                shq(runtime)
            ))
        }
        Guard::Sftp {
            before,
            state_before,
        } => {
            if restored {
                Ok(format!(
                    "{} [ \"$(lh_sftp_state)\" = {} ] || exit 42; ",
                    assert_file_evidence(before),
                    shq(state_before)
                ))
            } else {
                // Same inode, new digest, and `sshd -T` must now read the
                // effective line — file content alone is not proof.
                Ok(format!(
                    "lh_file {} && [ \"$lh_attrs\" = {} ] || exit 42; [ \"$(lh_sftp_state)\" = present ] || exit 42; ",
                    shq(&before.file),
                    shq(before
                        .attributes
                        .as_deref()
                        .ok_or_else(|| error("missing file identity"))?)
                ))
            }
        }
    }
}

/// `SFTP|<state>|<attrs>|<digest>` from `lh_sftp`; only an absent effective
/// state plans a write, anything else refuses instead of guessing.
fn parse_sftp(line: &str, file: &str) -> CoreResult<Guard> {
    let p: Vec<&str> = line.split('|').collect();
    if p.len() != 4 || p[0] != "SFTP" {
        return Err(error("unreadable sftp evidence"));
    }
    if !matches!(p[1], "absent" | "present") {
        return Err(error("sftp state not decidable"));
    }
    Ok(Guard::Sftp {
        before: evidence(file, p[2], p[3])?,
        state_before: p[1].to_owned(),
    })
}
fn change_attrs(file: &str, mode: u64, uid: u64, gid: u64) -> String {
    format!(
        "chown -- {} {}; chmod -- {} {}; ",
        shq(&format!("{uid}:{gid}")),
        shq(file),
        shq(&format!("{mode:o}")),
        shq(file)
    )
}
fn watch_delta(guard: &Guard, undo: bool) -> String {
    let Guard::Audit { runtime_before, .. } = guard else {
        return String::new();
    };
    AUTH_FILES
        .iter()
        .zip(wanted_rules())
        .filter(|(_, rule)| !runtime_before.lines().any(|line| line == rule))
        .map(|(path, _)| {
            format!(
                "auditctl {} {} -p wa -k {AUDIT_KEY} || exit 43; ",
                if undo { "-W" } else { "-w" },
                shq(path)
            )
        })
        .collect()
}

pub(super) fn apply_command(plan: &BaselineChangePlan) -> CoreResult<String> {
    let change = &plan.changes[0];
    let guard = change
        .host_guard
        .as_ref()
        .ok_or_else(|| error("missing plan"))?;
    guard.validate(definition(&change.item_id)?)?;
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    command.push_str(&guard_assertion(guard, true)?);
    command.push_str(&assert_file_evidence(guard.before()));
    // Verify parent ownership before creating a backup namespace or rule file.
    command.push_str(&format!(
        "lh_safe_dir /etc && lh_safe_dir {} || exit 41; ",
        shq(BASELINE_ROOT)
    ));
    if matches!(guard, Guard::Audit { .. }) {
        command.push_str("lh_safe_dir /etc/audit/rules.d || exit 41; ");
    }
    command.push_str(&backup_prelude(&plan.remote_root, &plan.files)?);
    // Attribute records are part of the immutable plan. The generic backup
    // row lacks them; replace it with an exact second marker used below.
    command.push_str(&files_read_body(
        &plan.files,
        "HOST_BACKUP=",
        guard.before().sha256.is_some(),
    )?);
    match guard {
        Guard::Permissions {
            before,
            desired_mode,
            desired_gid,
            ..
        } => {
            command.push_str(&assert_file_evidence(before));
            command.push_str(&change_attrs(
                &before.file,
                u64::from(*desired_mode),
                0,
                u64::from(*desired_gid),
            ));
        }
        Guard::Audit { before, .. } => {
            if before.sha256.is_none() {
                command.push_str(&format!("(set -C; umask 077; printf '%s' {} > {}) || exit 41; chown 0:0 {}; stat -c '%a:%u:%g:%d:%i:%h' -- {} > {}; ", shq(&rules_file()), shq(AUDIT_FILE), shq(AUDIT_FILE), shq(AUDIT_FILE), shq(&format!("{}/audit-created.attrs", plan.remote_root))));
            }
            command.push_str(&watch_delta(guard, false));
        }
        Guard::Sftp { before, .. } => {
            // Prepend at line 1: global scope is guaranteed before any Match
            // block, and `cat` back into the file keeps inode and attributes.
            command.push_str(&format!(
                "lr_tmp={}; {{ printf 'Subsystem sftp internal-sftp\\n'; cat -- {}; }} > \"$lr_tmp\" && cat -- \"$lr_tmp\" > {} && rm -f -- \"$lr_tmp\" || {{ rm -f -- \"$lr_tmp\"; exit 41; }}; sshd -t || exit 43; ",
                shq(&format!("{}/sftp-edit.tmp", plan.remote_root)),
                shq(&before.file),
                shq(&before.file)
            ));
            if plan.reload_policy == BaselineReloadPolicy::ApplyNow {
                command.push_str(SSHD_RELOAD);
            }
        }
    }
    command.push_str(&guard_assertion(guard, false)?);
    command.push_str(&files_read_body(&plan.files, "APPLIED_FILE=", true)?);
    command.push_str(&format!("printf '%s\\n' {APPLY_MARKER}"));
    Ok(command)
}

pub(super) fn restore_command(
    change: &PlannedBaselineChange,
    remote_root: &str,
    backups: &[BaselineBackupEvidence],
    applied: Option<&[BaselineBackupEvidence]>,
) -> CoreResult<String> {
    let guard = change
        .host_guard
        .as_ref()
        .ok_or_else(|| error("missing host plan"))?;
    guard.validate(definition(&change.item_id)?)?;
    validate_remote_root(remote_root)?;
    validate_backups(std::slice::from_ref(&change.file), backups)?;
    if backups != std::slice::from_ref(guard.before()) {
        return Err(error("backup state differs from the approved plan"));
    }
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    command.push_str(&guard_assertion(guard, false)?);
    if let Some(applied) = applied {
        validate_applied_files(std::slice::from_ref(&change.file), applied)?;
        command.push_str(&assert_file_evidence(&applied[0]));
    }
    if let Guard::Audit { before, .. } = guard {
        if before.sha256.is_some() {
            command.push_str(&assert_file_evidence(before));
        } else {
            let marker = format!("{remote_root}/audit-created.attrs");
            command.push_str(&format!("lh_file {} && [ \"$lh_digest\" = {} ] && lh_path {} && [ \"$(cat {})\" = \"$lh_attrs\" ] || exit 42; ", shq(AUDIT_FILE), shq(&sha256_hex(rules_file())), shq(&marker), shq(&marker)));
        }
    }
    let backup = format!("{remote_root}/file-0.before");
    if let Some(hash) = &guard.before().sha256 {
        command.push_str(&format!(
            "lh_path {} && [ -f {} ] && [ \"$(lh_hash {})\" = {} ] || exit 42; ",
            shq(&backup),
            shq(&backup),
            shq(&backup),
            shq(hash)
        ));
    }
    match guard {
        Guard::Permissions { before, .. } => {
            let a = attributes(before)?;
            command.push_str(&change_attrs(&before.file, a[0], a[1], a[2]));
        }
        Guard::Audit { before, .. } => {
            command.push_str(&watch_delta(guard, true));
            if before.sha256.is_none() {
                command.push_str(&format!(
                    "[ \"$(lh_hash {})\" = {} ] || exit 42; rm -- {}; ",
                    shq(AUDIT_FILE),
                    shq(&sha256_hex(rules_file())),
                    shq(AUDIT_FILE)
                ));
            }
        }
        Guard::Sftp { before, .. } => {
            // Restore = copy the verified backup over the same inode, then
            // reload so the running daemon matches the file again.
            command.push_str(&format!(
                "cat -- {} > {} || exit 43; sshd -t || exit 43; ",
                shq(&backup),
                shq(&before.file)
            ));
            command.push_str(SSHD_RELOAD);
        }
    }
    command.push_str(&assert_file_evidence(guard.before()));
    command.push_str(&guard_assertion(guard, true)?);
    command.push_str(&format!("printf '%s\\n' {RESTORE_MARKER}"));
    Ok(command)
}
pub(super) async fn verify(
    service: &BaselineService,
    session: &BoundSshSession,
    change: &PlannedBaselineChange,
    restored: bool,
) -> CoreResult<VerificationResult> {
    let guard = change
        .host_guard
        .as_ref()
        .ok_or_else(|| error("missing host plan"))?;
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    command.push_str(&guard_assertion(guard, restored)?);
    if matches!(guard, Guard::Audit { .. }) {
        if restored {
            command.push_str(&assert_file_evidence(guard.before()));
        } else {
            command.push_str(&format!("lh_file {} || exit 42; [ \"$lh_digest\" = {} ] || exit 42; case \"$lh_attrs\" in 600:0:0:*) ;; *) exit 42;; esac; ", shq(AUDIT_FILE), shq(&sha256_hex(rules_file()))));
        }
    }
    command.push_str("printf 'HOST_VERIFIED\\n'");
    let output = service
        .ssh
        .execute_bound(session, command, COMMAND_TIMEOUT)
        .await?;
    service.target.validate(session.target())?;
    let passed = !output.timed_out
        && output.exit_code == Some(0)
        && output.output.lines().any(|line| line == "HOST_VERIFIED");
    Ok(VerificationResult {
        passed,
        detail: if passed {
            match guard {
            Guard::Permissions { .. } => "已独立核对完整内容摘要、文件身份、属主、属组、权限与 ACL；文件正文未改动。",
            Guard::Audit { .. } => "已独立核对规则片段和内核规则，其他规则保持原状。尚未确认审计事件落盘或重启后的自动加载。",
            Guard::Sftp { .. } => "已用 sshd -T 独立核对生效的 sftp 子系统并核对文件身份；建议再以一次真实 SFTP 连接复核。",
        }.to_owned()
        } else {
            "独立复核未通过，请核对当前属性和运行规则；保留备份与操作记录，不能据此认定已恢复。"
                .to_owned()
        },
    })
}

fn partial_restore_command(
    guard: &Guard,
    remote_root: &str,
    observation: &str,
) -> CoreResult<String> {
    validate_remote_root(remote_root)?;
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    match guard {
        Guard::Permissions {
            before,
            desired_mode,
            desired_gid,
            group_hash,
        } => {
            let now = parse_permission(observation.trim())?;
            let old = attributes(before)?;
            let actual = attributes(&now.file)?;
            if before.sha256 != now.file.sha256
                || old[3..] != actual[3..]
                || group_hash != &now.group_hash
                || !((actual[0] == old[0] && actual[1] == old[1] && actual[2] == old[2])
                    || (actual[1] == 0
                        && actual[2] == u64::from(*desired_gid)
                        && (actual[0] == old[0] || actual[0] == u64::from(*desired_mode))))
            {
                return Err(error("文件在失败后有其他变化，未自动放回"));
            }
            command.push_str(&assert_file_evidence(&now.file));
            command.push_str(&format!(
                "lh_path {} && [ \"$(lh_hash {})\" = {} ] || exit 42; ",
                shq(&format!("{}/file-0.before", remote_root)),
                shq(&format!("{}/file-0.before", remote_root)),
                shq(before
                    .sha256
                    .as_deref()
                    .ok_or_else(|| error("missing original hash"))?)
            ));
            command.push_str(&change_attrs(&before.file, old[0], old[1], old[2]));
        }
        Guard::Audit {
            before,
            boot,
            daemon_pid,
            watched_hash,
            runtime_before,
            runtime_after,
        } => {
            let now = parse_audit(observation.trim())?;
            audit_policy(&now)?;
            let old: BTreeSet<_> = runtime_before.lines().collect();
            let after: BTreeSet<_> = runtime_after.lines().collect();
            let current: BTreeSet<_> = now.rules.lines().collect();
            if now.boot != *boot
                || now.daemon_pid != *daemon_pid
                || now.watched_hash != *watched_hash
                || (before.sha256.is_some() && now.file != *before)
                || !old.is_subset(&current)
                || !current.is_subset(&after)
            {
                return Err(error("审计规则或主机状态发生其他变化，未自动放回"));
            }
            let current_guard = Guard::Audit {
                before: before.clone(),
                boot: boot.clone(),
                daemon_pid: *daemon_pid,
                watched_hash: watched_hash.clone(),
                runtime_before: now.rules.clone(),
                runtime_after: runtime_after.clone(),
            };
            command.push_str(&guard_assertion(&current_guard, true)?);
            command.push_str(&assert_file_evidence(&now.file));
            if before.sha256.is_none() && now.file.sha256.is_some() {
                let marker = format!("{}/audit-created.attrs", remote_root);
                command.push_str(&format!(
                    "lh_path {} && [ -f {} ] && [ \"$(cat {})\" = {} ] || exit 42; ",
                    shq(&marker),
                    shq(&marker),
                    shq(&marker),
                    shq(now
                        .file
                        .attributes
                        .as_deref()
                        .ok_or_else(|| error("missing created file identity"))?)
                ));
            }
            for file in AUTH_FILES {
                let rule = format!("-w {file} -p wa -k {AUDIT_KEY}");
                if !old.contains(rule.as_str()) && current.contains(rule.as_str()) {
                    command.push_str(&format!(
                        "auditctl -W {} -p wa -k {AUDIT_KEY} || exit 43; ",
                        shq(file)
                    ));
                }
            }
            if before.sha256.is_none() && now.file.sha256.is_some() {
                command.push_str(&format!("rm -- {}; ", shq(AUDIT_FILE)));
            }
        }
        Guard::Sftp {
            before,
            state_before,
        } => {
            let now = parse_sftp(observation.trim(), &before.file)?;
            let Guard::Sftp {
                before: now_file,
                state_before: now_state,
            } = now
            else {
                return Err(error("sftp observation mismatch"));
            };
            // Only undo a file that is exactly this plan's result: same inode
            // and attributes, with the subsystem now effective.
            if now_state != "present"
                || now_file.attributes != before.attributes
                || now_file.sha256 == before.sha256
            {
                return if now_state == *state_before {
                    Ok(command)
                } else {
                    Err(error("sshd_config 在失败后有其他变化，未自动放回"))
                };
            }
            let backup = format!("{}/file-0.before", remote_root);
            command.push_str(&format!(
                "lh_path {} && [ \"$(lh_hash {})\" = {} ] || exit 42; cat -- {} > {} || exit 43; sshd -t || exit 43; ",
                shq(&backup),
                shq(&backup),
                shq(before
                    .sha256
                    .as_deref()
                    .ok_or_else(|| error("missing original hash"))?),
                shq(&backup),
                shq(&before.file)
            ));
            command.push_str(SSHD_RELOAD);
        }
    }
    Ok(command)
}

/// A nonzero exit may follow a partial chmod or rule insertion. Journal it and
/// only undo states that are a prefix of this exact plan, preserving every
/// unrelated change. A lost connection never becomes a successful restore.
pub(super) async fn failed_execution(
    service: &BaselineService,
    session: &BoundSshSession,
    plan: &BaselineChangePlan,
) -> CoreError {
    let change = &plan.changes[0];
    let recovery = async {
        let guard = change
            .host_guard
            .as_ref()
            .ok_or_else(|| error("missing plan"))?;
        if verify(service, session, change, true)
            .await
            .is_ok_and(|r| r.passed)
        {
            return Ok::<_, CoreError>(true);
        }
        let observation = match guard {
            Guard::Permissions { before, .. } => {
                run(service, session, &format!("lh_perm {}", shq(&before.file))).await?
            }
            Guard::Audit { .. } => run(service, session, "lh_audit").await?,
            Guard::Sftp { .. } => run(service, session, "lh_sftp").await?,
        };
        let command = partial_restore_command(guard, &plan.remote_root, &observation)?;
        successful_output(
            "放回本次未完成的属性或审计变更",
            service
                .ssh
                .execute_bound(session, command, COMMAND_TIMEOUT)
                .await?,
        )?;
        Ok(verify(service, session, change, true).await?.passed)
    }
    .await;
    let detail = if recovery.is_ok_and(|ok| ok) {
        "执行未完成；已独立核对原有属性与规则，未留下本次变更。"
    } else {
        "执行未完成，可能已有部分变更；未能独立确认放回。请核对目标状态，保留受管备份与审计记录。"
    };
    let entry = crate::operations::OperationJournalEntry {
        entry_id: Uuid::new_v4().to_string(),
        operation_id: plan.operation.id.clone(),
        target: plan.operation.target.clone(),
        summary: plan.operation.summary.clone(),
        dangerous: true,
        source: "baseline".to_owned(),
        restore_description: plan.operation.restore_description.clone(),
        phase: crate::operations::JournalPhase::VerificationFailed,
        detail: detail.to_owned(),
        occurred_at: Utc::now(),
    };
    if let Err(journal_error) = service.journal.append(entry) {
        tracing::warn!(error = %journal_error, "authentication baseline failure journal could not be saved");
        return error(format!(
            "{detail} 本机操作记录保存失败，请检查便携数据目录的空间与写入权限。"
        ));
    }
    error(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permission(file: &str, mode: &str, uid: u32, gid: u32) -> PermissionProbe {
        parse_permission(&format!(
            "PERM|{file}|{mode}:{uid}:{gid}:2049:19:1|{}|0|42|{}",
            "a".repeat(64),
            "b".repeat(64)
        ))
        .unwrap()
    }
    fn audit(rules: &str) -> AuditProbe {
        parse_audit(&format!(
            "AUDIT|-|-|11111111-1111-4111-8111-111111111111|123|{}|{}",
            STANDARD.encode(rules),
            "c".repeat(64)
        ))
        .unwrap()
    }

    #[test]
    fn permission_policy_retains_shadow_group_and_never_adds_access() {
        assert_eq!(
            permission_policy(&permission("/etc/shadow", "666", 0, 42)).unwrap(),
            (0o640, 42)
        );
        assert_eq!(
            permission_policy(&permission("/etc/shadow", "666", 0, 0)).unwrap(),
            (0o600, 0)
        );
        assert_eq!(
            permission_policy(&permission("/etc/gshadow", "400", 0, 42)).unwrap(),
            (0o400, 42)
        );
        assert_eq!(
            permission_policy(&permission("/etc/passwd", "6777", 1000, 1000)).unwrap(),
            (0o644, 0)
        );
        assert!(permission_policy(&permission("/etc/shadow", "640", 0, 1000)).is_err());
    }

    #[test]
    fn malformed_metadata_and_missing_observations_do_not_pass() {
        assert!(is_attribute_label("权限 0666，属主 UID 0，属组 GID 42"));
        for invalid in [
            "权限 0999，属主 UID 0，属组 GID 42",
            "权限 0666，属主 UID 0，属组 GID 42;id",
            "权限 0666，属主 UID 0，属组 GID 42\n",
            "权限 0666，属主 UID 0，属组 GID 4294967296",
        ] {
            assert!(!is_attribute_label(invalid));
        }
        for line in [
            "PERM|/etc/shadow|640:0:0:1:2:2|a|0|42|b",
            "PERM|/etc/passwd;id|640:0:0:1:2:1|a|0|42|b",
            "GAP|/etc/shadow",
        ] {
            assert!(parse_permission(line).is_err());
        }
        let missing = scan_from_output("GAP|audit\nGAP|/etc/shadow").unwrap();
        assert_eq!(
            missing.len(),
            BASELINE_CATALOG
                .iter()
                .filter(|d| matches!(d.reading, Reading::HostState))
                .count()
        );
        assert!(missing.iter().all(
            |status| status.observed == BaselineObservedValue::Unverified && !status.compliant
        ));
        assert!(!PROBE.contains("cat /etc/shadow"));
        assert!(PROBE.contains("getfacl -cp"));
    }

    #[test]
    fn audit_refuses_overlaps_exclusions_and_unowned_persistence() {
        for rule in [
            "-w /etc/shadow -p wa -k existing",
            "-a never,task",
            "-a always,exclude -F msgtype=PATH",
            "-a always,exit -F dir=/ -F perm=wa",
            "-w /etc -p wa -k whole-directory",
        ] {
            assert!(audit_policy(&audit(rule)).is_err(), "{rule}");
        }
        let mut probe = audit("");
        probe.file = evidence(AUDIT_FILE, "600:0:0:2049:20:1", &"d".repeat(64)).unwrap();
        assert!(audit_policy(&probe).is_err());
        assert!(canonical_rules("-w /tmp/a -p wa\n-w /tmp/a -p wa").is_err());
    }

    #[test]
    fn audit_only_adds_missing_owned_rules_and_preserves_unrelated_rules() {
        let first = wanted_rules()[0].clone();
        let probe = audit(&format!("{first}\n-w /var/log -p wa -k previous"));
        let after = audit_policy(&probe).unwrap();
        assert_eq!(after.lines().count(), 5);
        let guard = Guard::Audit {
            before: probe.file,
            boot: probe.boot,
            daemon_pid: probe.daemon_pid,
            watched_hash: probe.watched_hash,
            runtime_before: probe.rules,
            runtime_after: after,
        };
        guard.validate(&AUDIT_DEFINITION).unwrap();
        let add = watch_delta(&guard, false);
        assert_eq!(add.matches("auditctl -w ").count(), 3);
        assert!(!add.contains("/etc/passwd"));
        let remove = watch_delta(&guard, true);
        assert_eq!(remove.matches("auditctl -W ").count(), 3);
        assert!(!remove.contains("/var/log"));
        assert!(!add.contains("-D"));
    }

    #[test]
    fn metadata_plans_bind_identity_and_refuse_the_generic_writer() {
        let probe = permission("/etc/shadow", "666", 0, 42);
        let guard = Guard::Permissions {
            before: probe.file.clone(),
            desired_mode: 0o640,
            desired_gid: 42,
            group_hash: probe.group_hash,
        };
        let change = PlannedBaselineChange {
            item_id: "permissions-auth-shadow".to_owned(),
            before: BaselineObservedValue::Value("mode:0666,uid:0,gid:42".to_owned()),
            after: PERMISSION_SAFE.to_owned(),
            file: "/etc/shadow".to_owned(),
            host_guard: Some(guard.clone()),
        };
        validate_changes(std::slice::from_ref(&change)).unwrap();
        assert!(edit_body(&change, "/tmp", 0).is_err());
        let assertion = guard_assertion(&guard, false).unwrap();
        assert!(assertion.contains("640:0:42:2049:19:1"));
        assert!(assertion.contains(&"a".repeat(64)) && assertion.contains(&"b".repeat(64)));
        let mut forged = change.clone();
        forged.host_guard = None;
        assert!(validate_changes(&[forged]).is_err());
        assert!(validate_changes(&[change.clone(), change]).is_err());
        let root = expected_remote_root("11111111-1111-4111-8111-111111111111").unwrap();
        let restore = restore_command(
            &PlannedBaselineChange {
                item_id: "permissions-auth-shadow".to_owned(),
                before: BaselineObservedValue::Missing,
                after: PERMISSION_SAFE.to_owned(),
                file: "/etc/shadow".to_owned(),
                host_guard: Some(guard),
            },
            &root,
            &[probe.file],
            None,
        )
        .unwrap();
        assert!(restore.contains("chown -- '0:42' '/etc/shadow'"));
        assert!(!restore.contains("cp -p") && !restore.contains("cat --"));
    }

    #[test]
    fn partial_audit_recovery_rejects_replacement_of_an_existing_fragment() {
        let probe = audit("");
        let hash = sha256_hex(rules_file());
        let guard = Guard::Audit {
            before: evidence(AUDIT_FILE, "600:0:0:2049:20:1", &hash).unwrap(),
            boot: probe.boot.clone(),
            daemon_pid: probe.daemon_pid,
            watched_hash: probe.watched_hash.clone(),
            runtime_before: probe.rules,
            runtime_after: canonical_rules(&wanted_rules().join("\n")).unwrap(),
        };
        let observation = format!(
            "AUDIT|600:0:0:2049:21:1|{hash}|{}|123|{}|{}",
            probe.boot,
            STANDARD.encode(&wanted_rules()[0]),
            probe.watched_hash
        );
        let root = expected_remote_root("11111111-1111-4111-8111-111111111111").unwrap();
        assert!(partial_restore_command(&guard, &root, &observation).is_err());
        assert!(
            partial_restore_command(&guard, &root, &observation.replace(":21:1", ":20:1")).is_ok()
        );
    }

    // A fixture runner supplies real stat/hash observations from its private
    // directory. Export the production commands, not a second implementation.
    #[test]
    #[ignore = "requires an explicitly owned shell fixture input"]
    fn export_owned_fixture_commands() {
        let input = std::env::var("LOVELYHAWK_HOST_BASELINE_FIXTURE").unwrap();
        let input_path = std::path::Path::new(&input);
        assert!(input_path.is_absolute() && input_path.file_name().unwrap() == "host-input.json");
        let data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(input_path).unwrap()).unwrap();
        let line = data["observation"].as_str().unwrap();
        let (id, guard) = if line.starts_with("PERM|") {
            let p = parse_permission(line).unwrap();
            let (mode, gid) = permission_policy(&p).unwrap();
            (
                "permissions-auth-shadow",
                Guard::Permissions {
                    before: p.file,
                    desired_mode: mode,
                    desired_gid: gid,
                    group_hash: p.group_hash,
                },
            )
        } else {
            let p = parse_audit(line).unwrap();
            let after = audit_policy(&p).unwrap();
            (
                "logging-auth-file-watches",
                Guard::Audit {
                    before: p.file,
                    boot: p.boot,
                    daemon_pid: p.daemon_pid,
                    watched_hash: p.watched_hash,
                    runtime_before: p.rules,
                    runtime_after: after,
                },
            )
        };
        let definition = definition(id).unwrap();
        guard.validate(definition).unwrap();
        let change = PlannedBaselineChange {
            item_id: id.to_owned(),
            before: BaselineObservedValue::Missing,
            after: definition.recommendation.to_owned(),
            file: definition.file.to_owned(),
            host_guard: Some(guard.clone()),
        };
        let id = Uuid::new_v4().to_string();
        let remote_root = data["remoteRoot"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| expected_remote_root(&id).unwrap());
        validate_remote_root(&remote_root).unwrap();
        let plan = BaselineChangePlan {
            operation: OperationPlan::new(
                TargetGuard {
                    identity: TargetIdentity::new("owned-fixture").unwrap(),
                    generation: 1,
                },
                "fixture",
                true,
                Some("restore".to_owned()),
            )
            .unwrap(),
            changes: vec![change.clone()],
            files: vec![definition.file.to_owned()],
            remote_root: remote_root.clone(),
            reload_policy: BaselineReloadPolicy::ApplyNow,
            digest: String::new(),
        };
        let recovery = data["current"].as_str().map(|line| {
            partial_restore_command(&guard, &remote_root, line).map_err(|error| error.to_string())
        });
        let output = serde_json::json!({"recovery": recovery, "apply": apply_command(&plan).unwrap(), "restore": restore_command(&change, &remote_root, std::slice::from_ref(guard.before()), None).unwrap(), "root": remote_root});
        std::fs::write(
            input_path.with_file_name("host-commands.json"),
            serde_json::to_vec_pretty(&output).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn sshd_state_tokens_and_unknowns() {
        use super::{scan_from_output, sshd_observed};
        use crate::baseline::BaselineObservedValue::{Unverified, Value};
        let v = |s: &str| Value(s.to_owned());
        // sshd -T unreadable (no marker), even with stray lines: never compliant.
        for output in [
            "",
            "GAP|sshd
",
            "SSHD|ciphers aes256-ctr
",
        ] {
            let statuses = scan_from_output(output).unwrap();
            for id in [
                "ssh-weak-algorithms",
                "ssh-sftp-subsystem",
                "ssh-login-restriction",
            ] {
                let status = statuses.iter().find(|s| s.item_id == id).expect(id);
                assert_eq!(status.observed, Unverified, "{id} {output:?}");
                assert!(!status.compliant, "{id}");
            }
        }
        let defaults = "SSHD|ciphers aes256-ctr,chacha20-poly1305@openssh.com
SSHD|macs hmac-sha2-256
SSHD|kexalgorithms curve25519-sha256
SSHD|subsystem sftp /usr/lib/openssh/sftp-server
SSHD_OK
";
        assert_eq!(sshd_observed("ssh-weak-algorithms", defaults), v("none"));
        assert_eq!(sshd_observed("ssh-sftp-subsystem", defaults), v("enabled"));
        assert_eq!(
            sshd_observed("ssh-login-restriction", defaults),
            v("unrestricted")
        );
        let weak = "SSHD|ciphers aes128-cbc,3des-cbc,aes256-ctr
SSHD|macs hmac-sha1,hmac-sha2-256
SSHD|kexalgorithms gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==,curve25519-sha256
SSHD|allowusers root deploy
SSHD_OK
";
        assert_eq!(
            sshd_observed("ssh-weak-algorithms", weak),
            v("aes128-cbc,3des-cbc,hmac-sha1,+1")
        );
        assert_eq!(
            sshd_observed("ssh-login-restriction", weak),
            v("restricted")
        );
        assert_eq!(
            sshd_observed(
                "ssh-sftp-subsystem",
                "SSHD|subsystem internal-x y
SSHD_OK
"
            ),
            v("absent")
        );
        assert_eq!(
            sshd_observed(
                "ssh-login-restriction",
                "SSHD|allowgroups admins
SSHD_OK
"
            ),
            v("restricted")
        );
        let statuses = scan_from_output(&format!(
            "{defaults}SSHD|allowusers root
"
        ))
        .unwrap();
        for id in [
            "ssh-weak-algorithms",
            "ssh-sftp-subsystem",
            "ssh-login-restriction",
        ] {
            assert!(
                statuses.iter().find(|s| s.item_id == id).unwrap().compliant,
                "{id}"
            );
        }
        let statuses = scan_from_output(weak).unwrap();
        assert!(
            !statuses
                .iter()
                .find(|s| s.item_id == "ssh-weak-algorithms")
                .unwrap()
                .compliant
        );
    }

    #[test]
    fn sshd_state_items_are_check_only() {
        for id in [
            "ssh-weak-algorithms",
            "ssh-login-restriction",
            "session-idle-timeout",
            "password-history",
            "su-wheel-restriction",
            "dormant-login-accounts",
        ] {
            let definition = crate::baseline::definition(id).expect(id);
            assert!(!definition.is_writable(), "{id}");
        }
        // The sftp subsystem is the one SSH host-state item with a guarded
        // write path (Subsystem sftp internal-sftp through the sshd chain).
        assert!(
            crate::baseline::definition("ssh-sftp-subsystem")
                .unwrap()
                .is_writable()
        );
        // The managed permission/audit HostState items keep their write path.
        assert!(
            crate::baseline::definition("logging-auth-file-watches")
                .unwrap()
                .is_writable()
        );
    }

    #[test]
    fn auth_state_parsers_cover_values_comments_and_gaps() {
        use super::{dormant_observed, pwhist_observed, tmout_observed, wheel_observed};
        use crate::baseline::BaselineObservedValue::{Unverified, Value};
        let v = |s: &str| Value(s.to_owned());
        // Missing markers -> Unverified everywhere, never compliant.
        for f in [
            tmout_observed,
            pwhist_observed,
            wheel_observed,
            dormant_observed,
        ] {
            assert_eq!(
                f("GAP|x
"),
                Unverified
            );
        }
        // TMOUT: in range -> within-900; out of range -> the number; unset.
        assert_eq!(
            tmout_observed(
                "TMOUT|600
TMOUT_OK
"
            ),
            v("within-900")
        );
        assert_eq!(
            tmout_observed(
                "TMOUT|900
TMOUT_OK
"
            ),
            v("within-900")
        );
        assert_eq!(
            tmout_observed(
                "TMOUT|1
TMOUT_OK
"
            ),
            v("within-900")
        );
        assert_eq!(
            tmout_observed(
                "TMOUT|0
TMOUT_OK
"
            ),
            v("0")
        );
        assert_eq!(
            tmout_observed(
                "TMOUT|1200
TMOUT_OK
"
            ),
            v("1200")
        );
        assert_eq!(
            tmout_observed(
                "TMOUT|unset
TMOUT_OK
"
            ),
            v("unset")
        );
        // History: >=5 compliant; pwhistory.conf only counts when pam_pwhistory is referenced.
        assert_eq!(
            pwhist_observed(
                "PWHIST|pam:5
PWHIST_OK
"
            ),
            v("ge-5")
        );
        assert_eq!(
            pwhist_observed(
                "PWHIST|pam:3
PWHIST_OK
"
            ),
            v("3")
        );
        assert_eq!(
            pwhist_observed(
                "PWHIST|conf:10
PWHIST_OK
"
            ),
            v("unset")
        );
        assert_eq!(
            pwhist_observed(
                "PWHIST|uses-pwhistory
PWHIST|conf:6
PWHIST|pam:2
PWHIST_OK
"
            ),
            v("ge-5")
        );
        assert_eq!(
            pwhist_observed(
                "PWHIST_OK
"
            ),
            v("unset")
        );
        // Wheel: required/unset; no marker (file missing) -> Unverified.
        assert_eq!(
            wheel_observed(
                "WHEEL|required
WHEEL_OK
"
            ),
            v("required")
        );
        assert_eq!(
            wheel_observed(
                "WHEEL|unset
WHEEL_OK
"
            ),
            v("unset")
        );
        assert_eq!(
            wheel_observed(
                "WHEEL|unset
"
            ),
            Unverified
        );
        // Dormant: none; names; +N truncation stays inside the token alphabet.
        assert_eq!(
            dormant_observed(
                "DORMANT_N|0
DORMANT_OK
"
            ),
            v("none")
        );
        assert_eq!(
            dormant_observed(
                "DORMANT|olduser
DORMANT|www
DORMANT_N|2
DORMANT_OK
"
            ),
            v("olduser,www")
        );
        let many: String = (0..25)
            .map(|i| {
                format!(
                    "DORMANT|user{i:02}
"
                )
            })
            .collect();
        let observed = dormant_observed(&format!(
            "{many}DORMANT_N|25
DORMANT_OK
"
        ));
        match &observed {
            Value(label) => {
                assert!(label.len() <= 64, "{label}");
                assert!(label.ends_with(|c: char| c.is_ascii_digit()), "{label}");
                assert!(label.contains('+'), "{label}");
                assert!(
                    label.bytes().all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'_' | b'-' | b'.' | b':' | b'*' | b'/' | b',' | b'+')),
                    "{label}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    #[ignore = "needs disposable containers named in LOVELYHAWK_LAB_CONTAINERS"]
    fn auth_state_collectors_report_real_container_state() {
        let containers = std::env::var("LOVELYHAWK_LAB_CONTAINERS").expect("containers");
        let cli = std::env::var("LOVELYHAWK_LAB_CLI").unwrap_or_else(|_| "podman".to_owned());
        let exec = |container: &str, script: &str| -> String {
            let output = std::process::Command::new(&cli)
                .args(["exec", container, "/bin/sh", "-c", script])
                .output()
                .expect("container CLI");
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        let ids = [
            "session-idle-timeout",
            "password-history",
            "su-wheel-restriction",
            "dormant-login-accounts",
        ];
        let values = |output: &str| {
            let statuses = super::scan_from_output(output).unwrap();
            ids.iter()
                .map(|id| {
                    format!(
                        "{id}={:?}",
                        statuses.iter().find(|s| s.item_id == *id).unwrap().observed
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        let fixture = "cp -a /etc/pam.d/common-password /tmp/common-password.bak 2>/dev/null; cp -a /etc/pam.d/su /tmp/su.bak 2>/dev/null;             printf 'TMOUT=600
' > /etc/profile.d/lh-tmout.sh 2>/dev/null || true;             mkdir -p /etc/pam.d; printf 'password required pam_pwhistory.so remember=5
' > /etc/pam.d/common-password;             printf 'auth required pam_wheel.so use_uid
' > /etc/pam.d/su;             (useradd -m -s /bin/bash olduser 2>/dev/null || adduser -D -s /bin/bash olduser 2>/dev/null || true)";
        let restore = "[ -f /tmp/common-password.bak ] && cp -a /tmp/common-password.bak /etc/pam.d/common-password;             [ -f /tmp/su.bak ] && cp -a /tmp/su.bak /etc/pam.d/su || rm -f /etc/pam.d/su;             rm -f /etc/profile.d/lh-tmout.sh; (userdel -r olduser 2>/dev/null || deluser olduser 2>/dev/null || true)";
        let script = super::scan_script();
        let mut failures = Vec::new();
        for pair in containers.split(',') {
            let (name, container) = pair.split_once('=').expect("family=container");
            let before = values(&exec(container, &script));
            println!("== {name} defaults: {before}");
            exec(container, fixture);
            let after = values(&exec(container, &script));
            println!("== {name} fixtures: {after}");
            exec(container, restore);
            if name == "debian" && !after.contains("session-idle-timeout=Value(\"within-900\")") {
                failures.push(format!("{name}: TMOUT fixture not observed: {after}"));
            }
            if name == "debian" && !after.contains("password-history=Value(\"ge-5\")") {
                failures.push(format!("{name}: pwhistory fixture not observed: {after}"));
            }
            if name == "debian" && !after.contains("su-wheel-restriction=Value(\"required\")") {
                failures.push(format!("{name}: wheel fixture not observed: {after}"));
            }
            if name == "debian" && !after.contains("olduser") {
                failures.push(format!("{name}: dormant fixture not observed: {after}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{}",
            failures.join(
                "
"
            )
        );
    }

    #[test]
    fn sudolog_observation_maps_markers() {
        use BaselineObservedValue::{Unverified, Value};
        assert_eq!(sudolog_observed("GAP|sudolog"), Unverified);
        assert_eq!(
            sudolog_observed(
                "SUDOLOG|enabled
SUDOLOG_OK"
            ),
            Value("enabled".to_owned())
        );
        assert_eq!(
            sudolog_observed(
                "SUDOLOG|syslog-only
SUDOLOG_OK"
            ),
            Value("syslog-only".to_owned())
        );
        assert_eq!(
            sudolog_observed(
                "SUDOLOG|unset
SUDOLOG_OK"
            ),
            Value("unset".to_owned())
        );
        assert_eq!(sudolog_observed("SUDOLOG|enabled"), Unverified);
    }

    #[test]
    fn apache_observation_maps_markers() {
        use BaselineObservedValue::{NotInstalled, Unverified, Value};
        let v = |s: &str| Value(s.to_owned());
        assert_eq!(
            apache_observed("apache-options-indexes", "APACHE|ABSENT"),
            NotInstalled
        );
        assert_eq!(
            apache_observed("apache-options-indexes", "noise"),
            Unverified
        );
        let base = "APACHE|indexes|on\nAPACHE|status|exposed\nAPACHE|usr|www-data\nAPACHE|worker0|1\nAPACHE|tmo|600\nAPACHE|mods|autoindex,dav\nAPACHE_OK";
        assert_eq!(apache_observed("apache-options-indexes", base), v("on"));
        assert_eq!(apache_observed("apache-status-info", base), v("exposed"));
        assert_eq!(apache_observed("apache-run-user", base), v("root-worker"));
        assert_eq!(apache_observed("apache-timeout", base), v("600"));
        assert_eq!(
            apache_observed("apache-modules-minimal", base),
            v("autoindex,dav")
        );
        let ok = "APACHE|indexes|off\nAPACHE|status|restricted\nAPACHE|usr|www-data\nAPACHE|lrb|set\nAPACHE|mods|none\nAPACHE_OK";
        assert_eq!(apache_observed("apache-options-indexes", ok), v("off"));
        assert_eq!(apache_observed("apache-status-info", ok), v("off"));
        assert_eq!(apache_observed("apache-run-user", ok), v("non-root"));
        assert_eq!(apache_observed("apache-timeout", ok), v("within-300"));
        assert_eq!(
            apache_observed("apache-limit-request-body", ok),
            v("configured")
        );
        assert_eq!(apache_observed("apache-modules-minimal", ok), v("none"));
    }

    #[test]
    fn tomcat_observation_maps_markers() {
        use BaselineObservedValue::{NotInstalled, Unverified, Value};
        let v = |s: &str| Value(s.to_owned());
        assert_eq!(
            tomcat_observed("tomcat-manager-access", "TOMCAT|ABSENT"),
            NotInstalled
        );
        assert_eq!(
            tomcat_observed("tomcat-manager-access", "noise"),
            Unverified
        );
        let base = "TOMCAT|mgr|exposed\nTOMCAT|ajp|open\nTOMCAT|usr|root\nTOMCAT|lst|true\nTOMCAT|ses|60\nTOMCAT_OK";
        assert_eq!(tomcat_observed("tomcat-manager-access", base), v("exposed"));
        assert_eq!(tomcat_observed("tomcat-ajp-secret", base), v("open"));
        assert_eq!(tomcat_observed("tomcat-run-user", base), v("root"));
        assert_eq!(tomcat_observed("tomcat-listings-off", base), v("true"));
        assert_eq!(tomcat_observed("tomcat-session-timeout", base), v("60"));
        let ok = "TOMCAT|mgr|safe\nTOMCAT|ajp|secured\nTOMCAT|usr|non-root\nTOMCAT|lst|false\nTOMCAT|ses|30\nTOMCAT_OK";
        assert_eq!(tomcat_observed("tomcat-manager-access", ok), v("safe"));
        assert_eq!(tomcat_observed("tomcat-ajp-secret", ok), v("secured"));
        assert_eq!(tomcat_observed("tomcat-run-user", ok), v("non-root"));
        assert_eq!(tomcat_observed("tomcat-listings-off", ok), v("false"));
        assert_eq!(
            tomcat_observed("tomcat-session-timeout", ok),
            v("within-30")
        );
        let gap = "TOMCAT|mgr|safe\nTOMCAT|ajp|unverified\nTOMCAT|usr|unknown\nTOMCAT_OK";
        assert_eq!(tomcat_observed("tomcat-ajp-secret", gap), Unverified);
        assert_eq!(tomcat_observed("tomcat-run-user", gap), Unverified);
        // An unreadable deployment channel is a gap, never a pass.
        let blind =
            "TOMCAT|mgr|unverified\nTOMCAT|lst|unverified\nTOMCAT|ses|unverified\nTOMCAT_OK";
        assert_eq!(tomcat_observed("tomcat-manager-access", blind), Unverified);
        assert_eq!(tomcat_observed("tomcat-listings-off", blind), Unverified);
        assert_eq!(tomcat_observed("tomcat-session-timeout", blind), Unverified);
    }

    #[test]
    fn sftp_guard_parses_and_refuses_present() {
        let attrs = "600:0:0:2049:19:1";
        let digest = "a".repeat(64);
        let guard = parse_sftp(
            &format!("SFTP|absent|{attrs}|{digest}"),
            "/etc/ssh/sshd_config",
        )
        .unwrap();
        let def = crate::baseline::BASELINE_CATALOG
            .iter()
            .find(|d| d.id == "ssh-sftp-subsystem")
            .unwrap();
        guard.validate(def).unwrap();
        let present = parse_sftp(
            &format!("SFTP|present|{attrs}|{digest}"),
            "/etc/ssh/sshd_config",
        )
        .unwrap();
        assert!(present.validate(def).is_err());
        assert!(parse_sftp("garbage", "/etc/ssh/sshd_config").is_err());
        assert!(parse_sftp("SFTP|absent|x|y", "/etc/ssh/sshd_config").is_err());
    }
}
