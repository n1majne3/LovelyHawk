use super::*;
use crate::database::{DatabaseConnection, DatabaseEngine};
use crate::postgresql_native::{PostgresqlTlsMode, PostgresqlTlsSettings};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const CANARY: &str = "SecretCanary中123!";

fn connection(host: &str) -> DatabaseConnection {
    DatabaseConnection {
        engine: DatabaseEngine::Postgresql,
        host: host.to_owned(),
        port: 5432,
        username: Some("postgres".to_owned()),
        database: Some("postgres".to_owned()),
    }
}

fn request() -> NativeRuntimeRequest {
    NativeRuntimeRequest::new(
        connection("127.0.0.1"),
        PostgresqlTlsSettings {
            mode: PostgresqlTlsMode::SshLoopback,
            ca_certificate_pem: None,
        },
        Some(SecretValue::new(CANARY)),
    )
    .unwrap()
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

struct RowSpec {
    params: &'static [u32],
    columns: &'static [(&'static str, u32)],
    rows: &'static [&'static [Option<&'static str>]],
}

struct QuerySpec {
    /// Substring of the statement SQL this response answers.
    sql: &'static str,
    spec: RowSpec,
}

/// Minimal fake server: startup + extended protocol + simple query. All
/// statement text is captured so tests can assert exactly what was sent.
struct FakeServer {
    queries: Vec<String>,
    tables: HashMap<String, &'static RowSpec>,
    statements: HashMap<String, (&'static RowSpec, String)>,
    portals: HashMap<String, &'static RowSpec>,
    options: String,
}

impl FakeServer {
    fn lookup(tables: &HashMap<String, &'static RowSpec>, sql: &str) -> Option<&'static RowSpec> {
        tables
            .iter()
            .find(|(needle, _)| sql.contains(needle.as_str()))
            .map(|(_, spec)| *spec)
    }

    async fn message(&mut self, server: &mut DuplexStream, tag: u8, body: &[u8]) {
        match tag {
            b'P' => {
                let nul = body.iter().position(|b| *b == 0).unwrap();
                let name = std::str::from_utf8(&body[..nul]).unwrap().to_owned();
                let rest = &body[nul + 1..];
                let nul = rest.iter().position(|b| *b == 0).unwrap();
                let sql = std::str::from_utf8(&rest[..nul]).unwrap().to_owned();
                self.queries.push(sql.clone());
                self.statements.insert(
                    name,
                    (
                        Self::lookup(&self.tables, &sql).expect("scripted query response"),
                        sql,
                    ),
                );
                server.write_all(&frame(b'1', &[])).await.unwrap();
            }
            b'B' => {
                let nul = body.iter().position(|b| *b == 0).unwrap();
                let portal = std::str::from_utf8(&body[..nul]).unwrap().to_owned();
                let rest = &body[nul + 1..];
                let nul = rest.iter().position(|b| *b == 0).unwrap();
                let statement = std::str::from_utf8(&rest[..nul]).unwrap();
                self.portals.insert(
                    portal,
                    self.statements.get(statement).expect("bound statement").0,
                );
                server.write_all(&frame(b'2', &[])).await.unwrap();
            }
            b'D' => match body[0] {
                b'S' => {
                    let name = std::str::from_utf8(&body[1..body.len() - 1]).unwrap();
                    let (spec, _) = self.statements.get(name).expect("described statement");
                    let mut params = (spec.params.len() as i16).to_be_bytes().to_vec();
                    for oid in spec.params {
                        params.extend_from_slice(&oid.to_be_bytes());
                    }
                    server.write_all(&frame(b't', &params)).await.unwrap();
                    server
                        .write_all(&frame(b'T', &Self::description(spec)))
                        .await
                        .unwrap();
                }
                b'P' => {
                    let name = std::str::from_utf8(&body[1..body.len() - 1]).unwrap();
                    let spec = self.portals.get(name).expect("described portal");
                    server
                        .write_all(&frame(b'T', &Self::description(spec)))
                        .await
                        .unwrap();
                }
                _ => panic!("unexpected describe kind"),
            },
            b'E' => {
                let nul = body.iter().position(|b| *b == 0).unwrap();
                let name = std::str::from_utf8(&body[..nul]).unwrap();
                let spec = self.portals.get(name).expect("executed portal");
                let mut output = Vec::new();
                for row in spec.rows {
                    let mut data = (row.len() as i16).to_be_bytes().to_vec();
                    for (cell, (_, type_oid)) in row.iter().zip(spec.columns.iter()) {
                        match cell {
                            Some(value) => {
                                // The driver binds binary results; encode the
                                // few types these scripted queries produce.
                                let bytes: Vec<u8> = match type_oid {
                                    16 => vec![u8::from(*value == "t")],
                                    26 => value.parse::<u32>().unwrap().to_be_bytes().to_vec(),
                                    _ => value.as_bytes().to_vec(),
                                };
                                data.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                                data.extend_from_slice(&bytes);
                            }
                            None => data.extend_from_slice(&(-1_i32).to_be_bytes()),
                        }
                    }
                    output.extend_from_slice(&frame(b'D', &data));
                }
                output.extend_from_slice(&frame(b'C', b"SELECT 1\0"));
                server.write_all(&output).await.unwrap();
            }
            b'Q' => {
                let sql = std::str::from_utf8(&body[..body.len() - 1])
                    .unwrap()
                    .to_owned();
                self.queries.push(sql.clone());
                let tag = sql.split_whitespace().next().unwrap_or("OK");
                let complete = format!("{tag}\0");
                server
                    .write_all(&frame(b'C', complete.as_bytes()))
                    .await
                    .unwrap();
                server.write_all(&frame(b'Z', b"I")).await.unwrap();
            }
            b'C' => {
                server.write_all(&frame(b'3', &[])).await.unwrap();
            }
            b'H' => {}
            b'S' => {
                server.write_all(&frame(b'Z', b"I")).await.unwrap();
            }
            b'X' => {}
            other => panic!("unexpected client message {other}"),
        }
    }

    fn description(spec: &RowSpec) -> Vec<u8> {
        let mut body = (spec.columns.len() as i16).to_be_bytes().to_vec();
        for (name, type_oid) in spec.columns {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(&0_i32.to_be_bytes());
            body.extend_from_slice(&0_i16.to_be_bytes());
            body.extend_from_slice(&type_oid.to_be_bytes());
            body.extend_from_slice(&(-1_i16).to_be_bytes());
            body.extend_from_slice(&(-1_i32).to_be_bytes());
            body.extend_from_slice(&1_i16.to_be_bytes());
        }
        body
    }
}

async fn run_fake_server(
    mut server: DuplexStream,
    expected_options: &str,
    forbidden_options: &str,
    auth_error: Option<&'static str>,
    queries: Vec<QuerySpec>,
) -> (Vec<String>, String) {
    let length = server.read_u32().await.unwrap() as usize;
    assert!((8..4096).contains(&length));
    let mut bytes = vec![0_u8; length - 4];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..4], &196608_u32.to_be_bytes());
    let options = std::str::from_utf8(&bytes[4..]).unwrap().to_owned();
    assert!(options.contains(expected_options), "options: {options}");
    assert!(!options.contains(forbidden_options), "options: {options}");
    assert!(!options.contains(CANARY));
    if let Some(code) = auth_error {
        let body = format!("SFATAL\0C{code}\0M{CANARY}\0\0");
        server
            .write_all(&frame(b'E', body.as_bytes()))
            .await
            .unwrap();
        let mut rest = Vec::new();
        let _ = server.read_to_end(&mut rest).await;
        return (Vec::new(), options);
    }
    server
        .write_all(&frame(b'R', &0_u32.to_be_bytes()))
        .await
        .unwrap();
    server
        .write_all(&frame(
            b'K',
            &[12345_i32.to_be_bytes(), 6789_i32.to_be_bytes()].concat(),
        ))
        .await
        .unwrap();
    server.write_all(&frame(b'Z', b"I")).await.unwrap();
    let mut fake = FakeServer {
        queries: Vec::new(),
        tables: queries
            .into_iter()
            .map(|query| {
                (
                    query.sql.to_owned(),
                    Box::leak(Box::new(query.spec)) as &'static RowSpec,
                )
            })
            .collect(),
        statements: HashMap::new(),
        portals: HashMap::new(),
        options,
    };
    while let Ok(tag) = server.read_u8().await {
        let length = server.read_u32().await.unwrap() as usize;
        assert!((4..65536).contains(&length));
        let mut body = vec![0_u8; length - 4];
        server.read_exact(&mut body).await.unwrap();
        if tag == b'X' {
            break;
        }
        fake.message(&mut server, tag, &body).await;
    }
    (fake.queries, fake.options)
}

const INSPECT_SETTINGS: QuerySpec = QuerySpec {
    sql: "current_setting('server_version_num')",
    spec: RowSpec {
        params: &[],
        columns: &[("current_setting", 25), ("current_setting", 25)],
        rows: &[&[Some("160000"), Some("scram-sha-256")]],
    },
};

const INSPECT_CONNECTING: QuerySpec = QuerySpec {
    sql: "WHERE rolname = current_user",
    spec: RowSpec {
        params: &[],
        columns: &[("oid", 25), ("rolsuper", 16)],
        rows: &[&[Some("10"), Some("t")]],
    },
};

fn inspect_target_query(oid: u32, name: &'static str) -> QuerySpec {
    QuerySpec {
        sql: "WHERE oid = $1",
        spec: RowSpec {
            params: &[26],
            columns: &[
                ("oid", 25),
                ("rolname", 25),
                ("rolcanlogin", 16),
                ("rolsuper", 16),
                ("rolreplication", 16),
            ],
            rows: Box::leak(Box::new([Box::leak(Box::new([
                Some(match oid {
                    10 => "10",
                    _ => "16384",
                }),
                Some(name),
                Some("t"),
                Some("f"),
                Some("f"),
            ]))
                as &'static [Option<&'static str>]])),
        },
    }
}

const ROLE_CHECK: QuerySpec = QuerySpec {
    sql: "SELECT rolname::text, rolcanlogin FROM",
    spec: RowSpec {
        params: &[26],
        columns: &[("rolname", 25), ("rolcanlogin", 16)],
        rows: &[&[Some("app"), Some("t")]],
    },
};

const AUTHID: QuerySpec = QuerySpec {
    sql: "FROM pg_catalog.pg_authid",
    spec: RowSpec {
        params: &[26],
        columns: &[("rolpassword", 25)],
        rows: &[&[Some("SCRAM-SHA-256$4096:c2FsdA==$old:verifier")]],
    },
};

const CURRENT_USER_APP: QuerySpec = QuerySpec {
    sql: "SELECT current_user",
    spec: RowSpec {
        params: &[],
        columns: &[("current_user", 25)],
        rows: &[&[Some("app")]],
    },
};

async fn drive(
    step: PostgresqlPasswordStep,
    expected_options: &str,
    forbidden_options: &str,
    auth_error: Option<&'static str>,
    queries: Vec<QuerySpec>,
) -> (CoreResult<PostgresqlPasswordResult>, Vec<String>) {
    let (client, server) = tokio::io::duplex(16384);
    let peer = run_fake_server(
        server,
        expected_options,
        forbidden_options,
        auth_error,
        queries,
    );
    let (result, (sent, _)) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(run_step_on_stream(client, step), peer)
    })
    .await
    .expect("fake server timed out");
    (result, sent)
}

#[tokio::test]
async fn apply_uses_write_options_and_sends_only_the_verifier() {
    let verifier = postgres_protocol::password::scram_sha_256(CANARY.as_bytes());
    assert!(verifier.starts_with("SCRAM-SHA-256$"));
    let (result, sent) = drive(
        PostgresqlPasswordStep::Apply {
            request: request(),
            role_oid: 16384,
            role_name: "app".to_owned(),
            capture_old: true,
            verifier: Zeroizing::new(verifier.clone()),
        },
        "-c statement_timeout=20000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog",
        "default_transaction_read_only",
        None,
        vec![ROLE_CHECK, AUTHID],
    )
    .await;
    let PostgresqlPasswordResult::Applied { old_verifier } = result.unwrap() else {
        panic!("apply did not succeed");
    };
    assert_eq!(
        old_verifier.as_deref(),
        Some("SCRAM-SHA-256$4096:c2FsdA==$old:verifier")
    );
    let begin = sent.iter().position(|q| q == "BEGIN").unwrap();
    let role_check = sent
        .iter()
        .position(|q| q.starts_with("SELECT rolname"))
        .unwrap();
    let authid = sent.iter().position(|q| q.contains("pg_authid")).unwrap();
    let alter = sent
        .iter()
        .position(|q| q.starts_with("ALTER ROLE"))
        .unwrap();
    let commit = sent.iter().position(|q| q == "COMMIT").unwrap();
    assert!(begin < role_check && role_check < authid && authid < alter && alter < commit);
    let alter_sql = &sent[alter];
    assert!(alter_sql.contains(&verifier));
    assert!(!alter_sql.contains(CANARY));
    assert!(sent.iter().all(|query| !query.contains(CANARY)));
}

#[tokio::test]
async fn role_mismatch_at_apply_sends_no_alter() {
    let mismatch = QuerySpec {
        sql: "SELECT rolname::text, rolcanlogin FROM",
        spec: RowSpec {
            params: &[26],
            columns: &[("rolname", 25), ("rolcanlogin", 16)],
            rows: &[&[Some("other"), Some("t")]],
        },
    };
    let (result, sent) = drive(
        PostgresqlPasswordStep::Apply {
            request: request(),
            role_oid: 16384,
            role_name: "app".to_owned(),
            capture_old: false,
            verifier: Zeroizing::new("SCRAM-SHA-256$4096:c2FsdA==$v:w".to_owned()),
        },
        "search_path=pg_catalog",
        "default_transaction_read_only",
        None,
        vec![mismatch],
    )
    .await;
    let error = result.unwrap_err().to_string();
    assert!(error.contains("已变化"), "unexpected error: {error}");
    assert!(!sent.iter().any(|query| query.starts_with("ALTER ROLE")));
    assert!(sent.iter().any(|query| query == "ROLLBACK"));
}

#[tokio::test]
async fn inspect_reports_roles_and_login_verify_classifies() {
    let (result, _) = drive(
        PostgresqlPasswordStep::Inspect {
            request: request(),
            role: InspectTarget::Oid(16384),
        },
        "-c default_transaction_read_only=on -c statement_timeout=20000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog",
        "LovelyHawk password change",
        None,
        vec![INSPECT_SETTINGS, INSPECT_CONNECTING, inspect_target_query(16384, "app")],
    )
    .await;
    let PostgresqlPasswordResult::Inspected(inspected) = result.unwrap() else {
        panic!("inspect did not succeed");
    };
    assert_eq!(inspected.server_version_num, 160000);
    assert_eq!(inspected.password_encryption, "scram-sha-256");
    assert_eq!(inspected.target_name, "app");
    assert!(inspected.connecting_superuser);
    assert!(inspected.target_can_login);
    assert!(!inspected.target_superuser);

    for (auth_error, expected) in [
        (None, PostgresqlPasswordVerification::Passed),
        (Some("28P01"), PostgresqlPasswordVerification::Rejected),
        (
            Some("28000"),
            PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::AccessRule),
        ),
    ] {
        let (result, _) = drive(
            PostgresqlPasswordStep::VerifyLogin {
                request: request()
                    .for_user("app", Some(SecretValue::new(CANARY)))
                    .unwrap(),
                expected_user: "app".to_owned(),
            },
            "default_transaction_read_only=on",
            "LovelyHawk password change",
            auth_error,
            vec![CURRENT_USER_APP],
        )
        .await;
        let PostgresqlPasswordResult::VerifiedLogin(actual) = result.unwrap() else {
            panic!("verify login did not classify");
        };
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn restore_and_read_back_round_trip_the_old_verifier() {
    let role_check = QuerySpec {
        sql: "SELECT rolname::text FROM",
        spec: RowSpec {
            params: &[26],
            columns: &[("rolname", 25)],
            rows: &[&[Some("app")]],
        },
    };
    let (result, sent) = drive(
        PostgresqlPasswordStep::Restore {
            request: request(),
            role_oid: 16384,
            role_name: "app".to_owned(),
            old_verifier: Zeroizing::new(Some("md5oldverifier".to_owned())),
        },
        "search_path=pg_catalog",
        "default_transaction_read_only",
        None,
        vec![role_check, AUTHID],
    )
    .await;
    let PostgresqlPasswordResult::Restored { verifier } = result.unwrap() else {
        panic!("restore failed");
    };
    assert_eq!(
        verifier
            .expect("restore read-back must run on the restore connection")
            .as_deref(),
        Some("SCRAM-SHA-256$4096:c2FsdA==$old:verifier")
    );
    assert!(
        sent.iter()
            .any(|query| query == "ALTER ROLE \"app\" PASSWORD 'md5oldverifier'")
    );

    let (result, _) = drive(
        PostgresqlPasswordStep::ReadVerifier {
            request: request(),
            role_oid: 16384,
        },
        "default_transaction_read_only=on",
        "LovelyHawk password change",
        None,
        vec![AUTHID],
    )
    .await;
    let PostgresqlPasswordResult::Verifier(verifier) = result.unwrap() else {
        panic!("read verifier failed");
    };
    assert_eq!(
        verifier.as_deref(),
        Some("SCRAM-SHA-256$4096:c2FsdA==$old:verifier")
    );
}

#[test]
fn quoting_rules_cover_edge_characters() {
    assert_eq!(quote_ident("app").unwrap(), "\"app\"");
    assert_eq!(quote_ident("a\"b").unwrap(), "\"a\"\"b\"");
    assert_eq!(quote_ident("back\\slash").unwrap(), "\"back\\slash\"");
    assert_eq!(quote_ident("角色中").unwrap(), "\"角色中\"");
    assert!(quote_ident("a\0b").is_err());
    assert!(quote_ident("").is_err());
    assert_eq!(quote_literal("v").unwrap(), "'v'");
    assert_eq!(quote_literal("a'b").unwrap(), "'a''b'");
    assert!(quote_literal("a\0b").is_err());
}

#[test]
fn password_rules_enforce_the_closed_policy() {
    assert!(validate_new_password(&SecretValue::new("Aa1!bcdefghij")).is_ok());
    for (password, reason) in [
        ("Aa1!bcdefg", "too short: 11 bytes"),
        ("aaaaaaaaaaaaa", "one class"),
        ("Aaaaaaaaaaaaa", "two classes"),
        ("Aa1\0bcdefghij", "NUL"),
        ("Aa1\u{0007}bcdefghij", "control"),
        ("Aa1!中文中文字符", "utf8 ok"),
    ] {
        let result = validate_new_password(&SecretValue::new(password));
        if reason == "utf8 ok" {
            assert!(result.is_ok(), "{reason}");
        } else {
            assert!(result.is_err(), "{reason}");
        }
    }
    let long = "Aa1!".repeat(300);
    assert!(validate_new_password(&SecretValue::new(long)).is_err());
    assert!(validate_password_against_role(&SecretValue::new("Aa1!App_xyz_1234"), "app").is_err());
    assert!(validate_password_against_role(&SecretValue::new("Aa1!bcdefghij"), "app").is_ok());
}

#[test]
fn debug_and_public_views_never_expose_secrets_or_verifiers() {
    let token = DatabasePasswordRestoreToken {
        role_oid: 16384,
        role_name: "app".to_owned(),
        old_verifier: Zeroizing::new(Some(format!("SCRAM-{CANARY}"))),
        profile_id: "profile-a".to_owned(),
        target: crate::target::TargetGuard {
            identity: crate::target::TargetIdentity::new("host-a").unwrap(),
            generation: 1,
        },
        saved_password_updated: false,
        connect_password: Some(SecretValue::new(CANARY)),
        previous_saved_password: Some(SecretValue::new(CANARY)),
        created: Instant::now(),
        claimed: AtomicBool::new(false),
    };
    let debug = format!("{token:?}");
    assert!(!debug.contains(CANARY));
    assert!(debug.contains("app"));

    let outcome = DatabasePasswordOutcome {
        operation_id: "op".to_owned(),
        verification: PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::Timeout),
        saved_password: SavedPasswordUpdate::SkippedVerificationNotPassed,
        restorable: true,
        journal_recorded: false,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    assert!(!json.contains(CANARY));

    // The shared contract validates exact camelCase keys; a snake_case view
    // was silently rejected by the page while the backend reported success.
    let view = DatabasePasswordPlanView {
        role_name: "app".to_owned(),
        is_connection_role: true,
        superuser: false,
        replication: false,
        format: PostgresqlPasswordFormat::ScramSha256,
        restorable: true,
        updates_saved_password: true,
        warnings: vec![PostgresqlPasswordWarning::ConnectionRole],
    };
    let value = serde_json::to_value(&view).unwrap();
    for key in [
        "roleName",
        "isConnectionRole",
        "updatesSavedPassword",
        "restorable",
        "warnings",
    ] {
        assert!(value.get(key).is_some(), "{key}");
    }
    assert_eq!(value["format"], "scram-sha-256");
    assert_eq!(value["warnings"], serde_json::json!(["connection-role"]));
    let restore_view = DatabasePasswordRestorePlanView {
        role_name: "app".to_owned(),
        saved_password_was_updated: true,
    };
    assert!(
        serde_json::to_value(&restore_view)
            .unwrap()
            .get("savedPasswordWasUpdated")
            .is_some()
    );

    let step = PostgresqlPasswordStep::Restore {
        request: request(),
        role_oid: 1,
        role_name: "app".to_owned(),
        old_verifier: Zeroizing::new(Some(CANARY.to_owned())),
    };
    assert!(!format!("{step:?}").contains(CANARY));
    let secret = SecretValue::new(CANARY);
    assert!(!format!("{secret:?}").contains(CANARY));
}

#[test]
fn encryption_aliases_md5_on_only_before_pg14() {
    assert_eq!(
        parse_encryption("scram-sha-256", 160000).unwrap(),
        PostgresqlPasswordFormat::ScramSha256
    );
    for version in [100_000, 120_000, 139_999] {
        assert_eq!(
            parse_encryption("on", version).unwrap(),
            PostgresqlPasswordFormat::Md5,
            "version {version}"
        );
    }
    for (value, version) in [
        ("on", 140_000),
        ("on", 160_000),
        ("off", 130_000),
        ("scram", 160_000),
    ] {
        assert!(
            parse_encryption(value, version).is_err(),
            "{value}@{version}"
        );
    }
}

#[test]
fn write_step_transport_failures_report_unknown_state() {
    let ssh_error = write_step_error(CoreError::ssh(
        "PostgreSQL password step",
        "operation timed out",
    ));
    assert!(ssh_error.to_string().contains("可能已经改变"));
    let cancelled = write_step_error(CoreError::OperationCancelled {
        operation_id: "op".to_owned(),
    });
    assert!(cancelled.to_string().contains("可能已经改变"));
    let step_error = write_step_error(invalid("目标角色在修改前已变化，未执行口令修改"));
    assert!(step_error.to_string().contains("未执行口令修改"));
    let binding = write_step_error(CoreError::validation(
        "PostgreSQL SSH session binding",
        "session does not belong to the expected connection",
    ));
    assert!(binding.to_string().contains("expected connection"));
    assert!(!binding.to_string().contains("可能已经改变"));
}

#[test]
fn restore_plan_debug_never_exposes_secrets() {
    let plan = DatabasePasswordRestorePlan {
        operation: OperationPlan::new(
            crate::target::TargetGuard {
                identity: crate::target::TargetIdentity::new("host-a").unwrap(),
                generation: 1,
            },
            "restore summary",
            true,
            None,
        )
        .unwrap(),
        profile_id: "p".to_owned(),
        profile_digest: "d".to_owned(),
        snapshot: DatabaseProfileSnapshot::test_fixture(),
        role_oid: 1,
        role_name: "app".to_owned(),
        old_verifier: Zeroizing::new(Some(format!("SCRAM-{CANARY}"))),
        connect_password: Some(SecretValue::new(CANARY)),
        previous_saved_password: Some(SecretValue::new(CANARY)),
        saved_password_updated: true,
        view: DatabasePasswordRestorePlanView {
            role_name: "app".to_owned(),
            saved_password_was_updated: true,
        },
    };
    let debug = format!("{plan:?}");
    assert!(!debug.contains(CANARY));
    let json = serde_json::to_string(&DatabasePasswordRestoreOutcome {
        operation_id: "op".to_owned(),
        verification: PostgresqlRestoreVerification::Passed,
        saved_password: SavedPasswordRestore::Restored,
        journal_recorded: true,
    })
    .unwrap();
    assert!(!json.contains(CANARY));
}

#[test]
fn restore_token_single_use_and_expiry() {
    let make = |created: Instant| DatabasePasswordRestoreToken {
        role_oid: 1,
        role_name: "app".to_owned(),
        old_verifier: Zeroizing::new(None),
        profile_id: "p".to_owned(),
        target: crate::target::TargetGuard {
            identity: crate::target::TargetIdentity::new("host-a").unwrap(),
            generation: 1,
        },
        saved_password_updated: false,
        connect_password: None,
        previous_saved_password: None,
        created,
        claimed: AtomicBool::new(false),
    };
    let fresh = make(Instant::now());
    assert!(!fresh.expired());
    assert!(!fresh.claimed.swap(true, Ordering::SeqCst));
    assert!(fresh.claimed.swap(true, Ordering::SeqCst));
    let stale = make(Instant::now() - RESTORE_TOKEN_TTL - Duration::from_secs(1));
    assert!(stale.expired());
}

#[test]
fn constant_time_compare_and_detail_codes() {
    let a = Some("md5x".to_owned());
    assert!(constant_time_eq(&a, &Some("md5x".to_owned())));
    assert!(!constant_time_eq(&a, &Some("md5y".to_owned())));
    assert!(!constant_time_eq(&a, &Some("md5".to_owned())));
    assert!(constant_time_eq(&None, &None));
    assert!(!constant_time_eq(&a, &None));
    assert_eq!(
        PostgresqlPasswordVerification::Unverifiable(PostgresqlVerifyBlock::AccessRule).detail(),
        "verification:unverifiable:access-rule"
    );
}
