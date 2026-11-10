//! Invoked only by the owned WSL/Docker PostgreSQL password-change probe.
use super::*;
use crate::{
    BackendServices,
    database::{DatabaseProfileChanges, DatabaseProfileConfig, DatabaseSecretChange},
    postgresql_native::{PostgresqlTlsMode, PostgresqlTlsSettings},
    ssh::{BoundSshSession, HostKeyConfirmations},
    store::PortableStore,
    target::TargetIdentity,
};
use uuid::Uuid;

const NEW_PASSWORD: &str = "Lab'\"New中#2026z";
const NEW_PASSWORD_B: &str = "Lab'\"New中#2026y";
const OLD_SUPER: &str = "Lab'\"Sup中#2026a";
const OLD_OTHER: &str = "Lab'\"Oth中#2026b";
const OLD_CROLE: &str = "Lab'\"Cro中#2026c";

fn check(label: &str) {
    println!("POSTGRESQL_PASSWORD_CHECK {label}");
}

async fn command(services: &BackendServices, session: &BoundSshSession, command: &str) -> String {
    let output = services
        .ssh()
        .execute_bound(session, command.to_owned(), Duration::from_secs(20))
        .await
        .unwrap();
    assert!(!output.timed_out);
    assert_eq!(output.exit_code, Some(0), "owned fixture command failed");
    output.output.trim().to_owned()
}

async fn sql(services: &BackendServices, session: &BoundSshSession, query: &str) -> String {
    command(
        services,
        session,
        &format!(
            "runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres -c '{}'",
            query.replace('\'', "'\\''")
        ),
    )
    .await
}

async fn role_oid(services: &BackendServices, session: &BoundSshSession, name: &str) -> u32 {
    sql(
        services,
        session,
        &format!("SELECT oid FROM pg_roles WHERE rolname = '{name}'"),
    )
    .await
    .parse()
    .unwrap()
}

async fn verifier_kind(
    services: &BackendServices,
    session: &BoundSshSession,
    name: &str,
) -> String {
    sql(
        services,
        session,
        &format!(
            "SELECT CASE WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram' WHEN rolpassword LIKE 'md5%' THEN 'md5' ELSE 'other' END FROM pg_authid WHERE rolname = '{name}'"
        ),
    )
    .await
}

async fn password_works(
    services: &BackendServices,
    session: &BoundSshSession,
    username: &str,
    password: &str,
) -> bool {
    let probe = loopback_profile("probe", username);
    let snapshot = save_profile(services, &probe, password);
    services
        .database()
        .plan_postgresql_password(
            session,
            &snapshot,
            PostgresqlPasswordRole::Current,
            SecretValue::new("Aa1!placeholder99"),
            false,
        )
        .await
        .is_ok()
}

async fn bind(services: &BackendServices, id: &str) -> BoundSshSession {
    let status = services
        .ssh()
        .connect(id, HostKeyConfirmations::default())
        .await
        .unwrap();
    let guard = services
        .activate_target(TargetIdentity::new(id).unwrap())
        .unwrap();
    services
        .bind_active_ssh_session(&guard, &status.session_id)
        .await
        .unwrap()
}

fn save_profile(
    services: &BackendServices,
    profile: &DatabaseProfileConfig,
    password: &str,
) -> DatabaseProfileSnapshot {
    services
        .database()
        .upsert_profile(
            profile.clone(),
            DatabaseProfileChanges {
                password: DatabaseSecretChange::Replace(SecretValue::new(password)),
            },
        )
        .unwrap();
    services
        .database()
        .profile_snapshots()
        .unwrap()
        .into_iter()
        .find(|snapshot| snapshot.view().config.id == profile.id)
        .unwrap()
}

fn loopback_profile(name: &str, username: &str) -> DatabaseProfileConfig {
    let mut profile = DatabaseProfileConfig::new(name, DatabaseEngine::Postgresql);
    profile.connection.host = "127.0.0.1".to_owned();
    profile.connection.port = 5432;
    profile.connection.database = Some("postgres".to_owned());
    profile.connection.username = Some(username.to_owned());
    profile.postgresql_tls = Some(PostgresqlTlsSettings {
        mode: PostgresqlTlsMode::SshLoopback,
        ca_certificate_pem: None,
    });
    profile
}

#[tokio::test]
#[ignore = "requires tools/lab/probe-postgresql-password.mjs and its uniquely owned disposable target"]
async fn owned_postgresql_password_change() {
    let root = std::env::var("LOVELYHAWK_PG_PASSWORD_ROOT").expect("owned fixture data root");
    let run = std::env::var("LOVELYHAWK_PG_PASSWORD_RUN").expect("owned fixture UUID");
    assert!(Uuid::parse_str(&run).is_ok());
    let services = BackendServices::new(PortableStore::prepare(root.into()).unwrap()).unwrap();
    let session = bind(&services, &run).await;
    assert_eq!(
        command(&services, &session, "cat /tmp/lovelyres-pg-password-run").await,
        run
    );
    let journal = services.operation_journal();

    // (a) scram-sha-256: a superuser connection changes its own password.
    let super_profile = loopback_profile("owned superuser", "lr_super");
    let snapshot = save_profile(&services, &super_profile, OLD_SUPER);
    let plan = services
        .database()
        .plan_postgresql_password(
            &session,
            &snapshot,
            PostgresqlPasswordRole::Current,
            SecretValue::new(NEW_PASSWORD),
            true,
        )
        .await
        .unwrap();
    let view = plan.view().clone();
    assert_eq!(view.role_name, "lr_super");
    assert!(view.is_connection_role && view.restorable && view.updates_saved_password);
    assert!(view.superuser);
    assert_eq!(view.format, PostgresqlPasswordFormat::ScramSha256);
    assert!(
        view.warnings
            .contains(&PostgresqlPasswordWarning::SuperuserRole)
    );
    assert!(
        view.warnings
            .contains(&PostgresqlPasswordWarning::ConnectionRole)
    );
    assert!(!format!("{plan:?}").contains(NEW_PASSWORD));
    assert!(!serde_json::to_string(&view).unwrap().contains(NEW_PASSWORD));
    let confirmation = DangerousConfirmation::approve(plan.definition());
    let execution = services
        .database()
        .execute_postgresql_password(&session, plan, confirmation, journal)
        .await
        .unwrap();
    assert_eq!(
        execution.outcome.verification,
        PostgresqlPasswordVerification::Passed
    );
    assert_eq!(
        execution.outcome.saved_password,
        SavedPasswordUpdate::Updated
    );
    assert!(execution.restore_token.is_some());
    assert!(
        !serde_json::to_string(&execution.outcome)
            .unwrap()
            .contains(NEW_PASSWORD)
    );
    check("scram superuser changes own password; verification passes and saved password updates");

    assert!(
        password_works(&services, &session, "lr_super", NEW_PASSWORD).await,
        "saved profile now holds the new password"
    );
    assert!(!password_works(&services, &session, "lr_super", OLD_SUPER).await);
    check("old password fails and new password authenticates after the change");

    // Restore puts the captured verifier back; read-back comparison passes.
    let token = execution.restore_token.unwrap();
    let snapshot = save_profile(&services, &super_profile, NEW_PASSWORD);
    let restore_plan = services
        .database()
        .plan_postgresql_password_restore(&session, &snapshot, token)
        .await
        .unwrap();
    assert!(restore_plan.view().saved_password_was_updated);
    let confirmation = DangerousConfirmation::approve(restore_plan.definition());
    let restored = services
        .database()
        .execute_postgresql_password_restore(&session, restore_plan, confirmation, journal)
        .await
        .unwrap();
    assert_eq!(restored.verification, PostgresqlRestoreVerification::Passed);
    assert_eq!(restored.saved_password, SavedPasswordRestore::Restored);
    assert!(restored.journal_recorded);
    assert!(
        services
            .database()
            .test_profile(&session, &super_profile.id)
            .await
            .is_ok(),
        "saved profile is put back to the previous password"
    );
    assert!(password_works(&services, &session, "lr_super", OLD_SUPER).await);
    assert!(!password_works(&services, &session, "lr_super", NEW_PASSWORD).await);
    check("restore puts back the old verifier and read-back verification passes");

    // (b) a superuser changes another login role's password.
    let snapshot = save_profile(&services, &super_profile, OLD_SUPER);
    let oid = role_oid(&services, &session, "lr_other").await;
    let plan = services
        .database()
        .plan_postgresql_password(
            &session,
            &snapshot,
            PostgresqlPasswordRole::Oid(oid),
            SecretValue::new(NEW_PASSWORD_B),
            true,
        )
        .await
        .unwrap();
    assert_eq!(plan.view().role_name, "lr_other");
    assert!(!plan.view().is_connection_role && !plan.view().updates_saved_password);
    let confirmation = DangerousConfirmation::approve(plan.definition());
    let execution = services
        .database()
        .execute_postgresql_password(&session, plan, confirmation, journal)
        .await
        .unwrap();
    assert_eq!(
        execution.outcome.verification,
        PostgresqlPasswordVerification::Passed
    );
    assert_eq!(
        execution.outcome.saved_password,
        SavedPasswordUpdate::NotRequested
    );
    assert!(password_works(&services, &session, "lr_other", NEW_PASSWORD_B).await);
    assert!(!password_works(&services, &session, "lr_other", OLD_OTHER).await);
    check(
        "superuser changes another login role; verification passes without touching saved secrets",
    );

    // (c) a non-superuser connection changing its own password is not restorable.
    let crole_profile = loopback_profile("owned createrole", "lr_crole");
    let snapshot = save_profile(&services, &crole_profile, OLD_CROLE);
    let plan = services
        .database()
        .plan_postgresql_password(
            &session,
            &snapshot,
            PostgresqlPasswordRole::Current,
            SecretValue::new(NEW_PASSWORD_B),
            true,
        )
        .await
        .unwrap();
    assert!(!plan.view().restorable);
    assert!(
        plan.view()
            .warnings
            .contains(&PostgresqlPasswordWarning::NotRestorable)
    );
    check("non-superuser changing its own password plans as not restorable");

    // (d) password_encryption=md5 stores an md5 verifier.
    sql(
        &services,
        &session,
        "ALTER SYSTEM SET password_encryption = 'md5'",
    )
    .await;
    sql(&services, &session, "SELECT pg_reload_conf()").await;
    let snapshot = save_profile(&services, &super_profile, OLD_SUPER);
    let oid = role_oid(&services, &session, "lr_other").await;
    let plan = services
        .database()
        .plan_postgresql_password(
            &session,
            &snapshot,
            PostgresqlPasswordRole::Oid(oid),
            SecretValue::new(NEW_PASSWORD),
            false,
        )
        .await
        .unwrap();
    assert_eq!(plan.view().format, PostgresqlPasswordFormat::Md5);
    assert!(
        plan.view()
            .warnings
            .contains(&PostgresqlPasswordWarning::Md5Weak)
    );
    let confirmation = DangerousConfirmation::approve(plan.definition());
    let execution = services
        .database()
        .execute_postgresql_password(&session, plan, confirmation, journal)
        .await
        .unwrap();
    assert_eq!(
        execution.outcome.verification,
        PostgresqlPasswordVerification::Passed
    );
    assert_eq!(verifier_kind(&services, &session, "lr_other").await, "md5");
    assert!(password_works(&services, &session, "lr_other", NEW_PASSWORD).await);
    check("md5 password_encryption stores an md5 verifier that still authenticates");

    // (e) a NOLOGIN role is rejected at plan time.
    let snapshot = save_profile(&services, &super_profile, OLD_SUPER);
    let oid = role_oid(&services, &session, "lr_nologin").await;
    let error = services
        .database()
        .plan_postgresql_password(
            &session,
            &snapshot,
            PostgresqlPasswordRole::Oid(oid),
            SecretValue::new(NEW_PASSWORD),
            false,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("不能登录"));
    assert!(!error.to_string().contains(NEW_PASSWORD));
    check("a nologin role is rejected at plan time");

    // Journal and portable data never contain the plaintext.
    for entry in journal.entries().unwrap() {
        let text = serde_json::to_string(&entry).unwrap();
        assert!(!text.contains(NEW_PASSWORD) && !text.contains(NEW_PASSWORD_B));
        assert!(!text.contains("SCRAM-SHA-256$") && !text.contains("ALTER ROLE"));
    }
    check("journal entries contain no passwords, verifiers, or statement text");
    println!("POSTGRESQL_PASSWORD_SUITE_COMPLETE");
}
