//! Regression: in staging, a legacy policy file or unsigned override must not participate in
//! verdicts once a signed bundle is configured. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn policy_file_alongside_bundle_is_refused_in_staging() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    environment_env(ledger.path(), Some(&bundle), "staging");
    let policy = dir.path().join("policy.staging.json");
    std::fs::write(&policy, "{}").unwrap();
    std::env::set_var("AIGOV_POLICY_FILE", &policy);

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("AIGOV_POLICY_FILE is not permitted in staging"),
        "unexpected refusal: {err}"
    );
}
