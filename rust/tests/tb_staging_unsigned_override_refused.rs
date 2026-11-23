//! Regression: in staging, a legacy policy file or unsigned override must not participate in
//! verdicts once a signed bundle is configured. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn unsigned_override_is_refused_in_staging_when_a_bundle_is_configured() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    environment_env(ledger.path(), Some(&bundle), "staging");
    std::env::set_var("AIGOV_ALLOW_UNSIGNED_POLICY_FILE", "1");

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("AIGOV_ALLOW_UNSIGNED_POLICY_FILE is not permitted in staging"),
        "unexpected refusal: {err}"
    );
}
