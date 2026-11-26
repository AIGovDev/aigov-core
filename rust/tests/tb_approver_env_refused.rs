//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn approver_env_override_refused_in_prod() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    prod_env(ledger.path(), Some(&bundle));
    std::env::set_var("AIGOV_APPROVER_ALLOWLIST", "alice,mallory");

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("AIGOV_APPROVER_ALLOWLIST is not permitted"),
        "unexpected refusal: {err}"
    );
}
