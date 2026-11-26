//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn unsigned_policy_file_optin_refused_in_prod() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let policy = dir.path().join("policy.prod.json");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/policy.prod.json"),
        &policy,
    )
    .unwrap();
    prod_env(ledger.path(), None);
    std::env::set_var("AIGOV_POLICY_FILE", &policy);
    std::env::set_var("AIGOV_ALLOW_UNSIGNED_POLICY_FILE", "1");

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("AIGOV_POLICY_FILE is not permitted"),
        "unexpected refusal: {err}"
    );
}
