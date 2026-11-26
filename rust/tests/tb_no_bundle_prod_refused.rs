//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn prod_without_signed_bundle_refused() {
    let ledger = tempfile::tempdir().expect("ledger");
    prod_env(ledger.path(), None);

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("requires a signed policy bundle"),
        "unexpected refusal: {err}"
    );
}
