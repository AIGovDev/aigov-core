//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn v2_expiry_extension_refused_in_prod() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(past()));
    doc["signatures"][0]["expires_at_utc"] = serde_json::json!(future());
    let bundle = write_bundle(dir.path(), &doc);
    prod_env(ledger.path(), Some(&bundle));

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("payload_digest_sha256 mismatch"),
        "unexpected refusal: {err}"
    );
}
