//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn human_approved_without_approver_gate_refused_in_prod() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    doc["ingest_rules"]["event_types"]["human_approved"]["gates"] = serde_json::json!([]);
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    prod_env(ledger.path(), Some(&bundle));

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("requires_approver_allowlist gate"),
        "unexpected refusal: {err}"
    );
}
