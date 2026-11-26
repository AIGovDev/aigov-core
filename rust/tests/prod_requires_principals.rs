//! Production refuses to start without authenticated principals. The check runs before any database access, so this test
//! needs no PostgreSQL. The control is the same production environment with the principals removed.

mod common;

use aigov_audit::build_app_state;

#[tokio::test]
async fn production_refuses_to_start_without_principals() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = common::base_policy();
    common::sign_v1(&mut doc, "ci", common::created_at(), None);
    let bundle = common::write_bundle(dir.path(), &doc);
    common::prod_env(ledger.path(), Some(&bundle));
    // The policy revision anchor needs a database URL to be configured; the principal check runs before any connection.
    std::env::set_var("GOVAI_DATABASE_URL", "postgresql://unused:unused@127.0.0.1:1/unused");
    std::env::remove_var("GOVAI_PRINCIPALS_JSON");
    let err = build_app_state().await.err().expect("production must refuse without principals");
    assert!(err.contains("requires GOVAI_PRINCIPALS_JSON"), "wrong refusal: {err}");
}
