//! Staging is refused without principals. Its own file, because each integration-test file is one process and the
//! configuration is process-wide.

mod common;

use aigov_audit::build_app_state;

/// Staging is refused without principals as well: the same staging start, with the principals removed, must not start.
#[tokio::test]
async fn staging_refuses_to_start_without_principals() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = common::base_policy();
    common::sign_v1(&mut doc, "ci", common::created_at(), None);
    let bundle = common::write_bundle(dir.path(), &doc);
    common::environment_env(ledger.path(), Some(&bundle), "staging");
    std::env::remove_var("GOVAI_PRINCIPALS_JSON");
    std::env::set_var("GOVAI_DATABASE_URL", "postgresql://unused:unused@127.0.0.1:1/unused");
    let err = build_app_state().await.err().expect("staging must refuse without principals");
    assert!(err.contains("staging requires GOVAI_PRINCIPALS_JSON"), "wrong refusal: {err}");
}
