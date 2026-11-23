//! Regression: a signed bundle configured in staging must govern startup. Before the staging fix,
//! staging read the legacy policy path and refused to start with a valid bundle present.
//! Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn signed_bundle_starts_in_staging_without_a_policy_file() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    environment_env(ledger.path(), Some(&bundle), "staging");

    build_app_state()
        .await
        .expect("staging must start with a verified signed bundle");
}
