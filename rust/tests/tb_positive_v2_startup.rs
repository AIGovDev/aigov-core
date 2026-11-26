//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL); run with --ignored"]
async fn signed_v2_bundle_with_future_expiry_starts_in_prod() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    prod_env(ledger.path(), Some(&bundle));
    // The durable revision anchor needs PostgreSQL. Each run gets its own fresh database.
    let Some(url) = common::fresh_database_url().await else {
        panic!("requires AIGOV_TEST_PG_ADMIN_URL (run with --ignored against a PostgreSQL server)");
    };
    std::env::set_var("GOVAI_DATABASE_URL", url);
    std::env::set_var("GOVAI_AUTO_MIGRATE", "true");

    build_app_state().await.expect("startup must succeed");
}
