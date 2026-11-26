//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;

#[tokio::test]
async fn dev_unsigned_policy_file_still_starts() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let policy = dir.path().join("policy.dev.json");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/policy.dev.json"),
        &policy,
    )
    .unwrap();
    std::env::set_var("GOVAI_LEDGER_DIR", ledger.path());
    std::env::set_var("GOVAI_API_KEYS", "tb-key-dev");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"tb-key-dev":"tenant-dev"}"#);
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::set_var("AIGOV_POLICY_FILE", &policy);
    std::env::remove_var("AIGOV_POLICY_BUNDLE_FILE");
    std::env::remove_var("AIGOV_POLICY_TRUST_ED25519_JSON");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");

    build_app_state().await.expect("startup must succeed");
}
