//! Migration path: an explicit operator opt-in keeps an unsigned policy file usable in staging.
use aigov_audit::build_app_state;

#[tokio::test]
async fn staging_accepts_unsigned_policy_file_only_with_explicit_opt_in() {
    let ledger = tempfile::tempdir().expect("tempdir");
    let policy_dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_dir.path().join("policy.staging.json");
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/policy.staging.json"), &policy).unwrap();
    std::env::set_var("GOVAI_LEDGER_DIR", ledger.path());
    std::env::set_var("GOVAI_API_KEYS", "pol-key-two");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"pol-key-two":"tenant-pol2"}"#);
    std::env::set_var("AIGOV_ENVIRONMENT", "staging");
    std::env::set_var("AIGOV_POLICY_FILE", &policy);
    std::env::set_var("AIGOV_ALLOW_UNSIGNED_POLICY_FILE", "1");
    std::env::remove_var("AIGOV_POLICY_TRUST_ED25519_JSON");
    std::env::remove_var("AIGOV_POLICY_BUNDLE_FILE");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    build_app_state().await.expect("explicit opt-in must start");
}
