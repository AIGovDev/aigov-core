//! Regression: staging/prod must not start with an unsigned policy file that drives verdicts.
//! Separate test binary: process-wide environment.
use aigov_audit::build_app_state;

#[tokio::test]
async fn staging_refuses_unsigned_policy_file() {
    let ledger = tempfile::tempdir().expect("tempdir");
    let policy_dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_dir.path().join("policy.staging.json");
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/policy.staging.json"), &policy).unwrap();
    std::env::set_var("GOVAI_LEDGER_DIR", ledger.path());
    std::env::set_var("GOVAI_API_KEYS", "pol-key-one");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"pol-key-one":"tenant-pol"}"#);
    std::env::set_var("AIGOV_ENVIRONMENT", "staging");
    std::env::set_var("AIGOV_POLICY_FILE", &policy);
    std::env::remove_var("AIGOV_ALLOW_UNSIGNED_POLICY_FILE");
    std::env::remove_var("AIGOV_POLICY_TRUST_ED25519_JSON");
    std::env::remove_var("AIGOV_POLICY_BUNDLE_FILE");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    let err = build_app_state().await.err().expect("unsigned policy must fail closed in staging");
    assert!(err.contains("unsigned policy"), "{err}");
}
