//! Policy trust boundary scenario. Separate binary: process-wide startup state.
mod common;
use aigov_audit::build_app_state;
use common::*;

#[tokio::test]
async fn policy_signed_by_unknown_key_refused_in_prod() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    let other = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
    let digest = document_digest(&doc);
    let sig = ed25519_dalek::Signer::sign(&other, digest.as_bytes());
    doc["signatures"] = serde_json::json!([{
        "kind": "ed25519", "signer": "attacker", "created_at_utc": created_at(), "expires_at_utc": null,
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64", "value": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())},
        "sigstore": null}]);
    let bundle = write_bundle(dir.path(), &doc);
    prod_env(ledger.path(), Some(&bundle));

    let err = build_app_state()
        .await
        .err()
        .expect("startup must fail closed");
    assert!(
        err.contains("verification failed for all trusted keys"),
        "unexpected refusal: {err}"
    );
}
