//! Regression: audit export signatures must bind the signing metadata and enforce expiry.
//!
//! Before this change the signed digest covered only eight content fields. The signer label,
//! creation time and expiry in the signature record were unsigned, so they could be changed
//! without invalidating the signature. Expiry was never enforced.
//!
//! All keys here are fixed TEST-ONLY seeds.
use aigov_audit::audit_export_signing::{
    audit_export_payload_digest_sha256_hex, sign_audit_export_ed25519, signing_key_from_seed,
    verify_audit_export_ed25519_signature, verifying_key_from_seed,
};
use aigov_audit::bundle::portable_evidence_digest_v1;
use aigov_audit::policy_signing::PolicyTrustStore;
use aigov_audit::schema::EvidenceEvent;
use base64::Engine;
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const ISSUER: &str = "govai-export-signer";
const SEED: [u8; 32] = [0x33; 32];

fn export(run_id: &str) -> Value {
    let events = json!([{
        "event_id": format!("{run_id}-e1"),
        "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z",
        "actor": "test",
        "system": "test",
        "run_id": run_id,
        "payload": {"openai": false, "transformers": false, "model_artifacts": false}
    }]);
    let evs: Vec<EvidenceEvent> = serde_json::from_value(events.clone()).expect("events");
    let events_sha = portable_evidence_digest_v1(run_id, &evs);
    json!({
        "ok": true,
        "schema_version": "aigov.audit_export.v1",
        "policy_version": "test-policy",
        "environment": "dev",
        "run": {"run_id": run_id},
        "evidence_hashes": {
            "bundle_sha256": "a".repeat(64),
            "events_content_sha256": events_sha,
            "chain_head_record_sha256": "b".repeat(64),
            "log_chain": []
        },
        "decision": {"verdict": "BLOCKED"},
        "evidence_events": events
    })
}

fn trust() -> PolicyTrustStore {
    let mut map = BTreeMap::new();
    map.insert(ISSUER.to_string(), vec![verifying_key_from_seed(&SEED)]);
    PolicyTrustStore { ed25519_pubkeys: map }
}

fn signed(run_id: &str, expires: Option<&str>) -> Value {
    let mut doc = export(run_id);
    sign_audit_export_ed25519(
        &mut doc,
        ISSUER,
        "ci-signer",
        &signing_key_from_seed(&SEED),
        "2026-01-01T00:00:00Z",
        expires,
    )
    .expect("sign");
    doc
}

fn record_mut(doc: &mut Value) -> &mut Value {
    &mut doc["signatures"][0]
}

#[test]
fn positive_control_unexpired_signature_verifies() {
    let doc = signed("run-bind-ok", Some("2999-01-01T00:00:00Z"));
    let issuer = verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER))
        .expect("valid, unexpired signature must verify");
    assert_eq!(issuer, ISSUER);
}

#[test]
fn tampering_the_signer_label_invalidates_the_signature() {
    let mut doc = signed("run-bind-signer", None);
    record_mut(&mut doc)["signer"] = json!("attacker");
    assert!(
        verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER)).is_err(),
        "signer label must be covered by the signature"
    );
}

#[test]
fn tampering_the_creation_time_invalidates_the_signature() {
    let mut doc = signed("run-bind-created", None);
    record_mut(&mut doc)["created_at_utc"] = json!("2030-06-01T00:00:00Z");
    assert!(
        verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER)).is_err(),
        "created_at_utc must be covered by the signature"
    );
}

#[test]
fn extending_the_expiry_invalidates_the_signature() {
    let mut doc = signed("run-bind-extend", Some("2020-01-01T00:00:00Z"));
    record_mut(&mut doc)["expires_at_utc"] = json!("2999-01-01T00:00:00Z");
    assert!(
        verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER)).is_err(),
        "expires_at_utc must be covered by the signature"
    );
}

#[test]
fn expired_signature_is_rejected() {
    let doc = signed("run-bind-expired", Some("2020-01-01T00:00:00Z"));
    assert!(
        verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER)).is_err(),
        "a signature past its expiry must not verify"
    );
}

#[test]
fn legacy_signature_with_unsigned_expiry_is_rejected() {
    // Legacy (v1) digest does not cover expiry, so an expiry on such a record cannot be trusted.
    let mut doc = export("run-bind-v1-expiry");
    let digest = audit_export_payload_digest_sha256_hex(&doc);
    let sig = signing_key_from_seed(&SEED).sign(digest.as_bytes());
    doc["signatures"] = json!([{
        "kind": "ed25519",
        "issuer_id": ISSUER,
        "signer": "ci-signer",
        "created_at_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2020-01-01T00:00:00Z",
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64",
            "value": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())}
    }]);
    assert!(
        verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER)).is_err(),
        "legacy records cannot carry an unsigned expiry"
    );
}

#[test]
fn legacy_signature_without_expiry_still_verifies() {
    // Compatibility: records written before this change (no expiry, v1 digest) keep verifying.
    let mut doc = export("run-bind-v1-legacy");
    let digest = audit_export_payload_digest_sha256_hex(&doc);
    let sig = signing_key_from_seed(&SEED).sign(digest.as_bytes());
    doc["signatures"] = json!([{
        "kind": "ed25519",
        "issuer_id": ISSUER,
        "signer": "ci-signer",
        "created_at_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": null,
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64",
            "value": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())}
    }]);
    verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER))
        .expect("legacy signature without expiry must keep verifying");
}

/// Cross-language vector: the Python mirror (`aigov_py.audit_export_signing.audit_export_signing_digest_v2`)
/// asserts the same two digests in `python/tests/test_audit_export_binding.py`.
#[test]
fn v2_digest_matches_python_mirror_vector() {
    use aigov_audit::audit_export_signing::audit_export_signing_digest_v2;
    let doc = json!({
        "schema_version": "aigov.audit_export.v1",
        "policy_version": "p",
        "environment": "dev",
        "run": {"run_id": "run-vec"},
        "evidence_hashes": {
            "bundle_sha256": "a".repeat(64),
            "events_content_sha256": "b".repeat(64),
            "chain_head_record_sha256": "c".repeat(64),
            "log_chain": []
        },
        "decision": {"verdict": "BLOCKED"}
    });
    assert_eq!(
        audit_export_signing_digest_v2(&doc, ISSUER, "ci-signer", "2026-01-01T00:00:00Z", Some("2999-01-01T00:00:00Z")).expect("digest"),
        "ca0228a1e586093c8e247659445625bcf56b82d09654ad5b19c29582378a47f1"
    );
    assert_eq!(
        audit_export_signing_digest_v2(&doc, ISSUER, "ci-signer", "2026-01-01T00:00:00Z", None).expect("digest"),
        "fd92abcaebb77df2ab4f3f2f724ff88fec346d10bfcb3d231be9212348021a24"
    );
}

#[test]
fn tampering_unsigned_evidence_fields_invalidates_the_signature() {
    // log_chain and other evidence metadata were outside the signed digest before v2.
    let mut doc = signed("run-bind-doc", None);
    doc["evidence_hashes"]["log_chain"] = json!([{"record_hash": "forged"}]);
    assert!(
        verify_audit_export_ed25519_signature(&doc, &trust(), Some(ISSUER)).is_err(),
        "the whole document must be covered by the signature"
    );
}

#[test]
fn signing_a_document_with_floats_is_refused() {
    let mut doc = export("run-bind-float");
    doc["run"]["score"] = json!(0.5);
    let err = sign_audit_export_ed25519(
        &mut doc,
        ISSUER,
        "ci-signer",
        &signing_key_from_seed(&SEED),
        "2026-01-01T00:00:00Z",
        None,
    )
    .expect_err("floats must be refused");
    assert!(err.contains("floating-point"), "{err}");
}
