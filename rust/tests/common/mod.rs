//! Shared helpers for policy trust-boundary tests. All keys and seeds are TEST-ONLY.
//!
//! The v2 policy signature digest is specified here independently of the implementation, so the
//! tests check the contract rather than echoing the code under test:
//!   digest_v2 = sha256(canonical_json({
//!     "payload_version": 2, "policy_digest_sha256": <document digest>,
//!     "issuer_id", "signer", "created_at_utc", "expires_at_utc" (null or string)
//!   }))
//! where the document digest is `policy_signing::policy_payload_digest_sha256` (document minus
//! `signatures`). v1 records sign the document digest directly.
#![allow(dead_code)]

use aigov_audit::canonical_json::{canonical_json_bytes, sha256_hex_bytes};
use aigov_audit::contracts::GovaiPolicyV1;
use aigov_audit::policy_signing::policy_payload_digest_sha256;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const ISSUER: &str = "policy-issuer-test";
pub const SEED: [u8; 32] = [0x44; 32];

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

pub fn trust_env_json() -> String {
    let vk = signing_key().verifying_key();
    json!([{
        "issuer_id": ISSUER,
        "pubkeys_base64": [base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())],
    }])
    .to_string()
}

/// A valid, unsigned `govai.policy.v1` document with one human-approval gate and one ingest rule.
pub fn base_policy() -> Value {
    json!({
        "schema": "govai.policy.v1",
        "policy_id": "tb-policy",
        "version": "1",
        "created_at_utc": "2026-01-01T00:00:00Z",
        "issuer": { "issuer_id": ISSUER, "display_name": "Policy issuer (test)" },
        "selectors": { "tenants": ["*"], "environments": ["*"] },
        "inherits": [],
        "ingest_rules": {
            "unknown_event_types": { "behavior": "reject" },
            "event_types": {
                "ai_discovery_reported": {
                    "schema": { "required_types": { "openai": "boolean" }, "required_nonempty_strings": [] },
                    "gates": []
                },
                "human_approved": {
                    "schema": { "required_types": {}, "required_nonempty_strings": ["approver", "decision"] },
                    "gates": [{
                        "type": "requires_approver_allowlist",
                        "field": "approver",
                        "allowlist": ["alice"],
                        "code": "approver_not_allowlisted",
                        "message_prefix": "policy_violation: human_approved approver"
                    }]
                }
            }
        },
        "verdict_rules": { "required_evidence_codes": [], "invalid_conditions": [] },
        "signatures": []
    })
}

/// Document digest (document minus `signatures`), using the production canonicalization.
pub fn document_digest(doc: &Value) -> String {
    let typed: GovaiPolicyV1 = serde_json::from_value(doc.clone()).expect("policy document shape");
    policy_payload_digest_sha256(&typed)
}

/// v2 signature digest per the contract in the module doc.
pub fn digest_v2(doc: &Value, signer: &str, created: &str, expires: Option<&str>) -> String {
    let value = json!({
        "payload_version": 2,
        "policy_digest_sha256": document_digest(doc),
        "issuer_id": ISSUER,
        "signer": signer,
        "created_at_utc": created,
        "expires_at_utc": expires,
    });
    sha256_hex_bytes(&canonical_json_bytes(&value))
}

fn push_record(doc: &mut Value, record: Value) {
    doc["signatures"] = json!([record]);
}

/// Legacy (v1) signature record: signs the document digest; metadata is not covered.
pub fn sign_v1(doc: &mut Value, signer: &str, created: &str, expires: Option<&str>) {
    let digest = document_digest(doc);
    let sig = signing_key().sign(digest.as_bytes());
    push_record(
        doc,
        json!({
            "kind": "ed25519",
            "signer": signer,
            "created_at_utc": created,
            "expires_at_utc": expires,
            "payload_digest_sha256": digest,
            "signature": { "encoding": "base64",
                "value": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()) },
            "sigstore": null,
        }),
    );
}

/// v2 signature record: binds signer, creation time and expiry.
pub fn sign_v2(doc: &mut Value, signer: &str, created: &str, expires: Option<&str>) {
    let digest = digest_v2(doc, signer, created, expires);
    let sig = signing_key().sign(digest.as_bytes());
    push_record(
        doc,
        json!({
            "kind": "ed25519",
            "payload_version": 2,
            "signer": signer,
            "created_at_utc": created,
            "expires_at_utc": expires,
            "payload_digest_sha256": digest,
            "signature": { "encoding": "base64",
                "value": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()) },
            "sigstore": null,
        }),
    );
}

pub fn write_bundle(dir: &Path, doc: &Value) -> PathBuf {
    let p = dir.join("policy.bundle.json");
    std::fs::write(&p, serde_json::to_string_pretty(doc).unwrap()).unwrap();
    p
}

/// Process environment for a production-style start. Callers add the policy source under test.
pub fn prod_env(ledger: &Path, bundle: Option<&Path>) {
    environment_env(ledger, bundle, "prod");
}

/// Process environment for a start in `environment` ("staging" or "prod").
pub fn environment_env(ledger: &Path, bundle: Option<&Path>, environment: &str) {
    std::env::set_var("GOVAI_LEDGER_DIR", ledger);
    std::env::set_var("GOVAI_API_KEYS", "tb-key-admin");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"tb-key-admin":"tenant-tb"}"#);
    std::env::set_var("AIGOV_ENVIRONMENT", environment);
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::set_var("AIGOV_POLICY_TRUST_ED25519_JSON", trust_env_json());
    std::env::remove_var("AIGOV_POLICY_FILE");
    // An empty policy directory keeps the default search from picking up repository policy files.
    let empty = std::env::temp_dir().join(format!("tb-empty-policy-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    std::env::set_var("AIGOV_POLICY_DIR", &empty);
    std::env::remove_var("AIGOV_ALLOW_UNSIGNED_POLICY_FILE");
    std::env::remove_var("AIGOV_APPROVER_ALLOWLIST");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    match bundle {
        Some(p) => std::env::set_var("AIGOV_POLICY_BUNDLE_FILE", p),
        None => std::env::remove_var("AIGOV_POLICY_BUNDLE_FILE"),
    }
}

pub fn created_at() -> &'static str {
    "2026-01-01T00:00:00Z"
}

pub fn future() -> &'static str {
    "2999-01-01T00:00:00Z"
}

pub fn past() -> &'static str {
    "2020-01-01T00:00:00Z"
}

/// A fresh, empty PostgreSQL database for one test, created on the server named by `AIGOV_TEST_PG_ADMIN_URL`.
/// Returns `None` when the variable is unset, so PostgreSQL-backed tests are ignored rather than passed.
/// Used only with throwaway test servers. Never point it at a shared or production server.
pub async fn fresh_database_url() -> Option<String> {
    let admin = std::env::var("AIGOV_TEST_PG_ADMIN_URL").ok()?;
    let name = format!("aigov_anchor_{}", secrets_hex());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin)
        .await
        .ok()?;
    // `name` is built from hex digits only, so the statement is safe to assemble.
    sqlx::query(sqlx::AssertSqlSafe(format!("create database \"{name}\"")))
        .execute(&pool)
        .await
        .ok()?;
    pool.close().await;
    Some(replace_database(&admin, &name))
}

fn secrets_hex() -> String {
    // Unique within and across test processes: a counter, the process id, and a timestamp.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{:x}{:x}{:x}", std::process::id(), n, nanos)
}

fn replace_database(url: &str, name: &str) -> String {
    let (base, _) = url.rsplit_once('/').unwrap_or((url, ""));
    format!("{base}/{name}")
}
