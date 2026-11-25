//! Core-issued execution authorization: a signed statement that one consequential tool call was accepted.
//!
//! Core signs with a dedicated Ed25519 key (`GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX`). The key is never
//! given to the agent, and it is separate from the policy-bundle and audit-export keys. The signed message is
//!
//! ```text
//! b"govai.execution_authorization.v1\0" || canonical_json(payload)
//! ```
//!
//! The domain prefix stops a signature made for another purpose from being accepted here. The payload binds
//! the run, tool, argument digest, policy revision, the approval that allowed the call, the ledger record of
//! the accepted call, the executor audience, the expiry, and a unique authorization id.
//!
//! This module does not say the action happened. An authorization only says Core accepted the call. Actual
//! execution is recorded separately as an `execution_receipt` event from the executor.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::canonical_json::canonical_json_bytes;

pub const SCHEMA: &str = "govai.execution_authorization.v1";
pub const DOMAIN_PREFIX: &[u8] = b"govai.execution_authorization.v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationPayload {
    pub schema: String,
    pub authorization_id: String,
    pub run_id: String,
    pub tool_name: String,
    pub args_binding_hash: String,
    pub policy_revision: String,
    pub executor_audience: String,
    pub approval_event_id: String,
    pub consequential_record_hash: String,
    pub issued_at_utc: String,
    pub expires_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAuthorization {
    pub payload: AuthorizationPayload,
    /// base64 Ed25519 signature over [`signed_message`].
    pub signature: String,
    /// base64 Ed25519 public key that verifies the signature. Executors pin this value from configuration.
    pub public_key: String,
}

/// The exact bytes that are signed. Domain prefix first, then the canonical payload.
pub fn signed_message(payload: &AuthorizationPayload) -> Vec<u8> {
    let mut out = DOMAIN_PREFIX.to_vec();
    out.extend_from_slice(&canonical_json_bytes(payload));
    out
}

pub fn sign(key: &SigningKey, payload: AuthorizationPayload) -> SignedAuthorization {
    let sig: Signature = key.sign(&signed_message(&payload));
    let b64 = base64::engine::general_purpose::STANDARD;
    SignedAuthorization {
        payload,
        signature: b64.encode(sig.to_bytes()),
        public_key: b64.encode(key.verifying_key().to_bytes()),
    }
}

/// Verify the signature with the given public key, and that the payload has the expected schema.
/// Does not check expiry, audience, or any binding to the request. Those are the executor's checks.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    signed: &SignedAuthorization,
) -> Result<(), String> {
    if signed.payload.schema != SCHEMA {
        return Err("authorization_schema_mismatch".to_string());
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let raw = b64
        .decode(&signed.signature)
        .map_err(|_| "authorization_signature_invalid".to_string())?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "authorization_signature_invalid".to_string())?;
    let sig = Signature::from_bytes(&bytes);
    verifying_key
        .verify(&signed_message(&signed.payload), &sig)
        .map_err(|_| "authorization_signature_invalid".to_string())
}

#[derive(Debug, Clone)]
pub struct IssuerConfig {
    pub key: SigningKey,
    pub executor_audience: String,
    pub ttl_seconds: i64,
}

static ISSUER: OnceCell<Option<IssuerConfig>> = OnceCell::new();

/// Load issuance settings from the environment. Without a signing seed, issuance is disabled and
/// consequential calls are accepted without an authorization (the pre-existing behaviour).
pub fn init_from_env() -> Result<(), String> {
    let seed = crate::aigov_env::required(
        "AIGOV_EXECUTION_AUTH_SIGNING_SEED_HEX",
        "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX",
    )
    .unwrap_or_default();
    let cfg = if seed.trim().is_empty() {
        None
    } else {
        let bytes = crate::audit_export_signing::parse_seed_hex_strict(seed.trim())?;
        let audience =
            crate::aigov_env::required("AIGOV_EXECUTOR_AUDIENCE", "GOVAI_EXECUTOR_AUDIENCE")
                .unwrap_or_default();
        let audience = if audience.trim().is_empty() {
            "executor".to_string()
        } else {
            audience.trim().to_string()
        };
        let ttl = crate::aigov_env::required(
            "AIGOV_EXECUTION_AUTH_TTL_SECONDS",
            "GOVAI_EXECUTION_AUTH_TTL_SECONDS",
        )
        .unwrap_or_default();
        let ttl_seconds = if ttl.trim().is_empty() {
            60
        } else {
            ttl.trim()
                .parse::<i64>()
                .ok()
                .filter(|t| (1..=3600).contains(t))
                .ok_or_else(|| {
                    "GOVAI_EXECUTION_AUTH_TTL_SECONDS must be an integer from 1 to 3600".to_string()
                })?
        };
        Some(IssuerConfig {
            key: crate::audit_export_signing::signing_key_from_seed(&bytes),
            executor_audience: audience,
            ttl_seconds,
        })
    };
    let _ = ISSUER.set(cfg);
    Ok(())
}

/// The configured issuer, if execution authorization is enabled.
pub fn issuer() -> Option<&'static IssuerConfig> {
    ISSUER.get().and_then(|c| c.as_ref())
}

/// Identifiers and times fixed before the ledger append, so the accepted record can carry them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub authorization_id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Reserve an authorization id and its times before the append. `None` when issuance is disabled.
pub fn prepare(now: chrono::DateTime<chrono::Utc>) -> Option<Prepared> {
    let cfg = issuer()?;
    Some(Prepared {
        authorization_id: format!("auth_{}", uuid::Uuid::new_v4().simple()),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(cfg.ttl_seconds),
    })
}

/// Sign the authorization for a call that the ledger has accepted. `consequential_record_hash` is the hash of
/// that accepted record, so the authorization is bound to the ledger entry.
pub fn sign_prepared(
    prepared: &Prepared,
    run_id: &str,
    tool_name: &str,
    args_binding_hash: &str,
    policy_revision: &str,
    approval_event_id: &str,
    consequential_record_hash: &str,
) -> Option<SignedAuthorization> {
    let cfg = issuer()?;
    let payload = AuthorizationPayload {
        schema: SCHEMA.to_string(),
        authorization_id: prepared.authorization_id.clone(),
        run_id: run_id.to_string(),
        tool_name: tool_name.to_string(),
        args_binding_hash: args_binding_hash.to_string(),
        policy_revision: policy_revision.to_string(),
        executor_audience: cfg.executor_audience.clone(),
        approval_event_id: approval_event_id.to_string(),
        consequential_record_hash: consequential_record_hash.to_string(),
        issued_at_utc: prepared.issued_at.to_rfc3339(),
        expires_at_utc: prepared.expires_at.to_rfc3339(),
    };
    Some(sign(&cfg.key, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn payload() -> AuthorizationPayload {
        AuthorizationPayload {
            schema: SCHEMA.into(),
            authorization_id: "auth_1".into(),
            run_id: "run-1".into(),
            tool_name: "create_file".into(),
            args_binding_hash: "a".repeat(64),
            policy_revision: "1".into(),
            executor_audience: "executor".into(),
            approval_event_id: "human_approved-1".into(),
            consequential_record_hash: "b".repeat(64),
            issued_at_utc: "2026-11-25T10:00:00+00:00".into(),
            expires_at_utc: "2026-11-25T10:01:00+00:00".into(),
        }
    }

    #[test]
    fn signed_authorization_verifies() {
        let k = key();
        let s = sign(&k, payload());
        verify_signature(&k.verifying_key(), &s).unwrap();
    }

    #[test]
    fn modified_payload_is_refused() {
        let k = key();
        let mut s = sign(&k, payload());
        s.payload.tool_name = "request_deployment".into();
        assert!(verify_signature(&k.verifying_key(), &s).is_err());
    }

    #[test]
    fn modified_argument_digest_is_refused() {
        let k = key();
        let mut s = sign(&k, payload());
        s.payload.args_binding_hash = "c".repeat(64);
        assert!(verify_signature(&k.verifying_key(), &s).is_err());
    }

    #[test]
    fn signature_from_another_key_is_refused() {
        let k = key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let s = sign(&other, payload());
        assert!(verify_signature(&k.verifying_key(), &s).is_err());
    }

    #[test]
    fn signature_for_another_purpose_is_refused() {
        // A signature over the bare canonical payload, without the domain prefix, must not verify.
        let k = key();
        let p = payload();
        let sig = k.sign(&canonical_json_bytes(&p));
        let b64 = base64::engine::general_purpose::STANDARD;
        let forged = SignedAuthorization {
            payload: p,
            signature: b64.encode(sig.to_bytes()),
            public_key: b64.encode(k.verifying_key().to_bytes()),
        };
        assert!(verify_signature(&k.verifying_key(), &forged).is_err());
    }

    #[test]
    fn wrong_schema_is_refused() {
        let k = key();
        let mut p = payload();
        p.schema = "govai.something_else.v1".into();
        let s = sign(&k, p);
        assert_eq!(
            verify_signature(&k.verifying_key(), &s).unwrap_err(),
            "authorization_schema_mismatch"
        );
    }

    #[test]
    fn signed_message_starts_with_the_domain_prefix() {
        assert!(signed_message(&payload()).starts_with(DOMAIN_PREFIX));
    }
}
