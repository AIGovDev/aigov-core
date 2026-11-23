use crate::contracts::{GovaiPolicyV1, PolicySignatureV1};
use crate::govai_environment::GovaiEnvironment;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct PolicyTrustStore {
    /// issuer_id -> list of base64 public keys (Ed25519).
    pub ed25519_pubkeys: std::collections::BTreeMap<String, Vec<VerifyingKey>>,
}

#[derive(Debug, Clone, Deserialize)]
struct TrustConfigEd25519 {
    issuer_id: String,
    pubkeys_base64: Vec<String>,
}

/// Load trusted policy signing keys.
///
/// Format (JSON array):
/// `[{"issuer_id":"acme-security","pubkeys_base64":["...","..."]}]`
pub fn load_trust_store_from_env() -> Result<PolicyTrustStore, String> {
    let raw = std::env::var("AIGOV_POLICY_TRUST_ED25519_JSON")
        .ok()
        .unwrap_or_default();
    let t = raw.trim();
    if t.is_empty() {
        return Ok(PolicyTrustStore {
            ed25519_pubkeys: Default::default(),
        });
    }
    let items: Vec<TrustConfigEd25519> = serde_json::from_str(t)
        .map_err(|e| format!("invalid AIGOV_POLICY_TRUST_ED25519_JSON: {e}"))?;
    let mut out: std::collections::BTreeMap<String, Vec<VerifyingKey>> = Default::default();
    for it in items {
        if it.issuer_id.trim().is_empty() {
            return Err("invalid AIGOV_POLICY_TRUST_ED25519_JSON: issuer_id empty".to_string());
        }
        if it.pubkeys_base64.is_empty() {
            return Err(format!(
                "invalid AIGOV_POLICY_TRUST_ED25519_JSON: issuer_id={} has no keys",
                it.issuer_id
            ));
        }
        let mut keys: Vec<VerifyingKey> = Vec::new();
        for k in it.pubkeys_base64 {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(k.trim())
                .map_err(|e| {
                    format!(
                        "invalid base64 public key for issuer_id={}: {e}",
                        it.issuer_id
                    )
                })?;
            let vk = VerifyingKey::try_from(bytes.as_slice()).map_err(|e| {
                format!(
                    "invalid ed25519 public key for issuer_id={}: {e}",
                    it.issuer_id
                )
            })?;
            keys.push(vk);
        }
        out.insert(it.issuer_id.trim().to_string(), keys);
    }
    Ok(PolicyTrustStore {
        ed25519_pubkeys: out,
    })
}

pub fn policy_payload_digest_sha256(policy: &GovaiPolicyV1) -> String {
    // Canonical payload for signing is the policy document with `signatures` removed,
    // and keys sorted recursively.
    let mut v = serde_json::to_value(policy).expect("policy serde");
    if let Some(obj) = v.as_object_mut() {
        obj.remove("signatures");
    }
    let v = sort_json_value(v);
    let bytes = serde_json::to_vec(&v).expect("policy canonical json");
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn sort_json_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut items: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (k, vv) in items {
                out.insert(k, sort_json_value(vv));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}

pub fn verify_policy_signatures(
    deployment_env: GovaiEnvironment,
    trust: &PolicyTrustStore,
    policy: &GovaiPolicyV1,
) -> Result<(), String> {
    if policy.signatures.is_empty() {
        return Err("policy is unsigned (no signatures)".to_string());
    }

    let payload_digest = policy_payload_digest_sha256(policy);

    // Fail closed on unknown signature kinds in staging/prod; allow in dev only.
    let mut any_ok = false;
    let mut last_err: Option<String> = None;

    for sig in policy.signatures.iter() {
        match sig.kind.as_str() {
            "ed25519" => {
                match verify_ed25519(deployment_env, trust, policy, &payload_digest, sig) {
                    Ok(()) => {
                        any_ok = true;
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            other => {
                let msg = format!("unsupported policy signature kind: {other}");
                if matches!(deployment_env, GovaiEnvironment::Dev) {
                    last_err = Some(msg);
                    continue;
                }
                return Err(msg);
            }
        }
    }

    if any_ok {
        Ok(())
    } else {
        Err(last_err.unwrap_or_else(|| "no valid policy signature found".to_string()))
    }
}

/// Signed digest for a v2 policy signature record. Binds the policy document digest, issuer,
/// signer, creation time and expiry, so none of them can be changed without invalidating the signature.
pub const POLICY_PAYLOAD_VERSION_V2: u64 = 2;

pub fn policy_signature_digest_v2(
    policy_digest_sha256: &str,
    issuer_id: &str,
    signer: &str,
    created_at_utc: &str,
    expires_at_utc: Option<&str>,
) -> String {
    let v = serde_json::json!({
        "payload_version": POLICY_PAYLOAD_VERSION_V2,
        "policy_digest_sha256": policy_digest_sha256,
        "issuer_id": issuer_id,
        "signer": signer,
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
    });
    crate::canonical_json::sha256_hex_bytes(&crate::canonical_json::canonical_json_bytes(&v))
}

fn verify_ed25519(
    deployment_env: GovaiEnvironment,
    trust: &PolicyTrustStore,
    policy: &GovaiPolicyV1,
    payload_digest: &str,
    sig: &PolicySignatureV1,
) -> Result<(), String> {
    let non_dev = !matches!(deployment_env, GovaiEnvironment::Dev);
    let issuer_id = policy.issuer.issuer_id.trim();

    // The message that was signed, and the digest the record must declare.
    let expected_digest = match sig.payload_version {
        Some(POLICY_PAYLOAD_VERSION_V2) => policy_signature_digest_v2(
            payload_digest,
            issuer_id,
            sig.signer.trim(),
            sig.created_at_utc.trim(),
            sig.expires_at_utc.as_deref().map(str::trim),
        ),
        None => {
            // Legacy (v1): covers the document only. Its expiry and signer label are unsigned, so an
            // expiry is refused outside development.
            if non_dev && sig.expires_at_utc.is_some() {
                return Err(
                    "legacy policy signature cannot carry expires_at_utc (metadata is not signed); re-sign with payload_version 2"
                        .to_string(),
                );
            }
            payload_digest.to_string()
        }
        Some(other) => {
            return Err(format!(
                "unsupported policy signature payload_version {other}"
            ))
        }
    };

    if sig.payload_digest_sha256.trim().to_ascii_lowercase() != expected_digest {
        return Err("policy signature payload_digest_sha256 mismatch".to_string());
    }

    if non_dev {
        if let Some(exp) = sig.expires_at_utc.as_deref() {
            let exp_time = chrono::DateTime::parse_from_rfc3339(exp.trim())
                .map_err(|_| "policy signature expires_at_utc is not RFC 3339".to_string())?
                .with_timezone(&chrono::Utc);
            if chrono::Utc::now() >= exp_time {
                return Err(format!("policy signature expired at {}", exp.trim()));
            }
        }
    }

    if sig.signature.encoding != "base64" {
        return Err(format!(
            "unsupported policy signature encoding: {}",
            sig.signature.encoding
        ));
    }

    let keys = trust
        .ed25519_pubkeys
        .get(issuer_id)
        .ok_or_else(|| format!("no trusted keys for policy issuer_id={issuer_id}"))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig.signature.value.trim())
        .map_err(|e| format!("invalid signature base64: {e}"))?;
    let sig_obj = Signature::from_slice(sig_bytes.as_slice())
        .map_err(|e| format!("invalid ed25519 signature bytes: {e}"))?;

    let msg = expected_digest.as_bytes();
    for vk in keys.iter() {
        if vk.verify_strict(msg, &sig_obj).is_ok() {
            return Ok(());
        }
    }

    Err("ed25519 signature verification failed for all trusted keys".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-language vector: `aigov_py.policy_bundle_signing.policy_signature_digest_v2` asserts the
    /// same digests in `python/tests/test_policy_bundle_v2.py`.
    #[test]
    fn policy_signature_digest_v2_matches_python_mirror_vector() {
        assert_eq!(
            policy_signature_digest_v2(
                &"a".repeat(64),
                "iss",
                "ci",
                "2026-01-01T00:00:00Z",
                Some("2999-01-01T00:00:00Z"),
            ),
            "f038c7ff58adc61c0bbb1c4803f7aaf87e01f78a55dd118ae5409ab91a4a4466"
        );
        assert_eq!(
            policy_signature_digest_v2(&"a".repeat(64), "iss", "ci", "2026-01-01T00:00:00Z", None,),
            "4921b668db2abb463a835ab0165f9694ba966a204c400205b0cbf3bbb4bf5da7"
        );
    }
}
