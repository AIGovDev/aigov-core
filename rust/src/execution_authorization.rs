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
use serde_json::Value;

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
    /// The identifier of the key that signed this authorization. Absent on authorizations issued before key identifiers
    /// existed, which keeps their signed bytes unchanged. Executors use it to find the key in their trusted registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
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
    pub key_id: Option<String>,
    pub executor_audience: String,
    pub ttl_seconds: i64,
}

/// A key identifier: 1 to 64 characters from `A-Z a-z 0-9 . _ -`.
pub fn valid_key_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Where authorizations are signed from.
///
/// `EnvKey`: one seed from the environment, as before. The key id is fixed for the life of the process.
/// `Registry`: the trusted key registry decides the active key on every issuance and re-checks it before signing. The log is
/// verified from genesis against the trust file and the PostgreSQL anchor on every decision, so a rotation or revocation
/// takes effect without a restart, and a rolled-back or substituted registry is refused. The seed for each key is read
/// from `<seeds_dir>/<kid>.seed` and must match the public key the verified registry holds for that key id.
#[derive(Debug, Clone)]
enum Mode {
    EnvKey(IssuerConfig),
    Registry(RegistryIssuer),
}

#[derive(Debug, Clone)]
pub struct RegistryIssuer {
    pub registry_path: std::path::PathBuf,
    pub seeds_dir: std::path::PathBuf,
    pub trust: crate::key_registry::TrustConfig,
    pub anchor: crate::key_registry::AnchorSource,
    pub executor_audience: String,
    pub ttl_seconds: i64,
}

static MODE: OnceCell<Option<Mode>> = OnceCell::new();

fn env_value(primary: &str, alias: &str) -> String {
    crate::aigov_env::required(primary, alias)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn read_audience() -> String {
    let audience = env_value("AIGOV_EXECUTOR_AUDIENCE", "GOVAI_EXECUTOR_AUDIENCE");
    if audience.is_empty() {
        "executor".to_string()
    } else {
        audience
    }
}

fn read_ttl() -> Result<i64, String> {
    let ttl = env_value("AIGOV_EXECUTION_AUTH_TTL_SECONDS", "GOVAI_EXECUTION_AUTH_TTL_SECONDS");
    if ttl.is_empty() {
        return Ok(60);
    }
    ttl.parse::<i64>()
        .ok()
        .filter(|t| (1..=3600).contains(t))
        .ok_or_else(|| "GOVAI_EXECUTION_AUTH_TTL_SECONDS must be an integer from 1 to 3600".to_string())
}

/// Issuance settings as read from the environment, before they are checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssuerSettings {
    pub seed_hex: String,
    pub key_id: String,
    pub registry_path: String,
    pub registry_trust_path: String,
    pub registry_anchor_url: String,
    pub seeds_dir: String,
    pub audience: String,
    pub ttl_seconds: i64,
}

impl IssuerSettings {
    fn from_env() -> Result<Self, String> {
        let anchor_url = env_value("AIGOV_KEY_REGISTRY_ANCHOR_URL", "GOVAI_KEY_REGISTRY_ANCHOR_URL");
        let anchor_url = if anchor_url.is_empty() {
            crate::aigov_env::database_url_optional().unwrap_or_default()
        } else {
            anchor_url
        };
        Ok(Self {
            seed_hex: env_value("AIGOV_EXECUTION_AUTH_SIGNING_SEED_HEX", "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX"),
            key_id: env_value("AIGOV_EXECUTION_AUTH_KEY_ID", "GOVAI_EXECUTION_AUTH_KEY_ID"),
            registry_path: env_value("AIGOV_KEY_REGISTRY_PATH", "GOVAI_KEY_REGISTRY_PATH"),
            registry_trust_path: env_value("AIGOV_KEY_REGISTRY_TRUST_FILE", "GOVAI_KEY_REGISTRY_TRUST_FILE"),
            registry_anchor_url: anchor_url,
            seeds_dir: env_value("AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR", "GOVAI_EXECUTION_AUTH_SIGNING_SEEDS_DIR"),
            audience: read_audience(),
            ttl_seconds: read_ttl()?,
        })
    }
}

/// Choose the issuance mode from checked settings. Pure apart from reading the trust file, so the rules are testable.
/// Both a seed and a registry is refused: that would make the signing key ambiguous. Registry mode needs the trust file,
/// the anchor URL, and a seeds directory, and the trust file must load and validate now, not at the first request.
fn mode_from_settings(s: &IssuerSettings) -> Result<Option<Mode>, String> {
    match (!s.seed_hex.is_empty(), !s.registry_path.is_empty()) {
        (true, true) => Err(
            "configure either AIGOV_EXECUTION_AUTH_SIGNING_SEED_HEX or AIGOV_KEY_REGISTRY_PATH, not both".to_string(),
        ),
        (false, false) => Ok(None),
        (true, false) => {
            let bytes = crate::audit_export_signing::parse_seed_hex_strict(&s.seed_hex)?;
            let key_id = match s.key_id.as_str() {
                "" => None,
                id if valid_key_id(id) => Some(id.to_string()),
                _ => {
                    return Err(
                        "GOVAI_EXECUTION_AUTH_KEY_ID must be 1 to 64 characters from A-Z a-z 0-9 . _ -".to_string(),
                    )
                }
            };
            Ok(Some(Mode::EnvKey(IssuerConfig {
                key: crate::audit_export_signing::signing_key_from_seed(&bytes),
                key_id,
                executor_audience: s.audience.clone(),
                ttl_seconds: s.ttl_seconds,
            })))
        }
        (false, true) => {
            if s.seeds_dir.is_empty() {
                return Err(
                    "AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR is required when AIGOV_KEY_REGISTRY_PATH is set".to_string(),
                );
            }
            if s.registry_trust_path.is_empty() {
                return Err("AIGOV_KEY_REGISTRY_TRUST_FILE is required when AIGOV_KEY_REGISTRY_PATH is set".to_string());
            }
            let trust = crate::key_registry::TrustConfig::load(std::path::Path::new(&s.registry_trust_path))?;
            let anchor = crate::key_registry::AnchorSource::postgres(&s.registry_anchor_url, &trust.registry_id)?;
            Ok(Some(Mode::Registry(RegistryIssuer {
                registry_path: s.registry_path.clone().into(),
                seeds_dir: s.seeds_dir.clone().into(),
                trust,
                anchor,
                executor_audience: s.audience.clone(),
                ttl_seconds: s.ttl_seconds,
            })))
        }
    }
}

/// Load issuance settings from the environment. Without a seed or a registry, issuance is disabled and consequential calls
/// are accepted without an authorization (the pre-existing behaviour).
pub fn init_from_env() -> Result<(), String> {
    let mode = mode_from_settings(&IssuerSettings::from_env()?)?;
    let _ = MODE.set(mode);
    Ok(())
}

fn mode() -> Option<&'static Mode> {
    MODE.get().and_then(|m| m.as_ref())
}

/// True when execution authorization is enabled by either mode.
pub fn enabled() -> bool {
    mode().is_some()
}

/// The environment-seed issuer, if that mode is configured.
pub fn issuer() -> Option<&'static IssuerConfig> {
    match mode() {
        Some(Mode::EnvKey(cfg)) => Some(cfg),
        _ => None,
    }
}

/// Identifiers and times fixed before the ledger append, so the accepted record can carry them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub authorization_id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// The registry key chosen for this authorization. `None` in environment-seed mode.
    pub signing_kid: Option<String>,
}

/// The active authorization key in the verified registry.
async fn active_registry_key(r: &RegistryIssuer) -> Result<crate::key_registry::RegistryKey, String> {
    let view = crate::key_registry::load_verified(&r.registry_path, &r.trust, &r.anchor).await?;
    crate::key_registry::active_for(&view, crate::key_registry::PURPOSE_EXECUTION_AUTHORIZATION)
        .cloned()
        .ok_or_else(|| "no active execution authorization key in the trusted key registry".to_string())
}

/// The signing key for `kid`, provided the verified registry still lists it as active and the seed matches its public key.
async fn signing_key_for(r: &RegistryIssuer, kid: &str) -> Result<SigningKey, String> {
    if !valid_key_id(kid) {
        return Err("registry key id is not valid".to_string());
    }
    let view = crate::key_registry::load_verified(&r.registry_path, &r.trust, &r.anchor).await?;
    let rec = view
        .keys
        .get(kid)
        .ok_or_else(|| format!("authorization key {kid} is not in the registry"))?;
    if rec.purpose != crate::key_registry::PURPOSE_EXECUTION_AUTHORIZATION {
        return Err(format!("key {kid} is not an execution authorization key"));
    }
    if rec.status != "active" {
        return Err(format!("authorization key {kid} is {}", rec.status));
    }
    let path = r.seeds_dir.join(format!("{kid}.seed"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map_err(|_| format!("seed file for {kid} is missing"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!("seed file for {kid} must be readable only by its owner"));
        }
    }
    // The operator tool (`aigov_py.trusted.keys.new_signing_seed`) writes seeds as base64 of the 32-byte Ed25519 seed.
    let text = std::fs::read_to_string(&path).map_err(|_| format!("seed file for {kid} is unreadable"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| format!("seed for {kid} is not base64"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("seed for {kid} must be 32 bytes"))?;
    let key = crate::audit_export_signing::signing_key_from_seed(&bytes);
    let derived = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    if derived != rec.public_key_b64 {
        return Err(format!("seed for {kid} does not match the registry public key"));
    }
    Ok(key)
}

/// Why Core must not issue an authorization for this consequential call, given the events of its run. `None` when the
/// approval it names is a real, unrevoked, unused `human_approved` with decision `approve` for this same tool call. The
/// reasons are stable codes. Core checks this under the ledger lock, so two calls cannot both use one approval.
pub fn approval_refusal(events: &[crate::schema::EvidenceEvent], call: &crate::schema::EvidenceEvent) -> Option<&'static str> {
    let text = |e: &crate::schema::EvidenceEvent, k: &str| -> String {
        e.payload.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string()
    };
    let want = text(call, "approval_event_id");
    if want.is_empty() {
        return Some("approval_missing");
    }
    let Some(approval) = events
        .iter()
        .find(|e| e.event_type == "human_approved" && e.event_id == want)
    else {
        return Some("approval_not_found");
    };
    if events.iter().any(|e| {
        e.event_type == "human_approval_revoked" && text(e, "approval_event_id") == want
    }) {
        return Some("approval_revoked");
    }
    if text(approval, "decision") != "approve" {
        return Some("approval_not_approved");
    }
    let call_tool_call_id = text(call, "tool_call_id");
    if call_tool_call_id.is_empty() || call_tool_call_id != text(approval, "tool_call_id") {
        return Some("approval_tool_call_mismatch");
    }
    // Only calls consume an approval. A revocation names the approval too, but it does not use it.
    if events.iter().any(|e| {
        e.event_id != call.event_id
            && e.event_type != "human_approval_revoked"
            && text(e, "approval_event_id") == want
    }) {
        return Some("approval_already_consumed");
    }
    None
}

/// Reserve an authorization id and its times before the append. `Ok(None)` when issuance is disabled. An error means
/// issuance is enabled but no usable key exists: the caller refuses the request before anything is appended.
pub async fn prepare(now: chrono::DateTime<chrono::Utc>) -> Result<Option<Prepared>, String> {
    prepare_with(mode(), now).await
}

async fn prepare_with(mode: Option<&Mode>, now: chrono::DateTime<chrono::Utc>) -> Result<Option<Prepared>, String> {
    let (ttl, signing_kid) = match mode {
        None => return Ok(None),
        Some(Mode::EnvKey(cfg)) => (cfg.ttl_seconds, None),
        Some(Mode::Registry(r)) => (r.ttl_seconds, Some(active_registry_key(r).await?.kid)),
    };
    Ok(Some(Prepared {
        authorization_id: format!("auth_{}", uuid::Uuid::new_v4().simple()),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl),
        signing_kid,
    }))
}

/// The call's facts as bound into an authorization.
#[derive(Debug, Clone, Copy)]
pub struct CallBinding<'a> {
    pub run_id: &'a str,
    pub tool_name: &'a str,
    pub args_binding_hash: &'a str,
    pub policy_revision: &'a str,
    pub approval_event_id: &'a str,
    /// Hash of the accepted ledger record for the call.
    pub consequential_record_hash: &'a str,
}

/// Sign the authorization for a call that the ledger has accepted, so the authorization is bound to the ledger entry.
/// In registry mode the registry is verified again and the key re-checked: a revocation or rotation since `prepare`, a
/// rolled-back log, or a log that does not match the anchor refuses the signature.
pub async fn sign_prepared(prepared: &Prepared, call: &CallBinding<'_>) -> Result<Option<SignedAuthorization>, String> {
    sign_prepared_with(mode(), prepared, call).await
}

async fn sign_prepared_with(
    mode: Option<&Mode>,
    prepared: &Prepared,
    call: &CallBinding<'_>,
) -> Result<Option<SignedAuthorization>, String> {
    let build = |audience: &str, key_id: Option<String>| AuthorizationPayload {
        schema: SCHEMA.to_string(),
        authorization_id: prepared.authorization_id.clone(),
        run_id: call.run_id.to_string(),
        tool_name: call.tool_name.to_string(),
        args_binding_hash: call.args_binding_hash.to_string(),
        policy_revision: call.policy_revision.to_string(),
        executor_audience: audience.to_string(),
        approval_event_id: call.approval_event_id.to_string(),
        consequential_record_hash: call.consequential_record_hash.to_string(),
        issued_at_utc: prepared.issued_at.to_rfc3339(),
        expires_at_utc: prepared.expires_at.to_rfc3339(),
        signing_key_id: key_id,
    };
    match mode {
        None => Ok(None),
        Some(Mode::EnvKey(cfg)) => Ok(Some(sign(
            &cfg.key,
            build(&cfg.executor_audience, cfg.key_id.clone()),
        ))),
        Some(Mode::Registry(r)) => {
            let kid = prepared
                .signing_kid
                .clone()
                .ok_or("prepared authorization carries no registry key")?;
            let key = signing_key_for(r, &kid).await?;
            Ok(Some(sign(&key, build(&r.executor_audience, Some(kid)))))
        }
    }
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
            signing_key_id: None,
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

#[cfg(test)]
mod registry_issuance_tests {
    use super::*;
    use crate::key_registry::test_support::{append_event, signed_request, trust_for};
    use crate::key_registry::{events_path_for, AnchorSource, AnchorState, TrustConfig, GENESIS};
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use serde_json::{json, Map, Value};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCES: AtomicU64 = AtomicU64::new(1);

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn pub_b64(k: &SigningKey) -> String {
        STANDARD.encode(k.verifying_key().to_bytes())
    }

    /// A request signed by `signer`, against the version the caller expects. Nonces are unique within the test process.
    fn request(signer: &SigningKey, actor: &str, op: &str, expected: u64, fields: Value) -> Value {
        let mut p = Map::new();
        p.insert("op".into(), json!(op));
        p.insert("actor".into(), json!(actor));
        p.insert("expected_version".into(), json!(expected));
        p.insert("nonce".into(), json!(format!("nonce-{:016}", NONCES.fetch_add(1, Ordering::SeqCst))));
        p.insert("issued_at_utc".into(), json!(chrono::Utc::now().to_rfc3339()));
        for (k, v) in fields.as_object().unwrap() {
            p.insert(k.clone(), v.clone());
        }
        signed_request(signer, p)
    }

    fn events_of(snapshot: &Path) -> Vec<Value> {
        std::fs::read_to_string(events_path_for(snapshot))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn set_anchor(anchor: &AnchorSource, state: Option<AnchorState>) {
        if let AnchorSource::Memory(m) = anchor {
            *m.lock().unwrap() = state;
        }
    }

    /// The anchor records the log as it is now (what a successful commit does).
    fn anchor_to_log(snapshot: &Path, anchor: &AnchorSource) {
        let events = events_of(snapshot);
        let head = events.last().map(|e| e["hash"].as_str().unwrap().to_string()).unwrap_or_else(|| GENESIS.into());
        set_anchor(anchor, Some(AnchorState { seq: events.len() as u64, head_hash: head }));
    }

    /// Append a request and anchor the result, as a successful Python writer does.
    fn commit(w: &World, req: Value) {
        append_event(&w.snap, req);
        anchor_to_log(&w.snap, &w.anchor);
    }

    struct World {
        _dir: tempfile::TempDir,
        snap: PathBuf,
        seeds: PathBuf,
        root: SigningKey,
        trust: TrustConfig,
        anchor: AnchorSource,
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("registry.json");
        let seeds = dir.path().join("seeds");
        std::fs::create_dir_all(&seeds).unwrap();
        let root = key(1);
        let trust = trust_for("root-a", &root);
        let anchor = AnchorSource::memory(Some(AnchorState { seq: 0, head_hash: GENESIS.into() }));
        World { _dir: dir, snap, seeds, root, trust, anchor }
    }

    fn write_seed_text(seeds: &Path, kid: &str, text: &str, mode: u32) {
        let path = seeds.join(format!("{kid}.seed"));
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    fn write_seed(seeds: &Path, kid: &str, k: &SigningKey) {
        write_seed_text(seeds, kid, &STANDARD.encode(k.to_bytes()), 0o600);
    }

    /// The root installs the operator, which then registers and activates a key for the purpose.
    fn install_operator(w: &World, op: &SigningKey) {
        let n = events_of(&w.snap).len() as u64;
        commit(w, request(&w.root, "root-a", "operator_install", n, json!({
            "identity": "ops-admin", "public_key_b64": pub_b64(op), "roles": ["keyadmin", "revoker"]})));
    }

    fn register_active(w: &World, op: &SigningKey, kid: &str, k: &SigningKey) {
        let n = events_of(&w.snap).len() as u64;
        commit(w, request(op, "ops-admin", "register", n, json!({
            "kid": kid, "purpose": "execution_authorization", "public_key_b64": pub_b64(k), "owner": "authz"})));
        let n = events_of(&w.snap).len() as u64;
        commit(w, request(op, "ops-admin", "activate", n, json!({"kid": kid})));
        write_seed(&w.seeds, kid, k);
    }

    fn issuer(w: &World) -> Mode {
        Mode::Registry(RegistryIssuer {
            registry_path: w.snap.clone(),
            seeds_dir: w.seeds.clone(),
            trust: w.trust.clone(),
            anchor: w.anchor.clone(),
            executor_audience: "executor".into(),
            ttl_seconds: 60,
        })
    }

    fn prepared_stub() -> Prepared {
        Prepared {
            authorization_id: "auth_test".into(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
            signing_kid: Some("exe-k1".into()),
        }
    }

    fn call(hash: &str) -> CallBinding<'_> {
        CallBinding {
            run_id: "run-1",
            tool_name: "refund",
            args_binding_hash: "a",
            policy_revision: "rev-1",
            approval_event_id: "human_approved-1",
            consequential_record_hash: hash,
        }
    }

    #[tokio::test]
    async fn the_active_key_signs_and_its_signature_verifies_under_the_registry_key() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().expect("issuance enabled");
        assert_eq!(p.signing_kid.as_deref(), Some("exe-k1"));
        let signed = sign_prepared_with(Some(&m), &p, &call(&"b".repeat(64))).await.unwrap().expect("signed");
        assert_eq!(signed.payload.signing_key_id.as_deref(), Some("exe-k1"));
        let v = VerifyingKey::from_bytes(&k1.verifying_key().to_bytes()).unwrap();
        assert!(verify_signature(&v, &signed).is_ok());
    }

    #[tokio::test]
    async fn rotation_between_prepare_and_sign_refuses_the_retired_key_and_the_successor_signs() {
        let w = world();
        let (op, k1, k2) = (key(2), key(3), key(4));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        write_seed(&w.seeds, "exe-k2", &k2);
        let n = events_of(&w.snap).len() as u64;
        commit(&w, request(&op, "ops-admin", "register", n, json!({
            "kid": "exe-k2", "purpose": "execution_authorization", "public_key_b64": pub_b64(&k2), "owner": "authz"})));
        let m = issuer(&w);
        let old = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let n = events_of(&w.snap).len() as u64;
        commit(&w, request(&op, "ops-admin", "rotate", n, json!({"kid": "exe-k1", "successor_kid": "exe-k2"})));
        let err = sign_prepared_with(Some(&m), &old, &call(&"c".repeat(64))).await.unwrap_err();
        assert!(err.contains("retired"), "{err}");
        let new = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        assert_eq!(new.signing_kid.as_deref(), Some("exe-k2"));
        let signed = sign_prepared_with(Some(&m), &new, &call(&"c".repeat(64))).await.unwrap().unwrap();
        assert_eq!(signed.payload.signing_key_id.as_deref(), Some("exe-k2"));
    }

    #[tokio::test]
    async fn revocation_between_prepare_and_sign_refuses_the_signature() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let n = events_of(&w.snap).len() as u64;
        commit(&w, request(&op, "ops-admin", "revoke", n, json!({
            "kid": "exe-k1", "reason": "exposed", "compromised_from_utc": "2026-11-26T00:00:00+00:00"})));
        let err = sign_prepared_with(Some(&m), &p, &call(&"d".repeat(64))).await.unwrap_err();
        assert!(err.contains("revoked"), "{err}");
    }

    #[tokio::test]
    async fn with_no_active_key_core_refuses_before_anything_is_appended() {
        let w = world();
        install_operator(&w, &key(2));
        let m = issuer(&w);
        let err = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap_err();
        assert!(err.contains("no active execution authorization key"), "{err}");
    }

    #[tokio::test]
    async fn an_active_key_without_its_seed_file_refuses_the_signature() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        std::fs::remove_file(w.seeds.join("exe-k1.seed")).unwrap();
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let err = sign_prepared_with(Some(&m), &p, &call(&"e".repeat(64))).await.unwrap_err();
        assert!(err.contains("seed file for exe-k1 is missing"), "{err}");
    }

    #[tokio::test]
    async fn a_seed_that_does_not_match_the_registry_key_is_refused() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        write_seed(&w.seeds, "exe-k1", &key(9));
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let err = sign_prepared_with(Some(&m), &p, &call(&"f".repeat(64))).await.unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_seed_readable_by_other_users_is_refused() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        write_seed_text(&w.seeds, "exe-k1", &STANDARD.encode(k1.to_bytes()), 0o644);
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let err = sign_prepared_with(Some(&m), &p, &call(&"g".repeat(64))).await.unwrap_err();
        assert!(err.contains("owner"), "{err}");
    }

    #[tokio::test]
    async fn a_hex_seed_file_is_refused_because_the_operator_format_is_base64() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        write_seed_text(&w.seeds, "exe-k1", &hex::encode(k1.to_bytes()), 0o600);
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let err = sign_prepared_with(Some(&m), &p, &call(&"h".repeat(64))).await.unwrap_err();
        assert!(err.contains("must be 32 bytes"), "{err}");
    }

    #[tokio::test]
    async fn a_seed_written_by_the_python_operator_tool_signs_under_its_registry_key() {
        // Seed and public key from `aigov_py.trusted.keys.new_signing_seed()`: the cross-language seed format.
        let seed_b64 = "j+FLD+n3Bk33xM/eBOK2jDgmw66Sm5gEIHSzcnVk3Zc=";
        let pub_b64 = "yRdGm2ydP9LemYP/xO2gGmdsR6zoC8+GkNfC5Hlx8HM=";
        let w = world();
        let op = key(2);
        install_operator(&w, &op);
        let n = events_of(&w.snap).len() as u64;
        commit(&w, request(&op, "ops-admin", "register", n, json!({
            "kid": "exe-py", "purpose": "execution_authorization", "public_key_b64": pub_b64, "owner": "authz"})));
        let n = events_of(&w.snap).len() as u64;
        commit(&w, request(&op, "ops-admin", "activate", n, json!({"kid": "exe-py"})));
        write_seed_text(&w.seeds, "exe-py", seed_b64, 0o600);
        let m = issuer(&w);
        let p = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap().unwrap();
        let signed = sign_prepared_with(Some(&m), &p, &call(&"a".repeat(64))).await.unwrap().unwrap();
        let pk: [u8; 32] = STANDARD.decode(pub_b64).unwrap().try_into().unwrap();
        assert!(verify_signature(&VerifyingKey::from_bytes(&pk).unwrap(), &signed).is_ok());
    }

    #[tokio::test]
    async fn a_rolled_back_log_is_refused_while_the_anchor_remembers_the_later_state() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        let before_revoke = events_of(&w.snap);
        let n = before_revoke.len() as u64;
        commit(&w, request(&op, "ops-admin", "revoke", n, json!({
            "kid": "exe-k1", "reason": "exposed", "compromised_from_utc": "2026-11-26T00:00:00+00:00"})));
        // The writer restores the earlier log, so the revocation is gone from the file.
        let text: String = before_revoke.iter().map(|e| format!("{}\n", serde_json::to_string(e).unwrap())).collect();
        std::fs::write(events_path_for(&w.snap), text).unwrap();
        let m = issuer(&w);
        let err = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap_err();
        assert!(err.starts_with("anchor_log_behind"), "{err}");
    }

    #[tokio::test]
    async fn a_substituted_log_with_a_different_head_is_refused() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        // Another registry, with its own root and its own key, built the same way.
        let other = world();
        let other_root = key(7);
        let other_trust = trust_for("root-a", &other_root);
        let _ = other_trust;
        install_operator(&other, &key(8));
        register_active(&other, &key(8), "exe-evil", &key(9));
        std::fs::copy(events_path_for(&other.snap), events_path_for(&w.snap)).unwrap();
        let m = issuer(&w);
        let err = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap_err();
        assert!(err.starts_with("anchor_head_mismatch") || err.starts_with("root_not_authorized"), "{err}");
    }

    #[tokio::test]
    async fn an_event_appended_but_not_anchored_is_refused_until_reconciled() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        // A crash between the append and the anchor commit: the log is one event ahead of the anchor.
        let n = events_of(&w.snap).len() as u64;
        append_event(&w.snap, request(&op, "ops-admin", "revoke", n, json!({
            "kid": "exe-k1", "reason": "exposed", "compromised_from_utc": "2026-11-26T00:00:00+00:00"})));
        let m = issuer(&w);
        let err = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap_err();
        assert!(err.starts_with("anchor_log_ahead"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_anchor_refuses_every_decision() {
        let w = world();
        let (op, k1) = (key(2), key(3));
        install_operator(&w, &op);
        register_active(&w, &op, "exe-k1", &k1);
        set_anchor(&w.anchor, None);
        let m = issuer(&w);
        let err = prepare_with(Some(&m), chrono::Utc::now()).await.unwrap_err();
        assert!(err.starts_with("anchor_missing"), "{err}");
    }

    #[tokio::test]
    async fn with_issuance_disabled_nothing_is_reserved_or_signed() {
        let p = prepared_stub();
        assert!(prepare_with(None, chrono::Utc::now()).await.unwrap().is_none());
        assert!(sign_prepared_with(None, &p, &call(&"f".repeat(64))).await.unwrap().is_none());
    }

    #[test]
    fn settings_with_neither_seed_nor_registry_disable_issuance() {
        assert!(matches!(mode_from_settings(&IssuerSettings::default()), Ok(None)));
    }

    #[test]
    fn settings_with_both_a_seed_and_a_registry_are_refused() {
        let s = IssuerSettings {
            seed_hex: hex::encode([11u8; 32]),
            registry_path: "/tmp/registry.json".into(),
            seeds_dir: "/tmp/seeds".into(),
            audience: "executor".into(),
            ttl_seconds: 60,
            ..Default::default()
        };
        assert!(mode_from_settings(&s).unwrap_err().contains("not both"));
    }

    #[test]
    fn a_registry_without_a_seeds_directory_is_refused() {
        let s = IssuerSettings { registry_path: "/tmp/registry.json".into(), audience: "executor".into(), ttl_seconds: 60, ..Default::default() };
        assert!(mode_from_settings(&s).unwrap_err().contains("SEEDS_DIR is required"));
    }

    #[test]
    fn a_registry_without_a_trust_file_is_refused() {
        let s = IssuerSettings {
            registry_path: "/tmp/registry.json".into(),
            seeds_dir: "/tmp/seeds".into(),
            audience: "executor".into(),
            ttl_seconds: 60,
            ..Default::default()
        };
        assert!(mode_from_settings(&s).unwrap_err().contains("TRUST_FILE is required"));
    }

    #[test]
    fn a_trust_file_readable_by_others_is_refused_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let trust = dir.path().join("trust.json");
        let doc = json!({"schema": "govai.key_registry_trust.v1", "registry_id": "r",
            "roots": [{"kid": "root-a", "public_key_b64": pub_b64(&key(1)), "status": "current"}]});
        write_seed_text_path(&trust, &doc.to_string(), 0o644);
        let s = IssuerSettings {
            registry_path: "/tmp/registry.json".into(),
            registry_trust_path: trust.to_string_lossy().into(),
            registry_anchor_url: "postgresql://localhost/none".into(),
            seeds_dir: "/tmp/seeds".into(),
            audience: "executor".into(),
            ttl_seconds: 60,
            ..Default::default()
        };
        assert!(mode_from_settings(&s).unwrap_err().contains("trust_config_permissions"));
    }

    fn write_seed_text_path(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn seed_settings_with_an_invalid_key_id_are_refused_and_valid_ones_select_env_mode() {
        let base = IssuerSettings { seed_hex: hex::encode([12u8; 32]), audience: "executor".into(), ttl_seconds: 60, ..Default::default() };
        assert!(mode_from_settings(&IssuerSettings { key_id: "bad id!".into(), ..base.clone() }).unwrap_err().contains("KEY_ID"));
        assert!(matches!(mode_from_settings(&IssuerSettings { key_id: "exe-k1".into(), ..base }), Ok(Some(Mode::EnvKey(_)))));
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use crate::schema::EvidenceEvent;
    use serde_json::json;

    fn ev(id: &str, ty: &str, payload: Value) -> EvidenceEvent {
        EvidenceEvent {
            event_id: id.into(),
            event_type: ty.into(),
            ts_utc: "2026-11-26T10:00:00Z".into(),
            actor: "test".into(),
            system: "test".into(),
            run_id: "run-1".into(),
            environment: None,
            payload,
            parent_run_id: None,
            root_run_id: None,
            delegated_from_event_id: None,
            agent_id: None,
            agent_role: None,
            delegation_reason: None,
        }
    }

    fn approval(decision: &str, tool_call_id: &str) -> EvidenceEvent {
        ev("appr-1", "human_approved", json!({"decision": decision, "tool_call_id": tool_call_id}))
    }

    fn call(approval_id: &str, tool_call_id: &str) -> EvidenceEvent {
        ev(
            "call-1",
            "consequential_tool_call",
            json!({"tool_name": "create_file", "tool_call_id": tool_call_id, "approval_event_id": approval_id}),
        )
    }

    #[test]
    fn a_real_unused_approval_of_this_call_is_accepted() {
        assert_eq!(approval_refusal(&[approval("approve", "tc-1")], &call("appr-1", "tc-1")), None);
    }

    #[test]
    fn a_missing_or_blank_approval_id_is_refused() {
        assert_eq!(approval_refusal(&[], &call("", "tc-1")), Some("approval_missing"));
        assert_eq!(approval_refusal(&[], &call("   ", "tc-1")), Some("approval_missing"));
    }

    #[test]
    fn an_approval_that_does_not_exist_is_refused() {
        assert_eq!(approval_refusal(&[], &call("appr-1", "tc-1")), Some("approval_not_found"));
        // A different event with the same shape is not an approval.
        let other = ev("appr-1", "tool_call", json!({"decision": "approve", "tool_call_id": "tc-1"}));
        assert_eq!(approval_refusal(&[other], &call("appr-1", "tc-1")), Some("approval_not_found"));
    }

    #[test]
    fn a_rejection_is_not_an_approval() {
        assert_eq!(approval_refusal(&[approval("reject", "tc-1")], &call("appr-1", "tc-1")), Some("approval_not_approved"));
    }

    #[test]
    fn an_approval_for_another_tool_call_is_refused() {
        assert_eq!(
            approval_refusal(&[approval("approve", "tc-other")], &call("appr-1", "tc-1")),
            Some("approval_tool_call_mismatch")
        );
        assert_eq!(approval_refusal(&[approval("approve", "")], &call("appr-1", "")), Some("approval_tool_call_mismatch"));
    }

    #[test]
    fn a_revoked_approval_is_refused() {
        let revoked = ev("rev-1", "human_approval_revoked", json!({"approval_event_id": "appr-1"}));
        assert_eq!(
            approval_refusal(&[approval("approve", "tc-1"), revoked], &call("appr-1", "tc-1")),
            Some("approval_revoked")
        );
    }

    #[test]
    fn an_approval_already_used_by_another_call_is_refused() {
        let earlier = ev("call-0", "consequential_tool_call", json!({"approval_event_id": "appr-1", "tool_call_id": "tc-1"}));
        assert_eq!(
            approval_refusal(&[approval("approve", "tc-1"), earlier], &call("appr-1", "tc-1")),
            Some("approval_already_consumed")
        );
    }
}
