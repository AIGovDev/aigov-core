//! Core-side reader for the trusted key registry (format v2, `python/aigov_py/trusted/keys.py`).
//!
//! Core does not write the registry. It reads the event log and verifies it on every decision:
//!
//! - every event's hash, sequence number, and previous hash;
//! - every request's signature, by a root key pinned in the trust file (for root operations) or by an operator in the
//!   log with the needed role (for lifecycle operations), with the expected version and a fresh nonce;
//! - every state transition the lifecycle permits.
//!
//! Then the log must match the independent anchor exactly (`key_registry_anchor` in PostgreSQL): the same number of events
//! and the same head hash. A rolled-back log is shorter than the anchor, a substituted log has a different head, and an
//! unreconciled write is longer. All three are refused. Nothing in the registry's snapshot file is read.
//!
//! The canonical JSON and the hash match Python exactly. The cross-language fixture test enforces this.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const PURPOSE_EXECUTION_AUTHORIZATION: &str = "execution_authorization";
pub const EVENT_SCHEMA: &str = "govai.key_event.v2";
pub const OP_SCHEMA: &str = "govai.key_op.v2";
pub const OP_DOMAIN: &[u8] = b"govai.key_op.v2\0";
pub const TRUST_SCHEMA: &str = "govai.key_registry_trust.v1";
pub const GENESIS: &str = "GENESIS";
const NONCE_MIN_LENGTH: usize = 16;
pub const PROVENANCE_LEGACY_V1: &str = "legacy_v1_unsigned";

const ROOT_OPS: &[&str] = &["legacy_import", "operator_install", "operator_revoke"];
const OPERATOR_ROLES: &[&str] = &["keyadmin", "revoker", "reconciler"];

/// Canonical JSON: object keys sorted at every level, no whitespace, non-ASCII kept as UTF-8.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).expect("string key"), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).expect("scalar json"),
    }
}

/// SHA-256 hex of the canonical body (the event without its `hash` field).
pub fn event_hash(body: &Map<String, Value>) -> String {
    let mut h = Sha256::new();
    h.update(canonical_json(&Value::Object(body.clone())).as_bytes());
    hex::encode(h.finalize())
}

/// The authoritative log next to a registry snapshot: `registry.json` -> `registry.json.events.jsonl`.
pub fn events_path_for(snapshot: &Path) -> PathBuf {
    let mut s = snapshot.as_os_str().to_owned();
    s.push(".events.jsonl");
    PathBuf::from(s)
}

// --- trusted configuration -----------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootKey {
    pub kid: String,
    pub public_key: [u8; 32],
    /// `current`, or `retired` with `retired_after_seq`: a retired root may sign events up to that sequence number.
    pub retired_after_seq: Option<u64>,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustConfig {
    pub registry_id: String,
    pub roots: Vec<RootKey>,
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty() && kid.len() <= 64 && kid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

impl TrustConfig {
    /// Load the trust file. It must be readable only by its owner, like a seed file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path).map_err(|_| "trust_config_missing".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("trust_config_permissions: the trust file must be readable only by its owner".to_string());
            }
        }
        let _ = meta;
        let text = std::fs::read_to_string(path).map_err(|_| "trust_config_missing".to_string())?;
        let doc: Value = serde_json::from_str(&text).map_err(|_| "trust_config_invalid: not JSON".to_string())?;
        Self::from_value(&doc)
    }

    pub fn from_value(doc: &Value) -> Result<Self, String> {
        if doc.get("schema").and_then(Value::as_str) != Some(TRUST_SCHEMA) {
            return Err("trust_config_invalid: schema".to_string());
        }
        let registry_id = doc
            .get("registry_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "trust_config_invalid: registry_id".to_string())?
            .to_string();
        let raw = doc
            .get("roots")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| "trust_config_invalid: roots".to_string())?;
        let mut roots = Vec::new();
        let mut seen = BTreeSet::new();
        for r in raw {
            let kid = r.get("kid").and_then(Value::as_str).unwrap_or("");
            if !valid_kid(kid) || !seen.insert(kid.to_string()) {
                return Err(format!("trust_config_invalid: root kid {kid:?}"));
            }
            let pub_b64 = r.get("public_key_b64").and_then(Value::as_str).unwrap_or("");
            let public_key = decode_key32(pub_b64).ok_or_else(|| format!("trust_config_invalid: root {kid} public key"))?;
            match r.get("status").and_then(Value::as_str) {
                Some("current") => {
                    if r.get("retired_after_seq").is_some() {
                        return Err(format!("trust_config_invalid: current root {kid} has retired_after_seq"));
                    }
                    roots.push(RootKey { kid: kid.into(), public_key, retired_after_seq: None, current: true });
                }
                Some("retired") => {
                    let after = r
                        .get("retired_after_seq")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| format!("trust_config_invalid: retired root {kid} needs retired_after_seq"))?;
                    roots.push(RootKey { kid: kid.into(), public_key, retired_after_seq: Some(after), current: false });
                }
                _ => return Err(format!("trust_config_invalid: root {kid} status")),
            }
        }
        if !roots.iter().any(|r| r.current) {
            return Err("trust_config_invalid: at least one current root is required".to_string());
        }
        Ok(TrustConfig { registry_id, roots })
    }

    fn root(&self, kid: &str) -> Option<&RootKey> {
        self.roots.iter().find(|r| r.kid == kid)
    }

    fn root_may_sign(&self, kid: &str, seq: u64) -> Option<&RootKey> {
        let r = self.root(kid)?;
        if r.current {
            return Some(r);
        }
        match r.retired_after_seq {
            Some(after) if seq <= after => Some(r),
            _ => None,
        }
    }
}

fn decode_key32(b64: &str) -> Option<[u8; 32]> {
    base64::engine::general_purpose::STANDARD.decode(b64).ok()?.try_into().ok()
}

// --- anchor --------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorState {
    pub seq: u64,
    pub head_hash: String,
}

/// Where the anchor is read from. `Postgres` is production; the pool is created on first use, inside a request. `Memory` is
/// for tests and cross-language fixtures.
#[derive(Clone)]
pub enum AnchorSource {
    Postgres { url: String, registry_id: String, pool: Arc<tokio::sync::OnceCell<sqlx::PgPool>> },
    Memory(Arc<Mutex<Option<AnchorState>>>),
}

impl std::fmt::Debug for AnchorSource {
    /// The URL carries credentials, so it is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorSource::Postgres { registry_id, .. } => write!(f, "AnchorSource::Postgres({registry_id}, <url redacted>)"),
            AnchorSource::Memory(_) => write!(f, "AnchorSource::Memory"),
        }
    }
}

impl AnchorSource {
    /// A PostgreSQL anchor. A database that is down refuses decisions (fail closed).
    pub fn postgres(url: &str, registry_id: &str) -> Result<Self, String> {
        if url.trim().is_empty() {
            return Err("anchor_not_configured: a PostgreSQL URL is required for the registry anchor".to_string());
        }
        Ok(AnchorSource::Postgres {
            url: url.to_string(),
            registry_id: registry_id.to_string(),
            pool: Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    pub fn memory(state: Option<AnchorState>) -> Self {
        AnchorSource::Memory(Arc::new(Mutex::new(state)))
    }

    pub async fn current(&self) -> Result<Option<AnchorState>, String> {
        match self {
            AnchorSource::Memory(m) => Ok(m.lock().map_err(|_| "anchor_unavailable".to_string())?.clone()),
            AnchorSource::Postgres { url, registry_id, pool } => {
                let pool = pool
                    .get_or_try_init(|| async {
                        // A short acquire timeout: an unreachable anchor refuses the decision quickly.
                        sqlx::postgres::PgPoolOptions::new()
                            .acquire_timeout(std::time::Duration::from_secs(5))
                            .connect_lazy(url)
                            .map_err(|_| "anchor_unavailable".to_string())
                    })
                    .await?;
                let row: Option<(i64, String)> =
                    sqlx::query_as("SELECT seq, head_hash FROM key_registry_anchor WHERE registry_id = $1")
                        .bind(registry_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(|_| "anchor_unavailable".to_string())?;
                Ok(row.map(|(seq, head_hash)| AnchorState { seq: seq as u64, head_hash }))
            }
        }
    }
}

// --- verification ----------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryKey {
    pub kid: String,
    pub purpose: String,
    pub public_key_b64: String,
    /// `pending`, `active`, `retired`, or `revoked`.
    pub status: String,
    pub provenance: String,
    pub activated_at_utc: Option<String>,
    pub retired_at_utc: Option<String>,
    pub revoked_at_utc: Option<String>,
    pub compromised_from_utc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    pub public_key_b64: String,
    pub roles: Vec<String>,
    pub status: String,
}

/// A log that has been verified from genesis and matches the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryView {
    pub version: u64,
    pub head_hash: String,
    pub keys: BTreeMap<String, RegistryKey>,
    pub operators: BTreeMap<String, Operator>,
}

fn fail(code: &str, detail: impl AsRef<str>) -> String {
    format!("{code}: {}", detail.as_ref())
}

fn str_of<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("missing string field {k}"))
}

/// Verify a whole log (from genesis) without the anchor. Returns the state; the caller checks the anchor.
pub fn verify_log(events: &[Value], trust: &TrustConfig) -> Result<RegistryView, String> {
    let mut keys: BTreeMap<String, RegistryKey> = BTreeMap::new();
    let mut operators: BTreeMap<String, Operator> = BTreeMap::new();
    let mut nonces: BTreeSet<String> = BTreeSet::new();
    let mut prev: Option<String> = None;
    let mut head = GENESIS.to_string();
    for (i, ev) in events.iter().enumerate() {
        let seq = (i + 1) as u64;
        let obj = ev.as_object().ok_or_else(|| fail("event_schema", format!("event {seq}")))?;
        if obj.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA) {
            return Err(fail("event_schema", format!("event {seq}")));
        }
        if obj.get("seq").and_then(Value::as_u64) != Some(seq) {
            return Err(fail("event_sequence_broken", format!("event {seq}")));
        }
        let prev_claimed = obj.get("prev_hash").and_then(Value::as_str).map(str::to_string);
        if prev_claimed != prev {
            return Err(fail("event_chain_broken", format!("event {seq}")));
        }
        let claimed = str_of(ev, "hash")?.to_string();
        let mut body = obj.clone();
        body.remove("hash");
        if event_hash(&body) != claimed {
            return Err(fail("event_altered", format!("event {seq}")));
        }
        let request = obj.get("request").ok_or_else(|| fail("request_missing", format!("event {seq}")))?;
        let payload = request.get("payload").and_then(Value::as_object).ok_or_else(|| fail("request_schema_mismatch", format!("event {seq}")))?;
        if payload.get("schema").and_then(Value::as_str) != Some(OP_SCHEMA) {
            return Err(fail("request_schema_mismatch", format!("event {seq}")));
        }
        let op = payload.get("op").and_then(Value::as_str).unwrap_or("");
        let actor = payload.get("actor").and_then(Value::as_str).ok_or_else(|| fail("signer_missing", format!("event {seq}")))?;
        if payload.get("expected_version").and_then(Value::as_u64) != Some(seq - 1) {
            return Err(fail("expected_version_mismatch", format!("event {seq}")));
        }
        let nonce = payload.get("nonce").and_then(Value::as_str).unwrap_or("");
        if nonce.len() < NONCE_MIN_LENGTH || !nonces.insert(nonce.to_string()) {
            return Err(fail("replayed_nonce", format!("event {seq}")));
        }
        let issued = str_of(&Value::Object(payload.clone()), "issued_at_utc")?.to_string();
        if chrono::DateTime::parse_from_rfc3339(&issued).is_err() {
            return Err(fail("request_time_invalid", format!("event {seq}")));
        }
        if seq == 1 && op != "legacy_import" && op != "operator_install" {
            return Err(fail("genesis_invalid", format!("event {seq}")));
        }
        // Signer and signature.
        let signing_pub: [u8; 32] = if ROOT_OPS.contains(&op) {
            if op == "legacy_import" && seq != 1 {
                return Err(fail("legacy_import_not_first", format!("event {seq}")));
            }
            trust
                .root_may_sign(actor, seq)
                .ok_or_else(|| fail("root_not_authorized", format!("event {seq}: {actor} is not a root for this sequence")))?
                .public_key
        } else {
            let need = operator_role_for(op).ok_or_else(|| fail("unknown_event", format!("event {seq}: {op}")))?;
            let o = operators.get(actor).filter(|o| o.status == "active").ok_or_else(|| {
                fail("operator_not_authorized", format!("event {seq}: unknown or inactive operator"))
            })?;
            if !o.roles.iter().any(|r| r == need) {
                return Err(fail("operator_not_authorized", format!("event {seq}: {actor} lacks role {need}")));
            }
            decode_key32(&o.public_key_b64).ok_or_else(|| fail("operator_key_invalid", format!("event {seq}")))?
        };
        let sig_b64 = request.get("signature").and_then(Value::as_str).unwrap_or("");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|_| fail("request_signature_invalid", format!("event {seq}")))?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| fail("request_signature_invalid", format!("event {seq}")))?;
        let vk = VerifyingKey::from_bytes(&signing_pub).map_err(|_| fail("request_signature_invalid", format!("event {seq}")))?;
        let mut msg = OP_DOMAIN.to_vec();
        msg.extend_from_slice(canonical_json(&Value::Object(payload.clone())).as_bytes());
        vk.verify(&msg, &sig).map_err(|_| fail("request_signature_invalid", format!("event {seq}")))?;
        transition(&mut keys, &mut operators, seq, op, actor, payload, &issued)?;
        prev = Some(claimed.clone());
        head = claimed;
    }
    let version = events.len() as u64;
    Ok(RegistryView { version, head_hash: head, keys, operators })
}

fn operator_role_for(op: &str) -> Option<&'static str> {
    match op {
        "register" | "activate" | "retire" | "rotate" => Some("keyadmin"),
        "revoke" => Some("revoker"),
        _ => None,
    }
}

fn transition(
    keys: &mut BTreeMap<String, RegistryKey>,
    operators: &mut BTreeMap<String, Operator>,
    seq: u64,
    op: &str,
    actor: &str,
    p: &Map<String, Value>,
    ts: &str,
) -> Result<(), String> {
    let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
    let bad = |what: &str| fail("illegal_transition", format!("event {seq}: {what}"));
    match op {
        "legacy_import" => {
            if !keys.is_empty() || !operators.is_empty() {
                return Err(fail("legacy_import_not_empty", format!("event {seq}")));
            }
            if let Some(ops) = p.get("operators").and_then(Value::as_object) {
                for (id, rec) in ops {
                    let roles = rec.get("roles").and_then(Value::as_array).map(|a| {
                        a.iter().filter_map(|r| r.as_str().map(str::to_string)).collect::<Vec<_>>()
                    }).unwrap_or_default();
                    operators.insert(
                        id.clone(),
                        Operator {
                            public_key_b64: rec.get("public_key_b64").and_then(Value::as_str).unwrap_or("").to_string(),
                            roles,
                            status: "active".into(),
                        },
                    );
                }
            }
            if let Some(ks) = p.get("keys").and_then(Value::as_object) {
                for (kid, rec) in ks {
                    let g = |k: &str| rec.get(k).and_then(Value::as_str).map(str::to_string);
                    keys.insert(
                        kid.clone(),
                        RegistryKey {
                            kid: kid.clone(),
                            purpose: g("purpose").unwrap_or_default(),
                            public_key_b64: g("public_key_b64").unwrap_or_default(),
                            status: g("status").unwrap_or_default(),
                            provenance: PROVENANCE_LEGACY_V1.into(),
                            activated_at_utc: g("activated_at_utc"),
                            retired_at_utc: g("retired_at_utc"),
                            revoked_at_utc: g("revoked_at_utc"),
                            compromised_from_utc: g("compromised_from_utc"),
                        },
                    );
                }
            }
        }
        "operator_install" => {
            let identity = s("identity").unwrap_or_default();
            if operators.contains_key(&identity) || identity.is_empty() {
                return Err(bad("operator identity exists or is empty"));
            }
            let roles: Vec<String> = p
                .get("roles")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|r| r.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            if roles.is_empty() || roles.iter().any(|r| !OPERATOR_ROLES.contains(&r.as_str())) {
                return Err(bad("operator roles invalid"));
            }
            let pubk = s("public_key_b64").unwrap_or_default();
            if decode_key32(&pubk).is_none() {
                return Err(bad("operator key invalid"));
            }
            operators.insert(identity, Operator { public_key_b64: pubk, roles, status: "active".into() });
        }
        "operator_revoke" => {
            let identity = s("identity").unwrap_or_default();
            match operators.get_mut(&identity) {
                Some(o) if o.status == "active" => o.status = "revoked".into(),
                _ => return Err(bad("operator is not active")),
            }
        }
        "register" => {
            let kid = s("kid").unwrap_or_default();
            if !valid_kid(&kid) || keys.contains_key(&kid) {
                return Err(bad("kid invalid or already registered"));
            }
            let purpose = s("purpose").unwrap_or_default();
            let pubk = s("public_key_b64").unwrap_or_default();
            if !matches!(purpose.as_str(), "execution_authorization" | "reconciliation_evidence" | "policy_bundle" | "audit_export")
                || decode_key32(&pubk).is_none()
            {
                return Err(bad("register invalid"));
            }
            keys.insert(
                kid.clone(),
                RegistryKey {
                    kid,
                    purpose,
                    public_key_b64: pubk,
                    status: "pending".into(),
                    provenance: "signed".into(),
                    activated_at_utc: None,
                    retired_at_utc: None,
                    revoked_at_utc: None,
                    compromised_from_utc: None,
                },
            );
        }
        "activate" => {
            let kid = s("kid").unwrap_or_default();
            let purpose = match keys.get(&kid) {
                Some(k) if k.status == "pending" => k.purpose.clone(),
                _ => return Err(bad("activate requires a pending key")),
            };
            if keys.values().any(|k| k.status == "active" && k.purpose == purpose) {
                return Err(bad("a second active key for this purpose"));
            }
            let k = keys.get_mut(&kid).expect("present");
            k.status = "active".into();
            k.activated_at_utc = Some(ts.to_string());
        }
        "retire" => {
            let kid = s("kid").unwrap_or_default();
            match keys.get_mut(&kid) {
                Some(k) if k.status == "active" => {
                    k.status = "retired".into();
                    k.retired_at_utc = Some(ts.to_string());
                }
                _ => return Err(bad("retire requires an active key")),
            }
        }
        "rotate" => {
            let old_kid = s("kid").unwrap_or_default();
            let new_kid = s("successor_kid").unwrap_or_default();
            let old_purpose = match keys.get(&old_kid) {
                Some(k) if k.status == "active" => k.purpose.clone(),
                _ => return Err(bad("rotate: the kid is not the active key")),
            };
            match keys.get(&new_kid) {
                Some(n) if n.status == "pending" && n.purpose == old_purpose => {}
                _ => return Err(bad("rotate: successor must be pending and of the same purpose")),
            }
            {
                let o = keys.get_mut(&old_kid).expect("present");
                o.status = "retired".into();
                o.retired_at_utc = Some(ts.to_string());
            }
            let n = keys.get_mut(&new_kid).expect("present");
            n.status = "active".into();
            n.activated_at_utc = Some(ts.to_string());
        }
        "revoke" => {
            let kid = s("kid").unwrap_or_default();
            let reason = s("reason").unwrap_or_default();
            if reason.is_empty() {
                return Err(bad("revoke requires a reason"));
            }
            match keys.get_mut(&kid) {
                Some(k) if matches!(k.status.as_str(), "pending" | "active" | "retired") => {
                    k.status = "revoked".into();
                    k.revoked_at_utc = Some(ts.to_string());
                    k.compromised_from_utc = Some(s("compromised_from_utc").unwrap_or_else(|| ts.to_string()));
                }
                _ => return Err(bad("revoke from a terminal or unknown key")),
            }
        }
        other => return Err(fail("unknown_event", format!("event {seq}: {other} ({actor})"))),
    }
    Ok(())
}

/// Check that a verified log is exactly the state the anchor records.
pub fn check_anchor(view: &RegistryView, anchor: Option<&AnchorState>, log_len: usize) -> Result<(), String> {
    let a = anchor.ok_or_else(|| fail("anchor_missing", "the registry anchor is not initialized"))?;
    if (log_len as u64) < a.seq {
        return Err(fail("anchor_log_behind", "the log has fewer events than the anchor: rollback or truncation"));
    }
    if (log_len as u64) > a.seq {
        return Err(fail("anchor_log_ahead", "the log has events the anchor does not record: reconcile or investigate"));
    }
    if view.head_hash != a.head_hash {
        return Err(fail("anchor_head_mismatch", "the log head is not the anchored head: substitution"));
    }
    Ok(())
}

/// Read the log, verify it from genesis, and check it against the anchor. The only way Core decides on keys.
///
/// The log and the anchor are read without a lock, so a commit that lands between the two reads looks like a mismatch. A
/// mismatch is retried a few times; the view is accepted only when one attempt sees both agree. A real mismatch still refuses.
pub async fn load_verified(snapshot: &Path, trust: &TrustConfig, anchor: &AnchorSource) -> Result<RegistryView, String> {
    const ATTEMPTS: usize = 5;
    let events_path = events_path_for(snapshot);
    for attempt in 0..ATTEMPTS {
        let last = attempt + 1 == ATTEMPTS;
        let events = match read_events(&events_path) {
            Ok(e) => e,
            Err(e) if e.starts_with("event_unparseable") && !last => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
            Err(e) => return Err(e),
        };
        let view = match verify_log(&events, trust) {
            Ok(v) => v,
            Err(e) if e.starts_with("event_unparseable") && !last => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
            Err(e) => return Err(e),
        };
        let anchored = anchor.current().await?;
        match check_anchor(&view, anchored.as_ref(), events.len()) {
            Ok(()) => return Ok(view),
            Err(e) if (e.starts_with("anchor_log_behind") || e.starts_with("anchor_log_ahead")) && !last => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err("anchor_unavailable: no consistent read".to_string())
}

fn read_events(path: &Path) -> Result<Vec<Value>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("registry log unreadable: {}", e.kind()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| serde_json::from_str(l).map_err(|_| fail("event_unparseable", format!("event {}", i + 1))))
        .collect()
}

/// The single active key for a purpose, if any.
pub fn active_for<'a>(view: &'a RegistryView, purpose: &str) -> Option<&'a RegistryKey> {
    view.keys.values().find(|k| k.status == "active" && k.purpose == purpose)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A signed request, as the Python operator tool produces it: the schema is part of the signed payload.
    pub fn signed_request(seed: &SigningKey, mut payload: Map<String, Value>) -> Value {
        payload.insert("schema".into(), Value::String(OP_SCHEMA.into()));
        let mut msg = OP_DOMAIN.to_vec();
        msg.extend_from_slice(canonical_json(&Value::Object(payload.clone())).as_bytes());
        let sig = seed.sign(&msg);
        serde_json::json!({
            "payload": Value::Object(payload),
            "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        })
    }

    /// Append one event to the log at `snapshot`, with the previous hash computed from the file.
    pub fn append_event(snapshot: &Path, request: Value) {
        let path = events_path_for(snapshot);
        let existing = read_events(&path).unwrap_or_default();
        let seq = existing.len() as u64 + 1;
        let prev = existing.last().map(|e| e["hash"].as_str().unwrap().to_string());
        let mut body = Map::new();
        body.insert("schema".into(), Value::String(EVENT_SCHEMA.into()));
        body.insert("seq".into(), Value::from(seq));
        body.insert("prev_hash".into(), prev.map(Value::String).unwrap_or(Value::Null));
        body.insert("request".into(), request);
        let hash = event_hash(&body);
        body.insert("hash".into(), Value::String(hash));
        let mut out = std::fs::read_to_string(&path).unwrap_or_default();
        out.push_str(&serde_json::to_string(&Value::Object(body)).unwrap());
        out.push('\n');
        std::fs::write(&path, out).unwrap();
    }

    pub fn trust_for(root_kid: &str, root: &SigningKey) -> TrustConfig {
        TrustConfig {
            registry_id: "test-registry".into(),
            roots: vec![RootKey {
                kid: root_kid.into(),
                public_key: root.verifying_key().to_bytes(),
                retired_after_seq: None,
                current: true,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Events written by the Python registry (`aigov_py.trusted.keys`, v2) with its trust file and anchor. The hashes and
    /// signatures were produced by Python, so this fails if Rust canonicalization, hashing, or verification drift.
    const FIXTURE: &str = include_str!("../tests/fixtures/key_registry_v2/registry.json.events.jsonl");
    const TRUST: &str = include_str!("../tests/fixtures/key_registry_v2/trust.json");
    const ANCHOR: &str = include_str!("../tests/fixtures/key_registry_v2/anchor.json");
    const EXPECTED: &str = include_str!("../tests/fixtures/key_registry_v2/expected.json");

    fn fixture_events(text: &str) -> Vec<Value> {
        text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn fixture_anchor() -> AnchorState {
        let a: Value = serde_json::from_str(ANCHOR).unwrap();
        AnchorState { seq: a["seq"].as_u64().unwrap(), head_hash: a["head_hash"].as_str().unwrap().into() }
    }

    #[test]
    fn python_written_log_verifies_and_matches_the_python_expectations() {
        let trust = TrustConfig::from_value(&serde_json::from_str(TRUST).unwrap()).unwrap();
        let events = fixture_events(FIXTURE);
        let view = verify_log(&events, &trust).expect("fixture verifies");
        check_anchor(&view, Some(&fixture_anchor()), events.len()).expect("fixture matches its anchor");
        let expected: Value = serde_json::from_str(EXPECTED).unwrap();
        assert_eq!(view.version, expected["version"].as_u64().unwrap());
        assert_eq!(view.head_hash, expected["head_hash"].as_str().unwrap());
        for (kid, status) in expected["statuses"].as_object().unwrap() {
            assert_eq!(view.keys[kid].status, status.as_str().unwrap(), "status of {kid}");
        }
        let active = active_for(&view, PURPOSE_EXECUTION_AUTHORIZATION).map(|k| k.kid.clone());
        assert_eq!(active.as_deref(), expected["active_execution_key"].as_str());
    }

    #[test]
    fn a_fixture_event_altered_in_any_field_is_refused() {
        let trust = TrustConfig::from_value(&serde_json::from_str(TRUST).unwrap()).unwrap();
        let altered = FIXTURE.replacen("exe-b", "exe-x", 1);
        let err = verify_log(&fixture_events(&altered), &trust).unwrap_err();
        assert!(err.starts_with("event_altered") || err.starts_with("request_signature_invalid"), "{err}");
    }

    #[test]
    fn a_removed_middle_event_breaks_the_chain() {
        let trust = TrustConfig::from_value(&serde_json::from_str(TRUST).unwrap()).unwrap();
        let lines: Vec<&str> = FIXTURE.lines().collect();
        let broken = [lines[0], lines[2], lines[3]].join("\n");
        let err = verify_log(&fixture_events(&broken), &trust).unwrap_err();
        assert!(err.starts_with("event_chain_broken") || err.starts_with("event_sequence_broken"), "{err}");
    }

    #[test]
    fn the_fixture_log_does_not_match_a_rolled_back_anchor() {
        let trust = TrustConfig::from_value(&serde_json::from_str(TRUST).unwrap()).unwrap();
        let events = fixture_events(FIXTURE);
        let view = verify_log(&events, &trust).unwrap();
        // The anchor is one event ahead of the log: the log was truncated.
        let ahead = AnchorState { seq: fixture_anchor().seq + 1, head_hash: fixture_anchor().head_hash };
        let err = check_anchor(&view, Some(&ahead), events.len()).unwrap_err();
        assert!(err.starts_with("anchor_log_behind"), "{err}");
    }

    /// A small registry built with the same signed requests the Python writer produces: root installs an operator, the
    /// operator registers and activates a key. Returns (events, trust, root key, operator key).
    fn small_registry() -> (Vec<Value>, TrustConfig, ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        use ed25519_dalek::SigningKey;
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let op = SigningKey::from_bytes(&[2u8; 32]);
        let exe = SigningKey::from_bytes(&[3u8; 32]);
        let trust = test_support::trust_for("root-a", &root);
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("registry.json");
        let pub_of = |k: &SigningKey| base64::engine::general_purpose::STANDARD.encode(k.verifying_key().to_bytes());
        let mut n = 0u64;
        let mut nonce = || {
            n += 1;
            format!("nonce-{n:016}")
        };
        let mut payload = |op: &str, actor: &str, expected: u64, fields: Value| {
            let mut p = Map::new();
            p.insert("op".into(), Value::String(op.into()));
            p.insert("actor".into(), Value::String(actor.into()));
            p.insert("expected_version".into(), Value::from(expected));
            p.insert("nonce".into(), Value::String(nonce()));
            p.insert("issued_at_utc".into(), Value::String("2026-11-26T10:00:00+00:00".into()));
            for (k, v) in fields.as_object().unwrap() {
                p.insert(k.clone(), v.clone());
            }
            p
        };
        let p = payload("operator_install", "root-a", 0, serde_json::json!({
            "identity": "ops-admin", "public_key_b64": pub_of(&op), "roles": ["keyadmin", "revoker"]}));
        test_support::append_event(&snap, test_support::signed_request(&root, p));
        let p = payload("register", "ops-admin", 1, serde_json::json!({
            "kid": "exe-a", "purpose": "execution_authorization", "public_key_b64": pub_of(&exe), "owner": "authz"}));
        test_support::append_event(&snap, test_support::signed_request(&op, p));
        let p = payload("activate", "ops-admin", 2, serde_json::json!({"kid": "exe-a"}));
        test_support::append_event(&snap, test_support::signed_request(&op, p));
        (events_of(&snap), trust, root, op)
    }

    fn events_of(snap: &Path) -> Vec<Value> {
        read_events(&events_path_for(snap)).unwrap()
    }

    fn refusal(events: &[Value], trust: &TrustConfig) -> String {
        verify_log(events, trust).unwrap_err()
    }

    #[test]
    fn a_key_inserted_without_an_operator_signature_is_refused() {
        use ed25519_dalek::SigningKey;
        let (mut events, trust, _root, _op) = small_registry();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let mut p = Map::new();
        p.insert("op".into(), Value::String("register".into()));
        p.insert("actor".into(), Value::String("ops-admin".into()));
        p.insert("expected_version".into(), Value::from(3u64));
        p.insert("nonce".into(), Value::String("nonce-forged-000001".into()));
        p.insert("issued_at_utc".into(), Value::String("2026-11-26T10:00:00+00:00".into()));
        p.insert("kid".into(), Value::String("exe-evil".into()));
        p.insert("purpose".into(), Value::String("execution_authorization".into()));
        p.insert("public_key_b64".into(), Value::String(base64::engine::general_purpose::STANDARD.encode(attacker.verifying_key().to_bytes())));
        p.insert("owner".into(), Value::String("attacker".into()));
        let forged = test_support::signed_request(&attacker, p);
        // Append the forged event with a correct hash and chain.
        let prev = events.last().unwrap()["hash"].as_str().unwrap().to_string();
        let mut body = Map::new();
        body.insert("schema".into(), Value::String(EVENT_SCHEMA.into()));
        body.insert("seq".into(), Value::from(4u64));
        body.insert("prev_hash".into(), Value::String(prev));
        body.insert("request".into(), forged);
        let hash = event_hash(&body);
        body.insert("hash".into(), Value::String(hash));
        events.push(Value::Object(body));
        assert!(refusal(&events, &trust).starts_with("request_signature_invalid"));
    }

    #[test]
    fn an_operator_cannot_sign_a_root_operation() {
        use ed25519_dalek::SigningKey;
        let (events, trust, _root, op) = small_registry();
        let mut p = Map::new();
        p.insert("op".into(), Value::String("operator_install".into()));
        p.insert("actor".into(), Value::String("root-a".into()));
        p.insert("expected_version".into(), Value::from(3u64));
        p.insert("nonce".into(), Value::String("nonce-root-by-op-0001".into()));
        p.insert("issued_at_utc".into(), Value::String("2026-11-26T10:00:00+00:00".into()));
        p.insert("identity".into(), Value::String("ops-evil".into()));
        p.insert("public_key_b64".into(), Value::String(base64::engine::general_purpose::STANDARD.encode(SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes())));
        p.insert("roles".into(), serde_json::json!(["keyadmin"]));
        let mut events = events;
        let prev = events.last().unwrap()["hash"].as_str().unwrap().to_string();
        let mut body = Map::new();
        body.insert("schema".into(), Value::String(EVENT_SCHEMA.into()));
        body.insert("seq".into(), Value::from(4u64));
        body.insert("prev_hash".into(), Value::String(prev));
        body.insert("request".into(), test_support::signed_request(&op, p));
        let hash = event_hash(&body);
        body.insert("hash".into(), Value::String(hash));
        events.push(Value::Object(body));
        assert!(refusal(&events, &trust).starts_with("request_signature_invalid"));
    }

    #[test]
    fn a_registry_signed_by_a_different_root_is_refused() {
        use ed25519_dalek::SigningKey;
        let (events, _trust, _root, _op) = small_registry();
        let other_root = SigningKey::from_bytes(&[77u8; 32]);
        let pinned = test_support::trust_for("root-a", &other_root);
        assert!(refusal(&events, &pinned).starts_with("request_signature_invalid"));
    }

    #[test]
    fn a_duplicated_event_is_refused_as_a_replay() {
        let (mut events, trust, _root, _op) = small_registry();
        let mut copy = events.last().unwrap().clone();
        // Re-chain the copy so only the replay is wrong.
        let body = {
            let mut b = copy.as_object().unwrap().clone();
            b.remove("hash");
            b.insert("seq".into(), Value::from(4u64));
            b
        };
        let mut body = body;
        body.insert("prev_hash".into(), Value::String(events.last().unwrap()["hash"].as_str().unwrap().into()));
        let hash = event_hash(&body);
        body.insert("hash".into(), Value::String(hash));
        copy = Value::Object(body);
        events.push(copy);
        let err = refusal(&events, &trust);
        assert!(err.starts_with("expected_version_mismatch") || err.starts_with("replayed_nonce"), "{err}");
    }

    #[test]
    fn a_deleted_event_breaks_the_chain() {
        let (mut events, trust, _root, _op) = small_registry();
        events.remove(1);
        let err = refusal(&events, &trust);
        assert!(err.starts_with("event_sequence_broken") || err.starts_with("event_chain_broken"), "{err}");
    }

    #[test]
    fn an_operator_without_the_role_cannot_register() {
        use ed25519_dalek::SigningKey;
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let op = SigningKey::from_bytes(&[2u8; 32]);
        let trust = test_support::trust_for("root-a", &root);
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("registry.json");
        let pub_of = |k: &SigningKey| base64::engine::general_purpose::STANDARD.encode(k.verifying_key().to_bytes());
        let install = serde_json::json!({"op": "operator_install", "actor": "root-a", "expected_version": 0,
            "nonce": "nonce-install-000001", "issued_at_utc": "2026-11-26T10:00:00+00:00",
            "identity": "auditor", "public_key_b64": pub_of(&op), "roles": ["reconciler"]});
        let p = install.as_object().unwrap().clone();
        test_support::append_event(&snap, test_support::signed_request(&root, p));
        let reg = {
            let events = events_of(&snap);
            verify_log(&events, &trust).unwrap()
        };
        assert_eq!(reg.operators["auditor"].roles, vec!["reconciler".to_string()]);
        let reg_events = events_of(&snap);
        let register = serde_json::json!({"op": "register", "actor": "auditor", "expected_version": 1,
            "nonce": "nonce-register-00001", "issued_at_utc": "2026-11-26T10:00:00+00:00",
            "kid": "exe-x", "purpose": "execution_authorization", "public_key_b64": pub_of(&op), "owner": "x"});
        let p = register.as_object().unwrap().clone();
        let mut events = reg_events;
        let prev = events.last().unwrap()["hash"].as_str().unwrap().to_string();
        let mut body = Map::new();
        body.insert("schema".into(), Value::String(EVENT_SCHEMA.into()));
        body.insert("seq".into(), Value::from(2u64));
        body.insert("prev_hash".into(), Value::String(prev));
        body.insert("request".into(), test_support::signed_request(&op, p));
        let hash = event_hash(&body);
        body.insert("hash".into(), Value::String(hash));
        events.push(Value::Object(body));
        assert!(refusal(&events, &trust).starts_with("operator_not_authorized"));
    }

    #[test]
    fn canonical_json_sorts_keys_and_keeps_utf8() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":{"d":"é","c":[2,1]}}"#).unwrap();
        assert_eq!(canonical_json(&v), r#"{"a":{"c":[2,1],"d":"é"},"b":1}"#);
    }

    #[test]
    fn trust_config_refuses_a_root_without_a_retirement_bound_and_no_current_root() {
        let base = serde_json::json!({"schema": TRUST_SCHEMA, "registry_id": "r", "roots": [
            {"kid": "root-a", "public_key_b64": "AAAA", "status": "current"}]});
        assert!(TrustConfig::from_value(&base).is_err(), "a 3-byte key must be refused");
        let retired_only = serde_json::json!({"schema": TRUST_SCHEMA, "registry_id": "r", "roots": [
            {"kid": "root-a", "public_key_b64": base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
             "status": "retired", "retired_after_seq": 3}]});
        assert!(TrustConfig::from_value(&retired_only).unwrap_err().contains("at least one current root"));
    }
}
