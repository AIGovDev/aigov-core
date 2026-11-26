//! Core-side reader for the trusted key registry (`python/aigov_py/trusted/keys.py`).
//!
//! Core does not write the registry; the operator tool does. Core reads the authoritative event log, verifies its hash chain
//! and every lifecycle transition, and derives the status of each key from it. Core never trusts the snapshot file.
//!
//! The canonical JSON and the hash must match the Python implementation exactly: sorted keys, no whitespace, UTF-8 without
//! ASCII escaping, SHA-256 of the body without its `hash` field. A cross-language fixture test enforces this.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const PURPOSE_EXECUTION_AUTHORIZATION: &str = "execution_authorization";
pub const EVENT_SCHEMA: &str = "govai.key_event.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryKey {
    pub kid: String,
    pub purpose: String,
    pub public_key_b64: String,
    /// `pending`, `active`, `retired`, or `revoked`.
    pub status: String,
    pub activated_at_utc: Option<String>,
    pub retired_at_utc: Option<String>,
    pub revoked_at_utc: Option<String>,
    pub compromised_from_utc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryView {
    pub version: u64,
    pub keys: BTreeMap<String, RegistryKey>,
}

/// The authoritative log next to a registry snapshot: `registry.json` -> `registry.json.events.jsonl`.
pub fn events_path_for(snapshot: &Path) -> PathBuf {
    let mut s = snapshot.as_os_str().to_owned();
    s.push(".events.jsonl");
    PathBuf::from(s)
}

/// Canonical JSON: object keys sorted at every level, no whitespace, non-ASCII kept as UTF-8.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("string key"),
                        canonical_json(&map[k])
                    )
                })
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

fn str_field<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("registry event is missing string field {key}"))
}

fn detail_str(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get("detail")
        .and_then(Value::as_object)
        .and_then(|d| d.get(key))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Apply one event with the same transition rules as the Python registry. Any illegal transition is an error.
fn apply(keys: &mut BTreeMap<String, RegistryKey>, obj: &Map<String, Value>) -> Result<(), String> {
    let op = str_field(obj, "op")?;
    let ts = str_field(obj, "ts_utc")?.to_string();
    match op {
        // Operators do not affect which keys sign. Core does not authenticate operator requests.
        "operator_register" => Ok(()),
        "register" => {
            let kid = str_field(obj, "kid")?.to_string();
            if keys.contains_key(&kid) {
                return Err(format!("registry: kid {kid} registered twice"));
            }
            let purpose = detail_str(obj, "purpose").ok_or("registry: register without purpose")?;
            let public_key_b64 =
                detail_str(obj, "public_key_b64").ok_or("registry: register without public key")?;
            keys.insert(
                kid.clone(),
                RegistryKey {
                    kid,
                    purpose,
                    public_key_b64,
                    status: "pending".into(),
                    activated_at_utc: None,
                    retired_at_utc: None,
                    revoked_at_utc: None,
                    compromised_from_utc: None,
                },
            );
            Ok(())
        }
        "activate" => {
            let kid = str_field(obj, "kid")?.to_string();
            let purpose = keys
                .get(&kid)
                .map(|k| k.purpose.clone())
                .ok_or_else(|| format!("registry: activate of unknown kid {kid}"))?;
            let rec = keys.get(&kid).expect("present");
            if rec.status != "pending" {
                return Err(format!("registry: activate {kid} from {}", rec.status));
            }
            if keys
                .values()
                .any(|k| k.status == "active" && k.purpose == purpose)
            {
                return Err(format!("registry: second active {purpose} key"));
            }
            let rec = keys.get_mut(&kid).expect("present");
            rec.status = "active".into();
            rec.activated_at_utc = Some(ts);
            Ok(())
        }
        "retire" => {
            let kid = str_field(obj, "kid")?.to_string();
            let rec = keys
                .get_mut(&kid)
                .ok_or_else(|| format!("registry: retire of unknown kid {kid}"))?;
            if rec.status != "active" {
                return Err(format!("registry: retire {kid} from {}", rec.status));
            }
            rec.status = "retired".into();
            rec.retired_at_utc = Some(ts);
            Ok(())
        }
        "revoke" => {
            let kid = str_field(obj, "kid")?.to_string();
            let rec = keys
                .get_mut(&kid)
                .ok_or_else(|| format!("registry: revoke of unknown kid {kid}"))?;
            if !matches!(rec.status.as_str(), "pending" | "active" | "retired") {
                return Err(format!("registry: revoke {kid} from {}", rec.status));
            }
            rec.status = "revoked".into();
            rec.revoked_at_utc = Some(ts.clone());
            rec.compromised_from_utc =
                Some(detail_str(obj, "compromised_from_utc").unwrap_or(ts));
            Ok(())
        }
        other => Err(format!("registry: unknown event {other}")),
    }
}

/// Load and verify the registry at `snapshot` by replaying its event log. A missing log is an empty registry.
pub fn load(snapshot: &Path) -> Result<RegistryView, String> {
    let events = events_path_for(snapshot);
    let mut view = RegistryView {
        version: 0,
        keys: BTreeMap::new(),
    };
    if !events.exists() {
        return Ok(view);
    }
    let text = std::fs::read_to_string(&events)
        .map_err(|e| format!("registry log unreadable: {}", e.kind()))?;
    let mut prev: Option<String> = None;
    let mut seq: u64 = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        seq += 1;
        let ev: Value =
            serde_json::from_str(line).map_err(|_| format!("registry event {seq} is not JSON"))?;
        let obj = ev
            .as_object()
            .ok_or_else(|| format!("registry event {seq} is not an object"))?;
        if obj.get("seq").and_then(Value::as_u64) != Some(seq) {
            return Err(format!("registry event_sequence_broken at {seq}"));
        }
        let prev_claimed = obj.get("prev_hash").and_then(Value::as_str).map(str::to_string);
        if prev_claimed != prev {
            return Err(format!("registry event_chain_broken at {seq}"));
        }
        let claimed = str_field(obj, "hash")?.to_string();
        let mut body = obj.clone();
        body.remove("hash");
        if event_hash(&body) != claimed {
            return Err(format!("registry event_altered at {seq}"));
        }
        if str_field(obj, "schema")? != EVENT_SCHEMA {
            return Err(format!("registry event {seq} has an unexpected schema"));
        }
        apply(&mut view.keys, obj)?;
        view.version = obj
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("registry event {seq} has no version"))?;
        prev = Some(claimed);
    }
    Ok(view)
}

/// The single active key for a purpose, if any.
pub fn active_for<'a>(view: &'a RegistryView, purpose: &str) -> Option<&'a RegistryKey> {
    view.keys
        .values()
        .find(|k| k.status == "active" && k.purpose == purpose)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Events written by the Python registry (`aigov_py.trusted.keys`), public keys only. The hashes were produced by
    /// Python, so this test fails if the Rust canonicalization or hashing drifts from the Python implementation.
    const FIXTURE: &str = include_str!("../tests/fixtures/key_registry/registry.json.events.jsonl");

    fn load_fixture(text: &str) -> Result<RegistryView, String> {
        let dir = tempfile::tempdir().expect("temp dir");
        let snap = dir.path().join("registry.json");
        std::fs::write(events_path_for(&snap), text).unwrap();
        load(&snap)
    }

    #[test]
    fn python_written_log_verifies_and_yields_the_expected_statuses() {
        let view = load_fixture(FIXTURE).expect("fixture verifies");
        assert_eq!(view.version, 7);
        assert_eq!(view.keys["exe-a"].status, "revoked");
        assert_eq!(view.keys["exe-b"].status, "active");
        assert_eq!(
            active_for(&view, PURPOSE_EXECUTION_AUTHORIZATION).map(|k| k.kid.as_str()),
            Some("exe-b")
        );
    }

    #[test]
    fn an_altered_event_is_refused() {
        let altered = FIXTURE.replacen("exe-b", "exe-x", 1);
        let err = load_fixture(&altered).unwrap_err();
        assert!(err.contains("altered") || err.contains("chain") || err.contains("sequence"), "{err}");
    }

    #[test]
    fn a_removed_middle_event_breaks_the_chain() {
        let lines: Vec<&str> = FIXTURE.lines().collect();
        let broken = [lines[0], lines[2], lines[3]].join("\n");
        let err = load_fixture(&broken).unwrap_err();
        assert!(err.contains("chain") || err.contains("sequence"), "{err}");
    }

    #[test]
    fn canonical_json_sorts_keys_and_keeps_utf8() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":{"d":"é","c":[2,1]}}"#).unwrap();
        assert_eq!(canonical_json(&v), r#"{"a":{"c":[2,1],"d":"é"},"b":1}"#);
    }
}

/// Test helpers that append events in the Python registry's format, so tests can build real registries.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn append(snapshot: &Path, op: &str, kid: &str, purpose: Option<&str>, detail: Value, ts: &str) {
        let path = events_path_for(snapshot);
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = existing.lines().filter(|l| !l.trim().is_empty()).collect();
        let seq = lines.len() as u64 + 1;
        let prev = lines.last().map(|l| {
            let v: Value = serde_json::from_str(l).expect("json");
            v["hash"].as_str().expect("hash").to_string()
        });
        let mut body = Map::new();
        body.insert("schema".into(), Value::String(EVENT_SCHEMA.into()));
        body.insert("seq".into(), Value::from(seq));
        body.insert("version".into(), Value::from(seq));
        body.insert("ts_utc".into(), Value::String(ts.into()));
        body.insert("op".into(), Value::String(op.into()));
        body.insert("kid".into(), Value::String(kid.into()));
        body.insert(
            "purpose".into(),
            purpose.map(|p| Value::String(p.into())).unwrap_or(Value::Null),
        );
        body.insert("actor".into(), Value::String("ops-admin".into()));
        body.insert("group".into(), Value::Null);
        body.insert("nonce".into(), Value::Null);
        body.insert("request_sha256".into(), Value::Null);
        body.insert("detail".into(), detail);
        body.insert("prev_hash".into(), prev.map(Value::String).unwrap_or(Value::Null));
        let hash = event_hash(&body);
        body.insert("hash".into(), Value::String(hash));
        let mut out = existing;
        out.push_str(&serde_json::to_string(&Value::Object(body)).expect("json"));
        out.push('\n');
        std::fs::write(&path, out).expect("write registry log");
    }
}
