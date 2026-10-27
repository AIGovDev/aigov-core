//! Provider-neutral, decision-time model invocation and rationale evidence.
//!
//! These events are preserved in the ordinary append-only event ledger and audit
//! export. They are descriptive evidence, not inputs that cause the governance
//! verdict to change. A provider re-run is therefore never historical replay.

use crate::schema::EvidenceEvent;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const INVOCATION_TYPE: &str = "model_invocation_recorded";
const REASONING_TYPE: &str = "decision_reasoning_recorded";
const LINKS_TYPE: &str = "decision_trace_links_recorded";

pub fn validate_trace_event(event: &EvidenceEvent, prior_events: &[EvidenceEvent]) -> Result<(), String> {
    match event.event_type.as_str() {
        INVOCATION_TYPE => {
            let id = event.payload.get("invocation_id").and_then(Value::as_str).unwrap_or("");
            if prior_events.iter().any(|prior| prior.event_type == INVOCATION_TYPE && prior.payload.get("invocation_id").and_then(Value::as_str) == Some(id)) {
                return Err("invocation_id must be unique within the run".into());
            }
            validate_invocation(&event.payload, prior_events)
        }
        REASONING_TYPE => validate_reasoning(event, prior_events),
        LINKS_TYPE => validate_links(event, prior_events),
        _ => Ok(()),
    }
}

fn validate_links(event: &EvidenceEvent, prior: &[EvidenceEvent]) -> Result<(), String> {
    let p = &event.payload;
    require(p, "schema_version", "aigov.decision_trace_links.v1")?;
    for key in ["run_id", "decision_id", "reasoning_event_id"] { nonempty(p, key)?; }
    if p.get("run_id").and_then(Value::as_str) != Some(event.run_id.as_str()) {
        return Err("payload.run_id must match EvidenceEvent.run_id".into());
    }
    let by_id = |id: &str| prior.iter().find(|ev| ev.event_id == id);
    let reasoning_id = p["reasoning_event_id"].as_str().unwrap_or_default();
    let reasoning = by_id(reasoning_id).ok_or("reasoning_event_id must reference a prior event")?;
    if reasoning.event_type != REASONING_TYPE || reasoning.payload.get("decision_id").and_then(Value::as_str) != p.get("decision_id").and_then(Value::as_str) {
        return Err("reasoning_event_id must reference decision reasoning for this decision".into());
    }
    for field in ["action_event_ids", "human_endorsement_event_ids"] {
        let values = p.get(field).and_then(Value::as_array).ok_or_else(|| format!("{field} must be an array"))?;
        for value in values {
            let id = value.as_str().filter(|v| !v.trim().is_empty()).ok_or_else(|| format!("{field} values must be event ID strings"))?;
            if by_id(id).is_none() { return Err(format!("{field} references missing or not-yet-recorded event_id {id}")); }
        }
    }
    Ok(())
}

fn validate_invocation(p: &Value, prior_events: &[EvidenceEvent]) -> Result<(), String> {
    require(p, "schema_version", "aigov.model_invocation.v1")?;
    nonempty(p, "invocation_id")?;
    if let Some(outcome) = p.get("outcome").and_then(Value::as_str) {
        if !["succeeded", "failed"].contains(&outcome) { return Err("outcome must be succeeded or failed".into()); }
    }
    let provider = p.get("provider").ok_or("provider is required; use explicit unknown values when unavailable")?;
    for key in ["name", "endpoint", "requested_model", "reported_model", "api_version", "backend_fingerprint", "provider_request_id"] {
        nonempty(provider, key).map_err(|_| format!("provider.{key} is required; use 'unknown' when unavailable"))?;
    }
    if let Some(endpoint) = provider.get("endpoint").and_then(Value::as_str) {
        let lower = endpoint.to_ascii_lowercase();
        if ["api_key=", "api-key=", "access_token=", "bearer=", "token=", "secret=", "password=", "?key=", "&key="].iter().any(|needle| lower.contains(needle)) || uri_has_userinfo(endpoint) {
            return Err("provider.endpoint must not include credential-bearing query parameters".into());
        }
    }
    let det = provider.get("determinism").ok_or("provider.determinism is required")?;
    let status = det.get("status").and_then(Value::as_str).unwrap_or("");
    if !["guaranteed", "not_guaranteed", "unknown"].contains(&status) {
        return Err("provider.determinism.status must be guaranteed, not_guaranteed, or unknown".into());
    }
    let determinism_source = det.get("source").and_then(Value::as_str).unwrap_or("");
    if !["provider_reported", "unknown"].contains(&determinism_source) {
        return Err("provider.determinism.source must be provider_reported or unknown".into());
    }
    if determinism_source == "unknown" && status != "unknown" {
        return Err("unknown determinism source requires status=unknown".into());
    }
    if let Some(g) = p.get("generation") {
        if !g.is_object() { return Err("generation must be an object".into()); }
    }
    let capture = p.get("capture").ok_or("capture profile is required")?;
    let profile = capture.get("profile").and_then(Value::as_str).unwrap_or("");
    if !["full", "redacted", "digest_only"].contains(&profile) {
        return Err("capture.profile must be full, redacted, or digest_only".into());
    }
    for direction in ["request", "response"] {
        let artifact = capture.get(direction).ok_or_else(|| format!("capture.{direction} is required"))?;
        validate_artifact(artifact, profile).map_err(|e| format!("capture.{direction}: {e}"))?;
    }
    validate_decision_context(p.get("decision_context"), prior_events)?;
    reject_credentials(p)?;
    Ok(())
}

fn validate_decision_context(context: Option<&Value>, prior_events: &[EvidenceEvent]) -> Result<(), String> {
    let Some(context) = context else { return Ok(()); };
    if !context.is_object() { return Err("decision_context must be an object".into()); }
    for key in ["policy_version", "application_revision", "runtime_version"] {
        if context.get(key).is_some() { nonempty(context, key)?; }
    }
    if let Some(prompt) = context.get("prompt_template") {
        if !prompt.is_object() { return Err("decision_context.prompt_template must be an object".into()); }
        nonempty(prompt, "version")?;
        valid_digest(prompt, "sha256", "decision_context.prompt_template")?;
    }
    if let Some(tools) = context.get("tool_schemas") {
        let tools = tools.as_array().ok_or("decision_context.tool_schemas must be an array")?;
        for (i, tool) in tools.iter().enumerate() {
            nonempty(tool, "name").map_err(|_| format!("decision_context.tool_schemas[{i}].name is required"))?;
            nonempty(tool, "version").map_err(|_| format!("decision_context.tool_schemas[{i}].version is required"))?;
            valid_digest(tool, "sha256", &format!("decision_context.tool_schemas[{i}]"))?;
        }
    }
    if let Some(refs) = context.get("retrieval_snapshot_refs") {
        if !refs.is_array() { return Err("decision_context.retrieval_snapshot_refs must be an array".into()); }
        for (i, item) in refs.as_array().expect("checked").iter().enumerate() {
            if item.get("event_id").and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false) {
                let id = item.get("event_id").and_then(Value::as_str).unwrap_or_default();
                if !prior_events.iter().any(|event| event.event_id == id) {
                    return Err(format!("decision_context.retrieval_snapshot_refs[{i}] references missing event_id {id}"));
                }
                continue;
            }
            let uri = item.get("artifact_ref").and_then(Value::as_str).unwrap_or("");
            if !uri.contains("://") || uri.chars().any(char::is_whitespace) {
                return Err(format!("decision_context.retrieval_snapshot_refs[{i}] needs an event_id or absolute artifact_ref"));
            }
            valid_digest(item, "sha256", &format!("decision_context.retrieval_snapshot_refs[{i}]"))?;
        }
    }
    Ok(())
}

fn valid_digest(value: &Value, key: &str, path: &str) -> Result<(), String> {
    let digest = value.get(key).and_then(Value::as_str).unwrap_or("");
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err(format!("{path}.{key} must be a 64-character hexadecimal SHA-256"))
    } else { Ok(()) }
}

fn validate_artifact(a: &Value, profile: &str) -> Result<(), String> {
    let digest = a.get("sha256").and_then(Value::as_str).unwrap_or("");
    if digest.len() != 64 || !digest.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("sha256 must be 64 hexadecimal characters".into());
    }
    let availability = a.get("availability").and_then(Value::as_str).unwrap_or("");
    if !["retained", "expired", "inaccessible", "unknown"].contains(&availability) {
        return Err("availability must be retained, expired, inaccessible, or unknown".into());
    }
    let has_ref = a.get("artifact_ref").and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false);
    let has_content = a.get("content").is_some();
    match profile {
        "digest_only" => {
            if has_ref || has_content { return Err("digest_only must not include content or an artifact_ref; a digest cannot reconstruct content".into()); }
        }
        "full" | "redacted" => {
            if !has_ref && !has_content { return Err("full/redacted capture needs content or an artifact_ref".into()); }
            if has_ref {
                let reference = a.get("artifact_ref").and_then(Value::as_str).unwrap_or("");
                if !reference.contains("://") || reference.chars().any(char::is_whitespace) {
                    return Err("artifact_ref must be an absolute URI without whitespace".into());
                }
            }
            if profile == "redacted" && a.get("redacted").and_then(Value::as_bool) != Some(true) {
                return Err("redacted capture requires redacted=true".into());
            }
            if has_content {
                let bytes = canonical_json(a.get("content").expect("checked"));
                let actual = format!("{:x}", Sha256::digest(bytes));
                if actual != digest.to_ascii_lowercase() { return Err("content sha256 does not match".into()); }
            }
        }
        _ => unreachable!(),
    }
    if availability != "retained" && profile != "digest_only" && !has_ref {
        return Err("expired/inaccessible artifacts must retain their reference for follow-up".into());
    }
    Ok(())
}

fn validate_reasoning(event: &EvidenceEvent, prior: &[EvidenceEvent]) -> Result<(), String> {
    let p = &event.payload;
    require(p, "schema_version", "aigov.decision_reasoning.v1")?;
    for key in ["run_id", "decision_id", "step_id"] { nonempty(p, key)?; }
    if p.get("run_id").and_then(Value::as_str) != Some(event.run_id.as_str()) {
        return Err("payload.run_id must match EvidenceEvent.run_id".into());
    }
    if !["planning", "evidence_assessment", "policy_application", "action_selection", "other"]
        .contains(&p.get("reasoning_type").and_then(Value::as_str).unwrap_or("")) {
        return Err("reasoning_type is not recognized".into());
    }
    if !["runtime", "model_provided", "human"]
        .contains(&p.get("source").and_then(Value::as_str).unwrap_or("")) {
        return Err("source must be runtime, model_provided, or human".into());
    }
    let state = p.get("rationale_status").and_then(Value::as_str).unwrap_or("");
    if !["available", "unavailable", "unknown"].contains(&state) { return Err("rationale_status must be available, unavailable, or unknown".into()); }
    let rationale = p.get("rationale").and_then(Value::as_str).unwrap_or("");
    if state == "available" && (rationale.trim().is_empty() || rationale.len() > 2000) {
        return Err("available rationale must be non-empty and at most 2000 bytes".into());
    }
    if state != "available" && !rationale.trim().is_empty() { return Err("unavailable/unknown rationale must not fabricate inaccessible reasoning".into()); }
    if p.get("representation").and_then(Value::as_str) != Some("concise_rationale") {
        return Err("representation must be concise_rationale; do not claim hidden chain-of-thought".into());
    }
    for field in ["evidence_refs", "source_event_ids", "claims", "reliance", "action_event_ids", "human_endorsement_event_ids"] {
        if !p.get(field).map(Value::is_array).unwrap_or(false) { return Err(format!("{field} must be an array")); }
    }
    let existing: HashSet<&str> = prior.iter().map(|e| e.event_id.as_str()).collect();
    for field in ["source_event_ids", "action_event_ids", "human_endorsement_event_ids"] {
        if let Some(items) = p.get(field).and_then(Value::as_array) {
            for item in items {
                let id = item.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(|| format!("{field} values must be non-empty event ID strings"))?;
                if !existing.contains(id) { return Err(format!("{field} references missing or not-yet-recorded event_id {id}")); }
            }
        }
    }
    if let Some(refs) = p.get("evidence_refs").and_then(Value::as_array) {
        for (index, reference) in refs.iter().enumerate() {
            if let Some(id) = reference.get("event_id").and_then(Value::as_str) {
                if !existing.contains(id) { return Err(format!("evidence_refs[{index}] references missing event_id {id}")); }
            } else if let Some(uri) = reference.get("artifact_ref").and_then(Value::as_str) {
                if !uri.contains("://") || uri.chars().any(char::is_whitespace) { return Err(format!("evidence_refs[{index}].artifact_ref must be an absolute URI")); }
            } else {
                return Err(format!("evidence_refs[{index}] needs a prior event_id or artifact_ref"));
            }
        }
    }
    if let Some(claims) = p.get("claims").and_then(Value::as_array) {
        for (index, claim) in claims.iter().enumerate() {
            let statement_ok = ["claim", "statement"].iter().any(|key| claim.get(*key).and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false));
            let sources = claim.get("source_event_ids").and_then(Value::as_array).ok_or_else(|| format!("claims[{index}] needs source_event_ids"))?;
            if !statement_ok || sources.is_empty() { return Err(format!("claims[{index}] needs a statement and at least one source event")); }
            for source in sources {
                let id = source.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(|| format!("claims[{index}].source_event_ids values must be event ID strings"))?;
                if !existing.contains(id) { return Err(format!("claims[{index}] references missing source event_id {id}")); }
            }
        }
    }
    if let Some(reliance) = p.get("reliance").and_then(Value::as_array) {
        for (index, item) in reliance.iter().enumerate() {
            let id = item.get("source_event_id").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() || !existing.contains(id) || item.get("use").and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false) == false {
                return Err(format!("reliance[{index}] needs a prior source_event_id and non-empty use"));
            }
        }
    }
    reject_credentials(p)?;
    Ok(())
}

fn reject_credentials(v: &Value) -> Result<(), String> {
    match v {
        Value::Object(map) => for (k, child) in map {
            let key = k.to_ascii_lowercase().replace('-', "_");
            if ["api_key", "apikey", "authorization", "access_token", "refresh_token", "password", "secret", "credential", "bearer_token", "private_key", "cookie"]
                .iter().any(|b| key.contains(b)) {
                return Err(format!("credential-like field '{k}' is prohibited"));
            }
            reject_credentials(child)?;
        },
        Value::Array(items) => for child in items { reject_credentials(child)?; },
        Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            if ["bearer ", "sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "akia", "-----begin private key"]
                .iter().any(|marker| lower.contains(marker)) {
                return Err("credential-like value detected; remove it before evidence capture".into());
            }
            if uri_has_userinfo(s) || uri_has_sensitive_query(s) { return Err("credential-like URI credentials detected; remove them before evidence capture".into()); }
        }
        _ => {}
    }
    Ok(())
}

fn uri_has_userinfo(value: &str) -> bool {
    value.split_once("://").map(|(_, rest)| {
        let authority = rest.split(|ch| matches!(ch, '/' | '?' | '#')).next().unwrap_or("");
        authority.contains('@')
    }).unwrap_or(false)
}

fn uri_has_sensitive_query(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["?api_key=", "&api_key=", "?api-key=", "&api-key=", "?access_token=", "&access_token=", "?token=", "&token=", "?secret=", "&secret=", "?password=", "&password=", "?key=", "&key="]
        .iter().any(|marker| lower.contains(marker))
}

fn require(p: &Value, key: &str, expected: &str) -> Result<(), String> {
    if p.get(key).and_then(Value::as_str) == Some(expected) { Ok(()) } else { Err(format!("{key} must be {expected}")) }
}
fn nonempty(p: &Value, key: &str) -> Result<(), String> {
    if p.get(key).and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false) { Ok(()) } else { Err(format!("{key} is required and must be a non-empty string")) }
}
fn canonical_json(v: &Value) -> Vec<u8> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => { let mut keys: Vec<_> = m.keys().collect(); keys.sort(); let mut out = serde_json::Map::new(); for k in keys { out.insert(k.clone(), sort(&m[k])); } Value::Object(out) }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sort(v)).expect("JSON value serialization")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn validate_invocation(p: &Value) -> Result<(), String> {
        super::validate_invocation(p, &[])
    }

    fn base(event_type: &str, payload: Value) -> EvidenceEvent {
        EvidenceEvent { event_id:"e1".into(), event_type:event_type.into(), ts_utc:"2026-01-01T00:00:00Z".into(), actor:"test".into(), system:"test".into(), run_id:"r1".into(), environment:None, payload, parent_run_id:None, root_run_id:None, delegated_from_event_id:None, agent_id:None, agent_role:None, delegation_reason:None }
    }
    fn inv(profile:&str) -> Value {
        let content=json!({"messages":[{"role":"user","content":"review"}]});
        let digest=format!("{:x}", Sha256::digest(canonical_json(&content)));
        let artifact=|content:Option<Value>| { let mut a=json!({"sha256":digest,"availability":"retained"}); if let Some(c)=content { a["content"]=c; } else { a["artifact_ref"]="s3://audit/run/request.json".into(); } if profile=="redacted" {a["redacted"]=Value::Bool(true);} if profile=="digest_only" {a.as_object_mut().unwrap().remove("artifact_ref");} a };
        json!({"schema_version":"aigov.model_invocation.v1","invocation_id":"i1","provider":{"name":"example","endpoint":"https://api.example.test/v1/responses","requested_model":"model-x","reported_model":"model-x-2026-10-24","api_version":"2026-10-01","backend_fingerprint":"rev-42","provider_request_id":"req-1","determinism":{"status":"unknown","source":"unknown"}},"generation":{"temperature":0,"seed":7},"capture":{"profile":profile,"request":artifact(if profile=="full" {Some(content.clone())} else {None}),"response":artifact(None)}})
    }
    #[test] fn invocation_capture_profiles_and_unknown_identity_validate() {
        for profile in ["full","redacted","digest_only"] { assert!(validate_invocation(&inv(profile)).is_ok(), "{profile}"); }
        let mut p=inv("digest_only"); p["provider"]["name"]="unknown".into(); p["provider"]["backend_fingerprint"]="unknown".into(); assert!(validate_invocation(&p).is_ok());
        let mut p=inv("digest_only"); p["capture"]["request"]["availability"]="expired".into(); assert!(validate_invocation(&p).is_ok());
    }
    #[test] fn malformed_invocations_missing_identity_refs_secrets_and_tampering_fail() {
        let mut p=inv("full"); p["provider"].as_object_mut().unwrap().remove("name"); assert!(validate_invocation(&p).is_err());
        let mut p=inv("full"); p["capture"]["request"]["content"]["messages"][0]["content"]="changed".into(); assert!(validate_invocation(&p).unwrap_err().contains("sha256"));
        let mut p=inv("digest_only"); p["capture"]["request"]["artifact_ref"]="s3://x".into(); assert!(validate_invocation(&p).unwrap_err().contains("digest_only"));
        let mut p=inv("full"); p["api_key"]="secret".into(); assert!(validate_invocation(&p).unwrap_err().contains("credential"));
        let mut p=inv("full"); p["note"]="Bearer sk-example".into(); assert!(validate_invocation(&p).unwrap_err().contains("credential"));
        let mut p=inv("full"); p["provider"]["endpoint"]="https://user:password@provider.example/v1".into(); assert!(validate_invocation(&p).unwrap_err().contains("credential"));
        let mut p=inv("full"); p["capture"]["request"]["artifact_ref"]="s3://bucket/item?token=do-not-store".into(); assert!(validate_invocation(&p).unwrap_err().contains("credential"));
        let mut p=inv("full"); p["capture"]["response"].as_object_mut().unwrap().remove("artifact_ref"); assert!(validate_invocation(&p).unwrap_err().contains("content or an artifact_ref"));
        let mut p=inv("full"); p["capture"]["response"]["artifact_ref"]="relative/object".into(); assert!(validate_invocation(&p).unwrap_err().contains("absolute URI"));
        let mut p=inv("full"); p["capture"]["response"]["availability"]="expired".into(); assert!(validate_invocation(&p).is_ok());
    }
    #[test] fn duplicate_invocation_ids_are_rejected() {
        let event=base(INVOCATION_TYPE,inv("digest_only"));
        let mut prior=event.clone(); prior.event_id="prior".into();
        assert!(validate_trace_event(&event,&[prior]).unwrap_err().contains("unique"));
    }
    #[test] fn decision_context_versions_and_source_refs_are_pinned() {
        let digest = "a".repeat(64);
        let mut payload = inv("digest_only");
        payload["decision_context"] = json!({"prompt_template":{"version":"v3","sha256":digest},"tool_schemas":[{"name":"search","version":"v2","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"retrieval_snapshot_refs":[{"event_id":"retrieval"}],"policy_version":"policy-1","application_revision":"git:abc123","runtime_version":"1.2"});
        let event = base(INVOCATION_TYPE, payload.clone());
        let mut prior = base("retrieval_snapshot", json!({})); prior.event_id = "retrieval".into();
        assert!(validate_trace_event(&event, &[prior.clone()]).is_ok());
        let mut broken = payload.clone(); broken["decision_context"]["prompt_template"]["sha256"] = "bad".into();
        assert!(validate_trace_event(&base(INVOCATION_TYPE, broken), &[prior.clone()]).unwrap_err().contains("SHA-256"));
        let mut missing = payload; missing["decision_context"]["retrieval_snapshot_refs"][0]["event_id"] = "missing".into();
        assert!(validate_trace_event(&base(INVOCATION_TYPE, missing), &[prior]).unwrap_err().contains("missing event_id"));
    }
    #[test] fn reasoning_requires_linked_existing_events_and_truthful_availability() {
        let p=json!({"schema_version":"aigov.decision_reasoning.v1","run_id":"r1","decision_id":"d1","step_id":"s1","reasoning_type":"action_selection","source":"runtime","rationale_status":"available","rationale":"Human approval is required before promotion.","representation":"concise_rationale","evidence_refs":[],"source_event_ids":["prior"],"claims":[{"claim":"approval required","source_event_ids":["prior"]}],"reliance":[],"action_event_ids":[],"human_endorsement_event_ids":[]});
        let mut prior=base("x",json!({})); prior.event_id="prior".into();
        assert!(validate_trace_event(&base(REASONING_TYPE,p.clone()),&[prior.clone()]).is_ok());
        assert!(validate_trace_event(&base(REASONING_TYPE,p.clone()),&[]).unwrap_err().contains("missing or not-yet-recorded"));
        let mut inaccessible=p; inaccessible["rationale_status"]="unknown".into(); inaccessible["rationale"]="fabricated thought".into(); assert!(validate_trace_event(&base(REASONING_TYPE,inaccessible),&[prior]).is_err());
    }
    #[test] fn late_action_and_endorsement_links_are_validated_after_they_exist() {
        let reasoning = base(REASONING_TYPE, json!({"decision_id":"d1"}));
        let action = base("tool_call", json!({}));
        let approval = base("human_approved", json!({}));
        let payload = json!({"schema_version":"aigov.decision_trace_links.v1","run_id":"r1","decision_id":"d1","reasoning_event_id":"e1","action_event_ids":["action"],"human_endorsement_event_ids":["approval"]});
        let event = base(LINKS_TYPE, payload.clone());
        let mut prior = vec![reasoning, action.clone(), approval];
        prior[1].event_id = "action".into(); prior[2].event_id = "approval".into();
        assert!(validate_trace_event(&event, &prior).is_ok());
        let mut broken = payload; broken["action_event_ids"][0] = "future".into();
        assert!(validate_trace_event(&base(LINKS_TYPE, broken), &prior).unwrap_err().contains("not-yet-recorded"));
    }
}
