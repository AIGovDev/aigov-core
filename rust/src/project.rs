//! Tenant/project isolation helpers: resolve tenant id and ledger path per request.

use crate::api_usage;
use crate::audit_api_key;
use crate::govai_environment::GovaiEnvironment;
use axum::http::HeaderMap;

const HDR: &str = "x-govai-project";

/// Reads `X-GovAI-Project`; empty or missing → `"default"`.
/// Single entry for billing / `GET /usage` tenant scope: header + bearer (see [`tenant_id_for_usage`]).
pub fn usage_tenant_id(headers: &HeaderMap) -> String {
    tenant_id_for_usage(headers, audit_api_key::raw_bearer_token(headers))
}

/// Stable *project label* for usage / quotas: `X-GovAI-Project` (if set), else API key fingerprint, else `default`.
pub fn tenant_id_for_usage(headers: &HeaderMap, bearer_token: Option<&str>) -> String {
    let raw = headers
        .get(HDR)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if !raw.is_empty() {
        return sanitize_project_segment(raw);
    }
    if let Some(t) = bearer_token {
        let t = t.trim();
        if !t.is_empty() {
            return api_usage::key_fingerprint(t);
        }
    }
    "default".to_string()
}

/// Canonical tenant id for tenant-isolated ledger access (env map only; prefer [`require_tenant_id_for_ledger_async`]).
pub fn require_tenant_id_for_ledger(
    headers: &HeaderMap,
    deployment_env: GovaiEnvironment,
) -> Result<String, String> {
    audit_api_key::require_tenant_id_from_api_key_for_ledger(headers, deployment_env)
}

/// Resolves ledger tenant from env API-key map or DB-issued self-service keys.
pub async fn require_tenant_id_for_ledger_async(
    pool: &crate::db::DbPool,
    headers: &HeaderMap,
    deployment_env: GovaiEnvironment,
) -> Result<String, String> {
    crate::tenant_api_keys::resolve_ledger_tenant_for_bearer(pool, headers, deployment_env).await
}

/// Base ledger file name used for tenant ledgers (`audit_log.jsonl` → `audit_log__<segment>.jsonl`).
pub const TENANT_LEDGER_BASE: &str = "audit_log.jsonl";

/// Env var listing tenants that intentionally keep reading their pre-v2 (lossy) ledger file.
pub const LEGACY_TENANTS_ENV: &str = "AIGOV_LEDGER_LEGACY_TENANTS";

const MAX_IDENTITY_LEN: usize = 128;

/// True when the tenant id is used as its own ledger segment unchanged.
fn is_identity_segment(tenant_id: &str) -> bool {
    !tenant_id.is_empty()
        && tenant_id.len() <= MAX_IDENTITY_LEN
        && tenant_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Injective ledger segment (v2) for a tenant id.
///
/// * Ids made only of `[A-Za-z0-9_-]` (up to 128 characters) map to themselves, so existing
///   ledger files for those tenants keep working.
/// * Every other id maps to `~h` + lowercase hex of its UTF-8 bytes (or `~s` + SHA-256 hex when
///   the hex would be too long). `~` is never produced by the identity rule, so no two distinct
///   ids share a segment. The output contains no `.`, `/` or `\`, so it cannot traverse paths.
pub fn tenant_ledger_segment(tenant_id: &str) -> String {
    if is_identity_segment(tenant_id) {
        return tenant_id.to_string();
    }
    let bytes = tenant_id.as_bytes();
    if bytes.len() <= 100 {
        format!("~h{}", hex_lower(bytes))
    } else {
        use sha2::{Digest, Sha256};
        format!("~s{}", hex_lower(&Sha256::digest(bytes)))
    }
}

/// Pre-v2 segment: lossy character replacement (kept only for explicitly listed legacy tenants).
pub fn tenant_ledger_segment_legacy(tenant_id: &str) -> String {
    sanitize_project_segment(tenant_id)
}

/// Tenants listed in `AIGOV_LEDGER_LEGACY_TENANTS` (comma-separated, trimmed).
pub fn legacy_tenant_ids() -> std::collections::HashSet<String> {
    std::env::var(LEGACY_TENANTS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Segment actually used for a tenant's ledger file.
pub fn ledger_segment_for_tenant(tenant_id: &str) -> String {
    if legacy_tenant_ids().contains(tenant_id) {
        tenant_ledger_segment_legacy(tenant_id)
    } else {
        tenant_ledger_segment(tenant_id)
    }
}

/// Key used to detect collisions on case-insensitive file systems (macOS default).
pub fn segment_collision_key(segment: &str) -> String {
    segment.to_ascii_lowercase()
}

fn sanitize_project_segment(project_id: &str) -> String {
    let s: String = project_id
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .take(128)
        .collect();
    if s.is_empty() {
        "_".to_string()
    } else {
        s
    }
}

/// Directory and file name for a tenant ledger segment (no directory creation).
pub fn ledger_file_for_segment(ledger_base: &str, segment: &str) -> String {
    let stem = ledger_base.strip_suffix(".jsonl").unwrap_or(ledger_base);
    let filename = format!("{}__{}.jsonl", stem, segment);
    let has_parent_dir = std::path::Path::new(ledger_base)
        .parent()
        .is_some_and(|p| !p.as_os_str().is_empty() && p != std::path::Path::new("."));
    if !has_parent_dir {
        if let Ok(dir) = std::env::var("GOVAI_LEDGER_DIR") {
            let dir = dir.trim();
            if !dir.is_empty() {
                return std::path::Path::new(dir).join(filename).to_string_lossy().to_string();
            }
        }
    }
    filename
}

/// Deterministic tenant-scoped ledger path.
///
/// `ledger_base` is e.g. `audit_log.jsonl`. Always returns a tenant-specific `.jsonl` file.
pub fn resolve_ledger_path(ledger_base: &str, tenant_id: &str) -> String {
    ledger_file_for_segment(ledger_base, &ledger_segment_for_tenant(tenant_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn ensure_test_key_map() {
        if crate::audit_api_key::api_key_tenant_map_is_initialized() {
            return;
        }
        std::env::set_var(
            "GOVAI_API_KEYS_JSON",
            r#"{ "mysecret": "team_1", "othersecret": "team_2" }"#,
        );
        // Ignore errors if another test raced to init first.
        let _ = crate::audit_api_key::init_api_key_tenant_map(GovaiEnvironment::Prod);
    }

    /// Bearer token + ledger tenant expected in `GOVAI_API_KEYS_JSON` (works when another test module initialized the map first).
    fn test_api_key_and_ledger_tenant() -> (&'static str, &'static str) {
        if crate::audit_api_key::env_tenant_map_contains_token("mysecret") {
            return ("mysecret", "team_1");
        }
        if crate::audit_api_key::env_tenant_map_contains_token("test-api-key") {
            return ("test-api-key", "team-alpha");
        }
        ensure_test_key_map();
        ("mysecret", "team_1")
    }

    #[test]
    fn usage_tenant_prefers_x_govai_project() {
        let mut h = HeaderMap::new();
        h.insert("x-govai-project", HeaderValue::from_static("team-alpha"));
        assert_eq!(usage_tenant_id(&h), "team-alpha");
    }

    #[test]
    fn usage_tenant_falls_back_to_key_fingerprint() {
        let mut h = HeaderMap::new();
        h.insert("Authorization", HeaderValue::from_static("Bearer test-api-key"));
        let tid = usage_tenant_id(&h);
        assert_ne!(tid, "default");
        assert_eq!(tid, crate::api_usage::key_fingerprint("test-api-key"));
    }

    #[test]
    fn usage_tenant_default_without_header_or_bearer() {
        let h = HeaderMap::new();
        assert_eq!(usage_tenant_id(&h), "default");
    }

    #[test]
    fn require_tenant_id_for_ledger_does_not_trust_x_govai_project_header() {
        let _g = env_lock().lock().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-govai-project", HeaderValue::from_static("team-alpha"));
        ensure_test_key_map();
        let err = require_tenant_id_for_ledger(&h, GovaiEnvironment::Prod).unwrap_err();
        assert_eq!(err, "missing_api_key");
    }

    #[test]
    fn require_tenant_id_for_ledger_uses_api_key_tenant_mapping() {
        let _g = env_lock().lock().unwrap();
        let (token, expected_tenant) = test_api_key_and_ledger_tenant();
        let mut h = HeaderMap::new();
        let auth = format!("Bearer {token}");
        h.insert("Authorization", HeaderValue::from_str(&auth).unwrap());
        let tid = require_tenant_id_for_ledger(&h, GovaiEnvironment::Prod).unwrap();
        assert_eq!(tid, expected_tenant);
    }

    #[test]
    fn require_tenant_id_for_ledger_missing_rejected_in_prod() {
        let _g = env_lock().lock().unwrap();
        ensure_test_key_map();
        let h = HeaderMap::new();
        let err = require_tenant_id_for_ledger(&h, GovaiEnvironment::Prod).unwrap_err();
        assert_eq!(err, "missing_api_key");
    }

    #[test]
    fn ledger_path_is_always_tenant_scoped() {
        assert_eq!(
            resolve_ledger_path("audit_log.jsonl", "default"),
            "audit_log__default.jsonl"
        );
    }

    #[test]
    fn tenant_segments_are_injective_for_adversarial_ids() {
        let long = "x".repeat(129);
        let mut cases: Vec<&str> = vec![
            "team.a", "team_a", "a/b", "a_b", "a\\b", "../x", "x/../y", "café", "cafe\u{301}",
            "Team", "team", "team a", "team\n", "", "~h74", "~h",
        ];
        cases.push(&long);
        let mut seen = std::collections::HashMap::new();
        for id in cases {
            let seg = tenant_ledger_segment(id);
            assert!(!seg.contains('.') && !seg.contains('/') && !seg.contains('\\'), "unsafe segment {seg:?} for {id:?}");
            assert!(!seg.is_empty() && seg.len() <= 120 || seg.starts_with("~s"), "segment length for {id:?}");
            if let Some(prev) = seen.insert(seg.clone(), id) {
                assert_eq!(prev, id, "distinct ids {prev:?} and {id:?} share segment {seg:?}");
            }
        }
    }

    #[test]
    fn dotted_and_underscored_tenants_no_longer_share_a_file() {
        assert_ne!(tenant_ledger_segment("team.a"), tenant_ledger_segment("team_a"));
        assert_ne!(tenant_ledger_segment("a/b"), tenant_ledger_segment("a_b"));
        assert_eq!(tenant_ledger_segment("team_a"), "team_a", "safe ids keep their existing files");
    }

    #[test]
    fn unicode_normalization_variants_stay_distinct() {
        // NFC vs NFD are different byte strings, so they must not collide.
        assert_ne!(tenant_ledger_segment("café"), tenant_ledger_segment("cafe\u{301}"));
    }

    #[test]
    fn case_variants_are_flagged_by_collision_key() {
        assert_eq!(
            segment_collision_key(&tenant_ledger_segment("Team")),
            segment_collision_key(&tenant_ledger_segment("team"))
        );
        assert_ne!(tenant_ledger_segment("Team"), tenant_ledger_segment("team"));
    }

    #[test]
    fn long_ids_do_not_truncate_into_each_other() {
        let a = format!("{}x", "y".repeat(140));
        let b = format!("{}z", "y".repeat(140));
        assert_ne!(tenant_ledger_segment(&a), tenant_ledger_segment(&b));
    }

    #[test]
    fn legacy_segment_is_only_used_for_listed_tenants() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var(LEGACY_TENANTS_ENV);
        assert_eq!(ledger_segment_for_tenant("team.a"), tenant_ledger_segment("team.a"));
        std::env::set_var(LEGACY_TENANTS_ENV, " team.a , other ");
        assert_eq!(ledger_segment_for_tenant("team.a"), "team_a");
        assert_eq!(ledger_segment_for_tenant("team_a"), "team_a");
        std::env::remove_var(LEGACY_TENANTS_ENV);
    }

    /// Shared vectors: the Python mirror (`python/aigov_py/tenant_ledger.py`) asserts the same values.
    #[test]
    fn tenant_segment_vectors_match_python_mirror() {
        assert_eq!(tenant_ledger_segment("team.a"), "~h7465616d2e61");
        assert_eq!(tenant_ledger_segment("team_a"), "team_a");
        assert_eq!(tenant_ledger_segment("a/b"), "~h612f62");
        assert_eq!(tenant_ledger_segment("a_b"), "a_b");
        assert_eq!(tenant_ledger_segment("café"), "~h636166c3a9");
        assert_eq!(tenant_ledger_segment("cafe\u{301}"), "~h63616665cc81");
        assert_eq!(tenant_ledger_segment("Team"), "Team");
        assert_eq!(tenant_ledger_segment("../x"), "~h2e2e2f78");
        assert_eq!(tenant_ledger_segment(""), "~h");
        assert_eq!(tenant_ledger_segment_legacy("team.a"), "team_a");
        assert_eq!(tenant_ledger_segment_legacy("café"), "caf_");
        assert_eq!(tenant_ledger_segment_legacy(""), "_");
    }
}
