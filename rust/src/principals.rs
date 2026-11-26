//! Authenticated principals with roles: agent, approver, and executor.
//!
//! `GOVAI_PRINCIPALS_JSON` maps each bearer API key to one principal:
//!
//! ```json
//! {"<key>": {"principal": "agent:release-bot", "identity": "agent:release-bot",
//!            "role": "agent", "tenant": "acme"}}
//! ```
//!
//! When configured, every `POST /evidence` must come from a configured key. Core stamps the
//! authenticated `principal`, `identity`, and `role` into the event payload itself, overwriting anything the
//! client sent. The role decides which event types the principal may post (see [`allowed_event_types`]).
//!
//! Validation at startup refuses: keys that are not also in `GOVAI_API_KEYS`, a principal id or key reused
//! across principals, an approver identity that is also the agent's identity (self-approval by configuration),
//! and unknown roles.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::RwLock;

use once_cell::sync::OnceCell;
use serde::Deserialize;

use crate::govai_environment::GovaiEnvironment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Agent,
    Approver,
    Executor,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Agent => "agent",
            Role::Approver => "approver",
            Role::Executor => "executor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Stable identifier of the credential holder, e.g. `agent:release-bot`.
    pub principal_id: String,
    /// The human or service identity the principal acts as. For approvers this is the name that must
    /// match the `approver` field of an approval.
    pub identity: String,
    pub role: Role,
    pub tenant: String,
}

#[derive(Debug, Deserialize)]
struct RawPrincipal {
    principal: String,
    identity: String,
    role: String,
    tenant: String,
}

/// Event types each role may post to `POST /evidence`. Anything else is refused for that principal.
pub fn allowed_event_types(role: Role) -> &'static [&'static str] {
    match role {
        Role::Agent => &[
            "ai_discovery_reported",
            "tool_call",
            "tool_approval_requested",
            "consequential_tool_call",
            "tool_call_blocked",
        ],
        Role::Approver => &["human_approved", "human_approval_revoked"],
        Role::Executor => &["execution_receipt"],
    }
}

/// Parse and validate the principals document against the bearer allowlist (`GOVAI_API_KEYS`).
pub fn parse_principals(
    raw: &str,
    allowlist: &HashSet<String>,
) -> Result<HashMap<String, Principal>, String> {
    let doc: HashMap<String, RawPrincipal> = serde_json::from_str(raw)
        .map_err(|e| format!("GOVAI_PRINCIPALS_JSON is not valid: {e}"))?;
    let mut out = HashMap::new();
    let mut principal_ids: BTreeSet<String> = BTreeSet::new();
    let mut approver_identities: BTreeSet<String> = BTreeSet::new();
    let mut agent_identities: BTreeSet<String> = BTreeSet::new();
    for (key, raw_p) in doc {
        if key.trim().is_empty() {
            return Err("GOVAI_PRINCIPALS_JSON contains an empty key".to_string());
        }
        if !allowlist.contains(&key) {
            return Err(
                "GOVAI_PRINCIPALS_JSON has a key that is not in GOVAI_API_KEYS".to_string(),
            );
        }
        let role = match raw_p.role.trim() {
            "agent" => Role::Agent,
            "approver" => Role::Approver,
            "executor" => Role::Executor,
            other => return Err(format!("unknown role {other:?} in GOVAI_PRINCIPALS_JSON")),
        };
        let p = raw_p.principal.trim().to_string();
        let identity = raw_p.identity.trim().to_string();
        let tenant = raw_p.tenant.trim().to_string();
        if p.is_empty() || identity.is_empty() || tenant.is_empty() {
            return Err(
                "every principal needs a non-empty principal, identity, and tenant".to_string(),
            );
        }
        if !principal_ids.insert(p.clone()) {
            return Err(format!("principal {p:?} is configured more than once"));
        }
        match role {
            Role::Approver => {
                approver_identities.insert(identity.clone());
            }
            Role::Agent => {
                agent_identities.insert(identity.clone());
            }
            Role::Executor => {}
        }
        out.insert(
            key,
            Principal {
                principal_id: p,
                identity,
                role,
                tenant,
            },
        );
    }
    if let Some(overlap) = approver_identities.intersection(&agent_identities).next() {
        return Err(format!(
            "identity {overlap:?} is configured as both an agent and an approver (self-approval by configuration)"
        ));
    }
    Ok(out)
}

static PRINCIPALS: OnceCell<RwLock<HashMap<String, Principal>>> = OnceCell::new();

/// Load principals from the environment at startup. In staging and production, a missing configuration
/// is allowed only when the execution-authorization layer is also off (see `execution_authorization`).
pub fn init_principals(_deployment_env: GovaiEnvironment) -> Result<(), String> {
    let raw = crate::aigov_env::required("AIGOV_PRINCIPALS_JSON", "GOVAI_PRINCIPALS_JSON")
        .unwrap_or_default();
    let raw = raw.trim();
    let allowlist = crate::audit_api_key::parse_api_keys_allowlist(
        &crate::aigov_env::required("AIGOV_API_KEYS", "GOVAI_API_KEYS").unwrap_or_default(),
    );
    let map = if raw.is_empty() {
        HashMap::new()
    } else {
        parse_principals(raw, &allowlist)?
    };
    let _ = PRINCIPALS.set(RwLock::new(map));
    Ok(())
}

/// True when the principal layer is configured. Ingest then requires an authenticated principal. OIDC counts: with
/// OIDC configured, every authenticated request carries a principal from the explicit OIDC rules.
pub fn principals_configured() -> bool {
    crate::oidc::configured()
        || PRINCIPALS
            .get()
            .and_then(|c| c.read().ok().map(|g| !g.is_empty()))
            .unwrap_or(false)
}

/// The authenticated principal for a request: the one the gate verified from an OIDC token, else the one configured
/// for the API key. A verified OIDC principal is never looked up again as an API key.
pub fn request_principal(
    headers: &axum::http::HeaderMap,
    extensions: &axum::http::Extensions,
) -> Option<Principal> {
    if let Some(crate::oidc::AuthenticatedPrincipal(p)) = extensions.get::<crate::oidc::AuthenticatedPrincipal>() {
        return Some(p.clone());
    }
    crate::audit_api_key::raw_bearer_token(headers).and_then(principal_for_token)
}

/// The principal for a bearer token, if the token is configured.
pub fn principal_for_token(token: &str) -> Option<Principal> {
    PRINCIPALS.get()?.read().ok()?.get(token).cloned()
}

/// Test helper: install principals directly (only the first call takes effect in a process).
#[cfg(test)]
pub fn install_for_tests(map: HashMap<String, Principal>) {
    let _ = PRINCIPALS.set(RwLock::new(map));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }

    const VALID: &str = r#"{
        "k-agent": {"principal": "agent:bot", "identity": "agent:bot", "role": "agent", "tenant": "t"},
        "k-approver": {"principal": "approver:alice", "identity": "alice@x", "role": "approver", "tenant": "t"},
        "k-exec": {"principal": "executor:run", "identity": "executor:run", "role": "executor", "tenant": "t"}
    }"#;

    #[test]
    fn valid_principals_parse_with_roles() {
        let map = parse_principals(VALID, &allow(&["k-agent", "k-approver", "k-exec"])).unwrap();
        assert_eq!(map["k-agent"].role, Role::Agent);
        assert_eq!(map["k-approver"].identity, "alice@x");
        assert_eq!(map["k-exec"].role, Role::Executor);
    }

    #[test]
    fn key_missing_from_the_bearer_allowlist_is_refused() {
        let err = parse_principals(VALID, &allow(&["k-agent", "k-approver"])).unwrap_err();
        assert!(err.contains("not in GOVAI_API_KEYS"), "{err}");
    }

    #[test]
    fn unknown_role_is_refused() {
        let raw = r#"{"k": {"principal": "p", "identity": "i", "role": "admin", "tenant": "t"}}"#;
        let err = parse_principals(raw, &allow(&["k"])).unwrap_err();
        assert!(err.contains("unknown role"), "{err}");
    }

    #[test]
    fn approver_identity_equal_to_agent_identity_is_refused_by_configuration() {
        let raw = r#"{
            "k-agent": {"principal": "agent:bot", "identity": "shared@x", "role": "agent", "tenant": "t"},
            "k-approver": {"principal": "approver:x", "identity": "shared@x", "role": "approver", "tenant": "t"}
        }"#;
        let err = parse_principals(raw, &allow(&["k-agent", "k-approver"])).unwrap_err();
        assert!(err.contains("self-approval"), "{err}");
    }

    #[test]
    fn principal_id_reused_under_two_keys_is_refused() {
        let raw = r#"{
            "k1": {"principal": "same", "identity": "a", "role": "agent", "tenant": "t"},
            "k2": {"principal": "same", "identity": "b", "role": "executor", "tenant": "t"}
        }"#;
        let err = parse_principals(raw, &allow(&["k1", "k2"])).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn roles_allow_only_their_own_event_types() {
        assert!(allowed_event_types(Role::Agent).contains(&"consequential_tool_call"));
        assert!(!allowed_event_types(Role::Agent).contains(&"human_approved"));
        assert!(allowed_event_types(Role::Approver).contains(&"human_approved"));
        assert!(!allowed_event_types(Role::Approver).contains(&"consequential_tool_call"));
        assert!(allowed_event_types(Role::Executor).contains(&"execution_receipt"));
        assert!(!allowed_event_types(Role::Executor).contains(&"human_approved"));
    }
}
