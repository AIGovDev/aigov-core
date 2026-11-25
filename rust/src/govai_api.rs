//! Core audit HTTP surface (ledger ingest, bundle, compliance summary, export).

use crate::api_error::{api_error, api_error_with};
use crate::api_usage::ApiUsageState;
use crate::audit_api_key::{
    gate_audit_routes_with_state, validate_api_key_allowlist_consistency, AuditApiKeyConfig,
    AuditKeyGateState, ResolvedLedgerTenant,
};
use crate::audit_export::build_audit_export_v1;
use crate::audit_store::verify_chain;
use crate::bundle::{
    bundle_document_value, bundle_sha256, collect_events_for_run, find_model_artifact_path,
    portable_evidence_digest_v1,
};
use crate::compliance_summary::{
    compliance_summary_error_json, compliance_summary_success_json, derive_verdict_from_state,
};
use crate::db::{self, DbPool};
use crate::govai_environment::{self, GovaiEnvironment};
use crate::http_observability;
use crate::ledger_storage;
use crate::ledger_view::FileLedgerView;
use crate::metering;
use crate::ops_log;
use crate::policy_config::{self, PolicyConfig, PolicySource};
use crate::policy_store::PolicyStore;
use crate::projection::derive_current_state_from_events_with_context;
use crate::project;
use crate::runtime_diagnostics::{self, ProcessStartedAt};
use crate::runtime_metrics;
use crate::schema::EvidenceEvent;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

const LEDGER_STEM: &str = "audit_log.jsonl";

#[derive(Clone)]
pub struct AppState {
    pub deployment_env: GovaiEnvironment,
    pub policy_store: Arc<PolicyStore>,
    pub legacy_policy: PolicyConfig,
    pub policy_source: PolicySource,
    pub pool: DbPool,
    pub usage: ApiUsageState,
    pub api_key_cfg: AuditApiKeyConfig,
    pub base_url: Option<String>,
    pub started_at: ProcessStartedAt,
}

#[derive(Debug, Deserialize)]
struct RunIdQuery {
    run_id: String,
}

async fn pool_from_env() -> Result<DbPool, String> {
    if db::postgres_url_configured_nonempty().is_err() {
        return PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost:5432/govai_unused")
            .map_err(|e| format!("lazy pool: {e}"));
    }
    let pool = db::init_pool_from_env().await?;
    if matches!(
        std::env::var("GOVAI_AUTO_MIGRATE")
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default()
            .as_str(),
        "1" | "true" | "yes" | "on"
    ) {
        db::run_sqlx_migrations(&pool).await?;
    }
    Ok(pool)
}

/// Whether a signed policy bundle is configured for this environment. Mirrors the loader's lookup:
/// `AIGOV_POLICY_BUNDLE_FILE`, then `policy.bundle.<env>.json` or `policy.bundle.json` in `AIGOV_POLICY_DIR`.
pub fn signed_bundle_configured(env: GovaiEnvironment) -> bool {
    let set = |k: &str| {
        std::env::var(k)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    };
    let dir = std::env::var("AIGOV_POLICY_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    set("AIGOV_POLICY_BUNDLE_FILE")
        || dir
            .join(format!("policy.bundle.{}.json", env.as_str()))
            .exists()
        || dir.join("policy.bundle.json").exists()
}

/// Staging and production fail closed on the legacy policy path once a signed bundle is configured.
///
/// Production always requires a signed bundle. Staging requires one only when it is configured, so
/// staging without a bundle keeps its existing (opt-in) behavior. Environment overrides and legacy
/// policy files cannot participate in verdicts when the signed bundle governs.
pub fn enforce_signed_bundle_only(env: GovaiEnvironment) -> Result<(), String> {
    let label = match env {
        GovaiEnvironment::Prod => "production",
        GovaiEnvironment::Staging => "staging",
        GovaiEnvironment::Dev => return Ok(()),
    };
    let set = |k: &str| {
        std::env::var(k)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    };
    if set("AIGOV_POLICY_FILE") {
        return Err(format!(
            "refusing to start: AIGOV_POLICY_FILE is not permitted in {label}; use a signed policy bundle"
        ));
    }
    if std::env::var_os("AIGOV_ALLOW_UNSIGNED_POLICY_FILE").is_some() {
        return Err(format!(
            "refusing to start: AIGOV_ALLOW_UNSIGNED_POLICY_FILE is not permitted in {label}"
        ));
    }
    if set("AIGOV_APPROVER_ALLOWLIST") {
        return Err(format!(
            "refusing to start: AIGOV_APPROVER_ALLOWLIST is not permitted in {label}; express the allowlist in the signed bundle"
        ));
    }
    if matches!(env, GovaiEnvironment::Prod) && !signed_bundle_configured(env) {
        return Err(
            "refusing to start: production requires a signed policy bundle (AIGOV_POLICY_BUNDLE_FILE, or policy.bundle.prod.json / policy.bundle.json in AIGOV_POLICY_DIR)"
                .to_string(),
        );
    }
    Ok(())
}

/// Staging and production must not run verdicts from an unsigned policy *file*.
///
/// Built-in defaults are part of the code and are allowed. A file from `AIGOV_POLICY_FILE` or the
/// environment-named file is refused unless the operator sets `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1`,
/// which prints a warning. Migration: sign the policy as a bundle and load it with
/// `AIGOV_POLICY_BUNDLE_FILE` (see docs/operations/policy-signing.md).
pub fn enforce_policy_file_trust(
    deployment_env: GovaiEnvironment,
    source: &policy_config::PolicySource,
) -> Result<(), String> {
    if matches!(deployment_env, GovaiEnvironment::Dev) {
        return Ok(());
    }
    if matches!(source.kind, policy_config::PolicySourceKind::Defaults) {
        return Ok(());
    }
    let allowed = std::env::var("AIGOV_ALLOW_UNSIGNED_POLICY_FILE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    if allowed {
        eprintln!(
            "warning: running staging/prod verdicts from an unsigned policy file (AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1)"
        );
        return Ok(());
    }
    Err(format!(
        "refusing to start: unsigned policy file ({:?}) in {}; sign the policy as a bundle and set \
         AIGOV_POLICY_BUNDLE_FILE, or set AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1 explicitly",
        source.kind,
        deployment_env.as_str()
    ))
}

pub async fn build_app_state() -> Result<AppState, String> {
    let deployment_env = govai_environment::resolve_from_env()?;
    let bundle_only = match deployment_env {
        GovaiEnvironment::Prod => true,
        GovaiEnvironment::Staging => signed_bundle_configured(deployment_env),
        GovaiEnvironment::Dev => false,
    };
    let resolved = if bundle_only {
        // The verified signed bundle is the only policy source. No legacy file is read.
        enforce_signed_bundle_only(deployment_env)?;
        policy_config::ResolvedPolicyConfig {
            config: policy_config::PolicyConfig::default(),
            source: policy_config::PolicySource {
                kind: policy_config::PolicySourceKind::Defaults,
                path: None,
            },
        }
    } else {
        let resolved = policy_config::load_for_deployment(deployment_env)?;
        enforce_policy_file_trust(deployment_env, &resolved.source)?;
        resolved
    };
    let policy_store = Arc::new(PolicyStore::load_for_deployment(
        deployment_env,
        resolved.clone(),
    )?);
    let _ = ledger_storage::validate_startup(deployment_env)?;
    crate::immutable_store::ImmutableStoreConfig::from_env()?.validate_startup_wiring(deployment_env)?;
    crate::audit_api_key::init_api_key_tenant_map(deployment_env)?;
    validate_api_key_allowlist_consistency(deployment_env)?;
    crate::principals::init_principals(deployment_env)?;
    crate::oidc::init_from_env(deployment_env)?;
    crate::execution_authorization::init_from_env()?;
    if crate::execution_authorization::issuer().is_some()
        && !crate::principals::principals_configured()
    {
        return Err(
            "Invalid configuration: execution authorization requires GOVAI_PRINCIPALS_JSON (separate agent, approver, and executor keys)"
                .to_string(),
        );
    }
    let pool = pool_from_env().await?;
    if crate::db::postgres_url_configured_nonempty().is_ok() {
        crate::tenant_api_keys::check_db_tenants_against_env(&pool).await?;
    }
    let usage = ApiUsageState::from_env(&pool)?;
    let api_key_cfg = AuditApiKeyConfig::from_env();
    let base_url = std::env::var("GOVAI_BASE_URL")
        .or_else(|_| std::env::var("AIGOV_BASE_URL"))
        .ok()
        .filter(|s| !s.trim().is_empty());
    // The policy revision is committed by `crate::run` after the listener is bound, so a bind failure never
    // advances the anchor. See `PolicyStore::commit_revisions`.
    Ok(AppState {
        deployment_env,
        policy_store,
        legacy_policy: resolved.config,
        policy_source: resolved.source,
        pool,
        usage,
        api_key_cfg,
        base_url,
        started_at: ProcessStartedAt::now(),
    })
}

fn gate_state(st: &AppState) -> AuditKeyGateState {
    AuditKeyGateState {
        cfg: st.api_key_cfg.clone(),
        usage: st.usage.clone(),
        pool: st.pool.clone(),
        deployment_env: st.deployment_env,
    }
}

pub fn build_router(state: AppState) -> Router {
    let gate = gate_state(&state);
    let ledger_routes = Router::new()
        .route("/evidence", post(post_evidence))
        .route("/bundle", get(get_bundle_query))
        .route("/bundle/{run_id}", get(get_bundle_path))
        .route("/bundle-hash", get(get_bundle_hash_query))
        .route("/bundle-hash/{run_id}", get(get_bundle_hash_path))
        .route(
            "/execution-authorizations/{run_id}/{authorization_id}/status",
            get(get_execution_authorization_status),
        )
        .route("/compliance-summary", get(get_compliance_summary_query))
        .route("/compliance-summary/{run_id}", get(get_compliance_summary_path))
        .route("/api/export/{run_id}", get(get_api_export))
        .route("/verify", get(get_verify))
        .route("/verify/{run_id}", get(get_verify_run))
        .layer(middleware::from_fn_with_state(
            gate,
            gate_audit_routes_with_state,
        ));

    Router::new()
        .route("/", get(get_root))
        .route("/health", get(get_health))
        .route("/ready", get(get_ready))
        .route("/status", get(get_status))
        .route("/metrics", get(http_observability::metrics_handler))
        .merge(ledger_routes)
        .with_state(state)
}

async fn resolve_tenant(
    st: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> Result<String, (StatusCode, Json<Value>)> {
    if let Some(ResolvedLedgerTenant(tid)) = extensions.get::<ResolvedLedgerTenant>() {
        return Ok(tid.clone());
    }
    project::require_tenant_id_for_ledger_async(&st.pool, headers, st.deployment_env)
        .await
        .map_err(|e| {
            api_error(
                StatusCode::BAD_REQUEST,
                "TENANT_RESOLUTION_FAILED",
                &e,
                "Configure GOVAI_API_KEYS_JSON mapping api_key -> ledger_tenant_id.",
                None,
            )
        })
}

fn ledger_path_for_tenant(tenant_id: &str) -> String {
    project::resolve_ledger_path(LEDGER_STEM, tenant_id)
}

fn active_policy_version(st: &AppState, tenant_id: &str) -> String {
    st.policy_store
        .resolve_for_request(tenant_id)
        .version()
        .to_string()
}

async fn get_root() -> Json<Value> {
    Json(json!({
        "ok": true,
        "service": "aigov_audit",
        "surface": "aigov-core",
    }))
}

async fn get_health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn get_status(State(st): State<AppState>) -> Json<Value> {
    let body = runtime_diagnostics::build_status_body(&st, st.started_at, &st.policy_source).await;
    Json(body)
}

async fn get_ready(State(st): State<AppState>) -> impl IntoResponse {
    let components = runtime_diagnostics::readiness_components(&st).await;
    let database_ping = components
        .get("database_ping")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let migrations_complete = components
        .get("migrations_complete")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ledger_writable = components
        .get("ledger_writable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ledger_tenant_readable = components
        .get("ledger_tenant_readable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let checks = json!({
        "database_ping": database_ping,
        "migrations_complete": migrations_complete,
        "ledger_writable": ledger_writable,
        "ledger_tenant_readable": ledger_tenant_readable,
    });

    let ready =
        database_ping && migrations_complete && ledger_writable && ledger_tenant_readable;
    if ready {
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "ready": true,
                "checks": checks,
                "runtime_governance_enforcement": runtime_diagnostics::runtime_governance_enforcement_diag(),
            })),
        )
            .into_response();
    }

    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "NOT_READY",
        "One or more readiness checks failed.",
        "Verify DATABASE_URL, apply migrations (GOVAI_AUTO_MIGRATE=true), and set GOVAI_LEDGER_DIR.",
        Some(json!({ "checks": checks })),
    )
    .into_response()
}

/// Executor status check for an authorization. Requires the executor principal for this tenant.
/// `revoked` wins over `authorized`. `receipt_recorded` means an execution receipt exists for it.
async fn get_execution_authorization_status(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Path((run_id, authorization_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant(&st, &headers, &extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let principal = match crate::principals::request_principal(&headers, &extensions) {
        Some(p) => p,
        None => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "PRINCIPAL_REQUIRED",
                "Status checks need the executor principal.",
                "Send the executor key.",
                None,
            )
            .into_response();
        }
    };
    if principal.role != crate::principals::Role::Executor || principal.tenant != tenant_id {
        return api_error(
            StatusCode::FORBIDDEN,
            "ROLE_NOT_PERMITTED",
            "Only the executor for this tenant may check authorizations.",
            "Use the executor key.",
            None,
        )
        .into_response();
    }
    let log_path = ledger_path_for_tenant(&tenant_id);
    let events = match collect_events_for_run(&log_path, &run_id) {
        Ok(e) => e,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "LEDGER_READ_ERROR",
                &e,
                "Retry later.",
                None,
            )
            .into_response();
        }
    };
    let Some(issued) = events.iter().find(|e| {
        (e.event_type == "consequential_tool_call" || e.event_type == "tool_call")
            && e.payload
                .get("execution_authorization_id")
                .and_then(|v| v.as_str())
                == Some(authorization_id.as_str())
    }) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "AUTHORIZATION_NOT_FOUND",
            "No authorization with this id in this run.",
            "Check the run and authorization id.",
            None,
        )
        .into_response();
    };
    let field = |k: &str| {
        issued
            .payload
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let approval_event_id = field("approval_event_id");
    let expires_at = field("execution_authorization_expires_at_utc");
    let revoked = !approval_event_id.is_empty()
        && events.iter().any(|e| {
            e.event_type == "human_approval_revoked"
                && e.payload.get("approval_event_id").and_then(|v| v.as_str())
                    == Some(approval_event_id.as_str())
        });
    let receipted = events.iter().any(|e| {
        e.event_type == "execution_receipt"
            && e.payload
                .get("execution_authorization_id")
                .and_then(|v| v.as_str())
                == Some(authorization_id.as_str())
    });
    let now = chrono::Utc::now();
    let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|t| now > t.with_timezone(&chrono::Utc))
        .unwrap_or(true);
    let state = if receipted {
        "receipt_recorded"
    } else if revoked {
        "revoked"
    } else if expired {
        "expired"
    } else {
        "authorized"
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "authorization_id": authorization_id,
            "state": state,
            "run_id": run_id,
            "approval_event_id": approval_event_id,
            "tool_name": field("tool_name"),
            "args_binding_hash": field("args_binding_hash"),
            "expires_at_utc": expires_at,
            "checked_at_utc": now.to_rfc3339(),
        })),
    )
        .into_response()
}

async fn post_evidence(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Json(mut event): Json<EvidenceEvent>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant(&st, &headers, &extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let log_path = ledger_path_for_tenant(&tenant_id);
    let policy_version = active_policy_version(&st, &tenant_id);

    // Authenticated principals. When configured, the caller's key decides the principal, its role, and the event
    // types it may post. Core writes the authenticated fields itself, so a client cannot choose its own identity.
    let principal = if crate::principals::principals_configured() {
        match crate::principals::request_principal(&headers, &extensions) {
            Some(p) => Some(p),
            None => {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "PRINCIPAL_REQUIRED",
                    "This ingest requires an authenticated principal configured in GOVAI_PRINCIPALS_JSON.",
                    "Send the API key assigned to your role.",
                    None,
                )
                .into_response();
            }
        }
    } else {
        None
    };
    if let Some(p) = &principal {
        if p.tenant != tenant_id {
            return api_error(
                StatusCode::FORBIDDEN,
                "TENANT_MISMATCH",
                "The principal is not configured for this ledger tenant.",
                "Use the key configured for this tenant.",
                None,
            )
            .into_response();
        }
        if !crate::principals::allowed_event_types(p.role).contains(&event.event_type.as_str()) {
            return api_error(
                StatusCode::FORBIDDEN,
                "ROLE_NOT_PERMITTED",
                &format!(
                    "role {} may not post event_type {}",
                    p.role.as_str(),
                    event.event_type
                ),
                "Post with the key for the role that owns this event type.",
                None,
            )
            .into_response();
        }
        let Some(payload) = event.payload.as_object_mut() else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "PAYLOAD_NOT_OBJECT",
                "Authenticated events must carry a JSON object payload.",
                "Send payload as a JSON object.",
                None,
            )
            .into_response();
        };
        payload.insert("authenticated_principal".into(), json!(p.principal_id));
        payload.insert("authenticated_identity".into(), json!(p.identity));
        payload.insert("authenticated_role".into(), json!(p.role.as_str()));
        if matches!(
            event.event_type.as_str(),
            "consequential_tool_call" | "tool_approval_requested" | "tool_call"
        ) {
            // Stamped by Core: approvals must claim the revision that is actually in force.
            payload.insert("policy_revision".into(), json!(policy_version));
        }
    }
    // The authorization id and its times are fixed before the append, so the accepted record carries them.
    let prepared = if principal.is_some()
        && (event.event_type == "consequential_tool_call" || event.event_type == "tool_call")
    {
        crate::execution_authorization::prepare(chrono::Utc::now())
    } else {
        None
    };
    if let (Some(prep), Some(payload)) = (&prepared, event.payload.as_object_mut()) {
        payload.insert(
            "execution_authorization_id".into(),
            json!(prep.authorization_id),
        );
        payload.insert(
            "execution_authorization_expires_at_utc".into(),
            json!(prep.expires_at.to_rfc3339()),
        );
    }

    let existing = match collect_events_for_run(&log_path, &event.run_id) {
        Ok(e) => e,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "LEDGER_READ_ERROR",
                &e,
                "Retry later or contact the operator.",
                None,
            )
            .into_response();
        }
    };

    if let Err(e) =
        govai_environment::stamp_event_environment_for_ingest(&mut event, st.deployment_env, &existing)
    {
        return policy_violation_response(&policy_version, &e);
    }

    if let Err(e) = crate::decision_trace::validate_trace_event(&event, &existing) {
        return policy_violation_response(&policy_version, &format!("policy_violation: invalid_decision_trace {e}"));
    }

    let ledger_view = FileLedgerView::new(&log_path);
    if let Err(v) = st.policy_store.enforce_ingest_for_request(&tenant_id, &event, &ledger_view) {
        return policy_violation_response(&policy_version, &v.to_string());
    }

    // Events gated on an approval are checked again under the ledger lock, so a single approval cannot be
    // consumed twice by concurrent requests. Other events keep the existing path.
    let needs_locked_check = principal.is_some()
        || st
            .policy_store
            .event_type_requires_unconsumed_approval(&tenant_id, &event.event_type);
    let locked_check = |path: &str| -> Result<(), String> {
        if !needs_locked_check {
            return Ok(());
        }
        let view = FileLedgerView::new(path);
        st.policy_store
            .enforce_ingest_for_request(&tenant_id, &event, &view)
            .map_err(|v| v.to_string())
    };
    let append_result =
        match crate::audit_store::append_record_checked(&log_path, event.clone(), &locked_check) {
            Ok(v) => Ok(v),
            Err(crate::audit_store::CheckedAppendError::Rejected(msg)) => {
                return policy_violation_response(&policy_version, &msg);
            }
            Err(crate::audit_store::CheckedAppendError::Store(msg)) => Err(msg),
        };
    match append_result {
        Ok((rec, pre_count)) => {
            runtime_metrics::inc_evidence_ingest("appended");
            ops_log::evidence_ingest("appended", 200, &tenant_id);
            let mut body = json!({
                "ok": true,
                "record_hash": rec.record_hash,
                "policy_version": policy_version,
                "environment": st.deployment_env.as_str(),
            });
            if let Some(prep) = &prepared {
                let str_field =
                    |k: &str| event.payload.get(k).and_then(|v| v.as_str()).unwrap_or("");
                if let Some(signed) = crate::execution_authorization::sign_prepared(
                    prep,
                    &event.run_id,
                    str_field("tool_name"),
                    str_field("args_binding_hash"),
                    &policy_version,
                    str_field("approval_event_id"),
                    &rec.record_hash,
                ) {
                    body["execution_authorization"] = json!(signed);
                }
            }
            if metering::metering_enabled() {
                if let Some(extra) = metering::ingest_success_extras(
                    &tenant_id,
                    &event.run_id,
                    pre_count as u64,
                )
                .as_object()
                {
                    for (k, v) in extra {
                        body[k] = v.clone();
                    }
                }
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) if e.contains("duplicate event_id") => api_error(
            StatusCode::CONFLICT,
            "DUPLICATE_EVENT_ID",
            &e,
            "Use a new event_id or treat this ingest as idempotent no-op on the client.",
            Some(json!({ "policy_version": policy_version })),
        )
        .into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "LEDGER_APPEND_ERROR",
            &e,
            "Retry the request; if the failure persists, check ledger storage.",
            None,
        )
        .into_response(),
    }
}

fn policy_violation_response(policy_version: &str, message: &str) -> axum::response::Response {
    let code = if message.contains("policy_violation:") {
        message
            .split(':')
            .nth(1)
            .map(|s| s.trim().split_whitespace().next().unwrap_or("policy_violation"))
            .unwrap_or("policy_violation")
    } else {
        "policy_violation"
    };
    api_error_with(
        StatusCode::BAD_REQUEST,
        "policy_violation",
        message,
        "Fix the event payload or ordering per policy documentation.",
        None,
        Some(json!({
            "code": code,
            "policy_version": policy_version,
            "metering": if metering::metering_enabled() { "on" } else { "off" },
        })),
    )
    .into_response()
}

async fn get_bundle_query(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Query(q): Query<RunIdQuery>,
) -> impl IntoResponse {
    bundle_for_run(&st, &headers, &extensions, &q.run_id).await
}

async fn get_bundle_path(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    bundle_for_run(&st, &headers, &extensions, &run_id).await
}

async fn bundle_for_run(
    st: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    run_id: &str,
) -> axum::response::Response {
    let tenant_id = match resolve_tenant(st, headers, extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let log_path = ledger_path_for_tenant(&tenant_id);
    let policy_version = active_policy_version(st, &tenant_id);

    let events = match collect_events_for_run(&log_path, run_id) {
        Ok(e) => e,
        Err(e) => {
            return Json(json!({
                "ok": false,
                "error": "ledger_read_error",
                "message": e,
                "policy_version": policy_version,
                "run_id": run_id,
            }))
            .into_response();
        }
    };

    if events.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": "run_not_found",
                "message": "No events for run_id in tenant ledger.",
                "policy_version": policy_version,
                "run_id": run_id,
            })),
        )
            .into_response();
    }

    let doc = bundle_document_value(run_id, &policy_version, &log_path, &events);
    Json(doc).into_response()
}

async fn get_bundle_hash_query(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Query(q): Query<RunIdQuery>,
) -> impl IntoResponse {
    bundle_hash_for_run(&st, &headers, &extensions, &q.run_id).await
}

async fn get_bundle_hash_path(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    bundle_hash_for_run(&st, &headers, &extensions, &run_id).await
}

async fn bundle_hash_for_run(
    st: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    run_id: &str,
) -> axum::response::Response {
    let tenant_id = match resolve_tenant(st, headers, extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let log_path = ledger_path_for_tenant(&tenant_id);
    let policy_version = active_policy_version(st, &tenant_id);

    let events = match collect_events_for_run(&log_path, run_id) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "ok": false,
                    "error": "ledger_read_error",
                    "message": e,
                })),
            )
                .into_response();
        }
    };

    if events.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": "run_not_found",
                "message": "No events for run_id in tenant ledger.",
                "policy_version": policy_version,
                "run_id": run_id,
            })),
        )
            .into_response();
    }

    let artifact = find_model_artifact_path(&events);
    let bundle_sha = bundle_sha256(
        run_id,
        &policy_version,
        &log_path,
        artifact.as_deref(),
        &events,
    );
    let events_content_sha256 = portable_evidence_digest_v1(run_id, &events);

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "run_id": run_id,
            "policy_version": policy_version,
            "bundle_sha256": bundle_sha,
            "events_content_sha256": events_content_sha256,
        })),
    )
        .into_response()
}

async fn get_compliance_summary_query(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Query(q): Query<RunIdQuery>,
) -> impl IntoResponse {
    compliance_summary_for_run(&st, &headers, &extensions, &q.run_id).await
}

async fn get_compliance_summary_path(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    compliance_summary_for_run(&st, &headers, &extensions, &run_id).await
}

async fn compliance_summary_for_run(
    st: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    run_id: &str,
) -> axum::response::Response {
    let tenant_id = match resolve_tenant(st, headers, extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let log_path = ledger_path_for_tenant(&tenant_id);
    let policy_version = active_policy_version(st, &tenant_id);

    let events = match collect_events_for_run(&log_path, run_id) {
        Ok(e) => e,
        Err(e) => {
            return Json(compliance_summary_error_json(
                run_id,
                &policy_version,
                "ledger_read_error",
                &e,
                None,
            ))
            .into_response();
        }
    };

    if events.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(compliance_summary_error_json(
                run_id,
                &policy_version,
                "run_not_found",
                "No events for run_id in tenant ledger.",
                None,
            )),
        )
            .into_response();
    }

    let artifact = find_model_artifact_path(&events);
    let bundle_hash = bundle_sha256(
        run_id,
        &policy_version,
        &log_path,
        artifact.as_deref(),
        &events,
    );
    let exported_at = events.last().map(|e| e.ts_utc.clone());
    let state = derive_current_state_from_events_with_context(
        run_id,
        &events,
        Some(bundle_hash),
        exported_at,
    );
    let outcome = derive_verdict_from_state(&state, &st.legacy_policy);
    runtime_metrics::inc_compliance_summary();
    ops_log::compliance_summary_generated(&tenant_id, run_id.len(), &outcome.verdict);

    Json(compliance_summary_success_json(
        run_id,
        &policy_version,
        &state,
        &outcome,
    ))
    .into_response()
}

async fn get_api_export(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant(&st, &headers, &extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let log_path = ledger_path_for_tenant(&tenant_id);
    let policy_version = active_policy_version(&st, &tenant_id);

    match build_audit_export_v1(
        &run_id,
        &tenant_id,
        &log_path,
        &policy_version,
        st.deployment_env,
        &st.legacy_policy,
    ) {
        Ok(doc) => (StatusCode::OK, Json(doc)).into_response(),
        Err(e) if e == "run_not_found" => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": "run_not_found",
                "message": "No events for run_id in tenant ledger.",
                "run_id": run_id,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": "export_failed",
                "message": e,
                "run_id": run_id,
            })),
        )
            .into_response(),
    }
}

async fn get_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
) -> impl IntoResponse {
    verify_ledger(st, headers, extensions, None).await
}

async fn get_verify_run(
    State(st): State<AppState>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    verify_ledger(st, headers, extensions, Some(run_id.as_str())).await
}

async fn verify_ledger(
    st: AppState,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    run_id_filter: Option<&str>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant(&st, &headers, &extensions).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let log_path = ledger_path_for_tenant(&tenant_id);

    match verify_chain(&log_path) {
        Ok(()) => {
            if let Some(rid) = run_id_filter {
                let events = collect_events_for_run(&log_path, rid).unwrap_or_default();
                if events.is_empty() {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({
                            "ok": false,
                            "error": "run_not_found",
                            "message": "No events for run_id in tenant ledger.",
                            "run_id": rid,
                        })),
                    )
                        .into_response();
                }
            }
            Json(json!({ "ok": true, "message": "chain valid" })).into_response()
        }
        Err(e) => Json(json!({
            "ok": false,
            "error": "chain_invalid",
            "message": e,
        }))
        .into_response(),
    }
}
