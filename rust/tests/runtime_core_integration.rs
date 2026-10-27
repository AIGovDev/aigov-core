//! In-process HTTP integration tests: ingest → projection → verdict → export.

use aigov_audit::{build_app_state, build_router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

fn postgres_url_configured() -> bool {
    ["GOVAI_DATABASE_URL", "DATABASE_URL", "AIGOV_DATABASE_URL"]
        .into_iter()
        .any(|key| {
            std::env::var(key)
                .ok()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
        })
}

/// Isolate ledger-focused integration tests from CI-wide `DATABASE_URL` unless migrations run.
fn configure_runtime_core_test_env(ledger_dir: &std::path::Path) {
    std::fs::create_dir_all(ledger_dir).expect("ledger parent directory");
    std::env::set_var(
        "GOVAI_LEDGER_DIR",
        ledger_dir.to_string_lossy().to_string(),
    );
    if postgres_url_configured() {
        std::env::set_var("GOVAI_AUTO_MIGRATE", "true");
    }
}

async fn assert_ready_ok(app: &axum::Router) -> Value {
    let req = Request::builder()
        .uri("/ready")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/ready expected HTTP 200, got {status}; body: {body}"
    );
    assert_eq!(body["ready"], true, "/ready body: {body}");
    body
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<&Value>,
    api_key: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {api_key}"));
    let req = if let Some(b) = body {
        builder = builder.header("content-type", "application/json");
        builder
            .body(Body::from(serde_json::to_vec(b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let json = body_json(resp).await;
    (status, json)
}

fn discovery_event(run_id: &str, id: &str) -> Value {
    json!({
        "event_id": id,
        "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z",
        "actor": "test",
        "system": "test",
        "run_id": run_id,
        "payload": { "openai": false, "transformers": false, "model_artifacts": false }
    })
}

fn data_registered(run_id: &str) -> Value {
    json!({
        "event_id": format!("{run_id}-data"),
        "event_type": "data_registered",
        "ts_utc": "2026-01-01T00:00:02Z",
        "actor": "test",
        "system": "test",
        "run_id": run_id,
        "payload": {
            "ai_system_id": "as-1",
            "dataset_id": "ds-1",
            "dataset": "ds",
            "dataset_version": "v1",
            "dataset_fingerprint": "fp",
            "dataset_governance_id": "dg-1",
            "dataset_governance_commitment": "basic",
            "source": "internal",
            "intended_use": "test",
            "limitations": "none",
            "quality_summary": "ok",
            "governance_status": "registered"
        }
    })
}

fn evaluation_event(run_id: &str, passed: bool) -> Value {
    json!({
        "event_id": format!("{run_id}-eval"),
        "event_type": "evaluation_reported",
        "ts_utc": "2026-01-01T00:00:03Z",
        "actor": "test",
        "system": "test",
        "run_id": run_id,
        "payload": {
            "ai_system_id": "as-1",
            "dataset_id": "ds-1",
            "model_version_id": "mv-1",
            "metric": "accuracy",
            "value": 0.95,
            "threshold": 0.8,
            "passed": passed
        }
    })
}

fn golden_path_valid_events(run_id: &str) -> Vec<Value> {
    vec![
        discovery_event(run_id, &format!("{run_id}-disc")),
        data_registered(run_id),
        json!({
            "event_id": format!("{run_id}-train"),
            "event_type": "model_trained",
            "ts_utc": "2026-01-01T00:00:02Z",
            "actor": "test",
            "system": "test",
            "run_id": run_id,
            "payload": {
                "model_version_id": "mv-1",
                "ai_system_id": "as-1",
                "dataset_id": "ds-1",
                "model_type": "test",
                "artifact_path": "registry://test/model",
                "artifact_sha256": "abc1234567890123456789012345678901234567890123456789012345678901234"
            }
        }),
        evaluation_event(run_id, true),
        json!({
            "event_id": format!("{run_id}-risk"),
            "event_type": "risk_recorded",
            "ts_utc": "2026-01-01T00:00:04Z",
            "actor": "test",
            "system": "test",
            "run_id": run_id,
            "payload": {
                "assessment_id": "assess-1",
                "ai_system_id": "as-1",
                "dataset_id": "ds-1",
                "model_version_id": "mv-1",
                "risk_id": "risk-1",
                "risk_class": "high",
                "severity": 4.0,
                "likelihood": 0.3,
                "status": "submitted",
                "mitigation": "mitigate",
                "owner": "owner",
                "dataset_governance_commitment": "basic"
            }
        }),
        json!({
            "event_id": format!("{run_id}-review"),
            "event_type": "risk_reviewed",
            "ts_utc": "2026-01-01T00:00:05Z",
            "actor": "test",
            "system": "test",
            "run_id": run_id,
            "payload": {
                "assessment_id": "assess-1",
                "ai_system_id": "as-1",
                "dataset_id": "ds-1",
                "model_version_id": "mv-1",
                "risk_id": "risk-1",
                "decision": "approve",
                "reviewer": "risk_officer",
                "justification": "ok",
                "dataset_governance_commitment": "basic"
            }
        }),
        json!({
            "event_id": format!("{run_id}-human"),
            "event_type": "human_approved",
            "ts_utc": "2026-01-01T00:00:06Z",
            "actor": "test",
            "system": "test",
            "run_id": run_id,
            "payload": {
                "scope": "model_promoted",
                "decision": "approve",
                "approver": "compliance_officer",
                "justification": "ok",
                "assessment_id": "assess-1",
                "risk_id": "risk-1",
                "dataset_governance_commitment": "basic",
                "ai_system_id": "as-1",
                "dataset_id": "ds-1",
                "model_version_id": "mv-1"
            }
        }),
        json!({
            "event_id": format!("{run_id}-promote"),
            "event_type": "model_promoted",
            "ts_utc": "2026-01-01T00:00:07Z",
            "actor": "test",
            "system": "test",
            "run_id": run_id,
            "payload": {
                "ai_system_id": "as-1",
                "dataset_id": "ds-1",
                "model_version_id": "mv-1",
                "artifact_path": "registry://test/model",
                "artifact_sha256": "abc1234567890123456789012345678901234567890123456789012345678901234",
                "promotion_reason": "test",
                "approved_human_event_id": format!("{run_id}-human"),
                "assessment_id": "assess-1",
                "risk_id": "risk-1",
                "dataset_governance_commitment": "basic"
            }
        }),
    ]
}

async fn ingest_all(app: &axum::Router, events: &[Value], api_key: &str) {
    for ev in events {
        let (status, body) = send(app, "POST", "/evidence", Some(ev), api_key).await;
        assert_eq!(status, StatusCode::OK, "ingest failed: {body:?}");
        assert_eq!(body.get("ok"), Some(&json!(true)));
    }
}

/// Single sequential suite avoids API-key map OnceCell races and ledger probe collisions.
#[tokio::test]
async fn runtime_ingest_projection_verdict_export_suite() {
    let dir = tempfile::tempdir().expect("tempdir");
    configure_runtime_core_test_env(dir.path());
    std::env::set_var("GOVAI_API_KEYS", "tenant-a-key,tenant-b-key");
    std::env::set_var(
        "GOVAI_API_KEYS_JSON",
        r#"{"tenant-a-key":"tenant-a","tenant-b-key":"tenant-b"}"#,
    );
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", concat!(env!("CARGO_MANIFEST_DIR")));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");

    let state = build_app_state().await.expect("app state");
    let app = build_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], true);
    assert!(body.get("runtime_version").is_some());
    assert!(body.get("configuration").is_some());
    assert!(body.get("readiness_components").is_some());

    let ledger_path = dir.path().join("audit_log__default.jsonl");
    for _ in 0..3 {
        let body = assert_ready_ok(&app).await;
        let checks = body.get("checks").expect("checks");
        assert_eq!(
            checks["ledger_tenant_readable"], true,
            "ledger_tenant_readable check failed; /ready body: {body}"
        );
        assert!(checks.get("tenant_ledger_probe").is_none());
    }
    assert_eq!(count_ledger_lines(&ledger_path), 0);

    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let text = String::from_utf8(bytes.to_vec()).expect("utf8 metrics");
    assert!(text.contains("govai_http_requests_total"));

    // duplicate event rejection
    let run_id = "dup-run";
    let ev = discovery_event(run_id, "dup-event-1");
    let (s1, _) = send(&app, "POST", "/evidence", Some(&ev), "tenant-a-key").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, body) = send(&app, "POST", "/evidence", Some(&ev), "tenant-a-key").await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "DUPLICATE_EVENT_ID");

    // append-only chain verify
    let run_id = "chain-run";
    ingest_all(&app, &[discovery_event(run_id, "c1")], "tenant-a-key").await;
    let (status, body) = send(&app, "GET", "/verify", None, "tenant-a-key").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    // VALID verdict
    let run_id = "valid-run";
    ingest_all(&app, &golden_path_valid_events(run_id), "tenant-a-key").await;
    let (_, body) = send(
        &app,
        "GET",
        &format!("/compliance-summary?run_id={run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    assert_eq!(body["verdict"], "VALID");

    // INVALID verdict
    let run_id = "invalid-run";
    ingest_all(
        &app,
        &[
            discovery_event(run_id, &format!("{run_id}-disc")),
            evaluation_event(run_id, false),
        ],
        "tenant-a-key",
    )
    .await;
    let (_, body) = send(
        &app,
        "GET",
        &format!("/compliance-summary?run_id={run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    assert_eq!(body["verdict"], "INVALID");

    // BLOCKED verdict (discovery only)
    let run_id = "blocked-run";
    ingest_all(
        &app,
        &[discovery_event(run_id, &format!("{run_id}-disc"))],
        "tenant-a-key",
    )
    .await;
    let (_, body) = send(
        &app,
        "GET",
        &format!("/compliance-summary?run_id={run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    assert_eq!(body["verdict"], "BLOCKED");

    // tenant isolation
    let run_id = "iso-run";
    ingest_all(
        &app,
        &[discovery_event(run_id, "iso-a")],
        "tenant-a-key",
    )
    .await;
    let (_, body_b) = send(
        &app,
        "GET",
        &format!("/bundle?run_id={run_id}"),
        None,
        "tenant-b-key",
    )
    .await;
    assert_eq!(body_b["ok"], false);

    // export schema + hash parity
    let run_id = "export-run";
    ingest_all(&app, &golden_path_valid_events(run_id), "tenant-a-key").await;
    let (_, hash_body) = send(
        &app,
        "GET",
        &format!("/bundle-hash?run_id={run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    let (_, export) = send(
        &app,
        "GET",
        &format!("/api/export/{run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    assert_eq!(export["schema_version"], "aigov.audit_export.v1");
    assert_eq!(export["ok"], true);
    let eh = &export["evidence_hashes"];
    assert_eq!(
        eh["events_content_sha256"].as_str(),
        hash_body["events_content_sha256"].as_str()
    );
    assert_eq!(
        eh["bundle_sha256"].as_str(),
        hash_body["bundle_sha256"].as_str()
    );

    // bundle reconstruction parity
    let run_id = "recon-run";
    let events = golden_path_valid_events(run_id);
    ingest_all(&app, &events, "tenant-a-key").await;
    let (_, bundle) = send(
        &app,
        "GET",
        &format!("/bundle?run_id={run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    let (_, export) = send(
        &app,
        "GET",
        &format!("/api/export/{run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    let bundle_events = bundle["events"].as_array().expect("bundle events");
    let export_events = export["evidence_events"].as_array().expect("export events");
    assert_eq!(bundle_events.len(), export_events.len());
    for (b, e) in bundle_events.iter().zip(export_events.iter()) {
        assert_eq!(b["event_id"], e["event_id"]);
        assert_eq!(b["event_type"], e["event_type"]);
    }

    // replay validation on exported document
    let run_id = "replay-run";
    ingest_all(&app, &golden_path_valid_events(run_id), "tenant-a-key").await;
    let (_, export_for_replay) = send(
        &app,
        "GET",
        &format!("/api/export/{run_id}"),
        None,
        "tenant-a-key",
    )
    .await;
    let (replay_report, replay_events) =
        aigov_audit::replay_validation::run_export_validations(&export_for_replay);
    assert!(
        replay_report.is_ok(),
        "replay validation failed: {:?}",
        replay_report.errors
    );
    assert!(replay_report.events_content_sha256_ok);
    assert_eq!(replay_events.len(), golden_path_valid_events(run_id).len());
    assert!(export_for_replay.get("lineage").is_some());

    // Provider-neutral invocation evidence survives export and does not change
    // deterministic governance replay when the provider reports a new backend.
    let run_id = "decision-trace-run";
    ingest_all(&app, &golden_path_valid_events(run_id), "tenant-a-key").await;
    let source = json!({"event_id":"trace-source","event_type":"user_request","ts_utc":"2026-01-01T00:00:08Z","actor":"test","system":"test","run_id":run_id,"payload":{"request_id":"req-1"}});
    let (status, _) = send(&app, "POST", "/evidence", Some(&source), "tenant-a-key").await;
    assert_eq!(status, StatusCode::OK);
    let invocation = |event_id: &str, invocation_id: &str, fingerprint: &str| json!({
        "event_id":event_id,"event_type":"model_invocation_recorded","ts_utc":"2026-01-01T00:00:09Z","actor":"test","system":"test","run_id":run_id,
        "payload":{"schema_version":"aigov.model_invocation.v1","invocation_id":invocation_id,
            "provider":{"name":"provider-x","endpoint":"https://provider.example/v1/responses","requested_model":"model-x","reported_model":"model-x","api_version":"v1","backend_fingerprint":fingerprint,"provider_request_id":"unknown","determinism":{"status":"unknown","source":"unknown"}},
            "generation":{"temperature":0,"seed":7},"capture":{"profile":"digest_only","request":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","availability":"retained"},"response":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","availability":"retained"}}}
    });
    for (i, fp) in [("i1", "backend-a"), ("i2", "backend-b")] {
        let ev = invocation(&format!("trace-{i}"), i, fp);
        let (status, body) = send(&app, "POST", "/evidence", Some(&ev), "tenant-a-key").await;
        assert_eq!(status, StatusCode::OK, "valid invocation rejected: {body}");
    }
    let rationale = json!({"event_id":"trace-rationale","event_type":"decision_reasoning_recorded","ts_utc":"2026-01-01T00:00:10Z","actor":"test","system":"test","run_id":run_id,
        "payload":{"schema_version":"aigov.decision_reasoning.v1","run_id":run_id,"decision_id":"decision-1","step_id":"step-1","reasoning_type":"action_selection","source":"runtime","rationale_status":"available","rationale":"The recorded policy evidence requires a human approval gate.","representation":"concise_rationale","evidence_refs":[{"event_id":"trace-source"}],"source_event_ids":["trace-source","trace-i2"],"claims":[{"claim":"human approval required","source_event_ids":["trace-source"]}],"reliance":[{"source_event_id":"trace-source","use":"selected approval gate"}],"action_event_ids":[format!("{run_id}-promote")],"human_endorsement_event_ids":[format!("{run_id}-human")]}});
    let (status, body) = send(&app, "POST", "/evidence", Some(&rationale), "tenant-a-key").await;
    assert_eq!(status, StatusCode::OK, "valid reasoning rejected: {body}");
    let mut malformed = rationale.clone(); malformed["event_id"] = "bad-ref".into(); malformed["payload"]["source_event_ids"][0] = "missing-event".into();
    let (status, _) = send(&app, "POST", "/evidence", Some(&malformed), "tenant-a-key").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut missing_provider = invocation("bad-provider", "i3", "backend-c"); missing_provider["payload"]["provider"].as_object_mut().unwrap().remove("name");
    let (status, _) = send(&app, "POST", "/evidence", Some(&missing_provider), "tenant-a-key").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let links = json!({"event_id":"trace-links","event_type":"decision_trace_links_recorded","ts_utc":"2026-01-01T00:00:11Z","actor":"test","system":"test","run_id":run_id,
        "payload":{"schema_version":"aigov.decision_trace_links.v1","run_id":run_id,"decision_id":"decision-1","reasoning_event_id":"trace-rationale","action_event_ids":[format!("{run_id}-promote")],"human_endorsement_event_ids":[format!("{run_id}-human")]}});
    let (status, body) = send(&app, "POST", "/evidence", Some(&links), "tenant-a-key").await;
    assert_eq!(status, StatusCode::OK, "valid late trace links rejected: {body}");

    let (_, trace_export) = send(&app, "GET", &format!("/api/export/{run_id}"), None, "tenant-a-key").await;
    let events = trace_export["evidence_events"].as_array().unwrap();
    let invocations: Vec<_> = events.iter().filter(|e| e["event_type"] == "model_invocation_recorded").collect();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0]["payload"]["provider"]["requested_model"], invocations[1]["payload"]["provider"]["requested_model"]);
    assert_ne!(invocations[0]["payload"]["provider"]["backend_fingerprint"], invocations[1]["payload"]["provider"]["backend_fingerprint"]);
    let (first_replay, _) = aigov_audit::replay_validation::run_export_validations(&trace_export);
    let (second_replay, _) = aigov_audit::replay_validation::run_export_validations(&trace_export);
    assert!(first_replay.is_ok(), "trace export replay failed: {:?}", first_replay.errors);
    assert_eq!(first_replay.events_content_sha256_ok, second_replay.events_content_sha256_ok);
    let governance_first = aigov_audit::replay_engine::replay_audit_export_v1(&trace_export, &aigov_audit::policy_config::PolicyConfig::default());
    let governance_second = aigov_audit::replay_engine::replay_audit_export_v1(&trace_export, &aigov_audit::policy_config::PolicyConfig::default());
    assert!(governance_first.ok, "offline governance replay failed: {:?}", governance_first.validation.errors);
    assert_eq!(governance_first.determinism_digest, governance_second.determinism_digest);
    let mut tampered = trace_export.clone();
    let idx = tampered["evidence_events"].as_array().unwrap().iter().position(|e| e["event_type"] == "model_invocation_recorded").unwrap();
    tampered["evidence_events"][idx]["payload"]["provider"]["backend_fingerprint"] = "tampered".into();
    let (tamper_report, _) = aigov_audit::replay_validation::run_export_validations(&tampered);
    assert!(!tamper_report.is_ok(), "tampered exported trace must fail integrity validation");
}

fn count_ledger_lines(path: &std::path::Path) -> usize {
    if !path.exists() {
        return 0;
    }
    std::fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}
