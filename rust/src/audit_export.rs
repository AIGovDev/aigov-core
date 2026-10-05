//! Deterministic `aigov.audit_export.v1` document builder from ledger state.

use crate::bundle::{
    bundle_sha256, collect_events_for_run, find_model_artifact_path, portable_evidence_digest_v1,
};
use crate::compliance_summary::derive_verdict_from_state;
use crate::govai_environment::GovaiEnvironment;
use crate::policy_config::PolicyConfig;
use crate::epistemic_readiness::{
    epistemic_readiness_to_json, evaluate_epistemic_readiness_from_export,
    EpistemicReadinessOptions,
};
use crate::governance_graph::{build_governance_graph, lineage_block_from_graph};
use crate::projection::derive_current_state_from_events_with_context;
use crate::schema::EvidenceEvent;
use serde_json::{json, Value};

pub fn build_audit_export_v1(
    run_id: &str,
    ledger_tenant_id: &str,
    log_path: &str,
    policy_version: &str,
    deployment_env: GovaiEnvironment,
    policy_cfg: &PolicyConfig,
) -> Result<Value, String> {
    let events = collect_events_for_run(log_path, run_id)?;
    if events.is_empty() {
        return Err("run_not_found".to_string());
    }

    let artifact = find_model_artifact_path(&events);
    let bundle_sha = bundle_sha256(
        run_id,
        policy_version,
        log_path,
        artifact.as_deref(),
        &events,
    );
    let events_content_sha256 = portable_evidence_digest_v1(run_id, &events);
    let exported_at = events.last().map(|e| e.ts_utc.clone());
    let state = derive_current_state_from_events_with_context(
        run_id,
        &events,
        Some(bundle_sha.clone()),
        exported_at.clone(),
    );
    let outcome = derive_verdict_from_state(&state, policy_cfg);

    let log_chain = build_log_chain(log_path, run_id)?;
    let chain_head = log_chain
        .last()
        .and_then(|e| e.get("record_hash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let discovery = discovery_section(&state);
    let discovery_findings = discovery_findings_from_events(&events);
    let human_approval = human_approval_json(&events);
    let promotion = promotion_json(&events);
    let timestamps = export_timestamps(&events);

    let identifiers = serde_json::to_value(&state.identifiers).unwrap_or(json!({}));
    let requirements = export_requirements(&state);
    let graph_doc = build_governance_graph(run_id, &events);
    let lineage = lineage_block_from_graph(&graph_doc);

    let mut doc = json!({
        "ok": true,
        "schema_version": "aigov.audit_export.v1",
        "policy_version": policy_version,
        "environment": deployment_env.as_str(),
        "exported_at_utc": exported_at,
        "tenant": {
            "ledger_tenant_id": ledger_tenant_id,
            "billing_tenant_id": ledger_tenant_id,
        },
        "run": {
            "run_id": run_id,
            "policy_version": policy_version,
            "log_path": log_path,
            "model_artifact_path": artifact,
            "identifiers": identifiers,
        },
        "discovery": discovery,
        "discovery_findings": discovery_findings,
        "evidence_hashes": {
            "bundle_sha256": bundle_sha,
            "events_content_sha256": events_content_sha256,
            "chain_head_record_sha256": chain_head,
            "log_chain": log_chain,
        },
        "decision": {
            "human_approval": human_approval,
            "promotion": promotion,
            "evaluation_passed": state.model.evaluation_passed,
            "verdict": outcome.verdict,
            "blocked_reasons": outcome.blocked_reasons,
            "reason_codes": outcome.reason_codes,
        },
        "evidence_requirements": requirements,
        "evidence_events": events,
        "timestamps": timestamps,
        "lineage": lineage,
    });
    let readiness = evaluate_epistemic_readiness_from_export(
        &doc,
        &EpistemicReadinessOptions::for_export_time(policy_cfg),
    );
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "epistemic_readiness".to_string(),
            epistemic_readiness_to_json(&readiness),
        );
        obj.insert(
            "trace_verification_plan".to_string(),
            readiness.trace_verification_plan.clone(),
        );
    }
    Ok(doc)
}

fn build_log_chain(log_path: &str, run_id: &str) -> Result<Vec<Value>, String> {
    let (records, _) = crate::audit_store::scan_ledger_records(log_path)?;
    let mut chain: Vec<Value> = Vec::new();
    for rec in records {
        let ev: EvidenceEvent =
            serde_json::from_str(&rec.event_json).map_err(|e| e.to_string())?;
        if ev.run_id != run_id {
            continue;
        }
        chain.push(json!({
            "event_id": ev.event_id,
            "ts_utc": ev.ts_utc,
            "event_type": ev.event_type,
            "prev_hash": rec.prev_hash,
            "record_hash": rec.record_hash,
        }));
    }
    chain.sort_by(|a, b| {
        let ta = a.get("ts_utc").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("ts_utc").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb).then_with(|| {
            let ea = a.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
            let eb = b.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
            ea.cmp(eb)
        })
    });

    // `prev_hash` as scanned above is the *physical* ledger chain value: it
    // points at whatever record immediately preceded this one in the shared,
    // multi-run ledger file — which is almost never this run's own previous
    // record once any other run's evidence (or a delegated sub-agent's own
    // events) lands between them. A per-run export is a filtered, re-sorted
    // VIEW of that shared ledger, so validating physical adjacency against it
    // produces false "chain_break" results on entirely untampered data as
    // soon as a single foreign record (or just an out-of-order ts_utc) sits
    // between two of this run's records.
    //
    // What this export actually needs to guarantee is narrower and still
    // meaningful: that THIS run's records, in the order presented here,
    // form an unbroken, tamper-evident sequence on their own — each one
    // still carries its real, ledger-computed `record_hash` (so content
    // tampering of any single record is still caught), but `prev_hash` for
    // every record after the first is rewritten to point at the previous
    // record IN THIS EXPORT. That is a cryptographic chain over the subset
    // the recipient actually has, not an unverifiable claim about physical
    // neighbors they were never given. The first record keeps its real,
    // physical `prev_hash` as an informational anchor into the rest of the
    // ledger; replay intentionally does not validate it (a run-scoped
    // export may legitimately start mid-ledger).
    for i in 1..chain.len() {
        let prior_hash = chain[i - 1]
            .get("record_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(obj) = chain[i].as_object_mut() {
            obj.insert("prev_hash".to_string(), json!(prior_hash));
        }
    }

    Ok(chain)
}

fn discovery_section(state: &crate::projection::ComplianceCurrentState) -> Value {
    json!({
        "findings": {
            "openai": state.discovery.openai,
            "transformers": state.discovery.transformers,
            "model_artifacts": state.discovery.model_artifacts,
        },
        "required_evidence": state.requirements.required,
        "required_requirements": state.requirements.required_requirements,
    })
}

fn discovery_findings_from_events(events: &[EvidenceEvent]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for e in events.iter().rev() {
        if e.event_type != "ai_discovery_reported" {
            continue;
        }
        if let Some(arr) = e.payload.get("findings").and_then(|v| v.as_array()) {
            for item in arr {
                if item.is_object() {
                    out.push(item.clone());
                }
            }
        }
        break;
    }
    out.sort_by(|a, b| {
        let pa = a.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
        let pb = b.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
        pa.cmp(pb)
    });
    out
}

fn export_requirements(state: &crate::projection::ComplianceCurrentState) -> Value {
    json!({
        "required_evidence": state.requirements.required,
        "provided_evidence": state.requirements.satisfied,
        "missing_evidence": state.requirements.missing,
        "required_requirements": state.requirements.required_requirements,
        "provided_requirements": state.requirements.satisfied_requirements,
        "missing_requirements": state.requirements.missing_requirements,
    })
}

fn human_approval_json(events: &[EvidenceEvent]) -> Value {
    for e in events.iter().rev() {
        if e.event_type != "human_approved" {
            continue;
        }
        return json!({
            "approval_event_id": e.event_id,
            "ts_utc": e.ts_utc,
            "scope": e.payload.get("scope"),
            "decision": e.payload.get("decision"),
            "approver": e.payload.get("approver"),
        });
    }
    Value::Null
}

fn promotion_json(events: &[EvidenceEvent]) -> Value {
    for e in events.iter().rev() {
        if e.event_type != "model_promoted" {
            continue;
        }
        return json!({
            "promotion_event_id": e.event_id,
            "ts_utc": e.ts_utc,
            "artifact_path": e.payload.get("artifact_path"),
            "artifact_sha256": e.payload.get("artifact_sha256"),
        });
    }
    Value::Null
}

fn export_timestamps(events: &[EvidenceEvent]) -> Value {
    let first = events.first().map(|e| e.ts_utc.clone());
    let last = events.last().map(|e| e.ts_utc.clone());
    let human = events
        .iter()
        .rev()
        .find(|e| e.event_type == "human_approved")
        .map(|e| e.ts_utc.clone());
    let promotion = events
        .iter()
        .rev()
        .find(|e| e.event_type == "model_promoted")
        .map(|e| e.ts_utc.clone());
    json!({
        "first_event_ts_utc": first,
        "last_event_ts_utc": last,
        "human_approval_ts_utc": human,
        "promotion_ts_utc": promotion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_store::append_record_atomic_with_run_count;
    use crate::replay_validation::{run_export_validations, EXPORT_SCHEMA_V1};
    use crate::schema::EvidenceEvent;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    fn append_event(log_path: &str, event: EvidenceEvent) {
        append_record_atomic_with_run_count(log_path, event).expect("append");
    }

    /// Tenant-scoped ledger file under an isolated temp directory (no `GOVAI_LEDGER_DIR`).
    fn isolated_ledger_path(tmp: &std::path::Path, tenant: &str) -> std::path::PathBuf {
        tmp.join(format!("audit_log__{tenant}.jsonl"))
    }

    fn ensure_ledger_parent(log_path: &std::path::Path) {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    fn write_golden_path_run(log_path: &str, run_id: &str) {
        let events = vec![
            EvidenceEvent {
                event_id: format!("{run_id}-disc"),
                event_type: "ai_discovery_reported".to_string(),
                ts_utc: "2026-01-01T00:00:01Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({"openai": false, "transformers": false, "model_artifacts": false}),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
            EvidenceEvent {
                event_id: format!("{run_id}-data"),
                event_type: "data_registered".to_string(),
                ts_utc: "2026-01-01T00:00:02Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({
                    "ai_system_id": "as-1",
                    "dataset_id": "ds-1",
                    "dataset_version": "v1",
                    "governance_status": "registered"
                }),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
            EvidenceEvent {
                event_id: format!("{run_id}-eval"),
                event_type: "evaluation_reported".to_string(),
                ts_utc: "2026-01-01T00:00:03Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({
                    "ai_system_id": "as-1",
                    "dataset_id": "ds-1",
                    "model_version_id": "mv-1",
                    "passed": true
                }),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
            EvidenceEvent {
                event_id: format!("{run_id}-risk"),
                event_type: "risk_recorded".to_string(),
                ts_utc: "2026-01-01T00:00:04Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({
                    "risk_id": "risk-1",
                    "risk_class": "high",
                    "ai_system_id": "as-1",
                    "dataset_id": "ds-1",
                    "model_version_id": "mv-1"
                }),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
            EvidenceEvent {
                event_id: format!("{run_id}-review"),
                event_type: "risk_reviewed".to_string(),
                ts_utc: "2026-01-01T00:00:05Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({
                    "risk_id": "risk-1",
                    "decision": "approve",
                    "reviewer": "risk_officer"
                }),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
            EvidenceEvent {
                event_id: format!("{run_id}-human"),
                event_type: "human_approved".to_string(),
                ts_utc: "2026-01-01T00:00:06Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({
                    "scope": "model_promoted",
                    "decision": "approve",
                    "approver": "compliance_officer"
                }),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
            EvidenceEvent {
                event_id: format!("{run_id}-promote"),
                event_type: "model_promoted".to_string(),
                ts_utc: "2026-01-01T00:00:07Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({
                    "model_version_id": "mv-1",
                    "artifact_path": "registry://test/model"
                }),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
        ];
        for e in events {
            append_event(log_path, e);
        }
    }

    fn write_minimal_valid_run(tmp: &std::path::Path, tenant: &str, run_id: &str) -> String {
        let log_path = isolated_ledger_path(tmp, tenant);
        ensure_ledger_parent(&log_path);
        append_event(
            &log_path.to_string_lossy(),
            EvidenceEvent {
                event_id: format!("{run_id}-disc"),
                event_type: "ai_discovery_reported".to_string(),
                ts_utc: "2026-01-01T00:00:01Z".to_string(),
                actor: "t".to_string(),
                system: "t".to_string(),
                run_id: run_id.to_string(),
                environment: None,
                payload: json!({"openai": false, "transformers": false, "model_artifacts": false}),
                parent_run_id: None,
                root_run_id: None,
                delegated_from_event_id: None,
                agent_id: None,
                agent_role: None,
                delegation_reason: None,
            },
        );
        log_path.to_string_lossy().into_owned()
    }

    fn export_doc(
        run_id: &str,
        log_path: &str,
        tenant: &str,
    ) -> Value {
        build_audit_export_v1(
            run_id,
            tenant,
            log_path,
            "test-policy",
            GovaiEnvironment::Dev,
            &PolicyConfig::default(),
        )
        .expect("export")
    }

    const SCHEMA_REQUIRED_TOP_LEVEL: &[&str] = &[
        "ok",
        "schema_version",
        "policy_version",
        "environment",
        "exported_at_utc",
        "tenant",
        "run",
        "evidence_hashes",
        "decision",
        "evidence_requirements",
        "evidence_events",
        "timestamps",
    ];

    #[test]
    fn export_schema_version_and_hashes() {
        let tmp = TempDir::new().unwrap();
        let run_id = "export-run-1";
        let log_path = write_minimal_valid_run(tmp.path(), "tenant-x", run_id);
        let doc = export_doc(run_id, &log_path, "tenant-x");
        assert_eq!(
            doc.get("schema_version").and_then(|v| v.as_str()),
            Some("aigov.audit_export.v1")
        );
        let hashes = doc.get("evidence_hashes").expect("hashes");
        assert!(hashes.get("bundle_sha256").is_some());
        assert!(hashes.get("events_content_sha256").is_some());
    }

    #[test]
    fn export_full_event_chain_and_schema_shape() {
        let tmp = TempDir::new().unwrap();
        let run_id = "export-full-chain";
        let log_path = isolated_ledger_path(tmp.path(), "tenant-full");
        ensure_ledger_parent(&log_path);
        write_golden_path_run(&log_path.to_string_lossy(), run_id);
        let log_path = log_path.to_string_lossy().into_owned();
        let doc = export_doc(run_id, &log_path, "tenant-full");

        for key in SCHEMA_REQUIRED_TOP_LEVEL {
            assert!(doc.get(key).is_some(), "missing top-level key {key}");
        }
        assert_eq!(
            doc.get("schema_version").and_then(|v| v.as_str()),
            Some(EXPORT_SCHEMA_V1)
        );

        let events = doc
            .get("evidence_events")
            .and_then(|v| v.as_array())
            .expect("evidence_events array");
        assert_eq!(events.len(), 7);

        let chain = doc
            .get("evidence_hashes")
            .and_then(|h| h.get("log_chain"))
            .and_then(|v| v.as_array())
            .expect("log_chain");
        assert_eq!(chain.len(), events.len());

        assert_eq!(doc["decision"]["verdict"], "VALID");
    }

    #[test]
    fn export_is_deterministic_for_identical_ledger() {
        let tmp = TempDir::new().unwrap();
        let run_id = "export-deterministic";
        let log_path = write_minimal_valid_run(tmp.path(), "tenant-det", run_id);
        let first = export_doc(run_id, &log_path, "tenant-det");
        let second = export_doc(run_id, &log_path, "tenant-det");

        assert_eq!(
            first["evidence_hashes"]["events_content_sha256"],
            second["evidence_hashes"]["events_content_sha256"]
        );
        assert_eq!(
            first["evidence_hashes"]["bundle_sha256"],
            second["evidence_hashes"]["bundle_sha256"]
        );

        let stable = serde_json::to_string(&first["evidence_events"]).expect("serialize");
        let digest = Sha256::digest(stable.as_bytes());
        let digest_hex = hex::encode(digest);
        let digest2 = Sha256::digest(
            serde_json::to_string(&second["evidence_events"])
                .expect("serialize")
                .as_bytes(),
        );
        assert_eq!(digest_hex, hex::encode(digest2));
    }

    #[test]
    fn export_includes_lineage_block_and_passes_replay_validation() {
        let tmp = TempDir::new().unwrap();
        let run_id = "export-lineage";
        let log_path = write_minimal_valid_run(tmp.path(), "tenant-lin", run_id);
        let doc = export_doc(run_id, &log_path, "tenant-lin");

        let lineage = doc.get("lineage").expect("lineage block");
        assert!(lineage.get("root_run_id").is_some());
        assert!(lineage.get("graph").is_some());

        let (report, _) = run_export_validations(&doc);
        assert!(report.is_ok(), "replay validation errors: {:?}", report.errors);
        assert!(report.events_content_sha256_ok);
    }

    /// Regression test for a real bug found while building an offline-replay
    /// demo: a per-run export used to report a false `chain_break` whenever
    /// ANY other run's event physically sat between two of this run's own
    /// records (e.g. a concurrently delegated sub-agent writing to the same
    /// shared ledger) or when one of this run's own events carried a
    /// timestamp out of physical order. Neither condition is tampering —
    /// both are routine in a multi-run, multi-agent ledger — so export must
    /// not flag either as a broken chain.
    #[test]
    fn export_survives_foreign_interleaved_records_and_out_of_order_timestamps() {
        let tmp = TempDir::new().unwrap();
        let run_id = "target-run";
        let other_run_id = "other-run";
        let log_path = isolated_ledger_path(tmp.path(), "tenant-interleave");
        ensure_ledger_parent(&log_path);
        let log_path = log_path.to_string_lossy().into_owned();

        let base_event = |event_id: &str, event_type: &str, run: &str, ts: &str| EvidenceEvent {
            event_id: event_id.to_string(),
            event_type: event_type.to_string(),
            ts_utc: ts.to_string(),
            actor: "t".to_string(),
            system: "t".to_string(),
            run_id: run.to_string(),
            environment: None,
            payload: json!({}),
            parent_run_id: None,
            root_run_id: None,
            delegated_from_event_id: None,
            agent_id: None,
            agent_role: None,
            delegation_reason: None,
        };

        // Physical order: target, FOREIGN (other run), target (with an
        // out-of-order ts_utc earlier than the record before it), target.
        append_event(
            &log_path,
            base_event("t1", "data_registered", run_id, "2026-01-01T00:00:10Z"),
        );
        append_event(
            &log_path,
            base_event("o1", "evaluation_reported", other_run_id, "2026-01-01T00:00:11Z"),
        );
        append_event(
            &log_path,
            // Earlier timestamp than t1 above, even though it's physically later.
            base_event("t2", "model_trained", run_id, "2026-01-01T00:00:05Z"),
        );
        append_event(
            &log_path,
            base_event("t3", "ai_discovery_reported", run_id, "2026-01-01T00:00:12Z"),
        );

        let doc = export_doc(run_id, &log_path, "tenant-interleave");
        let chain = doc
            .get("evidence_hashes")
            .and_then(|h| h.get("log_chain"))
            .and_then(|v| v.as_array())
            .expect("log_chain");
        assert_eq!(chain.len(), 3, "foreign run's event must not appear in this run's chain");

        let (report, _) = run_export_validations(&doc);
        assert!(
            report.chain_continuity_ok,
            "false chain_break on untampered, merely interleaved/reordered data: {:?}",
            report.errors
        );
        assert!(report.is_ok(), "replay validation errors: {:?}", report.errors);

        // And genuine tampering — flipping one record_hash — must still be caught.
        let mut tampered = doc.clone();
        let tampered_chain = tampered["evidence_hashes"]["log_chain"]
            .as_array_mut()
            .unwrap();
        let rh = tampered_chain[1]["record_hash"].as_str().unwrap().to_string();
        let flipped = format!("{}{}", &rh[..rh.len() - 1], if rh.ends_with('0') { '1' } else { '0' });
        tampered_chain[1]["record_hash"] = json!(flipped);
        let (tampered_report, _) = run_export_validations(&tampered);
        assert!(
            !tampered_report.chain_continuity_ok,
            "tampering a record_hash must still be detected"
        );
    }
}
