//! Ingest gates for agent tool calls: an approval must exist, be approved, be in scope and in date, be
//! linked to the call, and be consumed at most once. Approval timestamps must be near server time at ingest.
//!
//! The race test uses the real ledger file and the real locked append, so it checks what production does.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};

use aigov_audit::audit_store::{
    append_record_atomic_with_run_count, append_record_checked, CheckedAppendError,
};
use aigov_audit::ledger_view::FileLedgerView;
use aigov_audit::policy_engine::{
    enforce_ingest_at, EventTypeRule, FieldType, Gate, LedgerView, PayloadSchema,
    PrincipalRelation, RuntimePolicy, UnknownEventTypeBehavior,
};
use aigov_audit::schema::EvidenceEvent;
use chrono::{DateTime, Utc};
use serde_json::json;

const RUN: &str = "run-tool-1";
const APPROVED_AT: &str = "2026-11-25T10:00:00Z";

fn rule(required: &[(&str, FieldType)], nonempty: &[&str], gates: Vec<Gate>) -> EventTypeRule {
    EventTypeRule {
        payload_schema: PayloadSchema {
            required: required
                .iter()
                .map(|(k, t)| (k.to_string(), t.clone()))
                .collect::<BTreeMap<_, _>>(),
            required_nonempty_strings: nonempty
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>(),
        },
        gates,
    }
}

fn policy() -> RuntimePolicy {
    let mut event_rules = BTreeMap::new();
    event_rules.insert(
        "human_approved".to_string(),
        rule(
            &[
                ("decision", FieldType::String),
                ("scope", FieldType::String),
            ],
            &["decision", "scope", "tool_call_id"],
            vec![Gate::RequiresTimestampNearServerTime {
                max_skew_seconds: 60,
                code: "approval_not_fresh".into(),
                message: "policy_violation: approval timestamp is not near server time".into(),
            }],
        ),
    );
    event_rules.insert(
        "consequential_tool_call".to_string(),
        rule(
            &[("tool_name", FieldType::String)],
            &["tool_name", "approval_event_id", "tool_call_id"],
            vec![
                Gate::RequiresDecisionEnum {
                    field: "tool_name".into(),
                    allowed: vec!["create_file".into()],
                    code: "tool_not_permitted".into(),
                    message: "policy_violation: tool is not permitted for this agent".into(),
                },
                Gate::RequiresUnconsumedApproval {
                    approval_field: "approval_event_id".into(),
                    scope: "tool_execution".into(),
                    max_age_seconds: 300,
                    linkage_keys: vec!["tool_call_id".into()],
                    code: "approval_required".into(),
                    message: "policy_violation: a human approval is required".into(),
                },
            ],
        ),
    );
    RuntimePolicy {
        policy_id: "tool-gate-test".into(),
        version: "1".into(),
        unknown_event_types: UnknownEventTypeBehavior::Reject,
        event_rules,
    }
}

fn ev(event_id: &str, event_type: &str, ts: &str, payload: serde_json::Value) -> EvidenceEvent {
    EvidenceEvent {
        event_id: event_id.into(),
        event_type: event_type.into(),
        ts_utc: ts.into(),
        actor: "test".into(),
        system: "test".into(),
        run_id: RUN.into(),
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

fn approval(event_id: &str, decision: &str, scope: &str, ts: &str) -> EvidenceEvent {
    ev(
        event_id,
        "human_approved",
        ts,
        json!({"decision": decision, "scope": scope, "tool_call_id": "call-1"}),
    )
}

fn call(event_id: &str, tool: &str, approval_id: &str, call_id: &str) -> EvidenceEvent {
    ev(
        event_id,
        "consequential_tool_call",
        "2026-11-25T10:01:00Z",
        json!({"tool_name": tool, "approval_event_id": approval_id, "tool_call_id": call_id}),
    )
}

struct Ledger(Vec<EvidenceEvent>);

impl LedgerView for Ledger {
    fn iter_events_for_run<'a>(
        &'a self,
        run_id: &'a str,
    ) -> Box<dyn Iterator<Item = EvidenceEvent> + 'a> {
        Box::new(self.0.iter().filter(move |e| e.run_id == run_id).cloned())
    }
}

fn now_at(ts: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(ts)
        .unwrap()
        .with_timezone(&Utc)
}

fn check(ledger: &[EvidenceEvent], event: &EvidenceEvent, now: &str) -> Result<(), String> {
    enforce_ingest_at(&policy(), event, &Ledger(ledger.to_vec()), now_at(now))
        .map_err(|v| v.message)
}

#[test]
fn approved_in_date_call_is_authorized() {
    let ledger = vec![approval("apr-1", "approve", "tool_execution", APPROVED_AT)];
    let c = call("call-ev-1", "create_file", "apr-1", "call-1");
    assert!(check(&ledger, &c, "2026-11-25T10:01:00Z").is_ok());
}

#[test]
fn rejected_approval_is_refused() {
    let ledger = vec![approval("apr-1", "reject", "tool_execution", APPROVED_AT)];
    let err = check(
        &ledger,
        &call("c", "create_file", "apr-1", "call-1"),
        "2026-11-25T10:01:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_not_approved"), "{err}");
}

#[test]
fn approval_for_another_scope_is_refused() {
    let ledger = vec![approval("apr-1", "approve", "model_promoted", APPROVED_AT)];
    let err = check(
        &ledger,
        &call("c", "create_file", "apr-1", "call-1"),
        "2026-11-25T10:01:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_scope_mismatch"), "{err}");
}

#[test]
fn expired_approval_is_refused() {
    let ledger = vec![approval("apr-1", "approve", "tool_execution", APPROVED_AT)];
    let err = check(
        &ledger,
        &call("c", "create_file", "apr-1", "call-1"),
        "2026-11-25T10:06:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_expired"), "{err}");
}

#[test]
fn approval_used_for_a_second_call_is_refused() {
    let ledger = vec![
        approval("apr-1", "approve", "tool_execution", APPROVED_AT),
        call("call-ev-1", "create_file", "apr-1", "call-1"),
    ];
    let err = check(
        &ledger,
        &call("call-ev-2", "create_file", "apr-1", "call-1"),
        "2026-11-25T10:02:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_already_consumed"), "{err}");
}

#[test]
fn call_without_an_approval_is_refused() {
    let err = check(
        &[],
        &call("c", "create_file", "apr-missing", "call-1"),
        "2026-11-25T10:01:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_not_found"), "{err}");
}

#[test]
fn approval_linked_to_another_call_is_refused() {
    let ledger = vec![approval("apr-1", "approve", "tool_execution", APPROVED_AT)];
    let err = check(
        &ledger,
        &call("c", "create_file", "apr-1", "call-OTHER"),
        "2026-11-25T10:01:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_linkage_mismatch"), "{err}");
}

#[test]
fn tool_outside_the_allowlist_is_refused_even_with_approval() {
    let ledger = vec![approval("apr-1", "approve", "tool_execution", APPROVED_AT)];
    let err = check(
        &ledger,
        &call("c", "request_deployment", "apr-1", "call-1"),
        "2026-11-25T10:01:00Z",
    )
    .unwrap_err();
    assert!(err.contains("tool is not permitted"), "{err}");
}

#[test]
fn backdated_approval_is_refused_at_ingest() {
    let stale = approval("apr-1", "approve", "tool_execution", "2026-11-25T09:00:00Z");
    let err = check(&[], &stale, "2026-11-25T10:00:00Z").unwrap_err();
    assert!(
        err.contains("approval timestamp is not near server time"),
        "{err}"
    );
}

#[test]
fn approval_in_the_future_is_refused() {
    let ledger = vec![approval(
        "apr-1",
        "approve",
        "tool_execution",
        "2026-11-25T10:00:30Z",
    )];
    let err = check(
        &ledger,
        &call("c", "create_file", "apr-1", "call-1"),
        "2026-11-25T10:00:00Z",
    )
    .unwrap_err();
    assert!(err.contains("reason=approval_in_future"), "{err}");
}

#[test]
fn concurrent_calls_cannot_both_consume_one_approval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let path_str = path.to_str().unwrap().to_string();
    append_record_atomic_with_run_count(
        &path_str,
        approval(
            "apr-1",
            "approve",
            "tool_execution",
            &Utc::now().to_rfc3339(),
        ),
    )
    .expect("approval append");

    let threads = 8;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|i| {
            let path_str = path_str.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let event = call(&format!("call-ev-{i}"), "create_file", "apr-1", "call-1");
                let policy = policy();
                let for_check = event.clone();
                let check = |p: &str| {
                    let view = FileLedgerView::new(p);
                    enforce_ingest_at(&policy, &for_check, &view, Utc::now()).map_err(|v| v.message)
                };
                barrier.wait();
                append_record_checked(&path_str, event, &check)
            })
        })
        .collect();

    let mut accepted = 0;
    let mut rejected = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => accepted += 1,
            Err(CheckedAppendError::Rejected(msg)) => {
                assert!(msg.contains("approval_already_consumed"), "{msg}");
                rejected += 1;
            }
            Err(CheckedAppendError::Store(msg)) => panic!("unexpected store error: {msg}"),
        }
    }
    assert_eq!(accepted, 1, "exactly one call may consume the approval");
    assert_eq!(rejected, threads - 1);
}

// ---- Trusted execution: authenticated approvers, self-approval, revocation, and receipts ----

fn trusted_policy() -> RuntimePolicy {
    let mut event_rules = BTreeMap::new();
    event_rules.insert(
        "tool_approval_requested".to_string(),
        rule(
            &[],
            &["tool_name", "tool_call_id", "args_binding_hash"],
            vec![],
        ),
    );
    event_rules.insert(
        "human_approved".to_string(),
        rule(
            &[],
            &[
                "approver",
                "decision",
                "scope",
                "tool_call_id",
                "args_binding_hash",
                "tool_name",
                "policy_revision",
                "request_event_id",
            ],
            vec![
                Gate::RequiresFieldMatchesField {
                    field: "approver".into(),
                    other_field: "authenticated_identity".into(),
                    code: "approver_identity_mismatch".into(),
                    message: "policy_violation: approver does not match the authenticated identity"
                        .into(),
                },
                Gate::RequiresPrincipalRelation {
                    reference_field: "request_event_id".into(),
                    relation: PrincipalRelation::Distinct,
                    code: "self_approval_refused".into(),
                    message: "policy_violation: an approver may not approve their own request"
                        .into(),
                },
            ],
        ),
    );
    event_rules.insert(
        "human_approval_revoked".to_string(),
        rule(
            &[],
            &["approval_event_id", "reason"],
            vec![Gate::RequiresPrincipalRelation {
                reference_field: "approval_event_id".into(),
                relation: PrincipalRelation::Same,
                code: "revocation_not_by_approver".into(),
                message: "policy_violation: only the approver who gave the approval may revoke it"
                    .into(),
            }],
        ),
    );
    event_rules.insert(
        "consequential_tool_call".to_string(),
        rule(
            &[],
            &[
                "tool_name",
                "approval_event_id",
                "tool_call_id",
                "args_binding_hash",
                "policy_revision",
            ],
            vec![Gate::RequiresUnconsumedApproval {
                approval_field: "approval_event_id".into(),
                scope: "tool_execution".into(),
                max_age_seconds: 300,
                linkage_keys: vec![
                    "tool_name".into(),
                    "tool_call_id".into(),
                    "args_binding_hash".into(),
                    "policy_revision".into(),
                ],
                code: "approval_required".into(),
                message: "policy_violation: a human approval is required".into(),
            }],
        ),
    );
    event_rules.insert(
        "execution_receipt".to_string(),
        rule(
            &[],
            &[
                "execution_authorization_id",
                "tool_name",
                "args_binding_hash",
                "outcome",
                "result_digest",
            ],
            vec![Gate::RequiresIssuedAuthorization {
                authorization_field: "execution_authorization_id".into(),
                code: "authorization_not_issued".into(),
                message: "policy_violation: no issued authorization matches this receipt".into(),
            }],
        ),
    );
    RuntimePolicy {
        policy_id: "trusted-test".into(),
        version: "1".into(),
        unknown_event_types: UnknownEventTypeBehavior::Reject,
        event_rules,
    }
}

fn check_trusted(ledger: &[EvidenceEvent], event: &EvidenceEvent) -> Result<(), String> {
    enforce_ingest_at(
        &trusted_policy(),
        event,
        &Ledger(ledger.to_vec()),
        now_at("2026-11-25T10:01:00Z"),
    )
    .map_err(|v| v.message)
}

/// A human_approved event carrying the authenticated fields Core stamps server-side.
fn approval_by(
    event_id: &str,
    approver_identity: &str,
    principal: &str,
    claimed: &str,
    request_id: &str,
) -> EvidenceEvent {
    ev(
        event_id,
        "human_approved",
        "2026-11-25T10:00:00Z",
        json!({
            "approver": claimed,
            "decision": "approve",
            "scope": "tool_execution",
            "tool_name": "create_file",
            "tool_call_id": "call-1",
            "args_binding_hash": "h1",
            "policy_revision": "1",
            "request_event_id": request_id,
            "authenticated_identity": approver_identity,
            "authenticated_principal": principal,
        }),
    )
}

fn request_by(event_id: &str, principal: &str) -> EvidenceEvent {
    ev(
        event_id,
        "tool_approval_requested",
        "2026-11-25T09:59:00Z",
        json!({"tool_name": "create_file", "tool_call_id": "call-1", "args_binding_hash": "h1",
               "authenticated_principal": principal, "policy_revision": "1"}),
    )
}

fn write_call(event_id: &str, approval_id: &str) -> EvidenceEvent {
    ev(
        event_id,
        "consequential_tool_call",
        "2026-11-25T10:01:00Z",
        json!({"tool_name": "create_file", "tool_call_id": "call-1", "args_binding_hash": "h1",
               "approval_event_id": approval_id, "policy_revision": "1"}),
    )
}

#[test]
fn approver_naming_someone_else_is_refused() {
    let req = request_by("req-1", "agent:bot");
    let appr = approval_by(
        "apr-1",
        "maintainer@acme-corp.example",
        "approver:maintainer",
        "lead@acme-corp.example",
        "req-1",
    );
    let err = check_trusted(&[req], &appr).unwrap_err();
    assert!(err.contains("reason=approver_identity_mismatch"), "{err}");
}

#[test]
fn approval_of_your_own_request_is_refused() {
    let req = request_by("req-1", "approver:maintainer");
    let appr = approval_by(
        "apr-1",
        "maintainer@acme-corp.example",
        "approver:maintainer",
        "maintainer@acme-corp.example",
        "req-1",
    );
    let err = check_trusted(&[req], &appr).unwrap_err();
    assert!(err.contains("reason=self_approval_refused"), "{err}");
}

#[test]
fn approval_by_a_different_approver_is_accepted() {
    let req = request_by("req-1", "agent:bot");
    let appr = approval_by(
        "apr-1",
        "maintainer@acme-corp.example",
        "approver:maintainer",
        "maintainer@acme-corp.example",
        "req-1",
    );
    assert!(check_trusted(&[req], &appr).is_ok());
}

#[test]
fn only_the_approver_may_revoke() {
    let req = request_by("req-1", "agent:bot");
    let appr = approval_by(
        "apr-1",
        "maintainer@acme-corp.example",
        "approver:maintainer",
        "maintainer@acme-corp.example",
        "req-1",
    );
    let by_other = ev(
        "rev-1",
        "human_approval_revoked",
        "2026-11-25T10:00:30Z",
        json!({"approval_event_id": "apr-1", "reason": "x", "authenticated_principal": "approver:lead"}),
    );
    let err = check_trusted(&[req.clone(), appr.clone()], &by_other).unwrap_err();
    assert!(err.contains("reason=revocation_not_by_approver"), "{err}");
    let by_same = ev(
        "rev-2",
        "human_approval_revoked",
        "2026-11-25T10:00:30Z",
        json!({"approval_event_id": "apr-1", "reason": "x", "authenticated_principal": "approver:maintainer"}),
    );
    assert!(check_trusted(&[req, appr], &by_same).is_ok());
}

#[test]
fn revoked_approval_is_refused_and_revocation_is_not_a_consumption() {
    let req = request_by("req-1", "agent:bot");
    let appr = approval_by(
        "apr-1",
        "maintainer@acme-corp.example",
        "approver:maintainer",
        "maintainer@acme-corp.example",
        "req-1",
    );
    let revoked = ev(
        "rev-1",
        "human_approval_revoked",
        "2026-11-25T10:00:30Z",
        json!({"approval_event_id": "apr-1", "reason": "withdrawn", "authenticated_principal": "approver:maintainer"}),
    );
    let call = write_call("call-ev-1", "apr-1");
    let err = check_trusted(&[req, appr, revoked], &call).unwrap_err();
    assert!(err.contains("reason=approval_revoked"), "{err}");
    assert!(
        !err.contains("already_consumed"),
        "a revocation must not count as a consumption: {err}"
    );
}

#[test]
fn receipt_needs_the_matching_issued_authorization_and_is_recorded_once() {
    let issued = ev(
        "call-ev-1",
        "consequential_tool_call",
        "2026-11-25T10:01:00Z",
        json!({"tool_name": "create_file", "args_binding_hash": "h1", "approval_event_id": "apr-1",
               "execution_authorization_id": "auth_1"}),
    );
    let receipt = |id: &str, digest: &str| {
        ev(
            id,
            "execution_receipt",
            "2026-11-25T10:02:00Z",
            json!({"execution_authorization_id": "auth_1", "tool_name": "create_file", "args_binding_hash": digest,
               "outcome": "success", "result_digest": "r"}),
        )
    };

    assert!(check_trusted(&[issued.clone()], &receipt("rcpt-1", "h1")).is_ok());

    let err = check_trusted(&[issued.clone()], &receipt("rcpt-2", "OTHER")).unwrap_err();
    assert!(err.contains("reason=authorization_not_issued"), "{err}");

    let first = receipt("rcpt-1", "h1");
    let err = check_trusted(&[issued.clone(), first], &receipt("rcpt-3", "h1")).unwrap_err();
    assert!(
        err.contains("reason=authorization_not_issued"),
        "a second receipt must be refused: {err}"
    );

    let unknown = ev(
        "rcpt-4",
        "execution_receipt",
        "2026-11-25T10:02:00Z",
        json!({"execution_authorization_id": "auth_none", "tool_name": "create_file", "args_binding_hash": "h1",
               "outcome": "success", "result_digest": "r"}),
    );
    assert!(check_trusted(&[issued], &unknown).is_err());
}

#[test]
fn read_authorization_can_be_receipted() {
    let read = ev(
        "read-1",
        "tool_call",
        "2026-11-25T10:01:00Z",
        json!({"tool_name": "read_repo_metadata", "args_binding_hash": "rh", "execution_authorization_id": "auth_r"}),
    );
    let receipt = ev(
        "rcpt-r",
        "execution_receipt",
        "2026-11-25T10:02:00Z",
        json!({"execution_authorization_id": "auth_r", "tool_name": "read_repo_metadata", "args_binding_hash": "rh",
               "outcome": "success", "result_digest": "r"}),
    );
    assert!(check_trusted(&[read], &receipt).is_ok());
}

#[test]
fn huggingface_observation_cannot_satisfy_passed_evaluation_gate() {
    let mut p = policy();
    p.event_rules.insert(
        "huggingface_evaluation_observed".into(),
        rule(&[], &["record_sha256"], vec![]),
    );
    p.event_rules.insert(
        "model_promoted".into(),
        rule(
            &[],
            &[],
            vec![Gate::RequiresPassedEvaluation {
                code: "evaluation_required".into(),
                message: "passed evaluation required".into(),
            }],
        ),
    );
    let observation = ev(
        "hf-1",
        "huggingface_evaluation_observed",
        APPROVED_AT,
        json!({"record_sha256": "a".repeat(64), "passed": true}),
    );
    let now = now_at(APPROVED_AT);
    assert!(enforce_ingest_at(&p, &observation, &Ledger(vec![]), now).is_ok());
    let promotion = ev("promote-1", "model_promoted", APPROVED_AT, json!({}));
    assert!(enforce_ingest_at(&p, &promotion, &Ledger(vec![observation]), now).is_err());
    let evaluation = ev("eval-1", "evaluation_reported", APPROVED_AT, json!({"passed": true}));
    assert!(enforce_ingest_at(&p, &promotion, &Ledger(vec![evaluation]), now).is_ok());
}
