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
    enforce_ingest_at, EventTypeRule, FieldType, Gate, LedgerView, PayloadSchema, RuntimePolicy,
    UnknownEventTypeBehavior,
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
