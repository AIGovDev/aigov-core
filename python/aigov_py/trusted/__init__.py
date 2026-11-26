"""Trusted execution for AIGov Core: the public SDK interface.

What a customer application imports:

- configuration and a run: ``IntegrationConfig``, ``Tool`` (``ToolSpec``), ``Integration``, ``start_core``, ``stop_core``
- the roles: ``AgentActor``, ``ApproverActor``, ``Executor``, ``ExecutionStore``
- the lifecycle: ``State``, ``ReceiptState``, ``RecoveryAction``
- decisions and Core's client: ``Decision``, ``CoreDecision``, ``CoreClient``
- refusals and outcomes: ``ExecutionOutcome``, ``Refused``, ``ReconciliationRefused``
- reconciliation: ``ReconcilerRegistry``, ``make_payload``, ``sign_evidence``, ``apply_reconciliation``,
  ``apply_escalation``, ``verify_reconciliation``
- receipts and visibility: ``deliver_pending``, ``report``
- independent verification: ``verify_authorization_signature``, ``offline_evidence_checks``
- schema (run by the operator, never by the executor): ``migrate``, ``SCHEMA_VERSION``
- policy and provisioning: ``build_policy_document``, ``provision``

Nothing here imports from ``examples/``. The framework adapters are not part of this package.
See ``docs/trusted-execution-sdk.md`` and ``docs/operations/executor-store-runbook.md``.
"""

from .actors import AgentActor, ApproverActor
from .authorization import Refused, verify_authorization_signature
from .core import CoreClient, CoreDecision, Decision, new_event
from .evidence import offline_evidence_checks
from .executor import (
    ExecutionOutcome,
    Executor,
    Performer,
    RecoveryAction,
    result_digest,
)
from .integration import Integration, IntegrationConfig, Tool, start_core, stop_core
from .launch import Running
from .lifecycle import ReceiptState, State
from .policy import (
    build_policy_document,
    generate_signing_keys,
    trust_store_json,
    write_signed_policy,
)
from .provision import load_state, provision
from .receipts import deliver_pending
from .reconcile import (
    RECON_SCHEMA,
    ReconcilerRegistry,
    ReconciliationRefused,
    apply_escalation,
    apply_reconciliation,
    make_payload,
    sign_evidence,
    verify_reconciliation,
)
from .store import (
    SCHEMA_VERSION,
    ExecutionStore,
    ExecutionStoreError,
    ExecutionStoreIntegrityError,
    ExecutionStoreSchemaError,
    SchemaMissing,
    SchemaVersionMismatch,
)
from .store_admin import migrate
from .tools import ToolSpec, args_binding_hash, resource_id, tool_registry
from .visibility import report

__all__ = [
    "RECON_SCHEMA",
    "SCHEMA_VERSION",
    "AgentActor",
    "ApproverActor",
    "CoreClient",
    "CoreDecision",
    "Decision",
    "ExecutionOutcome",
    "ExecutionStore",
    "ExecutionStoreError",
    "ExecutionStoreIntegrityError",
    "ExecutionStoreSchemaError",
    "Executor",
    "Integration",
    "IntegrationConfig",
    "Performer",
    "ReceiptState",
    "ReconcilerRegistry",
    "ReconciliationRefused",
    "RecoveryAction",
    "Refused",
    "Running",
    "SchemaMissing",
    "SchemaVersionMismatch",
    "State",
    "Tool",
    "ToolSpec",
    "apply_escalation",
    "apply_reconciliation",
    "args_binding_hash",
    "build_policy_document",
    "deliver_pending",
    "generate_signing_keys",
    "load_state",
    "make_payload",
    "migrate",
    "new_event",
    "offline_evidence_checks",
    "provision",
    "report",
    "resource_id",
    "result_digest",
    "sign_evidence",
    "start_core",
    "stop_core",
    "tool_registry",
    "trust_store_json",
    "verify_authorization_signature",
    "verify_reconciliation",
    "write_signed_policy",
]
