"""Trusted execution for AIGov Core: the public SDK interface.

What a customer application imports:

- configuration and a run: ``IntegrationConfig``, ``Tool`` (``ToolSpec``), ``Integration``, ``start_core``, ``stop_core``
- the four roles: ``AgentActor``, ``ApproverActor``, ``Executor``, ``ExecutionStore``
- decisions and Core's client: ``Decision``, ``CoreDecision``, ``CoreClient``
- the executor's outcome and refusal: ``ExecutionOutcome``, ``Refused``
- independent verification: ``verify_authorization_signature``, ``offline_evidence_checks``
- policy and provisioning: ``build_policy_document``, ``provision``

Nothing here imports from ``examples/``. The framework adapters (for example smolagents) are not part of this package.
See ``docs/trusted-execution-sdk.md`` for the API, the trust boundaries, and the production limitations.
"""

from .actors import AgentActor, ApproverActor
from .authorization import Refused, verify_authorization_signature
from .core import CoreClient, CoreDecision, Decision, new_event
from .evidence import offline_evidence_checks
from .executor import ExecutionOutcome, Executor, Performer, result_digest
from .integration import Integration, IntegrationConfig, Tool, start_core, stop_core
from .launch import Running
from .policy import (
    build_policy_document,
    generate_signing_keys,
    trust_store_json,
    write_signed_policy,
)
from .provision import load_state, provision
from .store import ExecutionStore, ExecutionStoreSchemaError, executor_store_migration
from .tools import ToolSpec, args_binding_hash, resource_id, tool_registry

__all__ = [
    "AgentActor",
    "ApproverActor",
    "CoreClient",
    "CoreDecision",
    "Decision",
    "ExecutionOutcome",
    "ExecutionStore",
    "ExecutionStoreSchemaError",
    "Executor",
    "Integration",
    "IntegrationConfig",
    "Performer",
    "Refused",
    "Running",
    "Tool",
    "ToolSpec",
    "args_binding_hash",
    "build_policy_document",
    "executor_store_migration",
    "generate_signing_keys",
    "load_state",
    "new_event",
    "offline_evidence_checks",
    "provision",
    "resource_id",
    "result_digest",
    "start_core",
    "stop_core",
    "tool_registry",
    "trust_store_json",
    "verify_authorization_signature",
    "write_signed_policy",
]
