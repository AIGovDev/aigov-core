# From evidence events to a policy gate

AI governance often begins as a checklist: describe the system, gather approvals, retain documentation, and review it later. Engineers still need an answer at the point where a run is proposed for promotion: what evidence was recorded, what policy applied, and what condition blocked or permitted the next step?

AIGov Core is an open-source experiment in making that path explicit. Its Rust audit runtime accepts structured evidence and appends it to a tenant-scoped ledger. A configured policy consumes the ledger projection and produces one of three outcomes: VALID, INVALID or BLOCKED. A run with missing prerequisites remains BLOCKED; a decisive policy failure is INVALID; VALID means the configured process requirements passed for the recorded run. It does not mean the model output is correct.

## What the chain contributes

Each ledger record links to a predecessor through a cryptographic digest. A verifier can recompute the digests and detect an altered record or broken link. That helps preserve consistency between copies of a recorded history.

The boundary matters. If an operator replaces the whole export and recomputes every digest, a self-contained chain can still be internally consistent. The chain alone does not establish who created the export, whether a signer is trusted, whether a real-world action occurred, whether all relevant events were submitted, or whether the system complies with law. Stronger claims require independent trust roots, authenticated submission, trusted timestamps where needed, and controls outside the ledger.

## A small local walkthrough

The repository documents a five-minute quickstart that starts the runtime locally, submits a sample event, reads the compliance summary and inspects an export. One event is expected to be BLOCKED because the configured promotion sequence is incomplete. This checkout's clean-install reproduction is still pending: the environment lacks the Rust toolchain. The deterministic demo is documented as a complete expected flow. The sample is synthetic; operators should not upload confidential evidence to a public demo.

For an integration, the important design review is not only whether an event can be posted. Ask whether the identity maps to a server-side tenant, whether approval binds to the exact run and action, how a consumed approval is protected against replay, and what happens if the process crashes after authorization but before the audit record is written.

## What the current evaluation says

The project's 20-scenario synthetic benchmark measured 0.90 accuracy for its evidence-verification condition, with two false accepts. The false accepts show that a structurally valid evidence chain can still lack correct authorization context or disagree with external state. The benchmark used no live language model, has a small sample, and was designed by the same engineer who implemented the verifier. It is a starting point for external critique, not a production safety claim.

## Where this fits

Observability systems collect traces, metrics and logs; experiment tracking records model runs and artifacts; evaluation tools score behavior. Those signals can inform a governance ledger. AIGov Core focuses on connecting supplied evidence to a configured policy decision and preserving an inspectable record of that decision. These categories can complement each other; this project has not published a head-to-head comparison.

The next technical milestone is an independent security review that examines the trust boundaries, approval and key lifecycle, tenant isolation, concurrent execution, crash recovery and supply chain. Until that review is completed, the project's internal tests remain precisely that: internal validation.

## References and reproducibility

- Five-minute quickstart: docs/quickstart-5min.md
- Trust model: docs/trust-model.md
- External audit preparation and invariant map: docs/security/external-audit-preparation.md
- Full benchmark report: docs/reports/aigov-independent-benchmark-2026-11-19.md
- Public benchmark summary: docs/launch/benchmark-report.md

All examples use the repository state linked from the release materials. Run them from a clean checkout and compare outputs against the documented expected behavior.
