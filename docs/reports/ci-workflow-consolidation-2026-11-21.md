# CI workflow consolidation — 2026-11-21

## Scope and motivation

This change is limited to GitHub Actions workflow maintenance. It reduces redundant checks while retaining the existing compliance, supply-chain, security, branch policy, and contributor agreement enforcement boundaries.

## Changes and impact

1. `oss-developer-experience`: remove redundant explicit Cursor-plugin and SDK checks. The remaining `make enterprise-readiness-check` already invokes `make cursor-plugin-check` and `make public-sdk-packages-check`, and the workflow continues to export the SDK JSON artifact.
2. `supply-chain-audit`: the Dependabot configuration validation installs PyYAML instead of the entire Python SDK development dependency set. `scripts/check_dependabot_config.py` requires PyYAML and the Python standard library. Rust `cargo audit` and Python `pip-audit` remain unchanged.
3. Rename contributor-agreement workflows to distinguish enforcement, unit tests, independent audit, workflow security, and retired legacy workflow. Retain existing job IDs and status-check names.
4. Scope contributor-agreement unit tests to changes of the CLA implementation and associated test/workflow files. Security guard and production enforcement remain in place.

## Risks and mitigations

- **Required checks:** Job IDs and required check contexts are preserved. Path scoping can make a required check absent on unrelated PRs; branch-protection/ruleset configuration must be verified before merge.
- **Audit traceability:** The retired legacy workflow is left unchanged in execution behavior, retaining the signature history and historical audit context.
- **Dependency drift:** PyYAML is the only non-standard-library import in the Dependabot validator at the inspected revision. CI must validate the minimal installation on a clean runner.
- **Verification coverage:** Removing duplicate command invocations does not remove their corresponding checks from the aggregate `enterprise-readiness-check`.

## Evaluation gate

**Status: PENDING final CI and branch-protection validation.** No weakening of the report gate or other compliance jobs is requested.

Review acceptance criteria:

- `compliance / report_gate`, `compliance / make_verify`, and downstream evidence jobs pass.
- `oss-developer-experience` passes on the modified workflow.
- `supply-chain-audit` passes with the minimal Dependabot validation environment.
- Contributor-agreement status `CLA v2 / agreement` remains successful and protection requirements remain satisfiable.
- Security and branch-policy checks pass.

No merge or production deployment is authorized by this report.

## Human approval gate

**PENDING.** Changes remain in draft/review until required checks and branch-protection behavior are verified. A human maintainer must explicitly authorize merge.
