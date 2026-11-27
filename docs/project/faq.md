# AIGov Core Frequently Asked Questions

## What is AIGov Core?

AIGov Core is a decision-level AI governance platform that verifies whether deployment and governance decisions are supported by complete, verifiable, and auditable evidence.

## What problem does AIGov Core solve?

AIGov Core addresses the auditability gap: the mismatch between model-centric validation and decision-level accountability.

## Is AIGov Core a model evaluation tool?

No. AIGov Core does not replace model evaluation. It verifies whether governance and deployment decisions are supported by sufficient evidence.

## What does AIGov Core enforce?

AIGov Core enforces evidence completeness, evaluation status, approval requirements, artifact continuity, and tenant isolation.

## What happens when evidence is missing?

AIGov Core fails closed. Incomplete or unsupported decisions should result in BLOCKED rather than VALID.

## What are VALID, INVALID, and BLOCKED?

- VALID means all required evidence is present and checks passed.
- INVALID means evaluation failed.
- BLOCKED means required evidence, approvals, or audit context is missing.

## How does AIGov Core verify artifact integrity?

AIGov Core uses digest continuity to bind audit records to concrete artifacts.

## How is tenant isolation enforced?

Tenant identity is derived from server-owned API key mappings rather than request headers.

## Can AIGov Core run locally?

Yes. AIGov Core supports local deployments and a Docker Compose demo.

## Is a hosted service available?

Yes. AIGov Core supports hosted compliance gate deployments and may be offered as a managed service.

## Who is AIGov Core for?

AIGov Core is intended for AI engineers, MLOps teams, security teams, compliance teams, auditors, and researchers.

## Does AIGov Core guarantee legal compliance?

No. AIGov Core provides technical controls and evidence, but legal compliance depends on broader organizational and regulatory factors.

## How is AIGov Core monetized?

Potential monetization paths include hosted services, enterprise features, advisory work, and training.

## Where should new users start?

New users should read the README, run the local demo, and review the one-page overview and threat model.
