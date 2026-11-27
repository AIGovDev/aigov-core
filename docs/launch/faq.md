# AIGov Core launch FAQ

## What does AIGov Core do?

It accepts structured evidence, stores records in a tenant-scoped ledger, applies configured policy and exposes an explicit VALID, INVALID or BLOCKED projection with export and verification paths.

## Does a valid hash chain prove that an action happened?

No. It shows that the supplied records are internally consistent relative to their chain. It does not establish factual truth, completeness, origin, signer identity, trusted time, external action occurrence or legal compliance.

## Is this a replacement for observability?

No. Telemetry and model-evaluation tools can provide context or evidence. AIGov Core focuses on policy-linked evidence handling, verdict projection and promotion gates.

## Is there a hosted demo?

The static viewer package exists in the repository. A public Space must not be claimed until it is created, deployed and verified in a real browser.

## Has the project passed an independent security audit?

No independent external review is verified. The repository contains internal tests and review reports; those are not independent assurance. The audit scope and evidence crosswalk are documented in docs/security/external-audit-preparation.md.

## What has been benchmarked?

A 20-scenario synthetic agent-verification study reported 0.90 accuracy with two false accepts. It did not use a live agent or production workload. See docs/launch/benchmark-report.md and the full dated report.

## Is AIGov Core legally compliant with the EU AI Act?

The project can support technical evidence and policy workflows. It is not legal advice, certification or proof of compliance.
