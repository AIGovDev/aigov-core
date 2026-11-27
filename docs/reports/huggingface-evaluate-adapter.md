# Hugging Face Evaluate result adapter

## Scope
Convert existing scalar metric results into versioned evaluation evidence without executing metric code.

## Risk assessment
Caller-reported results and digests do not prove execution or correctness. No raw predictions or references are required.

## Evaluation gate
Acceptance requires regression tests and repository CI. Live Evaluate compatibility remains pending.

## Human approval gate
Maintainer review and explicit merge approval required. Approval pending.

## Limitations
No nested metrics, automatic metric provenance, runtime policy enforcement or ledger submission.
