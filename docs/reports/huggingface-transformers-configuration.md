# Transformers configuration evidence

## Scope
Allowlisted snapshot of already loaded model and generation configuration, with digest compatible with evaluation evidence.

## Risk assessment
Selected configuration is not proof of actual inference settings or execution. No arbitrary configuration serialization or prompts are collected. Caller must trust the loaded Python object.

## Evaluation gate
Acceptance requires offline regression tests and repository CI. Live Transformers execution remains unverified.

## Human approval gate
Maintainer review and explicit merge approval required. Approval pending.

## Limitations
No call-time overrides, model loading, runtime enforcement or automatic evidence submission.
