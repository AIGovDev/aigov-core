# Hugging Face evaluation evidence

## Scope
Versioned caller-reported evaluation evidence binding model, dataset, policy and configuration digests to a run and finite numeric metrics.

## Risk assessment
Digest verification requires an independently trusted anchor. It does not establish that the referenced artifacts were used or that metrics are truthful.

## Evaluation gate
Acceptance requires regression tests and repository CI. Run `cd python && python -m pytest tests/test_huggingface_evaluation.py -q`. Results pending. No model quality claim is made.

## Human approval gate
Maintainer review and explicit merge approval required. Approval pending.

## Limitations
No live Transformers or Evaluate execution, policy enforcement, signature or ledger submission in this increment.
