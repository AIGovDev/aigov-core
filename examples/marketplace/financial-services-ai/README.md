# Financial services AI model risk

**Certification level:** community (see [`registry/certification-levels.json`](../../../registry/certification-levels.json))

## Audience

Model risk management teams in regulated financial institutions aligning AI/ML model documentation with existing model-risk frameworks (e.g. SR 11-7-style expectations).

## Scope

This pack's [`policy-module.json`](policy-module.json) documents the following requirement themes:

- `model_risk_management` — requires: `model_validation_report`, `independent_review`
- `robustness` — requires: `adversarial_test_report`, `stress_test_results`
- `traceability` — requires: `decision_log`, `audit_trail`

## Non-claims

This pack is a **documentation-level interchange example**. It does not certify legal compliance with any regulation, does not configure Rust runtime policy enforcement by itself, and is not a substitute for legal or compliance advice. See [`docs/registry/overview.md`](../../../docs/registry/overview.md#non-claims) and [`marketplace/policy-pack-format.md`](../../../marketplace/policy-pack-format.md).

## Validate

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/financial-services-ai
```
