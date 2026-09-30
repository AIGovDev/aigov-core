# Internal model risk inventory

**Certification level:** community (see [`registry/certification-levels.json`](../../../registry/certification-levels.json))

## Audience

Internal AI governance teams building a first model inventory and risk-tiering process, independent of any specific external regulation.

## Scope

This pack's [`policy-module.json`](policy-module.json) documents the following requirement themes:

- `model_inventory` — requires: `model_registration`, `owner_assignment`
- `risk_tiering` — requires: `risk_classification`, `mitigation_plan`
- `robustness` — requires: `performance_monitoring`, `drift_detection`

## Non-claims

This pack is a **documentation-level interchange example**. It does not certify legal compliance with any regulation, does not configure Rust runtime policy enforcement by itself, and is not a substitute for legal or compliance advice. See [`docs/registry/overview.md`](../../../docs/registry/overview.md#non-claims) and [`marketplace/policy-pack-format.md`](../../../marketplace/policy-pack-format.md).

## Validate

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/internal-model-risk
```
