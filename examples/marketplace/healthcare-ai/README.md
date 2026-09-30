# Healthcare AI clinical safety

**Certification level:** community (see [`registry/certification-levels.json`](../../../registry/certification-levels.json))

## Audience

Teams deploying AI-assisted clinical decision support, aligning documentation with clinical safety and human-in-the-loop expectations.

## Scope

This pack's [`policy-module.json`](policy-module.json) documents the following requirement themes:

- `clinical_risk_assessment` — requires: `risk_register`, `clinical_safety_case`
- `human_oversight` — requires: `clinician_review`, `override_capability_demonstrated`
- `traceability` — requires: `decision_log`, `training_data_provenance`

## Non-claims

This pack is a **documentation-level interchange example**. It does not certify legal compliance with any regulation, does not configure Rust runtime policy enforcement by itself, and is not a substitute for legal or compliance advice. See [`docs/registry/overview.md`](../../../docs/registry/overview.md#non-claims) and [`marketplace/policy-pack-format.md`](../../../marketplace/policy-pack-format.md).

## Validate

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/healthcare-ai
```
