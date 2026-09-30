# EU AI Act - basic Annex III alignment

**Certification level:** community (see [`registry/certification-levels.json`](../../../registry/certification-levels.json))

## Audience

Teams deploying AI systems that may fall under EU AI Act Annex III high-risk categories and want a starting checklist of documentation themes.

## Scope

This pack's [`policy-module.json`](policy-module.json) documents the following requirement themes:

- `risk_assessment` — requires: `risk_register`, `mitigation_plan`
- `human_oversight` — requires: `human_approval_record`, `escalation_procedure`
- `traceability` — requires: `decision_log`, `model_version_record`
- `post_market_monitoring` — requires: `incident_log`, `performance_review`

## Non-claims

This pack is a **documentation-level interchange example**. It does not certify legal compliance with any regulation, does not configure Rust runtime policy enforcement by itself, and is not a substitute for legal or compliance advice. See [`docs/registry/overview.md`](../../../docs/registry/overview.md#non-claims) and [`marketplace/policy-pack-format.md`](../../../marketplace/policy-pack-format.md).

## Validate

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/eu-ai-act-basic
```
