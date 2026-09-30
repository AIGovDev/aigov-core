# Third-party AI vendor evaluation

**Certification level:** community (see [`registry/certification-levels.json`](../../../registry/certification-levels.json))

## Audience

Procurement and security teams evaluating a third-party AI vendor before onboarding.

## Scope

This pack's [`policy-module.json`](policy-module.json) documents the following requirement themes:

- `vendor_due_diligence` — requires: `vendor_questionnaire`, `security_assessment`
- `traceability` — requires: `data_flow_diagram`, `subprocessor_list`
- `robustness` — requires: `sla_review`, `incident_history`

## Non-claims

This pack is a **documentation-level interchange example**. It does not certify legal compliance with any regulation, does not configure Rust runtime policy enforcement by itself, and is not a substitute for legal or compliance advice. See [`docs/registry/overview.md`](../../../docs/registry/overview.md#non-claims) and [`marketplace/policy-pack-format.md`](../../../marketplace/policy-pack-format.md).

## Validate

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/vendor-evaluation
```
