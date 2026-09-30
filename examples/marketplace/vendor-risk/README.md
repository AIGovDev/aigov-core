# Ongoing AI vendor risk monitoring

**Certification level:** community (see [`registry/certification-levels.json`](../../../registry/certification-levels.json))

## Audience

Vendor risk management teams tracking an already-onboarded AI vendor over the life of the contract (companion to vendor-evaluation, which covers pre-onboarding).

## Scope

This pack's [`policy-module.json`](policy-module.json) documents the following requirement themes:

- `ongoing_vendor_monitoring` — requires: `periodic_review`, `renewal_assessment`
- `traceability` — requires: `contract_reference`, `data_processing_terms`
- `robustness` — requires: `uptime_report`, `breach_notification_history`

## Non-claims

This pack is a **documentation-level interchange example**. It does not certify legal compliance with any regulation, does not configure Rust runtime policy enforcement by itself, and is not a substitute for legal or compliance advice. See [`docs/registry/overview.md`](../../../docs/registry/overview.md#non-claims) and [`marketplace/policy-pack-format.md`](../../../marketplace/policy-pack-format.md).

## Validate

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/vendor-risk
```
