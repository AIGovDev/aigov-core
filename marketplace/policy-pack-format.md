# Policy pack format

A **policy pack** is a directory under `examples/marketplace/<pack-id>/` containing exactly two files:

```
examples/marketplace/<pack-id>/
├── README.md            # human-readable summary: audience, scope, what it does NOT claim
└── policy-module.json   # a govai.standards.governance_policy_module.v1 document
```

## `policy-module.json`

Must validate against [`schemas/governance-policy-module.schema.json`](../schemas/governance-policy-module.schema.json), enforced in Python by [`aigov_py.standards.policy_module.validate_governance_policy_module_document`](../python/aigov_py/standards/policy_module.py). Shape:

```json
{
  "schema_version": "govai.standards.governance_policy_module.v1",
  "policy": { "id": "pol.<pack-id>", "name": "Human-readable name", "version": "1.0.0" },
  "requirements": [
    { "code": "some_requirement_code", "required_evidence": ["evidence_id_a", "evidence_id_b"] }
  ]
}
```

`requirements[].code` and `required_evidence[]` entries are **documentation-level identifiers** for this interchange format — they are not the same thing as the Rust core's `event_type` values on `POST /evidence`. A policy pack does not, by itself, configure runtime enforcement; see [`docs/customer-policy-modules.md`](../docs/customer-policy-modules.md) for how a policy module becomes the flat `required_evidence` set the audit service actually enforces.

## `README.md`

Should cover, briefly:

- **Audience** — who this pack's requirements are aimed at (e.g. "teams deploying AI systems that fall under EU AI Act Annex III").
- **Scope** — which `requirements[].code` entries exist and what each is trying to capture.
- **Non-claims** — this pack does not certify legal compliance with any regulation; see [`docs/registry/overview.md`](../docs/registry/overview.md#non-claims).

## Curation

A pack becomes **discoverable** (not just present on disk) by being added to both:

1. [`marketplace/manifest.json`](manifest.json) — the curated index this format doc describes.
2. [`registry/policy-pack-catalog.json`](../registry/policy-pack-catalog.json) — with matching `id` and `path`, plus `capability_ids` (from [`registry/capability-taxonomy.json`](../registry/capability-taxonomy.json)) and a `certification_level_id` (from [`registry/certification-levels.json`](../registry/certification-levels.json), default `community` for new submissions).

## Validation

```bash
python3 scripts/validate_policy_pack.py examples/marketplace/<pack-id>
python3 scripts/registry_check.py
```

See [`docs/registry/submission-guidelines.md`](../docs/registry/submission-guidelines.md) for the full contributor checklist.
