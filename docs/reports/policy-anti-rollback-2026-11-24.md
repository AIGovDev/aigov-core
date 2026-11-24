# Signed-policy anti-rollback — 2026-11-24

## Scope

A signed bundle stays valid after a newer version replaces it. An older bundle could be redeployed to restore a
weaker policy. This change records the highest accepted version of each policy in the ledger directory and refuses
anything older, in staging and production. Development is unchanged.

No external infrastructure was changed. No Railway resource, credential, or deployment was created or modified.

## What changed

- `rust/src/policy_watermark.rs`: the version record (`policy_watermark.json`, written atomically after verification),
  strict integer versions, and the decision rules.
- `rust/src/policy_store.rs`: the check runs after signature verification and the production contract, in both
  bundle-loading paths. Staging and production require `GOVAI_LEDGER_DIR`.
- `scripts/staging_policy_verify.py`: a cross-restart scenario that starts the real binary six times against one ledger.
- `docs/operations/policy-signing.md`: the anti-rollback rules and the rollback procedure. Rollback now means publishing
  the older content under a new, higher version.

## Rules

- Lower version than the record: refused (`rollback refused`).
- Same version and same document digest: accepted (re-signing the same content, for example to extend expiry).
- Same version and different content: refused.
- Higher version: accepted, and the record advances.
- Version must be a plain non-negative integer. `1.0`, `v1`, `01`, and similar are refused.
- Missing record on first start: created. Unreadable, malformed, or unknown-field record: startup refused.

## Evidence

| Check | Result |
|-------|--------|
| Unit tests `policy_watermark` | 10 passed |
| Cross-restart scenario, real binary, current code (`rollback.*`) | 6 of 6 passed |
| Same scenario, pre-change commit `origin/staging` (negative control) | 4 of 6 failed: older v1, changed v2, older v2 after v3, and `1.0` all **started** instead of being refused |
| Local simulation, full (`--skip-live`) | 33 passed, 0 failed |
| Harness unit tests | 20 passed |
| Rust `cargo test --locked` | 247 passed, 0 failed, 0 ignored |

The negative control shows the scenario discriminates. Before this change, the older bundles were accepted.

## Limits

- The record lives on the ledger volume. Whoever can write that volume can reset it. This is the same trust boundary
  as the ledger itself. Deleting the record is a recorded decision and must be logged.
- A single volume serves one instance. Replicas sharing a volume would need a lock, which is not implemented.
- The record is not replicated. If the volume is lost, the record is lost, and the first start afterwards accepts any
  correctly signed version. Back up the ledger volume, including this file.
- Replay of a valid, unexpired bundle with the same version is not prevented beyond same-content acceptance.

## Evaluation gate

Passes when the watermark unit tests, the cross-restart scenario against the real binary, the full local simulation, and
the Rust suite pass, and the pre-change control shows the scenario fails without the change. All of these hold for
the change set in this PR.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision.

Requires an operator decision before any deployment: whether the ledger volume backup includes the watermark record,
and who may reset it.
