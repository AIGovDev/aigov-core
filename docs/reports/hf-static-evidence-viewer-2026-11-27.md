# Static evidence viewer packaging and verification update

## Scope
Package the existing reconstructible-agent evidence viewer for a Hugging Face
Static Space and harden the browser-side integrity check.

## Changes
- Recompute record SHA-256 values from the previous hash and exact event JSON,
  starting at `GENESIS`; require and compare the declared final chain head.
- Render export values through text-only DOM APIs and bound files to 8 MiB and
  chains/events to 5,000 records.
- Restrict optional URL loading to same-origin GET requests without credentials
  or redirects. The file picker remains local to the browser tab.
- Add a synchronized Space package and a check script to detect stale copies
  and unsafe loading/rendering patterns.

## Security and verification scope
A passing check establishes internal consistency of the supplied records only.
It does not prove the export's origin, signer identity, an AI action's occurrence,
or legal compliance, and it does not validate signed export bundles. No runtime
authorization or ledger code changes are included.

## Validation
- `python3 scripts/prepare_hf_space.py --check`: passed.
- `python -m unittest python.tests.test_hf_space_package -v`: 1 test passed.
- `node examples/reconstructible-agent-demo/viewer/test_hash_chain.mjs`: passed
  for valid, tampered, broken-genesis, and missing-head cases.
- Extracted viewer JavaScript passed `node --check`.
- GitHub Actions for the pull request: pending on the final commit.

## Deployment status
The Space files are prepared in this repository only. No Hugging Face Space was
created or published, and no hosted demo is claimed.

## Evaluation gate
No model evaluation, policy decision, evidence ingestion, or runtime enforcement
behavior changed. The browser check reports hash-chain consistency only and must
not be interpreted as a compliance verdict or an external attestation.

## Human approval gate
This PR requires maintainer review and approval before merge. No approval is
claimed by this report.
