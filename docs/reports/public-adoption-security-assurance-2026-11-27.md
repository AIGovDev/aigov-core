# Public adoption and viewer security changes

**Target base:** `staging` at `be28b0dd231f980d105a93d76ee2db2f1f7cbd6a`  
**Scope:** adoption documentation, a static export viewer package, and publication/metrics workflows.

## Change impact

This change does not modify the Rust ledger, policy evaluation, authorization decisions, tenant identity mapping, cryptographic primitives, or evidence-verification algorithm. It adds a deterministic synthetic JSON export, expands tests around the existing browser viewer, and adds a manually dispatched workflow that can copy the checked static package to the fixed Hugging Face Space ID when a write token is configured.

The viewer continues to read local files in the browser or same-origin paths only. The test suite checks chain acceptance/rejection, malformed rows and hashes, a 5,000-record chain bound, sample reproducibility, URL origin/protocol restrictions, redirects and credential omission, and safe text insertion. Static source checks do not replace browser testing. The deployed Space has not been created or verified, so no public demo claim is made.

The weekly adoption workflow uses read-only repository access, does not commit data or contributor identities, and retains each metrics artifact for 90 days. Traffic views/clones remain unavailable without repository Administration: read permission. This workflow does not instrument users or add runtime telemetry.

## Verification run

Local checks at the feature-branch revision:

- `python3 scripts/prepare_hf_space.py --check` — passed.
- `python3 -m unittest python.tests.test_hf_space_package -v` — 3 passed.
- `node examples/reconstructible-agent-demo/viewer/test_hash_chain.mjs` — passed.
- Extracted inline viewer script and ran `node --check` — passed.
- Parsed both new GitHub Actions workflow files as YAML — passed.
- `git diff --check` — passed.

GitHub Actions additionally ran the repository Python smoke tests and Ruff. The first attempt found one unnecessary `noqa` suppression, now removed. A repository compliance gate requested this report because the PR touches evidence-viewer tests; that gate is documentation presence only and is not a security review.

Rust tests, Cargo Audit, pip-audit, Gitleaks, Trivy, full static analysis, dependency/license scanning, and fuzzing still require the supported toolchain/CI jobs or dedicated setup. Their current results must be checked against the final PR head before claiming completion.

## Assurance boundary

The sample is synthetic. Recomputing a SHA-256 chain only shows that the included records and declared head are internally consistent; it does not prove factual truth, completeness, signer identity, action occurrence, trusted time, or regulatory compliance. No external catalog submission, audit application, paid work, or public launch post is made by this repository change.
