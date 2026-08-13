# PR #206 — Compliance release promotion fix

## Summary

This change fixes compliance handling for staging → main release promotion pull requests.

Release promotion remains fully verified, but it no longer requires a duplicate docs/reports/*.md change when the underlying changes were already reviewed on staging.

## Files changed

- `.github/workflows/compliance.yml`
- `python/tests/test_compliance_workflow_contract.py`

## Audit findings addressed

The compliance workflow previously treated staging → main promotion as a normal core-changing pull request and required a new audit report.

The evidence-pack logic also failed when a valid release promotion contained no newly changed report file.

## Validation commands

```bash
git diff --check
python3 -m pytest -q python/tests/test_compliance_workflow_contract.py


## Evaluation gate

The staging → main release promotion continues to run core verification and artifact validation.

## Human approval gate

The release promotion still requires the existing GitHub branch protection and pull request approval flow.
