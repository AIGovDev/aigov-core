# tower-http 0.7.1 dependency update

## Summary

PR #540 upgrades the direct Rust runtime dependency `tower-http` from 0.6.11 to 0.7.1, updates the downstream Rust consumer lockfile, and refreshes installed Debian runtime packages to address the image scan findings.

## Scope

The changes cover Rust dependency metadata and generated lockfiles, the Debian runtime image package layer, and this validation report. Application source and public API contracts are unchanged.

## Evaluation gate

- The initial CI run built the runtime and passed the Rust unit and integration suite.
- The downstream Rust consumer smoke exposed two lockfile references requiring disambiguation: `aigov_audit` now uses `tower-http 0.7.1`; `reqwest` continues using `tower-http 0.6.11`.
- The downstream consumer lockfile now records both version-qualified references and package entries.
- The runtime image now applies Debian security updates before installing runtime packages.
- CI is running again after these corrections; final status is pending.

## Human approval gate

Status: pending maintainer review after dependency, lockfile, and image updates.

## Validation

GitHub Actions on PR #540 are the validation source. No local cargo or Docker executable was available in this workspace.
