# Tokio and ZIP dependency security remediation

## Summary

This Dependabot update keeps Tokio 1.53.3 and replaces vulnerable ZIP 8.6.0 with ZIP 9.0.5. The ZIP upgrade requires handling entry-name decoding as a fallible operation. The Cargo audit findings for ctutils, rustls-webpki, and webpki-roots are also updated to patched releases.

## Files changed

| File | Change |
|------|--------|
| `rust/Cargo.toml` | Requires ZIP 9.x. |
| `rust/Cargo.lock` | Locks Tokio 1.53.3, ZIP 9.0.5, and patched transitive dependencies. |
| `rust/src/audit_export_bundle.rs` | Propagates ZIP entry-name decoding errors before normalizing paths. |

## Security findings addressed

- `zip 8.6.0`: three extraction advisories; upgraded to 9.0.5.
- `ctutils 0.4.2`: upgraded to 0.4.4.
- `rustls-webpki 0.103.15`: upgraded to 0.103.16.
- `webpki-roots 1.0.8`: upgraded to 1.0.10.

## Validation

- `cargo build --locked --bin aigov_audit`
- `cargo audit`
- GitHub Actions CI for this pull request

## Evaluation gate

Status: pending CI.

Evidence:
- The dependency lockfile retains all resolved package variants and updates references to the patched webpki-roots release.
- CI must confirm locked builds and the supply-chain audit before this remediation is considered complete.

## Human approval gate

Status: pending maintainer review.

Reviewer: Monika Dvořáčková
