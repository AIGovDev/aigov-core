# RUSTSEC-2026-0285 rustls remediation

## Summary

This change updates the Rust dependency lockfile to remediate RUSTSEC-2026-0285.

## Dependency changes

- `rustls`: `0.23.41` -> `0.23.45`
- `rustls-webpki`: `0.103.13` -> `0.103.15`

No application source code or `Cargo.toml` dependency declarations are changed.

## Security rationale

RUSTSEC-2026-0285 affects `rustls` versions prior to `0.23.45`.

The dependency was updated to `rustls 0.23.45`, which satisfies the advisory remediation requirement.

## Validation

The following validation was completed on the remediation branch:

- `cargo check --all-targets`
- `cargo test --all-targets`
- `cargo audit`

`cargo audit` reports no vulnerabilities after the update.

Two pre-existing allowed warnings remain:

- `event-listener 5.4.1` — RUSTSEC-2026-0221
- `chacha20 0.10.0` — yanked crate warning

These warnings are outside the scope of RUSTSEC-2026-0285 remediation.

## Scope

Changed files:

- `rust/Cargo.lock`
- `docs/reports/rustsec-2026-0285-rustls-remediation.md`

## Evaluation gate

The remediation was validated with:

- `cargo check --all-targets`
- `cargo test --all-targets`
- `cargo audit`

The targeted RUSTSEC-2026-0285 vulnerability is no longer reported after upgrading `rustls` to `0.23.45`.

## Human approval gate

This dependency remediation requires normal pull-request review and explicit human approval before merge into `staging`.

No automatic merge is authorized by this report.
