# quinn-proto and rustls security audit

## Summary

This change updates the Rust dependency lockfile to remediate nine `RustSec` advisories affecting `quinn-proto` and `rustls`, and bundles a routine `tokio` bugfix-release bump.

## Dependency changes

- `quinn-proto`: `0.11.15` -> `0.11.18` (pulls in `rand_pcg 0.10.2`, `rand 0.9.4` -> `0.10.3`, `getrandom 0.3.4` -> `0.4.3` as transitive upgrades)
- `rustls`: `0.23.45` -> `0.23.46`
- `tokio`: `1.53.1` -> `1.53.2`

No application source code or `Cargo.toml` dependency declarations are changed. `rust/Cargo.lock` is the only file this PR touches.

## Security rationale

`cargo audit` against the pre-change lockfile (`origin/staging`) reported 9 vulnerabilities:

| Advisory | Crate | Version | Severity | Title |
|---|---|---|---|---|
| RUSTSEC-2026-0338 | quinn-proto | 0.11.15 | - | Remote peer can panic quinn-proto with zero-length STREAM frames during unordered reads |
| RUSTSEC-2026-0339 | quinn-proto | 0.11.15 | - | Unbounded growth of pending connection ID retirements in quinn-proto |
| RUSTSEC-2026-0340 | quinn-proto | 0.11.15 | 7.5 (high) | Peer minimum ACK delay can panic quinn-proto when ACK_FREQUENCY transmission is enabled |
| RUSTSEC-2026-0341 | quinn-proto | 0.11.15 | 7.5 (high) | Stream reassembly memory-exhaustion guard in quinn-proto can be bypassed |
| RUSTSEC-2026-0342 | quinn-proto | 0.11.15 | - | Zero-length DATAGRAM frames bypass the receive buffer limit in quinn-proto |
| RUSTSEC-2026-0346 | rustls | 0.23.45 | 4 (medium) | `Debug` impls for client session values expose TLS secrets |
| RUSTSEC-2026-0347 | rustls | 0.23.45 | 2.3 (low) | Buffered application data sent to outer server after ECH rejection |
| RUSTSEC-2026-0348 | rustls | 0.23.45 | 3.7 (low) | Brotli certificate decompression can allocate up to 1 GiB before authentication |
| RUSTSEC-2026-0349 | rustls | 0.23.45 | 3.7 (low) | Unauthenticated ServerHello can downgrade later connections to classical key exchange |

All five `quinn-proto` advisories require `>=0.11.17` or `>=0.11.18`; this change upgrades to `0.11.18`, which satisfies every one. All four `rustls` advisories require `>=0.23.46`; this change upgrades to exactly `0.23.46`.

`tokio 1.53.1` -> `1.53.2` has no associated `RustSec` advisory — it is a routine upstream bugfix release (semaphore/mpsc/timer edge cases) bundled into this lockfile refresh alongside the two security-driven upgrades, not itself a vulnerability remediation.

## Validation

The following validation was completed on the remediation branch:

- `cargo check --all-targets --locked`
- `cargo test --all-targets --locked`
- `cargo audit`

`cargo check` and `cargo test` both pass cleanly: 159 tests passed (158 unit + 1 integration), 0 failed.

`cargo audit` reports no vulnerabilities after the update — all 9 advisories above are resolved.

Two pre-existing allowed warnings remain, unaffected by this change:

- `event-listener 5.4.1` — RUSTSEC-2026-0221
- `chacha20 0.10.0` — yanked crate warning

These warnings are outside the scope of this remediation.

## Scope

Changed files:

- `rust/Cargo.lock`
- `docs/reports/quinn-proto-rustls-security-audit.md`

## Evaluation gate

The remediation was validated with:

- `cargo check --all-targets --locked`
- `cargo test --all-targets --locked`
- `cargo audit`

All 9 targeted advisories (5 `quinn-proto`, 4 `rustls`) are no longer reported after the lockfile update.

## Human approval gate

This dependency remediation requires normal pull-request review and explicit human approval before merge into `staging`.

No automatic merge is authorized by this report.
