# Rust supply-chain security update

## Scope
Update transitive Rust dependencies in Cargo.lock.

## Changes
- quinn-proto: 0.11.18 -> 0.11.19
- quinn-udp: 0.5.14 -> 0.5.16

## Motivation
Resolve RustSec security advisories affecting the locked dependency versions.

## Validation
- cargo test --locked: passed locally
- cargo audit: verify successful completion in CI

## Impact
No application source code changes. Dependency lockfile update only.
