# Offline Audit Export Signing

## Summary

This change exposes the existing Ed25519 audit-export signing and verification functionality through offline command-line binaries.

It adds offline tooling to sign an `aigov.audit_export.v1` export, derive the corresponding public verification key, and verify the export signature without requiring a running server or network access.

The signature protects the defined signing payload. Internal `log_chain` continuity remains independently verified by the existing replay/chain-continuity mechanism.

## Evaluation gate

Expected behavior:

- a valid signed audit export verifies successfully;
- modification of signed evidence-event content causes signature verification to fail;
- modification of an individual stored `log_chain` record hash is not claimed to be detected by the signature alone;
- internal hash-chain consistency remains verified by the existing replay mechanism;
- signing and verification operate offline.

Validation:

    cargo check --locked
    ./examples/talk-demo/07-sign-and-verify.sh

## Human approval gate

This change does not modify automatic approval, policy enforcement, evidence admission, or compliance verdict semantics.

Human review is required before merge to confirm that the CLI exposure preserves the existing cryptographic trust model.

## Risk assessment

The primary risk is interpreting `signature_verified: true` as verification of every individual `log_chain` record.

Signature verification and internal chain-continuity verification remain separate controls.

No network service, ledger mutation path, policy rule, tenant-isolation behavior, or evidence-ingestion behavior is changed.

## Rollback plan

Rollback consists of reverting this change set and removing the new offline signing and verification binaries and their Cargo configuration.

The underlying audit-export signing implementation and existing replay verification remain unchanged.
