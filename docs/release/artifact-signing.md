# Artifact signing procedure (not executed)

**No signing key, credential, or signing identity has been created, stored, or referenced in this repository, and none is created by
this document.** This is the procedure the release owner runs when they decide to sign. It is written so that the decision can be made and reviewed
before anyone holds a key.

## What is signed

For each release candidate, the signed set is:

1. the Core release binary, `aigov_audit` (its SHA-256 is in `docs/evidence/release-candidate/provenance.json`);
2. the SDK wheel, `aigov_py-<version>-py3-none-any.whl`;
3. the container image, by digest (not by tag);
4. the two CycloneDX SBOMs (`docs/evidence/release-candidate/sbom/`);
5. the provenance record (`provenance.json`) for the source commit it names.

Signing the provenance record binds the artifacts to the commit and the toolchain. It does not prove that the build machine was clean. That is stated in the record.

## Options (owner chooses one)

| Option | Key held by | What it needs | Trade-off |
|---|---|---|---|
| A. Keyless signing with an OIDC identity (for example a CI workflow identity) | the identity provider and the transparency log | a CI identity the owner controls; a public transparency log entry | No long-lived key to protect; the signer identity must be trusted and the log is public |
| B. A long-lived key in an HSM or KMS, used by a release job | the HSM or KMS | the key custodian, rotation, and revocation procedure | Full control; one more service to run |
| C. An offline key used by one person, for each release | a named person's device | a documented ceremony and a backup plan | Simple; a single person is a single point of failure |

The recommendation is A for the pilot if the owner accepts a public log entry for each release; otherwise B. C is not recommended for a pilot.

## Procedure (after the owner has chosen an option and created the identity or key under their own control)

1. Build from a clean checkout of the release commit. Record the commit, the toolchains, and the base image digests (`scripts/release_provenance.py`).
2. Build the binary, the wheel, and the SBOMs. Verify them with `scripts/verify_release_artifacts.py`. Every check must pass.
3. Sign each artifact in the signed set with the chosen mechanism. Store the signatures next to the artifacts, not in the repository.
4. Record the signer identity or key id, the time, and the artifact digests in the release record.
5. Verify each signature from a clean machine that holds only the public trust material, before the artifact is used.

## Verification (for the customer or the auditor)

- Recompute the SHA-256 of each artifact and compare it with `provenance.json`.
- Verify each signature against the expected signer identity or public key. Refuse an artifact whose signature does not verify.
- Confirm that the binary contains no fault-injection code: `make fault-absence-check`.

## Rotation and revocation

- A key that is rotated keeps its earlier signatures verifiable. The release record names the key in use for each release.
- A compromised key or identity is revoked by the owner. The release record marks every artifact signed after the compromise date as untrusted, and
  the artifacts are rebuilt and re-signed under the new key.

## What this document does not do

It does not sign anything, choose an option, or create an identity. Those are owner decisions. The owner's record is in
`docs/decisions/release-0.4.0-rc.1-owner-acceptance.md`.
