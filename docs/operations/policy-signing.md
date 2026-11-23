# Policy trust in staging and production

Status: 2026-11-23.

## What is enforced

- **Signed policy bundles** (`AIGOV_POLICY_BUNDLE_FILE`, or `policy.bundle.<env>.json` in `AIGOV_POLICY_DIR`): in staging and production the service requires `AIGOV_POLICY_TRUST_ED25519_JSON` and at least one valid Ed25519 signature over the bundle digest. Unsigned or unknown-kind signatures are refused.
- **Policy files** (`AIGOV_POLICY_FILE`, or `policy.<env>.json`): these are not signed. They set the verdict configuration (for example `require_approval`). In staging and production the service now refuses to start with such a file, unless the operator sets `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1`.
- **Built-in defaults** are part of the code and are allowed.

## Migration for existing deployments

1. Preferred: keep the verdict configuration in code (defaults) or sign it. Signing a policy bundle does not yet govern verdicts, because verdicts still read the policy file. That is a known gap; see the blockers in the report.
2. Until then, set `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` explicitly for staging or production, and record the decision. The service logs a warning on each start.
3. Do not set the flag in development. Development behavior is unchanged.

## Known limitation

The unsigned policy file still controls verdicts when the opt-in is set. Closing that requires making the verdict configuration part of a signed bundle, which is a separate change.
