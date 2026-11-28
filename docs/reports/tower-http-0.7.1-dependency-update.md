# tower-http 0.7.1 dependency update

## Scope

PR #540 upgrades the direct `tower-http` dependency of the Rust runtime from 0.6.11 to 0.7.1. This is a dependency-only change; the application code and HTTP behavior are unchanged.

## Validation and correction

The initial CI run built the runtime and passed its Rust unit and integration suite. The downstream Rust consumer smoke check then failed because its committed lockfile did not include the new direct dependency version. The consumer lockfile now records `tower-http 0.7.1` for `aigov_audit`, while retaining 0.6.11 for its separate transitive consumer.

The container image vulnerability scan also reported five HIGH Debian OS package findings. Those findings are in the image base packages and are unrelated to this Rust dependency update.

## Follow-up

CI was rerun after the lockfile correction. Final downstream smoke and full workflow results are pending.
