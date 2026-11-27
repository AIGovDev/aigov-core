# Hugging Face live validation

## Scope
CPU-only integration workflow for pinned Hub artifacts, Transformers inference, Evaluate metrics and evidence tampering detection.

## Risk assessment
External package and Hub availability affect reproducibility. Direct dependencies are pinned but transitive dependencies are not locked. The workflow uses read-only repository permissions and no Hub credentials.

## Evaluation gate
The initial Hugging Face live validation workflow (run 45955937088) completed successfully according to GitHub Actions. Final validation of this revision remains pending. No model quality or production enforcement claim is made.

## Human approval gate
Maintainer review and explicit merge approval required. Approval pending.

## Limitations
No independent external attestation or Core evidence submission. The initial Hub revision is resolved per CI run.
