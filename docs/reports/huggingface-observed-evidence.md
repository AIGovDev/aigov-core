# Hugging Face observational submission

## Evaluation gate
Client verifies the record against a supplied digest and submits a distinct observational event. It does not assert passed evaluation. Mock transport regression test added; real HTTP acceptance and server gate regression remain pending.

## Human approval gate
Maintainer review required; approval pending.

## Deployment
Explicitly add huggingface_evaluation_observed to the tenant's reviewed runtime policy event_types with required nonempty strings record_sha256 and measurement and no gates. Do not add it as a substitute for evaluation_reported. Existing strict policies may reject it until configured. No server policy is silently changed. The digest is not a signature; the caller must obtain a trusted anchor separately. Submission is not idempotent.
