# DEV Community draft

**Title:** From audit events to a policy gate: a small AIGov Core walkthrough

**Outline:** use the existing local quickstart; send one evidence event; show why the first verdict is BLOCKED; run the deterministic demo; inspect an export; alter one record and run the verifier.

**Intro:** An audit log is useful only if engineers can connect evidence to a decision and inspect what the system actually checked. AIGov Core is an open-source experiment in that workflow: evidence is stored in a tenant-scoped ledger, configured policy produces an explicit verdict, and exports can be checked for internal consistency.

Keep the article focused on the runnable flow. State that the demo uses synthetic data, the hash chain does not prove event truth or signer identity, and the current benchmark is small. Link to docs/quickstart-5min.md, docs/trust-model.md and docs/launch/benchmark-report.md.

Publish only after reproducing every command on a clean checkout and verifying any public demo link.
