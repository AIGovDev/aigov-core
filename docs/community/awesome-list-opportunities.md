# Curated list submission opportunities

**Reviewed:** 2026-11-27  
**Status:** Research and draft copy only. No external submissions have been made.

This note records a small set of relevant third-party catalogs for a maintainer to review. It complements the repository's existing launch, onboarding, adoption, and metrics documentation; it does not replace those materials. Inclusion is a curator decision, not a promised launch outcome.

## Recommended opportunities

| Priority | Catalog | Fit and current status | Submission notes |
| --- | --- | --- | --- |
| 1 | [AI Governance Tools](https://github.com/aglio-lab/ai-governance-tools) | Broad AI-governance catalog with an AI assurance category. AIGov Core did not appear in the README checked on 2026-11-27. This is the clearest topical fit, though the catalog's own “Last reviewed” date is 2026-07-16. | Recheck that the catalog is being maintained before proposing an entry. Its guide asks for one tool per PR, a neutral self-contained description, an availability marker and primary-source link; it also requires running python3 scripts/generate_catalog.py and committing generated JSON/CSV. |
| 2 | [Awesome AI Agent Governance (AgenTrust)](https://github.com/agentrust-io/awesome-ai-governance) | The audience is relevant and its README welcomes open-source governance tools. AIGov Core did not appear in the README checked on 2026-11-27. Fit is conditional: its “Agent Action Records” section is specifically about signed receipts and public logs; AIGov Core verifies ledger hash chains but does not independently attest that a represented agent action occurred. | Ask whether the curator considers a tenant-scoped audit runtime in scope before drafting a PR. If accepted, use that section only with the limitation stated plainly. The guide requests a short, neutral entry and working links. |
| 3 | [Awesome AI Agent Governance (Permission Protocol)](https://github.com/permission-protocol/awesome-ai-agent-governance) | Direct audience fit, but overlaps with the AgenTrust list. AIGov Core did not appear in the README checked on 2026-11-27. | Keep this as an alternative to priority 2, not a simultaneous duplicate submission. The guide requests one factual line in the most specific category and a maintainer-project disclosure. It states that contributions are released under CC0; review that contribution condition before submitting. |

## Draft entry copy for review

These are internal drafts, not approved external copy. Use only after confirming the catalog's current scope and the applicable contribution terms.

### AI Governance Tools

> AIGov Core is an AGPL-3.0 Rust audit runtime for tenant-scoped evidence ledgers, deterministic compliance summaries, audit export, and hash-chain verification.

The catalog's availability marker should be selected according to its current guide and the repository's AGPL-3.0 license. Link to the [AIGov Core repository](https://github.com/AIGovDev/aigov-core), not a promotional landing page.

### Agent-governance lists, only if the curator confirms fit

> AIGov Core is an AGPL-3.0 Rust audit runtime that records supplied evidence in tenant-scoped ledgers, derives compliance status from ledger projection, and verifies ledger hash chains; it does not independently attest that a represented agent action occurred.

Add the list's required maintainer-project disclosure. Do not describe the runtime as a signed-receipt issuer, agent identity system, or enforcement gateway.

## Submission sequence

1. Recheck the target README, contribution guide, latest activity, and whether AIGov Core is already listed.
2. For the broad AI-governance catalog, confirm the catalog has had a current review before preparing its generated data changes.
3. For an agent-governance list, ask the curator whether the runtime's evidence-ledger scope fits the named category; prefer one list and do not submit the same entry to overlapping lists in parallel.
4. Review the receiving repository's contribution license before opening any external PR. In particular, the Permission Protocol guide states CC0 terms.
5. Have a maintainer approve the final copy and any external submission separately.

## Sources checked

GitHub README and contribution-guide contents were checked on 2026-11-27:

- [AI Governance Tools README](https://github.com/aglio-lab/ai-governance-tools) and [contribution guide](https://github.com/aglio-lab/ai-governance-tools/blob/main/CONTRIBUTING.md)
- [AgenTrust list README](https://github.com/agentrust-io/awesome-ai-governance) and [contribution guide](https://github.com/agentrust-io/awesome-ai-governance/blob/main/CONTRIBUTING.md)
- [Permission Protocol list README](https://github.com/permission-protocol/awesome-ai-agent-governance) and [contribution guide](https://github.com/permission-protocol/awesome-ai-agent-governance/blob/main/CONTRIBUTING.md)
- [AIGov Core README](https://github.com/AIGovDev/aigov-core/blob/staging/README.md)

The “not listed” observation is based on searching each checked README for AIGov, GovAI, and MonikaDvorackova; it is not a claim about every branch, file, or catalog.
