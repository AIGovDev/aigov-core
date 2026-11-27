# Curated list submission opportunities

**Reviewed:** 2026-11-27  
**Status:** Catalog research and draft copy, plus one verified external submission now open for maintainer review.

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

## Additional catalog check (2026-11-27)

The following requested channels were checked against their current public contribution rules and repository metadata. No external submission was made in this review.

| Resource | Eligibility / status | Decision |
| --- | --- | --- |
| [Awesome AI Agents Enhanced](https://github.com/DanWaheed/awesome-ai-agents-enhanced) | Publicly maintained; its contribution guide requests a public agent repository and observable agent behavior. The current AIGov Core repo is a governance/audit runtime rather than an agent or agent framework. | Do not submit; weak category fit. |
| [Awesome MLOps](https://github.com/kelvins/awesome-mlops) | Public, not archived, active default-branch commits observed in October 2026. It curates MLOps tools and workflows; AIGov Core is adjacent but not primarily an MLOps platform. | Do not submit unless a specific existing category for governance evidence is confirmed with maintainers. |
| [Awesome AI Governance Tools](https://github.com/aglio-lab/ai-governance-tools) | Direct topical fit, but repository metadata showed last push 2026-07-16 and the README's last review date is also 2026-07-16 despite its monthly review claim. A current maintenance cadence could not be verified. | Strongest candidate after confirming an active maintainer/review cycle. Neutral entry draft above is ready; no fork or PR yet. |
| [Awesome GenAI Security](https://github.com/jassics/awesome-genai-security) | Relevant AI security scope and a contribution guide exists. The project should only be listed if the maintainers accept governance/audit evidence infrastructure in the tool categories; it is not a vulnerability scanner or red-team testing tool. | Ask the maintainer about fit before a PR; no submission. |
| [Awesome Rust](https://github.com/rust-unofficial/awesome-rust) | Actively maintained, but its current policy requires at least 50 GitHub stars or 2,000 crate downloads, or equivalent evidence. AIGov Core's verified GitHub baseline is 2 stars and no qualifying crates.io download metric was established. | Ineligible on currently verified popularity requirements; do not submit. |
| [Hugging Face AI Governance & Responsible AI collection](https://huggingface.co/collections/aigovdev/ai-governance-and-responsible-ai) | AIGov governance scenario Space and related assets already appear in the collection. The new Core evidence viewer is not verified as published or included. | Existing presence confirmed for related assets; add the viewer only after its public Space is live and account authorization is available. |
| [AlternativeTo](https://alternativeto.net/faq/) | New software submissions require a verified account email, use a review queue, and may incur an optional paid priority-review fee. The site excludes unreleased/private-beta software and disallows link-filled promotional descriptions. | Potential later listing for the released open-source CLI/runtime, but requires an authenticated verified account; do not pay for priority. |
| [OpenSSF Best Practices Badge](https://bestpractices.dev/en) | Free, voluntary self-certification is available to FLOSS projects. This is a project assessment, not a catalog PR and not an independent security audit. | Add as a separate evidence-led self-assessment after all current criteria have been checked; no badge currently claimed. |

### Submission status

Verified external catalog PRs: **1 open**. [AIGov Core in Awesome AI Governance](https://github.com/Aperintelligence/awesome-ai-governance/pull/14) was submitted after checking the current category and contribution policy; it discloses the maintainer relationship and states hash-chain verification limits. Its status is open and inclusion is pending maintainer decision. The AIGov Core PR #536 remains internal research. Other candidates were not submitted where fit, active maintenance, or eligibility could not be verified.
