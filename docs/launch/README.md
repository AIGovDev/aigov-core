# AIGov Core public launch materials

**Status:** prepared drafts; no launch post has been published.  
**Launch gate:** do not announce a hosted demo until its public URL and browser behavior have been verified.

AIGov Core is an AGPL-3.0 Rust audit runtime with Python tooling for recording supplied evidence, enforcing configured policy at ingest, deriving VALID / INVALID / BLOCKED from ledger state, exporting evidence and checking ledger integrity. It complements model and agent observability by providing policy-linked evidence records and an explicit promotion gate. It does not establish that the supplied evidence is true or complete, that an external action occurred, or that a system complies with law.

## Working public assets

- Five-minute quickstart: ../quickstart-5min.md
- Architecture and replay diagram: ../architecture/diagrams/audit_replay_architecture.md
- Evidence export sample: ../examples/audit_export_v1.example.json
- Agent verification benchmark, 20 deterministic scenarios: ../reports/aigov-independent-benchmark-2026-11-19.md
- Benchmark limitations and measured results: benchmark-report.md
- Comparison with adjacent tools: competitive-positioning.md
- Independent audit scope and evidence map: ../security/external-audit-preparation.md

The proposed Hugging Face viewer Space is not published yet. It must not be described as a working hosted demo until authentication is available, the Space is created, and valid, tampered, malformed, oversized and XSS-shaped samples have been checked in the deployed browser.

## Publication copy

- Show HN: hacker-news.md
- Product Hunt: product-hunt.md
- Hugging Face community: hugging-face.md
- Reddit: reddit.md
- DEV Community: dev-community.md
- LinkedIn: linkedin.md
- Technical newsletter pitch: newsletter.md

All drafts are factual and conditional where the demo or benchmark has not been verified. They contain no claim of an official partnership with Hugging Face, OpenAI, Anthropic or another organization.

## Coordinated release checklist

- [ ] Publish and browser-test the static Space from the canonical viewer package.
- [ ] Record the exact commit and deployed Space URL; test on desktop and narrow mobile viewport.
- [ ] Publish this repository PR only after review and successful exact-head CI.
- [ ] Confirm each announcement target community rules, self-promotion limit and launch date.
- [ ] Publish the technical article and benchmark limitations with the benchmark source and scenario count.
- [ ] Record launch channel, timestamp and promotional activity in the private adoption tracker.
- [ ] Collect the following week's metrics with the weekly workflow and compare like-for-like sources.
- [ ] Publish posts individually; do not cross-post identical copy where community rules prohibit it.

## Current publication status

| Deliverable | State |
|---|---|
| Quickstart, architecture diagram, sample export | Existing repository assets; not modified here |
| Channel announcements and technical article | Drafts in this directory |
| Benchmark evidence | Existing synthetic benchmark report; not a production performance test |
| Hosted public demo | Blocked on Hugging Face authentication and browser verification |
| Public posts | Not published |
| 1,000-star objective | Target only; no outcome implied |
