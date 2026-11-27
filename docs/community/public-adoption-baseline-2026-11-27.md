# Public adoption baseline — 2026-11-27

Collected with scripts/oss_metrics_snapshot.py at **2026-11-27 11:11:25 UTC**. Sources are the GitHub repository, contributor and release APIs, plus PyPI Stats. This is a point-in-time baseline, not a forecast.

| Metric | Observed value | Source / qualification |
|---|---:|---|
| GitHub stars | 2 | GitHub repository API |
| GitHub forks | 3 | Includes inactive forks |
| Distinct non-bot contributor accounts | 5 | Account IDs only; one person with multiple accounts cannot be deduplicated |
| Contributor API entries | 6 | Includes one bot account |
| PyPI downloads, rolling day / week / month | 0 / 36 / 61 | Package aigov-py; aggregate downloads, not unique installs or users |
| GitHub release-asset downloads | 0 | No release assets attached; source archives excluded |
| GitHub views and clones, rolling 14 days | Unavailable | Traffic API requires repository Administration: read token |
| Hugging Face Space engagement | Not available | No public aigov-core-evidence-viewer Space verified at collection time |
| Catalog submissions | 0 verified external PRs | Internal research/drafts in AIGov Core PR #536 are not submissions |
| External security audit | None verified | Internal reports do not count as independent review |
| Public audit funding applications | None verified | No application receipt found |
| Inbound customer/partnership inquiries | Not measured here | Use existing private acquisition tracker; do not publish private contact data |

## Interpretation

The target is **1,000 genuine GitHub stars**, not a guaranteed result. Stars, forks, registry downloads, release downloads and traffic are separate signals. They do not establish active deployments, unique human users, commercial adoption or security assurance.

No estimate is substituted for inaccessible traffic or Space analytics. Missing values remain unavailable rather than zero. Promotions and launches should be logged by date and channel separately from organic contributions and usage.

## Reproduce and compare

Run from the repository root: python3 scripts/oss_metrics_snapshot.py --repo AIGovDev/aigov-core --pypi-package aigov-py --output metrics/aigov-core-2026-11-27.json

For later runs, pass the prior JSON with --previous. The token is optional; it must be kept in a secret manager and is never written to the snapshot. See metrics-tracking.md for definitions and limitations.

The automated weekly workflow stores each weekly JSON as a GitHub Actions artifact. Workflow artifacts are retained for 90 days; download and archive selected snapshots if a longer time series is needed.
