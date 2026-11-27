# Open-source adoption metrics

Use the read-only snapshot script to collect dated repository and package statistics. It does not create stars, forks, traffic, or downloads; it only reads GitHub and PyPI statistics APIs.

## Collect a snapshot

From the repository root, using Python 3.10 or newer:

```bash
python3 scripts/oss_metrics_snapshot.py \
  --repo AIGovDev/aigov-core \
  --pypi-package aigov-py \
  --output ./metrics/aigov-core-$(date -u +%F).json
```

The script collects GitHub stars, forks, open issues/PRs, unique non-bot contributor accounts, bot accounts, and release asset downloads. With `--pypi-package aigov-py`, it also reads aggregated PyPI download counts for the last day, week, and month. It does not save credentials or account identities.

Repository traffic views and clones are collected when `GITHUB_TOKEN` is set to a fine-grained token with repository **Administration: read** permission. Keep the token in a secret manager or shell environment; never put it in a command argument or snapshot file.

Set `GITHUB_TOKEN` through your secret manager or CI secret store, then run:

```bash
python3 scripts/oss_metrics_snapshot.py \
  --repo AIGovDev/aigov-core \
  --pypi-package aigov-py \
  --previous ./metrics/aigov-core-2026-11-26.json \
  --output ./metrics/aigov-core-2026-11-27.json
```

The output is JSON (`aigov.opensource.metrics.v1`). It records collection time, metric values, API source, and an explicit `status`. Existing metric keys remain available; the account-level contributor counts and PyPI metric are additive. Unavailable data is represented as `status: "unavailable"` with a reason, never as zero. The `comparison` object reports deltas only when both snapshots contain available values.

## Metric definitions and interpretation

| Field | Meaning | Scope |
| --- | --- | --- |
| `stars` | Current GitHub stargazer count | Current counter; retain snapshots to form a time series |
| `forks` | Current GitHub fork count | Does not distinguish active from abandoned forks |
| `open_issues_and_prs` | GitHub repository API `open_issues_count` | Includes open pull requests |
| `contributors_listed` | Number of entries returned by GitHub's contributors endpoint, including anonymous entries | Retained with its original meaning for compatibility with existing snapshots |
| `contributors_unique_accounts` | Distinct GitHub user account IDs returned by the contributors endpoint | Anonymous entries are excluded; bot accounts are separate; multiple accounts belonging to one person cannot be identified or merged |
| `contributors_bot_accounts` | Distinct bot account IDs returned by the contributors endpoint | Reported separately and not included in user account count |
| `pypi_downloads` | PyPI Stats API download aggregates for `aigov-py` | Rolling day/week/month windows; known mirrors excluded; downloads do not identify unique installations or users |
| `release_asset_downloads` | Sum of download counts for assets attached to published GitHub releases | Separate from PyPI downloads; excludes GitHub source archives and direct clones |
| `traffic_views_14d` | GitHub's rolling 14-day total and unique view counts | Requires token access; adjacent windows overlap and “unique” is GitHub's estimate |
| `traffic_clones_14d` | GitHub's rolling 14-day total and unique clone counts | Requires token access; adjacent windows overlap and does not equal unique developers |

PyPI Stats API data is updated daily, excludes known mirrors, and its time series is retained for 180 days. Deltas for PyPI and GitHub traffic compare overlapping rolling windows, so they are changes in window totals—not downloads, visits, or clones during the interval between snapshots. See the [PyPI Stats API documentation](https://pypistats.org/api/).

GitHub does not expose per-download counts for source archives through the repository statistics endpoints used here. Those downloads therefore remain outside the measured totals; do not add them to release asset downloads or PyPI counts. GitHub clone traffic is reported separately when authorized.

Store snapshots outside the repository unless there is a deliberate reason to publish a public time series. If published, include collection timestamps and preserve the status/source fields so missing data cannot be mistaken for zero. These metrics are not customer or unique-human adoption counts.

## Weekly reporting

The workflow in `.github/workflows/weekly-adoption-metrics.yml` runs every Monday at 09:15 UTC and can also be dispatched manually. It writes a dated JSON snapshot to a 90-day workflow artifact and a short summary to the Actions run. The GitHub-provided read-only token collects public counters; repository traffic stays unavailable unless the token has Administration: read permission. The workflow does not commit metrics or publish user identities.

The initial verified snapshot is in [public-adoption-baseline-2026-11-27.md](public-adoption-baseline-2026-11-27.md). Compare future artifacts against saved snapshots with `--previous` to measure deltas. GitHub traffic endpoints expose only the recent rolling window, and PyPI Stats retains a limited time series, so retain snapshots regularly for longer-term comparisons.
