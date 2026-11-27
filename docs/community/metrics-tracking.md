# Open-source adoption metrics

Use the read-only snapshot script to collect a dated record of public GitHub adoption metrics. It does not create stars, forks, traffic, or downloads; it only reads GitHub's API.

## Collect a snapshot

From the repository root, using Python 3.10 or newer:

```bash
python3 scripts/oss_metrics_snapshot.py \
  --repo AIGovDev/aigov-core \
  --output ./metrics/aigov-core-$(date -u +%F).json
```

Public repository counters, contributor entries, and attached release asset download counts are available without a token. The script does not save credentials or contributor identities.

Repository traffic views and clones are only collected when `GITHUB_TOKEN` is set to a fine-grained token with repository **Administration: read** permission. Keep the token in a secret manager or shell environment; never put it in a command argument or snapshot file.

```bash
python3 scripts/oss_metrics_snapshot.py \
  --repo AIGovDev/aigov-core \
  --previous ./metrics/aigov-core-2026-11-26.json \
  --output ./metrics/aigov-core-2026-11-27.json
```

When traffic access is enabled, compare snapshots with the same `--previous` option. For an ephemeral token supplied through the environment, set `GITHUB_TOKEN` using your local secret manager or CI secret store before running the command.

The output is JSON (`aigov.opensource.metrics.v1`). It records collection time, metric values, API source, and an explicit `status`. Unavailable data is represented as `status: "unavailable"` with a reason, never as zero. The `comparison` object reports deltas only when both snapshots contain available values.

## Metric definitions and limitations

| Field | Meaning | Limitation |
| --- | --- | --- |
| `stars` | Current GitHub stargazer count | A current counter, not a time series by itself |
| `forks` | Current GitHub fork count | Does not distinguish active from abandoned forks |
| `open_issues_and_prs` | GitHub repository API `open_issues_count` | Includes open pull requests |
| `contributors_listed` | Number of entries returned by GitHub's contributors endpoint, including anonymous entries when provided | Not a unique-human count; GitHub may cache the endpoint |
| `release_asset_downloads` | Sum of download counts for assets attached to published GitHub releases | Excludes source archives, package-registry downloads, and direct clones |
| `traffic_views_14d` | GitHub's rolling 14-day total and unique view counts | Requires token access; adjacent windows overlap and “unique” is GitHub's estimate |
| `traffic_clones_14d` | GitHub's rolling 14-day total and unique clone counts | Requires token access; adjacent windows overlap and does not equal unique developers |

Store snapshots outside the repository unless there is a deliberate reason to publish a public time series. If published, include collection timestamps and preserve the status/source fields so missing data cannot be mistaken for zero adoption. This tool does not collect package-registry downloads or claim customer adoption.

## Manual cadence

Run the command weekly or before and after a launch activity, retain the dated JSON snapshots, and compare with `--previous`. GitHub traffic endpoints expose only the recent rolling window, so collect and retain snapshots regularly if a longer history is needed. No scheduled workflow or external analytics account is required.
