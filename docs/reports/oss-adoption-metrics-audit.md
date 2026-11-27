# Open-source Adoption Metrics Snapshot Audit

## Summary

This change adds a standard-library-only, read-only collector for GitHub repository counters, distinct contributor accounts and bots, GitHub release asset downloads, authenticated GitHub traffic views/clones, and optional PyPI package downloads. It compares snapshots and reports values only when both readings are available.

Contributor identities are not persisted: the existing `contributors_listed` field remains for snapshot compatibility, while new fields count distinct numeric GitHub user account IDs and separately count accounts marked as bots. It cannot infer when one person controls multiple accounts, and it does not claim that an account, download, view, or clone is a unique human adopter.

The PyPI source is the PyPI Stats API. It provides aggregate rolling day/week/month counts for a configured package; known mirrors are excluded and counts are not unique installs. GitHub does not expose per-download source archive counts through the repository endpoints used here, so source archives remain outside the measured totals. Release asset downloads, PyPI downloads, and GitHub clone traffic are separate metrics and are never combined.

## Evaluation gate

Offline tests use a fake API transport and verify pagination, unique account deduplication, bot separation, PyPI response validation, rolling-window comparisons, explicit unavailable states for restricted traffic, token non-retention, and input validation.

Local validation:

```bash
python3 -m unittest discover -s python/tests -p 'test_oss_metrics_snapshot.py'
python3 -m py_compile scripts/oss_metrics_snapshot.py python/tests/test_oss_metrics_snapshot.py
python3 scripts/oss_metrics_snapshot.py --help
```

No live snapshot or adoption figures are fabricated or committed by this change.

## Human approval gate

The script is a manually invoked GET-only tool. It does not change GitHub repository settings or publish snapshots. A maintainer decides whether dated snapshots remain private or are deliberately published.

## Risk assessment

GitHub contributor data may be cached and cannot join a person's multiple accounts. Traffic and PyPI comparisons use overlapping rolling windows, and download totals do not identify unique users. GitHub's public repository statistics do not provide source archive download counts. These measurement boundaries are labeled in the output and documentation. Missing or unauthorized metrics remain unavailable and never become zero. Credentials are read only from `GITHUB_TOKEN` and are not written to output. Pagination links are restricted to HTTPS `api.github.com` before a request can carry the token; PyPI requests are unauthenticated.

## Rollback plan

Revert this PR to remove the collector, offline tests, and tracking guide. No API, database, release, or repository settings migration is required.

## Changed files

| File | Role |
| --- | --- |
| `scripts/oss_metrics_snapshot.py` | Read-only GitHub and optional PyPI metrics collector and snapshot comparator |
| `python/tests/test_oss_metrics_snapshot.py` | Offline tests with fake API responses |
| `docs/community/metrics-tracking.md` | Usage, metric definitions, and interpretation boundaries |
| `docs/reports/oss-adoption-metrics-audit.md` | Scope, tests, measurement risks, and rollback record |
