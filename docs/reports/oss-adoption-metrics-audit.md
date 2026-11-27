# Open-source Adoption Metrics Snapshot Audit

## Summary

This change adds a standard-library-only, read-only collector for public repository counters, listed contributors, published release asset download totals, and authenticated GitHub traffic views/clones. It can compare a current snapshot with a prior snapshot to calculate deltas.

It does not automate promotion, create engagement, collect customer data, call package registries, or persist credentials. It does not claim that a star, fork, contributor API entry, release download, view, or clone is a unique human adopter.

## Evaluation gate

Offline tests use a fake API transport and verify pagination, metric counts, explicit unavailable states for restricted traffic, token non-retention, delta comparisons, and input validation.

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

The main measurement risks are API cache delay, contributor records not equaling unique people, GitHub traffic covering only a rolling 14-day window, and release asset downloads excluding source archives and package registries. These are labeled in the output and documentation. Missing or unauthorized metrics remain unavailable and never become zero. Credentials are read only from the `GITHUB_TOKEN` environment variable and are not written to output. Pagination links are restricted to HTTPS `api.github.com` before a request can carry the token.

## Rollback plan

Revert this PR to remove the collector, offline tests, and tracking guide. No API, database, release, or repository settings migration is required.

## Changed files

| File | Role |
| --- | --- |
| `scripts/oss_metrics_snapshot.py` | Read-only GitHub metrics collector and snapshot comparator |
| `python/tests/test_oss_metrics_snapshot.py` | Offline tests with fake API responses |
| `docs/community/metrics-tracking.md` | User instructions, metric definitions, and limitations |
| `docs/reports/oss-adoption-metrics-audit.md` | Scope, test, measurement-risk, and rollback record |
