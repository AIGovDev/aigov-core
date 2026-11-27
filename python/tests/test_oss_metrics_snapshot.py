from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from oss_metrics_snapshot import (  # noqa: E402
    GitHubAPIError,
    collect_snapshot,
    compare_snapshots,
)


class FakeAPI:
    def __init__(self, responses):
        self.responses = responses

    def __call__(self, url, token=None):
        value = self.responses.get(url)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise AssertionError(f"Unexpected request: {url}")
        return value


def base_responses():
    root = "https://api.github.com/repos/AIGovDev/aigov-core"
    return root, {
        root: (
            {
                "stargazers_count": 17,
                "forks_count": 4,
                "open_issues_count": 8,
            },
            {},
        ),
        f"{root}/contributors?anon=1&per_page=100": (
            [{"login": "alice"}],
            {"Link": '<https://api.github.com/page/2>; rel="next"'},
        ),
        "https://api.github.com/page/2": ([{"name": "Anonymous"}], {}),
        f"{root}/releases?per_page=100": (
            [
                {"assets": [{"download_count": 7}, {"download_count": 3}]},
                {"assets": []},
            ],
            {},
        ),
    }


class OSSMetricsSnapshotTests(unittest.TestCase):
    def test_snapshot_counts_public_metrics_and_paginates_contributors(self):
        _, responses = base_responses()
        snapshot = collect_snapshot(
            "AIGovDev/aigov-core",
            now=datetime(2026, 11, 27, tzinfo=timezone.utc),
            fetcher=FakeAPI(responses),
        )

        self.assertEqual(snapshot["metrics"]["stars"]["value"], 17)
        self.assertEqual(snapshot["metrics"]["forks"]["value"], 4)
        self.assertEqual(snapshot["metrics"]["open_issues_and_prs"]["value"], 8)
        self.assertEqual(snapshot["metrics"]["contributors_listed"]["value"], 2)
        self.assertEqual(snapshot["metrics"]["release_asset_downloads"]["value"], 10)
        self.assertEqual(
            snapshot["metrics"]["traffic_views_14d"],
            {
                "status": "unavailable",
                "reason": "token_not_provided",
                "source": "GET /repos/AIGovDev/aigov-core/traffic/views",
            },
        )
        self.assertEqual(snapshot["collected_at"], "2026-11-27T00:00:00Z")

    def test_pagination_link_cannot_send_token_to_another_host(self):
        root, responses = base_responses()
        responses[f"{root}/contributors?anon=1&per_page=100"] = (
            [{"login": "alice"}],
            {"Link": '<https://attacker.example/collect>; rel="next"'},
        )
        responses[f"{root}/traffic/views"] = GitHubAPIError(403)
        responses[f"{root}/traffic/clones"] = GitHubAPIError(403)
        snapshot = collect_snapshot(
            "AIGovDev/aigov-core", token="secret-token", fetcher=FakeAPI(responses)
        )

        metric = snapshot["metrics"]["contributors_listed"]
        self.assertEqual(metric["status"], "unavailable")
        self.assertEqual(metric["reason"], "invalid_api_response")
        self.assertNotIn("secret-token", repr(snapshot))

    def test_restricted_traffic_is_unavailable_not_zero(self):
        root, responses = base_responses()
        responses[f"{root}/traffic/views"] = GitHubAPIError(403)
        responses[f"{root}/traffic/clones"] = GitHubAPIError(403)
        snapshot = collect_snapshot(
            "AIGovDev/aigov-core",
            token="do-not-store-this",
            fetcher=FakeAPI(responses),
        )

        for name in ("traffic_views_14d", "traffic_clones_14d"):
            metric = snapshot["metrics"][name]
            self.assertEqual(metric["status"], "unavailable")
            self.assertEqual(metric["reason"], "permission_or_rate_limit")
            self.assertNotIn("value", metric)
        self.assertNotIn("do-not-store-this", repr(snapshot))

    def test_traffic_snapshot_and_growth_delta_are_explicit(self):
        root, responses = base_responses()
        responses[f"{root}/traffic/views"] = ({"count": 31, "uniques": 20}, {})
        responses[f"{root}/traffic/clones"] = ({"count": 12, "uniques": 9}, {})
        current = collect_snapshot(
            "AIGovDev/aigov-core", token="token", fetcher=FakeAPI(responses)
        )
        previous = {
            "schema": current["schema"],
            "repository": current["repository"],
            "collected_at": "2026-11-26T00:00:00Z",
            "metrics": {
                name: {"status": "available", "value": 10}
                for name in (
                    "stars",
                    "forks",
                    "open_issues_and_prs",
                    "contributors_listed",
                    "release_asset_downloads",
                )
            },
        }
        previous["metrics"]["traffic_views_14d"] = {
            "status": "available",
            "value": {"total": 24, "unique": 16, "window_days": 14},
        }
        previous["metrics"]["traffic_clones_14d"] = {
            "status": "unavailable",
            "reason": "token_not_provided",
        }
        comparison = compare_snapshots(current, previous)

        self.assertEqual(comparison["changes"]["stars"]["delta"], 7)
        self.assertEqual(
            comparison["changes"]["traffic_views_14d"]["delta"],
            {"total": 7, "unique": 4},
        )
        self.assertEqual(
            comparison["changes"]["traffic_clones_14d"]["status"], "unavailable"
        )

    def test_invalid_repo_and_mismatched_previous_snapshot_fail_closed(self):
        with self.assertRaises(ValueError):
            collect_snapshot("not a repo")
        snapshot = {
            "schema": "aigov.opensource.metrics.v1",
            "repository": "a/b",
            "metrics": {},
        }
        previous = {
            "schema": "aigov.opensource.metrics.v1",
            "repository": "a/c",
            "metrics": {},
        }
        with self.assertRaises(ValueError):
            compare_snapshots(snapshot, previous)


if __name__ == "__main__":
    unittest.main()
