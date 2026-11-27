#!/usr/bin/env python3
"""Collect a privacy-conscious, read-only GitHub adoption metrics snapshot."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

API_ROOT = "https://api.github.com"
SCHEMA = "aigov.opensource.metrics.v1"
USER_AGENT = "aigov-oss-metrics/1.0"


class GitHubAPIError(Exception):
    def __init__(self, status: int):
        super().__init__(f"GitHub API returned HTTP {status}")
        self.status = status


def request_json(url: str, token: str | None = None) -> tuple[Any, dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=20) as response:
            status = response.status
            body = response.read()
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        raise GitHubAPIError(exc.code) from None
    except URLError as exc:
        raise RuntimeError("Could not reach the GitHub API") from exc
    if status == 202:
        raise GitHubAPIError(status)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub API returned invalid JSON") from exc
    return payload, response_headers


def _next_url(link_header: str) -> str | None:
    for match in re.finditer(r'<([^>]+)>\s*;\s*rel="([^"]+)"', link_header):
        if match.group(2) == "next":
            return match.group(1)
    return None


def _pages(
    url: str,
    token: str | None,
    fetcher: Callable[[str, str | None], tuple[Any, dict[str, str]]],
):
    while url:
        payload, headers = fetcher(url, token)
        if not isinstance(payload, list):
            raise RuntimeError("GitHub API returned an unexpected paginated response")
        yield from payload
        next_page = _next_url(headers.get("Link", headers.get("link", "")))
        if not next_page:
            url = ""
            continue
        parsed = urlsplit(next_page)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise RuntimeError("GitHub pagination link is outside the API host")
        url = next_page


def _available(value: Any, source: str, note: str | None = None) -> dict[str, Any]:
    metric = {"status": "available", "value": value, "source": source}
    if note:
        metric["note"] = note
    return metric


def _unavailable(reason: str, source: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason, "source": source}


def _unavailable_reason(exc: GitHubAPIError, token: str | None) -> str:
    if exc.status == 202:
        return "github_computation_pending"
    if exc.status == 403:
        return "permission_or_rate_limit" if token else "authentication_required"
    if exc.status == 404:
        return "data_not_available"
    return f"github_http_{exc.status}"


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def collect_snapshot(
    repo: str,
    *,
    token: str | None = None,
    now: datetime | None = None,
    fetcher: Callable[[str, str | None], tuple[Any, dict[str, str]]] = request_json,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Repository must use OWNER/REPO form")
    owner, name = repo.split("/", 1)
    encoded_repo = f"{quote(owner, safe='')}/{quote(name, safe='')}"
    repo_url = f"{API_ROOT}/repos/{encoded_repo}"
    metadata, _ = fetcher(repo_url, token)
    if not isinstance(metadata, dict):
        raise RuntimeError("GitHub API returned unexpected repository metadata")
    count_keys = {
        "stars": "stargazers_count",
        "forks": "forks_count",
        "open_issues_and_prs": "open_issues_count",
    }
    metrics: dict[str, Any] = {}
    for metric_name, field in count_keys.items():
        value = metadata.get(field)
        if not _nonnegative_int(value):
            raise RuntimeError(f"GitHub API returned invalid {field}")
        metrics[metric_name] = _available(value, f"GET /repos/{repo}")

    contributors_source = f"GET /repos/{repo}/contributors?anon=1"
    try:
        contributors = list(
            _pages(f"{repo_url}/contributors?anon=1&per_page=100", token, fetcher)
        )
        metrics["contributors_listed"] = _available(
            len(contributors),
            contributors_source,
            (
                "Count of API entries, including anonymous entries when returned; "
                "not a unique-human count. GitHub may cache this endpoint."
            ),
        )
    except (GitHubAPIError, RuntimeError) as exc:
        reason = (
            _unavailable_reason(exc, token)
            if isinstance(exc, GitHubAPIError)
            else "invalid_api_response"
        )
        metrics["contributors_listed"] = _unavailable(reason, contributors_source)

    releases_source = f"GET /repos/{repo}/releases"
    try:
        release_assets = 0
        for release in _pages(f"{repo_url}/releases?per_page=100", token, fetcher):
            if not isinstance(release, dict):
                raise RuntimeError("GitHub API returned an invalid release entry")
            assets = release.get("assets", [])
            if not isinstance(assets, list):
                raise RuntimeError("GitHub API returned invalid release assets")
            for asset in assets:
                if not isinstance(asset, dict) or not _nonnegative_int(
                    asset.get("download_count")
                ):
                    raise RuntimeError(
                        "GitHub API returned an invalid asset download count"
                    )
                release_assets += asset["download_count"]
        metrics["release_asset_downloads"] = _available(
            release_assets,
            releases_source,
            (
                "Cumulative downloads of attached GitHub release assets only; "
                "excludes source archives and package-registry downloads."
            ),
        )
    except (GitHubAPIError, RuntimeError) as exc:
        reason = (
            _unavailable_reason(exc, token)
            if isinstance(exc, GitHubAPIError)
            else "invalid_api_response"
        )
        metrics["release_asset_downloads"] = _unavailable(reason, releases_source)

    traffic_endpoints = (
        ("traffic_views_14d", "views"),
        ("traffic_clones_14d", "clones"),
    )
    for key, endpoint in traffic_endpoints:
        source = f"GET /repos/{repo}/traffic/{endpoint}"
        if not token:
            metrics[key] = _unavailable("token_not_provided", source)
            continue
        try:
            traffic, _ = fetcher(f"{repo_url}/traffic/{endpoint}", token)
            total = traffic.get("count") if isinstance(traffic, dict) else None
            unique = traffic.get("uniques") if isinstance(traffic, dict) else None
            if not _nonnegative_int(total) or not _nonnegative_int(unique):
                raise RuntimeError("GitHub API returned invalid traffic totals")
            metrics[key] = _available(
                {"total": total, "unique": unique, "window_days": 14},
                source,
                "Rolling 14-day GitHub traffic window; adjacent snapshots overlap.",
            )
        except (GitHubAPIError, RuntimeError) as exc:
            reason = (
                _unavailable_reason(exc, token)
                if isinstance(exc, GitHubAPIError)
                else "invalid_api_response"
            )
            metrics[key] = _unavailable(reason, source)

    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return {
        "schema": SCHEMA,
        "collected_at": (
            timestamp.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "repository": repo,
        "metrics": metrics,
    }


def compare_snapshots(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    if current.get("schema") != SCHEMA or previous.get("schema") != SCHEMA:
        raise ValueError("Both snapshots must use the supported schema")
    if current.get("repository") != previous.get("repository"):
        raise ValueError("Snapshots must refer to the same repository")
    changes: dict[str, Any] = {}
    current_metrics = current.get("metrics", {})
    previous_metrics = previous.get("metrics", {})
    for name, metric in current_metrics.items():
        old = previous_metrics.get(name)
        if (
            metric.get("status") != "available"
            or not isinstance(old, dict)
            or old.get("status") != "available"
        ):
            changes[name] = {"status": "unavailable"}
            continue
        new_value, old_value = metric["value"], old.get("value")
        if _nonnegative_int(new_value) and _nonnegative_int(old_value):
            changes[name] = {"status": "available", "delta": new_value - old_value}
        elif isinstance(new_value, dict) and isinstance(old_value, dict):
            deltas = {
                key: new_value[key] - old_value[key]
                for key in ("total", "unique")
                if _nonnegative_int(new_value.get(key))
                and _nonnegative_int(old_value.get(key))
            }
            changes[name] = {
                "status": "available" if deltas else "unavailable",
                "delta": deltas if deltas else None,
                "note": "Rolling 14-day windows overlap; this is not a daily count.",
            }
        else:
            changes[name] = {"status": "unavailable"}
    return {
        "previous_collected_at": previous.get("collected_at"),
        "changes": changes,
    }


def _load_snapshot(path: Path) -> dict[str, Any]:
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read previous snapshot: {path}") from exc
    if not isinstance(snapshot, dict):
        raise ValueError("Previous snapshot must contain a JSON object")
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", required=True, help="GitHub repository in OWNER/REPO form"
    )
    parser.add_argument(
        "--output", type=Path, help="Write JSON to a file instead of stdout"
    )
    parser.add_argument(
        "--previous", type=Path, help="Compare against a prior JSON snapshot"
    )
    args = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN") or None
    try:
        snapshot = collect_snapshot(args.repo, token=token)
        if args.previous:
            snapshot["comparison"] = compare_snapshots(
                snapshot, _load_snapshot(args.previous)
            )
        rendered = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (ValueError, RuntimeError, GitHubAPIError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
