#!/usr/bin/env python3
"""Read-only, fail-closed CLA audit; never grants merge approval itself."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
ALLOWLIST = {"MonikaDvorackova", "dependabot[bot]", "github-actions[bot]"}

class AuditError(Exception):
    pass

def get(path):
    req = urllib.request.Request(API + path, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aigov-cla-v2-shadow",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError, KeyError) as exc:
        raise AuditError(f"GitHub API failed: {path}: {exc}") from exc

def pages(path):
    result = []
    for page in range(1, 1001):
        separator = "&" if "?" in path else "?"
        batch = get(f"{path}{separator}per_page=100&page={page}")
        if not isinstance(batch, list):
            raise AuditError("Unexpected paginated API response")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise AuditError("Pagination safety limit reached")

def contributors(repo, number, expected_count=None):
    # GitHub pull-commits REST endpoint is capped at 250 commits.
    # Do not approve PRs whose complete commit history cannot be enumerated.
    if expected_count is not None and (type(expected_count) is not int or expected_count < 1 or expected_count > 250):
        raise AuditError("PR commit count outside verifiable REST API range")
    commits = pages(f"/repos/{repo}/pulls/{number}/commits")
    if len(commits) >= 250 or (expected_count is not None and len(commits) != expected_count):
        raise AuditError("Incomplete or capped PR commit enumeration")
    if not commits:
        raise AuditError("PR has no commits")
    identities = {}
    for commit in commits:
        author = commit.get("author")
        login = author.get("login") if isinstance(author, dict) else None
        if not isinstance(login, str) or not login:
            raise AuditError("Unmapped commit author; manual review required")
        uid = author.get("id")
        if type(uid) is not int or uid <= 0:
            raise AuditError("Missing GitHub numeric author ID")
        if login in identities and identities[login] != uid:
            raise AuditError("Conflicting GitHub author identity")
        identities[login] = uid
    return identities

def signatures(repo):
    path = urllib.parse.quote("signatures/version1/cla.json", safe="/")
    raw = get(f"/repos/{repo}/contents/{path}?ref=cla-signatures")
    import base64
    if raw.get("encoding") != "base64":
        raise AuditError("Unexpected signature encoding")
    try:
        document = json.loads(base64.b64decode(raw["content"]))
    except (ValueError, KeyError) as exc:
        raise AuditError("Corrupt signature store") from exc
    entries = document.get("signedContributors")
    if not isinstance(entries, list):
        raise AuditError("Invalid signature schema")
    signed = set()
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("id"), int) or not isinstance(item.get("comment_id"), int):
            raise AuditError("Malformed signature record")
        if item["id"] <= 0 or item["comment_id"] <= 0 or not item["name"].strip():
            raise AuditError("Invalid signature identity or evidence reference")
        signed.add((item["name"].casefold(), item["id"]))
    return signed

def audit(repo, number):
    pr = get(f"/repos/{repo}/pulls/{number}")
    if not isinstance(pr, dict):
        raise AuditError("Invalid PR API response")
    names = contributors(repo, number, pr.get("commits"))
    submitter = pr.get("user") if isinstance(pr, dict) else None
    if not isinstance(submitter, dict) or not isinstance(submitter.get("login"), str) or type(submitter.get("id")) is not int or submitter["id"] <= 0:
        raise AuditError("Unmapped pull request submitter")
    login, uid = submitter["login"], submitter["id"]
    if login in names and names[login] != uid:
        raise AuditError("Conflicting PR submitter identity")
    names[login] = uid
    signed = signatures(repo)
    missing = sorted(login for login, uid in names.items() if login not in ALLOWLIST and (login.casefold(), uid) not in signed)
    return {"approved": not missing, "authors": sorted(names), "unsigned": missing,
            "mode": "shadow-only", "legacy_signatures": True}

def main():
    try:
        repo = os.environ["GITHUB_REPOSITORY"]
        number = int(os.environ["PR_NUMBER"])
        result = audit(repo, number)
    except (AuditError, KeyError, ValueError) as exc:
        result = {"approved": False, "error": str(exc), "mode": "shadow-only"}
    print(json.dumps(result, sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### CLA v2 shadow (not a required gate)\n\n```json\n" + json.dumps(result, indent=2) + "\n```\n")
    # The shadow job is deliberately informational until rollout review.
    return 0

if __name__ == "__main__":
    sys.exit(main())
