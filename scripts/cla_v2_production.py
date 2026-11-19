#!/usr/bin/env python3
"""First-party CLA v2: trusted consent writer and fail-closed commit status."""
import base64
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

import cla_v2_shadow as legacy
from cla_v2_evidence import CONSENT, EvidenceError, record

CONTEXT = "CLA v2 / agreement"
STORE = "signatures/version2/users"
AGREEMENT = "legal/published/individual-contributor-license-agreement.md"

def request(method, path, payload=None, missing_ok=False):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(legacy.API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "aigov-cla-v2",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and missing_ok:
            return None
        raise legacy.AuditError(f"GitHub API {method} {path} returned {exc.code}") from exc
    except (urllib.error.URLError, ValueError) as exc:
        raise legacy.AuditError(f"GitHub API {method} {path} failed: {exc}") from exc

def evidence_path(uid):
    if type(uid) is not int or uid <= 0:
        raise legacy.AuditError("Invalid numeric user ID")
    return f"{STORE}/{uid}.json"

def load_evidence(repo, uid):
    path = evidence_path(uid)
    encoded = urllib.parse.quote(path, safe="/")
    item = request("GET", f"/repos/{repo}/contents/{encoded}?ref=cla-signatures", missing_ok=True)
    if item is None:
        return None
    if item.get("encoding") != "base64":
        raise legacy.AuditError("Invalid v2 evidence encoding")
    try:
        value = json.loads(base64.b64decode(item["content"], validate=False))
    except (ValueError, KeyError, TypeError) as exc:
        raise legacy.AuditError("Invalid v2 evidence JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != "aigov-cla-evidence-v1" or value.get("github_user_id") != uid or value.get("repo") != repo:
        raise legacy.AuditError("Invalid v2 evidence identity")
    digest = value.get("evidence_sha256")
    unsigned = {k: v for k, v in value.items() if k != "evidence_sha256"}
    actual = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != actual:
        raise legacy.AuditError("Tampered v2 evidence")
    return value

def verify_evidence(repo, uid):
    value = load_evidence(repo, uid)
    if value is None:
        return False
    comment = request("GET", f"/repos/{repo}/issues/comments/{value['comment_id']}")
    pr = request("GET", f"/repos/{repo}/pulls/{value['pull_request']}")
    if pr.get("number") != value["pull_request"]:
        raise legacy.AuditError("Signature PR mismatch")
    event = {"issue": {"number": value["pull_request"], "pull_request": {}},
             "comment": comment}
    event["issue"]["pull_request"] = {"url": "verified"}
    try:
        current = record(event, repo, value["agreement_sha256"])
    except EvidenceError as exc:
        raise legacy.AuditError(f"Invalid stored consent: {exc}") from exc
    if current != value:
        raise legacy.AuditError("Stored evidence does not match live GitHub comment")
    return True

def agreement_hash(repo):
    # Read the published agreement from protected main, never from untrusted PR code.
    path = urllib.parse.quote(AGREEMENT, safe="/")
    item = request("GET", f"/repos/{repo}/contents/{path}?ref=main")
    if item.get("encoding") != "base64":
        raise legacy.AuditError("Invalid published agreement encoding")
    return hashlib.sha256(base64.b64decode(item["content"])).hexdigest()

def save_consent(repo, event):
    comment_id = (event.get("comment") or {}).get("id")
    issue_no = (event.get("issue") or {}).get("number")
    if type(comment_id) is not int or type(issue_no) is not int:
        raise legacy.AuditError("Missing comment or PR identifier")
    # Never trust the webhook comment body, author, timestamps or PR designation.
    live_comment = request("GET", f"/repos/{repo}/issues/comments/{comment_id}")
    live_pr = request("GET", f"/repos/{repo}/pulls/{issue_no}")
    if live_pr.get("number") != issue_no:
        raise legacy.AuditError("Not a verified pull request")
    live = {"issue": {"number": issue_no, "pull_request": {"verified": True}},
            "comment": live_comment}
    try:
        evidence = record(live, repo, agreement_hash(repo))
    except EvidenceError as exc:
        raise legacy.AuditError(str(exc)) from exc
    uid = evidence["github_user_id"]
    existing = load_evidence(repo, uid)
    if existing:
        if not verify_evidence(repo, uid):
            raise legacy.AuditError("Existing evidence invalid")
        return
    path = evidence_path(uid)
    encoded = urllib.parse.quote(path, safe="/")
    try:
        request("PUT", f"/repos/{repo}/contents/{encoded}", {
            "message": f"chore(cla): record verified consent for GitHub user {uid}",
            "content": base64.b64encode((json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()).decode(),
            "branch": "cla-signatures",
        })
    except legacy.AuditError:
        # A concurrent write may have won; only accept a fully verified record.
        if not verify_evidence(repo, uid):
            raise

def audit(repo, number):
    pr = legacy.get(f"/repos/{repo}/pulls/{number}")
    names = legacy.contributors(repo, number, pr.get("commits"))
    submitter = pr.get("user")
    if not isinstance(submitter, dict) or type(submitter.get("id")) is not int or not isinstance(submitter.get("login"), str):
        raise legacy.AuditError("Unmapped PR submitter")
    if submitter["login"] in names and names[submitter["login"]] != submitter["id"]:
        raise legacy.AuditError("Conflicting submitter identity")
    names[submitter["login"]] = submitter["id"]
    old = legacy.signatures(repo)
    missing = []
    for login, uid in names.items():
        if (login.casefold(), uid) in legacy.ALLOWLIST or (login in legacy.BOT_IDENTITY_MAP and uid == legacy.BOT_IDENTITY_MAP[login]):
            continue
        if (login.casefold(), uid) in old:
            continue
        if not verify_evidence(repo, uid):
            missing.append(login)
    return pr, sorted(missing)

def set_status(repo, sha, state, description):
    if not isinstance(sha, str) or len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha.lower()):
        raise legacy.AuditError("Invalid PR head SHA")
    request("POST", f"/repos/{repo}/statuses/{sha}", {
        "state": state, "context": CONTEXT, "description": description[:140],
    })

def check(repo, number):
    pr = request("GET", f"/repos/{repo}/pulls/{number}")
    sha = (pr.get("head") or {}).get("sha")
    try:
        _, missing = audit(repo, number)
        state = "failure" if missing else "success"
        desc = "Unsigned contributors: " + ", ".join(missing) if missing else "All contributors have verified CLA evidence"
    except (legacy.AuditError, KeyError, TypeError, ValueError) as exc:
        state, desc = "error", f"CLA verification unavailable: {exc}"
    set_status(repo, sha, state, desc)
    print(json.dumps({"pr": number, "state": state, "description": desc}))
    return state == "success"

def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    kind = os.environ["GITHUB_EVENT_NAME"]
    if kind == "issue_comment":
        issue = event.get("issue") or {}
        if not issue.get("pull_request"):
            return 0
        number = issue["number"]
        if (event.get("comment") or {}).get("body") == CONSENT:
            try:
                save_consent(repo, event)
            except legacy.AuditError as exc:
                print(f"Consent not recorded: {exc}", file=sys.stderr)
        elif (event.get("comment") or {}).get("body") != "recheck":
            return 0
    elif kind == "pull_request_target":
        number = event["pull_request"]["number"]
    elif kind == "workflow_dispatch":
        number = int(os.environ["PR_NUMBER"])
    else:
        raise legacy.AuditError("Unsupported event")
    return 0 if check(repo, number) else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (legacy.AuditError, KeyError, TypeError, ValueError) as exc:
        print(f"CLA v2 fatal: {exc}", file=sys.stderr)
        sys.exit(1)
