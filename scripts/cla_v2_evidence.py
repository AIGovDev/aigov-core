#!/usr/bin/env python3
"""Build deterministic, append-only CLA evidence records from GitHub events.

This module does not write repository contents or grant approval. A separate,
narrowly scoped writer must persist and reconcile the resulting evidence.
"""
import hashlib
import json

CONSENT = "I have read the CLA Document and I hereby sign the CLA"

class EvidenceError(ValueError):
    pass

def record(event, repo, agreement_sha256):
    issue = event.get("issue") or {}
    comment = event.get("comment") or {}
    user = comment.get("user") or {}
    if not issue.get("pull_request"):
        raise EvidenceError("Consent must be on a pull request")
    if comment.get("body") != CONSENT:
        raise EvidenceError("Consent phrase must match exactly")
    if not isinstance(user.get("login"), str) or type(user.get("id")) is not int or user["id"] <= 0:
        raise EvidenceError("Missing numeric GitHub identity")
    if type(comment.get("id")) is not int or comment["id"] <= 0:
        raise EvidenceError("Missing comment identifier")
    if type(issue.get("number")) is not int or issue["number"] <= 0:
        raise EvidenceError("Missing pull request number")
    if not isinstance(comment.get("created_at"), str) or not comment["created_at"]:
        raise EvidenceError("Missing consent timestamp")
    if comment.get("updated_at") != comment["created_at"]:
        raise EvidenceError("Edited consent is not accepted")
    if not isinstance(agreement_sha256, str) or len(agreement_sha256) != 64 or any(c not in "0123456789abcdef" for c in agreement_sha256):
        raise EvidenceError("Agreement SHA-256 required")
    url = comment.get("html_url")
    expected = f"https://github.com/{repo}/pull/{issue['number']}#issuecomment-{comment['id']}"
    if url != expected:
        raise EvidenceError("Consent source URL mismatch")
    payload = {
        "schema": "aigov-cla-evidence-v1",
        "repo": repo,
        "agreement_sha256": agreement_sha256,
        "github_user_id": user["id"],
        "github_login": user["login"],
        "pull_request": issue["number"],
        "comment_id": comment["id"],
        "consent": CONSENT,
        "created_at": comment["created_at"],
        "source_url": url,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload
