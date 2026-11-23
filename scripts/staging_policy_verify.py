#!/usr/bin/env python3
"""Staging verification for signed Ed25519 v2 policy bundles.

Two scopes, recorded separately in the evidence file so they are never mixed:

* ``local_simulation`` (default): generates disposable Ed25519 keys in memory, signs synthetic
  policies with the production signer (``aigov_py.policy_bundle_signing``), starts the release
  ``aigov_audit`` binary once per scenario with ``AIGOV_ENVIRONMENT=staging`` or ``prod``, and checks
  startup refusals and HTTP verdict behavior. Nothing is written to the repository except the evidence
  file. Keys never leave process memory; only public keys appear in the evidence.

* ``live_staging``: runs infrastructure-level checks against a deployed staging service identified by
  ``GOVAI_STAGING_BASE_URL`` and ``GOVAI_STAGING_API_KEY``. It refuses any host without an explicit
  ``staging`` (or ``stg``/``test``) label, and it refuses localhost unless ``--allow-local-for-self-test``
  is given, which labels the result as a self-test rather than staging evidence. If the variables are
  absent, the live checks are recorded as ``blocked``, never as passed.

Exit status: 1 if any check failed. With ``--require-live``, 2 if live checks were blocked.

Usage (repository root, after ``cargo build --release`` in ``rust/`` and ``pip install -e python``)::

    python scripts/staging_policy_verify.py --out artifacts/staging-verify/evidence.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
BINARY = REPO_ROOT / "rust" / "target" / "release" / "aigov_audit"

ISSUER = "govai-staging-verify"
CREATED = "2026-11-23T00:00:00Z"
FUTURE = "2999-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"
STAGING_LABELS = {"staging", "stg", "test"}

# --------------------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------------------


class Evidence:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.checks: list[dict[str, Any]] = []
        self.started_at = dt.datetime.now(dt.UTC).isoformat()

    def record(
        self,
        check_id: str,
        scope: str,
        description: str,
        expected: str,
        observed: str,
        status: str,
        detail: str = "",
    ) -> None:
        assert status in {"passed", "failed", "blocked"}, status
        assert scope in {"local_simulation", "live_staging"}, scope
        self.checks.append(
            {
                "id": check_id,
                "scope": scope,
                "description": description,
                "expected": expected,
                "observed": observed,
                "status": status,
                "detail": detail,
            }
        )

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {"total": len(self.checks)}
        for s in ("passed", "failed", "blocked"):
            out[s] = sum(1 for c in self.checks if c["status"] == s)
        for scope in ("local_simulation", "live_staging"):
            subset = [c for c in self.checks if c["scope"] == scope]
            out[scope] = {
                s: sum(1 for c in subset if c["status"] == s)
                for s in ("passed", "failed", "blocked")
            }
        return out

    def document(self) -> dict[str, Any]:
        return {
            "schema": "govai.staging_policy_verification.v1",
            "mode": self.mode,
            "started_at_utc": self.started_at,
            "finished_at_utc": dt.datetime.now(dt.UTC).isoformat(),
            "git_sha": _git_sha(),
            "binary_sha256": _sha256_file(BINARY) if BINARY.exists() else None,
            "summary": self.summary(),
            "checks": self.checks,
        }


def _git_sha() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# --------------------------------------------------------------------------------------------------
# Synthetic policies and disposable keys
# --------------------------------------------------------------------------------------------------


def synthetic_policy(
    policy_id: str = "staging-verify-policy", version: str = "1"
) -> dict[str, Any]:
    return {
        "schema": "govai.policy.v1",
        "policy_id": policy_id,
        "version": version,
        "created_at_utc": CREATED,
        "issuer": {
            "issuer_id": ISSUER,
            "display_name": "Staging verification (synthetic)",
        },
        "selectors": {"tenants": ["*"], "environments": ["*"]},
        "inherits": [],
        "ingest_rules": {
            "unknown_event_types": {"behavior": "reject"},
            "event_types": {
                "ai_discovery_reported": {
                    "schema": {
                        "required_types": {"openai": "boolean"},
                        "required_nonempty_strings": [],
                    },
                    "gates": [],
                },
                "evaluation_reported": {
                    "schema": {
                        "required_types": {"passed": "boolean"},
                        "required_nonempty_strings": [],
                    },
                    "gates": [],
                },
                "human_approved": {
                    "schema": {
                        "required_types": {},
                        "required_nonempty_strings": ["approver", "decision"],
                    },
                    "gates": [
                        {
                            "type": "requires_approver_allowlist",
                            "field": "approver",
                            "allowlist": ["alice"],
                            "code": "approver_not_allowlisted",
                            "message_prefix": "policy_violation: human_approved approver",
                        }
                    ],
                },
                "model_promoted": {
                    "schema": {"required_types": {}, "required_nonempty_strings": []},
                    "gates": [
                        {
                            "type": "requires_passed_evaluation",
                            "code": "evaluation_not_passed",
                            "message": "policy_violation: model_promoted requires a passed evaluation",
                        }
                    ],
                },
            },
        },
        "verdict_rules": {"required_evidence_codes": [], "invalid_conditions": []},
        "signatures": [],
    }


def _doc_digest(doc: dict[str, Any]) -> str:
    from aigov_py.policy_bundle_signing import policy_payload_digest_sha256_hex

    return policy_payload_digest_sha256_hex(doc)


def write_signed_bundle(
    path: Path,
    doc: dict[str, Any],
    *,
    seed_b64: str,
    expires: str | None,
    signer: str = "staging-verify-ci",
) -> Path:
    from aigov_py.policy_bundle_signing import sign_policy_bundle_ed25519

    src = path.with_suffix(".unsigned.json")
    src.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    sign_policy_bundle_ed25519(
        src,
        out_path=path,
        issuer_id=ISSUER,
        signer=signer,
        private_key_base64=seed_b64,
        created_at_utc=CREATED,
        expires_at_utc=expires,
    )
    src.unlink()
    return path


def write_v1_record_with_expiry(
    path: Path, doc: dict[str, Any], *, seed_b64: str, expires: str
) -> Path:
    """Sign as a legacy (v1) record, which covers the document digest only, and add an expiry.

    The expiry is not covered by a v1 signature, so the verifier must refuse this record.
    """
    from nacl.signing import SigningKey

    digest = _doc_digest(doc)
    sig = SigningKey(base64.b64decode(seed_b64)).sign(digest.encode("utf-8")).signature
    signed = json.loads(json.dumps(doc))
    signed["signatures"] = [
        {
            "kind": "ed25519",
            "signer": "staging-verify-ci",
            "created_at_utc": CREATED,
            "expires_at_utc": expires,
            "payload_digest_sha256": digest,
            "signature": {
                "encoding": "base64",
                "value": base64.b64encode(sig).decode("ascii"),
            },
            "sigstore": None,
        }
    ]
    path.write_text(json.dumps(signed, indent=2), encoding="utf-8")
    return path


def trust_json(pubkey_b64: str) -> str:
    return json.dumps([{"issuer_id": ISSUER, "pubkeys_base64": [pubkey_b64]}])


# --------------------------------------------------------------------------------------------------
# Server process management
# --------------------------------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(
        self, proc: subprocess.Popen, base_url: str, api_key: str, log: Path
    ) -> None:
        self.proc = proc
        self.base_url = base_url
        self.api_key = api_key
        self.log = log

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def stderr_text(self) -> str:
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


def base_env(
    *,
    ledger: Path,
    policy_dir: Path,
    environment: str,
    trust: str,
    api_key: str,
    bind: str,
) -> dict[str, str]:
    # Start from a clean environment so no ambient AIGOV_/GOVAI_ variable can change the outcome.
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("AIGOV_", "GOVAI_")) and k not in {"DATABASE_URL"}
    }
    env.update(
        {
            "GOVAI_LEDGER_DIR": str(ledger),
            "GOVAI_API_KEYS": api_key,
            "GOVAI_API_KEYS_JSON": json.dumps({api_key: "tenant-staging-verify"}),
            "GOVAI_API_USAGE_STORE": "memory",
            "AIGOV_ENVIRONMENT": environment,
            "AIGOV_BIND": bind,
            "AIGOV_POLICY_DIR": str(policy_dir),
            "AIGOV_POLICY_TRUST_ED25519_JSON": trust,
        }
    )
    return env


def start_server(
    env: dict[str, str], work: Path, *, timeout_s: float = 15.0
) -> tuple[Server | None, str]:
    """Start the binary. Returns (server, "") when it becomes ready, else (None, stderr text)."""
    bind = env["AIGOV_BIND"]
    base_url = f"http://{bind}"
    log = work / f"server-{bind.rsplit(':', 1)[1]}.log"
    with open(log, "wb") as fh:
        proc = subprocess.Popen(
            [str(BINARY)], env=env, stdout=fh, stderr=subprocess.STDOUT
        )
    server = Server(proc, base_url, env["GOVAI_API_KEYS"], log)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return None, server.stderr_text()
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1) as r:
                if r.status == 200:
                    return server, ""
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.2)
    server.stop()
    return None, server.stderr_text() or "timed out waiting for /health"


def last_error_line(stderr: str) -> str:
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    errs = [
        ln
        for ln in lines
        if "failed" in ln or "refusing" in ln or "error" in ln.lower()
    ]
    return (errs[-1] if errs else (lines[-1] if lines else ""))[:400]


# --------------------------------------------------------------------------------------------------
# HTTP probes
# --------------------------------------------------------------------------------------------------


def http(
    method: str,
    url: str,
    *,
    api_key: str | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    except (urllib.error.URLError, OSError) as e:
        return 0, {"transport_error": str(e)}
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        parsed = {"raw": raw[:200].decode("utf-8", errors="replace")}
    return status, parsed if isinstance(parsed, dict) else {"value": parsed}


def _event(
    run_id: str, event_id: str, event_type: str, payload: dict[str, Any]
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "ts_utc": "2026-11-23T00:00:01Z",
        "actor": "staging-verify",
        "system": "staging-verify",
        "run_id": run_id,
        "payload": payload,
    }


def _refusal_message(body: dict[str, Any]) -> str:
    """The policy refusal text. Clients receive the gate message, not the gate code."""
    err = body.get("error")
    if isinstance(err, dict):
        return str(err.get("message", ""))
    return str(body.get("message", ""))


# --------------------------------------------------------------------------------------------------
# Local simulation scenarios
# --------------------------------------------------------------------------------------------------


class Keys:
    def __init__(self) -> None:
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        self.seed_b64 = base64.b64encode(bytes(sk)).decode("ascii")
        self.pub_b64 = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
        other = SigningKey.generate()
        self.other_seed_b64 = base64.b64encode(bytes(other)).decode("ascii")
        self.fingerprint = hashlib.sha256(bytes(sk.verify_key)).hexdigest()[:16]


def _startup_scenario(
    ev: Evidence,
    work: Path,
    keys: Keys,
    cid: str,
    desc: str,
    *,
    environment: str,
    policy_dir: Path,
    bundle: Path | None,
    trust: str,
    extra_env: dict[str, str],
    expect_start: bool,
    expect_substring: str = "",
) -> Server | None:
    ledger = work / f"ledger-{cid}"
    ledger.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    env = base_env(
        ledger=ledger,
        policy_dir=policy_dir,
        environment=environment,
        trust=trust,
        api_key=f"k-{cid}",
        bind=f"127.0.0.1:{port}",
    )
    if bundle is not None:
        env["AIGOV_POLICY_BUNDLE_FILE"] = str(bundle)
    env.update(extra_env)
    server, err = start_server(env, work)
    if expect_start:
        ok = server is not None
        ev.record(
            cid,
            "local_simulation",
            desc,
            "server starts and reports healthy",
            "started" if ok else f"refused: {last_error_line(err)}",
            "passed" if ok else "failed",
            detail=f"environment={environment}",
        )
    else:
        refused = server is None
        msg = last_error_line(err)
        matched = refused and (expect_substring in err)
        ev.record(
            cid,
            "local_simulation",
            desc,
            f"server refuses to start (message contains {expect_substring!r})",
            "refused: " + msg if refused else "started",
            "passed" if matched else "failed",
            detail=f"environment={environment}",
        )
    return server


def run_local(ev: Evidence, work: Path) -> None:
    keys = Keys()
    trust = trust_json(keys.pub_b64)
    policy_dir = work / "empty-policy-dir"
    policy_dir.mkdir()
    ev.record(
        "keys.fingerprint",
        "local_simulation",
        "disposable Ed25519 public key fingerprint",
        "generated in memory for this run",
        keys.fingerprint,
        "passed",
        detail="private key never written to disk or evidence",
    )

    doc = synthetic_policy()
    valid = write_signed_bundle(
        work / "valid.bundle.json", doc, seed_b64=keys.seed_b64, expires=FUTURE
    )

    # --- Trusted, unexpired, correctly signed bundle: starts in staging.
    srv = _startup_scenario(
        ev,
        work,
        keys,
        "bundle.valid_v2.starts_in_staging",
        "signed v2 bundle with future expiry starts in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=valid,
        trust=trust,
        extra_env={},
        expect_start=True,
    )
    if srv is not None:
        try:
            run_http_scenarios(ev, srv, keys)
        finally:
            srv.stop()

    # --- Rejections in staging.
    expired = write_signed_bundle(
        work / "expired.bundle.json", doc, seed_b64=keys.seed_b64, expires=PAST
    )
    _startup_scenario(
        ev,
        work,
        keys,
        "bundle.expired_v2.refused_in_staging",
        "expired v2 bundle is refused in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=expired,
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="expired",
    )

    tampered_path = work / "tampered.bundle.json"
    tampered_doc = json.loads(valid.read_text(encoding="utf-8"))
    tampered_doc["ingest_rules"]["event_types"]["human_approved"]["gates"][0][
        "allowlist"
    ] = ["alice", "mallory"]
    tampered_path.write_text(json.dumps(tampered_doc, indent=2), encoding="utf-8")
    _startup_scenario(
        ev,
        work,
        keys,
        "bundle.tampered_rule.refused_in_staging",
        "bundle with an allowlist edited after signing is refused in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=tampered_path,
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="payload_digest_sha256 mismatch",
    )

    untrusted = write_signed_bundle(
        work / "untrusted.bundle.json",
        doc,
        seed_b64=keys.other_seed_b64,
        expires=FUTURE,
    )
    _startup_scenario(
        ev,
        work,
        keys,
        "bundle.untrusted_key.refused_in_staging",
        "bundle signed by a key absent from the trust store is refused in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=untrusted,
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="verification failed",
    )

    unsigned = work / "unsigned.bundle.json"
    unsigned.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _startup_scenario(
        ev,
        work,
        keys,
        "bundle.unsigned.refused_in_staging",
        "unsigned bundle is refused in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=unsigned,
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="unsigned",
    )

    _startup_scenario(
        ev,
        work,
        keys,
        "bundle.missing_file.refused_in_staging",
        "configured bundle path that does not exist is refused in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=work / "does-not-exist.json",
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="No such file",
    )

    legacy_path = work / "legacy-expiry.bundle.json"
    write_v1_record_with_expiry(
        legacy_path, doc, seed_b64=keys.seed_b64, expires=FUTURE
    )
    _startup_scenario(
        ev,
        work,
        keys,
        "bundle.v1_record_with_expiry.refused_in_staging",
        "legacy (v1) record that carries an expiry is refused in staging",
        environment="staging",
        policy_dir=policy_dir,
        bundle=legacy_path,
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="cannot carry expires_at_utc",
    )

    # --- Unsigned overrides and production contract.
    policy_file = work / "policy.staging.json"
    policy_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    _startup_scenario(
        ev,
        work,
        keys,
        "override.unsigned_file.refused_in_staging",
        "unsigned policy file is refused in staging without the explicit opt-in",
        environment="staging",
        policy_dir=policy_dir,
        bundle=None,
        trust=trust,
        extra_env={"AIGOV_POLICY_FILE": str(policy_file)},
        expect_start=False,
        expect_substring="unsigned policy file",
    )

    _startup_scenario(
        ev,
        work,
        keys,
        "override.policy_file.refused_in_prod",
        "AIGOV_POLICY_FILE is refused in production",
        environment="prod",
        policy_dir=policy_dir,
        bundle=valid,
        trust=trust,
        extra_env={"AIGOV_POLICY_FILE": str(policy_file)},
        expect_start=False,
        expect_substring="AIGOV_POLICY_FILE is not permitted",
    )

    _startup_scenario(
        ev,
        work,
        keys,
        "override.allow_unsigned_env.refused_in_prod",
        "AIGOV_ALLOW_UNSIGNED_POLICY_FILE is refused in production",
        environment="prod",
        policy_dir=policy_dir,
        bundle=valid,
        trust=trust,
        extra_env={"AIGOV_ALLOW_UNSIGNED_POLICY_FILE": "1"},
        expect_start=False,
        expect_substring="AIGOV_ALLOW_UNSIGNED_POLICY_FILE is not permitted",
    )

    _startup_scenario(
        ev,
        work,
        keys,
        "override.approver_env.refused_in_prod",
        "AIGOV_APPROVER_ALLOWLIST is refused in production",
        environment="prod",
        policy_dir=policy_dir,
        bundle=valid,
        trust=trust,
        extra_env={"AIGOV_APPROVER_ALLOWLIST": "mallory"},
        expect_start=False,
        expect_substring="AIGOV_APPROVER_ALLOWLIST is not permitted",
    )

    _startup_scenario(
        ev,
        work,
        keys,
        "prod.no_bundle.refused",
        "production without a signed bundle is refused",
        environment="prod",
        policy_dir=policy_dir,
        bundle=None,
        trust=trust,
        extra_env={},
        expect_start=False,
        expect_substring="requires a signed policy bundle",
    )

    # --- Development compatibility control: unsigned file still starts in dev.
    _startup_scenario(
        ev,
        work,
        keys,
        "dev.unsigned_file.starts",
        "development compatibility: unsigned policy file still starts in dev",
        environment="dev",
        policy_dir=policy_dir,
        bundle=None,
        trust=trust,
        extra_env={"AIGOV_POLICY_FILE": str(policy_file)},
        expect_start=True,
    )


def run_http_scenarios(ev: Evidence, srv: Server, keys: Keys) -> None:
    """Verdict, evaluation, and approval behavior against the running staging-mode server."""
    key = srv.api_key
    base = srv.base_url
    run = "staging-verify-run-1"

    status, body = http("GET", f"{base}/health")
    ev.record(
        "http.health",
        "local_simulation",
        "health endpoint is reachable",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        body=_event(run, "sv-unauth", "ai_discovery_reported", {"openai": False}),
    )
    ev.record(
        "http.evidence.unauthenticated",
        "local_simulation",
        "evidence ingest without an API key is rejected",
        "401",
        str(status),
        "passed" if status == 401 else "failed",
    )

    status, body = http("GET", f"{base}/compliance-summary?run_id={run}", api_key=key)
    ev.record(
        "http.verdict.unknown_run",
        "local_simulation",
        "verdict summary for a run with no evidence is not invented",
        "404 run_not_found",
        f"{status} {body.get('code', '')}".strip(),
        "passed" if status == 404 else "failed",
    )

    status, body = http("GET", f"{base}/compliance-summary?run_id={run}")
    ev.record(
        "http.verdict.unauthenticated_read",
        "local_simulation",
        "verdict summary without an API key is rejected",
        "401",
        str(status),
        "passed" if status == 401 else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(run, "sv-disc", "ai_discovery_reported", {"openai": False}),
    )
    ev.record(
        "ingest.allowed_event",
        "local_simulation",
        "allowed event type with valid payload is admitted",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    # Evaluation requirement: promotion needs a passed evaluation for the same run.
    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(run, "sv-promo-1", "model_promoted", {}),
    )
    msg = _refusal_message(body)
    ev.record(
        "evaluation.promotion_without_evaluation",
        "local_simulation",
        "promotion without any evaluation is refused",
        "refused: requires a passed evaluation",
        f"{status} {msg}".strip(),
        "passed"
        if status >= 400 and "requires a passed evaluation" in msg
        else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(run, "sv-eval-fail", "evaluation_reported", {"passed": False}),
    )
    ev.record(
        "evaluation.failed_evaluation_recorded",
        "local_simulation",
        "failed evaluation is recorded but does not satisfy the requirement",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(run, "sv-promo-2", "model_promoted", {}),
    )
    msg = _refusal_message(body)
    ev.record(
        "evaluation.promotion_after_failed_evaluation",
        "local_simulation",
        "promotion after only a failed evaluation is refused",
        "refused: requires a passed evaluation",
        f"{status} {msg}".strip(),
        "passed"
        if status >= 400 and "requires a passed evaluation" in msg
        else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(run, "sv-eval-pass", "evaluation_reported", {"passed": True}),
    )
    ev.record(
        "evaluation.passed_evaluation_recorded",
        "local_simulation",
        "passed evaluation is recorded",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(run, "sv-promo-3", "model_promoted", {}),
    )
    ev.record(
        "evaluation.promotion_after_passed_evaluation",
        "local_simulation",
        "promotion after a passed evaluation is admitted",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    # Authorized versus unauthorized human approvals.
    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(
            run,
            "sv-appr-bad",
            "human_approved",
            {"approver": "mallory", "decision": "approve"},
        ),
    )
    msg = _refusal_message(body)
    ev.record(
        "approval.unauthorized_approver",
        "local_simulation",
        "approval by an approver outside the signed allowlist is refused",
        "refused: approver not allowlisted",
        f"{status} {msg}".strip(),
        "passed"
        if status >= 400 and "human_approved approver 'mallory'" in msg
        else "failed",
    )

    status, body = http(
        "POST",
        f"{base}/evidence",
        api_key=key,
        body=_event(
            run,
            "sv-appr-ok",
            "human_approved",
            {"approver": "alice", "decision": "approve"},
        ),
    )
    ev.record(
        "approval.authorized_approver",
        "local_simulation",
        "approval by an allowlisted approver is admitted",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, body = http("GET", f"{base}/compliance-summary?run_id={run}", api_key=key)
    ev.record(
        "verdict.summary_after_flow",
        "local_simulation",
        "verdict summary is available after the full flow",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )


# --------------------------------------------------------------------------------------------------
# Live staging checks (infrastructure-level only; no bundle assumptions)
# --------------------------------------------------------------------------------------------------


def _host_is_staging(host: str) -> bool:
    """Guard against pointing the live checks at production by mistake.

    A host qualifies when one of its dot- or hyphen-separated tokens is ``staging``, ``stg`` or
    ``test`` (for example ``api.staging.example.com`` or ``govai-staging.example.com``). Whole tokens
    only, so ``teststaging`` does not qualify. This is a safety check on the operator's input, not an
    authentication of the host.
    """
    tokens = set(re.split(r"[.-]", host.lower()))
    return bool(tokens & STAGING_LABELS)


def run_live(ev: Evidence, *, allow_local: bool) -> None:
    base = os.environ.get("GOVAI_STAGING_BASE_URL", "").strip().rstrip("/")
    key = os.environ.get("GOVAI_STAGING_API_KEY", "").strip()
    if not base or not key:
        for cid, desc in [
            ("live.health", "deployed staging service answers /health"),
            (
                "live.auth.unauthenticated_rejected",
                "deployed staging rejects requests without a key",
            ),
            (
                "live.auth.invalid_key_rejected",
                "deployed staging rejects an invalid key",
            ),
            (
                "live.verdict.authenticated_read",
                "deployed staging serves a verdict summary with a valid key",
            ),
        ]:
            ev.record(
                cid,
                "live_staging",
                desc,
                "checked against a configured staging URL",
                "not run",
                "blocked",
                detail="GOVAI_STAGING_BASE_URL and GOVAI_STAGING_API_KEY are not configured",
            )
        return

    from urllib.parse import urlparse

    parsed = urlparse(base)
    host = parsed.hostname or ""
    is_local = host in {"localhost", "127.0.0.1", "::1"}
    if is_local and not allow_local:
        ev.record(
            "live.target",
            "live_staging",
            "live target is a deployed staging host",
            "non-local host with a staging label",
            f"refused local host {host}",
            "failed",
            detail="use --allow-local-for-self-test only to test this code path",
        )
        return
    if not is_local and not _host_is_staging(host):
        ev.record(
            "live.target",
            "live_staging",
            "live target is a deployed staging host",
            "host carries a staging, stg, or test label",
            f"refused host {host}",
            "failed",
        )
        return
    scope_note = (
        "self-test against localhost (not staging evidence)"
        if is_local
        else "deployed staging"
    )
    ev.record(
        "live.target",
        "live_staging",
        "live target identified",
        scope_note,
        host,
        "passed",
    )

    status, _ = http("GET", f"{base}/health")
    ev.record(
        "live.health",
        "live_staging",
        "deployed staging service answers /health",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, _ = http(
        "POST",
        f"{base}/evidence",
        body=_event(
            "live-probe", "live-unauth", "ai_discovery_reported", {"openai": False}
        ),
    )
    ev.record(
        "live.auth.unauthenticated_rejected",
        "live_staging",
        "deployed staging rejects requests without a key",
        "401",
        str(status),
        "passed" if status == 401 else "failed",
    )

    status, _ = http(
        "GET",
        f"{base}/compliance-summary?run_id=live-probe",
        api_key="invalid-key-for-probe",
    )
    ev.record(
        "live.auth.invalid_key_rejected",
        "live_staging",
        "deployed staging rejects an invalid key",
        "401",
        str(status),
        "passed" if status == 401 else "failed",
    )

    # A valid key must be authorized. The probe run has no evidence, so 404 run_not_found is the
    # correct, authorized answer; 401 or 403 would mean the key was not accepted.
    status, body = http(
        "GET", f"{base}/compliance-summary?run_id=live-probe", api_key=key
    )
    ev.record(
        "live.verdict.authenticated_read",
        "live_staging",
        "deployed staging accepts a valid key for verdict reads (200, or 404 run_not_found for the probe run)",
        "200 or 404 run_not_found",
        f"{status} {body.get('code', '')}".strip(),
        "passed" if status in (200, 404) else "failed",
    )


# --------------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", type=Path, required=True, help="evidence JSON to write")
    ap.add_argument("--skip-local", action="store_true", help="run only live checks")
    ap.add_argument(
        "--skip-live", action="store_true", help="run only local simulation"
    )
    ap.add_argument(
        "--allow-local-for-self-test",
        action="store_true",
        help="allow GOVAI_STAGING_BASE_URL to point at localhost; recorded as a self-test",
    )
    ap.add_argument(
        "--require-live",
        action="store_true",
        help="exit 2 if live staging checks are blocked",
    )
    args = ap.parse_args(argv)

    if not args.skip_local and not BINARY.exists():
        print(
            f"release binary not found: {BINARY}; run `cargo build --release --locked` in rust/",
            file=sys.stderr,
        )
        return 1

    ev = Evidence(
        mode="local+live"
        if not (args.skip_local or args.skip_live)
        else ("live" if args.skip_local else "local")
    )
    if not args.skip_local:
        work = Path(tempfile.mkdtemp(prefix="staging-verify-"))
        try:
            run_local(ev, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if not args.skip_live:
        run_live(ev, allow_local=args.allow_local_for_self_test)

    doc = ev.document()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    s = doc["summary"]
    print(f"evidence: {args.out}")
    print(f"local_simulation: {s['local_simulation']}")
    print(f"live_staging:     {s['live_staging']}")

    if s["failed"]:
        return 1
    if args.require_live and s["live_staging"]["blocked"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
