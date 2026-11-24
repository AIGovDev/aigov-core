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
import functools
import hashlib
import json
import os
import re
import secrets
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
SCOPES = ("local_simulation", "local_container", "live_staging")

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
        assert scope in SCOPES, scope
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
        for scope in SCOPES:
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
    """HEAD commit, with `-dirty` and the tree hash appended when the working tree differs from HEAD.

    Evidence must not name a commit that the tested artifact does not match.
    """
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    if not status.strip():
        return head
    tree = hashlib.sha256(status.encode("utf-8")).hexdigest()[:12]
    return f"{head}-dirty-{tree}"


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


def _start_once(
    ev: Evidence,
    cid: str,
    desc: str,
    *,
    ledger: Path,
    policy_dir: Path,
    bundle: Path,
    trust: str,
    expect_start: bool,
    expect_substring: str,
) -> None:
    """Start the binary once against a shared ledger. Each start is a separate process."""
    port = _free_port()
    env = base_env(
        ledger=ledger,
        policy_dir=policy_dir,
        environment="staging",
        trust=trust,
        api_key=f"k-{cid}",
        bind=f"127.0.0.1:{port}",
    )
    env["AIGOV_POLICY_BUNDLE_FILE"] = str(bundle)
    server, err = start_server(env, ledger.parent)
    if server is not None:
        server.stop()
    if expect_start:
        ok = server is not None
        ev.record(
            cid,
            "local_simulation",
            desc,
            "server starts and reports healthy",
            "started" if ok else f"refused: {last_error_line(err)}",
            "passed" if ok else "failed",
        )
    else:
        matched = server is None and expect_substring in err
        ev.record(
            cid,
            "local_simulation",
            desc,
            f"refused (message contains {expect_substring!r})",
            "refused: " + last_error_line(err) if server is None else "started",
            "passed" if matched else "failed",
        )


def run_rollback_e2e(ev: Evidence, work: Path, keys: Keys, trust: str) -> None:
    """Anti-rollback across real restarts: one ledger, several separate processes."""
    ledger = work / "rollback-ledger"
    ledger.mkdir()
    policy_dir = work / "rollback-policy-dir"
    policy_dir.mkdir()

    def bundle(name: str, version: str, *, allowlist: list[str] | None = None) -> Path:
        doc = synthetic_policy(policy_id="rollback-policy", version=version)
        if allowlist is not None:
            doc["ingest_rules"]["event_types"]["human_approved"]["gates"][0][
                "allowlist"
            ] = allowlist
        return write_signed_bundle(
            work / f"{name}.bundle.json", doc, seed_b64=keys.seed_b64, expires=FUTURE
        )

    v2 = bundle("v2", "2")
    v1 = bundle("v1", "1")
    v2_changed = bundle("v2-changed", "2", allowlist=["alice", "mallory"])
    v3 = bundle("v3", "3")
    v1_point = bundle("v1-point", "1.0")

    start = functools.partial(
        _start_once, ledger=ledger, policy_dir=policy_dir, trust=trust
    )
    start(
        ev,
        "rollback.first_start_v2",
        "first start with version 2 records the version",
        bundle=v2,
        expect_start=True,
        expect_substring="",
    )
    start(
        ev,
        "rollback.older_v1_refused",
        "redeploying version 1 after 2 is refused as a rollback",
        bundle=v1,
        expect_start=False,
        expect_substring="rollback refused",
    )
    start(
        ev,
        "rollback.same_version_changed_refused",
        "changing the content of version 2 without a new version is refused",
        bundle=v2_changed,
        expect_start=False,
        expect_substring="same-version content change refused",
    )
    start(
        ev,
        "rollback.higher_v3_accepted",
        "a higher version 3 is accepted and advances the record",
        bundle=v3,
        expect_start=True,
        expect_substring="",
    )
    start(
        ev,
        "rollback.older_v2_after_v3_refused",
        "redeploying version 2 after 3 is refused",
        bundle=v2,
        expect_start=False,
        expect_substring="rollback refused",
    )
    start(
        ev,
        "rollback.non_integer_version_refused",
        "a non-integer version is refused",
        bundle=v1_point,
        expect_start=False,
        expect_substring="not a non-negative integer",
    )


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

    run_rollback_e2e(ev, work, keys, trust)

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


def run_http_scenarios(
    ev: Evidence,
    srv: Any,
    keys: Any = None,
    *,
    scope: str = "local_simulation",
    run: str | None = None,
) -> None:
    """Verdict, evaluation, and approval behavior against the running staging-mode server."""
    key = srv.api_key
    base = srv.base_url
    run = run or "staging-verify-run-1"

    status, body = http("GET", f"{base}/health")
    ev.record(
        "http.health",
        scope,
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
        scope,
        "evidence ingest without an API key is rejected",
        "401",
        str(status),
        "passed" if status == 401 else "failed",
    )

    status, body = http("GET", f"{base}/compliance-summary?run_id={run}", api_key=key)
    ev.record(
        "http.verdict.unknown_run",
        scope,
        "verdict summary for a run with no evidence is not invented",
        "404 run_not_found",
        f"{status} {body.get('code', '')}".strip(),
        "passed" if status == 404 else "failed",
    )

    status, body = http("GET", f"{base}/compliance-summary?run_id={run}")
    ev.record(
        "http.verdict.unauthenticated_read",
        scope,
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
        scope,
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
        scope,
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
        scope,
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
        scope,
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
        scope,
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
        scope,
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
        scope,
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
        scope,
        "approval by an allowlisted approver is admitted",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, body = http("GET", f"{base}/compliance-summary?run_id={run}", api_key=key)
    ev.record(
        "verdict.summary_after_flow",
        scope,
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


class Target:
    """A running service under test: base URL and an API key read from the environment."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key


def _host_of(base: str) -> str:
    from urllib.parse import urlparse

    return urlparse(base).hostname or ""


def _is_loopback(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"}


def _run_id() -> str:
    # Unique per execution: the ledger persists across runs, so a fixed run id would make the
    # evaluation and unknown-run checks depend on earlier runs.
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"staging-verify-{stamp}-{secrets.token_hex(3)}"


def run_infra_checks(ev: Evidence, target: Target, scope: str) -> None:
    """Behavior that does not depend on which bundle the service runs."""
    base, key = target.base_url, target.api_key

    status, _ = http("GET", f"{base}/health")
    ev.record(
        "live.health",
        scope,
        "service answers /health",
        "200",
        str(status),
        "passed" if status == 200 else "failed",
    )

    status, body = http("GET", f"{base}/ready")
    ev.record(
        "live.ready",
        scope,
        "service reports ready (database, migrations, ledger writable)",
        "200",
        f"{status} {body.get('ready', '')}".strip(),
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
        scope,
        "requests without a key are rejected",
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
        scope,
        "an invalid key is rejected",
        "401",
        str(status),
        "passed" if status == 401 else "failed",
    )

    # A valid key must be authorized. The probe run has no evidence, so 404 run_not_found is the
    # authorized answer; 401 or 403 would mean the key was not accepted.
    status, body = http(
        "GET", f"{base}/compliance-summary?run_id=live-probe", api_key=key
    )
    ev.record(
        "live.auth.valid_key_accepted",
        scope,
        "a valid key is authorized for verdict reads (200, or 404 run_not_found for the probe run)",
        "200 or 404",
        f"{status} {body.get('code', '')}".strip(),
        "passed" if status in (200, 404) else "failed",
    )


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def check_deployed_container(
    ev: Evidence, container: str, image: str | None, manifest: dict[str, Any] | None
) -> bool:
    """Verify the running container's identity and the hash of the bundle it mounts.

    Returns True only when the deployed bundle hash equals the manifest produced at signing time.
    """
    scope = "local_container"
    try:
        insp = _docker(
            "inspect",
            "--format",
            "{{.State.Status}}|{{.Image}}|{{.Created}}",
            container,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        ev.record(
            "deployment.container",
            scope,
            "container is inspectable",
            "running",
            f"docker error: {e}",
            "failed",
        )
        return False
    if insp.returncode != 0:
        ev.record(
            "deployment.container",
            scope,
            "container is inspectable",
            "running",
            insp.stderr.strip()[:200],
            "failed",
        )
        return False
    status, image_id, created = insp.stdout.strip().split("|", 2)
    ev.record(
        "deployment.container_running",
        scope,
        "container is running",
        "running",
        status,
        "passed" if status == "running" else "failed",
    )
    ev.record(
        "deployment.container_identity",
        scope,
        "container identity (image id and creation time)",
        "recorded",
        f"{image_id} created {created}",
        "passed",
    )

    if image:
        ref = _docker("image", "inspect", "--format", "{{.Id}}", image)
        expected_id = ref.stdout.strip()
        ev.record(
            "deployment.image_matches_container",
            scope,
            "container runs the image that was built and tested",
            expected_id or "image not found",
            image_id,
            "passed" if ref.returncode == 0 and expected_id == image_id else "failed",
        )

    bundle_path = "/app/policies/policy.bundle.staging.json"
    if manifest is None:
        ev.record(
            "deployment.bundle_hash_matches_manifest",
            scope,
            "deployed bundle hash equals the expected artifact",
            "manifest provided",
            "no manifest",
            "blocked",
            detail="pass --manifest from `prepare` to verify the deployed bundle",
        )
        return False
    sha = _docker("exec", container, "sha256sum", bundle_path)
    if sha.returncode != 0:
        ev.record(
            "deployment.bundle_hash_matches_manifest",
            scope,
            "deployed bundle hash equals the expected artifact",
            manifest["bundle_sha256"],
            sha.stderr.strip()[:200],
            "failed",
        )
        return False
    observed = sha.stdout.split()[0] if sha.stdout.split() else ""
    ok = observed == manifest["bundle_sha256"]
    ev.record(
        "deployment.bundle_hash_matches_manifest",
        scope,
        "deployed bundle hash equals the expected artifact",
        manifest["bundle_sha256"],
        observed,
        "passed" if ok else "failed",
        detail=f"path={bundle_path}",
    )
    return ok


def _mount_dir(prefix: str) -> Path:
    """A directory for `docker run -v`. Docker Desktop shares only some host paths, so mounts are created
    under the repository's git-ignored artifacts directory rather than the system temporary directory."""
    base = REPO_ROOT / "artifacts" / "staging-verify" / "mounts"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def check_image_refusals(
    ev: Evidence, image: str, fixtures: Path, manifest: dict[str, Any]
) -> None:
    """Start the same image with each invalid bundle. Each start must be refused for its stated reason."""
    scope = "local_container"
    trust = (fixtures / "trust.json").read_text(encoding="utf-8").strip()
    cases = [
        (
            "tampered",
            "payload_digest_sha256 mismatch",
            "tampered bundle is refused by the deployed image",
        ),
        ("expired", "expired", "expired bundle is refused by the deployed image"),
        (
            "untrusted",
            "verification failed for all trusted keys",
            "bundle signed by an untrusted key is refused by the deployed image",
        ),
        (
            "unsigned",
            "policy is unsigned",
            "unsigned bundle is refused by the deployed image",
        ),
    ]
    for name, needle, desc in cases:
        work = Path(_mount_dir("refusal-"))
        try:
            shutil.copy(
                fixtures / "negative" / f"{name}.json",
                work / "policy.bundle.staging.json",
            )
            proc = _docker(
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{work}:/app/policies:ro",
                "-e",
                "AIGOV_ENVIRONMENT=staging",
                "-e",
                "AIGOV_POLICY_DIR=/app/policies",
                "-e",
                "AIGOV_POLICY_BUNDLE_FILE=/app/policies/policy.bundle.staging.json",
                "-e",
                f"AIGOV_POLICY_TRUST_ED25519_JSON={trust}",
                "-e",
                "GOVAI_API_KEYS=refusal-probe",
                "-e",
                'GOVAI_API_KEYS_JSON={"refusal-probe":"tenant-probe"}',
                image,
                timeout=120,
            )
            text = proc.stdout + proc.stderr
            refused = proc.returncode != 0 and needle in text
            ev.record(
                f"image.refuses_{name}",
                scope,
                desc,
                f"non-zero exit containing {needle!r}",
                f"exit {proc.returncode}: {last_error_line(text)}",
                "passed" if refused else "failed",
            )
        finally:
            shutil.rmtree(work, ignore_errors=True)

    # Valid bundle plus an unsigned file override: the file must not participate.
    work = Path(_mount_dir("override-"))
    try:
        shutil.copy(fixtures / "valid.json", work / "policy.bundle.staging.json")
        proc = _docker(
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{work}:/app/policies:ro",
            "-e",
            "AIGOV_ENVIRONMENT=staging",
            "-e",
            "AIGOV_POLICY_DIR=/app/policies",
            "-e",
            "AIGOV_POLICY_BUNDLE_FILE=/app/policies/policy.bundle.staging.json",
            "-e",
            f"AIGOV_POLICY_TRUST_ED25519_JSON={trust}",
            "-e",
            "AIGOV_POLICY_FILE=/app/policy.staging.json",
            "-e",
            "GOVAI_API_KEYS=refusal-probe",
            "-e",
            'GOVAI_API_KEYS_JSON={"refusal-probe":"tenant-probe"}',
            image,
            timeout=120,
        )
        text = proc.stdout + proc.stderr
        needle = "AIGOV_POLICY_FILE is not permitted in staging"
        ev.record(
            "image.refuses_policy_file_override",
            scope,
            "unsigned policy file override is refused by the deployed image when a bundle is configured",
            f"non-zero exit containing {needle!r}",
            f"exit {proc.returncode}: {last_error_line(text)}",
            "passed" if proc.returncode != 0 and needle in text else "failed",
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_live_target(ev: Evidence, args: argparse.Namespace) -> None:
    base = (args.base_url or os.environ.get("GOVAI_STAGING_BASE_URL", "")).strip()
    key = os.environ.get(args.api_key_env, "").strip()
    if not base or not key:
        for cid, desc in [
            ("live.health", "service answers /health"),
            ("live.ready", "service reports ready"),
            (
                "live.auth.unauthenticated_rejected",
                "requests without a key are rejected",
            ),
            ("live.auth.invalid_key_rejected", "an invalid key is rejected"),
            ("live.auth.valid_key_accepted", "a valid key is authorized"),
        ]:
            ev.record(
                cid,
                "live_staging",
                desc,
                "checked against a configured service",
                "not run",
                "blocked",
                detail=f"base URL and the {args.api_key_env} variable are required",
            )
        return

    host = _host_of(base)
    if args.target_kind == "local_container":
        scope = "local_container"
        if not _is_loopback(host):
            ev.record(
                "live.target",
                scope,
                "target is the local container",
                "loopback host",
                f"refused host {host}",
                "failed",
            )
            return
    else:
        scope = "live_staging"
        if _is_loopback(host) or not _host_is_staging(host):
            ev.record(
                "live.target",
                scope,
                "target is a deployed staging host",
                "non-loopback host with a staging, stg, or test label",
                f"refused host {host}",
                "failed",
            )
            return
    ev.record(
        "live.target",
        scope,
        "live target",
        args.target_kind,
        f"{args.target_kind} {host}",
        "passed",
    )

    target = Target(base, key)
    run_infra_checks(ev, target, scope)

    manifest = None
    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    bundle_ok = False
    if args.container:
        bundle_ok = check_deployed_container(ev, args.container, args.image, manifest)
    elif args.target_kind == "remote":
        ev.record(
            "deployment.bundle_hash_matches_manifest",
            scope,
            "deployed bundle hash equals the expected artifact",
            "manifest provided",
            "not accessible",
            "blocked",
            detail="a remote service's mounted bundle cannot be hashed from this machine",
        )

    if bundle_ok:
        run_http_scenarios(ev, target, None, scope=scope, run=_run_id())
    else:
        ev.record(
            "live.bundle_dependent_checks",
            scope,
            "verdict, evaluation, and approval behavior for the expected bundle",
            "deployed bundle verified",
            "not run",
            "blocked",
            detail="bundle identity must be verified before bundle-dependent behavior is checked",
        )

    if args.image and args.fixtures:
        if args.target_kind == "local_container":
            check_image_refusals(ev, args.image, Path(args.fixtures), manifest or {})
    elif args.image or args.fixtures:
        ev.record(
            "image.refusals",
            "local_container",
            "deployed image refuses invalid bundles",
            "image and fixtures provided",
            "incomplete",
            "blocked",
            detail="both --image and --fixtures are required",
        )


def prepare(out_dir: Path, expires_days: int) -> dict[str, Any]:
    """Create the staging bundle, trust store, negative fixtures, and manifest. Never writes a private key.

    The signing seed exists only in this process's memory. It is not written to disk, returned, or
    printed, and the function checks that the seed does not appear in any file it writes.
    """
    from nacl.signing import SigningKey

    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    neg = out_dir / "negative"
    neg.mkdir(exist_ok=True, mode=0o700)

    signing = SigningKey.generate()
    seed_b64 = base64.b64encode(bytes(signing)).decode("ascii")
    pub_b64 = base64.b64encode(bytes(signing.verify_key)).decode("ascii")
    other_seed_b64 = base64.b64encode(bytes(SigningKey.generate())).decode("ascii")

    expires = (dt.datetime.now(dt.UTC) + dt.timedelta(days=expires_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    past = "2020-01-01T00:00:00Z"
    doc = synthetic_policy(policy_id="staging-synthetic-policy", version="1")

    valid = write_signed_bundle(
        out_dir / "policy.bundle.staging.json", doc, seed_b64=seed_b64, expires=expires
    )
    write_signed_bundle(out_dir / "valid.json", doc, seed_b64=seed_b64, expires=expires)
    write_signed_bundle(neg / "expired.json", doc, seed_b64=seed_b64, expires=past)
    write_signed_bundle(
        neg / "untrusted.json", doc, seed_b64=other_seed_b64, expires=expires
    )
    tampered = json.loads(valid.read_text(encoding="utf-8"))
    tampered["ingest_rules"]["event_types"]["human_approved"]["gates"][0][
        "allowlist"
    ] = ["alice", "mallory"]
    (neg / "tampered.json").write_text(json.dumps(tampered, indent=2), encoding="utf-8")
    (neg / "unsigned.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    trust = trust_json(pub_b64)
    (out_dir / "trust.json").write_text(trust + "\n", encoding="utf-8")

    manifest: dict[str, Any] = {
        "schema": "govai.staging_bundle_manifest.v1",
        "prepared_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "git_sha": _git_sha(),
        "issuer_id": ISSUER,
        "signer": "staging-verify-ci",
        "policy_id": doc["policy_id"],
        "policy_version": doc["version"],
        "policy_digest_sha256": _doc_digest(doc),
        "bundle_sha256": _sha256_file(valid),
        "bundle_expires_at_utc": expires,
        "key_fingerprint_sha256": hashlib.sha256(bytes(signing.verify_key)).hexdigest()[
            :16
        ],
        "fixtures": {
            name: _sha256_file(neg / f"{name}.json")
            for name in ("expired", "untrusted", "tampered", "unsigned")
        },
    }
    (out_dir / "expected-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Guard: the seed must not be present in anything written.
    for path in out_dir.rglob("*"):
        if path.is_file():
            assert seed_b64 not in path.read_text(encoding="utf-8", errors="ignore"), (
                path
            )
    return manifest


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "prepare":
        ap = argparse.ArgumentParser(prog="staging_policy_verify.py prepare")
        ap.add_argument("--out-dir", type=Path, required=True)
        ap.add_argument("--expires-days", type=int, default=30)
        pa = ap.parse_args(argv[1:])
        manifest = prepare(pa.out_dir, pa.expires_days)
        print(f"prepared: {pa.out_dir}")
        print(f"bundle_sha256: {manifest['bundle_sha256']}")
        print(f"key_fingerprint_sha256: {manifest['key_fingerprint_sha256']}")
        return 0

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", type=Path, required=True, help="evidence JSON to write")
    ap.add_argument("--skip-local", action="store_true", help="run only live checks")
    ap.add_argument(
        "--skip-live", action="store_true", help="run only local simulation"
    )
    ap.add_argument(
        "--target-kind",
        choices=["local_container", "remote"],
        default="remote",
        help="local_container: a container on this machine; remote: a deployed staging host",
    )
    ap.add_argument(
        "--base-url",
        default="",
        help="service base URL (default: $GOVAI_STAGING_BASE_URL)",
    )
    ap.add_argument(
        "--api-key-env",
        default="GOVAI_STAGING_API_KEY",
        help="name of the environment variable holding the API key (never passed on the command line)",
    )
    ap.add_argument(
        "--container", default="", help="container name to verify (local_container)"
    )
    ap.add_argument(
        "--image",
        default="",
        help="image reference the container runs (and to test refusals against)",
    )
    ap.add_argument(
        "--manifest", default="", help="expected-manifest.json from `prepare`"
    )
    ap.add_argument(
        "--fixtures",
        default="",
        help="directory from `prepare` containing trust.json and negative/",
    )
    ap.add_argument(
        "--require-live", action="store_true", help="exit 2 if live checks are blocked"
    )
    args = ap.parse_args(argv)

    if not args.skip_local and not BINARY.exists():
        print(
            f"release binary not found: {BINARY}; run `cargo build --release --locked` in rust/",
            file=sys.stderr,
        )
        return 1

    local = not args.skip_local
    live = not args.skip_live
    ev = Evidence(
        mode="local+live" if (local and live) else ("local" if local else "live")
    )
    if local:
        work = Path(tempfile.mkdtemp(prefix="staging-verify-"))
        try:
            run_local(ev, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if live:
        run_live_target(ev, args)

    doc = ev.document()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    s = doc["summary"]
    print(f"evidence: {args.out}")
    for scope in SCOPES:
        print(f"{scope}: {s[scope]}")

    if s["failed"]:
        return 1
    if (
        args.require_live
        and s["live_staging"]["blocked"] + s["local_container"]["blocked"]
    ):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
