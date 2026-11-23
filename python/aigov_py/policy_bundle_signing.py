from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from nacl.signing import SigningKey, VerifyKey

from .canonical_json import canonical_bytes


def _sort_json_value(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _sort_json_value(v[k]) for k in sorted(v.keys())}
    if isinstance(v, list):
        return [_sort_json_value(x) for x in v]
    return v


def canonical_policy_payload_bytes(policy_doc: Dict[str, Any]) -> bytes:
    """
    Canonical bytes for policy signature payload:
    - JSON with keys sorted recursively
    - `signatures` field removed
    """
    doc = dict(policy_doc)
    doc.pop("signatures", None)
    canon = _sort_json_value(doc)
    return json.dumps(canon, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def policy_payload_digest_sha256_hex(policy_doc: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy_payload_bytes(policy_doc)).hexdigest()


POLICY_PAYLOAD_VERSION_V2 = 2


def policy_signature_digest_v2(
    *,
    policy_digest_sha256: str,
    issuer_id: str,
    signer: str,
    created_at_utc: str,
    expires_at_utc: Optional[str],
) -> str:
    """Digest signed by a v2 policy record. Mirrors rust/src/policy_signing.rs::policy_signature_digest_v2."""
    value = {
        "payload_version": POLICY_PAYLOAD_VERSION_V2,
        "policy_digest_sha256": policy_digest_sha256,
        "issuer_id": issuer_id,
        "signer": signer,
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
    }
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class TrustEd25519:
    issuer_id: str
    pubkeys_base64: tuple[str, ...]


def load_trust_from_env_json(raw: str) -> list[TrustEd25519]:
    t = (raw or "").strip()
    if not t:
        return []
    items = json.loads(t)
    if not isinstance(items, list):
        raise ValueError("trust JSON must be a list")
    out: list[TrustEd25519] = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise ValueError(f"trust[{i}] must be an object")
        issuer_id = str(it.get("issuer_id") or "").strip()
        if not issuer_id:
            raise ValueError(f"trust[{i}].issuer_id must be non-empty")
        pks = it.get("pubkeys_base64")
        if not isinstance(pks, list) or not pks:
            raise ValueError(f"trust[{i}].pubkeys_base64 must be a non-empty list")
        out.append(TrustEd25519(issuer_id=issuer_id, pubkeys_base64=tuple(str(x).strip() for x in pks)))
    return out


def _iter_verify_keys(trust: Iterable[TrustEd25519], issuer_id: str) -> Iterable[VerifyKey]:
    for t in trust:
        if t.issuer_id != issuer_id:
            continue
        for pk_b64 in t.pubkeys_base64:
            pk_bytes = base64.b64decode(pk_b64)
            yield VerifyKey(pk_bytes)


def sign_policy_bundle_ed25519(
    policy_path: str | Path,
    *,
    out_path: str | Path,
    issuer_id: str,
    signer: str,
    private_key_base64: str,
    created_at_utc: str,
    expires_at_utc: Optional[str] = None,
) -> None:
    p = Path(policy_path)
    doc = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("policy bundle must be a JSON object")
    if str(doc.get("schema") or "").strip() != "govai.policy.v1":
        raise ValueError("unsupported policy schema (expected govai.policy.v1)")
    issuer_obj = doc.get("issuer")
    if not isinstance(issuer_obj, dict) or str(issuer_obj.get("issuer_id") or "").strip() != issuer_id:
        raise ValueError("policy.issuer.issuer_id does not match --issuer-id")

    doc_digest = policy_payload_digest_sha256_hex(doc)
    record_digest = policy_signature_digest_v2(
        policy_digest_sha256=doc_digest,
        issuer_id=issuer_id,
        signer=signer,
        created_at_utc=created_at_utc,
        expires_at_utc=expires_at_utc,
    )

    sk = SigningKey(base64.b64decode(private_key_base64.strip()))
    sig_bytes = sk.sign(record_digest.encode("utf-8")).signature
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    sig_record: Dict[str, Any] = {
        "kind": "ed25519",
        "payload_version": POLICY_PAYLOAD_VERSION_V2,
        "signer": signer,
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
        "payload_digest_sha256": record_digest,
        "signature": {"encoding": "base64", "value": sig_b64},
        "sigstore": None,
    }

    sigs = doc.get("signatures")
    if sigs is None:
        doc["signatures"] = [sig_record]
    elif isinstance(sigs, list):
        doc["signatures"] = list(sigs) + [sig_record]
    else:
        raise ValueError("policy.signatures must be an array when present")

    out = Path(out_path)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def verify_policy_bundle_ed25519(
    policy_doc: Dict[str, Any],
    *,
    trust: Iterable[TrustEd25519],
) -> None:
    if str(policy_doc.get("schema") or "").strip() != "govai.policy.v1":
        raise ValueError("unsupported policy schema (expected govai.policy.v1)")
    issuer = policy_doc.get("issuer")
    if not isinstance(issuer, dict):
        raise ValueError("policy.issuer must be an object")
    issuer_id = str(issuer.get("issuer_id") or "").strip()
    if not issuer_id:
        raise ValueError("policy.issuer.issuer_id must be non-empty")

    sigs = policy_doc.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise ValueError("policy is unsigned (signatures missing/empty)")

    doc_digest = policy_payload_digest_sha256_hex(policy_doc)

    last_err: Optional[str] = None
    for s in sigs:
        if not isinstance(s, dict):
            last_err = "signature record must be an object"
            continue
        if str(s.get("kind") or "") != "ed25519":
            last_err = "unsupported signature kind"
            continue
        pv = s.get("payload_version")
        expires = s.get("expires_at_utc")
        if pv is None:
            # Legacy (v1): covers the document digest only. An expiry on it cannot be trusted.
            if expires is not None:
                last_err = "legacy policy signature cannot carry expires_at_utc; re-sign with payload_version 2"
                continue
            expected = doc_digest
        elif pv == POLICY_PAYLOAD_VERSION_V2:
            expected = policy_signature_digest_v2(
                policy_digest_sha256=doc_digest,
                issuer_id=issuer_id,
                signer=str(s.get("signer") or "").strip(),
                created_at_utc=str(s.get("created_at_utc") or "").strip(),
                expires_at_utc=str(expires).strip() if expires is not None else None,
            )
        else:
            last_err = f"unsupported policy signature payload_version {pv!r}"
            continue
        if str(s.get("payload_digest_sha256") or "").strip().lower() != expected:
            last_err = "policy signature payload_digest_sha256 mismatch"
            continue
        if expires is not None:
            try:
                exp = datetime.fromisoformat(str(expires).strip().replace("Z", "+00:00"))
            except ValueError:
                last_err = "policy signature expires_at_utc is not RFC 3339"
                continue
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= exp:
                last_err = f"policy signature expired at {expires}"
                continue
        sig = s.get("signature")
        if not isinstance(sig, dict) or str(sig.get("encoding") or "") != "base64":
            last_err = "unsupported signature encoding"
            continue
        sig_b64 = str(sig.get("value") or "").strip()
        if not sig_b64:
            last_err = "signature value empty"
            continue
        sig_bytes = base64.b64decode(sig_b64)

        ok = False
        for vk in _iter_verify_keys(trust, issuer_id):
            try:
                vk.verify(expected.encode("utf-8"), sig_bytes)
                ok = True
                break
            except Exception as e:  # noqa: BLE001
                last_err = str(e) or "verify failed"
        if ok:
            return
    raise ValueError(last_err or "no valid signature found")

