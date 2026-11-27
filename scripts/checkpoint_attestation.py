"""Verify checkpoint attestations using independently provisioned trust anchors."""
import json
import re
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

def canonical_statement(statement):
    fields = {"schema", "issuer", "tenant", "count", "head"}
    if not isinstance(statement, dict) or set(statement) != fields:
        raise ValueError("invalid statement fields")
    if statement["schema"] != "aigov.checkpoint.v1":
        raise ValueError("unsupported schema")
    for field in ("issuer", "tenant"):
        if not isinstance(statement[field], str) or not statement[field]:
            raise ValueError("invalid identity")
    count, head = statement["count"], statement["head"]
    if type(count) is not int or count < 0 or not isinstance(head, str):
        raise ValueError("invalid checkpoint")
    if not ((count == 0 and head == "GENESIS") or (count > 0 and re.fullmatch(r"[0-9a-f]{64}", head))):
        raise ValueError("invalid head")
    return b"AIGOV-CHECKPOINT-V1\x00" + json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def verify_attestation(statement, signature_hex, trust, *, expected_issuer, expected_tenant, minimum_count):
    """Trust maps (issuer, tenant) to an independently provisioned Ed25519 public key."""
    try:
        message = canonical_statement(statement)
        if statement["issuer"] != expected_issuer or statement["tenant"] != expected_tenant:
            return False
        if type(minimum_count) is not int or minimum_count < 0 or statement["count"] < minimum_count:
            return False
        key = trust[(expected_issuer, expected_tenant)]
        VerifyKey(bytes.fromhex(key)).verify(message, bytes.fromhex(signature_hex))
        return True
    except (ValueError, TypeError, KeyError, BadSignatureError):
        return False
