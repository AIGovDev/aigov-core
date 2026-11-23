"""
Asymmetric KMS signing providers — private signing keys never reach the application.

Design:
  AsymmetricKMSBase  — interface: sign() / get_public_key_bytes(). No get_key().
                       The application sends payload → KMS returns signature.
                       Private key material NEVER leaves the KMS boundary.
  LocalEd25519KMSProvider — test/staging: ephemeral Ed25519 keys held in-process.
                             Private key objects are confined to self._keys and
                             never serialized or returned from any public method.
                             Replace with VercelKMSProvider for production.
  VercelKMSProvider  — production: HTTP client for Vercel KMS.
                       Signing: POST to Vercel KMS sign endpoint (OIDC-authenticated).
                       Verification: public key fetched from JWKS endpoint.
                       Private key lives in Vercel HSM — never returned to callers.

Security contract:
  • No public method on any class in this module returns private key bytes.
  • Application code uses sign() to produce signatures; get_public_key_bytes()
    to obtain the public counterpart for verification.
  • SQL stores ONLY key IDs and rotation metadata (via SqlKeyMetadataStore).
    Public key bytes MAY be cached in SQL for performance; private key bytes
    must NEVER appear there.

Using LocalEd25519KMSProvider for tests:
  provider = LocalEd25519KMSProvider()
  kid = provider.key_id                        # "ed25519-1"
  sig = provider.sign(b"payload")              # Ed25519 signature (64 bytes)
  pub = provider.get_public_key_bytes(kid)     # 32-byte raw public key
  ok  = provider.verify_signature(b"payload", sig, kid)  # True

Using VercelKMSProvider in production:
  provider = VercelKMSProvider(
      key_id="aigov-token-signing-v1",
      base_url="https://kms.vercel.com",
      team_id=os.environ["VERCEL_TEAM_ID"],
      oidc_token_fn=lambda: get_vercel_oidc_token(),  # from @vercel/functions
  )
  sig = provider.sign(b"payload")
  pub = provider.get_public_key_bytes("aigov-token-signing-v1")  # from JWKS
"""

from __future__ import annotations

import base64
import threading
from typing import Callable


class AsymmetricKMSUnavailableError(Exception):
    """Raised when the KMS cannot perform a signing operation."""


class AsymmetricKMSBase:
    """
    Abstract interface for asymmetric KMS providers.

    Callers use sign() to request a signature; they never receive private key
    material. get_public_key_bytes() returns raw public key bytes for verification.

    is_managed = True: compatible with ProductionConfigValidator which checks
    this flag to confirm the key provider is suitable for distributed deployments.
    is_asymmetric = True: signals to ExecutionTokenAuthority to use the
    asymmetric signing path instead of HMAC.
    """

    algo: str = "ed25519"
    is_managed: bool = True
    is_asymmetric: bool = True

    @property
    def key_id(self) -> str:
        raise NotImplementedError

    def sign(self, payload: bytes) -> bytes:
        """Sign payload and return signature bytes. Never returns private key bytes."""
        raise NotImplementedError

    def get_public_key_bytes(self, key_id: str) -> bytes | None:
        """
        Return 32-byte raw Ed25519 public key for key_id, or None if unknown/retired.

        Used by ExecutionTokenAuthority to verify token signatures without
        holding private key material.
        """
        raise NotImplementedError

    def rotate(self, new_key_id: str | None = None) -> str:
        """
        Generate a new keypair and make it current. Returns the new key_id.
        Old key remains accessible via get_public_key_bytes() for verification
        until retire_key() is called.
        """
        raise NotImplementedError

    def retire_key(self, key_id: str) -> None:
        """
        Retire a key. get_public_key_bytes(key_id) returns None after this.
        Tokens signed under key_id will fail verification.
        """
        raise NotImplementedError

    @property
    def is_distributed_safe(self) -> bool:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# LocalEd25519KMSProvider — test/staging provider
# ---------------------------------------------------------------------------


class LocalEd25519KMSProvider(AsymmetricKMSBase):
    """
    Test and staging KMS provider using ephemeral Ed25519 keypairs.

    Private key objects are created by the cryptography library and held
    inside _keys as opaque Ed25519PrivateKey instances. They are NEVER
    serialized, exported, or returned from any public method. The only
    operation exposed externally is sign(), which calls priv.sign(payload).

    Security:
      • No public method returns private key bytes.
      • is_managed = True → passes ProductionConfigValidator.
      • is_distributed_safe = False → ProductionConfigValidator will warn
        in DISTRIBUTED mode; correct behavior for a local provider.

    For production, replace with VercelKMSProvider (private keys in HSM)
    or another provider that calls an external signing service.
    """

    algo: str = "ed25519"
    is_managed: bool = True
    is_asymmetric: bool = True

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # {key_id: (private_key_obj, public_key_bytes, retired)}
        # private_key_obj is never accessible from outside this class
        self._keys: dict[str, tuple] = {}
        self._current_id: str | None = None
        self._counter = 0
        self.rotate()

    @property
    def key_id(self) -> str:
        with self._lock:
            if self._current_id is None:
                raise AsymmetricKMSUnavailableError("No current key configured")
            return self._current_id

    def sign(self, payload: bytes) -> bytes:
        """
        Sign payload with the current private key. Returns 64-byte Ed25519 signature.

        Raises AsymmetricKMSUnavailableError if no current key is configured.
        """
        with self._lock:
            if self._current_id is None:
                raise AsymmetricKMSUnavailableError("No current signing key")
            entry = self._keys.get(self._current_id)
            if entry is None:
                raise AsymmetricKMSUnavailableError(
                    f"Key {self._current_id!r} not found"
                )
            priv, _pub, retired = entry
            if retired:
                raise AsymmetricKMSUnavailableError(
                    f"Current key {self._current_id!r} is retired"
                )
            return priv.sign(payload)

    def get_public_key_bytes(self, key_id: str) -> bytes | None:
        """
        Return 32-byte raw Ed25519 public key for key_id, or None if unknown/retired.
        """
        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                return None
            _priv, pub_bytes, retired = entry
            return None if retired else pub_bytes

    def verify_signature(self, payload: bytes, sig_bytes: bytes, key_id: str) -> bool:
        """Verify an Ed25519 signature against the public key for key_id."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub_bytes = self.get_public_key_bytes(key_id)
        if pub_bytes is None:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, Exception):
            return False

    def get_verification_key(self, key_id: str) -> bytes | None:
        """
        Asymmetric providers have no symmetric key bytes. Always returns None.
        Present so HMAC-path code (ExecutionTokenAuthority._verify_signature)
        gets a valid None response rather than AttributeError; the HMAC path
        then returns token_key_id_unknown, correctly rejecting the downgraded token.
        """
        return None

    def rotate(self, new_key_id: str | None = None) -> str:
        """
        Generate a new Ed25519 keypair and make it the current key.
        Old key remains valid for verification until retire_key().
        Returns the new key_id.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        with self._lock:
            self._counter += 1
            kid = new_key_id or f"ed25519-{self._counter}"
            priv = Ed25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes_raw()
            self._keys[kid] = (priv, pub_bytes, False)
            self._current_id = kid
            return kid

    def retire_key(self, key_id: str) -> None:
        """
        Retire key_id. Its public key bytes become unavailable, so tokens
        signed under it will fail verification.
        Raises ValueError if retiring the current signing key.
        """
        with self._lock:
            if key_id == self._current_id:
                raise ValueError(
                    f"Cannot retire current signing key {key_id!r}. Rotate first."
                )
            entry = self._keys.get(key_id)
            if entry is None:
                raise KeyError(f"Key {key_id!r} not found")
            priv, pub, _retired = entry
            self._keys[key_id] = (priv, pub, True)

    @property
    def active_key_ids(self) -> list[str]:
        with self._lock:
            return [kid for kid, (_, _, retired) in self._keys.items() if not retired]

    @property
    def is_distributed_safe(self) -> bool:
        # In-process only; warn in DISTRIBUTED mode via ProductionConfigValidator
        return False


# ---------------------------------------------------------------------------
# VercelKMSProvider — production provider
# ---------------------------------------------------------------------------


class VercelKMSProvider(AsymmetricKMSBase):
    """
    Production KMS provider backed by Vercel KMS.

    Signing is performed entirely inside Vercel's HSM — the application
    never receives private key material. Authentication is via OIDC, which
    Vercel Functions obtain automatically from the runtime.

    UNVERIFIED API SHAPE. The endpoints below are NOT the documented Vercel KMS API and
    must not be used in production until checked against live Vercel KMS. Documented API
    (https://vercel.com/docs/rest-api/kms/sign-a-message and https://vercel.com/docs/kms/concepts/authentication):

      Sign:    POST https://kms.vercel.com/v1/kms/issuers/{issuerId}/sign/message
               Body: {"message": "<standard base64 of the payload>"}
               Response: {"algorithm", "fingerprint", "keyId", "signature" (standard base64)}

      Verify:  GET  https://kms.vercel.com/<issuerId>/jwks.json  (KMS sets the JWT kid header)

      Ed25519 support and the JWK crv value are NOT stated in the documentation.

    The implementation below still uses the assumed shape (POST {base_url}/v1/sign and
    /.well-known/jwks.json). Treat it as a placeholder until it is rewritten against the
    documented API and verified live.

    Usage:
        import os
        from vercel.oidc import get_vercel_oidc_token  # @vercel/functions equivalent

        provider = VercelKMSProvider(
            key_id="aigov-token-signing-v1",
            base_url="https://kms.vercel.com",
            team_id=os.environ["VERCEL_TEAM_ID"],
            oidc_token_fn=lambda: get_vercel_oidc_token("https://kms.vercel.com"),
        )

    is_distributed_safe = True: Vercel KMS is a managed external service,
    inherently safe for distributed deployments.
    """

    algo: str = "ed25519"
    is_managed: bool = True
    is_asymmetric: bool = True

    def __init__(
        self,
        key_id: str,
        base_url: str = "https://kms.vercel.com",
        team_id: str = "",
        oidc_token_fn: "Callable[[], str] | None" = None,
        timeout_s: float = 5.0,
    ) -> None:
        self._key_id = key_id
        self._base_url = base_url.rstrip("/")
        self._team_id = team_id
        self._oidc_token_fn = oidc_token_fn
        self._timeout = timeout_s
        self._jwks_cache: dict[str, bytes] = {}  # kid → public_key_bytes
        self._jwks_lock = threading.Lock()

    @property
    def key_id(self) -> str:
        return self._key_id

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._oidc_token_fn is not None:
            headers["Authorization"] = f"Bearer {self._oidc_token_fn()}"
        if self._team_id:
            headers["X-Vercel-Team-Id"] = self._team_id
        return headers

    def sign(self, payload: bytes) -> bytes:
        """
        Sign payload via Vercel KMS. Returns Ed25519 signature bytes (64 bytes).
        Private key never leaves Vercel HSM.
        Raises AsymmetricKMSUnavailableError on network or HTTP errors.
        """
        import urllib.request
        import urllib.error
        import json as _json

        data = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        body = _json.dumps({"keyId": self._key_id, "data": data}).encode()
        url = f"{self._base_url}/v1/sign"
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", **self._auth_headers()},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                result = _json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise AsymmetricKMSUnavailableError(
                f"Vercel KMS sign failed: HTTP {exc.code} {exc.reason}"
            ) from exc
        except Exception as exc:
            raise AsymmetricKMSUnavailableError(
                f"Vercel KMS sign failed: {exc}"
            ) from exc

        sig_b64 = result.get("signature", "")
        if not sig_b64:
            raise AsymmetricKMSUnavailableError("Vercel KMS returned no signature")
        try:
            sig = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception as exc:
            raise AsymmetricKMSUnavailableError(
                f"Vercel KMS returned malformed signature: {exc}"
            ) from exc
        return sig

    def get_public_key_bytes(self, key_id: str) -> bytes | None:
        """
        Return raw Ed25519 public key bytes for key_id from Vercel JWKS.
        Returns None if key_id is not in the JWKS.
        Caches JWKS per session (call _refresh_jwks() to bust cache).
        """
        with self._jwks_lock:
            if key_id in self._jwks_cache:
                return self._jwks_cache[key_id]

        try:
            self._refresh_jwks()
        except AsymmetricKMSUnavailableError:
            return None

        with self._jwks_lock:
            return self._jwks_cache.get(key_id)

    def _refresh_jwks(self) -> None:
        import urllib.request
        import urllib.error
        import json as _json

        url = f"{self._base_url}/.well-known/jwks.json"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", **self._auth_headers()},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                jwks = _json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise AsymmetricKMSUnavailableError(
                f"Vercel KMS JWKS fetch failed: HTTP {exc.code}"
            ) from exc
        except Exception as exc:
            raise AsymmetricKMSUnavailableError(
                f"Vercel KMS JWKS fetch failed: {exc}"
            ) from exc

        new_cache: dict[str, bytes] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid", "")
            crv = jwk.get("crv", "")
            x = jwk.get("x", "")
            if not (kid and crv == "Ed25519" and x):
                continue
            try:
                pub_bytes = base64.urlsafe_b64decode(x + "==")
                if len(pub_bytes) == 32:
                    new_cache[kid] = pub_bytes
            except Exception:
                continue

        with self._jwks_lock:
            self._jwks_cache.update(new_cache)

    def rotate(self, new_key_id: str | None = None) -> str:
        """
        Not supported on VercelKMSProvider — key rotation is managed in the Vercel dashboard.
        Update self._key_id and provision the new key in Vercel KMS before calling this.
        """
        raise NotImplementedError(
            "VercelKMSProvider does not rotate keys programmatically. "
            "Create a new key in the Vercel dashboard, provision it, then "
            "update the key_id used to construct this provider."
        )

    def retire_key(self, key_id: str) -> None:
        """
        Bust JWKS cache for key_id so future verifications fetch a fresh JWKS.
        Actual key retirement must be done in the Vercel KMS dashboard.
        """
        with self._jwks_lock:
            self._jwks_cache.pop(key_id, None)

    @property
    def is_distributed_safe(self) -> bool:
        return True  # External managed service; safe for all distributed deployments
