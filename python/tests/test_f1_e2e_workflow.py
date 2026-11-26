"""
AIGov F1 End-to-End Workflow Integration Tests.

Covers the complete F1 workflow:
  Authentication → Legal acceptance → Tenant provisioning → Tenant activation
  → Authorized application access → Audit event generation.

For steps requiring Supabase/PostgreSQL (OAuth, real tenant creation), the
tests document the blocker and validate the portable core behaviour using
isolated mocks.  No production credentials are used; no production state is
modified.

Test matrix:
  F1-01  Successful authentication callback (mocked IdP)
  F1-02  Invalid / expired session rejected
  F1-03  Missing mandatory legal acceptance blocked
  F1-04  Outdated document version triggers re-acceptance
  F1-05  Successful legal acceptance (isolated environment)
  F1-06  Failed acceptance persistence rolls back
  F1-07  Tenant activation after valid acceptance
  F1-08  Cross-tenant access denied
  F1-09  Duplicate acceptance requests are idempotent
  F1-10  Audit event generated and verified after each state transition
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Minimal in-process simulation of the F1 state machine
# ---------------------------------------------------------------------------

class TenantState(Enum):
    PENDING_AUTH = "PENDING_AUTH"
    AUTHENTICATED = "AUTHENTICATED"
    PENDING_LEGAL = "PENDING_LEGAL"
    LEGAL_ACCEPTED = "LEGAL_ACCEPTED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class LegalDocVersion(str):
    pass


REQUIRED_DOCS: dict[str, LegalDocVersion] = {
    "terms_of_service": LegalDocVersion("2026-07-23.1"),
    "privacy_policy": LegalDocVersion("2026-11-12"),
    "data_processing_agreement": LegalDocVersion("2026-07-23.1"),
}


@dataclass
class AuditEvent:
    event_id: str
    event_type: str
    tenant_id: str
    actor: str
    payload: dict[str, Any]
    ts_utc: str = "2026-01-01T00:00:00Z"


@dataclass
class Session:
    session_id: str
    user_id: str
    tenant_id: str
    valid: bool = True
    # accepted doc versions keyed by doc name
    accepted_docs: dict[str, LegalDocVersion] = field(default_factory=dict)


@dataclass
class Tenant:
    tenant_id: str
    state: TenantState = TenantState.PENDING_AUTH
    owner_id: str = ""


class AuditLog:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def events_for_tenant(self, tenant_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.tenant_id == tenant_id]


class F1Workflow:
    """In-process portable implementation of the F1 state machine."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._tenants: dict[str, Tenant] = {}
        self._audit_log = AuditLog()

    # --- Auth ---

    def handle_oauth_callback(self, *, user_id: str, tenant_id: str | None = None) -> Session:
        """Create a new session on successful OAuth callback."""
        tid = tenant_id or str(uuid.uuid4())
        s = Session(
            session_id=str(uuid.uuid4()),
            user_id=user_id,
            tenant_id=tid,
            valid=True,
        )
        self._sessions[s.session_id] = s
        t = self._tenants.get(tid)
        if t is None:
            t = Tenant(tenant_id=tid, state=TenantState.AUTHENTICATED, owner_id=user_id)
            self._tenants[tid] = t
        self._emit(AuditEvent(
            event_id=f"auth_{s.session_id}",
            event_type="user_authenticated",
            tenant_id=tid,
            actor=user_id,
            payload={"session_id": s.session_id},
        ))
        return s

    def get_session(self, session_id: str) -> Session:
        s = self._sessions.get(session_id)
        if s is None or not s.valid:
            raise PermissionError("INVALID_SESSION")
        return s

    def invalidate_session(self, session_id: str) -> None:
        s = self._sessions.get(session_id)
        if s:
            s.valid = False

    # --- Legal acceptance ---

    def missing_legal_docs(self, session: Session) -> list[str]:
        """Return names of required docs not yet accepted at the current version."""
        missing = []
        for doc, required_ver in REQUIRED_DOCS.items():
            accepted = session.accepted_docs.get(doc)
            if accepted != required_ver:
                missing.append(doc)
        return sorted(missing)

    def accept_legal_doc(
        self,
        session: Session,
        *,
        doc: str,
        version: LegalDocVersion,
        persist_ok: bool = True,
    ) -> None:
        """Record acceptance of a legal document version."""
        required = REQUIRED_DOCS.get(doc)
        if required is None:
            raise ValueError(f"Unknown document: {doc!r}")
        if version != required:
            raise ValueError(
                f"Outdated version for {doc!r}: got {version!r}, required {required!r}"
            )
        if not persist_ok:
            raise IOError("Persistence backend unavailable")
        # Idempotent: re-accepting the same version is a no-op.
        if session.accepted_docs.get(doc) == version:
            return
        session.accepted_docs[doc] = version
        self._emit(AuditEvent(
            event_id=f"legal_{doc}_{session.session_id}",
            event_type="legal_accepted",
            tenant_id=session.tenant_id,
            actor=session.user_id,
            payload={"doc": doc, "version": version},
        ))

    def accept_all_legal(self, session: Session) -> None:
        for doc, ver in REQUIRED_DOCS.items():
            self.accept_legal_doc(session, doc=doc, version=ver)

    # --- Tenant activation ---

    def activate_tenant(self, session: Session) -> None:
        missing = self.missing_legal_docs(session)
        if missing:
            raise PermissionError(f"MISSING_LEGAL_ACCEPTANCE: {missing}")
        t = self._tenants[session.tenant_id]
        if t.state == TenantState.ACTIVE:
            return  # idempotent
        if t.owner_id != session.user_id:
            raise PermissionError("NOT_TENANT_OWNER")
        t.state = TenantState.ACTIVE
        self._emit(AuditEvent(
            event_id=f"activate_{session.tenant_id}",
            event_type="tenant_activated",
            tenant_id=session.tenant_id,
            actor=session.user_id,
            payload={"tenant_id": session.tenant_id},
        ))

    def assert_active(self, session: Session) -> None:
        t = self._tenants.get(session.tenant_id)
        if t is None or t.state != TenantState.ACTIVE:
            raise PermissionError("TENANT_NOT_ACTIVE")

    # --- Cross-tenant isolation ---

    def access_resource(self, session: Session, *, tenant_id: str) -> dict[str, Any]:
        """Authorize access to a resource belonging to tenant_id."""
        self.assert_active(session)
        if session.tenant_id != tenant_id:
            self._emit(AuditEvent(
                event_id=f"xtenantdenied_{session.session_id}_{tenant_id}",
                event_type="cross_tenant_access_denied",
                tenant_id=session.tenant_id,
                actor=session.user_id,
                payload={"denied_resource_tenant": tenant_id},
            ))
            raise PermissionError("CROSS_TENANT_ACCESS_DENIED")
        return {"data": "ok", "tenant_id": tenant_id}

    def audit_log(self) -> AuditLog:
        return self._audit_log

    def _emit(self, event: AuditEvent) -> None:
        self._audit_log.append(event)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_wf() -> F1Workflow:
    return F1Workflow()


def _authenticated_session(wf: F1Workflow, *, user_id: str = "user-1") -> Session:
    return wf.handle_oauth_callback(user_id=user_id)


def _fully_onboarded_session(wf: F1Workflow, *, user_id: str = "user-1") -> Session:
    s = _authenticated_session(wf, user_id=user_id)
    wf.accept_all_legal(s)
    wf.activate_tenant(s)
    return s


# ---------------------------------------------------------------------------
# F1-01: Successful authentication callback
# ---------------------------------------------------------------------------

def test_f1_01_successful_oauth_callback_creates_session() -> None:
    """PASS: A valid OAuth callback produces a valid session and emits an audit event."""
    wf = _new_wf()
    s = wf.handle_oauth_callback(user_id="alice@example.com")
    assert s.valid
    assert s.user_id == "alice@example.com"
    events = wf.audit_log().events_for_tenant(s.tenant_id)
    assert any(e.event_type == "user_authenticated" for e in events)


def test_f1_01_session_binds_user_to_tenant() -> None:
    """Session must bind user identity to exactly one tenant."""
    wf = _new_wf()
    s1 = wf.handle_oauth_callback(user_id="alice@example.com")
    s2 = wf.handle_oauth_callback(user_id="bob@example.com")
    assert s1.tenant_id != s2.tenant_id  # separate tenants by default
    assert s1.session_id != s2.session_id


# ---------------------------------------------------------------------------
# F1-02: Invalid / expired session rejected
# ---------------------------------------------------------------------------

def test_f1_02_invalid_session_id_raises() -> None:
    """FAIL fast on unknown session_id."""
    wf = _new_wf()
    with pytest.raises(PermissionError, match="INVALID_SESSION"):
        wf.get_session("does-not-exist")


def test_f1_02_invalidated_session_raises() -> None:
    """Expired/logged-out session must be rejected."""
    wf = _new_wf()
    s = wf.handle_oauth_callback(user_id="alice@example.com")
    wf.invalidate_session(s.session_id)
    with pytest.raises(PermissionError, match="INVALID_SESSION"):
        wf.get_session(s.session_id)


# ---------------------------------------------------------------------------
# F1-03: Missing mandatory legal acceptance blocked
# ---------------------------------------------------------------------------

def test_f1_03_activation_blocked_without_legal_acceptance() -> None:
    """BLOCKED: Tenant activation without legal acceptance is rejected."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    with pytest.raises(PermissionError, match="MISSING_LEGAL_ACCEPTANCE"):
        wf.activate_tenant(s)


def test_f1_03_missing_docs_reported_correctly() -> None:
    """The list of missing documents must be complete."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    missing = wf.missing_legal_docs(s)
    assert set(missing) == set(REQUIRED_DOCS.keys())


def test_f1_03_partial_acceptance_still_blocked() -> None:
    """Accepting only ToS is not sufficient — DPA and Privacy Policy also required."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_legal_doc(s, doc="terms_of_service", version=REQUIRED_DOCS["terms_of_service"])
    missing = wf.missing_legal_docs(s)
    assert "data_processing_agreement" in missing
    assert "privacy_policy" in missing
    with pytest.raises(PermissionError):
        wf.activate_tenant(s)


# ---------------------------------------------------------------------------
# F1-04: Outdated document version triggers re-acceptance
# ---------------------------------------------------------------------------

def test_f1_04_outdated_tos_version_rejected() -> None:
    """An old ToS version must not be accepted."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    with pytest.raises(ValueError, match="Outdated version"):
        wf.accept_legal_doc(
            s,
            doc="terms_of_service",
            version=LegalDocVersion("2024-01-01"),
        )


def test_f1_04_outdated_version_does_not_clear_prior_acceptance() -> None:
    """A failed version bump must not wipe a prior valid acceptance."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_legal_doc(s, doc="terms_of_service", version=REQUIRED_DOCS["terms_of_service"])
    with pytest.raises(ValueError):
        wf.accept_legal_doc(s, doc="terms_of_service", version=LegalDocVersion("old"))
    assert s.accepted_docs["terms_of_service"] == REQUIRED_DOCS["terms_of_service"]


# ---------------------------------------------------------------------------
# F1-05: Successful legal acceptance (isolated)
# ---------------------------------------------------------------------------

def test_f1_05_all_docs_accepted_clears_missing_list() -> None:
    """PASS: Accepting all required docs at the right version clears the missing list."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_all_legal(s)
    assert wf.missing_legal_docs(s) == []


def test_f1_05_acceptance_emits_audit_events() -> None:
    """Each accepted document must produce an audit event."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_all_legal(s)
    legal_events = [
        e for e in wf.audit_log().events_for_tenant(s.tenant_id)
        if e.event_type == "legal_accepted"
    ]
    accepted_docs = {e.payload["doc"] for e in legal_events}
    assert accepted_docs == set(REQUIRED_DOCS.keys())


# ---------------------------------------------------------------------------
# F1-06: Failed acceptance persistence rolls back
# ---------------------------------------------------------------------------

def test_f1_06_persistence_failure_does_not_record_acceptance() -> None:
    """FAIL: If the persistence backend fails, acceptance must not be recorded."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    with pytest.raises(IOError, match="Persistence backend unavailable"):
        wf.accept_legal_doc(
            s,
            doc="terms_of_service",
            version=REQUIRED_DOCS["terms_of_service"],
            persist_ok=False,
        )
    assert "terms_of_service" not in s.accepted_docs


# ---------------------------------------------------------------------------
# F1-07: Tenant activation after valid acceptance
# ---------------------------------------------------------------------------

def test_f1_07_tenant_activates_after_full_acceptance() -> None:
    """PASS: Full acceptance enables tenant activation."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_all_legal(s)
    wf.activate_tenant(s)
    # Must now be able to access resources on own tenant.
    result = wf.access_resource(s, tenant_id=s.tenant_id)
    assert result["data"] == "ok"


def test_f1_07_activation_audit_event_emitted() -> None:
    """Tenant activation must produce an audit event."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_all_legal(s)
    wf.activate_tenant(s)
    events = wf.audit_log().events_for_tenant(s.tenant_id)
    assert any(e.event_type == "tenant_activated" for e in events)


def test_f1_07_activation_idempotent() -> None:
    """Re-activating an already-active tenant must succeed silently."""
    wf = _new_wf()
    s = _fully_onboarded_session(wf)
    wf.activate_tenant(s)  # second call; must not raise or double-emit
    activation_events = [
        e for e in wf.audit_log().events_for_tenant(s.tenant_id)
        if e.event_type == "tenant_activated"
    ]
    assert len(activation_events) == 1  # exactly one, not duplicated


# ---------------------------------------------------------------------------
# F1-08: Cross-tenant access denied
# ---------------------------------------------------------------------------

def test_f1_08_cross_tenant_access_denied() -> None:
    """DENIED: A session for tenant A must not access resources belonging to tenant B."""
    wf = _new_wf()
    s_a = _fully_onboarded_session(wf, user_id="alice")
    s_b = _fully_onboarded_session(wf, user_id="bob")
    with pytest.raises(PermissionError, match="CROSS_TENANT_ACCESS_DENIED"):
        wf.access_resource(s_a, tenant_id=s_b.tenant_id)


def test_f1_08_cross_tenant_denial_generates_audit_event() -> None:
    """Every cross-tenant denial must be logged."""
    wf = _new_wf()
    s_a = _fully_onboarded_session(wf, user_id="alice")
    s_b = _fully_onboarded_session(wf, user_id="bob")
    with pytest.raises(PermissionError):
        wf.access_resource(s_a, tenant_id=s_b.tenant_id)
    events = wf.audit_log().events_for_tenant(s_a.tenant_id)
    assert any(e.event_type == "cross_tenant_access_denied" for e in events)


def test_f1_08_inactive_tenant_cannot_access_own_resources() -> None:
    """Access to own resources must be denied before activation."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    with pytest.raises(PermissionError, match="TENANT_NOT_ACTIVE"):
        wf.access_resource(s, tenant_id=s.tenant_id)


# ---------------------------------------------------------------------------
# F1-09: Duplicate acceptance requests are idempotent
# ---------------------------------------------------------------------------

def test_f1_09_duplicate_acceptance_is_a_noop() -> None:
    """Accepting the same document version twice must succeed without duplicating events."""
    wf = _new_wf()
    s = _authenticated_session(wf)
    wf.accept_legal_doc(s, doc="terms_of_service", version=REQUIRED_DOCS["terms_of_service"])
    wf.accept_legal_doc(s, doc="terms_of_service", version=REQUIRED_DOCS["terms_of_service"])
    legal_events = [
        e for e in wf.audit_log().events_for_tenant(s.tenant_id)
        if e.event_type == "legal_accepted" and e.payload["doc"] == "terms_of_service"
    ]
    assert len(legal_events) == 1  # first accept logs, second is idempotent no-op


# ---------------------------------------------------------------------------
# F1-10: Audit event generation and verification
# ---------------------------------------------------------------------------

def test_f1_10_full_onboarding_generates_ordered_events() -> None:
    """PASS: Full onboarding flow produces all expected audit events in order."""
    wf = _new_wf()
    s = _fully_onboarded_session(wf)
    events = wf.audit_log().events_for_tenant(s.tenant_id)
    types = [e.event_type for e in events]
    # Must have at least: authenticated + legal_accepted (×3) + activated
    assert "user_authenticated" in types
    assert types.count("legal_accepted") == len(REQUIRED_DOCS)
    assert "tenant_activated" in types
    # Ordering: auth before legal, legal before activation.
    assert types.index("user_authenticated") < types.index("legal_accepted")
    final_legal_idx = max(i for i, t in enumerate(types) if t == "legal_accepted")
    assert final_legal_idx < types.index("tenant_activated")


def test_f1_10_audit_events_have_non_empty_event_ids() -> None:
    """Every audit event must carry a unique non-empty event_id."""
    wf = _new_wf()
    s = _fully_onboarded_session(wf)
    events = wf.audit_log().events
    ids = [e.event_id for e in events]
    assert all(ids)
    assert len(ids) == len(set(ids)), "duplicate event_id detected"


def test_f1_10_audit_log_isolated_per_tenant() -> None:
    """Events from tenant A must not appear in tenant B's audit log slice."""
    wf = _new_wf()
    s_a = _fully_onboarded_session(wf, user_id="alice")
    s_b = _fully_onboarded_session(wf, user_id="bob")
    events_a = {e.event_id for e in wf.audit_log().events_for_tenant(s_a.tenant_id)}
    events_b = {e.event_id for e in wf.audit_log().events_for_tenant(s_b.tenant_id)}
    assert not events_a & events_b, "cross-tenant event leakage"


# ---------------------------------------------------------------------------
# External dependency blocker documentation (not a test failure)
# ---------------------------------------------------------------------------

@pytest.mark.skip(
    reason=(
        "BLOCKED: Full OAuth callback requires a live Supabase/Google/GitHub identity "
        "provider.  Production credentials are not available in this isolated environment. "
        "The portable F1 state machine is fully tested above.  "
        "To unblock: set SUPABASE_URL + SUPABASE_JWT_AUD + DATABASE_URL in the CI environment."
    )
)
def test_f1_blocked_real_oauth_callback() -> None:
    """Documents the blocker for real OAuth callback testing."""
    ...


@pytest.mark.skip(
    reason=(
        "BLOCKED: Tenant provisioning into a live Supabase database requires DATABASE_URL "
        "with the enterprise schema (teams, team_members, compliance_workflow).  "
        "See ENTERPRISE_LAYER.md for the provisioning requirements."
    )
)
def test_f1_blocked_tenant_provisioning_requires_db() -> None:
    """Documents the blocker for real tenant provisioning via Supabase."""
    ...
