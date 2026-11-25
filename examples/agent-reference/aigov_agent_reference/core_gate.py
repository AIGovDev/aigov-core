"""The reference's view of the Core client. The implementation is the SDK's (``aigov_py.trusted.core``).

This module keeps the reference's names and its default labels: events the reference submits say
``agent-reference``. Its decision mapping and HTTP behaviour are the SDK's, unchanged.
"""

from __future__ import annotations

from typing import Any

from aigov_py.runtime.models import EvidenceEvent
from aigov_py.trusted.core import (
    REASON_RE,
    REQUIRE_APPROVAL_REASONS,
    CoreDecision,
    Decision,
    _error,
    _reason_from_refusal,
    utc_now_rfc3339,
)
from aigov_py.trusted.core import CoreClient as _SDKCoreClient
from aigov_py.trusted.core import new_event as _sdk_new_event

REFERENCE_ACTOR = "agent-reference"
REFERENCE_SYSTEM = "aigov-agent-reference"

__all__ = [
    "REASON_RE",
    "REQUIRE_APPROVAL_REASONS",
    "CoreClient",
    "CoreDecision",
    "Decision",
    "_error",
    "_reason_from_refusal",
    "new_event",
    "utc_now_rfc3339",
]


class CoreClient(_SDKCoreClient):
    """The SDK client, with the reference's default labels."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout_sec: float = 10.0,
        actor: str = REFERENCE_ACTOR,
        system: str = REFERENCE_SYSTEM,
    ) -> None:
        super().__init__(
            base_url, api_key, timeout_sec=timeout_sec, actor=actor, system=system
        )


def new_event(
    event_type: str,
    run_id: str,
    payload: dict[str, Any],
    *,
    ts_utc: str | None = None,
    event_id: str | None = None,
) -> EvidenceEvent:
    return _sdk_new_event(
        event_type,
        run_id,
        payload,
        ts_utc=ts_utc,
        event_id=event_id,
        actor=REFERENCE_ACTOR,
        system=REFERENCE_SYSTEM,
    )
