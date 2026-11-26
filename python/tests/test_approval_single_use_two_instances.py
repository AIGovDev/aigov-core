"""Single use of an approval across two Core processes that share one ledger directory.

Two instances receive a consequential call naming the same approval at the same time. Exactly one may be authorized.
The other must be refused, and the ledger must hold exactly one consequential record and verify.
"""

from __future__ import annotations

import json
import tempfile
import threading
import uuid
from pathlib import Path

import pytest

from test_crash_consistency_core import _append_injected, _approval, _consequential, _drop_sidecars, _records, _verify_chain
from test_receipt_provenance_core import AGENT, Node


@pytest.mark.parametrize("rounds", [5])
def test_one_approval_authorizes_at_most_once_across_two_processes(rounds):
    for _ in range(rounds):
        with tempfile.TemporaryDirectory(prefix="approval-2i-") as d:
            ledger = Path(d) / "ledger"
            ledger.mkdir()
            approval_id = f"human_approved-{uuid.uuid4().hex}"
            tool_call_id = f"call-{uuid.uuid4().hex[:8]}"
            _append_injected(ledger, _approval(approval_id, tool_call_id))
            _drop_sidecars(ledger)
            a = Node(ledger, principals=True)
            b = Node(ledger, principals=True)
            try:
                results: dict[str, tuple[int, dict]] = {}
                barrier = threading.Barrier(2)

                def fire(name: str, node: Node) -> None:
                    barrier.wait()
                    results[name] = node.post(AGENT, _consequential(f"call-{uuid.uuid4().hex}", tool_call_id, approval_id))

                ta = threading.Thread(target=fire, args=("a", a))
                tb = threading.Thread(target=fire, args=("b", b))
                ta.start(); tb.start(); ta.join(60); tb.join(60)
            finally:
                a.close()
                b.close()
            authorized = [k for k, (s, body) in results.items() if s == 200 and body.get("execution_authorization")]
            refused = [k for k, (s, body) in results.items() if not (s == 200 and body.get("execution_authorization"))]
            assert len(authorized) == 1, f"expected exactly one authorization, got {results}"
            assert len(refused) == 1
            _s, body = results[refused[0]]
            assert "approval_already_consumed" in json.dumps(body), body
            consequential = [r for r in _records(ledger) if "consequential_tool_call" in r["event_json"]]
            assert len(consequential) == 1, f"approval consumed more than once: {len(consequential)} records"
            _verify_chain(ledger)
