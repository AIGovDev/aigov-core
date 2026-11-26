"""Cross-language check (Python side): the committed v2 fixture, written by the Python writer, must verify here and match
``expected.json``. The Rust reader verifies the same files (``key_registry::tests``). Rust does not write registries, so the
compatibility claim is: Python writes, and both readers verify.

Regenerate the fixture with ``python python/tests/_registry_fixture.py rust/tests/fixtures/key_registry_v2``.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from aigov_py.trusted import keys as K
from _sqlite_anchor import SqliteAnchor
from aigov_py.trusted.registry_anchor import AnchorState

FIXTURE = Path(__file__).resolve().parents[2] / "rust" / "tests" / "fixtures" / "key_registry_v2"


@pytest.fixture
def fixture_copy():
    with tempfile.TemporaryDirectory(prefix="registry-fixture-py-") as d:
        root = Path(d)
        shutil.copy(FIXTURE / "registry.json.events.jsonl", root / "registry.json.events.jsonl")
        shutil.copy(FIXTURE / "trust.json", root / "trust.json")
        # Git does not keep file modes, so the copy is made owner-only the way a deployed trust file is.
        os.chmod(root / "trust.json", 0o600)
        anchored = json.loads((FIXTURE / "anchor.json").read_text())
        anchor = SqliteAnchor(root / "anchor.sqlite", "fixture-registry")
        anchor.init()
        with anchor.exclusive() as tx:
            tx.set(AnchorState(anchored["seq"], anchored["head_hash"]), expected=tx.current())
        yield root, K.TrustConfig.load(root / "trust.json"), anchor


def test_the_python_reader_verifies_the_fixture_and_matches_expected(fixture_copy):
    root, trust, anchor = fixture_copy
    reg = K.KeyRegistry(root / "registry.json", trust=trust, anchor=anchor)
    expected = json.loads((FIXTURE / "expected.json").read_text())
    assert reg.version == expected["version"]
    assert reg.events[-1]["hash"] == expected["head_hash"]
    assert {kid: rec.status for kid, rec in reg.state.keys.items()} == expected["statuses"]
    assert reg.active_for("execution_authorization").kid == expected["active_execution_key"]
    assert {k: v["status"] for k, v in reg.state.operators.items()} == expected["operators"]


def _write_events(root: Path, events: list[dict]) -> None:
    (root / "registry.json.events.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events))


def test_altered_fixture_event_is_refused_by_the_python_reader(fixture_copy):
    root, trust, anchor = fixture_copy
    events = [json.loads(line) for line in (root / "registry.json.events.jsonl").read_text().splitlines()]
    events[3]["request"]["payload"]["kid"] = "exe-x"
    _write_events(root, events)
    with pytest.raises(K.KeyRegistryError) as exc:
        K.KeyRegistry(root / "registry.json", trust=trust, anchor=anchor)
    assert exc.value.code in ("event_altered", "request_signature_invalid")


def test_removed_fixture_event_is_refused_by_the_python_reader(fixture_copy):
    root, trust, anchor = fixture_copy
    events = [json.loads(line) for line in (root / "registry.json.events.jsonl").read_text().splitlines()]
    del events[4]
    _write_events(root, events)
    with pytest.raises(K.KeyRegistryError) as exc:
        K.KeyRegistry(root / "registry.json", trust=trust, anchor=anchor)
    assert exc.value.code in ("event_sequence_broken", "event_chain_broken", "anchor_log_behind")
