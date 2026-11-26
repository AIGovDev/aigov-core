"""Hash-chained decision log (JSON Lines).

Each line stores a canonical JSON entry, the hash of the previous line, and its own hash.
Any edit, reordering, or deletion of a line breaks verification.

The gate writes an entry before it executes a tool (write-ahead), and a second entry
after the attempt. Verification checks that every sandbox execution is preceded by an
ALLOW entry for the same execution ID.

This log is local evidence for the reference. It is not the AIGov Core ledger, and it is
not anchored anywhere outside this file.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _entry_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + _canonical(body)).hexdigest()


class DecisionLog:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("")

    @property
    def path(self) -> Path:
        return self._path

    def _last_hash(self) -> str:
        last = GENESIS
        if self._path.stat().st_size == 0:
            return last
        for line in self._path.read_text().splitlines():
            last = json.loads(line)["hash"]
        return last

    def append(self, entry: dict[str, Any]) -> str:
        with self._lock:
            prev = self._last_hash()
            body = {"seq": self._count_lines(), "prev_hash": prev, "entry": entry}
            digest = _entry_hash(prev, body)
            record = dict(body, hash=digest)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                fh.flush()
            return digest

    def _count_lines(self) -> int:
        if self._path.stat().st_size == 0:
            return 0
        return sum(1 for _ in self._path.read_text().splitlines())

    def entries(self) -> list[dict[str, Any]]:
        if self._path.stat().st_size == 0:
            return []
        return [
            json.loads(line)["entry"] for line in self._path.read_text().splitlines()
        ]


def verify_chain(path: Path) -> tuple[bool, str]:
    """Return (ok, reason). Recomputes every hash and checks sequence and linkage."""
    p = Path(path)
    if not p.exists():
        return False, "log_missing"
    prev = GENESIS
    lines = [ln for ln in p.read_text().splitlines() if ln.strip()]
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, f"line_{index}_not_json"
        if record.get("seq") != index:
            return False, f"line_{index}_bad_sequence"
        if record.get("prev_hash") != prev:
            return False, f"line_{index}_broken_link"
        body = {
            "seq": record["seq"],
            "prev_hash": record["prev_hash"],
            "entry": record["entry"],
        }
        if _entry_hash(prev, body) != record.get("hash"):
            return False, f"line_{index}_hash_mismatch"
        prev = record["hash"]
    return True, "ok"
