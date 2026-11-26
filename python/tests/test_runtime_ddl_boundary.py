"""Boundary regression: shipped Python packages must not own database schema at runtime.

Schema for the production Rust service is owned by versioned SQL migrations in ``rust/migrations``
(see ``docs/operations/runtime-schema-ownership.md``). The Python agent-verification and OpenAI Agents
SDK stores create tables at runtime, so they live under ``benchmarks/`` and are NOT part of the
release artifact. These tests keep it that way.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHIPPED_PACKAGES = [REPO / "python" / "govai", REPO / "python" / "aigov_py"]
DDL = re.compile(r"\b(CREATE|ALTER|DROP)\s+(TABLE|INDEX)\b", re.IGNORECASE)
SCHEMA_STORE_MODULES = {
    "nonce_store",
    "revocation_list",
    "sql_audit_store",
    "sql_key_store",
    "sql_approval_registry",
    "document_store",
}


def _python_files(root: Path):
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_shipped_packages_contain_no_ddl():
    offenders = []
    for root in SHIPPED_PACKAGES:
        assert root.is_dir(), f"missing package directory {root}"
        for path in _python_files(root):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if DDL.search(line):
                    offenders.append(f"{path.relative_to(REPO)}:{lineno}: {line.strip()[:120]}")
    assert not offenders, "DDL found in shipped packages:\n" + "\n".join(offenders)


def test_shipped_packages_do_not_import_schema_store_modules():
    offenders = []
    pattern = re.compile(r"^\s*(from|import)\s+([\w.]+)", re.MULTILINE)
    for root in SHIPPED_PACKAGES:
        for path in _python_files(root):
            text = path.read_text(encoding="utf-8")
            for match in pattern.finditer(text):
                module = match.group(2).split(".")[-1]
                if module in SCHEMA_STORE_MODULES:
                    offenders.append(f"{path.relative_to(REPO)} imports {match.group(2)}")
    assert not offenders, "shipped code imports benchmark schema stores:\n" + "\n".join(offenders)
