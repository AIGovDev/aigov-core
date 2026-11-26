"""Capture selected Hugging Face Hub artifacts at an immutable revision.

Local digests describe downloaded bytes, not publisher authenticity.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Sequence

_REVISION = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)?")


def _digest(path: str | Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def capture_hub_provenance(
    repo_id: str,
    filenames: Sequence[str],
    *,
    repo_type: str = "model",
    revision: str = "main",
    token: str | bool | None = None,
) -> dict[str, Any]:
    """Capture selected files; never execute model or dataset code.

    Install huggingface_hub separately. Token is passed only to Hub calls.
    Raw remote exceptions are suppressed to avoid exposing credentials.
    """
    if repo_type not in {"model", "dataset"} or not _REPO.fullmatch(repo_id):
        raise ValueError("Invalid Hub repository")
    if isinstance(filenames, str) or not filenames:
        raise ValueError("Explicit artifact filenames required")
    names = list(filenames)
    for name in names:
        if (
            not isinstance(name, str)
            or "\\" in name
            or any(ord(c) < 32 for c in name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
        ):
            raise ValueError("Invalid artifact filename")
    if len(set(names)) != len(names):
        raise ValueError("Duplicate artifact filename")

    from huggingface_hub import HfApi, hf_hub_download

    try:
        info = HfApi().repo_info(
            repo_id=repo_id, repo_type=repo_type, revision=revision, token=token
        )
        commit = info.sha
        if not isinstance(commit, str) or not _REVISION.fullmatch(commit):
            raise ValueError("Invalid resolved revision")
        if _REVISION.fullmatch(revision) and revision != commit:
            raise ValueError("Resolved revision mismatch")
        pinned = HfApi().repo_info(
            repo_id=repo_id, repo_type=repo_type, revision=commit, token=token
        )
        if pinned.sha != commit:
            raise ValueError("Pinned revision mismatch")
        artifacts = []
        for name in sorted(names):
            path = hf_hub_download(
                repo_id=repo_id, repo_type=repo_type, revision=commit,
                filename=name, token=token,
            )
            digest, size = _digest(path)
            artifacts.append({"path": name, "sha256": digest, "size_bytes": size})
    except Exception:
        raise RuntimeError("Hub provenance capture failed") from None

    return {
        "schema": "aigov.huggingface.provenance.v1",
        "repo_id": repo_id,
        "repo_type": repo_type,
        "commit": commit,
        "source_reported": {"private": getattr(pinned, "private", None)},
        "artifact_verification": "locally_hashed_selected_files",
        "artifacts": artifacts,
    }
