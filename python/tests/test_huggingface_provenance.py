import hashlib
import sys
from types import SimpleNamespace

import pytest

from aigov_py.huggingface_provenance import (
    capture_hub_provenance, manifest_digest, verify_artifact,
)

COMMIT = "a" * 40


@pytest.fixture
def hub(monkeypatch, tmp_path):
    artifact = tmp_path / "weights.bin"
    artifact.write_bytes(b"weights")
    calls = []

    def info(**kwargs):
        calls.append(("info", kwargs))
        return SimpleNamespace(sha=COMMIT, private=True,
                               card_data=SimpleNamespace(license="mit"))

    def download(**kwargs):
        calls.append(("download", kwargs))
        return str(artifact)

    module = SimpleNamespace(HfApi=lambda: SimpleNamespace(repo_info=info),
                             hf_hub_download=download)
    monkeypatch.setitem(sys.modules, "huggingface_hub", module)
    return module, artifact, calls


@pytest.mark.parametrize("repo_type", ["model", "dataset"])
def test_pinned_capture(hub, repo_type):
    _, _, calls = hub
    result = capture_hub_provenance("org/repo", ["weights.bin"],
                                    repo_type=repo_type, token="secret")
    assert result["commit"] == COMMIT
    assert result["source_reported"]["license"] == "mit"
    assert result["artifacts"][0]["sha256"] == hashlib.sha256(b"weights").hexdigest()
    assert calls[-1][1]["revision"] == COMMIT
    assert calls[-1][1]["token"] == "secret"
    assert "secret" not in repr(result)


def test_tampering(hub):
    _, artifact, _ = hub
    result = capture_hub_provenance("org/repo", ["weights.bin"])
    anchor = manifest_digest(result)
    assert verify_artifact(result, "weights.bin", artifact,
                           expected_manifest_sha256=anchor)
    artifact.write_bytes(b"altered")
    assert not verify_artifact(result, "weights.bin", artifact,
                               expected_manifest_sha256=anchor)
    result["artifacts"][0]["sha256"] = hashlib.sha256(b"altered").hexdigest()
    assert not verify_artifact(result, "weights.bin", artifact,
                               expected_manifest_sha256=anchor)


@pytest.mark.parametrize("names", [["../x"], ["/x"], ["a/../x"], ["a", "a"], []])
def test_reject_paths(hub, names):
    with pytest.raises(ValueError):
        capture_hub_provenance("org/repo", names)
    assert not hub[2]


def test_revision_mismatch(hub):
    with pytest.raises(RuntimeError):
        capture_hub_provenance("org/repo", ["weights.bin"], revision="b" * 40)
    assert all(kind != "download" for kind, _ in hub[2])


def test_remote_error_redacted(hub):
    def fail(**kwargs):
        raise ValueError("secret-token")
    hub[0].hf_hub_download = fail
    with pytest.raises(RuntimeError) as error:
        capture_hub_provenance("org/repo", ["weights.bin"], token="secret-token")
    assert "secret-token" not in str(error.value)
    assert error.value.__suppress_context__
