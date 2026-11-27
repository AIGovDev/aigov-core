from types import SimpleNamespace

import pytest

from aigov_py.huggingface_transformers import (
    capture_transformers_configuration, transformers_configuration_digest,
)


def model():
    return SimpleNamespace(
        config=SimpleNamespace(model_type="gpt2", hidden_size=32, token="secret"),
        generation_config=SimpleNamespace(max_new_tokens=8, do_sample=False, prompt="secret"),
    )


def test_allowlist_and_digest():
    m = model()
    snapshot = capture_transformers_configuration(m, transformers_version="4.50.0")
    assert snapshot["model"]["hidden_size"] == 32
    assert "secret" not in repr(snapshot)
    before = transformers_configuration_digest(m, transformers_version="4.50.0")
    m.generation_config.max_new_tokens = 9
    assert before != transformers_configuration_digest(m, transformers_version="4.50.0")


def test_nonfinite():
    m = model()
    m.generation_config.temperature = float("nan")
    with pytest.raises(ValueError):
        capture_transformers_configuration(m, transformers_version="4.50.0")


def test_no_generation_config():
    m = model()
    del m.generation_config
    assert capture_transformers_configuration(m, transformers_version="4.50.0")["generation"] is None
