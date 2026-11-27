"""Capture allowlisted Transformers configuration, not execution evidence."""
from __future__ import annotations

import math
from typing import Any

from .huggingface_provenance import manifest_digest

_MODEL_FIELDS = ("model_type", "vocab_size", "hidden_size", "num_hidden_layers",
                 "num_attention_heads", "is_encoder_decoder")
_GENERATION_FIELDS = ("max_new_tokens", "do_sample", "temperature", "top_p",
                      "top_k", "num_beams", "repetition_penalty")


def _select(config: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    result = {}
    for key in fields:
        value = getattr(config, key, None)
        if value is None or type(value) in (bool, int):
            result[key] = value
        elif type(value) is float and math.isfinite(value):
            result[key] = value
        elif key == "model_type" and type(value) is str and value.isascii() and value.replace("_", "").replace("-", "").isalnum() and len(value) <= 80:
            result[key] = value
        else:
            raise ValueError("Unsupported configuration value")
    return result


def capture_transformers_configuration(
    model: Any, *, transformers_version: str,
) -> dict[str, Any]:
    """Snapshot selected attributes of an already loaded model.

    Does not load weights, execute inference or capture call-time overrides.
    """
    if not isinstance(transformers_version, str) or not transformers_version or len(transformers_version) > 80 or not all(c.isascii() and (c.isalnum() or c in ".+-_") for c in transformers_version):
        raise ValueError("Invalid Transformers version")
    config = getattr(model, "config", None)
    if config is None:
        raise ValueError("Missing model configuration")
    generation = getattr(model, "generation_config", None)
    return {
        "schema": "aigov.huggingface.transformers.configuration.v1",
        "transformers_version": transformers_version,
        "model": _select(config, _MODEL_FIELDS),
        "generation": None if generation is None else _select(generation, _GENERATION_FIELDS),
        "measurement": "selected_configuration_snapshot",
    }


def transformers_configuration_digest(model: Any, *, transformers_version: str) -> str:
    return manifest_digest(capture_transformers_configuration(
        model, transformers_version=transformers_version))
