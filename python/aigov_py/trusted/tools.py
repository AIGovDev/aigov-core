"""Customer-defined tools, and the argument digest that binds an approval and an authorization to one exact call.

The digest is part of the security contract. An approval and an execution authorization both carry it, and the
executor recomputes it from the arguments it is about to use. Changing this function changes which calls verify, so it
is covered by golden values in ``python/tests/test_trusted_sdk.py``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_KINDS = ("read", "write")


@dataclass(frozen=True)
class ToolSpec:
    """A tool the agent may call.

    ``action`` is the capability recorded in the binding, for example ``"repo:write"``. ``kind`` is ``"read"`` (Core
    allows it without approval, and the executor still verifies and receipts it) or ``"write"`` (Core requires a
    recorded human approval). ``resource_key`` names the argument that identifies the resource the call touches.
    """

    name: str
    action: str
    kind: str
    resource_key: str = "resource_id"

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("tool name must be a non-empty string")
        if not self.action:
            raise ValueError(f"tool {self.name}: action must be non-empty")
        if self.kind not in _KINDS:
            raise ValueError(
                f"tool {self.name}: kind must be 'read' or 'write', not {self.kind!r}"
            )
        if not self.resource_key:
            raise ValueError(f"tool {self.name}: resource_key must be non-empty")


def tool_registry(tools: Any) -> dict[str, ToolSpec]:
    """Validate a sequence of ToolSpec into a name -> ToolSpec mapping. Names must be unique."""
    registry: dict[str, ToolSpec] = {}
    for spec in tools:
        if not isinstance(spec, ToolSpec):
            raise TypeError("tools must be ToolSpec instances")
        if spec.name in registry:
            raise ValueError(f"duplicate tool name {spec.name!r}")
        registry[spec.name] = spec
    return registry


def resource_id(spec: ToolSpec, arguments: Mapping[str, Any]) -> str:
    """The resource a call touches, read from the argument named by the tool's ``resource_key``."""
    return str(arguments.get(spec.resource_key, ""))


def args_binding_hash(spec: ToolSpec, arguments: Mapping[str, Any]) -> str:
    """SHA-256 over canonical JSON of (tool name, arguments, action, resource). Changing any of them changes the hash."""
    payload = json.dumps(
        {
            "tool_name": spec.name,
            "arguments": dict(arguments),
            "action_type": spec.action,
            "resource_id": resource_id(spec, arguments),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()
