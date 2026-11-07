"""Canonical JSON and action hashing.

What the approver sees is what runs: the hash covers the connector,
operation, every parameter, the agent and the on-behalf-of user.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import Action


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8.

    Floats are rejected because their text form is not stable across
    platforms; money amounts must be integers in minor units (cents).
    """
    _reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floats are not allowed in actions; use integer minor units")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def action_hash(action: Action) -> str:
    payload = canonical_json(action.to_dict())
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
