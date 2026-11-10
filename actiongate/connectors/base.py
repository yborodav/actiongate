"""Connector interface: the only code that ever touches a third-party credential."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ConnectorError(Exception):
    pass


@dataclass(frozen=True)
class Operation:
    name: str
    description: str
    read_only: bool
    # JSON Schema for the parameters; exposed to agents as the MCP tool schema.
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})


class Connector(ABC):
    name: str

    @abstractmethod
    def operations(self) -> dict[str, Operation]:
        ...

    @abstractmethod
    def execute(self, operation: str, params: dict[str, Any], idempotency_key: str) -> Any:
        """Run the operation with the stored credential. Must be JSON-serialisable."""

    def inspect(self, operation: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """Optional pre-check for write operations, run before approval.

        Return display context for approvers (at least a "summary" line), or
        None. Raise ConnectorError to reject an action that cannot succeed.
        Must only read from the upstream system, never change it.
        """
        return None

    def validate(self, operation: str, params: dict[str, Any]) -> None:
        """Reject unknown operations and parameters before policy runs."""
        ops = self.operations()
        if operation not in ops:
            raise ConnectorError(f"unknown operation '{self.name}.{operation}'")
        schema = ops[operation].input_schema
        allowed = set(schema.get("properties", {}))
        extra = set(params) - allowed
        if extra:
            raise ConnectorError(f"unexpected parameters: {sorted(extra)}")
        missing = set(schema.get("required", [])) - set(params)
        if missing:
            raise ConnectorError(f"missing required parameters: {sorted(missing)}")
        for pname, pschema in schema.get("properties", {}).items():
            if pname in params:
                _check_type(pname, params[pname], pschema.get("type"))


_PY_TYPES = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _check_type(name: str, value: Any, json_type: str | None) -> None:
    if json_type is None:
        return
    expected = _PY_TYPES.get(json_type)
    if expected is None:
        return
    # bool is a subclass of int; don't accept True as an integer amount.
    if json_type == "integer" and isinstance(value, bool):
        raise ConnectorError(f"parameter '{name}' must be an integer")
    if not isinstance(value, expected):
        raise ConnectorError(f"parameter '{name}' must be of type {json_type}")
