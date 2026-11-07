"""Generic HTTP connector for a company's internal APIs, configured in YAML.

Example config:

    connectors:
      - type: http
        name: billing
        base_url: https://billing.internal.example.com
        auth: {type: bearer, secret: billing_api_token}
        operations:
          issue_credit:
            method: POST
            path: /accounts/{account_id}/credits
            read_only: false
            description: Issue an account credit in cents.
            params:
              account_id: {type: string, in: path, required: true}
              amount: {type: integer, in: body, required: true}
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import quote

import requests

from .base import Connector, ConnectorError, Operation

_PATH_VAR = re.compile(r"{(\w+)}")


class HttpConnector(Connector):
    def __init__(self, name: str, base_url: str, operations: dict[str, dict[str, Any]],
                 secret_lookup: Callable[[], str] | None = None, auth_type: str = "bearer",
                 auth_header: str = "Authorization", session: requests.Session | None = None, timeout: float = 20.0):
        if not base_url.startswith("https://") and not base_url.startswith("http://localhost"):
            raise ConnectorError(f"connector {name}: base_url must use https")
        self.name = name
        self._base = base_url.rstrip("/")
        self._ops_cfg = operations
        self._secret = secret_lookup
        self._auth_type = auth_type
        self._auth_header = auth_header
        self._http = session or requests.Session()
        self._timeout = timeout
        self._ops = self._build_ops()

    def _build_ops(self) -> dict[str, Operation]:
        ops = {}
        for op_name, cfg in self._ops_cfg.items():
            method = cfg.get("method", "GET").upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                raise ConnectorError(f"{self.name}.{op_name}: unsupported method {method}")
            props, required = {}, []
            for pname, pcfg in (cfg.get("params") or {}).items():
                if pcfg.get("in", "body") not in {"path", "query", "body"}:
                    raise ConnectorError(f"{self.name}.{op_name}.{pname}: 'in' must be path, query or body")
                props[pname] = {k: v for k, v in pcfg.items() if k in {"type", "description"}}
                if pcfg.get("required"):
                    required.append(pname)
            for var in _PATH_VAR.findall(cfg["path"]):
                if var not in props:
                    raise ConnectorError(f"{self.name}.{op_name}: path variable '{var}' has no param")
            # Writes default to non-read-only: forgetting the flag must never skip policy.
            read_only = bool(cfg.get("read_only", False)) and method == "GET"
            schema = {"type": "object", "properties": props}
            if required:
                schema["required"] = required
            ops[op_name] = Operation(op_name, cfg.get("description", ""), read_only, schema)
        return ops

    def operations(self) -> dict[str, Operation]:
        return self._ops

    def execute(self, operation: str, params: dict[str, Any], idempotency_key: str) -> Any:
        cfg = self._ops_cfg.get(operation)
        if cfg is None:
            raise ConnectorError(f"unknown operation '{operation}'")
        pcfg = cfg.get("params") or {}
        path = cfg["path"]
        for var in _PATH_VAR.findall(path):
            path = path.replace("{" + var + "}", quote(str(params[var]), safe=""))
        query = {k: v for k, v in params.items() if pcfg.get(k, {}).get("in") == "query"}
        body = {k: v for k, v in params.items() if pcfg.get(k, {}).get("in", "body") == "body"}
        method = cfg.get("method", "GET").upper()

        headers = {"Idempotency-Key": idempotency_key}
        if self._secret is not None:
            secret = self._secret()
            headers[self._auth_header] = f"Bearer {secret}" if self._auth_type == "bearer" else secret
        try:
            resp = self._http.request(method, self._base + path, params=query or None,
                                      json=body if body and method != "GET" else None,
                                      headers=headers, timeout=self._timeout)
        except requests.RequestException as e:
            raise ConnectorError(f"{self.name} request failed: {e.__class__.__name__}") from e
        if resp.status_code >= 400:
            raise ConnectorError(f"{self.name} returned {resp.status_code}")
        if not resp.content:
            return {"status": resp.status_code}
        try:
            return resp.json()
        except ValueError:
            return {"status": resp.status_code, "text": resp.text[:2000]}
