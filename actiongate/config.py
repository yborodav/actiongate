"""Load YAML config and wire the gateway together."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .audit import AuditLog
from .connectors import Connector, HttpConnector, StripeConnector
from .gateway import Gateway
from .grants import GrantIssuer
from .keys import SigningKey
from .notify import ConsoleNotifier, Notifier, SlackNotifier
from .policy import PolicyEngine
from .store import Store
from .vault import MemoryVault, Vault


def hash_key(raw: str) -> str:
    """Agent keys and approver tokens are stored as SHA-256 hashes, never in plain text."""
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class Principals:
    """Maps presented secrets to identities."""

    agents: dict[str, str] = field(default_factory=dict)      # key hash -> agent id
    approvers: dict[str, str] = field(default_factory=dict)   # token hash -> approver id
    admins: dict[str, str] = field(default_factory=dict)      # token hash -> admin id
    slack_users: dict[str, str] = field(default_factory=dict)  # slack user id -> approver id

    def _lookup(self, table: dict[str, str], raw: str | None) -> str | None:
        if not raw:
            return None
        h = hash_key(raw)
        for stored, ident in table.items():
            if hmac.compare_digest(stored, h):
                return ident
        return None

    def agent(self, raw: str | None) -> str | None:
        return self._lookup(self.agents, raw)

    def approver(self, raw: str | None) -> str | None:
        return self._lookup(self.approvers, raw)

    def admin(self, raw: str | None) -> str | None:
        return self._lookup(self.admins, raw)


@dataclass
class App:
    gateway: Gateway
    principals: Principals
    slack_signing_secret: str | None
    public_url: str


def load(path: str | Path, *, vault=None, session=None) -> App:
    cfg: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
    base_dir = Path(path).resolve().parent
    data_dir = base_dir / cfg.get("data_dir", "data")

    vault = vault or Vault(data_dir / "vault.bin")
    store = Store(data_dir / "actiongate.db")
    key = SigningKey.load_or_create(data_dir / "signing_key.pem")
    return build(cfg, store=store, key=key, vault=vault, session=session)


def build(cfg: dict[str, Any], *, store: Store, key: SigningKey, vault: Vault | MemoryVault,
          session=None, clock=None, notifier: Notifier | None = None) -> App:
    import time as _time

    clock = clock or _time.time
    connectors: dict[str, Connector] = {}
    for c in cfg.get("connectors") or []:
        conn = _build_connector(c, vault, session)
        if conn.name in connectors:
            raise ValueError(f"duplicate connector name '{conn.name}'")
        connectors[conn.name] = conn

    principals = Principals()
    for a in cfg.get("agents") or []:
        principals.agents[a["key_sha256"]] = a["id"]
    for a in cfg.get("approvers") or []:
        if "token_sha256" in a:
            principals.approvers[a["token_sha256"]] = a["id"]
        if "slack_user" in a:
            principals.slack_users[a["slack_user"]] = a["id"]
    for a in cfg.get("admins") or []:
        principals.admins[a["token_sha256"]] = a["id"]

    known_approvers = {a["id"] for a in cfg.get("approvers") or []}
    agent_ids = {a["id"] for a in cfg.get("agents") or []}
    policy = PolicyEngine.from_config(cfg.get("rules") or [])
    for rule in policy.rules:
        unknown = set(rule.approvers) - known_approvers
        if unknown:
            raise ValueError(f"rule {rule.name}: unknown approvers {sorted(unknown)}")
        if set(rule.approvers) & agent_ids:
            raise ValueError(f"rule {rule.name}: an agent cannot be an approver")

    slack_cfg = cfg.get("slack")
    if notifier is None:
        if slack_cfg:
            notifier = SlackNotifier(
                bot_token_lookup=lambda: vault.get(slack_cfg["bot_token_secret"]),
                channel=slack_cfg["channel"],
                approver_slack_ids={v: k for k, v in principals.slack_users.items()},
                session=session,
            )
        else:
            notifier = ConsoleNotifier()

    gateway = Gateway(
        store=store,
        policy=policy,
        connectors=connectors,
        grants=GrantIssuer(key, store, ttl_seconds=int(cfg.get("grant_ttl_seconds", 300)), clock=clock),
        audit=AuditLog(store, key, clock=clock),
        notifier=notifier,
        clock=clock,
    )
    signing_secret = None
    if slack_cfg and slack_cfg.get("signing_secret_name"):
        signing_secret = vault.get(slack_cfg["signing_secret_name"])
    return App(gateway, principals, signing_secret,
               public_url=cfg.get("public_url") or os.environ.get("ACTIONGATE_PUBLIC_URL", "http://localhost:8080"))


def _build_connector(c: dict[str, Any], vault, session) -> Connector:
    ctype = c.get("type")
    secret_name = (c.get("auth") or {}).get("secret") or c.get("secret")
    lookup = (lambda: vault.get(secret_name)) if secret_name else None
    if ctype == "stripe":
        if lookup is None:
            raise ValueError("stripe connector needs a 'secret' naming a vault entry")
        kwargs = {"api_base": c["api_base"]} if c.get("api_base") else {}
        return StripeConnector(lookup, name=c.get("name", "stripe"), session=session, **kwargs)
    if ctype == "http":
        auth = c.get("auth") or {}
        return HttpConnector(
            name=c["name"],
            base_url=c["base_url"],
            operations=c["operations"],
            secret_lookup=lookup,
            auth_type=auth.get("type", "bearer"),
            auth_header=auth.get("header", "Authorization"),
            session=session,
        )
    raise ValueError(f"unknown connector type '{ctype}'")
