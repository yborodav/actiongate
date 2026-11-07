"""Encrypted credential vault. Connectors read secrets here; agents never do."""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ENV_KEY = "ACTIONGATE_VAULT_KEY"


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: str | Path, key: bytes | None = None):
        self.path = Path(path)
        key = key or os.environ.get(ENV_KEY, "").encode()
        if not key:
            raise VaultError(f"set {ENV_KEY} (generate one with: python -m actiongate vault-key)")
        self._fernet = Fernet(key)

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self._fernet.decrypt(self.path.read_bytes()))
        except InvalidToken as e:
            raise VaultError("vault key does not match the vault file") from e

    def _save(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(self._fernet.encrypt(json.dumps(data).encode()))
        os.replace(tmp, self.path)

    def put(self, name: str, secret: str) -> None:
        data = self._load()
        data[name] = secret
        self._save(data)

    def get(self, name: str) -> str:
        data = self._load()
        if name not in data:
            raise VaultError(f"no secret named '{name}' in the vault")
        return data[name]

    def names(self) -> list[str]:
        return sorted(self._load())


class MemoryVault:
    """In-memory vault for tests and local experiments."""

    def __init__(self, secrets: dict[str, str] | None = None):
        self._data = dict(secrets or {})

    def put(self, name: str, secret: str) -> None:
        self._data[name] = secret

    def get(self, name: str) -> str:
        if name not in self._data:
            raise VaultError(f"no secret named '{name}' in the vault")
        return self._data[name]

    def names(self) -> list[str]:
        return sorted(self._data)
