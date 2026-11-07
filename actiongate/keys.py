"""Ed25519 signing keys for grants and audit records."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SigningKey:
    def __init__(self, private_key: Ed25519PrivateKey, kid: str = "k1"):
        self.private_key = private_key
        self.public_key: Ed25519PublicKey = private_key.public_key()
        self.kid = kid

    @classmethod
    def generate(cls, kid: str = "k1") -> "SigningKey":
        return cls(Ed25519PrivateKey.generate(), kid)

    @classmethod
    def load_or_create(cls, path: str | Path, kid: str = "k1") -> "SigningKey":
        path = Path(path)
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{path} is not an Ed25519 private key")
            return cls(key, kid)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # Write with owner-only permissions.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return cls(key, kid)

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
