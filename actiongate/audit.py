"""Append-only, hash-chained, signed audit log.

Each record's hash covers the previous record's hash, so editing or
deleting any record breaks every hash after it. Each hash is signed with
the server's Ed25519 key, so the chain cannot be rebuilt by someone who
can write to the database but does not hold the key.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonical_json
from .keys import SigningKey
from .store import Store

GENESIS = "0" * 64


def _record_hash(prev_hash: str, ts: float, event: str, data_json: str) -> str:
    body = canonical_json({"prev": prev_hash, "ts": repr(ts), "event": event, "data": data_json})
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    error: str | None = None
    bad_seq: int | None = None


class AuditLog:
    def __init__(self, store: Store, key: SigningKey, clock=time.time):
        self.store = store
        self.key = key
        self.clock = clock

    def append(self, event: str, data: dict[str, Any]) -> int:
        data_json = canonical_json(data)
        with self.store.lock:
            last = self.store.last_audit()
            prev = last["hash"] if last else GENESIS
            ts = self.clock()
            h = _record_hash(prev, ts, event, data_json)
            sig = base64.b64encode(self.key.sign(bytes.fromhex(h))).decode()
            return self.store.insert_audit(ts, event, data_json, prev, h, sig, self.key.kid)

    def verify(self) -> VerifyResult:
        prev = GENESIS
        n = 0
        for row in self.store.iter_audit():
            n += 1
            if row["prev_hash"] != prev:
                return VerifyResult(False, n, "chain broken (record missing or reordered)", row["seq"])
            expected = _record_hash(row["prev_hash"], row["ts"], row["event"], row["data_json"])
            if row["hash"] != expected:
                return VerifyResult(False, n, "record contents changed", row["seq"])
            try:
                self.key.public_key.verify(base64.b64decode(row["signature"]), bytes.fromhex(row["hash"]))
            except (InvalidSignature, ValueError):
                return VerifyResult(False, n, "bad signature", row["seq"])
            prev = row["hash"]
        return VerifyResult(True, n)
