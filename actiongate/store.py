"""SQLite persistence for requests, used grant IDs and the audit log.

SQLite keeps the MVP dependency-free; the schema maps directly onto Postgres.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator

from .models import Action, Request, Status

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    action_json TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    rule_name TEXT,
    approvers_json TEXT NOT NULL,
    reason TEXT,
    created_at REAL NOT NULL,
    expires_at REAL,
    decided_by TEXT,
    decided_at REAL,
    result_json TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status);

CREATE TABLE IF NOT EXISTS used_grants (
    jti TEXT PRIMARY KEY,
    used_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    event TEXT NOT NULL,
    data_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    kid TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        # One writer at a time; SQLite serialises anyway, this keeps
        # read-modify-write sequences atomic within the process.
        self.lock = threading.RLock()

    # ---------- requests ----------

    def insert_request(self, r: Request) -> None:
        with self.lock:
            self._conn.execute(
                "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    r.id,
                    json.dumps(r.action.to_dict()),
                    r.action_hash,
                    r.status.value,
                    r.rule_name,
                    json.dumps(r.approvers),
                    r.reason,
                    r.created_at,
                    r.expires_at,
                    r.decided_by,
                    r.decided_at,
                    json.dumps(r.result) if r.result is not None else None,
                    r.error,
                ),
            )

    def update_request(self, r: Request) -> None:
        with self.lock:
            self._conn.execute(
                """UPDATE requests SET status=?, decided_by=?, decided_at=?, result_json=?, error=?
                   WHERE id=?""",
                (
                    r.status.value,
                    r.decided_by,
                    r.decided_at,
                    json.dumps(r.result) if r.result is not None else None,
                    r.error,
                    r.id,
                ),
            )

    def transition(self, request_id: str, from_status: Status, to_status: Status, **fields: Any) -> bool:
        """Compare-and-set a status change. Returns False if the request was not in from_status.

        This is what stops a double approval, or an approval racing a timeout,
        from executing an action twice.
        """
        sets = ["status=?"]
        values: list[Any] = [to_status.value]
        for k in ("decided_by", "decided_at", "error"):
            if k in fields:
                sets.append(f"{k}=?")
                values.append(fields[k])
        if "result" in fields:
            sets.append("result_json=?")
            values.append(json.dumps(fields["result"]) if fields["result"] is not None else None)
        values += [request_id, from_status.value]
        with self.lock:
            cur = self._conn.execute(
                f"UPDATE requests SET {', '.join(sets)} WHERE id=? AND status=?", values
            )
            return cur.rowcount == 1

    def get_request(self, request_id: str) -> Request | None:
        row = self._conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        return _row_to_request(row) if row else None

    def pending_expired(self, now: float) -> list[Request]:
        rows = self._conn.execute(
            "SELECT * FROM requests WHERE status=? AND expires_at IS NOT NULL AND expires_at <= ?",
            (Status.PENDING.value, now),
        ).fetchall()
        return [_row_to_request(r) for r in rows]

    # ---------- grants ----------

    def consume_jti(self, jti: str, now: float) -> bool:
        """Mark a grant ID as used. Returns False if it was already used (replay)."""
        with self.lock:
            try:
                self._conn.execute("INSERT INTO used_grants VALUES (?,?)", (jti, now))
                return True
            except sqlite3.IntegrityError:
                return False

    # ---------- audit ----------

    def last_audit(self) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()

    def insert_audit(self, ts: float, event: str, data_json: str, prev_hash: str, h: str, sig: str, kid: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO audit (ts, event, data_json, prev_hash, hash, signature, kid) VALUES (?,?,?,?,?,?,?)",
            (ts, event, data_json, prev_hash, h, sig, kid),
        )
        return int(cur.lastrowid)

    def iter_audit(self) -> Iterator[sqlite3.Row]:
        yield from self._conn.execute("SELECT * FROM audit ORDER BY seq ASC")

    def raw(self) -> sqlite3.Connection:
        """Direct connection access, used by tests to simulate tampering."""
        return self._conn


def _row_to_request(row: sqlite3.Row) -> Request:
    return Request(
        id=row["id"],
        action=Action.from_dict(json.loads(row["action_json"])),
        action_hash=row["action_hash"],
        status=Status(row["status"]),
        rule_name=row["rule_name"],
        approvers=json.loads(row["approvers_json"]),
        reason=row["reason"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        decided_by=row["decided_by"],
        decided_at=row["decided_at"],
        result=json.loads(row["result_json"]) if row["result_json"] else None,
        error=row["error"],
    )
