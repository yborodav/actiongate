"""Single-use grants bound to one action hash.

A grant is an Ed25519-signed JWT. The executor verifies it immediately
before calling the connector and consumes its jti, so it cannot be replayed.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt

from .keys import SigningKey
from .store import Store

ISSUER = "actiongate"
AUDIENCE = "actiongate-executor"
DEFAULT_TTL = 300  # seconds


class GrantError(Exception):
    pass


@dataclass(frozen=True)
class GrantClaims:
    jti: str
    request_id: str
    action_hash: str
    agent_id: str
    approver: str


class GrantIssuer:
    def __init__(self, key: SigningKey, store: Store, ttl_seconds: int = DEFAULT_TTL, clock=time.time):
        self.key = key
        self.store = store
        self.ttl = ttl_seconds
        self.clock = clock

    def issue(self, *, request_id: str, action_hash: str, agent_id: str, approver: str) -> str:
        now = int(self.clock())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": agent_id,
            "jti": uuid.uuid4().hex,
            "req": request_id,
            "ahs": action_hash,
            "apv": approver,
            "iat": now,
            "exp": now + self.ttl,
        }
        return jwt.encode(claims, self.key.private_key, algorithm="EdDSA", headers={"kid": self.key.kid})

    def verify_and_consume(self, token: str, *, request_id: str, action_hash: str) -> GrantClaims:
        """Verify signature, audience, expiry and binding, then burn the jti.

        Raises GrantError on any failure. Order matters: every check runs
        before the jti is consumed, so a bad token cannot burn a good one.
        """
        try:
            claims = jwt.decode(
                token,
                self.key.public_key,
                algorithms=["EdDSA"],  # pin the algorithm; never trust the header's alg
                audience=AUDIENCE,
                issuer=ISSUER,
                # Time checks run below against the injected clock, the single
                # source of time for the whole gateway.
                options={"require": ["exp", "iat", "jti", "aud", "iss", "sub"],
                         "verify_exp": False, "verify_iat": False, "verify_nbf": False},
            )
        except jwt.PyJWTError as e:
            raise GrantError(f"invalid grant: {e}") from e

        now = int(self.clock())
        if now >= int(claims["exp"]):
            raise GrantError("grant expired")
        if int(claims["iat"]) > now + 5:
            raise GrantError("grant issued in the future")
        if int(claims["exp"]) - int(claims["iat"]) > self.ttl:
            raise GrantError("grant lifetime exceeds policy")
        if claims.get("req") != request_id:
            raise GrantError("grant is for a different request")
        if claims.get("ahs") != action_hash:
            raise GrantError("grant does not match this action")
        if not self.store.consume_jti(claims["jti"], self.clock()):
            raise GrantError("grant already used")

        return GrantClaims(
            jti=claims["jti"],
            request_id=claims["req"],
            action_hash=claims["ahs"],
            agent_id=claims["sub"],
            approver=claims["apv"],
        )
