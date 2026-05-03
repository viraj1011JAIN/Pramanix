# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Zero-Trust JWT Identity Linker.

Architecture:
    Request → Extract Bearer token → Verify JWT signature →
    Extract (sub, roles) → Fetch state(sub) from StateLoader →
    Return (claims, state)

The caller's request body state is NEVER used. JWT sub claim is the
ONLY state lookup key. This is the zero-trust boundary.

Security guarantees:
1. JWT signature verified with HMAC-SHA256 before ANY claims are trusted
2. Token expiry checked — expired tokens rejected
3. State ALWAYS loaded using verified sub claim as key
4. Caller-provided state in request body is IGNORED
5. JWTs are never decoded before signature verification
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class IdentityClaims:
    """Parsed and validated JWT claims for a bearer token."""

    sub: str
    roles: list[str]
    exp: int
    iat: int
    raw: dict[str, Any]


class StateLoader(Protocol):
    """Protocol for loading application state keyed by verified identity claims."""

    async def load(self, claims: IdentityClaims) -> dict[str, Any]:
        """Return a state dict for the given verified identity claims."""
        ...


class StateLoadError(Exception):
    """Raised when application state cannot be loaded for the given claims."""


class JWTVerificationError(Exception):
    """Raised when a JWT has an invalid signature or is structurally malformed."""


class JWTExpiredError(Exception):
    """Raised when a JWT token has passed its expiry time (exp claim)."""


class JWTIdentityLinker:
    """Zero-Trust JWT Identity Linker.

    Configuration:
        PRAMANIX_JWT_SECRET environment variable (min 32 chars)

    Usage with FastAPI:
        linker = JWTIdentityLinker(state_loader=RedisStateLoader(...))

        @app.post("/transfer")
        async def transfer(request: Request):
            claims, state = await linker.extract_and_load(request)
            decision = await guard.verify_async(intent=intent, state=state)
    """

    _ENV_SECRET = "PRAMANIX_JWT_SECRET"
    _MIN_SECRET_LENGTH = 32

    def __init__(
        self,
        state_loader: StateLoader,
        jwt_secret: str | None = None,
        clock_skew_seconds: int = 30,
    ) -> None:
        raw = jwt_secret or os.environ.get(self._ENV_SECRET, "")
        if not raw or len(raw) < self._MIN_SECRET_LENGTH:
            raise ValueError(
                f"JWT secret must be >= {self._MIN_SECRET_LENGTH} characters. "
                f"Set {self._ENV_SECRET} environment variable."
            )
        self._secret = raw.encode()
        self._loader = state_loader
        self._skew = clock_skew_seconds

    async def extract_and_load(self, request: Any) -> tuple[IdentityClaims, dict[str, Any]]:
        """Extract verified claims and load state.

        Returns (claims, state) on success.
        The returned state comes EXCLUSIVELY from the StateLoader
        using claims.sub — never from the request body.

        Raises: JWTVerificationError, JWTExpiredError, StateLoadError
        """
        auth_header = request.headers.get("Authorization", "")
        token = self._extract_bearer(auth_header)
        claims = self._verify_token(token)
        state = await self._loader.load(claims)
        return claims, state

    def _extract_bearer(self, auth_header: str) -> str:
        if not auth_header.startswith("Bearer "):
            raise JWTVerificationError("Authorization header must be: Bearer <token>")
        token = auth_header[7:].strip()
        if not token:
            raise JWTVerificationError("Bearer token is empty")
        return token

    def _verify_token(self, token: str) -> IdentityClaims:
        """Verify HMAC-SHA256 JWT. Claims decoded ONLY after signature passes."""
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTVerificationError("JWT must have exactly 3 parts")

        header_b64, payload_b64, sig_b64 = parts

        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(self._secret, signing_input.encode(), hashlib.sha256).digest()
        expected_b64 = self._b64url(expected_sig)

        if not hmac.compare_digest(sig_b64.encode(), expected_b64.encode()):
            raise JWTVerificationError("JWT signature verification failed")

        try:
            payload = json.loads(self._b64url_decode(payload_b64))
        except Exception as e:
            raise JWTVerificationError(f"JWT payload decode failed: {e}") from e

        now = int(time.time())
        exp = payload.get("exp", 0)
        if exp and now > exp + self._skew:
            raise JWTExpiredError(f"JWT expired at {exp}, current time {now}")

        return IdentityClaims(
            sub=str(payload.get("sub", "")),
            roles=list(payload.get("roles", [])),
            exp=int(payload.get("exp", 0)),
            iat=int(payload.get("iat", 0)),
            raw=payload,
        )

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)
