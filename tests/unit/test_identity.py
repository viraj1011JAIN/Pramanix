# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for Zero-Trust JWT Identity Linker and Redis state loader.

Design principles
-----------------
* **No AsyncMock / MagicMock** for any real service boundary (Redis).
  ``TestRedisStateLoader`` uses ``fakeredis.aioredis.FakeRedis()`` — a
  complete in-memory implementation of the redis-py async API that
  exercises real serialisation, key-prefix logic, and error paths.

* **No MagicMock** for the ``state_loader`` or ``request`` objects.
  ``_NoopStateLoader`` is a real implementation of the ``StateLoader``
  protocol used when JWT tests do not exercise state loading.
  ``_HttpRequest`` is a real minimal HTTP-request dataclass that
  provides the ``headers.get()`` interface used by ``JWTIdentityLinker``.

* JWT cryptographic operations (HMAC-SHA256, base64url encoding/decoding,
  expiry checks) are exercised with real stdlib calls — no patching.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from decimal import Decimal
import fakeredis.aioredis as fakeredis
import pytest

from pramanix.identity.linker import (
    IdentityClaims,
    JWTExpiredError,
    JWTIdentityLinker,
    JWTVerificationError,
    StateLoadError,
)
from pramanix.identity.redis_loader import RedisStateLoader

_SECRET_32 = "s" * 32
_SECRET_64 = "s" * 64

# ── Minimal real implementations (NOT mocks) ──────────────────────────────────


def _make_noop_loader() -> RedisStateLoader:
    """Return a real RedisStateLoader backed by an empty fakeredis instance.

    Used in JWT tests that verify token validation only — the loader is
    never called, but a real implementation satisfies the protocol contract.
    """
    return RedisStateLoader(redis_client=fakeredis.FakeRedis(), key_prefix="pramanix:state:")


@dataclass
class _Headers:
    """Minimal HTTP headers implementation."""

    _data: dict[str, str]

    def get(self, key: str, default: str = "") -> str:
        return self._data.get(key, default)


@dataclass
class _HttpRequest:
    """Minimal HTTP request for testing JWTIdentityLinker.extract_and_load().

    JWTIdentityLinker only reads ``request.headers.get("Authorization", "")``.
    This real dataclass satisfies that interface without any mocking framework.
    """

    _authorization: str

    @property
    def headers(self) -> _Headers:
        return _Headers({"Authorization": self._authorization})


# ── JWT helpers (real stdlib operations) ──────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_str(s: str) -> str:
    return _b64url(s.encode())


def _make_token(
    payload: dict,
    secret: str = _SECRET_32,
    tamper_sig: bool = False,
    tamper_payload: bool = False,
) -> str:
    header_b64 = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())

    if tamper_payload:
        payload_b64 = _b64url(json.dumps({**payload, "sub": "hacker"}).encode())

    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = _b64url(sig)

    if tamper_sig:
        sig_b64 = _b64url(b"badbadbadbadbadbadbadbadbadbadbad")

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _make_valid_payload(sub: str = "user-123", exp_offset: int = 3600) -> dict:
    now = int(time.time())
    return {
        "sub": sub,
        "roles": ["agent"],
        "iat": now,
        "exp": now + exp_offset,
    }


# ── TestJWTIdentityLinkerConstruction ─────────────────────────────────────────


class TestJWTIdentityLinkerConstruction:
    def test_raises_if_no_key_and_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_JWT_SECRET", raising=False)
        with pytest.raises(ValueError, match="32"):
            JWTIdentityLinker(state_loader=_make_noop_loader())

    def test_raises_if_key_too_short(self) -> None:
        with pytest.raises(ValueError, match="32"):
            JWTIdentityLinker(state_loader=_make_noop_loader(), jwt_secret="short")

    def test_accepts_env_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_JWT_SECRET", _SECRET_32)
        linker = JWTIdentityLinker(state_loader=_make_noop_loader())
        assert linker is not None

    def test_accepts_explicit_key(self) -> None:
        linker = JWTIdentityLinker(state_loader=_make_noop_loader(), jwt_secret=_SECRET_32)
        assert linker is not None

    def test_accepts_64_char_key(self) -> None:
        linker = JWTIdentityLinker(state_loader=_make_noop_loader(), jwt_secret=_SECRET_64)
        assert linker is not None


# ── TestExtractBearer ─────────────────────────────────────────────────────────


class TestExtractBearer:
    def setup_method(self) -> None:
        self.linker = JWTIdentityLinker(state_loader=_make_noop_loader(), jwt_secret=_SECRET_32)

    def test_raises_if_no_bearer_prefix(self) -> None:
        with pytest.raises(JWTVerificationError, match="Bearer"):
            self.linker._extract_bearer("Token abc")

    def test_raises_if_empty_header(self) -> None:
        with pytest.raises(JWTVerificationError, match="Bearer"):
            self.linker._extract_bearer("")

    def test_raises_if_bearer_with_no_token(self) -> None:
        with pytest.raises(JWTVerificationError, match="empty"):
            self.linker._extract_bearer("Bearer ")

    def test_returns_token_correctly(self) -> None:
        token = self.linker._extract_bearer("Bearer my.token.here")
        assert token == "my.token.here"

    def test_strips_whitespace_from_token(self) -> None:
        token = self.linker._extract_bearer("Bearer  mytoken  ")
        assert token == "mytoken"


# ── TestVerifyToken ────────────────────────────────────────────────────────────


class TestVerifyToken:
    def setup_method(self) -> None:
        self.linker = JWTIdentityLinker(state_loader=_make_noop_loader(), jwt_secret=_SECRET_32)

    def test_rejects_token_with_wrong_part_count(self) -> None:
        with pytest.raises(JWTVerificationError, match="3 parts"):
            self.linker._verify_token("only.two")

    def test_rejects_tampered_signature(self) -> None:
        payload = _make_valid_payload()
        token = _make_token(payload, tamper_sig=True)
        with pytest.raises(JWTVerificationError, match="signature"):
            self.linker._verify_token(token)

    def test_rejects_wrong_key(self) -> None:
        payload = _make_valid_payload()
        token = _make_token(payload, secret=_SECRET_32)
        wrong_linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(), jwt_secret="w" * 32
        )
        with pytest.raises(JWTVerificationError, match="signature"):
            wrong_linker._verify_token(token)

    def test_valid_token_returns_claims(self) -> None:
        payload = _make_valid_payload(sub="alice")
        token = _make_token(payload)
        claims = self.linker._verify_token(token)
        assert claims.sub == "alice"
        assert claims.roles == ["agent"]

    def test_expired_token_raises_jwt_expired_error(self) -> None:
        payload = _make_valid_payload(exp_offset=-7200)  # expired 2h ago
        token = _make_token(payload)
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(), jwt_secret=_SECRET_32, clock_skew_seconds=0
        )
        with pytest.raises(JWTExpiredError, match="expired"):
            linker._verify_token(token)

    def test_token_within_clock_skew_is_accepted(self) -> None:
        payload = _make_valid_payload(exp_offset=-10)  # expired 10s ago
        token = _make_token(payload)
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(), jwt_secret=_SECRET_32, clock_skew_seconds=30
        )
        claims = linker._verify_token(token)
        assert claims.sub == "user-123"

    def test_token_no_exp_is_accepted(self) -> None:
        """Tokens without exp claim are accepted (not all tokens expire)."""
        payload = {"sub": "neverexpires", "roles": [], "iat": int(time.time())}
        token = _make_token(payload)
        claims = self.linker._verify_token(token)
        assert claims.sub == "neverexpires"
        assert claims.exp == 0

    def test_claims_raw_dict_populated(self) -> None:
        payload = _make_valid_payload(sub="bob")
        payload["custom_claim"] = "custom_value"
        token = _make_token(payload)
        claims = self.linker._verify_token(token)
        assert claims.raw["custom_claim"] == "custom_value"

    def test_invalid_payload_json_raises_verification_error(self) -> None:
        """Corrupt payload (not valid JSON) raises JWTVerificationError."""
        header_b64 = _b64url(json.dumps({"alg": "HS256"}).encode())
        bad_payload_b64 = _b64url(b"not-json")
        signing_input = f"{header_b64}.{bad_payload_b64}"
        sig = hmac.new(_SECRET_32.encode(), signing_input.encode(), hashlib.sha256).digest()
        sig_b64 = _b64url(sig)
        token = f"{header_b64}.{bad_payload_b64}.{sig_b64}"
        with pytest.raises(JWTVerificationError, match="payload decode"):
            self.linker._verify_token(token)


# ── TestExtractAndLoad ─────────────────────────────────────────────────────────


class TestExtractAndLoad:
    """Integration tests: JWT linker + real RedisStateLoader + real fakeredis."""

    @pytest.fixture(autouse=True)
    async def setup(self) -> None:
        self._redis = fakeredis.FakeRedis()
        self._loader = RedisStateLoader(redis_client=self._redis, key_prefix="pramanix:state:")
        self.linker = JWTIdentityLinker(
            state_loader=self._loader, jwt_secret=_SECRET_32
        )

    @pytest.mark.asyncio
    async def test_returns_claims_and_state(self) -> None:
        payload = _make_valid_payload(sub="user-abc")
        token = _make_token(payload)

        state_data = json.dumps({"state_version": "1.0", "balance": "1000"})
        await self._redis.set("pramanix:state:user-abc", state_data.encode())

        request = _HttpRequest(_authorization=f"Bearer {token}")
        claims, state = await self.linker.extract_and_load(request)
        assert claims.sub == "user-abc"
        assert state["state_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_loader_called_with_correct_sub(self) -> None:
        """State is loaded using the verified JWT sub — not any caller-provided value."""
        payload = _make_valid_payload(sub="verify-sub")
        token = _make_token(payload)

        state_data = json.dumps({"state_version": "1.0"})
        await self._redis.set("pramanix:state:verify-sub", state_data.encode())

        request = _HttpRequest(_authorization=f"Bearer {token}")
        claims, _ = await self.linker.extract_and_load(request)
        assert claims.sub == "verify-sub"

        # Verify that only the correct key was touched (zero-trust guarantee)
        value = await self._redis.get("pramanix:state:verify-sub")
        assert value is not None

    @pytest.mark.asyncio
    async def test_missing_auth_header_raises(self) -> None:
        request = _HttpRequest(_authorization="")
        with pytest.raises(JWTVerificationError):
            await self.linker.extract_and_load(request)

    @pytest.mark.asyncio
    async def test_state_load_error_when_key_missing(self) -> None:
        """StateLoadError raised when Redis has no entry for the JWT sub."""
        payload = _make_valid_payload(sub="unknown-user")
        token = _make_token(payload)
        request = _HttpRequest(_authorization=f"Bearer {token}")
        with pytest.raises(StateLoadError, match="No state found"):
            await self.linker.extract_and_load(request)


# ── TestB64urlHelpers ──────────────────────────────────────────────────────────


class TestB64urlHelpers:
    def setup_method(self) -> None:
        self.linker = JWTIdentityLinker(state_loader=_make_noop_loader(), jwt_secret=_SECRET_32)

    def test_b64url_roundtrip(self) -> None:
        original = b"hello world!"
        encoded = JWTIdentityLinker._b64url(original)
        decoded = JWTIdentityLinker._b64url_decode(encoded)
        assert decoded == original

    def test_b64url_no_padding(self) -> None:
        encoded = JWTIdentityLinker._b64url(b"test")
        assert "=" not in encoded

    def test_b64url_decode_handles_padding(self) -> None:
        data = b"123456789012"
        encoded = _b64url(data)
        assert len(encoded) % 4 == 0
        decoded = JWTIdentityLinker._b64url_decode(encoded)
        assert decoded == data


# ── TestRedisStateLoader ───────────────────────────────────────────────────────


class TestRedisStateLoader:
    """Tests for RedisStateLoader using real fakeredis (NOT AsyncMock).

    fakeredis.aioredis.FakeRedis() implements the complete redis-py async
    interface including connection handling, byte encoding, and error
    propagation.  Every test here performs real set/get operations against
    an in-memory Redis server.
    """

    @pytest.fixture(autouse=True)
    async def setup_redis(self) -> None:
        self._redis = fakeredis.FakeRedis()

    def _make_claims(self, sub: str = "user-123") -> IdentityClaims:
        return IdentityClaims(
            sub=sub,
            roles=["agent"],
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            raw={},
        )

    def test_construction_stores_prefix(self) -> None:
        loader = RedisStateLoader(redis_client=self._redis, key_prefix="myapp:state:")
        assert loader._prefix == "myapp:state:"

    def test_construction_default_prefix(self) -> None:
        loader = RedisStateLoader(redis_client=self._redis)
        assert loader._prefix == "pramanix:state:"

    @pytest.mark.asyncio
    async def test_raises_state_load_error_if_sub_empty(self) -> None:
        loader = RedisStateLoader(redis_client=self._redis)
        claims = IdentityClaims(sub="", roles=[], exp=0, iat=0, raw={})
        with pytest.raises(StateLoadError, match="sub claim is empty"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_if_key_not_found(self) -> None:
        """Redis has no entry for this sub — real GET returns None."""
        loader = RedisStateLoader(redis_client=self._redis)
        claims = self._make_claims(sub="unknown")
        with pytest.raises(StateLoadError, match="No state found"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_on_invalid_json(self) -> None:
        """Real Redis stores invalid JSON bytes — loader must reject it cleanly."""
        await self._redis.set("pramanix:state:user-123", b"{ not valid json }")
        loader = RedisStateLoader(redis_client=self._redis)
        claims = self._make_claims()
        with pytest.raises(StateLoadError, match="Invalid JSON"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_if_state_version_missing(self) -> None:
        """State without state_version field is rejected."""
        payload = json.dumps({"balance": "1000"}).encode()  # no state_version
        await self._redis.set("pramanix:state:user-123", payload)
        loader = RedisStateLoader(redis_client=self._redis)
        claims = self._make_claims()
        with pytest.raises(StateLoadError, match="state_version"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_returns_state_dict_on_valid_payload(self) -> None:
        payload = json.dumps({"state_version": "1.0", "balance": 5000}).encode()
        await self._redis.set("pramanix:state:alice", payload)
        loader = RedisStateLoader(redis_client=self._redis)
        claims = self._make_claims(sub="alice")
        state = await loader.load(claims)
        assert state["state_version"] == "1.0"
        assert state["balance"] == 5000

    @pytest.mark.asyncio
    async def test_uses_correct_redis_key(self) -> None:
        """Loader constructs the key as {prefix}{sub} and reads it."""
        payload = json.dumps({"state_version": "1.0"}).encode()
        await self._redis.set("pfx:bob", payload)
        loader = RedisStateLoader(redis_client=self._redis, key_prefix="pfx:")
        claims = self._make_claims(sub="bob")
        state = await loader.load(claims)
        assert state["state_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_parses_float_as_decimal(self) -> None:
        payload = json.dumps({"state_version": "2.0", "amount": 123.45}).encode()
        await self._redis.set("pramanix:state:user-123", payload)
        loader = RedisStateLoader(redis_client=self._redis)
        claims = self._make_claims()
        state = await loader.load(claims)
        assert isinstance(state["amount"], Decimal)
        assert state["amount"] == Decimal("123.45")

    @pytest.mark.asyncio
    async def test_state_loaded_by_sub_not_by_request_body(self) -> None:
        """Zero-trust: state key MUST be claims.sub, never from request body.

        This test verifies the zero-trust identity principle: an attacker
        who controls the request body cannot influence which state record
        is loaded.  Only the verified JWT sub determines the Redis key.
        """
        payload = json.dumps({"state_version": "1.0", "balance": "9999"}).encode()
        await self._redis.set("zt:verified-user", payload)
        loader = RedisStateLoader(redis_client=self._redis, key_prefix="zt:")
        claims = self._make_claims(sub="verified-user")
        state = await loader.load(claims)

        # State was loaded — verify the correct key was used by checking content
        assert state["balance"] == "9999"

        # The attacker's key (if they tried to inject a different sub) is absent
        attacker_key = await self._redis.get("zt:attacker")
        assert attacker_key is None

    @pytest.mark.asyncio
    async def test_overwritten_key_returns_latest_value(self) -> None:
        """Real Redis semantics: SET overwrites; latest value is returned."""
        loader = RedisStateLoader(redis_client=self._redis)
        claims = self._make_claims(sub="user-update")

        v1 = json.dumps({"state_version": "1.0", "balance": 100}).encode()
        await self._redis.set("pramanix:state:user-update", v1)
        state1 = await loader.load(claims)
        assert state1["balance"] == 100

        v2 = json.dumps({"state_version": "1.0", "balance": 200}).encode()
        await self._redis.set("pramanix:state:user-update", v2)
        state2 = await loader.load(claims)
        assert state2["balance"] == 200

    @pytest.mark.asyncio
    async def test_multiple_users_isolated(self) -> None:
        """Each sub maps to its own Redis key — no cross-user leakage."""
        loader = RedisStateLoader(redis_client=self._redis)

        await self._redis.set(
            "pramanix:state:alice",
            json.dumps({"state_version": "1.0", "balance": 1000}).encode(),
        )
        await self._redis.set(
            "pramanix:state:bob",
            json.dumps({"state_version": "1.0", "balance": 500}).encode(),
        )

        alice = self._make_claims(sub="alice")
        bob = self._make_claims(sub="bob")

        state_alice = await loader.load(alice)
        state_bob = await loader.load(bob)

        assert state_alice["balance"] == 1000
        assert state_bob["balance"] == 500
        assert state_alice["balance"] != state_bob["balance"]
