# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for Zero-Trust JWT Identity Linker and Redis state loader.

Tests JWTIdentityLinker, IdentityClaims, RedisStateLoader — all stdlib-only,
no external dependencies needed (Redis is mocked via AsyncMock/MagicMock).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock

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


# ── JWT helpers ───────────────────────────────────────────────────────────────


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
    def test_raises_if_no_key_and_no_env(self, monkeypatch):
        monkeypatch.delenv("PRAMANIX_JWT_SECRET", raising=False)
        with pytest.raises(ValueError, match="32"):
            JWTIdentityLinker(state_loader=MagicMock())

    def test_raises_if_key_too_short(self):
        with pytest.raises(ValueError, match="32"):
            JWTIdentityLinker(state_loader=MagicMock(), jwt_secret="short")

    def test_accepts_env_key(self, monkeypatch):
        monkeypatch.setenv("PRAMANIX_JWT_SECRET", _SECRET_32)
        linker = JWTIdentityLinker(state_loader=MagicMock())
        assert linker is not None

    def test_accepts_explicit_key(self):
        linker = JWTIdentityLinker(state_loader=MagicMock(), jwt_secret=_SECRET_32)
        assert linker is not None

    def test_accepts_64_char_key(self):
        linker = JWTIdentityLinker(state_loader=MagicMock(), jwt_secret=_SECRET_64)
        assert linker is not None


# ── TestExtractBearer ─────────────────────────────────────────────────────────


class TestExtractBearer:
    def setup_method(self):
        self.linker = JWTIdentityLinker(state_loader=MagicMock(), jwt_secret=_SECRET_32)

    def test_raises_if_no_bearer_prefix(self):
        with pytest.raises(JWTVerificationError, match="Bearer"):
            self.linker._extract_bearer("Token abc")

    def test_raises_if_empty_header(self):
        with pytest.raises(JWTVerificationError, match="Bearer"):
            self.linker._extract_bearer("")

    def test_raises_if_bearer_with_no_token(self):
        with pytest.raises(JWTVerificationError, match="empty"):
            self.linker._extract_bearer("Bearer ")

    def test_returns_token_correctly(self):
        token = self.linker._extract_bearer("Bearer my.token.here")
        assert token == "my.token.here"

    def test_strips_whitespace_from_token(self):
        token = self.linker._extract_bearer("Bearer  mytoken  ")
        assert token == "mytoken"


# ── TestVerifyToken ────────────────────────────────────────────────────────────


class TestVerifyToken:
    def setup_method(self):
        self.linker = JWTIdentityLinker(state_loader=MagicMock(), jwt_secret=_SECRET_32)

    def test_rejects_token_with_wrong_part_count(self):
        with pytest.raises(JWTVerificationError, match="3 parts"):
            self.linker._verify_token("only.two")

    def test_rejects_tampered_signature(self):
        payload = _make_valid_payload()
        token = _make_token(payload, tamper_sig=True)
        with pytest.raises(JWTVerificationError, match="signature"):
            self.linker._verify_token(token)

    def test_rejects_wrong_key(self):
        payload = _make_valid_payload()
        token = _make_token(payload, secret=_SECRET_32)
        wrong_linker = JWTIdentityLinker(state_loader=MagicMock(), jwt_secret="w" * 32)
        with pytest.raises(JWTVerificationError, match="signature"):
            wrong_linker._verify_token(token)

    def test_valid_token_returns_claims(self):
        payload = _make_valid_payload(sub="alice")
        token = _make_token(payload)
        claims = self.linker._verify_token(token)
        assert claims.sub == "alice"
        assert claims.roles == ["agent"]

    def test_expired_token_raises_jwt_expired_error(self):
        payload = _make_valid_payload(exp_offset=-7200)  # expired 2h ago
        token = _make_token(payload)
        # Use clock_skew_seconds=0 to make expiry strict
        linker = JWTIdentityLinker(
            state_loader=MagicMock(), jwt_secret=_SECRET_32, clock_skew_seconds=0
        )
        with pytest.raises(JWTExpiredError, match="expired"):
            linker._verify_token(token)

    def test_token_within_clock_skew_is_accepted(self):
        # Expired 10 seconds ago, but skew is 30s → should be accepted
        payload = _make_valid_payload(exp_offset=-10)
        token = _make_token(payload)
        linker = JWTIdentityLinker(
            state_loader=MagicMock(), jwt_secret=_SECRET_32, clock_skew_seconds=30
        )
        claims = linker._verify_token(token)
        assert claims.sub == "user-123"

    def test_token_no_exp_is_accepted(self):
        """Tokens without exp claim are accepted (not all tokens expire)."""
        payload = {"sub": "neverexpires", "roles": [], "iat": int(time.time())}
        token = _make_token(payload)
        claims = self.linker._verify_token(token)
        assert claims.sub == "neverexpires"
        assert claims.exp == 0

    def test_claims_raw_dict_populated(self):
        payload = _make_valid_payload(sub="bob")
        payload["custom_claim"] = "custom_value"
        token = _make_token(payload)
        claims = self.linker._verify_token(token)
        assert claims.raw["custom_claim"] == "custom_value"

    def test_invalid_payload_json_raises_verification_error(self):
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
    def setup_method(self):
        self._state = {"state_version": "1.0", "balance": Decimal("1000")}
        self._mock_loader = AsyncMock()
        self._mock_loader.load = AsyncMock(return_value=self._state)
        self.linker = JWTIdentityLinker(state_loader=self._mock_loader, jwt_secret=_SECRET_32)

    @pytest.mark.asyncio
    async def test_returns_claims_and_state(self):
        payload = _make_valid_payload(sub="user-abc")
        token = _make_token(payload)
        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(return_value=f"Bearer {token}")
        claims, state = await self.linker.extract_and_load(mock_request)
        assert claims.sub == "user-abc"
        assert state == self._state

    @pytest.mark.asyncio
    async def test_loader_called_with_correct_claims(self):
        payload = _make_valid_payload(sub="verify-sub")
        token = _make_token(payload)
        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(return_value=f"Bearer {token}")
        claims, _ = await self.linker.extract_and_load(mock_request)
        self._mock_loader.load.assert_called_once()
        call_claims = self._mock_loader.load.call_args[0][0]
        assert call_claims.sub == "verify-sub"

    @pytest.mark.asyncio
    async def test_missing_auth_header_raises(self):
        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(return_value="")
        with pytest.raises(JWTVerificationError):
            await self.linker.extract_and_load(mock_request)

    @pytest.mark.asyncio
    async def test_state_load_error_propagates(self):
        self._mock_loader.load = AsyncMock(side_effect=StateLoadError("Redis unavailable"))
        payload = _make_valid_payload()
        token = _make_token(payload)
        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(return_value=f"Bearer {token}")
        with pytest.raises(StateLoadError, match="Redis unavailable"):
            await self.linker.extract_and_load(mock_request)


# ── TestB64urlHelpers ──────────────────────────────────────────────────────────


class TestB64urlHelpers:
    def setup_method(self):
        self.linker = JWTIdentityLinker(state_loader=MagicMock(), jwt_secret=_SECRET_32)

    def test_b64url_roundtrip(self):
        original = b"hello world!"
        encoded = JWTIdentityLinker._b64url(original)
        decoded = JWTIdentityLinker._b64url_decode(encoded)
        assert decoded == original

    def test_b64url_no_padding(self):
        encoded = JWTIdentityLinker._b64url(b"test")
        assert "=" not in encoded

    def test_b64url_decode_handles_padding(self):
        # 12 bytes → 16 base64 chars (padding already aligned)
        data = b"123456789012"
        encoded = _b64url(data)
        assert len(encoded) % 4 == 0  # already aligned — no padding needed
        decoded = JWTIdentityLinker._b64url_decode(encoded)
        assert decoded == data


# ── TestRedisStateLoader ───────────────────────────────────────────────────────


class TestRedisStateLoader:
    def _make_redis(self, return_value: Any = None, side_effect=None) -> AsyncMock:
        r = AsyncMock()
        if side_effect:
            r.get = AsyncMock(side_effect=side_effect)
        else:
            r.get = AsyncMock(return_value=return_value)
        return r

    def _make_claims(self, sub: str = "user-123") -> IdentityClaims:
        return IdentityClaims(
            sub=sub,
            roles=["agent"],
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            raw={},
        )

    def test_construction_stores_prefix(self):
        r = self._make_redis()
        loader = RedisStateLoader(redis_client=r, key_prefix="myapp:state:")
        assert loader._prefix == "myapp:state:"

    def test_construction_default_prefix(self):
        r = self._make_redis()
        loader = RedisStateLoader(redis_client=r)
        assert loader._prefix == "pramanix:state:"

    @pytest.mark.asyncio
    async def test_raises_state_load_error_if_sub_empty(self):
        r = self._make_redis()
        loader = RedisStateLoader(redis_client=r)
        claims = IdentityClaims(sub="", roles=[], exp=0, iat=0, raw={})
        with pytest.raises(StateLoadError, match="sub claim is empty"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_if_key_not_found(self):
        r = self._make_redis(return_value=None)
        loader = RedisStateLoader(redis_client=r)
        claims = self._make_claims(sub="unknown")
        with pytest.raises(StateLoadError, match="No state found"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_on_redis_exception(self):
        r = self._make_redis(side_effect=ConnectionError("Redis down"))
        loader = RedisStateLoader(redis_client=r)
        claims = self._make_claims()
        with pytest.raises(StateLoadError, match="Redis error"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_on_invalid_json(self):
        r = self._make_redis(return_value=b"{ not valid json }")
        loader = RedisStateLoader(redis_client=r)
        claims = self._make_claims()
        with pytest.raises(StateLoadError, match="Invalid JSON"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_raises_state_load_error_if_state_version_missing(self):
        payload = json.dumps({"balance": "1000"})  # no state_version
        r = self._make_redis(return_value=payload.encode())
        loader = RedisStateLoader(redis_client=r)
        claims = self._make_claims()
        with pytest.raises(StateLoadError, match="state_version"):
            await loader.load(claims)

    @pytest.mark.asyncio
    async def test_returns_state_dict_on_valid_payload(self):
        payload = json.dumps({"state_version": "1.0", "balance": 5000})
        r = self._make_redis(return_value=payload.encode())
        loader = RedisStateLoader(redis_client=r)
        claims = self._make_claims(sub="alice")
        state = await loader.load(claims)
        assert state["state_version"] == "1.0"
        assert state["balance"] == 5000

    @pytest.mark.asyncio
    async def test_uses_correct_redis_key(self):
        payload = json.dumps({"state_version": "1.0"})
        r = self._make_redis(return_value=payload.encode())
        loader = RedisStateLoader(redis_client=r, key_prefix="pfx:")
        claims = self._make_claims(sub="bob")
        await loader.load(claims)
        r.get.assert_called_once_with("pfx:bob")

    @pytest.mark.asyncio
    async def test_parses_float_as_decimal(self):
        payload = json.dumps({"state_version": "2.0", "amount": 123.45})
        r = self._make_redis(return_value=payload.encode())
        loader = RedisStateLoader(redis_client=r)
        claims = self._make_claims()
        state = await loader.load(claims)
        assert isinstance(state["amount"], Decimal)
        assert state["amount"] == Decimal("123.45")

    @pytest.mark.asyncio
    async def test_state_loaded_by_sub_not_by_request_body(self):
        """Zero-trust: state key MUST be claims.sub, never from request body."""
        payload = json.dumps({"state_version": "1.0", "balance": "9999"})
        r = self._make_redis(return_value=payload.encode())
        loader = RedisStateLoader(redis_client=r, key_prefix="zt:")
        claims = self._make_claims(sub="verified-user")
        await loader.load(claims)
        # The Redis key MUST be derived from verified JWT sub only
        r.get.assert_called_once_with("zt:verified-user")
