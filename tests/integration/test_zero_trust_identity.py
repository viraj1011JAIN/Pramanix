# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Zero-Trust Identity Linker integration tests.

Uses testcontainers to spin up a REAL Redis instance.
No mocking of Redis. Tests the full identity → state → guard pipeline.
Skipped if redis or testcontainers are not installed.

THE CRITICAL TEST: test_caller_cannot_inject_own_state
This test proves the zero-trust invariant: even if a caller sends
fake state in the request body, the state is loaded from Redis
using ONLY the verified JWT sub claim. The caller's fake state
is IGNORED. If this test fails, the system is not zero-trust.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from decimal import Decimal
from typing import ClassVar

import pytest

pytest.importorskip("redis", reason="redis not installed")
pytest.importorskip("testcontainers", reason="testcontainers not installed")

import redis.asyncio as aioredis
from testcontainers.redis import RedisContainer

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.identity.linker import (
    JWTExpiredError,
    JWTIdentityLinker,
    JWTVerificationError,
    StateLoadError,
)
from pramanix.identity.redis_loader import RedisStateLoader

# ── JWT test helper ───────────────────────────────────────────────────────────


def _make_jwt(
    sub: str,
    roles: list[str],
    secret: str,
    exp_offset: int = 3600,
) -> str:
    """Create a real HMAC-SHA256 JWT for testing."""
    header = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    now = int(time.time())
    payload_dict = {
        "sub": sub,
        "roles": roles,
        "iat": now,
        "exp": now + exp_offset,
    }
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(payload_dict, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    signing_input = f"{header}.{payload}"
    sig = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


# ── Banking policy ────────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class _BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount, "balance": _balance}

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Insufficient balance for transfer")
        ]


# ── Testcontainers fixtures ───────────────────────────────────────────────────


@pytest.fixture(scope="module")
def redis_container():
    with RedisContainer() as container:
        yield container


@pytest.fixture(scope="module")
def redis_url(redis_container):
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    return f"redis://{host}:{port}"


@pytest.fixture
async def redis_client(redis_url):
    client = aioredis.from_url(redis_url, decode_responses=True)
    yield client
    await client.aclose()


SECRET = "zero-trust-jwt-signing-secret-minimum-32-chars"


# ── THE CRITICAL TEST ─────────────────────────────────────────────────────────


class TestZeroTrustBoundary:
    @pytest.mark.asyncio
    async def test_caller_cannot_inject_own_state(self, redis_client):
        """CORE ZERO-TRUST TEST.

        Scenario: Alice has only $100 in her real account (Redis).
        The caller sends {"balance": 999999} in the request body
        attempting to convince the system she has more money.

        Expected: The system uses ONLY the Redis state (balance=100).
        The caller-provided fake state is IGNORED. Period.

        If this test fails, Pramanix is NOT zero-trust.
        """
        # Pre-load Alice's REAL state
        real_state = {"balance": "100", "state_version": "v1"}
        await redis_client.set("pramanix:state:alice", json.dumps(real_state))

        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)

        token = _make_jwt("alice", ["user"], SECRET)

        class _Request:
            headers: ClassVar[dict] = {"Authorization": f"Bearer {token}"}
            # Caller tries to inject high balance in body — this must be IGNORED
            body_data: ClassVar[dict] = {
                "amount": "99999",
                "balance": "999999",
            }

        claims, state = await linker.extract_and_load(_Request())

        # State must come from Redis, NOT from request body
        assert str(state["balance"]) == "100", (
            f"ZERO-TRUST FAILURE: state balance is {state['balance']!r}, "
            "expected '100' from Redis. Caller injection succeeded — this is a bug."
        )
        assert claims.sub == "alice"

    @pytest.mark.asyncio
    async def test_full_pipeline_allow(self, redis_client):
        """End-to-end: JWT → Redis → Guard → ALLOW."""
        await redis_client.set(
            "pramanix:state:bob",
            json.dumps({"balance": "5000", "state_version": "v1"}),
        )
        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))

        token = _make_jwt("bob", ["user"], SECRET)

        class _Req:
            headers: ClassVar[dict] = {"Authorization": f"Bearer {token}"}

        _claims, state = await linker.extract_and_load(_Req())
        decision = await guard.verify_async(
            intent={
                "amount": Decimal("100"),
                "balance": Decimal(state["balance"]),
            },
            state=state,
        )
        assert decision.allowed

    @pytest.mark.asyncio
    async def test_full_pipeline_block_insufficient_balance(
        self, redis_client
    ):
        """End-to-end: JWT → Redis → Guard → BLOCK."""
        await redis_client.set(
            "pramanix:state:carol",
            json.dumps({"balance": "50", "state_version": "v1"}),
        )
        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))

        token = _make_jwt("carol", ["user"], SECRET)

        class _Req:
            headers: ClassVar[dict] = {"Authorization": f"Bearer {token}"}

        _claims, state = await linker.extract_and_load(_Req())
        decision = await guard.verify_async(
            intent={
                "amount": Decimal("1000"),
                "balance": Decimal(state["balance"]),
            },
            state=state,
        )
        assert not decision.allowed
        assert "sufficient_balance" in decision.violated_invariants

    @pytest.mark.asyncio
    async def test_expired_jwt_raises(self, redis_client):
        expired_token = _make_jwt("dave", ["user"], SECRET, exp_offset=-7200)
        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)

        class _Req:
            headers: ClassVar[dict] = {
                "Authorization": f"Bearer {expired_token}"
            }

        with pytest.raises(JWTExpiredError):
            await linker.extract_and_load(_Req())

    @pytest.mark.asyncio
    async def test_tampered_jwt_raises(self, redis_client):
        token = _make_jwt("eve", ["user"], SECRET)
        parts = token.split(".")
        tampered = f"{parts[0]}.TAMPERED_PAYLOAD_HERE.{parts[2]}"

        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)

        class _Req:
            headers: ClassVar[dict] = {"Authorization": f"Bearer {tampered}"}

        with pytest.raises(JWTVerificationError):
            await linker.extract_and_load(_Req())

    @pytest.mark.asyncio
    async def test_unknown_user_raises_state_load_error(self, redis_client):
        token = _make_jwt("unknown-user-xyz-12345", ["user"], SECRET)
        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)

        class _Req:
            headers: ClassVar[dict] = {"Authorization": f"Bearer {token}"}

        with pytest.raises(StateLoadError):
            await linker.extract_and_load(_Req())

    @pytest.mark.asyncio
    async def test_missing_bearer_prefix_raises(self, redis_client):
        loader = RedisStateLoader(redis_client=redis_client)
        linker = JWTIdentityLinker(state_loader=loader, jwt_secret=SECRET)

        class _Req:
            headers: ClassVar[dict] = {"Authorization": "Basic abc123"}

        with pytest.raises(JWTVerificationError):
            await linker.extract_and_load(_Req())

    def test_short_secret_raises_value_error(self, redis_client):
        loader = RedisStateLoader(redis_client=redis_client)
        with pytest.raises(ValueError, match="secret"):
            JWTIdentityLinker(state_loader=loader, jwt_secret="short")

    def test_empty_secret_raises_value_error(self, redis_client):
        loader = RedisStateLoader(redis_client=redis_client)
        with pytest.raises(ValueError):
            JWTIdentityLinker(state_loader=loader, jwt_secret="")
