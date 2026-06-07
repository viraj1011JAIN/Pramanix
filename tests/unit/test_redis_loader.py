# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for RedisStateLoader (pramanix.identity.redis_loader).

All tests use real async stub objects — no mocks, no patches.
"""

from __future__ import annotations

import json

import pytest

from pramanix.identity.linker import IdentityClaims, StateLoadError
from pramanix.identity.redis_loader import RedisStateLoader

# ── Real async Redis stubs ────────────────────────────────────────────────────


class _FakeRedis:
    """Async Redis stub that serves a pre-configured data dict."""

    def __init__(self, data: dict[str, bytes | None]) -> None:
        self._data = data

    async def get(self, key: str) -> bytes | None:
        return self._data.get(key)


class _RaisingRedis:
    """Async Redis stub that raises OSError on every get()."""

    async def get(self, key: str) -> None:
        raise OSError("connection refused")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _claims(sub: str = "user-42") -> IdentityClaims:
    import time

    now = int(time.time())
    return IdentityClaims(
        sub=sub,
        roles=[],
        exp=now + 3600,
        iat=now,
        raw={"sub": sub},
    )


def _good_state(sub: str = "user-42") -> bytes:
    return json.dumps({"state_version": "1", "balance": "500"}).encode()


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_load_returns_state_on_valid_key() -> None:
    """load() returns the parsed state dict for a valid sub."""
    claims = _claims()
    redis = _FakeRedis({"pramanix:state:user-42": _good_state()})
    loader = RedisStateLoader(redis_client=redis)
    result = await loader.load(claims)
    assert result["state_version"] == "1"


@pytest.mark.asyncio
async def test_load_uses_custom_key_prefix() -> None:
    """Constructor key_prefix is prepended to the sub claim when building the key."""
    claims = _claims(sub="alice")
    redis = _FakeRedis({"custom:alice": json.dumps({"state_version": "2"}).encode()})
    loader = RedisStateLoader(redis_client=redis, key_prefix="custom:")
    result = await loader.load(claims)
    assert result["state_version"] == "2"


@pytest.mark.asyncio
async def test_load_raises_when_sub_is_empty() -> None:
    """StateLoadError raised immediately when sub is empty string."""
    import time

    now = int(time.time())
    claims = IdentityClaims(sub="", roles=[], exp=now + 3600, iat=now, raw={"sub": ""})
    loader = RedisStateLoader(redis_client=_FakeRedis({}))
    with pytest.raises(StateLoadError, match="sub claim is empty"):
        await loader.load(claims)


@pytest.mark.asyncio
async def test_load_raises_when_key_not_found() -> None:
    """StateLoadError raised when Redis returns None (key does not exist)."""
    claims = _claims(sub="missing-user")
    # Key not in the dict → _FakeRedis.get() returns None
    redis = _FakeRedis({})
    loader = RedisStateLoader(redis_client=redis)
    with pytest.raises(StateLoadError, match="No state found for the authenticated principal"):
        await loader.load(claims)


@pytest.mark.asyncio
async def test_load_raises_on_redis_connection_error() -> None:
    """StateLoadError (wrapping OSError) raised when Redis.get() throws."""
    claims = _claims()
    loader = RedisStateLoader(redis_client=_RaisingRedis())
    with pytest.raises(StateLoadError, match="Redis error loading state"):
        await loader.load(claims)


@pytest.mark.asyncio
async def test_load_raises_on_invalid_json() -> None:
    """StateLoadError raised when Redis value is not valid JSON."""
    claims = _claims()
    redis = _FakeRedis({"pramanix:state:user-42": b"not-valid-json!!"})
    loader = RedisStateLoader(redis_client=redis)
    with pytest.raises(StateLoadError, match="Invalid JSON in state"):
        await loader.load(claims)


@pytest.mark.asyncio
async def test_load_raises_when_state_version_missing() -> None:
    """StateLoadError raised when the JSON object lacks the state_version field."""
    claims = _claims()
    # Valid JSON but missing state_version
    redis = _FakeRedis({"pramanix:state:user-42": json.dumps({"balance": "100"}).encode()})
    loader = RedisStateLoader(redis_client=redis)
    with pytest.raises(StateLoadError, match="missing required field: state_version"):
        await loader.load(claims)
