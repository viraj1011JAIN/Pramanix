# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for RedisExecutionTokenVerifier  -- distributed single-use token enforcement.

Uses a real Redis 7-alpine testcontainer (via the ``redis_url`` session fixture
in conftest.py).  Test isolation is achieved with per-test unique key prefixes
rather than per-test isolated servers.  Tests that do not touch Redis
(construction validation, _BrokenRedis, connection-failure paths) run without
any Docker requirement.
"""

from __future__ import annotations

import secrets
import threading
import time

import pytest
import redis

from pramanix import (
    ExecutionToken,
    ExecutionTokenSigner,
    RedisExecutionTokenVerifier,
)
from pramanix.decision import Decision
from pramanix.execution_token import ExecutionTokenVerifier
# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_decision(allowed: bool = True) -> Decision:
    """Return a real Decision using the production factory methods."""
    if allowed:
        return Decision.safe(intent_dump={"action": "send_email", "amount": 42})
    return Decision.unsafe(explanation="Blocked by test policy")


def _fresh_redis(redis_url: str) -> redis.Redis:
    """Return a real synchronous Redis client connected to the testcontainer."""
    return redis.Redis.from_url(redis_url, decode_responses=True)


def _unique_prefix() -> str:
    """Return a unique key prefix for per-test isolation (avoids flushdb)."""
    return f"test:{secrets.token_hex(6)}:"


def _signer_verifier(redis_url: str, ttl: float = 30.0):
    """Return a matched (signer, in-memory verifier, redis verifier) triple."""
    key = secrets.token_bytes(32)
    prefix = _unique_prefix()
    signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=ttl)
    mem_verifier = ExecutionTokenVerifier(secret_key=key)
    redis_verifier = RedisExecutionTokenVerifier(
        secret_key=key, redis_client=_fresh_redis(redis_url), key_prefix=prefix
    )
    return signer, mem_verifier, redis_verifier


class _SetOnlyRedis:
    """Real Redis-protocol stub with only `.set`  -- no `.scan`.

    Used to verify RedisExecutionTokenVerifier rejects incomplete clients.
    Not a mock: real class, real (no-op) behaviour, deterministic outcome.
    """

    def set(self, name: str, value: object, **kwargs: object) -> None:
        pass


# ── Construction / validation ──────────────────────────────────────────────────


class TestRedisVerifierConstruction:
    def test_short_key_raises(self):
        # _BrokenRedis satisfies the protocol check; ValueError fires before any I/O
        r = _BrokenRedis()
        with pytest.raises(ValueError, match="16 bytes"):
            RedisExecutionTokenVerifier(secret_key=b"tooshort", redis_client=r)

    def test_non_redis_client_raises(self):
        with pytest.raises(TypeError, match=r"redis\.Redis-compatible"):
            RedisExecutionTokenVerifier(
                secret_key=secrets.token_bytes(32),
                redis_client=object(),
            )

    def test_missing_scan_raises(self):
        """Client with .set but no .scan should be rejected."""
        bad = _SetOnlyRedis()
        with pytest.raises(TypeError, match=r"redis\.Redis-compatible"):
            RedisExecutionTokenVerifier(
                secret_key=secrets.token_bytes(32),
                redis_client=bad,
            )

    def test_custom_prefix_accepted(self, redis_url: str):
        r = _fresh_redis(redis_url)
        v = RedisExecutionTokenVerifier(
            secret_key=secrets.token_bytes(32),
            redis_client=r,
            key_prefix="myapp:tok:",
        )
        assert v._prefix == "myapp:tok:"

    def test_default_prefix(self, redis_url: str):
        v = RedisExecutionTokenVerifier(
            secret_key=secrets.token_bytes(32), redis_client=_fresh_redis(redis_url)
        )
        assert v._prefix == "pramanix:token:"


# ── Happy path ─────────────────────────────────────────────────────────────────


class TestRedisVerifierHappyPath:
    def test_valid_token_consumed_once(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        decision = _make_decision()
        token = signer.mint(decision)
        assert redis_v.consume(token) is True

    def test_valid_token_rejected_on_replay(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        token = signer.mint(_make_decision())
        assert redis_v.consume(token) is True
        assert redis_v.consume(token) is False  # replay blocked

    def test_consumed_count_increments(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        assert redis_v.consumed_count() == 0
        redis_v.consume(signer.mint(_make_decision()))
        assert redis_v.consumed_count() == 1
        redis_v.consume(signer.mint(_make_decision()))
        assert redis_v.consumed_count() == 2


# ── Cross-instance (distributed) guarantee ────────────────────────────────────


class TestCrossInstanceSingleUse:
    """Simulate two server processes sharing the same Redis backend."""

    def test_two_verifiers_same_redis_one_wins(self, redis_url: str):
        key = secrets.token_bytes(32)
        prefix = _unique_prefix()
        redis_a = _fresh_redis(redis_url)
        redis_b = _fresh_redis(redis_url)

        signer = ExecutionTokenSigner(secret_key=key)
        verifier_a = RedisExecutionTokenVerifier(
            secret_key=key, redis_client=redis_a, key_prefix=prefix
        )
        verifier_b = RedisExecutionTokenVerifier(
            secret_key=key, redis_client=redis_b, key_prefix=prefix
        )

        token = signer.mint(_make_decision())
        results = [verifier_a.consume(token), verifier_b.consume(token)]
        # Exactly one server wins
        assert results.count(True) == 1
        assert results.count(False) == 1

    def test_different_tokens_both_win(self, redis_url: str):
        key = secrets.token_bytes(32)
        prefix = _unique_prefix()
        ra = _fresh_redis(redis_url)
        rb = _fresh_redis(redis_url)

        signer = ExecutionTokenSigner(secret_key=key)
        va = RedisExecutionTokenVerifier(secret_key=key, redis_client=ra, key_prefix=prefix)
        vb = RedisExecutionTokenVerifier(secret_key=key, redis_client=rb, key_prefix=prefix)

        token_a = signer.mint(_make_decision())
        token_b = signer.mint(_make_decision())
        assert va.consume(token_a) is True
        assert vb.consume(token_b) is True

    def test_cross_prefix_isolation(self, redis_url: str):
        """Tokens with different prefixes do not collide."""
        key = secrets.token_bytes(32)
        r = _fresh_redis(redis_url)

        signer = ExecutionTokenSigner(secret_key=key)
        v_prod = RedisExecutionTokenVerifier(
            secret_key=key, redis_client=r, key_prefix="prod:token:"
        )
        v_staging = RedisExecutionTokenVerifier(
            secret_key=key, redis_client=r, key_prefix="staging:token:"
        )

        token = signer.mint(_make_decision())
        # Same token consumed once in each namespace  -- both succeed independently
        assert v_prod.consume(token) is True
        assert v_staging.consume(token) is True


# ── Security: tampered / wrong-key tokens ─────────────────────────────────────


class TestRedisVerifierSecurity:
    def test_wrong_key_rejected(self, redis_url: str):
        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)
        signer_a = ExecutionTokenSigner(secret_key=key_a)
        verifier_b = RedisExecutionTokenVerifier(
            secret_key=key_b, redis_client=_fresh_redis(redis_url), key_prefix=_unique_prefix()
        )
        token = signer_a.mint(_make_decision())
        assert verifier_b.consume(token) is False

    def test_tampered_decision_id_rejected(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        token = signer.mint(_make_decision())
        tampered = ExecutionToken(
            decision_id="evil-id",
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature=token.signature,
        )
        assert redis_v.consume(tampered) is False

    def test_tampered_intent_rejected(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        token = signer.mint(_make_decision())
        tampered = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump={"action": "wire_transfer", "amount": 999999},
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature=token.signature,
        )
        assert redis_v.consume(tampered) is False

    def test_tampered_allowed_flag_rejected(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        token = signer.mint(_make_decision())
        tampered = ExecutionToken(
            decision_id=token.decision_id,
            allowed=False,  # flipped
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature=token.signature,
        )
        assert redis_v.consume(tampered) is False

    def test_expired_token_rejected(self, redis_url: str):
        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=0.001)
        redis_v = RedisExecutionTokenVerifier(
            secret_key=key, redis_client=_fresh_redis(redis_url), key_prefix=_unique_prefix()
        )
        token = signer.mint(_make_decision())
        time.sleep(0.05)  # wait for expiry
        assert redis_v.consume(token) is False

    def test_signature_empty_string_rejected(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        token = signer.mint(_make_decision())
        bad = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature="",
        )
        assert redis_v.consume(bad) is False


# ── Concurrency ────────────────────────────────────────────────────────────────


class TestRedisVerifierConcurrency:
    def test_concurrent_consume_exactly_one_wins(self, redis_url: str):
        """50 threads race to consume the same token  -- exactly one succeeds."""
        key = secrets.token_bytes(32)
        prefix = _unique_prefix()
        signer = ExecutionTokenSigner(secret_key=key)
        token = signer.mint(_make_decision())

        results: list[bool] = []
        lock = threading.Lock()

        def consume_worker():
            r = _fresh_redis(redis_url)
            v = RedisExecutionTokenVerifier(secret_key=key, redis_client=r, key_prefix=prefix)
            result = v.consume(token)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=consume_worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 1
        assert results.count(False) == 49

    def test_concurrent_different_tokens_all_win(self, redis_url: str):
        """Each of 20 threads mints and consumes its own distinct token."""
        key = secrets.token_bytes(32)
        prefix = _unique_prefix()
        signer = ExecutionTokenSigner(secret_key=key)

        results: list[bool] = []
        lock = threading.Lock()

        def worker():
            token = signer.mint(_make_decision())
            r = _fresh_redis(redis_url)
            v = RedisExecutionTokenVerifier(secret_key=key, redis_client=r, key_prefix=prefix)
            with lock:
                results.append(v.consume(token))

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results)
        assert len(results) == 20


# ── consumed_count ─────────────────────────────────────────────────────────────


class TestRedisConsumedCount:
    def test_zero_initially(self, redis_url: str):
        _, _, redis_v = _signer_verifier(redis_url)
        assert redis_v.consumed_count() == 0

    def test_counts_valid_consumed(self, redis_url: str):
        signer, _, redis_v = _signer_verifier(redis_url)
        for _ in range(5):
            redis_v.consume(signer.mint(_make_decision()))
        assert redis_v.consumed_count() == 5

    def test_does_not_count_invalid(self, redis_url: str):
        """Rejected tokens (wrong key) must not pollute the count."""
        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)
        signer_a = ExecutionTokenSigner(secret_key=key_a)
        redis_v = RedisExecutionTokenVerifier(
            secret_key=key_b,
            redis_client=_fresh_redis(redis_url),
            key_prefix=_unique_prefix(),
        )
        token = signer_a.mint(_make_decision())
        redis_v.consume(token)  # will be rejected  -- nothing written to Redis
        assert redis_v.consumed_count() == 0

    def test_expired_keys_not_counted_after_ttl(self, redis_url: str):
        """Real Redis respects TTL  -- expired keys vanish from SCAN after TTL elapses."""
        key = secrets.token_bytes(32)
        r = _fresh_redis(redis_url)
        prefix = _unique_prefix()
        signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=1)
        redis_v = RedisExecutionTokenVerifier(secret_key=key, redis_client=r, key_prefix=prefix)

        token = signer.mint(_make_decision())
        redis_v.consume(token)
        assert redis_v.consumed_count() == 1

        # Wait for real TTL expiry then verify key is gone
        time.sleep(2)
        assert redis_v.consumed_count() == 0


# ── Redis key format ───────────────────────────────────────────────────────────


class TestRedisKeyFormat:
    def test_key_uses_prefix_and_token_id(self, redis_url: str):
        key = secrets.token_bytes(32)
        pfx = "test:pfx2:"
        r = _fresh_redis(redis_url)
        signer = ExecutionTokenSigner(secret_key=key)
        redis_v = RedisExecutionTokenVerifier(secret_key=key, redis_client=r, key_prefix=pfx)
        token = signer.mint(_make_decision())
        redis_v.consume(token)

        expected_key = f"{pfx}{token.token_id}"
        assert r.exists(expected_key) == 1

    def test_key_has_ttl(self, redis_url: str):
        key = secrets.token_bytes(32)
        r = _fresh_redis(redis_url)
        pfx = _unique_prefix()
        signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=30.0)
        redis_v = RedisExecutionTokenVerifier(secret_key=key, redis_client=r, key_prefix=pfx)
        token = signer.mint(_make_decision())
        redis_v.consume(token)

        redis_key = f"{pfx}{token.token_id}"
        ttl = r.ttl(redis_key)
        assert 0 < ttl <= 30


# ── Redis connection failure handling ─────────────────────────────────────────


class _BrokenRedis:
    """Stub that raises ConnectionError on every method call.

    Simulates a Redis server that is unreachable (network partition,
    container crash, DNS failure).  Not a mock  -- a real class with
    deterministic, documented behaviour.
    """

    def set(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")

    def get(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")

    def scan(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")

    def scan_iter(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")

    def exists(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")

    def ttl(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")

    def ping(self, *args: object, **kwargs: object) -> None:
        raise ConnectionError("Redis unreachable")


class TestRedisConnectionFailure:
    """Redis unavailability must never allow a token  -- fail closed."""

    def test_consume_fails_closed_on_connection_error(self):
        """If Redis is unreachable, consume() must return False (deny, not crash)."""
        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key)
        token = signer.mint(_make_decision())

        broken = _BrokenRedis()
        verifier = RedisExecutionTokenVerifier(
            secret_key=key,
            redis_client=broken,
        )
        # Must return False (fail-safe DENY), never raise
        result = verifier.consume(token)
        assert result is False

    def test_consumed_count_returns_zero_on_connection_error(self):
        """consumed_count() must not crash when Redis is unavailable."""
        key = secrets.token_bytes(32)
        broken = _BrokenRedis()
        verifier = RedisExecutionTokenVerifier(
            secret_key=key,
            redis_client=broken,
        )
        # Must return 0 (safe default), never raise
        count = verifier.consumed_count()
        assert count == 0

    def test_no_exception_propagates_on_connection_error(self):
        """No ConnectionError or any other exception must escape consume()."""
        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key)
        token = signer.mint(_make_decision())
        verifier = RedisExecutionTokenVerifier(
            secret_key=key,
            redis_client=_BrokenRedis(),
        )
        try:
            verifier.consume(token)
        except Exception as exc:
            pytest.fail(
                f"consume() raised {type(exc).__name__} when Redis was "
                f"unavailable  -- must silently return False instead: {exc}"
            )


# ── Compatibility: matches in-memory verifier ──────────────────────────────────


class TestCompatibilityWithInMemory:
    """RedisExecutionTokenVerifier must accept tokens minted for the in-memory verifier."""

    def test_same_token_accepted_by_both_verifiers(self, redis_url: str):
        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key)
        mem_v = ExecutionTokenVerifier(secret_key=key)
        redis_v = RedisExecutionTokenVerifier(
            secret_key=key,
            redis_client=_fresh_redis(redis_url),
            key_prefix=_unique_prefix(),
        )

        # Mint two distinct tokens  -- one per verifier
        token_for_mem = signer.mint(_make_decision())
        token_for_redis = signer.mint(_make_decision())

        assert mem_v.consume(token_for_mem) is True
        assert redis_v.consume(token_for_redis) is True

    def test_cross_verifier_type_replay_blocked(self, redis_url: str):
        """Consuming via in-memory does NOT prevent Redis from consuming (different stores)."""
        key = secrets.token_bytes(32)
        prefix = _unique_prefix()
        signer = ExecutionTokenSigner(secret_key=key)
        mem_v = ExecutionTokenVerifier(secret_key=key)
        redis_v = RedisExecutionTokenVerifier(
            secret_key=key,
            redis_client=_fresh_redis(redis_url),
            key_prefix=prefix,
        )

        token = signer.mint(_make_decision())
        assert mem_v.consume(token) is True
        # Redis has its own store  -- it has NOT seen this token, so it accepts
        assert redis_v.consume(token) is True
        # But Redis rejects a second attempt on the same token
        assert redis_v.consume(token) is False
