# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for ExecutionToken / ExecutionTokenSigner and verifier constructors.

These tests cover logic that does NOT require a real database:
  - ExecutionToken.is_allowed() (pure dataclass method)
  - PostgresExecutionTokenVerifier constructor validation (ValueError before pool)
  - RedisExecutionTokenVerifier state_version mismatch (uses real fakeredis)

All PostgresExecutionTokenVerifier database tests (consume, double-spend, pool
reuse, consume_within, etc.) live in:
  tests/integration/test_postgres_token.py
"""
from __future__ import annotations

import time

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.execution_token import ExecutionToken, ExecutionTokenSigner

_SECRET = b"test_secret_key_32_bytes_exact!!"


def _allowed_decision() -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="allowed",
    )


# ── ExecutionToken.is_allowed() ───────────────────────────────────────────────


@pytest.fixture
def signer() -> ExecutionTokenSigner:
    return ExecutionTokenSigner(_SECRET, ttl_seconds=60.0)


def test_is_allowed_returns_true_for_allowed_token(signer: ExecutionTokenSigner) -> None:
    token = signer.mint(_allowed_decision())
    assert token.is_allowed() is True


def test_is_allowed_returns_false_for_denied_token() -> None:
    token = ExecutionToken(
        decision_id="x",
        allowed=False,
        intent_dump={},
        policy_hash=None,
        expires_at=time.time() + 60,
        token_id="t1",
        signature="",
    )
    assert token.is_allowed() is False


# ── PostgresExecutionTokenVerifier constructor validation ─────────────────────


def test_init_raises_value_error_for_short_key() -> None:
    """ValueError is raised before any asyncpg pool creation for a short key."""
    pytest.importorskip("asyncpg")
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    with pytest.raises(ValueError, match="at least 16 bytes"):
        PostgresExecutionTokenVerifier(b"tooshort", "postgresql://test/db")


# ── RedisExecutionTokenVerifier state_version mismatch ───────────────────────


def test_redis_verifier_rejects_token_with_state_version_mismatch() -> None:
    """RedisExecutionTokenVerifier returns False when state_version != expected."""
    import fakeredis

    from pramanix.execution_token import RedisExecutionTokenVerifier

    redis = fakeredis.FakeRedis()
    verifier = RedisExecutionTokenVerifier(_SECRET, redis)
    signer = ExecutionTokenSigner(_SECRET, ttl_seconds=60.0)

    token = signer.mint(_allowed_decision(), state_version="v1")
    assert verifier.consume(token, expected_state_version="v2") is False
    assert verifier.consume(token, expected_state_version="v1") is True
