# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real Postgres integration tests for PostgresExecutionTokenVerifier — T-03.

Tests run against a real Postgres 16 container started by testcontainers.
Validates behaviour that in-memory fakes cannot replicate:
  - Real UniqueViolationError on duplicate token consumption (double-spend)
  - Real connection pool under concurrent consume() calls (H-11)
  - Real TIMESTAMPTZ expiry semantics
  - consume_within() with real asyncpg connection in caller-managed transaction
"""
from __future__ import annotations

import threading
import time
from collections.abc import Generator
from dataclasses import replace
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.execution_token import (
    ExecutionTokenSigner,
    PostgresExecutionTokenVerifier,
)

from .conftest import requires_docker

_SECRET = b"real-postgres-integration-secret-32bytes"
_SIGNER = ExecutionTokenSigner(_SECRET, ttl_seconds=60.0)


def _allowed_decision(**kwargs: Any) -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="allowed",
        **kwargs,
    )


@pytest.fixture
def verifier(postgres_dsn: str) -> Generator[PostgresExecutionTokenVerifier, None, None]:
    """Fresh PostgresExecutionTokenVerifier backed by a real Postgres container."""
    v = PostgresExecutionTokenVerifier(_SECRET, postgres_dsn)
    yield v
    v.close()


# ── Basic consume() ───────────────────────────────────────────────────────────


@requires_docker
def test_postgres_token_mint_and_consume(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """A token minted and consumed against real Postgres succeeds once."""
    token = _SIGNER.mint(_allowed_decision())
    assert verifier.consume(token) is True


@requires_docker
def test_postgres_token_double_spend_rejected(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """Consuming the same token twice fails on the second attempt.

    The UniqueViolationError from real Postgres triggers the double-spend guard.
    An in-memory fake would never raise this error correctly.
    """
    token = _SIGNER.mint(_allowed_decision())
    assert verifier.consume(token) is True
    assert verifier.consume(token) is False, "Double-spend must be rejected by real Postgres"


@requires_docker
def test_postgres_token_expired_is_rejected(postgres_dsn: str) -> None:
    """A token with 1-second TTL is rejected after it expires."""
    signer = ExecutionTokenSigner(_SECRET, ttl_seconds=1.0)
    v = PostgresExecutionTokenVerifier(_SECRET, postgres_dsn)
    try:
        token = signer.mint(_allowed_decision())
        time.sleep(2.0)
        assert v.consume(token) is False, "Expired token must be rejected"
    finally:
        v.close()


@requires_docker
def test_postgres_token_tampered_signature_rejected(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """A token with a tampered signature is rejected before Postgres is queried."""
    token = _SIGNER.mint(_allowed_decision())
    tampered = replace(token, signature="00" * 32)
    assert verifier.consume(tampered) is False


@requires_docker
def test_postgres_token_state_version_mismatch_rejected(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """State version mismatch causes rejection before Postgres is queried."""
    token = _SIGNER.mint(_allowed_decision(), state_version="v1")
    assert verifier.consume(token, expected_state_version="v2") is False
    assert verifier.consume(token, expected_state_version="v1") is True


# ── Concurrent consume() — real UniqueViolationError ─────────────────────────


@requires_docker
def test_postgres_token_concurrent_consume_only_one_succeeds(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """Concurrent consume() calls on the same token: exactly one wins.

    Real Postgres PRIMARY KEY constraint enforces single consumption even under
    concurrent requests.  An asyncio fake serialises all operations and cannot
    detect the race.
    """
    token = _SIGNER.mint(_allowed_decision())
    outcomes: list[bool] = []
    lock = threading.Lock()

    def _try_consume() -> None:
        result = verifier.consume(token)
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=_try_consume) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(True) == 1, f"Exactly one consume should succeed, got {outcomes}"
    assert outcomes.count(False) == 9


# ── Pool reuse (H-11) ─────────────────────────────────────────────────────────


@requires_docker
def test_postgres_token_pool_reuse_under_load(postgres_dsn: str) -> None:
    """Pool is reused across 50 sequential consume() calls without exhausting connections.

    H-11: _async_consume was opening a new connection per call.  Real Postgres
    has a max_connections limit; the pool must reuse connections.
    """
    v = PostgresExecutionTokenVerifier(_SECRET, postgres_dsn)
    try:
        tokens = [_SIGNER.mint(_allowed_decision()) for _ in range(50)]
        successes = sum(1 for t in tokens if v.consume(t) is True)
        assert successes == 50, "All 50 unique tokens should be consumed successfully"
    finally:
        v.close()


# ── evict_expired() and consumed_count() ─────────────────────────────────────


@requires_docker
def test_postgres_token_evict_expired_returns_zero_for_fresh_tokens(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """evict_expired() returns 0 when no expired rows exist."""
    token = _SIGNER.mint(_allowed_decision())
    verifier.consume(token)
    assert verifier.evict_expired() == 0


@requires_docker
def test_postgres_consumed_count_increments(
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """consumed_count() reflects the number of non-expired tokens consumed."""
    initial = verifier.consumed_count()
    token = _SIGNER.mint(_allowed_decision())
    verifier.consume(token)
    assert verifier.consumed_count() == initial + 1


# ── consume_within() — real asyncpg connection ───────────────────────────────


@requires_docker
@pytest.mark.asyncio
async def test_consume_within_valid_token(
    postgres_dsn: str,
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """consume_within() returns True for a valid token using a real connection."""
    token = _SIGNER.mint(_allowed_decision())
    conn = await asyncpg.connect(postgres_dsn)
    try:
        result = await verifier.consume_within(conn, token)
        assert result is True
    finally:
        await conn.close()


@requires_docker
@pytest.mark.asyncio
async def test_consume_within_duplicate_returns_false(
    postgres_dsn: str,
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """Second consume_within call for the same token returns False (UniqueViolationError)."""
    token = _SIGNER.mint(_allowed_decision())
    conn = await asyncpg.connect(postgres_dsn)
    try:
        assert await verifier.consume_within(conn, token) is True
        assert await verifier.consume_within(conn, token) is False
    finally:
        await conn.close()


@requires_docker
@pytest.mark.asyncio
async def test_consume_within_tampered_signature_rejected(
    postgres_dsn: str,
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """consume_within() rejects a tampered token without touching Postgres."""
    token = _SIGNER.mint(_allowed_decision())
    bad = replace(token, signature="cafebabe" * 8)
    conn = await asyncpg.connect(postgres_dsn)
    try:
        assert await verifier.consume_within(conn, bad) is False
    finally:
        await conn.close()


@requires_docker
@pytest.mark.asyncio
async def test_consume_within_state_version_mismatch(
    postgres_dsn: str,
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """consume_within() returns False when state_version does not match."""
    token = _SIGNER.mint(_allowed_decision(), state_version="v1")
    conn = await asyncpg.connect(postgres_dsn)
    try:
        assert await verifier.consume_within(conn, token, expected_state_version="v2") is False
        assert await verifier.consume_within(conn, token, expected_state_version="v1") is True
    finally:
        await conn.close()


@requires_docker
@pytest.mark.asyncio
async def test_consume_within_transaction_rollback_allows_retry(
    postgres_dsn: str,
    verifier: PostgresExecutionTokenVerifier,
) -> None:
    """Rolling back a transaction that contained consume_within allows the token to be reused.

    consume_within does NOT commit — the caller controls the transaction boundary.
    If the caller's business logic fails and rolls back, the token consumption
    is also rolled back (atomically), allowing the whole operation to be retried.
    """
    token = _SIGNER.mint(_allowed_decision())

    # Consume within a transaction and then roll it back
    conn1 = await asyncpg.connect(postgres_dsn)
    try:
        async with conn1.transaction():
            result = await verifier.consume_within(conn1, token)
            assert result is True
            raise ValueError("intentional rollback for test")
    except ValueError:
        pass  # rollback triggered
    finally:
        await conn1.close()

    # After rollback, the same token must be consumable again
    conn2 = await asyncpg.connect(postgres_dsn)
    try:
        result2 = await verifier.consume_within(conn2, token)
        assert result2 is True, "Token must be re-consumable after its transaction was rolled back"
    finally:
        await conn2.close()
