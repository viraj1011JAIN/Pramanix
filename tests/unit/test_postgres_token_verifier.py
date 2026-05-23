# SPDX-License-Identifier: AGPL-3.0-only
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for PostgresExecutionTokenVerifier (E-1)."""

from __future__ import annotations

import importlib.util as _ilu
import time

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import ConfigurationError
from pramanix.execution_token import (
    ExecutionToken,
    ExecutionTokenSigner,
    SQLiteExecutionTokenVerifier,
)

# Shared secret — bytes, at least 16
_SECRET = b"test_secret_key_16bytes!"
_DSN = "postgresql://localhost/test"


def _allowed_decision() -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="allowed for test",
    )


# ── Import guard ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(
    _ilu.find_spec("asyncpg") is not None,
    reason="run in tox:no-asyncpg — asyncpg is installed in this env",
)
def test_postgres_verifier_raises_config_error_without_asyncpg() -> None:
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[postgres\\]'"):
        PostgresExecutionTokenVerifier(_SECRET, _DSN)


# ── Pool-injection tests (no real Postgres connection) ────────────────────────


class _ConnStub:
    async def execute(self, sql: str, *args: object) -> None:
        pass


class _AcquireCtx:
    async def __aenter__(self) -> _ConnStub:
        return _ConnStub()

    async def __aexit__(self, *_: object) -> None:
        pass


class _PoolStub:
    def acquire(self) -> _AcquireCtx:
        return _AcquireCtx()

    async def close(self) -> None:
        pass


def test_postgres_verifier_init() -> None:
    """PostgresExecutionTokenVerifier stores secret as self._key."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    v = PostgresExecutionTokenVerifier(_SECRET, _DSN, _pool=_PoolStub())
    assert v._key == _SECRET


def test_postgres_verifier_consume_bad_signature() -> None:
    """Tokens with invalid HMAC signatures are rejected without DB access."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    token = ExecutionToken(
        decision_id="test-decision-id",
        allowed=True,
        intent_dump={},
        policy_hash=None,
        expires_at=time.time() + 300,
        token_id="test-token-id",
        signature="incorrect_hmac_signature",
    )
    v = PostgresExecutionTokenVerifier(_SECRET, _DSN, _pool=_PoolStub())
    assert v.consume(token) is False


def test_postgres_verifier_single_use_with_sqlite() -> None:
    """Single-use enforcement works via the shared SQLite verifier."""
    signer = ExecutionTokenSigner(secret_key=_SECRET, ttl_seconds=300.0)
    verifier = SQLiteExecutionTokenVerifier(secret_key=_SECRET, db_path=":memory:")

    decision = _allowed_decision()
    token = signer.mint(decision, state_version="v1")

    # First consume: must succeed
    assert verifier.consume(token, expected_state_version="v1") is True
    # Second consume: must fail (replay protection)
    assert verifier.consume(token, expected_state_version="v1") is False


def test_postgres_verifier_expired_token_rejected() -> None:
    """Tokens with a past expires_at are rejected before DB access."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    signer = ExecutionTokenSigner(secret_key=_SECRET, ttl_seconds=-100.0)
    decision = _allowed_decision()
    token = signer.mint(decision)  # expires_at already in the past

    v = PostgresExecutionTokenVerifier(_SECRET, _DSN, _pool=_PoolStub())
    assert v.consume(token) is False
