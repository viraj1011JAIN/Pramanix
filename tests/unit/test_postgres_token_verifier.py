# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for PostgresExecutionTokenVerifier (E-1)."""
from __future__ import annotations

import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

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


def test_postgres_verifier_raises_config_error_without_asyncpg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "asyncpg", None)
    if "pramanix.execution_token" in sys.modules:
        del sys.modules["pramanix.execution_token"]
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[postgres\\]'"):
        from pramanix.execution_token import PostgresExecutionTokenVerifier
        PostgresExecutionTokenVerifier(_SECRET, _DSN)


# ── Mocked asyncpg tests ──────────────────────────────────────────────────────


def _make_mock_asyncpg() -> MagicMock:
    """Build a mock asyncpg module with create_pool as AsyncMock."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=None)
    mock_pool_cm = AsyncMock()
    mock_pool_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool_cm.__aexit__ = AsyncMock(return_value=False)
    mock_pool = MagicMock()
    mock_pool.acquire = MagicMock(return_value=mock_pool_cm)
    mock_pool.close = AsyncMock()
    mock_pkg = MagicMock()
    mock_pkg.create_pool = AsyncMock(return_value=mock_pool)
    return mock_pkg


def test_postgres_verifier_init(monkeypatch: pytest.MonkeyPatch) -> None:
    """PostgresExecutionTokenVerifier stores secret as self._key."""
    mock_pkg = _make_mock_asyncpg()

    with patch.dict(sys.modules, {"asyncpg": mock_pkg}):
        if "pramanix.execution_token" in sys.modules:
            del sys.modules["pramanix.execution_token"]
        from pramanix.execution_token import PostgresExecutionTokenVerifier

        v = PostgresExecutionTokenVerifier(_SECRET, _DSN)
        assert v._key == _SECRET


def test_postgres_verifier_consume_bad_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tokens with invalid HMAC signatures are rejected without DB access."""
    mock_pkg = _make_mock_asyncpg()

    with patch.dict(sys.modules, {"asyncpg": mock_pkg}):
        if "pramanix.execution_token" in sys.modules:
            del sys.modules["pramanix.execution_token"]
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
        v = PostgresExecutionTokenVerifier(_SECRET, _DSN)
        result = v.consume(token)
    assert result is False


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


def test_postgres_verifier_expired_token_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tokens with a past expires_at are rejected before DB access."""
    mock_pkg = _make_mock_asyncpg()

    with patch.dict(sys.modules, {"asyncpg": mock_pkg}):
        if "pramanix.execution_token" in sys.modules:
            del sys.modules["pramanix.execution_token"]
        from pramanix.execution_token import PostgresExecutionTokenVerifier

        signer = ExecutionTokenSigner(secret_key=_SECRET, ttl_seconds=-100.0)
        decision = _allowed_decision()
        token = signer.mint(decision)  # expires_at already in the past

        v = PostgresExecutionTokenVerifier(_SECRET, _DSN)
        result = v.consume(token)
    assert result is False
