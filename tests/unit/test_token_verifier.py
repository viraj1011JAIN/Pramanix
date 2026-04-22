# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase E-1: Redis-Free Token Verification Backends.

Gate condition (from engineering plan):
    pytest -k 'token_verifier'
    # All backends must pass the same compliance test suite.
    # A token used once must be rejected on second use.
    # A token must expire correctly.
"""
from __future__ import annotations

import secrets
import time
from decimal import Decimal
from typing import Any

import pytest

from pramanix import (
    ExecutionTokenSigner,
    ExecutionTokenVerifier,
    Field,
    Guard,
    GuardConfig,
    InMemoryExecutionTokenVerifier,
    Policy,
    SQLiteExecutionTokenVerifier,
)
from pramanix.execution_token import ExecutionToken

# ── Shared fixtures ───────────────────────────────────────────────────────────

_SECRET = secrets.token_bytes(32)
_amt = Field("amount", Decimal, "Real")
_bal = Field("balance", Decimal, "Real")


class _P(Policy):
    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls):  # type: ignore[override]
        from pramanix import E

        return [
            (E(_amt) <= Decimal("10000")).named("max_tx"),
            (E(_bal) - E(_amt) >= 0).named("funds"),
        ]


def _make_token(ttl: float = 30.0) -> ExecutionToken:
    guard = Guard(_P, GuardConfig(solver_timeout_ms=5000))
    d = guard.verify(
        intent={"amount": Decimal("100")},
        state={"balance": Decimal("500")},
    )
    signer = ExecutionTokenSigner(secret_key=_SECRET, ttl_seconds=ttl)
    return signer.mint(d)


# ═══════════════════════════════════════════════════════════════════════════════
# Compliance suite — parameterized over all backends
# ═══════════════════════════════════════════════════════════════════════════════


def _make_verifier(backend: str) -> Any:
    if backend == "memory_legacy":
        return ExecutionTokenVerifier(secret_key=_SECRET)
    if backend == "memory_explicit":
        return InMemoryExecutionTokenVerifier(secret_key=_SECRET)
    if backend == "sqlite":
        return SQLiteExecutionTokenVerifier(secret_key=_SECRET, db_path=":memory:")
    raise ValueError(f"Unknown backend: {backend}")


BACKENDS = ["memory_legacy", "memory_explicit", "sqlite"]


@pytest.mark.parametrize("backend", BACKENDS)
class TestTokenVerifierCompliance:
    """Identical compliance tests run against every backend."""

    def test_valid_token_returns_true(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        token = _make_token()
        assert verifier.consume(token) is True

    def test_second_consume_returns_false(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        token = _make_token()
        assert verifier.consume(token) is True
        assert verifier.consume(token) is False

    def test_expired_token_returns_false(self, backend: str) -> None:
        token = _make_token(ttl=0.001)
        time.sleep(0.05)
        verifier = _make_verifier(backend)
        assert verifier.consume(token) is False

    def test_tampered_signature_returns_false(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        token = _make_token()
        bad = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature="0" * len(token.signature),
            state_version=token.state_version,
        )
        assert verifier.consume(bad) is False

    def test_state_version_mismatch_returns_false(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        guard = Guard(_P, GuardConfig(solver_timeout_ms=5000))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        signer = ExecutionTokenSigner(secret_key=_SECRET)
        token = signer.mint(d, state_version="v1")
        # Consuming with wrong version must fail.
        assert verifier.consume(token, expected_state_version="v2") is False

    def test_state_version_match_returns_true(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        guard = Guard(_P, GuardConfig(solver_timeout_ms=5000))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        signer = ExecutionTokenSigner(secret_key=_SECRET)
        token = signer.mint(d, state_version="v1")
        assert verifier.consume(token, expected_state_version="v1") is True

    def test_wrong_secret_key_returns_false(self, backend: str) -> None:
        other_key = secrets.token_bytes(32)
        if backend == "memory_legacy":
            verifier = ExecutionTokenVerifier(secret_key=other_key)
        elif backend == "memory_explicit":
            verifier = InMemoryExecutionTokenVerifier(secret_key=other_key)
        else:
            verifier = SQLiteExecutionTokenVerifier(secret_key=other_key, db_path=":memory:")
        token = _make_token()
        assert verifier.consume(token) is False

    def test_different_tokens_each_consumed_once(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        t1 = _make_token()
        t2 = _make_token()
        assert verifier.consume(t1) is True
        assert verifier.consume(t2) is True
        assert verifier.consume(t1) is False
        assert verifier.consume(t2) is False

    def test_consumed_count_increments(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        t1 = _make_token()
        t2 = _make_token()
        verifier.consume(t1)
        verifier.consume(t2)
        assert verifier.consumed_count() >= 2

    def test_evict_expired_reduces_count(self, backend: str) -> None:
        verifier = _make_verifier(backend)
        short_token = _make_token(ttl=0.001)
        verifier.consume(short_token)
        time.sleep(0.05)
        evicted = verifier.evict_expired()
        assert evicted >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# SQLite-specific tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSQLiteTokenVerifier:
    def test_persists_across_verifier_instances(self, tmp_path) -> None:
        db = str(tmp_path / "tokens.db")
        v1 = SQLiteExecutionTokenVerifier(secret_key=_SECRET, db_path=db)
        token = _make_token()
        assert v1.consume(token) is True
        v1.close()

        # Second verifier instance on same DB should see the token as consumed.
        v2 = SQLiteExecutionTokenVerifier(secret_key=_SECRET, db_path=db)
        assert v2.consume(token) is False
        v2.close()

    def test_wal_mode_enabled(self, tmp_path) -> None:
        db = str(tmp_path / "tokens.db")
        v = SQLiteExecutionTokenVerifier(secret_key=_SECRET, db_path=db)
        import sqlite3

        conn = sqlite3.connect(db)
        cur = conn.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
        conn.close()
        v.close()
        assert mode == "wal"

    def test_table_created_on_init(self, tmp_path) -> None:
        db = str(tmp_path / "tokens.db")
        v = SQLiteExecutionTokenVerifier(secret_key=_SECRET, db_path=db)
        import sqlite3

        conn = sqlite3.connect(db)
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='consumed_tokens'"
        )
        assert cur.fetchone() is not None
        conn.close()
        v.close()

    def test_short_secret_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            SQLiteExecutionTokenVerifier(secret_key=b"short", db_path=":memory:")


# ═══════════════════════════════════════════════════════════════════════════════
# InMemoryExecutionTokenVerifier-specific tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestInMemoryExecutionTokenVerifier:
    def test_is_subclass_of_base_verifier(self) -> None:
        assert issubclass(InMemoryExecutionTokenVerifier, ExecutionTokenVerifier)

    def test_short_secret_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            InMemoryExecutionTokenVerifier(secret_key=b"short")

    def test_basic_consume(self) -> None:
        v = InMemoryExecutionTokenVerifier(secret_key=_SECRET)
        t = _make_token()
        assert v.consume(t) is True
        assert v.consume(t) is False
