# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for pramanix.wal — Write-Ahead Log sinks.

All tests use real objects: real Guard, real Policy, real Z3 solver, real
InMemoryWalSink.  No mocks, no monkeypatching.
"""

from __future__ import annotations

import threading
from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ConfigurationError, WalWriteError
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy
from pramanix.wal import CompositeWalSink, InMemoryWalSink, WalAuditSink

# ── Shared policy fixture ─────────────────────────────────────────────────────


class _Intent(BaseModel):
    amount: Decimal


class _State(BaseModel):
    state_version: str = "1"
    balance: Decimal


class _TransferPolicy(Policy):
    class Meta:
        version = "1"
        intent_model = _Intent
        state_model = _State

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.amount) <= E(cls.balance)).named("within_balance")]


def _make_guard(wal_sink: WalAuditSink | None = None) -> Guard:
    return Guard(_TransferPolicy, GuardConfig(wal_sink=wal_sink))


# ── InMemoryWalSink ───────────────────────────────────────────────────────────


class TestInMemoryWalSink:
    def test_protocol_check(self):
        """InMemoryWalSink satisfies the WalAuditSink protocol."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink()
        assert isinstance(sink, WalAuditSink)

    def test_write_stores_decision(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink()
        guard = _make_guard(wal_sink=sink)
        decision = guard.verify(
            {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert decision.allowed
        assert len(sink) == 1
        assert sink.entries[0].allowed

    def test_write_blocked_decision_also_recorded(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink()
        guard = _make_guard(wal_sink=sink)
        decision = guard.verify(
            {"amount": Decimal("1000")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert not decision.allowed
        assert len(sink) == 1
        assert not sink.entries[0].allowed

    def test_raise_after_forces_block(self):
        """Guard force-converts ALLOW → BLOCK when WAL write fails."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            # Fail on first write
            sink = InMemoryWalSink(raise_after=0)
        guard = _make_guard(wal_sink=sink)
        # The request is ALLOW (100 <= 500) but WAL fails — must get BLOCK
        decision = guard.verify(
            {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert (
            not decision.allowed
        ), "Guard must force BLOCK when WAL write fails (fail-closed invariant)"
        assert "Write-Ahead Log failure" in (decision.explanation or "")

    def test_clear_resets_entries(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink()
        guard = _make_guard(wal_sink=sink)
        guard.verify({"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")})
        assert len(sink) == 1
        sink.clear()
        assert len(sink) == 0

    def test_max_entries_eviction(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink(max_entries=2)
        guard = _make_guard(wal_sink=sink)
        for _ in range(4):
            guard.verify(
                {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
            )
        assert len(sink) == 2

    def test_production_env_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="PRAMANIX_ENV=production"):
            InMemoryWalSink()

    def test_thread_safe_concurrent_writes(self):
        """Multiple threads writing concurrently must not corrupt the list."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink()
        guard = _make_guard(wal_sink=sink)
        errors: list[Exception] = []
        lock = threading.Lock()

        def _write() -> None:
            try:
                guard.verify(
                    {"amount": Decimal("100")},
                    {"state_version": "1", "balance": Decimal("500")},
                )
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_write) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Concurrent writes raised: {errors}"
        assert len(sink) == 10


# ── CompositeWalSink ──────────────────────────────────────────────────────────


class TestCompositeWalSink:
    def _make_sink(self, raise_after: int | None = None) -> InMemoryWalSink:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            return InMemoryWalSink(raise_after=raise_after)

    def test_writes_to_all_sinks(self):
        s1 = self._make_sink()
        s2 = self._make_sink()
        composite = CompositeWalSink([s1, s2])
        guard = _make_guard(wal_sink=composite)
        guard.verify(
            {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert len(s1) == 1
        assert len(s2) == 1

    def test_raises_if_one_sink_fails(self):
        s_good = self._make_sink()
        s_bad = self._make_sink(raise_after=0)
        composite = CompositeWalSink([s_good, s_bad])
        guard = _make_guard(wal_sink=composite)
        # CompositeWalSink raises → Guard forces BLOCK
        decision = guard.verify(
            {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert not decision.allowed
        assert "Write-Ahead Log failure" in (decision.explanation or "")

    def test_empty_sinks_raises_configuration_error(self):
        with pytest.raises(ConfigurationError, match="at least one"):
            CompositeWalSink([])

    def test_three_sinks_all_succeed(self):
        sinks = [self._make_sink() for _ in range(3)]
        composite = CompositeWalSink(sinks)  # type: ignore[arg-type]
        guard = _make_guard(wal_sink=composite)
        for _ in range(5):
            guard.verify(
                {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
            )
        for s in sinks:
            assert len(s) == 5


# ── WalWriteError ─────────────────────────────────────────────────────────────


class TestWalWriteError:
    def test_attributes(self):
        err = WalWriteError("test error", decision_id="abc", backend="PostgresWalSink")
        assert err.decision_id == "abc"
        assert err.backend == "PostgresWalSink"
        assert "test error" in str(err)

    def test_is_pramanix_error(self):
        from pramanix.exceptions import PramanixError

        err = WalWriteError("oops")
        assert isinstance(err, PramanixError)

    def test_guard_force_block_on_wal_error(self):
        """When WAL raises WalWriteError, Guard must return a BLOCK decision."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            sink = InMemoryWalSink(raise_after=0)
        guard = _make_guard(wal_sink=sink)
        decision = guard.verify(
            {"amount": Decimal("50")}, {"state_version": "1", "balance": Decimal("1000")}
        )
        # The Z3 result is ALLOW (50 <= 1000), but WAL failed → must be BLOCK
        assert not decision.allowed
        assert "Write-Ahead Log" in (decision.explanation or "")


# ── No-WAL path (wal_sink=None) ───────────────────────────────────────────────


class TestNoWalSink:
    def test_verify_works_without_wal(self):
        """When wal_sink=None, verify() works normally (backwards compatible)."""
        guard = _make_guard(wal_sink=None)
        decision = guard.verify(
            {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert decision.allowed

    def test_verify_block_without_wal(self):
        guard = _make_guard(wal_sink=None)
        decision = guard.verify(
            {"amount": Decimal("1000")}, {"state_version": "1", "balance": Decimal("500")}
        )
        assert not decision.allowed
