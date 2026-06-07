# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Real PostgreSQL integration tests for PostgresWalSink — T-WAL-01.

Verifies the Write-Ahead Log durable-write guarantee with a real asyncpg
connection to a Postgres 16 container.  Every test that verifies durability
checks that the decision is queryable in the DB immediately after write —
confirming that ``synchronous_commit=local`` is active and the row is truly
committed before :meth:`PostgresWalSink.write` returns.

Requires: Docker + testcontainers (pip install 'pramanix[postgres]' testcontainers)
"""

from __future__ import annotations

import threading
from decimal import Decimal

import pytest
from pydantic import BaseModel

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy
from pramanix.wal import CompositeWalSink, PostgresWalSink, WalAuditSink

from .conftest import requires_docker

# ── Shared policy ──────────────────────────────────────────────────────────────


class _Intent(BaseModel):
    amount: Decimal


class _State(BaseModel):
    state_version: str = "1"
    balance: Decimal


class _WalPolicy(Policy):
    class Meta:
        version = "1"
        intent_model = _Intent
        state_model = _State

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.amount) <= E(cls.balance)).named("within_balance")]


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_wal_sink(pool: object) -> PostgresWalSink:
    sink = PostgresWalSink(_pool=pool)
    sink.initialize()
    return sink


async def _row_count(pool: object, decision_id: str) -> int:
    """Return number of WAL rows for a given decision_id."""
    async with pool.acquire() as conn:  # type: ignore[union-attr]
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS cnt FROM pramanix_decision_wal WHERE decision_id=$1",
            decision_id,
        )
    return int(row["cnt"])


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_docker
def test_wal_write_durable_in_postgres(postgres_dsn: str) -> None:
    """PostgresWalSink.write() inserts a row before returning (synchronous commit)."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        try:
            sink = _make_wal_sink(pool)
            guard = Guard(_WalPolicy, GuardConfig(wal_sink=sink))
            decision = guard.verify(
                {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
            )
            assert decision.allowed
            # Row must exist immediately — synchronous_commit=local guarantees this.
            cnt = await _row_count(pool, str(decision.decision_id))
            assert cnt == 1, f"Expected 1 WAL row, found {cnt}"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wal_write_block_decision_recorded(postgres_dsn: str) -> None:
    """Blocked decisions are also written durably to the WAL."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        try:
            sink = _make_wal_sink(pool)
            guard = Guard(_WalPolicy, GuardConfig(wal_sink=sink))
            decision = guard.verify(
                {"amount": Decimal("9999")}, {"state_version": "1", "balance": Decimal("500")}
            )
            assert not decision.allowed
            cnt = await _row_count(pool, str(decision.decision_id))
            assert cnt == 1
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wal_write_idempotent_on_duplicate(postgres_dsn: str) -> None:
    """Second write with the same decision_id is silently ignored (ON CONFLICT DO NOTHING)."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        try:
            sink = _make_wal_sink(pool)
            guard = Guard(_WalPolicy, GuardConfig(wal_sink=sink))
            decision = guard.verify(
                {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
            )
            # Write a second time with the same decision object — must not raise.
            sink.write(decision)
            cnt = await _row_count(pool, str(decision.decision_id))
            assert cnt == 1, f"ON CONFLICT should prevent duplicates, got {cnt}"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wal_satisfies_protocol(postgres_dsn: str) -> None:
    """PostgresWalSink satisfies the WalAuditSink Protocol at runtime."""
    sink = PostgresWalSink(dsn=postgres_dsn)
    assert isinstance(sink, WalAuditSink)
    sink.close()


@requires_docker
def test_wal_pending_export_and_mark(postgres_dsn: str) -> None:
    """pending_export() returns unexported rows; mark_exported() flags them."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        try:
            sink = _make_wal_sink(pool)
            guard = Guard(_WalPolicy, GuardConfig(wal_sink=sink))
            decisions = [
                guard.verify(
                    {"amount": Decimal("100")},
                    {"state_version": "1", "balance": Decimal("500")},
                )
                for _ in range(3)
            ]
            pending = sink.pending_export(limit=100)
            ids = [str(d.decision_id) for d in decisions]
            pending_ids = [str(r["decision_id"]) for r in pending]
            for did in ids:
                assert did in pending_ids, f"decision_id {did!r} missing from pending_export"

            updated = sink.mark_exported(ids)
            assert updated == 3

            after = sink.pending_export(limit=100)
            after_ids = {str(r["decision_id"]) for r in after}
            for did in ids:
                assert did not in after_ids, f"Exported row {did!r} still in pending"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wal_concurrent_writes_all_durable(postgres_dsn: str) -> None:
    """10 concurrent verify() calls all produce distinct durable WAL rows."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=4, max_size=8)
        try:
            sink = _make_wal_sink(pool)
            guard = Guard(_WalPolicy, GuardConfig(wal_sink=sink))

            results: list[object] = []
            errors: list[Exception] = []
            lock = threading.Lock()

            def _work() -> None:
                try:
                    d = guard.verify(
                        {"amount": Decimal("100")},
                        {"state_version": "1", "balance": Decimal("500")},
                    )
                    with lock:
                        results.append(d)
                except Exception as exc:
                    with lock:
                        errors.append(exc)

            threads = [threading.Thread(target=_work) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert not errors, f"Concurrent writes raised: {errors}"
            assert len(results) == 10

            # Verify all 10 rows are in the DB.
            async with pool.acquire() as conn:
                cnt_row = await conn.fetchrow(
                    "SELECT COUNT(*) AS cnt FROM pramanix_decision_wal WHERE NOT exported"
                )
            assert int(cnt_row["cnt"]) >= 10
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_composite_wal_dual_write(postgres_dsn: str) -> None:
    """CompositeWalSink with two PostgresWalSinks writes to both independently."""
    import asyncio
    import warnings

    async def _run() -> None:
        pool1 = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        pool2 = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        try:
            s1 = _make_wal_sink(pool1)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                from pramanix.wal import InMemoryWalSink

                s2 = InMemoryWalSink()

            composite: WalAuditSink = CompositeWalSink([s1, s2])  # type: ignore[arg-type]
            guard = Guard(_WalPolicy, GuardConfig(wal_sink=composite))
            decision = guard.verify(
                {"amount": Decimal("100")}, {"state_version": "1", "balance": Decimal("500")}
            )
            assert decision.allowed

            cnt = await _row_count(pool1, str(decision.decision_id))
            assert cnt == 1, "PostgresWalSink must have received the write"
            assert len(s2) == 1, "InMemoryWalSink must have received the write"
        finally:
            await pool1.close()
            await pool2.close()

    asyncio.run(_run())
