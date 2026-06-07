# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Integration tests for PostgresApprovalWorkflow.wait_for_decision() — T-HITL-01.

Verifies durable human-in-the-loop orchestration with a real Postgres 16
container.  Tests cross-server resume, distributed locking, and timeout
handling — the core of Deferral 2 / EU AI Act Article 14 compliance.

Requires: Docker + testcontainers (pip install 'pramanix[postgres]' testcontainers)
"""

from __future__ import annotations

import threading
import time

import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg not installed")

from pramanix.exceptions import OversightRequiredError
from pramanix.oversight.workflow import (
    ApprovalStatus,
    PostgresApprovalWorkflow,
)

from .conftest import requires_docker

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_workflow(pool: object, ttl: float = 60.0) -> PostgresApprovalWorkflow:
    """Build a PostgresApprovalWorkflow with a real pre-built pool."""
    wf = PostgresApprovalWorkflow(_pool=pool, default_ttl_s=ttl)
    wf.initialize()
    return wf


def _request(workflow: PostgresApprovalWorkflow, action: str = "wire $500,000") -> str:
    """Submit an approval request; capture and return its request_id."""
    try:
        workflow.request_approval(
            principal_id="agent-001",
            action=action,
            decision_id="dec-abc",
            policy_hash="sha256:cafe",
            intent_dump={"amount": "500000"},
            required_scopes=["FINANCIAL"],
            blast_radius="$500,000",
            reason="FINANCIAL scope requires dual-control approval",
        )
    except OversightRequiredError as exc:
        return exc.request_id
    raise AssertionError("request_approval must always raise OversightRequiredError")


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_docker
def test_wait_for_decision_approved(postgres_dsn: str) -> None:
    """wait_for_decision() returns APPROVED after reviewer approves."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=2, max_size=4)
        try:
            wf = _make_workflow(pool)
            rid = _request(wf)

            # Approve in a background thread after a short delay.
            def _approve() -> None:
                time.sleep(0.2)
                wf.approve(rid, reviewer_id="alice@corp.com", comment="Looks good")

            t = threading.Thread(target=_approve, daemon=True)
            t.start()

            result = wf.wait_for_decision(rid, timeout_s=10.0, poll_interval_s=0.1)
            t.join(timeout=5)

            assert result.status == ApprovalStatus.APPROVED
            assert result.reviewer_id == "alice@corp.com"
            assert result.request_id == rid
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wait_for_decision_rejected(postgres_dsn: str) -> None:
    """wait_for_decision() returns REJECTED after reviewer rejects."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=2, max_size=4)
        try:
            wf = _make_workflow(pool)
            rid = _request(wf, action="delete all records")

            def _reject() -> None:
                time.sleep(0.2)
                wf.reject(rid, reviewer_id="bob@corp.com", comment="Not authorised")

            t = threading.Thread(target=_reject, daemon=True)
            t.start()
            result = wf.wait_for_decision(rid, timeout_s=10.0, poll_interval_s=0.1)
            t.join(timeout=5)

            assert result.status == ApprovalStatus.REJECTED
            assert result.reviewer_id == "bob@corp.com"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wait_for_decision_timeout(postgres_dsn: str) -> None:
    """wait_for_decision() returns TIMEOUT when no reviewer acts within deadline."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=2)
        try:
            wf = _make_workflow(pool, ttl=300.0)
            rid = _request(wf)

            t0 = time.monotonic()
            result = wf.wait_for_decision(rid, timeout_s=0.3, poll_interval_s=0.1)
            elapsed = time.monotonic() - t0

            assert result.status == ApprovalStatus.TIMEOUT
            assert result.request_id == rid
            assert elapsed < 2.0, f"Timeout took {elapsed:.2f}s — should be ≤ 2s"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_wait_for_decision_cross_server_resume(postgres_dsn: str) -> None:
    """Any server (new workflow instance, same pool) can resume a paused workflow."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=2, max_size=4)
        try:
            # "Server A" submits the request.
            wf_a = _make_workflow(pool)
            rid = _request(wf_a, action="cross-server-test")

            # Simulate "Server A" crashing: wf_a is gone.
            # "Server B" is a fresh workflow instance with the same pool.
            wf_b = _make_workflow(pool)

            def _approve_on_b() -> None:
                time.sleep(0.2)
                wf_b.approve(rid, reviewer_id="carol@corp.com", comment="Cross-server OK")

            t = threading.Thread(target=_approve_on_b, daemon=True)
            t.start()

            # "Server B" waits — must see the approval from the same DB.
            result = wf_b.wait_for_decision(rid, timeout_s=10.0, poll_interval_s=0.1)
            t.join(timeout=5)

            assert result.status == ApprovalStatus.APPROVED
            assert result.reviewer_id == "carol@corp.com"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_concurrent_approve_only_one_succeeds(postgres_dsn: str) -> None:
    """SELECT FOR UPDATE prevents double-approval: only one concurrent approve wins."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=4, max_size=8)
        try:
            wf = _make_workflow(pool)
            rid = _request(wf, action="concurrent-lock-test")

            successes: list[object] = []
            failures: list[Exception] = []
            lock = threading.Lock()

            def _try_approve(reviewer: str) -> None:
                try:
                    rec = wf.approve(rid, reviewer_id=reviewer, comment="")
                    with lock:
                        successes.append(rec)
                except Exception as exc:
                    with lock:
                        failures.append(exc)

            # 5 concurrent approve attempts — only 1 must succeed.
            threads = [
                threading.Thread(target=_try_approve, args=(f"reviewer-{i}",)) for i in range(5)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)

            assert len(successes) == 1, (
                f"Expected exactly 1 successful approve, got {len(successes)} "
                f"(failures: {[str(f) for f in failures]})"
            )
            assert (
                len(failures) == 4
            ), f"Expected 4 KeyError failures (already decided), got {len(failures)}"
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_revoke_prevents_subsequent_approve(postgres_dsn: str) -> None:
    """After revoke(), approve() must raise KeyError (already decided)."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=2, max_size=4)
        try:
            wf = _make_workflow(pool)
            rid = _request(wf, action="revoke-then-approve-test")

            wf.revoke(rid, reviewer_id="admin@corp.com", comment="Policy change")

            with pytest.raises(KeyError, match="already been decided"):
                wf.approve(rid, reviewer_id="alice@corp.com", comment="Late approval")

            result = wf.wait_for_decision(rid, timeout_s=1.0, poll_interval_s=0.1)
            assert result.status == ApprovalStatus.REVOKED
        finally:
            await pool.close()

    asyncio.run(_run())


@requires_docker
def test_check_after_wait(postgres_dsn: str) -> None:
    """check() is consistent with wait_for_decision() verdict."""
    import asyncio

    async def _run() -> None:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=2, max_size=4)
        try:
            wf = _make_workflow(pool)
            rid = _request(wf, action="check-after-wait")
            wf.approve(rid, reviewer_id="alice@corp.com", comment="")

            result = wf.wait_for_decision(rid, timeout_s=5.0, poll_interval_s=0.1)
            assert result.status == ApprovalStatus.APPROVED
            assert wf.check(rid) is True
        finally:
            await pool.close()

    asyncio.run(_run())
