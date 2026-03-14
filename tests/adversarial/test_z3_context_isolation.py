# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Adversarial test — T4: Z3 context isolation under concurrent load.

Security threat: T4 — Z3 context poisoning via cross-worker AST sharing.

Z3's C++ core is NOT thread-safe across a shared ``z3.Context()``.  If two
threads create Z3 variables with the same name in the same context, the
second thread's ``Real("balance")`` is the same Z3 AST node as the first
thread's — binding thread A's value resolves thread B's formula, silently
producing an incorrect (and potentially exploitable) decision.

Mitigation under test:
    ``solve()`` creates a private ``z3.Context()`` per call, isolating every
    verification from concurrent activity.  See
    ``src/pramanix/solver.py:solve`` and ``docs/security.md §T4``.

What this test does:
    1. Spins up 10 concurrent threads (mimicking 10 simultaneous API requests).
    2. Each thread runs ``Guard.verify()`` with a *unique* balance/amount pair.
    3. The expected decision for every thread is precomputed deterministically.
    4. After all threads complete, ALL decisions must match their own inputs —
       no thread may receive another thread's result (no cross-contamination).
    5. No ``Z3Exception`` may escape from any thread.
    6. No ``Decision(allowed=True)`` may be returned from a thread whose
       balance < amount (the classic context-poisoning exploit).

Test design follows the CTO's "sledgehammer" brief:
    * Use ``threading.Barrier`` to maximise the probability of concurrent
      context access (all 10 solves launch simultaneously).
    * Each scenario uses a distinct balance gap so there is zero ambiguity in
      which thread produced any given result.
"""
from __future__ import annotations

import threading
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import SolverStatus

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr

# ── Shared policy (same class — only field VALUES differ per thread) ──────────


class _BankingPolicy(Policy):
    """Simple single-invariant policy.  All 10 threads use this same class,
    which exercises the exact failure mode of T4 — multiple threads calling
    ``Guard.verify()`` against the *same* policy, building the Z3 formula from
    the same ``Field`` descriptors but with different runtime values.
    """

    class Meta:
        version = "1.0"
        name = "isolation_test"

    # Using Decimal/Real so valuations span a large range and collisions are
    # trivially detectable.
    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= Decimal("0")).named(
                "non_negative_balance"
            )
        ]


# Shared guard, sync mode — 10 threads all call guard.verify() concurrently.
_GUARD = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))


# ── Scenario table ─────────────────────────────────────────────────────────────
# Each row: (thread_id, balance, amount, expected_allowed)
# Rows 0-4: SAFE (balance > amount by a distinct margin).
# Rows 5-9: UNSAFE (amount > balance by a distinct margin).
# Zero ambiguity: no two rows share the same outcome *due to another row's
# values* — the sentinel gap makes cross-contamination immediately visible.

_SCENARIOS: list[tuple[int, Decimal, Decimal, bool]] = [
    (0, Decimal("1000.00"), Decimal("100.00"), True),   # safe by 900
    (1, Decimal("2000.00"), Decimal("500.00"), True),   # safe by 1500
    (2, Decimal("5000.00"), Decimal("999.99"), True),   # safe by ~4000
    (3, Decimal("10.00"),   Decimal("9.99"),   True),   # safe by 0.01
    (4, Decimal("50000.00"), Decimal("1.00"),  True),   # very safe
    (5, Decimal("100.00"),  Decimal("100.01"), False),  # unsafe by 0.01
    (6, Decimal("0.00"),    Decimal("1.00"),   False),  # zero balance
    (7, Decimal("999.99"),  Decimal("1000.00"), False), # unsafe by 0.01
    (8, Decimal("250.00"),  Decimal("500.00"),  False), # unsafe by 250
    (9, Decimal("1.00"),    Decimal("99999.00"), False),# wildly unsafe
]


# ── Thread worker ──────────────────────────────────────────────────────────────


def _run_scenario(
    tid: int,
    balance: Decimal,
    amount: Decimal,
    expected_allowed: bool,
    barrier: threading.Barrier,
    results: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Run one Guard.verify() call, store the outcome for later assertion."""
    try:
        # All threads block here until all 10 are ready — maximises concurrency
        # at the Z3 solve stage.
        barrier.wait(timeout=10.0)

        decision = _GUARD.verify(
            intent={"amount": amount},
            state={"balance": balance, "state_version": "1.0"},
        )
        results[tid] = {
            "allowed": decision.allowed,
            "status": decision.status,
            "balance": balance,
            "amount": amount,
            "expected": expected_allowed,
        }
    except Exception as exc:
        errors.append(f"Thread {tid}: {type(exc).__name__}: {exc}")


# ── Test class ─────────────────────────────────────────────────────────────────


class TestZ3ContextIsolation:
    """Concurrent Guard.verify() calls on 10 threads must not cross-contaminate."""

    def _run_all(self) -> tuple[list[dict[str, Any]], list[str]]:
        """Launch 10 threads simultaneously and collect results."""
        n = len(_SCENARIOS)
        results: list[dict[str, Any]] = [{}] * n
        errors: list[str] = []
        barrier = threading.Barrier(n)

        threads = [
            threading.Thread(
                target=_run_scenario,
                args=(tid, bal, amt, exp, barrier, results, errors),
                daemon=True,
                name=f"z3-isolation-{tid}",
            )
            for tid, bal, amt, exp in _SCENARIOS
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        return results, errors

    # ── Gate tests ─────────────────────────────────────────────────────────────

    def test_no_z3_exceptions_propagate(self) -> None:
        """No thread may raise a Z3Exception or any other uncaught error."""
        _, errors = self._run_all()
        assert errors == [], (
            f"Z3 exceptions escaped in {len(errors)} thread(s):\n"
            + "\n".join(errors)
        )

    def test_all_threads_produce_decisions(self) -> None:
        """Every thread slot must have been populated with a result dict."""
        results, _ = self._run_all()
        empty = [i for i, r in enumerate(results) if not r]
        assert empty == [], f"Threads {empty} produced no result (timed out?)"

    def test_correct_decision_for_each_thread(self) -> None:
        """Every Decision must match the *own* thread's balance/amount, not any
        other thread's balance/amount.  This is the T4 isolation check."""
        results, errors = self._run_all()
        assert not errors, f"Threads raised exceptions: {errors}"

        failures = []
        for r in results:
            if not r:
                failures.append("Empty result slot — thread may have timed out.")
                continue
            if r["allowed"] != r["expected"]:
                failures.append(
                    f"Thread balance={r['balance']} amount={r['amount']}: "
                    f"expected allowed={r['expected']}, got allowed={r['allowed']} "
                    f"(status={r['status']}). "
                    "POSSIBLE Z3 CONTEXT CONTAMINATION — another thread's values "
                    "were used in this thread's solver."
                )

        assert not failures, "\n".join(failures)

    def test_safe_threads_never_return_unsafe(self) -> None:
        """T4 worst-case: a SAFE thread returns UNSAFE due to an UNSAFE thread's
        binding polluting the shared context.  All 5 SAFE threads must be SAFE."""
        results, _ = self._run_all()
        for r in results:
            if not r:
                continue
            if r["expected"] is True:
                assert r["allowed"] is True and r["status"] is SolverStatus.SAFE, (
                    f"SAFE scenario (balance={r['balance']}, amount={r['amount']}) "
                    f"returned allowed={r['allowed']}, status={r['status']}. "
                    "Z3 context contamination from a concurrent UNSAFE thread is suspected."
                )

    def test_unsafe_threads_never_return_safe(self) -> None:
        """T4 worst-case: an UNSAFE thread returns SAFE due to a SAFE thread's
        binding polluting the context.  All 5 UNSAFE threads must be UNSAFE."""
        results, _ = self._run_all()
        for r in results:
            if not r:
                continue
            if r["expected"] is False:
                assert r["allowed"] is False, (
                    f"UNSAFE scenario (balance={r['balance']}, amount={r['amount']}) "
                    f"returned allowed=True. "
                    "Z3 context contamination from a concurrent SAFE thread is suspected. "
                    "This is the exact exploit vector described in T4."
                )

    def test_status_is_consistent_with_allowed(self) -> None:
        """Invariant: allowed=True ↔ status=SAFE; allowed=False ↔ UNSAFE/ERROR/etc."""
        results, _ = self._run_all()
        for r in results:
            if not r:
                continue
            if r["allowed"]:
                assert r["status"] is SolverStatus.SAFE, (
                    f"allowed=True but status={r['status']} — Decision consistency violated."
                )
            else:
                assert r["status"] is not SolverStatus.SAFE, (
                    "allowed=False but status=SAFE — Decision consistency violated."
                )

    def test_repeated_runs_are_deterministic(self) -> None:
        """Run the full 10-thread scenario three times and verify identical outcomes.
        Non-determinism indicates a data race in the Z3 layer."""
        all_outcomes = []
        for _run in range(3):
            results, errors = self._run_all()
            assert not errors, f"Run {_run}: errors: {errors}"
            outcomes = tuple(r.get("allowed") for r in results)
            all_outcomes.append(outcomes)

        assert all_outcomes[0] == all_outcomes[1] == all_outcomes[2], (
            f"Non-deterministic outcomes across 3 runs:\n"
            f"  Run 0: {all_outcomes[0]}\n"
            f"  Run 1: {all_outcomes[1]}\n"
            f"  Run 2: {all_outcomes[2]}\n"
            "This indicates a data race in the Z3 context layer."
        )
