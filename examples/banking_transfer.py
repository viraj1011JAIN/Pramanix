#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
banking_transfer.py — Pramanix reference implementation for banking transfers.

Demonstrates:
  * Policy definition with Field declarations and named invariants
  * Pydantic intent / state models and Policy.Meta version pinning
  * Guard construction and synchronous verification
  * All six decision outcomes: SAFE, UNSAFE, TIMEOUT (simulated), ERROR (simulated),
    STALE_STATE, and VALIDATION_FAILURE

Run directly::

    python examples/banking_transfer.py
"""
from __future__ import annotations

import sys
from decimal import Decimal

# ── Must be importable from the repository root with `python examples/...` ───
# Adjust sys.path so the src layout works without installation when running
# the file directly.
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pydantic import BaseModel

from pramanix import (
    Decision,
    E,
    Field,
    Guard,
    GuardConfig,
    Policy,
    SolverStatus,
)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Pydantic models — intent and state schemas
# ═══════════════════════════════════════════════════════════════════════════════


class TransferIntent(BaseModel):
    """What the AI agent *wants* to do — the proposed action."""

    amount: Decimal
    """Transfer amount in the account's base currency."""


class AccountState(BaseModel):
    """Current observable state of the account — must include state_version."""

    state_version: str
    """Version tag matching Policy.Meta.version — used for stale-state detection."""

    balance: Decimal
    """Current account balance."""

    daily_limit: Decimal
    """Maximum single-transaction amount permitted per policy."""

    is_frozen: bool
    """Whether the account has been administratively frozen."""


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Policy definition
# ═══════════════════════════════════════════════════════════════════════════════


class BankingPolicy(Policy):
    """Formal safety policy for outbound banking transfers.

    Three invariants must all hold simultaneously for a transfer to be approved:

    1. ``non_negative_balance``  — balance must not go below zero after transfer
    2. ``within_daily_limit``    — single transfer must not exceed the daily limit
    3. ``account_not_frozen``    — frozen accounts cannot transact
    """

    class Meta:
        """Guard metadata: version pinning and Pydantic model associations."""

        version = "1.0"
        intent_model = TransferIntent
        state_model = AccountState

    # ── Field declarations ────────────────────────────────────────────────────
    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    is_frozen = Field("is_frozen", bool, "Bool")

    # ── Formal invariants ─────────────────────────────────────────────────────
    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft prevented: balance={balance} < amount={amount}"),
            (E(cls.amount) <= E(cls.daily_limit))
            .named("within_daily_limit")
            .explain(
                "Daily limit exceeded: amount={amount} > daily_limit={daily_limit}"
            ),
            (E(cls.is_frozen) == False)  # noqa: E712
            .named("account_not_frozen")
            .explain("Account is frozen — all transfers blocked"),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Guard construction
# ═══════════════════════════════════════════════════════════════════════════════

guard = Guard(
    BankingPolicy,
    config=GuardConfig(solver_timeout_ms=5_000),
)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Helper
# ═══════════════════════════════════════════════════════════════════════════════


def _print(d: Decision) -> None:
    indicator = "✓ SAFE   " if d.allowed else "✗ BLOCKED"
    print(
        f"  [{indicator}] status={d.status.value:<20} "
        f"violated={list(d.violated_invariants)}"
    )
    if not d.allowed:
        print(f"             explanation: {d.explanation}")
    print(f"             decision_id: {d.decision_id}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Scenarios
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_a_safe() -> Decision:
    """A: Normal transfer — all invariants satisfied."""
    return guard.verify(
        intent={"amount": Decimal("500.00")},
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": False,
            "state_version": "1.0",
        },
    )


def scenario_b_overdraft() -> Decision:
    """B: Overdraft attempt — non_negative_balance violated."""
    return guard.verify(
        intent={"amount": Decimal("1_500.00")},
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": False,
            "state_version": "1.0",
        },
    )


def scenario_c_multi_violation() -> Decision:
    """C: Overdraft + frozen account — two invariants violated simultaneously."""
    return guard.verify(
        intent={"amount": Decimal("2_000.00")},
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": True,
            "state_version": "1.0",
        },
    )


def scenario_d_boundary_exact() -> Decision:
    """D: Exact boundary — balance == amount → SAT (zero remaining is allowed)."""
    return guard.verify(
        intent={"amount": Decimal("1_000.00")},
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": False,
            "state_version": "1.0",
        },
    )


def scenario_e_one_over_boundary() -> Decision:
    """E: One cent over balance — amount = balance + 0.01 → UNSAT."""
    return guard.verify(
        intent={"amount": Decimal("1_000.01")},
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": False,
            "state_version": "1.0",
        },
    )


def scenario_f_stale_state() -> Decision:
    """F: State version mismatch — policy expects 1.0, state carries 0.9."""
    return guard.verify(
        intent={"amount": Decimal("100.00")},
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": False,
            "state_version": "0.9",  # ← stale
        },
    )


def scenario_g_validation_failure() -> Decision:
    """G: Pydantic strict-mode rejection — amount is a string, not Decimal."""
    return guard.verify(
        intent={"amount": "not-a-number"},  # type: ignore[arg-type]
        state={
            "balance": Decimal("1_000.00"),
            "daily_limit": Decimal("5_000.00"),
            "is_frozen": False,
            "state_version": "1.0",
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Main
# ═══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    print("═" * 72)
    print("  Pramanix — Banking Transfer Reference Scenarios")
    print("═" * 72)
    print()

    scenarios = [
        ("A — Normal transfer (SAFE)", scenario_a_safe),
        ("B — Overdraft attempt (UNSAFE)", scenario_b_overdraft),
        ("C — Overdraft + frozen account (UNSAFE, two violations)", scenario_c_multi_violation),
        ("D — Exact boundary: balance == amount (SAFE)", scenario_d_boundary_exact),
        ("E — One cent over boundary (UNSAFE)", scenario_e_one_over_boundary),
        ("F — Stale state version (STALE_STATE)", scenario_f_stale_state),
        ("G — Validation failure: bad intent type (VALIDATION_FAILURE)", scenario_g_validation_failure),
    ]

    failures: list[str] = []

    for name, fn in scenarios:
        print(f"Scenario {name}")
        d = fn()
        _print(d)

        # Quick smoke assertions so the script exits non-zero on regression
        if "(SAFE)" in name and not d.allowed:
            failures.append(f"{name}: expected SAFE, got {d.status}")
        if "(UNSAFE" in name and d.allowed:
            failures.append(f"{name}: expected UNSAFE, got {d.status}")
        if "STALE_STATE" in name and d.status is not SolverStatus.STALE_STATE:
            failures.append(f"{name}: expected STALE_STATE, got {d.status}")
        if "VALIDATION_FAILURE" in name and d.status is not SolverStatus.VALIDATION_FAILURE:
            failures.append(f"{name}: expected VALIDATION_FAILURE, got {d.status}")

    print("═" * 72)
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  ✗ {f}")
        sys.exit(1)
    else:
        print("  All scenarios produced expected decisions.")
        print("═" * 72)


if __name__ == "__main__":
    main()
