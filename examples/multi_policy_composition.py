#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Multi-policy composition example — two guards, both must pass.

Demonstrates:
* Running two independent Guards sequentially (composition)
* Policy 1: Financial safety (balance, daily limit)
* Policy 2: RBAC — only authorised roles can initiate transfers
* A transaction allowed by finance but blocked by RBAC never goes through

Run::

    python examples/multi_policy_composition.py
"""
from __future__ import annotations

from decimal import Decimal

from pramanix import Field, Guard, GuardConfig, Policy
from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit
from pramanix.primitives.rbac import RoleMustBeIn

# ── Policy definitions ────────────────────────────────────────────────────────


class FinancialPolicy(Policy):
    """Enforces balance and daily-limit invariants."""

    class Meta:
        name = "financial_safety"
        version = "1.0"

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list:
        return [
            NonNegativeBalance(cls.balance, cls.amount),
            UnderDailyLimit(cls.amount, cls.daily_limit),
        ]


class AuthorisationPolicy(Policy):
    """Enforces that only teller (1) and manager (2) roles can transfer."""

    class Meta:
        name = "transfer_authorisation"
        version = "1.0"

    role = Field("role", int, "Int")

    @classmethod
    def invariants(cls) -> list:
        return [RoleMustBeIn(cls.role, [1, 2])]  # 1=teller, 2=manager


# ── Guard instances (created once at startup) ─────────────────────────────────

_config = GuardConfig(execution_mode="sync")
finance_guard = Guard(FinancialPolicy, _config)
auth_guard = Guard(AuthorisationPolicy, _config)


def verify_transfer(
    *,
    amount: Decimal,
    balance: Decimal,
    daily_limit: Decimal,
    role: int,
) -> bool:
    """Verify a transfer against both guards; both must allow."""
    fin_state = {
        "balance": balance,
        "daily_limit": daily_limit,
        "state_version": "1.0",
    }
    auth_state = {"state_version": "1.0"}

    fin_decision = finance_guard.verify(intent={"amount": amount}, state=fin_state)
    auth_decision = auth_guard.verify(intent={"role": role}, state=auth_state)

    allowed = fin_decision.allowed and auth_decision.allowed
    print(
        f"  amount={amount} balance={balance} role={role} → "
        f"finance={fin_decision.status.value} auth={auth_decision.status.value} "
        f"→ {'✅ ALLOW' if allowed else '🚫 BLOCK'}"
    )
    if not fin_decision.allowed:
        print(f"    Finance violations: {fin_decision.violated_invariants}")
    if not auth_decision.allowed:
        print(f"    Auth violations:    {auth_decision.violated_invariants}")
    return allowed


def run() -> None:
    print("=== Multi-Policy Composition: Finance + RBAC ===\n")

    # Scenario A: Teller, sufficient funds → ALLOW both
    result = verify_transfer(
        amount=Decimal("100"), balance=Decimal("500"),
        daily_limit=Decimal("1000"), role=1,
    )
    assert result

    # Scenario B: Manager, over daily limit → BLOCK (finance)
    result = verify_transfer(
        amount=Decimal("2000"), balance=Decimal("5000"),
        daily_limit=Decimal("1000"), role=2,
    )
    assert not result

    # Scenario C: External role (99), sufficient funds → BLOCK (auth)
    result = verify_transfer(
        amount=Decimal("50"), balance=Decimal("500"),
        daily_limit=Decimal("1000"), role=99,
    )
    assert not result

    # Scenario D: Teller, overdraft → BLOCK (finance)
    result = verify_transfer(
        amount=Decimal("1000"), balance=Decimal("100"),
        daily_limit=Decimal("2000"), role=1,
    )
    assert not result

    print("\n✅ All multi-policy composition scenarios passed.")


if __name__ == "__main__":
    run()
