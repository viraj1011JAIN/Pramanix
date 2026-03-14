# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Financial constraint primitives for Pramanix policies.

Each factory returns a :class:`~pramanix.expressions.ConstraintExpr` with
``.named()`` and ``.explain()`` pre-set and ready to include in a Policy's
``invariants()`` list.

Example::

    from decimal import Decimal
    from pramanix import Policy, Field
    from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit

    class BankingPolicy(Policy):
        balance     = Field("balance",     Decimal, "Real")
        amount      = Field("amount",      Decimal, "Real")
        daily_limit = Field("daily_limit", Decimal, "Real")

        @classmethod
        def invariants(cls):
            return [
                NonNegativeBalance(cls.balance, cls.amount),
                UnderDailyLimit(cls.amount, cls.daily_limit),
            ]
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pramanix.expressions import E

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "NonNegativeBalance",
    "UnderDailyLimit",
    "UnderSingleTxLimit",
    "RiskScoreBelow",
    "SecureBalance",
    "MinimumReserve",
]


def NonNegativeBalance(balance: Field, amount: Field) -> ConstraintExpr:
    """Enforce that the post-transaction balance is non-negative.

    DSL: ``(E(balance) - E(amount) >= 0)``

    Args:
        balance: Field representing the current account balance.
        amount:  Field representing the transfer/withdrawal amount.
    """
    return (
        (E(balance) - E(amount) >= 0)
        .named("non_negative_balance")
        .explain(
            "Insufficient funds: balance ({balance}) minus amount ({amount}) "
            "would be negative."
        )
    )


def UnderDailyLimit(amount: Field, daily_limit: Field) -> ConstraintExpr:
    """Enforce that the transaction amount does not exceed the daily limit.

    DSL: ``(E(amount) <= E(daily_limit))``

    Args:
        amount:      Field representing the transaction amount.
        daily_limit: Field representing the rolling daily transfer cap.
    """
    return (
        (E(amount) <= E(daily_limit))
        .named("under_daily_limit")
        .explain(
            "Daily limit exceeded: amount ({amount}) exceeds daily_limit ({daily_limit})."
        )
    )


def UnderSingleTxLimit(amount: Field, tx_limit: Field) -> ConstraintExpr:
    """Enforce that the transaction amount does not exceed the per-transaction limit.

    DSL: ``(E(amount) <= E(tx_limit))``

    Args:
        amount:   Field representing the transaction amount.
        tx_limit: Field representing the single-transaction cap.
    """
    return (
        (E(amount) <= E(tx_limit))
        .named("under_single_tx_limit")
        .explain(
            "Single-transaction limit exceeded: amount ({amount}) "
            "exceeds tx_limit ({tx_limit})."
        )
    )


def RiskScoreBelow(risk_score: Field, threshold: Field) -> ConstraintExpr:
    """Enforce that the risk score is strictly below the danger threshold.

    DSL: ``(E(risk_score) < E(threshold))``

    Args:
        risk_score: Field representing the computed risk score (0-100).
        threshold:  Field representing the maximum acceptable risk score.
    """
    return (
        (E(risk_score) < E(threshold))
        .named("risk_score_below_threshold")
        .explain(
            "Risk score too high: risk_score ({risk_score}) >= threshold ({threshold})."
        )
    )


def SecureBalance(
    balance: Field, amount: Field, minimum_reserve: Field
) -> ConstraintExpr:
    """Enforce a post-transaction minimum-reserve floor.

    Security-hardened replacement for :func:`NonNegativeBalance`.  Instead
    of ``balance - amount >= 0``, this primitive checks
    ``balance - amount >= minimum_reserve``, preventing full-drain attacks
    and ensuring a non-trivial floor even for zero-reserve configurations.

    Use this primitive in any policy that handles real monetary value.
    Pair it with a policy ``Field`` for ``minimum_reserve`` (e.g. 0.01).

    DSL: ``(E(balance) - E(amount) >= E(minimum_reserve))``

    Args:
        balance:         Field representing the current account balance.
        amount:          Field representing the transfer/withdrawal amount.
        minimum_reserve: Field for the minimum post-transaction balance floor.

    Example::

        minimum_reserve = Field("minimum_reserve", Decimal, "Real")

        SecureBalance(cls.balance, cls.amount, cls.minimum_reserve)
    """
    return (
        (E(balance) - E(amount) >= E(minimum_reserve))
        .named("minimum_reserve_maintained")
        .explain(
            "Transfer blocked: post-transaction balance ({balance} - {amount}) "
            "would fall below the minimum reserve ({minimum_reserve})."
        )
    )


def MinimumReserve(
    balance: Field, amount: Field, minimum_reserve: Field
) -> ConstraintExpr:
    """Alias for :func:`SecureBalance` — identical semantics.

    Prefer :func:`SecureBalance` for new policies.  This alias is provided
    for readability when the field is named ``minimum_reserve``.
    """
    return SecureBalance(balance, amount, minimum_reserve)
