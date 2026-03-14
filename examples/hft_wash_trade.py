#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
hft_wash_trade.py — IRC § 1091 Wash-Sale Detection via Z3 SMT solver.

This example demonstrates Pramanix's "abs-free" reformulation of the
30-day wash-sale test.  The Z3 DSL does not support symbolic abs(), so
|sell_epoch - buy_epoch| >= 30 * 86400 is expressed as an OR constraint:

    (sell - buy >= window) | (buy - sell >= window)

This is mathematically identical to the absolute-value form, but requires
only Z3 linear integer arithmetic — making it provably decidable in
polynomial time.

Regulatory background
---------------------
IRS IRC § 1091: If you sell or trade stock/securities at a loss AND buy
substantially identical securities within 30 days before or after the sale,
you cannot deduct the loss.  The disallowed loss is added to the cost basis
of the new position.

HFT relevance: algorithmic strategies that generate synthetic wash sales
(e.g., pairs trading with correlated ETFs) can inadvertently trigger § 1091.
Pramanix detects this at order-entry time, before the trade is submitted.

Run::

    python examples/hft_wash_trade.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pydantic import BaseModel

from pramanix import Decision, Field, Guard, GuardConfig, Policy
from pramanix.primitives.fintech import WashSaleDetection

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Domain models
# ═══════════════════════════════════════════════════════════════════════════════


class RepurchaseIntent(BaseModel):
    """The AI agent's proposed buy order — repurchase after a loss sale."""

    buy_epoch: int
    """UNIX timestamp of the proposed repurchase."""


class SaleHistory(BaseModel):
    """Historical sell event retrieved from the trade journal."""

    state_version: str
    sell_epoch: int
    """UNIX timestamp when the original loss-generating sale occurred."""


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Policy
# ═══════════════════════════════════════════════════════════════════════════════


class WashSalePolicy(Policy):
    """Enforce IRC § 1091 wash-sale disallowance window.

    The constraint is evaluated at order-entry time — before the trade hits
    the exchange.  If the repurchase falls within 30 calendar days of the
    sale, the order is blocked and the tax-lot is flagged for manual review.
    """

    class Meta:
        version = "0.6"
        intent_model = RepurchaseIntent
        state_model = SaleHistory

    sell_epoch = Field("sell_epoch", int, "Int")
    buy_epoch = Field("buy_epoch", int, "Int")

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            WashSaleDetection(cls.sell_epoch, cls.buy_epoch, wash_window_days=30),
        ]


guard = Guard(WashSalePolicy, config=GuardConfig(solver_timeout_ms=5_000))

# Reference timestamps (2024-01-15 midnight UTC)
_SALE_EPOCH = 1_705_276_800


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Print helper
# ═══════════════════════════════════════════════════════════════════════════════


def _print(label: str, d: Decision) -> None:
    symbol = "✓" if d.allowed else "✗"
    print(f"\n{symbol} [{label}]")
    print(f"  allowed  : {d.allowed}")
    print(f"  status   : {d.status.value}")
    if d.violated_invariants:
        print(f"  violated : {sorted(d.violated_invariants)}")
    if d.explanation:
        print(f"  reason   : {d.explanation}")
    print(f"  audit_id : {d.decision_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Scenarios
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_clean_repurchase_61_days_later() -> Decision:
    """Repurchase 61 days after sale — well outside the wash window."""
    buy = _SALE_EPOCH + 61 * 86_400
    return guard.verify(
        intent={"buy_epoch": buy},
        state={"state_version": "0.6", "sell_epoch": _SALE_EPOCH},
    )


def scenario_wash_sale_10_days_later() -> Decision:
    """Repurchase 10 days after sale — inside the 30-day wash window. BLOCKED."""
    buy = _SALE_EPOCH + 10 * 86_400
    return guard.verify(
        intent={"buy_epoch": buy},
        state={"state_version": "0.6", "sell_epoch": _SALE_EPOCH},
    )


def scenario_wash_sale_before_sale() -> Decision:
    """Repurchase 5 days BEFORE the sale — § 1091 is symmetric. BLOCKED."""
    buy = _SALE_EPOCH - 5 * 86_400
    return guard.verify(
        intent={"buy_epoch": buy},
        state={"state_version": "0.6", "sell_epoch": _SALE_EPOCH},
    )


def scenario_boundary_exactly_30_days() -> Decision:
    """Repurchase exactly 30 days after sale — at the boundary. ALLOWED (>=)."""
    buy = _SALE_EPOCH + 30 * 86_400
    return guard.verify(
        intent={"buy_epoch": buy},
        state={"state_version": "0.6", "sell_epoch": _SALE_EPOCH},
    )


def scenario_boundary_29_days_23_hours() -> Decision:
    """One hour inside the 30-day window — still BLOCKED."""
    buy = _SALE_EPOCH + 30 * 86_400 - 3_600
    return guard.verify(
        intent={"buy_epoch": buy},
        state={"state_version": "0.6", "sell_epoch": _SALE_EPOCH},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Main
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("PRAMANIX — HFT Wash-Sale Detection (IRC § 1091)")
    print("Abs-free Z3 disjunction | Decidable in polynomial time")
    print("=" * 70)

    _print("CLEAN: repurchase 61 days later", scenario_clean_repurchase_61_days_later())
    _print("WASH SALE: repurchase 10 days later", scenario_wash_sale_10_days_later())
    _print("WASH SALE: repurchase BEFORE sale (5 days prior)", scenario_wash_sale_before_sale())
    _print("BOUNDARY: exactly 30 days (allowed)", scenario_boundary_exactly_30_days())
    _print("BOUNDARY: 29d 23h (blocked, 1h before window)", scenario_boundary_29_days_23_hours())

    print("\n" + "=" * 70)
    print("Every timestamp comparison is exact integer arithmetic — no float drift.")
    print("=" * 70)
