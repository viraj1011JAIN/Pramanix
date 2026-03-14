#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
fintech_killshot.py — Multi-layer FinTech compliance with Z3-verified constraints.

Demonstrates Pramanix's advantage over LangChain callbacks, LlamaIndex
guardrails, and AutoGen validation hooks: every constraint is formally
verified by the Z3 SMT solver — NOT a regex, NOT an LLM call, NOT a heuristic.

Compliance stack demonstrated
------------------------------
  ① OFAC SDN Sanctions Screen      (31 CFR § 501.805)
  ② Reg. T Initial Margin Check    (12 CFR § 220 — 50% margin requirement)
  ③ Anti-Structuring Detection     (31 CFR § 1020.320 — BSA $10,000 CTR)
  ④ Sufficient Balance Pre-Check   (BSA / Reg. E)
  ⑤ KYC Tier Enforcement           (FATF Rec. 10 / FinCEN CDD Rule)

Every NO decision includes a machine-readable violation label, the exact
regulatory citation embedded in the ConstraintExpr explanation, and a
cryptographically-derived decision_id for audit trails.

Run::

    python examples/fintech_killshot.py
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pydantic import BaseModel

from pramanix import Decision, Field, Guard, GuardConfig, Policy
from pramanix.primitives.fintech import (
    AntiStructuring,
    KYCTierCheck,
    MarginRequirement,
    SanctionsScreen,
    SufficientBalance,
)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Domain models
# ═══════════════════════════════════════════════════════════════════════════════


class TradeIntent(BaseModel):
    """Proposed trade execution from the AI agent / algorithmic system."""

    amount: Decimal
    """Notional USD value of the proposed trade."""

    cumulative_24h: Decimal
    """Rolling 24-hour aggregate transaction volume for structuring detection."""


class TradeState(BaseModel):
    """Observable pre-trade state — injected from real-time risk engine."""

    state_version: str
    balance: Decimal
    account_equity: Decimal
    position_value: Decimal
    counterparty_flagged: bool
    kyc_tier: int


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Composite compliance policy
# ═══════════════════════════════════════════════════════════════════════════════


class FintechCompliancePolicy(Policy):
    """Five-layer FinTech compliance guardrail — Z3-verified, not LLM-inferred.

    A single call to ``guard.verify()`` atomically checks all five constraints.
    Z3 reports *all* violated constraints simultaneously — no waterfall of
    individual checks, no silent short-circuits.
    """

    class Meta:
        version = "0.6"
        intent_model = TradeIntent
        state_model = TradeState

    # Field declarations
    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")
    cumulative_24h = Field("cumulative_24h", Decimal, "Real")
    account_equity = Field("account_equity", Decimal, "Real")
    position_value = Field("position_value", Decimal, "Real")
    counterparty_flagged = Field("counterparty_flagged", bool, "Bool")
    kyc_tier = Field("kyc_tier", int, "Int")

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            # ① OFAC SDN check — zero tolerance, immediate hard stop
            SanctionsScreen(cls.counterparty_flagged),
            # ② Sufficient balance pre-authorisation
            SufficientBalance(cls.balance, cls.amount),
            # ③ Anti-structuring — BSA CTR threshold $10,000
            AntiStructuring(cls.cumulative_24h, Decimal("10_000")),
            # ④ Reg. T initial margin — 50% equity cover
            MarginRequirement(cls.account_equity, cls.position_value, Decimal("0.50")),
            # ⑤ KYC CDD tier — minimum Standard (tier 2) for derivatives
            KYCTierCheck(cls.kyc_tier, required_tier=2),
        ]


guard = Guard(FintechCompliancePolicy, config=GuardConfig(solver_timeout_ms=5_000))


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
# 4. Scenarios — the killshots
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_clean_trade() -> Decision:
    """All five compliance layers pass — trade approved."""
    return guard.verify(
        intent={"amount": Decimal("5_000"), "cumulative_24h": Decimal("7_000")},
        state={
            "state_version": "0.6",
            "balance": Decimal("100_000"),
            "account_equity": Decimal("60_000"),
            "position_value": Decimal("100_000"),
            "counterparty_flagged": False,
            "kyc_tier": 3,
        },
    )


def scenario_ofac_hit() -> Decision:
    """SDN-listed counterparty — immediate hard block regardless of financials."""
    return guard.verify(
        intent={"amount": Decimal("5_000"), "cumulative_24h": Decimal("7_000")},
        state={
            "state_version": "0.6",
            "balance": Decimal("100_000"),
            "account_equity": Decimal("60_000"),
            "position_value": Decimal("100_000"),
            "counterparty_flagged": True,  # ← OFAC SDN match
            "kyc_tier": 3,
        },
    )


def scenario_structuring_alert() -> Decision:
    """Cumulative 24h amount hits CTR threshold — SAR investigation required."""
    return guard.verify(
        intent={"amount": Decimal("1_000"), "cumulative_24h": Decimal("10_000")},
        state={
            "state_version": "0.6",
            "balance": Decimal("100_000"),
            "account_equity": Decimal("60_000"),
            "position_value": Decimal("100_000"),
            "counterparty_flagged": False,
            "kyc_tier": 3,
        },
    )


def scenario_margin_call() -> Decision:
    """Equity below Reg. T 50% threshold — trade blocked."""
    return guard.verify(
        intent={"amount": Decimal("1_000"), "cumulative_24h": Decimal("500")},
        state={
            "state_version": "0.6",
            "balance": Decimal("100_000"),
            "account_equity": Decimal("30_000"),  # ← 30% < 50% required
            "position_value": Decimal("100_000"),
            "counterparty_flagged": False,
            "kyc_tier": 3,
        },
    )


def scenario_kyc_insufficient() -> Decision:
    """Anonymous (tier 0) customer — CDD rule blocks derivatives trading."""
    return guard.verify(
        intent={"amount": Decimal("1_000"), "cumulative_24h": Decimal("500")},
        state={
            "state_version": "0.6",
            "balance": Decimal("100_000"),
            "account_equity": Decimal("60_000"),
            "position_value": Decimal("100_000"),
            "counterparty_flagged": False,
            "kyc_tier": 0,  # ← No CDD performed
        },
    )


def scenario_three_simultaneous_violations() -> Decision:
    """Z3 reports all three violations atomically — not sequentially."""
    return guard.verify(
        intent={"amount": Decimal("5_000"), "cumulative_24h": Decimal("11_000")},
        state={
            "state_version": "0.6",
            "balance": Decimal("1_000"),      # ← insufficient
            "account_equity": Decimal("10_000"),  # ← margin call
            "position_value": Decimal("100_000"),
            "counterparty_flagged": True,     # ← OFAC hit
            "kyc_tier": 0,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Main
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("PRAMANIX — FinTech Compliance Killshot")
    print("Z3 SMT-verified constraints | Not an LLM | Not a regex")
    print("=" * 70)

    _print("CLEAN TRADE (all 5 layers pass)", scenario_clean_trade())
    _print("OFAC SDN HIT (sanctions screen)", scenario_ofac_hit())
    _print("STRUCTURING ALERT (31 CFR § 1020.320)", scenario_structuring_alert())
    _print("MARGIN CALL (Reg. T — 50% floor)", scenario_margin_call())
    _print("KYC INSUFFICIENT (FATF Rec. 10)", scenario_kyc_insufficient())
    _print("3-WAY VIOLATION (OFAC + overdraft + margin)", scenario_three_simultaneous_violations())

    print("\n" + "=" * 70)
    print("All scenarios complete — every decision is cryptographically audited.")
    print("=" * 70)
