#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
autogen_multi_agent.py — Two-agent financial system with Pramanix safety gates.

A CFO agent requests fund transfers via a tool. A Pramanix-guarded execution
agent intercepts every tool call and formally verifies it against treasury
policy before execution. Blocked calls return structured rejection messages
that the CFO agent can read and adapt to — not opaque 403 errors.

Compatible with AutoGen >= 0.2 (ConversableAgent pattern).

Install: pip install 'pramanix[autogen]' pyautogen

Run:
    OPENAI_API_KEY=... python examples/autogen_multi_agent.py
"""
from __future__ import annotations

import asyncio
import json
from decimal import Decimal
from typing import Any

from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.autogen import PramanixToolCallback


# ── Treasury policy ───────────────────────────────────────────────────────────

_amount    = Field("amount",      Decimal, "Real")
_balance   = Field("balance",     Decimal, "Real")
_threshold = Field("threshold",   Decimal, "Real")   # single-signature limit

class TreasuryPolicy(Policy):
    """CFO treasury transfer policy.

    Single-signature transfers up to $25,000.
    Board approval required above threshold.
    Always must have sufficient liquidity buffer (10% reserve).
    """

    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount, "balance": _balance, "threshold": _threshold}

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) > Decimal("0")).named("positive_amount").explain(
                "Transfer amount {amount} must be positive"
            ),
            (E(_amount) <= E(_threshold)).named("single_sig_limit").explain(
                "Transfer {amount} exceeds single-signature limit {threshold} — board approval required"
            ),
            ((E(_balance) - E(_amount)) >= E(_balance) * Decimal("0.10")).named("liquidity_buffer").explain(
                "Transfer {amount} violates 10% liquidity buffer requirement (balance: {balance})"
            ),
        ]


# ── Intent schema ─────────────────────────────────────────────────────────────

class TransferIntent(BaseModel):
    amount: Decimal
    payee:  str = "vendor"
    memo:   str = ""


# ── Live treasury state ───────────────────────────────────────────────────────

_TREASURY: dict[str, Any] = {
    "state_version": "1.0",
    "balance":     Decimal("500000.00"),
    "threshold":   Decimal("25000.00"),
}


def get_treasury_state() -> dict:
    return dict(_TREASURY)


# ── Tool implementation ───────────────────────────────────────────────────────

guard = Guard(TreasuryPolicy, GuardConfig(execution_mode="async-thread", solver_timeout_ms=5_000))
callback = PramanixToolCallback(
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=get_treasury_state,
    name="treasury_transfer",
    description="Execute a treasury wire transfer with formal verification",
)


@callback
async def treasury_transfer(amount: Decimal, payee: str = "vendor", memo: str = "") -> str:
    """Execute the treasury transfer (only reached after Pramanix ALLOW)."""
    _TREASURY["balance"] -= amount
    return (
        f"Wire transfer complete: ${amount:,.2f} to {payee}. "
        f"Memo: {memo}. New treasury balance: ${_TREASURY['balance']:,.2f}"
    )


# ── Demo (simulates AutoGen multi-agent conversation) ─────────────────────────

async def simulate_agent_conversation() -> None:
    """Simulate the CFO agent requesting transfers via the guarded tool."""

    print("=== Pramanix AutoGen Treasury Multi-Agent Demo ===\n")
    print("[CFO Agent] I need to make several treasury transfers.\n")

    # Transfer 1: ALLOW — within limits
    print("[CFO Agent] Request 1: Wire $10,000 to Acme Corp for SaaS license")
    result = await treasury_transfer(
        amount=Decimal("10000"), payee="Acme Corp", memo="Annual SaaS license Q1"
    )
    print(f"[Execution Agent] {result}\n")

    # Transfer 2: BLOCK — exceeds single-sig threshold
    print("[CFO Agent] Request 2: Wire $50,000 to BuildCo for construction advance")
    result = await treasury_transfer(
        amount=Decimal("50000"), payee="BuildCo", memo="Construction advance"
    )
    print(f"[Execution Agent] {result}\n")
    print("[CFO Agent] I see — I'll submit a board approval request for that amount.\n")

    # Transfer 3: BLOCK — violates 10% liquidity buffer
    large = Decimal("460000")
    print(f"[CFO Agent] Request 3: Wire ${large:,} for acquisition deposit")
    result = await treasury_transfer(
        amount=large, payee="Target Corp", memo="Acquisition deposit"
    )
    print(f"[Execution Agent] {result}\n")
    print("[CFO Agent] Understood — we need to maintain the liquidity buffer.\n")

    print("=== Treasury policy enforced with mathematical proof on every transfer ===")
    print(f"=== Final balance: ${_TREASURY['balance']:,.2f} ===")


if __name__ == "__main__":
    asyncio.run(simulate_agent_conversation())
