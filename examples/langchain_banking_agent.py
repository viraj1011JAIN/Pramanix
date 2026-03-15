#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
langchain_banking_agent.py — Formally-verified LangChain banking agent.

A LangChain agent that can transfer funds, check balances, and apply for
credit. Every tool call is formally verified with Z3 before execution.
Blocked calls return structured natural-language feedback — the agent
can read it, understand the constraint, and adjust its plan.

Install: pip install 'pramanix[langchain]' langchain langchain-openai

Run:
    OPENAI_API_KEY=... python examples/langchain_banking_agent.py
"""
from __future__ import annotations

import asyncio
import json
from decimal import Decimal
from typing import Any

from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools


# ── Transfer policy ──────────────────────────────────────────────────────────

_amount  = Field("amount",      Decimal, "Real")
_balance = Field("balance",     Decimal, "Real")
_limit   = Field("daily_limit", Decimal, "Real")
_spent   = Field("daily_spent", Decimal, "Real")


class TransferPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount, "balance": _balance, "daily_limit": _limit, "daily_spent": _spent}

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) > Decimal("0")).named("positive").explain("Amount {amount} must be positive"),
            ((E(_balance) - E(_amount)) >= Decimal("0")).named("sufficient_balance").explain(
                "Balance {balance} insufficient for transfer {amount}"
            ),
            ((E(_spent) + E(_amount)) <= E(_limit)).named("daily_limit").explain(
                "Daily limit {daily_limit} exceeded: spent {daily_spent} + requested {amount}"
            ),
        ]


# ── Intent schema ─────────────────────────────────────────────────────────────

class TransferIntent(BaseModel):
    amount: Decimal
    recipient: str = "default"


# ── Live account state (production: fetch from DB/Redis) ──────────────────────

_ACCOUNT_STATE: dict[str, Any] = {
    "state_version": "1.0",
    "balance":     Decimal("3000.00"),
    "daily_limit": Decimal("2000.00"),
    "daily_spent": Decimal("500.00"),
}


def get_state() -> dict:
    return dict(_ACCOUNT_STATE)


# ── Tool implementations ──────────────────────────────────────────────────────

def execute_transfer(intent: dict) -> str:
    """Execute the actual transfer after Guard approves it."""
    amount = intent["amount"]
    recipient = intent.get("recipient", "default")
    _ACCOUNT_STATE["balance"] -= Decimal(str(amount))
    _ACCOUNT_STATE["daily_spent"] += Decimal(str(amount))
    return f"Transferred ${amount:,.2f} to {recipient}. New balance: ${_ACCOUNT_STATE['balance']:,.2f}"


# ── Guarded tool ─────────────────────────────────────────────────────────────

guard = Guard(TransferPolicy, GuardConfig(execution_mode="async-thread", solver_timeout_ms=5_000))

transfer_tool = PramanixGuardedTool(
    name="bank_transfer",
    description=(
        "Transfer funds from the user's account to a recipient. "
        "Input: JSON with 'amount' (Decimal) and 'recipient' (str). "
        "Returns confirmation or a structured explanation of why the transfer was blocked."
    ),
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=get_state,
    execute_fn=execute_transfer,
)


# ── Demo ──────────────────────────────────────────────────────────────────────

async def demo() -> None:
    print("=== Pramanix LangChain Banking Agent Demo ===\n")

    # Scenario A: ALLOW — small transfer
    print("Scenario A: Transfer $100 (within limits)")
    result = await transfer_tool._arun(json.dumps({"amount": "100", "recipient": "Alice"}))
    print(f"  Result: {result}\n")

    # Scenario B: BLOCK — exceeds daily limit
    print("Scenario B: Transfer $2000 (exceeds remaining daily limit of $1500)")
    result = await transfer_tool._arun(json.dumps({"amount": "2000", "recipient": "Bob"}))
    print(f"  Result: {result}\n")

    # Scenario C: BLOCK — insufficient balance
    print("Scenario C: Transfer $5000 (exceeds balance)")
    result = await transfer_tool._arun(json.dumps({"amount": "5000", "recipient": "Carol"}))
    print(f"  Result: {result}\n")

    print("=== Demo complete. The agent receives structured feedback ===")
    print("=== and can adjust its plan accordingly — unlike a raw 403 ===")


if __name__ == "__main__":
    asyncio.run(demo())
