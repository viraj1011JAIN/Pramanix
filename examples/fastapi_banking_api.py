#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
fastapi_banking_api.py — Bank-grade mathematical safety in one middleware line.

Demonstrates PramanixMiddleware protecting a FastAPI banking API.
Every POST /transfer request is formally verified against TransferPolicy
(Z3 SMT) before the handler executes. Blocked requests return 403 + proof.

Run:
    uvicorn examples.fastapi_banking_api:app --reload

Try:
    # ALLOW — within limits
    curl -X POST http://localhost:8000/transfer \\
        -H "Content-Type: application/json" \\
        -d '{"amount": 100.00}'

    # BLOCK — overdraft
    curl -X POST http://localhost:8000/transfer \\
        -H "Content-Type: application/json" \\
        -d '{"amount": 99999.00}'
"""
from __future__ import annotations

from decimal import Decimal

from fastapi import FastAPI, Request
from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route

# ── Policy ────────────────────────────────────────────────────────────────────

_amount  = Field("amount",      Decimal, "Real")
_balance = Field("balance",     Decimal, "Real")
_daily   = Field("daily_limit", Decimal, "Real")
_spent   = Field("daily_spent", Decimal, "Real")


class TransferPolicy(Policy):
    """Bank transfer policy — Z3-verified on every request."""

    class Meta:
        version = "2.0"

    @classmethod
    def fields(cls) -> dict:
        return {
            "amount":      _amount,
            "balance":     _balance,
            "daily_limit": _daily,
            "daily_spent": _spent,
        }

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) > Decimal("0"))
                .named("positive_amount")
                .explain("Transfer amount {amount} must be positive"),
            (E(_amount) <= Decimal("50000"))
                .named("single_tx_cap")
                .explain("Single transfer capped at 50,000 — got {amount}"),
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance")
                .explain("Insufficient balance {balance} for transfer {amount}"),
            ((E(_spent) + E(_amount)) <= E(_daily))
                .named("daily_limit")
                .explain("Daily limit {daily_limit} exceeded: spent {daily_spent} + requested {amount}"),
        ]


# ── Pydantic intent schema ────────────────────────────────────────────────────

class TransferRequest(BaseModel):
    amount: Decimal


# ── State loader — would query Redis/DB in production ─────────────────────────

async def load_account_state(request: Request) -> dict:
    """Fetch current account state for the authenticated user.

    In production: extract user_id from JWT, query database.
    Here: hardcoded demo state.
    """
    return {
        "state_version": "2.0",
        "balance":     Decimal("10000.00"),
        "daily_limit": Decimal("5000.00"),
        "daily_spent": Decimal("200.00"),
    }


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Pramanix Banking API",
    description="Bank-grade mathematical safety via Z3 formal verification",
    version="1.0.0",
)

# One line — that's it.
app.add_middleware(
    PramanixMiddleware,
    policy=TransferPolicy,
    intent_model=TransferRequest,
    state_loader=load_account_state,
    config=GuardConfig(
        execution_mode="async-thread",
        solver_timeout_ms=5_000,
        metrics_enabled=True,
    ),
    max_body_bytes=65_536,    # 64 KB — reject oversized payloads
    timing_budget_ms=50.0,    # Pad BLOCK responses — no timing oracle
)


@app.post("/transfer")
async def transfer(payload: TransferRequest) -> dict:
    """Execute a bank transfer (only reached if Guard allows it)."""
    amount = payload.amount
    # In production: debit account, create transaction record
    return {
        "status":  "success",
        "message": f"Transferred ${amount:,.2f}",
        "amount":  str(amount),
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "sdk": "pramanix", "version": "0.5.0"}


# ── Per-route alternative (granular security) ─────────────────────────────────

_withdrawal_guard = Guard(
    TransferPolicy,
    GuardConfig(execution_mode="sync", solver_timeout_ms=3_000),
)


@app.post("/withdraw")
@pramanix_route(policy=TransferPolicy, on_block="raise")
async def withdraw(intent: dict, state: dict) -> dict:
    """Withdrawal endpoint protected by @pramanix_route decorator."""
    return {"status": "withdrawn", "amount": intent.get("amount")}
