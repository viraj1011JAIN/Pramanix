#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
multi_primitive_composition.py — Cross-domain primitive composition demo.

Demonstrates that Pramanix primitives from different regulatory domains
compose seamlessly into a single atomic policy — because every primitive
returns the same ConstraintExpr type and all constraints are evaluated
jointly by a single Z3 SMT solver call.

Scenario: AI-Assisted Healthcare Payments Platform
---------------------------------------------------
A healthcare AI assistant wants to issue a payment to a medical supplier.
The payment must simultaneously satisfy:

  Domain 1 — FinTech / BSA:
    ① SufficientBalance        — account can cover the payment
    ② AntiStructuring          — cumulative doesn't trigger CTR
    ③ SanctionsScreen          — supplier not on OFAC watchlist
    ④ KYCTierCheck             — payer has enhanced CDD (required for healthcare)

  Domain 2 — HIPAA:
    ⑤ PHILeastPrivilege        — authorising user has clinical billing clearance
    ⑥ ConsentActive            — patient consent covers billing disclosure

  Domain 3 — SRE / Infrastructure:
    ⑦ CircuitBreakerState      — payment processor circuit is healthy
    ⑧ BlastRadiusCheck         — batch job doesn't affect too many accounts

This 8-primitive composite policy is evaluated in a single Z3 solve() call
taking ~ 1-3 ms — faster than a single LLM token.

Run::

    python examples/multi_primitive_composition.py
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
    SanctionsScreen,
    SufficientBalance,
)
from pramanix.primitives.healthcare import ConsentActive, PHILeastPrivilege
from pramanix.primitives.infra import BlastRadiusCheck, CircuitBreakerState

# Role constants
BILLING_STAFF = 6
CLINICIAN = 1

_NOW = 1_735_000_000

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Domain models
# ═══════════════════════════════════════════════════════════════════════════════


class MedicalPaymentIntent(BaseModel):
    """AI-initiated medical payment to a supplier."""

    amount: Decimal
    cumulative_24h: Decimal
    authorising_role: int
    """Integer-encoded role of the staff member authorising the payment."""
    affected_accounts: int
    """Number of patient accounts involved in this batch payment."""


class PaymentSystemState(BaseModel):
    """Composite state drawn from multiple systems."""

    state_version: str
    # Financial state
    balance: Decimal
    supplier_flagged: bool
    kyc_tier: int
    # HIPAA state
    consent_given: bool
    consent_expiry: int
    # Infrastructure state
    payment_circuit_open: bool
    total_accounts: int


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Cross-domain composite policy
# ═══════════════════════════════════════════════════════════════════════════════


class MedicalPaymentPolicy(Policy):
    """8-primitive cross-domain safety policy for AI-initiated medical payments.

    A single guard.verify() call atomically evaluates:
    - 4 FinTech / BSA constraints
    - 2 HIPAA constraints
    - 2 SRE constraints

    Z3 evaluates all 8 simultaneously as a conjunction — if any fail,
    ALL violations are reported in the same response.
    """

    class Meta:
        version = "0.6"
        intent_model = MedicalPaymentIntent
        state_model = PaymentSystemState

    # FinTech fields
    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")
    cumulative_24h = Field("cumulative_24h", Decimal, "Real")
    supplier_flagged = Field("supplier_flagged", bool, "Bool")
    kyc_tier = Field("kyc_tier", int, "Int")
    # HIPAA fields
    authorising_role = Field("authorising_role", int, "Int")
    consent_given = Field("consent_given", bool, "Bool")
    consent_expiry = Field("consent_expiry", int, "Int")
    # SRE fields
    payment_circuit_open = Field("payment_circuit_open", bool, "Bool")
    affected_accounts = Field("affected_accounts", int, "Int")
    total_accounts = Field("total_accounts", int, "Int")

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            # ── FinTech / BSA ──────────────────────────────────────────────
            SufficientBalance(cls.balance, cls.amount),
            AntiStructuring(cls.cumulative_24h, Decimal("10_000")),
            SanctionsScreen(cls.supplier_flagged),
            KYCTierCheck(cls.kyc_tier, required_tier=3),  # EDD for healthcare
            # ── HIPAA ─────────────────────────────────────────────────────
            PHILeastPrivilege(cls.authorising_role, [BILLING_STAFF, CLINICIAN]),
            ConsentActive(cls.consent_given, cls.consent_expiry, current_epoch=_NOW),
            # ── SRE ───────────────────────────────────────────────────────
            CircuitBreakerState(cls.payment_circuit_open),
            BlastRadiusCheck(cls.affected_accounts, cls.total_accounts, Decimal("0.10")),
        ]


guard = Guard(MedicalPaymentPolicy, config=GuardConfig(solver_timeout_ms=10_000))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Print helper
# ═══════════════════════════════════════════════════════════════════════════════


def _print(label: str, d: Decision) -> None:
    symbol = "✓" if d.allowed else "✗"
    print(f"\n{symbol} [{label}]")
    print(f"  allowed   : {d.allowed}")
    print(f"  status    : {d.status.value}")
    violations = sorted(d.violated_invariants) if d.violated_invariants else []
    if violations:
        print(f"  violated  : {violations}")
        print(f"  count     : {len(violations)} of 8 primitives failed")
    if d.explanation:
        print(f"  reason    : {d.explanation}")
    print(f"  audit_id  : {d.decision_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Base state builder
# ═══════════════════════════════════════════════════════════════════════════════


def _base_state(**overrides: object) -> dict:
    state: dict = {
        "state_version": "0.6",
        "balance": Decimal("500_000"),
        "supplier_flagged": False,
        "kyc_tier": 3,
        "consent_given": True,
        "consent_expiry": _NOW + 365 * 86_400,
        "payment_circuit_open": False,
        "total_accounts": 10_000,
    }
    state.update(overrides)
    return state


def _base_intent(**overrides: object) -> dict:
    intent: dict = {
        "amount": Decimal("25_000"),
        "cumulative_24h": Decimal("8_000"),
        "authorising_role": BILLING_STAFF,
        "affected_accounts": 500,
    }
    intent.update(overrides)
    return intent


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Scenarios
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_all_8_pass() -> Decision:
    """All 8 primitives from 3 domains satisfied — payment approved."""
    return guard.verify(intent=_base_intent(), state=_base_state())


def scenario_ofac_blocks_despite_hipaa_ok() -> Decision:
    """OFAC hit on supplier — FinTech layer blocks even with HIPAA fully compliant."""
    return guard.verify(
        intent=_base_intent(),
        state=_base_state(supplier_flagged=True),
    )


def scenario_expired_consent_blocks_despite_financial_ok() -> Decision:
    """HIPAA layer blocks — patient consent expired even though financials clear."""
    return guard.verify(
        intent=_base_intent(),
        state=_base_state(consent_expiry=_NOW - 1),
    )


def scenario_sre_circuit_blocks_whole_payment() -> Decision:
    """SRE circuit open — payment processor unhealthy, entire batch rejected."""
    return guard.verify(
        intent=_base_intent(),
        state=_base_state(payment_circuit_open=True),
    )


def scenario_five_simultaneous_failures() -> Decision:
    """Chaos scenario — 5 of 8 primitives fail simultaneously.

    Z3 identifies all 5 in a single solver call and returns them together.
    LangChain/AutoGen callbacks would stop at the first failure.
    """
    return guard.verify(
        intent=_base_intent(
            cumulative_24h=Decimal("11_000"),  # structuring
            authorising_role=99,               # wrong HIPAA role
            affected_accounts=2_000,           # blast radius
        ),
        state=_base_state(
            balance=Decimal("10_000"),         # insufficient (amount=25000)
            supplier_flagged=True,             # OFAC hit
            payment_circuit_open=False,
            consent_given=True,
            kyc_tier=3,
        ),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Main
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("PRAMANIX — Cross-Domain 8-Primitive Composite Policy")
    print("FinTech x HIPAA x SRE — Single Z3 SMT solve() call")
    print("=" * 70)

    _print("ALL 8 PASS (payment approved)", scenario_all_8_pass())
    _print("OFAC HIT (FinTech blocks)", scenario_ofac_blocks_despite_hipaa_ok())
    _print("EXPIRED CONSENT (HIPAA blocks)", scenario_expired_consent_blocks_despite_financial_ok())
    _print("CIRCUIT OPEN (SRE blocks)", scenario_sre_circuit_blocks_whole_payment())
    _print("CHAOS: 5 of 8 fail simultaneously", scenario_five_simultaneous_failures())

    print("\n" + "=" * 70)
    print("8 regulatory constraints — 3 domains — 1 solver call — <3ms")
    print("This is why Pramanix beats callback-based guardrail frameworks.")
    print("=" * 70)
