# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/100m_domain_policies.py

Five production-grade Policy classes and their deterministic payload generators
for the 100 M decision audit benchmark.

Design constraints
------------------
* All numeric fields use z3_type="Real" (Decimal) — avoids Int/Real sort-mismatch
  issues with literal transpilation and uses Z3's fastest linear arithmetic solver.
* All boolean guard fields use z3_type="Bool".
* No Int-sorted fields: integer role codes, replica counts, etc. are encoded as
  Decimal(1), Decimal(2), ... and compared against Decimal literals.
* Every policy has 2-3 invariants: enough to be domain-realistic, few enough
  to stay well inside the 150 ms Z3 timeout per decision.
* Payload generators target ~25% BLOCK rate overall, exercising both the
  fast-path (sat) and attribution-path (unsat) code in pramanix.solver.

DOMAINS registry
-----------------
    DOMAINS[name] = (PolicyClass, payload_generator_fn)

Payload generator signature:
    fn(rng: random.Random) -> dict[str, Any]

Returns a merged dict of all field values needed by the policy's invariants.
"""
from __future__ import annotations

import random
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

# ── path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pramanix import Field, Policy
from pramanix.expressions import E

# ── 1. Finance — post-trade balance + AML risk score ─────────────────────────
#
# Two invariants, all Real.  Simulates SEC/FINRA trade-execution gate:
#   (a) the post-trade account balance must remain non-negative.
#   (b) the transaction's AML risk score must be below the 75-point threshold.
#
# Expected BLOCK rate: ~25 % (overdraft ≈ 20 %, high risk ≈ 10 %, overlap ≈ 5 %).


class Finance100MPolicy(Policy):
    """Finance domain: post-trade balance and AML risk score enforcement."""

    balance    = Field("balance",    Decimal, "Real")
    amount     = Field("amount",     Decimal, "Real")
    risk_score = Field("risk_score", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (
                E(cls.balance) - E(cls.amount) >= Decimal("0")
            ).named("non_negative_balance"),
            (
                E(cls.risk_score) < Decimal("75")
            ).named("risk_score_below_threshold"),
        ]


def _gen_finance(rng: random.Random) -> dict[str, Any]:
    # balance: $500 – $50 000, stored in integer cents for exact Decimal.
    balance_cents = rng.randint(50_000, 5_000_000)
    balance = Decimal(balance_cents) / 100

    # 20 % overdraft → BLOCK on non_negative_balance.
    if rng.random() < 0.20:
        extra_cents = rng.randint(100, 1_000_000)
        amount = Decimal(balance_cents + extra_cents) / 100
    else:
        # Valid amount: 0.1 % – 90 % of balance.
        amount_cents = rng.randint(max(1, balance_cents // 1000), balance_cents - 1)
        amount = Decimal(amount_cents) / 100

    # risk_score 0.0 – 100.0 (one decimal place).
    # 10 % high-risk (≥ 75) → BLOCK on risk_score_below_threshold.
    if rng.random() < 0.10:
        risk_score = Decimal(rng.randint(750, 1000)) / 10   # 75.0 – 100.0
    else:
        risk_score = Decimal(rng.randint(0, 749)) / 10      # 0.0 – 74.9

    return {"balance": balance, "amount": amount, "risk_score": risk_score}


# ── 2. Banking — AML/BSA account controls ────────────────────────────────────
#
# Three invariants, Real + Bool.  Simulates a core-banking transaction gate:
#   (a) non-negative post-transaction balance.
#   (b) amount within the rolling daily transfer cap.
#   (c) account is not frozen.
#
# Expected BLOCK rate: ~28 % across the three invariants.


class Banking100MPolicy(Policy):
    """Banking domain: balance, daily cap, and account-freeze enforcement."""

    balance     = Field("balance",     Decimal, "Real")
    amount      = Field("amount",      Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    is_frozen   = Field("is_frozen",   bool,    "Bool")

    @classmethod
    def invariants(cls):
        return [
            (
                E(cls.balance) - E(cls.amount) >= Decimal("0")
            ).named("non_negative_balance"),
            (
                E(cls.amount) <= E(cls.daily_limit)
            ).named("within_daily_limit"),
            (
                E(cls.is_frozen) == False  # noqa: E712
            ).named("account_not_frozen"),
        ]


def _gen_banking(rng: random.Random) -> dict[str, Any]:
    balance_cents     = rng.randint(10_000, 1_000_000)   # $100 – $10 000
    daily_limit_cents = rng.randint(50_000, 500_000)     # $500 – $5 000
    balance           = Decimal(balance_cents) / 100
    daily_limit       = Decimal(daily_limit_cents) / 100

    r = rng.random()
    if r < 0.15:
        # Overdraft → BLOCK on non_negative_balance.
        amount = balance + Decimal(rng.randint(100, 100_000)) / 100
    elif r < 0.25:
        # Over daily limit → BLOCK on within_daily_limit.
        amount = daily_limit + Decimal(rng.randint(100, 100_000)) / 100
    else:
        # Valid: within both balance and daily limit.
        ceiling = max(101, min(balance_cents, daily_limit_cents) - 1)
        amount = Decimal(rng.randint(100, ceiling)) / 100

    # 15 % frozen accounts → BLOCK on account_not_frozen.
    is_frozen = rng.random() < 0.15

    return {
        "balance":     balance,
        "amount":      amount,
        "daily_limit": daily_limit,
        "is_frozen":   is_frozen,
    }


# ── 3. FinTech — wire-transfer / HFT compliance ───────────────────────────────
#
# Three invariants, Real + Bool.  Simulates a SWIFT/HFT pre-flight gate:
#   (a) post-transfer balance remains non-negative (BSA / Reg. E).
#   (b) counterparty has cleared the OFAC sanctions screen.
#   (c) Basel III collateral haircut: collateral × 0.85 ≥ loan_value.
#
# Expected BLOCK rate: ~27 %.


class FinTech100MPolicy(Policy):
    """FinTech domain: wire-transfer balance, sanctions, and collateral check."""

    balance            = Field("balance",            Decimal, "Real")
    amount             = Field("amount",             Decimal, "Real")
    collateral         = Field("collateral",         Decimal, "Real")
    loan_value         = Field("loan_value",         Decimal, "Real")
    counterparty_clear = Field("counterparty_clear", bool,    "Bool")

    @classmethod
    def invariants(cls):
        # Collateral haircut 15 % (Basel III CSA): effective coverage ≥ loan.
        return [
            (
                E(cls.balance) - E(cls.amount) >= Decimal("0")
            ).named("sufficient_balance"),
            (
                E(cls.counterparty_clear) == True  # noqa: E712
            ).named("sanctions_clear"),
            (
                E(cls.collateral) * Decimal("0.85") >= E(cls.loan_value)
            ).named("collateral_haircut"),
        ]


def _gen_fintech(rng: random.Random) -> dict[str, Any]:
    balance_cents = rng.randint(100_000, 10_000_000)   # $1 000 – $100 000
    balance       = Decimal(balance_cents) / 100

    # 15 % overdraft.
    if rng.random() < 0.15:
        amount = balance + Decimal(rng.randint(100, 500_000)) / 100
    else:
        amount = Decimal(rng.randint(100, balance_cents - 1)) / 100

    # 12 % sanctioned counterparty → BLOCK on sanctions_clear.
    counterparty_clear = rng.random() >= 0.12

    # Loan + collateral.  15 % under-collateralized → BLOCK on collateral_haircut.
    loan_cents = rng.randint(50_000, 10_000_000)   # $500 – $100 000
    loan_value = Decimal(loan_cents) / 100
    if rng.random() < 0.15:
        # Under-collateralized: collateral × 0.85 < loan → BLOCK.
        # 0.90 × 0.85 = 0.765 < 1.0  ✓
        collateral = loan_value * Decimal("0.90")
    else:
        # Adequately collateralized: 1.30 × 0.85 = 1.105 ≥ 1.0  ✓
        collateral = loan_value * Decimal("1.30")

    return {
        "balance":            balance,
        "amount":             amount,
        "counterparty_clear": counterparty_clear,
        "collateral":         collateral,
        "loan_value":         loan_value,
    }


# ── 4. Healthcare — HIPAA PHI access control + dosage safety ─────────────────
#
# Three invariants, Real + Bool.  Simulates a clinical decision-support gate:
#   (a) patient has valid, active consent (HIPAA 45 CFR § 164.508).
#   (b) dose escalation ≤ 25 % per titration step (Joint Commission NPSG 03.06.01).
#   (c) requestor role is CLINICIAN (1.0) or NURSE (2.0) — minimum-necessary
#       access (HIPAA 45 CFR § 164.502(b)).
#
# Role codes are Decimal (Real sort) to avoid Int/Real sort-coercion issues:
#   1.0 = CLINICIAN, 2.0 = NURSE, 3.0 = ADMIN, 4.0 = AUDITOR
#
# Expected BLOCK rate: ~30 %.


class Healthcare100MPolicy(Policy):
    """Healthcare domain: consent, dosage gradient, and PHI role gate."""

    consent_active = Field("consent_active", bool,    "Bool")
    new_dose       = Field("new_dose",       Decimal, "Real")
    current_dose   = Field("current_dose",   Decimal, "Real")
    requestor_role = Field("requestor_role", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (
                E(cls.consent_active) == True  # noqa: E712
            ).named("consent_active"),
            (
                E(cls.new_dose) - E(cls.current_dose)
                <= Decimal("0.25") * E(cls.current_dose)
            ).named("dosage_gradient_check"),
            (
                (E(cls.requestor_role) == Decimal("1"))
                | (E(cls.requestor_role) == Decimal("2"))
            ).named("phi_least_privilege"),
        ]


def _gen_healthcare(rng: random.Random) -> dict[str, Any]:
    # Consent active in 80 % of cases.
    consent_active = rng.random() >= 0.20

    # current_dose: 10.0 – 500.0 mg (one decimal place).
    current_dose_x10 = rng.randint(100, 5000)
    current_dose = Decimal(current_dose_x10) / 10

    # 20 % exceed 25 % titration limit → BLOCK on dosage_gradient_check.
    if rng.random() < 0.20:
        new_dose = current_dose * Decimal("1.30")  # 30 % increase
    else:
        # 0 – 20 % increase (safe).
        inc_thousandths = rng.randint(0, 200)
        new_dose = current_dose * (Decimal("1000") + Decimal(inc_thousandths)) / 1000

    # Role distribution: CLINICIAN 40 %, NURSE 40 %, ADMIN 15 %, AUDITOR 5 %.
    # ADMIN + AUDITOR (20 %) → BLOCK on phi_least_privilege.
    rv = rng.random()
    if rv < 0.40:
        role = Decimal("1")   # CLINICIAN — ALLOW
    elif rv < 0.80:
        role = Decimal("2")   # NURSE — ALLOW
    elif rv < 0.95:
        role = Decimal("3")   # ADMIN — BLOCK
    else:
        role = Decimal("4")   # AUDITOR — BLOCK

    return {
        "consent_active": consent_active,
        "new_dose":       new_dose,
        "current_dose":   current_dose,
        "requestor_role": role,
    }


# ── 5. Infra — Kubernetes SRE deployment gate ─────────────────────────────────
#
# Three invariants, Real + Bool.  Simulates a GitOps/K8s change-approval gate:
#   (a) blast radius ≤ 20 % of total fleet (pre-computed as affected_pct).
#   (b) replica count within [2, 50] budget (min HA + cost ceiling).
#   (c) deployment has passed the change-approval-board workflow.
#
# Expected BLOCK rate: ~27 %.


class Infra100MPolicy(Policy):
    """Infra domain: blast radius, replica budget, and deployment approval."""

    affected_pct        = Field("affected_pct",        Decimal, "Real")
    replicas            = Field("replicas",             Decimal, "Real")
    deployment_approved = Field("deployment_approved",  bool,    "Bool")

    @classmethod
    def invariants(cls):
        return [
            (
                E(cls.affected_pct) <= Decimal("0.20")
            ).named("blast_radius_check"),
            (
                (E(cls.replicas) >= Decimal("2"))
                & (E(cls.replicas) <= Decimal("50"))
            ).named("replica_budget"),
            (
                E(cls.deployment_approved) == True  # noqa: E712
            ).named("prod_deploy_approval"),
        ]


def _gen_infra(rng: random.Random) -> dict[str, Any]:
    # affected_pct: 0.000 – 0.350 (three decimal places).
    # 20 % exceed 20 % blast radius → BLOCK on blast_radius_check.
    if rng.random() < 0.20:
        affected_pct = Decimal(rng.randint(201, 350)) / 1000   # 0.201 – 0.350
    else:
        affected_pct = Decimal(rng.randint(0, 199)) / 1000     # 0.000 – 0.199

    # replicas: 1 – 55.
    # 5 % over max (51-55), 5 % under min (1) → 10 % BLOCK on replica_budget.
    rv = rng.random()
    if rv < 0.05:
        replicas = Decimal(rng.randint(51, 55))   # over max
    elif rv < 0.10:
        replicas = Decimal("1")                    # under min
    else:
        replicas = Decimal(rng.randint(2, 50))     # valid range

    # 15 % unapproved → BLOCK on prod_deploy_approval.
    deployment_approved = rng.random() >= 0.15

    return {
        "affected_pct":        affected_pct,
        "replicas":            replicas,
        "deployment_approved": deployment_approved,
    }


# ── DOMAINS registry ──────────────────────────────────────────────────────────

DOMAINS: dict[str, tuple] = {
    "finance":    (Finance100MPolicy,    _gen_finance),
    "banking":    (Banking100MPolicy,    _gen_banking),
    "fintech":    (FinTech100MPolicy,    _gen_fintech),
    "healthcare": (Healthcare100MPolicy, _gen_healthcare),
    "infra":      (Infra100MPolicy,      _gen_infra),
}

__all__ = ["DOMAINS"]
