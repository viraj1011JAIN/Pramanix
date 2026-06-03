# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Integration tests: non-numeric state injection into Guard.verify().

Verifies that every possible non-numeric or corrupted value injected into a
numeric Policy field causes Guard.verify() to return a BLOCKED (allowed=False)
Decision — never a raised exception, never an allowed=True result.

This module addresses §5 item 8 of flaws.md:

    "Add integration tests for non-numeric state injection in guard_pipeline.py —
    Parametrised test covering balance='CORRUPTED', balance=None, balance={},
    balance='NaN', dosage='MAX', replica_count='unlimited' — each must result
    in a BLOCKED decision via a full Guard.verify() call (not mocked)."

Design rules
------------
- Zero mocks.  Real Guard, real Z3 solver, real policy definitions.
- Parametrised over a range of type-confused and semantically invalid values.
- Each test makes exactly one assertion beyond the basics: the decision is not
  allowed.  No assertion on the specific error message — those vary by path.
- Uses GuardConfig(execution_mode="sync") for determinism.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel
from pydantic import Field as PydanticField

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import Decision

# ── Policy definitions ────────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: Decimal = PydanticField(gt=0, le=Decimal("1_000_000"))


class _TransferState(BaseModel):
    balance: Decimal
    state_version: str


class _TransferPolicy(Policy):
    """Banking transfer policy — balance must remain non-negative after transfer."""

    class Meta:
        version = "1.0"
        intent_model = _TransferIntent
        state_model = _TransferState

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (
                (E(cls.balance) - E(cls.amount)) >= Decimal("0")
            )
            .named("non_negative_balance")
            .explain("Balance after transfer must be non-negative")
        ]


class _MedicalIntent(BaseModel):
    dosage_mg: Decimal = PydanticField(gt=0, le=Decimal("500"))


class _MedicalState(BaseModel):
    max_dosage_mg: Decimal
    state_version: str


class _MedicalPolicy(Policy):
    """Medical dose policy — prescribed dosage must not exceed maximum safe dosage."""

    class Meta:
        version = "1.0"
        intent_model = _MedicalIntent
        state_model = _MedicalState

    dosage_mg = Field("dosage_mg", Decimal, "Real")
    max_dosage_mg = Field("max_dosage_mg", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.dosage_mg) <= E(cls.max_dosage_mg))
            .named("safe_dosage")
            .explain("Dosage must not exceed maximum safe dosage")
        ]


class _InfraIntent(BaseModel):
    replica_count: Decimal = PydanticField(ge=1, le=Decimal("100"))


class _InfraState(BaseModel):
    max_replicas: Decimal
    state_version: str


class _InfraPolicy(Policy):
    """Infrastructure replica policy — request must not exceed cluster max."""

    class Meta:
        version = "1.0"
        intent_model = _InfraIntent
        state_model = _InfraState

    replica_count = Field("replica_count", Decimal, "Real")
    max_replicas = Field("max_replicas", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.replica_count) <= E(cls.max_replicas))
            .named("within_capacity")
            .explain("Replica count must not exceed cluster maximum")
        ]


# ── Guards (instantiated once, reused across parametrised tests) ───────────────

_TRANSFER_GUARD = Guard(_TransferPolicy, GuardConfig(execution_mode="sync"))
_MEDICAL_GUARD = Guard(_MedicalPolicy, GuardConfig(execution_mode="sync"))
_INFRA_GUARD = Guard(_InfraPolicy, GuardConfig(execution_mode="sync"))

# ── Helper ─────────────────────────────────────────────────────────────────────


def _assert_blocked(decision: Any, label: str) -> None:
    """Guard must return Decision(allowed=False) — never raise, never allow."""
    assert isinstance(decision, Decision), (
        f"[{label}] Guard.verify() returned {type(decision).__name__!r} instead of Decision. "
        "Raw exceptions must not propagate to callers — fail-safe invariant violated."
    )
    assert decision.allowed is False, (
        f"[{label}] Guard.verify() returned allowed=True for a corrupted state value. "
        "CRITICAL SECURITY VIOLATION: Guard must block on non-numeric injection."
    )


# ── §5 item 8: balance field injection ────────────────────────────────────────


@pytest.mark.parametrize(
    "balance_value,label",
    [
        ("CORRUPTED", "string-CORRUPTED"),
        (None, "None"),
        ({}, "empty-dict"),
        ("NaN", "string-NaN"),
        ([], "empty-list"),
        (object(), "arbitrary-object"),
        (float("inf"), "float-inf"),
        (float("nan"), "float-nan"),
        ("", "empty-string"),
        ("   ", "whitespace-string"),
    ],
)
class TestNonNumericBalanceInjection:
    """Inject non-numeric values as the 'balance' state field."""

    def test_corrupted_balance_is_blocked(self, balance_value: Any, label: str) -> None:
        """Non-numeric balance must produce a blocked Decision, not a raised exception."""
        decision = _TRANSFER_GUARD.verify(
            intent={"amount": Decimal("100")},
            state={"balance": balance_value, "state_version": "1.0"},
        )
        _assert_blocked(decision, f"balance={label!r}")


# ── §5 item 8: dosage field injection ─────────────────────────────────────────


@pytest.mark.parametrize(
    "dosage_value,label",
    [
        ("MAX", "string-MAX"),
        (None, "None"),
        ({}, "empty-dict"),
        ("∞", "unicode-infinity"),
        (float("nan"), "float-nan"),
    ],
)
class TestNonNumericDosageInjection:
    """Inject non-numeric values as the 'max_dosage_mg' state field."""

    def test_corrupted_dosage_is_blocked(self, dosage_value: Any, label: str) -> None:
        """Non-numeric max_dosage_mg must produce a blocked Decision."""
        decision = _MEDICAL_GUARD.verify(
            intent={"dosage_mg": Decimal("50")},
            state={"max_dosage_mg": dosage_value, "state_version": "1.0"},
        )
        _assert_blocked(decision, f"max_dosage_mg={label!r}")


# ── §5 item 8: replica_count field injection ───────────────────────────────────


@pytest.mark.parametrize(
    "replicas_value,label",
    [
        ("unlimited", "string-unlimited"),
        (None, "None"),
        ({}, "empty-dict"),
        (float("nan"), "float-nan"),
        ("many", "string-many"),
    ],
)
class TestNonNumericReplicaCountInjection:
    """Inject non-numeric values as the 'max_replicas' state field."""

    def test_corrupted_replicas_is_blocked(self, replicas_value: Any, label: str) -> None:
        """Non-numeric max_replicas must produce a blocked Decision."""
        decision = _INFRA_GUARD.verify(
            intent={"replica_count": Decimal("5")},
            state={"max_replicas": replicas_value, "state_version": "1.0"},
        )
        _assert_blocked(decision, f"max_replicas={replicas_value!r}")


# ── Non-numeric intent injection ───────────────────────────────────────────────


class TestNonNumericIntentInjection:
    """Non-numeric values in intent fields must also be blocked at Pydantic validation."""

    @pytest.mark.parametrize(
        "amount_value,label",
        [
            ("CORRUPTED", "string-CORRUPTED"),
            (None, "None"),
            ({}, "empty-dict"),
            ("transfer_all", "string-transfer_all"),
            (float("nan"), "float-nan"),
        ],
    )
    def test_corrupted_intent_amount_is_blocked(self, amount_value: Any, label: str) -> None:
        """Non-numeric intent amount must produce a blocked Decision."""
        decision = _TRANSFER_GUARD.verify(
            intent={"amount": amount_value},
            state={"balance": Decimal("1000"), "state_version": "1.0"},
        )
        _assert_blocked(decision, f"intent.amount={label!r}")

    def test_completely_corrupted_state_is_blocked(self) -> None:
        """State dict with only garbage values must produce a blocked Decision."""
        decision = _TRANSFER_GUARD.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": "GARBAGE_VALUE",
                "state_version": "not-a-version",
            },
        )
        _assert_blocked(decision, "completely-corrupted-state")

    def test_state_version_numeric_injection(self) -> None:
        """Integer state_version (should be string) must produce a blocked Decision."""
        decision = _TRANSFER_GUARD.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("1000"), "state_version": 999},
        )
        # Either validation_failure (pydantic) or stale_state; either way, blocked
        _assert_blocked(decision, "integer-state_version")
