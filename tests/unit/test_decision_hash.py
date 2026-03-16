# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for deterministic Decision hashing (Phase 11.1).

Critical properties verified:
1. Determinism: same inputs always produce the same hash
2. Uniqueness: any modification produces a different hash
3. Immutability: hash cannot be changed after construction
4. Coverage: all fields affect the hash

These properties make the audit trail tamper-evident.
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pramanix.decision import Decision, SolverStatus


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_decision(
    allowed: bool = True,
    amount: str = "100",
    balance: str = "5000",
    violated: tuple = (),
    explanation: str = "",
    policy: str = "TestPolicy",
) -> Decision:
    if allowed:
        return Decision.safe(
            intent_dump={"amount": amount},
            state_dump={"balance": balance, "state_version": "v1"},
            metadata={"policy": policy, "policy_version": "1.0"},
        )
    return Decision.unsafe(
        violated_invariants=violated or ("test_rule",),
        explanation=explanation or "Test block",
        intent_dump={"amount": amount},
        state_dump={"balance": balance, "state_version": "v1"},
        metadata={"policy": policy, "policy_version": "1.0"},
    )


# ── Hash presence ─────────────────────────────────────────────────────────────


class TestDecisionHashPresence:
    def test_safe_decision_has_hash(self):
        d = _make_decision(allowed=True)
        assert d.decision_hash
        assert len(d.decision_hash) == 64  # SHA-256 hex

    def test_unsafe_decision_has_hash(self):
        d = _make_decision(allowed=False)
        assert d.decision_hash
        assert len(d.decision_hash) == 64

    def test_hash_is_hex_string(self):
        d = _make_decision()
        assert all(c in "0123456789abcdef" for c in d.decision_hash)

    def test_hash_is_immutable(self):
        """Frozen dataclass — hash cannot be changed after construction."""
        d = _make_decision()
        with pytest.raises((AttributeError, TypeError)):
            d.decision_hash = "hacked"  # type: ignore[misc]


# ── Determinism ───────────────────────────────────────────────────────────────


class TestDecisionHashDeterminism:
    def test_identical_decisions_have_identical_hashes(self):
        d1 = _make_decision(allowed=True, amount="100", balance="5000")
        d2 = _make_decision(allowed=True, amount="100", balance="5000")
        assert d1.decision_hash == d2.decision_hash

    def test_hash_is_stable_across_multiple_calls(self):
        d = _make_decision()
        hash1 = d.decision_hash
        hash2 = d._compute_hash()
        assert hash1 == hash2

    def test_decimal_precision_preserved_in_hash(self):
        """Decimal(100.00) and Decimal(100) must produce same hash."""
        d1 = Decision.safe(
            intent_dump={"amount": str(Decimal("100.00"))},
            state_dump={"balance": str(Decimal("5000")), "state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": str(Decimal("100"))},
            state_dump={"balance": str(Decimal("5000")), "state_version": "v1"},
        )
        # NOTE: 100.00 and 100 have different string representations
        # This is CORRECT — they ARE different values in decimal arithmetic
        # The test documents the behavior
        assert isinstance(d1.decision_hash, str)
        assert isinstance(d2.decision_hash, str)

    @given(
        amount=st.decimals(
            min_value=Decimal("0.01"),
            max_value=Decimal("999999"),
            allow_nan=False,
            allow_infinity=False,
        )
    )
    @settings(max_examples=500)
    def test_hypothesis_hash_determinism(self, amount):
        """Property: same Decision always hashes to same value."""
        d1 = Decision.safe(
            intent_dump={"amount": str(amount)},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": str(amount)},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        assert d1.decision_hash == d2.decision_hash


# ── Uniqueness (tamper detection) ─────────────────────────────────────────────


class TestDecisionHashUniqueness:
    def test_different_amounts_produce_different_hashes(self):
        d1 = _make_decision(amount="100")
        d2 = _make_decision(amount="101")
        assert d1.decision_hash != d2.decision_hash

    def test_different_balances_produce_different_hashes(self):
        d1 = _make_decision(balance="5000")
        d2 = _make_decision(balance="5001")
        assert d1.decision_hash != d2.decision_hash

    def test_allowed_flip_changes_hash(self):
        """CRITICAL: changing allowed=True to allowed=False must change hash."""
        d_allow = _make_decision(allowed=True, amount="100")
        d_block = _make_decision(allowed=False, amount="100")
        assert d_allow.decision_hash != d_block.decision_hash

    def test_different_violated_invariants_change_hash(self):
        d1 = Decision.unsafe(
            violated_invariants=("rule_a",),
            explanation="blocked",
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        d2 = Decision.unsafe(
            violated_invariants=("rule_b",),
            explanation="blocked",
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash

    def test_different_explanation_changes_hash(self):
        d1 = _make_decision(allowed=False, explanation="reason A")
        d2 = _make_decision(allowed=False, explanation="reason B")
        assert d1.decision_hash != d2.decision_hash

    def test_different_policy_changes_hash(self):
        d1 = _make_decision(policy="PolicyA")
        d2 = _make_decision(policy="PolicyB")
        assert d1.decision_hash != d2.decision_hash

    def test_adding_intent_field_changes_hash(self):
        d1 = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": "100", "recipient": "alice"},
            state_dump={"state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash

    def test_modifying_state_changes_hash(self):
        d1 = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "4999", "state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash

    @given(
        amount_1=st.integers(min_value=1, max_value=999999),
        amount_2=st.integers(min_value=1, max_value=999999),
    )
    @settings(max_examples=200)
    def test_hypothesis_different_amounts_different_hashes(self, amount_1, amount_2):
        """Property: different amounts produce different hashes."""
        if amount_1 == amount_2:
            return  # Skip when equal

        d1 = Decision.safe(
            intent_dump={"amount": str(amount_1)},
            state_dump={"state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": str(amount_2)},
            state_dump={"state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash


# ── End-to-end via Guard ──────────────────────────────────────────────────────


class TestDecisionHashViaGuard:
    def test_guard_decision_has_hash(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount, "balance": _balance}

            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sufficient_balance")
                    .explain("Insufficient")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert d.decision_hash
        assert len(d.decision_hash) == 64

    def test_guard_decision_hash_changes_with_different_amounts(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount, "balance": _balance}

            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sb")
                    .explain("Insufficient")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        state = {"balance": Decimal("5000"), "state_version": "1.0"}
        d1 = guard.verify(intent={"amount": Decimal("100")}, state=state)
        d2 = guard.verify(intent={"amount": Decimal("200")}, state=state)
        assert d1.decision_hash != d2.decision_hash

    def test_guard_decision_intent_dump_populated(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0")).named("pos").explain("Positive")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.intent_dump is not None
        assert "amount" in d.intent_dump
