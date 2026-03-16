# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Phase 10.3 — Semantic Fast-Path Pre-screener.

Verifies that fast-path rules correctly block obvious violations,
pass-through legitimate requests, and integrate correctly with Guard.
"""
from __future__ import annotations

from decimal import Decimal

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.fast_path import (
    FastPathEvaluator,
    FastPathResult,
    SemanticFastPath,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")
_frozen = Field("is_frozen", bool, "Bool")
_limit = Field("daily_limit", Decimal, "Real")
_risk = Field("risk_score", float, "Real")


class FPPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount,
            "balance": _balance,
            "is_frozen": _frozen,
            "daily_limit": _limit,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Insufficient balance"),
            (E(_frozen) == False).named("account_not_frozen").explain("Account is frozen"),  # noqa: E712
            (E(_amount) <= E(_limit)).named("within_daily_limit").explain("Exceeds daily limit"),
            (E(_risk) <= 0.8).named("acceptable_risk").explain("Risk too high"),
            (E(_amount) > Decimal("0")).named("positive_amount").explain("Must be positive"),
        ]


# ── Tests: FastPathResult ─────────────────────────────────────────────────────


class TestFastPathResult:
    def test_pass_through_not_blocked(self):
        r = FastPathResult.pass_through()
        assert r.blocked is False
        assert r.reason == ""

    def test_block_is_blocked(self):
        r = FastPathResult.block("bad", "rule_x")
        assert r.blocked is True
        assert r.reason == "bad"
        assert r.rule_name == "rule_x"


# ── Tests: SemanticFastPath rules ─────────────────────────────────────────────


class TestNegativeAmount:
    def test_blocks_negative(self):
        rule = SemanticFastPath.negative_amount("amount")
        result = rule({"amount": Decimal("-1")}, {})
        assert result is not None
        assert "non-negative" in result.lower() or "negative" in result.lower()

    def test_passes_zero(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": Decimal("0")}, {}) is None

    def test_passes_positive(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": Decimal("100")}, {}) is None

    def test_passes_missing_field(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({}, {}) is None

    def test_handles_string_value(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": "-50"}, {}) is not None

    def test_has_name(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert "amount" in getattr(rule, "__name__", "")


class TestZeroOrNegativeBalance:
    def test_blocks_zero(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        result = rule({}, {"balance": Decimal("0")})
        assert result is not None

    def test_blocks_negative(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        result = rule({}, {"balance": Decimal("-100")})
        assert result is not None

    def test_passes_positive(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert rule({}, {"balance": Decimal("1")}) is None

    def test_passes_missing(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert rule({}, {}) is None


class TestAccountFrozen:
    def test_blocks_true(self):
        rule = SemanticFastPath.account_frozen("is_frozen")
        assert rule({}, {"is_frozen": True}) is not None

    def test_blocks_string_true(self):
        rule = SemanticFastPath.account_frozen("is_frozen")
        assert rule({}, {"is_frozen": "true"}) is not None

    def test_passes_false(self):
        rule = SemanticFastPath.account_frozen("is_frozen")
        assert rule({}, {"is_frozen": False}) is None

    def test_passes_missing(self):
        rule = SemanticFastPath.account_frozen("is_frozen")
        assert rule({}, {}) is None


class TestExceedsHardCap:
    def test_blocks_over_cap(self):
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        result = rule({"amount": Decimal("1_000_001")}, {})
        assert result is not None

    def test_passes_at_cap(self):
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert rule({"amount": Decimal("1000000")}, {}) is None

    def test_passes_below_cap(self):
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert rule({"amount": Decimal("100")}, {}) is None


class TestAmountExceedsBalance:
    def test_blocks_overdraft(self):
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        result = rule(
            {"amount": Decimal("600")},
            {"balance": Decimal("500")},
        )
        assert result is not None

    def test_passes_within_balance(self):
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert (
            rule(
                {"amount": Decimal("100")},
                {"balance": Decimal("500")},
            )
            is None
        )

    def test_passes_missing_amount(self):
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert rule({}, {"balance": Decimal("500")}) is None

    def test_passes_missing_balance(self):
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert rule({"amount": Decimal("100")}, {}) is None


# ── Tests: FastPathEvaluator ─────────────────────────────────────────────────


class TestFastPathEvaluator:
    def test_no_rules_returns_pass_through(self):
        ev = FastPathEvaluator([])
        result = ev.evaluate({}, {})
        assert result.blocked is False

    def test_first_blocking_rule_stops_evaluation(self):
        calls = []

        def rule_a(intent, state):
            calls.append("a")
            return "blocked by a"

        def rule_b(intent, state):
            calls.append("b")
            return None

        ev = FastPathEvaluator([rule_a, rule_b])
        result = ev.evaluate({}, {})
        assert result.blocked is True
        assert "b" not in calls  # rule_b never called

    def test_pass_through_if_no_rule_blocks(self):
        rules = [
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.account_frozen("is_frozen"),
        ]
        ev = FastPathEvaluator(rules)
        result = ev.evaluate(
            {"amount": Decimal("100")},
            {"is_frozen": False},
        )
        assert result.blocked is False

    def test_rule_exception_is_swallowed(self):
        def bad_rule(intent, state):
            raise RuntimeError("internal error")

        ev = FastPathEvaluator([bad_rule])
        # Must not raise — exception is swallowed, evaluation continues
        result = ev.evaluate({}, {})
        assert result.blocked is False

    def test_rule_count(self):
        rules = [
            SemanticFastPath.negative_amount(),
            SemanticFastPath.account_frozen(),
        ]
        ev = FastPathEvaluator(rules)
        assert ev.rule_count == 2

    def test_defensive_copy_of_rules(self):
        rules = [SemanticFastPath.negative_amount()]
        ev = FastPathEvaluator(rules)
        rules.clear()  # mutate original list
        assert ev.rule_count == 1  # evaluator unaffected

    def test_block_result_has_rule_name(self):
        rules = [SemanticFastPath.negative_amount("amount")]
        ev = FastPathEvaluator(rules)
        result = ev.evaluate({"amount": Decimal("-10")}, {})
        assert result.blocked is True
        assert "amount" in result.rule_name


# ── Tests: Guard integration with fast-path ───────────────────────────────────


class TestGuardFastPathIntegration:
    def _make_guard(self, rules):
        return Guard(
            FPPolicy,
            GuardConfig(
                execution_mode="sync",
                fast_path_enabled=True,
                fast_path_rules=tuple(rules),
            ),
        )

    def test_fast_path_disabled_by_default(self):
        guard = Guard(FPPolicy, GuardConfig(execution_mode="sync"))
        assert guard._fast_path is None

    def test_fast_path_enabled_creates_evaluator(self):
        from pramanix.fast_path import FastPathEvaluator

        guard = self._make_guard([SemanticFastPath.negative_amount()])
        assert isinstance(guard._fast_path, FastPathEvaluator)

    def test_fast_path_blocks_negative_amount(self):
        guard = self._make_guard([SemanticFastPath.negative_amount("amount")])
        d = guard.verify(
            intent={"amount": Decimal("-100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                "risk_score": 0.3,
                "state_version": "1.0",
            },
        )
        assert d.allowed is False
        assert "non-negative" in d.explanation.lower() or "negative" in d.explanation.lower()

    def test_fast_path_passes_valid_request_to_z3(self):
        """Fast-path pass → Z3 runs → allowed=True for valid intent."""
        guard = self._make_guard([SemanticFastPath.negative_amount("amount")])
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                "risk_score": 0.3,
                "state_version": "1.0",
            },
        )
        assert d.allowed is True

    def test_fast_path_block_is_unsafe_status(self):
        guard = self._make_guard([SemanticFastPath.account_frozen("is_frozen")])
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": True,
                "daily_limit": Decimal("10000"),
                "risk_score": 0.3,
                "state_version": "1.0",
            },
        )
        assert d.allowed is False
        from pramanix.decision import SolverStatus

        assert d.status == SolverStatus.UNSAFE
