# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Adversarial tests — numeric boundary values in fast-path rules.

Verifies that non-finite Decimal values (Infinity, -Infinity, NaN) and other
numeric edge-cases are BLOCKED by the fast-path before reaching Z3.

INVARIANT: fast-path is fail-closed — every parse failure or non-finite value
must produce a block reason string, never None (pass-through).

Boundary vectors covered:
  A  +Infinity amount   → must block  (not a valid financial value)
  B  -Infinity amount   → must block  (not a valid financial value)
  C  NaN amount         → must block  (not a valid financial value)
  D  +Infinity balance  → must block
  E  -Infinity balance  → must block
  F  NaN balance        → must block
  G  Negative zero      → passes negative_amount (0 is not < 0) — correct
  H  Subnormal float    → parsed fine, normal comparison applies
  I  sys.float_info.max → passes if below hard cap (finite)
  J  Non-numeric string → blocked as malformed
  K  FastPathEvaluator  → stops at first blocking rule
  L  End-to-end Guard   → Infinity blocked before Z3
"""

from __future__ import annotations

import sys

from pramanix.fast_path import FastPathEvaluator, FastPathResult, SemanticFastPath

# ── Helpers ───────────────────────────────────────────────────────────────────


def _block_or_pass(rule, intent: dict, state: dict) -> str | None:
    """Invoke a single rule and return its result."""
    return rule(intent, state)


def assert_blocks(rule, intent: dict, state: dict, *, substr: str = "") -> None:
    reason = _block_or_pass(rule, intent, state)
    assert (
        reason is not None
    ), f"Expected block but got pass-through; intent={intent}, state={state}"
    if substr:
        assert substr.lower() in reason.lower(), f"Expected {substr!r} in reason: {reason!r}"


def assert_passes(rule, intent: dict, state: dict) -> None:
    reason = _block_or_pass(rule, intent, state)
    assert reason is None, f"Expected pass-through but got block: {reason!r}"


# ── A: positive Infinity in negative_amount ───────────────────────────────────


class TestNegativeAmountNonFinite:
    def test_A_positive_infinity_blocks(self) -> None:
        """+Infinity is not a valid financial amount — must block."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_blocks(rule, {"amount": "Infinity"}, {}, substr="non-finite")

    def test_A_positive_infinity_float_string_blocks(self) -> None:
        """String 'inf' (case-insensitive) also resolves to +Infinity."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_blocks(rule, {"amount": "inf"}, {}, substr="non-finite")

    def test_B_negative_infinity_blocks(self) -> None:
        """-Infinity is negative — doubly invalid. Must block."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_blocks(rule, {"amount": "-Infinity"}, {}, substr="non-finite")

    def test_C_nan_blocks(self) -> None:
        """NaN is not parseable in comparison — must block."""
        rule = SemanticFastPath.negative_amount("amount")
        reason = _block_or_pass(rule, {"amount": "NaN"}, {})
        assert reason is not None, "NaN must always block"

    def test_G_negative_zero_passes_negative_check(self) -> None:
        """-0 is not < 0 in Decimal arithmetic — a valid boundary value."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_passes(rule, {"amount": "-0"}, {})

    def test_H_subnormal_positive_passes(self) -> None:
        """Subnormal (denormal) positive float is a valid small positive number."""
        rule = SemanticFastPath.negative_amount("amount")
        subnormal = repr(sys.float_info.min * sys.float_info.epsilon)
        assert_passes(rule, {"amount": subnormal}, {})

    def test_I_sys_float_max_is_finite_passes(self) -> None:
        """sys.float_info.max is finite — passes negative check (not negative)."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_passes(rule, {"amount": str(sys.float_info.max)}, {})

    def test_negative_amount_blocks(self) -> None:
        """-0.01 is correctly blocked as negative."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_blocks(rule, {"amount": "-0.01"}, {}, substr="non-negative")

    def test_positive_finite_passes(self) -> None:
        """Normal positive amount passes."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_passes(rule, {"amount": "100.00"}, {})

    def test_from_state_dict_infinity_blocks(self) -> None:
        """Infinity sourced from state dict is also blocked."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_blocks(rule, {}, {"amount": "Infinity"}, substr="non-finite")

    def test_J_non_numeric_string_blocks(self) -> None:
        """Non-numeric string triggers parse failure → fail-closed block."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_blocks(rule, {"amount": "not-a-number"}, {})

    def test_none_value_passes(self) -> None:
        """Missing field is a pass-through — rule is opt-in."""
        rule = SemanticFastPath.negative_amount("amount")
        assert_passes(rule, {}, {})


# ── D/E/F: Infinity in zero_or_negative_balance ───────────────────────────────


class TestZeroOrNegativeBalanceNonFinite:
    def test_D_positive_infinity_balance_blocks(self) -> None:
        """+Infinity balance is not a real account balance — must block."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert_blocks(rule, {}, {"balance": "Infinity"}, substr="non-finite")

    def test_D_inf_lowercase_blocks(self) -> None:
        """'inf' string is +Infinity — must block."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert_blocks(rule, {}, {"balance": "inf"}, substr="non-finite")

    def test_E_negative_infinity_balance_blocks(self) -> None:
        """-Infinity balance is doubly invalid — must block."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert_blocks(rule, {}, {"balance": "-Infinity"}, substr="non-finite")

    def test_F_nan_balance_blocks(self) -> None:
        """NaN balance must block."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        reason = _block_or_pass(rule, {}, {"balance": "NaN"})
        assert reason is not None, "NaN balance must always block"

    def test_zero_balance_blocks(self) -> None:
        """Zero balance is a zero_or_negative violation."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert_blocks(rule, {}, {"balance": "0"}, substr="zero or negative")

    def test_positive_balance_passes(self) -> None:
        """Normal positive balance passes."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert_passes(rule, {}, {"balance": "5000.00"})

    def test_none_balance_passes(self) -> None:
        """Missing balance is a pass-through."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert_passes(rule, {}, {})


# ── exceeds_hard_cap non-finite values ────────────────────────────────────────


class TestExceedsHardCapNonFinite:
    def test_positive_infinity_blocks(self) -> None:
        """+Infinity exceeds any finite cap AND is non-finite — must block."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert_blocks(rule, {"amount": "Infinity"}, {}, substr="non-finite")

    def test_negative_infinity_blocks(self) -> None:
        """-Infinity is non-finite — must block (previously it passed the > cap check)."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert_blocks(rule, {"amount": "-Infinity"}, {}, substr="non-finite")

    def test_nan_blocks(self) -> None:
        """NaN must block."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        reason = _block_or_pass(rule, {"amount": "NaN"}, {})
        assert reason is not None, "NaN must always block"

    def test_amount_exactly_at_cap_passes(self) -> None:
        """Amount == cap is NOT > cap → passes fast-path (Z3 will verify)."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert_passes(rule, {"amount": "1000000"}, {})

    def test_amount_above_cap_blocks(self) -> None:
        """1_000_001 > 1_000_000 → blocked."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert_blocks(rule, {"amount": "1000001"}, {}, substr="hard cap")

    def test_sys_float_max_blocks_when_above_cap(self) -> None:
        """sys.float_info.max is finite but enormous — blocked by cap check."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert_blocks(rule, {"amount": str(sys.float_info.max)}, {}, substr="hard cap")

    def test_none_passes(self) -> None:
        """Missing amount is a pass-through."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert_passes(rule, {}, {})


# ── amount_exceeds_balance non-finite values ──────────────────────────────────


class TestAmountExceedsBalanceNonFinite:
    def test_infinity_amount_blocks(self) -> None:
        """+Infinity amount is non-finite — must block before balance comparison."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_blocks(rule, {"amount": "Infinity"}, {"balance": "1000.00"}, substr="non-finite")

    def test_negative_infinity_amount_blocks(self) -> None:
        """-Infinity amount is non-finite — must block (previously slipped past)."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_blocks(rule, {"amount": "-Infinity"}, {"balance": "1000.00"}, substr="non-finite")

    def test_nan_amount_blocks(self) -> None:
        """NaN amount must block."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        reason = _block_or_pass(rule, {"amount": "NaN"}, {"balance": "1000.00"})
        assert reason is not None, "NaN amount must block"

    def test_infinity_balance_blocks(self) -> None:
        """+Infinity balance is an invalid state — must block."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_blocks(rule, {"amount": "100.00"}, {"balance": "Infinity"}, substr="non-finite")

    def test_negative_infinity_balance_blocks(self) -> None:
        """-Infinity balance is invalid — must block."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_blocks(rule, {"amount": "100.00"}, {"balance": "-Infinity"}, substr="non-finite")

    def test_both_infinity_blocks_on_amount_first(self) -> None:
        """When both are Infinity, amount check fires first."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        reason = _block_or_pass(rule, {"amount": "Infinity"}, {"balance": "Infinity"})
        assert reason is not None, "Both Infinity must block"
        assert "amount" in reason.lower()

    def test_normal_overdraft_blocks(self) -> None:
        """100 > 50 → blocked as insufficient balance."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_blocks(rule, {"amount": "100"}, {"balance": "50"}, substr="insufficient")

    def test_amount_equal_to_balance_passes(self) -> None:
        """100 == 100 → not > balance, so passes fast-path."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_passes(rule, {"amount": "100"}, {"balance": "100"})

    def test_amount_less_than_balance_passes(self) -> None:
        """50 < 100 → passes fast-path (Z3 will verify further constraints)."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_passes(rule, {"amount": "50"}, {"balance": "100"})

    def test_missing_amount_passes(self) -> None:
        """Missing amount is a pass-through — rule requires both fields."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_passes(rule, {}, {"balance": "100"})

    def test_missing_balance_passes(self) -> None:
        """Missing balance is a pass-through — rule requires both fields."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert_passes(rule, {"amount": "50"}, {})


# ── K: FastPathEvaluator stops at first block ─────────────────────────────────


class TestFastPathEvaluatorOrdering:
    def test_K_evaluator_stops_on_first_block(self) -> None:
        """Evaluator must return on the first blocking rule, not run all rules."""
        executed = []

        def _rule_a(intent, state):
            executed.append("a")
            return "blocked by A"

        def _rule_b(intent, state):
            executed.append("b")
            return "blocked by B"

        evaluator = FastPathEvaluator([_rule_a, _rule_b])
        result = evaluator.evaluate({"amount": "Infinity"}, {})
        assert result.blocked
        assert result.reason == "blocked by A"
        assert executed == ["a"], "Rule B must not be executed after Rule A blocks"

    def test_evaluator_runs_all_rules_if_none_block(self) -> None:
        """All rules run when none block."""
        executed = []

        def _rule_a(intent, state):
            executed.append("a")
            return None

        def _rule_b(intent, state):
            executed.append("b")
            return None

        evaluator = FastPathEvaluator([_rule_a, _rule_b])
        result = evaluator.evaluate({}, {})
        assert not result.blocked
        assert executed == ["a", "b"]

    def test_evaluator_rule_count(self) -> None:
        """rule_count reflects registered rules."""
        rules = [
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.zero_or_negative_balance("balance"),
            SemanticFastPath.exceeds_hard_cap("amount", cap=500_000),
        ]
        evaluator = FastPathEvaluator(rules)
        assert evaluator.rule_count == 3

    def test_evaluator_exception_in_rule_blocks_fail_closed(self) -> None:
        """A rule that raises an exception causes fail-closed BLOCK; subsequent rules skipped."""

        def _buggy_rule(intent, state):
            raise RuntimeError("simulated rule crash")

        def _safe_rule(intent, state):
            return "blocked by safe rule"

        evaluator = FastPathEvaluator([_buggy_rule, _safe_rule])
        result = evaluator.evaluate({}, {})
        assert result.blocked
        assert "fail-closed" in result.reason
        assert result.rule_name == "_buggy_rule"

    def test_evaluator_infinity_blocked_by_combined_rules(self) -> None:
        """Infinity amount blocked at first applicable rule in a multi-rule evaluator."""
        evaluator = FastPathEvaluator(
            [
                SemanticFastPath.negative_amount("amount"),
                SemanticFastPath.zero_or_negative_balance("balance"),
                SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000),
            ]
        )
        result = evaluator.evaluate({"amount": "Infinity"}, {"balance": "5000"})
        assert result.blocked
        assert "non-finite" in result.reason.lower()

    def test_evaluator_empty_rules_pass_through(self) -> None:
        """No rules → always pass-through."""
        evaluator = FastPathEvaluator([])
        result = evaluator.evaluate({"amount": "Infinity"}, {})
        assert not result.blocked


# ── FastPathResult contract ───────────────────────────────────────────────────


class TestFastPathResultContract:
    def test_pass_through_not_blocked(self) -> None:
        result = FastPathResult.pass_through()
        assert not result.blocked
        assert result.reason == ""

    def test_block_is_blocked(self) -> None:
        result = FastPathResult.block("test reason", rule_name="test_rule")
        assert result.blocked
        assert result.reason == "test reason"
        assert result.rule_name == "test_rule"

    def test_block_without_rule_name(self) -> None:
        result = FastPathResult.block("test reason")
        assert result.blocked
        assert result.rule_name == ""


# ── L: End-to-end Guard blocks Infinity before Z3 ────────────────────────────


class TestGuardBlocksNonFiniteEndToEnd:
    """Verify that Infinity/NaN reach Guard.verify() and come back BLOCK."""

    def test_L_infinity_amount_blocked_end_to_end(self) -> None:
        """Guard with fast_path enabled blocks +Infinity before reaching Z3."""
        from pramanix.expressions import E, Field
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _TransferPolicy(Policy):
            amount = Field("amount", float, "Real")

            class Meta:
                name = "TransferPolicy"

            @classmethod
            def invariants(cls):
                return [(E(cls.amount) >= 0).named("non_negative_amount")]

        config = GuardConfig(
            fast_path_enabled=True,
            fast_path_rules=(SemanticFastPath.negative_amount("amount"),),
        )
        guard = Guard(_TransferPolicy, config=config)
        decision = guard.verify(
            intent={"amount": "Infinity"},
            state={},
        )
        assert not decision.allowed, "Infinity amount must be blocked"

    def test_L_negative_infinity_blocked_end_to_end(self) -> None:
        """Guard blocks -Infinity amount end-to-end."""
        from pramanix.expressions import E, Field
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _TransferPolicy2(Policy):
            amount = Field("amount", float, "Real")

            class Meta:
                name = "TransferPolicy2"

            @classmethod
            def invariants(cls):
                return [(E(cls.amount) >= 0).named("non_negative_amount")]

        config = GuardConfig(
            fast_path_enabled=True,
            fast_path_rules=(SemanticFastPath.negative_amount("amount"),),
        )
        guard = Guard(_TransferPolicy2, config=config)
        decision = guard.verify(
            intent={"amount": "-Infinity"},
            state={},
        )
        assert not decision.allowed, "-Infinity amount must be blocked"

    def test_L_valid_amount_reaches_z3_and_is_allowed(self) -> None:
        """A valid finite amount passes fast-path and Z3 allows it."""
        from pramanix.expressions import E, Field
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _TransferPolicy3(Policy):
            amount = Field("amount", float, "Real")

            class Meta:
                name = "TransferPolicy3"

            @classmethod
            def invariants(cls):
                return [(E(cls.amount) >= 0).named("non_negative_amount")]

        config = GuardConfig(
            fast_path_enabled=True,
            fast_path_rules=(SemanticFastPath.negative_amount("amount"),),
        )
        guard = Guard(_TransferPolicy3, config=config)
        decision = guard.verify(
            intent={"amount": 100.0},
            state={},
        )
        assert decision.allowed, "Valid positive amount must be allowed"
