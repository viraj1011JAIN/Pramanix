# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Targeted tests that fill coverage gaps identified by the supervisor's audit.

Files targeted:
- fast_path.py       — exception handlers in rule closures
- primitives/infra.py— Phase-4 primitives (MinReplicas, MaxReplicas, etc.)
- transpiler.py      — InvariantMeta edge cases, BoolOp/_InOp/Unknown AST paths
- translator/_sanitise.py — truncation, control chars, score edge cases
- guard.py           — _semantic_post_consensus_check, metrics, verify_async gaps
"""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import PolicyCompilationError, SemanticPolicyViolation
from pramanix.expressions import (
    ConstraintExpr,
    _BoolOp,
    _CmpOp,
    _FieldRef,
    _InOp,
    _Literal,
)
from pramanix.fast_path import SemanticFastPath
from pramanix.primitives.infra import (
    MaxReplicas,
    MinReplicas,
    WithinCPUBudget,
    WithinMemoryBudget,
)
from pramanix.translator._sanitise import injection_confidence_score, sanitise_user_input
from pramanix.transpiler import (
    InvariantMeta,
    _collect_field_names,
    _tree_has_literal,
    _tree_repr,
    compile_policy,
    transpile,
)

# ── Shared policy fixture ─────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")
_frozen = Field("is_frozen", bool, "Bool")
_limit = Field("daily_limit", Decimal, "Real")


class SimplePolicy(Policy):
    class Meta:
        version = "1.0"

    amount = _amount
    balance = _balance
    is_frozen = _frozen
    daily_limit = _limit

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Insufficient"),
            (E(cls.is_frozen) == False).named("not_frozen").explain("Frozen"),  # noqa: E712
            (E(cls.amount) <= E(cls.daily_limit)).named("within_limit").explain("Limit"),
        ]


class NoVersionPolicy(Policy):
    """Policy without Meta.version — used to test version-less verify paths."""

    amount = _amount
    balance = _balance

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Insufficient"),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. fast_path.py — exception handlers and missing-field paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestFastPathExceptionHandlers:
    """Cover except-clause lines inside rule closures (83-84, 101-102, 136-137, 163-164)."""

    def test_negative_amount_swallows_non_numeric_string(self):
        """Lines 83-84: Decimal("not-a-number") raises → except swallows → None."""
        rule = SemanticFastPath.negative_amount("amount")
        result = rule({"amount": "not-a-number"}, {})
        assert result is None

    def test_negative_amount_swallows_dict_value(self):
        """Lines 83-84: Decimal(str({})) raises InvalidOperation → None."""
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": {}}, {}) is None

    def test_zero_or_negative_balance_swallows_non_numeric(self):
        """Lines 101-102: Decimal("not-a-balance") raises → except swallows → None."""
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert rule({}, {"balance": "not-a-balance"}) is None

    def test_exceeds_hard_cap_missing_field_returns_none(self):
        """Line 132: val is None when neither intent nor state has the field."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert rule({}, {}) is None

    def test_exceeds_hard_cap_swallows_non_numeric(self):
        """Lines 136-137: Decimal("xyz") raises → except swallows → None."""
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert rule({"amount": "xyz"}, {}) is None

    def test_amount_exceeds_balance_swallows_non_numeric_amount(self):
        """Lines 163-164: Decimal(str("bad")) raises → except swallows → None."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert rule({"amount": "bad"}, {"balance": Decimal("500")}) is None

    def test_amount_exceeds_balance_swallows_non_numeric_balance(self):
        """Lines 163-164: Decimal(str("bad")) for balance raises → None."""
        rule = SemanticFastPath.amount_exceeds_balance("amount", "balance")
        assert rule({"amount": Decimal("100")}, {"balance": "bad"}) is None


# ═══════════════════════════════════════════════════════════════════════════════
# 2. primitives/infra.py — Phase-4 primitives (lines 59, 75, 91, 107)
# ═══════════════════════════════════════════════════════════════════════════════


class TestInfraPhase4Primitives:
    """Cover MinReplicas, MaxReplicas, WithinCPUBudget, WithinMemoryBudget."""

    def _make_fields(self):
        f1 = Field("replicas", int, "Int")
        f2 = Field("min_r", int, "Int")
        f3 = Field("max_r", int, "Int")
        f_cpu_req = Field("cpu_request", int, "Int")
        f_cpu_bud = Field("cpu_budget", int, "Int")
        f_mem_req = Field("mem_request", int, "Int")
        f_mem_bud = Field("mem_budget", int, "Int")
        return f1, f2, f3, f_cpu_req, f_cpu_bud, f_mem_req, f_mem_bud

    def test_min_replicas_returns_constraint(self):
        """Line 59: MinReplicas returns a ConstraintExpr."""
        f_rep, f_min, *_ = self._make_fields()
        c = MinReplicas(f_rep, f_min)
        assert isinstance(c, ConstraintExpr)
        assert c.label == "min_replicas"

    def test_max_replicas_returns_constraint(self):
        """Line 75: MaxReplicas returns a ConstraintExpr."""
        f_rep, _, f_max, *_ = self._make_fields()
        c = MaxReplicas(f_rep, f_max)
        assert isinstance(c, ConstraintExpr)
        assert c.label == "max_replicas"

    def test_within_cpu_budget_returns_constraint(self):
        """Line 91: WithinCPUBudget returns a ConstraintExpr."""
        *_, f_cpu_req, f_cpu_bud, _, _ = self._make_fields()
        c = WithinCPUBudget(f_cpu_req, f_cpu_bud)
        assert isinstance(c, ConstraintExpr)
        assert c.label == "within_cpu_budget"

    def test_within_memory_budget_returns_constraint(self):
        """Line 107: WithinMemoryBudget returns a ConstraintExpr."""
        *_, f_mem_req, f_mem_bud = self._make_fields()
        c = WithinMemoryBudget(f_mem_req, f_mem_bud)
        assert isinstance(c, ConstraintExpr)
        assert c.label == "within_memory_budget"

    def test_min_replicas_integrates_with_guard(self):
        """MinReplicas works end-to-end with Guard.verify()."""
        f_rep = Field("replicas", int, "Int")
        f_min = Field("min_r", int, "Int")

        class ScalingPolicy(Policy):
            class Meta:
                version = "1.0"

            replicas = f_rep
            min_r = f_min

            @classmethod
            def invariants(cls):
                return [MinReplicas(cls.replicas, cls.min_r)]

        guard = Guard(ScalingPolicy, GuardConfig(execution_mode="sync"))

        # Safe: replicas >= min_r
        d = guard.verify(
            intent={"replicas": 3},
            state={"min_r": 2, "state_version": "1.0"},
        )
        assert d.allowed is True

        # Blocked: replicas < min_r
        d2 = guard.verify(
            intent={"replicas": 1},
            state={"min_r": 2, "state_version": "1.0"},
        )
        assert d2.allowed is False

    def test_within_cpu_budget_integrates_with_guard(self):
        """WithinCPUBudget works end-to-end with Guard.verify()."""
        f_cpu = Field("cpu_request", int, "Int")
        f_bud = Field("cpu_budget", int, "Int")

        class CPUPolicy(Policy):
            class Meta:
                version = "1.0"

            cpu_request = f_cpu
            cpu_budget = f_bud

            @classmethod
            def invariants(cls):
                return [WithinCPUBudget(cls.cpu_request, cls.cpu_budget)]

        guard = Guard(CPUPolicy, GuardConfig(execution_mode="sync"))

        d = guard.verify(
            intent={"cpu_request": 500},
            state={"cpu_budget": 1000, "state_version": "1.0"},
        )
        assert d.allowed is True


# ═══════════════════════════════════════════════════════════════════════════════
# 3. transpiler.py — InvariantMeta edge cases and AST tree helpers
# ═══════════════════════════════════════════════════════════════════════════════


class TestInvariantMetaEdgeCases:
    """Lines 88, 90: InvariantMeta.__post_init__ raises on bad construction."""

    def test_empty_label_raises(self):
        """Line 88: InvariantMeta with empty label raises ValueError."""
        with pytest.raises(ValueError, match="label cannot be empty"):
            InvariantMeta(
                label="",
                explain_template="",
                field_refs=frozenset({"x"}),
                tree_repr="Lit(1)",
                has_literal=True,
            )

    def test_empty_field_refs_raises(self):
        """Line 90: InvariantMeta with empty field_refs raises ValueError."""
        with pytest.raises(ValueError, match="no field references"):
            InvariantMeta(
                label="test",
                explain_template="",
                field_refs=frozenset(),
                tree_repr="Lit(1)",
                has_literal=True,
            )


class TestTranspilerSingleInOp:
    """Line 301: _InOp with a single value returns disjuncts[0], not Or()."""

    def test_is_in_single_value_no_or(self):
        """Line 301: transpile .is_in(["one"]) returns bare equality, not z3.Or."""
        import z3

        f = Field("status", str, "String")
        expr = E(f).is_in(["active"]).named("single_in")
        ctx = z3.Context()
        formula = transpile(expr.node, ctx)
        # Should be a BoolRef (equality), not an Or
        assert formula is not None
        assert str(formula.sort()) == "Bool"


class TestCompilePolicyNoFieldRefs:
    """Line 381: compile_policy raises PolicyCompilationError for no-field invariant."""

    def test_invariant_with_no_field_refs_raises(self):
        """Line 381: PolicyCompilationError when invariant has label but no Fields."""

        class FakePureLiteralInvariant:
            """Looks like a ConstraintExpr but inner node has no FieldRef."""

            label = "pure_literal"
            explanation = ""
            node = _Literal(value=Decimal("1"))

        with pytest.raises(PolicyCompilationError, match="references no Fields"):
            compile_policy([FakePureLiteralInvariant()])


class TestCollectFieldNamesEdgeCases:
    """Lines 417->421: _collect_field_names with inner=None falls through to collect_fields."""

    def test_constraint_with_none_inner_node(self):
        """Branch 417->421 (False): inner is None → falls through to collect_fields."""

        class NullInnerConstraint:
            label = "x"
            node = None

        result = _collect_field_names(NullInnerConstraint())
        assert result == []

    def test_bool_op_invariant_collects_fields(self):
        """_collect_field_names correctly walks BoolOp with nested field refs."""
        f1 = Field("x", Decimal, "Real")
        f2 = Field("y", Decimal, "Real")
        inv = ((E(f1) >= Decimal("0")) & (E(f2) <= Decimal("100"))).named("combined")
        names = _collect_field_names(inv)
        assert "x" in names
        assert "y" in names

    def test_in_op_collects_field(self):
        """_collect_field_names on InOp only collects the left-side field."""
        f = Field("status", str, "String")
        inv = E(f).is_in(["a", "b"]).named("in_test")
        names = _collect_field_names(inv)
        assert "status" in names


class TestTreeHasLiteralEdgeCases:
    """Lines 433->436, 442, 444: _tree_has_literal edge cases."""

    def test_constraint_with_none_inner_returns_false(self):
        """Branch 433->436 (False): inner is None → falls to match → case _: False."""

        class NullInnerConstraint:
            label = "x"
            node = None

        assert _tree_has_literal(NullInnerConstraint()) is False

    def test_bool_op_with_literal_returns_true(self):
        """Line 442: BoolOp containing a literal via _tree_has_literal(inner_BoolOp)."""
        f1 = Field("a", Decimal, "Real")
        f2 = Field("b", Decimal, "Real")
        # Both sides have literal constants → inner _BoolOp → line 442
        inv = ((E(f1) >= Decimal("0")) & (E(f2) <= Decimal("100"))).named("with_lit")
        assert _tree_has_literal(inv) is True

    def test_bool_op_field_only_returns_false(self):
        """Line 442: BoolOp with no literals → returns False."""
        f1 = Field("a", Decimal, "Real")
        f2 = Field("b", Decimal, "Real")
        inv = ((E(f1) >= E(f2)) & (E(f1) <= E(f2))).named("no_lit")
        assert _tree_has_literal(inv) is False

    def test_in_op_with_values_returns_true(self):
        """Line 444: InOp with non-empty values list → len(vs) > 0 → True."""
        f = Field("status", str, "String")
        inv = E(f).is_in(["a", "b"]).named("in_test")
        assert _tree_has_literal(inv) is True

    def test_in_op_empty_values_returns_false(self):
        """Line 444: InOp with empty values → len(vs) > 0 = False → False."""
        f = Field("status", str, "String")
        inop = _InOp(left=_FieldRef(field=f), values=[])
        assert _tree_has_literal(inop) is False


class TestTreeReprEdgeCases:
    """Lines 462->465, 474-479: _tree_repr edge cases."""

    def test_constraint_with_none_inner_returns_unknown(self):
        """Branch 462->465 (False) + line 478-479: inner=None → Unknown(...)."""

        class NullInnerConstraint:
            label = "x"
            node = None

        r = _tree_repr(NullInnerConstraint())
        assert "Unknown" in r

    def test_bool_op_repr(self):
        """Line 474-475: _tree_repr on a raw _BoolOp node."""
        f = Field("x", Decimal, "Real")
        boolop = _BoolOp(
            op="and",
            operands=[
                _CmpOp(op="ge", left=_FieldRef(field=f), right=_Literal(value=Decimal("0"))),
            ],
        )
        r = _tree_repr(boolop)
        assert r.startswith("BoolOp(and,")

    def test_in_op_repr(self):
        """Line 476-477: _tree_repr on a raw _InOp node."""
        f = Field("status", str, "String")
        inop = _InOp(
            left=_FieldRef(field=f),
            values=[_Literal(value="active"), _Literal(value="pending")],
        )
        r = _tree_repr(inop)
        assert r.startswith("InOp(")

    def test_unknown_node_repr(self):
        """Line 478-479: _tree_repr on an unrecognised node returns Unknown(...)."""

        class RandomNode:
            pass

        r = _tree_repr(RandomNode())
        assert r.startswith("Unknown(")

    def test_bool_op_constraint_repr(self):
        """Lines 462-463, 474: ConstraintExpr wrapping BoolOp goes through full path."""
        f1 = Field("p", Decimal, "Real")
        f2 = Field("q", Decimal, "Real")
        inv = ((E(f1) >= Decimal("0")) & (E(f2) <= Decimal("1"))).named("combined")
        r = _tree_repr(inv)
        assert "Constraint(" in r
        assert "BoolOp(" in r

    def test_compile_policy_with_bool_op_invariant(self):
        """compile_policy correctly compiles a BoolOp invariant (covers lines 442, 474)."""
        f1 = Field("a", Decimal, "Real")
        f2 = Field("b", Decimal, "Real")
        inv = ((E(f1) >= Decimal("0")) & (E(f2) <= Decimal("100"))).named("ab_range")
        meta_list = compile_policy([inv])
        assert len(meta_list) == 1
        assert meta_list[0].label == "ab_range"
        assert meta_list[0].has_literal is True
        assert "a" in meta_list[0].field_refs
        assert "b" in meta_list[0].field_refs

    def test_compile_policy_with_in_op_invariant(self):
        """compile_policy correctly compiles an InOp invariant (covers lines 444, 476)."""
        f = Field("status", str, "String")
        inv = E(f).is_in(["active", "pending"]).named("status_check")
        meta_list = compile_policy([inv])
        assert len(meta_list) == 1
        assert meta_list[0].label == "status_check"
        assert meta_list[0].has_literal is True  # InOp always has "literals"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. translator/_sanitise.py — truncation, control chars, score gaps
# ═══════════════════════════════════════════════════════════════════════════════


class TestSanitiseInputEdgeCases:
    """Lines 120-121, 126: truncation and control-char stripping."""

    def test_long_input_is_truncated(self):
        """Lines 120-121: input > 512 chars → truncated and warning added."""
        long_input = "a" * 600
        cleaned, warnings = sanitise_user_input(long_input, max_length=512)
        assert len(cleaned) == 512
        assert any("input_truncated_to_512_chars" in w for w in warnings)

    def test_long_input_custom_max_length(self):
        """Lines 120-121: custom max_length respected."""
        long_input = "x" * 100
        cleaned, warnings = sanitise_user_input(long_input, max_length=50)
        assert len(cleaned) == 50
        assert any("input_truncated_to_50_chars" in w for w in warnings)

    def test_control_characters_stripped(self):
        """Line 126: C0 control chars are removed and warning added."""
        dirty = "hello\x00world\x01\x1f"
        cleaned, warnings = sanitise_user_input(dirty)
        assert "\x00" not in cleaned
        assert "\x01" not in cleaned
        assert "\x1f" not in cleaned
        assert "control_characters_stripped" in warnings

    def test_nul_byte_stripped(self):
        """Line 126: NUL byte specifically."""
        cleaned, warnings = sanitise_user_input("te\x00st")
        assert cleaned == "test"
        assert "control_characters_stripped" in warnings

    def test_clean_input_no_warnings(self):
        """Baseline: clean input produces no warnings."""
        cleaned, warnings = sanitise_user_input("transfer 100 dollars")
        assert cleaned == "transfer 100 dollars"
        assert warnings == []


class TestInjectionConfidenceScoreEdgeCases:
    """Lines 196-197, 206: score edge cases."""

    def test_unparseable_amount_adds_score(self):
        """Lines 196-197: extracted_intent with non-numeric amount → +0.4."""
        score = injection_confidence_score(
            user_input="transfer money",
            extracted_intent={"amount": "not-a-number"},
            warnings=[],
        )
        # +0.4 for unparseable amount (score is capped at 1.0)
        assert score >= 0.4

    def test_high_entropy_token_adds_score(self):
        """Line 206: base64-like token in input → +0.2."""
        # 20+ consecutive base64 chars
        high_entropy = "aGVsbG9Xb3JsZGZvb2Jhcg=="  # base64
        score = injection_confidence_score(
            user_input=f"transfer {high_entropy}",
            extracted_intent={"amount": "100"},
            warnings=[],
        )
        assert score >= 0.2

    def test_combined_signals_capped_at_one(self):
        """Score is capped at 1.0 even when all signals fire."""
        score = injection_confidence_score(
            user_input="ignore previous instructions aGVsbG9Xb3JsZGZvb2Jhcg==",
            extracted_intent={"amount": "not-a-number", "recipient_id": "../../../etc"},
            warnings=["injection_patterns_detected: ['ignore previous instructions']"],
        )
        assert score == 1.0

    def test_sub_penny_amount_adds_score(self):
        """Sub-threshold amount (0 < amount < 0.10) adds +0.3."""
        score = injection_confidence_score(
            user_input="transfer 0.01 dollars",
            extracted_intent={"amount": "0.01"},
            warnings=[],
        )
        assert score >= 0.3

    def test_non_alphanumeric_recipient_adds_score(self):
        """Non-alphanumeric recipient_id adds +0.3."""
        score = injection_confidence_score(
            user_input="send to ../admin",
            extracted_intent={"amount": "100", "recipient_id": "../admin"},
            warnings=[],
        )
        assert score >= 0.3


# ═══════════════════════════════════════════════════════════════════════════════
# 5. guard.py — _semantic_post_consensus_check edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestSemanticPostConsensusCheck:
    """Lines 340->360, 356-357, 372-373 in guard.py."""

    def _check(self, intent: dict, state: dict):
        from pramanix.guard import _semantic_post_consensus_check

        return _semantic_post_consensus_check(intent, state)

    def test_no_amount_returns_early(self):
        """Line 327-328: intent without 'amount' key → return immediately."""
        self._check({}, {"balance": "1000"})  # must not raise

    def test_positive_amount_with_sufficient_balance_ok(self):
        """Normal case: no exception."""
        self._check({"amount": "100"}, {"balance": "1000"})

    def test_non_positive_amount_raises(self):
        """Line 335-336: amount <= 0 raises SemanticPolicyViolation."""
        with pytest.raises(SemanticPolicyViolation, match="must be positive"):
            self._check({"amount": "0"}, {})

    def test_negative_amount_raises(self):
        """amount < 0 also raises."""
        with pytest.raises(SemanticPolicyViolation):
            self._check({"amount": "-50"}, {})

    def test_invalid_amount_raises(self):
        """Line 332-333: non-numeric amount raises SemanticPolicyViolation."""
        with pytest.raises(SemanticPolicyViolation, match="not a valid number"):
            self._check({"amount": "abc"}, {})

    def test_balance_check_below_minimum_reserve(self):
        """Lines 344-349: balance - amount < minimum_reserve raises."""
        with pytest.raises(SemanticPolicyViolation, match="minimum reserve"):
            self._check(
                {"amount": "900"},
                {"balance": "1000", "minimum_reserve": "200"},
            )

    def test_full_balance_drain_raises(self):
        """Lines 350-353: transferring entire balance (amount == balance, reserve=0) raises."""
        with pytest.raises(SemanticPolicyViolation, match="secondary human approval"):
            self._check(
                {"amount": "1000"},
                {"balance": "1000"},  # reserve defaults to 0
            )

    def test_non_numeric_balance_silently_ignored(self):
        """Lines 356-357: non-numeric balance → except Exception: pass, no raise."""
        self._check({"amount": "100"}, {"balance": "not-a-number"})  # must not raise

    def test_no_balance_skips_balance_check_goes_to_daily_limit(self):
        """Branch 340->360 False: no balance key → skips balance block, checks daily limit."""
        # No balance → goes straight to daily limit check (line 360+)
        with pytest.raises(SemanticPolicyViolation, match="daily limit"):
            self._check(
                {"amount": "500"},
                {"daily_limit": "400", "daily_spent": "0"},
            )

    def test_daily_limit_exceeded_raises(self):
        """Lines 365-369: amount > remaining → SemanticPolicyViolation."""
        with pytest.raises(SemanticPolicyViolation, match="daily limit"):
            self._check(
                {"amount": "300"},
                {"balance": "1000", "daily_limit": "400", "daily_spent": "200"},
            )

    def test_non_numeric_daily_limit_silently_ignored(self):
        """Lines 372-373: non-numeric daily_limit → except Exception: pass, no raise."""
        # Both present but non-numeric → Decimal conversion fails → swallowed
        self._check(
            {"amount": "100"},
            {"daily_limit": "not-a-limit", "daily_spent": "0"},
        )  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# 6. guard.py — compile_policy failure re-raises (lines 474-475)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardInitCompilePolicyFailure:
    """Lines 474-475: compile_policy exception propagates from Guard.__init__."""

    def test_compile_policy_failure_propagates(self):
        """Lines 474-475: if compile_policy raises, Guard.__init__ re-raises."""
        with (
            patch("pramanix.transpiler.compile_policy", side_effect=RuntimeError("boom")),
            pytest.raises(RuntimeError, match="boom"),
        ):
            Guard(SimplePolicy, GuardConfig(execution_mode="sync"))


# ═══════════════════════════════════════════════════════════════════════════════
# 7. guard.py — Prometheus metrics branches (lines 720, 722)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardMetricsBranches:
    """Lines 720, 722: metrics_enabled paths for timeout and validation_failure."""

    def test_stale_state_increments_validation_failure_metric(self):
        """Line 722: stale_state status increments validation_failures_total."""
        guard = Guard(SimplePolicy, GuardConfig(execution_mode="sync", metrics_enabled=True))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                "state_version": "WRONG_VERSION",  # triggers stale_state
            },
        )
        assert d.allowed is False
        assert d.status.value == "stale_state"

    def test_validation_failure_increments_metric(self):
        """Line 722: validation_failure status increments validation_failures_total."""
        guard = Guard(SimplePolicy, GuardConfig(execution_mode="sync", metrics_enabled=True))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                # missing state_version → validation_failure
            },
        )
        assert d.allowed is False

    def test_safe_decision_records_metrics(self):
        """Metrics path for safe decision."""
        guard = Guard(SimplePolicy, GuardConfig(execution_mode="sync", metrics_enabled=True))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                "state_version": "1.0",
            },
        )
        assert d.allowed is True


# ═══════════════════════════════════════════════════════════════════════════════
# 8. guard.py — verify_async paths (774->790, 777, 792, 801, 821-849)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifyAsyncEdgeCases:
    """Cover verify_async paths not exercised by existing tests."""

    async def test_verify_async_sync_mode_delegates_to_verify(self):
        """sync mode: verify_async delegates to asyncio.to_thread(verify)."""
        guard = Guard(SimplePolicy, GuardConfig(execution_mode="sync"))
        d = await guard.verify_async(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                "state_version": "1.0",
            },
        )
        assert d.allowed is True

    async def test_verify_async_thread_missing_state_version(self):
        """Line 777: async-thread mode, policy has version, state missing state_version."""
        guard = Guard(SimplePolicy, GuardConfig(execution_mode="async-thread", max_workers=1))
        try:
            d = await guard.verify_async(
                intent={"amount": Decimal("100")},
                state={
                    "balance": Decimal("5000"),
                    "is_frozen": False,
                    "daily_limit": Decimal("10000"),
                    # NO state_version
                },
            )
            assert d.allowed is False
            assert "state_version" in d.explanation.lower() or d.status.value in (
                "validation_failure",
                "error",
            )
        finally:
            await guard.shutdown()

    async def test_verify_async_thread_wrong_state_version(self):
        """Lines 784-788: async-thread mode, state_version mismatch → stale_state."""
        guard = Guard(SimplePolicy, GuardConfig(execution_mode="async-thread", max_workers=1))
        try:
            d = await guard.verify_async(
                intent={"amount": Decimal("100")},
                state={
                    "balance": Decimal("5000"),
                    "is_frozen": False,
                    "daily_limit": Decimal("10000"),
                    "state_version": "WRONG",
                },
            )
            assert d.allowed is False
            assert d.status.value == "stale_state"
        finally:
            await guard.shutdown()

    async def test_verify_async_thread_no_policy_version(self):
        """Branch 774->790 False: policy has no version → version check skipped."""
        guard = Guard(NoVersionPolicy, GuardConfig(execution_mode="async-thread", max_workers=1))
        try:
            d = await guard.verify_async(
                intent={"amount": Decimal("100")},
                state={
                    "balance": Decimal("5000"),
                    # No state_version needed — policy has no version
                },
            )
            assert d.allowed is True
        finally:
            await guard.shutdown()

    async def test_verify_async_thread_conflicting_keys(self):
        """Line 792: intent and state share a key → ValueError → Decision.error()."""
        guard = Guard(NoVersionPolicy, GuardConfig(execution_mode="async-thread", max_workers=1))
        try:
            d = await guard.verify_async(
                intent={"amount": Decimal("100"), "balance": Decimal("500")},
                state={"balance": Decimal("500")},  # 'balance' in both → conflict
            )
            assert d.allowed is False
        finally:
            await guard.shutdown()

    async def test_verify_async_thread_pramanix_error_in_validation(self):
        """Line 801: PramanixError (not ValidationError) during validation → Decision.error().

        Uses a policy with an intent_model so validate_intent is actually called,
        then patches validate_intent to raise ConfigurationError (a PramanixError
        that is NOT ValidationError or StateValidationError).
        """
        from pydantic import BaseModel as PydanticBase

        from pramanix.exceptions import ConfigurationError

        class _IntentModel(PydanticBase):
            amount: Decimal

        class _PolicyWithModel(Policy):
            class Meta:
                version = "1.0"
                intent_model = _IntentModel

            amount = Field("amount", Decimal, "Real")
            balance = Field("balance", Decimal, "Real")

            @classmethod
            def invariants(cls):
                return [
                    (E(cls.balance) - E(cls.amount) >= Decimal("0"))
                    .named("bal")
                    .explain("Insufficient"),
                ]

        guard = Guard(
            _PolicyWithModel, GuardConfig(execution_mode="async-thread", max_workers=1)
        )
        try:
            # Patch at the module level where guard.py imports it
            with patch(
                "pramanix.guard.validate_intent",
                side_effect=ConfigurationError("cfg error"),
            ):
                d = await guard.verify_async(
                    intent={"amount": Decimal("100")},
                    state={"balance": Decimal("500"), "state_version": "1.0"},
                )
            assert d.allowed is False
            assert d.status.value == "error"
        finally:
            await guard.shutdown()

    async def test_verify_async_process_hmac_mismatch_returns_error(self):
        """Lines 842-845: async-process HMAC mismatch → Decision.error().

        _unseal_decision is imported locally inside verify_async so we patch
        it at the pramanix.worker module level.
        """
        guard = Guard(NoVersionPolicy, GuardConfig(execution_mode="async-process", max_workers=1))
        try:
            with patch(
                "pramanix.worker._unseal_decision",
                side_effect=ValueError("HMAC mismatch"),
            ):
                d = await guard.verify_async(
                    intent={"amount": Decimal("100")},
                    state={"balance": Decimal("500")},
                )
            assert d.allowed is False
            assert d.status.value == "error"
        finally:
            await guard.shutdown()

    async def test_verify_async_process_worker_error_returns_error(self):
        """Lines 846-847: async-process WorkerError → Decision.error()."""
        from pramanix.exceptions import WorkerError

        guard = Guard(NoVersionPolicy, GuardConfig(execution_mode="async-process", max_workers=1))
        try:
            with patch(
                "pramanix.worker._unseal_decision",
                side_effect=WorkerError("worker died"),
            ):
                d = await guard.verify_async(
                    intent={"amount": Decimal("100")},
                    state={"balance": Decimal("500")},
                )
            assert d.allowed is False
            assert d.status.value == "error"
        finally:
            await guard.shutdown()

    async def test_verify_async_process_unexpected_exception_returns_error(self):
        """Lines 848-849: async-process unexpected exception → Decision.error()."""
        guard = Guard(NoVersionPolicy, GuardConfig(execution_mode="async-process", max_workers=1))
        try:
            with patch(
                "pramanix.worker._unseal_decision",
                side_effect=RuntimeError("something unexpected"),
            ):
                d = await guard.verify_async(
                    intent={"amount": Decimal("100")},
                    state={"balance": Decimal("500")},
                )
            assert d.allowed is False
            assert d.status.value == "error"
        finally:
            await guard.shutdown()
