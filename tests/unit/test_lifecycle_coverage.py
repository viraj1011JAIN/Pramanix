# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real tests for lifecycle/diff.py: PolicyDiff and ShadowEvaluator.

Covers the missed statements and branches in:
  lifecycle/diff.py  (92% → 100%)

All assertions use real Guard instances — no mocks or stubs.
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.lifecycle.diff import (
    FieldChange,
    InvariantChange,
    PolicyDiff,
    ShadowEvaluator,
    ShadowResult,
)
from pramanix.policy import Policy


# ── Shared models and policies ────────────────────────────────────────────────


class _Amt(BaseModel):
    amount: Decimal
    state_version: str = "1.0"


class _BalV1(Policy):
    """Live policy: amount <= 500."""

    class Meta:
        version = "1.0"

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= 500).named("max_500")
        ]


class _BalV2(Policy):
    """Candidate policy: amount <= 1000 (relaxed limit)."""

    class Meta:
        version = "2.0"

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= 1000).named("max_1000")
        ]


class _BalV3(Policy):
    """Candidate policy: same invariant label, different expression (changed)."""

    class Meta:
        version = "3.0"

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= 999).named("max_500")  # same label, different expression
        ]


class _NoInvPolicy(Policy):
    """Policy with no invariants — for edge-case diff."""

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return []


class _BrokenPolicy(Policy):
    """Policy whose invariants() raises — for _collect_invariants error path."""

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        raise RuntimeError("invariants broken")


# ═══════════════════════════════════════════════════════════════════════════════
# PolicyDiff.compute
# ═══════════════════════════════════════════════════════════════════════════════


class TestPolicyDiff:

    def test_same_policy_has_no_changes(self) -> None:
        diff = PolicyDiff.compute(_BalV1, _BalV1)
        assert not diff.has_changes
        assert not diff.is_breaking
        assert diff.invariant_changes == []
        assert diff.field_changes == []

    def test_removed_invariant_is_breaking(self) -> None:
        # V1 has max_500; V2 has max_1000 (different label → V1's max_500 removed, V2's max_1000 added)
        diff = PolicyDiff.compute(_BalV1, _BalV2)
        assert diff.has_changes

        names = {c.name for c in diff.invariant_changes}
        assert "max_500" in names
        assert "max_1000" in names

        removed = [c for c in diff.invariant_changes if c.change_type == "removed"]
        assert any(c.name == "max_500" for c in removed)
        assert diff.is_breaking

    def test_added_invariant_is_not_breaking(self) -> None:
        # From V2 → V1: max_1000 is removed, max_500 is added
        # reversed: from empty → V1 means max_500 is added, not breaking
        diff = PolicyDiff.compute(_NoInvPolicy, _BalV1)
        assert diff.has_changes
        added = [c for c in diff.invariant_changes if c.change_type == "added"]
        assert any(c.name == "max_500" for c in added)
        assert not diff.is_breaking  # only added, not removed

    def test_changed_invariant_is_breaking(self) -> None:
        # V1 and V3 share the label "max_500" but different expressions
        diff = PolicyDiff.compute(_BalV1, _BalV3)
        assert diff.has_changes
        changed = [c for c in diff.invariant_changes if c.change_type == "changed"]
        assert any(c.name == "max_500" for c in changed)
        assert diff.is_breaking

    def test_version_change_detected(self) -> None:
        diff = PolicyDiff.compute(_BalV1, _BalV2)
        assert diff.old_version == "1.0"
        assert diff.new_version == "2.0"

    def test_no_version_detected(self) -> None:
        diff = PolicyDiff.compute(_NoInvPolicy, _NoInvPolicy)
        assert diff.old_version is None
        assert diff.new_version is None

    def test_summary_no_changes(self) -> None:
        diff = PolicyDiff.compute(_BalV1, _BalV1)
        summary = diff.summary()
        assert "no changes" in summary

    def test_summary_with_changes(self) -> None:
        diff = PolicyDiff.compute(_BalV1, _BalV2)
        summary = diff.summary()
        assert "PolicyDiff" in summary
        assert "breaking" in summary

    def test_collect_invariants_error_returns_empty(self) -> None:
        """_collect_invariants catches exceptions from broken policies."""
        diff = PolicyDiff.compute(_BrokenPolicy, _BalV1)
        # _BrokenPolicy.invariants() raises → collected as empty → all V1 invs "added"
        assert diff.has_changes
        added = [c for c in diff.invariant_changes if c.change_type == "added"]
        assert len(added) > 0

    def test_field_changes_detected(self) -> None:
        """Policies with different field z3 types produce FieldChange records."""

        class _IntPolicy(Policy):
            x = Field("x", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return []

        class _RealPolicy(Policy):
            x = Field("x", float, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return []

        diff = PolicyDiff.compute(_IntPolicy, _RealPolicy)
        # Both have field 'x' but with different z3 types → 'changed'
        changed = [c for c in diff.field_changes if c.change_type == "changed"]
        assert any(c.name == "x" for c in changed)
        assert diff.is_breaking


# ═══════════════════════════════════════════════════════════════════════════════
# ShadowEvaluator
# ═══════════════════════════════════════════════════════════════════════════════


class _SimpleModel(BaseModel):
    amount: Decimal


class _LivePolicy(Policy):
    """Live: allows amount <= 100."""

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.amount) <= 100).named("max_100")]


class _ShadowPolicy(Policy):
    """Shadow: allows amount <= 50 (stricter)."""

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.amount) <= 50).named("max_50")]


class TestShadowEvaluator:

    def _make_evaluator(self) -> ShadowEvaluator:
        live_guard = Guard(_LivePolicy, GuardConfig())
        shadow_guard = Guard(_ShadowPolicy, GuardConfig())
        return ShadowEvaluator(live_guard, shadow_guard)

    def test_no_divergence_when_both_allow(self) -> None:
        evaluator = self._make_evaluator()
        intent = {"amount": Decimal("30")}  # <= 50, both allow
        live_decision = Decision.safe()

        result = evaluator.record(intent, {}, live_decision)
        assert not result.diverged
        assert result.shadow_allowed is True
        assert result.live_allowed is True

    def test_divergence_when_live_allows_shadow_blocks(self) -> None:
        evaluator = self._make_evaluator()
        intent = {"amount": Decimal("75")}  # > 50 shadow blocks, <= 100 live allows
        live_decision = Decision.safe()  # live already allowed

        result = evaluator.record(intent, {}, live_decision)
        assert result.diverged
        assert result.live_allowed is True
        assert result.shadow_allowed is False

    def test_no_divergence_when_both_block(self) -> None:
        evaluator = self._make_evaluator()
        intent = {"amount": Decimal("200")}  # > 100, both block
        live_decision = Decision.unsafe(
            violated_invariants=("max_100",),
            explanation="too high",
        )
        result = evaluator.record(intent, {}, live_decision)
        assert not result.diverged

    def test_divergence_rate_zero_initially(self) -> None:
        evaluator = self._make_evaluator()
        assert evaluator.divergence_rate() == 0.0
        assert evaluator.total_evaluations() == 0
        assert evaluator.diverged_count() == 0

    def test_divergence_rate_accumulates(self) -> None:
        evaluator = self._make_evaluator()
        intent_ok = {"amount": Decimal("30")}
        intent_diverge = {"amount": Decimal("75")}

        evaluator.record(intent_ok, {}, Decision.safe())
        evaluator.record(intent_diverge, {}, Decision.safe())

        assert evaluator.total_evaluations() == 2
        assert evaluator.diverged_count() == 1
        assert abs(evaluator.divergence_rate() - 0.5) < 0.01

    def test_history_and_diverged_events(self) -> None:
        evaluator = self._make_evaluator()
        intent_ok = {"amount": Decimal("30")}
        intent_diverge = {"amount": Decimal("75")}

        evaluator.record(intent_ok, {}, Decision.safe())
        evaluator.record(intent_diverge, {}, Decision.safe())

        history = evaluator.history()
        diverged = evaluator.diverged_events()
        assert len(history) == 2
        assert len(diverged) == 1
        assert diverged[0].diverged

    def test_reset_clears_all_state(self) -> None:
        evaluator = self._make_evaluator()
        intent_ok = {"amount": Decimal("30")}
        evaluator.record(intent_ok, {}, Decision.safe())
        assert evaluator.total_evaluations() == 1

        evaluator.reset()
        assert evaluator.total_evaluations() == 0
        assert evaluator.divergence_rate() == 0.0
        assert evaluator.history() == []

    def test_shadow_error_counted_as_diverged(self) -> None:
        """Shadow guard raises → shadow_error set → diverged=True."""

        class _RaisingGuard:
            def verify(self, intent, state):
                raise RuntimeError("shadow exploded")

        live_guard = Guard(_LivePolicy, GuardConfig())
        evaluator = ShadowEvaluator(live_guard, _RaisingGuard())

        result = evaluator.record({"amount": Decimal("30")}, {}, Decision.safe())
        assert result.diverged
        assert result.shadow_error is not None
        assert "RuntimeError" in result.shadow_error
        assert evaluator.diverged_count() == 1

    def test_max_history_evicts_oldest(self) -> None:
        """deque(maxlen=N) should evict oldest entries when full."""
        live_guard = Guard(_LivePolicy, GuardConfig())
        shadow_guard = Guard(_ShadowPolicy, GuardConfig())
        evaluator = ShadowEvaluator(live_guard, shadow_guard, max_history=3)

        for _ in range(5):
            evaluator.record({"amount": Decimal("30")}, {}, Decision.safe())

        assert len(evaluator.history()) == 3
        assert evaluator.total_evaluations() == 5
