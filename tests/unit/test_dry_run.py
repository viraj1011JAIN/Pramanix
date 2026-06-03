# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Coverage tests for dry_run.py — PolicyDryRun and DryRunResult."""

from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix import E, Field, Policy
from pramanix.dry_run import DryRunResult, PolicyDryRun
from pramanix.guard_config import GuardConfig

# ── Minimal Policy fixtures ───────────────────────────────────────────────────

_amt = Field("amount", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amt}

    @classmethod
    def invariants(cls):
        return [(E(_amt) >= Decimal("0")).named("non_neg").explain("non-negative")]


class _BlockPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amt}

    @classmethod
    def invariants(cls):
        return [(E(_amt) > Decimal("9999")).named("huge").explain("must be huge")]


_ALLOW_INTENT = {"amount": Decimal("50")}
_BLOCK_INTENT = {"amount": Decimal("1")}
_STATE: dict = {"state_version": "1.0"}


# ── DryRunResult ──────────────────────────────────────────────────────────────


class TestDryRunResult:
    def test_post_init_mismatch_raises(self) -> None:
        """would_allow disagreeing with decision.allowed raises ValueError."""
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        results = runner.simulate()
        dec = results[0].decision
        with pytest.raises(ValueError, match="disagrees"):
            DryRunResult(
                index=0,
                intent=_ALLOW_INTENT,
                state=_STATE,
                decision=dec,
                would_allow=not dec.allowed,
            )

    def test_post_init_matching_is_fine(self) -> None:
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        r = runner.simulate()[0]
        assert r.would_allow is r.decision.allowed


# ── PolicyDryRun constructor ─────────────────────────────────────────────────


class TestPolicyDryRunInit:
    def test_non_policy_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="subclass of Policy"):
            PolicyDryRun(object, [(_ALLOW_INTENT, _STATE)])  # type: ignore[arg-type]

    def test_non_class_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="subclass of Policy"):
            PolicyDryRun("not_a_class", [(_ALLOW_INTENT, _STATE)])  # type: ignore[arg-type]

    def test_empty_examples_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            PolicyDryRun(_AllowPolicy, [])

    def test_custom_config_is_stored(self) -> None:
        cfg = GuardConfig(execution_mode="sync", min_response_ms=0.0, audit_sinks=[])
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)], config=cfg)
        assert runner._config is cfg

    def test_default_config_used_when_none(self) -> None:
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        assert runner._config is not None


# ── Properties ───────────────────────────────────────────────────────────────


class TestProperties:
    def test_policy_property(self) -> None:
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        assert runner.policy is _AllowPolicy

    def test_examples_property_returns_copy(self) -> None:
        examples = [(_ALLOW_INTENT, _STATE)]
        runner = PolicyDryRun(_AllowPolicy, examples)
        got = runner.examples
        assert got == examples
        got.append((_BLOCK_INTENT, _STATE))
        assert len(runner.examples) == 1  # original not mutated


# ── simulate() ───────────────────────────────────────────────────────────────


class TestSimulate:
    def test_allowed_example(self) -> None:
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        results = runner.simulate()
        assert len(results) == 1
        assert results[0].would_allow is True
        assert results[0].index == 0
        assert results[0].intent == _ALLOW_INTENT
        assert results[0].state == _STATE

    def test_blocked_example(self) -> None:
        runner = PolicyDryRun(_BlockPolicy, [(_BLOCK_INTENT, _STATE)])
        results = runner.simulate()
        assert len(results) == 1
        assert results[0].would_allow is False

    def test_multiple_examples_indexed_correctly(self) -> None:
        runner = PolicyDryRun(
            _AllowPolicy,
            [(_ALLOW_INTENT, _STATE), (_ALLOW_INTENT, _STATE), (_ALLOW_INTENT, _STATE)],
        )
        results = runner.simulate()
        assert [r.index for r in results] == [0, 1, 2]

    def test_mixed_allow_block(self) -> None:
        class _MixedPolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls) -> dict:
                return {"amount": _amt}

            @classmethod
            def invariants(cls):
                return [(E(_amt) >= Decimal("10")).named("min10").explain(">=10")]

        runner = PolicyDryRun(
            _MixedPolicy,
            [
                ({"amount": Decimal("50")}, _STATE),
                ({"amount": Decimal("1")}, _STATE),
            ],
        )
        results = runner.simulate()
        assert results[0].would_allow is True
        assert results[1].would_allow is False

    def test_pydantic_model_intent(self) -> None:
        class _Intent(BaseModel):
            amount: Decimal

        runner = PolicyDryRun(_AllowPolicy, [(_Intent(amount=Decimal("5")), _STATE)])
        results = runner.simulate()
        assert results[0].would_allow is True


# ── assert_all_allowed() ─────────────────────────────────────────────────────


class TestAssertAllAllowed:
    def test_all_allowed_does_not_raise(self) -> None:
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        runner.assert_all_allowed()  # must not raise

    def test_some_blocked_raises_assertion(self) -> None:
        runner = PolicyDryRun(_BlockPolicy, [(_BLOCK_INTENT, _STATE)])
        with pytest.raises(AssertionError, match="blocked"):
            runner.assert_all_allowed()

    def test_assertion_message_contains_count(self) -> None:
        runner = PolicyDryRun(
            _BlockPolicy,
            [(_BLOCK_INTENT, _STATE), (_BLOCK_INTENT, _STATE)],
        )
        with pytest.raises(AssertionError, match="2 example"):
            runner.assert_all_allowed()


# ── assert_all_blocked() ─────────────────────────────────────────────────────


class TestAssertAllBlocked:
    def test_all_blocked_does_not_raise(self) -> None:
        runner = PolicyDryRun(_BlockPolicy, [(_BLOCK_INTENT, _STATE)])
        runner.assert_all_blocked()  # must not raise

    def test_some_allowed_raises_assertion(self) -> None:
        runner = PolicyDryRun(_AllowPolicy, [(_ALLOW_INTENT, _STATE)])
        with pytest.raises(AssertionError, match="allowed"):
            runner.assert_all_blocked()

    def test_assertion_message_contains_count_and_status(self) -> None:
        runner = PolicyDryRun(
            _AllowPolicy,
            [(_ALLOW_INTENT, _STATE), (_ALLOW_INTENT, _STATE)],
        )
        with pytest.raises(AssertionError, match="2 example"):
            runner.assert_all_blocked()
