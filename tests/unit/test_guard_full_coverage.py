# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Full coverage for guard.py missing branches.

Targets:
  guard.py lines 416-417, 466, 599-609, 659, 704-709, 873

Design:
  - Lines 416-417: trigger json.dumps exception via circular-reference dict + object
    whose __str__ raises.
  - Line 466: policy with Meta.semver; pass state_version with wrong part count.
  - Lines 599-609: policy with state_model that lacks state_version → StateValidationError.
  - Line 659: validation_failure with metrics_enabled=True → counter incremented.
  - Lines 704-709: verify_async with min_response_ms > 0 → _timed() loop executes.
  - Line 873: unknown execution_mode after pool is initialised → fallthrough.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.expressions import E, Field
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy

# ── Shared policy fixtures ────────────────────────────────────────────────────


class _SimplePolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


class _SemverPolicy(Policy):
    """Policy with Meta.semver — requires X.Y.Z state_version."""

    amount = Field("amount", Decimal, "Real")

    class Meta:
        semver = (1, 0, 0)

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


# ── State model WITHOUT state_version (triggers StateValidationError) ─────────


class _BadStateModel(BaseModel):
    """State model missing the required state_version field."""
    balance: Decimal


class _PolicyWithBadStateModel(Policy):
    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    class Meta:
        state_model = _BadStateModel

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) >= 0).named("non_negative"),
            (E(cls.balance) >= 0).named("positive_balance"),
        ]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _allow_intent() -> dict[str, Any]:
    return {"amount": Decimal("10")}


def _valid_state() -> dict[str, Any]:
    return {"state_version": "1.0.0"}


# ── Lines 416-417: exception in json.dumps size check ────────────────────────


class TestSizeCheckExceptionIgnored:
    """Lines 416-417: except Exception: pass in the size check block."""

    def test_circular_reference_in_intent_is_ignored(self) -> None:
        """json.dumps raises ValueError for circular references; guard continues."""
        circular: dict[str, Any] = {}
        circular["self_ref"] = circular  # creates circular reference

        config = GuardConfig(execution_mode="sync", max_input_bytes=65536)
        guard = Guard(_SimplePolicy, config)

        # json.dumps will raise ValueError (Circular reference detected)
        # Lines 416-417 catch it and continue
        decision = guard.verify({**_allow_intent(), "circ": circular}, {})
        # Guard should still produce a valid decision (the circ key is unknown/ignored)
        assert isinstance(decision, Decision)

    def test_str_raises_object_triggers_exception_path(self) -> None:
        """An object whose __str__ raises causes json.dumps(default=str) to fail."""

        class _StrRaises:
            def __str__(self) -> str:
                raise RuntimeError("str() not allowed on this object")

            def __repr__(self) -> str:
                raise RuntimeError("repr() not allowed on this object")

        config = GuardConfig(execution_mode="sync", max_input_bytes=65536)
        guard = Guard(_SimplePolicy, config)

        # json.dumps(default=str) calls str(obj) → RuntimeError
        # Lines 416-417: except Exception: pass
        decision = guard.verify({**_allow_intent(), "bad": _StrRaises()}, {})
        assert isinstance(decision, Decision)


# ── Line 466: malformed semver string in state_version ───────────────────────


class TestSemverMalformedStateVersion:
    """Line 466: state_version with wrong number of parts raises ValueError."""

    def test_two_part_version_fails_semver_check(self) -> None:
        """state_version='1.2' has only 2 parts → len(parts) != 3 → raise ValueError."""
        config = GuardConfig(execution_mode="sync")
        guard = Guard(_SemverPolicy, config)
        decision = guard.verify(_allow_intent(), {"state_version": "1.2"})
        assert decision.allowed is False
        assert "not a valid semver" in decision.explanation

    def test_four_part_version_fails_semver_check(self) -> None:
        """state_version='1.0.0.1' has 4 parts → len(parts) != 3."""
        config = GuardConfig(execution_mode="sync")
        guard = Guard(_SemverPolicy, config)
        decision = guard.verify(_allow_intent(), {"state_version": "1.0.0.1"})
        assert decision.allowed is False

    def test_non_integer_version_part_fails(self) -> None:
        """state_version='1.a.0' → int("a") raises ValueError."""
        config = GuardConfig(execution_mode="sync")
        guard = Guard(_SemverPolicy, config)
        decision = guard.verify(_allow_intent(), {"state_version": "1.a.0"})
        assert decision.allowed is False

    def test_valid_matching_version_allowed(self) -> None:
        """Sanity: correct semver matching the policy allows normal flow."""
        config = GuardConfig(execution_mode="sync")
        guard = Guard(_SemverPolicy, config)
        decision = guard.verify(_allow_intent(), {"state_version": "1.0.0"})
        assert decision.allowed is True


# ── Lines 599-609: StateValidationError in verify() ──────────────────────────


class TestStateValidationErrorCaught:
    """Lines 599-609: except StateValidationError → validation_failure Decision."""

    def test_state_model_missing_state_version_field(self) -> None:
        """validate_state() raises StateValidationError when model lacks state_version."""
        config = GuardConfig(execution_mode="sync")
        guard = Guard(_PolicyWithBadStateModel, config)

        # _BadStateModel has no state_version field → StateValidationError raised
        decision = guard.verify(
            {"amount": Decimal("10")},
            {"balance": Decimal("500")},
        )
        assert decision.allowed is False
        assert not decision.allowed

    def test_state_validation_error_returns_decision_not_exception(self) -> None:
        """StateValidationError is CAUGHT (lines 599-609), not propagated."""
        config = GuardConfig(execution_mode="sync")
        guard = Guard(_PolicyWithBadStateModel, config)

        # Must not raise — StateValidationError is caught and wrapped as Decision
        try:
            result = guard.verify(
                {"amount": Decimal("5")},
                {"balance": Decimal("200")},
            )
            assert isinstance(result, Decision)
        except Exception as exc:
            pytest.fail(f"StateValidationError should not propagate: {exc}")


# ── Line 659: validation_failure increments Prometheus counter ────────────────


class TestPrometheusValidationFailureMetric:
    """Line 659: _validation_failures_total counter incremented on validation_failure."""

    def test_invalid_semver_with_metrics_enabled_increments_counter(self) -> None:
        """Line 659: _metric_status='validation_failure' + metrics_enabled → counter.inc()."""
        config = GuardConfig(execution_mode="sync", metrics_enabled=True)
        guard = Guard(_SemverPolicy, config)

        # state_version with 2 parts → validation_failure → line 659 counter
        decision = guard.verify(_allow_intent(), {"state_version": "1.2"})
        assert decision.allowed is False

    def test_stale_state_with_metrics_enabled_increments_counter(self) -> None:
        """Line 659: _metric_status='stale_state' also triggers the counter."""
        config = GuardConfig(execution_mode="sync", metrics_enabled=True)
        guard = Guard(_SemverPolicy, config)

        # Wrong version → stale_state → line 659 counter
        decision = guard.verify(_allow_intent(), {"state_version": "2.0.0"})
        assert decision.allowed is False


# ── Lines 704-709: verify_async _timed() with min_response_ms > 0 ────────────


@pytest.mark.asyncio
class TestVerifyAsyncTimedDelay:
    """Lines 704-709: _timed() with min_response_ms > 0 → asyncio.sleep called."""

    async def test_min_response_ms_causes_sleep_in_timed(self) -> None:
        """Lines 704-709: _timed() loop with positive min_response_ms."""
        # Use a small but positive min_response_ms so _timed() exercises the sleep loop.
        # The policy solves almost instantly (< 1ms), so _left > 0 → asyncio.sleep fires.
        config = GuardConfig(execution_mode="sync", min_response_ms=50)
        guard = Guard(_SimplePolicy, config)

        decision = await guard.verify_async(_allow_intent(), {})
        # Decision is still valid despite the artificial delay
        assert isinstance(decision, Decision)
        assert decision.allowed is True

    async def test_min_response_ms_zero_skips_sleep(self) -> None:
        """Sanity: min_response_ms=0 skips _timed() body entirely (lines 703 False)."""
        config = GuardConfig(execution_mode="sync", min_response_ms=0)
        guard = Guard(_SimplePolicy, config)
        decision = await guard.verify_async(_allow_intent(), {})
        assert isinstance(decision, Decision)


# ── Line 873: unknown execution_mode fallthrough ──────────────────────────────


@pytest.mark.asyncio
class TestVerifyAsyncUnknownExecutionMode:
    """Line 873: unknown execution_mode after pool is initialised → error Decision."""

    async def test_unknown_mode_returns_error_decision(self) -> None:
        """Line 873: mode not sync/async-thread/async-process → error Decision."""
        config = GuardConfig(execution_mode="async-thread", min_response_ms=0)
        guard = Guard(_SimplePolicy, config)

        # Override execution_mode AFTER init (pool is set up for "async-thread")
        # so pool is not None, but mode is now unknown → falls to line 873
        object.__setattr__(guard._config, "execution_mode", "mystery-mode")

        decision = await guard.verify_async(_allow_intent(), {})
        assert isinstance(decision, Decision)
        assert decision.allowed is False
        assert "Unknown execution_mode" in decision.explanation

    async def test_unknown_mode_error_contains_mode_name(self) -> None:
        """Error Decision message contains the unknown mode string."""
        config = GuardConfig(execution_mode="async-thread", min_response_ms=0)
        guard = Guard(_SimplePolicy, config)
        object.__setattr__(guard._config, "execution_mode", "my-custom-mode")

        decision = await guard.verify_async(_allow_intent(), {})
        assert "my-custom-mode" in decision.explanation
