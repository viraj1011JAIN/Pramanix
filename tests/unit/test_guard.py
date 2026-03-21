# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.guard — Guard and GuardConfig.

Coverage targets:
- GuardConfig: all fields, defaults, env-var-independent validation, frozen
- Guard.__init__: policy validation at construction, Meta extraction
- Guard.verify — SAFE: all invariants pass, solver_time set, UUID present
- Guard.verify — UNSAFE: single violation, multi-violation (exact attribution)
- Guard.verify — STALE_STATE: version mismatch, missing state_version
- Guard.verify — VALIDATION_FAILURE: bad intent type, bad state type
- Guard.verify — raw-dict mode (no Meta): no models, no version check
- Guard.verify — fail-safe: every exception class returns Decision(allowed=False)
- Guard.verify — pydantic BaseModel instances accepted directly
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest
from pydantic import BaseModel

import pramanix.guard as _guard_mod
from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import (
    ConfigurationError,
    InvariantLabelError,
    PolicyError,
    SolverTimeoutError,
    TranspileError,
)
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Pydantic models ───────────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: Decimal


class _AccountState(BaseModel):
    state_version: str
    balance: Decimal
    daily_limit: Decimal
    is_frozen: bool


# ── Reference policy (with Meta) ──────────────────────────────────────────────


class _TradePolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = _TransferIntent
        state_model = _AccountState

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    is_frozen = Field("is_frozen", bool, "Bool")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft: balance={balance}, amount={amount}"),
            (E(cls.amount) <= E(cls.daily_limit))
            .named("within_daily_limit")
            .explain("Exceeds daily limit: amount={amount}, limit={daily_limit}"),
            (E(cls.is_frozen) == False)  # noqa: E712
            .named("account_not_frozen")
            .explain("Account is frozen"),
        ]


# ── Policy without Meta (raw-dict mode) ───────────────────────────────────────


class _RawPolicy(Policy):
    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft: balance={balance}, amount={amount}"),
        ]


# ── Shared test data ──────────────────────────────────────────────────────────

_GOOD_INTENT: dict[str, object] = {"amount": Decimal("100")}
_GOOD_STATE: dict[str, object] = {
    "balance": Decimal("1000"),
    "daily_limit": Decimal("5000"),
    "is_frozen": False,
    "state_version": "1.0",
}
_OVERDRAFT_INTENT: dict[str, object] = {"amount": Decimal("2000")}
_OVERDRAFT_STATE: dict[str, object] = {
    "balance": Decimal("50"),
    "daily_limit": Decimal("5000"),
    "is_frozen": False,
    "state_version": "1.0",
}


# ═══════════════════════════════════════════════════════════════════════════════
# GuardConfig
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardConfig:
    """GuardConfig is a frozen dataclass; all fields must have sensible defaults."""

    def test_default_solver_timeout_ms(self) -> None:
        assert GuardConfig().solver_timeout_ms == 5_000

    def test_custom_solver_timeout_ms(self) -> None:
        assert GuardConfig(solver_timeout_ms=1_000).solver_timeout_ms == 1_000

    def test_zero_timeout_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="positive"):
            GuardConfig(solver_timeout_ms=0)

    def test_negative_timeout_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError):
            GuardConfig(solver_timeout_ms=-1)

    def test_default_execution_mode_is_sync(self) -> None:
        assert GuardConfig().execution_mode == "sync"

    def test_invalid_execution_mode_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            GuardConfig(execution_mode="not-a-valid-mode")

    def test_default_max_workers(self) -> None:
        assert GuardConfig().max_workers == 4

    def test_zero_max_workers_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError):
            GuardConfig(max_workers=0)

    def test_negative_max_workers_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError):
            GuardConfig(max_workers=-1)

    def test_default_translator_disabled(self) -> None:
        assert GuardConfig().translator_enabled is False

    def test_default_metrics_disabled(self) -> None:
        assert GuardConfig().metrics_enabled is False

    def test_default_otel_disabled(self) -> None:
        assert GuardConfig().otel_enabled is False

    def test_default_worker_warmup_enabled(self) -> None:
        assert GuardConfig().worker_warmup is True

    def test_default_max_decisions_per_worker(self) -> None:
        assert GuardConfig().max_decisions_per_worker == 10_000

    def test_negative_solver_rlimit_raises(self) -> None:
        from pramanix.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="solver_rlimit"):
            GuardConfig(solver_rlimit=-1)

    def test_negative_max_input_bytes_raises(self) -> None:
        from pramanix.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="max_input_bytes"):
            GuardConfig(max_input_bytes=-1)

    def test_negative_min_response_ms_raises(self) -> None:
        from pramanix.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="min_response_ms"):
            GuardConfig(min_response_ms=-0.1)

    def test_frozen_instance_cannot_be_mutated(self) -> None:
        cfg = GuardConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.solver_timeout_ms = 999  # type: ignore[misc]

    def test_all_documented_fields_present(self) -> None:
        cfg = GuardConfig()
        required_attrs = {
            "execution_mode",
            "solver_timeout_ms",
            "max_workers",
            "max_decisions_per_worker",
            "worker_warmup",
            "log_level",
            "metrics_enabled",
            "otel_enabled",
            "translator_enabled",
        }
        for attr in required_attrs:
            assert hasattr(cfg, attr), f"GuardConfig is missing attribute: {attr}"

    @pytest.mark.parametrize("timeout", [1, 10, 100, 5_000, 10_000])
    def test_valid_positive_timeouts_accepted(self, timeout: int) -> None:
        cfg = GuardConfig(solver_timeout_ms=timeout)
        assert cfg.solver_timeout_ms == timeout


# ═══════════════════════════════════════════════════════════════════════════════
# Guard construction
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardInit:
    def test_valid_policy_constructs_without_error(self) -> None:
        Guard(_TradePolicy)

    def test_default_config_applied(self) -> None:
        g = Guard(_TradePolicy)
        assert g.config.solver_timeout_ms == 5_000

    def test_custom_config_stored(self) -> None:
        cfg = GuardConfig(solver_timeout_ms=1_000)
        g = Guard(_TradePolicy, config=cfg)
        assert g.config.solver_timeout_ms == 1_000

    def test_policy_accessible_via_property(self) -> None:
        g = Guard(_TradePolicy)
        assert g.policy is _TradePolicy

    def test_unlabelled_invariant_raises_at_construction(self) -> None:
        class _Unlabelled(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [E(cls.x) >= 0]  # missing .named()

        with pytest.raises(InvariantLabelError):
            Guard(_Unlabelled)

    def test_empty_invariants_raises_at_construction(self) -> None:
        class _Empty(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return []

        with pytest.raises(PolicyError):
            Guard(_Empty)

    def test_duplicate_labels_raises_at_construction(self) -> None:
        class _Dup(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    (E(cls.x) >= 0).named("dup"),
                    (E(cls.x) <= 100).named("dup"),
                ]

        with pytest.raises(InvariantLabelError):
            Guard(_Dup)

    def test_raw_policy_no_meta_constructs(self) -> None:
        Guard(_RawPolicy)


# ═══════════════════════════════════════════════════════════════════════════════
# Guard.verify — SAFE
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardVerifySafe:
    def setup_method(self) -> None:
        self.guard = Guard(_TradePolicy)

    def test_returns_decision_instance(self) -> None:
        assert isinstance(self.guard.verify(_GOOD_INTENT, _GOOD_STATE), Decision)

    def test_allowed_true(self) -> None:
        assert self.guard.verify(_GOOD_INTENT, _GOOD_STATE).allowed is True

    def test_status_safe(self) -> None:
        assert self.guard.verify(_GOOD_INTENT, _GOOD_STATE).status is SolverStatus.SAFE

    def test_no_violated_invariants(self) -> None:
        d = self.guard.verify(_GOOD_INTENT, _GOOD_STATE)
        assert d.violated_invariants == ()

    def test_explanation_empty_on_safe(self) -> None:
        d = self.guard.verify(_GOOD_INTENT, _GOOD_STATE)
        assert d.explanation == ""

    def test_solver_time_ms_non_negative(self) -> None:
        d = self.guard.verify(_GOOD_INTENT, _GOOD_STATE)
        assert d.solver_time_ms >= 0.0

    def test_decision_id_is_valid_uuid4(self) -> None:
        d = self.guard.verify(_GOOD_INTENT, _GOOD_STATE)
        parsed = uuid.UUID(d.decision_id, version=4)
        assert str(parsed) == d.decision_id

    def test_boundary_exact_balance_equals_amount(self) -> None:
        """balance - amount == 0 must be SAT (>= 0)."""
        intent = {"amount": Decimal("1000")}
        state = {**_GOOD_STATE, "balance": Decimal("1000")}
        assert self.guard.verify(intent, state).allowed is True

    def test_pydantic_model_instances_accepted_for_intent(self) -> None:
        intent_model = _TransferIntent(amount=Decimal("100"))
        d = self.guard.verify(intent_model, _GOOD_STATE)
        assert d.allowed is True

    def test_pydantic_model_instances_accepted_for_state(self) -> None:
        state_model = _AccountState(
            state_version="1.0",
            balance=Decimal("1000"),
            daily_limit=Decimal("5000"),
            is_frozen=False,
        )
        d = self.guard.verify(_GOOD_INTENT, state_model)
        assert d.allowed is True


# ═══════════════════════════════════════════════════════════════════════════════
# Guard.verify — UNSAFE
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardVerifyUnsafe:
    def setup_method(self) -> None:
        self.guard = Guard(_TradePolicy)

    def test_allowed_false(self) -> None:
        assert self.guard.verify(_OVERDRAFT_INTENT, _OVERDRAFT_STATE).allowed is False

    def test_status_unsafe(self) -> None:
        d = self.guard.verify(_OVERDRAFT_INTENT, _OVERDRAFT_STATE)
        assert d.status is SolverStatus.UNSAFE

    def test_violated_invariant_label_present(self) -> None:
        d = self.guard.verify(_OVERDRAFT_INTENT, _OVERDRAFT_STATE)
        assert "non_negative_balance" in d.violated_invariants

    def test_explanation_non_empty(self) -> None:
        d = self.guard.verify(_OVERDRAFT_INTENT, _OVERDRAFT_STATE)
        assert d.explanation != ""

    def test_explanation_formatted_with_concrete_values(self) -> None:
        d = self.guard.verify(_OVERDRAFT_INTENT, _OVERDRAFT_STATE)
        # Explanation template = "Overdraft: balance={balance}, amount={amount}"
        assert "50" in d.explanation or "2000" in d.explanation

    def test_multi_violation_all_reported(self) -> None:
        """Overdraft + frozen account: both labels must appear."""
        state = {**_OVERDRAFT_STATE, "is_frozen": True}
        d = self.guard.verify(_OVERDRAFT_INTENT, state)
        assert "non_negative_balance" in d.violated_invariants
        assert "account_not_frozen" in d.violated_invariants

    def test_one_cent_over_boundary_is_unsafe(self) -> None:
        intent = {"amount": Decimal("1000.01")}
        state = {**_GOOD_STATE, "balance": Decimal("1000.00")}
        d = self.guard.verify(intent, state)
        assert d.allowed is False
        assert "non_negative_balance" in d.violated_invariants

    def test_frozen_account_blocked(self) -> None:
        state = {**_GOOD_STATE, "is_frozen": True}
        d = self.guard.verify(_GOOD_INTENT, state)
        assert d.allowed is False
        assert "account_not_frozen" in d.violated_invariants


# ═══════════════════════════════════════════════════════════════════════════════
# Guard.verify — STALE_STATE
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardVerifyStaleState:
    def setup_method(self) -> None:
        self.guard = Guard(_TradePolicy)

    def test_wrong_version_blocked(self) -> None:
        state = {**_GOOD_STATE, "state_version": "0.9"}
        d = self.guard.verify(_GOOD_INTENT, state)
        assert d.allowed is False
        assert d.status is SolverStatus.STALE_STATE

    def test_explanation_contains_both_versions(self) -> None:
        state = {**_GOOD_STATE, "state_version": "0.9"}
        d = self.guard.verify(_GOOD_INTENT, state)
        assert "1.0" in d.explanation
        assert "0.9" in d.explanation

    def test_future_version_also_blocked(self) -> None:
        """Even a 'future' version string must be blocked if it doesn't match."""
        state = {**_GOOD_STATE, "state_version": "99.0"}
        d = self.guard.verify(_GOOD_INTENT, state)
        assert d.allowed is False
        assert d.status is SolverStatus.STALE_STATE

    def test_missing_state_version_returns_blocked(self) -> None:
        """Pydantic strict mode will reject the missing required field."""
        state = {k: v for k, v in _GOOD_STATE.items() if k != "state_version"}
        d = self.guard.verify(_GOOD_INTENT, state)
        assert d.allowed is False
        assert d.status in {SolverStatus.VALIDATION_FAILURE, SolverStatus.STALE_STATE}


# ═══════════════════════════════════════════════════════════════════════════════
# Guard.verify — VALIDATION_FAILURE
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardVerifyValidationFailure:
    def setup_method(self) -> None:
        self.guard = Guard(_TradePolicy)

    def test_invalid_intent_type_blocked(self) -> None:
        d = self.guard.verify({"amount": "not-a-number"}, _GOOD_STATE)
        assert d.allowed is False
        assert d.status is SolverStatus.VALIDATION_FAILURE

    def test_invalid_state_type_blocked(self) -> None:
        state = {**_GOOD_STATE, "balance": "not-a-decimal"}
        d = self.guard.verify(_GOOD_INTENT, state)
        assert d.allowed is False
        assert d.status is SolverStatus.VALIDATION_FAILURE

    def test_explanation_describes_failure(self) -> None:
        d = self.guard.verify({"amount": "not-a-number"}, _GOOD_STATE)
        assert d.explanation != ""

    def test_missing_required_intent_field_blocked(self) -> None:
        d = self.guard.verify({}, _GOOD_STATE)
        assert d.allowed is False


# ═══════════════════════════════════════════════════════════════════════════════
# Guard.verify — raw-dict mode (no Meta on policy)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardVerifyRawMode:
    def setup_method(self) -> None:
        self.guard = Guard(_RawPolicy)

    def test_safe_with_raw_dicts(self) -> None:
        d = self.guard.verify(
            {"amount": Decimal("100")},
            {"balance": Decimal("1000")},
        )
        assert d.allowed is True

    def test_unsafe_with_raw_dicts(self) -> None:
        d = self.guard.verify(
            {"amount": Decimal("2000")},
            {"balance": Decimal("1000")},
        )
        assert d.allowed is False
        assert d.status is SolverStatus.UNSAFE

    def test_no_version_check_without_meta(self) -> None:
        """Without Policy.Meta.version, state_version is never checked."""
        d = self.guard.verify(
            {"amount": Decimal("50")},
            {"balance": Decimal("1000"), "state_version": "ANYTHING"},
        )
        assert d.allowed is True

    def test_conflicting_keys_blocked(self) -> None:
        """Intent and state must not share keys."""
        d = self.guard.verify(
            {"balance": Decimal("100"), "amount": Decimal("50")},
            {"balance": Decimal("1000")},
        )
        assert d.allowed is False


# ═══════════════════════════════════════════════════════════════════════════════
# Guard.verify — fail-safe contract (never raises)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardFailSafe:
    """Guard.verify() must return Decision(allowed=False) for ALL exception types."""

    def setup_method(self) -> None:
        self.guard = Guard(_TradePolicy)

    def _patch_solve(self, monkeypatch: pytest.MonkeyPatch, side_effect: Exception) -> Decision:
        def _raise(*a, **kw): raise side_effect
        monkeypatch.setattr(_guard_mod, "solve", _raise)
        return self.guard.verify(_GOOD_INTENT, _GOOD_STATE)

    def test_solver_timeout_returns_timeout_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = self._patch_solve(monkeypatch, SolverTimeoutError("non_negative_balance", 5_000))
        assert d.allowed is False
        assert d.status is SolverStatus.TIMEOUT
        assert "non_negative_balance" in d.violated_invariants

    def test_transpile_error_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = self._patch_solve(monkeypatch, TranspileError("bad node"))
        assert d.allowed is False
        assert d.status is SolverStatus.ERROR

    def test_runtime_error_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = self._patch_solve(monkeypatch, RuntimeError("z3 segfault simulation"))
        assert d.allowed is False
        assert d.status is SolverStatus.ERROR

    def test_unexpected_exception_explanation_contains_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = self._patch_solve(monkeypatch, ValueError("surprise"))
        assert "ValueError" in d.explanation

    def test_memory_error_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        d = self._patch_solve(monkeypatch, MemoryError("OOM"))
        assert d.allowed is False

    @pytest.mark.parametrize(
        "exc",
        [
            RuntimeError("unexpected"),
            MemoryError("oom"),
            ValueError("bad value"),
            TypeError("wrong type"),
            AttributeError("missing attr"),
            ZeroDivisionError("div by zero"),
        ],
    )
    def test_all_exception_types_return_allowed_false(
        self, monkeypatch: pytest.MonkeyPatch, exc: Exception
    ) -> None:
        d = self._patch_solve(monkeypatch, exc)
        assert d.allowed is False, f"{type(exc).__name__} produced allowed=True"

    def test_invariants_raising_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _ExplodingPolicy(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("pos")]

        g = Guard(_ExplodingPolicy)
        def _boom(*a, **kw): raise RuntimeError("boom")
        monkeypatch.setattr(_ExplodingPolicy, "invariants", classmethod(_boom))
        d = g.verify({"x": Decimal("1")}, {})
        assert d.allowed is False
        assert d.status is SolverStatus.ERROR

    def test_verify_is_callable_100_times_without_raises(self) -> None:
        """Stress: verify must never raise regardless of call count."""
        for _ in range(100):
            d = self.guard.verify(_GOOD_INTENT, _GOOD_STATE)
            assert isinstance(d, Decision)
