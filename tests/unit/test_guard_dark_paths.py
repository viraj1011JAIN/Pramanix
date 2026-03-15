# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for guard.py dark / uncovered paths.

Coverage targets
----------------
* _env_int  - valid env var, invalid env var (ValueError)
* _env_bool - non-None env var branch
* _fmt      - empty template, KeyError/ValueError format failure
* _semantic_post_consensus_check - all branches
* Guard.verify_async - async-thread mode (validation, version, errors)
* Guard.verify_async - pool=None, unknown mode
* Guard.shutdown     - with pool (non-None)
* Guard.parse_and_verify - generic Exception branch
* OTel span set_attribute path (mocked)
* Prometheus metrics path (mocked)
"""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import SemanticPolicyViolation


# ===============================================================
# Minimal policies
# ===============================================================

_amount_field = Field("amount", Decimal, "Real")


class _MinimalPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _amount_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [
            (E(_amount_field) >= 0)
            .named("non_negative")
            .explain("amount {amount} must be >= 0"),
        ]


class _Intent(BaseModel):
    amount: Decimal


class _State(BaseModel):
    state_version: str
    balance: Decimal


class _ModelledPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = _Intent
        state_model = _State

    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _amount_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [
            (E(_amount_field) >= 0)
            .named("non_negative")
            .explain("amount {amount} must be >= 0"),
        ]


# ===============================================================
# _env_int
# ===============================================================


class TestEnvInt:
    def test_valid_env_var_returns_int(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_int

        monkeypatch.setenv("PRAMANIX_SOLVER_TIMEOUT_MS", "9999")
        assert _env_int("SOLVER_TIMEOUT_MS", 5000) == 9999

    def test_invalid_env_var_returns_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_int

        monkeypatch.setenv("PRAMANIX_SOLVER_TIMEOUT_MS", "not_a_number")
        assert _env_int("SOLVER_TIMEOUT_MS", 5000) == 5000

    def test_missing_env_var_returns_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_int

        monkeypatch.delenv("PRAMANIX_SOLVER_TIMEOUT_MS", raising=False)
        assert _env_int("SOLVER_TIMEOUT_MS", 42) == 42


# ===============================================================
# _env_bool
# ===============================================================


class TestEnvBool:
    def test_true_string_returns_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.setenv("PRAMANIX_METRICS_ENABLED", "true")
        assert _env_bool("METRICS_ENABLED", False) is True

    def test_one_string_returns_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.setenv("PRAMANIX_METRICS_ENABLED", "1")
        assert _env_bool("METRICS_ENABLED", False) is True

    def test_false_string_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.setenv("PRAMANIX_METRICS_ENABLED", "false")
        assert _env_bool("METRICS_ENABLED", True) is False

    def test_missing_env_var_returns_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.delenv("PRAMANIX_METRICS_ENABLED", raising=False)
        assert _env_bool("METRICS_ENABLED", True) is True


# ===============================================================
# _fmt
# ===============================================================


class TestFmt:
    def test_empty_label_returns_empty_string(self) -> None:
        from pramanix.guard import _fmt

        inv = (E(_amount_field) >= 0).named("")
        assert _fmt(inv, {"amount": "100"}) == ""

    def test_normal_interpolation_works(self) -> None:
        from pramanix.guard import _fmt

        inv = (
            (E(_amount_field) >= 0)
            .named("lbl")
            .explain("amount is {amount}")
        )
        assert _fmt(inv, {"amount": "50"}) == "amount is 50"

    def test_missing_key_returns_raw_template(self) -> None:
        from pramanix.guard import _fmt

        inv = (
            (E(_amount_field) >= 0)
            .named("lbl")
            .explain("value={missing_key}")
        )
        result = _fmt(inv, {"amount": "50"})
        assert result == "value={missing_key}"

    def test_bad_format_spec_returns_raw_template(self) -> None:
        from pramanix.guard import _fmt

        inv = (
            (E(_amount_field) >= 0)
            .named("lbl")
            .explain("{amount!invalid_conversion}")
        )
        result = _fmt(inv, {"amount": "50"})
        assert result == "{amount!invalid_conversion}"


# ===============================================================
# _semantic_post_consensus_check
# ===============================================================


class TestSemanticPostConsensusCheck:
    def _call(self, intent: dict, state: dict) -> None:
        from pramanix.guard import _semantic_post_consensus_check

        _semantic_post_consensus_check(intent, state)

    def test_no_amount_field_returns_without_error(self) -> None:
        self._call({"other": "value"}, {})

    def test_invalid_amount_raises(self) -> None:
        with pytest.raises(
            SemanticPolicyViolation, match="not a valid number"
        ):
            self._call({"amount": "not-a-decimal"}, {})

    def test_zero_amount_raises(self) -> None:
        with pytest.raises(
            SemanticPolicyViolation, match="must be positive"
        ):
            self._call({"amount": "0"}, {})

    def test_negative_amount_raises(self) -> None:
        with pytest.raises(
            SemanticPolicyViolation, match="must be positive"
        ):
            self._call({"amount": "-50"}, {})

    def test_balance_below_minimum_reserve_raises(self) -> None:
        with pytest.raises(
            SemanticPolicyViolation, match="minimum reserve"
        ):
            self._call(
                {"amount": "900"},
                {"balance": "1000", "minimum_reserve": "200"},
            )

    def test_full_balance_drain_raises(self) -> None:
        with pytest.raises(
            SemanticPolicyViolation, match="secondary human approval"
        ):
            self._call(
                {"amount": "1000"},
                {"balance": "1000", "minimum_reserve": "0"},
            )

    def test_valid_transfer_passes(self) -> None:
        self._call(
            {"amount": "100"},
            {"balance": "1000", "minimum_reserve": "0"},
        )

    def test_daily_limit_exceeded_raises(self) -> None:
        with pytest.raises(
            SemanticPolicyViolation, match="daily limit"
        ):
            self._call(
                {"amount": "600"},
                {
                    "balance": "5000",
                    "daily_limit": "1000",
                    "daily_spent": "500",
                },
            )

    def test_daily_limit_ok_passes(self) -> None:
        self._call(
            {"amount": "100"},
            {
                "balance": "5000",
                "daily_limit": "1000",
                "daily_spent": "500",
            },
        )

    def test_non_numeric_balance_is_skipped(self) -> None:
        self._call({"amount": "100"}, {"balance": "not-a-number"})


# ===============================================================
# Guard.verify_async -- async-thread mode paths
# ===============================================================


@pytest.fixture
def async_thread_guard():
    """Guard in async-thread mode; shut down after use."""
    import asyncio

    cfg = GuardConfig(
        execution_mode="async-thread",
        max_workers=1,
        worker_warmup=False,
    )
    g = Guard(policy=_ModelledPolicy, config=cfg)
    yield g
    asyncio.get_event_loop().run_until_complete(g.shutdown())


class TestVerifyAsyncThreadMode:
    @pytest.mark.asyncio
    async def test_allow_with_decimal_intent_and_state(
        self, async_thread_guard: Guard
    ) -> None:
        """dict->validate_intent + validate_state + version check (ALLOW)."""
        result = await async_thread_guard.verify_async(
            intent={"amount": Decimal("50")},
            state={
                "state_version": "1.0",
                "balance": Decimal("1000"),
            },
        )
        assert result.allowed

    @pytest.mark.asyncio
    async def test_state_version_none_returns_validation_failure(
        self, async_thread_guard: Guard
    ) -> None:
        """state_version missing -> validation_failure (line 738)."""
        from pramanix import SolverStatus

        result = await async_thread_guard.verify_async(
            intent={"amount": Decimal("50")},
            state={"balance": Decimal("1000")},  # no state_version
        )
        assert not result.allowed
        assert result.status == SolverStatus.VALIDATION_FAILURE

    @pytest.mark.asyncio
    async def test_stale_state_version_returns_stale(
        self, async_thread_guard: Guard
    ) -> None:
        """Wrong state_version -> stale_state (line 746)."""
        from pramanix import SolverStatus

        result = await async_thread_guard.verify_async(
            intent={"amount": Decimal("50")},
            state={
                "state_version": "9.9",
                "balance": Decimal("1000"),
            },
        )
        assert not result.allowed
        assert result.status == SolverStatus.STALE_STATE

    @pytest.mark.asyncio
    async def test_pydantic_validation_error_returns_validation_failure(
        self, async_thread_guard: Guard
    ) -> None:
        """Bad type in intent -> ValidationError -> validation_failure."""
        from pramanix import SolverStatus

        result = await async_thread_guard.verify_async(
            intent={"amount": "not-a-decimal"},
            state={
                "state_version": "1.0",
                "balance": Decimal("1000"),
            },
        )
        assert not result.allowed
        assert result.status == SolverStatus.VALIDATION_FAILURE

    @pytest.mark.asyncio
    async def test_generic_exception_in_validate_returns_error(
        self, async_thread_guard: Guard
    ) -> None:
        """Generic exception during validation -> error Decision."""
        from pramanix import SolverStatus

        with patch(
            "pramanix.guard.validate_intent",
            side_effect=RuntimeError("unexpected"),
        ):
            result = await async_thread_guard.verify_async(
                intent={"amount": Decimal("50")},
                state={
                    "state_version": "1.0",
                    "balance": Decimal("1000"),
                },
            )
        assert not result.allowed
        assert result.status == SolverStatus.ERROR


# ===============================================================
# Guard.verify_async -- pool=None and unknown mode
# ===============================================================


class TestVerifyAsyncEdgeModes:
    @pytest.mark.asyncio
    async def test_pool_none_returns_error(self) -> None:
        """pool is None -> Decision.error (line 771)."""
        from pramanix import SolverStatus

        cfg = GuardConfig(
            execution_mode="async-thread",
            max_workers=1,
            worker_warmup=False,
        )
        g = Guard(policy=_MinimalPolicy, config=cfg)
        await g.shutdown()
        g._pool = None  # type: ignore[assignment]

        result = await g.verify_async(
            intent={"amount": Decimal("50")},
            state={"state_version": "1.0"},
        )
        assert not result.allowed
        assert result.status == SolverStatus.ERROR

    @pytest.mark.asyncio
    async def test_unknown_mode_returns_error(self) -> None:
        """Unknown execution_mode -> Decision.error (line 814)."""
        from pramanix import SolverStatus

        g = Guard(policy=_MinimalPolicy, config=GuardConfig())
        mock_cfg = MagicMock()
        mock_cfg.execution_mode = "turbo-quantum"
        mock_cfg.solver_timeout_ms = 5000
        g._config = mock_cfg  # type: ignore[assignment]
        g._pool = MagicMock()  # type: ignore[assignment]

        result = await g.verify_async(
            intent={"amount": Decimal("50")},
            state={"state_version": "1.0"},
        )
        assert not result.allowed
        assert result.status == SolverStatus.ERROR


# ===============================================================
# Guard.shutdown -- with pool
# ===============================================================


class TestGuardShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_with_pool_delegates(self) -> None:
        """Pool is not None -> to_thread(pool.shutdown) called."""
        cfg = GuardConfig(
            execution_mode="async-thread",
            max_workers=1,
            worker_warmup=False,
        )
        g = Guard(policy=_MinimalPolicy, config=cfg)
        assert g._pool is not None
        await g.shutdown()

    @pytest.mark.asyncio
    async def test_shutdown_without_pool_is_noop(self) -> None:
        g = Guard(policy=_MinimalPolicy, config=GuardConfig())
        assert g._pool is None
        await g.shutdown()


# ===============================================================
# OTel span set_attribute path
# ===============================================================


class TestOtelSpanAttributes:
    def test_verify_emits_span_attributes_when_span_not_none(self) -> None:
        """Patch _span so it yields a non-None mock; verify set_attribute called."""
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        g = Guard(policy=_MinimalPolicy, config=GuardConfig())

        with patch("pramanix.guard._span", return_value=mock_span):
            g.verify(
                intent={"amount": Decimal("100")},
                state={"state_version": "1.0"},
            )

        calls = [
            str(c) for c in mock_span.set_attribute.call_args_list
        ]
        assert any("decision_id" in c for c in calls)


# ===============================================================
# Prometheus metrics path
# ===============================================================


class TestPrometheusMetrics:
    def test_verify_increments_metrics_when_enabled(self) -> None:
        """metrics_enabled=True + _PROM_AVAILABLE=True -> counters called."""
        import pramanix.guard as _guard_mod

        mock_counter = MagicMock()
        mock_histogram = MagicMock()

        with (
            patch.object(_guard_mod, "_PROM_AVAILABLE", True),
            patch.object(_guard_mod, "_decisions_total", mock_counter),
            patch.object(_guard_mod, "_decision_latency", mock_histogram),
            patch.object(
                _guard_mod, "_solver_timeouts_total", MagicMock()
            ),
            patch.object(
                _guard_mod, "_validation_failures_total", MagicMock()
            ),
        ):
            cfg = GuardConfig(metrics_enabled=True)
            g = Guard(policy=_MinimalPolicy, config=cfg)
            g.verify(
                intent={"amount": Decimal("50")},
                state={"state_version": "1.0"},
            )

        mock_counter.labels.assert_called()
        mock_histogram.labels.assert_called()


# ===============================================================
# Guard.parse_and_verify -- generic Exception branch
# ===============================================================


class TestParseAndVerifyGenericException:
    @pytest.mark.asyncio
    async def test_generic_exception_branch_via_mock_create_translator(
        self,
    ) -> None:
        """RuntimeError inside parse_and_verify -> Decision.error (899-900)."""
        from pramanix import SolverStatus

        g = Guard(policy=_MinimalPolicy, config=GuardConfig())

        with patch(
            "pramanix.translator.redundant.create_translator",
            side_effect=RuntimeError("injected error"),
        ):
            result = await g.parse_and_verify(
                prompt="transfer 100",
                intent_schema=_Intent,
                state={"state_version": "1.0", "balance": Decimal("1000")},
            )

        assert not result.allowed
        assert result.status == SolverStatus.ERROR
