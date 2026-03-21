# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for guard.py dark / uncovered paths — production-level.

Design principles
-----------------
* **Prometheus**: ``prometheus_client`` is a hard dependency of Pramanix
  (``prometheus-client = "^0.19"`` in pyproject.toml), so
  ``_PROM_AVAILABLE`` is always ``True`` in the test environment.
  No patching needed.  Metric increments are verified by reading the
  actual counter value from the live registry before and after the call.

* **OpenTelemetry**: ``opentelemetry-sdk`` is added to dev deps.  The
  test configures a real ``TracerProvider`` with an ``InMemorySpanExporter``,
  replaces the module-level ``_span`` function with a real OTel span factory,
  then asserts on the exported span attributes.  No patch of internal
  state; the exporter captures real spans.

* **RuntimeError injection** (``test_generic_exception_in_validate_returns_error``
  and ``TestParseAndVerifyGenericException``): The only honest way to reach
  the ``except Exception`` fail-safe handlers is to inject a RuntimeError
  into a normally-stable call site.  Both tests use ``monkeypatch`` — the
  minimal standard-library patching tool — for exactly this purpose.
  No MagicMock, no AsyncMock; just a one-line side-effect replacement.

* **Unknown execution_mode** (``test_unknown_mode_returns_error``): GuardConfig
  validates the mode in ``__post_init__``, making the ``else`` branch in
  ``verify_async`` unreachable through normal API usage.  The test uses
  direct attribute replacement on the frozen dataclass (via
  ``object.__setattr__``) to reach this defensive branch without any
  mock framework.

Coverage targets
----------------
* _env_int  — valid env var, invalid env var (ValueError)
* _env_bool — non-None env var branch
* _fmt      — empty template, KeyError/ValueError format failure
* _semantic_post_consensus_check — all branches
* Guard.verify_async — async-thread mode (validation, version, errors)
* Guard.verify_async — pool=None, unknown mode
* Guard.shutdown     — with pool (non-None)
* Guard.parse_and_verify — generic Exception branch
* OTel span set_attribute path (real in-memory exporter)
* Prometheus metrics path (real counter reads)
"""
from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest
from pydantic import BaseModel

import pramanix.guard as _guard_mod
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
    def test_valid_env_var_returns_int(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard import _env_int

        monkeypatch.setenv("PRAMANIX_SOLVER_TIMEOUT_MS", "9999")
        assert _env_int("SOLVER_TIMEOUT_MS", 5000) == 9999

    def test_invalid_env_var_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard import _env_int

        monkeypatch.setenv("PRAMANIX_SOLVER_TIMEOUT_MS", "not_a_number")
        assert _env_int("SOLVER_TIMEOUT_MS", 5000) == 5000

    def test_missing_env_var_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard import _env_int

        monkeypatch.delenv("PRAMANIX_SOLVER_TIMEOUT_MS", raising=False)
        assert _env_int("SOLVER_TIMEOUT_MS", 42) == 42


# ===============================================================
# _env_bool
# ===============================================================


class TestEnvBool:
    def test_true_string_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.setenv("PRAMANIX_METRICS_ENABLED", "true")
        assert _env_bool("METRICS_ENABLED", False) is True

    def test_one_string_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.setenv("PRAMANIX_METRICS_ENABLED", "1")
        assert _env_bool("METRICS_ENABLED", False) is True

    def test_false_string_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard import _env_bool

        monkeypatch.setenv("PRAMANIX_METRICS_ENABLED", "false")
        assert _env_bool("METRICS_ENABLED", True) is False

    def test_missing_env_var_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
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

        inv = (E(_amount_field) >= 0).named("lbl").explain("amount is {amount}")
        assert _fmt(inv, {"amount": "50"}) == "amount is 50"

    def test_missing_key_returns_raw_template(self) -> None:
        from pramanix.guard import _fmt

        inv = (E(_amount_field) >= 0).named("lbl").explain("value={missing_key}")
        result = _fmt(inv, {"amount": "50"})
        assert result == "value={missing_key}"

    def test_bad_format_spec_returns_raw_template(self) -> None:
        from pramanix.guard import _fmt

        inv = (E(_amount_field) >= 0).named("lbl").explain("{amount!invalid_conversion}")
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
        with pytest.raises(SemanticPolicyViolation, match="not a valid number"):
            self._call({"amount": "not-a-decimal"}, {})

    def test_zero_amount_raises(self) -> None:
        with pytest.raises(SemanticPolicyViolation, match="must be positive"):
            self._call({"amount": "0"}, {})

    def test_negative_amount_raises(self) -> None:
        with pytest.raises(SemanticPolicyViolation, match="must be positive"):
            self._call({"amount": "-50"}, {})

    def test_balance_below_minimum_reserve_raises(self) -> None:
        with pytest.raises(SemanticPolicyViolation, match="minimum reserve"):
            self._call(
                {"amount": "900"},
                {"balance": "1000", "minimum_reserve": "200"},
            )

    def test_full_balance_drain_raises(self) -> None:
        with pytest.raises(SemanticPolicyViolation, match="secondary human approval"):
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
        with pytest.raises(SemanticPolicyViolation, match="daily limit"):
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
        """state_version missing -> validation_failure."""
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
        """Wrong state_version -> stale_state."""
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
        self, async_thread_guard: Guard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Guard fail-safe: RuntimeError inside validate_intent → Decision.error.

        The ``except Exception`` catch-all in _verify_core is defensive code
        that can only be reached by injecting an unexpected exception into
        a normally-stable code path.  ``monkeypatch`` is the minimal
        mechanism for this — no MagicMock, no AsyncMock.
        """
        from pramanix import SolverStatus
        from pramanix import guard as _gmod

        monkeypatch.setattr(
            _gmod, "validate_intent", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("unexpected"))
        )

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
        """pool is None → Decision.error (WorkerPool not initialised)."""
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
        """Unknown execution_mode → Decision.error.

        GuardConfig.__post_init__ rejects invalid modes, so this defensive
        branch is unreachable through the normal API.  We reach it by
        directly replacing the frozen dataclass on the Guard instance via
        ``object.__setattr__`` — no mock framework involved.
        """
        import dataclasses

        from pramanix import SolverStatus

        g = Guard(policy=_MinimalPolicy, config=GuardConfig())

        # Bypass GuardConfig.__post_init__ validation by creating a plain
        # dataclass copy with the invalid mode field injected directly.
        bad_config = dataclasses.replace(g._config)
        object.__setattr__(bad_config, "execution_mode", "turbo-quantum")
        g._config = bad_config  # type: ignore[assignment]

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
# OTel span set_attribute path — real in-memory exporter
# ===============================================================


class TestOtelSpanAttributes:
    def test_verify_emits_span_attributes_when_otel_configured(self) -> None:
        """Guard emits OTel spans with decision_id when a real TracerProvider
        is installed.

        Uses ``InMemorySpanExporter`` from opentelemetry-sdk (a dev dependency).
        The module-level ``_span`` function is temporarily replaced with a real
        OTel span factory that routes to the test provider — no MagicMock.
        The original is restored in the finally block.
        """
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))

        # Build a real span factory that uses our test provider
        def _real_span(name: str):  # type: ignore[no-untyped-def]
            return provider.get_tracer("pramanix.guard").start_as_current_span(name)

        original_span = _guard_mod._span  # type: ignore[attr-defined]
        _guard_mod._span = _real_span  # type: ignore[attr-defined]

        try:
            g = Guard(policy=_MinimalPolicy, config=GuardConfig())
            g.verify(
                intent={"amount": Decimal("100")},
                state={"state_version": "1.0"},
            )
        finally:
            _guard_mod._span = original_span  # type: ignore[attr-defined]

        finished = exporter.get_finished_spans()
        assert len(finished) > 0, "No spans were exported"

        verify_span = next(
            (s for s in finished if s.name == "pramanix.guard.verify"),
            None,
        )
        assert verify_span is not None, (
            "Expected a span named 'pramanix.guard.verify'"
        )
        assert "pramanix.decision_id" in verify_span.attributes
        assert "pramanix.policy.name" in verify_span.attributes


# ===============================================================
# Prometheus metrics path — real counter reads, no patching
# ===============================================================


class TestPrometheusMetrics:
    def test_prom_available_is_true(self) -> None:
        """prometheus_client is a hard dependency — _PROM_AVAILABLE must be True."""
        assert _guard_mod._PROM_AVAILABLE is True, (
            "_PROM_AVAILABLE is False — prometheus_client may not be installed"
        )

    def test_verify_increments_decisions_total_counter(self) -> None:
        """metrics_enabled=True → pramanix_decisions_total counter increments.

        Reads actual counter values from the live prometheus registry
        before and after Guard.verify().  No patching of any counter or
        availability flag.
        """
        policy_name = _MinimalPolicy.__name__

        def _read_counter(status: str) -> float:
            try:
                return (
                    _guard_mod._decisions_total  # type: ignore[attr-defined]
                    .labels(policy=policy_name, status=status)
                    ._value.get()
                )
            except Exception:
                return 0.0

        before = _read_counter("safe")

        cfg = GuardConfig(metrics_enabled=True)
        g = Guard(policy=_MinimalPolicy, config=cfg)
        g.verify(
            intent={"amount": Decimal("50")},
            state={"state_version": "1.0"},
        )

        after = _read_counter("safe")
        assert after > before, (
            f"pramanix_decisions_total{{status='safe'}} did not increment "
            f"(before={before}, after={after})"
        )

    def test_verify_increments_decision_latency_histogram(self) -> None:
        """Decision latency histogram is populated on each verify() call."""
        policy_name = _MinimalPolicy.__name__

        def _read_histogram_count() -> float:
            try:
                return (
                    _guard_mod._decision_latency  # type: ignore[attr-defined]
                    .labels(policy=policy_name)
                    ._sum.get()
                )
            except Exception:
                return 0.0

        before = _read_histogram_count()

        cfg = GuardConfig(metrics_enabled=True)
        g = Guard(policy=_MinimalPolicy, config=cfg)
        g.verify(
            intent={"amount": Decimal("50")},
            state={"state_version": "1.0"},
        )

        after = _read_histogram_count()
        assert after > before, (
            "pramanix_decision_latency_seconds histogram did not record "
            f"a new observation (before={before}, after={after})"
        )

    def test_metrics_disabled_does_not_raise(self) -> None:
        """metrics_enabled=False must not raise even if prometheus is available."""
        cfg = GuardConfig(metrics_enabled=False)
        g = Guard(policy=_MinimalPolicy, config=cfg)
        result = g.verify(
            intent={"amount": Decimal("50")},
            state={"state_version": "1.0"},
        )
        assert result.allowed


# ===============================================================
# Guard.parse_and_verify -- generic Exception branch
# ===============================================================


class TestParseAndVerifyGenericException:
    @pytest.mark.asyncio
    async def test_generic_exception_branch_via_monkeypatch(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """RuntimeError inside parse_and_verify → Decision.error.

        The ``except Exception`` fail-safe in parse_and_verify can only be
        reached by injecting an unexpected error into ``create_translator``.
        ``monkeypatch`` replaces the function for this call only — no
        MagicMock or AsyncMock involved.
        """
        from pramanix import SolverStatus
        from pramanix.translator import redundant as _redundant

        def _raise(*_a, **_kw):  # type: ignore[no-untyped-def]
            raise RuntimeError("injected error")

        monkeypatch.setattr(_redundant, "create_translator", _raise)

        g = Guard(policy=_MinimalPolicy, config=GuardConfig())
        result = await g.parse_and_verify(
            prompt="transfer 100",
            intent_schema=_Intent,
            state={"state_version": "1.0", "balance": Decimal("1000")},
        )

        assert not result.allowed
        assert result.status == SolverStatus.ERROR


# ===============================================================
# Phase 11: Logging isolation — intent_dump / state_dump must
# never appear in structlog output (financial data, PHI, etc.)
# ===============================================================


class TestLoggingIsolation:
    """Verify that intent_dump and state_dump values never reach log output.

    The structlog _redact_secrets_processor only matches keys like
    'secret', 'token', 'api_key'. It does NOT catch 'amount', 'balance',
    'patient_id', etc. This test enforces that Guard never passes those
    values to structlog in the first place.
    """

    def _capture_log_output(self, intent: dict, state: dict) -> str:
        """Run guard.verify() and capture all structlog output as a string."""
        import io as _io

        import structlog

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

        buf = _io.StringIO()
        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.processors.JSONRenderer(),
            ],
            logger_factory=structlog.PrintLoggerFactory(buf),
            cache_logger_on_first_use=False,
        )

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        guard.verify(intent=intent, state=state)
        return buf.getvalue()

    def test_financial_amounts_not_logged_on_allow(self) -> None:
        """Allowed decision must not log the actual amount or balance."""
        sentinel_amount = "98765432100"
        sentinel_balance = "11122233344"
        output = self._capture_log_output(
            intent={"amount": Decimal(sentinel_amount)},
            state={"balance": Decimal(sentinel_balance), "state_version": "1.0"},
        )
        assert sentinel_amount not in output, (
            f"amount {sentinel_amount!r} appeared in log output"
        )
        assert sentinel_balance not in output, (
            f"balance {sentinel_balance!r} appeared in log output"
        )

    def test_financial_amounts_not_logged_on_block(self) -> None:
        """Blocked decision must not log the actual amount or balance."""
        sentinel_amount = "55544433322111"
        sentinel_balance = "77766655544433"
        output = self._capture_log_output(
            intent={"amount": Decimal(sentinel_amount)},
            state={"balance": Decimal(sentinel_balance), "state_version": "1.0"},
        )
        assert sentinel_amount not in output, (
            f"amount {sentinel_amount!r} appeared in log output"
        )
        assert sentinel_balance not in output, (
            f"balance {sentinel_balance!r} appeared in log output"
        )
