# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Coverage tests for circuit_breaker.py — prometheus metrics paths and production guards.

Covers:
  TranslatorCircuitBreaker._register_metrics — ImportError path (lines 1203-1204)
  TranslatorCircuitBreaker._register_metrics — _prom_register returns None (1201->exit)
  TranslatorCircuitBreaker._update_state_metric — early return when unavailable (1208)
  TranslatorCircuitBreaker._update_state_metric — exception swallowed (1214-1215)
  TranslatorCircuitBreaker.call — all False-branch metrics arcs (1246->1251, 1272->1276,
      1293->1303, 1301-1302, 1307->1310, 1324->1331, 1329-1330)
  AdaptiveCircuitBreaker._register_metrics — ImportError path (450-451)
  AdaptiveCircuitBreaker._increment_pressure_metric — exception swallowed (472-473)
  DistributedCircuitBreaker.__init__ — no backend ConfigurationError (601)
  DistributedCircuitBreaker._register_metrics — ImportError path (796-797)
  InMemoryDistributedBackend.__init__ — PRAMANIX_ENV=production guard (511-513)
  _inc_sync_failure_counter — exception during registration (66-91)
"""

from __future__ import annotations

import asyncio
import time
from decimal import Decimal
from typing import Any

import pytest

from tests.helpers.real_protocols import _ErrorGauge


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_guard() -> Any:
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
            return [(E(_amount) >= Decimal("0")).named("pos").explain("non-negative")]

    return Guard(_P, GuardConfig(execution_mode="sync", audit_sinks=[]))


class _ErrorCounter:
    """Prometheus Counter duck-type whose labels().inc() raises RuntimeError."""

    def labels(self, **kw: Any) -> _ErrorCounter:
        return self

    def inc(self) -> None:
        raise RuntimeError("counter increment error")


# ── TranslatorCircuitBreaker: _register_metrics ImportError (lines 1203-1204) ─


class TestTranslatorCBRegisterMetricsImportError:
    def test_register_metrics_import_error_sets_unavailable(self) -> None:
        """Lines 1203-1204: ImportError in _register_metrics sets _metrics_available=False."""
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        def _raise_import():
            raise ImportError("prometheus_client not installed")

        cb = TranslatorCircuitBreaker("model-import-error", _prom_factory=_raise_import)
        assert cb._metrics_available is False
        assert cb._state_gauge is None


class TestTranslatorCBRegisterMetrics:
    def test_register_metrics_prom_register_none_sets_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Line 1201->exit: when _prom_register returns None, _metrics_available is False."""
        import pramanix.circuit_breaker as _cb_mod

        monkeypatch.setattr(_cb_mod, "_prom_register", lambda *a, **kw: None)
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("model-prom-none")
        assert cb._metrics_available is False
        # _update_state_metric must NOT have been called (metrics unavailable)
        assert cb._state_gauge is None

    def test_register_metrics_prom_exception_sets_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 1203-1204: non-ImportError exception also handled."""
        import pramanix.circuit_breaker as _cb_mod

        def _boom(*a: Any, **kw: Any) -> Any:
            raise RuntimeError("registry boom during TranslatorCB registration")

        monkeypatch.setattr(_cb_mod, "_prom_register", _boom)
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        with pytest.raises(RuntimeError, match="registry boom"):
            TranslatorCircuitBreaker("model-boom")


# ── TranslatorCircuitBreaker: _update_state_metric (lines 1207-1215) ──────────


class TestTranslatorCBUpdateStateMetric:
    def test_update_state_metric_early_return_when_unavailable(self) -> None:
        """Line 1208: _update_state_metric returns immediately when _metrics_available=False."""
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("model-no-state-gauge")
        cb._metrics_available = False
        cb._update_state_metric()  # must not raise

    def test_update_state_metric_exception_is_swallowed(self) -> None:
        """Lines 1214-1215: exception from state_gauge.labels() is logged, not raised."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("model-error-gauge")
        cb._metrics_available = True
        cb._state_gauge = _ErrorGauge()
        cb._state = CircuitState.CLOSED
        cb._update_state_metric()  # must not raise despite _ErrorGauge raising


# ── TranslatorCircuitBreaker.call: False-branch metrics arcs ─────────────────


class TestTranslatorCBCallNoMetrics:
    """Run all call() code paths with _metrics_available=False to cover False arcs."""

    @pytest.mark.asyncio
    async def test_open_rejection_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Arc 1246->1251: OPEN rejection fast path when metrics unavailable."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("nm-reject", failure_threshold=1, recovery_seconds=600.0)
        cb._state = CircuitState.OPEN
        cb._opened_at = time.monotonic()
        monkeypatch.setattr(cb, "_metrics_available", False)

        with pytest.raises(ExtractionFailureError, match="OPEN"):
            await cb.call(lambda: asyncio.sleep(0))

    @pytest.mark.asyncio
    async def test_probe_start_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Arc 1272->1276: probe starts in HALF_OPEN window when metrics unavailable."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("nm-probe", failure_threshold=1, recovery_seconds=0.001)
        cb._state = CircuitState.OPEN
        cb._opened_at = time.monotonic() - 1.0
        monkeypatch.setattr(cb, "_metrics_available", False)

        async def _succeed() -> str:
            return "recovered"

        result = await cb.call(_succeed)
        assert result == "recovered"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_failure_trips_open_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 1293->1303: circuit trips OPEN on consecutive failures, metrics unavailable."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("nm-trip", failure_threshold=1)
        monkeypatch.setattr(cb, "_metrics_available", False)

        async def _fail() -> None:
            raise ExtractionFailureError("down")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_failure_probe_trips_open_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 1293-1303 is_probe=True path: probe fails → OPEN, metrics unavailable."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("nm-probe-trip", failure_threshold=1, recovery_seconds=0.001)
        cb._state = CircuitState.OPEN
        cb._opened_at = time.monotonic() - 1.0
        monkeypatch.setattr(cb, "_metrics_available", False)

        async def _fail() -> None:
            raise ExtractionFailureError("probe failed")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_metrics_failure_counter_exception_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 1301-1302: except Exception in trips counter inc; metrics_available but counter raises."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("nm-counter-err", failure_threshold=1)
        cb._metrics_available = True
        cb._trips_counter = _ErrorCounter()
        cb._calls_counter = _ErrorCounter()
        # state_gauge and probes_counter stay as None (metrics partially broken)
        cb._state_gauge = _ErrorGauge()
        cb._probes_counter = _ErrorCounter()
        monkeypatch.setattr(cb, "_state", CircuitState.CLOSED)

        async def _fail() -> None:
            raise ExtractionFailureError("down")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)
        # must not raise even though counters raised

    @pytest.mark.asyncio
    async def test_unexpected_exception_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Arc 1307->1310: non-LLM exception path when metrics unavailable."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("nm-unexpected", failure_threshold=5)
        monkeypatch.setattr(cb, "_metrics_available", False)

        async def _boom() -> None:
            raise ValueError("unexpected error")

        with pytest.raises(ValueError):
            await cb.call(_boom)
        assert cb.state == CircuitState.CLOSED  # non-LLM errors don't trip

    @pytest.mark.asyncio
    async def test_success_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Arcs 1324->1331, 1329->1330: success path when metrics unavailable."""
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("nm-success")
        monkeypatch.setattr(cb, "_metrics_available", False)

        async def _ok() -> str:
            return "ok"

        result = await cb.call(_ok)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_success_after_failures_no_metrics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 1324-1331: recovery arc (prior failures reset) with metrics off."""
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("nm-recover")
        cb._consecutive_failures = 3  # simulate prior partial failures
        monkeypatch.setattr(cb, "_metrics_available", False)

        async def _ok() -> str:
            return "recovered"

        result = await cb.call(_ok)
        assert result == "recovered"
        assert cb._consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_success_counter_exception_swallowed(self) -> None:
        """Lines 1329-1330: exception in success counter inc is swallowed."""
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("nm-success-err")
        cb._metrics_available = True
        cb._calls_counter = _ErrorCounter()
        cb._probes_counter = _ErrorCounter()
        cb._state_gauge = _ErrorGauge()

        async def _ok() -> str:
            return "ok"

        result = await cb.call(_ok)
        assert result == "ok"  # exception in counter must not propagate


# ── AdaptiveCircuitBreaker: ImportError in _register_metrics (450-451) ────────


class TestAdaptiveCBRegisterMetricsImportError:
    def test_register_metrics_import_error_sets_unavailable(self) -> None:
        """Lines 475-476: ImportError in _register_metrics sets _metrics_available=False."""
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker

        def _raise_import():
            raise ImportError("prometheus_client not installed")

        guard = _make_guard()
        cb = AdaptiveCircuitBreaker(guard, _prom_factory=_raise_import)
        assert cb._metrics_available is False
        assert cb._state_gauge is None
        assert cb._pressure_counter is None


# ── DistributedCircuitBreaker: ImportError in _register_metrics (796-797) ─────


class TestDistributedCBRegisterMetricsImportError:
    def test_register_metrics_import_error_sets_unavailable(self) -> None:
        """Lines 826-827: ImportError in _register_metrics sets _metrics_available=False."""
        from pramanix.circuit_breaker import DistributedCircuitBreaker, InMemoryDistributedBackend
        import warnings

        def _raise_import():
            raise ImportError("prometheus_client not installed")

        guard = _make_guard()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            backend = InMemoryDistributedBackend()
        cb = DistributedCircuitBreaker(guard, backend=backend, _prom_factory=_raise_import)
        assert cb._metrics_available is False
        assert cb._state_gauge is None
        assert cb._pressure_counter is None


# ── AdaptiveCircuitBreaker: _increment_pressure_metric exception (472-473) ────


class TestAdaptiveCBPressureMetricException:
    def test_pressure_metric_exception_is_swallowed(self) -> None:
        """Lines 472-473: exception in pressure_counter.labels().inc() is swallowed."""
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker

        guard = _make_guard()
        cb = AdaptiveCircuitBreaker(guard)
        cb._metrics_available = True
        cb._pressure_counter = _ErrorGauge()  # labels() raises RuntimeError
        cb._increment_pressure_metric()  # must not raise


# ── DistributedCircuitBreaker: no backend ConfigurationError (601) ─────────────


class TestDistributedCBNoBackend:
    def test_no_backend_raises_configuration_error(self) -> None:
        """Line 601: ConfigurationError when backend=None (default)."""
        from pramanix.circuit_breaker import DistributedCircuitBreaker
        from pramanix.exceptions import ConfigurationError

        guard = _make_guard()
        with pytest.raises(ConfigurationError, match="explicit backend"):
            DistributedCircuitBreaker(guard, backend=None)


# ── DistributedCircuitBreaker: ImportError in _register_metrics (796-797) ─────


# ── InMemoryDistributedBackend: production guard (511-513) ────────────────────


class TestInMemoryDistributedBackendProductionGuard:
    def test_production_env_raises_configuration_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 511-513: ConfigurationError when PRAMANIX_ENV=production."""
        from pramanix.circuit_breaker import InMemoryDistributedBackend
        from pramanix.exceptions import ConfigurationError

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="PRAMANIX_ENV=production"):
            InMemoryDistributedBackend()

    def test_non_production_env_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """InMemoryDistributedBackend emits UserWarning in non-production environments."""
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)
        from pramanix.circuit_breaker import InMemoryDistributedBackend

        with pytest.warns(UserWarning, match="testing only"):
            backend = InMemoryDistributedBackend()
        assert backend is not None


# ── _inc_sync_failure_counter: exception path (lines 66-91) ──────────────────


class TestIncSyncFailureCounter:
    def test_increment_import_error_leaves_counter_none(self) -> None:
        """Lines 78-98: ImportError from _prom_factory logs warning and returns early."""
        from pramanix.circuit_breaker import _SyncFailureMetric

        def _raise_import():
            raise ImportError("prometheus_client not installed")

        metric = _SyncFailureMetric()
        # Must not raise despite ImportError
        metric.increment(_prom_factory=_raise_import)
        assert metric._counter is None  # counter never set

    def test_increment_exception_during_registration_logs_warning(self) -> None:
        """Lines 91-98: generic Exception from factory is caught and logged."""
        from pramanix.circuit_breaker import _SyncFailureMetric

        def _raise_runtime():
            raise RuntimeError("unexpected registry failure")

        metric = _SyncFailureMetric()
        metric.increment(_prom_factory=_raise_runtime)
        assert metric._counter is None

    def test_increment_counter_inc_exception_is_swallowed(self) -> None:
        """Lines 102-107: exception in counter.inc() is swallowed."""
        from pramanix.circuit_breaker import _SyncFailureMetric

        class _BoomCounter:
            def inc(self) -> None:
                raise RuntimeError("counter boom")

        metric = _SyncFailureMetric()
        metric._counter = _BoomCounter()  # pre-set counter that raises on inc()
        metric.increment()  # must not raise


# ── RedisDistributedBackend._warn_unclosed finalizer (P3.7) ──────────────────


class TestRedisDistributedBackendWarnUnclosed:
    """P3.7 — _warn_unclosed() must emit WARNING when a live client is GC'd.

    The finalizer is registered via weakref.finalize() in __init__; this test
    calls the static method directly so no Redis connection is required.
    """

    def test_warn_emitted_when_client_is_open(self, caplog: pytest.LogCaptureFixture) -> None:
        """cell[0] is not None → WARNING is emitted about the unclosed connection."""
        import logging

        from pramanix.circuit_breaker import RedisDistributedBackend

        cell: list[object] = [object()]  # non-None sentinel — simulates open client
        with caplog.at_level(logging.WARNING, logger="pramanix.circuit_breaker"):
            RedisDistributedBackend._warn_unclosed(cell)

        assert any(
            "GC" in r.message and "open Redis connection" in r.message
            for r in caplog.records
        ), f"Expected unclosed-connection WARNING but got: {[r.message for r in caplog.records]}"

    def test_no_warn_when_client_is_already_closed(self, caplog: pytest.LogCaptureFixture) -> None:
        """cell[0] is None → connection already closed; no WARNING should be emitted."""
        import logging

        from pramanix.circuit_breaker import RedisDistributedBackend

        cell: list[object] = [None]  # None sentinel — simulates already-closed client
        with caplog.at_level(logging.WARNING, logger="pramanix.circuit_breaker"):
            RedisDistributedBackend._warn_unclosed(cell)

        assert not caplog.records, (
            "Unexpected WARNING emitted when client_cell was already None: "
            f"{[r.message for r in caplog.records]}"
        )
