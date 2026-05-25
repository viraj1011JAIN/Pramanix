# SPDX-License-Identifier: AGPL-3.0-only
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
import sys
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


class TestTranslatorCBRegisterMetrics:
    def test_register_metrics_import_error_sets_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 1203-1204: except ImportError sets _metrics_available=False."""
        monkeypatch.setitem(sys.modules, "prometheus_client", None)  # block import
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("model-import-err")
        assert cb._metrics_available is False

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


class TestAdaptiveCBRegisterMetrics:
    def test_register_metrics_import_error_sets_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 450-451: prometheus ImportError → _metrics_available=False."""
        monkeypatch.setitem(sys.modules, "prometheus_client", None)
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker

        guard = _make_guard()
        cb = AdaptiveCircuitBreaker(guard)
        assert cb._metrics_available is False


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


class TestDistributedCBRegisterMetrics:
    def test_register_metrics_import_error_sets_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 796-797: prometheus ImportError → _metrics_available=False."""
        monkeypatch.setitem(sys.modules, "prometheus_client", None)
        from pramanix.circuit_breaker import DistributedCircuitBreaker, InMemoryDistributedBackend

        guard = _make_guard()
        with pytest.warns(UserWarning, match="testing only"):
            backend = InMemoryDistributedBackend()

        cb = DistributedCircuitBreaker(guard, backend=backend)
        assert cb._metrics_available is False


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
    def test_prom_register_exception_returns_silently(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 79-86: non-ImportError exception during registration is logged + return."""
        import pramanix.circuit_breaker as _cb_mod

        # Reset the global counter so the lazy-init branch is entered.
        monkeypatch.setattr(_cb_mod, "_CB_SYNC_FAILURE_COUNTER", None)

        def _boom(*a: Any, **kw: Any) -> Any:
            raise RuntimeError("prom register exploded")

        monkeypatch.setattr(_cb_mod, "_prom_register", _boom)
        # Must not propagate — the function catches all exceptions.
        _cb_mod._inc_sync_failure_counter()

    def test_counter_inc_exception_is_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 90-94: exception in counter.inc() is swallowed."""
        import pramanix.circuit_breaker as _cb_mod

        broken = _ErrorCounter()
        # Set a counter that raises on inc().
        monkeypatch.setattr(_cb_mod, "_CB_SYNC_FAILURE_COUNTER", broken)
        _cb_mod._inc_sync_failure_counter()  # must not raise

    def test_counter_none_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_inc_sync_failure_counter is a no-op when counter is None (prometheus absent)."""
        import pramanix.circuit_breaker as _cb_mod

        # Use a counter object so the lazy-init is skipped and the None guard is hit.
        monkeypatch.setattr(_cb_mod, "_CB_SYNC_FAILURE_COUNTER", None)
        # Block prometheus so lazy-init falls back to None.
        monkeypatch.setitem(sys.modules, "prometheus_client", None)
        _cb_mod._inc_sync_failure_counter()  # must not raise
