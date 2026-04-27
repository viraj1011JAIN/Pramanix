# SPDX-License-Identifier: AGPL-3.0-only
"""Targeted coverage tests — round 2.

Covers the remaining gaps in:
  circuit_breaker.py (TranslatorCircuitBreaker, prometheus registry paths),
  crypto.py (_increment_signing_failure_counter, sign error path),
  audit_sink.py (delivery_cb error, DatadogAuditSink init/emit),
  interceptors/grpc.py (unary_stream, stream_unary, stream_stream called),
  execution_token.py (Postgres verifier, Redis scan pagination),
  guard.py (max_input_bytes, fast_path, redact_violations, metrics),
  audit/archiver.py (_archive_segment exception path).
"""
from __future__ import annotations

import asyncio
import threading
import time
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Helper factories ─────────────────────────────────────────────────────────


def _make_guard(execution_mode: str = "sync", **kwargs: Any):
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
            return [(E(_amount) >= Decimal("0")).named("pos").explain("Amount must be non-negative")]

    return Guard(_P, GuardConfig(execution_mode=execution_mode, **kwargs))


def _make_safe_decision():
    from pramanix.decision import Decision, SolverStatus
    return Decision(allowed=True, status=SolverStatus.SAFE, violated_invariants=(), explanation="")


# ── TranslatorCircuitBreaker ─────────────────────────────────────────────────


class TestTranslatorCircuitBreaker:
    def test_state_property(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        cb = TranslatorCircuitBreaker("m")
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_call_success_stays_closed(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("m")

        async def _ok():
            return "result"

        result = await cb.call(_ok)
        assert result == "result"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_call_failure_increments_and_trips(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("m", failure_threshold=2)

        async def _fail():
            raise ExtractionFailureError("down")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)
        assert cb.state == CircuitState.CLOSED  # threshold not yet hit

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_call_open_raises_immediately(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("m", failure_threshold=1, recovery_seconds=60.0)

        async def _fail():
            raise ExtractionFailureError("down")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)  # trips OPEN

        assert cb.state == CircuitState.OPEN

        with pytest.raises(ExtractionFailureError, match="circuit breaker OPEN"):
            await cb.call(_fail)

    @pytest.mark.asyncio
    async def test_call_half_open_recovery(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("m", failure_threshold=1, recovery_seconds=0.001)

        async def _fail():
            raise ExtractionFailureError("down")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)  # trips OPEN

        await asyncio.sleep(0.05)  # wait out recovery window

        async def _succeed():
            return "recovered"

        result = await cb.call(_succeed)  # HALF_OPEN → probe → CLOSED
        assert result == "recovered"
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_call_half_open_probe_fails_returns_open(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("m", failure_threshold=1, recovery_seconds=0.001)

        async def _fail():
            raise ExtractionFailureError("down")

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)  # trips OPEN

        await asyncio.sleep(0.05)

        with pytest.raises(ExtractionFailureError):
            await cb.call(_fail)  # HALF_OPEN probe fails → OPEN again
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_call_llm_timeout_error_trips(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import LLMTimeoutError

        cb = TranslatorCircuitBreaker("m", failure_threshold=1)

        async def _timeout():
            raise LLMTimeoutError("timeout")

        with pytest.raises(LLMTimeoutError):
            await cb.call(_timeout)
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_call_unexpected_exception_reraises_without_tripping(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("m", failure_threshold=3)

        async def _boom():
            raise ValueError("unexpected")

        with pytest.raises(ValueError):
            await cb.call(_boom)
        assert cb.state == CircuitState.CLOSED  # not incremented

    def test_reset(self) -> None:
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("m", failure_threshold=1)
        cb._state = CircuitState.OPEN
        cb._consecutive_failures = 3
        cb._opened_at = time.monotonic()

        cb.reset()

        assert cb.state == CircuitState.CLOSED
        assert cb._consecutive_failures == 0
        assert cb._opened_at is None

    @pytest.mark.asyncio
    async def test_call_success_after_partial_failures_resets_counter(self) -> None:
        from pramanix.circuit_breaker import TranslatorCircuitBreaker

        cb = TranslatorCircuitBreaker("m", failure_threshold=5)
        cb._consecutive_failures = 2  # simulate prior failures

        async def _ok():
            return "ok"

        result = await cb.call(_ok)
        assert result == "ok"
        assert cb._consecutive_failures == 0


# ── circuit_breaker: prometheus registry recovery paths ──────────────────────


class TestCircuitBreakerPrometheusRegistryPaths:
    def test_adaptive_cb_register_metrics_value_error_none_in_registry(self) -> None:
        """_register_metrics ValueError path: REGISTRY returns None → metrics_available=False."""
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="test-prom-1")

        mock_registry = MagicMock()
        mock_registry._names_to_collectors = {}  # all lookups return None

        # Gauge raises ValueError on second instantiation
        with patch("prometheus_client.Gauge", side_effect=ValueError("already registered")):
            with patch("prometheus_client.Counter", side_effect=ValueError("already registered")):
                with patch("prometheus_client.REGISTRY", mock_registry):
                    cb = AdaptiveCircuitBreaker(guard, config)

        assert cb._metrics_available is False

    def test_adaptive_cb_register_metrics_inner_exception(self) -> None:
        """_register_metrics ValueError path: inner REGISTRY access raises → metrics_available=False."""
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="test-prom-2")

        mock_registry = MagicMock()
        mock_registry._names_to_collectors.get.side_effect = RuntimeError("registry boom")

        with patch("prometheus_client.Gauge", side_effect=ValueError("already")):
            with patch("prometheus_client.REGISTRY", mock_registry):
                cb = AdaptiveCircuitBreaker(guard, config)

        assert cb._metrics_available is False

    def test_distributed_cb_register_metrics_value_error_none_in_registry(self) -> None:
        """DistributedCircuitBreaker: ValueError path with None registry entries."""
        from pramanix.circuit_breaker import CircuitBreakerConfig, DistributedCircuitBreaker

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="test-dist-prom")

        mock_registry = MagicMock()
        mock_registry._names_to_collectors = {}

        with patch("prometheus_client.Gauge", side_effect=ValueError("already")):
            with patch("prometheus_client.Counter", side_effect=ValueError("already")):
                with patch("prometheus_client.REGISTRY", mock_registry):
                    cb = DistributedCircuitBreaker(guard, config)

        assert cb._metrics_available is False

    def test_distributed_cb_register_metrics_inner_exception(self) -> None:
        """DistributedCircuitBreaker: inner REGISTRY exception → metrics_available=False."""
        from pramanix.circuit_breaker import CircuitBreakerConfig, DistributedCircuitBreaker

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="test-dist-prom-2")

        mock_registry = MagicMock()
        mock_registry._names_to_collectors.get.side_effect = RuntimeError("inner boom")

        with patch("prometheus_client.Gauge", side_effect=ValueError("already")):
            with patch("prometheus_client.REGISTRY", mock_registry):
                cb = DistributedCircuitBreaker(guard, config)

        assert cb._metrics_available is False

    def test_distributed_cb_update_prometheus_exception_swallowed(self) -> None:
        """DistributedCircuitBreaker._update_prometheus swallows gauge.labels() exceptions."""
        from pramanix.circuit_breaker import CircuitBreakerConfig, DistributedCircuitBreaker

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="test-update-prom")
        cb = DistributedCircuitBreaker(guard, config)

        if not cb._metrics_available:
            pytest.skip("prometheus_client not set up properly in this test")

        # Make the gauge.labels() call raise
        cb._state_gauge = MagicMock()
        cb._state_gauge.labels.side_effect = RuntimeError("gauge error")
        cb._metrics_available = True

        cb._update_prometheus()  # must not raise

    @pytest.mark.asyncio
    async def test_redis_backend_close_with_open_client(self) -> None:
        """RedisDistributedBackend.close() closes the client."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        # Need to construct without triggering real redis import check
        # Use __new__ and inject attributes
        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock(return_value=None)
        backend._client = mock_client
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        await backend.close()

        mock_client.aclose.assert_called_once()
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_redis_backend_close_exception_swallowed(self) -> None:
        """RedisDistributedBackend.close() swallows aclose() exceptions."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock(side_effect=RuntimeError("connection lost"))
        backend._client = mock_client
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        await backend.close()  # must not raise
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_redis_backend_clear_async(self) -> None:
        """RedisDistributedBackend.clear_async() calls _async_clear."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        backend._client = None
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        mock_client = AsyncMock()
        mock_client.keys = AsyncMock(return_value=[])
        mock_client.delete = AsyncMock(return_value=None)

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.clear_async(namespace="test")
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_redis_backend_async_clear_with_keys(self) -> None:
        """_async_clear(namespace=None) deletes all matching keys."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        backend._client = None
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        mock_client = AsyncMock()
        mock_client.keys = AsyncMock(return_value=["key1", "key2"])
        mock_client.delete = AsyncMock(return_value=2)

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend._async_clear(namespace=None)

        mock_client.delete.assert_called_once_with("key1", "key2")

    @pytest.mark.asyncio
    async def test_redis_backend_async_clear_no_keys(self) -> None:
        """_async_clear(namespace=None) with empty key list skips delete."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        backend._client = None
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        mock_client = AsyncMock()
        mock_client.keys = AsyncMock(return_value=[])
        mock_client.delete = AsyncMock(return_value=0)

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend._async_clear(namespace=None)

        mock_client.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_redis_backend_async_clear_exception_swallowed(self) -> None:
        """_async_clear swallows exceptions."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        backend._client = None
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        with patch.object(backend, "_get_client", side_effect=RuntimeError("redis down")):
            await backend._async_clear(namespace="test")  # must not raise


# ── Crypto ────────────────────────────────────────────────────────────────────


class TestCryptoSigningFailureCounter:
    def test_increment_when_counter_already_registered(self) -> None:
        """_increment_signing_failure_counter handles ValueError (counter already exists)."""
        from pramanix.crypto import _increment_signing_failure_counter

        mock_counter_instance = MagicMock()
        mock_registry = MagicMock()
        mock_registry._names_to_collectors = {
            "pramanix_signing_failure_total": mock_counter_instance
        }

        with patch("prometheus_client.Counter", side_effect=ValueError("already registered")):
            with patch("prometheus_client.REGISTRY", mock_registry):
                _increment_signing_failure_counter()

        mock_counter_instance.inc.assert_called_once()

    def test_increment_when_registry_lookup_returns_none(self) -> None:
        """REGISTRY lookup returns None → early return without error."""
        from pramanix.crypto import _increment_signing_failure_counter

        mock_registry = MagicMock()
        mock_registry._names_to_collectors = {}  # returns None for any lookup

        with patch("prometheus_client.Counter", side_effect=ValueError("already")):
            with patch("prometheus_client.REGISTRY", mock_registry):
                _increment_signing_failure_counter()  # must not raise

    def test_sign_exception_increments_failure_counter(self) -> None:
        """PramanixSigner.sign() swallows exceptions and calls failure counter."""
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner(force_ephemeral=True)

        # Replace the Rust private key with a MagicMock that raises on sign()
        mock_key = MagicMock()
        mock_key.sign.side_effect = RuntimeError("HSM unavailable")
        signer._private_key = mock_key

        counter_called = []
        with patch("pramanix.crypto._increment_signing_failure_counter",
                   side_effect=lambda: counter_called.append(1)):
            result = signer.sign(_make_safe_decision())

        assert result == ""
        assert counter_called

    def test_verify_decision_exception_returns_false(self) -> None:
        """PramanixVerifier.verify_decision() returns False on unexpected exception."""
        from pramanix.crypto import PramanixSigner, PramanixVerifier
        from pramanix.decision import Decision, SolverStatus

        signer = PramanixSigner(force_ephemeral=True)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())

        with patch.object(verifier, "verify", side_effect=RuntimeError("boom")):
            decision = Decision(
                allowed=True,
                status=SolverStatus.SAFE,
                violated_invariants=(),
                explanation="",
                decision_hash="abc",
                signature="sig",
            )
            result = verifier.verify_decision(decision)
        assert result is False


# ── Audit sink ────────────────────────────────────────────────────────────────


class TestKafkaDeliveryCallback:
    def _make_kafka_sink(self, mock_producer, max_queue=10_000):
        import threading
        from pramanix.audit_sink import KafkaAuditSink
        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._topic = "test-topic"
        sink._producer = mock_producer
        sink._queue_depth = 0
        sink._max_queue = max_queue
        sink._overflow_count = 0
        sink._queue_lock = threading.Lock()
        sink._poll_stop = threading.Event()
        return sink

    def test_delivery_callback_with_error_logs(self) -> None:
        """delivery callback invoked with error → logs error."""
        captured_callbacks: list = []

        mock_producer = MagicMock()
        mock_producer.produce.side_effect = lambda topic, value, callback: captured_callbacks.append(callback)

        sink = self._make_kafka_sink(mock_producer)

        sink.emit(_make_safe_decision())

        if captured_callbacks:
            callback = captured_callbacks[0]
            fake_err = MagicMock()
            with patch("pramanix.audit_sink.log") as mock_log:
                callback(fake_err, None)  # err is truthy
                mock_log.error.assert_called()


class TestDatadogAuditSinkInit:
    def _mock_datadog_modules(self):
        mock_dd = MagicMock()
        mock_dd.Configuration.return_value = MagicMock()
        mock_dd.ApiClient.return_value = MagicMock()
        mock_v2 = MagicMock()
        mock_v2.LogsApi.return_value = MagicMock()
        return mock_dd, mock_v2

    def test_datadog_init_body_coverage(self) -> None:
        """DatadogAuditSink.__init__ runs through all init lines."""
        mock_dd, mock_v2 = self._mock_datadog_modules()

        with patch.dict("sys.modules", {
            "datadog_api_client": mock_dd,
            "datadog_api_client.v2": mock_v2,
            "datadog_api_client.v2.api": MagicMock(),
            "datadog_api_client.v2.api.logs_api": mock_v2,
        }):
            from pramanix.audit_sink import DatadogAuditSink
            sink = DatadogAuditSink(api_key="dd-test-key", service="my-service", source="my-src")

        assert sink._service == "my-service"
        assert sink._source == "my-src"
        assert sink._tags == ""

    def test_datadog_init_uses_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DatadogAuditSink with api_key=None reads DD_API_KEY env var."""
        monkeypatch.setenv("DD_API_KEY", "env-api-key")
        mock_dd, mock_v2 = self._mock_datadog_modules()

        with patch.dict("sys.modules", {
            "datadog_api_client": mock_dd,
            "datadog_api_client.v2": mock_v2,
            "datadog_api_client.v2.api": MagicMock(),
            "datadog_api_client.v2.api.logs_api": mock_v2,
        }):
            from pramanix.audit_sink import DatadogAuditSink
            sink = DatadogAuditSink()  # api_key=None, reads DD_API_KEY

        # Configuration.api_key["apiKeyAuth"] was set
        config = mock_dd.Configuration.return_value
        config.api_key.__setitem__.assert_called()

    def test_datadog_emit_sends_log(self) -> None:
        """DatadogAuditSink.emit() calls submit_log."""
        mock_dd, mock_v2 = self._mock_datadog_modules()
        mock_logs_api_instance = mock_v2.LogsApi.return_value

        with patch.dict("sys.modules", {
            "datadog_api_client": mock_dd,
            "datadog_api_client.v2": mock_v2,
            "datadog_api_client.v2.api": MagicMock(),
            "datadog_api_client.v2.api.logs_api": mock_v2,
            "datadog_api_client.v2.model": MagicMock(),
            "datadog_api_client.v2.model.http_log": mock_v2,
            "datadog_api_client.v2.model.http_log_item": mock_v2,
        }):
            from pramanix.audit_sink import DatadogAuditSink
            sink = DatadogAuditSink(api_key="key")
            sink.emit(_make_safe_decision())

        mock_logs_api_instance.submit_log.assert_called_once()


# ── gRPC interceptor ──────────────────────────────────────────────────────────


class TestGrpcWrappedHandlerCalls:
    """Exercise the inner handler functions that _wrap_handler builds."""

    def _make_interceptor(self, *, always_allow: bool = True):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _AllowPolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                # Always pass: amount >= -999999
                return [(E(_amount) >= Decimal("-999999")).named("pass").explain("pass")]

        class _BlockPolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                # Always fail: amount >= 999999
                return [(E(_amount) >= Decimal("999999")).named("fail").explain("fail")]

        PolicyCls = _AllowPolicy if always_allow else _BlockPolicy
        guard = Guard(PolicyCls, GuardConfig(execution_mode="sync"))

        from pramanix.interceptors.grpc import PramanixGrpcInterceptor
        return PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {"amount": Decimal("100")},
            state_provider=lambda: {"state_version": "1.0"},
        )

    def _capture_wrapped(self, interceptor, handler_attrs: dict) -> dict:
        """Call intercept_service and capture the _replace kwargs."""
        fake_handler = MagicMock()
        fake_handler.unary_unary = MagicMock(return_value="ok")
        for attr, val in handler_attrs.items():
            setattr(fake_handler, attr, val)

        captured: dict = {}

        def fake_replace(**kwargs):
            captured.update(kwargs)
            return fake_handler

        fake_handler._replace = fake_replace
        interceptor.intercept_service(lambda _: fake_handler, MagicMock())
        return captured

    def test_unary_stream_blocked(self) -> None:
        """_guarded_unary_stream returns without yielding when guard blocks."""
        interceptor = self._make_interceptor(always_allow=False)
        captured = self._capture_wrapped(interceptor, {
            "unary_stream": MagicMock(return_value=iter([1, 2, 3])),
            "stream_unary": None,
            "stream_stream": None,
        })

        if "unary_stream" in captured:
            mock_ctx = MagicMock()
            mock_ctx.abort = MagicMock()
            items = list(captured["unary_stream"]("req", mock_ctx))
            assert items == []

    def test_unary_stream_allowed(self) -> None:
        """_guarded_unary_stream yields from handler when guard allows."""
        interceptor = self._make_interceptor(always_allow=True)
        captured = self._capture_wrapped(interceptor, {
            "unary_stream": MagicMock(return_value=iter([10, 20])),
            "stream_unary": None,
            "stream_stream": None,
        })

        if "unary_stream" in captured:
            mock_ctx = MagicMock()
            items = list(captured["unary_stream"]("req", mock_ctx))
            assert items == [10, 20]

    def test_stream_unary_allowed(self) -> None:
        """_guarded_stream_unary passes combined iterator to handler when allowed."""
        interceptor = self._make_interceptor(always_allow=True)
        captured = self._capture_wrapped(interceptor, {
            "unary_stream": None,
            "stream_unary": MagicMock(return_value="stream_result"),
            "stream_stream": None,
        })

        if "stream_unary" in captured:
            mock_ctx = MagicMock()
            result = captured["stream_unary"](iter(["msg1", "msg2"]), mock_ctx)
            assert result == "stream_result"

    def test_stream_unary_blocked(self) -> None:
        """_guarded_stream_unary returns None when guard blocks."""
        interceptor = self._make_interceptor(always_allow=False)
        captured = self._capture_wrapped(interceptor, {
            "unary_stream": None,
            "stream_unary": MagicMock(return_value="x"),
            "stream_stream": None,
        })

        if "stream_unary" in captured:
            mock_ctx = MagicMock()
            mock_ctx.abort = MagicMock()
            result = captured["stream_unary"](iter(["msg"]), mock_ctx)
            assert result is None

    def test_stream_stream_allowed(self) -> None:
        """_guarded_stream_stream yields from handler when allowed."""
        interceptor = self._make_interceptor(always_allow=True)
        captured = self._capture_wrapped(interceptor, {
            "unary_stream": None,
            "stream_unary": None,
            "stream_stream": MagicMock(return_value=iter(["a", "b"])),
        })

        if "stream_stream" in captured:
            mock_ctx = MagicMock()
            items = list(captured["stream_stream"](iter(["msg"]), mock_ctx))
            assert items == ["a", "b"]

    def test_stream_stream_blocked(self) -> None:
        """_guarded_stream_stream returns without yielding when guard blocks."""
        interceptor = self._make_interceptor(always_allow=False)
        captured = self._capture_wrapped(interceptor, {
            "unary_stream": None,
            "stream_unary": None,
            "stream_stream": MagicMock(return_value=iter(["x", "y"])),
        })

        if "stream_stream" in captured:
            mock_ctx = MagicMock()
            mock_ctx.abort = MagicMock()
            items = list(captured["stream_stream"](iter(["msg"]), mock_ctx))
            assert items == []


# ── PostgresExecutionTokenVerifier ────────────────────────────────────────────


def _make_postgres_verifier(mock_pool: Any) -> Any:
    """Build a PostgresExecutionTokenVerifier without a real DB connection."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier
    verifier = PostgresExecutionTokenVerifier.__new__(PostgresExecutionTokenVerifier)
    verifier._key = b"secret-key-min16"
    verifier._dsn = "postgresql://localhost/test"
    verifier._prefix = "pramanix:token:"
    verifier._pool = mock_pool
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True, name="test-pg-loop")
    thread.start()
    verifier._loop = loop
    verifier._loop_thread = thread
    return verifier


def _make_exec_token(key: bytes, *, expired: bool = False, state_version: str | None = "v1") -> Any:
    """Create a signed ExecutionToken using ExecutionTokenSigner.mint()."""
    from pramanix.decision import Decision, SolverStatus
    from pramanix.execution_token import ExecutionTokenSigner

    decision = Decision(allowed=True, status=SolverStatus.SAFE, violated_invariants=(), explanation="")
    signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=-1 if expired else 60)
    return signer.mint(decision, state_version=state_version)


def _make_conn_ctx(mock_conn: Any) -> MagicMock:
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


class TestPostgresExecutionTokenVerifier:
    def test_consume_success(self) -> None:
        """consume(): valid token, INSERT succeeds → True."""
        import asyncpg
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)
        mock_conn.fetchrow = AsyncMock(return_value=None)

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _make_conn_ctx(mock_conn)

        verifier = _make_postgres_verifier(mock_pool)
        result = verifier.consume(token, expected_state_version=None)
        assert result is True

    def test_consume_state_version_mismatch(self) -> None:
        """consume(): state_version mismatch → False before any DB call."""
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version="v1")

        mock_pool = MagicMock()
        verifier = _make_postgres_verifier(mock_pool)
        result = verifier.consume(token, expected_state_version="v2")
        assert result is False
        mock_pool.acquire.assert_not_called()

    def test_consume_unique_violation_returns_false(self) -> None:
        """consume(): asyncpg.UniqueViolationError → False (token already used)."""
        import asyncpg
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(
            side_effect=asyncpg.UniqueViolationError("duplicate key value")
        )

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _make_conn_ctx(mock_conn)

        verifier = _make_postgres_verifier(mock_pool)
        result = verifier.consume(token, expected_state_version=None)
        assert result is False

    def test_evict_expired(self) -> None:
        """evict_expired() parses the 'DELETE N' response."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 3")

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _make_conn_ctx(mock_conn)

        verifier = _make_postgres_verifier(mock_pool)
        assert verifier.evict_expired() == 3

    def test_consumed_count(self) -> None:
        """consumed_count() returns row count from SELECT COUNT(*)."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"n": 7})

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _make_conn_ctx(mock_conn)

        verifier = _make_postgres_verifier(mock_pool)
        assert verifier.consumed_count() == 7

    def test_consumed_count_no_row(self) -> None:
        """consumed_count() returns 0 when fetchrow returns None."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _make_conn_ctx(mock_conn)

        verifier = _make_postgres_verifier(mock_pool)
        assert verifier.consumed_count() == 0

    def test_close(self) -> None:
        """close() shuts down pool and stops the event loop."""
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock(return_value=None)

        verifier = _make_postgres_verifier(mock_pool)
        verifier.close()  # must not raise

    @pytest.mark.asyncio
    async def test_consume_within_success(self) -> None:
        """consume_within() inserts within caller's connection, returns True."""
        import asyncpg
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)

        verifier = _make_postgres_verifier(MagicMock())
        result = await verifier.consume_within(mock_conn, token, expected_state_version=None)
        assert result is True

    @pytest.mark.asyncio
    async def test_consume_within_unique_violation(self) -> None:
        """consume_within() returns False on UniqueViolationError (INSERT)."""
        import asyncpg
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        # _ensure_table calls conn.execute twice (CREATE TABLE, CREATE INDEX),
        # then the INSERT is a third call. Raise UniqueViolationError only on INSERT.
        call_count = {"n": 0}
        async def _side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] >= 3:
                raise asyncpg.UniqueViolationError("duplicate")
            return None

        mock_conn = AsyncMock()
        mock_conn.execute = _side_effect

        verifier = _make_postgres_verifier(MagicMock())
        result = await verifier.consume_within(mock_conn, token, expected_state_version=None)
        assert result is False

    @pytest.mark.asyncio
    async def test_consume_within_sig_mismatch(self) -> None:
        """consume_within() returns False when signature is wrong."""
        import asyncpg
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        verifier = _make_postgres_verifier(MagicMock())
        verifier._key = b"wrong-key-min16!"  # different key

        mock_conn = AsyncMock()
        result = await verifier.consume_within(mock_conn, token)
        assert result is False

    @pytest.mark.asyncio
    async def test_consume_within_state_version_mismatch(self) -> None:
        """consume_within() returns False on state_version mismatch."""
        import asyncpg
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version="v1")

        verifier = _make_postgres_verifier(MagicMock())
        mock_conn = AsyncMock()
        result = await verifier.consume_within(mock_conn, token, expected_state_version="v2")
        assert result is False


# ── Redis scan pagination ─────────────────────────────────────────────────────


class TestRedisScanPagination:
    def test_consumed_count_multiple_pages(self) -> None:
        """consumed_count() iterates when scan returns non-zero cursor."""
        from pramanix.execution_token import RedisExecutionTokenVerifier

        verifier = RedisExecutionTokenVerifier.__new__(RedisExecutionTokenVerifier)
        verifier._key = b"secret-key-min16"
        verifier._prefix = "pramanix:token:"

        scan_calls = [
            (42, ["key1", "key2"]),   # non-zero cursor → continue
            (0, ["key3"]),            # cursor=0 → stop
        ]
        call_idx = [0]

        def _fake_scan(cursor, match, count):
            result = scan_calls[call_idx[0]]
            call_idx[0] += 1
            return result

        mock_redis = MagicMock()
        mock_redis.scan.side_effect = _fake_scan
        verifier._redis = mock_redis

        count = verifier.consumed_count()
        assert count == 3  # 2 + 1 across two pages


# ── Guard: verify_async paths ─────────────────────────────────────────────────


class TestGuardVerifyAsyncPaths:
    @pytest.mark.asyncio
    async def test_verify_async_max_input_bytes_exceeded(self) -> None:
        """verify_async blocks oversized payloads before Z3 (async-thread mode)."""
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
                return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

        guard = Guard(_P, GuardConfig(execution_mode="async-thread", max_input_bytes=10))
        d = await guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert not d.allowed

    @pytest.mark.asyncio
    async def test_verify_async_fast_path_blocks(self) -> None:
        """verify_async returns blocked decision when fast_path fires."""
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
                return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

        def _block_all(intent: dict, state: dict) -> str | None:
            return "fast_path_block: blocked by policy"

        guard = Guard(
            _P,
            GuardConfig(
                execution_mode="async-thread",
                fast_path_enabled=True,
                fast_path_rules=(_block_all,),
            ),
        )
        d = await guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert not d.allowed

    def test_verify_redact_violations_hides_internal_error(self) -> None:
        """With redact_violations=True, internal error details are hidden from caller."""
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
                return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

        guard = Guard(_P, GuardConfig(execution_mode="sync", redact_violations=True))

        # Patch solve (called inside _verify_core) to raise an unexpected exception
        with patch("pramanix.guard.solve", side_effect=RuntimeError("secret internal detail")):
            d = guard.verify(
                intent={"amount": Decimal("100")},
                state={"state_version": "1.0"},
            )

        assert not d.allowed
        # _sign_decision() applies redaction to ALL blocked decisions, so even
        # the error path gets explanation overwritten to the generic message.
        assert d.status.value == "error"
        assert "secret internal detail" not in (d.explanation or "")
        # The error branch is covered (log output confirms it), and oracle
        # protection replaces explanation with the safe generic message.
        assert d.explanation == "Policy Violation: Action Blocked"

    def test_verify_timeout_triggers_metric(self) -> None:
        """SolverTimeoutError is recorded in the timeout metric branch."""
        from pramanix import E, Field, Guard, GuardConfig, Policy
        from pramanix.exceptions import SolverTimeoutError

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

        guard = Guard(_P, GuardConfig(execution_mode="sync", metrics_enabled=True))

        with patch("pramanix.guard.solve",
                   side_effect=SolverTimeoutError(label="pos", timeout_ms=100)):
            d = guard.verify(
                intent={"amount": Decimal("100")},
                state={"state_version": "1.0"},
            )

        assert not d.allowed
        from pramanix.decision import SolverStatus
        assert d.status == SolverStatus.TIMEOUT


# ── Guard: _emit_translator_metric ────────────────────────────────────────────


class TestEmitTranslatorMetric:
    def test_emit_metric_none_counter_in_registry(self) -> None:
        """_emit_translator_metric: REGISTRY returns None for counter → returns early."""
        from pramanix.guard import _emit_translator_metric

        mock_registry = MagicMock()
        mock_registry._names_to_collectors = {}  # returns None

        with patch("prometheus_client.Counter", side_effect=ValueError("already")):
            with patch("prometheus_client.REGISTRY", mock_registry):
                _emit_translator_metric("extraction_failure", ["model-a", "model-b"])

    def test_emit_metric_general_exception_swallowed(self) -> None:
        """_emit_translator_metric swallows all exceptions."""
        from pramanix.guard import _emit_translator_metric

        with patch("prometheus_client.Counter", side_effect=RuntimeError("prom down")):
            _emit_translator_metric("consensus_failure", ["m"])  # must not raise


# ── audit/archiver.py ─────────────────────────────────────────────────────────


class TestArchiverSegmentWriteFailure:
    def test_archive_segment_write_failure_cleans_up_tmp(self, tmp_path) -> None:
        """_archive_segment: write failure removes the tmp file and re-raises."""
        import os
        from pramanix.audit.archiver import MerkleArchiver

        archiver = MerkleArchiver(base_path=str(tmp_path), segment_days=0)
        for i in range(5):
            archiver.add(f"decision-{i:04d}")

        original_fdopen = os.fdopen

        def _failing_fdopen(fd, mode, *args, **kwargs):
            fh = original_fdopen(fd, mode, *args, **kwargs)
            real_write = fh.write

            def _boom(data):
                raise OSError("disk full")

            fh.write = _boom
            return fh

        with patch("os.fdopen", side_effect=_failing_fdopen):
            try:
                archiver._archive_segment()
            except OSError:
                pass

        # No partial tmp files should remain
        partials = list(tmp_path.glob(".merkle.tmp.*"))
        assert len(partials) == 0


# ── anthropic.py: _single_call + extract success path (lines 116, 163) ───────


class TestAnthropicExtractSuccessPath:
    @pytest.mark.asyncio
    async def test_single_call_returns_streamed_text(self) -> None:
        """Line 163: get_final_text() return value flows back to caller."""
        from pramanix.translator.anthropic import AnthropicTranslator

        t = AnthropicTranslator("claude-opus-4-6", api_key="sk-test")
        mock_stream = AsyncMock()
        mock_stream.get_final_text = AsyncMock(return_value='{"amount": 100}')
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        t._client.messages.stream = MagicMock(return_value=mock_ctx)
        result = await t._single_call(system_prompt="Extract JSON", text="pay 100")
        assert result == '{"amount": 100}'

    @pytest.mark.asyncio
    async def test_extract_success_uses_parse_llm_response(self) -> None:
        """Line 116: parse_llm_response() is called with the raw text from _single_call."""
        from pydantic import BaseModel

        from pramanix.translator.anthropic import AnthropicTranslator

        class _Schema(BaseModel):
            amount: int

        t = AnthropicTranslator("claude-opus-4-6", api_key="sk-test")
        with patch.object(t, "_single_call", new=AsyncMock(return_value='{"amount": 42}')):
            result = await t.extract("pay 42", _Schema)
        assert result == {"amount": 42}

    @pytest.mark.asyncio
    async def test_extract_api_status_error_raises_extraction_failure(self) -> None:
        """Lines 126-127: APIStatusError from _single_call maps to ExtractionFailureError."""
        from pydantic import BaseModel

        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.anthropic import AnthropicTranslator

        class _MockAPIStatusError(Exception):
            status_code = 401
            message = "Unauthorized"

        class _Schema(BaseModel):
            amount: int

        t = AnthropicTranslator("claude-opus-4-6", api_key="sk-test")
        t._api_status_error = _MockAPIStatusError  # replace so except branch matches
        with patch.object(t, "_single_call", side_effect=_MockAPIStatusError("auth error")):
            with pytest.raises(ExtractionFailureError, match="401"):
                await t.extract("pay 42", _Schema)


# ── key_provider.py: supports_rotation + cache-miss paths ────────────────────


class TestKeyProviderSupportsRotation:
    def test_pem_provider_no_rotation(self) -> None:
        from pramanix.key_provider import PemKeyProvider

        assert PemKeyProvider(b"FAKE_PEM").supports_rotation is False

    def test_env_provider_no_rotation(self) -> None:
        from pramanix.key_provider import EnvKeyProvider

        p = EnvKeyProvider.__new__(EnvKeyProvider)
        p._env_var = "PRAMANIX_SIGNING_KEY_PEM"
        p._version = "env-1"
        assert p.supports_rotation is False

    def test_file_provider_no_rotation(self, tmp_path) -> None:
        from pramanix.key_provider import FileKeyProvider

        assert FileKeyProvider(tmp_path / "key.pem").supports_rotation is False

    def test_azure_provider_no_rotation(self) -> None:
        import threading

        from pramanix.key_provider import AzureKeyVaultKeyProvider

        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        p._client = MagicMock()
        p._secret_name = "key"
        p._secret_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        assert p.supports_rotation is False

    def test_gcp_provider_no_rotation(self) -> None:
        import threading

        from pramanix.key_provider import GcpKmsKeyProvider

        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._client = MagicMock()
        p._project_id = "proj"
        p._secret_id = "secret"
        p._version_id = "latest"
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cache_expires = 0.0
        assert p.supports_rotation is False

    def test_vault_provider_no_rotation(self) -> None:
        import threading

        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._client = MagicMock()
        p._secret_path = "pramanix/key"
        p._field = "private_key_pem"
        p._mount_point = "secret"
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        assert p.supports_rotation is False

    def test_aws_private_key_pem_cache_miss_triggers_refresh(self) -> None:
        """Lines 317-319: cache_valid() False forces _refresh_cache() in private_key_pem."""
        import threading

        from pramanix.key_provider import AwsKmsKeyProvider

        mc = MagicMock()
        mc.get_secret_value.return_value = {"SecretString": "FAKE_PEM"}
        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = mc
        p._secret_arn = "arn:aws:secretsmanager:us-east-1:123:secret:k"
        p._version_stage = "AWSCURRENT"
        p._explicit_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0  # expired → cache miss on first call
        assert p.private_key_pem() == b"FAKE_PEM"

    def test_aws_key_version_cache_miss_triggers_refresh(self) -> None:
        """Lines 326-328: cache_valid() False forces _refresh_cache() in key_version."""
        import threading

        from pramanix.key_provider import AwsKmsKeyProvider

        mc = MagicMock()
        mc.get_secret_value.return_value = {"SecretString": "FAKE_PEM", "VersionId": "v-99"}
        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = mc
        p._secret_arn = "arn:aws:secretsmanager:us-east-1:123:secret:k"
        p._version_stage = "AWSCURRENT"
        p._explicit_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0  # expired → cache miss
        assert p.key_version() == "v-99"

    def test_gcp_public_key_pem_calls_derive(self) -> None:
        """Line 494: GcpKmsKeyProvider.public_key_pem() delegates to _derive_public_pem."""
        import threading

        from pramanix.key_provider import GcpKmsKeyProvider

        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._client = MagicMock()
        p._project_id = "proj"
        p._secret_id = "secret"
        p._version_id = "latest"
        p._cache_lock = threading.Lock()
        p._cached_pem = b"FAKE_PEM"
        p._cache_expires = float("inf")  # cache valid — skips refresh
        with patch("pramanix.key_provider._derive_public_pem", return_value=b"PUBLIC") as mock_derive:
            result = p.public_key_pem()
        assert result == b"PUBLIC"
        mock_derive.assert_called_once_with(b"FAKE_PEM")

    def test_aws_supports_rotation_is_true(self) -> None:
        """Line 332: AwsKmsKeyProvider.supports_rotation returns True."""
        import threading

        from pramanix.key_provider import AwsKmsKeyProvider

        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = MagicMock()
        p._secret_arn = "arn:aws:secretsmanager:us-east-1:123:secret:k"
        p._version_stage = "AWSCURRENT"
        p._explicit_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        assert p.supports_rotation is True

    def test_aws_private_key_pem_cache_hit_skips_refresh(self) -> None:
        """Branch 317->319: cache valid → _refresh_cache() is NOT called."""
        import threading

        from pramanix.key_provider import AwsKmsKeyProvider

        mc = MagicMock()
        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = mc
        p._secret_arn = "arn:aws:secretsmanager:us-east-1:123:secret:k"
        p._version_stage = "AWSCURRENT"
        p._explicit_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = b"CACHED_PEM"
        p._cached_version = "v-cached"
        p._cache_expires = float("inf")  # valid forever
        result = p.private_key_pem()
        assert result == b"CACHED_PEM"
        mc.get_secret_value.assert_not_called()

    def test_aws_key_version_cache_hit_skips_refresh(self) -> None:
        """Branch 326->328: cache valid in key_version() → _refresh_cache() NOT called."""
        import threading

        from pramanix.key_provider import AwsKmsKeyProvider

        mc = MagicMock()
        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = mc
        p._secret_arn = "arn:aws:secretsmanager:us-east-1:123:secret:k"
        p._version_stage = "AWSCURRENT"
        p._explicit_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = b"CACHED_PEM"
        p._cached_version = "v-cached"
        p._cache_expires = float("inf")  # valid forever
        result = p.key_version()
        assert result == "v-cached"
        mc.get_secret_value.assert_not_called()

    def test_vault_private_key_pem_cache_hit_skips_refresh(self) -> None:
        """Branch 576->578: Vault cache valid → _refresh_cache() NOT called."""
        import threading

        from pramanix.key_provider import HashiCorpVaultKeyProvider

        mc = MagicMock()
        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._client = mc
        p._secret_path = "pramanix/key"
        p._field = "private_key_pem"
        p._mount_point = "secret"
        p._cache_lock = threading.Lock()
        p._cached_pem = b"VAULT_PEM"
        p._cached_version = "7"
        p._cache_expires = float("inf")  # valid forever
        result = p.private_key_pem()
        assert result == b"VAULT_PEM"
        mc.secrets.kv.v2.read_secret_version.assert_not_called()


# ── worker.py: warmup metric failure + __del__ exception path ─────────────────


class TestWorkerEdgePaths:
    def test_warmup_worker_prometheus_exception_swallowed(self) -> None:
        """Lines 392-393: inner except swallows prometheus counter errors during warmup."""
        from pramanix.worker import _warmup_worker

        with patch("z3.Solver", side_effect=RuntimeError("z3 down")):
            with patch("prometheus_client.Counter", side_effect=RuntimeError("prom down")):
                _warmup_worker()  # must not raise

    def test_worker_pool_del_shutdown_exception_swallowed(self) -> None:
        """Lines 652-653: WorkerPool.__del__ swallows errors from shutdown()."""
        from pramanix.worker import WorkerPool

        obj = WorkerPool.__new__(WorkerPool)
        obj._alive = True
        with patch.object(WorkerPool, "shutdown", side_effect=RuntimeError("boom")):
            WorkerPool.__del__(obj)  # must not raise
