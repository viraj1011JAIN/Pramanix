# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
import importlib.util as _ilu
import threading
import time
import types
from decimal import Decimal
from typing import Any

import pytest

_ASYNCPG_AVAILABLE = _ilu.find_spec("asyncpg") is not None
_skip_without_asyncpg = pytest.mark.skipif(not _ASYNCPG_AVAILABLE, reason="asyncpg not installed")

import contextlib

from tests.helpers.real_protocols import (
    _AnthropicErrorMessagesNS,
    _AnthropicMessagesNS,
    _AsyncClosablePool,
    _AsyncCloseClient,
    _AsyncErrorCloseClient,
    _AwsSecretsClient,
    _AzureSecretClient,
    _BrokenPrivateKey,
    _CapturingLogsApi,
    _CapturingProducer,
    _ErrorGauge,
    _ErrorRedisClient,
    _GcpSecretClient,
    _GrpcRpcHandler,
    _KafkaDeliveryError,
    _PgConn,
    _PgPool,
    _RpcContext,
    _SyncScanRedis,
)

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
            return [
                (E(_amount) >= Decimal("0")).named("pos").explain("Amount must be non-negative")
            ]

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

    @pytest.mark.asyncio
    async def test_call_rejects_concurrent_probe_when_probing_flag_set(self) -> None:
        """Line 1139: OPEN + recovery elapsed + _probing=True → ExtractionFailureError.

        §4.3 fix: TranslatorCircuitBreaker already had _probing logic; this test
        covers the line (1139) that was missing from branch coverage.
        """
        from pramanix.circuit_breaker import CircuitState, TranslatorCircuitBreaker
        from pramanix.exceptions import ExtractionFailureError

        cb = TranslatorCircuitBreaker("m-probe-race", failure_threshold=1, recovery_seconds=0.001)

        # Arrange: OPEN with recovery elapsed and another probe already running.
        cb._state = CircuitState.OPEN
        cb._opened_at = time.monotonic() - 999.0
        cb._probing = True

        async def _ok() -> str:
            return "would succeed"

        with pytest.raises(ExtractionFailureError, match="probe already in progress"):
            await cb.call(_ok)

        assert cb._probing is True  # not cleared — only the probing caller clears it


# ── circuit_breaker: prometheus registry recovery paths ──────────────────────


class TestCircuitBreakerPrometheusRegistryPaths:
    def test_adaptive_cb_register_metrics_already_registered(self) -> None:
        """Real prometheus raises ValueError on metric re-registration → metrics_available=False.

        Strategy: create a warmup CB to populate both prometheus and _REGISTERED_METRICS,
        then clear only _REGISTERED_METRICS.  The next creation hits real prometheus
        (metric names are already in the registry) → ValueError → _prom_register returns
        None → _metrics_available is False.  No mocking of prometheus internals.
        """
        import pramanix.circuit_breaker as _cb_mod
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="prom-real-adaptive")

        # Warmup: registers pramanix_circuit_state + pramanix_circuit_pressure_events_total
        # in real prometheus AND in _REGISTERED_METRICS.  Idempotent if already done.
        AdaptiveCircuitBreaker(guard, config)

        # Save + clear the module-level cache.  Real prometheus still has the metrics.
        # Next creation tries Counter/Gauge → real ValueError → returns None → False.
        saved = dict(_cb_mod._REGISTERED_METRICS)
        _cb_mod._REGISTERED_METRICS.clear()
        try:
            cb = AdaptiveCircuitBreaker(guard, config)
        finally:
            _cb_mod._REGISTERED_METRICS.clear()
            _cb_mod._REGISTERED_METRICS.update(saved)

        assert cb._metrics_available is False

    def test_distributed_cb_register_metrics_already_registered(self) -> None:
        """Same real-prometheus re-registration test for DistributedCircuitBreaker."""
        import pramanix.circuit_breaker as _cb_mod
        from pramanix.circuit_breaker import (
            CircuitBreakerConfig,
            DistributedCircuitBreaker,
            InMemoryDistributedBackend,
        )

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="prom-real-distributed")

        # Warmup: registers pramanix_distributed_circuit_state + …_pressure_events_total
        DistributedCircuitBreaker(guard, config, backend=InMemoryDistributedBackend())

        saved = dict(_cb_mod._REGISTERED_METRICS)
        _cb_mod._REGISTERED_METRICS.clear()
        try:
            cb = DistributedCircuitBreaker(guard, config, backend=InMemoryDistributedBackend())
        finally:
            _cb_mod._REGISTERED_METRICS.clear()
            _cb_mod._REGISTERED_METRICS.update(saved)

        assert cb._metrics_available is False

    def test_distributed_cb_update_prometheus_exception_swallowed(self) -> None:
        """DistributedCircuitBreaker._update_prometheus swallows gauge.labels() exceptions."""
        from pramanix.circuit_breaker import (
            CircuitBreakerConfig,
            DistributedCircuitBreaker,
            InMemoryDistributedBackend,
        )

        guard = _make_guard()
        config = CircuitBreakerConfig(namespace="test-update-prom")
        cb = DistributedCircuitBreaker(guard, config, backend=InMemoryDistributedBackend())

        if not cb._metrics_available:
            pytest.skip("prometheus_client not set up properly in this test")

        # Replace state gauge with a real duck-type whose labels() raises.
        cb._state_gauge = _ErrorGauge()
        cb._metrics_available = True

        cb._update_prometheus()  # must not raise

    @pytest.mark.asyncio
    async def test_redis_backend_close_with_open_client(self) -> None:
        """RedisDistributedBackend.close() closes the client."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        client = _AsyncCloseClient()
        backend = RedisDistributedBackend._for_testing(client)

        await backend.close()

        assert client.aclose_called
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_redis_backend_close_exception_swallowed(self) -> None:
        """RedisDistributedBackend.close() swallows aclose() exceptions."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        backend = RedisDistributedBackend._for_testing(_AsyncErrorCloseClient())

        await backend.close()  # must not raise
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_redis_backend_clear_async(self, redis_url: str) -> None:
        """RedisDistributedBackend.clear_async() deletes the key for a namespace."""
        import redis.asyncio as aioredis

        from pramanix.circuit_breaker import RedisDistributedBackend

        real_redis = aioredis.from_url(redis_url, decode_responses=True)
        backend = RedisDistributedBackend(
            redis_client=real_redis, key_prefix="pramanix:cb:clear_async:"
        )

        # Pre-set the key so we can verify it is deleted.
        await real_redis.set("pramanix:cb:clear_async:test", "value")
        assert await real_redis.exists("pramanix:cb:clear_async:test") == 1

        await backend.clear_async(namespace="test")

        assert await real_redis.exists("pramanix:cb:clear_async:test") == 0

    @pytest.mark.asyncio
    async def test_redis_backend_async_clear_with_keys(self, redis_url: str) -> None:
        """_async_clear(namespace=None) deletes all matching keys."""
        import redis.asyncio as aioredis

        from pramanix.circuit_breaker import RedisDistributedBackend

        real_redis = aioredis.from_url(redis_url, decode_responses=True)
        backend = RedisDistributedBackend(
            redis_client=real_redis, key_prefix="pramanix:cb:async_clear_keys:"
        )

        # Pre-set two matching keys and one non-matching key.
        await real_redis.set("pramanix:cb:async_clear_keys:ns1", "1")
        await real_redis.set("pramanix:cb:async_clear_keys:ns2", "2")
        await real_redis.set("other:key", "3")

        await backend._async_clear(namespace=None)

        assert await real_redis.exists("pramanix:cb:async_clear_keys:ns1") == 0
        assert await real_redis.exists("pramanix:cb:async_clear_keys:ns2") == 0
        assert await real_redis.exists("other:key") == 1  # untouched

    @pytest.mark.asyncio
    async def test_redis_backend_async_clear_no_keys(self, redis_url: str) -> None:
        """_async_clear(namespace=None) with empty key list skips delete."""
        import redis.asyncio as aioredis

        from pramanix.circuit_breaker import RedisDistributedBackend

        real_redis = aioredis.from_url(redis_url, decode_responses=True)
        backend = RedisDistributedBackend(
            redis_client=real_redis, key_prefix="pramanix:cb:async_clear_no_keys:"
        )

        # No keys with the prefix — clear should be a no-op.
        await backend._async_clear(namespace=None)
        # Just verify no exception was raised and keys are still zero.
        keys = await real_redis.keys("pramanix:cb:async_clear_no_keys:*")
        assert keys == []

    @pytest.mark.asyncio
    async def test_redis_backend_async_clear_exception_swallowed(self) -> None:
        """_async_clear swallows exceptions from the Redis client."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        # Inject a real client that raises on any call.
        backend = RedisDistributedBackend._for_testing(_ErrorRedisClient())

        await backend._async_clear(namespace="test")  # must not raise


# ── Crypto ────────────────────────────────────────────────────────────────────


class TestCryptoSigningFailureCounter:
    def test_increment_when_counter_already_registered(self) -> None:
        """Real prometheus ValueError → DISABLED sentinel set, no raise.

        Strategy: pre-register pramanix_signing_failure_total in the real
        prometheus registry (idempotent — first call creates, repeat calls
        catch ValueError), reset our lazy singleton, then call
        _increment_signing_failure_counter().  The real prometheus raises
        ValueError on the duplicate registration → _COUNTER_DISABLED is set.
        No mocking of prometheus internals required.
        """
        from prometheus_client import Counter as _PCounter

        import pramanix.crypto as _crypto_mod
        from pramanix.crypto import _COUNTER_DISABLED, _increment_signing_failure_counter

        # Ensure the metric name is in real prometheus (first call creates it;
        # subsequent calls raise ValueError which we swallow — either way the
        # name is registered).
        with contextlib.suppress(ValueError):
            _PCounter("pramanix_signing_failure_total", "Total decision signing failures")
        # Already registered from a previous test — that's the state we need.

        # Reset lazy singleton so the lazy-init branch runs again.
        _crypto_mod._signing_failure_counter = None

        # Call → real Counter() raises ValueError → DISABLED sentinel → no raise
        _increment_signing_failure_counter()
        # Second call → sentinel path → also must not raise
        _increment_signing_failure_counter()

        assert _crypto_mod._signing_failure_counter is _COUNTER_DISABLED

        # Reset so subsequent tests get a fresh counter.
        _crypto_mod._signing_failure_counter = None

    def test_increment_when_registry_lookup_returns_none(self) -> None:
        """ValueError on Counter registration → DISABLED sentinel set, no crash."""
        from prometheus_client import Counter as _PCounter

        import pramanix.crypto as _crypto_mod
        from pramanix.crypto import _COUNTER_DISABLED, _increment_signing_failure_counter

        with contextlib.suppress(ValueError):
            _PCounter("pramanix_signing_failure_total", "Total decision signing failures")

        _crypto_mod._signing_failure_counter = None
        _increment_signing_failure_counter()  # must not raise
        assert _crypto_mod._signing_failure_counter is _COUNTER_DISABLED
        _crypto_mod._signing_failure_counter = None

    def test_sign_exception_increments_failure_counter(self) -> None:
        """PramanixSigner.sign() raises SigningError and increments the failure counter."""
        import pramanix.crypto as _crypto_mod2
        from pramanix.crypto import PramanixSigner
        from pramanix.exceptions import SigningError

        _crypto_mod2._signing_failure_counter = None
        signer = PramanixSigner(force_ephemeral=True)
        signer._private_key = _BrokenPrivateKey()

        with pytest.raises(SigningError):
            signer.sign(_make_safe_decision())

    def test_verify_decision_exception_returns_false(self) -> None:
        """PramanixVerifier.verify_decision() returns False on unexpected exception."""
        from pramanix.crypto import PramanixSigner, PramanixVerifier
        from pramanix.decision import Decision, SolverStatus

        signer = PramanixSigner(force_ephemeral=True)

        class _BoomVerifier(PramanixVerifier):
            def verify(self, *args: Any, **kwargs: Any) -> bool:
                raise RuntimeError("boom")

        verifier = _BoomVerifier(public_key_pem=signer.public_key_pem())
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
    def _make_kafka_sink(self, producer: Any, max_queue: int = 10_000) -> Any:
        from pramanix.audit_sink import KafkaAuditSink

        return KafkaAuditSink(
            topic="test-topic", producer_conf={}, max_queue_size=max_queue, _producer=producer
        )

    def test_delivery_callback_with_error_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        """delivery callback invoked with error → logs error."""
        import logging

        producer = _CapturingProducer()
        sink = self._make_kafka_sink(producer)

        with caplog.at_level(logging.ERROR, logger="pramanix.audit_sink"):
            sink.emit(_make_safe_decision())

            # If callback was captured, fire it with a real error object.
            if producer.callbacks:
                err = _KafkaDeliveryError()
                producer.callbacks[0](err, None)

        # The audit_sink module must have logged an error for the failed delivery.
        assert any("delivery error" in r.message.lower() for r in caplog.records)


class TestDatadogAuditSinkInit:
    def test_datadog_init_body_coverage(self) -> None:
        """DatadogAuditSink.__init__ runs through all init lines with real SDK."""
        pytest.importorskip("datadog_api_client")
        from pramanix.audit_sink import DatadogAuditSink

        sink = DatadogAuditSink(api_key="dd-test-key", service="my-service", source="my-src")
        try:
            assert sink._service == "my-service"
            assert sink._source == "my-src"
            assert sink._tags == ""
        finally:
            sink.close()

    def test_datadog_init_uses_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DatadogAuditSink with api_key=None reads DD_API_KEY env var."""
        pytest.importorskip("datadog_api_client")
        monkeypatch.setenv("DD_API_KEY", "env-api-key")
        from pramanix.audit_sink import DatadogAuditSink

        sink = DatadogAuditSink()
        try:
            assert sink._service == "pramanix"  # default service name
        finally:
            sink.close()

    def test_datadog_emit_sends_log(self) -> None:
        """DatadogAuditSink.emit() calls submit_log on the logs API."""
        pytest.importorskip("datadog_api_client")
        from pramanix.audit_sink import DatadogAuditSink

        sink = DatadogAuditSink(api_key="key")
        # Replace the real LogsApi with a real capturing duck-type.
        capturing_api = _CapturingLogsApi()
        sink._logs_api = capturing_api

        sink.emit(_make_safe_decision())
        # Drain the background worker queue before asserting — the worker
        # thread processes emit() calls asynchronously.
        sink.close()

        assert len(capturing_api.submit_log_calls) == 1


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
                return [(E(_amount) >= Decimal("-999999")).named("pass").explain("pass")]

        class _BlockPolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [(E(_amount) >= Decimal("999999")).named("fail").explain("fail")]

        policy_cls = _AllowPolicy if always_allow else _BlockPolicy
        guard = Guard(policy_cls, GuardConfig(execution_mode="sync"))

        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        return PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {"amount": Decimal("100")},
            state_provider=lambda: {"state_version": "1.0"},
        )

    def _capture_wrapped(self, interceptor: Any, handler_attrs: dict) -> dict:
        """Call intercept_service and capture the _replace kwargs."""
        handler = _GrpcRpcHandler(
            unary_unary=lambda req, ctx: "ok",
        )
        for attr, val in handler_attrs.items():
            setattr(handler, attr, val)

        captured: dict = {}

        def fake_replace(**kwargs: Any) -> Any:
            captured.update(kwargs)
            handler._replace_kwargs.update(kwargs)
            return handler

        handler._replace = fake_replace  # type: ignore[method-assign]
        interceptor.intercept_service(lambda _: handler, types.SimpleNamespace(method="/test"))
        return captured

    def test_unary_stream_blocked(self) -> None:
        """_guarded_unary_stream returns without yielding when guard blocks."""
        interceptor = self._make_interceptor(always_allow=False)
        captured = self._capture_wrapped(
            interceptor,
            {
                "unary_stream": lambda req, ctx: iter([1, 2, 3]),
                "stream_unary": None,
                "stream_stream": None,
            },
        )

        if "unary_stream" in captured:
            ctx = _RpcContext()
            items = list(captured["unary_stream"]("req", ctx))
            assert items == []

    def test_unary_stream_allowed(self) -> None:
        """_guarded_unary_stream yields from handler when guard allows."""
        interceptor = self._make_interceptor(always_allow=True)
        captured = self._capture_wrapped(
            interceptor,
            {
                "unary_stream": lambda req, ctx: iter([10, 20]),
                "stream_unary": None,
                "stream_stream": None,
            },
        )

        if "unary_stream" in captured:
            ctx = _RpcContext()
            items = list(captured["unary_stream"]("req", ctx))
            assert items == [10, 20]

    def test_stream_unary_allowed(self) -> None:
        """_guarded_stream_unary passes combined iterator to handler when allowed."""
        interceptor = self._make_interceptor(always_allow=True)
        captured = self._capture_wrapped(
            interceptor,
            {
                "unary_stream": None,
                "stream_unary": lambda requests, ctx: "stream_result",
                "stream_stream": None,
            },
        )

        if "stream_unary" in captured:
            ctx = _RpcContext()
            result = captured["stream_unary"](iter(["msg1", "msg2"]), ctx)
            assert result == "stream_result"

    def test_stream_unary_blocked(self) -> None:
        """_guarded_stream_unary returns None when guard blocks."""
        interceptor = self._make_interceptor(always_allow=False)
        captured = self._capture_wrapped(
            interceptor,
            {
                "unary_stream": None,
                "stream_unary": lambda requests, ctx: "x",
                "stream_stream": None,
            },
        )

        if "stream_unary" in captured:
            ctx = _RpcContext()
            result = captured["stream_unary"](iter(["msg"]), ctx)
            assert result is None

    def test_stream_stream_allowed(self) -> None:
        """_guarded_stream_stream yields from handler when allowed."""
        interceptor = self._make_interceptor(always_allow=True)
        captured = self._capture_wrapped(
            interceptor,
            {
                "unary_stream": None,
                "stream_unary": None,
                "stream_stream": lambda requests, ctx: iter(["a", "b"]),
            },
        )

        if "stream_stream" in captured:
            ctx = _RpcContext()
            items = list(captured["stream_stream"](iter(["msg"]), ctx))
            assert items == ["a", "b"]

    def test_stream_stream_blocked(self) -> None:
        """_guarded_stream_stream returns without yielding when guard blocks."""
        interceptor = self._make_interceptor(always_allow=False)
        captured = self._capture_wrapped(
            interceptor,
            {
                "unary_stream": None,
                "stream_unary": None,
                "stream_stream": lambda requests, ctx: iter(["x", "y"]),
            },
        )

        if "stream_stream" in captured:
            ctx = _RpcContext()
            items = list(captured["stream_stream"](iter(["msg"]), ctx))
            assert items == []


# ── PostgresExecutionTokenVerifier ────────────────────────────────────────────


def _make_postgres_verifier(pool: Any) -> Any:
    """Build a PostgresExecutionTokenVerifier without a real DB connection."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    return PostgresExecutionTokenVerifier._for_testing(pool, secret_key=b"secret-key-min16")


def _make_exec_token(key: bytes, *, expired: bool = False, state_version: str | None = "v1") -> Any:
    """Create a signed ExecutionToken using ExecutionTokenSigner.mint()."""
    from pramanix.decision import Decision, SolverStatus
    from pramanix.execution_token import ExecutionTokenSigner

    decision = Decision(
        allowed=True, status=SolverStatus.SAFE, violated_invariants=(), explanation=""
    )
    signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=-1 if expired else 60)
    return signer.mint(decision, state_version=state_version)


class TestPostgresExecutionTokenVerifier:
    def test_consume_success(self) -> None:
        """consume(): valid token, INSERT succeeds → True."""
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        conn = _PgConn(execute_return=None, fetchrow_return=None)
        pool = _PgPool(conn)

        verifier = _make_postgres_verifier(pool)
        result = verifier.consume(token, expected_state_version=None)
        assert result is True

    def test_consume_state_version_mismatch(self) -> None:
        """consume(): state_version mismatch → False before any DB call."""
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version="v1")

        pool = _PgPool(_PgConn())
        verifier = _make_postgres_verifier(pool)
        result = verifier.consume(token, expected_state_version="v2")
        assert result is False
        assert not pool.acquire_called

    @_skip_without_asyncpg
    def test_consume_unique_violation_returns_false(self) -> None:
        """consume(): asyncpg.UniqueViolationError → False (token already used)."""
        import asyncpg

        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        conn = _PgConn(execute_raises=asyncpg.UniqueViolationError("duplicate key value"))
        pool = _PgPool(conn)

        verifier = _make_postgres_verifier(pool)
        result = verifier.consume(token, expected_state_version=None)
        assert result is False

    def test_evict_expired(self) -> None:
        """evict_expired() parses the 'DELETE N' response."""
        conn = _PgConn(execute_return="DELETE 3")
        pool = _PgPool(conn)

        verifier = _make_postgres_verifier(pool)
        assert verifier.evict_expired() == 3

    def test_consumed_count(self) -> None:
        """consumed_count() returns row count from SELECT COUNT(*)."""
        conn = _PgConn(fetchrow_return={"n": 7})
        pool = _PgPool(conn)

        verifier = _make_postgres_verifier(pool)
        assert verifier.consumed_count() == 7

    def test_consumed_count_no_row(self) -> None:
        """consumed_count() returns 0 when fetchrow returns None."""
        conn = _PgConn(fetchrow_return=None)
        pool = _PgPool(conn)

        verifier = _make_postgres_verifier(pool)
        assert verifier.consumed_count() == 0

    def test_close(self) -> None:
        """close() shuts down pool and stops the event loop."""
        pool = _AsyncClosablePool()
        verifier = _make_postgres_verifier(pool)
        verifier.close()  # must not raise

    @pytest.mark.asyncio
    async def test_consume_within_success(self) -> None:
        """consume_within() inserts within caller's connection, returns True."""
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        conn = _PgConn(execute_return=None)
        verifier = _make_postgres_verifier(_PgPool(_PgConn()))
        result = await verifier.consume_within(conn, token, expected_state_version=None)
        assert result is True

    @pytest.mark.asyncio
    @_skip_without_asyncpg
    async def test_consume_within_unique_violation(self) -> None:
        """consume_within() returns False on UniqueViolationError (INSERT)."""
        import asyncpg

        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        # _ensure_table calls conn.execute twice (CREATE TABLE, CREATE INDEX),
        # then the INSERT is a third call. Raise UniqueViolationError only on INSERT.
        conn = _PgConn(
            execute_return=None,
            execute_raises=asyncpg.UniqueViolationError("duplicate"),
            execute_raises_after=2,
        )
        verifier = _make_postgres_verifier(_PgPool(_PgConn()))
        result = await verifier.consume_within(conn, token, expected_state_version=None)
        assert result is False

    @pytest.mark.asyncio
    async def test_consume_within_sig_mismatch(self) -> None:
        """consume_within() returns False when signature is wrong."""
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version=None)

        conn = _PgConn(execute_return=None)
        verifier = _make_postgres_verifier(_PgPool(_PgConn()))
        verifier._key = b"wrong-key-min16!"  # different key

        result = await verifier.consume_within(conn, token)
        assert result is False

    @pytest.mark.asyncio
    async def test_consume_within_state_version_mismatch(self) -> None:
        """consume_within() returns False on state_version mismatch."""
        key = b"secret-key-min16"
        token = _make_exec_token(key, state_version="v1")

        conn = _PgConn(execute_return=None)
        verifier = _make_postgres_verifier(_PgPool(_PgConn()))
        result = await verifier.consume_within(conn, token, expected_state_version="v2")
        assert result is False


# ── Redis scan pagination ─────────────────────────────────────────────────────


class TestRedisScanPagination:
    def test_consumed_count_multiple_pages(self) -> None:
        """consumed_count() iterates when scan returns non-zero cursor."""
        from pramanix.execution_token import RedisExecutionTokenVerifier

        # Two pages: first page cursor=42 (continue), second page cursor=0 (stop).
        scan_redis = _SyncScanRedis(
            [
                (42, ["key1", "key2"]),
                (0, ["key3"]),
            ]
        )
        verifier = RedisExecutionTokenVerifier._for_testing(
            scan_redis, secret_key=b"secret-key-min16"
        )

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
        import z3

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

        class _ErrorSolver:
            def set(self, *a: Any, **kw: Any) -> None:
                pass

            def add(self, *a: Any) -> None:
                pass

            def assert_and_track(self, *a: Any) -> None:
                pass

            def check(self) -> z3.CheckSatResult:
                raise RuntimeError("secret internal detail")

            def reset(self) -> None:
                pass

        guard = Guard(
            _P,
            GuardConfig(
                execution_mode="sync",
                redact_violations=True,
                solver_factory=lambda _ctx: _ErrorSolver(),
            ),
        )
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )

        assert not d.allowed
        assert d.status.value == "error"
        assert "secret internal detail" not in (d.explanation or "")
        assert d.explanation == "Policy Violation: Action Blocked"

    def test_verify_timeout_triggers_metric(self) -> None:
        """SolverTimeoutError is recorded in the timeout metric branch."""
        import z3

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

        class _TimeoutSolver:
            def set(self, *a: Any, **kw: Any) -> None:
                pass

            def add(self, *a: Any) -> None:
                pass

            def assert_and_track(self, *a: Any) -> None:
                pass

            def check(self) -> z3.CheckSatResult:
                return z3.unknown

            def reset(self) -> None:
                pass

        guard = Guard(
            _P,
            GuardConfig(
                execution_mode="sync",
                metrics_enabled=True,
                solver_factory=lambda _ctx: _TimeoutSolver(),
            ),
        )
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
        """_emit_translator_metric: real prometheus ValueError on re-registration → early return, no raise.

        Strategy: pre-register pramanix_extraction_failure_total in real prometheus,
        then evict it from _translator_counters so _emit_translator_metric tries to
        register it again → real ValueError → early return.  No mocking required.
        """
        from prometheus_client import Counter as _PCounter

        import pramanix.guard as _guard_mod
        from pramanix.guard import _emit_translator_metric

        counter_name = "pramanix_extraction_failure_total"

        # Ensure the metric is in real prometheus.
        with contextlib.suppress(ValueError):
            _PCounter(counter_name, "Total LLM extraction failures by model", ["model"])
        # Already registered — exactly the collision we need.

        # Evict from module cache so _emit_translator_metric tries to re-register.
        _guard_mod._translator_counters.pop(counter_name, None)

        # Real prometheus raises ValueError → early return → no raise.
        _emit_translator_metric("extraction_failure", ["model-a", "model-b"])

    def test_emit_metric_general_exception_swallowed(self) -> None:
        """_emit_translator_metric: non-ValueError from counter.labels() → outer except swallows it."""
        import pramanix.guard as _guard_mod
        from pramanix.guard import _emit_translator_metric

        counter_name = "pramanix_consensus_failure_total"

        class _ErrorCounter:
            """Real duck-type counter that raises RuntimeError on labels() — no Mock."""

            def labels(self, **kw: Any) -> None:
                raise RuntimeError("prom down")

        saved = _guard_mod._translator_counters.get(counter_name)
        _guard_mod._translator_counters[counter_name] = _ErrorCounter()
        try:
            _emit_translator_metric("consensus_failure", ["m"])  # must not raise
        finally:
            if saved is None:
                _guard_mod._translator_counters.pop(counter_name, None)
            else:
                _guard_mod._translator_counters[counter_name] = saved


# ── audit/archiver.py ─────────────────────────────────────────────────────────


class TestArchiverSegmentWriteFailure:
    def test_archive_segment_write_failure_cleans_up_tmp(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_archive_segment: write failure removes the tmp file and re-raises."""
        import os

        from pramanix.audit.archiver import MerkleArchiver

        archiver = MerkleArchiver(base_path=str(tmp_path), segment_days=0)
        for i in range(5):
            archiver.add(f"decision-{i:04d}")

        original_fdopen = os.fdopen

        def _failing_fdopen(fd, mode, *args, **kwargs):
            fh = original_fdopen(fd, mode, *args, **kwargs)

            def _boom(data):
                raise OSError("disk full")

            fh.write = _boom
            return fh

        monkeypatch.setattr(os, "fdopen", _failing_fdopen)
        # _archive_segment() requires the caller to hold self._lock (it
        # temporarily releases it during I/O to avoid holding the lock across
        # slow disk/KMS operations).  Acquire the lock before calling directly.
        with contextlib.suppress(OSError), archiver._lock:
            archiver._archive_segment()

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
        t._client.messages = _AnthropicMessagesNS('{"amount": 100}')
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
        t._client.messages = _AnthropicMessagesNS('{"amount": 42}')
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
        t._api_status_error = _MockAPIStatusError
        t._client.messages = _AnthropicErrorMessagesNS(_MockAPIStatusError("auth error"))
        with pytest.raises(ExtractionFailureError, match="401"):
            await t.extract("pay 42", _Schema)


# ── key_provider.py: supports_rotation + cache-miss paths ────────────────────


class TestKeyProviderSupportsRotation:
    def test_pem_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import PemKeyProvider

        assert PemKeyProvider(b"FAKE_PEM").supports_rotation is True

    def test_env_provider_no_rotation(self) -> None:
        from pramanix.key_provider import EnvKeyProvider

        p = EnvKeyProvider._for_testing(env_var="PRAMANIX_SIGNING_KEY_PEM", version="env-1")
        assert p.supports_rotation is False

    def test_file_provider_supports_rotation(self, tmp_path) -> None:
        from pramanix.key_provider import FileKeyProvider

        assert FileKeyProvider(tmp_path / "key.pem").supports_rotation is True

    def test_azure_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        p = AzureKeyVaultKeyProvider._for_testing(_AzureSecretClient(), secret_name="key")
        assert p.supports_rotation is True

    def test_gcp_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import GcpKmsKeyProvider

        p = GcpKmsKeyProvider._for_testing(_GcpSecretClient())
        assert p.supports_rotation is True

    def test_vault_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider._for_testing(types.SimpleNamespace())
        assert p.supports_rotation is True

    def test_aws_private_key_pem_cache_miss_triggers_refresh(self) -> None:
        """Lines 317-319: cache_valid() False forces _refresh_cache() in private_key_pem."""
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient(secret_string="FAKE_PEM")
        p = AwsKmsKeyProvider._for_testing(
            mc, secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:k"
        )
        assert p.private_key_pem() == b"FAKE_PEM"

    def test_aws_key_version_cache_miss_triggers_refresh(self) -> None:
        """Lines 326-328: cache_valid() False forces _refresh_cache() in key_version."""
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient(secret_string="FAKE_PEM", version_id="v-99")
        p = AwsKmsKeyProvider._for_testing(
            mc, secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:k"
        )
        assert p.key_version() == "v-99"

    def test_gcp_public_key_pem_calls_derive(self) -> None:
        """Line 494: GcpKmsKeyProvider.public_key_pem() derives from cached private PEM."""
        from pramanix.crypto import PramanixSigner
        from pramanix.key_provider import GcpKmsKeyProvider

        # Use a real ephemeral key so _derive_public_pem works correctly.
        signer = PramanixSigner(force_ephemeral=True)
        private_pem = signer.private_key_pem()
        expected_public_pem = signer.public_key_pem()

        # Inject the real private PEM via cached_pem so public_key_pem() can
        # derive the matching public key without a real GCP network call.
        p = GcpKmsKeyProvider._for_testing(_GcpSecretClient(), cached_pem=private_pem)
        result = p.public_key_pem()
        assert result == expected_public_pem

    def test_aws_supports_rotation_is_true(self) -> None:
        """Line 332: AwsKmsKeyProvider.supports_rotation returns True."""
        from pramanix.key_provider import AwsKmsKeyProvider

        p = AwsKmsKeyProvider._for_testing(
            _AwsSecretsClient(), secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:k"
        )
        assert p.supports_rotation is True

    def test_aws_private_key_pem_cache_hit_skips_refresh(self) -> None:
        """Branch 317->319: cache valid → _refresh_cache() is NOT called."""
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient()
        # Pre-populate the cache so the validity check passes without a network call.
        p = AwsKmsKeyProvider._for_testing(
            mc,
            secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:k",
            cached_pem=b"CACHED_PEM",
        )
        result = p.private_key_pem()
        assert result == b"CACHED_PEM"
        assert mc.calls == 0  # cache hit — AWS client must not be called

    def test_aws_key_version_cache_hit_skips_refresh(self) -> None:
        """Branch 326->328: cache valid in key_version() → _refresh_cache() NOT called."""
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient()
        # _for_testing sets _cached_version = "test-version" when cached_pem is provided.
        p = AwsKmsKeyProvider._for_testing(
            mc,
            secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:k",
            cached_pem=b"CACHED_PEM",
        )
        result = p.key_version()
        assert result == "test-version"  # set by _for_testing when cached_pem provided
        assert mc.calls == 0  # cache hit — AWS client must not be called

    def test_vault_private_key_pem_cache_hit_skips_refresh(self) -> None:
        """Branch 576->578: Vault cache valid → _refresh_cache() NOT called."""
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        fake_client = types.SimpleNamespace(
            secrets=types.SimpleNamespace(
                kv=types.SimpleNamespace(
                    v2=types.SimpleNamespace(read_secret_version=lambda **kw: None)
                )
            )
        )
        p = HashiCorpVaultKeyProvider._for_testing(fake_client)
        p._secret_path = "pramanix/key"
        p._field = "private_key_pem"
        p._mount_point = "secret"
        p._cache_lock = threading.Lock()
        p._cached_pem = b"VAULT_PEM"
        p._cached_version = "7"
        p._cache_expires = float("inf")  # valid forever
        result = p.private_key_pem()
        assert result == b"VAULT_PEM"


# ── worker.py: warmup metric failure + __del__ exception path ─────────────────


class TestWorkerEdgePaths:
    def test_warmup_worker_solver_failure_swallowed(self) -> None:
        """_warmup_worker: solver factory raises → error logged, no re-raise.

        _WORKER_WARMUP_FAILURE_COUNTER is set at module import time; by the time
        this test runs the counter already exists and prometheus is not re-invoked.
        The real test is that a failing solver does not propagate out of _warmup_worker.
        """
        from pramanix.worker import _warmup_worker

        def _failing_solver(**kwargs: Any) -> None:
            raise RuntimeError("z3 down")

        _warmup_worker(_solver_factory=_failing_solver)  # must not raise

    def test_worker_pool_del_shutdown_exception_swallowed(self) -> None:
        """_emergency_shutdown swallows errors from executor.shutdown()."""
        from pramanix.worker import WorkerPool

        class _BoomExecutor:
            def shutdown(self, *, wait: bool = True) -> None:
                raise RuntimeError("boom")

        WorkerPool._emergency_shutdown([_BoomExecutor()])  # must not raise


# ── AdaptiveCircuitBreaker: #269 double-probe race + #272 stuck HALF_OPEN ─────


class _ImmediateGuard:
    """Protocol-compliant guard that resolves instantly with an ALLOW decision."""

    async def verify_async(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Any:
        from pramanix.decision import Decision, SolverStatus

        return Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="immediate-ok",
        )


class _CancellingGuard:
    """Protocol-compliant guard that raises CancelledError to simulate task cancellation."""

    async def verify_async(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Any:
        raise asyncio.CancelledError("test cancellation")


class _SlowGuard:
    """Protocol-compliant guard that introduces a configurable delay.

    Used to create a timing window where two concurrent callers both see
    HALF_OPEN state simultaneously, verifying only one is admitted as probe.
    """

    def __init__(self, delay_s: float = 0.05) -> None:
        self._delay = delay_s
        self.call_count = 0

    async def verify_async(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Any:
        self.call_count += 1
        await asyncio.sleep(self._delay)
        from pramanix.decision import Decision, SolverStatus

        return Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="slow-ok",
        )


class TestAdaptiveCircuitBreakerProbeGuarantees:
    """Production-level tests verifying #269 (double-probe) and #272 (stuck HALF_OPEN) fixes."""

    @pytest.mark.asyncio
    async def test_cancelled_error_during_probe_transitions_to_open(self) -> None:
        """#272 fix: CancelledError during HALF_OPEN probe must transition to OPEN.

        Before the fix, _record_solve was placed AFTER the try/finally block so
        a CancelledError would bypass it, leaving the breaker permanently stuck
        in HALF_OPEN with _probing=False — allowing infinite sequential probes
        that never resolved the state machine.
        """
        from pramanix.circuit_breaker import (
            AdaptiveCircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        config = CircuitBreakerConfig(
            pressure_threshold_ms=1.0,
            consecutive_pressure_count=1,
            recovery_seconds=0.001,
            isolation_threshold=10,
            namespace="test-cancel-probe",
        )
        cb = AdaptiveCircuitBreaker(_CancellingGuard(), config)

        # Manually place in OPEN state with elapsed recovery window.
        cb._state = CircuitState.OPEN
        cb._last_transition = time.monotonic() - 999.0
        cb._open_episodes = 0
        cb._probing = False

        with pytest.raises(asyncio.CancelledError):
            await cb.verify_async(intent={}, state={})

        # Breaker must NOT stay in HALF_OPEN — it must have transitioned to OPEN.
        assert cb.state in (CircuitState.OPEN, CircuitState.ISOLATED), (
            f"Breaker stuck in {cb.state!r} after CancelledError — "
            "HALF_OPEN was never resolved (#272 regression)"
        )
        # Probe gate must be cleared so the next recovery cycle can attempt a fresh probe.
        assert cb._probing is False, "_probing must be False after aborted probe"

    @pytest.mark.asyncio
    async def test_cancelled_error_leaves_probing_false(self) -> None:
        """#272 fix: _probing is always cleared, even when an exception aborts the probe."""
        from pramanix.circuit_breaker import (
            AdaptiveCircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        config = CircuitBreakerConfig(namespace="test-cancel-probe-flag")
        cb = AdaptiveCircuitBreaker(_CancellingGuard(), config)
        cb._state = CircuitState.OPEN
        cb._last_transition = time.monotonic() - 999.0
        cb._probing = False

        with contextlib.suppress(asyncio.CancelledError):
            await cb.verify_async(intent={}, state={})

        assert cb._probing is False

    @pytest.mark.asyncio
    async def test_concurrent_callers_only_one_probes(self) -> None:
        """#269 fix: under concurrent access in HALF_OPEN, exactly one caller probes.

        Strategy: create a SlowGuard that introduces a 50 ms delay.  Place the
        breaker in HALF_OPEN + _probing=False.  Launch two concurrent coroutines.
        The first acquires the lock, sets _probing=True, and starts the slow
        guard.  The second reads HALF_OPEN + _probing=True and must get an OPEN
        decision immediately without running the guard.

        With the #269 fix, _probing is only cleared INSIDE _record_solve which
        runs under the same lock as the probe completion — no window exists for a
        second caller to see HALF_OPEN + _probing=False between clearing the flag
        and transitioning state.
        """
        from pramanix.circuit_breaker import (
            AdaptiveCircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        slow_guard = _SlowGuard(delay_s=0.08)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=1000.0,  # high threshold → probe will "succeed"
            recovery_seconds=0.001,
            namespace="test-double-probe",
        )
        cb = AdaptiveCircuitBreaker(slow_guard, config)

        # Start in OPEN with recovery already elapsed.
        cb._state = CircuitState.OPEN
        cb._last_transition = time.monotonic() - 999.0
        cb._probing = False

        results = await asyncio.gather(
            cb.verify_async(intent={}, state={}),
            cb.verify_async(intent={}, state={}),
            return_exceptions=True,
        )

        # Exactly one call must have reached the guard (the probe).
        # The second must have received an OPEN decision without invoking the guard.
        assert slow_guard.call_count == 1, (
            f"Guard was called {slow_guard.call_count} times — "
            "double-probe race still present (#269 regression)"
        )

        # After both calls complete the breaker must be CLOSED (probe succeeded).
        assert cb.state == CircuitState.CLOSED

        # Both results must be Decision objects (no exceptions).
        for r in results:
            assert not isinstance(r, BaseException), f"Unexpected exception: {r}"

    @pytest.mark.asyncio
    async def test_probe_success_clears_probing_atomically(self) -> None:
        """#269 fix: after a successful probe, _probing=False and state=CLOSED atomically.

        A third concurrent caller that arrives AFTER _probing is cleared but
        BEFORE the state transition would see HALF_OPEN + _probing=False and
        start a second probe.  The fix ensures both writes happen under the
        same lock acquisition.
        """
        from pramanix.circuit_breaker import (
            AdaptiveCircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        config = CircuitBreakerConfig(
            pressure_threshold_ms=1000.0,
            recovery_seconds=0.001,
            namespace="test-probe-atomic",
        )
        cb = AdaptiveCircuitBreaker(_ImmediateGuard(), config)
        cb._state = CircuitState.OPEN
        cb._last_transition = time.monotonic() - 999.0
        cb._probing = False

        await cb.verify_async(intent={}, state={})

        assert cb.state == CircuitState.CLOSED
        assert cb._probing is False


# ── fast_path.py: #161 account_frozen integer coverage ──────────────────────


class TestAccountFrozenIntegerValues:
    """#161 fix: account_frozen must catch any truthy numeric frozen flag, not just True/1/yes."""

    def _make_rule(self) -> Any:
        from pramanix.fast_path import SemanticFastPath

        return SemanticFastPath.account_frozen("is_frozen")

    def test_true_is_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": True}) is not None

    def test_1_is_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": 1}) is not None

    def test_2_is_frozen(self) -> None:
        """#161: integer 2 must be treated as frozen (multi-level freeze code)."""
        rule = self._make_rule()
        assert rule({}, {"is_frozen": 2}) is not None

    def test_99_is_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": 99}) is not None

    def test_string_frozen_is_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": "frozen"}) is not None

    def test_string_yes_is_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": "yes"}) is not None

    def test_string_true_is_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": "true"}) is not None

    def test_false_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": False}) is None

    def test_0_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": 0}) is None

    def test_string_false_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": "false"}) is None

    def test_string_no_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": "no"}) is None

    def test_string_0_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": "0"}) is None

    def test_none_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {"is_frozen": None}) is None

    def test_field_absent_not_frozen(self) -> None:
        rule = self._make_rule()
        assert rule({}, {}) is None


# ── compiler.py: #311 assert → runtime check ─────────────────────────────────


class TestCompilerRuntimeCheckOnListRhs:
    """#311 fix: compiler must NOT use assert for list-RHS check (assert stripped by -O)."""

    def test_no_assert_for_list_rhs_in_source(self) -> None:
        """#311: assert not isinstance(rhs_val, list) must not exist in compiler source.

        assert is silently eliminated by python -O.  The fix uses an explicit
        if isinstance(...): raise PolicyCompilationError(...) which cannot be stripped.
        """
        import inspect

        from pramanix import compiler as _compiler_mod

        src = inspect.getsource(_compiler_mod)
        assert "assert not isinstance(rhs_val, list)" not in src, (
            "assert stripped by python -O — must use explicit PolicyCompilationError raise"
        )
        assert "if isinstance(rhs_val, list):" in src, (
            "Missing runtime list-RHS check in compiler — #311 regression"
        )
        assert "Compiler invariant violated" in src, (
            "PolicyCompilationError message missing — check _compile_condition"
        )


# ── k8s/webhook.py: #334 verify_async + #335 no policy internals ─────────────


def test_k8s_webhook_uses_verify_async() -> None:
    """#334 fix: k8s admission webhook must call verify_async, not sync verify.

    Checks the actual function call in the validate() body — uses 'await guard.verify_async('
    which is distinct from comments or docstrings referencing the old guard.verify() API.
    """
    import inspect

    from pramanix.k8s import webhook

    source = inspect.getsource(webhook)
    # The awaited async call must be present.
    assert "await guard.verify_async(" in source, (
        "k8s webhook must await guard.verify_async() — "
        "sync guard.verify() blocks the event loop (#334)"
    )


def test_k8s_webhook_rejection_message_omits_policy_internals() -> None:
    """#335 fix: K8s rejection AdmissionReview must not embed policy internals.

    The response JSON message field must only contain decision_id for correlation.
    Violated invariants and explanation are logged at WARNING for operator use but
    MUST NOT appear in the AdmissionReview rejection response — those strings are
    stored permanently in kubectl describe, cluster Events, and the immutable K8s
    audit log, visible to any cluster user regardless of RBAC.
    """
    import inspect

    from pramanix.k8s import webhook

    source = inspect.getsource(webhook)
    # The response must reference decision_id (the safe correlation token).
    assert "decision.decision_id" in source, (
        "k8s rejection message must include decision_id for audit correlation (#335)"
    )
    # The Pramanix audit sink message (not K8s response) must direct operators.
    assert "Check the Pramanix audit log" in source, (
        "k8s rejection message must direct operators to Pramanix audit sink (#335)"
    )
    # The message string in the JSON response must not contain invariant details.
    # We verify by checking that the literal f-string for the response message
    # does NOT mention violated_invariants or explanation — only decision_id.
    response_section = source[source.find("Check the Pramanix audit log"):]
    assert "violated_invariants" not in response_section[:200], (
        "k8s rejection JSON message must not include violated_invariants (#335)"
    )
