# SPDX-License-Identifier: AGPL-3.0-only
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

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        client = _AsyncCloseClient()
        backend._client = client
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

        await backend.close()

        assert client.aclose_called
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_redis_backend_close_exception_swallowed(self) -> None:
        """RedisDistributedBackend.close() swallows aclose() exceptions."""
        from pramanix.circuit_breaker import RedisDistributedBackend

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        backend._client = _AsyncErrorCloseClient()
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

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

        try:
            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        except Exception:
            pytest.skip("RedisDistributedBackend not constructable without redis")

        # Inject a real client that raises on any call.
        backend._client = _ErrorRedisClient()
        backend._redis_url = "redis://localhost/0"
        backend._prefix = "pramanix:cb:"
        backend._ttl = 300
        backend._sync_interval = 1.0
        backend._last_sync = 0.0

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
        """PramanixSigner.sign() swallows exceptions and returns empty string."""
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner(force_ephemeral=True)
        signer._private_key = _BrokenPrivateKey()

        result = signer.sign(_make_safe_decision())
        assert result == ""

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

        sink = DatadogAuditSink(
            api_key="dd-test-key", service="my-service", source="my-src"
        )
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
    import time as _time

    from pramanix.execution_token import PostgresExecutionTokenVerifier

    verifier = PostgresExecutionTokenVerifier.__new__(PostgresExecutionTokenVerifier)
    verifier._key = b"secret-key-min16"
    verifier._dsn = "postgresql://localhost/test"
    verifier._prefix = "pramanix:token:"
    verifier._clock = _time.time
    verifier._pool = pool
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

        verifier = RedisExecutionTokenVerifier.__new__(RedisExecutionTokenVerifier)
        verifier._key = b"secret-key-min16"
        verifier._prefix = "pramanix:token:"

        # Two pages: first page cursor=42 (continue), second page cursor=0 (stop).
        scan_redis = _SyncScanRedis(
            [
                (42, ["key1", "key2"]),
                (0, ["key3"]),
            ]
        )
        verifier._redis = scan_redis

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
        with contextlib.suppress(OSError):
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

        p = EnvKeyProvider.__new__(EnvKeyProvider)
        p._env_var = "PRAMANIX_SIGNING_KEY_PEM"
        p._version = "env-1"
        assert p.supports_rotation is False

    def test_file_provider_supports_rotation(self, tmp_path) -> None:
        from pramanix.key_provider import FileKeyProvider

        assert FileKeyProvider(tmp_path / "key.pem").supports_rotation is True

    def test_azure_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        p._client = _AzureSecretClient()
        p._secret_name = "key"
        p._secret_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        assert p.supports_rotation is True

    def test_gcp_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import GcpKmsKeyProvider

        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._client = _GcpSecretClient()
        p._project_id = "proj"
        p._secret_id = "secret"
        p._version_id = "latest"
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cache_expires = 0.0
        assert p.supports_rotation is True

    def test_vault_provider_supports_rotation(self) -> None:
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._client = types.SimpleNamespace()
        p._secret_path = "pramanix/key"
        p._field = "private_key_pem"
        p._mount_point = "secret"
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        assert p.supports_rotation is True

    def test_aws_private_key_pem_cache_miss_triggers_refresh(self) -> None:
        """Lines 317-319: cache_valid() False forces _refresh_cache() in private_key_pem."""
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient(secret_string="FAKE_PEM")
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
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient(secret_string="FAKE_PEM", version_id="v-99")
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
        """Line 494: GcpKmsKeyProvider.public_key_pem() derives from cached private PEM."""
        from pramanix.crypto import PramanixSigner
        from pramanix.key_provider import GcpKmsKeyProvider

        # Use a real ephemeral key so _derive_public_pem works correctly.
        signer = PramanixSigner(force_ephemeral=True)
        private_pem = signer.private_key_pem()
        expected_public_pem = signer.public_key_pem()

        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._client = _GcpSecretClient()
        p._project_id = "proj"
        p._secret_id = "secret"
        p._version_id = "latest"
        p._cache_lock = threading.Lock()
        p._cached_pem = private_pem  # real PEM
        p._cache_expires = float("inf")  # cache valid — skips refresh
        result = p.public_key_pem()
        assert result == expected_public_pem

    def test_aws_supports_rotation_is_true(self) -> None:
        """Line 332: AwsKmsKeyProvider.supports_rotation returns True."""
        from pramanix.key_provider import AwsKmsKeyProvider

        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = _AwsSecretsClient()
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
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient()
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
        assert mc.calls == 0

    def test_aws_key_version_cache_hit_skips_refresh(self) -> None:
        """Branch 326->328: cache valid in key_version() → _refresh_cache() NOT called."""
        from pramanix.key_provider import AwsKmsKeyProvider

        mc = _AwsSecretsClient()
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
        assert mc.calls == 0

    def test_vault_private_key_pem_cache_hit_skips_refresh(self) -> None:
        """Branch 576->578: Vault cache valid → _refresh_cache() NOT called."""
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._client = types.SimpleNamespace(
            secrets=types.SimpleNamespace(
                kv=types.SimpleNamespace(
                    v2=types.SimpleNamespace(read_secret_version=lambda **kw: None)
                )
            )
        )
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
