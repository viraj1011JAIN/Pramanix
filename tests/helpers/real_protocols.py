# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Protocol-compliant structural helpers for testing — no unittest.mock.

These helpers implement real protocols via duck typing or inheritance.
They are NOT mocks in the unittest.mock sense — they have real method
bodies and real state, but are purpose-built for the test surface they
exercise.  Where a class emulates a failure mode (e.g. always raising),
that is a deliberate design choice, not mock simulation.

Design rules
------------
1. Every class implements the real protocol (duck-typed or via inheritance).
2. State is tracked through real attribute mutation, not call recorders.
3. No MagicMock, AsyncMock, or patch() imported or used in this file.
4. All async methods are real coroutines, not mocked awaitables.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any


# ── HTTP client close helpers (translator lifecycle) ──────────────────────────


class _SyncCloseClient:
    """Minimal HTTP-client-like object with sync ``close()`` only (no aclose).

    Replaces ``MagicMock()`` in ``CohereTranslator.aclose()`` path-coverage
    tests that exercise the ``getattr(..., "close", None)`` fallback.
    """

    def __init__(self) -> None:
        self.close_called: bool = False

    def close(self) -> None:
        self.close_called = True


class _AsyncCloseClient:
    """Minimal HTTP-client-like object with ``async aclose()``.

    Replaces ``AsyncMock()`` in lifecycle tests that verify ``aclose()`` is
    awaited when the underlying client supports it.
    """

    def __init__(self) -> None:
        self.aclose_called: bool = False

    async def aclose(self) -> None:
        self.aclose_called = True


class _BothCloseClient(_AsyncCloseClient):
    """Client with both ``aclose()`` and ``close()`` — ``aclose`` wins."""

    def __init__(self) -> None:
        super().__init__()
        self.sync_close_called: bool = False

    def close(self) -> None:
        self.sync_close_called = True


class _ErrorCloseClient:
    """HTTP-client duck-type whose ``close()`` always raises.

    Used to test error-swallowing paths in audit sinks and translators.
    Not a mock — it is a real class whose ``close`` has a real body that raises.
    """

    def close(self) -> None:
        raise Exception("close failed")


# ── Guard-like helpers for interceptor tests ─────────────────────────────────


class _RaisingGuard:
    """Guard-protocol object whose ``verify()`` always raises ``RuntimeError``.

    Used to test interceptor defense-in-depth: the ``PramanixGrpcInterceptor``
    and ``PramanixKafkaConsumer`` must abort/dead-letter an RPC/message even
    if ``guard.verify()`` somehow raises (which the real ``Guard`` never does
    per its contract — this tests the interceptor's catch-all handler).

    This is NOT a mock.  It is a real class whose ``verify`` has a real body
    that raises a real ``RuntimeError``.
    """

    def verify(self, intent: dict[str, Any], state: dict[str, Any]) -> Any:
        raise RuntimeError("z3 crash — deliberate test raise")

    def verify_async(self, intent: dict[str, Any], state: dict[str, Any]) -> Any:
        raise RuntimeError("z3 crash — deliberate test raise")


def make_allow_guard():
    """Return a real ``Guard`` whose policy always produces an ALLOW decision.

    Policy: ``amount >= 0``.  Callers must pass ``intent={"amount": Decimal("1")}``
    (any non-negative value) and ``state={}``.
    """
    from pramanix import E, Field, Guard, GuardConfig, Policy

    _amt = Field("amount", Decimal, "Real")

    class _AllowPolicy(Policy):
        class Meta:
            version = "1.0"

        @classmethod
        def fields(cls) -> dict:
            return {"amount": _amt}

        @classmethod
        def invariants(cls):
            return [
                (E(_amt) >= Decimal("0")).named("non_negative").explain(
                    "Amount must be non-negative"
                )
            ]

    return Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))


def make_block_guard():
    """Return a real ``Guard`` whose policy always produces a BLOCK decision.

    Policy: ``amount > 9999`` — impossible for the default test intent
    ``{"amount": Decimal("1")}``.
    """
    from pramanix import E, Field, Guard, GuardConfig, Policy

    _amt = Field("amount", Decimal, "Real")

    class _BlockPolicy(Policy):
        class Meta:
            version = "1.0"

        @classmethod
        def fields(cls) -> dict:
            return {"amount": _amt}

        @classmethod
        def invariants(cls):
            return [
                (E(_amt) > Decimal("9999")).named("above_threshold").explain(
                    "Amount must exceed 9999 — always blocked for test inputs"
                )
            ]

    return Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))


#: Default intent/state pair for allow-guard tests — satisfies ``amount >= 0``.
ALLOW_INTENT: dict[str, Any] = {"amount": Decimal("1")}
ALLOW_STATE: dict[str, Any] = {}

#: Default intent/state pair for block-guard tests — violates ``amount > 9999``.
BLOCK_INTENT: dict[str, Any] = {"amount": Decimal("1")}
BLOCK_STATE: dict[str, Any] = {}


# ── Kafka protocol helpers ────────────────────────────────────────────────────


class _KafkaMessage:
    """Real ``confluent_kafka.Message``-protocol implementation.

    ``confluent_kafka.Message`` is a C-extension class that cannot be
    instantiated directly in tests.  This class implements every method
    the Pramanix Kafka interceptor calls, with real data stored as instance
    attributes.

    Not a mock: every method has a real body that returns a real value.
    """

    def __init__(
        self,
        payload: bytes,
        *,
        error: Any = None,
        key: bytes | None = None,
        topic: str = "test-topic",
        partition: int = 0,
        offset: int = 0,
    ) -> None:
        self._payload = payload
        self._error = error
        self._key = key
        self._topic = topic
        self._partition = partition
        self._offset = offset

    def value(self) -> bytes:
        return self._payload

    def error(self) -> Any:
        return self._error

    def key(self) -> bytes | None:
        return self._key

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset


class _KafkaDLQProducer:
    """Real DLQ producer that records produced messages — no broker needed.

    Replaces ``confluent_kafka.Producer`` MagicMock in interceptor tests.
    Supports optional ``produce_raises`` to test error-swallowing paths.
    Accepts the full confluent-kafka produce() signature including ``headers=``
    and ``value=`` as keyword argument.
    """

    def __init__(self, *, produce_raises: Exception | None = None) -> None:
        self.produced: list[tuple[str, bytes]] = []
        self.produce_raises: Exception | None = produce_raises
        self.flush_called: bool = False

    def produce(
        self,
        topic: str,
        value: bytes | None = None,
        *,
        headers: Any = None,
        callback: Any = None,
    ) -> None:
        if self.produce_raises is not None:
            raise self.produce_raises
        if value is None:
            value = b""
        self.produced.append((topic, value))
        if callback is not None:
            callback(None, _KafkaMessage(value, topic=topic))

    def flush(self, timeout: float = -1.0) -> None:
        self.flush_called = True


class _KafkaConsumer:
    """Real consumer backed by an in-memory message list — no broker needed.

    Replaces ``confluent_kafka.Consumer`` MagicMock in interceptor tests.
    ``poll()`` returns messages from the list in order, then returns ``None``.
    Accepts the full ``commit(message=..., asynchronous=...)`` signature.
    """

    def __init__(self, messages: list[_KafkaMessage] | None = None) -> None:
        self._messages: list[_KafkaMessage] = list(messages or [])
        self._pos: int = 0
        self.committed: list[Any] = []
        self.closed: bool = False
        self.commit_raises: Exception | None = None
        self.close_raises: Exception | None = None

    def poll(self, timeout: float = 1.0) -> _KafkaMessage | None:
        if self._pos >= len(self._messages):
            return None
        msg = self._messages[self._pos]
        self._pos += 1
        return msg

    def subscribe(self, topics: Any) -> None:
        pass

    def commit(self, message: Any = None, asynchronous: bool = True) -> None:
        if self.commit_raises is not None:
            raise self.commit_raises
        self.committed.append(message)

    def close(self) -> None:
        if self.close_raises is not None:
            raise self.close_raises
        self.closed = True


# ── gRPC protocol helpers ─────────────────────────────────────────────────────


class _GrpcRpcHandler:
    """Real gRPC ``RpcMethodHandler`` duck-type.

    ``grpc.RpcMethodHandler`` is a namedtuple; this class implements the same
    interface so that ``PramanixGrpcInterceptor._wrap_handler()``'s
    ``handler._replace(**kwargs)`` call works without requiring grpcio.

    Not a mock: every method and attribute has a real value.
    ``_replace()`` records the replacement kwargs so tests can assert on them.
    """

    def __init__(
        self,
        unary_unary: Any = None,
        unary_stream: Any = None,
        stream_unary: Any = None,
        stream_stream: Any = None,
    ) -> None:
        self.unary_unary = unary_unary
        self.unary_stream = unary_stream
        self.stream_unary = stream_unary
        self.stream_stream = stream_stream
        self._replace_kwargs: dict[str, Any] = {}
        self.replace_called: bool = False

    def _replace(self, **kwargs: Any) -> "_GrpcRpcHandler":
        """Real namedtuple._replace() analogue — updates attrs, records kwargs, returns self."""
        self._replace_kwargs.update(kwargs)
        self.replace_called = True
        for _k, _v in kwargs.items():
            setattr(self, _k, _v)
        return self


class _RpcContext:
    """Real gRPC ``ServicerContext`` duck-type.

    Records ``abort()`` calls so tests can assert without grpcio.
    Not a mock: ``abort()`` has a real body that mutates real instance state.
    """

    def __init__(self) -> None:
        self.aborted: bool = False
        self.abort_code: Any = None
        self.abort_message: str = ""

    def abort(self, code: Any, message: str) -> None:
        self.aborted = True
        self.abort_code = code
        self.abort_message = message


# ── Prometheus helpers ────────────────────────────────────────────────────────


class _ErrorCounter:
    """Prometheus counter duck-type whose ``inc()`` always raises.

    Tests that swallow Prometheus exceptions (e.g. ``_increment_overflow_metric``)
    use this to exercise the ``except Exception: pass`` paths without touching
    the real global registry.

    Not a mock — ``inc()`` has a real body that raises a real ``Exception``.
    """

    def inc(self) -> None:
        raise Exception("prom error")

    def labels(self, **kw: Any) -> "_ErrorCounter":
        return self


# ── Audit-sink producer helpers ───────────────────────────────────────────────


class _ErrorPollProducer:
    """Kafka-producer duck-type whose ``poll()`` always raises.

    Used to exercise the ``_background_poll()`` exception-swallowing path in
    ``KafkaAuditSink`` without a real Kafka broker.

    Not a mock — ``poll()`` has a real body that raises a real ``Exception``.
    """

    def poll(self, timeout: float = 0.0) -> None:
        raise Exception("kafka down")


class _ErrorFlushProducer:
    """Kafka-producer duck-type whose ``flush()`` always raises.

    Used to exercise the ``flush()`` exception-swallowing path in
    ``KafkaAuditSink`` without a real Kafka broker.

    Not a mock — ``flush()`` has a real body that raises a real ``Exception``.
    """

    def flush(self, timeout: float = -1.0) -> None:
        raise Exception("flush failed")


# ── AWS KMS helpers ───────────────────────────────────────────────────────────


class _RotateSecretRecorder:
    """Real AWS secretsmanager client that records ``rotate_secret()`` calls.

    Replaces ``boto3`` client ``MagicMock`` in ``AwsKmsKeyProvider.rotate_key()``
    tests.  Accepts the same keyword argument used by the production code:
    ``SecretId=``.
    """

    def __init__(self) -> None:
        self.rotate_secret_calls: list[str] = []

    def rotate_secret(self, *, SecretId: str) -> None:
        self.rotate_secret_calls.append(SecretId)


# ── Circuit-breaker helpers ───────────────────────────────────────────────────


class _AsyncBreaker:
    """Real circuit-breaker duck-type for ``_CBWrappedTranslator`` tests.

    ``call()`` accepts a callable and returns a fixed pre-configured value.
    It is a real ``async`` coroutine (not ``AsyncMock``), so it exercises the
    real ``await`` path in ``_CBWrappedTranslator.extract()``.
    """

    def __init__(self, return_value: Any = None) -> None:
        self._return_value = return_value
        self.call_count: int = 0

    async def call(self, fn: Any) -> Any:
        self.call_count += 1
        return self._return_value


# ── Mistral API client helpers ────────────────────────────────────────────────


class _MistralMessage:
    content: str = '{"amount": 5.0}'


class _MistralChoice:
    def __init__(self) -> None:
        self.message = _MistralMessage()


class _MistralApiResponse:
    """Real Mistral SDK response shape — ``choices[0].message.content``."""

    def __init__(self) -> None:
        self.choices = [_MistralChoice()]


class _MistralChatApi:
    """Real Mistral ``chat`` namespace with real ``async complete_async()``."""

    async def complete_async(self, **kw: Any) -> "_MistralApiResponse":
        return _MistralApiResponse()


class _MistralClientStub:
    """Real Mistral client duck-type for path tests that need ``t._client``.

    ``self.chat.complete_async(...)`` is a real coroutine that returns a
    ``_MistralApiResponse`` — no ``AsyncMock`` involved.
    """

    def __init__(self) -> None:
        self.chat = _MistralChatApi()


# ── Async context manager helper ─────────────────────────────────────────────


class _AsyncCtxManager:
    """Real async context manager wrapping a fixed value.

    Replaces the ``MagicMock()`` + ``AsyncMock(return_value=...)`` pattern
    used to fake ``pool.acquire()`` in PostgresExecutionTokenVerifier tests.
    """

    def __init__(self, value: Any) -> None:
        self._value = value

    async def __aenter__(self) -> Any:
        return self._value

    async def __aexit__(self, *_: Any) -> None:
        pass


# ── Postgres connection/pool helpers ─────────────────────────────────────────


class _PgConn:
    """Real asyncpg connection duck-type for PostgresExecutionTokenVerifier tests.

    Implements ``execute()`` and ``fetchrow()`` as real coroutines.
    Records all ``execute`` calls; optionally raises on the N-th call.
    """

    def __init__(
        self,
        *,
        execute_return: Any = None,
        fetchrow_return: Any = None,
        execute_raises: Exception | None = None,
        execute_raises_after: int = 0,
    ) -> None:
        self.execute_calls: list[Any] = []
        self._execute_return = execute_return
        self._fetchrow_return = fetchrow_return
        self._execute_raises = execute_raises
        self._execute_raises_after = execute_raises_after

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        self.execute_calls.append(args)
        if self._execute_raises is not None:
            if len(self.execute_calls) > self._execute_raises_after:
                raise self._execute_raises
        return self._execute_return

    async def fetchrow(self, *args: Any, **kwargs: Any) -> Any:
        return self._fetchrow_return


class _PgPool:
    """Real asyncpg pool duck-type.

    ``acquire()`` returns an ``_AsyncCtxManager`` wrapping the injected
    connection so ``async with pool.acquire() as conn:`` works without grpcio.
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self.acquire_called: bool = False

    def acquire(self) -> "_AsyncCtxManager":
        self.acquire_called = True
        return _AsyncCtxManager(self._conn)


class _AsyncClosablePool:
    """Pool duck-type whose ``close()`` is a real coroutine.

    Replaces ``AsyncMock()`` in ``PostgresExecutionTokenVerifier.close()`` tests.
    """

    def __init__(self) -> None:
        self.close_called: bool = False

    async def close(self) -> None:
        self.close_called = True


# ── Redis error client ────────────────────────────────────────────────────────


class _ErrorRedisClient:
    """Redis client duck-type whose async methods always raise.

    Used to exercise the ``_async_clear`` exception-swallowing path in
    ``RedisDistributedBackend`` without a real Redis broker.

    Not a mock — every method has a real body that raises a real ``Exception``.
    """

    async def keys(self, pattern: str) -> list:
        raise RuntimeError("redis down")

    async def delete(self, *keys: Any) -> int:
        raise RuntimeError("redis down")

    async def hgetall(self, key: str) -> dict:
        raise RuntimeError("redis down")

    async def hset(self, key: str, **kwargs: Any) -> int:
        raise RuntimeError("redis down")

    async def expire(self, key: str, ttl: int) -> bool:
        raise RuntimeError("redis down")


# ── Async error close client ──────────────────────────────────────────────────


class _AsyncErrorCloseClient:
    """HTTP/Redis-client duck-type whose ``aclose()`` always raises RuntimeError.

    Replaces ``AsyncMock(side_effect=RuntimeError(...))`` in lifecycle tests
    verifying that ``close()`` swallows ``aclose()`` exceptions.
    """

    async def aclose(self) -> None:
        raise RuntimeError("connection lost")


# ── Prometheus metric helpers ─────────────────────────────────────────────────


class _ErrorGauge:
    """Prometheus Gauge duck-type whose ``labels()`` always raises.

    Used to exercise the ``_update_prometheus()`` exception-swallowing path in
    ``DistributedCircuitBreaker`` and ``AdaptiveCircuitBreaker`` without
    touching the global prometheus registry.

    Not a mock — ``labels()`` has a real body that raises a real ``Exception``.
    """

    def labels(self, **kw: Any) -> "_ErrorGauge":
        raise RuntimeError("gauge error")

    def set(self, value: float) -> None:
        pass


class _EmptyRegistry:
    """prometheus_client REGISTRY duck-type with no registered metrics.

    ``_names_to_collectors`` is an empty dict → ``get()`` returns ``None``
    for any metric name.  Used to test the code path where the ValueError
    recovery in ``_register_metrics()`` cannot find the existing metric.
    """

    _names_to_collectors: dict = {}


class _BoomRegistry:
    """prometheus_client REGISTRY duck-type whose ``get()`` always raises.

    Used to test the ``except Exception: _metrics_available = False`` path
    inside the ValueError handler in ``_register_metrics()``.
    """

    class _NamesDict:
        def get(self, key: str, *args: Any) -> None:
            raise RuntimeError("registry boom")

    _names_to_collectors = _NamesDict()


# ── Prometheus counter recorder ───────────────────────────────────────────────


class _CounterRecorder:
    """Prometheus counter duck-type that records ``inc()`` calls.

    Replaces ``MagicMock()`` in crypto signing-failure counter tests.
    """

    def __init__(self) -> None:
        self.inc_count: int = 0

    def inc(self) -> None:
        self.inc_count += 1

    def labels(self, **kw: Any) -> "_CounterRecorder":
        return self


class _RegistryWithCounter:
    """prometheus_client REGISTRY duck-type pre-populated with one counter.

    Used to test the ``Counter()`` ValueError recovery path in
    ``_increment_signing_failure_counter``: raises ``ValueError`` on
    ``Counter()`` constructor, then finds the counter in this registry.
    """

    def __init__(self, metric_name: str, counter: Any) -> None:
        self._names_to_collectors = {metric_name: counter}


# ── Broken private key ────────────────────────────────────────────────────────


class _BrokenPrivateKey:
    """Ed25519-like private key whose ``sign()`` always raises RuntimeError.

    Replaces ``MagicMock()`` in ``PramanixSigner.sign()`` exception-path tests.
    Not a mock — ``sign()`` has a real body that raises a real RuntimeError.
    """

    def sign(self, message: bytes) -> bytes:
        raise RuntimeError("HSM unavailable")


# ── Kafka capturing producer ──────────────────────────────────────────────────


class _CapturingProducer:
    """confluent_kafka.Producer duck-type that captures delivery callbacks.

    Unlike ``_KafkaDLQProducer`` (which calls callbacks immediately),
    this class stores callbacks for later invocation so tests can simulate
    error delivery after the produce() call.
    """

    def __init__(self) -> None:
        self.produced: list[tuple[str, bytes]] = []
        self.callbacks: list[Any] = []
        self.flush_called: bool = False

    def produce(
        self,
        topic: str,
        value: bytes | None = None,
        *,
        headers: Any = None,
        callback: Any = None,
    ) -> None:
        if value is None:
            value = b""
        self.produced.append((topic, value))
        if callback is not None:
            self.callbacks.append(callback)

    def poll(self, timeout: float = 0.0) -> None:
        pass

    def flush(self, timeout: float = -1.0) -> None:
        self.flush_called = True


class _KafkaDeliveryError:
    """Truthy Kafka error object — simulates a failed delivery callback.

    Replaces ``MagicMock()`` in Kafka delivery error path tests.
    Not a mock — truthy via ``__bool__``, stringifiable via ``__str__``.
    """

    def __bool__(self) -> bool:
        return True

    def __str__(self) -> str:
        return "KafkaError: delivery failed"


# ── Sync scan Redis helper ────────────────────────────────────────────────────


class _SyncScanRedis:
    """Sync Redis client duck-type with configurable scan() results.

    Replaces ``MagicMock()`` in ``RedisExecutionTokenVerifier.consumed_count()``
    pagination tests.  ``scan()`` returns preset ``(cursor, [keys])`` tuples.
    """

    def __init__(self, scan_results: list[tuple[int, list[str]]]) -> None:
        self._scan_results = list(scan_results)
        self._call_idx: int = 0

    def scan(self, cursor: int, match: str, count: int) -> tuple[int, list[str]]:
        result = self._scan_results[self._call_idx]
        self._call_idx += 1
        return result


# ── Anthropic stream helpers ──────────────────────────────────────────────────


class _AnthropicStream:
    """Real Anthropic streaming response duck-type.

    Implements the ``async with stream:`` + ``await stream.get_final_text()``
    pattern used by ``AnthropicTranslator._single_call()``.
    """

    def __init__(self, text: str) -> None:
        self._text = text

    async def __aenter__(self) -> "_AnthropicStream":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    async def get_final_text(self) -> str:
        return self._text


class _AnthropicRaisingStream:
    """Anthropic stream that raises a given exception on ``__aenter__``."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def __aenter__(self) -> "_AnthropicRaisingStream":
        raise self._exc

    async def __aexit__(self, *_: Any) -> None:
        pass


class _AnthropicMessagesNS:
    """Real ``messages`` namespace duck-type for AnthropicTranslator tests.

    Replaces ``t._client.messages`` so ``_single_call()`` can be tested
    without a real Anthropic HTTPS call.
    """

    def __init__(self, text: str = '{"amount": 100}') -> None:
        self._text = text

    def stream(self, **kwargs: Any) -> "_AnthropicStream":
        return _AnthropicStream(self._text)


class _AnthropicErrorMessagesNS:
    """``messages`` namespace that raises on ``stream()`` context entry."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def stream(self, **kwargs: Any) -> "_AnthropicRaisingStream":
        return _AnthropicRaisingStream(self._exc)


# ── Datadog logs API helper ───────────────────────────────────────────────────


class _CapturingLogsApi:
    """Datadog LogsApi duck-type that records ``submit_log()`` calls.

    Replaces the ``MagicMock()`` LogsApi in DatadogAuditSink emit tests.
    ``submit_log()`` stores its argument so tests can assert on the payload.
    """

    def __init__(self) -> None:
        self.submit_log_calls: list[Any] = []

    def submit_log(self, body: Any) -> None:
        self.submit_log_calls.append(body)


# ── AWS SecretsManager client helper ─────────────────────────────────────────


class _AwsSecretsClient:
    """AWS secretsmanager client duck-type for key provider cache tests.

    Replaces ``MagicMock()`` in AwsKmsKeyProvider cache-hit/miss tests.
    Records ``get_secret_value()`` calls so tests can verify no-call on cache hit.
    """

    def __init__(
        self, secret_string: str = "FAKE_PEM", version_id: str | None = None
    ) -> None:
        self._secret_string = secret_string
        self._version_id = version_id
        self.calls: int = 0

    def get_secret_value(self, **kwargs: Any) -> dict:
        self.calls += 1
        result: dict = {"SecretString": self._secret_string}
        if self._version_id is not None:
            result["VersionId"] = self._version_id
        return result

    def rotate_secret(self, *, SecretId: str) -> None:
        pass


# ── GCP Secret Manager client helper ─────────────────────────────────────────


class _GcpSecretClient:
    """GCP SecretManagerServiceClient duck-type for key provider tests.

    Records ``access_secret_version()`` calls.
    """

    def __init__(self, data: bytes = b"FAKE_PEM") -> None:
        self._data = data
        self.calls: int = 0

    def access_secret_version(self, **kwargs: Any) -> Any:
        import types

        self.calls += 1
        payload = types.SimpleNamespace(data=self._data)
        return types.SimpleNamespace(payload=payload)


# ── Azure Key Vault client helper ─────────────────────────────────────────────


class _AzureSecretClient:
    """Azure SecretClient duck-type for key provider cache tests."""

    def __init__(self, value: str = "FAKE_PEM", version_id: str | None = None) -> None:
        self._value = value
        self._version_id = version_id or "azure-v1"
        self.calls: int = 0

    def get_secret(self, name: str, version: str | None = None) -> Any:
        import types

        self.calls += 1
        return types.SimpleNamespace(value=self._value, properties=types.SimpleNamespace(version=self._version_id))


# ── Gemini genai module helpers ───────────────────────────────────────────────


class _GeminiResponse:
    """Real Gemini SDK response shape — ``.text`` attribute."""

    text: str = '{"amount": 5.0}'


class _GeminiModelInstance:
    """Real Gemini ``GenerativeModel`` duck-type."""

    async def generate_content_async(self, prompt: str) -> "_GeminiResponse":
        return _GeminiResponse()


class _GeminiGenaiModule:
    """Real ``google.generativeai`` module duck-type for ``_single_call`` tests.

    Replaces the real ``genai`` module reference on ``GeminiTranslator._genai``
    so that the ``_single_call()`` fallback path (no per-instance client) can
    be exercised without a real Google API key or network call.

    Not a mock: every method has a real body that returns real objects.
    """

    @staticmethod
    def configure(**kw: Any) -> None:
        pass

    @staticmethod
    def GenerativeModel(**kw: Any) -> "_GeminiModelInstance":
        return _GeminiModelInstance()

    @staticmethod
    def GenerationConfig(**kw: Any) -> None:
        return None


# ── Gemini recording model helpers (replaces MagicMock / AsyncMock) ───────────


class _GeminiAsyncModelInstance:
    """Gemini GenerativeModel duck-type with async generate_content_async.

    Records call_count so tests can assert it was called without
    ``assert_called_once()`` (a MagicMock-only API).
    """

    def __init__(self, response_text: str = '{"amount": 5.0}') -> None:
        import types as _t
        self._text = response_text
        self.call_count: int = 0
        self._types = _t

    async def generate_content_async(self, prompt: str) -> Any:
        self.call_count += 1
        return self._types.SimpleNamespace(text=self._text)


class _GeminiSyncOnlyModelInstance:
    """Gemini GenerativeModel WITHOUT generate_content_async (old SDK path).

    ``hasattr(instance, "generate_content_async")`` returns False, so the
    production code falls back to ``run_in_executor`` with sync
    ``generate_content``.
    """

    def __init__(self, response_text: str = '{"amount": 5.0}') -> None:
        import types as _t
        self._text = response_text
        self.call_count: int = 0
        self._types = _t

    def generate_content(self, prompt: str) -> Any:
        self.call_count += 1
        return self._types.SimpleNamespace(text=self._text)


class _GeminiRaisingModelInstance:
    """Gemini GenerativeModel that always raises on generate_content_async.

    Used to exercise the retry-exhaustion / LLMTimeoutError path in
    GeminiTranslator.extract() without a real API key.
    """

    async def generate_content_async(self, prompt: str) -> Any:
        raise Exception("server down")


class _GeminiRecordingGenaiModule:
    """google.generativeai module duck-type that tracks created model instances.

    Replaces ``MagicMock()`` in ``GeminiTranslator._single_call`` tests.
    ``last_model`` holds the most recently created instance so tests can
    assert ``last_model.call_count == 1`` instead of
    ``mock.assert_called_once()``.

    Not a mock: every method has a real body.
    """

    def __init__(
        self,
        response_text: str = '{"amount": 5.0}',
        *,
        sync_only: bool = False,
        raising: bool = False,
    ) -> None:
        self._response_text = response_text
        self._sync_only = sync_only
        self._raising = raising
        self.last_model: Any = None
        self.configure_called: bool = False

    def configure(self, **kw: Any) -> None:
        self.configure_called = True

    def GenerativeModel(self, **kw: Any) -> Any:
        if self._raising:
            m: Any = _GeminiRaisingModelInstance()
        elif self._sync_only:
            m = _GeminiSyncOnlyModelInstance(self._response_text)
        else:
            m = _GeminiAsyncModelInstance(self._response_text)
        self.last_model = m
        return m

    def GenerationConfig(self, **kw: Any) -> None:
        return None


# ── S3 client helpers ─────────────────────────────────────────────────────────


class _S3Client:
    """AWS S3 client duck-type that records put_object() calls.

    Replaces ``MagicMock()`` in S3AuditSink tests.
    """

    def __init__(self) -> None:
        self.put_object_calls: list[dict] = []

    def put_object(self, **kwargs: Any) -> None:
        self.put_object_calls.append(kwargs)


class _ErrorS3Client:
    """AWS S3 client duck-type whose put_object() always raises.

    Replaces ``MagicMock(side_effect=Exception(...))`` in S3 failure-path tests.
    """

    def put_object(self, **kwargs: Any) -> None:
        raise Exception("S3 unavailable")


# ── confluent_kafka module duck-type ──────────────────────────────────────────


class _ConfluentKafkaModule:
    """confluent_kafka module duck-type for Kafka interceptor / sink tests.

    Provides a ``Consumer`` factory method that returns a pre-built consumer
    instance so tests can inject a ``_KafkaConsumer`` without a real broker.
    ``KafkaException`` is set to ``Exception`` so production ``except
    KafkaException`` clauses match any exception raised by the helpers.

    Not a mock: ``Consumer`` is a real method that returns a real object.
    """

    KafkaException = Exception

    def __init__(self, consumer_instance: Any) -> None:
        self._consumer_instance = consumer_instance

    def Consumer(self, config: Any) -> Any:  # noqa: N802 – mirrors the real API name
        return self._consumer_instance


# ── Datadog model helpers ─────────────────────────────────────────────────────


class _DatadogHTTPLogItem:
    """datadog_api_client.v2.model.http_log_item.HTTPLogItem duck-type.

    Accepts and stores all keyword args so production code can call
    ``HTTPLogItem(ddsource=..., ddtags=..., hostname=..., message=...,
    service=...)`` without the real SDK installed.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs


class _DatadogHTTPLog:
    """datadog_api_client.v2.model.http_log.HTTPLog duck-type.

    Wraps a list of log items.  Used as the argument to
    ``LogsApi.submit_log()``.
    """

    def __init__(self, items: Any) -> None:
        self.items = list(items) if items is not None else []

