# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
from typing import Any, ClassVar

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
    (any non-negative value) and ``state={"state_version": "1.0"}``.
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
                (E(_amt) >= Decimal("0"))
                .named("non_negative")
                .explain("Amount must be non-negative")
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
                (E(_amt) > Decimal("9999"))
                .named("above_threshold")
                .explain("Amount must exceed 9999 — always blocked for test inputs")
            ]

    return Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))


#: Default intent/state pair for allow-guard tests — satisfies ``amount >= 0``.
ALLOW_INTENT: dict[str, Any] = {"amount": Decimal("1")}
ALLOW_STATE: dict[str, Any] = {"state_version": "1.0"}

#: Default intent/state pair for block-guard tests — violates ``amount > 9999``.
BLOCK_INTENT: dict[str, Any] = {"amount": Decimal("1")}
BLOCK_STATE: dict[str, Any] = {"state_version": "1.0"}


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

    def _replace(self, **kwargs: Any) -> _GrpcRpcHandler:
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

    def labels(self, **kw: Any) -> _ErrorCounter:
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

    def rotate_secret(self, *, SecretId: str) -> None:  # noqa: N803
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
    def __init__(self, content: str = '{"amount": 5.0}') -> None:
        self.content: str = content


class _MistralChoice:
    def __init__(self, content: str = '{"amount": 5.0}') -> None:
        self.message = _MistralMessage(content)


class _MistralApiResponse:
    """Real Mistral SDK response shape — ``choices[0].message.content``."""

    def __init__(self, content: str = '{"amount": 5.0}') -> None:
        self.choices = [_MistralChoice(content)]


class _NullContentMistralApiResponse:
    """Mistral SDK response with ``content=None`` — exercises the ``content or ""`` branch."""

    def __init__(self) -> None:
        import types

        msg = types.SimpleNamespace(content=None)
        self.choices = [types.SimpleNamespace(message=msg)]


class _MistralChatApi:
    """Real Mistral ``chat`` namespace with real ``async complete_async()``."""

    def __init__(self, content: str = '{"amount": 5.0}') -> None:
        self._content = content

    async def complete_async(self, **kw: Any) -> _MistralApiResponse:
        return _MistralApiResponse(self._content)


class _NullContentMistralChatApi:
    """Mistral ``chat`` namespace that returns ``content=None`` (old-SDK empty path)."""

    async def complete_async(self, **kw: Any) -> _NullContentMistralApiResponse:
        return _NullContentMistralApiResponse()


class _MistralClientStub:
    """Real Mistral client duck-type for path tests that need ``t._client``.

    ``self.chat.complete_async(...)`` is a real coroutine that returns a
    ``_MistralApiResponse`` — no ``AsyncMock`` involved.

    Pass ``response_text`` to control the JSON string returned by the stub so
    tests can verify parsing without asserting on the exact default value.
    Pass ``null_content=True`` to return ``content=None``, exercising the
    ``content or ""`` fallback branch in ``MistralTranslator._single_call()``.
    """

    def __init__(
        self,
        response_text: str = '{"amount": 5.0}',
        *,
        null_content: bool = False,
    ) -> None:
        if null_content:
            self.chat: Any = _NullContentMistralChatApi()
        else:
            self.chat = _MistralChatApi(response_text)


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
        if (
            self._execute_raises is not None
            and len(self.execute_calls) > self._execute_raises_after
        ):
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

    def acquire(self) -> _AsyncCtxManager:
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

    def labels(self, **kw: Any) -> _ErrorGauge:
        raise RuntimeError("gauge error")

    def set(self, value: float) -> None:
        pass


class _EmptyRegistry:
    """prometheus_client REGISTRY duck-type with no registered metrics.

    ``_names_to_collectors`` is an empty dict → ``get()`` returns ``None``
    for any metric name.  Used to test the code path where the ValueError
    recovery in ``_register_metrics()`` cannot find the existing metric.
    """

    _names_to_collectors: ClassVar[dict] = {}


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

    def labels(self, **kw: Any) -> _CounterRecorder:
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

    async def __aenter__(self) -> _AnthropicStream:
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    async def get_final_text(self) -> str:
        return self._text


class _AnthropicRaisingStream:
    """Anthropic stream that raises a given exception on ``__aenter__``."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def __aenter__(self) -> _AnthropicRaisingStream:
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

    def stream(self, **kwargs: Any) -> _AnthropicStream:
        return _AnthropicStream(self._text)


class _AnthropicErrorMessagesNS:
    """``messages`` namespace that raises on ``stream()`` context entry."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def stream(self, **kwargs: Any) -> _AnthropicRaisingStream:
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
    Records ``get_secret_value()`` and ``rotate_secret()`` calls so tests can
    assert on call counts and arguments without ``assert_called_once_with()``.

    Set ``secret_binary`` to return a ``SecretBinary`` payload instead of
    ``SecretString`` (exercises the binary-secret branch in AwsKmsKeyProvider).
    """

    def __init__(
        self,
        secret_string: str = "FAKE_PEM",  # noqa: S107
        version_id: str | None = None,
        *,
        secret_binary: bytes | None = None,
    ) -> None:
        self._secret_string = secret_string
        self._secret_binary = secret_binary
        self._version_id = version_id
        self.calls: int = 0
        self.rotate_secret_calls: list[str] = []

    def get_secret_value(self, **kwargs: Any) -> dict:
        self.calls += 1
        if self._secret_binary is not None:
            result: dict = {"SecretBinary": self._secret_binary}
        else:
            result = {"SecretString": self._secret_string}
        if self._version_id is not None:
            result["VersionId"] = self._version_id
        return result

    def rotate_secret(self, *, SecretId: str) -> None:  # noqa: N803
        self.rotate_secret_calls.append(SecretId)


# ── GCP Secret Manager client helper ─────────────────────────────────────────


class _GcpSecretClient:
    """GCP SecretManagerServiceClient duck-type for key provider tests.

    Records ``access_secret_version()`` calls.

    Set ``as_str=True`` to return payload.data as a decoded string rather than
    bytes — exercises the string-payload branch in GcpKmsKeyProvider.
    """

    def __init__(self, data: bytes = b"FAKE_PEM", *, as_str: bool = False) -> None:
        self._data = data
        self._as_str = as_str
        self.calls: int = 0

    def access_secret_version(self, **kwargs: Any) -> Any:
        import types

        self.calls += 1
        raw: Any = self._data.decode() if self._as_str else self._data
        payload = types.SimpleNamespace(data=raw)
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
        return types.SimpleNamespace(
            value=self._value, properties=types.SimpleNamespace(version=self._version_id)
        )


# ── Gemini genai module helpers ───────────────────────────────────────────────


class _GeminiResponse:
    """Real Gemini SDK response shape — ``.text`` attribute."""

    text: str = '{"amount": 5.0}'


class _GeminiModelInstance:
    """Real Gemini ``GenerativeModel`` duck-type."""

    async def generate_content_async(self, prompt: str) -> _GeminiResponse:
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
    def GenerativeModel(**kw: Any) -> _GeminiModelInstance:  # noqa: N802
        return _GeminiModelInstance()

    @staticmethod
    def GenerationConfig(**kw: Any) -> None:  # noqa: N802
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

    Raises DeadlineExceeded when google.api_core is available so it lands in
    _retryable and eventually surfaces as LLMTimeoutError.  Falls back to plain
    Exception when the optional SDK is absent (triggering the except Exception
    catch-all with _retryable=(Exception,) fallback in the translator).
    """

    async def generate_content_async(self, prompt: str) -> Any:
        try:
            import google.api_core.exceptions as _gapi_exc

            raise _gapi_exc.DeadlineExceeded("server down")
        except ImportError:
            raise Exception("server down") from None


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

    def GenerativeModel(self, **kw: Any) -> Any:  # noqa: N802
        if self._raising:
            m: Any = _GeminiRaisingModelInstance()
        elif self._sync_only:
            m = _GeminiSyncOnlyModelInstance(self._response_text)
        else:
            m = _GeminiAsyncModelInstance(self._response_text)
        self.last_model = m
        return m

    def GenerationConfig(self, **kw: Any) -> None:  # noqa: N802
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

    def Consumer(self, config: Any) -> Any:  # noqa: N802 - mirrors the real API name
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


# ── HashiCorp Vault hvac client helpers ───────────────────────────────────────


class _HvacKvV2:
    """hvac.Client().secrets.kv.v2 duck-type."""

    def __init__(self, pem: bytes, version: int, field: str) -> None:
        self._pem = pem
        self._version = version
        self._field = field

    def read_secret_version(self, path: str, mount_point: str) -> dict:
        return {
            "data": {
                "data": {self._field: self._pem.decode()},
                "metadata": {"version": self._version},
            }
        }


class _HvacKv:
    def __init__(self, pem: bytes, version: int, field: str) -> None:
        self.v2 = _HvacKvV2(pem, version, field)


class _HvacSecrets:
    def __init__(self, pem: bytes, version: int, field: str) -> None:
        self.kv = _HvacKv(pem, version, field)


class _HvacClient:
    """hvac.Client duck-type for HashiCorpVaultKeyProvider tests.

    Replaces ``MagicMock()`` in tests that set
    ``mc.secrets.kv.v2.read_secret_version.return_value = ...``.
    The nested ``secrets.kv.v2.read_secret_version(path=..., mount_point=...)``
    structure mirrors the real hvac API; no MagicMock involved.

    Not a mock — every attribute access reaches a real object with a real method.
    """

    def __init__(
        self,
        pem: bytes,
        version: int = 3,
        field: str = "private_key_pem",
    ) -> None:
        self.secrets = _HvacSecrets(pem, version, field)


# ── Cohere async client helpers ───────────────────────────────────────────────


class _CohereChatV5Stub:
    """Cohere AsyncClientV2 duck-type returning a v5 SDK response shape.

    ``chat()`` is a real coroutine returning ``response.message.content[0].text``.
    Replaces ``MagicMock()`` + ``AsyncMock(return_value=...)`` in Cohere
    translator tests that exercise the SDK v5 response path.
    """

    def __init__(self, text: str = '{"amount": 5.0}') -> None:
        import types

        content_item = types.SimpleNamespace(text=text)
        message = types.SimpleNamespace(content=[content_item])
        self._response = types.SimpleNamespace(message=message)

    async def chat(self, **kw: Any) -> Any:
        return self._response


class _CohereTypeErrorChatClient:
    """Cohere async client whose ``chat()`` always raises ``TypeError``.

    Exercises the old-SDK fallback branch in ``CohereTranslator._single_call()``
    where ``AsyncClientV2.chat()`` raises ``TypeError`` (unknown ``response_format``
    kwarg) and the code falls back to sync ``cohere.Client.chat()`` via executor.

    Not a mock — ``chat()`` has a real body that raises a real ``TypeError``.
    """

    async def chat(self, **kw: Any) -> Any:
        raise TypeError("unexpected kwarg: response_format")


class _CohereNoMessageResponse:
    """Cohere response where ``.message`` raises ``AttributeError``.

    Exercises the ``.text`` fallback in ``CohereTranslator._single_call()``
    when ``response.message.content[0].text`` fails.
    """

    def __init__(self, text: str) -> None:
        self.text = text

    @property
    def message(self) -> Any:
        raise AttributeError("no message attribute on this SDK version")


class _CohereNoMessageChatClient:
    """Cohere async client returning a ``_CohereNoMessageResponse``.

    Replaces ``MagicMock()`` + ``AsyncMock(return_value=mock_no_message_response)``
    in tests that exercise the ``.text`` fallback path.
    """

    def __init__(self, text: str) -> None:
        self._response = _CohereNoMessageResponse(text)

    async def chat(self, **kw: Any) -> Any:
        return self._response


class _CohereLegacySyncResponse:
    """Cohere v4 sync response with ``response.text`` but no ``.message``.

    Replaces ``MagicMock() + del mock.message`` in the old-SDK fallback tests.
    """

    def __init__(self, text: str) -> None:
        self.text = text

    @property
    def message(self) -> Any:
        raise AttributeError("v4 SDK has no .message")


class _CohereLegacySyncClient:
    """Cohere v4 sync ``Client`` duck-type.

    ``chat()`` is a real synchronous method (not a coroutine) — it runs in
    ``run_in_executor`` inside ``CohereTranslator._single_call()`` when the
    async client raises ``TypeError``.
    """

    def __init__(self, text: str) -> None:
        self._response = _CohereLegacySyncResponse(text)

    def chat(self, **kw: Any) -> _CohereLegacySyncResponse:
        return self._response


class _CohereLegacyModule:
    """``cohere`` module duck-type with a ``Client`` factory.

    Replaces ``MagicMock()`` in old-SDK fallback tests where the production
    code calls ``self._cohere.Client(api_key=...).chat(...)``.

    ``Client(...)`` returns a pre-built ``_CohereLegacySyncClient`` instance.
    """

    def __init__(self, text: str) -> None:
        self._client_instance = _CohereLegacySyncClient(text)

    def Client(self, **kw: Any) -> _CohereLegacySyncClient:  # noqa: N802
        return self._client_instance


# ── OS process duck-types (for _force_kill_processes tests) ───────────────────


class _AliveProcess:
    """multiprocessing.Process duck-type that is alive and tracks ``kill()`` calls.

    Replaces ``MagicMock()`` in ``_force_kill_processes`` tests.
    """

    def __init__(self, pid: int = 99999) -> None:
        self.pid = pid
        self.kill_called: int = 0

    def is_alive(self) -> bool:
        return True

    def kill(self) -> None:
        self.kill_called += 1


class _DeadProcess:
    """multiprocessing.Process duck-type that is NOT alive.

    ``kill()`` is tracked to prove it was never called.
    """

    def __init__(self, pid: int = 12345) -> None:
        self.pid = pid
        self.kill_called: int = 0

    def is_alive(self) -> bool:
        return False

    def kill(self) -> None:
        self.kill_called += 1


class _KillRaisesProcess:
    """multiprocessing.Process duck-type whose ``kill()`` always raises ``OSError``.

    Exercises the exception-swallowing path in ``_force_kill_processes``.
    """

    def __init__(self, pid: int = 55555) -> None:
        self.pid = pid

    def is_alive(self) -> bool:
        return True

    def kill(self) -> None:
        raise OSError("permission denied")


class _ExecutorStub:
    """concurrent.futures.ProcessPoolExecutor duck-type with a ``_processes`` dict.

    Replaces ``MagicMock()`` in ``_force_kill_processes`` tests.
    The ``_processes`` attribute maps ``pid → process`` exactly like the real
    ``ProcessPoolExecutor`` internal attribute.
    """

    def __init__(self, processes: dict) -> None:
        self._processes = processes


class _NoProcessesExecutorStub:
    """Executor duck-type with NO ``_processes`` attribute.

    Exercises the ``getattr(executor, "_processes", {})`` fallback in
    ``_force_kill_processes`` — must not raise.
    """


# ── Callable tracker (replaces MagicMock for simple callables) ───────────────


class _CallTracker:
    """Callable that records invocations and returns a configurable value.

    Replaces ``MagicMock(return_value=...)`` for simple callable stubs where
    only call-count and return value matter.  ``assert_not_called()`` and
    ``assert_called_once()`` raise ``AssertionError`` rather than silently
    pass — real assertions, not MagicMock auto-pass.
    """

    def __init__(self, return_value: Any = None) -> None:
        self._return_value = return_value
        self.call_count: int = 0

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.call_count += 1
        return self._return_value

    def assert_not_called(self) -> None:
        assert self.call_count == 0, f"Expected 0 calls, got {self.call_count}"

    def assert_called_once(self) -> None:
        assert self.call_count == 1, f"Expected 1 call, got {self.call_count}"


class _DSPyForwardFn:
    """Callable forward() method that records calls and returns a configurable result."""

    def __init__(self, return_value: Any = None) -> None:
        self._return_value = return_value
        self.call_count: int = 0

    def __call__(self, **kwargs: Any) -> Any:
        self.call_count += 1
        return self._return_value

    def assert_not_called(self) -> None:
        assert self.call_count == 0, f"Expected 0 calls, got {self.call_count}"

    def assert_called_once(self) -> None:
        assert self.call_count == 1, f"Expected 1 call, got {self.call_count}"


class _DSPyModule:
    """DSPy module duck-type with a real forward() that tracks calls.

    Replaces ``MagicMock()`` in ``PramanixGuardedModule`` integration tests.
    ``forward(**kwargs)`` has a real body with a configurable return value.
    ``inner.forward.assert_not_called()`` and ``inner.forward.assert_called_once()``
    use real ``AssertionError`` — no MagicMock magic.
    """

    def __init__(self, return_value: Any = None) -> None:
        self.forward = _DSPyForwardFn(return_value=return_value)


# ── Kafka audit sink helpers ──────────────────────────────────────────────────


class _KafkaAuditProducer:
    """confluent_kafka.Producer duck-type for KafkaAuditSink tests.

    Records the delivery callback passed to ``produce()`` so tests can trigger
    delivery callbacks directly.  Supports a configurable poll side-effect so
    the ``_background_poll`` exception-swallowing path can be tested without
    threads or MagicMock.

    Not a mock: every method has a real body that mutates real instance state.
    """

    def __init__(self) -> None:
        self._last_callback: Any = None
        self._poll_side_effect: Any = None  # nullable zero-arg callable

    def produce(
        self,
        topic: str,
        *,
        value: bytes | None = None,
        callback: Any = None,
    ) -> None:
        self._last_callback = callback

    def poll(self, timeout: float = 0.1) -> int:
        if self._poll_side_effect is not None:
            self._poll_side_effect()
        return 0

    def flush(self, timeout: float = -1.0) -> None:
        pass


class _KafkaAuditModule:
    """confluent_kafka module duck-type for ``KafkaAuditSink`` construction.

    ``Producer(config)`` returns the injected ``_KafkaAuditProducer`` instance.
    Replaces ``MagicMock()`` as the confluent_kafka sys.modules stub.
    """

    def __init__(self, producer: _KafkaAuditProducer) -> None:
        self._producer = producer

    def Producer(self, config: Any) -> _KafkaAuditProducer:  # noqa: N802
        return self._producer


# ── WorkerPool executor stub ──────────────────────────────────────────────────


class _RaisingSubmitExecutor:
    """Executor duck-type whose ``submit()`` always raises a given exception.

    Replaces ``MagicMock(side_effect=WorkerError("..."))`` assigned to
    ``pool._executor`` in ``WorkerPool`` error-path tests.

    Not a mock: ``submit()`` has a real body that raises the stored exception.
    """

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def submit(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        raise self._exc

    def shutdown(self, wait: bool = True) -> None:
        pass


# ── Redis client stubs ────────────────────────────────────────────────────────


class _PingFailRedisClient:
    """Redis client duck-type whose ``ping()`` raises ``ConnectionRefusedError``.

    Replaces ``MagicMock()`` + ``ping.side_effect = ConnectionRefusedError(...)``
    in doctor CLI tests verifying the ``redis-ping ERROR`` path.
    """

    def ping(self) -> None:
        raise ConnectionRefusedError("Connection refused")


class _PingOkRedisClient:
    """Redis client duck-type whose ``ping()`` returns ``True``.

    Replaces ``MagicMock()`` + ``ping.return_value = True`` in doctor CLI tests
    verifying the ``redis-ping OK`` path.  ``close()`` is a no-op — the CLI
    calls it after a successful ping.
    """

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass


# ── Entry-point duck-type ─────────────────────────────────────────────────────


class _FakeEntryPoint:
    """importlib.metadata.EntryPoint duck-type for redundant translator tests.

    Replaces ``MagicMock()`` used to stub entry-point objects returned by
    ``importlib.metadata.entry_points()``.  ``load()`` returns the injected
    callable directly — no auto-attribute magic.
    """

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self._fn = fn

    def load(self) -> Any:
        return self._fn


# ── LlamaCpp module duck-type ─────────────────────────────────────────────────


class _LlamaCppLlm:
    """llama_cpp.Llama duck-type for LlamaCppTranslator tests.

    ``create_chat_completion()`` returns a real response dict so the production
    code can extract ``response["choices"][0]["message"]["content"]`` without
    any MagicMock auto-attribute magic.
    """

    def __init__(self, response_text: str = '{"amount": 50}') -> None:
        self._response_text = response_text
        self.call_count: int = 0

    def create_chat_completion(
        self,
        messages: Any,
        max_tokens: int = 512,
        temperature: float = 0.0,
    ) -> dict:
        self.call_count += 1
        return {"choices": [{"message": {"content": self._response_text}}]}


class _LlamaCppModule:
    """llama_cpp module duck-type for sys.modules injection.

    ``Llama(model_path=..., ...)`` returns a pre-built ``_LlamaCppLlm`` instance.
    Replaces ``MagicMock()`` as the llama_cpp sys.modules stub in
    ``LlamaCppTranslator`` tests.
    """

    def __init__(self, response_text: str = '{"amount": 50}') -> None:
        self._llm = _LlamaCppLlm(response_text)

    def Llama(self, model_path: str = "", **kw: Any) -> _LlamaCppLlm:  # noqa: N802
        return self._llm


# ── Error-raising cloud SDK clients ──────────────────────────────────────────
# These replace MagicMock() clients in TestKeyProviderRefreshCacheErrors.
# Each class raises the same exception the real SDK would raise on network
# failure so the provider's _refresh_cache except-block executes.


class _AwsSecretsClientError:
    """AWS secretsmanager client duck-type — always raises ConnectionError.

    Replaces ``MagicMock(side_effect=ConnectionError(...))`` in
    ``test_aws_refresh_cache_wraps_exception``.
    """

    def get_secret_value(self, **kwargs: Any) -> dict:
        raise ConnectionError("no route to AWS")


class _AzureSecretClientError:
    """Azure SecretClient duck-type — always raises ConnectionError on get_secret.

    Replaces ``MagicMock(side_effect=ConnectionError(...))`` in
    ``test_azure_refresh_cache_wraps_exception``.
    """

    def get_secret(self, secret_name: str, **kwargs: Any) -> object:
        raise ConnectionError("Azure vault unreachable")


class _GcpSecretClientError:
    """GCP SecretManagerServiceClient duck-type — always raises ConnectionError.

    Replaces ``MagicMock(side_effect=ConnectionError(...))`` in
    ``test_gcp_refresh_cache_wraps_exception``.
    """

    def access_secret_version(self, **kwargs: Any) -> object:
        raise ConnectionError("GCP unreachable")


class _VaultKvV2Error:
    def read_secret_version(self, **kwargs: Any) -> dict:
        raise OSError("Vault sealed")


class _VaultKvError:
    v2 = _VaultKvV2Error()


class _VaultSecretsError:
    kv = _VaultKvError()


class _VaultKvClientError:
    """hvac.Client duck-type — read_secret_version raises OSError.

    Replaces ``MagicMock(side_effect=OSError(...))`` in
    ``test_vault_refresh_cache_wraps_exception``.
    """

    secrets = _VaultSecretsError()


class _VaultKvV2MissingField:
    def read_secret_version(self, **kwargs: Any) -> dict:
        return {
            "data": {
                "data": {"other_field": "some-value"},
                "metadata": {"version": 1},
            }
        }


class _VaultKvMissingField:
    v2 = _VaultKvV2MissingField()


class _VaultSecretsMissingField:
    kv = _VaultKvMissingField()


class _VaultKvClientMissingField:
    """hvac.Client duck-type — returns a response that is missing the expected key field.

    Replaces ``MagicMock(return_value={...})`` in
    ``test_vault_missing_field_raises_configuration_error``.
    """

    secrets = _VaultSecretsMissingField()


# ── Real module stubs (replace MagicMock() used as sys.modules entries) ───────
# These are real types.ModuleType instances — not MagicMock.  They satisfy
# the minimum import requirements of optional-dependency providers without
# any auto-attribute magic.

import types as _types_module  # local alias to avoid shadowing the outer namespace  # noqa: E402


class _Boto3ModuleStub(_types_module.ModuleType):
    """Minimal boto3 module stub for key provider constructor tests.

    The ``client()`` factory raises AssertionError so tests that accidentally
    call it instead of injecting ``_client=`` directly fail loudly.
    """

    def __init__(self) -> None:
        super().__init__("boto3")
        self.__package__ = "boto3"

    def client(self, service_name: str, **kwargs: Any) -> object:
        raise AssertionError("boto3.client() must not be called when _client is injected")


class _AzureModuleStub(_types_module.ModuleType):
    """Top-level ``azure`` package stub."""

    def __init__(self) -> None:
        super().__init__("azure")
        self.__package__ = "azure"


class _AzureIdentityModuleStub(_types_module.ModuleType):
    """``azure.identity`` module stub — provides DefaultAzureCredential class."""

    DefaultAzureCredential = type("DefaultAzureCredential", (), {})

    def __init__(self) -> None:
        super().__init__("azure.identity")
        self.__package__ = "azure"


class _AzureKVModuleStub(_types_module.ModuleType):
    """``azure.keyvault`` module stub."""

    def __init__(self) -> None:
        super().__init__("azure.keyvault")
        self.__package__ = "azure"


class _AzureKVSecretsModuleStub(_types_module.ModuleType):
    """``azure.keyvault.secrets`` module stub — provides SecretClient class."""

    SecretClient = type("SecretClient", (), {})

    def __init__(self) -> None:
        super().__init__("azure.keyvault.secrets")
        self.__package__ = "azure"


class _GcpModuleStub(_types_module.ModuleType):
    """Top-level ``google`` package stub."""

    def __init__(self) -> None:
        super().__init__("google")
        self.__package__ = "google"


class _GcpCloudModuleStub(_types_module.ModuleType):
    """``google.cloud`` package stub."""

    def __init__(self) -> None:
        super().__init__("google.cloud")
        self.__package__ = "google"


class _GcpSecretManagerModuleStub(_types_module.ModuleType):
    """``google.cloud.secretmanager`` module stub — provides SecretManagerServiceClient."""

    SecretManagerServiceClient = type("SecretManagerServiceClient", (), {})

    def __init__(self) -> None:
        super().__init__("google.cloud.secretmanager")
        self.__package__ = "google"


class _GoogleProtobufModuleStub(_types_module.ModuleType):
    """``google.protobuf`` module stub (needed by some gemini path tests)."""

    def __init__(self) -> None:
        super().__init__("google.protobuf")
        self.__package__ = "google"


class _GeminiGenaiModuleStub(_types_module.ModuleType):
    """``google.generativeai`` module stub with ``Client = None``.

    Simulates the older SDK shape that lacks a per-instance Client class,
    causing ``GeminiTranslator.__init__`` to set ``self._client = None``
    when no API key is provided.
    """

    Client: Any = None  # older SDK: no per-instance Client

    def __init__(self) -> None:
        super().__init__("google.generativeai")
        self.__package__ = "google"


class _HvacModuleStub(_types_module.ModuleType):
    """``hvac`` module stub — provides a Client class that accepts keyword args."""

    Client = type("Client", (), {"__init__": lambda self, **kw: None})

    def __init__(self) -> None:
        super().__init__("hvac")
        self.__package__ = "hvac"


# ── Tracking Redis client + module stub ───────────────────────────────────────


class _TrackingPingRedisClient:
    """Sync Redis client duck-type whose ``ping()`` tracks call count.

    Used in tests that need to assert ``ping()`` was called once after
    ``IntentCache.from_env()`` sets up the redis backend path.
    Provides all the methods ``_RedisCache`` may call so the constructor
    does not raise.
    """

    ping_call_count: int = 0

    def ping(self) -> bool:
        _TrackingPingRedisClient.ping_call_count += 1
        return True

    def set(self, *args: Any, **kwargs: Any) -> None:
        pass

    def get(self, name: str, **kwargs: Any) -> Any:
        return None

    def setex(self, *args: Any, **kwargs: Any) -> None:
        pass

    def delete(self, *args: Any, **kwargs: Any) -> None:
        pass

    def scan(self, cursor: int = 0, **kwargs: Any) -> tuple:
        return (0, [])

    def ttl(self, name: str) -> int:
        return -1

    def close(self) -> None:
        pass


class _TrackingRedisModule:
    """Minimal ``redis`` module duck-type providing ``from_url()``.

    When constructed with a client instance, ``from_url()`` returns that
    exact instance so the caller can inspect its state after cache init.
    When constructed without a client, a fresh ``_TrackingPingRedisClient``
    is created on each ``from_url()`` call.
    """

    def __init__(self, client: _TrackingPingRedisClient | None = None) -> None:
        self._client = client

    def from_url(self, url: str, **kwargs: Any) -> _TrackingPingRedisClient:
        if self._client is not None:
            return self._client
        client = _TrackingPingRedisClient()
        _TrackingPingRedisClient.ping_call_count = 0  # reset counter per call
        return client


# ── Recording async translator (replaces AsyncMock in natural policy tests) ───


class _RecordingTranslator:
    """Real async translator duck-type — not AsyncMock.

    Has a real async ``extract()`` coroutine that returns a pre-configured
    response dict.  Tracks ``call_count`` and the last prompt for assertions
    without requiring any MagicMock/AsyncMock API.

    Usage::

        translator = _RecordingTranslator({"amount_lte_50k": True, ...})
        policy = await NaturalLanguagePolicy.build(translator, ...)
        assert translator.call_count == 1
    """

    def __init__(self, response: dict) -> None:
        self._response = response
        self.call_count: int = 0
        self.last_prompt: str | None = None
        self.last_schema: object = None

    async def extract(
        self,
        prompt: str = "",
        schema: object = None,
        config: object = None,
        *,
        text: str = "",
        intent_schema: object = None,
        context: object = None,
        **kwargs: object,
    ) -> dict:
        self.call_count += 1
        self.last_prompt = text or prompt
        self.last_schema = intent_schema or schema
        return self._response

    async def aclose(self) -> None:
        pass


# ── Worker-process duck-type (replaces MagicMock for multiprocessing tests) ───


class _FakeWorkerProcess:
    """Real process duck-type with ``.name`` attribute for ``_warmup_worker`` tests.

    Replaces ``MagicMock(); fake_proc.name = "ForkPoolWorker-1"`` in
    ``test_hardening.py`` tests that check whether the current process name
    indicates a worker.
    """

    name: str = "ForkPoolWorker-1"
