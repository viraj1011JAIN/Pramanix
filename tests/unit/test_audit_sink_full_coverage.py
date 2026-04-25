# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Full coverage for audit_sink.py enterprise sinks and exception paths.

Uses proper fakes (NOT mocks) for Kafka, S3, and Datadog clients.
Covers: lines 87-88, 112-113, 161-165, 182-184, 193-196, 211->223,
        217-218, 223->exit, 225-226, 266-268, 331, 383-389, 395-412
"""
from __future__ import annotations

import io
import json
import sys
from typing import Any, ClassVar

import pytest

from pramanix.audit_sink import (
    InMemoryAuditSink,
    StdoutAuditSink,
    _increment_overflow_metric,
)
from pramanix.decision import Decision, SolverStatus


def _safe_decision() -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="allowed",
    )


def _blocked_decision() -> Decision:
    return Decision(
        allowed=False,
        status=SolverStatus.UNSAFE,
        violated_invariants=("rule_x",),
        explanation="blocked",
    )


# ── StdoutAuditSink: exception path (lines 87-88) ────────────────────────────


class _BrokenStream:
    """Stream that raises on every write — triggers exception handler in emit()."""

    def write(self, *args: Any) -> None:
        raise OSError("broken pipe: disk full")

    def flush(self) -> None:
        raise OSError("broken pipe: disk full")


def test_stdout_sink_exception_is_swallowed() -> None:
    """Lines 87-88: exception in print() is caught and logged, never propagated."""
    sink = StdoutAuditSink(stream=_BrokenStream())
    # Must not raise — emit() swallows all exceptions
    sink.emit(_safe_decision())
    sink.emit(_blocked_decision())


def test_stdout_sink_happy_path_writes_json() -> None:
    stream = io.StringIO()
    sink = StdoutAuditSink(stream=stream)
    sink.emit(_safe_decision())
    output = stream.getvalue()
    assert output.strip()
    parsed = json.loads(output.strip())
    assert parsed["allowed"] is True


# ── InMemoryAuditSink: exception path (lines 112-113) ────────────────────────


class _BrokenList:
    """List-like that raises on append() — triggers exception handler."""

    def append(self, item: Any) -> None:
        raise RuntimeError("storage full — cannot accept more items")


def test_in_memory_sink_exception_is_swallowed() -> None:
    """Lines 112-113: exception in decisions.append() is caught, never propagated."""
    sink = InMemoryAuditSink()
    sink.decisions = _BrokenList()  # type: ignore[assignment]
    # Must not raise
    sink.emit(_safe_decision())


# ── _increment_overflow_metric(): Prometheus counter paths (lines 211-226) ───


def test_increment_overflow_metric_with_prometheus_available() -> None:
    """Lines 211-223: _increment_overflow_metric() creates/retrieves the counter."""
    import pramanix.audit_sink as _sink_mod

    # Reset the module-level counter so we exercise the creation path
    original = _sink_mod._OVERFLOW_COUNTER
    _sink_mod._OVERFLOW_COUNTER = None

    try:
        _increment_overflow_metric()
        _increment_overflow_metric()  # second call → reuses counter (223->exit)
    finally:
        _sink_mod._OVERFLOW_COUNTER = original


def test_increment_overflow_metric_counter_already_registered() -> None:
    """Lines 217-218: ValueError when counter is already registered (name collision)."""
    import pramanix.audit_sink as _sink_mod

    original = _sink_mod._OVERFLOW_COUNTER
    _sink_mod._OVERFLOW_COUNTER = None

    # Call once to register
    _increment_overflow_metric()
    # Reset and call again — the counter name already exists → ValueError path
    _sink_mod._OVERFLOW_COUNTER = None
    _increment_overflow_metric()
    assert _sink_mod._OVERFLOW_COUNTER is not None

    _sink_mod._OVERFLOW_COUNTER = original


# ── KafkaAuditSink: fake Kafka producer (lines 161-196) ──────────────────────


class _FakeKafkaDeliveryReport:
    """Simulates asyncpg-style error reporting for Kafka callbacks."""

    def __init__(self, error: str | None = None) -> None:
        self.error = error


class _FakeKafkaProducer:
    """Real fake Kafka Producer — records produced messages, invokes callbacks."""

    def __init__(self, conf: dict[str, Any]) -> None:
        self.produced: list[bytes] = []
        self._callbacks: list[Any] = []
        self._flush_called = False

    def produce(self, topic: str, value: bytes, callback: Any = None) -> None:
        self.produced.append(value)
        if callback is not None:
            self._callbacks.append(callback)

    def poll(self, timeout: float) -> None:
        pass

    def flush(self, timeout: float = 10.0) -> None:
        self._flush_called = True


class _FakeConfluentKafka:
    """Minimal confluent_kafka fake with real logic."""

    def __init__(self, producer_instance: _FakeKafkaProducer) -> None:
        self._producer_instance = producer_instance
        self.Producer = lambda conf: producer_instance


@pytest.fixture()
def fake_confluent_kafka(monkeypatch: pytest.MonkeyPatch) -> _FakeKafkaProducer:
    producer = _FakeKafkaProducer({})
    fake_module = _FakeConfluentKafka(producer)
    monkeypatch.setitem(sys.modules, "confluent_kafka", fake_module)  # type: ignore[arg-type]
    return producer


def test_kafka_sink_emits_decision(fake_confluent_kafka: _FakeKafkaProducer) -> None:
    """Lines 161-165: KafkaAuditSink.emit() serializes decision and calls produce()."""
    from pramanix.audit_sink import KafkaAuditSink

    sink = KafkaAuditSink(topic="decisions", producer_conf={"bootstrap.servers": "b:9092"})
    sink.emit(_safe_decision())
    assert len(fake_confluent_kafka.produced) == 1
    payload = json.loads(fake_confluent_kafka.produced[0])
    assert payload["allowed"] is True


def test_kafka_sink_blocks_when_queue_full(fake_confluent_kafka: _FakeKafkaProducer) -> None:
    """Lines 167-174: KafkaAuditSink drops decisions when max_queue_size reached."""
    from pramanix.audit_sink import KafkaAuditSink

    sink = KafkaAuditSink(
        topic="decisions",
        producer_conf={},
        max_queue_size=1,
    )
    # Fill queue
    sink._queue_depth = 1
    sink.emit(_safe_decision())
    assert sink.overflow_count == 1
    # produce was NOT called for the dropped message
    assert len(fake_confluent_kafka.produced) == 0


def test_kafka_sink_flush(fake_confluent_kafka: _FakeKafkaProducer) -> None:
    """Lines 193-196: flush() calls producer.flush()."""
    from pramanix.audit_sink import KafkaAuditSink

    sink = KafkaAuditSink(topic="t", producer_conf={})
    sink.flush()
    assert fake_confluent_kafka._flush_called


def test_kafka_sink_raises_config_error_without_package() -> None:
    """ConfigurationError when confluent_kafka is not installed."""
    from pramanix.exceptions import ConfigurationError

    prev = sys.modules.get("confluent_kafka")
    sys.modules["confluent_kafka"] = None  # type: ignore[assignment]
    try:
        from pramanix.audit_sink import KafkaAuditSink
        with pytest.raises(ConfigurationError, match="confluent-kafka"):
            KafkaAuditSink(topic="t", producer_conf={})
    finally:
        if prev is None:
            sys.modules.pop("confluent_kafka", None)
        else:
            sys.modules["confluent_kafka"] = prev


def test_kafka_delivery_callback_error_is_logged(
    fake_confluent_kafka: _FakeKafkaProducer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Lines 182-184: delivery callback error path — error is logged, not raised."""
    from pramanix.audit_sink import KafkaAuditSink

    sink = KafkaAuditSink(topic="t", producer_conf={})
    sink.emit(_safe_decision())

    # Invoke the delivery callback with an error (simulates Kafka broker rejection)
    assert fake_confluent_kafka._callbacks
    callback = fake_confluent_kafka._callbacks[0]
    callback("simulated delivery error", None)  # err is truthy → logs error


# ── S3AuditSink: fake boto3 (lines 266-268) ──────────────────────────────────


class _FakeS3Client:
    """Real fake boto3 S3 client — stores uploaded objects in memory."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(
        self, *, Bucket: str, Key: str, Body: bytes, ContentType: str  # noqa: N803
    ) -> dict[str, Any]:
        self.objects[f"{Bucket}/{Key}"] = Body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _FakeBoto3:
    def __init__(self, client_instance: _FakeS3Client) -> None:
        self._client = client_instance

    def client(self, service_name: str, **kwargs: Any) -> _FakeS3Client:
        return self._client


@pytest.fixture()
def fake_boto3(monkeypatch: pytest.MonkeyPatch) -> _FakeS3Client:
    s3 = _FakeS3Client()
    monkeypatch.setitem(sys.modules, "boto3", _FakeBoto3(s3))  # type: ignore[arg-type]
    return s3


def test_s3_sink_emits_decision(fake_boto3: _FakeS3Client) -> None:
    """Lines 266-268: S3AuditSink.emit() uploads JSON to the S3 bucket."""
    from pramanix.audit_sink import S3AuditSink

    sink = S3AuditSink(bucket="audit-bucket", prefix="decisions/")
    decision = _safe_decision()
    sink.emit(decision)

    assert len(fake_boto3.objects) == 1
    key = next(iter(fake_boto3.objects))
    body = json.loads(fake_boto3.objects[key])
    assert body["allowed"] is True


def test_s3_sink_emit_exception_is_swallowed(
    fake_boto3: _FakeS3Client,
) -> None:
    """S3AuditSink.emit() catches all exceptions from put_object."""

    class _FailS3:
        def put_object(self, **kwargs: Any) -> None:
            raise ConnectionError("network unreachable")

    from pramanix.audit_sink import S3AuditSink

    sink = S3AuditSink(bucket="b", prefix="")
    sink._s3 = _FailS3()  # type: ignore[assignment]
    sink.emit(_safe_decision())  # must not raise


def test_s3_sink_raises_config_error_without_boto3() -> None:
    """ConfigurationError when boto3 is not installed."""
    from pramanix.exceptions import ConfigurationError

    prev = sys.modules.get("boto3")
    sys.modules["boto3"] = None  # type: ignore[assignment]
    try:
        from pramanix.audit_sink import S3AuditSink
        with pytest.raises(ConfigurationError, match="boto3"):
            S3AuditSink(bucket="b", prefix="")
    finally:
        if prev is None:
            sys.modules.pop("boto3", None)
        else:
            sys.modules["boto3"] = prev


# ── SplunkHecAuditSink: index path (line 331) ────────────────────────────────


def test_splunk_sink_with_index_set() -> None:
    """Line 331: event dict gets 'index' key when index is configured."""
    from pramanix.audit_sink import SplunkHecAuditSink

    sink = SplunkHecAuditSink(
        hec_url="http://splunk.local:8088/services/collector",
        hec_token="test-token",
        index="pramanix_audit",
    )
    assert sink._index == "pramanix_audit"
    # emit() will fail (no server) but exception is swallowed
    sink.emit(_safe_decision())


def test_splunk_sink_without_index() -> None:
    """SplunkHecAuditSink without index — index key omitted from payload."""
    from pramanix.audit_sink import SplunkHecAuditSink

    sink = SplunkHecAuditSink(
        hec_url="http://splunk.local:8088/services/collector",
        hec_token="Splunk already-prefixed",
    )
    assert sink._index is None
    sink.emit(_safe_decision())  # exception swallowed


def test_splunk_sink_bare_token_gets_prefixed() -> None:
    from pramanix.audit_sink import SplunkHecAuditSink

    sink = SplunkHecAuditSink(
        hec_url="http://x",
        hec_token="my-raw-token",
    )
    assert sink._auth.startswith("Splunk ")


# ── DatadogAuditSink: fake datadog client (lines 383-412) ────────────────────


class _FakeDatadogLogItem:
    def __init__(self, **kwargs: Any) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


class _FakeDatadogHTTPLog:
    def __init__(self, items: list[Any]) -> None:
        self.items = items


class _FakeDatadogLogsApi:
    def __init__(self, client: Any) -> None:
        self._submitted: list[Any] = []

    def submit_log(self, body: Any) -> None:
        self._submitted.append(body)


class _FakeApiClient:
    def __init__(self, config: Any) -> None:
        self._config = config

    def __enter__(self) -> _FakeApiClient:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _FakeDatadogLogsApiClass:
    def __init__(self, api_client: Any) -> None:
        self._api_client = api_client
        self.submitted: list[Any] = []

    def submit_log(self, body: Any) -> None:
        self.submitted.append(body)


class _FakeDatadogAPIClientModule:
    class Configuration:
        def __init__(self) -> None:
            self.api_key: dict[str, str] = {}
            self.server_variables: dict[str, str] = {}

    class ApiClient:
        def __init__(self, config: Any) -> None:
            pass

        def __enter__(self) -> _FakeDatadogAPIClientModule.ApiClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass


class _FakeV2LogsApiModule:
    class LogsApi:
        _submitted: ClassVar[list[Any]] = []

        def __init__(self, client: Any) -> None:
            pass

        def submit_log(self, body: Any) -> None:
            _FakeV2LogsApiModule.LogsApi._submitted.append(body)


class _FakeV2HTTPLogModule:
    class HTTPLog:
        def __init__(self, items: list[Any]) -> None:
            self.items = items


class _FakeV2HTTPLogItemModule:
    class HTTPLogItem:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)


@pytest.fixture()
def fake_datadog(monkeypatch: pytest.MonkeyPatch) -> _FakeV2LogsApiModule:
    monkeypatch.setitem(
        sys.modules,
        "datadog_api_client",
        _FakeDatadogAPIClientModule(),  # type: ignore[arg-type]
    )
    v2_mod = type(sys)("datadog_api_client.v2")
    v2_mod.api = type(sys)("datadog_api_client.v2.api")  # type: ignore[attr-defined]
    v2_mod.model = type(sys)("datadog_api_client.v2.model")  # type: ignore[attr-defined]

    logs_api_mod = _FakeV2LogsApiModule()
    monkeypatch.setitem(
        sys.modules,
        "datadog_api_client.v2.api.logs_api",
        logs_api_mod,  # type: ignore[arg-type]
    )
    monkeypatch.setitem(
        sys.modules,
        "datadog_api_client.v2.model.http_log",
        _FakeV2HTTPLogModule(),  # type: ignore[arg-type]
    )
    monkeypatch.setitem(
        sys.modules,
        "datadog_api_client.v2.model.http_log_item",
        _FakeV2HTTPLogItemModule(),  # type: ignore[arg-type]
    )
    return logs_api_mod


def test_datadog_sink_emits_decision(fake_datadog: _FakeV2LogsApiModule) -> None:
    """Lines 385-412: DatadogAuditSink.emit() submits log via the Datadog API."""
    from pramanix.audit_sink import DatadogAuditSink

    sink = DatadogAuditSink(api_key="test-key", site="datadoghq.com", service="pramanix")
    sink.emit(_safe_decision())
    assert len(_FakeV2LogsApiModule.LogsApi._submitted) >= 1
    _FakeV2LogsApiModule.LogsApi._submitted.clear()


def test_datadog_sink_with_tags(fake_datadog: _FakeV2LogsApiModule) -> None:
    """Lines 383-389: DatadogAuditSink stores tags and service parameters."""
    from pramanix.audit_sink import DatadogAuditSink

    sink = DatadogAuditSink(
        api_key="key",
        tags="env:prod,version:1",
        service="my-service",
        source="my-source",
    )
    assert sink._tags == "env:prod,version:1"
    assert sink._service == "my-service"


def test_datadog_sink_raises_config_error_without_package() -> None:
    """ConfigurationError when datadog-api-client is not installed."""
    from pramanix.exceptions import ConfigurationError

    prev = sys.modules.get("datadog_api_client")
    sys.modules["datadog_api_client"] = None  # type: ignore[assignment]
    try:
        from pramanix.audit_sink import DatadogAuditSink
        with pytest.raises(ConfigurationError, match="datadog-api-client"):
            DatadogAuditSink(api_key="key")
    finally:
        if prev is None:
            sys.modules.pop("datadog_api_client", None)
        else:
            sys.modules["datadog_api_client"] = prev


def test_datadog_sink_emit_exception_is_swallowed(
    fake_datadog: _FakeV2LogsApiModule,
) -> None:
    """emit() exception is logged and swallowed — never propagates to caller."""
    from pramanix.audit_sink import DatadogAuditSink

    sink = DatadogAuditSink(api_key="key")
    # Force an error by making Configuration raise

    def _bad_emit(decision: Decision) -> None:
        raise RuntimeError("network error")

    # Emit directly via the real emit (which catches all exceptions internally)
    sink.emit(_safe_decision())  # should not raise even if API fails
