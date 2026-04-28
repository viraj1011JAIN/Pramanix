# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for enterprise audit sinks: Kafka, S3, Splunk, Datadog (E-4)."""
from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

from pramanix.audit_sink import (
    DatadogAuditSink,
    InMemoryAuditSink,
    KafkaAuditSink,
    S3AuditSink,
    SplunkHecAuditSink,
)
from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import ConfigurationError
from tests.helpers.real_protocols import (
    _CapturingLogsApi,
    _CapturingProducer,
    _DatadogHTTPLog,
    _DatadogHTTPLogItem,
    _ErrorS3Client,
    _KafkaDLQProducer,
    _S3Client,
)


def _make_decision(allowed: bool = True) -> Decision:
    return Decision(
        allowed=allowed,
        status=SolverStatus.SAFE if allowed else SolverStatus.UNSAFE,
        violated_invariants=(),
        explanation="test decision",
    )


# ── InMemoryAuditSink sanity ──────────────────────────────────────────────────


def test_in_memory_sink_records() -> None:
    sink = InMemoryAuditSink()
    d = _make_decision()
    sink.emit(d)
    assert len(sink.decisions) == 1
    assert sink.decisions[0] is d


def test_in_memory_sink_clear() -> None:
    sink = InMemoryAuditSink()
    sink.emit(_make_decision())
    sink.clear()
    assert len(sink.decisions) == 0


# ── KafkaAuditSink ────────────────────────────────────────────────────────────


def test_kafka_sink_raises_config_error_without_confluent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "confluent_kafka", None)
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[kafka\\]'"):
        KafkaAuditSink("my-topic", {"bootstrap.servers": "localhost:9092"})


def _make_kafka_sink(producer: _CapturingProducer, max_queue: int = 10_000) -> KafkaAuditSink:
    """Build a KafkaAuditSink via __new__ with all required attrs set."""
    import threading
    sink = KafkaAuditSink.__new__(KafkaAuditSink)
    sink._topic = "test-topic"
    sink._producer = producer
    sink._queue_depth = 0
    sink._max_queue = max_queue
    sink._overflow_count = 0
    sink._queue_lock = threading.Lock()
    sink._poll_stop = threading.Event()
    return sink


def test_kafka_sink_records_to_queue() -> None:
    producer = _CapturingProducer()
    sink = _make_kafka_sink(producer)
    sink.emit(_make_decision())
    assert len(producer.produced) == 1


def test_kafka_sink_overflow_increments_counter() -> None:
    producer = _CapturingProducer()
    sink = _make_kafka_sink(producer, max_queue=0)
    sink.emit(_make_decision())
    assert sink.overflow_count == 1


def test_kafka_sink_failure_does_not_propagate() -> None:
    # Producer whose produce() raises — emit() must swallow the exception.
    producer = _KafkaDLQProducer(produce_raises=Exception("broker down"))
    sink = _make_kafka_sink(producer)
    sink.emit(_make_decision())  # must not raise


# ── S3AuditSink ───────────────────────────────────────────────────────────────


def test_s3_sink_raises_config_error_without_boto3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[s3\\]'"):
        S3AuditSink("my-bucket")


def test_s3_sink_records_puts_object() -> None:
    import concurrent.futures

    s3 = _S3Client()
    sink = S3AuditSink.__new__(S3AuditSink)
    sink._bucket = "test-bucket"
    sink._prefix = "audit/"
    sink._s3 = s3
    sink._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    sink.emit(_make_decision())
    sink._pool.shutdown(wait=True)  # wait for upload thread
    assert len(s3.put_object_calls) == 1
    call_kwargs = s3.put_object_calls[0]
    assert call_kwargs["Bucket"] == "test-bucket"
    assert call_kwargs["Key"].startswith("audit/")


def test_s3_sink_failure_does_not_propagate() -> None:
    s3 = _ErrorS3Client()
    sink = S3AuditSink.__new__(S3AuditSink)
    sink._bucket = "bucket"
    sink._prefix = ""
    sink._s3 = s3
    sink.emit(_make_decision())  # must not raise


# ── SplunkHecAuditSink ────────────────────────────────────────────────────────


def test_splunk_sink_records_sends_http() -> None:
    import httpx
    import respx

    with respx.mock(base_url="http://splunk:8088") as mock_splunk:
        mock_splunk.post("/services/collector").mock(
            return_value=httpx.Response(200, json={"text": "Success", "code": 0})
        )
        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "my-token")
        sink.emit(_make_decision())

        assert mock_splunk.calls.call_count == 1
        req = mock_splunk.calls[0].request
        assert req.headers["Authorization"] == "Splunk my-token"


def test_splunk_sink_accepts_bare_token() -> None:
    """SplunkHecAuditSink accepts tokens without 'Splunk ' prefix."""
    import httpx
    import respx

    with respx.mock(base_url="http://splunk:8088") as mock_splunk:
        mock_splunk.post("/services/collector").mock(
            return_value=httpx.Response(200, json={"text": "Success", "code": 0})
        )
        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "bare-token")
        sink.emit(_make_decision())

        req = mock_splunk.calls[0].request
        assert "Splunk bare-token" in req.headers["Authorization"]


def test_splunk_sink_failure_does_not_propagate() -> None:
    with patch("urllib.request.urlopen", side_effect=Exception("network error")):
        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "tok")
        sink.emit(_make_decision())  # must not raise


# ── DatadogAuditSink ──────────────────────────────────────────────────────────


def test_datadog_sink_raises_config_error_without_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "datadog_api_client", None)
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[datadog\\]'"):
        DatadogAuditSink("dd-api-key")


def test_datadog_sink_records_sends_log() -> None:
    """emit() calls logs_api.submit_log with a real HTTPLog payload."""
    # Inject real Datadog model types as module-like namespace objects so that
    # `from datadog_api_client.v2.model.http_log import HTTPLog` resolves to our
    # duck-type class — no MagicMock involved.
    fake_log_mod = types.SimpleNamespace(HTTPLog=_DatadogHTTPLog)
    fake_log_item_mod = types.SimpleNamespace(HTTPLogItem=_DatadogHTTPLogItem)

    with patch.dict(sys.modules, {
        "datadog_api_client.v2.model.http_log": fake_log_mod,
        "datadog_api_client.v2.model.http_log_item": fake_log_item_mod,
    }):
        logs_api = _CapturingLogsApi()
        sink = DatadogAuditSink.__new__(DatadogAuditSink)
        sink._service = "pramanix"
        sink._source = "pramanix-audit"
        sink._tags = ""
        sink._logs_api = logs_api

        sink.emit(_make_decision())

    assert len(logs_api.submit_log_calls) == 1
    payload = logs_api.submit_log_calls[0]
    assert isinstance(payload, _DatadogHTTPLog)
    assert len(payload.items) == 1

