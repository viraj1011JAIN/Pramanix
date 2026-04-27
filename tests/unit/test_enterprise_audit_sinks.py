# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for enterprise audit sinks: Kafka, S3, Splunk, Datadog (E-4)."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

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


def _make_kafka_sink(mock_producer: MagicMock, max_queue: int = 10_000) -> KafkaAuditSink:
    """Build a KafkaAuditSink via __new__ with all required attrs set."""
    import threading
    sink = KafkaAuditSink.__new__(KafkaAuditSink)
    sink._topic = "test-topic"
    sink._producer = mock_producer
    sink._queue_depth = 0
    sink._max_queue = max_queue
    sink._overflow_count = 0
    sink._queue_lock = threading.Lock()
    sink._poll_stop = threading.Event()
    return sink


def test_kafka_sink_records_to_queue() -> None:
    mock_confluent = MagicMock()
    mock_producer = MagicMock()
    mock_confluent.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_confluent}):
        sink = _make_kafka_sink(mock_producer)
        d = _make_decision()
        sink.emit(d)
        mock_producer.produce.assert_called_once()


def test_kafka_sink_overflow_increments_counter() -> None:
    mock_confluent = MagicMock()
    mock_producer = MagicMock()
    mock_confluent.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_confluent}):
        sink = _make_kafka_sink(mock_producer, max_queue=0)
        d = _make_decision()
        sink.emit(d)
        assert sink.overflow_count == 1


def test_kafka_sink_failure_does_not_propagate() -> None:
    mock_confluent = MagicMock()
    mock_producer = MagicMock()
    mock_producer.produce.side_effect = Exception("broker down")
    mock_confluent.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_confluent}):
        sink = _make_kafka_sink(mock_producer)
        # Should not raise
        sink.emit(_make_decision())


# ── S3AuditSink ───────────────────────────────────────────────────────────────


def test_s3_sink_raises_config_error_without_boto3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[s3\\]'"):
        S3AuditSink("my-bucket")


def test_s3_sink_records_puts_object() -> None:
    import concurrent.futures

    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client

    with patch.dict(sys.modules, {"boto3": mock_boto3}):
        sink = S3AuditSink.__new__(S3AuditSink)
        sink._bucket = "test-bucket"
        sink._prefix = "audit/"
        sink._s3 = mock_client
        sink._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

        sink.emit(_make_decision())
        sink._pool.shutdown(wait=True)  # wait for the upload thread
        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"].startswith("audit/")


def test_s3_sink_failure_does_not_propagate() -> None:
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_client.put_object.side_effect = Exception("S3 unavailable")
    mock_boto3.client.return_value = mock_client

    with patch.dict(sys.modules, {"boto3": mock_boto3}):
        sink = S3AuditSink.__new__(S3AuditSink)
        sink._bucket = "bucket"
        sink._prefix = ""
        sink._s3 = mock_client
        # Must not raise
        sink.emit(_make_decision())


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
    from unittest.mock import patch as _patch

    with _patch("urllib.request.urlopen", side_effect=Exception("network error")):
        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "tok")
        # Must not raise
        sink.emit(_make_decision())


# ── DatadogAuditSink ──────────────────────────────────────────────────────────


def test_datadog_sink_raises_config_error_without_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "datadog_api_client", None)
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[datadog\\]'"):
        DatadogAuditSink("dd-api-key")


def test_datadog_sink_records_sends_log() -> None:
    mock_dd = MagicMock()
    mock_config_cls = MagicMock()
    mock_config_instance = MagicMock()
    mock_config_cls.return_value = mock_config_instance
    mock_api_client = MagicMock()
    mock_logs_api = MagicMock()
    mock_logs_api_instance = MagicMock()
    mock_logs_api.return_value = mock_logs_api_instance

    mock_dd.Configuration = mock_config_cls
    mock_dd.ApiClient = MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=mock_api_client), __exit__=MagicMock(return_value=False)))
    mock_dd_v2 = MagicMock()
    mock_dd_v2.LogsApi = mock_logs_api

    with patch.dict(sys.modules, {"datadog_api_client": mock_dd, "datadog_api_client.v2": mock_dd_v2}):
        sink = DatadogAuditSink.__new__(DatadogAuditSink)
        sink._api_key = "dd-test-key"
        sink._service = "pramanix"
        sink._source = "pramanix-audit"
        # Just ensure emit() does not raise
        sink.emit(_make_decision())
