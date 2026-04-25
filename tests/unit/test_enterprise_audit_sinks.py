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


def test_kafka_sink_records_to_queue() -> None:
    mock_confluent = MagicMock()
    mock_producer = MagicMock()
    mock_confluent.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_confluent}):
        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._topic = "test-topic"
        sink._producer = mock_producer
        sink._queue_depth = 0
        sink._max_queue = 10_000
        sink._overflow_count = 0

        d = _make_decision()
        sink.emit(d)
        mock_producer.produce.assert_called_once()
        mock_producer.poll.assert_called_once_with(0)


def test_kafka_sink_overflow_increments_counter() -> None:
    mock_confluent = MagicMock()
    mock_producer = MagicMock()
    mock_confluent.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_confluent}):
        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._topic = "test-topic"
        sink._producer = mock_producer
        sink._queue_depth = 0
        sink._max_queue = 0  # full from the start
        sink._overflow_count = 0

        d = _make_decision()
        sink.emit(d)
        assert sink.overflow_count == 1


def test_kafka_sink_failure_does_not_propagate() -> None:
    mock_confluent = MagicMock()
    mock_producer = MagicMock()
    mock_producer.produce.side_effect = Exception("broker down")
    mock_confluent.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_confluent}):
        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._topic = "test-topic"
        sink._producer = mock_producer
        sink._queue_depth = 0
        sink._max_queue = 10_000
        sink._overflow_count = 0
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
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client

    with patch.dict(sys.modules, {"boto3": mock_boto3}):
        sink = S3AuditSink.__new__(S3AuditSink)
        sink._bucket = "test-bucket"
        sink._prefix = "audit/"
        sink._s3 = mock_client

        sink.emit(_make_decision())
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


def test_splunk_sink_records_sends_http(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch as _patch

    responses = []

    def fake_urlopen(req, timeout=None):
        responses.append(req)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    with _patch("urllib.request.urlopen", fake_urlopen):
        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "my-token")
        sink.emit(_make_decision())

    assert len(responses) == 1
    req = responses[0]
    assert req.get_header("Authorization") == "Splunk my-token"


def test_splunk_sink_accepts_bare_token() -> None:
    """SplunkHecAuditSink accepts tokens without 'Splunk ' prefix."""
    from unittest.mock import patch as _patch

    with _patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = mock_resp

        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "bare-token")
        sink.emit(_make_decision())

    call_args = mock_open.call_args[0][0]
    assert "Splunk bare-token" in call_args.get_header("Authorization")


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
