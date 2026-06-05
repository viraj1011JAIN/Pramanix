# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for enterprise audit sinks: Kafka, S3, Splunk, Datadog (E-4)."""

from __future__ import annotations

import pytest

from pramanix.audit_sink import (
    DatadogAuditSink,
    InMemoryAuditSink,
    KafkaAuditSink,
    S3AuditSink,
    SplunkHecAuditSink,
)
from pramanix.decision import Decision, SolverStatus
from tests.helpers.real_protocols import (
    _CapturingLogsApi,
    _CapturingProducer,
    _ErrorS3Client,
    _FakeApiClient,
    _FakeHttpxClient,
    _FakeLogsApi,
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


def _make_kafka_sink(producer: _CapturingProducer, max_queue: int = 10_000) -> KafkaAuditSink:
    """Build a KafkaAuditSink with a real constructor using injected producer."""
    return KafkaAuditSink(
        topic="test-topic", producer_conf={}, max_queue_size=max_queue, _producer=producer
    )


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


def test_s3_sink_records_puts_object() -> None:
    s3 = _S3Client()
    sink = S3AuditSink._for_testing(s3, prefix="audit/")

    sink.emit(_make_decision())
    sink.close()  # drains queue, joins worker, shuts down pool

    assert len(s3.put_object_calls) == 1
    call_kwargs = s3.put_object_calls[0]
    assert call_kwargs["Bucket"] == "test-bucket"
    assert call_kwargs["Key"].startswith("audit/")


def test_s3_sink_failure_does_not_propagate() -> None:
    s3 = _ErrorS3Client()
    sink = S3AuditSink._for_testing(s3)
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
        # Drain background worker INSIDE mock context so the HTTP call is
        # intercepted before respx deactivates the transport mock.
        sink.close()

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
        sink.close()  # drain before respx context exits

        req = mock_splunk.calls[0].request
        assert "Splunk bare-token" in req.headers["Authorization"]


def test_splunk_sink_failure_does_not_propagate() -> None:
    import httpx
    import respx

    with respx.mock(base_url="http://splunk:8088"):
        respx.post("http://splunk:8088/services/collector").mock(
            side_effect=httpx.ConnectError("network error")
        )
        sink = SplunkHecAuditSink("http://splunk:8088/services/collector", "tok")
        sink.emit(_make_decision())  # must not raise
        sink.close()


# ── DatadogAuditSink ──────────────────────────────────────────────────────────


def test_datadog_sink_records_sends_log() -> None:
    """emit() calls logs_api.submit_log with a real HTTPLog payload."""
    pytest.importorskip("datadog_api_client")
    logs_api = _CapturingLogsApi()
    # _for_testing() starts the background worker automatically.
    sink = DatadogAuditSink._for_testing(logs_api, _FakeApiClient())

    sink.emit(_make_decision())
    sink.close()

    assert len(logs_api.submit_log_calls) == 1
    assert logs_api.submit_log_calls[0] is not None


# ── InMemoryAuditSink __len__ / __getitem__ ───────────────────────────────────


def test_in_memory_sink_len_uses_dunder() -> None:
    """len(sink) delegates to __len__, not len(sink.decisions)."""
    sink = InMemoryAuditSink()
    assert len(sink) == 0
    sink.emit(_make_decision())
    assert len(sink) == 1


def test_in_memory_sink_getitem_returns_decision() -> None:
    """sink[0] returns the first emitted decision via __getitem__."""
    sink = InMemoryAuditSink()
    d = _make_decision()
    sink.emit(d)
    assert sink[0] is d


# ── S3AuditSink overflow + upload error ──────────────────────────────────────


def test_s3_sink_emit_overflow_increments_counter() -> None:
    """emit() increments overflow_count and does NOT raise when queue is full."""
    s3 = _S3Client()
    # start_worker=False: overflow detection happens in emit(), no worker needed.
    sink = S3AuditSink._for_testing(s3, max_queue_size=1, start_worker=False)
    # Pre-fill the queue so the next put_nowait raises queue.Full.
    sink._queue.put_nowait(("blocker_key", b"blocker_body"))

    sink.emit(_make_decision())  # queue is full so put_nowait raises queue.Full
    assert sink.overflow_count == 1


def test_s3_sink_overflow_count_property_thread_safe() -> None:
    """overflow_count property returns the current overflow count safely."""
    sink = S3AuditSink._for_testing(_S3Client(), start_worker=False)
    sink._overflow_count = 7  # simulate accumulated overflow
    assert sink.overflow_count == 7


def test_s3_upload_failure_swallowed() -> None:
    """_upload() logs the exception from put_object and does NOT raise."""
    s3 = _ErrorS3Client()
    sink = S3AuditSink._for_testing(s3)
    sink.emit(_make_decision())  # _upload will raise, but must be swallowed
    sink.close()
    # The ErrorS3Client always raises — verify no exception propagated.
    # (No assertion on put_object_calls; the error path IS the test.)


# ── SplunkHecAuditSink overflow ───────────────────────────────────────────────


def test_splunk_sink_overflow_drops_silently() -> None:
    """emit() increments overflow_count and does NOT raise when Splunk queue full."""
    # start_worker=False: overflow detection in emit(), no worker needed.
    sink = SplunkHecAuditSink._for_testing(_FakeHttpxClient(), max_queue_size=1, start_worker=False)
    sink._queue.put_nowait(b"blocker")  # fill the single-item queue

    sink.emit(_make_decision())
    assert sink._overflow_count == 1


# ── DatadogAuditSink overflow + close error swallowing ───────────────────────


def test_datadog_sink_overflow_drops_silently() -> None:
    """emit() increments overflow_count and does NOT raise when Datadog queue full."""
    # start_worker=False: overflow detection in emit(), no worker needed.
    sink = DatadogAuditSink._for_testing(_FakeLogsApi(), _FakeApiClient(), max_queue_size=1, start_worker=False)
    sink._queue.put_nowait("blocker")  # fill the single-item queue

    sink.emit(_make_decision())
    assert sink._overflow_count == 1


def test_datadog_sink_close_swallows_api_client_error() -> None:
    """close() joins the worker and swallows api_client.close() failures."""
    pytest.importorskip("datadog_api_client")
    logs_api = _CapturingLogsApi()

    class _BrokenApiClient:
        def close(self) -> None:
            raise RuntimeError("connection reset")

    sink = DatadogAuditSink._for_testing(logs_api, _BrokenApiClient())
    # close() must NOT propagate the RuntimeError from _api_client.close()
    sink.close()
