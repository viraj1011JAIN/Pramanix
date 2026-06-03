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
    import concurrent.futures
    import queue
    import threading

    s3 = _S3Client()
    sink = S3AuditSink.__new__(S3AuditSink)
    sink._bucket = "test-bucket"
    sink._prefix = "audit/"
    sink._s3 = s3
    sink._max_queue = 1_000
    sink._queue: queue.Queue = queue.Queue(maxsize=1_000)
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0
    sink._stop_event = threading.Event()
    sink._pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=4, thread_name_prefix="pramanix-s3-test"
    )
    # Start the real worker thread so the queue is drained properly.
    sink._worker_thread = threading.Thread(
        target=sink._worker, daemon=True, name="pramanix-s3-test-worker"
    )
    sink._worker_thread.start()

    sink.emit(_make_decision())
    sink.close()  # drains queue, joins worker, shuts down pool

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
    import queue
    import threading

    logs_api = _CapturingLogsApi()
    sink = DatadogAuditSink.__new__(DatadogAuditSink)
    sink._service = "pramanix"
    sink._source = "pramanix-audit"
    sink._tags = ""
    sink._max_queue = 500
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0
    sink._logs_api = logs_api
    # Start a real background worker so emit() can be processed.
    sink._queue: queue.Queue = queue.Queue(maxsize=500)
    sink._stop_event = threading.Event()
    sink._worker = threading.Thread(target=sink._send_loop, daemon=True, name="pramanix-dd-test")
    sink._worker.start()

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
    import queue
    import threading

    s3 = _S3Client()
    sink = S3AuditSink.__new__(S3AuditSink)
    sink._bucket = "bucket"
    sink._prefix = ""
    sink._s3 = s3
    sink._max_queue = 1
    # Pre-fill the queue with a blocker so the next put_nowait raises queue.Full.
    # No worker thread is needed — overflow detection happens entirely in emit().
    sink._queue = queue.Queue(maxsize=1)
    sink._queue.put_nowait(("blocker_key", b"blocker_body"))
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0

    sink.emit(_make_decision())  # queue is full so put_nowait raises queue.Full
    assert sink.overflow_count == 1


def test_s3_sink_overflow_count_property_thread_safe() -> None:
    """overflow_count property returns the current overflow count safely."""
    import threading

    sink = S3AuditSink.__new__(S3AuditSink)
    sink._overflow_count = 7
    sink._queue_lock = threading.Lock()
    assert sink.overflow_count == 7


def test_s3_upload_failure_swallowed() -> None:
    """_upload() logs the exception from put_object and does NOT raise."""
    import concurrent.futures
    import queue
    import threading

    s3 = _ErrorS3Client()
    sink = S3AuditSink.__new__(S3AuditSink)
    sink._bucket = "bucket"
    sink._prefix = ""
    sink._s3 = s3
    sink._max_queue = 1_000
    sink._queue = queue.Queue(maxsize=1_000)
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0
    sink._stop_event = threading.Event()
    sink._pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    sink._worker_thread = threading.Thread(
        target=sink._worker, daemon=True, name="pramanix-s3-err-test"
    )
    sink._worker_thread.start()

    sink.emit(_make_decision())  # _upload will raise, but must be swallowed
    sink.close()
    # The ErrorS3Client always raises — verify no exception propagated.
    # (No assertion on put_object_calls; the error path IS the test.)


# ── SplunkHecAuditSink overflow ───────────────────────────────────────────────


def test_splunk_sink_overflow_drops_silently() -> None:
    """emit() increments overflow_count and does NOT raise when Splunk queue full."""
    import queue as _queue
    import threading

    sink = SplunkHecAuditSink.__new__(SplunkHecAuditSink)
    sink._url = "http://splunk:8088/services/collector"
    sink._auth = "Splunk test-token"
    sink._index = None
    sink._sourcetype = "pramanix:decision"
    sink._max_queue = 1
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0
    # Pre-fill queue so the next emit() call hits queue.Full.
    sink._queue: _queue.Queue = _queue.Queue(maxsize=1)
    sink._queue.put_nowait(b"blocker")

    sink.emit(_make_decision())
    assert sink._overflow_count == 1


# ── DatadogAuditSink overflow + close error swallowing ───────────────────────


def test_datadog_sink_overflow_drops_silently() -> None:
    """emit() increments overflow_count and does NOT raise when Datadog queue full."""
    import queue as _queue
    import threading

    sink = DatadogAuditSink.__new__(DatadogAuditSink)
    sink._service = "pramanix"
    sink._source = "pramanix"
    sink._tags = ""
    sink._max_queue = 1
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0
    sink._queue: _queue.Queue = _queue.Queue(maxsize=1)
    sink._queue.put_nowait("blocker")

    sink.emit(_make_decision())
    assert sink._overflow_count == 1


def test_datadog_sink_close_swallows_api_client_error() -> None:
    """close() joins the worker and swallows api_client.close() failures."""
    pytest.importorskip("datadog_api_client")
    import queue as _queue
    import threading

    logs_api = _CapturingLogsApi()

    class _BrokenApiClient:
        def close(self) -> None:
            raise RuntimeError("connection reset")

    sink = DatadogAuditSink.__new__(DatadogAuditSink)
    sink._service = "svc"
    sink._source = "src"
    sink._tags = ""
    sink._max_queue = 500
    sink._queue_lock = threading.Lock()
    sink._overflow_count = 0
    sink._logs_api = logs_api
    sink._api_client = _BrokenApiClient()
    sink._queue: _queue.Queue = _queue.Queue(maxsize=500)
    sink._stop_event = threading.Event()
    sink._worker = threading.Thread(
        target=sink._send_loop, daemon=True, name="pramanix-dd-close-err-test"
    )
    sink._worker.start()

    # close() must NOT propagate the RuntimeError from _api_client.close()
    sink.close()
