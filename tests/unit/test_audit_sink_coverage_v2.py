# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Targeted coverage tests for audit_sink.py — round 2.

Covers:
  audit_sink._OVERFLOW_COUNTER — prometheus cache-hit path (line 187)
  audit_sink._OVERFLOW_COUNTER — prometheus ImportError path (line 189)
  KafkaAuditSink.__init__ — ImportError / ConfigurationError (240-243)
  KafkaAuditSink._delivery_cb — err=None branch exits without logging (294->exit)
  S3AuditSink.__init__ — ImportError / ConfigurationError (354-357)
  S3AuditSink._worker — queue.Empty + stop_event path (387-390)
  S3AuditSink._worker — pool.submit exception path (396-397)
  SplunkHecAuditSink._send_loop — queue.Empty + stop_event break (520)
  SplunkHecAuditSink.emit — outer except Exception path (555-556)
  DatadogAuditSink.__init__ — ImportError / ConfigurationError (608-611)
  DatadogAuditSink._send_loop — queue.Empty + stop_event break (652)
  DatadogAuditSink.emit — outer except Exception path (687-688)
"""

from __future__ import annotations

import concurrent.futures
import importlib
import queue
import threading
import time
from typing import Any

import pytest

from pramanix.audit_sink import (
    DatadogAuditSink,
    KafkaAuditSink,
    S3AuditSink,
    SplunkHecAuditSink,
)
from pramanix.decision import Decision, SolverStatus
from tests.helpers.real_protocols import (
    _CapturingLogsApi,
    _KafkaDLQProducer,
    _S3Client,
)


def _make_decision(allowed: bool = True) -> Decision:
    return Decision(
        allowed=allowed,
        status=SolverStatus.SAFE if allowed else SolverStatus.UNSAFE,
        violated_invariants=(),
        explanation="test",
    )


def _make_kafka_sink(producer: Any, max_queue: int = 10_000) -> KafkaAuditSink:
    """Create a KafkaAuditSink with a real constructor using injected producer."""
    return KafkaAuditSink(
        topic="test-topic", producer_conf={}, max_queue_size=max_queue, _producer=producer
    )


class _BoomDecision:
    """Decision duck-type whose to_dict() always raises RuntimeError."""

    decision_id = "boom-id"

    def to_dict(self) -> dict:
        raise RuntimeError("to_dict deliberate failure — testing outer except")


# ── Prometheus module-level ImportError path ──────────────────────────────────


class TestPrometheusModuleLevelPaths:
    def test_prometheus_import_error_returns_none(self) -> None:
        """ImportError branch: _init_audit_overflow_counter returns None when
        prometheus_client is unavailable (via DI factory)."""
        from pramanix.audit_sink import _init_audit_overflow_counter

        def _raise_import() -> None:
            raise ImportError("prometheus_client not installed")

        result = _init_audit_overflow_counter(_prom_factory=_raise_import)
        assert result is None

    def test_prometheus_counter_cache_hit_on_reload(self) -> None:
        """Line 197: reloading audit_sink triggers the else branch (cache hit).

        On the first load, the metric is registered and stored in
        _AUDIT_REGISTERED_METRICS.  A subsequent reload finds the existing
        entry and takes the else branch instead of registering again.
        Since audit_sink defines no enums, a reload is safe — no cross-test
        SolverStatus identity contamination.
        """
        import pramanix.audit_sink as _sink_mod

        importlib.reload(_sink_mod)
        assert _sink_mod._OVERFLOW_COUNTER is not None


# ── KafkaAuditSink: ImportError / ConfigurationError ─────────────────────────


class TestKafkaAuditSinkImportError:
    def test_confluent_kafka_absent_raises_configuration_error(self) -> None:
        """ImportError branch: raises ConfigurationError when confluent-kafka absent."""
        from pramanix.audit_sink import KafkaAuditSink
        from pramanix.exceptions import ConfigurationError

        def _raise_import():
            raise ImportError("confluent_kafka not installed")

        with pytest.raises(ConfigurationError, match="confluent-kafka"):
            KafkaAuditSink("topic", {}, _kafka_factory=_raise_import)


# ── S3AuditSink: ImportError / ConfigurationError ────────────────────────────


class TestS3AuditSinkImportError:
    def test_boto3_absent_raises_configuration_error(self) -> None:
        """ImportError branch: raises ConfigurationError when boto3 is absent."""
        from pramanix.audit_sink import S3AuditSink
        from pramanix.exceptions import ConfigurationError

        def _raise_import():
            raise ImportError("boto3 not installed")

        with pytest.raises(ConfigurationError, match="boto3"):
            S3AuditSink("bucket", _boto3_factory=_raise_import)


# ── DatadogAuditSink: ImportError / ConfigurationError ───────────────────────


class TestDatadogAuditSinkImportError:
    def test_datadog_api_client_absent_raises_configuration_error(self) -> None:
        """ImportError branch: raises ConfigurationError when datadog-api-client absent."""
        from pramanix.audit_sink import DatadogAuditSink
        from pramanix.exceptions import ConfigurationError

        def _raise_import():
            raise ImportError("datadog_api_client not installed")

        with pytest.raises(ConfigurationError, match="datadog-api-client"):
            DatadogAuditSink(_datadog_factory=_raise_import)


# ── KafkaAuditSink delivery callback err=None (294->exit) ────────────────────


class TestKafkaDeliveryCallbackBranch:
    def test_delivery_callback_no_error_exits_without_logging(self) -> None:
        """294->exit: _delivery_cb called with err=None skips log.error.

        _KafkaDLQProducer calls the callback synchronously with err=None,
        covering the falsy-err branch that exits the closure without logging.
        """
        producer = _KafkaDLQProducer()  # calls callback(None, msg) immediately
        sink = _make_kafka_sink(producer)
        sink.emit(_make_decision())
        # If we reach here without exception, the callback ran and 294->exit covered.
        assert producer.flush_called is False  # no flush called in emit


# ── S3AuditSink._worker — stop_event paths (lines 387-390) ───────────────────


class TestS3WorkerStopEventPaths:
    def test_worker_continue_and_stop_event_break(self) -> None:
        """Lines 387-390: worker loops on empty queue (continue), then breaks on stop.

        Line 390 (continue): queue.get times out, stop_event NOT set → loop again.
        Lines 387-389 (break): queue.get times out, stop_event IS set → exit.
        Setting stop_event directly (no sentinel) exercises the stop_event
        branch rather than the sentinel branch.
        """
        sink = S3AuditSink.__new__(S3AuditSink)
        sink._bucket = "test-bucket"
        sink._prefix = ""
        sink._s3 = _S3Client()
        sink._max_queue = 1_000
        sink._queue = queue.Queue(maxsize=1_000)
        sink._queue_lock = threading.Lock()
        sink._overflow_count = 0
        sink._stop_event = threading.Event()
        sink._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pramanix-s3-test"
        )
        sink._worker_thread = threading.Thread(
            target=sink._worker,
            daemon=True,
            name="pramanix-s3-stop-test",
        )
        sink._worker_thread.start()

        # Let worker loop at least once with an empty queue → covers `continue` (390)
        time.sleep(0.2)

        # Set stop_event without a sentinel → next queue.Empty sees it → break (389)
        sink._stop_event.set()
        sink._worker_thread.join(timeout=2.0)
        sink._pool.shutdown(wait=False)

        assert not sink._worker_thread.is_alive()


# ── S3AuditSink._worker — pool.submit exception (lines 396-397) ──────────────


class _RaisingSubmitPool:
    """Executor duck-type whose submit() raises RuntimeError — no MagicMock."""

    def submit(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("worker pool rejected task — deliberate test raise")

    def shutdown(self, wait: bool = True, **kwargs: Any) -> None:
        pass


class TestS3WorkerPoolSubmitException:
    def test_worker_pool_submit_exception_is_swallowed(self) -> None:
        """Lines 396-397: worker catches pool.submit() exception and logs it.

        A _RaisingSubmitPool raises on every submit() call so the except
        block at lines 396-397 executes.  A sentinel is then placed so the
        worker exits cleanly.
        """
        sink = S3AuditSink.__new__(S3AuditSink)
        sink._bucket = "test-bucket"
        sink._prefix = ""
        sink._s3 = _S3Client()
        sink._max_queue = 1_000
        q: queue.Queue = queue.Queue(maxsize=1_000)
        sink._queue = q
        sink._queue_lock = threading.Lock()
        sink._overflow_count = 0
        sink._stop_event = threading.Event()
        sink._pool = _RaisingSubmitPool()

        # Put a real item first so the worker tries pool.submit → raises → 396-397 hit.
        q.put_nowait(("audit/test-key.json", b'{"test": true}'))
        # Put a sentinel so the worker exits after the failing item.
        q.put_nowait(None)

        sink._worker_thread = threading.Thread(
            target=sink._worker,
            daemon=True,
            name="pramanix-s3-exc-test",
        )
        sink._worker_thread.start()
        sink._worker_thread.join(timeout=2.0)

        assert not sink._worker_thread.is_alive()


# ── SplunkHecAuditSink._send_loop — stop_event break (line 520) ──────────────


class TestSplunkWorkerStopEventPath:
    def test_send_loop_stops_on_stop_event_without_sentinel(self) -> None:
        """Line 520: _send_loop breaks when stop_event is set and queue is empty.

        Setting _stop_event directly (no sentinel) forces the queue.Empty
        handler to take the `break` branch at line 520 rather than the
        sentinel (`if payload is None: break`) branch.
        """
        sink = SplunkHecAuditSink.__new__(SplunkHecAuditSink)
        sink._url = "http://splunk.test:8088/services/collector"
        sink._auth = "Splunk test-token"
        sink._index = None
        sink._sourcetype = "pramanix:decision"
        sink._timeout = 5.0
        sink._max_queue = 500
        sink._queue_lock = threading.Lock()
        sink._overflow_count = 0
        sink._queue = queue.Queue(maxsize=500)
        sink._stop_event = threading.Event()
        # _client is not set — the send path is never reached (queue is empty).

        # Signal from inside the worker the moment queue.get() is first entered.
        # This eliminates the time.sleep(0.65) race: we set stop_event only
        # AFTER the loop is provably blocked in queue.get(), so the next
        # queue.Empty check is guaranteed to see stop_event=True.
        _loop_entered = threading.Event()
        _orig_get = sink._queue.get

        def _signalling_get(block: bool = True, timeout: float | None = None) -> Any:
            _loop_entered.set()
            return _orig_get(block=block, timeout=timeout)

        sink._queue.get = _signalling_get  # type: ignore[method-assign]

        worker = threading.Thread(
            target=sink._send_loop,
            daemon=True,
            name="pramanix-splunk-stop-test",
        )
        worker.start()

        # Wait until the thread is provably inside queue.get(), then stop it.
        assert _loop_entered.wait(timeout=5.0), "worker never entered send loop"
        sink._stop_event.set()
        worker.join(timeout=2.0)

        assert not worker.is_alive()


# ── SplunkHecAuditSink.emit — outer except Exception (lines 555-556) ─────────


class TestSplunkEmitOuterException:
    def test_emit_swallows_to_dict_exception(self) -> None:
        """Lines 555-556: outer except catches exception from decision.to_dict()."""
        sink = SplunkHecAuditSink.__new__(SplunkHecAuditSink)
        sink._url = "http://splunk.test:8088/services/collector"
        sink._auth = "Splunk test-token"
        sink._index = None
        sink._sourcetype = "pramanix:decision"
        sink._max_queue = 500
        sink._queue = queue.Queue(maxsize=500)
        sink._queue_lock = threading.Lock()
        sink._overflow_count = 0

        # _BoomDecision.to_dict() raises → outer except covers lines 555-556.
        sink.emit(_BoomDecision())  # must not propagate the exception


# ── DatadogAuditSink._send_loop — stop_event break (line 652) ────────────────


class TestDatadogWorkerStopEventPath:
    def test_send_loop_stops_on_stop_event_without_sentinel(self) -> None:
        """Line 652: _send_loop breaks when stop_event is set and queue is empty.

        Requires datadog_api_client because _send_loop imports from it at the
        top of the function body (lazy import inside the function).

        We pre-warm those submodule imports here so the worker thread's
        `from datadog_api_client.v2.model.http_log import HTTPLog` is an
        instant sys.modules cache hit instead of a slow first-import.  Without
        pre-warming the import can take >5 s, defeating the synchronisation
        event that signals when queue.get() has been entered.
        """
        pytest.importorskip("datadog_api_client")

        # Pre-warm the two submodule imports _send_loop does lazily.
        import datadog_api_client.v2.model.http_log
        import datadog_api_client.v2.model.http_log_item  # noqa: F401

        sink = DatadogAuditSink.__new__(DatadogAuditSink)
        sink._service = "pramanix"
        sink._source = "pramanix"
        sink._tags = ""
        sink._max_queue = 500
        sink._queue_lock = threading.Lock()
        sink._overflow_count = 0
        sink._logs_api = _CapturingLogsApi()
        sink._queue = queue.Queue(maxsize=500)
        sink._stop_event = threading.Event()

        # Signal from inside the worker the moment queue.get() is first entered.
        # Because the imports are pre-warmed the thread reaches queue.get()
        # almost immediately, making the synchronisation reliable.
        _loop_entered = threading.Event()
        _orig_get = sink._queue.get

        def _signalling_get(block: bool = True, timeout: float | None = None) -> Any:
            _loop_entered.set()
            return _orig_get(block=block, timeout=timeout)

        sink._queue.get = _signalling_get  # type: ignore[method-assign]

        worker = threading.Thread(
            target=sink._send_loop,
            daemon=True,
            name="pramanix-datadog-stop-test",
        )
        worker.start()

        # Wait until the thread is provably inside queue.get(), then stop it.
        assert _loop_entered.wait(timeout=5.0), "worker never entered send loop"
        sink._stop_event.set()
        worker.join(timeout=2.0)

        assert not worker.is_alive()


# ── DatadogAuditSink.emit — outer except Exception (lines 687-688) ────────────


class TestDatadogEmitOuterException:
    def test_emit_swallows_to_dict_exception(self) -> None:
        """Lines 687-688: outer except catches exception from decision.to_dict()."""
        sink = DatadogAuditSink.__new__(DatadogAuditSink)
        sink._service = "pramanix"
        sink._source = "pramanix"
        sink._tags = ""
        sink._max_queue = 500
        sink._queue = queue.Queue(maxsize=500)
        sink._queue_lock = threading.Lock()
        sink._overflow_count = 0

        # _BoomDecision.to_dict() raises → outer except covers lines 687-688.
        sink.emit(_BoomDecision())  # must not propagate the exception
