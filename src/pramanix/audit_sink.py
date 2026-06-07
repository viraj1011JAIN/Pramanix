# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Pluggable audit sinks for Decision events.

Every Decision produced by :class:`~pramanix.guard.Guard` is emitted to all
configured sinks.  Sink failures are caught and logged — they never propagate
to the caller and never affect the Decision returned.

Built-in sinks
--------------
- :class:`StdoutAuditSink` — structured JSON to stdout (default)
- :class:`InMemoryAuditSink` — collects decisions in a list (testing)

Adding custom sinks::

    from pramanix.audit_sink import AuditSink, InMemoryAuditSink
    from pramanix import Guard, GuardConfig

    sink = InMemoryAuditSink()
    guard = Guard(MyPolicy, GuardConfig(audit_sinks=(sink,)))
    guard.verify(intent={...}, state={...})
    assert len(sink.decisions) == 1
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import logging
import queue
import sys
import threading
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pramanix.decision import Decision

__all__ = [
    "AuditSink",
    "DatadogAuditSink",
    "InMemoryAuditSink",
    "KafkaAuditSink",
    "S3AuditSink",
    "SplunkHecAuditSink",
    "StdoutAuditSink",
]

log = logging.getLogger(__name__)


@runtime_checkable
class AuditSink(Protocol):
    """Protocol for audit sink implementations.

    Every :class:`~pramanix.guard.Guard` emits each
    :class:`~pramanix.decision.Decision` to all configured sinks.  Sink
    failures are **never** propagated to the caller.
    """

    def emit(self, decision: Decision) -> None:
        """Emit a decision to this sink.

        This method must not raise.  Implementations should catch all
        exceptions internally and log them.

        Args:
            decision: The :class:`~pramanix.decision.Decision` to emit.
        """
        ...


class StdoutAuditSink:
    """Emit decisions as JSON-lines to stdout.

    Each line is a complete JSON object containing the decision fields
    (via :meth:`~pramanix.decision.Decision.to_dict`).  Use shell tools
    like ``jq`` to filter and format.

    Example output::

        {"decision_id": "abc123", "allowed": true, "status": "ALLOW", ...}
    """

    def __init__(self, *, stream: Any = None) -> None:
        self._stream = stream or sys.stdout

    def emit(self, decision: Decision) -> None:
        """Serialize decision as a JSON line and write it to the configured stream."""
        try:
            line = json.dumps(decision.to_dict(), default=str)
            print(line, file=self._stream, flush=True)
        except Exception as exc:
            _increment_send_error_metric("stdout")
            log.error("StdoutAuditSink: failed to emit decision: %s", exc, exc_info=True)


class InMemoryAuditSink:
    """Collect emitted decisions in an in-process list.

    Intended for testing.  All emitted decisions are appended to
    :attr:`decisions` in the order they are emitted.  Thread-safe: a
    :class:`threading.Lock` protects all mutations and snapshot reads so that
    concurrent Guard instances don't produce race conditions on test assertions.

    Usage::

        sink = InMemoryAuditSink()
        guard = Guard(policy, GuardConfig(audit_sinks=(sink,)))
        guard.verify(...)
        assert len(sink.decisions) == 1
        assert sink.decisions[0].allowed
    """

    def __init__(self) -> None:
        import os as _os
        import warnings as _w

        if _os.environ.get("PRAMANIX_ENV", "").lower() == "production":
            from pramanix.exceptions import ConfigurationError as _CE

            raise _CE(
                "InMemoryAuditSink is not permitted when PRAMANIX_ENV=production. "
                "All decisions would be lost on process restart. "
                "Configure a persistent AuditSink: KafkaAuditSink, S3AuditSink, "
                "SplunkHecAuditSink, or DatadogAuditSink."
            )
        _w.warn(
            "InMemoryAuditSink is for testing only — all decisions are lost on "
            "process restart. Use a persistent AuditSink (KafkaAuditSink, "
            "S3AuditSink, SplunkHecAuditSink, DatadogAuditSink) in production.",
            UserWarning,
            stacklevel=2,
        )
        self._lock = threading.Lock()
        self._decisions: list[Decision] = []

    @property
    def decisions(self) -> list[Decision]:
        """Thread-safe snapshot copy of all collected decisions."""
        with self._lock:
            return list(self._decisions)

    def emit(self, decision: Decision) -> None:
        """Append decision to the in-memory decisions list."""
        with self._lock:
            self._decisions.append(decision)

    def clear(self) -> None:
        """Remove all collected decisions."""
        with self._lock:
            self._decisions.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._decisions)

    def __getitem__(self, index: int) -> Decision:
        with self._lock:
            return self._decisions[index]


# ── E-4: Enterprise audit sinks ───────────────────────────────────────────────


# §2.1: catch ImportError and ValueError separately — a broad `except Exception`
# silently swallows legitimate programming errors (metric name collision with
# different labelset), which is a real bug that must surface immediately.
_OVERFLOW_COUNTER: Any = None
_SEND_ERROR_COUNTER: Any = None
_AUDIT_METRICS_LOCK = threading.Lock()
_AUDIT_REGISTERED_METRICS: dict[str, Any] = globals().get("_AUDIT_REGISTERED_METRICS", {})


def _init_audit_overflow_counter(_prom_factory: Any = None) -> Any:
    """Register the overflow and send-error Prometheus counters.

    Accepts an optional ``_prom_factory`` callable for dependency injection in
    tests — when provided, the callable is invoked instead of importing
    ``prometheus_client`` so that the ImportError branch can be exercised without
    touching ``sys.modules``.
    """
    global _OVERFLOW_COUNTER, _SEND_ERROR_COUNTER
    try:
        if _prom_factory is not None:
            _prom_init = _prom_factory()
        else:
            import prometheus_client as _prom_init

        with _AUDIT_METRICS_LOCK:
            _ov_name = "pramanix_audit_sink_overflow_total"
            if _ov_name not in _AUDIT_REGISTERED_METRICS:
                _OVERFLOW_COUNTER = _prom_init.Counter(
                    _ov_name,
                    "Number of audit decisions dropped due to sink queue overflow",
                )
                _AUDIT_REGISTERED_METRICS[_ov_name] = _OVERFLOW_COUNTER
            else:
                _OVERFLOW_COUNTER = _AUDIT_REGISTERED_METRICS[_ov_name]

            _err_name = "pramanix_audit_sink_emit_errors_total"
            if _err_name not in _AUDIT_REGISTERED_METRICS:
                _SEND_ERROR_COUNTER = _prom_init.Counter(
                    _err_name,
                    "Number of audit sink send/emit errors by sink type",
                    ["sink"],
                )
                _AUDIT_REGISTERED_METRICS[_err_name] = _SEND_ERROR_COUNTER
            else:
                _SEND_ERROR_COUNTER = _AUDIT_REGISTERED_METRICS[_err_name]

        return _OVERFLOW_COUNTER
    except ImportError:
        return None  # prometheus_client not installed — metrics silently disabled
    except ValueError as _prom_val_err:
        log.warning(
            "pramanix.audit_sink: Prometheus metric registration error "
            "(name collision with different labelset — this is a programming error): %s",
            _prom_val_err,
        )
        return None


_init_audit_overflow_counter()


def _increment_overflow_metric() -> None:
    """Increment pramanix_audit_sink_overflow_total Prometheus counter."""
    try:
        if _OVERFLOW_COUNTER is not None:
            _OVERFLOW_COUNTER.inc()
    except Exception as exc:
        log.warning(
            "pramanix.audit_sink: failed to increment overflow metric: %s", exc, exc_info=True
        )


def _increment_send_error_metric(sink: str) -> None:
    """Increment pramanix_audit_sink_emit_errors_total{sink=...} counter."""
    try:
        if _SEND_ERROR_COUNTER is not None:
            _SEND_ERROR_COUNTER.labels(sink=sink).inc()
    except Exception as exc:
        log.debug("pramanix.audit_sink: failed to increment send_error metric (%s): %s", sink, exc)


class KafkaAuditSink:
    """Emit decisions to a Kafka topic using ``confluent_kafka.Producer``.

    Decisions are serialised as JSON and produced asynchronously.  An internal
    bounded queue (``max_queue_size``, default 10 000) decouples the hot path
    from Kafka back-pressure.  When the queue is full, the overflow metric
    ``pramanix_audit_sink_overflow_total`` is incremented and the decision is
    dropped (never propagated to the caller).

    Requires: ``pip install 'pramanix[kafka]'`` (``confluent-kafka``).

    Args:
        topic:          Kafka topic name.
        producer_conf:  ``confluent_kafka.Producer`` configuration dict
                        (e.g. ``{"bootstrap.servers": "broker:9092"}``).
        max_queue_size: Maximum number of pending decisions.  Default: 10 000.

    Raises:
        ConfigurationError: If ``confluent-kafka`` is not installed.
    """

    def __init__(
        self,
        topic: str,
        producer_conf: dict[str, Any],
        *,
        max_queue_size: int = 10_000,
        _producer: Any = None,
        _kafka_factory: Any = None,
    ) -> None:
        if _producer is None:
            try:
                if _kafka_factory is not None:
                    Producer = _kafka_factory()
                else:
                    from confluent_kafka import Producer
            except ImportError as exc:
                from pramanix.exceptions import ConfigurationError

                raise ConfigurationError(
                    "confluent-kafka is required for KafkaAuditSink. "
                    "Install it with: pip install 'pramanix[kafka]'"
                ) from exc
            self._producer: Any = Producer(producer_conf)
        else:
            self._producer = _producer
        self._topic = topic
        self._max_queue = max_queue_size
        # H-08: protect _queue_depth with a lock — incremented in the emit
        # thread and decremented in the Kafka delivery-callback thread.
        self._queue_lock = threading.Lock()
        self._queue_depth = 0
        self._overflow_count = 0
        # M-15: start a background poller thread so delivery callbacks fire
        # even during idle periods (not only when emit() is called).
        self._poll_stop = threading.Event()
        self._poll_thread = threading.Thread(
            target=self._background_poll,
            daemon=True,
            name="pramanix-kafka-poll",
        )
        self._poll_thread.start()

    def _background_poll(self) -> None:
        """Background thread: poll Kafka delivery callbacks every 100 ms."""
        while not self._poll_stop.is_set():
            try:
                self._producer.poll(timeout=0.1)
            except Exception as exc:
                log.warning("KafkaAuditSink: poll error: %s", exc, exc_info=True)

    def emit(self, decision: Decision) -> None:
        """Emit decision to the Kafka topic."""
        # _depth_incremented tracks whether this call owns the decrement.
        # Set to False once produce() succeeds so the delivery callback takes over.
        # Ensures _queue_depth is decremented even on BaseException (flaw #175).
        _depth_incremented = False
        try:
            with self._queue_lock:
                if self._queue_depth >= self._max_queue:
                    self._overflow_count += 1
                    _increment_overflow_metric()
                    log.warning(
                        "KafkaAuditSink: queue full (%d), dropping decision %s",
                        self._max_queue,
                        getattr(decision, "decision_id", "?"),
                    )
                    return
                self._queue_depth += 1
                _depth_incremented = True

            payload = json.dumps(decision.to_dict(), default=str).encode()

            def _delivery_cb(err: Any, _msg: Any) -> None:
                with self._queue_lock:
                    self._queue_depth = max(0, self._queue_depth - 1)
                if err:
                    log.error("KafkaAuditSink: delivery error: %s", err)

            self._producer.produce(self._topic, value=payload, callback=_delivery_cb)
            _depth_incremented = False  # delivery callback now owns the decrement
        except Exception as exc:
            if _depth_incremented:
                with self._queue_lock:
                    self._queue_depth = max(0, self._queue_depth - 1)
            _increment_send_error_metric("kafka")
            log.error("KafkaAuditSink: failed to produce decision: %s", exc, exc_info=True)
        except BaseException:
            if _depth_incremented:
                with self._queue_lock:
                    self._queue_depth = max(0, self._queue_depth - 1)
            raise

    def flush(self, timeout: float = 10.0) -> None:
        """Flush all pending messages to Kafka.  Call at shutdown."""
        try:
            self._poll_stop.set()
            self._producer.flush(timeout)
        except Exception as exc:
            log.error("KafkaAuditSink: flush error: %s", exc, exc_info=True)

    @property
    def overflow_count(self) -> int:
        """Number of decisions dropped due to queue overflow since init."""
        with self._queue_lock:
            return self._overflow_count


class S3AuditSink:
    """Upload each decision as a JSON object to Amazon S3 (or compatible).

    Each decision is serialised as a JSON string and uploaded as a new object
    ``{prefix}{decision_id}.json``.  Upload failures are logged and never
    propagate to the caller.

    §14.3 fix: uploads use a bounded internal queue (``max_queue_size``, default
    1 000) backed by a thread pool.  When the queue is full the decision is
    dropped and the overflow metric is incremented — identical to KafkaAuditSink.
    This prevents unbounded memory growth under sustained write pressure.

    Requires: ``pip install 'pramanix[s3]'`` (``boto3``).

    Args:
        bucket:         S3 bucket name.
        prefix:         Key prefix (e.g. ``"pramanix/audit/"``).  Default: ``""``.
        timeout:        Per-upload request timeout in seconds.  Default: 30.
        max_queue_size: Maximum number of pending uploads.  Default: 1 000.
        boto3_kwargs:   Additional kwargs forwarded to ``boto3.client("s3", ...)``.

    Raises:
        ConfigurationError: If ``boto3`` is not installed.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        timeout: float = 30.0,
        *,
        max_queue_size: int = 1_000,
        _boto3_factory: Any = None,
        **boto3_kwargs: Any,
    ) -> None:
        try:
            if _boto3_factory is not None:
                _boto3 = _boto3_factory()
            else:
                import importlib as _importlib

                _boto3 = _importlib.import_module("boto3")
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "boto3 is required for S3AuditSink. " "Install it with: pip install 'pramanix[s3]'"
            ) from exc

        self._bucket = bucket
        self._prefix = prefix
        self._timeout = timeout
        self._max_queue = max_queue_size
        self._s3: Any = _boto3.client("s3", **boto3_kwargs)
        # Bounded queue provides backpressure; pool submits are non-blocking.
        self._queue: queue.Queue[tuple[str, bytes] | None] = queue.Queue(maxsize=max_queue_size)
        self._queue_lock = threading.Lock()
        self._overflow_count = 0
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="pramanix-s3"
        )
        # Start dedicated worker thread that drains the bounded queue.
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker,
            daemon=True,
            name="pramanix-s3-worker",
        )
        self._worker_thread.start()

    def _worker(self) -> None:
        """Background thread: drains the upload queue."""
        while True:
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
                continue
            if item is None:
                break  # sentinel received — all queued uploads have been submitted
            key, body = item
            try:
                self._pool.submit(self._upload, key, body)
            except Exception as exc:
                log.error("S3AuditSink: worker error: %s", exc, exc_info=True)

    def emit(self, decision: Decision) -> None:
        """Enqueue S3 upload — never blocks the event loop."""
        try:
            decision_id = getattr(decision, "decision_id", "unknown")
            key = f"{self._prefix}{decision_id}.json"
            body = json.dumps(decision.to_dict(), default=str).encode()
            try:
                self._queue.put_nowait((key, body))
            except queue.Full:
                with self._queue_lock:
                    self._overflow_count += 1
                _increment_overflow_metric()
                log.warning(
                    "S3AuditSink: queue full (%d), dropping decision %s",
                    self._max_queue,
                    decision_id,
                )
        except Exception as exc:
            _increment_send_error_metric("s3")
            log.error("S3AuditSink: failed to enqueue upload: %s", exc, exc_info=True)

    def _upload(self, key: str, body: bytes) -> None:
        try:
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
            )
        except Exception as exc:
            _increment_send_error_metric("s3")
            log.error("S3AuditSink: failed to upload decision: %s", exc, exc_info=True)

    @classmethod
    def _for_testing(
        cls,
        s3_client: Any,
        *,
        bucket: str = "test-bucket",
        prefix: str = "",
        max_queue_size: int = 1_000,
        start_worker: bool = True,
    ) -> S3AuditSink:
        """Construct a fully-wired instance without real AWS credentials.

        Accepts an already-constructed S3 client duck-type so tests can
        inject fake/stub clients without requiring boto3 or real credentials.
        Pass ``start_worker=False`` when the test manages the worker itself.
        """
        inst = cls.__new__(cls)
        inst._bucket = bucket
        inst._prefix = prefix
        inst._timeout = 30.0
        inst._max_queue = max_queue_size
        inst._s3 = s3_client
        inst._queue = queue.Queue(maxsize=max_queue_size)
        inst._queue_lock = threading.Lock()
        inst._overflow_count = 0
        inst._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pramanix-s3-test"
        )
        inst._stop_event = threading.Event()
        inst._worker_thread = threading.Thread(
            target=inst._worker,
            daemon=True,
            name="pramanix-s3-test-worker",
        )
        if start_worker:
            inst._worker_thread.start()
        return inst

    @property
    def overflow_count(self) -> int:
        """Number of decisions dropped due to queue overflow since init."""
        with self._queue_lock:
            return self._overflow_count

    def close(self) -> None:
        """Shut down the upload worker and thread pool.  Call at application teardown."""
        # Put the sentinel BEFORE setting stop_event to guarantee all queued
        # uploads are submitted before the worker exits.  Setting stop_event
        # first would allow the worker to exit via the `except queue.Empty`
        # branch before draining pending items — identical fix to Splunk/Datadog.
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)  # sentinel to unblock and drain worker
        self._stop_event.set()
        self._worker_thread.join(timeout=5.0)
        if self._worker_thread.is_alive():
            log.warning(
                "S3AuditSink: worker thread did not exit within 5 s during close() — "
                "some in-flight uploads may be lost.  Proceeding with thread pool shutdown.",
            )
        self._pool.shutdown(wait=True, cancel_futures=False)


class SplunkHecAuditSink:
    """Send decisions to Splunk via the HTTP Event Collector (HEC) API.

    §7.1 fix: ``emit()`` is **non-blocking**.  HTTP calls are submitted to a
    bounded background thread pool — a slow or unreachable Splunk server
    never stalls the Guard's ``verify()`` hot path.

    Requires: ``pip install 'pramanix[splunk]'`` (``httpx``).

    Args:
        hec_url:        Full HEC endpoint URL.
        hec_token:      Splunk HEC token (``"Splunk <token>"`` or bare token).
        index:          Optional Splunk index name.
        sourcetype:     Splunk sourcetype.  Default: ``"pramanix:decision"``.
        timeout:        HTTP request timeout in seconds.  Default: 5 s.
        ca_bundle:      Path to a CA bundle for private TLS deployments.
        max_queue_size: Maximum pending HTTP calls.  Default: 500.
    """

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        *,
        index: str | None = None,
        sourcetype: str = "pramanix:decision",
        timeout: float = 5.0,
        ca_bundle: str | None = None,
        max_queue_size: int = 500,
    ) -> None:
        try:
            import httpx
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "httpx is required for SplunkHecAuditSink. "
                "Install it with: pip install 'pramanix[splunk]'"
            ) from exc

        self._url = hec_url
        self._auth = hec_token if hec_token.startswith("Splunk ") else f"Splunk {hec_token}"
        self._index = index
        self._sourcetype = sourcetype
        self._timeout = timeout
        self._max_queue = max_queue_size
        self._queue_lock = threading.Lock()
        self._overflow_count = 0
        # Persistent blocking httpx.Client shared by background threads only.
        # The event loop (verify hot path) never touches this client directly.
        self._client = httpx.Client(
            verify=ca_bundle if ca_bundle is not None else True,
            timeout=timeout,
        )
        self._queue: queue.Queue[bytes | None] = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._worker = threading.Thread(
            target=self._send_loop,
            daemon=True,
            name="pramanix-splunk-worker",
        )
        self._worker.start()

    def _send_loop(self) -> None:
        """Background thread: serialises HTTP calls to Splunk HEC."""
        while True:
            try:
                payload = self._queue.get(timeout=0.5)
            except queue.Empty:
                # No items; check stop signal (belt-and-suspenders for empty queue).
                if self._stop_event.is_set():
                    break
                continue
            if payload is None:
                break  # sentinel received — all queued events have been processed
            try:
                resp = self._client.post(
                    self._url,
                    content=payload,
                    headers={
                        "Authorization": self._auth,
                        "Content-Type": "application/json",
                    },
                )
                # HTTP-level errors (401 rotated token, 429 rate-limit, 503
                # HEC backpressure) do NOT raise — check the status code so
                # decisions are never silently dropped on non-2xx responses
                # (#171).
                if resp.status_code >= 400:
                    _increment_send_error_metric("splunk")
                    log.error(
                        "SplunkHecAuditSink: HTTP %d from HEC endpoint — "
                        "decision may be lost. Check token/index config.",
                        resp.status_code,
                    )
            except Exception as exc:
                _increment_send_error_metric("splunk")
                log.error("SplunkHecAuditSink: send error: %s", exc, exc_info=True)

    def emit(self, decision: Decision) -> None:
        """Enqueue decision for async delivery to Splunk — never blocks caller."""
        try:
            event: dict[str, Any] = {"event": decision.to_dict()}
            event["sourcetype"] = self._sourcetype
            if self._index:
                event["index"] = self._index
            payload = json.dumps(event, default=str).encode()
            try:
                self._queue.put_nowait(payload)
            except queue.Full:
                with self._queue_lock:
                    self._overflow_count += 1
                _increment_overflow_metric()
                log.warning(
                    "SplunkHecAuditSink: queue full (%d), dropping decision %s",
                    self._max_queue,
                    getattr(decision, "decision_id", "?"),
                )
        except Exception as exc:
            log.error("SplunkHecAuditSink: failed to enqueue decision: %s", exc, exc_info=True)

    @classmethod
    def _for_testing(
        cls,
        http_client: Any,
        *,
        url: str = "http://localhost:8088/services/collector",
        token: str = "Splunk test-token",  # noqa: S107 — test-factory default, not a real credential
        index: str | None = None,
        sourcetype: str = "pramanix:decision",
        max_queue_size: int = 500,
        start_worker: bool = True,
    ) -> SplunkHecAuditSink:
        """Construct a fully-wired instance without real Splunk credentials.

        Accepts an already-constructed HTTP client duck-type so tests can
        inject fakes without requiring httpx or a running Splunk HEC endpoint.
        Pass ``start_worker=False`` when the test needs to manage the
        background thread itself (e.g. to instrument ``_send_loop`` directly).
        """
        inst = cls.__new__(cls)
        inst._url = url
        inst._auth = token if token.startswith("Splunk ") else f"Splunk {token}"
        inst._index = index
        inst._sourcetype = sourcetype
        inst._timeout = 5.0
        inst._max_queue = max_queue_size
        inst._queue_lock = threading.Lock()
        inst._overflow_count = 0
        inst._client = http_client
        inst._queue = queue.Queue(maxsize=max_queue_size)
        inst._stop_event = threading.Event()
        inst._worker = threading.Thread(
            target=inst._send_loop,
            daemon=True,
            name="pramanix-splunk-test-worker",
        )
        if start_worker:
            inst._worker.start()
        return inst

    def close(self) -> None:
        """Flush pending events and close the HTTP client.  Call at shutdown."""
        # Put the sentinel BEFORE setting stop_event to guarantee every enqueued
        # event is delivered before the worker exits.  Setting stop_event first
        # would allow the worker to exit the `while True` loop via the
        # `except queue.Empty` branch before draining pending items.
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)
        self._stop_event.set()  # unblocks any in-progress queue.get() timeout
        self._worker.join(timeout=10.0)
        try:
            self._client.close()
        except Exception as exc:
            log.warning("SplunkHecAuditSink: error closing HTTP client: %s", exc, exc_info=True)


class DatadogAuditSink:
    """Send decisions as Datadog logs via the Datadog API.

    §7.2 fix: ``emit()`` is **non-blocking**.  The synchronous Datadog SDK
    HTTP call runs in a background thread pool so the Guard hot path is never
    stalled by slow Datadog ingestion.

    Requires: ``pip install 'pramanix[datadog]'`` (``datadog-api-client``).

    Args:
        api_key:        Datadog API key.  Falls back to ``DD_API_KEY`` env var.
        site:           Datadog site (e.g. ``"datadoghq.com"``).
        service:        Datadog service tag.  Default: ``"pramanix"``.
        source:         Datadog source tag.  Default: ``"pramanix"``.
        tags:           Additional comma-separated tags.
        max_queue_size: Maximum pending SDK calls.  Default: 500.

    Raises:
        ConfigurationError: If ``datadog-api-client`` is not installed.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        site: str = "datadoghq.com",
        service: str = "pramanix",
        source: str = "pramanix",
        tags: str = "",
        max_queue_size: int = 500,
        _datadog_factory: Any = None,
    ) -> None:
        try:
            if _datadog_factory is not None:
                ApiClient, Configuration, LogsApi = _datadog_factory()
            else:
                from datadog_api_client import ApiClient, Configuration
                from datadog_api_client.v2.api.logs_api import LogsApi
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "datadog-api-client is required for DatadogAuditSink. "
                "Install it with: pip install 'pramanix[datadog]'"
            ) from exc

        import os

        self._service = service
        self._source = source
        self._tags = tags
        self._max_queue = max_queue_size
        self._queue_lock = threading.Lock()
        self._overflow_count = 0

        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = api_key or os.environ.get("DD_API_KEY") or ""
        configuration.server_variables["site"] = site

        self._api_client = ApiClient(configuration)
        self._logs_api = LogsApi(self._api_client)

        # Bounded queue + background pool so emit() never blocks the hot path.
        self._queue: queue.Queue[str | None] = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._worker = threading.Thread(
            target=self._send_loop,
            daemon=True,
            name="pramanix-datadog-worker",
        )
        self._worker.start()

    def _send_loop(self) -> None:
        """Background thread: serialises Datadog SDK calls."""
        from datadog_api_client.v2.model.http_log import HTTPLog
        from datadog_api_client.v2.model.http_log_item import HTTPLogItem

        while True:
            try:
                message = self._queue.get(timeout=0.5)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
                continue
            if message is None:
                break  # sentinel received — all queued events have been processed
            try:
                log_item = HTTPLogItem(
                    ddsource=self._source,
                    ddtags=self._tags,
                    hostname="pramanix",
                    message=message,
                    service=self._service,
                )
                resp = self._logs_api.submit_log(HTTPLog([log_item]))
                # submit_log() returns an ApiResponse; check HTTP status to
                # catch auth failures (403), rate limits (429), and upstream
                # errors (5xx) that do NOT raise exceptions (#172).
                status = getattr(resp, "status", None) or getattr(
                    getattr(resp, "http_info", None), "status", None
                )
                if status is not None and status >= 400:
                    _increment_send_error_metric("datadog")
                    log.error(
                        "DatadogAuditSink: HTTP %d from API — decision may be lost.",
                        status,
                    )
            except Exception as exc:
                _increment_send_error_metric("datadog")
                log.error(
                    "DatadogAuditSink: send error: %s (%.120s)",
                    type(exc).__name__,
                    str(exc).split("\n")[0],
                )

    def emit(self, decision: Decision) -> None:
        """Enqueue decision for async delivery to Datadog — never blocks caller."""
        try:
            message = json.dumps(decision.to_dict(), default=str)
            try:
                self._queue.put_nowait(message)
            except queue.Full:
                with self._queue_lock:
                    self._overflow_count += 1
                _increment_overflow_metric()
                log.warning(
                    "DatadogAuditSink: queue full (%d), dropping decision %s",
                    self._max_queue,
                    getattr(decision, "decision_id", "?"),
                )
        except Exception as exc:
            log.error("DatadogAuditSink: failed to enqueue decision: %s", exc, exc_info=True)

    @classmethod
    def _for_testing(
        cls,
        logs_api: Any,
        api_client: Any,
        *,
        service: str = "pramanix-test",
        source: str = "pramanix",
        tags: str = "",
        max_queue_size: int = 500,
        start_worker: bool = True,
    ) -> DatadogAuditSink:
        """Construct a fully-wired instance without real Datadog credentials.

        Accepts already-constructed logs_api and api_client duck-types so
        tests can inject fakes without requiring datadog-api-client or
        a real Datadog account.
        """
        inst = cls.__new__(cls)
        inst._service = service
        inst._source = source
        inst._tags = tags
        inst._max_queue = max_queue_size
        inst._queue_lock = threading.Lock()
        inst._overflow_count = 0
        inst._api_client = api_client
        inst._logs_api = logs_api
        inst._queue = queue.Queue(maxsize=max_queue_size)
        inst._stop_event = threading.Event()
        inst._worker = threading.Thread(
            target=inst._send_loop,
            daemon=True,
            name="pramanix-datadog-test-worker",
        )
        if start_worker:
            inst._worker.start()
        return inst

    def close(self) -> None:
        """Flush pending events and close the Datadog client.  Call at shutdown."""
        # Put the sentinel BEFORE setting stop_event to guarantee all enqueued
        # events are delivered before the worker exits.
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)
        self._stop_event.set()
        self._worker.join(timeout=10.0)
        try:
            self._api_client.close()
        except Exception as exc:
            log.warning("DatadogAuditSink: error closing API client: %s", exc, exc_info=True)
