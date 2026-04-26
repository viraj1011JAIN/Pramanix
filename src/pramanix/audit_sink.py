# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
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

import json
import logging
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
        try:
            line = json.dumps(decision.to_dict(), default=str)
            print(line, file=self._stream, flush=True)
        except Exception as exc:
            log.error("StdoutAuditSink: failed to emit decision: %s", exc)


class InMemoryAuditSink:
    """Collect emitted decisions in an in-process list.

    Intended for testing.  All emitted decisions are appended to
    :attr:`decisions` in the order they are emitted.

    Usage::

        sink = InMemoryAuditSink()
        guard = Guard(policy, GuardConfig(audit_sinks=(sink,)))
        guard.verify(...)
        assert len(sink.decisions) == 1
        assert sink.decisions[0].allowed
    """

    def __init__(self) -> None:
        self.decisions: list[Decision] = []

    def emit(self, decision: Decision) -> None:
        # L-07: list.append() cannot raise under normal conditions; the try/except
        # added no value and has been removed.
        self.decisions.append(decision)

    def clear(self) -> None:
        """Remove all collected decisions."""
        self.decisions.clear()


# ── E-4: Enterprise audit sinks ───────────────────────────────────────────────


# L-08: initialise the overflow counter at module load time to avoid the racy
# lazy-init pattern (two threads both passing the `is None` check).
_OVERFLOW_COUNTER: Any = None
try:
    import prometheus_client as _prom_init

    _OVERFLOW_COUNTER = _prom_init.Counter(
        "pramanix_audit_sink_overflow_total",
        "Number of audit decisions dropped due to sink queue overflow",
    )
except Exception:
    pass  # prometheus_client not installed or already registered


def _increment_overflow_metric() -> None:
    """Increment pramanix_audit_sink_overflow_total Prometheus counter."""
    try:
        if _OVERFLOW_COUNTER is not None:
            _OVERFLOW_COUNTER.inc()
    except Exception as exc:
        log.warning(
            "pramanix.audit_sink: failed to increment overflow metric: %s", exc
        )


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
    ) -> None:
        try:
            from confluent_kafka import Producer
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "confluent-kafka is required for KafkaAuditSink. "
                "Install it with: pip install 'pramanix[kafka]'"
            ) from exc

        self._topic = topic
        self._producer: Any = Producer(producer_conf)
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
                log.warning("KafkaAuditSink: poll error: %s", exc)

    def emit(self, decision: Decision) -> None:
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

            payload = json.dumps(decision.to_dict(), default=str).encode()

            def _delivery_cb(err: Any, _msg: Any) -> None:
                with self._queue_lock:
                    self._queue_depth = max(0, self._queue_depth - 1)
                if err:
                    log.error("KafkaAuditSink: delivery error: %s", err)

            self._producer.produce(self._topic, value=payload, callback=_delivery_cb)
        except Exception as exc:
            with self._queue_lock:
                self._queue_depth = max(0, self._queue_depth - 1)
            log.error("KafkaAuditSink: failed to produce decision: %s", exc)

    def flush(self, timeout: float = 10.0) -> None:
        """Flush all pending messages to Kafka.  Call at shutdown."""
        try:
            self._poll_stop.set()
            self._producer.flush(timeout)
        except Exception as exc:
            log.error("KafkaAuditSink: flush error: %s", exc)

    @property
    def overflow_count(self) -> int:
        """Number of decisions dropped due to queue overflow since init."""
        return self._overflow_count


class S3AuditSink:
    """Upload each decision as a JSON object to Amazon S3 (or compatible).

    Each decision is serialised as a JSON string and uploaded as a new object
    ``{prefix}{decision_id}.json``.  Upload failures are logged and swallowed —
    they never propagate to the caller.

    H-09: uploads run in a thread-pool executor so the event loop is never
    blocked by the synchronous ``boto3.put_object`` call.

    Requires: ``pip install 'pramanix[s3]'`` (``boto3``).

    Args:
        bucket:     S3 bucket name.
        prefix:     Key prefix (e.g. ``"pramanix/audit/"``).  Default: ``""``.
        timeout:    Per-upload request timeout in seconds.  Default: 30.
        boto3_kwargs: Additional kwargs forwarded to ``boto3.client("s3", ...)``.

    Raises:
        ConfigurationError: If ``boto3`` is not installed.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        timeout: float = 30.0,
        **boto3_kwargs: Any,
    ) -> None:
        try:
            import boto3
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "boto3 is required for S3AuditSink. "
                "Install it with: pip install 'pramanix[s3]'"
            ) from exc

        self._bucket = bucket
        self._prefix = prefix
        self._timeout = timeout
        self._s3: Any = boto3.client("s3", **boto3_kwargs)
        self._executor = threading.Thread  # type annotation placeholder
        import concurrent.futures
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="pramanix-s3"
        )

    def emit(self, decision: Decision) -> None:
        """Schedule S3 upload in a thread — never blocks the event loop."""
        try:
            decision_id = getattr(decision, "decision_id", "unknown")
            key = f"{self._prefix}{decision_id}.json"
            body = json.dumps(decision.to_dict(), default=str).encode()
            self._pool.submit(self._upload, key, body)
        except Exception as exc:
            log.error("S3AuditSink: failed to schedule upload: %s", exc)

    def _upload(self, key: str, body: bytes) -> None:
        try:
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
            )
        except Exception as exc:
            log.error("S3AuditSink: failed to upload decision: %s", exc)

    def close(self) -> None:
        """Shut down the upload thread pool.  Call at application teardown."""
        self._pool.shutdown(wait=True)


class SplunkHecAuditSink:
    """Send decisions to Splunk via the HTTP Event Collector (HEC) API.

    H-10: uses ``httpx`` (already a dependency) instead of the blocking
    ``urllib.request.urlopen`` so the event loop is never stalled.  A
    persistent ``httpx.Client`` is reused across calls for connection pooling.

    Requires: ``pip install 'pramanix[splunk]'`` (``httpx``).

    Args:
        hec_url:    Full HEC endpoint URL.
        hec_token:  Splunk HEC token (``"Splunk <token>"`` or bare token).
        index:      Optional Splunk index name.
        sourcetype: Splunk sourcetype.  Default: ``"pramanix:decision"``.
        timeout:    HTTP request timeout in seconds.  Default: 5 s.
        ca_bundle:  Path to a CA bundle for private TLS deployments.
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
        self._auth = (
            hec_token if hec_token.startswith("Splunk ") else f"Splunk {hec_token}"
        )
        self._index = index
        self._sourcetype = sourcetype
        self._timeout = timeout
        # Persistent connection pool — reused across all emit() calls.
        self._client = httpx.Client(
            verify=ca_bundle if ca_bundle is not None else True,
            timeout=timeout,
        )

    def emit(self, decision: Decision) -> None:
        try:
            event: dict[str, Any] = {"event": decision.to_dict()}
            event["sourcetype"] = self._sourcetype
            if self._index:
                event["index"] = self._index
            payload = json.dumps(event, default=str).encode()
            self._client.post(
                self._url,
                content=payload,
                headers={
                    "Authorization": self._auth,
                    "Content-Type": "application/json",
                },
            )
        except Exception as exc:
            log.error("SplunkHecAuditSink: failed to send decision: %s", exc)

    def close(self) -> None:
        """Close the underlying HTTP client.  Call at application teardown."""
        try:
            self._client.close()
        except Exception:
            pass


class DatadogAuditSink:
    """Send decisions as Datadog logs via the Datadog API.

    M-16: ``ApiClient`` and ``LogsApi`` are constructed once in ``__init__``
    and reused across all ``emit()`` calls, eliminating per-call object
    allocation overhead and connection churn.

    Requires: ``pip install 'pramanix[datadog]'`` (``datadog-api-client``).

    Args:
        api_key:   Datadog API key.  Falls back to ``DD_API_KEY`` env var.
        site:      Datadog site (e.g. ``"datadoghq.com"``).  Default: ``"datadoghq.com"``.
        service:   Datadog service tag.  Default: ``"pramanix"``.
        source:    Datadog source tag.  Default: ``"pramanix"``.
        tags:      Additional comma-separated tags, e.g. ``"env:prod,version:2"``.

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
    ) -> None:
        try:
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

        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = api_key or os.environ.get("DD_API_KEY") or ""
        configuration.server_variables["site"] = site

        # M-16: construct ApiClient and LogsApi once, reuse across all emit() calls.
        self._api_client = ApiClient(configuration)
        self._logs_api = LogsApi(self._api_client)

    def emit(self, decision: Decision) -> None:
        try:
            from datadog_api_client.v2.model.http_log import HTTPLog
            from datadog_api_client.v2.model.http_log_item import HTTPLogItem

            message = json.dumps(decision.to_dict(), default=str)
            log_item = HTTPLogItem(
                ddsource=self._source,
                ddtags=self._tags,
                hostname="pramanix",
                message=message,
                service=self._service,
            )
            self._logs_api.submit_log(HTTPLog([log_item]))
        except Exception as exc:
            log.error("DatadogAuditSink: failed to send decision: %s", exc)

    def close(self) -> None:
        """Close the Datadog API client.  Call at application teardown."""
        try:
            self._api_client.close()
        except Exception:
            pass
