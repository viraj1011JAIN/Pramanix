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
        try:
            self.decisions.append(decision)
        except Exception as exc:
            log.error("InMemoryAuditSink: failed to append decision: %s", exc)

    def clear(self) -> None:
        """Remove all collected decisions."""
        self.decisions.clear()


# ── E-4: Enterprise audit sinks ───────────────────────────────────────────────


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
            from confluent_kafka import Producer  # type: ignore[import-untyped]
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "confluent-kafka is required for KafkaAuditSink. "
                "Install it with: pip install 'pramanix[kafka]'"
            ) from exc

        self._topic = topic
        self._producer: Any = Producer(producer_conf)
        self._max_queue = max_queue_size
        self._queue_depth = 0
        self._overflow_count = 0

    def emit(self, decision: Decision) -> None:
        try:
            if self._queue_depth >= self._max_queue:
                self._overflow_count += 1
                _increment_overflow_metric()
                log.warning(
                    "KafkaAuditSink: queue full (%d), dropping decision %s",
                    self._max_queue,
                    getattr(decision, "decision_id", "?"),
                )
                return
            payload = json.dumps(decision.to_dict(), default=str).encode()
            self._queue_depth += 1

            def _delivery_cb(err: Any, _msg: Any) -> None:
                self._queue_depth = max(0, self._queue_depth - 1)
                if err:
                    log.error("KafkaAuditSink: delivery error: %s", err)

            self._producer.produce(self._topic, value=payload, callback=_delivery_cb)
            self._producer.poll(0)  # non-blocking trigger of delivery callbacks
        except Exception as exc:
            log.error("KafkaAuditSink: failed to produce decision: %s", exc)

    def flush(self, timeout: float = 10.0) -> None:
        """Flush all pending messages to Kafka.  Call at shutdown."""
        try:
            self._producer.flush(timeout)
        except Exception as exc:
            log.error("KafkaAuditSink: flush error: %s", exc)

    @property
    def overflow_count(self) -> int:
        """Number of decisions dropped due to queue overflow since init."""
        return self._overflow_count


def _increment_overflow_metric() -> None:
    """Increment pramanix_audit_sink_overflow_total Prometheus counter."""
    try:
        import prometheus_client as _prom  # type: ignore[import-untyped]

        # Use a module-level singleton counter (registered once).
        global _OVERFLOW_COUNTER  # noqa: PLW0603
        if _OVERFLOW_COUNTER is None:
            try:
                _OVERFLOW_COUNTER = _prom.Counter(
                    "pramanix_audit_sink_overflow_total",
                    "Number of audit decisions dropped due to sink queue overflow",
                )
            except ValueError:
                _OVERFLOW_COUNTER = (
                    _prom.REGISTRY._names_to_collectors.get(  # pyright: ignore[reportAttributeAccessIssue]
                        "pramanix_audit_sink_overflow_total"
                    )
                )
        if _OVERFLOW_COUNTER is not None:
            _OVERFLOW_COUNTER.inc()
    except Exception:
        pass


_OVERFLOW_COUNTER: Any = None


class S3AuditSink:
    """Upload each decision as a JSON object to Amazon S3 (or compatible).

    Each decision is serialised as a JSON string and uploaded as a new object
    ``{prefix}{decision_id}.json``.  Upload failures are logged and swallowed —
    they never propagate to the caller.

    Requires: ``pip install 'pramanix[s3]'`` (``boto3``).

    Args:
        bucket:     S3 bucket name.
        prefix:     Key prefix (e.g. ``"pramanix/audit/"``).  Default: ``""``.
        boto3_kwargs: Additional kwargs forwarded to ``boto3.client("s3", ...)``.

    Raises:
        ConfigurationError: If ``boto3`` is not installed.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        **boto3_kwargs: Any,
    ) -> None:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "boto3 is required for S3AuditSink. "
                "Install it with: pip install 'pramanix[s3]'"
            ) from exc

        self._bucket = bucket
        self._prefix = prefix
        self._s3: Any = boto3.client("s3", **boto3_kwargs)

    def emit(self, decision: Decision) -> None:
        try:
            decision_id = getattr(decision, "decision_id", "unknown")
            key = f"{self._prefix}{decision_id}.json"
            body = json.dumps(decision.to_dict(), default=str).encode()
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
            )
        except Exception as exc:
            log.error("S3AuditSink: failed to upload decision: %s", exc)


class SplunkHecAuditSink:
    """Send decisions to Splunk via the HTTP Event Collector (HEC) API.

    Uses ``urllib.request`` (stdlib) so no extra dependency is required
    beyond the network.  If the HEC endpoint is unavailable, failures are
    logged and swallowed.

    Requires: ``pip install 'pramanix[splunk]'`` — no external package needed
    currently; the extra is reserved for future ``splunklib`` integration.

    Args:
        hec_url:   Full HEC endpoint URL, e.g.
                   ``"https://splunk.corp.example.com:8088/services/collector"``.
        hec_token: Splunk HEC token (``"Splunk <token>`` or bare token).
        index:     Optional Splunk index name.
        sourcetype: Splunk sourcetype.  Default: ``"pramanix:decision"``.
        timeout:   HTTP request timeout in seconds.  Default: 5 s.
    """

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        *,
        index: str | None = None,
        sourcetype: str = "pramanix:decision",
        timeout: float = 5.0,
    ) -> None:
        self._url = hec_url
        # Accept either bare token or "Splunk <token>" format.
        self._auth = (
            hec_token
            if hec_token.startswith("Splunk ")
            else f"Splunk {hec_token}"
        )
        self._index = index
        self._sourcetype = sourcetype
        self._timeout = timeout

    def emit(self, decision: Decision) -> None:
        import urllib.request

        try:
            event: dict[str, Any] = {"event": decision.to_dict()}
            event["sourcetype"] = self._sourcetype
            if self._index:
                event["index"] = self._index
            payload = json.dumps(event, default=str).encode()
            req = urllib.request.Request(
                self._url,
                data=payload,
                headers={
                    "Authorization": self._auth,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout):
                pass
        except Exception as exc:
            log.error("SplunkHecAuditSink: failed to send decision: %s", exc)


class DatadogAuditSink:
    """Send decisions as Datadog logs via the Datadog API.

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
            import datadog_api_client  # type: ignore[import-untyped]  # noqa: F401
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "datadog-api-client is required for DatadogAuditSink. "
                "Install it with: pip install 'pramanix[datadog]'"
            ) from exc

        import os

        self._api_key = api_key or os.environ.get("DD_API_KEY") or ""
        self._site = site
        self._service = service
        self._source = source
        self._tags = tags

    def emit(self, decision: Decision) -> None:
        try:
            from datadog_api_client import ApiClient, Configuration  # type: ignore[import-untyped]
            from datadog_api_client.v2.api.logs_api import LogsApi  # type: ignore[import-untyped]
            from datadog_api_client.v2.model.http_log import HTTPLog  # type: ignore[import-untyped]
            from datadog_api_client.v2.model.http_log_item import HTTPLogItem  # type: ignore[import-untyped]

            configuration = Configuration()
            configuration.api_key["apiKeyAuth"] = self._api_key
            configuration.server_variables["site"] = self._site

            message = json.dumps(decision.to_dict(), default=str)
            log_item = HTTPLogItem(
                ddsource=self._source,
                ddtags=self._tags,
                hostname="pramanix",
                message=message,
                service=self._service,
            )
            body = HTTPLog([log_item])
            with ApiClient(configuration) as api_client:
                LogsApi(api_client).submit_log(body)
        except Exception as exc:
            log.error("DatadogAuditSink: failed to send decision: %s", exc)
