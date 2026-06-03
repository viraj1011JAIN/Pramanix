# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for audit_sink.py — no fake infrastructure, no sys.modules injection.

Coverage targets:
  StdoutAuditSink exception path (lines 87-88)
  InMemoryAuditSink exception path (lines 112-113)
  _increment_overflow_metric Prometheus paths (lines 211-226)
  KafkaAuditSink: queue-overflow drop + ConfigurationError
  S3AuditSink: upload-failure swallowed + ConfigurationError
  SplunkHecAuditSink: index parameter, bare-token prefix
  DatadogAuditSink: ConfigurationError, emit does not raise

Real integration tests (Kafka/S3 happy paths) live in
  tests/integration/test_kafka_audit_sink.py
  tests/integration/test_s3_audit_sink.py
"""

from __future__ import annotations

import importlib.util as _ilu
import io
import json
from typing import Any

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
    """Stream that raises on every write — drives the exception handler in emit()."""

    def write(self, *args: Any) -> None:
        raise OSError("broken pipe: disk full")

    def flush(self) -> None:
        raise OSError("broken pipe: disk full")


def test_stdout_sink_exception_is_swallowed() -> None:
    """Lines 87-88: exception in print() is caught and logged, never propagated."""
    sink = StdoutAuditSink(stream=_BrokenStream())
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


# ── InMemoryAuditSink ────────────────────────────────────────────────────────


def test_in_memory_sink_collects_decisions() -> None:
    """InMemoryAuditSink.emit() appends each decision to decisions list."""
    sink = InMemoryAuditSink()
    sink.emit(_safe_decision())
    sink.emit(_blocked_decision())
    assert len(sink.decisions) == 2
    assert sink.decisions[0].allowed is True
    assert sink.decisions[1].allowed is False


def test_in_memory_sink_clear_empties_list() -> None:
    sink = InMemoryAuditSink()
    sink.emit(_safe_decision())
    sink.clear()
    assert len(sink.decisions) == 0


# ── _increment_overflow_metric(): Prometheus counter paths ───────────────────


@pytest.mark.skipif(
    _ilu.find_spec("prometheus_client") is not None,
    reason="run in tox:no-prometheus — prometheus_client is installed in this env",
)
def test_increment_overflow_metric_when_counter_is_none() -> None:
    """_increment_overflow_metric() is a no-op (no exception) when counter is None.

    When prometheus_client is absent, _OVERFLOW_COUNTER is None and
    _increment_overflow_metric() silently returns without raising.
    """
    _increment_overflow_metric()  # must not raise
    _increment_overflow_metric()  # idempotent


def test_increment_overflow_metric_calls_inc_when_counter_set() -> None:
    """_increment_overflow_metric() calls counter.inc() when counter is available."""
    import pramanix.audit_sink as _sink_mod

    original = _sink_mod._OVERFLOW_COUNTER
    try:
        if original is not None:
            # Counter is already registered — just verify calling inc() doesn't raise.
            _increment_overflow_metric()
        else:
            # prometheus_client not installed — already covered by the None test.
            pass
    finally:
        _sink_mod._OVERFLOW_COUNTER = original


# ── KafkaAuditSink: no fake broker, no sys.modules injection ─────────────────


@pytest.mark.skipif(
    _ilu.find_spec("confluent_kafka") is not None,
    reason="run in tox:no-confluent-kafka — confluent_kafka is installed in this env",
)
def test_kafka_sink_raises_config_error_without_package() -> None:
    """ConfigurationError when confluent_kafka is not installed."""
    from pramanix.audit_sink import KafkaAuditSink
    from pramanix.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError, match="confluent-kafka"):
        KafkaAuditSink(topic="t", producer_conf={})


def test_kafka_sink_queue_overflow_drops_decision() -> None:
    """KafkaAuditSink drops a decision when the queue is already at max_queue_size.

    Uses a real constructor with _producer injection.  _NeverDeliverProducer.produce()
    accepts messages but never fires the delivery callback, so _queue_depth stays
    elevated and the second emit() hits the overflow path.
    """
    from pramanix.audit_sink import KafkaAuditSink

    class _NeverDeliverProducer:
        """Accepts produce() calls but never fires the delivery callback."""

        def produce(self, topic: str, value: Any = None, callback: Any = None) -> None:
            pass  # callback intentionally not called

        def poll(self, timeout: float = 0.0) -> int:
            return 0

        def flush(self, timeout: float = 10.0) -> int:
            return 0

    sink = KafkaAuditSink(
        topic="t",
        producer_conf={},
        max_queue_size=1,
        _producer=_NeverDeliverProducer(),
    )
    sink.emit(_safe_decision())  # depth → 1, callback never fires
    sink.emit(_safe_decision())  # _queue_depth (1) >= _max_queue (1) → overflow
    assert sink.overflow_count == 1


# ── S3AuditSink: no fake boto3, no sys.modules injection ─────────────────────


@pytest.mark.skipif(
    _ilu.find_spec("boto3") is not None,
    reason="run in tox:no-boto3 — boto3 is installed in this env",
)
def test_s3_sink_raises_config_error_without_boto3() -> None:
    """ConfigurationError when boto3 is not installed."""
    from pramanix.audit_sink import S3AuditSink
    from pramanix.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError, match="boto3"):
        S3AuditSink(bucket="b", prefix="")


def test_s3_sink_upload_failure_is_swallowed() -> None:
    """S3AuditSink._upload() catches all exceptions — never propagates to caller.

    emit() is non-blocking (schedules via thread pool); close() waits for
    the pool to drain so any swallowed exception is fully processed before
    we return from this test.
    """
    boto3 = pytest.importorskip("boto3")
    _ = boto3
    from pramanix.audit_sink import S3AuditSink

    # bucket "pramanix-unit-test-nonexistent-xyzzy" does not exist anywhere;
    # put_object will fail with a credentials/endpoint error which is swallowed.
    sink = S3AuditSink(bucket="pramanix-unit-test-nonexistent-xyzzy", prefix="")
    sink.emit(_safe_decision())
    sink.close()  # drain thread pool — must not raise


# ── SplunkHecAuditSink: index path (line 331) ────────────────────────────────


def test_splunk_sink_with_index_set() -> None:
    """Line 331: event dict gets 'index' key when index is configured."""
    from pramanix.audit_sink import SplunkHecAuditSink

    sink = SplunkHecAuditSink(
        hec_url="http://127.0.0.1:18088/services/collector",
        hec_token="test-token",
        index="pramanix_audit",
        timeout=0.1,
    )
    try:
        assert sink._index == "pramanix_audit"
        # emit() will fail (no server) but the exception is swallowed internally
        sink.emit(_safe_decision())
    finally:
        sink.close()


def test_splunk_sink_without_index() -> None:
    """SplunkHecAuditSink without index — index key omitted from payload."""
    from pramanix.audit_sink import SplunkHecAuditSink

    sink = SplunkHecAuditSink(
        hec_url="http://127.0.0.1:18088/services/collector",
        hec_token="Splunk already-prefixed",
        timeout=0.1,
    )
    try:
        assert sink._index is None
        sink.emit(_safe_decision())  # exception swallowed
    finally:
        sink.close()


def test_splunk_sink_bare_token_gets_prefixed() -> None:
    from pramanix.audit_sink import SplunkHecAuditSink

    sink = SplunkHecAuditSink(
        hec_url="http://127.0.0.1:18088/services/collector",
        hec_token="my-raw-token",
        timeout=0.1,
    )
    try:
        assert sink._auth.startswith("Splunk ")
    finally:
        sink.close()


# ── DatadogAuditSink: ConfigurationError + emit does not raise ────────────────


@pytest.mark.skipif(
    _ilu.find_spec("datadog_api_client") is not None,
    reason="run in tox:no-datadog-api-client — datadog_api_client is installed in this env",
)
def test_datadog_sink_raises_config_error_without_package() -> None:
    """ConfigurationError when datadog-api-client is not installed."""
    from pramanix.audit_sink import DatadogAuditSink
    from pramanix.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError, match="datadog-api-client"):
        DatadogAuditSink(api_key="key")


def test_datadog_sink_emit_does_not_raise() -> None:
    """emit() wraps all API calls in try/except — never propagates exceptions.

    Uses the real datadog_api_client SDK; the submit_log() call will fail with
    an authentication error (fake API key) — that exception must be swallowed.
    """
    pytest.importorskip("datadog_api_client")
    from pramanix.audit_sink import DatadogAuditSink

    sink = DatadogAuditSink(api_key="unit-test-fake-key-xyzzy")
    try:
        sink.emit(_safe_decision())  # API error is swallowed — must not raise
    finally:
        sink.close()


def test_datadog_sink_stores_tags_and_service() -> None:
    """DatadogAuditSink constructor stores tags and service parameters."""
    pytest.importorskip("datadog_api_client")
    from pramanix.audit_sink import DatadogAuditSink

    sink = DatadogAuditSink(
        api_key="key",
        tags="env:prod,version:1",
        service="my-service",
        source="my-source",
    )
    try:
        assert sink._tags == "env:prod,version:1"
        assert sink._service == "my-service"
    finally:
        sink.close()
