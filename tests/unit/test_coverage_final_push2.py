import logging
import sys
from unittest.mock import patch

import pytest

from pramanix.exceptions import WorkerError
from pramanix.expressions import E, Field
from pramanix.policy import Policy
from pramanix.transpiler import analyze_string_promotions
from pramanix.worker import WorkerPool
from tests.helpers.real_protocols import (
    _KafkaAuditModule,
    _KafkaAuditProducer,
    _RaisingSubmitExecutor,
)


def test_analyze_string_promotions_disqualified_continue():
    from pramanix.expressions import ConstraintExpr
    s = Field("s", str, "String")
    invariants = [
        ConstraintExpr(E(s) == "ok", label="inv1"),
        ConstraintExpr(E(s).starts_with("x"), label="inv2"),
    ]
    promotions = analyze_string_promotions(invariants)
    assert "s" not in promotions


class DummyPolicy(Policy):
    @classmethod
    def invariants(cls):
        return []


def test_worker_pool_worker_error():
    pool = WorkerPool(
        mode="async-thread",
        max_workers=1,
        max_decisions_per_worker=10,
        warmup=False,
    )
    pool.spawn()
    pool._executor = _RaisingSubmitExecutor(WorkerError("submit failed"))
    with pytest.raises(WorkerError):
        pool.submit_solve(DummyPolicy, {}, 1000)
    pool.shutdown(wait=False)


@pytest.mark.slow
def test_worker_pool_async_process_normal_unseal():
    pool = WorkerPool(
        mode="async-process",
        max_workers=1,
        max_decisions_per_worker=10,
        warmup=False,
    )
    pool.spawn()
    decision = pool.submit_solve(DummyPolicy, {}, 30_000)  # 30s solver + 60s host = 90s deadline
    assert decision.allowed is True
    pool.shutdown(wait=False)


def test_kafka_audit_sink_delivery_err(caplog):
    from pramanix.audit_sink import KafkaAuditSink
    from pramanix.decision import Decision

    producer = _KafkaAuditProducer()
    kafka_mod = _KafkaAuditModule(producer)

    with patch.dict(sys.modules, {"confluent_kafka": kafka_mod}):  # type: ignore[arg-type]
        sink = KafkaAuditSink("test_topic", {"bootstrap.servers": "localhost"})

        # Stop the background poll thread so it doesn't interfere
        sink._poll_stop.set()
        sink._poll_thread.join(timeout=2.0)

        # Emit a decision so produce() is called and the callback is registered
        with caplog.at_level(logging.ERROR, logger="pramanix.audit_sink"):
            sink.emit(Decision.safe())
            assert producer._last_callback is not None
            producer._last_callback(Exception("delivery failed"), None)
        assert "delivery error" in caplog.text
        assert "delivery failed" in caplog.text

        # Test _background_poll exception path — reset stop event for the direct call
        sink._poll_stop.clear()

        def _poll_se() -> None:
            sink._poll_stop.set()
            raise Exception("poll error")

        producer._poll_side_effect = _poll_se
        with caplog.at_level(logging.WARNING, logger="pramanix.audit_sink"):
            sink._background_poll()
        assert "poll error" in caplog.text
