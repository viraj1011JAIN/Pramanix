from pramanix.expressions import Field, E
from pramanix.transpiler import analyze_string_promotions
from pramanix.worker import WorkerPool
from pramanix.exceptions import WorkerError
from pramanix.policy import Policy
from unittest.mock import MagicMock
import pytest

def test_analyze_string_promotions_disqualified_continue():
    from pramanix.expressions import ConstraintExpr
    s = Field("s", "String")
    invariants = [
        ConstraintExpr(E(s) == "ok", label="inv1"),
        ConstraintExpr(E(s).startswith("x"), label="inv2")
    ]
    promotions = analyze_string_promotions(invariants)
    assert "s" not in promotions

class DummyPolicy(Policy):
    @classmethod
    def invariants(cls):
        return []

def test_worker_pool_worker_error():
    pool = WorkerPool(mode="async-thread", max_workers=1, max_decisions_per_worker=10, warmup=False)
    pool.spawn()
    
    # Mock executor to raise WorkerError on submit
    pool._executor.submit = MagicMock(side_effect=WorkerError("mock error"))
    
    with pytest.raises(WorkerError):
        pool.submit_solve(DummyPolicy, {}, 1000)
    pool.shutdown(wait=False)

def test_worker_pool_async_process_normal_unseal():
    pool = WorkerPool(mode="async-process", max_workers=1, max_decisions_per_worker=10, warmup=False)
    pool.spawn()
    decision = pool.submit_solve(DummyPolicy, {}, 1000)
    assert decision.allowed is True
    pool.shutdown(wait=False)

def test_kafka_audit_sink_delivery_err():
    from pramanix.audit_sink import KafkaAuditSink
    from pramanix.decision import Decision
    from unittest.mock import patch
    import sys

    # Mock confluent_kafka module completely to avoid ImportError
    mock_ck = MagicMock()
    mock_producer = MagicMock()
    mock_ck.Producer.return_value = mock_producer

    with patch.dict(sys.modules, {"confluent_kafka": mock_ck}):
        sink = KafkaAuditSink("test_topic", {"bootstrap.servers": "localhost"})
        sink.emit(Decision.safe())

        # The produce method takes a callback
        # Find the callback and call it with an error
        kwargs = mock_producer.produce.call_args.kwargs
        cb = kwargs["callback"]
        
        # Test error case (231->exit)
        with patch("pramanix.audit_sink.log.error") as mock_log:
            cb(Exception("delivery failed"), None)
            mock_log.assert_called_with("KafkaAuditSink: delivery error: %s", Exception("delivery failed"))
        
        # Test poll exception
        def side_effect(*args, **kwargs):
            sink._poll_stop.set()
            raise Exception("poll error")
        
        mock_producer.poll.side_effect = side_effect
        with patch("pramanix.audit_sink.log.warning") as mock_warn:
            sink._background_poll()
            mock_warn.assert_called_with("KafkaAuditSink: poll error: %s", Exception("poll error"))

