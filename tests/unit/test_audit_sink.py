# SPDX-License-Identifier: AGPL-3.0-only
# Phase E-4: Tests for AuditSink implementations and GuardConfig integration
"""Verifies audit sinks emit decisions and failures never affect callers."""
from __future__ import annotations

import io

from pramanix import Guard, GuardConfig
from pramanix.audit_sink import AuditSink, InMemoryAuditSink, StdoutAuditSink
from pramanix.decision import Decision
from pramanix.expressions import E, Field
from pramanix.policy import Policy


class _SimplePolicy(Policy):
    amount = Field("amount", int, "Int")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


def _make_guard(*sinks: AuditSink) -> Guard:
    return Guard(
        _SimplePolicy,
        config=GuardConfig(execution_mode="sync", audit_sinks=tuple(sinks)),
    )


class TestInMemoryAuditSink:
    """InMemoryAuditSink collects decisions."""

    def test_allow_decision_collected(self) -> None:
        sink = InMemoryAuditSink()
        guard = _make_guard(sink)
        guard.verify(intent={"amount": 10}, state={})
        assert len(sink.decisions) == 1
        assert sink.decisions[0].allowed

    def test_block_decision_collected(self) -> None:
        sink = InMemoryAuditSink()
        guard = _make_guard(sink)
        guard.verify(intent={"amount": -1}, state={})
        assert len(sink.decisions) == 1
        assert not sink.decisions[0].allowed

    def test_multiple_decisions_collected(self) -> None:
        sink = InMemoryAuditSink()
        guard = _make_guard(sink)
        guard.verify(intent={"amount": 5}, state={})
        guard.verify(intent={"amount": -5}, state={})
        assert len(sink.decisions) == 2
        assert sink.decisions[0].allowed
        assert not sink.decisions[1].allowed

    def test_clear_empties_list(self) -> None:
        sink = InMemoryAuditSink()
        guard = _make_guard(sink)
        guard.verify(intent={"amount": 1}, state={})
        sink.clear()
        assert len(sink.decisions) == 0

    def test_decisions_are_decision_instances(self) -> None:
        sink = InMemoryAuditSink()
        guard = _make_guard(sink)
        guard.verify(intent={"amount": 7}, state={})
        assert isinstance(sink.decisions[0], Decision)

    def test_no_sinks_configured_does_not_raise(self) -> None:
        guard = _make_guard()
        d = guard.verify(intent={"amount": 5}, state={})
        assert d.allowed


class TestStdoutAuditSink:
    """StdoutAuditSink emits JSON-lines."""

    def test_emits_json_line(self) -> None:
        stream = io.StringIO()
        sink = StdoutAuditSink(stream=stream)
        guard = _make_guard(sink)
        guard.verify(intent={"amount": 10}, state={})
        output = stream.getvalue().strip()
        assert output.startswith("{")
        assert '"allowed"' in output

    def test_block_decision_emitted(self) -> None:
        stream = io.StringIO()
        sink = StdoutAuditSink(stream=stream)
        guard = _make_guard(sink)
        guard.verify(intent={"amount": -5}, state={})
        output = stream.getvalue()
        assert "false" in output.lower() or '"allowed": false' in output

    def test_multiple_decisions_multiple_lines(self) -> None:
        stream = io.StringIO()
        sink = StdoutAuditSink(stream=stream)
        guard = _make_guard(sink)
        guard.verify(intent={"amount": 1}, state={})
        guard.verify(intent={"amount": 2}, state={})
        lines = [ln for ln in stream.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 2


class TestMultipleSinks:
    """Multiple sinks all receive decisions."""

    def test_two_sinks_both_receive(self) -> None:
        s1 = InMemoryAuditSink()
        s2 = InMemoryAuditSink()
        guard = _make_guard(s1, s2)
        guard.verify(intent={"amount": 5}, state={})
        assert len(s1.decisions) == 1
        assert len(s2.decisions) == 1

    def test_second_sink_receives_even_if_first_fails(self) -> None:
        class _FailingSink:
            def emit(self, decision: Decision) -> None:
                raise RuntimeError("boom")

        s2 = InMemoryAuditSink()
        guard = _make_guard(_FailingSink(), s2)  # type: ignore[arg-type]
        # Should not raise even though first sink fails
        d = guard.verify(intent={"amount": 5}, state={})
        assert d.allowed
        assert len(s2.decisions) == 1

    def test_sink_failure_does_not_affect_decision(self) -> None:
        class _BrokenSink:
            def emit(self, decision: Decision) -> None:
                raise ValueError("deliberate failure")

        guard = _make_guard(_BrokenSink())  # type: ignore[arg-type]
        d = guard.verify(intent={"amount": 100}, state={})
        assert d.allowed


class TestAuditSinkProtocol:
    """AuditSink is a runtime-checkable Protocol."""

    def test_in_memory_satisfies_protocol(self) -> None:
        sink = InMemoryAuditSink()
        assert isinstance(sink, AuditSink)

    def test_stdout_satisfies_protocol(self) -> None:
        sink = StdoutAuditSink()
        assert isinstance(sink, AuditSink)

    def test_custom_sink_satisfies_protocol(self) -> None:
        class _MySink:
            def emit(self, decision: Decision) -> None:
                pass

        assert isinstance(_MySink(), AuditSink)
