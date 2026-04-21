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
    "InMemoryAuditSink",
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
