# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""FlowEnforcer — stateful enforcement of information-flow policies."""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from pramanix.exceptions import FlowViolationError
from pramanix.ifc.flow_policy import FlowPolicy
from pramanix.ifc.labels import ClassifiedData, TrustLabel

__all__ = ["FlowEnforcer"]

_log = logging.getLogger(__name__)


class FlowEnforcer:
    """Stateful enforcer that applies a :class:`FlowPolicy` to data transitions.

    The enforcer is the runtime gate that every data movement should pass
    through.  It:

    1. Evaluates the flow against the active :class:`FlowPolicy`.
    2. Applies a redaction callable when the policy demands it.
    3. Records every enforcement decision in an in-memory audit log
       (flushed to ``audit_sink`` if configured).
    4. Emits structured WARNING logs for every denied flow so that SIEM
       systems can detect data-leakage attempts.

    Args:
        policy:     The :class:`FlowPolicy` to enforce.
        audit_sink: Optional callable receiving ``(ClassifiedData, str, bool)``
                    for every enforcement event — ``(data, sink_component, permitted)``.

    Thread-safety: all public methods are thread-safe.

    Example::

        enforcer = FlowEnforcer(FlowPolicy.regulated())

        user_input = ClassifiedData(
            data="send $500 to Bob",
            label=TrustLabel.UNTRUSTED,
            source="user_input",
        )

        # Gate: can UNTRUSTED data reach the LLM extractor?
        safe = enforcer.gate(
            user_input,
            sink_label=TrustLabel.UNTRUSTED,
            sink_component="llm_extractor",
        )
        # OK — same-label flow

        # Gate: can UNTRUSTED data directly reach the executor?
        enforcer.gate(
            user_input,
            sink_label=TrustLabel.INTERNAL,
            sink_component="executor",
        )  # raises FlowViolationError
    """

    def __init__(
        self,
        policy: FlowPolicy,
        *,
        audit_sink: Callable[[ClassifiedData, str, bool], None] | None = None,
    ) -> None:
        self._policy = policy
        self._audit_sink = audit_sink
        self._lock = threading.Lock()
        # Audit trail: list of (source_label, sink_label, sink_component, permitted)
        self._audit_log: list[dict[str, object]] = []

    # ── Core gate ─────────────────────────────────────────────────────────

    def gate(
        self,
        data: ClassifiedData,
        *,
        sink_label: TrustLabel,
        sink_component: str,
        redactor: Callable[[Any], Any] | None = None,
    ) -> ClassifiedData:
        """Enforce the flow policy; return (possibly redacted) data or raise.

        Args:
            data:            The :class:`ClassifiedData` being moved.
            sink_label:      The trust label of the destination.
            sink_component:  Name of the receiving component.
            redactor:        If the policy requires redaction, this callable
                             is applied to ``data.data`` before passing it on.
                             If redaction is required but no redactor is
                             provided, :exc:`FlowViolationError` is raised.

        Returns:
            The original :class:`ClassifiedData` (possibly downgraded if
            redaction was applied) with the sink component appended to lineage.

        Raises:
            FlowViolationError: When the flow is denied or when redaction is
                required but no *redactor* was provided.
        """
        decision = self._policy.evaluate(
            data_label=data.label,
            sink_label=sink_label,
            source_component=data.source,
            sink_component=sink_component,
        )

        self._record(data, sink_label, sink_component, decision.permitted)

        if not decision.permitted:
            _log.warning(
                "ifc.flow_denied: %s → %s (%s → %s): %s",
                data.label.name,
                sink_label.name,
                data.source,
                sink_component,
                decision.reason,
            )
            raise FlowViolationError(
                f"Flow denied: {data.label.name} data from '{data.source}' "
                f"may not flow to '{sink_component}' (label={sink_label.name}). "
                f"Reason: {decision.reason}",
                source_label=data.label,
                sink_label=sink_label,
                sink_component=sink_component,
                rule=decision.matched_rule,
            )

        if decision.requires_redaction:
            if redactor is None:
                raise FlowViolationError(
                    f"Flow from {data.label.name} to '{sink_component}' requires "
                    "redaction, but no redactor was provided.",
                    source_label=data.label,
                    sink_label=sink_label,
                    sink_component=sink_component,
                    rule=decision.matched_rule,
                )
            result = data.downgrade(sink_label, redactor)
            _log.debug(
                "ifc.flow_redacted: %s → %s (%s → %s)",
                data.label.name,
                sink_label.name,
                data.source,
                sink_component,
            )
            return result

        return data.taint(sink_component)

    def check(
        self,
        data: ClassifiedData,
        *,
        sink_label: TrustLabel,
        sink_component: str,
    ) -> bool:
        """Non-raising check: return True if the flow would be permitted.

        Useful for pre-flight checks before assembling a data pipeline.
        Does NOT record an audit event (use :meth:`gate` for enforced flows).
        """
        decision = self._policy.evaluate(
            data_label=data.label,
            sink_label=sink_label,
            source_component=data.source,
            sink_component=sink_component,
        )
        return decision.permitted

    # ── Audit ─────────────────────────────────────────────────────────────

    def audit_log(self) -> list[dict[str, object]]:
        """Return a copy of all recorded enforcement events."""
        with self._lock:
            return list(self._audit_log)

    def clear_audit_log(self) -> None:
        """Discard all recorded enforcement events."""
        with self._lock:
            self._audit_log.clear()

    # ── Internal ──────────────────────────────────────────────────────────

    def _record(
        self,
        data: ClassifiedData,
        sink_label: TrustLabel,
        sink_component: str,
        permitted: bool,
    ) -> None:
        entry: dict[str, object] = {
            "source_label": data.label.name,
            "sink_label": sink_label.name,
            "source_component": data.source,
            "sink_component": sink_component,
            "permitted": permitted,
            "lineage": list(data.lineage),
        }
        with self._lock:
            self._audit_log.append(entry)
        if self._audit_sink is not None:
            try:
                self._audit_sink(data, sink_component, permitted)
            except Exception as exc:
                _log.error("ifc.audit_sink_error: %s", exc)
