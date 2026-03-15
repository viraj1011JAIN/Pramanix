# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Shared feedback string formatters for all ecosystem integrations.

Security note: these formatters NEVER leak invariant DSL source code,
Z3 expressions, Policy class internals, or field definitions.  They only
surface the human-readable .explain() templates and invariant labels that
the policy author has explicitly chosen to expose.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision

__all__ = ["format_block_feedback", "format_autogen_rejection"]


def _format_intent_values(intent: dict[str, Any]) -> str:
    """Format intent dict as ``key=val; key2=val2`` pairs (safe, no DSL exposure)."""
    return "; ".join(f"{k}={v}" for k, v in intent.items())


def format_block_feedback(decision: Decision, intent: dict[str, Any]) -> str:
    """Return a compact one-line block message suitable for tool output.

    This formatter is intentionally minimal: it surfaces only the invariant
    *labels* that the policy author chose to name (via ``.named()``) and the
    human-readable ``.explain()`` text.  No Z3 internals, DSL source code, or
    Field definitions are included.

    Format::

        ACTION BLOCKED by Pramanix. Violated rules: {rules}: {explanation}. Current values: {k=v; ...}.

    Args:
        decision: A :class:`~pramanix.decision.Decision` with ``allowed=False``.
        intent:   The raw intent dict that was verified.

    Returns:
        A single-line string safe to return as tool output or HTTP body text.
    """
    rules = (
        ", ".join(decision.violated_invariants)
        if decision.violated_invariants
        else "policy violation"
    )
    explanation = decision.explanation or "Action blocked by safety policy."
    values_str = _format_intent_values(intent)
    return (
        f"ACTION BLOCKED by Pramanix. "
        f"Violated rules: {rules}: {explanation}. "
        f"Current values: {values_str}."
    )


def format_autogen_rejection(decision: Decision, intent: dict[str, Any]) -> str:
    """Return a structured multi-line rejection message for AutoGen agent context.

    Designed to be inserted as an agent message so that the orchestrating LLM
    can understand exactly why the action was blocked and what to revise.

    Format (newline-separated)::

        [PRAMANIX BLOCKED]
        Decision ID: {id}
        Status: {status}
        Violated rules: {rules}
        Reason: {explanation}
        Input values: {k=v; ...}
        Please revise the action and try again.

    Args:
        decision: A :class:`~pramanix.decision.Decision` with ``allowed=False``.
        intent:   The raw intent dict that was verified.

    Returns:
        A multi-line string safe to use as an AutoGen agent reply.
    """
    rules = (
        ", ".join(decision.violated_invariants)
        if decision.violated_invariants
        else "policy violation"
    )
    explanation = decision.explanation or "Action blocked by safety policy."
    values_str = _format_intent_values(intent)
    status_str = (
        decision.status.value
        if hasattr(decision.status, "value")
        else str(decision.status)
    )
    lines = [
        "[PRAMANIX BLOCKED]",
        f"Decision ID: {decision.decision_id}",
        f"Status: {status_str}",
        f"Violated rules: {rules}",
        f"Reason: {explanation}",
        f"Input values: {values_str}",
        "Please revise the action and try again.",
    ]
    return "\n".join(lines)
