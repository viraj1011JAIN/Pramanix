# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Block feedback formatters for Pramanix ecosystem integrations.

SECURITY CONTRACT:
These formatters NEVER include raw intent or state field values.
They use ONLY:
  - decision.explanation (populated from author-supplied .explain() templates)
  - decision.violated_invariants (invariant label names only)
  - decision.decision_id (for audit correlation)
  - decision.status (enum string)

The .explain() template is the ONLY channel through which field values
may appear in feedback — and only values the policy author explicitly
chose to surface via {field_name} interpolation in .explain().

Raw values from the intent dict are NEVER appended directly.
This prevents binary-search policy probing by malicious agents.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision

__all__ = ["format_block_feedback", "format_autogen_rejection"]


def format_block_feedback(decision: Decision, intent: dict[str, Any]) -> str:
    """Format a block decision as a LangChain-safe feedback string.

    The intent parameter is accepted for API compatibility but its raw
    values are NEVER included in the output. Policy authors surface
    field values through .explain() template interpolation only.

    Output format:
    ACTION BLOCKED [decision_id={id}]. Rules violated: {rules}. Reason: {explanation}.
    """
    rules = (
        ", ".join(decision.violated_invariants)
        if decision.violated_invariants
        else "policy violation"
    )
    explanation = decision.explanation or "Action blocked by safety policy."
    return (
        f"ACTION BLOCKED [decision_id={decision.decision_id}]. "
        f"Rules violated: {rules}. "
        f"Reason: {explanation}."
    )


def format_autogen_rejection(decision: Decision, intent: dict[str, Any]) -> str:
    """Format a block decision as a structured AutoGen rejection message.

    Multi-line format safe for agent conversation context.
    Raw field values from intent are NEVER included.

    The intent parameter is accepted for API compatibility only.
    """
    rules = (
        ", ".join(decision.violated_invariants)
        if decision.violated_invariants
        else "policy violation"
    )
    explanation = decision.explanation or "Action blocked by safety policy."
    status_str = (
        decision.status.value if hasattr(decision.status, "value") else str(decision.status)
    )
    return (
        f"[PRAMANIX BLOCKED]\n"
        f"Decision ID: {decision.decision_id}\n"
        f"Status: {status_str}\n"
        f"Violated rules: {rules}\n"
        f"Reason: {explanation}\n"
        f"Please revise the action parameters and try again."
    )
