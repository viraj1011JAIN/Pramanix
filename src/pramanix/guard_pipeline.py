# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Guard pipeline helpers — semantic checks, policy fingerprinting, formatting.

Extracted from ``guard.py`` to reduce module size. These are internal helpers
for the Guard verification pipeline and are not part of the public API.

Contents
--------
* :func:`_semantic_post_consensus_check` — fast pure-Python semantic guard
  applied after LLM consensus, before Z3.
* :func:`_compute_policy_fingerprint` — stable SHA-256 fingerprint of a
  compiled policy for drift detection.
* :func:`_fmt` — formats an invariant's explanation template with concrete
  field values.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pramanix.exceptions import SemanticPolicyViolation

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr
    from pramanix.policy import Policy


# ── Semantic post-consensus check ─────────────────────────────────────────────


def _semantic_post_consensus_check(
    intent_dict: dict[str, Any],
    state_values: dict[str, Any],
) -> None:
    """Fast pure-Python semantic guard applied after LLM consensus, before Z3.

    Catches obvious business-rule violations immediately without invoking
    the Z3 solver, reducing latency and attack surface:

    * Positive-amount enforcement (amount > 0).
    * Minimum-reserve floor (balance - amount >= minimum_reserve).
    * Full-balance drain guard (requires secondary approval when reserve = 0).
    * Daily limit breach (when ``daily_limit`` and ``daily_spent`` are present).

    Only activates for the fields that are present in *both* intent and state,
    so it is safe to call for any policy/intent combination regardless of
    the domain.

    Args:
        intent_dict:  Validated dict extracted from the LLM (post-consensus).
        state_values: Plain dict of current system state.

    Raises:
        SemanticPolicyViolation: If a business rule is violated.
    """
    from decimal import Decimal, InvalidOperation

    # ── Extract amount (skip check if no amount field) ───────────────────────
    raw_amount = intent_dict.get("amount")
    if raw_amount is None:
        return  # no amount field — nothing to check

    try:
        amount = Decimal(str(raw_amount))
    except InvalidOperation as exc:
        raise SemanticPolicyViolation(f"amount is not a valid number: {raw_amount!r}") from exc

    if amount <= 0:
        raise SemanticPolicyViolation(f"amount must be positive, got {amount}")

    # ── Balance / minimum-reserve check ────────────────────────────────────
    raw_balance = state_values.get("balance")
    if raw_balance is not None:
        try:
            balance = Decimal(str(raw_balance))
            minimum_reserve = Decimal(str(state_values.get("minimum_reserve", "0")))
            if balance - amount < minimum_reserve:
                raise SemanticPolicyViolation(
                    f"Transfer would leave balance below minimum reserve "
                    f"(balance={balance}, amount={amount}, "
                    f"minimum_reserve={minimum_reserve})."
                )
            if minimum_reserve == Decimal("0") and amount == balance:
                raise SemanticPolicyViolation(
                    "Full balance transfer requires secondary human approval."
                )
        except SemanticPolicyViolation:
            raise
        except Exception:
            pass  # Non-numeric balance — let Z3 enforce the invariant

    # ── Daily limit check ───────────────────────────────────────────────
    raw_daily_limit = state_values.get("daily_limit")
    raw_daily_spent = state_values.get("daily_spent")
    if raw_daily_limit is not None and raw_daily_spent is not None:
        try:
            remaining = Decimal(str(raw_daily_limit)) - Decimal(str(raw_daily_spent))
            if amount > remaining:
                raise SemanticPolicyViolation(
                    f"Transfer exceeds remaining daily limit "
                    f"(remaining={remaining}, amount={amount})."
                )
        except SemanticPolicyViolation:
            raise
        except Exception:
            pass  # Let Z3 handle non-numeric daily fields


# ── Policy fingerprint ────────────────────────────────────────────────────────


def _compute_policy_fingerprint(policy: type[Policy]) -> str:
    """Compute a stable SHA-256 fingerprint of a compiled policy.

    Covers: class name, version, sorted invariant labels + explanations, and
    the name + Z3 type of every field referenced by those invariants.
    Stable across restarts; invariant to code comments and whitespace.
    """
    import hashlib
    import json

    from pramanix.transpiler import collect_fields

    invariants = policy.invariants()
    version = policy.meta_version() or ""
    all_fields: dict[str, Any] = {}
    for inv in invariants:
        all_fields.update(collect_fields(inv.node))

    payload = {
        "name": policy.__name__,
        "version": version,
        "invariants": sorted(
            ({"label": inv.label or "", "explanation": inv.explanation or ""}
             for inv in invariants),
            key=lambda x: x["label"],
        ),
        "fields": sorted(
            ({"name": n, "type": f.z3_type} for n, f in all_fields.items()),
            key=lambda x: x["name"],
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Explanation formatter ─────────────────────────────────────────────────────


def _fmt(inv: ConstraintExpr, values: dict[str, Any]) -> str:
    """Format an invariant's explanation template with concrete *values*.

    The template may contain ``{field_name}`` placeholders.  If formatting
    fails (missing key, bad format string), the raw template is returned
    unchanged so the violation is never silently swallowed.
    """
    template = inv.explanation or inv.label or ""
    if not template:
        return ""
    try:
        return template.format_map(values)
    except (KeyError, ValueError):
        return template
