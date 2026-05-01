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

    # ── Fintech: amount / balance / daily-limit checks ───────────────────────
    raw_amount = intent_dict.get("amount")
    if raw_amount is not None:
        try:
            amount = Decimal(str(raw_amount))
        except InvalidOperation as exc:
            raise SemanticPolicyViolation(f"amount is not a valid number: {raw_amount!r}") from exc

        if amount <= 0:
            raise SemanticPolicyViolation(f"amount must be positive, got {amount}")

        # Balance / minimum-reserve check
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

        # Daily limit check
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

    # ── Healthcare: dosage checks ────────────────────────────────────────
    raw_dosage = intent_dict.get("dosage")
    if raw_dosage is not None:
        try:
            dosage = Decimal(str(raw_dosage))
            if dosage <= 0:
                raise SemanticPolicyViolation(
                    f"dosage must be positive, got {dosage}."
                )
            raw_max_daily_dose = state_values.get("max_daily_dose")
            raw_total_daily_dose = state_values.get("total_daily_dose")
            if raw_max_daily_dose is not None and raw_total_daily_dose is not None:
                try:
                    remaining_dose = Decimal(str(raw_max_daily_dose)) - Decimal(str(raw_total_daily_dose))
                    if dosage > remaining_dose:
                        raise SemanticPolicyViolation(
                            f"Dosage exceeds remaining daily dose allowance "
                            f"(remaining={remaining_dose}, dosage={dosage})."
                        )
                except SemanticPolicyViolation:
                    raise
                except Exception:
                    pass
        except SemanticPolicyViolation:
            raise
        except Exception:
            pass

    # ── Infra: resource request vs limit checks ──────────────────────────
    raw_requested_replicas = intent_dict.get("requested_replicas") or intent_dict.get("replica_count")
    if raw_requested_replicas is not None:
        try:
            requested = int(raw_requested_replicas)
            if requested < 0:
                raise SemanticPolicyViolation(
                    f"requested_replicas must be non-negative, got {requested}."
                )
            raw_max_replicas = state_values.get("max_replicas")
            if raw_max_replicas is not None:
                try:
                    max_r = int(raw_max_replicas)
                    if requested > max_r:
                        raise SemanticPolicyViolation(
                            f"Requested replicas ({requested}) exceeds cluster max ({max_r})."
                        )
                except SemanticPolicyViolation:
                    raise
                except Exception:
                    pass
        except SemanticPolicyViolation:
            raise
        except Exception:
            pass

    raw_cpu_request = intent_dict.get("cpu_request")
    raw_cpu_limit = state_values.get("cpu_limit")
    if raw_cpu_request is not None and raw_cpu_limit is not None:
        try:
            cpu_req = Decimal(str(raw_cpu_request))
            cpu_lim = Decimal(str(raw_cpu_limit))
            if cpu_req > cpu_lim:
                raise SemanticPolicyViolation(
                    f"cpu_request ({cpu_req}) exceeds cpu_limit ({cpu_lim})."
                )
        except SemanticPolicyViolation:
            raise
        except Exception:
            pass

    raw_mem_request = intent_dict.get("memory_request")
    raw_mem_limit = state_values.get("memory_limit")
    if raw_mem_request is not None and raw_mem_limit is not None:
        try:
            mem_req = Decimal(str(raw_mem_request))
            mem_lim = Decimal(str(raw_mem_limit))
            if mem_req > mem_lim:
                raise SemanticPolicyViolation(
                    f"memory_request ({mem_req}) exceeds memory_limit ({mem_lim})."
                )
        except SemanticPolicyViolation:
            raise
        except Exception:
            pass


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


# ── StringEnumField auto-coercion ────────────────────────────────────────────


def _apply_enum_coercions(
    intent_values: dict[str, Any],
    state_values: dict[str, Any],
    coercions: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Encode string values in intent/state for fields registered in *coercions*.

    For each ``(field_name, StringEnumField)`` pair in *coercions*, if the
    corresponding value in *intent_values* or *state_values* is a ``str``,
    the value is encoded to its integer code via ``StringEnumField.encode()``.
    Values already stored as ``int`` (already encoded) pass through unchanged.

    Args:
        intent_values: Plain intent dict (post model_dump).
        state_values:  Plain state dict (post model_dump).
        coercions:     ``{field_name: StringEnumField}`` from
                       ``Policy.string_enum_coercions()``.

    Returns:
        ``(encoded_intent, encoded_state)`` — new dicts with string enum
        values replaced by their integer codes.

    Raises:
        ValueError: If a string value is not a member of its StringEnumField.
                    The message is caller-friendly and names the field.
    """
    def _coerce(d: dict[str, Any]) -> dict[str, Any]:
        out = dict(d)
        for fname, sef in coercions.items():
            if fname in out and isinstance(out[fname], str):
                try:
                    out[fname] = sef.encode(out[fname])
                except ValueError:
                    valid = getattr(sef, "values", [])
                    raise ValueError(
                        f"StringEnumField auto-coercion failed for field {fname!r}: "
                        f"value {out[fname]!r} is not in the enumeration. "
                        f"Valid labels: {valid!r}. "
                        "Check your intent/state or update the StringEnumField definition."
                    ) from None
        return out

    return _coerce(intent_values), _coerce(state_values)


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
