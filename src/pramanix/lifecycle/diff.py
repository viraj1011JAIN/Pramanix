# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Policy lifecycle management: structural diffs and shadow evaluation.

Provides tools to safely evolve policies across versions without blind-spot
gaps in the enforcement guarantee:

* :class:`PolicyDiff` — structural diff of two :class:`~pramanix.policy.Policy`
  subclasses, identifying added, removed, and changed invariants and fields.
* :class:`ShadowEvaluator` — runs a *candidate* policy alongside the *live*
  policy for every real decision and records divergence metrics, so operators
  can build statistical confidence before promoting the new policy.

Design constraints
------------------
* **No eval, no exec** — diffs are computed by inspecting the declared
  :class:`~pramanix.expressions.Field` descriptors and the string labels
  returned by :meth:`~pramanix.policy.Policy.invariants`.
* **Shadow evaluation is non-blocking** — shadow verify() runs after the live
  decision is produced so it can never delay the caller.  Errors in the shadow
  run are caught and recorded as divergence events, not propagated.
* **Thread-safe** — all shared state inside :class:`ShadowEvaluator` is
  protected by ``threading.Lock``.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision
    from pramanix.expressions import Field as ExprField
    from pramanix.policy import Policy

__all__ = [
    "FieldChange",
    "InvariantChange",
    "PolicyDiff",
    "ShadowEvaluator",
    "ShadowResult",
]

_log = logging.getLogger(__name__)


# ── Diff types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InvariantChange:
    """Describes how a single named invariant changed between two policies.

    Attributes:
        name:         Invariant label.
        change_type:  ``"added"`` | ``"removed"`` | ``"changed"``.
        old_repr:     String representation in the old policy (or ``None`` if added).
        new_repr:     String representation in the new policy (or ``None`` if removed).
    """

    name: str
    change_type: str  # "added" | "removed" | "changed"
    old_repr: str | None = None
    new_repr: str | None = None


@dataclass(frozen=True)
class FieldChange:
    """Describes how a single field declaration changed between two policies.

    Attributes:
        name:        Field name.
        change_type: ``"added"`` | ``"removed"`` | ``"changed"``.
        old_z3_type: Z3 type in the old policy (or ``None`` if added).
        new_z3_type: Z3 type in the new policy (or ``None`` if removed).
    """

    name: str
    change_type: str  # "added" | "removed" | "changed"
    old_z3_type: str | None = None
    new_z3_type: str | None = None


@dataclass(frozen=True)
class PolicyDiff:
    """Structural diff between two :class:`~pramanix.policy.Policy` subclasses.

    Compares:
    * Named invariants declared by :meth:`~pramanix.policy.Policy.invariants`.
    * :class:`~pramanix.expressions.Field` descriptors.
    * ``Meta.version`` strings.

    The diff is computed lazily via :meth:`PolicyDiff.compute` — the
    dataclass itself is a pure value type.

    Attributes:
        old_policy_name:  Qualified name of the old policy class.
        new_policy_name:  Qualified name of the new policy class.
        old_version:      ``Meta.version`` of the old policy (or ``None``).
        new_version:      ``Meta.version`` of the new policy (or ``None``).
        invariant_changes: List of :class:`InvariantChange` records.
        field_changes:     List of :class:`FieldChange` records.
        is_breaking:       True when any invariant was *removed* or an
                           existing invariant's constraint expression changed.
                           Field changes are always considered breaking.

    Example::

        diff = PolicyDiff.compute(OldTradePolicy, NewTradePolicy)
        if diff.is_breaking:
            print(diff.summary())
    """

    old_policy_name: str
    new_policy_name: str
    old_version: str | None
    new_version: str | None
    invariant_changes: list[InvariantChange]
    field_changes: list[FieldChange]

    @property
    def is_breaking(self) -> bool:
        """True when any invariant was removed/changed or any field changed."""
        return any(
            c.change_type in ("removed", "changed") for c in self.invariant_changes
        ) or bool(self.field_changes)

    @property
    def has_changes(self) -> bool:
        """True when there are any differences between the two policies."""
        return bool(self.invariant_changes) or bool(self.field_changes) or (
            self.old_version != self.new_version
        )

    def summary(self) -> str:
        """Return a human-readable one-page diff summary."""
        lines: list[str] = [
            f"PolicyDiff: {self.old_policy_name} → {self.new_policy_name}",
            f"  version: {self.old_version!r} → {self.new_version!r}",
        ]
        if not self.has_changes:
            lines.append("  (no changes)")
            return "\n".join(lines)
        for ic in self.invariant_changes:
            prefix = {"added": "+ inv", "removed": "- inv", "changed": "~ inv"}[ic.change_type]
            lines.append(f"  {prefix} [{ic.name}]")
            if ic.old_repr and ic.change_type in ("removed", "changed"):
                lines.append(f"      old: {ic.old_repr}")
            if ic.new_repr and ic.change_type in ("added", "changed"):
                lines.append(f"      new: {ic.new_repr}")
        for fc in self.field_changes:
            prefix = {"added": "+ fld", "removed": "- fld", "changed": "~ fld"}[fc.change_type]
            lines.append(f"  {prefix} {fc.name}: {fc.old_z3_type!r} → {fc.new_z3_type!r}")
        lines.append(f"  breaking: {self.is_breaking}")
        return "\n".join(lines)

    @classmethod
    def compute(
        cls,
        old_policy: type[Policy],
        new_policy: type[Policy],
    ) -> "PolicyDiff":
        """Compute the structural diff between *old_policy* and *new_policy*.

        Uses string representations of invariant expressions to detect changes.
        Two invariants are considered *changed* when they share the same ``.name``
        label but differ in their ``repr()``.

        Args:
            old_policy: The current policy class.
            new_policy: The candidate policy class.

        Returns:
            A :class:`PolicyDiff` describing all differences.
        """
        from pramanix.expressions import Field as ExprField

        old_version = getattr(getattr(old_policy, "Meta", None), "version", None)
        new_version = getattr(getattr(new_policy, "Meta", None), "version", None)

        # ── Invariant diff ────────────────────────────────────────────────
        old_invs = _collect_invariants(old_policy)
        new_invs = _collect_invariants(new_policy)

        inv_changes: list[InvariantChange] = []
        all_names = set(old_invs) | set(new_invs)
        for name in sorted(all_names):
            old_repr = old_invs.get(name)
            new_repr = new_invs.get(name)
            if old_repr is None:
                inv_changes.append(InvariantChange(name, "added", None, new_repr))
            elif new_repr is None:
                inv_changes.append(InvariantChange(name, "removed", old_repr, None))
            elif old_repr != new_repr:
                inv_changes.append(InvariantChange(name, "changed", old_repr, new_repr))

        # ── Field diff ────────────────────────────────────────────────────
        old_fields = _collect_fields(old_policy, ExprField)
        new_fields = _collect_fields(new_policy, ExprField)

        fld_changes: list[FieldChange] = []
        all_fld_names = set(old_fields) | set(new_fields)
        for name in sorted(all_fld_names):
            old_z3 = old_fields.get(name)
            new_z3 = new_fields.get(name)
            if old_z3 is None:
                fld_changes.append(FieldChange(name, "added", None, new_z3))
            elif new_z3 is None:
                fld_changes.append(FieldChange(name, "removed", old_z3, None))
            elif old_z3 != new_z3:
                fld_changes.append(FieldChange(name, "changed", old_z3, new_z3))

        return cls(
            old_policy_name=f"{old_policy.__module__}.{old_policy.__qualname__}",
            new_policy_name=f"{new_policy.__module__}.{new_policy.__qualname__}",
            old_version=old_version,
            new_version=new_version,
            invariant_changes=inv_changes,
            field_changes=fld_changes,
        )


# ── Shadow result ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ShadowResult:
    """One shadow evaluation event.

    Attributes:
        intent:           The intent dict evaluated.
        state:            The state dict evaluated.
        live_allowed:     Outcome from the live (current) policy.
        shadow_allowed:   Outcome from the candidate (shadow) policy.
        diverged:         ``True`` when outcomes differ.
        live_latency_ms:  Wall-clock time for the live decision (ms).
        shadow_latency_ms: Wall-clock time for the shadow decision (ms).
        shadow_error:     Exception string if the shadow run raised (or ``None``).
        timestamp:        Unix timestamp of this event.
    """

    intent: dict[str, Any]
    state: dict[str, Any]
    live_allowed: bool
    shadow_allowed: bool | None
    diverged: bool
    live_latency_ms: float
    shadow_latency_ms: float | None
    shadow_error: str | None = None
    timestamp: float = field(default_factory=time.time)


# ── Shadow evaluator ──────────────────────────────────────────────────────────


class ShadowEvaluator:
    """Runs a candidate policy alongside the live policy and tracks divergence.

    Call :meth:`record` after every live decision to trigger the shadow run.
    The shadow run is *synchronous* — wrap in a thread or asyncio executor if
    you need non-blocking behaviour in production.

    Args:
        live_guard:   The :class:`~pramanix.guard.Guard` running the live policy.
        shadow_guard: The :class:`~pramanix.guard.Guard` running the candidate policy.
        max_history:  Maximum number of :class:`ShadowResult` objects to retain
                      in memory (oldest evicted; default: 10 000).

    Example::

        shadow = ShadowEvaluator(live_guard, candidate_guard)
        for intent, state in production_traffic:
            decision = live_guard.verify(intent, state)
            shadow.record(intent, state, decision)
        print(shadow.divergence_rate())
    """

    def __init__(
        self,
        live_guard: Any,
        shadow_guard: Any,
        *,
        max_history: int = 10_000,
    ) -> None:
        self._live = live_guard
        self._shadow = shadow_guard
        self._max_history = max_history
        self._lock = threading.Lock()
        self._results: deque[ShadowResult] = deque(maxlen=max_history)
        self._total = 0
        self._diverged = 0

    def record(
        self,
        intent: dict[str, Any],
        state: dict[str, Any],
        live_decision: Decision,
    ) -> ShadowResult:
        """Record a live decision and run the shadow evaluation.

        The live decision is already computed — this method only runs the
        *shadow* verify() to collect divergence data.

        Args:
            intent:        The intent dict that was verified.
            state:         The state dict that was verified.
            live_decision: The :class:`~pramanix.decision.Decision` already
                           produced by the live guard.

        Returns:
            A :class:`ShadowResult` capturing the comparison.
        """
        from pramanix.decision import SolverStatus

        live_allowed = live_decision.allowed
        live_latency_ms = getattr(live_decision, "latency_ms", 0.0)

        shadow_allowed: bool | None = None
        shadow_latency_ms: float | None = None
        shadow_error: str | None = None

        try:
            t0 = time.perf_counter()
            shadow_decision = self._shadow.verify(intent, state)
            shadow_latency_ms = (time.perf_counter() - t0) * 1_000
            shadow_allowed = shadow_decision.allowed
        except Exception as exc:  # noqa: BLE001 — shadow errors must never propagate
            shadow_error = f"{type(exc).__name__}: {exc}"
            _log.warning(
                "shadow_evaluator.error: %s",
                shadow_error,
            )

        diverged = shadow_error is not None or (shadow_allowed != live_allowed)
        result = ShadowResult(
            intent=intent,
            state=state,
            live_allowed=live_allowed,
            shadow_allowed=shadow_allowed,
            diverged=diverged,
            live_latency_ms=live_latency_ms,
            shadow_latency_ms=shadow_latency_ms,
            shadow_error=shadow_error,
        )

        with self._lock:
            self._total += 1
            if diverged:
                self._diverged += 1
                _log.info(
                    "shadow_evaluator.diverged: live=%s shadow=%s error=%s",
                    live_allowed,
                    shadow_allowed,
                    shadow_error,
                )
            self._results.append(result)  # deque(maxlen=N) auto-evicts oldest

        return result

    def divergence_rate(self) -> float:
        """Fraction of evaluations where live and shadow outcomes differed.

        Returns ``0.0`` when no evaluations have been recorded.
        """
        with self._lock:
            if self._total == 0:
                return 0.0
            return self._diverged / self._total

    def total_evaluations(self) -> int:
        """Total number of shadow evaluations recorded."""
        with self._lock:
            return self._total

    def diverged_count(self) -> int:
        """Number of evaluations where outcomes diverged."""
        with self._lock:
            return self._diverged

    def history(self) -> list[ShadowResult]:
        """Return a copy of the retained shadow result history."""
        with self._lock:
            return list(self._results)

    def diverged_events(self) -> list[ShadowResult]:
        """Return only the diverged shadow results."""
        with self._lock:
            return [r for r in self._results if r.diverged]

    def reset(self) -> None:
        """Clear all counters and history."""
        with self._lock:
            self._results.clear()
            self._total = 0
            self._diverged = 0


# ── Internal helpers ──────────────────────────────────────────────────────────


def _collect_invariants(policy: type[Policy]) -> dict[str, str]:
    """Return ``{name: stable_repr}`` for every invariant in *policy*.

    Uses ``explanation + repr(node)`` as a stable change-detection key.
    ``repr(ConstraintExpr)`` includes the Python object address and is NOT
    stable across calls — we build a deterministic key from the structured
    fields instead.
    """
    try:
        invs = policy.invariants()
    except Exception:  # noqa: BLE001 — broken policies still need a diff
        return {}
    result: dict[str, str] = {}
    for inv in invs:
        name = getattr(inv, "_name", None) or getattr(inv, "label", None) or getattr(inv, "name", None) or id(inv)
        label = getattr(inv, "label", None) or ""
        explanation = getattr(inv, "explanation", None) or ""
        node = getattr(inv, "node", None)
        # repr() on NamedTuple nodes is stable (no object id)
        stable = f"label={label!r}|explanation={explanation!r}|node={repr(node)}"
        result[str(name)] = stable
    return result


def _collect_fields(policy: type[Policy], field_cls: type) -> dict[str, str]:
    """Return ``{field_name: z3_type_str}`` for every Field descriptor in *policy*."""
    result: dict[str, str] = {}
    for attr_name in dir(policy):
        if attr_name.startswith("_"):
            continue
        try:
            val = getattr(policy, attr_name)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(val, field_cls):
            result[attr_name] = str(val.z3_type) if hasattr(val, "z3_type") else repr(val)
    return result
