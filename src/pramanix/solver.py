# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Z3 solver wrapper — runs policy invariants against a concrete fact.

Two-phase verification
----------------------
1. **Fast path** — one shared ``z3.Solver`` with all invariants added via
   ``add()``.  If the result is ``sat``, we return immediately without
   attribution work.  This is the common case for valid requests.
2. **Attribution path** — only entered on ``unsat``.  Each invariant gets its
   own ``z3.Solver`` instance with a single ``assert_and_track`` call.  With
   exactly one tracked assertion per solver, ``unsat_core()`` is always
   ``{label}`` — no minimal-core ambiguity, complete violation reporting.

See *docs/architecture.md* §Phase-1-Findings for the full rationale.

Fail-safe behaviour
-------------------
* Every ``z3.Solver`` instance has ``set("timeout", timeout_ms)`` applied.
* ``z3.unknown`` (timeout) on the fast path  → :exc:`~pramanix.exceptions.SolverTimeoutError`
  with label ``"<all-invariants>"``.
* ``z3.unknown`` on a per-invariant solver   → :exc:`~pramanix.exceptions.SolverTimeoutError`
  with the invariant's label.
* Both are caught by ``Guard.verify()`` and converted to ``Decision.timeout()``.
"""
from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import z3

from pramanix.exceptions import FieldTypeError, InvariantLabelError, SolverTimeoutError
from pramanix.transpiler import collect_fields, transpile, z3_val, z3_var

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__: list[str] = []  # internal module


# ── OpenTelemetry — graceful optional dependency ──────────────────────────────
# If the ``otel`` extra is not installed, every span call is a no-op
# (contextlib.nullcontext).  The hot path has zero overhead when OTel is absent.

try:
    from opentelemetry import trace as _otel_trace

    def _span(name: str, **attrs: Any) -> Any:
        """Return a live OTel span context-manager."""
        tracer = _otel_trace.get_tracer("pramanix.solver")
        span_cm = tracer.start_as_current_span(name)
        return span_cm

except ImportError:

    def _span(name: str, **attrs: Any) -> Any:
        """No-op span when opentelemetry is not installed."""
        return contextlib.nullcontext()


# ── Internal result type ──────────────────────────────────────────────────────


@dataclass
class _SolveResult:
    """Intermediate result produced by :func:`solve`, consumed by ``Guard``."""

    sat: bool
    """``True`` iff all invariants are satisfied."""

    violated: list[ConstraintExpr]
    """Invariants that are violated (empty when ``sat=True``)."""

    solver_time_ms: float
    """Wall-clock time spent in Z3 (milliseconds)."""


# ── Sort-safe equality helper ─────────────────────────────────────────────────


def _z3_eq(a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
    """Return a Z3 equality formula ``(= a b)`` that works for all sorts.

    Python's ``==`` on Z3 ``SeqRef`` (String sort) objects falls through to
    ``AstRef.__eq__`` which returns a *Python bool* (AST identity check) rather
    than a Z3 ``BoolRef`` formula.  ``ArithRef`` and ``BoolRef`` override
    ``__eq__`` correctly, but ``SeqRef`` does not.

    Using ``Z3_mk_eq`` directly bypasses the Python operator and always
    produces a Bool-sorted Z3 formula regardless of the operand sorts.
    """
    return z3.BoolRef(z3.Z3_mk_eq(a.ctx_ref(), a.as_ast(), b.as_ast()), a.ctx)


# ── Value binding builder ─────────────────────────────────────────────────────


def _build_bindings(
    all_fields: dict[str, Field],
    values: dict[str, Any],
    ctx: z3.Context | None = None,
) -> list[tuple[z3.ExprRef, z3.ExprRef]]:
    """Map concrete *values* to Z3 ``(variable == value)`` binding pairs.

    Only fields that appear in *all_fields* and whose names match a key in
    *values* are included.  Extra keys in *values* that are not referenced by
    any invariant are silently ignored.

    Args:
        ctx: Optional Z3 context.  Must match the context used for all other
             Z3 operations in the same solve call.

    Raises:
        FieldTypeError: If a value cannot be coerced to its field's Z3 sort.
    """
    bindings: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for name, val in values.items():
        if name not in all_fields:
            continue
        f = all_fields[name]
        # Explicit bool-as-Real guard (z3_val handles this, but surface
        # the error with a clear field name before z3_var is even called)
        if f.z3_type == "Real" and isinstance(val, bool):
            raise FieldTypeError(
                f"Field '{name}' is declared as Real; "
                "bool values are not allowed (bool is a subclass of int in Python)."
            )
        bindings.append((z3_var(f, ctx), z3_val(f, val, ctx)))
    return bindings


# ── Fast-path helper ──────────────────────────────────────────────────────────


def _fast_check(
    invariants: list[ConstraintExpr],
    bindings: list[tuple[z3.ExprRef, z3.ExprRef]],
    timeout_ms: int,
    ctx: z3.Context | None = None,
    rlimit: int = 0,
) -> z3.CheckSatResult:
    """Run all invariants in a single solver; return the raw Z3 result.

    Uses ``add()`` (not ``assert_and_track``) — no unsat-core attribution here.
    The result is used only to decide whether to proceed to the attribution path.

    Args:
        ctx:      Optional Z3 context for thread-safety.
        rlimit:   Z3 resource limit (elementary operations).  ``0`` = disabled.
                  When exceeded, Z3 returns ``unknown`` which is treated as
                  a timeout and converted to ``Decision.timeout()`` (BLOCK).
                  Prevents logic-bomb and non-linear expression DoS.

    Raises:
        SolverTimeoutError: If Z3 returns ``unknown`` (timeout or resource
            limit exceeded) on the shared solver.
    """
    s = z3.Solver(ctx=ctx)
    s.set("timeout", timeout_ms)
    if rlimit > 0:
        s.set("rlimit", rlimit)
    for z3v, z3val in bindings:
        s.add(_z3_eq(z3v, z3val))
    for inv in invariants:
        s.add(transpile(inv.node, ctx))
    with _span("pramanix.z3_solve"):
        result = s.check()
    del s  # prompt Z3 memory release
    if result == z3.unknown:
        raise SolverTimeoutError("<all-invariants>", timeout_ms)
    return result


# ── Per-invariant attribution ─────────────────────────────────────────────────


def _attribute_violations(
    invariants: list[ConstraintExpr],
    bindings: list[tuple[z3.ExprRef, z3.ExprRef]],
    timeout_ms: int,
    ctx: z3.Context | None = None,
    rlimit: int = 0,
) -> list[ConstraintExpr]:
    """Determine exactly which invariants are violated.

    Each invariant gets its own ``z3.Solver`` with exactly one
    ``assert_and_track`` call, so ``unsat_core()`` returns ``{label}``
    with certainty — no minimal-core ambiguity.

    Args:
        ctx:    Optional Z3 context for thread-safety.
        rlimit: Z3 resource limit per-invariant solver.  ``0`` = disabled.

    Raises:
        InvariantLabelError: If an invariant reached this path without a label
            (should never happen after ``Policy.validate()``).
        SolverTimeoutError: If Z3 returns ``unknown`` on any per-invariant check.
    """
    violated: list[ConstraintExpr] = []
    for inv in invariants:
        label = inv.label
        if label is None:
            raise InvariantLabelError(
                "An invariant without a label reached the solver. "
                "Call Policy.validate() before Guard.verify()."
            )
        s = z3.Solver(ctx=ctx)
        s.set("timeout", timeout_ms)
        if rlimit > 0:
            s.set("rlimit", rlimit)
        for z3v, z3val in bindings:
            s.add(_z3_eq(z3v, z3val))
        s.assert_and_track(transpile(inv.node, ctx), z3.Bool(label, ctx))
        with _span("pramanix.z3_solve"):
            result = s.check()
        del s  # prompt Z3 memory release
        if result == z3.unknown:
            raise SolverTimeoutError(label, timeout_ms)
        if result == z3.unsat:
            violated.append(inv)
    return violated


# ── Public entry point ────────────────────────────────────────────────────────


def solve(
    invariants: list[ConstraintExpr],
    values: dict[str, Any],
    timeout_ms: int,
    rlimit: int = 0,
) -> _SolveResult:
    """Verify that *values* satisfy all *invariants*.

    Args:
        invariants: Named ``ConstraintExpr`` objects from
            :meth:`~pramanix.policy.Policy.invariants`.  Every invariant must
            carry a ``.named()`` label.
        values:     Concrete input fact — ``{field_name: python_value}``.
        timeout_ms: Per-solver Z3 timeout in milliseconds.
        rlimit:     Z3 resource limit (elementary operations).  ``0`` = disabled.
                    Prevents logic-bomb / non-linear-explosion DoS regardless of
                    wall-clock time.  Both ``timeout_ms`` and ``rlimit`` apply
                    simultaneously — whichever is hit first triggers a BLOCK.

    Returns:
        A :class:`_SolveResult` with ``sat=True`` and an empty ``violated``
        list if all invariants pass, or ``sat=False`` with the full list of
        violated invariants if any fail.

    Raises:
        SolverTimeoutError:  If any solver instance exceeds ``timeout_ms`` or
                             ``rlimit``.
        FieldTypeError:      If a value cannot be coerced to its field's sort.
        InvariantLabelError: If an invariant is missing its label.
        TranspileError:      If a DSL expression cannot be lowered to Z3.
    """
    start = time.perf_counter()

    # Create a per-call Z3 context so this function is safe to call from
    # multiple threads simultaneously.  Z3's global default context is NOT
    # thread-safe; sharing it across threads causes access violations.
    ctx = z3.Context()
    try:
        # Collect all fields referenced across all invariants, then build bindings.
        all_fields: dict[str, Field] = {}
        for inv in invariants:
            all_fields.update(collect_fields(inv.node))
        bindings = _build_bindings(all_fields, values, ctx)

        # ── Phase 1: fast path ────────────────────────────────────────────────
        fast_result = _fast_check(invariants, bindings, timeout_ms, ctx, rlimit)

        if fast_result == z3.sat:
            return _SolveResult(
                sat=True,
                violated=[],
                solver_time_ms=(time.perf_counter() - start) * 1000.0,
            )

        # ── Phase 2: attribution path (only reached on unsat) ─────────────────
        violated = _attribute_violations(invariants, bindings, timeout_ms, ctx, rlimit)

        return _SolveResult(
            sat=False,
            violated=violated,
            solver_time_ms=(time.perf_counter() - start) * 1000.0,
        )
    finally:
        del ctx  # release Z3 context memory
