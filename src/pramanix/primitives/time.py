# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Temporal constraint primitives using UNIX epoch integer fields.

Design note: Time fields must be declared as ``Int``-sorted in the Policy,
representing UNIX timestamps (seconds since epoch).  This avoids floating-
point imprecision and makes Z3 arithmetic exact.

Trusted-clock model (#201/#202)
--------------------------------
``NotExpired`` defaults to the Guard's **trusted system clock** (``_NowOp``):
the current Unix timestamp is embedded into the Z3 AST at *solve time* by the
transpiler, not pulled from caller-supplied ``state`` or ``intent``.  This
eliminates the canonical bypass::

    # Attacker sets now_ts=0 → every token appears permanently valid
    guard.verify(intent=..., state={"now_ts": 0, "expiry_ts": ...})

For the window / cutoff bounds in ``WithinTimeWindow``, ``Before``, and
``After``, pass **integer literals** fixed at policy-definition time.  Passing
a :class:`~pramanix.expressions.Field` is still accepted for backward
compatibility but emits a :class:`~pramanix.exceptions.PramanixSecurityWarning`
because a caller controlling the window edges defeats enforcement.

Example (recommended pattern)::

    import time
    from pramanix.primitives.time import NotExpired, WithinTimeWindow

    WINDOW_OPEN  = 1_700_000_000   # fixed UNIX epoch — policy author controls this
    WINDOW_CLOSE = 1_800_000_000

    class TokenPolicy(Policy):
        expiry_ts = Field("expiry_ts", int, "Int")
        request_ts = Field("request_ts", int, "Int")

        @classmethod
        def invariants(cls):
            return [
                NotExpired(cls.expiry_ts),                             # trusted clock
                WithinTimeWindow(cls.request_ts, WINDOW_OPEN, WINDOW_CLOSE),
            ]

Legacy pattern (backward-compatible, emits SecurityWarning)::

    class TokenPolicy(Policy):
        expiry_ts = Field("expiry_ts", int, "Int")
        now_ts    = Field("now_ts",    int, "Int")

        @classmethod
        def invariants(cls):
            return [NotExpired(cls.expiry_ts, cls.now_ts)]   # warns: use trusted clock
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Union

from pramanix.exceptions import PramanixSecurityWarning
from pramanix.expressions import E, ExpressionNode, _Literal, _NowOp

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "After",
    "Before",
    "NotExpired",
    "WithinTimeWindow",
]

# Union accepted for time bound parameters: int literal (safe) or Field (warned).
_TimeBound = Union[int, "Field"]


def _bound_expr(bound: _TimeBound, param_name: str, caller_depth: int = 3) -> ExpressionNode:
    """Return an ExpressionNode for a time bound.

    * ``int`` → compile-time ``_Literal`` embedded in Z3 AST (caller cannot alter it).
    * :class:`~pramanix.expressions.Field` → ``E(bound)`` resolved from caller-supplied
      state; emits :class:`~pramanix.exceptions.PramanixSecurityWarning`.
    """
    if isinstance(bound, int):
        return ExpressionNode(_Literal(bound))
    # Field path — warn and fall back to caller-supplied resolution.
    warnings.warn(
        f"Temporal primitive: `{param_name}` is a Field resolved from caller-supplied "
        f"state.  A caller can manipulate `{param_name}` to bypass time enforcement.  "
        f"Pass a literal int fixed at policy-definition time instead, or populate "
        f"`{param_name}` exclusively via `trusted_state` in Guard.verify().",
        PramanixSecurityWarning,
        stacklevel=caller_depth,
    )
    return E(bound)


def NotExpired(
    expiry_ts: Field,
    now_ts: Field | None = None,
) -> ConstraintExpr:
    """Enforce that the entity has not yet expired.

    DSL: ``(E(expiry_ts) > now_expr)``

    By default *now_ts* is ``None`` and the Guard's trusted system clock
    (``_NowOp``) is used.  The timestamp is captured lazily at each
    ``Guard.verify()`` call — the caller cannot influence it.

    Passing a :class:`~pramanix.expressions.Field` for *now_ts* is accepted
    for backward compatibility but emits a
    :class:`~pramanix.exceptions.PramanixSecurityWarning` because the caller
    can set ``now_ts=0`` to make every token appear permanently valid.

    Args:
        expiry_ts: Field representing the expiry timestamp of the entity
                   (certificate, token, session, …).  Must be ``Int``-sorted.
        now_ts:    ``None`` (default) to use the Guard's trusted system clock,
                   or a ``Field`` for backward-compatible caller-supplied time
                   (emits :class:`~pramanix.exceptions.PramanixSecurityWarning`).
    """
    if now_ts is None:
        # Trusted path: clock is captured by the transpiler at solve time.
        now_expr: ExpressionNode = ExpressionNode(_NowOp())
        explain_msg = "Entity has expired: expiry_ts ({expiry_ts}) <= now (trusted clock)."
    else:
        warnings.warn(
            "NotExpired: `now_ts` is caller-supplied.  A caller can set "
            "`now_ts=0` to bypass expiry enforcement entirely.  Omit `now_ts` "
            "to use the Guard's trusted system clock (_NowOp) instead.",
            PramanixSecurityWarning,
            stacklevel=2,
        )
        now_expr = E(now_ts)
        explain_msg = "Entity has expired: expiry_ts ({expiry_ts}) <= now_ts ({now_ts})."

    return (E(expiry_ts) > now_expr).named("not_expired").explain(explain_msg)


def WithinTimeWindow(
    timestamp: Field,
    window_start: _TimeBound,
    window_end: _TimeBound,
) -> ConstraintExpr:
    """Enforce that a timestamp falls inside [window_start, window_end].

    DSL: ``(E(timestamp) >= window_start) & (E(timestamp) <= window_end)``

    Pass *window_start* and *window_end* as **integer literals** fixed at
    policy-definition time.  Passing a :class:`~pramanix.expressions.Field`
    emits a :class:`~pramanix.exceptions.PramanixSecurityWarning`.

    Args:
        timestamp:    Field representing the event/request timestamp.
        window_start: Policy-fixed window open time (int literal, UNIX epoch)
                      or a Field (warned: caller can widen the window).
        window_end:   Policy-fixed window close time (int literal, UNIX epoch)
                      or a Field (warned: caller can widen the window).
    """
    start_expr = _bound_expr(window_start, "window_start", caller_depth=2)
    end_expr = _bound_expr(window_end, "window_end", caller_depth=2)

    if isinstance(window_start, int) and isinstance(window_end, int):
        explain_msg = (
            f"Request outside allowed time window: timestamp ({{timestamp}}) "
            f"is not in [{window_start}, {window_end}]."
        )
    else:
        explain_msg = (
            "Request outside allowed time window: timestamp ({timestamp}) "
            "is not in [{window_start}, {window_end}]."
        )

    return (
        ((E(timestamp) >= start_expr) & (E(timestamp) <= end_expr))
        .named("within_time_window")
        .explain(explain_msg)
    )


def After(
    timestamp: Field,
    cutoff: _TimeBound,
) -> ConstraintExpr:
    """Enforce that a timestamp is strictly after the cutoff.

    DSL: ``(E(timestamp) > cutoff)``

    Pass *cutoff* as an **integer literal** fixed at policy-definition time.
    Passing a :class:`~pramanix.expressions.Field` emits a
    :class:`~pramanix.exceptions.PramanixSecurityWarning`.

    Args:
        timestamp: Field representing the event timestamp.
        cutoff:    Policy-fixed earliest acceptable timestamp (int literal)
                   or a Field (warned: caller can lower the cutoff).
    """
    cutoff_expr = _bound_expr(cutoff, "cutoff", caller_depth=2)

    if isinstance(cutoff, int):
        explain_msg = f"Too early: timestamp ({{timestamp}}) is not after cutoff ({cutoff})."
    else:
        explain_msg = "Too early: timestamp ({timestamp}) is not after cutoff ({cutoff})."

    return (E(timestamp) > cutoff_expr).named("after_cutoff").explain(explain_msg)


def Before(
    timestamp: Field,
    cutoff: _TimeBound,
) -> ConstraintExpr:
    """Enforce that a timestamp is strictly before the cutoff.

    DSL: ``(E(timestamp) < cutoff)``

    Pass *cutoff* as an **integer literal** fixed at policy-definition time.
    Passing a :class:`~pramanix.expressions.Field` emits a
    :class:`~pramanix.exceptions.PramanixSecurityWarning`.

    Args:
        timestamp: Field representing the event timestamp.
        cutoff:    Policy-fixed latest acceptable timestamp (int literal)
                   or a Field (warned: caller can raise the cutoff).
    """
    cutoff_expr = _bound_expr(cutoff, "cutoff", caller_depth=2)

    if isinstance(cutoff, int):
        explain_msg = f"Too late: timestamp ({{timestamp}}) is not before cutoff ({cutoff})."
    else:
        explain_msg = "Too late: timestamp ({timestamp}) is not before cutoff ({cutoff})."

    return (E(timestamp) < cutoff_expr).named("before_cutoff").explain(explain_msg)
