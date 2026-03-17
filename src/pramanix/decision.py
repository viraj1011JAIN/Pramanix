# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Decision — the immutable, JSON-serialisable result of a Guard verification.

Every call to ``Guard.verify()`` returns exactly one :class:`Decision`.
The decision is **frozen** (immutable after construction), carries a UUID4
``decision_id`` for distributed tracing, and is fully serialisable via
:meth:`~Decision.to_dict`.

Typical usage::

    decision = guard.verify(intent, state)

    if decision.allowed:
        execute_action()
    else:
        log.warning(
            "action_blocked",
            decision_id=decision.decision_id,
            status=decision.status.value,
            violated=decision.violated_invariants,
            explanation=decision.explanation,
        )

Status semantics
----------------
``SolverStatus`` encodes *why* a decision was reached:

* ``SAFE``              — Z3 proved all invariants hold  → ``allowed=True``
* ``UNSAFE``            — Z3 found a counterexample       → ``allowed=False``
* ``TIMEOUT``           — Z3 exceeded the time budget     → ``allowed=False``
* ``ERROR``             — unexpected internal error        → ``allowed=False``
* ``STALE_STATE``       — ``state_version`` mismatch       → ``allowed=False``
* ``VALIDATION_FAILURE``— Pydantic model validation failed → ``allowed=False``

The invariant ``allowed=True ↔ status=SAFE`` is enforced in ``__post_init__``.
"""
from __future__ import annotations

import enum
import hashlib
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

try:
    import orjson as _orjson

    def _canonical_bytes(payload: dict[str, Any]) -> bytes:
        """Deterministic canonical bytes via orjson (sorted keys, non-str keys)."""
        return _orjson.dumps(
            payload,
            option=_orjson.OPT_SORT_KEYS | _orjson.OPT_NON_STR_KEYS,
        )

except ImportError:  # pragma: no cover
    import json as _json

    def _canonical_bytes(payload: dict[str, Any]) -> bytes:  # pragma: no cover
        """Deterministic canonical bytes via stdlib json (sorted keys)."""
        return _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


__all__ = ["Decision", "SolverStatus", "_make_json_safe"]


def _make_json_safe(d: dict) -> dict:
    """Convert a dict to JSON-safe types, preserving Decimal precision.

    Decimal → str (exact representation, no float drift)
    datetime → ISO 8601 UTC string
    dict     → recursively converted (deterministic key ordering)
    list/tuple → each element converted via _json_safe_value()
    All other types → str fallback
    """
    result = {}
    for k, v in sorted(d.items()):  # Sorted for determinism
        result[str(k)] = _json_safe_value(v)
    return result


def _json_safe_value(v: Any) -> Any:
    """Convert a single value to a JSON-safe type (recursive helper)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return _make_json_safe(v)
    if isinstance(v, (list, tuple)):
        return [_json_safe_value(i) for i in v]
    if hasattr(v, "isoformat"):  # datetime
        return v.isoformat()
    return str(v)

# ---------------------------------------------------------------------------
# Compatibility shim: FrozenInstanceError was added in Python 3.11.
# In 3.10 frozen dataclasses raise AttributeError directly.
# ---------------------------------------------------------------------------
try:
    from dataclasses import FrozenInstanceError  # type: ignore[attr-defined,unused-ignore]
except ImportError:  # Python 3.10
    FrozenInstanceError = AttributeError  # type: ignore[assignment, misc]


# ── SolverStatus ──────────────────────────────────────────────────────────────


class SolverStatus(str, enum.Enum):
    """Outcome code attached to every :class:`Decision`.

    Inherits from ``str`` so instances serialise naturally to their value
    string (e.g. ``json.dumps({"s": SolverStatus.SAFE})`` works without a
    custom encoder).
    """

    SAFE = "safe"
    """All invariants are satisfied — the action is permitted."""

    UNSAFE = "unsafe"
    """One or more invariants are violated — the action is blocked."""

    TIMEOUT = "timeout"
    """The Z3 solver exceeded the configured time budget."""

    ERROR = "error"
    """An unexpected internal error occurred (fail-safe: always blocks)."""

    STALE_STATE = "stale_state"
    """The ``state_version`` field does not match ``Policy.Meta.version``."""

    VALIDATION_FAILURE = "validation_failure"
    """Pydantic validation of intent or state data failed."""

    RATE_LIMITED = "rate_limited"
    """Request shed by adaptive load limiter (fail-safe: always blocks)."""

    CONSENSUS_FAILURE = "consensus_failure"
    """Dual-LLM models disagreed on intent extraction — action blocked (expected outcome)."""

    CACHE_HIT = "cache_hit"
    """Observability tag: intent extracted from LRU/Redis cache; Z3 still ran."""


# ── Decision ──────────────────────────────────────────────────────────────────

# SolverStatus three-way taxonomy — every member must belong to exactly one:
#
#   1. BLOCKING      — in _BLOCKED_STATUSES; Decision.allowed=False enforced.
#                      Signals either a policy outcome (UNSAFE, CONSENSUS_FAILURE)
#                      or an operational/fault condition (TIMEOUT, ERROR, etc.).
#
#   2. SAFE          — only SolverStatus.SAFE; Decision.allowed=True enforced.
#                      The sole path to permitting an action.
#
#   3. OBSERVABILITY — currently {CACHE_HIT}; decorates an existing SAFE/UNSAFE
#                      decision for metrics/tracing purposes.  Neither blocking
#                      nor safe on its own.
#
# If you add a new SolverStatus member, classify it here consciously.
# tests/unit/test_decision.py::test_safe_is_the_only_non_blocked_non_observability_status
# will fail until you do.
_BLOCKED_STATUSES: frozenset[SolverStatus] = frozenset(
    {
        SolverStatus.UNSAFE,
        SolverStatus.TIMEOUT,
        SolverStatus.ERROR,
        SolverStatus.STALE_STATE,
        SolverStatus.VALIDATION_FAILURE,
        SolverStatus.RATE_LIMITED,
        SolverStatus.CONSENSUS_FAILURE,
    }
)


@dataclass(frozen=True)
class Decision:
    """Immutable, JSON-serialisable result of a single ``Guard.verify()`` call.

    Construct via the factory class-methods (:meth:`safe`, :meth:`unsafe`,
    :meth:`timeout`, :meth:`error`, :meth:`stale_state`,
    :meth:`validation_failure`) rather than calling the constructor directly.

    Attributes:
        allowed:             ``True`` iff the action is permitted.
        status:              Machine-readable outcome code.
        violated_invariants: Labels of the invariants that failed.
        explanation:         Human-readable explanation of the outcome.
        metadata:            Arbitrary caller-supplied key/value pairs.
        solver_time_ms:      Wall-clock time spent in Z3 (milliseconds).
        decision_id:         UUID4 string — unique per verification call.
    """

    allowed: bool
    status: SolverStatus
    violated_invariants: tuple[str, ...] = ()
    explanation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    solver_time_ms: float = 0.0
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    intent_dump: dict = field(default_factory=dict)
    state_dump: dict = field(default_factory=dict)
    decision_hash: str = field(default="")
    signature: str | None = None
    public_key_id: str | None = None

    # ── Cross-invariant validation ────────────────────────────────────────────

    def __post_init__(self) -> None:
        if self.allowed and self.status is not SolverStatus.SAFE:
            raise ValueError(
                f"Decision.allowed=True requires status=SAFE, "
                f"got status={self.status.name}. "
                "Use Decision.safe() to construct an allowed decision."
            )
        if not self.allowed and self.status is SolverStatus.SAFE:
            raise ValueError(
                "Decision(allowed=False, status=SAFE) is inconsistent. "
                "SAFE status implies the action is permitted."
            )
        # Compute decision_hash if not already set
        if not self.decision_hash:
            object.__setattr__(self, "decision_hash", self._compute_hash())

    # ── Hash computation ──────────────────────────────────────────────────────

    def _compute_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of this Decision.

        Canonical representation includes intent_dump, state_dump, policy,
        status, allowed, violated_invariants, and explanation.
        signature and public_key_id are intentionally excluded (not circular).
        """
        canonical = {
            "allowed": bool(self.allowed),
            "explanation": str(self.explanation or ""),
            "intent_dump": _make_json_safe(self.intent_dump),
            "policy": str(self.metadata.get("policy", "") if self.metadata else ""),
            "state_dump": _make_json_safe(self.state_dump),
            "status": str(self.status.value if hasattr(self.status, "value") else self.status),
            "violated_invariants": sorted(str(v) for v in (self.violated_invariants or ())),
        }
        try:
            serialized = _canonical_bytes(canonical)
        except Exception:
            import json
            serialized = json.dumps(canonical, sort_keys=True, default=str).encode()
        return hashlib.sha256(serialized).hexdigest()

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable ``dict`` representation.

        All fields are converted to basic Python types:

        * ``status``              → its ``.value`` string
        * ``violated_invariants`` → list of strings
        * All other fields        → unchanged (caller is responsible for
          ensuring ``metadata`` values are JSON-compatible)
        """
        return {
            "decision_id": self.decision_id,
            "allowed": self.allowed,
            "status": self.status.value,
            "violated_invariants": list(self.violated_invariants),
            "explanation": self.explanation,
            "solver_time_ms": self.solver_time_ms,
            "metadata": dict(self.metadata),
            "intent_dump": _make_json_safe(self.intent_dump),
            "state_dump": _make_json_safe(self.state_dump),
            "decision_hash": self.decision_hash,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
        }

    # ── Factory: SAFE ─────────────────────────────────────────────────────────

    @classmethod
    def safe(
        cls,
        *,
        solver_time_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
        intent_dump: dict | None = None,
        state_dump: dict | None = None,
    ) -> "Decision":
        """Construct an *allowed* decision (all invariants satisfied).

        Args:
            solver_time_ms: Time spent in Z3 (milliseconds).
            metadata:       Optional caller-supplied tracing data.
            intent_dump:    Serialized intent dict for hash replay.
            state_dump:     Serialized state dict for hash replay.
        """
        return cls(
            allowed=True,
            status=SolverStatus.SAFE,
            solver_time_ms=solver_time_ms,
            metadata=dict(metadata) if metadata is not None else {},
            intent_dump=dict(intent_dump) if intent_dump is not None else {},
            state_dump=dict(state_dump) if state_dump is not None else {},
        )

    # ── Factory: UNSAFE ───────────────────────────────────────────────────────

    @classmethod
    def unsafe(
        cls,
        *,
        violated_invariants: tuple[str, ...] = (),
        explanation: str = "",
        solver_time_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
        intent_dump: dict | None = None,
        state_dump: dict | None = None,
    ) -> "Decision":
        """Construct a *blocked* decision (one or more invariants violated).

        Args:
            violated_invariants: Labels of violated invariants.
            explanation:         Human-readable summary of violations.
            solver_time_ms:      Time spent in Z3 (milliseconds).
            metadata:            Optional caller-supplied tracing data.
            intent_dump:         Serialized intent dict for hash replay.
            state_dump:          Serialized state dict for hash replay.
        """
        if not explanation and violated_invariants:
            explanation = "Invariant(s) violated: " + ", ".join(violated_invariants)
        return cls(
            allowed=False,
            status=SolverStatus.UNSAFE,
            violated_invariants=violated_invariants,
            explanation=explanation,
            solver_time_ms=solver_time_ms,
            metadata=dict(metadata) if metadata is not None else {},
            intent_dump=dict(intent_dump) if intent_dump is not None else {},
            state_dump=dict(state_dump) if state_dump is not None else {},
        )

    # ── Factory: TIMEOUT ──────────────────────────────────────────────────────

    @classmethod
    def timeout(
        cls,
        *,
        label: str,
        timeout_ms: int,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision for a Z3 solver timeout.

        Args:
            label:      The invariant label that timed out.
            timeout_ms: The timeout budget that was exceeded.
            metadata:   Optional caller-supplied tracing data.
        """
        return cls(
            allowed=False,
            status=SolverStatus.TIMEOUT,
            violated_invariants=(label,),
            explanation=(
                f"Solver timeout after {timeout_ms} ms on invariant '{label}'. "
                "Increase GuardConfig.solver_timeout_ms or simplify the constraint."
            ),
            metadata=dict(metadata) if metadata is not None else {},
        )

    # ── Factory: ERROR ────────────────────────────────────────────────────────

    @classmethod
    def error(
        cls,
        *,
        reason: str = "Internal verification error — action blocked (fail-safe).",
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision for an unexpected internal error.

        The fail-safe contract guarantees that any unhandled exception inside
        ``Guard.verify()`` produces this decision rather than propagating.

        Args:
            reason:   Human-readable error summary (safe to log).
            metadata: Optional caller-supplied tracing data.
        """
        return cls(
            allowed=False,
            status=SolverStatus.ERROR,
            explanation=reason,
            metadata=dict(metadata) if metadata is not None else {},
        )

    # ── Factory: STALE_STATE ──────────────────────────────────────────────────

    @classmethod
    def stale_state(
        cls,
        *,
        expected: str,
        actual: str,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision for a ``state_version`` mismatch.

        Args:
            expected: The version declared in ``Policy.Meta.version``.
            actual:   The version received in the state data.
            metadata: Optional caller-supplied tracing data.
        """
        return cls(
            allowed=False,
            status=SolverStatus.STALE_STATE,
            explanation=(
                f"State version mismatch: policy expects '{expected}', "
                f"state carries '{actual}'. Refresh state before retrying."
            ),
            metadata=dict(metadata) if metadata is not None else {},
        )

    # ── Factory: VALIDATION_FAILURE ───────────────────────────────────────────

    @classmethod
    def validation_failure(
        cls,
        *,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision for a Pydantic validation failure.

        Args:
            reason:   Human-readable description of the validation error.
            metadata: Optional caller-supplied tracing data.
        """
        return cls(
            allowed=False,
            status=SolverStatus.VALIDATION_FAILURE,
            explanation=reason,
            metadata=dict(metadata) if metadata is not None else {},
        )

    # ── Factory: RATE_LIMITED ─────────────────────────────────────────────────────

    @classmethod
    def rate_limited(
        cls,
        reason: str = "Request shed by adaptive load limiter. Retry after backoff.",
        *,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision for a shed request.

        Returns allowed=False, status=RATE_LIMITED.
        The caller MUST NOT allow the action regardless of this decision.

        Args:
            reason:   Human-readable shedding explanation.
            metadata: Optional caller-supplied tracing data.
        """
        return cls(
            allowed=False,
            status=SolverStatus.RATE_LIMITED,
            explanation=reason,
            metadata=dict(metadata) if metadata is not None else {},
        )

    # ── Factory: CONSENSUS_FAILURE ────────────────────────────────────────────

    @classmethod
    def consensus_failure(
        cls,
        *,
        reason: str = "Dual-LLM models disagreed on intent extraction — action blocked.",
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision for a dual-LLM consensus disagreement.

        Unlike :meth:`error`, this is a deliberate, expected policy outcome —
        not an internal fault.  The two LLMs returned different structured
        intents; without agreement, the action cannot proceed.

        Operationally: a spike in ``CONSENSUS_FAILURE`` decisions signals
        ambiguous or adversarially crafted user inputs, not a system fault.
        A spike in ``ERROR`` decisions signals an internal failure.  Never
        conflate them in dashboards or alerts.

        Args:
            reason:   Human-readable explanation (safe to log).
            metadata: Optional caller-supplied tracing data.
        """
        return cls(
            allowed=False,
            status=SolverStatus.CONSENSUS_FAILURE,
            explanation=reason,
            metadata=dict(metadata) if metadata is not None else {},
        )
