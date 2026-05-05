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

except ImportError:
    import json as _json

    def _canonical_bytes(payload: dict[str, Any]) -> bytes:
        """Deterministic canonical bytes via stdlib json (sorted keys)."""
        return _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


__all__ = ["Decision", "SolverStatus", "_build_decision_canonical", "_make_json_safe"]


def _make_json_safe(d: dict[str, Any]) -> dict[str, Any]:
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
    if isinstance(v, int | float):
        return v
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return _make_json_safe(v)
    if isinstance(v, list | tuple):
        return [_json_safe_value(i) for i in v]
    if hasattr(v, "isoformat"):  # datetime
        return v.isoformat()
    return str(v)


def _build_decision_canonical(
    *,
    allowed: bool,
    explanation: str,
    intent_dump: dict[str, Any],
    policy: str,
    state_dump: dict[str, Any],
    status: str,
    violated_invariants: Any,
) -> dict[str, Any]:
    """Build the canonical dict used for :meth:`Decision._compute_hash`.

    Extracted as a module-level function so the CLI audit verifier can
    import it directly — single source of truth for the canonical-field
    set and their serialisation rules.  Any change here is automatically
    reflected in both the library and the CLI with no risk of silent drift.

    Args:
        allowed:             ``Decision.allowed`` as a plain ``bool``.
        explanation:         Human-readable explanation string.
        intent_dump:         Serialised intent dict (``Decision.intent_dump``).
        policy:              Policy name extracted from ``Decision.metadata``.
        state_dump:          Serialised state dict (``Decision.state_dump``).
        status:              ``SolverStatus`` value string.
        violated_invariants: Iterable of invariant label strings.

    Returns:
        Canonical ``dict`` ready for :func:`_canonical_bytes`.
    """
    return {
        "allowed": bool(allowed),
        "explanation": str(explanation or ""),
        "hash_alg": "sha256-v1",
        "intent_dump": _make_json_safe(dict(intent_dump) if intent_dump else {}),
        "policy": str(policy or ""),
        "state_dump": _make_json_safe(dict(state_dump) if state_dump else {}),
        "status": str(status or ""),
        "violated_invariants": sorted(str(v) for v in (violated_invariants or ())),
    }


# ---------------------------------------------------------------------------
# Compatibility shim: FrozenInstanceError was added in Python 3.11.
# In 3.10 frozen dataclasses raise AttributeError directly.
# ---------------------------------------------------------------------------
try:
    from dataclasses import FrozenInstanceError  # type: ignore[attr-defined,unused-ignore]
except ImportError:  # Python 3.10
    FrozenInstanceError = AttributeError  # type: ignore[assignment, misc]


# ── SolverStatus ──────────────────────────────────────────────────────────────


class SolverStatus(enum.StrEnum):
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

    GOVERNANCE_BLOCKED = "governance_blocked"
    """Post-Z3 governance gate denied the action.

    Raised by one of three inline governance steps that run after the Z3
    solver returns SAFE:

    * **Privilege scope** — :class:`~pramanix.privilege.ScopeEnforcer` found
      the requested tool's required scopes were not in the execution context.
    * **Human oversight** — :class:`~pramanix.oversight.InMemoryApprovalWorkflow`
      requires a human approval that has not yet been granted.
    * **Information-flow control** — :class:`~pramanix.ifc.FlowEnforcer`
      denied a data-flow that would violate the configured :class:`~pramanix.ifc.FlowPolicy`.

    The ``metadata`` dict carries ``stage`` (``"privilege"`` | ``"oversight"``
    | ``"ifc"``) and, when applicable, ``oversight_request_id`` so callers can
    route human-approval requests.
    """


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
        SolverStatus.GOVERNANCE_BLOCKED,
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
    intent_dump: dict[str, Any] = field(default_factory=dict)
    state_dump: dict[str, Any] = field(default_factory=dict)
    decision_hash: str = field(default="")
    hash_alg: str = "sha256-v1"
    signature: str | None = None
    public_key_id: str | None = None
    policy_hash: str | None = None
    """SHA-256 fingerprint of the policy that produced this decision.
    Set by Guard._sign_decision().  Not included in decision_hash (treated
    as metadata, like signature and public_key_id).
    """

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

    # ── Python hash (for use in sets/dicts) ──────────────────────────────────

    def __hash__(self) -> int:
        # M-47: auto-generated __hash__ includes unhashable dict fields.
        # Hash only the stable, hashable identity fields.
        return hash((self.decision_id, self.decision_hash, self.status, self.allowed))

    # ── Hash computation ──────────────────────────────────────────────────────

    def _compute_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of this Decision.

        Delegates to the module-level :func:`_build_decision_canonical` so
        that the CLI audit verifier shares the exact same canonical-dict
        construction logic — single source of truth, no drift risk.
        """
        # M-50: use self.policy_hash directly — not metadata.get("policy").
        policy = str(self.policy_hash or "")
        status = str(self.status.value if hasattr(self.status, "value") else self.status)
        canonical = _build_decision_canonical(
            allowed=self.allowed,
            explanation=self.explanation,
            intent_dump=self.intent_dump,
            policy=policy,
            state_dump=self.state_dump,
            status=status,
            violated_invariants=self.violated_invariants,
        )
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
            "hash_alg": self.hash_alg,
            "signature": self.signature,
            "public_key_id": self.public_key_id,
            "policy_hash": self.policy_hash,
        }

    # ── Factory: SAFE ─────────────────────────────────────────────────────────

    @classmethod
    def safe(
        cls,
        *,
        solver_time_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
        intent_dump: dict[str, Any] | None = None,
        state_dump: dict[str, Any] | None = None,
    ) -> Decision:
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
        intent_dump: dict[str, Any] | None = None,
        state_dump: dict[str, Any] | None = None,
    ) -> Decision:
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

    # ── Factory: GOVERNANCE_BLOCKED ───────────────────────────────────────────

    @classmethod
    def governance_blocked(
        cls,
        *,
        reason: str,
        stage: str = "governance",
        metadata: dict[str, Any] | None = None,
        intent_dump: dict[str, Any] | None = None,
        state_dump: dict[str, Any] | None = None,
    ) -> Decision:
        """Construct a *blocked* decision when a post-Z3 governance gate fires.

        This factory is used by the three inline governance steps that run
        after the Z3 solver returns SAFE:

        * ``stage="privilege"`` — :class:`~pramanix.privilege.ScopeEnforcer`
          denied the tool's required scopes.
        * ``stage="oversight"`` — human approval is required but not yet
          granted.  ``metadata["oversight_request_id"]`` carries the ID the
          caller must poll or route to a reviewer.
        * ``stage="ifc"`` — :class:`~pramanix.ifc.FlowEnforcer` denied the
          data flow.

        Args:
            reason:       Human-readable explanation of why the gate fired.
            stage:        Which governance gate blocked (``"privilege"``,
                          ``"oversight"``, or ``"ifc"``).
            metadata:     Additional context (e.g. ``oversight_request_id``).
            intent_dump:  Serialized intent dict for audit trail.
            state_dump:   Serialized state dict for audit trail.
        """
        merged: dict[str, Any] = {"stage": stage}
        if metadata:
            merged.update(metadata)
        return cls(
            allowed=False,
            status=SolverStatus.GOVERNANCE_BLOCKED,
            explanation=reason,
            metadata=merged,
            intent_dump=dict(intent_dump) if intent_dump is not None else {},
            state_dump=dict(state_dump) if state_dump is not None else {},
        )

    # ── Factory: CACHE_HIT ───────────────────────────────────────────────────

    @classmethod
    def cache_hit(
        cls,
        *,
        base: Decision,
    ) -> Decision:
        """Return a copy of *base* decorated with the ``CACHE_HIT`` observability tag.

        M-30: ``SolverStatus.CACHE_HIT`` is an *observability decorator* — it
        signals that the input was served from cache before Z3 ran.  The
        underlying ``allowed`` and ``status`` values are preserved from *base*;
        CACHE_HIT is recorded in ``metadata["_solver_status_tag"]`` so dashboards
        can distinguish cache-path from cold-path decisions without changing
        policy-outcome semantics.

        Args:
            base: The original :class:`Decision` produced by Z3.
        """
        return cls(
            allowed=base.allowed,
            status=base.status,
            violated_invariants=base.violated_invariants,
            explanation=base.explanation,
            metadata={
                **base.metadata,
                "_solver_status_tag": SolverStatus.CACHE_HIT.value,
            },
            solver_time_ms=base.solver_time_ms,
            decision_id=base.decision_id,
            intent_dump=dict(base.intent_dump),
            state_dump=dict(base.state_dump),
            decision_hash=base.decision_hash,
            signature=base.signature,
            public_key_id=base.public_key_id,
            policy_hash=base.policy_hash,
        )

    # ── Deserialisation ────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Decision:
        """Reconstruct a :class:`Decision` from its :meth:`to_dict` representation.

        This is the inverse of :meth:`to_dict` and is the single authoritative
        deserialisation path.  It is used by the CLI audit verifier, test
        fixtures, and any distributed component that serialises decisions to
        JSON for storage or transport.

        The reconstructed ``Decision`` has:

        * ``allowed``, ``status``, ``violated_invariants``, ``explanation``,
          ``solver_time_ms``, ``metadata``, ``intent_dump``, ``state_dump``
          from the dict.
        * ``decision_id``, ``decision_hash``, ``signature``, ``public_key_id``,
          ``policy_hash`` preserved from the dict (not re-computed).
          ``decision_hash`` is passed directly to bypass recomputation in
          ``__post_init__`` — the stored hash is authoritative for audit replay.

        Args:
            d: A dict as returned by :meth:`to_dict`.

        Returns:
            A :class:`Decision` instance equivalent to the original.

        Raises:
            KeyError:   If a required field is missing from *d*.
            ValueError: If ``status`` is not a valid :class:`SolverStatus` value,
                        or if the ``allowed``/``status`` invariant is violated.
        """
        return cls(
            allowed=bool(d["allowed"]),
            status=SolverStatus(d["status"]),
            violated_invariants=tuple(d.get("violated_invariants", [])),
            explanation=str(d.get("explanation", "")),
            solver_time_ms=float(d.get("solver_time_ms", 0.0)),
            metadata=dict(d.get("metadata", {})),
            decision_id=str(d["decision_id"]),
            intent_dump=dict(d.get("intent_dump", {})),
            state_dump=dict(d.get("state_dump", {})),
            # Preserve the stored hash — do NOT recompute.  Pass it as a
            # non-empty string so __post_init__ skips recomputation.
            decision_hash=str(d.get("decision_hash", "")),
            signature=d.get("signature"),
            public_key_id=d.get("public_key_id"),
            policy_hash=d.get("policy_hash"),
        )

    # ── Human-readable representation ────────────────────────────────────────

    def __repr__(self) -> str:
        """Return a concise, safe representation that never exposes sensitive data.

        ``intent_dump`` and ``state_dump`` are intentionally excluded — they
        may contain financial values, PII, or other sensitive fields that must
        not appear in logs, error messages, or REPL output.

        Example::

            Decision(id='3fa85f64', allowed=False, status=UNSAFE,
                     violated=['non_negative_balance'])
        """
        short_id = self.decision_id[:8] if self.decision_id else "?"
        vi = list(self.violated_invariants)
        return (
            f"Decision(id={short_id!r}, allowed={self.allowed}, "
            f"status={self.status.name}, violated={vi!r})"
        )
