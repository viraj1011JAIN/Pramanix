# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix exception hierarchy.

Every exception raised inside ``Guard.verify()`` is caught and collapsed into a
``Decision(allowed=False)`` so the fail-safe invariant is preserved:
**any error path → BLOCK, never ALLOW**.

Hierarchy::

    PramanixError
    ├── InputTooLongError               # user input exceeds configured character limit
    ├── PolicyError                     # bad policy definition (compile-time)
    │   ├── PolicyCompilationError      # unsupported type / general compile error
    │   ├── InvariantLabelError         # missing / duplicate .named() label
    │   ├── FieldTypeError              # unsupported or mismatched Field type
    │   └── TranspileError              # DSL tree → Z3 AST conversion failure
    ├── GuardError                      # runtime verification errors
    │   ├── ValidationError             # Pydantic validation failure (wraps pydantic exc)
    │   ├── StateValidationError        # state_version missing or mismatched
    │   ├── SolverTimeoutError          # Z3 exceeded the time budget
    │   ├── SolverError                 # unexpected Z3 result
    │   ├── WorkerError                 # worker-pool error (M2)
    │   ├── ExtractionFailureError      # LLM returned bad/unparseable JSON (M3)
    │   ├── ExtractionMismatchError     # dual-model consensus failed (M3)
    │   ├── LLMTimeoutError             # LLM API timed out after retries (M3)
    │   ├── SemanticPolicyViolation     # post-consensus business-rule check (M3)
    │   └── InjectionBlockedError       # pre-LLM injection scorer blocked input (M3)
    └── ConfigurationError              # Guard / Policy misconfiguration
"""
from __future__ import annotations

__all__ = [
    "ConfigurationError",
    # Translator exceptions
    "ExtractionFailureError",
    "ExtractionMismatchError",
    "FieldTypeError",
    "FlowViolationError",
    "GuardError",
    "GuardViolationError",
    "InjectionBlockedError",
    "InputTooLongError",
    "InvariantLabelError",
    "LLMTimeoutError",
    "MemoryViolationError",
    "MigrationError",
    "OversightRequiredError",
    "PolicyCompilationError",
    "PolicyError",
    "PramanixError",
    "PrivilegeEscalationError",
    "ProvenanceError",
    "ResolverConflictError",
    # Hardening exceptions (Phase 4)
    "SemanticPolicyViolation",
    "SolverError",
    "SolverTimeoutError",
    "StateValidationError",
    "TranspileError",
    "ValidationError",
    "WorkerError",
]



# ── Root ──────────────────────────────────────────────────────────────────────


class PramanixError(Exception):
    """Base class for all Pramanix exceptions."""


# ── Input validation errors ───────────────────────────────────────────────────


class InputTooLongError(PramanixError):
    """User input exceeds the maximum allowed character limit.

    Raised by :func:`~pramanix.translator._sanitise.sanitise_user_input` when
    the character count of the raw input exceeds the configured
    ``max_input_chars`` limit.  Previously Pramanix silently truncated long
    inputs; this exception makes the rejection explicit and auditable.

    Attributes:
        actual:            Actual character count of the input.
        limit:             Maximum allowed character count.
        truncated_preview: First 100 chars of the input for diagnostic logging.
    """

    def __init__(self, actual: int, limit: int, truncated_preview: str) -> None:
        self.actual = actual
        self.limit = limit
        self.truncated_preview = truncated_preview
        super().__init__(
            f"Input too long: {actual} chars exceeds limit of {limit}. "
            f"Preview: {truncated_preview!r}"
        )


# ── Policy definition errors (compile-time) ───────────────────────────────────


class PolicyError(PramanixError):
    """Raised when a :class:`~pramanix.policy.Policy` definition is invalid.

    These are programmer errors that should be caught during development,
    not at request-handling time.
    """


class PolicyCompilationError(PolicyError):
    """Raised when a Policy cannot be compiled due to an unsupported type or
    structural issue in the DSL.

    Examples: using ``str`` or ``list`` as a :class:`~pramanix.expressions.Field`
    Python type; circular field references; type-mapping failures.
    """


class InvariantLabelError(PolicyError):
    """An invariant is missing a ``.named()`` label, or labels are duplicated.

    Every invariant passed to ``Guard.verify`` must carry a unique string
    label so that violation attribution is unambiguous.
    """


class FieldTypeError(PolicyError):
    """A :class:`~pramanix.expressions.Field` has an unsupported or mismatched type.

    Raised when ``z3_type`` is not one of ``"Real"``, ``"Int"``, ``"Bool"``,
    or when a runtime value cannot be coerced to the declared sort.
    """


class TranspileError(PolicyError):
    """The DSL expression tree could not be converted to a Z3 formula.

    Raised by the transpiler when it encounters an unknown node type.
    Wraps the original exception as ``__cause__`` when applicable.
    """


# ── Runtime solver / guard errors ─────────────────────────────────────────────


class GuardError(PramanixError):
    """Base class for runtime errors that occur inside the Guard or Solver.

    All ``GuardError`` subclasses are caught by the Guard's fail-safe wrapper
    and converted to ``Decision.error()``.
    """


class ValidationError(GuardError):
    """Pydantic intent or state model validation failed.

    Wraps :class:`pydantic.ValidationError` so that Pydantic internals are
    never exposed to callers.  The ``__cause__`` attribute holds the original
    Pydantic exception when available.

    Converted by ``Guard.verify()`` to ``Decision.validation_failure()``.
    """


class StateValidationError(GuardError):
    """The ``state_version`` field is missing from the state model or data,
    or the state version does not match ``Policy.Meta.version``.

    Attributes:
        expected:  The version the policy requires (``Policy.Meta.version``),
                   or ``None`` if the state model itself is missing the field.
        actual:    The version found in the incoming state data, or ``None``
                   if the field was absent from the data.
    """

    def __init__(
        self,
        message: str,
        *,
        expected: str | None = None,
        actual: str | None = None,
    ) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(message)


class SolverTimeoutError(GuardError):
    """Z3 solver exceeded the configured timeout for one or more invariants.

    Attributes:
        label:      The invariant label whose check timed out.
        timeout_ms: The timeout budget that was exceeded (milliseconds).
    """

    def __init__(self, label: str, timeout_ms: int) -> None:
        self.label = label
        self.timeout_ms = timeout_ms
        super().__init__(
            f"Z3 timeout on invariant '{label}' after {timeout_ms} ms. "
            "Increase GuardConfig.solver_timeout_ms or simplify the constraint."
        )


class SolverError(GuardError):
    """Unexpected Z3 solver failure (result is ``z3.unknown`` for a non-timeout reason).

    This should never occur in normal operation.  If it does, the Guard
    fail-safe returns ``Decision.error()``.
    """


class WorkerError(GuardError):
    """Worker-pool error raised when a thread or process worker fails.

    Raised when a thread or process worker raises an unhandled exception,
    or when the worker pool cannot be initialised.
    """


class GuardViolationError(GuardError):
    """Raised by the ``@guard`` decorator when ``decision.allowed`` is ``False``.

    The ``decision`` attribute holds the full :class:`~pramanix.decision.Decision`
    object so callers can inspect ``status``, ``violated_invariants``, and
    ``explanation`` without needing to catch a different exception type.

    Attributes:
        decision: The :class:`~pramanix.decision.Decision` that blocked the action.

    Example::

        try:
            await transfer(intent, state)
        except GuardViolationError as exc:
            log.warning("blocked", status=exc.decision.status.value)
    """

    def __init__(self, decision: object) -> None:
        # Avoid importing Decision at class definition time (circular risk).
        self.decision = decision
        super().__init__(
            f"Guard blocked action: {decision.status!s} — {decision.explanation}"
        )


# ── Configuration errors ──────────────────────────────────────────────────────


class ConfigurationError(PramanixError):
    """Guard or Policy is misconfigured.

    Examples: non-positive ``solver_timeout_ms``, zero ``max_workers``,
    conflicting executor mode settings.
    """


# ── Translator errors ─────────────────────────────────────────────────────────


class ExtractionFailureError(GuardError):
    """LLM failed to produce parseable JSON or return a schema-valid response.

    Raised when:

    * The LLM response cannot be decoded as valid JSON.
    * The parsed JSON does not satisfy the intent schema validation.
    * The LLM returns an empty or nonsensical response.

    Always causes ``Guard.parse_and_verify()`` to return ``Decision.error()``
    (fail-safe: extraction failure → BLOCK).
    """


class ExtractionMismatchError(GuardError):
    """Two LLM models extracted conflicting values for one or more intent fields.

    Raised by :func:`~pramanix.translator.redundant.extract_with_consensus`
    when dual-model consensus fails.  This indicates the request was
    ambiguous or potentially adversarial.

    Always causes ``Guard.parse_and_verify()`` to return ``Decision.error()``
    (fail-safe: disagreement → BLOCK).

    Attributes:
        model_a:    Identifier of the first model.
        model_b:    Identifier of the second model.
        mismatches: Mapping of field name → ``(value_from_a, value_from_b)``.
    """

    def __init__(
        self,
        message: str,
        *,
        model_a: str = "",
        model_b: str = "",
        mismatches: dict[str, tuple[object, object]] | None = None,
    ) -> None:
        self.model_a = model_a
        self.model_b = model_b
        self.mismatches: dict[str, tuple[object, object]] = mismatches or {}
        super().__init__(message)

    @property
    def disagreeing_fields(self) -> list[str]:
        """Ordered list of field names where the two models disagreed."""
        return sorted(self.mismatches.keys())


class LLMTimeoutError(GuardError):
    """LLM API call exceeded the configured timeout after all retry attempts.

    Raised when a network call to an LLM provider times out and all
    tenacity exponential-backoff retries are exhausted.

    Always causes ``Guard.parse_and_verify()`` to return ``Decision.error()``
    (fail-safe: timeout → BLOCK).

    Attributes:
        model:    Name of the model that timed out.
        attempts: Total number of attempts made (including the initial call).
    """

    def __init__(self, message: str, *, model: str = "", attempts: int = 0) -> None:
        self.model = model
        self.attempts = attempts
        super().__init__(message)


class SemanticPolicyViolation(GuardError):
    """Extracted intent passed LLM consensus but violates a host-side business rule.

    This is the Layer-2.5 defence: a fast pure-Python check applied
    **after** dual-model agreement and **before** invoking the Z3 solver.
    It catches obvious violations (zero/negative amount, full-balance drain,
    daily limit breach) immediately without solver overhead.

    Always causes ``Guard.parse_and_verify()`` to return ``Decision.error()``
    (fail-safe: semantic violation → BLOCK).
    """


class InjectionBlockedError(GuardError):
    """User input was blocked by the pre-LLM injection confidence scorer.

    Raised when :func:`~pramanix.translator._sanitise.injection_confidence_score`
    returns a value ≥ 0.5, indicating a probable adversarial prompt-injection
    attempt.  The LLM models are **not** consulted for blocked inputs.

    Always causes ``Guard.parse_and_verify()`` to return ``Decision.error()``
    (fail-safe: injection block → BLOCK).
    """


class ResolverConflictError(PramanixError):
    """A resolver name collision was detected during registration.

    Raised by :meth:`~pramanix.resolvers.ResolverRegistry.register` when a
    name is already registered and ``force=False`` (the default).  Pass
    ``force=True`` to overwrite the existing resolver with a warning.
    """


class MigrationError(PramanixError):
    """A :class:`~pramanix.migration.PolicyMigration` could not be applied.

    Raised by :meth:`~pramanix.migration.PolicyMigration.migrate` when
    ``strict=True`` and a key declared in ``field_renames`` is absent from
    the state dict being migrated.

    Attributes:
        missing_key:    The ``field_renames`` key that was not found.
        from_version:   Version string of the migration source.
        to_version:     Version string of the migration target.
    """

    def __init__(
        self,
        message: str,
        *,
        missing_key: str = "",
        from_version: str = "",
        to_version: str = "",
    ) -> None:
        self.missing_key = missing_key
        self.from_version = from_version
        self.to_version = to_version
        super().__init__(message)


# ── Information-flow control errors ──────────────────────────────────────────


class FlowViolationError(PramanixError):
    """A data flow was attempted that violates the active :class:`FlowPolicy`.

    Raised by :class:`~pramanix.ifc.FlowEnforcer` when data at trust label
    *source_label* cannot flow to a sink at *sink_label* under the registered
    policy.  The ``rule`` attribute holds the matching :class:`FlowRule` when
    one was found; ``None`` when the flow was denied by the default-deny policy.

    Attributes:
        source_label:    The trust label of the data being moved.
        sink_label:      The trust label of the target sink.
        sink_component:  The name of the receiving component.
        rule:            The :class:`FlowRule` that matched, if any.
    """

    def __init__(
        self,
        message: str,
        *,
        source_label: object = None,
        sink_label: object = None,
        sink_component: str = "",
        rule: object = None,
    ) -> None:
        self.source_label = source_label
        self.sink_label = sink_label
        self.sink_component = sink_component
        self.rule = rule
        super().__init__(message)


# ── Privilege separation errors ───────────────────────────────────────────────


class PrivilegeEscalationError(PramanixError):
    """An operation required a scope not present in the active capability manifest.

    Raised by :class:`~pramanix.privilege.ScopeEnforcer` when a tool or action
    requires *required_scope* but the current execution context only holds
    *held_scopes*.

    Attributes:
        required_scope:  The missing scope name.
        held_scopes:     Frozenset of scope names currently held.
        tool:            Name of the tool / action that triggered the check.
    """

    def __init__(
        self,
        message: str,
        *,
        required_scope: str = "",
        held_scopes: frozenset[str] | None = None,
        tool: str = "",
    ) -> None:
        self.required_scope = required_scope
        self.held_scopes: frozenset[str] = held_scopes or frozenset()
        self.tool = tool
        super().__init__(message)


# ── Human oversight errors ────────────────────────────────────────────────────


class OversightRequiredError(PramanixError):
    """An action requires human approval before it can be executed.

    Raised by :class:`~pramanix.oversight.ApprovalWorkflow` when an action
    with a scope that requires dual-control or explicit approval is attempted
    without a pending approval already granted.

    Attributes:
        request_id:   The UUID of the :class:`~pramanix.oversight.ApprovalRequest`
                      that was created.
        action:       Description of the blocked action.
        reason:       Why approval is required.
    """

    def __init__(
        self,
        message: str,
        *,
        request_id: str = "",
        action: str = "",
        reason: str = "",
    ) -> None:
        self.request_id = request_id
        self.action = action
        self.reason = reason
        super().__init__(message)


# ── Memory security errors ────────────────────────────────────────────────────


class MemoryViolationError(PramanixError):
    """A memory write or read violates the active memory-security policy.

    Raised by :class:`~pramanix.memory.SecureMemoryStore` when:

    * UNTRUSTED data attempts to write to a partition at CONFIDENTIAL or
      higher trust level (write-up prevention).
    * A read attempts to retrieve data across tenant or workflow boundaries
      (isolation violation).

    Attributes:
        partition_id:  Identifier of the partition being accessed.
        operation:     ``"read"`` or ``"write"``.
        reason:        Human-readable reason for the rejection.
    """

    def __init__(
        self,
        message: str,
        *,
        partition_id: str = "",
        operation: str = "",
        reason: str = "",
    ) -> None:
        self.partition_id = partition_id
        self.operation = operation
        self.reason = reason
        super().__init__(message)


# ── Provenance errors ─────────────────────────────────────────────────────────


class ProvenanceError(PramanixError):
    """A provenance chain is broken, incomplete, or tampered.

    Raised by :class:`~pramanix.provenance.ProvenanceChain` when a chain link
    fails integrity verification or required fields are absent.

    Attributes:
        decision_id:  The decision whose provenance could not be verified.
        reason:       Specific failure description.
    """

    def __init__(
        self,
        message: str,
        *,
        decision_id: str = "",
        reason: str = "",
    ) -> None:
        self.decision_id = decision_id
        self.reason = reason
        super().__init__(message)
