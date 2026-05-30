# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Guard configuration — immutable GuardConfig dataclass, logging, observability.

Extracted from ``guard.py`` to separate configuration concerns from orchestration.
All public names remain importable from ``pramanix.guard`` for backward compatibility.

Contents
--------
* Structlog secrets-redaction processor and logging setup.
* OpenTelemetry ``_span()`` context-manager (no-op when ``otel`` extra absent).
* Prometheus counter/histogram initialisation (no-op when ``prometheus-client`` absent).
* Module-level :class:`~pramanix.resolvers.ResolverRegistry` singleton.
* Environment-variable helper functions (``_env_str``, ``_env_int``, ``_env_bool``).
* :class:`GuardConfig` — the immutable configuration dataclass for :class:`~pramanix.guard.Guard`.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from pramanix.exceptions import ConfigurationError
from pramanix.resolvers import resolver_registry

if TYPE_CHECKING:
    from collections.abc import Callable

    from pramanix.crypto import PramanixSigner
    from pramanix.solver import SolverProtocol

__all__ = ["GovernanceConfig", "GuardConfig", "Path"]

from pramanix.governance_config import GovernanceConfig

# ── Structlog secrets redaction ───────────────────────────────────────────────
# Pattern matches any event-dict key that looks like a credential.
# The processor is applied BEFORE any renderer so secrets never reach disk.
_SECRET_KEY_RE = re.compile(
    r"(secret|api[_\-]?key|token|hmac|password|passwd|credential|private[_\-]?key"
    r"|access[_\-]?key|signing[_\-]?key|session|authorization|bearer|pii|ssn|phi)",
    re.IGNORECASE,
)
_REDACTED = "<redacted>"


def _redact_value(v: Any, depth: int = 0) -> Any:
    """Recursively redact secret values in nested dicts (§14.2 fix)."""
    if depth > 8:
        return v  # guard against pathological nesting
    if isinstance(v, dict):
        return {
            kk: (_REDACTED if _SECRET_KEY_RE.search(str(kk)) else _redact_value(vv, depth + 1))
            for kk, vv in v.items()
        }
    return v


def _redact_secrets_processor(
    _logger: Any,
    _method: str,
    event_dict: Any,
) -> Any:
    """Structlog processor — redact any event-dict key that looks like a secret.

    §14.2 fix: recurses into nested dicts so that ``{"config": {"api_key": "sk-..."}}``
    is fully redacted, not just top-level keys.

    Applied as the first processor in the chain so that secret values are
    never visible in any downstream processor, renderer, or log sink.

    Matches keys containing: ``secret``, ``api_key``, ``apikey``, ``token``,
    ``hmac``, ``password``, ``passwd``, ``credential``, ``private_key``.
    """
    return {
        k: (_REDACTED if _SECRET_KEY_RE.search(k) else _redact_value(v))
        for k, v in event_dict.items()
    }


def _safe_add_logger_name(logger: Any, method_name: str, event_dict: Any) -> Any:
    """Add logger name to event dict, safely handling structlog's PrintLogger.

    ``structlog.stdlib.add_logger_name`` calls ``logger.name`` which only
    exists on stdlib ``logging.Logger`` objects.  When structlog is configured
    with ``PrintLoggerFactory()`` (the default in tests and lightweight
    deployments), ``PrintLogger`` has no ``.name`` attribute, causing an
    ``AttributeError`` that propagates out of the logging call.

    This processor is a safe drop-in replacement: it reads ``_record.name``
    for stdlib-bridged log records (identical to the stdlib behaviour) and
    falls back to ``getattr(logger, 'name', 'pramanix')`` for all other
    logger types.
    """
    record = event_dict.get("_record")
    if record is not None:
        event_dict["logger"] = record.name
    else:
        event_dict["logger"] = getattr(logger, "name", "pramanix")
    return event_dict


# Shared pre-chain applied to ALL log events that enter the structlog pipeline,
# whether they originate from structlog.get_logger() or stdlib logging.getLogger().
# _redact_secrets_processor MUST be first so secrets never appear in any
# downstream processor, renderer, or sink.
_SHARED_LOG_PROCESSORS: list[Any] = [
    _redact_secrets_processor,
    structlog.stdlib.add_log_level,
    _safe_add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
    structlog.processors.UnicodeDecoder(),
]

structlog.configure(
    processors=[*_SHARED_LOG_PROCESSORS, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# ── Stdlib logging bridge ─────────────────────────────────────────────────────
# Structlog is configured with LoggerFactory=stdlib.LoggerFactory() above, so
# every structlog.get_logger() call is backed by a stdlib logging.Logger.
# This means ALL log records — whether from structlog.get_logger() or
# logging.getLogger() — flow through the same stdlib handler chain below.
# The ProcessorFormatter applies _SHARED_LOG_PROCESSORS (including
# _redact_secrets_processor) to BOTH sources, then renders to JSON.
# There is exactly ONE output pipeline; no split-brain.
#
# foreign_pre_chain applies _SHARED_LOG_PROCESSORS to stdlib LogRecord objects
# that did NOT originate from structlog (e.g. worker.py's stdlib logger calls).
_stdlib_formatter = structlog.stdlib.ProcessorFormatter(
    processor=structlog.processors.JSONRenderer(),
    foreign_pre_chain=_SHARED_LOG_PROCESSORS,
)
_stdlib_handler = logging.StreamHandler()
_stdlib_handler.setFormatter(_stdlib_formatter)

# Attach once to the "pramanix" root logger.  The guard is idempotent so
# re-importing guard_config in tests never installs duplicate handlers.
# propagate is intentionally left True (Python's default) so that pytest's
# caplog fixture and application-configured root handlers can still capture
# pramanix log records.  Applications that want to suppress duplicate output
# from a separately configured root handler should set
# logging.getLogger("pramanix").propagate = False in their own logging setup.
_pramanix_root = logging.getLogger("pramanix")
if not _pramanix_root.handlers:
    _pramanix_root.addHandler(_stdlib_handler)

_log = structlog.get_logger("pramanix.guard")


# ── OpenTelemetry — graceful optional dependency ──────────────────────────────
# Each span is a no-op (contextlib.nullcontext) when the ``otel`` extra is
# absent, so there is zero overhead on deployments that do not use tracing.


def _noop_span(name: str) -> Any:
    """No-op span context-manager — always available, used as OTel fallback."""
    return contextlib.nullcontext()


try:
    from opentelemetry import trace as _otel_trace

    def _span(name: str) -> Any:
        """Return a live OTel span context-manager."""
        return _otel_trace.get_tracer("pramanix.guard").start_as_current_span(name)

    _OTEL_AVAILABLE = True

except ImportError:
    warnings.warn(
        "opentelemetry is not installed — OTel spans will be no-ops. "
        "Install tracing support with: pip install 'pramanix[otel]'",
        UserWarning,
        stacklevel=2,
    )

    _span = _noop_span
    _OTEL_AVAILABLE = False


# ── Prometheus — graceful optional dependency ─────────────────────────────────
# Each metric is a no-op when ``prometheus_client`` is absent, so there is zero
# overhead on deployments that do not expose a /metrics endpoint.
_decisions_total: Any = None
_decision_latency: Any = None
_solver_timeouts_total: Any = None
_validation_failures_total: Any = None
_PROM_AVAILABLE = False

import threading as _gc_threading  # noqa: E402

_GC_PROM_LOCK = _gc_threading.Lock()
_GC_PROM_METRICS: dict[str, Any] = {}


def _gc_prom_register(factory: Any, name: str, description: str, *args: Any, **kwargs: Any) -> Any:
    """Register a guard_config Prometheus metric or return existing instance."""
    with _GC_PROM_LOCK:
        if name in _GC_PROM_METRICS:
            return _GC_PROM_METRICS[name]
        metric = factory(name, description, *args, **kwargs)
        _GC_PROM_METRICS[name] = metric
        return metric


try:
    import prometheus_client as _prom

    _decisions_total = _gc_prom_register(
        _prom.Counter,
        "pramanix_decisions_total",
        "Total policy decisions by outcome",
        ["policy", "status"],
    )
    _decision_latency = _gc_prom_register(
        _prom.Histogram,
        "pramanix_decision_latency_seconds",
        "End-to-end verify() latency in seconds",
        ["policy"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )
    _solver_timeouts_total = _gc_prom_register(
        _prom.Counter,
        "pramanix_solver_timeouts_total",
        "Number of Z3 solver timeouts by policy",
        ["policy"],
    )
    _validation_failures_total = _gc_prom_register(
        _prom.Counter,
        "pramanix_validation_failures_total",
        "Number of intent/state validation failures by policy",
        ["policy"],
    )
    _PROM_AVAILABLE = True

except ImportError:
    warnings.warn(
        "prometheus_client is not installed — Prometheus metrics will be disabled. "
        "Install metrics support with: pip install 'pramanix[metrics]'",
        UserWarning,
        stacklevel=2,
    )
except ValueError as _prom_val_err:
    import logging as _gc_log

    _gc_log.getLogger(__name__).warning(
        "pramanix.guard_config: Prometheus metric registration error "
        "(name collision with different labelset — this is a programming error): %s",
        _prom_val_err,
    )


# ── Module-level resolver registry ───────────────────────────────────────────
# Alias the public singleton from resolvers.py so that Guard's internal
# clear_cache() call operates on the SAME object that users register into
# via ``from pramanix.resolvers import resolver_registry``.
# Prior to this fix guard_config created its own private ResolverRegistry()
# instance, so user-registered resolvers were silently ignored by Guard.

_resolver_registry = resolver_registry


# ── Environment variable helpers ──────────────────────────────────────────────


def _env_str(key: str, default: str) -> str:
    return os.environ.get(f"PRAMANIX_{key}", default)


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(f"PRAMANIX_{key}")
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(f"PRAMANIX_{key}")
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes"}


# ── Configuration ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GuardConfig:
    """Immutable configuration for a :class:`~pramanix.guard.Guard` instance.

    All fields have defaults and can be overridden via ``PRAMANIX_*``
    environment variables, which are read at *construction time*
    (i.e. when you call ``GuardConfig()``).

    Environment variable precedence: ``PRAMANIX_<UPPER_FIELD_NAME>`` overrides
    the coded default but is superseded by an explicit constructor argument.

    Attributes:
        execution_mode:           Execution backend. ``"sync"`` only in v0.1.
        solver_timeout_ms:        Per-solver Z3 timeout (ms).  Must be > 0.
        max_workers:              Worker pool size (M2).  Must be > 0.
        max_decisions_per_worker: Max verifications per worker before restart.
        worker_warmup:            Run a dummy Z3 solve on worker startup.
        log_level:                Structured logging level string.
        metrics_enabled:          Enable Prometheus metrics export.
        otel_enabled:             Enable OpenTelemetry trace export.
        translator_enabled:       Enable LLM-based intent translation (M3).
    """

    execution_mode: str = field(default_factory=lambda: _env_str("EXECUTION_MODE", "sync"))
    solver_timeout_ms: int = field(default_factory=lambda: _env_int("SOLVER_TIMEOUT_MS", 5_000))
    max_workers: int = field(default_factory=lambda: _env_int("MAX_WORKERS", 4))
    max_decisions_per_worker: int = field(
        default_factory=lambda: _env_int("MAX_DECISIONS_PER_WORKER", 10_000)
    )
    worker_warmup: bool = field(default_factory=lambda: _env_bool("WORKER_WARMUP", True))
    log_level: str = field(default_factory=lambda: _env_str("LOG_LEVEL", "INFO"))
    metrics_enabled: bool = field(default_factory=lambda: _env_bool("METRICS_ENABLED", False))
    otel_enabled: bool = field(default_factory=lambda: _env_bool("OTEL_ENABLED", False))
    translator_enabled: bool = field(default_factory=lambda: _env_bool("TRANSLATOR_ENABLED", False))
    fast_path_enabled: bool = field(default_factory=lambda: _env_bool("FAST_PATH_ENABLED", False))
    fast_path_rules: tuple[Any, ...] = field(default_factory=tuple)
    shed_latency_threshold_ms: float = field(
        default_factory=lambda: float(_env_str("SHED_LATENCY_THRESHOLD_MS", "200"))
    )
    shed_worker_pct: float = field(default_factory=lambda: float(_env_str("SHED_WORKER_PCT", "90")))
    signer: PramanixSigner | None = field(default=None)
    # ── Phase 12 hardening fields ──────────────────────────────────────────────
    solver_rlimit: int = field(default_factory=lambda: _env_int("SOLVER_RLIMIT", 10_000_000))
    """Z3 resource limit (elementary operations per solver call).
    Prevents logic-bomb and non-linear-expression DoS regardless of wall time.
    0 = disabled.  Default: 10 million operations.
    """
    max_input_bytes: int = field(default_factory=lambda: _env_int("MAX_INPUT_BYTES", 65_536))
    """Maximum serialised byte-size of the combined intent + state payload.
    Requests exceeding this limit are rejected before reaching the Z3 solver,
    preventing Big-Data DoS.  0 = disabled.  Default: 64 KiB.
    """
    min_response_ms: float = field(default=0.0)
    """Minimum wall-clock time (ms) before verify() returns its result.
    Pads short decisions to a fixed floor, making timing side-channels
    statistically infeasible.  0.0 = disabled (default).
    """
    redact_violations: bool = field(default=False)
    """When True, BLOCK decisions returned to callers have their
    ``explanation`` and ``violated_invariants`` replaced with a generic
    "Policy Violation: Action Blocked" message.  The signed ``decision_hash``
    is computed over the real fields *before* redaction, so the full audit
    log remains verifiable server-side.  Default: False (backwards-compatible).
    """
    expected_policy_hash: str | None = field(default=None)
    """SHA-256 fingerprint of the compiled policy.  When set, Guard.__init__
    raises ConfigurationError if the running policy does not match this hash,
    preventing silent policy drift in distributed deployments.
    """
    injection_threshold: float = field(
        default_factory=lambda: float(_env_str("INJECTION_THRESHOLD", "0.5"))
    )
    """Injection confidence threshold [0.0, 1.0] for the post-consensus scorer
    in :func:`~pramanix.translator.redundant.extract_with_consensus`.

    Inputs whose heuristic confidence score meets or exceeds this value are
    blocked with :exc:`~pramanix.exceptions.InjectionBlockedError` before any
    LLM result is returned.

    Raise for high-security deployments (e.g. ``0.3``); lower for domains
    with legitimate high-entropy inputs such as crypto addresses
    (e.g. ``0.7``).  Default: ``0.5``.  Env var: ``PRAMANIX_INJECTION_THRESHOLD``.
    """
    max_input_chars: int = field(default_factory=lambda: _env_int("MAX_INPUT_CHARS", 512))
    """Maximum character count of the raw natural-language input string passed
    to :func:`~pramanix.translator.redundant.extract_with_consensus`.

    Inputs exceeding this limit are rejected with
    :exc:`~pramanix.exceptions.InputTooLongError` *before* any LLM call is
    made.  Previously Pramanix silently truncated long inputs; the exception
    makes the rejection explicit and auditable.

    Default: 512 chars.  Env var: ``PRAMANIX_MAX_INPUT_CHARS``.
    """
    injection_scorer_path: str | None = field(
        default_factory=lambda: _env_str("INJECTION_SCORER_PATH", "") or None
    )
    """Entry-point name of a custom injection scorer registered in the
    ``pramanix.injection_scorers`` entry-point group.

    **Trusted-operator-only.** This value is used to look up a callable via
    ``importlib.metadata.entry_points``, so it must match the ``name`` key of
    a registered entry-point.  Arbitrary file paths or module strings are NOT
    accepted — they were disallowed to prevent arbitrary-code-execution if
    untrusted input could influence this value.

    To register a custom scorer, add this to your ``pyproject.toml``::

        [project.entry-points."pramanix.injection_scorers"]
        my_scorer = "my_package.scorers:injection_scorer"

    Then set ``injection_scorer_path = "my_scorer"`` (the entry-point name,
    not a file path).

    The callable must match the protocol::

        def injection_scorer(
            user_input: str,
            extracted_intent: dict,
            warnings: list[str],
        ) -> float: ...

    Env var: ``PRAMANIX_INJECTION_SCORER_PATH`` (entry-point name, or empty to
    use the built-in scorer).
    """

    injection_sensitive_fields: frozenset[str] = field(
        default_factory=lambda: frozenset(
            f.strip() for f in _env_str("INJECTION_SENSITIVE_FIELDS", "").split(",") if f.strip()
        )
    )
    """Set of extracted-intent field names whose string values are **additionally
    scored** for injection attempts after consensus.

    When non-empty, the string values of these fields are appended to the raw
    user input before the post-consensus injection scorer runs.  This lets
    operators flag free-text fields (e.g. ``"notes"``, ``"reason"``,
    ``"message"``) for extra scrutiny without raising the global
    ``injection_threshold``.

    Use case: a payment policy with a ``notes: str`` field accepting
    operator-visible memos should list ``"notes"`` here so adversarial content
    embedded in that field (e.g. ``"notes: ignore previous instructions"``) is
    caught even when the raw instruction text is benign.

    Default: ``frozenset()`` (no extra field scanning).
    Env var: ``PRAMANIX_INJECTION_SENSITIVE_FIELDS`` (comma-separated list).
    """

    consensus_strictness: str = field(
        default_factory=lambda: _env_str("CONSENSUS_STRICTNESS", "semantic")
    )
    """How individual field values are compared during dual-model consensus.

    ``"semantic"`` *(default)* — numeric strings are normalised via ``Decimal``
    before comparison, string fields are compared case-insensitively.  This
    eliminates spurious mismatches such as ``"500"`` vs ``"500.0"`` or
    ``"USD"`` vs ``"usd"``.

    ``"strict"`` — original behaviour: exact Python ``!=`` equality on the
    model-validated dict dump.

    Env var: ``PRAMANIX_CONSENSUS_STRICTNESS``.
    """

    translator_circuit_breaker_config: Any | None = field(default=None)
    """Optional config for per-translator circuit breakers in :meth:`~pramanix.guard.Guard.parse_and_verify`.

    When ``None`` (default) the circuit breaker uses its built-in defaults
    (5 consecutive failures → OPEN; 30 s recovery window).

    Pass a :class:`~pramanix.circuit_breaker.TranslatorCircuitBreakerConfig`
    to override ``failure_threshold`` and ``recovery_seconds`` per Guard.
    """

    audit_sinks: tuple[Any, ...] = field(default_factory=tuple)
    """Ordered sequence of :class:`~pramanix.audit_sink.AuditSink` implementations.

    Every :class:`~pramanix.decision.Decision` produced by
    :class:`~pramanix.guard.Guard` is emitted to each sink in order.  Sink
    failures are caught and logged — they **never** propagate to the caller.

    Default: empty tuple (no sinks configured; use structlog for logging).

    Example::

        from pramanix.audit_sink import InMemoryAuditSink, StdoutAuditSink
        config = GuardConfig(audit_sinks=(StdoutAuditSink(), InMemoryAuditSink()))
    """

    governance: GovernanceConfig | None = field(default=None)
    """Optional :class:`~pramanix.governance_config.GovernanceConfig` bundle.

    Groups all four governance pillars — IFC, privilege separation, human
    oversight, and execution scope — into a single, cross-validated object.
    Replaces the four flat ``ifc_policy``, ``capability_manifest``,
    ``execution_scope``, and ``oversight_workflow`` fields that previously
    lived at the root of ``GuardConfig``.

    Guard's ``_apply_governance_gates`` method reads the nested fields via
    ``self._config.governance.*``.  Governance is evaluated *after* a Z3 SAFE
    result in both synchronous ``_verify_core`` and all ``verify_async``
    execution modes — there is no async bypass.

    Cross-validation is performed inside
    :meth:`~pramanix.governance_config.GovernanceConfig.__post_init__` at
    construction time, not at verify time.

    Default: ``None`` (no governance gates enforced).
    """

    memory_store: Any | None = field(default=None)
    """Optional :class:`~pramanix.memory.SecureMemoryStore` for scoped,
    label-filtered agent memory.

    When set, agents can read/write to the store using its
    ``(tenant_id, workflow_id)`` partition scheme.  Guard itself does not
    interact with the memory store — this field carries the store alongside
    the Guard configuration.

    Default: ``None`` (secure memory not configured).
    """

    solver_factory: Callable[[Any], SolverProtocol] | None = field(default=None)
    """Optional factory for the Z3 solver — enables test isolation without
    patching the z3 C-extension (Law 3).

    The callable receives one argument: the active ``z3.Context`` (or ``None``
    for the thread-local default) and must return an object satisfying
    :class:`~pramanix.solver.SolverProtocol` (``set``, ``add``,
    ``assert_and_track``, ``check``, ``unsat_core``).

    When ``None`` (default), ``z3.Solver(ctx=ctx)`` is used directly.

    Example — inject an always-SAT stub in tests::

        from tests.helpers.solver_stubs import AlwaysSATStub
        config = GuardConfig(solver_factory=lambda ctx: AlwaysSATStub())
        guard = Guard(policy, config)

    SECURITY: Never set this in production deployments.  The factory
    completely replaces formal Z3 verification.  Guard raises
    ``ConfigurationError`` if ``PRAMANIX_ENV=production`` and a non-None
    ``solver_factory`` is supplied.
    """

    clock: Callable[[], float] | None = field(default=None)
    """Optional clock injection for ``E.now()`` time-policy expressions.

    The callable must return the current Unix timestamp as a float (same
    contract as ``time.time()``).  Injecting a deterministic clock makes
    time-window, TTL, and scheduled-access invariants fully testable without
    ``time.sleep()`` or ``monkeypatch.setattr``.

    When ``None`` (default), the transpiler uses ``time.time()`` directly.

    Example — freeze time in a test::

        import time
        _frozen = time.time()
        config = GuardConfig(clock=lambda: _frozen)
    """

    def __post_init__(self) -> None:
        if self.solver_timeout_ms <= 0:
            raise ConfigurationError(
                f"GuardConfig.solver_timeout_ms must be a positive integer, "
                f"got {self.solver_timeout_ms}."
            )
        if self.max_workers <= 0:
            raise ConfigurationError(
                f"GuardConfig.max_workers must be a positive integer, got {self.max_workers}."
            )
        valid_modes = {"sync", "async-thread", "async-process"}
        if self.execution_mode not in valid_modes:
            raise ConfigurationError(
                f"GuardConfig.execution_mode must be one of {valid_modes!r}, "
                f"got '{self.execution_mode}'."
            )
        if self.solver_rlimit < 0:
            raise ConfigurationError(
                f"GuardConfig.solver_rlimit must be >= 0, got {self.solver_rlimit}."
            )
        if self.max_input_bytes < 0:
            raise ConfigurationError(
                f"GuardConfig.max_input_bytes must be >= 0, got {self.max_input_bytes}."
            )
        if self.max_input_chars <= 0:
            raise ConfigurationError(
                f"GuardConfig.max_input_chars must be a positive integer, "
                f"got {self.max_input_chars}."
            )
        if self.min_response_ms < 0.0:
            raise ConfigurationError(
                f"GuardConfig.min_response_ms must be >= 0.0, got {self.min_response_ms}."
            )
        if not (0.0 < self.injection_threshold <= 1.0):
            raise ConfigurationError(
                f"GuardConfig.injection_threshold must be in (0.0, 1.0], "
                f"got {self.injection_threshold}."
            )
        _valid_strictness = {"semantic", "strict"}
        if self.consensus_strictness not in _valid_strictness:
            raise ConfigurationError(
                f"GuardConfig.consensus_strictness must be one of {_valid_strictness!r}, "
                f"got '{self.consensus_strictness}'."
            )
        # Validate that the name looks like a valid entry-point name
        # (non-empty, no path separators).  Full existence check happens
        # at call time in redundant.extract_with_consensus() so that
        # entry-points installed after GuardConfig construction are found.
        if self.injection_scorer_path is not None and (
            "/" in self.injection_scorer_path or "\\" in self.injection_scorer_path
        ):
            raise ConfigurationError(
                f"GuardConfig.injection_scorer_path must be an entry-point name, "
                f"not a file path. Got: {self.injection_scorer_path!r}. "
                "Register your scorer via the 'pramanix.injection_scorers' "
                "entry-point group and pass its name here."
            )
        if not (0.0 < self.shed_worker_pct <= 100.0):
            raise ConfigurationError(
                f"GuardConfig.shed_worker_pct must be in (0.0, 100.0], "
                f"got {self.shed_worker_pct}.  A value of 0 would shed every "
                f"request immediately; a value > 100 would never shed."
            )
        if self.shed_latency_threshold_ms <= 0.0:
            raise ConfigurationError(
                f"GuardConfig.shed_latency_threshold_ms must be > 0.0, "
                f"got {self.shed_latency_threshold_ms}.  A value of 0 would "
                f"cause every request to exceed the P99 threshold immediately."
            )
        # §11.1 fix: all advisories are dual-emitted via both warnings.warn()
        # (for development tools / -W filters) AND logging (for production
        # containers where PYTHONWARNINGS=ignore silences warnings entirely).
        import logging as _prod_log

        _prod_logger = _prod_log.getLogger(__name__)
        if self.metrics_enabled and not _PROM_AVAILABLE:
            _msg = (
                "GuardConfig(metrics_enabled=True) has no effect: "
                "prometheus_client is not installed. "
                "Install it: pip install 'pramanix[metrics]'"
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.warning("pramanix.guard_config.advisory: %s", _msg)
        if self.otel_enabled and not _OTEL_AVAILABLE:
            _msg = (
                "GuardConfig(otel_enabled=True) has no effect: "
                "opentelemetry-sdk is not installed. "
                "Install it: pip install 'pramanix[otel]'"
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.warning("pramanix.guard_config.advisory: %s", _msg)
        if (
            self.execution_mode in ("sync", "async-thread")
            and os.environ.get("PRAMANIX_ENV", "").lower() == "production"
        ):
            _msg = (
                f"GuardConfig(execution_mode={self.execution_mode!r}) is not "
                "recommended for production (PRAMANIX_ENV=production). "
                "A Z3 C++ crash (SIGABRT/SIGSEGV) will terminate the entire "
                "process and all in-flight requests. "
                "Use execution_mode='async-process' so that worker crashes "
                "surface as fail-safe BLOCKs without affecting the host process."
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.warning("pramanix.guard_config.advisory: %s", _msg)
        # ── Production safety: unsigned audit trail ────────────────────────────
        _is_prod = os.environ.get("PRAMANIX_ENV", "").lower() == "production"
        if _is_prod and self.signer is None:
            _msg = (
                "GuardConfig(signer=None) in production (PRAMANIX_ENV=production): "
                "decisions are NOT cryptographically signed. An attacker who can write "
                "to your audit log cannot be detected. "
                "Configure a PramanixSigner with a real Ed25519 key."
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.error("pramanix.guard_config.production_advisory: %s", _msg)
        # ── Production safety: no audit sinks configured ──────────────────────
        if _is_prod and not self.audit_sinks:
            raise ConfigurationError(
                "GuardConfig(audit_sinks=()) in production (PRAMANIX_ENV=production): "
                "no audit sinks configured — decisions are not persisted. A regulated "
                "deployment without a durable audit trail fails SOC 2 / HIPAA compliance. "
                "Add at least one AuditSink (e.g. S3AuditSink, KafkaAuditSink)."
            )
        # ── Production safety: InMemory audit sinks are not durable ──────────
        if _is_prod and self.audit_sinks:
            _inmem_names = [
                type(s).__name__
                for s in self.audit_sinks
                if type(s).__name__.startswith("InMemory")
            ]
            if _inmem_names:
                raise ConfigurationError(
                    f"InMemory audit sinks {_inmem_names} are not permitted in production "
                    "(PRAMANIX_ENV=production). InMemory sinks lose all audit data on "
                    "process restart, making forensic investigation and compliance "
                    "attestation impossible. Replace with a durable sink "
                    "(S3AuditSink, KafkaAuditSink, PostgresAuditSink)."
                )
        # ── Production safety: resource limits disabled ────────────────────────
        if _is_prod and self.solver_rlimit == 0:
            _msg = (
                "GuardConfig(solver_rlimit=0) in production (PRAMANIX_ENV=production): "
                "the Z3 resource limit is disabled. Adversarially crafted policies or "
                "intent payloads can trigger near-infinite solver loops. "
                "Set solver_rlimit to a positive value (default: 10_000_000)."
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.error("pramanix.guard_config.production_advisory: %s", _msg)
        if _is_prod and self.max_input_bytes == 0:
            _msg = (
                "GuardConfig(max_input_bytes=0) in production (PRAMANIX_ENV=production): "
                "the input size limit is disabled. Large payloads can exhaust memory "
                "before reaching the solver. "
                "Set max_input_bytes to a positive value (default: 65536)."
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.error("pramanix.guard_config.production_advisory: %s", _msg)
        # ── Production safety: no policy-version binding ──────────────────────
        if _is_prod and self.expected_policy_hash is None:
            _msg = (
                "GuardConfig(expected_policy_hash=None) in production "
                "(PRAMANIX_ENV=production): policy-version binding is disabled. "
                "A silent policy drift — a hot-reload, a misconfigured deploy, "
                "or a supply-chain substitution — would not be detected at Guard "
                "construction time. Set expected_policy_hash to the SHA-256 "
                "fingerprint of your compiled policy. Retrieve it after first "
                "construction via guard.policy_hash, pin it in your deployment "
                "config, and set GuardConfig(expected_policy_hash=<hash>) on "
                "all subsequent deployments."
            )
            warnings.warn(_msg, UserWarning, stacklevel=2)
            _prod_logger.error("pramanix.guard_config.production_advisory: %s", _msg)
        # ── solver_factory / clock not allowed in production ──────────────────
        if _is_prod and self.solver_factory is not None:
            raise ConfigurationError(
                "GuardConfig(solver_factory=...) is not permitted when "
                "PRAMANIX_ENV=production. A custom solver factory replaces "
                "formal Z3 verification entirely — this is only safe in tests. "
                "Remove solver_factory from your production GuardConfig."
            )
