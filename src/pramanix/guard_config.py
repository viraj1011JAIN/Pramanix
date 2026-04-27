# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
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
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path  # noqa: F401 — re-exported for backward compatibility
from typing import TYPE_CHECKING, Any

import structlog

from pramanix.exceptions import ConfigurationError
from pramanix.resolvers import resolver_registry

if TYPE_CHECKING:
    from pramanix.crypto import PramanixSigner

__all__ = ["GuardConfig"]

# ── Structlog secrets redaction ───────────────────────────────────────────────
# Pattern matches any event-dict key that looks like a credential.
# The processor is applied BEFORE any renderer so secrets never reach disk.
_SECRET_KEY_RE = re.compile(
    r"(secret|api[_\-]?key|token|hmac|password|passwd|credential|private[_\-]?key)",
    re.IGNORECASE,
)
_REDACTED = "<redacted>"


def _redact_secrets_processor(
    _logger: Any,
    _method: str,
    event_dict: Any,
) -> Any:
    """Structlog processor — redact any event-dict key that looks like a secret.

    Applied as the first processor in the chain so that secret values are
    never visible in any downstream processor, renderer, or log sink.

    Matches keys containing: ``secret``, ``api_key``, ``apikey``, ``token``,
    ``hmac``, ``password``, ``passwd``, ``credential``, ``private_key``.
    """
    return {k: (_REDACTED if _SECRET_KEY_RE.search(k) else v) for k, v in event_dict.items()}


structlog.configure(
    processors=[
        _redact_secrets_processor,  # must be first — sanitise before anything else
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    wrapper_class=structlog.BoundLogger,
    cache_logger_on_first_use=True,
)

_log = structlog.get_logger("pramanix.guard")


# ── OpenTelemetry — graceful optional dependency ──────────────────────────────
# Each span is a no-op (contextlib.nullcontext) when the ``otel`` extra is
# absent, so there is zero overhead on deployments that do not use tracing.

try:
    from opentelemetry import trace as _otel_trace  # pragma: no cover

    def _span(name: str) -> Any:  # pragma: no cover
        """Return a live OTel span context-manager."""
        return _otel_trace.get_tracer("pramanix.guard").start_as_current_span(name)

    _OTEL_AVAILABLE = True  # pragma: no cover

except ImportError:  # pragma: no cover

    def _span(name: str) -> Any:  # pragma: no cover
        """No-op span when opentelemetry is not installed."""
        return contextlib.nullcontext()

    _OTEL_AVAILABLE = False  # pragma: no cover


# ── Prometheus — graceful optional dependency ─────────────────────────────────
# Each metric is a no-op when ``prometheus_client`` is absent, so there is zero
# overhead on deployments that do not expose a /metrics endpoint.

try:
    import prometheus_client as _prom

    _decisions_total = _prom.Counter(
        "pramanix_decisions_total",
        "Total policy decisions by outcome",
        ["policy", "status"],
    )
    _decision_latency = _prom.Histogram(
        "pramanix_decision_latency_seconds",
        "End-to-end verify() latency in seconds",
        ["policy"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )
    _solver_timeouts_total = _prom.Counter(
        "pramanix_solver_timeouts_total",
        "Number of Z3 solver timeouts by policy",
        ["policy"],
    )
    _validation_failures_total = _prom.Counter(
        "pramanix_validation_failures_total",
        "Number of intent/state validation failures by policy",
        ["policy"],
    )
    _PROM_AVAILABLE = True

except ImportError:  # pragma: no cover
    _PROM_AVAILABLE = False  # pragma: no cover
    _decisions_total = None  # type: ignore[assignment]  # pragma: no cover
    _decision_latency = None  # type: ignore[assignment]  # pragma: no cover
    _solver_timeouts_total = None  # type: ignore[assignment]  # pragma: no cover
    _validation_failures_total = None  # type: ignore[assignment]  # pragma: no cover


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
    solver_rlimit: int = field(
        default_factory=lambda: _env_int("SOLVER_RLIMIT", 10_000_000)
    )
    """Z3 resource limit (elementary operations per solver call).
    Prevents logic-bomb and non-linear-expression DoS regardless of wall time.
    0 = disabled.  Default: 10 million operations.
    """
    max_input_bytes: int = field(
        default_factory=lambda: _env_int("MAX_INPUT_BYTES", 65_536)
    )
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
    max_input_chars: int = field(
        default_factory=lambda: _env_int("MAX_INPUT_CHARS", 512)
    )
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
        if self.injection_scorer_path is not None:
            # Validate that the name looks like a valid entry-point name
            # (non-empty, no path separators).  Full existence check happens
            # at call time in redundant.extract_with_consensus() so that
            # entry-points installed after GuardConfig construction are found.
            if "/" in self.injection_scorer_path or "\\" in self.injection_scorer_path:
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
        if self.metrics_enabled and not _PROM_AVAILABLE:
            warnings.warn(
                "GuardConfig(metrics_enabled=True) has no effect: "
                "prometheus_client is not installed. "
                "Install it: pip install 'pramanix[metrics]'",
                UserWarning,
                stacklevel=2,
            )
        if self.otel_enabled and not _OTEL_AVAILABLE:
            warnings.warn(
                "GuardConfig(otel_enabled=True) has no effect: "
                "opentelemetry-sdk is not installed. "
                "Install it: pip install 'pramanix[otel]'",
                UserWarning,
                stacklevel=2,
            )
        if (
            self.execution_mode in ("sync", "async-thread")
            and os.environ.get("PRAMANIX_ENV", "").lower() == "production"
        ):
            warnings.warn(
                f"GuardConfig(execution_mode={self.execution_mode!r}) is not "
                "recommended for production (PRAMANIX_ENV=production). "
                "A Z3 C++ crash (SIGABRT/SIGSEGV) will terminate the entire "
                "process and all in-flight requests. "
                "Use execution_mode='async-process' so that worker crashes "
                "surface as fail-safe BLOCKs without affecting the host process.",
                UserWarning,
                stacklevel=2,
            )
        # ── Production safety: unsigned audit trail ────────────────────────────
        _is_prod = os.environ.get("PRAMANIX_ENV", "").lower() == "production"
        if _is_prod and self.signer is None:
            warnings.warn(
                "GuardConfig(signer=None) in production (PRAMANIX_ENV=production): "
                "decisions are NOT cryptographically signed. An attacker who can write "
                "to your audit log cannot be detected. "
                "Configure a PramanixSigner with a real Ed25519 key.",
                UserWarning,
                stacklevel=2,
            )
        # ── Production safety: no audit sinks configured ──────────────────────
        if _is_prod and not self.audit_sinks:
            warnings.warn(
                "GuardConfig(audit_sinks=()) in production (PRAMANIX_ENV=production): "
                "no audit sinks configured — decisions are not persisted. "
                "Add at least one AuditSink (e.g. S3AuditSink, KafkaAuditSink) "
                "to maintain a durable audit trail.",
                UserWarning,
                stacklevel=2,
            )
        # ── Production safety: resource limits disabled ────────────────────────
        if _is_prod and self.solver_rlimit == 0:
            warnings.warn(
                "GuardConfig(solver_rlimit=0) in production (PRAMANIX_ENV=production): "
                "the Z3 resource limit is disabled. Adversarially crafted policies or "
                "intent payloads can trigger near-infinite solver loops. "
                "Set solver_rlimit to a positive value (default: 10_000_000).",
                UserWarning,
                stacklevel=2,
            )
        if _is_prod and self.max_input_bytes == 0:
            warnings.warn(
                "GuardConfig(max_input_bytes=0) in production (PRAMANIX_ENV=production): "
                "the input size limit is disabled. Large payloads can exhaust memory "
                "before reaching the solver. "
                "Set max_input_bytes to a positive value (default: 65536).",
                UserWarning,
                stacklevel=2,
            )
