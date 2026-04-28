# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Production logging utilities for Pramanix deployments.

Pramanix emits all runtime signals through two logging channels:

1. **structlog** (``pramanix.guard``, ``pramanix.worker``, …) — structured
   JSON by default.  Records contain ``event``, ``level``, ``timestamp``, and
   arbitrary context fields.  structlog is configured at import time in
   ``pramanix.guard_config`` and is always active.

2. **stdlib ``logging``** (``pramanix.*`` namespace) — used for ``WARNING``
   and ``ERROR`` signals that must reach operator dashboards regardless of
   whether structlog is configured (e.g. the replay-protection warning from
   ``ExecutionTokenVerifier``, the policy-hash gap warning from
   ``ExecutionTokenSigner``, and all ``GuardConfig`` production safety alerts).

Production deployments **must** configure at least one stdlib ``logging``
handler for the ``pramanix`` namespace (or the root logger) so that these
warnings reach your log aggregator.  Without a handler, Python's built-in
``logging.lastResort`` handler writes WARNING+ to ``sys.stderr`` only — which
is acceptable for development but insufficient for production observability.

Quick-start::

    from pramanix.logging_helpers import configure_production_logging
    configure_production_logging()   # JSON to stderr, pramanix INFO+

Advanced::

    import logging, sys
    from pramanix.logging_helpers import configure_production_logging
    configure_production_logging(
        level="WARNING",
        fmt="json",
        stream=sys.stdout,
    )

Health check (call from ``pramanix doctor`` or your startup probe)::

    from pramanix.logging_helpers import check_logging_configuration
    status = check_logging_configuration()
    if not status["ok"]:
        print(status["detail"])

Logger namespace reference
--------------------------
``pramanix.guard``        — Guard verification decisions, latency, errors
``pramanix.guard_config`` — GuardConfig validation warnings
``pramanix.worker``       — WorkerPool lifecycle, warmup, crashes
``pramanix.execution_token`` — Replay-protection gap warnings (H-01)
``pramanix.audit.archiver`` — Audit-log plaintext warning (L-02)
``pramanix.integrations.langchain`` — execute_fn warnings (H-03)
``pramanix.integrations.crewai`` — underlying_fn warnings (H-04)
"""
from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import Any, TextIO

__all__ = [
    "PRAMANIX_LOGGER_NAMES",
    "check_logging_configuration",
    "configure_production_logging",
]

# Canonical logger names emitted by Pramanix.  Operators can subscribe to
# any of these individually or to the root ``pramanix`` namespace.
PRAMANIX_LOGGER_NAMES: tuple[str, ...] = (
    "pramanix",
    "pramanix.guard",
    "pramanix.guard_config",
    "pramanix.worker",
    "pramanix.execution_token",
    "pramanix.audit.archiver",
    "pramanix.integrations.langchain",
    "pramanix.integrations.crewai",
    "pramanix.integrations.fastapi",
    "pramanix.translator",
)

_JSON_FORMAT = (
    '{"ts":"%(asctime)s","level":"%(levelname)s",'
    '"logger":"%(name)s","msg":%(message)r}'
)
_TEXT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"


def configure_production_logging(
    level: str = "INFO",
    fmt: str = "json",
    stream: TextIO = sys.stderr,
    logger_name: str = "pramanix",
) -> logging.Logger:
    """Configure a production-ready stdlib logging handler for Pramanix.

    Installs a :class:`~logging.StreamHandler` on the ``pramanix`` root
    logger (or *logger_name*) so that all WARNING/ERROR signals reach
    whatever *stream* you point it at (stderr, stdout, or a file opened
    to your log aggregator's pipe).

    Idempotent: calling this function a second time with the same arguments
    is a no-op (it checks for existing handlers before adding a new one).

    Args:
        level:       Minimum log level to emit.  One of ``"DEBUG"``,
                     ``"INFO"``, ``"WARNING"``, ``"ERROR"``, ``"CRITICAL"``.
                     Default: ``"INFO"``.
        fmt:         Output format.  ``"json"`` produces single-line JSON
                     records; ``"text"`` produces human-readable lines.
                     Default: ``"json"``.
        stream:      Output stream.  Default: ``sys.stderr``.  For
                     containerised deployments, ``sys.stdout`` is often
                     preferable (unbuffered, captured by Docker/k8s).
        logger_name: Logger to attach the handler to.  Default: ``"pramanix"``
                     (catches all sub-loggers via propagation).

    Returns:
        The configured :class:`logging.Logger` instance.

    Example::

        from pramanix.logging_helpers import configure_production_logging
        configure_production_logging(level="WARNING", fmt="json")
    """
    log = logging.getLogger(logger_name)

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    log.setLevel(numeric_level)

    # Check whether an equivalent handler already exists to stay idempotent.
    for existing in log.handlers:
        if (
            isinstance(existing, logging.StreamHandler)
            and getattr(existing, "stream", None) is stream
        ):
            return log  # already configured

    handler = logging.StreamHandler(stream)
    handler.setLevel(numeric_level)

    if fmt == "json":
        formatter = logging.Formatter(
            _JSON_FORMAT,
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        formatter = logging.Formatter(
            _TEXT_FORMAT,
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log


def check_logging_configuration(
    logger_name: str = "pramanix",
) -> dict[str, Any]:
    """Inspect whether the Pramanix logger namespace has reachable handlers.

    Walks the logger hierarchy from *logger_name* up to the root to find
    any active :class:`~logging.Handler`.  Returns a status dict suitable
    for use in ``pramanix doctor`` checks, health endpoints, or startup probes.

    Args:
        logger_name: Logger namespace to inspect.  Default: ``"pramanix"``.

    Returns:
        A dict with the following keys:

        ``ok`` (bool)
            True if at least one active handler is reachable.

        ``level`` (str | None)
            ``"OK"`` / ``"WARN"`` — matches ``pramanix doctor`` level naming.

        ``detail`` (str)
            Human-readable description of what was found.

        ``hint`` (str)
            Remediation advice when ``ok`` is False.

        ``handlers`` (list[str])
            String descriptions of reachable handlers.

        ``using_last_resort`` (bool)
            True if only Python's built-in lastResort handler is active
            (WARNING+ to stderr, no formatting).

    Example::

        from pramanix.logging_helpers import check_logging_configuration
        status = check_logging_configuration()
        assert status["ok"], status["detail"]
    """
    log = logging.getLogger(logger_name)

    # Walk the hierarchy collecting handlers.
    reachable: list[logging.Handler] = []
    current: logging.Logger | logging.PlaceHolder | None = log
    while current is not None:
        if isinstance(current, logging.Logger):
            reachable.extend(current.handlers)
            if not current.propagate:
                break
        parent_name = current.parent if hasattr(current, "parent") else None
        if parent_name is None:
            break
        current = parent_name  # type: ignore[assignment]

    # Root logger handlers
    root = logging.getLogger()
    root_handlers = list(root.handlers)
    all_handlers = reachable + root_handlers

    # Exclude the internal lastResort handler (it's a fallback, not a real sink).
    last_resort = getattr(logging, "lastResort", None)
    real_handlers = [h for h in all_handlers if h is not last_resort]

    handler_descs = []
    for h in real_handlers:
        cls_name = type(h).__name__
        if isinstance(h, logging.StreamHandler):
            stream_name = getattr(
                getattr(h, "stream", None), "name", str(type(h).__name__)
            )
            handler_descs.append(f"{cls_name}({stream_name})")
        else:
            handler_descs.append(cls_name)

    using_last_resort = bool(last_resort in all_handlers and not real_handlers)

    if real_handlers:
        return {
            "ok": True,
            "level": "OK",
            "detail": (
                f"{len(real_handlers)} handler(s) reachable for '{logger_name}': "
                + ", ".join(handler_descs)
            ),
            "hint": "",
            "handlers": handler_descs,
            "using_last_resort": False,
        }

    if using_last_resort:
        detail = (
            f"No explicit handlers configured for '{logger_name}' — "
            "WARNING+ reaches sys.stderr via Python's lastResort fallback only. "
            "Pramanix production warnings (replay protection, policy binding, "
            "plaintext audit logs) will NOT reach your log aggregator."
        )
    else:
        detail = (
            f"No handlers reachable for '{logger_name}'. "
            "Pramanix WARNING logs will be silently discarded."
        )

    return {
        "ok": False,
        "level": "WARN",
        "detail": detail,
        "hint": (
            "Call pramanix.logging_helpers.configure_production_logging() "
            "at application startup, or attach a logging.Handler to the "
            f"'{logger_name}' logger before instantiating any Guard."
        ),
        "handlers": handler_descs,
        "using_last_resort": using_last_resort,
    }
