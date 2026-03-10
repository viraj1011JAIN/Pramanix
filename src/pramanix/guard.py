# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Guard — the public SDK entrypoint for synchronous policy verification.

Usage::

    from decimal import Decimal
    from pydantic import BaseModel
    from pramanix import Guard, GuardConfig, Policy, Field, E

    class TransferIntent(BaseModel):
        amount: Decimal

    class AccountState(BaseModel):
        state_version: str
        balance: Decimal
        daily_limit: Decimal
        is_frozen: bool

    class BankingPolicy(Policy):
        class Meta:
            version = "1.0"
            intent_model = TransferIntent
            state_model  = AccountState

        amount      = Field("amount",      Decimal, "Real")
        balance     = Field("balance",     Decimal, "Real")
        daily_limit = Field("daily_limit", Decimal, "Real")
        is_frozen   = Field("is_frozen",   bool,    "Bool")

        @classmethod
        def invariants(cls):
            return [
                (E(cls.balance) - E(cls.amount) >= 0).named("non_negative_balance"),
                (E(cls.amount) <= E(cls.daily_limit)).named("within_daily_limit"),
                (E(cls.is_frozen) == False).named("account_not_frozen"),  # noqa: E712
            ]

    guard = Guard(BankingPolicy)

    decision = guard.verify(
        intent={"amount": Decimal("500.00")},
        state={"balance": Decimal("1000.00"), "daily_limit": Decimal("5000.00"),
               "is_frozen": False, "state_version": "1.0"},
    )

    if decision.allowed:
        execute_transfer(...)
    else:
        raise PolicyViolation(decision.explanation)

Fail-safe contract
------------------
``Guard.verify()`` **never raises**.  Every exception — including unexpected
ones from user-defined ``invariants()`` overrides — is caught and returned
as ``Decision.error()``.  The calling code always receives a :class:`Decision`
with ``allowed=False`` on any error path.

``Decision(allowed=True)`` is **never** returned from any error handler.

Phase 2 scope (M1 — sync only)
--------------------------------
Async worker-pool modes (``ThreadPoolExecutor`` / ``ProcessPoolExecutor``) are
reserved for M2.  This implementation is single-threaded and synchronous.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.exceptions import (
    ConfigurationError,
    PramanixError,
    SolverTimeoutError,
    StateValidationError,
    ValidationError,
    WorkerError,
)
from pramanix.helpers.serialization import safe_dump
from pramanix.solver import _SolveResult, solve
from pramanix.validator import validate_intent, validate_state
from pramanix.worker import WorkerPool, _worker_solve

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr
    from pramanix.policy import Policy

__all__ = ["GuardConfig", "Guard"]


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
    """Immutable configuration for a :class:`Guard` instance.

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

    execution_mode: str = field(
        default_factory=lambda: _env_str("EXECUTION_MODE", "sync")
    )
    solver_timeout_ms: int = field(
        default_factory=lambda: _env_int("SOLVER_TIMEOUT_MS", 5_000)
    )
    max_workers: int = field(
        default_factory=lambda: _env_int("MAX_WORKERS", 4)
    )
    max_decisions_per_worker: int = field(
        default_factory=lambda: _env_int("MAX_DECISIONS_PER_WORKER", 10_000)
    )
    worker_warmup: bool = field(
        default_factory=lambda: _env_bool("WORKER_WARMUP", True)
    )
    log_level: str = field(
        default_factory=lambda: _env_str("LOG_LEVEL", "INFO")
    )
    metrics_enabled: bool = field(
        default_factory=lambda: _env_bool("METRICS_ENABLED", False)
    )
    otel_enabled: bool = field(
        default_factory=lambda: _env_bool("OTEL_ENABLED", False)
    )
    translator_enabled: bool = field(
        default_factory=lambda: _env_bool("TRANSLATOR_ENABLED", False)
    )

    def __post_init__(self) -> None:
        if self.solver_timeout_ms <= 0:
            raise ConfigurationError(
                f"GuardConfig.solver_timeout_ms must be a positive integer, "
                f"got {self.solver_timeout_ms}."
            )
        if self.max_workers <= 0:
            raise ConfigurationError(
                f"GuardConfig.max_workers must be a positive integer, "
                f"got {self.max_workers}."
            )
        valid_modes = {"sync", "async-thread", "async-process"}
        if self.execution_mode not in valid_modes:
            raise ConfigurationError(
                f"GuardConfig.execution_mode must be one of {valid_modes!r}, "
                f"got '{self.execution_mode}'."
            )


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


# ── Guard ─────────────────────────────────────────────────────────────────────


class Guard:
    """Synchronous policy verification entrypoint.

    Instantiate once per policy type (e.g., at application startup), then
    call :meth:`verify` for each incoming request.

    Construction validates the policy (calls :meth:`~pramanix.policy.Policy.validate`)
    and registers any Pydantic intent/state models from ``Policy.Meta``, so
    authoring errors surface immediately — not at request time.

    Args:
        policy: A :class:`~pramanix.policy.Policy` subclass (*not* an
            instance — the class itself).
        config: Optional :class:`GuardConfig`.  Defaults to
            ``GuardConfig()`` (5 000 ms timeout, sync mode).

    Raises:
        PolicyError:         If ``policy.invariants()`` returns an empty list.
        InvariantLabelError: If any invariant is missing or has a duplicate label.
        ConfigurationError:  If *config* contains invalid values.
    """

    def __init__(
        self,
        policy: type[Policy],
        config: GuardConfig | None = None,
    ) -> None:
        policy.validate()  # fail-fast: raise PolicyError / InvariantLabelError now
        self._policy = policy
        self._config = config or GuardConfig()

        # Extract Pydantic models from Policy.Meta (may be None)
        self._intent_model: type[BaseModel] | None = policy.meta_intent_model()  # type: ignore[assignment,unused-ignore]
        self._state_model: type[BaseModel] | None = policy.meta_state_model()  # type: ignore[assignment,unused-ignore]
        self._policy_version: str | None = policy.meta_version()

        # Spawn WorkerPool for async modes.
        mode = self._config.execution_mode
        if mode in ("async-thread", "async-process"):
            self._pool: WorkerPool | None = WorkerPool(
                mode=mode,
                max_workers=self._config.max_workers,
                max_decisions_per_worker=self._config.max_decisions_per_worker,
                warmup=self._config.worker_warmup,
            )
            self._pool.spawn()
        else:
            self._pool = None

    # ── verify ────────────────────────────────────────────────────────────────

    def verify(
        self,
        intent: dict[str, Any] | BaseModel,
        state: dict[str, Any] | BaseModel,
    ) -> Decision:
        """Verify *intent* and *state* against the policy invariants.

        This method **never raises**.  All exceptions — Z3 timeouts,
        transpiler errors, Pydantic validation errors, unexpected bugs in
        ``invariants()`` — are caught and returned as an appropriate
        ``Decision(allowed=False)``.

        Six-step pipeline:

        1. **Intent validation** — if a Pydantic model is registered, validate
           the intent dict in strict mode.
        2. **State validation** — if a Pydantic model is registered, validate
           the state dict in strict mode (including ``state_version`` field).
        3. **model_dump()** — convert validated models to plain dicts via
           :func:`~pramanix.helpers.serialization.safe_dump`.
        4. **Version check** — compare ``state["state_version"]`` against
           ``Policy.Meta.version``; return :meth:`~pramanix.decision.Decision.stale_state`
           on mismatch.
        5. **Z3 solve** — run the two-phase solver.
        6. **Build Decision** — construct immutable :class:`Decision` from result.

        Args:
            intent: Intent data — either a validated ``BaseModel`` instance or
                a raw ``dict`` (validated internally if a model is registered).
            state:  State data — either a validated ``BaseModel`` instance or
                a raw ``dict`` (validated internally if a model is registered).

        Returns:
            One of:

            * ``Decision.safe()``              — all invariants satisfied
            * ``Decision.unsafe()``            — one or more invariants violated
            * ``Decision.timeout()``           — Z3 solver time budget exceeded
            * ``Decision.error()``             — unexpected internal error
            * ``Decision.stale_state()``       — state version mismatch
            * ``Decision.validation_failure()``— Pydantic validation failed
        """
        try:
            # ── Step 1: Validate intent ────────────────────────────────────────
            if isinstance(intent, dict) and self._intent_model is not None:
                intent = validate_intent(self._intent_model, intent)

            # ── Step 2: Validate state ─────────────────────────────────────────
            if isinstance(state, dict) and self._state_model is not None:
                state = validate_state(self._state_model, state)

            # ── Step 3: model_dump() → plain dicts ────────────────────────────
            intent_values: dict[str, Any] = (
                safe_dump(intent) if isinstance(intent, BaseModel) else dict(intent)
            )
            state_values: dict[str, Any] = (
                safe_dump(state) if isinstance(state, BaseModel) else dict(state)
            )

            # ── Step 4: State version check ───────────────────────────────────
            if self._policy_version is not None:
                actual_version = state_values.get("state_version")
                if actual_version is None:
                    return Decision.validation_failure(
                        reason=(
                            "state_version is missing from state data. "
                            f"Policy '{self._policy.__name__}' requires "
                            f"version='{self._policy_version}'."
                        )
                    )
                if str(actual_version) != self._policy_version:
                    return Decision.stale_state(
                        expected=self._policy_version,
                        actual=str(actual_version),
                    )

            # ── Step 5: Z3 solve ──────────────────────────────────────────────
            conflicting = intent_values.keys() & state_values.keys()
            if conflicting:
                raise ValueError(
                    f"Intent and state share conflicting keys: {sorted(conflicting)}. "
                    "Each key must appear in exactly one of intent or state."
                )
            values: dict[str, Any] = {**intent_values, **state_values}
            result: _SolveResult = solve(
                self._policy.invariants(),
                values,
                self._config.solver_timeout_ms,
            )

            # ── Step 6: Build Decision ────────────────────────────────────────
            if result.sat:
                return Decision.safe(solver_time_ms=result.solver_time_ms)

            filtered = [inv for inv in result.violated if inv.label]
            explanation = "; ".join(
                e for inv in filtered if (e := _fmt(inv, values))
            )
            return Decision.unsafe(
                violated_invariants=tuple(label for inv in filtered if (label := inv.label)),
                explanation=explanation,
                solver_time_ms=result.solver_time_ms,
            )

        except ValidationError as exc:
            return Decision.validation_failure(reason=str(exc))
        except StateValidationError as exc:
            return Decision.validation_failure(reason=str(exc))
        except SolverTimeoutError as exc:
            return Decision.timeout(label=exc.label, timeout_ms=exc.timeout_ms)
        except PramanixError as exc:
            return Decision.error(reason=str(exc))
        except Exception as exc:  # — intentional fail-safe catch-all
            return Decision.error(
                reason=f"Unexpected internal error ({type(exc).__name__}): {exc}"
            )

    # ── verify_async ───────────────────────────────────────────────────────────

    async def verify_async(
        self,
        intent: dict[str, Any] | BaseModel,
        state: dict[str, Any] | BaseModel,
    ) -> Decision:
        """Async-aware policy verification entrypoint.

        Steps 1-4 (validate + version check) run on the caller's thread.
        Steps 5-6 (Z3 solve) are dispatched based on ``execution_mode``:

        * ``"sync"``          — offloads sync :meth:`verify` to a thread pool
          via ``asyncio.to_thread()``; safe to call from async contexts.
        * ``"async-thread"``  — runs in the managed :class:`WorkerPool`
          (``ThreadPoolExecutor``) via ``asyncio.to_thread()``.
        * ``"async-process"`` — serialises values to a plain dict, calls
          ``_worker_solve`` inside processpool via ``run_in_executor()``.
          **No Z3 objects or AST nodes cross the process boundary.**

        This method **never raises**.  All exceptions are returned as
        ``Decision(allowed=False)``.

        Args:
            intent: Intent data (dict or validated BaseModel).
            state:  State data (dict or validated BaseModel).

        Returns:
            A :class:`Decision`.
        """
        mode = self._config.execution_mode

        # Sync mode: delegate entirely to sync verify() in a thread.
        if mode == "sync":
            return await asyncio.to_thread(self.verify, intent, state)

        # Steps 1-4: validation and version check run on the caller's thread.
        try:
            if isinstance(intent, dict) and self._intent_model is not None:
                intent = validate_intent(self._intent_model, intent)
            if isinstance(state, dict) and self._state_model is not None:
                state = validate_state(self._state_model, state)

            intent_values: dict[str, Any] = (
                safe_dump(intent) if isinstance(intent, BaseModel) else dict(intent)
            )
            state_values: dict[str, Any] = (
                safe_dump(state) if isinstance(state, BaseModel) else dict(state)
            )

            if self._policy_version is not None:
                actual_version = state_values.get("state_version")
                if actual_version is None:
                    return Decision.validation_failure(
                        reason=(
                            "state_version is missing from state data. "
                            f"Policy '{self._policy.__name__}' requires "
                            f"version='{self._policy_version}'."
                        )
                    )
                if str(actual_version) != self._policy_version:
                    return Decision.stale_state(
                        expected=self._policy_version,
                        actual=str(actual_version),
                    )

            conflicting = intent_values.keys() & state_values.keys()
            if conflicting:
                raise ValueError(
                    f"Intent and state share conflicting keys: {sorted(conflicting)}. "
                    "Each key must appear in exactly one of intent or state."
                )
            values: dict[str, Any] = {**intent_values, **state_values}

        except (ValidationError, StateValidationError) as exc:
            return Decision.validation_failure(reason=str(exc))
        except PramanixError as exc:
            return Decision.error(reason=str(exc))
        except Exception as exc:
            return Decision.error(
                reason=f"Unexpected error during validation ({type(exc).__name__}): {exc}"
            )

        # Steps 5-6: dispatch to worker pool.
        pool = self._pool
        if pool is None:
            return Decision.error(reason="WorkerPool not initialised for async mode.")

        if mode == "async-thread":
            # asyncio.to_thread() offloads the blocking submit_solve call.
            # We are NOT nesting asyncio.to_thread() inside another — this is
            # the first and only thread dispatch.
            return await asyncio.to_thread(
                pool.submit_solve, self._policy, values, self._config.solver_timeout_ms
            )

        if mode == "async-process":
            loop = asyncio.get_running_loop()
            # _worker_solve is a module-level free function — picklable.
            # policy_cls is passed as a class reference (import path in pickle).
            # values is a plain dict. Nothing Z3-flavoured crosses the boundary.
            try:
                result_dict: dict[str, Any] = await loop.run_in_executor(
                    pool.executor,
                    _worker_solve,
                    self._policy,
                    values,
                    self._config.solver_timeout_ms,
                )
                return pool._dict_to_decision(result_dict)
            except WorkerError as exc:
                return Decision.error(reason=str(exc))
            except Exception as exc:
                return Decision.error(
                    reason=f"Process worker error ({type(exc).__name__}): {exc}"
                )

        return Decision.error(reason=f"Unknown execution_mode: {mode!r}")

    # ── shutdown ────────────────────────────────────────────────────────────────────

    async def shutdown(self) -> None:
        """Gracefully shut down the worker pool (async-aware).

        Safe to call regardless of ``execution_mode``; no-op when the pool
        was not created.  Should be awaited at application teardown.

        Example::

            async with asyncio.TaskGroup() as tg:
                ...
            await guard.shutdown()
        """
        if self._pool is not None:
            await asyncio.to_thread(self._pool.shutdown)

    # ── Accessors ───────────────────────────────────────────────────────────────────

    @property
    def policy(self) -> type[Policy]:
        """The policy class this Guard was constructed with."""
        return self._policy

    @property
    def config(self) -> GuardConfig:
        """The active :class:`GuardConfig`."""
        return self._config
