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

See also
--------
:mod:`pramanix.guard_config`  — :class:`GuardConfig` dataclass, logging,
    OTel, Prometheus, and environment-variable helpers.
:mod:`pramanix.guard_pipeline` — semantic post-consensus check, policy
    fingerprinting, and explanation formatting helpers.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import time
import uuid
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.exceptions import (
    ConfigurationError,
    ExtractionFailureError,
    ExtractionMismatchError,
    InjectionBlockedError,
    InputTooLongError,
    LLMTimeoutError,
    PramanixError,
    SemanticPolicyViolation,
    SolverTimeoutError,
    StateValidationError,
    ValidationError,
    WorkerError,
)
from pramanix.guard_config import (
    _PROM_AVAILABLE,
    GuardConfig,
    _decision_latency,
    _decisions_total,
    _log,
    _resolver_registry,
    _solver_timeouts_total,
    _span,
    _validation_failures_total,
)
from pramanix.guard_pipeline import (
    _compute_policy_fingerprint,
    _fmt,
    _semantic_post_consensus_check,
)
from pramanix.helpers.serialization import safe_dump
from pramanix.solver import _SolveResult, solve
from pramanix.validator import validate_intent, validate_state
from pramanix.worker import WorkerPool

if TYPE_CHECKING:
    from pramanix.policy import Policy

__all__ = ["Guard", "GuardConfig"]


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
        self._intent_model: type[BaseModel] | None = (  # type: ignore[assignment,unused-ignore]
            policy.meta_intent_model()
        )
        self._state_model: type[BaseModel] | None = (  # type: ignore[assignment,unused-ignore]
            policy.meta_state_model()
        )
        self._policy_version: str | None = policy.meta_version()

        # ── Phase 12: Policy fingerprinting ───────────────────────────────────
        self._policy_hash: str = _compute_policy_fingerprint(policy)
        expected = self._config.expected_policy_hash
        if expected is not None and self._policy_hash != expected:
            raise ConfigurationError(
                f"Policy fingerprint mismatch — possible policy drift. "
                f"Expected: {expected!r}, "
                f"Got: {self._policy_hash!r}. "
                "Update expected_policy_hash in GuardConfig or investigate "
                "whether a different policy version is running on this node."
            )

        # Spawn WorkerPool for async modes.
        mode = self._config.execution_mode
        if mode in ("async-thread", "async-process"):
            self._pool: WorkerPool | None = WorkerPool(
                mode=mode,
                max_workers=self._config.max_workers,
                max_decisions_per_worker=self._config.max_decisions_per_worker,
                warmup=self._config.worker_warmup,
                latency_threshold_ms=self._config.shed_latency_threshold_ms,
                worker_pct=self._config.shed_worker_pct,
            )
            self._pool.spawn()
        else:
            self._pool = None

        # ── Phase 10.3: Semantic fast-path ────────────────────────────────────
        from pramanix.fast_path import FastPathEvaluator as _FastPathEvaluator

        if self._config.fast_path_enabled and self._config.fast_path_rules:
            self._fast_path: _FastPathEvaluator | None = _FastPathEvaluator(
                self._config.fast_path_rules
            )
        else:
            self._fast_path = None

        # ── Phase 10.1: Pre-compile expression tree metadata ──────────────
        import logging as _logging

        from pramanix.transpiler import compile_policy as _compile_policy

        _ph10_log = _logging.getLogger(__name__)
        try:
            self._compiled_meta: list[Any] = _compile_policy(self._policy.invariants())
            _ph10_log.debug(
                "Policy compiled",
                extra={
                    "policy": getattr(self._policy, "__name__", str(self._policy)),
                    "invariant_count": len(self._compiled_meta),
                    "field_count": len(
                        {f for meta in self._compiled_meta for f in meta.field_refs}
                    ),
                },
            )
        except Exception:
            raise  # compile_policy failures are fatal at init time

    # ── verify ────────────────────────────────────────────────────────────────

    def _sign_decision(self, decision: Decision) -> Decision:
        """Apply Ed25519 signature + policy_hash; redact violations if configured.

        Fail-closed: if sign() returns an empty string (signing failure),
        returns Decision.error() rather than returning an unsigned decision.
        This prevents the audit trail from silently containing unsigned records.

        Redaction (``redact_violations=True``): replaces ``explanation`` and
        ``violated_invariants`` on BLOCK decisions with a generic message before
        returning to the caller.  The ``decision_hash`` and ``signature`` are
        computed over the *real* fields, so the server-side audit log remains
        fully verifiable.
        """
        # Attach policy fingerprint (outside canonical hash — like signature).
        decision = dataclasses.replace(decision, policy_hash=self._policy_hash)

        if self._config.signer is None:
            # Redact even without signing (oracle protection applies regardless).
            if self._config.redact_violations and not decision.allowed:
                decision = dataclasses.replace(
                    decision,
                    explanation="Policy Violation: Action Blocked",
                    violated_invariants=(),
                )
            return decision

        sig = self._config.signer.sign(decision)
        if not sig:
            return Decision.error(
                reason=(
                    "Signing failed — audit trail integrity compromised. "
                    "Check signer configuration and key availability."
                )
            )
        decision = dataclasses.replace(
            decision,
            signature=sig,
            public_key_id=self._config.signer.key_id(),
        )
        # Apply oracle-attack redaction AFTER signing (hash covers real fields).
        if self._config.redact_violations and not decision.allowed:
            decision = dataclasses.replace(
                decision,
                explanation="Policy Violation: Action Blocked",
                violated_invariants=(),
            )
        return decision

    def verify(
        self,
        intent: dict[str, Any] | BaseModel,
        state: dict[str, Any] | BaseModel,
    ) -> Decision:
        """Verify *intent* and *state* against the policy invariants, then sign.

        Delegates to _verify_core() and attaches an Ed25519 signature when
        a signer is configured in GuardConfig.  Applies min_response_ms timing
        padding to defeat side-channel timing analysis.
        """
        _t0 = time.perf_counter()
        decision = self._sign_decision(self._verify_core(intent, state))
        # ── Timing jitter buffer (side-channel mitigation) ─────────────────────
        # Loop until the minimum has truly elapsed.  time.sleep() can return
        # early when interrupted by a signal (e.g. SIGCHLD from a subprocess);
        # the loop re-sleeps for any remaining time so the floor is guaranteed.
        if self._config.min_response_ms > 0.0:
            _deadline = _t0 + self._config.min_response_ms / 1000.0
            while True:
                _left = _deadline - time.perf_counter()
                if _left <= 0.0:
                    break
                with contextlib.suppress(InterruptedError, OSError):
                    time.sleep(_left)
        return decision

    def _verify_core(
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
        # ── Phase 12: input size cap (pre-solver Big-Data DoS protection) ───────
        if self._config.max_input_bytes > 0:
            try:
                import json as _json_size

                _raw_intent: dict[str, Any] = (
                    intent if isinstance(intent, dict) else intent.model_dump()
                )
                _raw_state: dict[str, Any] = (
                    state if isinstance(state, dict) else state.model_dump()
                )
                _payload_size = len(
                    _json_size.dumps(
                        {"i": _raw_intent, "s": _raw_state}, default=str
                    ).encode()
                )
                if _payload_size > self._config.max_input_bytes:
                    return Decision.error(
                        reason=(
                            f"Input payload size ({_payload_size} bytes) exceeds "
                            f"max_input_bytes limit ({self._config.max_input_bytes}). "
                            "Request rejected before reaching the solver."
                        )
                    )
            except Exception:
                pass  # size check is best-effort; never block on serialisation error

        decision_id = str(uuid.uuid4())
        _t0 = time.perf_counter()
        _metric_status = "error"  # overwritten before every return
        try:
            with _span("pramanix.guard.verify") as span:
                if span is not None:  # pragma: no branch
                    # Attach audit-trail metadata so SREs can correlate this
                    # span with a specific policy evaluation in any OTel backend.
                    span.set_attribute("pramanix.decision_id", decision_id)
                    span.set_attribute("pramanix.policy.name", self._policy.__name__)
                    span.set_attribute(
                        "pramanix.policy.version",
                        self._policy_version or "unversioned",
                    )
                # ── Step 1: Validate intent ────────────────────────────────────────
                if isinstance(intent, dict) and self._intent_model is not None:
                    intent = validate_intent(self._intent_model, intent)

                # ── Step 2: Validate state ─────────────────────────────────────────
                if isinstance(state, dict) and self._state_model is not None:
                    state = validate_state(self._state_model, state)

                with _span("pramanix.resolve"):
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
                            _metric_status = "validation_failure"
                            return Decision.validation_failure(
                                reason=(
                                    "state_version is missing from state data. "
                                    f"Policy '{self._policy.__name__}' requires "
                                    f"version='{self._policy_version}'."
                                )
                            )
                        if str(actual_version) != self._policy_version:
                            _metric_status = "stale_state"
                            return Decision.stale_state(
                                expected=self._policy_version,
                                actual=str(actual_version),
                            )

                    # ── Step 5 prep: merge field dicts ────────────────────────────────
                    conflicting = intent_values.keys() & state_values.keys()
                    if conflicting:
                        raise ValueError(
                            f"Intent and state share conflicting keys: {sorted(conflicting)}. "
                            "Each key must appear in exactly one of intent or state."
                        )
                    values: dict[str, Any] = {**intent_values, **state_values}

                    # ── Phase 10.1: Field presence pre-check ──────────────────────────────
                    # Fast O(n_fields) check using compiled metadata — short-circuits Z3
                    # for the common case of missing required fields.
                    _combined_keys = set(values.keys())
                    _missing_fields = []
                    for _meta in self._compiled_meta:
                        _absent = _meta.field_refs - _combined_keys
                        if _absent:
                            _missing_fields.append((_meta.label, _absent))

                    if _missing_fields:
                        _missing_str = "; ".join(
                            f"'{_lbl}' needs {sorted(_flds)}" for _lbl, _flds in _missing_fields
                        )
                        _metric_status = "error"
                        return Decision.error(reason=f"Missing required fields: {_missing_str}")

                    # ── Phase 10.3: Semantic fast-path pre-screen ─────────────────────────
                    if self._fast_path is not None:
                        _fp_result = self._fast_path.evaluate(intent_values, state_values)
                        if _fp_result.blocked:
                            _metric_status = "unsafe"
                            return Decision.unsafe(
                                violated_invariants=(_fp_result.rule_name or "fast_path_block",),
                                explanation=_fp_result.reason,
                                intent_dump=intent_values,
                                state_dump=state_values,
                            )

                # ── Step 5: Z3 solve (solver.py adds pramanix.z3_solve child span) ──
                result: _SolveResult = solve(
                    self._policy.invariants(),
                    values,
                    self._config.solver_timeout_ms,
                    self._config.solver_rlimit,
                )

                # ── Step 6: Build Decision ────────────────────────────────────────
                if result.sat:
                    decision_safe = Decision.safe(
                        solver_time_ms=result.solver_time_ms,
                        intent_dump=intent_values,
                        state_dump=state_values,
                    )
                    _metric_status = decision_safe.status.value
                    _log.info(
                        "pramanix.guard.decision",
                        decision_id=decision_id,
                        policy=self._policy.__name__,
                        allowed=True,
                        status=decision_safe.status.value,
                        solver_time_ms=result.solver_time_ms,
                    )
                    return decision_safe

                filtered = [inv for inv in result.violated if inv.label]
                explanation = "; ".join(e for inv in filtered if (e := _fmt(inv, values)))
                decision_unsafe = Decision.unsafe(
                    violated_invariants=tuple(label for inv in filtered if (label := inv.label)),
                    explanation=explanation,
                    solver_time_ms=result.solver_time_ms,
                    intent_dump=intent_values,
                    state_dump=state_values,
                )
                _metric_status = decision_unsafe.status.value
                _log.info(
                    "pramanix.guard.decision",
                    decision_id=decision_id,
                    policy=self._policy.__name__,
                    allowed=False,
                    status=decision_unsafe.status.value,
                    violated=list(decision_unsafe.violated_invariants),
                    solver_time_ms=result.solver_time_ms,
                )
                return decision_unsafe

        except ValidationError as exc:
            decision = Decision.validation_failure(reason=str(exc))
            _metric_status = decision.status.value
            _log.warning(
                "pramanix.guard.decision",
                decision_id=decision_id,
                policy=self._policy.__name__,
                allowed=False,
                status=decision.status.value,
                reason=str(exc),
            )
            return decision
        except StateValidationError as exc:
            decision = Decision.validation_failure(reason=str(exc))
            _metric_status = decision.status.value
            _log.warning(
                "pramanix.guard.decision",
                decision_id=decision_id,
                policy=self._policy.__name__,
                allowed=False,
                status=decision.status.value,
                reason=str(exc),
            )
            return decision
        except SolverTimeoutError as exc:
            decision = Decision.timeout(label=exc.label, timeout_ms=exc.timeout_ms)
            _metric_status = decision.status.value
            _log.warning(
                "pramanix.guard.decision",
                decision_id=decision_id,
                policy=self._policy.__name__,
                allowed=False,
                status=decision.status.value,
                reason=f"solver timeout after {exc.timeout_ms}ms",
            )
            return decision
        except PramanixError as exc:
            decision = Decision.error(reason=str(exc))
            _metric_status = decision.status.value
            _log.error(
                "pramanix.guard.decision",
                decision_id=decision_id,
                policy=self._policy.__name__,
                allowed=False,
                status=decision.status.value,
                reason=str(exc),
            )
            return decision
        except Exception as exc:  # — intentional fail-safe catch-all
            decision = Decision.error(
                reason=f"Unexpected internal error ({type(exc).__name__}): {exc}"
            )
            _metric_status = decision.status.value
            _log.error(
                "pramanix.guard.decision",
                decision_id=decision_id,
                policy=self._policy.__name__,
                allowed=False,
                status=decision.status.value,
                exc_type=type(exc).__name__,
                reason=str(exc),
            )
            return decision
        finally:
            # Always clear the per-context resolver cache after every decision
            # (context = asyncio Task or OS thread).  Prevents User A's resolved
            # field values from bleeding into User B's subsequent request.
            _resolver_registry.clear_cache()
            if self._config.metrics_enabled and _PROM_AVAILABLE:
                _policy_name = self._policy.__name__
                _decisions_total.labels(policy=_policy_name, status=_metric_status).inc()
                _decision_latency.labels(policy=_policy_name).observe(time.perf_counter() - _t0)
                if _metric_status == "timeout":
                    _solver_timeouts_total.labels(policy=_policy_name).inc()
                if _metric_status in ("validation_failure", "stale_state"):
                    _validation_failures_total.labels(policy=_policy_name).inc()

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
        _t0_async = time.perf_counter()

        async def _timed(d: Decision) -> Decision:
            """Apply min_response_ms timing pad and return decision.

            Uses a deadline loop: asyncio.sleep() can return early if the event
            loop is under heavy load; the loop re-sleeps for any remaining time
            so the minimum floor is guaranteed regardless of scheduling noise.
            """
            if self._config.min_response_ms > 0.0:
                _deadline_async = _t0_async + self._config.min_response_ms / 1000.0
                while True:
                    _left = _deadline_async - time.perf_counter()
                    if _left <= 0.0:
                        break
                    await asyncio.sleep(_left)
            return d

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
                    return await _timed(
                        self._sign_decision(
                            Decision.validation_failure(
                                reason=(
                                    "state_version is missing from state data. "
                                    f"Policy '{self._policy.__name__}' requires "
                                    f"version='{self._policy_version}'."
                                )
                            )
                        )
                    )
                if str(actual_version) != self._policy_version:
                    return await _timed(
                        self._sign_decision(
                            Decision.stale_state(
                                expected=self._policy_version,
                                actual=str(actual_version),
                            )
                        )
                    )

            conflicting = intent_values.keys() & state_values.keys()
            if conflicting:
                raise ValueError(
                    f"Intent and state share conflicting keys: {sorted(conflicting)}. "
                    "Each key must appear in exactly one of intent or state."
                )
            values: dict[str, Any] = {**intent_values, **state_values}

        except (ValidationError, StateValidationError) as exc:
            return await _timed(
                self._sign_decision(Decision.validation_failure(reason=str(exc)))
            )
        except PramanixError as exc:
            return await _timed(
                self._sign_decision(Decision.error(reason=str(exc)))
            )
        except Exception as exc:
            return await _timed(
                self._sign_decision(
                    Decision.error(
                        reason=f"Unexpected error during validation ({type(exc).__name__}): {exc}"
                    )
                )
            )

        # Steps 5-6: dispatch to worker pool.
        pool = self._pool
        if pool is None:
            return await _timed(
                self._sign_decision(
                    Decision.error(reason="WorkerPool not initialised for async mode.")
                )
            )

        if mode == "async-thread":
            # asyncio.to_thread() offloads the blocking submit_solve call.
            # We are NOT nesting asyncio.to_thread() inside another — this is
            # the first and only thread dispatch.
            decision = await asyncio.to_thread(
                pool.submit_solve,
                self._policy,
                values,
                self._config.solver_timeout_ms,
                self._config.solver_rlimit,
            )
            return await _timed(self._sign_decision(decision))

        if mode == "async-process":
            from pramanix.worker import (
                _RESULT_SEAL_KEY,
                _unseal_decision,
                _worker_solve_sealed,
            )

            loop = asyncio.get_running_loop()
            # _worker_solve_sealed is a module-level free function — picklable.
            # seal_key is plain bytes — picklable.
            # Nothing Z3-flavoured crosses the process boundary.
            try:
                sealed = await loop.run_in_executor(
                    pool.executor,
                    _worker_solve_sealed,
                    self._policy,
                    values,
                    self._config.solver_timeout_ms,
                    _RESULT_SEAL_KEY.bytes,
                    self._config.solver_rlimit,
                )
                result_dict_p: dict[str, Any] = _unseal_decision(sealed)
                decision = pool._dict_to_decision(result_dict_p)
            except (ValueError, KeyError):
                return await _timed(
                    self._sign_decision(
                        Decision.error(
                            reason="Worker result integrity check failed — HMAC mismatch."
                        )
                    )
                )
            except WorkerError as exc:
                return await _timed(
                    self._sign_decision(Decision.error(reason=str(exc)))
                )
            except Exception as exc:
                return await _timed(
                    self._sign_decision(
                        Decision.error(
                            reason=f"Process worker error ({type(exc).__name__}): {exc}"
                        )
                    )
                )
            return await _timed(self._sign_decision(decision))

        return await _timed(
            self._sign_decision(
                Decision.error(reason=f"Unknown execution_mode: {mode!r}")
            )
        )

    # ── parse_and_verify ────────────────────────────────────────────────────────

    async def parse_and_verify(
        self,
        prompt: str,
        intent_schema: type[BaseModel],
        state: dict[str, Any] | BaseModel,
        models: tuple[str, str] = ("gpt-4o", "claude-opus-4-5"),
        context: Any | None = None,
    ) -> Decision:
        """Extract structured intent from natural language, then verify.

        This is the neuro-symbolic entry-point that bridges the unstructured
        world (free-form user text) and the deterministic Z3 verification
        engine.  The pipeline is:

        1. Call both LLM models **concurrently** via
           :func:`~pramanix.translator.redundant.extract_with_consensus`.
        2. Require the two models to agree on every field
           (:class:`~pramanix.exceptions.ExtractionMismatchError` if not).
        3. Pass the validated intent dict to :meth:`verify_async`.

        The method **never raises**.  All translator and verification failures
        are collapsed into ``Decision.error()`` (fail-safe).

        Args:
            prompt:        Raw natural-language user input.
            intent_schema: Pydantic model class defining the expected intent
                           fields.
            state:         Current system state (dict or validated BaseModel).
            models:        Two model-name strings used for dual-model consensus.
                           Defaults to ``("gpt-4o", "claude-opus-4-5")``.
                           Routing: ``"gpt-*"``/``"o?-*"`` → OpenAI;
                           ``"claude-*"`` → Anthropic.
            context:       Optional :class:`~pramanix.translator.base.TranslatorContext`
                           supplying request ID, user ID, available accounts, etc.

        Returns:
            A :class:`~pramanix.decision.Decision`.

        Example::

            class TransferIntent(BaseModel):
                amount: Decimal

            guard = Guard(BankingPolicy)
            decision = await guard.parse_and_verify(
                "Please move five hundred dollars",
                TransferIntent,
                state={"balance": Decimal("1000"), ...},
            )
        """
        try:
            from pramanix.translator.redundant import create_translator, extract_with_consensus

            translator_a = create_translator(models[0])
            translator_b = create_translator(models[1])

            intent_dict = await extract_with_consensus(
                prompt,
                intent_schema,
                (translator_a, translator_b),
                context,
                injection_threshold=self._config.injection_threshold,
                max_input_chars=self._config.max_input_chars,
                injection_scorer_path=(
                    str(self._config.injection_scorer_path)
                    if self._config.injection_scorer_path is not None
                    else None
                ),
            )

            # ── Semantic post-consensus check: fast Python rules before Z3 ─────
            state_check_values: dict[str, Any] = (
                safe_dump(state) if isinstance(state, BaseModel) else dict(state)
            )
            _semantic_post_consensus_check(intent_dict, state_check_values)

            return await self.verify_async(intent=intent_dict, state=state)

        except ExtractionMismatchError as exc:
            # Deliberate, expected outcome: the two LLMs disagreed on intent.
            # Use consensus_failure(), not error() — these are operationally
            # distinct signals (adversarial/ambiguous input vs. internal fault).
            return Decision.consensus_failure(reason=str(exc))
        except (
            ExtractionFailureError,
            LLMTimeoutError,
            InjectionBlockedError,
            InputTooLongError,
            SemanticPolicyViolation,
        ) as exc:
            return Decision.error(reason=str(exc))
        except Exception as exc:
            return Decision.error(reason=f"Translator error ({type(exc).__name__}): {exc}")

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
