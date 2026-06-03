# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""LangGraph execution protocol integration for Pramanix.

This module provides a zero-friction decorator and a reusable guard-node
object for LangGraph nodes.

Primary API:
    - ``@pramanix_node(...)``
    - ``PramanixGuardNode``

Design goals:
    - Keep business logic untouched (decorator model)
    - Attach a machine-readable policy verdict sidecar to node state
    - Support fail-closed, fail-warn, and shadow modes
    - Expose low-overhead observability hooks
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from prometheus_client import Counter, Histogram

from pydantic import BaseModel

from pramanix.decision import Decision, SolverStatus
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig

_log = logging.getLogger(__name__)

_NODE_LATENCY_MS: Histogram | None = None
_NODE_VERDICT_TOTAL: Counter | None = None
try:
    from prometheus_client import Counter, Histogram

    _NODE_LATENCY_MS = Histogram(
        "pramanix_node_latency_ms",
        "Latency of Pramanix LangGraph gate node in milliseconds",
        ["policy", "node"],
    )
    _NODE_VERDICT_TOTAL = Counter(
        "pramanix_node_verdict_total",
        "Policy verdict counts for Pramanix LangGraph gate node",
        ["policy", "node", "verdict"],
    )
except Exception as _e:
    _log.debug("pramanix.integrations.langgraph: metrics setup failed: %s", _e)

__all__ = [
    "GuardNodeAdapterProtocol",
    "PramanixGuardNode",
    "PramanixNodeBlockedError",
    "pramanix_node",
]


@runtime_checkable
class GuardNodeAdapterProtocol(Protocol):
    """Structural interface every Pramanix guard-node adapter must satisfy.

    Conforming types can wrap a callable node function with a Pramanix
    policy gate regardless of the underlying agent orchestration framework
    (LangGraph, SemanticKernel, Haystack, …).

    ``isinstance(obj, GuardNodeAdapterProtocol)`` returns True for any object
    that exposes a ``decorate`` method with the correct signature.
    """

    def decorate(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap *fn* with a policy gate; return the gated callable.

        The returned callable must accept the same positional arguments
        as *fn* and must preserve its return type annotation.
        """
        ...


class PramanixNodeBlockedError(RuntimeError):
    """Raised when ``on_fail='halt'`` and a policy gate blocks execution."""

    def __init__(self, message: str, verdict: dict[str, Any]) -> None:
        super().__init__(message)
        self.verdict = verdict


def _state_to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    if isinstance(state, dict):
        return dict(state)
    if hasattr(state, "model_dump"):
        return dict(state.model_dump())
    if hasattr(state, "dict"):
        return dict(state.dict())
    if hasattr(state, "__dict__"):
        return dict(state.__dict__)
    raise TypeError("State must be a dict or Pydantic model.")


def _extract_keys_from_model(model: Any) -> set[str]:
    fields = getattr(model, "model_fields", None)
    if isinstance(fields, dict):
        return set(fields.keys())
    return set()


def _coerce_payload_with_model(payload: dict[str, Any], model: Any) -> dict[str, Any]:
    if model is None:
        return dict(payload)
    fields = getattr(model, "model_fields", None)
    if not isinstance(fields, dict):
        return dict(payload)

    out = dict(payload)
    for key, field in fields.items():
        if key not in out:
            continue
        annotation = getattr(field, "annotation", None)
        value = out[key]
        if annotation is Decimal and isinstance(value, int | float) and not isinstance(value, bool):
            out[key] = Decimal(str(value))
    return out


def _suggest_remediation(
    decision: Decision,
    intent_payload: dict[str, Any],
    state_payload: dict[str, Any],
) -> str:
    violated = [v.lower() for v in decision.violated_invariants]
    for rule in violated:
        if "limit" in rule or "max" in rule or "cap" in rule or "budget" in rule:
            numeric_intent = [
                (k, v)
                for k, v in intent_payload.items()
                if isinstance(v, int | float) and not isinstance(v, bool)
            ]
            numeric_state = [
                (k, v)
                for k, v in state_payload.items()
                if isinstance(v, int | float) and not isinstance(v, bool)
            ]
            if numeric_intent and numeric_state:
                key_i, val_i = numeric_intent[0]
                key_s, val_s = numeric_state[0]
                if val_i > val_s:
                    return (
                        f"Consider updating '{key_s}' "
                        f"from {val_s} to at least {val_i} "
                        f"for request field '{key_i}'."
                    )
    if decision.violated_invariants:
        first = decision.violated_invariants[0]
        return f"Review invariant '{first}' and adjust request or policy."
    return "No remediation available."


class PramanixGuardNode:
    """Execution protocol wrapper for LangGraph nodes.

    This object runs policy verification before node execution and can attach
    a structured policy verdict to the returned node state.
    """

    def __init__(
        self,
        *,
        policy: Any | None = None,
        guard: Guard | None = None,
        on_fail: str = "halt",
        shadow: bool = False,
        timeout_ms: int = 100,
        bypass_on_timeout: bool = True,
        sidecar_key: str = "_pramanix_policy_verdict",
        intent_extractor: (Callable[[dict[str, Any]], dict[str, Any]] | None) = None,
        state_extractor: (Callable[[dict[str, Any]], dict[str, Any]] | None) = None,
        audit_sink: Any | None = None,
        node_name: str | None = None,
    ) -> None:
        if guard is None and policy is None:
            raise ValueError("Provide either 'guard' or 'policy'.")
        if on_fail not in {"halt", "warn"}:
            raise ValueError("on_fail must be 'halt' or 'warn'.")

        if guard is None:
            assert policy is not None
            cfg = GuardConfig(
                execution_mode="sync",
                solver_timeout_ms=timeout_ms,
            )
            guard = Guard(policy=policy, config=cfg)

        self._guard = guard
        self._on_fail = on_fail
        self._shadow = shadow
        self._timeout_ms = timeout_ms
        self._bypass_on_timeout = bypass_on_timeout
        self._sidecar_key = sidecar_key
        self._intent_extractor = intent_extractor
        self._state_extractor = state_extractor
        self._audit_sink = audit_sink
        self._node_name = node_name or "langgraph_node"

    def decorate(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):

            async def _awrapper(state: Any, *args: Any, **kwargs: Any) -> Any:
                return await self._run(
                    node_fn=fn,
                    state=state,
                    args=args,
                    kwargs=kwargs,
                )

            return _awrapper

        def _swrapper(state: Any, *args: Any, **kwargs: Any) -> Any:
            # asyncio.run() raises RuntimeError when called from inside a running
            # event loop (FastAPI, Jupyter, pytest-asyncio, any ASGI framework).
            # Detect this case and dispatch to a fresh thread with its own event
            # loop so that sync LangGraph nodes work correctly in async hosts.
            try:
                asyncio.get_running_loop()
                _in_async_host = True
            except RuntimeError:
                _in_async_host = False

            if _in_async_host:
                import concurrent.futures as _cf

                with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                    return _pool.submit(
                        lambda: asyncio.run(
                            self._run(
                                node_fn=fn,
                                state=state,
                                args=args,
                                kwargs=kwargs,
                            )
                        )
                    ).result()

            return asyncio.run(
                self._run(
                    node_fn=fn,
                    state=state,
                    args=args,
                    kwargs=kwargs,
                )
            )

        return _swrapper

    async def _run(
        self,
        *,
        node_fn: Callable[..., Any],
        state: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        request_id = str(uuid.uuid4())
        state_dict = _state_to_dict(state)

        intent_payload, state_payload = self._build_payloads(state_dict)
        started = time.perf_counter()
        decision = await self._guard.verify_async(
            intent=intent_payload,
            state=state_payload,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        verdict = self._build_verdict(
            decision=decision,
            request_id=request_id,
            latency_ms=elapsed_ms,
            intent_payload=intent_payload,
            state_payload=state_payload,
        )

        self._emit_metrics(verdict=verdict, latency_ms=elapsed_ms)
        self._emit_audit(verdict)

        should_bypass_timeout = decision.status is SolverStatus.TIMEOUT and self._bypass_on_timeout
        should_block = (
            not decision.allowed
            and not self._shadow
            and self._on_fail == "halt"
            and not should_bypass_timeout
        )

        if should_block:
            raise PramanixNodeBlockedError(
                f"Pramanix blocked node '{self._node_name}'",
                verdict,
            )

        result = node_fn(state, *args, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        return self._inject_sidecar(result=result, verdict=verdict)

    def _build_payloads(self, state_dict: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if self._intent_extractor is not None:
            intent_payload = dict(self._intent_extractor(state_dict))
        else:
            intent_payload = dict(state_dict)

        if self._state_extractor is not None:
            state_payload = dict(self._state_extractor(state_dict))
        else:
            policy_meta = getattr(
                getattr(self._guard, "_policy", None),
                "Meta",
                None,
            )
            intent_model = getattr(policy_meta, "intent_model", None)
            state_model = getattr(policy_meta, "state_model", None)
            if intent_model is not None and state_model is not None:
                intent_keys = _extract_keys_from_model(intent_model)
                state_keys = _extract_keys_from_model(state_model)
                intent_payload = {key: state_dict[key] for key in intent_keys if key in state_dict}
                state_payload = {key: state_dict[key] for key in state_keys if key in state_dict}
            else:
                state_payload = {}

        policy_meta = getattr(
            getattr(self._guard, "_policy", None),
            "Meta",
            None,
        )
        intent_model = getattr(policy_meta, "intent_model", None)
        state_model = getattr(policy_meta, "state_model", None)

        intent_payload = _coerce_payload_with_model(
            intent_payload,
            intent_model,
        )
        state_payload = _coerce_payload_with_model(state_payload, state_model)
        return intent_payload, state_payload

    def _build_verdict(
        self,
        *,
        decision: Decision,
        request_id: str,
        latency_ms: float,
        intent_payload: dict[str, Any],
        state_payload: dict[str, Any],
    ) -> dict[str, Any]:
        if decision.allowed:
            verdict_name = "SAT"
        elif decision.status is SolverStatus.TIMEOUT:
            verdict_name = "TIMEOUT"
        elif decision.status in (
            SolverStatus.ERROR,
            SolverStatus.VALIDATION_FAILURE,
        ):
            verdict_name = "ERROR"
        else:
            verdict_name = "UNSAT"

        formal_proof = (
            "; ".join(decision.violated_invariants)
            if decision.violated_invariants
            else decision.status.value
        )
        return {
            "request_id": request_id,
            "node": self._node_name,
            "policy_name": getattr(self._guard._policy, "__name__", "Policy"),
            "decision_id": decision.decision_id,
            "production_verdict": verdict_name,
            "shadow_mode": self._shadow,
            "latency_ms": round(latency_ms, 3),
            "plain_explanation": (decision.explanation or "Action blocked by policy."),
            "formal_proof": formal_proof,
            "remediation": _suggest_remediation(
                decision,
                intent_payload,
                state_payload,
            ),
            "status": decision.status.value,
            "violated_invariants": list(decision.violated_invariants),
        }

    def _emit_metrics(
        self,
        *,
        verdict: dict[str, Any],
        latency_ms: float,
    ) -> None:
        policy_name = str(verdict.get("policy_name", "Policy"))
        node_name = str(verdict.get("node", "langgraph_node"))
        verdict_name = str(verdict.get("production_verdict", "ERROR"))

        if _NODE_LATENCY_MS is not None:
            _NODE_LATENCY_MS.labels(
                policy=policy_name,
                node=node_name,
            ).observe(latency_ms)
        if _NODE_VERDICT_TOTAL is not None:
            _NODE_VERDICT_TOTAL.labels(
                policy=policy_name,
                node=node_name,
                verdict=verdict_name,
            ).inc()

    def _emit_audit(self, verdict: dict[str, Any]) -> None:
        if self._audit_sink is None:
            return
        try:
            if callable(self._audit_sink):
                self._audit_sink(verdict)
                return
            emit_fn = getattr(self._audit_sink, "emit", None)
            if callable(emit_fn):
                emit_fn(verdict)
        except Exception as exc:
            _log.warning("pramanix.langgraph.audit_emit_failed: %s", exc)

    def _inject_sidecar(self, *, result: Any, verdict: dict[str, Any]) -> Any:
        if isinstance(result, dict):
            out = dict(result)
            out[self._sidecar_key] = verdict
            return out
        return result


def pramanix_node(
    *,
    policy: Any | None = None,
    guard: Guard | None = None,
    on_fail: str = "halt",
    shadow: bool = False,
    timeout_ms: int = 100,
    bypass_on_timeout: bool = True,
    sidecar_key: str = "_pramanix_policy_verdict",
    intent_extractor: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    state_extractor: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    audit_sink: Any | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that turns a LangGraph node into a Pramanix-gated node."""

    def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        node = PramanixGuardNode(
            policy=policy,
            guard=guard,
            on_fail=on_fail,
            shadow=shadow,
            timeout_ms=timeout_ms,
            bypass_on_timeout=bypass_on_timeout,
            sidecar_key=sidecar_key,
            intent_extractor=intent_extractor,
            state_extractor=state_extractor,
            audit_sink=audit_sink,
            node_name=getattr(fn, "__name__", "langgraph_node"),
        )
        return node.decorate(fn)

    return _decorator
