# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""FastAPI / Starlette integration for Pramanix.

Install: pip install 'pramanix[fastapi]'

Two integration points are provided:

1. :class:`PramanixMiddleware` — ASGI middleware that intercepts every request
   before it reaches your route handlers.  Validates the JSON body as an intent,
   loads state, runs ``guard.verify_async()``, and returns 403 on BLOCK.

2. :func:`pramanix_route` — per-route decorator factory that creates a
   ``Guard`` once at decoration time and wraps the async handler.  The Guard
   is accessible on the decorated function as ``fn.__guard__``.

Security properties
-------------------
* The Guard instance is created **once** at startup — never per-request.
* Timing-pad: BLOCK responses are delayed to ``timing_budget_ms`` to prevent
  timing oracles that could reveal policy details.
* Body size cap (``max_body_bytes``) prevents memory exhaustion attacks.
* Content-type enforcement (``application/json``) rejects non-JSON bodies
  before any parsing occurs.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Literal

_log = logging.getLogger(__name__)

from pramanix.audit.signer import DecisionSigner
from pramanix.exceptions import GuardViolationError, PolicyCompilationError
from pramanix.guard import Guard, GuardConfig


class JSONResponse:  # pragma: no cover
    """Fallback stub — replaced by starlette import when available."""

    headers: dict[str, str]

    def __init__(self, *, status_code: int = 200, content: Any = None) -> None:
        self.headers: dict[str, str] = {}
        raise RuntimeError("starlette is not installed")


try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request  # noqa: F401
    from starlette.responses import JSONResponse, Response  # type: ignore[assignment]
    from starlette.types import ASGIApp  # noqa: F401

    _STARLETTE_AVAILABLE = True
    _BaseHTTPMiddleware: type = BaseHTTPMiddleware
except ImportError:  # pragma: no cover
    _STARLETTE_AVAILABLE = False
    _BaseHTTPMiddleware = object

if TYPE_CHECKING:
    from starlette.responses import Response

__all__ = ["PramanixMiddleware", "pramanix_route"]


class PramanixMiddleware(_BaseHTTPMiddleware):  # type: ignore[misc]
    """ASGI middleware that guards every request with a Pramanix policy.

    The Guard instance is created once at ``__init__`` time and reused for
    all requests.  This avoids per-request overhead from policy compilation
    and worker pool startup.

    Pipeline per request:

    1. Check ``Content-Type: application/json`` — return 415 if absent.
    2. Read body; return 413 if it exceeds ``max_body_bytes``.
    3. Parse JSON body — return 422 if invalid JSON.
    4. Validate intent via ``intent_model.model_validate(raw, strict=True)``
       — return 422 if validation fails.
    5. Load state via ``await state_loader(request)`` — return 500 if it raises.
    6. ``decision = await guard.verify_async(intent=intent_dict, state=state)``
    7. If BLOCK: apply timing pad, return 403 with decision details.
    8. If ALLOW: forward to the next ASGI handler (your route).

    Args:
        app:            The ASGI application to wrap.
        policy:         A :class:`~pramanix.policy.Policy` subclass.
        intent_model:   Pydantic model class for intent validation.
        state_loader:   Async callable ``(Request) -> dict`` that returns state.
        config:         Optional :class:`~pramanix.guard.GuardConfig`.  Defaults
                        to ``GuardConfig(execution_mode="async-thread")``.
        max_body_bytes: Maximum request body size in bytes (default 65,536).
        timing_budget_ms: Minimum BLOCK response time in milliseconds to prevent
                          timing-oracle attacks (default 50.0 ms).

    Raises:
        ImportError: If FastAPI/Starlette is not installed.
    """

    def __init__(
        self,
        app: Any,
        *,
        policy: Any,
        intent_model: Any,
        state_loader: Callable[..., Awaitable[dict[str, Any]]],
        config: GuardConfig | None = None,
        max_body_bytes: int = 65_536,
        timing_budget_ms: float = 50.0,
    ) -> None:
        if not _STARLETTE_AVAILABLE:
            raise ImportError("FastAPI/Starlette required: pip install 'pramanix[fastapi]'")
        super().__init__(app)
        self._intent_model = intent_model
        self._state_loader = state_loader
        self._max_body_bytes = max_body_bytes
        self._timing_budget_s: float = timing_budget_ms / 1000.0
        # Default to async-thread since we are in an async ASGI context.
        effective_config = config or GuardConfig(execution_mode="async-thread")
        self._guard: Guard = Guard(policy, effective_config)
        self._signer = DecisionSigner()
        self._redact_violations: bool = effective_config.redact_violations

    async def dispatch(self, request: Any, call_next: Any) -> Any:
        """Run the Pramanix guard pipeline for each incoming request."""
        t_start = time.monotonic()

        # ── 1. Content-type check ─────────────────────────────────────────────
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return Response(
                status_code=415,
                content=b"Unsupported Media Type: expected application/json",
            )

        # ── 2. Body size check ────────────────────────────────────────────────
        # Starlette caches request.body() internally after the first read.
        body: bytes = await request.body()
        if len(body) > self._max_body_bytes:
            return Response(
                status_code=413,
                content=b"Request Entity Too Large",
            )

        # ── 3. JSON parse ─────────────────────────────────────────────────────
        try:
            raw: dict[str, Any] = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return Response(
                status_code=422,
                content=b"Unprocessable Entity: invalid JSON body",
            )

        # ── 4. Intent validation ──────────────────────────────────────────────
        try:
            intent_obj = self._intent_model.model_validate(raw)
            intent_dict: dict[str, Any] = intent_obj.model_dump()
        except Exception as exc:
            _log.warning("pramanix.fastapi.intent_validation_error: %s", exc, exc_info=True)
            return JSONResponse(
                status_code=422,
                content={"detail": "Intent validation failed."},
            )

        # ── 5. State loading ──────────────────────────────────────────────────
        try:
            state = await self._state_loader(request)
        except Exception as exc:
            _log.error("pramanix.fastapi.state_loader_error: %s", exc, exc_info=True)
            return JSONResponse(
                status_code=500,
                content={"detail": "State loader error — request denied."},
            )

        # ── 6. Verify ─────────────────────────────────────────────────────────
        decision = await self._guard.verify_async(intent=intent_dict, state=state)

        # ── 7. Timing pad — applied to ALL responses (ALLOW and BLOCK) ──────────
        # Prevents timing-oracle attacks that distinguish fast-BLOCK from ALLOW.
        elapsed = time.monotonic() - t_start
        pad = max(0.0, self._timing_budget_s - elapsed)
        if pad > 0.0:
            await asyncio.sleep(pad)

        # ── 8. BLOCK path — 403 ───────────────────────────────────────────────
        if not decision.allowed:
            if self._redact_violations:
                block_content: dict[str, Any] = {
                    "decision_id": decision.decision_id,
                    "status": decision.status.value,
                }
            else:
                block_content = {
                    "decision_id": decision.decision_id,
                    "status": decision.status.value,
                    "violated_invariants": list(decision.violated_invariants),
                    "explanation": decision.explanation,
                }
            response = JSONResponse(status_code=403, content=block_content)
            signed = self._signer.sign(decision)
            if signed:
                response.headers["X-Pramanix-Proof"] = signed.token
                response.headers["X-Pramanix-Decision-Id"] = decision.decision_id
            return response

        # ── 9. ALLOW path — forward to route handler ──────────────────────────
        response = await call_next(request)
        signed = self._signer.sign(decision)
        if signed:
            response.headers["X-Pramanix-Proof"] = signed.token
            response.headers["X-Pramanix-Decision-Id"] = decision.decision_id
        return response


def pramanix_route(
    *,
    policy: Any,
    config: GuardConfig | None = None,
    on_block: Literal["raise", "return"] = "raise",
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Per-route decorator factory that guards an async route handler.

    The :class:`~pramanix.guard.Guard` is created **once** at decoration time
    and stored on the wrapper as ``wrapper.__guard__`` for introspection.

    The decorated function must receive ``intent`` and ``state`` as keyword
    arguments (or as Pydantic ``BaseModel`` instances — they are converted via
    ``.model_dump()`` before verification).

    Args:
        policy:   A :class:`~pramanix.policy.Policy` subclass.
        config:   Optional :class:`~pramanix.guard.GuardConfig`.
        on_block: What to do when the Guard blocks:

                  * ``"raise"`` (default) — raise
                    :class:`~pramanix.exceptions.GuardViolationError`.
                  * ``"return"`` — return a ``JSONResponse(403, decision.to_dict())``.

    Returns:
        A decorator that wraps an async function.

    Example::

        @pramanix_route(policy=BankingPolicy, on_block="raise")
        async def transfer(intent: dict, state: dict) -> dict:
            ...
    """
    _guard: Guard = Guard(policy, config or GuardConfig())

    def decorator(
        fn: Callable[..., Awaitable[Any]],
    ) -> Callable[..., Awaitable[Any]]:
        sig = inspect.signature(fn)
        params = set(sig.parameters.keys())
        missing = [p for p in ("intent", "state") if p not in params]
        if missing:
            raise PolicyCompilationError(
                f"pramanix_route: '{fn.__name__}' is missing required parameters: "
                f"{missing}. Add 'intent: dict, state: dict' to the function signature."
            )

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract intent and state from kwargs; fall back to positional args.
            intent: Any = kwargs.get("intent")
            state: Any = kwargs.get("state")

            if intent is None and len(args) >= 1:
                intent = args[0]
            if state is None and len(args) >= 2:
                state = args[1]

            # Pydantic BaseModel → plain dict (safe for ProcessPoolExecutor).
            try:
                from pydantic import BaseModel as _BaseModel

                if isinstance(intent, _BaseModel):
                    intent = intent.model_dump()
                if isinstance(state, _BaseModel):
                    state = state.model_dump()
            except ImportError:
                pass

            decision = await _guard.verify_async(intent=intent or {}, state=state or {})

            if not decision.allowed:
                if on_block == "raise":
                    raise GuardViolationError(decision)
                else:
                    # on_block == "return"
                    if _STARLETTE_AVAILABLE:
                        return JSONResponse(status_code=403, content=decision.to_dict())
                    # Starlette not available — raise as fallback.
                    raise GuardViolationError(decision)

            return await fn(*args, **kwargs)

        # Attach the guard for introspection / testing.
        wrapper.__guard__ = _guard  # type: ignore[attr-defined]
        return wrapper

    return decorator
