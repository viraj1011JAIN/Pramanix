# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""gRPC server interceptor — Phase F-3.

Wraps a ``grpc.ServerInterceptor`` so every incoming RPC is gated by a
``Guard.verify()`` call before the handler executes.  When the guard blocks,
the RPC is aborted with ``PERMISSION_DENIED`` and the violation reason is
surfaced in the gRPC status detail — never in a raw exception traceback.

Install: pip install 'pramanix[grpc]'
Requires: grpcio >= 1.50

Usage::

    from pramanix.interceptors.grpc import PramanixGrpcInterceptor

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=[
            PramanixGrpcInterceptor(
                guard=Guard(TransferPolicy, config=GuardConfig(execution_mode="sync")),
                intent_extractor=extract_intent_from_request,
                state_provider=lambda: fetch_state(),
            )
        ],
    )
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from pramanix.guard import Guard

__all__ = ["PramanixGrpcInterceptor"]

_log = logging.getLogger(__name__)

try:
    import grpc

    _GRPC_AVAILABLE = True
    _InterceptorBase: Any = grpc.ServerInterceptor
except ImportError:
    _GRPC_AVAILABLE = False
    _InterceptorBase = object


class PramanixGrpcInterceptor(_InterceptorBase):  # type: ignore[misc]
    """gRPC ``ServerInterceptor`` with Z3 formal verification gate.

    If ``grpcio`` is not installed, the class is still importable as a plain
    object — useful for unit testing without the gRPC stack.

    Args:
        guard:             A fully constructed :class:`~pramanix.guard.Guard`.
        intent_extractor:  Callable ``(handler_call_details, request) → intent dict``.
                           Receives the ``HandlerCallDetails`` and the
                           deserialized request protobuf; returns an intent
                           dict matching the guard's policy schema.
        state_provider:    Callable ``() → state dict`` that fetches current
                           system state at call time.
        denied_status_code: gRPC status code used when the guard blocks.
                            Defaults to ``grpc.StatusCode.PERMISSION_DENIED``.
    """

    def __init__(
        self,
        *,
        guard: Guard,
        intent_extractor: Callable[[Any, Any], dict[str, Any]],
        state_provider: Callable[[], dict[str, Any]],
        denied_status_code: Any | None = None,
    ) -> None:
        self._guard = guard
        self._intent_extractor = intent_extractor
        self._state_provider = state_provider

        if _GRPC_AVAILABLE:
            import grpc as _grpc

            self._denied_code = denied_status_code or _grpc.StatusCode.PERMISSION_DENIED
        else:
            self._denied_code = denied_status_code

    # ── grpc.ServerInterceptor protocol ──────────────────────────────────────

    def intercept_service(self, continuation: Callable[..., Any], handler_call_details: Any) -> Any:
        """Intercept the service-handler lookup.

        This is the grpc.ServerInterceptor entry-point.  We wrap the returned
        handler so the guard check happens per-call, not per-lookup.
        """
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        return self._wrap_handler(handler, handler_call_details)

    def _wrap_handler(self, handler: Any, handler_call_details: Any) -> Any:
        """Return a new handler that runs the guard before the real handler."""
        if not _GRPC_AVAILABLE:
            return handler

        import grpc as _grpc

        interceptor = self
        original_unary = handler.unary_unary

        def _guarded_unary(request: Any, context: Any) -> Any:
            try:
                intent = interceptor._intent_extractor(handler_call_details, request)
                state = interceptor._state_provider()
                decision = interceptor._guard.verify(intent=intent, state=state)
            except Exception as exc:
                _log.exception("pramanix.grpc.guard_error: %s", exc)
                context.abort(
                    _grpc.StatusCode.INTERNAL,
                    f"Pramanix guard error: {exc}",
                )
                return None

            if not decision.allowed:
                violated = ", ".join(decision.violated_invariants or [])
                context.abort(
                    interceptor._denied_code,
                    f"Pramanix guard blocked RPC. Violated: [{violated}]. "
                    f"Reason: {decision.explanation or 'policy violation'}",
                )
                return None

            return original_unary(request, context)

        # Return a new handler descriptor with only unary_unary patched.
        # For stream handlers, callers should subclass and override.
        return handler._replace(unary_unary=_guarded_unary)
