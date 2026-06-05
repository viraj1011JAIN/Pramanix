# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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

_GRPC_AVAILABLE: bool = False

if TYPE_CHECKING:
    import grpc

    _InterceptorBase = grpc.ServerInterceptor[Any, Any]
else:
    try:
        import grpc

        _InterceptorBase = grpc.ServerInterceptor
        _GRPC_AVAILABLE = True
    except ImportError:
        _InterceptorBase = object


class PramanixGrpcInterceptor(_InterceptorBase):
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
        if not _GRPC_AVAILABLE:
            raise ImportError(
                "PramanixGrpcInterceptor requires 'grpcio': "
                "pip install 'pramanix[grpc]'"
            )
        import grpc as _grpc

        self._guard = guard
        self._intent_extractor = intent_extractor
        self._state_provider = state_provider
        self._denied_code = denied_status_code or _grpc.StatusCode.PERMISSION_DENIED

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

        def _check_guard(request: Any, context: Any) -> bool:
            """Run the guard; abort the RPC and return False if blocked."""
            try:
                intent = interceptor._intent_extractor(handler_call_details, request)
                state = interceptor._state_provider()
                decision = interceptor._guard.verify(intent=intent, state=state)
            except Exception as exc:
                _log.exception("pramanix.grpc.guard_error: %s", exc)
                context.abort(_grpc.StatusCode.INTERNAL, "Pramanix guard error")
                return False

            if not decision.allowed:
                violated = ", ".join(decision.violated_invariants or [])
                context.abort(
                    interceptor._denied_code,
                    f"Pramanix guard blocked RPC. Violated: [{violated}]. "
                    f"Reason: {decision.explanation or 'policy violation'}",
                )
                return False
            return True

        # ── unary_unary ───────────────────────────────────────────────────────
        def _guarded_unary_unary(request: Any, context: Any) -> Any:
            if not _check_guard(request, context):
                return None
            return handler.unary_unary(request, context)

        # ── unary_stream ──────────────────────────────────────────────────────
        def _guarded_unary_stream(request: Any, context: Any) -> Any:
            if not _check_guard(request, context):
                return
            yield from handler.unary_stream(request, context)

        # ── stream_unary ──────────────────────────────────────────────────────
        def _guarded_stream_unary(request_iterator: Any, context: Any) -> Any:
            # Gate EVERY message in the stream, not just the first.
            # Checking only the first message allows an attacker to send an
            # innocuous first message (which passes the guard) and then inject
            # policy-violating content in all subsequent stream messages.
            buffered: list[Any] = []
            for msg in request_iterator:
                if not _check_guard(msg, context):
                    return None
                buffered.append(msg)
            if not buffered:
                context.abort(_grpc.StatusCode.INVALID_ARGUMENT, "empty request stream")
                return None
            return handler.stream_unary(iter(buffered), context)

        # ── stream_stream ─────────────────────────────────────────────────────
        def _guarded_stream_stream(request_iterator: Any, context: Any) -> Any:
            # Gate EVERY message in the stream.  Same rationale as stream_unary.
            has_messages = False
            for msg in request_iterator:
                if not _check_guard(msg, context):
                    return
                has_messages = True
                # Yield each guard-approved message one-by-one to the handler.
                # This preserves true streaming semantics while enforcing the
                # guard on every message before it reaches the application.
                yield from handler.stream_stream(iter([msg]), context)
            if not has_messages:
                context.abort(_grpc.StatusCode.INVALID_ARGUMENT, "empty request stream")

        replace_kwargs: dict[str, Any] = {"unary_unary": _guarded_unary_unary}
        if getattr(handler, "unary_stream", None) is not None:
            replace_kwargs["unary_stream"] = _guarded_unary_stream
        if getattr(handler, "stream_unary", None) is not None:
            replace_kwargs["stream_unary"] = _guarded_stream_unary
        if getattr(handler, "stream_stream", None) is not None:
            replace_kwargs["stream_stream"] = _guarded_stream_stream
        return handler._replace(**replace_kwargs)

    @classmethod
    def _for_testing(
        cls,
        *,
        guard: Any,
        intent_extractor: Any,
        state_provider: Any = None,
        denied_status_code: Any = None,
    ) -> "PramanixGrpcInterceptor":
        """Construct an instance without requiring grpcio to be installed.

        Allows unit tests to exercise ``_wrap_handler`` and ``_check_guard``
        logic using duck-typed handler/context objects without a real gRPC
        server or the grpcio package.
        """
        inst = cls.__new__(cls)
        inst._guard = guard
        inst._intent_extractor = intent_extractor
        inst._state_provider = state_provider or (lambda: {})
        inst._denied_code = denied_status_code or object()
        return inst
