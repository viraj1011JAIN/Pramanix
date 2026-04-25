# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Kubernetes admission webhook — Phase F-4.

Creates a FastAPI application that acts as a Kubernetes ``ValidatingWebhook``.
Every ``AdmissionReview`` request is gated by ``Guard.verify()`` before being
forwarded to the cluster.  The webhook returns
``{"allowed": false, "status": {"message": "<reason>"}}`` when blocked.

Install: pip install 'pramanix[k8s]'
Requires: fastapi >= 0.110, uvicorn

Usage::

    from pramanix.k8s.webhook import create_admission_webhook
    import uvicorn

    app = create_admission_webhook(
        guard=Guard(DeployPolicy, config=GuardConfig(execution_mode="sync")),
        intent_extractor=lambda review: build_intent(review),
        state_provider=lambda: fetch_cluster_state(),
    )

    uvicorn.run(app, host="0.0.0.0", port=8443)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from pramanix.guard import Guard

__all__ = ["create_admission_webhook"]

_log = logging.getLogger(__name__)

# ── optional dependency guard ─────────────────────────────────────────────────
try:
    from fastapi import FastAPI

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    FastAPI = None  # type: ignore[assignment, misc]


def create_admission_webhook(
    *,
    guard: Guard,
    intent_extractor: Callable[[dict[str, Any]], dict[str, Any]],
    state_provider: Callable[[], dict[str, Any]],
    path: str = "/validate",
) -> Any:
    """Build a FastAPI application that acts as a Kubernetes admission webhook.

    Args:
        guard:            A fully constructed :class:`~pramanix.guard.Guard`.
        intent_extractor: Callable ``(admission_review_dict) → intent dict``.
                          Receives the full AdmissionReview JSON payload as a
                          dict and must return a dict matching the guard's
                          policy schema.
        state_provider:   Callable ``() → state dict`` for current system state.
        path:             URL path to register the validation endpoint on.

    Returns:
        A ``fastapi.FastAPI`` application instance ready to be served.

    Raises:
        :class:`~pramanix.exceptions.ConfigurationError`: if FastAPI is not
            installed.
    """
    if not _FASTAPI_AVAILABLE:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "FastAPI is required for the Kubernetes admission webhook. "
            "Install it with: pip install 'pramanix[k8s]'"
        )

    import fastapi as _fastapi
    import fastapi.responses as _fastapi_responses

    app = _fastapi.FastAPI(title="Pramanix Admission Webhook")

    @app.post(path, response_class=_fastapi_responses.JSONResponse)
    async def validate(
        body: dict[str, Any] = _fastapi.Body(...),  # noqa: B008
    ) -> _fastapi_responses.JSONResponse:
        """Process a Kubernetes AdmissionReview request."""
        uid: str = ""
        try:
            uid = body.get("request", {}).get("uid", "")

            intent = intent_extractor(body)
            state = state_provider()
            decision = guard.verify(intent=intent, state=state)
        except Exception as exc:
            _log.exception("pramanix.k8s.webhook_error uid=%s: %s", uid, exc)
            return _fastapi_responses.JSONResponse(
                content={
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": uid,
                        "allowed": False,
                        "status": {
                            "code": 500,
                            "message": f"Pramanix webhook error: {exc}",
                        },
                    },
                },
                status_code=200,  # K8s expects 200 even for error responses
            )

        if decision.allowed:
            return _fastapi_responses.JSONResponse(
                content={
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": uid,
                        "allowed": True,
                    },
                }
            )

        violated = ", ".join(decision.violated_invariants or [])
        message = (
            f"Pramanix guard blocked admission. "
            f"Violated: [{violated}]. "
            f"Reason: {decision.explanation or 'policy violation'}"
        )
        _log.warning("pramanix.k8s.blocked uid=%s violated=[%s]", uid, violated)
        return _fastapi_responses.JSONResponse(
            content={
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": False,
                    "status": {
                        "code": 403,
                        "message": message,
                    },
                },
            }
        )

    return app
