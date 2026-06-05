# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
class _FastAPIFallback:
    """Raises ConfigurationError when fastapi is not installed."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "Kubernetes webhook support requires the 'fastapi' package: "
            "pip install 'pramanix[k8s]'"
        )


_FASTAPI_AVAILABLE: bool = False

if TYPE_CHECKING:
    from fastapi import FastAPI
else:
    try:
        from fastapi import FastAPI

        _FASTAPI_AVAILABLE = True
    except ImportError:
        FastAPI = _FastAPIFallback


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
            # #334 fix: call verify_async — guard.verify() is synchronous and
            # blocks the entire FastAPI event loop for the Z3 solve duration
            # (potentially hundreds of ms), starving all concurrent admission
            # requests and triggering Kubernetes webhook timeout retries.
            decision = await guard.verify_async(intent=intent, state=state)
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
                            "message": "Pramanix guard error — request denied as a precaution",
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

        # #335 fix: NEVER include violated_invariants or explanation in the
        # Kubernetes rejection message.  AdmissionReview rejection messages are
        # stored permanently in `kubectl describe pod`, cluster Events, and the
        # immutable Kubernetes audit log — they are visible to any kubectl user
        # regardless of RBAC and cannot be redacted after the fact.  Exposing
        # policy invariant names enables binary-search policy probing from the
        # cluster audit log alone.
        #
        # Operators who need violation details for debugging should read the
        # Pramanix audit sink (Kafka/S3/Splunk/Datadog) or structured logs,
        # which are controlled by access policies and can be filtered/redacted.
        _log.warning(
            "pramanix.k8s.blocked uid=%s decision_id=%s violated=%s",
            uid,
            decision.decision_id,
            list(decision.violated_invariants or []),
        )
        return _fastapi_responses.JSONResponse(
            content={
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": False,
                    "status": {
                        "code": 403,
                        "message": (
                            f"Pramanix admission guard blocked this request "
                            f"(decision_id={decision.decision_id}). "
                            "Check the Pramanix audit log for details."
                        ),
                    },
                },
            }
        )

    return app
