# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for F-3/F-4 — gRPC, Kafka, and Kubernetes admission webhook interceptors.

Coverage:
- PramanixGrpcInterceptor: blocked → aborts with PERMISSION_DENIED
- PramanixGrpcInterceptor: allowed → calls original handler
- PramanixKafkaConsumer: blocked message → not yielded (returns None)
- PramanixKafkaConsumer: allowed message → yielded
- create_admission_webhook: requires FastAPI; blocked → allowed=False
- create_admission_webhook: allowed → allowed=True
"""
from __future__ import annotations

import sys
from decimal import Decimal
from typing import ClassVar
from unittest.mock import patch

import pytest

from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy
from tests.helpers.real_protocols import (
    _ConfluentKafkaModule,
    _GrpcRpcHandler,
    _KafkaConsumer,
    _KafkaMessage,
    _RpcContext,
)

# ── Shared test policy ────────────────────────────────────────────────────────


class _TestPolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) > Decimal("0")).named("positive_amount")]


_CONFIG = GuardConfig(execution_mode="sync")


def _make_guard() -> Guard:
    return Guard(_TestPolicy, config=_CONFIG)


# ── PramanixGrpcInterceptor ───────────────────────────────────────────────────


class TestPramanixGrpcInterceptor:
    """Uses real grpcio (installed) — no sys.modules injection needed."""

    def _make_interceptor(self, intent: dict):
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        return PramanixGrpcInterceptor(
            guard=_make_guard(),
            intent_extractor=lambda details, req: intent,
            state_provider=lambda: {},
        )

    def test_allowed_calls_original_handler(self):
        """When guard allows, intercept_service returns a non-None wrapped handler."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        def _original(req, ctx):
            return "handler_result"

        handler = _GrpcRpcHandler(unary_unary=_original)

        interceptor = PramanixGrpcInterceptor(
            guard=_make_guard(),
            intent_extractor=lambda d, r: {"amount": Decimal("100")},
            state_provider=lambda: {},
        )

        result = interceptor.intercept_service(lambda _: handler, object())
        assert result is not None

    def test_none_handler_returned_as_is(self):
        """If continuation returns None, intercept_service returns None."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        interceptor = PramanixGrpcInterceptor(
            guard=_make_guard(),
            intent_extractor=lambda d, r: {"amount": Decimal("100")},
            state_provider=lambda: {},
        )
        result = interceptor.intercept_service(lambda _: None, object())
        assert result is None

    def test_guarded_unary_blocks_when_denied(self):
        """_guarded_unary must call context.abort when guard blocks."""
        import grpc

        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        def _original(req, ctx):
            return "should_not_reach"

        handler = _GrpcRpcHandler(unary_unary=_original)

        interceptor = PramanixGrpcInterceptor(
            guard=_make_guard(),
            intent_extractor=lambda d, r: {"amount": Decimal("-100")},  # always blocks
            state_provider=lambda: {},
        )

        wrapped = interceptor._wrap_handler(handler, object())
        ctx = _RpcContext()
        wrapped.unary_unary(object(), ctx)

        assert ctx.aborted is True
        assert ctx.abort_code == grpc.StatusCode.PERMISSION_DENIED


# ── PramanixKafkaConsumer ─────────────────────────────────────────────────────


class TestPramanixKafkaConsumer:
    """Bypasses __init__ via __new__ + direct attribute injection.

    confluent_kafka IS installed, so PramanixKafkaConsumer is directly
    importable.  We avoid a real broker by injecting a _KafkaConsumer
    (from real_protocols) as the private _consumer attribute — no
    sys.modules injection or importlib.reload required.
    """

    def _build(self, messages, intent_extractor):
        from pramanix.interceptors.kafka import PramanixKafkaConsumer

        consumer_instance = _KafkaConsumer(messages=messages)
        c = PramanixKafkaConsumer.__new__(PramanixKafkaConsumer)
        c._guard = _make_guard()
        c._intent_extractor = intent_extractor
        c._state_provider = lambda: {}
        c._dlq_producer = None
        c._dlq_topic = "pramanix.dlq"
        c._consumer = consumer_instance
        return c

    def test_blocked_message_not_yielded(self):
        """A message that fails guard verification must not be yielded."""
        blocked_msg = _KafkaMessage(b'{"amount": -100}')
        consumer = self._build(
            messages=[blocked_msg],
            intent_extractor=lambda msg: {"amount": Decimal("-100")},
        )
        yielded = list(consumer.safe_poll(timeout=0.1))
        assert yielded == []

    def test_allowed_message_is_yielded(self):
        """A message that passes guard verification must be yielded."""
        allowed_msg = _KafkaMessage(b'{"amount": 100}')
        consumer = self._build(
            messages=[allowed_msg],
            intent_extractor=lambda msg: {"amount": Decimal("100")},
        )
        yielded = list(consumer.safe_poll(timeout=0.1))
        assert len(yielded) == 1
        assert yielded[0] is allowed_msg


# ── Kubernetes Admission Webhook ──────────────────────────────────────────────


class TestAdmissionWebhook:
    _REVIEW: ClassVar[dict] = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "test-uid-1234",
            "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
            "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
            "name": "my-deploy",
            "namespace": "default",
            "operation": "CREATE",
            "object": {"spec": {"replicas": 1}},
        },
    }

    def test_create_webhook_requires_fastapi(self):
        """create_admission_webhook raises ConfigurationError when FastAPI missing."""
        from pramanix.exceptions import ConfigurationError

        with patch.dict("sys.modules", {"fastapi": None, "fastapi.responses": None}):
            import importlib

            from pramanix.k8s import webhook as wh_mod
            importlib.reload(wh_mod)

            with pytest.raises((ConfigurationError, Exception)):
                wh_mod.create_admission_webhook(
                    guard=_make_guard(),
                    intent_extractor=lambda r: {"amount": Decimal("100")},
                    state_provider=lambda: {},
                )

    def test_webhook_allowed_returns_allowed_true(self):
        """Allowed admission request → response contains allowed=true."""
        pytest.importorskip("fastapi")
        pytest.importorskip("httpx")

        from fastapi.testclient import TestClient

        from pramanix.k8s.webhook import create_admission_webhook

        app = create_admission_webhook(
            guard=_make_guard(),
            intent_extractor=lambda r: {"amount": Decimal("100")},
            state_provider=lambda: {},
        )

        with TestClient(app) as client:
            resp = client.post("/validate", json=self._REVIEW)
        assert resp.status_code == 200
        body = resp.json()
        assert body["response"]["allowed"] is True
        assert body["response"]["uid"] == "test-uid-1234"

    def test_webhook_blocked_returns_allowed_false(self):
        """Blocked admission request → response contains allowed=false."""
        pytest.importorskip("fastapi")

        from fastapi.testclient import TestClient

        from pramanix.k8s.webhook import create_admission_webhook

        app = create_admission_webhook(
            guard=_make_guard(),
            intent_extractor=lambda r: {"amount": Decimal("-100")},
            state_provider=lambda: {},
        )

        with TestClient(app) as client:
            resp = client.post("/validate", json=self._REVIEW)
        assert resp.status_code == 200
        body = resp.json()
        assert body["response"]["allowed"] is False
        assert "status" in body["response"]
        assert body["response"]["uid"] == "test-uid-1234"

