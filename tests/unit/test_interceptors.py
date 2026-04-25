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

from decimal import Decimal
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

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
    def _make_interceptor(self, intent: dict):
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = _make_guard()
        return PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: intent,
            state_provider=lambda: {},
        )

    def test_allowed_calls_original_handler(self):
        """When guard allows, the original unary handler must be called."""

        mock_grpc = MagicMock()
        mock_grpc.StatusCode = MagicMock()
        mock_grpc.StatusCode.PERMISSION_DENIED = "PERMISSION_DENIED"
        mock_grpc.StatusCode.INTERNAL = "INTERNAL"
        mock_grpc.ServerInterceptor = object

        with patch.dict("sys.modules", {"grpc": mock_grpc}):
            # Reload to pick up mock
            import importlib

            from pramanix.interceptors import grpc as grpc_mod
            importlib.reload(grpc_mod)

            original_handler = MagicMock(return_value="handler_result")
            mock_handler = MagicMock()
            mock_handler.unary_unary = original_handler
            mock_handler._replace = MagicMock(return_value=mock_handler)

            interceptor = grpc_mod.PramanixGrpcInterceptor(
                guard=_make_guard(),
                intent_extractor=lambda d, r: {"amount": Decimal("100")},
                state_provider=lambda: {},
            )
            interceptor._denied_code = "PERMISSION_DENIED"

            continuation = MagicMock(return_value=mock_handler)
            details = MagicMock()

            result = interceptor.intercept_service(continuation, details)
            assert result is not None

    def test_none_handler_returned_as_is(self):
        """If continuation returns None, intercept_service returns None."""
        mock_grpc = MagicMock()
        mock_grpc.ServerInterceptor = object

        with patch.dict("sys.modules", {"grpc": mock_grpc}):
            import importlib

            from pramanix.interceptors import grpc as grpc_mod
            importlib.reload(grpc_mod)

            interceptor = grpc_mod.PramanixGrpcInterceptor(
                guard=_make_guard(),
                intent_extractor=lambda d, r: {"amount": Decimal("100")},
                state_provider=lambda: {},
            )
            result = interceptor.intercept_service(lambda _: None, MagicMock())
            assert result is None

    def test_guarded_unary_blocks_when_denied(self):
        """_guarded_unary must call context.abort when guard blocks."""
        mock_grpc = MagicMock()
        mock_grpc.StatusCode = MagicMock()
        mock_grpc.StatusCode.PERMISSION_DENIED = "PERMISSION_DENIED"
        mock_grpc.StatusCode.INTERNAL = "INTERNAL"
        mock_grpc.ServerInterceptor = object

        with patch.dict("sys.modules", {"grpc": mock_grpc}):
            import importlib

            from pramanix.interceptors import grpc as grpc_mod
            importlib.reload(grpc_mod)

            original_handler_fn = MagicMock(return_value="result")
            mock_handler = MagicMock()
            mock_handler.unary_unary = original_handler_fn

            captured_wrapped = {}

            def fake_replace(**kwargs):
                captured_wrapped.update(kwargs)
                new_handler = MagicMock()
                new_handler.unary_unary = kwargs.get("unary_unary", original_handler_fn)
                return new_handler

            mock_handler._replace = fake_replace

            interceptor = grpc_mod.PramanixGrpcInterceptor(
                guard=_make_guard(),
                intent_extractor=lambda d, r: {"amount": Decimal("-100")},  # will be blocked
                state_provider=lambda: {},
            )
            interceptor._denied_code = "PERMISSION_DENIED"

            wrapped = interceptor._wrap_handler(mock_handler, MagicMock())
            context = MagicMock()
            wrapped.unary_unary(MagicMock(), context)
            context.abort.assert_called_once()
            call_args = context.abort.call_args[0]
            assert call_args[0] == "PERMISSION_DENIED"


# ── PramanixKafkaConsumer ─────────────────────────────────────────────────────


class TestPramanixKafkaConsumer:
    def _build_mock_message(self, value: bytes = b"{}") -> MagicMock:
        msg = MagicMock()
        msg.error.return_value = None
        msg.value.return_value = value
        msg.topic.return_value = "test-topic"
        msg.offset.return_value = 0
        return msg

    def test_blocked_message_not_yielded(self):
        """A message that fails guard verification must not be yielded."""
        mock_confluent = MagicMock()
        mock_consumer_instance = MagicMock()
        blocked_msg = self._build_mock_message(b'{"amount": -100}')

        # First call returns blocked message, second returns None to stop iteration
        mock_consumer_instance.poll.side_effect = [blocked_msg, None]
        mock_confluent.Consumer.return_value = mock_consumer_instance

        with patch.dict("sys.modules", {"confluent_kafka": mock_confluent}):
            import importlib

            from pramanix.interceptors import kafka as kafka_mod
            importlib.reload(kafka_mod)

            consumer = kafka_mod.PramanixKafkaConsumer(
                kafka_config={"bootstrap.servers": "localhost:9092", "group.id": "test"},
                topics=["test-topic"],
                guard=_make_guard(),
                intent_extractor=lambda msg: {"amount": Decimal("-100")},  # always blocks
                state_provider=lambda: {},
            )
            yielded = list(consumer.safe_poll(timeout=0.1))
            assert yielded == []

    def test_allowed_message_is_yielded(self):
        """A message that passes guard verification must be yielded."""
        mock_confluent = MagicMock()
        mock_consumer_instance = MagicMock()
        allowed_msg = self._build_mock_message(b'{"amount": 100}')

        mock_consumer_instance.poll.side_effect = [allowed_msg, None]
        mock_confluent.Consumer.return_value = mock_consumer_instance
        mock_confluent.KafkaException = Exception

        with patch.dict("sys.modules", {"confluent_kafka": mock_confluent}):
            import importlib

            from pramanix.interceptors import kafka as kafka_mod
            importlib.reload(kafka_mod)

            consumer = kafka_mod.PramanixKafkaConsumer(
                kafka_config={"bootstrap.servers": "localhost:9092", "group.id": "test"},
                topics=["test-topic"],
                guard=_make_guard(),
                intent_extractor=lambda msg: {"amount": Decimal("100")},  # always passes
                state_provider=lambda: {},
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
            intent_extractor=lambda r: {"amount": Decimal("100")},  # always passes
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
            intent_extractor=lambda r: {"amount": Decimal("-100")},  # always blocks
            state_provider=lambda: {},
        )

        with TestClient(app) as client:
            resp = client.post("/validate", json=self._REVIEW)
        assert resp.status_code == 200
        body = resp.json()
        assert body["response"]["allowed"] is False
        assert "status" in body["response"]
        assert body["response"]["uid"] == "test-uid-1234"
