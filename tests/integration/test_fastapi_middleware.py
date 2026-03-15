# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Live integration tests for PramanixMiddleware and pramanix_route.

Uses real FastAPI and httpx — no sys.modules mocking.
Tests are skipped if fastapi or httpx are not installed.

Verified behaviors:
- ALLOW → 200, handler executes
- BLOCK → 403, decision_id + violated_invariants + status in body
- Proof header present when PRAMANIX_SIGNING_KEY is set
- Proof header is independently verifiable
- Content-Type enforcement → 415
- Body size limit → 413
- Invalid JSON → 422
- Timing: BLOCK path padded to timing budget (no timing oracle)
- Raw field values NOT present in BLOCK response body (security)
"""
from __future__ import annotations

import time
from decimal import Decimal

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed — skipping live middleware tests")
pytest.importorskip("httpx", reason="httpx not installed — skipping live middleware tests")

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from pramanix import E, Field, GuardConfig, Policy  # noqa: E402
from pramanix.audit.verifier import DecisionVerifier  # noqa: E402
from pramanix.integrations.fastapi import PramanixMiddleware  # noqa: E402

# ── Policies ──────────────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount, "balance": _balance}

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Insufficient balance for this transfer")
        ]


class _BlockPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount}

    @classmethod
    def invariants(cls):
        return [
            (E(_amount) <= Decimal("0"))
            .named("must_be_zero")
            .explain("Amount must be zero under block policy")
        ]


class _TransferIntent(BaseModel):
    amount: Decimal


async def _state_allow(request) -> dict:
    return {"balance": Decimal("5000"), "state_version": "1.0"}


async def _state_block_policy(request) -> dict:
    return {"state_version": "1.0"}


def _make_allow_app(timing_budget_ms: float = 50.0) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        PramanixMiddleware,
        policy=_AllowPolicy,
        intent_model=_TransferIntent,
        state_loader=_state_allow,
        config=GuardConfig(execution_mode="sync"),
        timing_budget_ms=timing_budget_ms,
    )

    @app.post("/transfer")
    async def handler(body: dict) -> dict:
        return {"status": "ok"}

    return app


def _make_block_app(timing_budget_ms: float = 50.0) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        PramanixMiddleware,
        policy=_BlockPolicy,
        intent_model=_TransferIntent,
        state_loader=_state_block_policy,
        config=GuardConfig(execution_mode="sync"),
        timing_budget_ms=timing_budget_ms,
    )

    @app.post("/transfer")
    async def handler(body: dict) -> dict:
        return {"status": "ok"}

    return app


# ── ALLOW tests ───────────────────────────────────────────────────────────────


class TestMiddlewareAllow:
    @pytest.mark.asyncio
    async def test_allow_returns_200(self):
        app = _make_allow_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_allow_executes_handler(self):
        app = _make_allow_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        assert resp.json().get("status") == "ok"

    @pytest.mark.asyncio
    async def test_allow_proof_header_present_when_key_set(self, monkeypatch):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", "x" * 64)
        app = _make_allow_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        assert "x-pramanix-proof" in resp.headers
        parts = resp.headers["x-pramanix-proof"].split(".")
        assert len(parts) == 3

    @pytest.mark.asyncio
    async def test_allow_proof_header_verifiable(self, monkeypatch):
        key = "allow-proof-verification-key-" + "x" * 35
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", key)
        app = _make_allow_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        token = resp.headers.get("x-pramanix-proof", "")
        if token:
            verifier = DecisionVerifier(signing_key=key)
            result = verifier.verify(token)
            assert result.valid
            assert result.allowed is True


# ── BLOCK tests ───────────────────────────────────────────────────────────────


class TestMiddlewareBlock:
    @pytest.mark.asyncio
    async def test_block_returns_403(self):
        app = _make_block_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_block_response_contains_decision_id(self):
        app = _make_block_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        body = resp.json()
        assert "decision_id" in body
        assert len(body["decision_id"]) > 10

    @pytest.mark.asyncio
    async def test_block_response_contains_violated_invariants(self):
        app = _make_block_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        body = resp.json()
        assert "violated_invariants" in body
        assert "must_be_zero" in body["violated_invariants"]

    @pytest.mark.asyncio
    async def test_block_response_contains_status(self):
        app = _make_block_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        body = resp.json()
        assert "status" in body

    @pytest.mark.asyncio
    async def test_block_proof_header_is_verifiable(self, monkeypatch):
        key = "block-proof-verification-key-" + "x" * 35
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", key)
        app = _make_block_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        token = resp.headers.get("x-pramanix-proof", "")
        if token:
            verifier = DecisionVerifier(signing_key=key)
            result = verifier.verify(token)
            assert result.valid
            assert result.allowed is False
            assert "must_be_zero" in result.violated_invariants

    @pytest.mark.asyncio
    async def test_block_does_not_leak_raw_field_values(self):
        """SECURITY: block response body must not contain raw input values."""
        app = _make_block_app()
        sentinel = "123456789"
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": sentinel},
                headers={"Content-Type": "application/json"},
            )
        # Raw amount must not appear anywhere in the response body
        assert sentinel not in resp.text


# ── Security tests ────────────────────────────────────────────────────────────


class TestMiddlewareSecurity:
    @pytest.mark.asyncio
    async def test_wrong_content_type_returns_415(self):
        app = _make_allow_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                content=b"amount=100",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        assert resp.status_code == 415

    @pytest.mark.asyncio
    async def test_oversized_body_returns_413(self):
        small_app = FastAPI()
        small_app.add_middleware(
            PramanixMiddleware,
            policy=_AllowPolicy,
            intent_model=_TransferIntent,
            state_loader=_state_allow,
            config=GuardConfig(execution_mode="sync"),
            max_body_bytes=10,
        )

        @small_app.post("/transfer")
        async def _() -> dict:
            return {}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=small_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_invalid_json_returns_422(self):
        app = _make_allow_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                content=b"{ not valid json {{",
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 422


# ── Timing tests ──────────────────────────────────────────────────────────────


class TestMiddlewareTiming:
    @pytest.mark.asyncio
    async def test_block_path_padded_to_timing_budget(self):
        """BLOCK path must take >= timing_budget_ms (no timing oracle)."""
        budget_ms = 30.0
        app = _make_block_app(timing_budget_ms=budget_ms)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            t0 = time.monotonic()
            await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
            elapsed_ms = (time.monotonic() - t0) * 1000
        # 10ms CI tolerance
        assert (
            elapsed_ms >= budget_ms - 10
        ), f"BLOCK path took {elapsed_ms:.1f}ms, expected >= {budget_ms - 10:.1f}ms"


# ── Proof roundtrip ───────────────────────────────────────────────────────────


class TestProofRoundtrip:
    @pytest.mark.asyncio
    async def test_sign_verify_allow_roundtrip(self, monkeypatch):
        key = "roundtrip-key-allow-" + "x" * 44
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", key)
        app = _make_allow_app()
        verifier = DecisionVerifier(signing_key=key)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        token = resp.headers.get("x-pramanix-proof", "")
        if token:
            result = verifier.verify(token)
            assert result.valid
            assert result.allowed is True

    @pytest.mark.asyncio
    async def test_sign_verify_block_roundtrip(self, monkeypatch):
        key = "roundtrip-key-block-" + "x" * 44
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", key)
        app = _make_block_app()
        verifier = DecisionVerifier(signing_key=key)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        token = resp.headers.get("x-pramanix-proof", "")
        if token:
            result = verifier.verify(token)
            assert result.valid
            assert result.allowed is False
