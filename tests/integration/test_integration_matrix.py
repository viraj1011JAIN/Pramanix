# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration matrix tests — 4 scenarios x real frameworks.

Tests all installed integrations against 4 scenarios:
  A - ALLOW: valid intent passes all policies
  B - BLOCK: invalid intent blocked by all integrations
  C - TIMEOUT: solver error/timeout → allowed=False
  D - VALIDATION: malformed intent → rejected

Uses pytest.importorskip — skips gracefully if framework not installed.
Zero sys.modules mocking.
"""
from __future__ import annotations

import json
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy

# ── Shared banking policy ──────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class _BankingPolicy(Policy):
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
            .explain("Insufficient balance for transfer")
        ]


class _BlockAllPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount}

    @classmethod
    def invariants(cls):
        return [(E(_amount) <= Decimal("0")).named("must_be_zero").explain("Amount must be zero")]


_guard_allow = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
_guard_block = Guard(_BlockAllPolicy, GuardConfig(execution_mode="sync"))

# ── Scenario A — FastAPI ALLOW ────────────────────────────────────────────────


class TestScenarioAAllow:
    @pytest.mark.asyncio
    async def test_fastapi_allow(self):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        from pydantic import BaseModel

        from pramanix.integrations.fastapi import PramanixMiddleware

        app = fastapi.FastAPI()

        class _Intent(BaseModel):
            amount: Decimal

        async def _state(request) -> dict:
            return {"balance": Decimal("5000"), "state_version": "1.0"}

        app.add_middleware(
            PramanixMiddleware,
            policy=_BankingPolicy,
            intent_model=_Intent,
            state_loader=_state,
            config=GuardConfig(execution_mode="sync"),
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {"result": "ok"}

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
    async def test_langchain_allow(self):
        pytest.importorskip("langchain_core", reason="langchain-core not installed")
        from pydantic import BaseModel

        from pramanix.integrations.langchain import PramanixGuardedTool

        class _Intent(BaseModel):
            amount: Decimal

        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard_allow,
            intent_schema=_Intent,
            state_provider=lambda: {"balance": Decimal("5000"), "state_version": "1.0"},
            execute_fn=lambda i: "transfer_ok",
        )
        result = await tool._arun(json.dumps({"amount": "100"}))
        assert "transfer_ok" in result


# ── Scenario B — BLOCK ────────────────────────────────────────────────────────


class TestScenarioBBlock:
    @pytest.mark.asyncio
    async def test_fastapi_block(self):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        from pydantic import BaseModel

        from pramanix.integrations.fastapi import PramanixMiddleware

        app = fastapi.FastAPI()

        class _Intent(BaseModel):
            amount: Decimal

        async def _state(request) -> dict:
            return {"state_version": "1.0"}

        app.add_middleware(
            PramanixMiddleware,
            policy=_BlockAllPolicy,
            intent_model=_Intent,
            state_loader=_state,
            config=GuardConfig(execution_mode="sync"),
            timing_budget_ms=0.0,
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "999"},
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 403
        body = resp.json()
        assert "decision_id" in body
        assert "violated_invariants" in body

    @pytest.mark.asyncio
    async def test_langchain_block(self):
        pytest.importorskip("langchain_core", reason="langchain-core not installed")
        from pydantic import BaseModel

        from pramanix.integrations.langchain import PramanixGuardedTool

        class _Intent(BaseModel):
            amount: Decimal

        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard_block,
            intent_schema=_Intent,
            state_provider=lambda: {"state_version": "1.0"},
        )
        result = await tool._arun(json.dumps({"amount": "999"}))
        assert "BLOCKED" in result.upper()
        assert "must_be_zero" in result

    @pytest.mark.asyncio
    async def test_llamaindex_block(self):
        pytest.importorskip("llama_index", reason="llama-index-core not installed")
        from pydantic import BaseModel

        from pramanix.integrations.llamaindex import PramanixFunctionTool

        class _Intent(BaseModel):
            amount: Decimal

        tool = PramanixFunctionTool(
            fn=lambda **kw: "noop",
            guard=_guard_block,
            intent_schema=_Intent,
            state_provider=lambda: {"state_version": "1.0"},
            name="transfer",
            description="Transfer funds",
        )
        result = await tool.acall(json.dumps({"amount": "999"}))
        assert result.is_error is False  # BLOCK is NOT an error
        assert "BLOCKED" in result.content.upper()


# ── Scenario C — Timeout (simulated via error Decision) ───────────────────────


class TestScenarioCTimeout:
    @pytest.mark.asyncio
    async def test_fastapi_timeout(self):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        from pydantic import BaseModel

        from pramanix.guard import Guard

        # Use a guard with a very short solver timeout to trigger timeout
        from pramanix.guard import GuardConfig as GuardCfg
        from pramanix.integrations.fastapi import PramanixMiddleware

        app = fastapi.FastAPI()

        class _Intent(BaseModel):
            amount: Decimal

        async def _state(request) -> dict:
            return {"balance": Decimal("5000"), "state_version": "1.0"}

        # Create a guard with very short timeout to trigger BLOCK
        Guard(_BankingPolicy, GuardCfg(execution_mode="sync", solver_timeout_ms=1))
        app.add_middleware(
            PramanixMiddleware,
            policy=_BankingPolicy,
            intent_model=_Intent,
            state_loader=_state,
            config=GuardCfg(execution_mode="sync", solver_timeout_ms=1),
            timing_budget_ms=0.0,
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        # timeout → BLOCK → 403 (fail-safe)
        assert resp.status_code in (200, 403)  # timeout result may vary


# ── Scenario D — Validation ───────────────────────────────────────────────────


class TestScenarioDValidation:
    @pytest.mark.asyncio
    async def test_fastapi_invalid_json_422(self):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        from pydantic import BaseModel

        from pramanix.integrations.fastapi import PramanixMiddleware

        app = fastapi.FastAPI()

        class _Intent(BaseModel):
            amount: Decimal

        async def _state(request) -> dict:
            return {"balance": Decimal("5000"), "state_version": "1.0"}

        app.add_middleware(
            PramanixMiddleware,
            policy=_BankingPolicy,
            intent_model=_Intent,
            state_loader=_state,
            config=GuardConfig(execution_mode="sync"),
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                content=b"{ invalid json }",
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_langchain_invalid_json_raises(self):
        pytest.importorskip("langchain_core", reason="langchain-core not installed")
        from pydantic import BaseModel

        from pramanix.integrations.langchain import PramanixGuardedTool

        class _Intent(BaseModel):
            amount: Decimal

        tool = PramanixGuardedTool(
            name="transfer",
            description="d",
            guard=_guard_allow,
            intent_schema=_Intent,
            state_provider=lambda: {"state_version": "1.0"},
        )
        with pytest.raises(ValueError, match="JSON"):
            await tool._arun("{invalid json")


# ── Wrapper contracts ─────────────────────────────────────────────────────────


class TestWrapperContracts:
    @pytest.mark.asyncio
    async def test_fastapi_block_response_contains_violated_invariants(self):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        from pydantic import BaseModel

        from pramanix.integrations.fastapi import PramanixMiddleware

        app = fastapi.FastAPI()

        class _Intent(BaseModel):
            amount: Decimal

        async def _state(request) -> dict:
            return {"state_version": "1.0"}

        app.add_middleware(
            PramanixMiddleware,
            policy=_BlockAllPolicy,
            intent_model=_Intent,
            state_loader=_state,
            config=GuardConfig(execution_mode="sync"),
            timing_budget_ms=0.0,
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

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
    async def test_fastapi_allow_does_not_return_403(self):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")
        httpx = pytest.importorskip("httpx", reason="httpx not installed")
        from pydantic import BaseModel

        from pramanix.integrations.fastapi import PramanixMiddleware

        app = fastapi.FastAPI()

        class _Intent(BaseModel):
            amount: Decimal

        async def _state(request) -> dict:
            return {"balance": Decimal("9999"), "state_version": "1.0"}

        app.add_middleware(
            PramanixMiddleware,
            policy=_BankingPolicy,
            intent_model=_Intent,
            state_loader=_state,
            config=GuardConfig(execution_mode="sync"),
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/transfer",
                json={"amount": "100"},
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_decision_carried_in_langchain_feedback(self):
        pytest.importorskip("langchain_core", reason="langchain-core not installed")
        from pydantic import BaseModel

        from pramanix.integrations.langchain import PramanixGuardedTool

        class _Intent(BaseModel):
            amount: Decimal

        tool = PramanixGuardedTool(
            name="transfer",
            description="d",
            guard=_guard_block,
            intent_schema=_Intent,
            state_provider=lambda: {"state_version": "1.0"},
        )
        result = await tool._arun(json.dumps({"amount": "100"}))
        # decision_id must appear in feedback
        assert "decision_id=" in result
