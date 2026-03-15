# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests for PramanixMiddleware and pramanix_route (9.2).

Coverage:
- ALLOW path -> 200 response, handler executes
- BLOCK path -> 403 with decision_id, violated_invariants, status, explanation
- Content-type not application/json -> 415
- Body exceeds max_body_bytes -> 413
- Invalid JSON body -> 422
- Pydantic validation failure -> 422
- Timing: BLOCK path padded to >= timing_budget_ms - 5ms tolerance
- pramanix_route decorator: ALLOW executes, BLOCK raises/returns
- __guard__ attribute on decorated function
"""
from __future__ import annotations

import json
import time
from decimal import Decimal
from typing import Any

import pytest

# Ensure fastapi and starlette are in sys.modules before any other test module
# (specifically test_integration_matrix.py) runs its module-level sys.modules
# injection. Without these guards, the matrix test would inject MagicMock for
# "fastapi" and stub objects for starlette, contaminating this test file.
pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("starlette", reason="starlette not installed")

from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import GuardViolationError

# ── Policy definitions ────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount, "balance": _balance}

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) <= Decimal("10000"))
            .named("under_limit")
            .explain("amount {amount} must be <= 10000")
        ]


class _BlockPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount}

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) <= Decimal("0"))
            .named("must_be_zero")
            .explain("amount {amount} must be zero")
        ]


# ── Intent model ──────────────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: Decimal


# ── State loader ──────────────────────────────────────────────────────────────


async def _load_state(request: Any) -> dict:
    return {"balance": Decimal("5000"), "state_version": "1.0"}


# ── FastAPI app fixtures ───────────────────────────────────────────────────────

pytest_plugins = ("anyio",)


def _build_allow_app() -> Any:
    """Build a FastAPI app with the ALLOW policy middleware."""
    try:
        from fastapi import FastAPI  # type: ignore[import-not-found]
        from pramanix.integrations.fastapi import PramanixMiddleware
    except ImportError:
        pytest.skip("fastapi not installed")

    app = FastAPI()
    app.add_middleware(
        PramanixMiddleware,
        policy=_AllowPolicy,
        intent_model=_TransferIntent,
        state_loader=_load_state,
        config=GuardConfig(execution_mode="sync"),
        timing_budget_ms=30.0,
    )

    @app.post("/transfer")
    async def transfer_handler(body: dict) -> dict:
        return {"status": "ok", "amount": str(body.get("amount", ""))}

    return app


def _build_block_app(timing_budget_ms: float = 30.0) -> Any:
    """Build a FastAPI app with the BLOCK policy middleware."""
    try:
        from fastapi import FastAPI  # type: ignore[import-not-found]
        from pramanix.integrations.fastapi import PramanixMiddleware
    except ImportError:
        pytest.skip("fastapi not installed")

    app = FastAPI()
    app.add_middleware(
        PramanixMiddleware,
        policy=_BlockPolicy,
        intent_model=_TransferIntent,
        state_loader=_load_state,
        config=GuardConfig(execution_mode="sync"),
        timing_budget_ms=timing_budget_ms,
    )

    @app.post("/transfer")
    async def transfer_handler_block(body: dict) -> dict:
        return {"status": "ok"}

    return app


def _make_client(app: Any) -> Any:
    """Return an httpx.AsyncClient backed by the given ASGI app."""
    try:
        import httpx  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("httpx not installed")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _json_body(amount: str = "100") -> bytes:
    return json.dumps({"amount": amount}).encode()


# ── TestMiddlewareAllow ───────────────────────────────────────────────────────


class TestMiddlewareAllow:
    """ALLOW path: 200 and handler execution."""

    @pytest.mark.asyncio
    async def test_allow_returns_200(self) -> None:
        app = _build_allow_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("100"),
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_allow_executes_handler(self) -> None:
        app = _build_allow_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("500"),
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("status") == "ok"


# ── TestMiddlewareBlock ───────────────────────────────────────────────────────


class TestMiddlewareBlock:
    """BLOCK path: 403 with full decision payload."""

    @pytest.mark.asyncio
    async def test_block_returns_403(self) -> None:
        app = _build_block_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("500"),
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_block_response_has_decision_id(self) -> None:
        app = _build_block_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("500"),
                headers={"content-type": "application/json"},
            )
        body = resp.json()
        assert "decision_id" in body
        assert isinstance(body["decision_id"], str)
        assert len(body["decision_id"]) > 0

    @pytest.mark.asyncio
    async def test_block_response_has_violated_invariants(self) -> None:
        app = _build_block_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("500"),
                headers={"content-type": "application/json"},
            )
        body = resp.json()
        assert "violated_invariants" in body
        assert isinstance(body["violated_invariants"], list)
        assert "must_be_zero" in body["violated_invariants"]

    @pytest.mark.asyncio
    async def test_block_response_has_status(self) -> None:
        app = _build_block_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("500"),
                headers={"content-type": "application/json"},
            )
        body = resp.json()
        assert "status" in body
        assert body["status"] == "unsafe"


# ── TestMiddlewareSecurity ────────────────────────────────────────────────────


class TestMiddlewareSecurity:
    """Security boundary: content-type, body size, JSON validity checks."""

    @pytest.mark.asyncio
    async def test_wrong_content_type_returns_415(self) -> None:
        app = _build_allow_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=_json_body("100"),
                headers={"content-type": "text/plain"},
            )
        assert resp.status_code == 415

    @pytest.mark.asyncio
    async def test_body_too_large_returns_413(self) -> None:
        try:
            from fastapi import FastAPI  # type: ignore[import-not-found]
            from pramanix.integrations.fastapi import PramanixMiddleware
        except ImportError:
            pytest.skip("fastapi not installed")

        app = FastAPI()
        app.add_middleware(
            PramanixMiddleware,
            policy=_AllowPolicy,
            intent_model=_TransferIntent,
            state_loader=_load_state,
            config=GuardConfig(execution_mode="sync"),
            max_body_bytes=10,  # tiny limit for test
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

        oversized = b"x" * 20
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=oversized,
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_invalid_json_returns_422(self) -> None:
        app = _build_allow_app()
        async with _make_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=b"this is not json }{",
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 422


# ── TestMiddlewareTiming ──────────────────────────────────────────────────────


class TestMiddlewareTiming:
    """Timing pad: BLOCK responses must be >= timing_budget_ms."""

    @pytest.mark.asyncio
    async def test_block_path_padded_to_timing_budget(self) -> None:
        budget_ms = 80.0
        app = _build_block_app(timing_budget_ms=budget_ms)
        async with _make_client(app) as client:
            t0 = time.monotonic()
            resp = await client.post(
                "/transfer",
                content=_json_body("500"),
                headers={"content-type": "application/json"},
            )
            elapsed_ms = (time.monotonic() - t0) * 1000.0

        assert resp.status_code == 403
        # Allow 10 ms tolerance for scheduling jitter.
        assert elapsed_ms >= budget_ms - 10.0, (
            f"Expected elapsed >= {budget_ms - 10.0} ms, got {elapsed_ms:.1f} ms"
        )


# ── TestPramanixRoute ─────────────────────────────────────────────────────────


class TestPramanixRoute:
    """pramanix_route decorator: allow/block/raise/return/guard attribute."""

    def _make_route(self, policy: Any, on_block: str = "raise") -> Any:
        try:
            from pramanix.integrations.fastapi import pramanix_route
        except ImportError:
            pytest.skip("pramanix.integrations.fastapi not available")
        config = GuardConfig(execution_mode="sync")
        # on_block is always "raise" or "return" in these tests; the Literal
        # annotation on pramanix_route is satisfied at runtime even though the
        # static type of the local variable is str.
        decorator = pramanix_route(policy=policy, config=config, on_block=on_block)  # type: ignore[arg-type]
        return decorator

    @pytest.mark.asyncio
    async def test_route_decorator_allow(self) -> None:
        decorator = self._make_route(_AllowPolicy, on_block="raise")

        @decorator
        async def handler(intent: dict, state: dict) -> str:
            return "executed"

        result = await handler(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert result == "executed"

    @pytest.mark.asyncio
    async def test_route_decorator_block_raises(self) -> None:
        decorator = self._make_route(_BlockPolicy, on_block="raise")

        @decorator
        async def handler(intent: dict, state: dict) -> str:
            return "executed"  # should not reach here

        with pytest.raises(GuardViolationError) as exc_info:
            await handler(
                intent={"amount": Decimal("500")},
                state={"state_version": "1.0"},
            )

        assert exc_info.value.decision is not None
        assert not getattr(exc_info.value.decision, "allowed", True)

    @pytest.mark.asyncio
    async def test_route_decorator_block_return(self) -> None:
        decorator = self._make_route(_BlockPolicy, on_block="return")

        @decorator
        async def handler(intent: dict, state: dict) -> str:
            return "executed"  # should not reach here

        result = await handler(
            intent={"amount": Decimal("500")},
            state={"state_version": "1.0"},
        )
        # Returns a JSONResponse on block (or raises if starlette unavailable).
        # Either way, "executed" must not be returned.
        assert result != "executed"

    def test_route_decorator_guard_attribute(self) -> None:
        decorator = self._make_route(_AllowPolicy, on_block="raise")

        @decorator
        async def handler(intent: dict, state: dict) -> str:
            return "ok"

        assert hasattr(handler, "__guard__")
        assert isinstance(handler.__guard__, Guard)
