# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Dark-path coverage for pramanix.integrations modules.

Targets uncovered lines in fastapi.py, langchain.py, llamaindex.py,
autogen.py, and integrations/__init__.py after Phase 9 implementation.
"""
from __future__ import annotations

import json
import types
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

# ── Skip entire module if required frameworks not installed ───────────────────
pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("starlette", reason="starlette not installed")
pytest.importorskip("langchain_core", reason="langchain-core not installed")

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.autogen import PramanixToolCallback, _get_state_inner
from pramanix.integrations.langchain import PramanixGuardedTool
from pramanix.integrations.llamaindex import (
    PramanixFunctionTool,
    PramanixQueryEngineTool,
)

# ── Shared policy definitions ─────────────────────────────────────────────────

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
        return [(E(_amount) <= Decimal("0")).named("must_be_zero").explain("amount must be zero")]


class _IntentModel(BaseModel):
    amount: Decimal


def _guard_allow() -> Guard:
    return Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))


def _guard_block() -> Guard:
    return Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))


# ── TestIntegrationsInit ───────────────────────────────────────────────────────


class TestIntegrationsInit:
    """pramanix.integrations.__getattr__ lazy routing — all 4 branches + error."""

    def test_getattr_fastapi_middleware(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.fastapi import PramanixMiddleware

        obj = integrations.__getattr__("PramanixMiddleware")
        assert obj is PramanixMiddleware

    def test_getattr_pramanix_route(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.fastapi import pramanix_route

        obj = integrations.__getattr__("pramanix_route")
        assert obj is pramanix_route

    def test_getattr_langchain_guarded_tool(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.langchain import PramanixGuardedTool as _Cls

        obj = integrations.__getattr__("PramanixGuardedTool")
        assert obj is _Cls

    def test_getattr_wrap_tools(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.langchain import wrap_tools

        obj = integrations.__getattr__("wrap_tools")
        assert obj is wrap_tools

    def test_getattr_llama_function_tool(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.llamaindex import PramanixFunctionTool as _Cls

        obj = integrations.__getattr__("PramanixFunctionTool")
        assert obj is _Cls

    def test_getattr_llama_query_engine_tool(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.llamaindex import PramanixQueryEngineTool as _Cls

        obj = integrations.__getattr__("PramanixQueryEngineTool")
        assert obj is _Cls

    def test_getattr_autogen_callback(self) -> None:
        from pramanix import integrations
        from pramanix.integrations.autogen import PramanixToolCallback as _Cls

        obj = integrations.__getattr__("PramanixToolCallback")
        assert obj is _Cls

    def test_getattr_unknown_name_raises_attribute_error(self) -> None:
        from pramanix import integrations

        with pytest.raises(AttributeError, match="no attribute"):
            integrations.__getattr__("NoSuchIntegration")


# ── TestFastapiDarkPaths ───────────────────────────────────────────────────────


def _make_httpx_client(app: Any) -> Any:
    try:
        import httpx
    except ImportError:
        pytest.skip("httpx not installed")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


class TestFastapiDarkPaths:
    """Covers intent validation failure (422) and state loader error (500)."""

    @pytest.mark.asyncio
    async def test_intent_validation_failure_returns_422(self) -> None:
        """Line 151-152: except Exception returns 422 when Pydantic rejects body."""
        from fastapi import FastAPI

        from pramanix.integrations.fastapi import PramanixMiddleware

        async def _state_loader(request: Any) -> dict:
            return {"balance": Decimal("5000"), "state_version": "1.0"}

        app = FastAPI()
        app.add_middleware(
            PramanixMiddleware,
            policy=_AllowPolicy,
            intent_model=_IntentModel,
            state_loader=_state_loader,
            config=GuardConfig(execution_mode="sync"),
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

        # Valid JSON but missing required `amount` field → Pydantic ValidationError
        async with _make_httpx_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=json.dumps({"wrong_field": "not-amount"}).encode(),
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_state_loader_exception_returns_500(self) -> None:
        """Lines 160-161: except Exception returns 500 when state_loader raises."""
        from fastapi import FastAPI

        from pramanix.integrations.fastapi import PramanixMiddleware

        async def _failing_loader(request: Any) -> dict:
            raise RuntimeError("DB unavailable")

        app = FastAPI()
        app.add_middleware(
            PramanixMiddleware,
            policy=_AllowPolicy,
            intent_model=_IntentModel,
            state_loader=_failing_loader,
            config=GuardConfig(execution_mode="sync"),
        )

        @app.post("/transfer")
        async def _handler(body: dict) -> dict:
            return {}

        async with _make_httpx_client(app) as client:
            resp = await client.post(
                "/transfer",
                content=json.dumps({"amount": "100"}).encode(),
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 500
        assert "State loader error" in resp.json()["detail"]


# ── TestLangchainDarkPaths ────────────────────────────────────────────────────


class TestLangchainDarkPaths:
    """Covers async execute_fn, async state_provider, _run thread-pool path."""

    @pytest.mark.asyncio
    async def test_async_execute_fn_is_awaited(self) -> None:
        """Line 168: coroutine execute_fn is awaited on ALLOW path."""

        async def _async_exec(intent: dict) -> str:
            return "async-exec-result"

        tool = PramanixGuardedTool(
            name="test",
            description="test",
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
            execute_fn=_async_exec,
        )
        result = await tool._arun('{"amount": "100"}')
        assert result == "async-exec-result"

    @pytest.mark.asyncio
    async def test_async_state_provider_is_awaited(self) -> None:
        """Line 178: coroutine from state_provider is awaited."""

        async def _async_state() -> dict:
            return {"state_version": "1.0"}

        tool = PramanixGuardedTool(
            name="test",
            description="test",
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=_async_state,
        )
        result = await tool._arun('{"amount": "100"}')
        assert result == "OK"

    def test_run_sync_no_loop(self) -> None:
        """Lines 196-200: _run uses asyncio.run() when no event loop is active."""
        tool = PramanixGuardedTool(
            name="test",
            description="test",
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )
        # Synchronous context — no running event loop
        result = tool._run('{"amount": "100"}')
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_run_thread_pool_when_loop_already_running(self) -> None:
        """Lines 203-207: _run offloads to thread pool when loop is active."""
        tool = PramanixGuardedTool(
            name="test",
            description="test",
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )
        # We are inside an async test — event loop IS running — hits thread path
        result = tool._run('{"amount": "100"}')
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_schema_validation_failure_raises_value_error(self) -> None:
        """Lines 156-157: Pydantic model_validate failure raises ValueError."""
        tool = PramanixGuardedTool(
            name="test",
            description="test",
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )
        # Valid JSON but missing required `amount` field → Pydantic ValidationError
        with pytest.raises(ValueError, match="Pramanix"):
            await tool._arun('{"wrong_field": "not-amount"}')


# ── TestLlamaindexFunctionTool ────────────────────────────────────────────────


class TestLlamaindexFunctionTool:
    """Covers PramanixFunctionTool: all paths including call(), from_function_tool."""

    def _tool(self, guard: Guard | None = None, fn: Any = None) -> PramanixFunctionTool:
        return PramanixFunctionTool(
            fn=fn or (lambda **kw: f"transferred {kw.get('amount')}"),
            guard=guard or _guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
            name="transfer",
            description="Transfer funds",
        )

    def test_metadata_property(self) -> None:
        meta = self._tool().metadata
        assert meta.name == "transfer"
        assert meta.description == "Transfer funds"

    @pytest.mark.asyncio
    async def test_acall_allow_executes_fn(self) -> None:
        output = await self._tool().acall(json.dumps({"amount": "100"}))
        assert output.is_error is False
        assert "100" in output.content

    @pytest.mark.asyncio
    async def test_acall_block_returns_feedback(self) -> None:
        output = await self._tool(guard=_guard_block()).acall(json.dumps({"amount": "500"}))
        assert output.is_error is False
        assert len(output.content) > 0

    @pytest.mark.asyncio
    async def test_acall_invalid_json_returns_error_output(self) -> None:
        output = await self._tool().acall("not json {")
        assert output.is_error is True
        assert "invalid input" in output.content

    @pytest.mark.asyncio
    async def test_acall_schema_failure_returns_error_output(self) -> None:
        """Lines 148-155: Pydantic validation error → is_error=True ToolOutput."""
        output = await self._tool().acall(json.dumps({"wrong_field": "abc"}))
        assert output.is_error is True

    @pytest.mark.asyncio
    async def test_acall_async_fn_is_awaited(self) -> None:
        """Line 167: coroutine fn result is awaited on ALLOW path."""

        async def _async_fn(**kw: Any) -> str:
            return "async-fn-result"

        output = await self._tool(fn=_async_fn).acall(json.dumps({"amount": "100"}))
        assert "async-fn-result" in output.content

    @pytest.mark.asyncio
    async def test_acall_async_state_provider_is_awaited(self) -> None:
        """LlamaIndex: async state_provider coroutine is awaited."""

        async def _async_state() -> dict:
            return {"state_version": "1.0"}

        tool = PramanixFunctionTool(
            fn=lambda **kw: "ok",
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=_async_state,
            name="test",
        )
        output = await tool.acall(json.dumps({"amount": "100"}))
        assert output.is_error is False

    def test_call_sync_no_loop(self) -> None:
        """call() sync wrapper uses asyncio.run() when no event loop is active."""
        output = self._tool().call(json.dumps({"amount": "100"}))
        assert output.is_error is False

    @pytest.mark.asyncio
    async def test_call_thread_pool_when_loop_running(self) -> None:
        """call() offloads to thread pool when event loop is already running."""
        output = self._tool().call(json.dumps({"amount": "100"}))
        assert output.is_error is False

    def test_from_function_tool_with_metadata(self) -> None:
        """from_function_tool() extracts fn/name/description from existing tool."""
        meta = types.SimpleNamespace(name="my_tool", description="My desc")
        existing = types.SimpleNamespace(
            metadata=meta,
            fn=lambda **kw: "result",
        )
        wrapped = PramanixFunctionTool.from_function_tool(
            existing,
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )
        assert wrapped._name == "my_tool"
        assert wrapped._description == "My desc"

    def test_from_function_tool_no_metadata(self) -> None:
        """from_function_tool() falls back to tool.name/description when no metadata."""
        existing = types.SimpleNamespace(
            name="bare_tool",
            description="bare desc",
        )
        existing.fn = lambda **kw: "ok"
        wrapped = PramanixFunctionTool.from_function_tool(
            existing,
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )
        assert wrapped._name == "bare_tool"


# ── TestLlamaindexQueryEngineTool ─────────────────────────────────────────────


class TestLlamaindexQueryEngineTool:
    """Covers PramanixQueryEngineTool: aquery, query, neither, block, errors."""

    def _tool(self, engine: Any, guard: Guard | None = None) -> PramanixQueryEngineTool:
        return PramanixQueryEngineTool(
            query_engine=engine,
            guard=guard or _guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
            name="rag",
            description="RAG engine",
        )

    def test_metadata_property(self) -> None:
        tool = self._tool("engine")
        assert tool.metadata.name == "rag"

    @pytest.mark.asyncio
    async def test_acall_allow_async_aquery(self) -> None:
        """Lines 394-397: engine.aquery returns coroutine → awaited."""

        class _AsyncEngine:
            async def aquery(self, q: str) -> str:
                return "async-query-result"

        output = await self._tool(_AsyncEngine()).acall(json.dumps({"amount": "100"}))
        assert output.is_error is False
        assert "async-query-result" in output.content

    @pytest.mark.asyncio
    async def test_acall_allow_sync_query(self) -> None:
        """Lines 398-401: engine.query (sync, no aquery) → result not awaited."""

        class _SyncEngine:
            def query(self, q: str) -> str:
                return "sync-query-result"

        output = await self._tool(_SyncEngine()).acall(json.dumps({"amount": "100"}))
        assert output.is_error is False
        assert "sync-query-result" in output.content

    @pytest.mark.asyncio
    async def test_acall_allow_neither_method(self) -> None:
        """Line 402-403: engine has neither aquery nor query → str(engine) used."""
        output = await self._tool("plain-string-engine").acall(json.dumps({"amount": "100"}))
        assert output.is_error is False
        assert "plain-string-engine" in output.content

    @pytest.mark.asyncio
    async def test_acall_block_returns_feedback(self) -> None:
        output = await self._tool("x", guard=_guard_block()).acall(json.dumps({"amount": "500"}))
        assert output.is_error is False
        assert len(output.content) > 0

    @pytest.mark.asyncio
    async def test_acall_invalid_json_returns_error(self) -> None:
        output = await self._tool("x").acall("bad {json")
        assert output.is_error is True

    @pytest.mark.asyncio
    async def test_acall_invalid_schema_returns_error(self) -> None:
        output = await self._tool("x").acall(json.dumps({"wrong_field": "abc"}))
        assert output.is_error is True

    def test_call_sync_no_loop(self) -> None:
        output = self._tool("x").call(json.dumps({"amount": "100"}))
        assert output.is_error is False

    @pytest.mark.asyncio
    async def test_call_thread_pool_when_loop_running(self) -> None:
        output = self._tool("x").call(json.dumps({"amount": "100"}))
        assert output.is_error is False


# ── TestAutogenDarkPaths ──────────────────────────────────────────────────────


class TestAutogenDarkPaths:
    """Covers _get_state() instance method and async coroutine state_provider."""

    @pytest.mark.asyncio
    async def test_get_state_instance_method(self) -> None:
        """Line 183: PramanixToolCallback._get_state() delegates to inner helper."""

        async def _async_state() -> dict:
            return {"state_version": "1.0"}

        callback = PramanixToolCallback(
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=_async_state,
        )
        state = await callback._get_state()
        assert state == {"state_version": "1.0"}

    @pytest.mark.asyncio
    async def test_get_state_inner_with_coroutine(self) -> None:
        """Line 233: _get_state_inner awaits when provider returns a coroutine."""

        async def _coro_provider() -> dict:
            return {"state_version": "2.0"}

        result = await _get_state_inner(_coro_provider)
        assert result == {"state_version": "2.0"}

    @pytest.mark.asyncio
    async def test_async_state_provider_in_guarded_fn(self) -> None:
        """Async state_provider is awaited inside _guarded closure."""

        async def _async_state() -> dict:
            return {"state_version": "1.0"}

        callback = PramanixToolCallback(
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=_async_state,
        )

        @callback
        async def _fn(amount: Decimal) -> str:
            return f"ok-{amount}"

        result = await _fn(amount=Decimal("100"))
        assert "100" in result

    @pytest.mark.asyncio
    async def test_fn_execution_error_propagates(self) -> None:
        """Lines 160-168: genuine fn exception re-raised (not silently returned)."""
        callback = PramanixToolCallback(
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )

        @callback
        async def _fn(amount: Decimal) -> str:
            raise ValueError("db exploded")

        with pytest.raises(ValueError, match="db exploded"):
            await _fn(amount=Decimal("100"))

    @pytest.mark.asyncio
    async def test_async_fn_result_awaited(self) -> None:
        """Lines 162-163: coroutine fn result is awaited on ALLOW path."""
        callback = PramanixToolCallback(
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )

        @callback
        async def _fn(amount: Decimal) -> str:
            return "async-ok"

        result = await _fn(amount=Decimal("100"))
        assert result == "async-ok"

    def test_wrap_classmethod(self) -> None:
        """PramanixToolCallback.wrap() convenience factory."""

        async def _fn(amount: Decimal) -> str:
            return "ok"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard_allow(),
            intent_schema=_IntentModel,
            state_provider=lambda: {"state_version": "1.0"},
        )
        assert callable(guarded)
        assert guarded.__name__ == "_fn"
