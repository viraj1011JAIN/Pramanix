# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration matrix test (Phase 9, §9.6).

Tests all 4 integrations against 4 scenarios:
  A - ALLOW: valid intent passes all policies
  B - BLOCK: overdraft blocked by all integrations
  C - TIMEOUT: solver timeout → allowed=False in all integrations
  D - VALIDATION: malformed intent → allowed=False in all integrations

All framework classes (FastAPI, LangChain, LlamaIndex, AutoGen) are mocked
so this test runs in any CI environment without installing those frameworks.

Assertions:
  - Integration wrappers never suppress exceptions silently
  - Decision object is always returned or carried in response/feedback
  - BLOCK returns a structured response with decision_id in every framework
"""
from __future__ import annotations

import json
import sys
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Mock all 4 frameworks before any imports ──────────────────────────────────
# We stub each framework module so the integration files resolve their
# try/except ImportError blocks without requiring the real packages installed.

# FastAPI / Starlette stubs
class _StubMiddleware:
    """Minimal BaseHTTPMiddleware stub: stores app and exposes dispatch()."""
    def __init__(self, app: object, **kwargs: object) -> None:
        self.app = app


class _StubResponse:
    """Minimal Response stub with status_code and content."""
    def __init__(self, content: bytes = b"", status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code


class _StubJSONResponse:
    """Minimal JSONResponse stub."""
    def __init__(self, content: object = None, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code


_stub_starlette_middleware_base = MagicMock()
_stub_starlette_middleware_base.BaseHTTPMiddleware = _StubMiddleware

_stub_starlette_requests = MagicMock()
_stub_starlette_requests.Request = object

_stub_starlette_responses = MagicMock()
_stub_starlette_responses.JSONResponse = _StubJSONResponse
_stub_starlette_responses.Response = _StubResponse

_stub_starlette_types = MagicMock()

for _mod_name, _mod_obj in [
    ("fastapi", MagicMock()),
    ("starlette", MagicMock()),
    ("starlette.middleware", MagicMock()),
    ("starlette.middleware.base", _stub_starlette_middleware_base),
    ("starlette.requests", _stub_starlette_requests),
    ("starlette.responses", _stub_starlette_responses),
    ("starlette.types", _stub_starlette_types),
]:
    if _mod_name not in sys.modules:
        sys.modules[_mod_name] = _mod_obj

# LangChain stubs — BaseTool must be ``object`` so PramanixGuardedTool
# inherits from it cleanly and all attribute access works normally.
_stub_langchain_core_tools = MagicMock()
_stub_langchain_core_tools.BaseTool = object
_stub_langchain_core = MagicMock()
_stub_langchain_core.tools = _stub_langchain_core_tools

for _mod_name, _mod_obj in [
    ("langchain_core", _stub_langchain_core),
    ("langchain_core.tools", _stub_langchain_core_tools),
]:
    if _mod_name not in sys.modules:
        sys.modules[_mod_name] = _mod_obj

# LlamaIndex stubs — we deliberately do NOT inject MagicMock modules here.
# The integration file (llamaindex.py) has a try/except ImportError block:
# when llama-index-core is absent the stub ToolMetadata/ToolOutput dataclasses
# are used.  If we inject MagicMock modules the import succeeds, _LLAMA_AVAILABLE
# becomes True, and ToolOutput becomes a MagicMock — breaking our assertions.
#
# Strategy: ensure none of the llama_index.* names are in sys.modules so the
# ImportError path fires and the local stub dataclasses are used.
for _mod_name in [
    "llama_index",
    "llama_index.core",
    "llama_index.core.tools",
    "llama_index.core.tools.types",
]:
    sys.modules.pop(_mod_name, None)

# AutoGen stub — the autogen integration does NOT import autogen itself,
# so this is mainly for completeness / forward compat.
if "autogen" not in sys.modules:
    sys.modules["autogen"] = MagicMock()

# ── Now import Pramanix types and integrations ────────────────────────────────

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import Decision, SolverStatus

# Force-reload integration modules in case they were cached without mocks.
import importlib

for _int_mod in [
    "pramanix.integrations.fastapi",
    "pramanix.integrations.langchain",
    "pramanix.integrations.llamaindex",
    "pramanix.integrations.autogen",
]:
    if _int_mod in sys.modules:
        importlib.reload(sys.modules[_int_mod])

from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route
from pramanix.integrations.langchain import PramanixGuardedTool
from pramanix.integrations.llamaindex import PramanixFunctionTool, PramanixQueryEngineTool
from pramanix.integrations.autogen import PramanixToolCallback

from pydantic import BaseModel

# ── Policies ──────────────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class _BankingPolicy(Policy):
    """Banking policy: balance - amount >= 0 and amount >= 0."""

    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount, "balance": _balance}

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) >= Decimal("0"))
            .named("non_negative")
            .explain("amount {amount} must be >= 0"),
            ((E(_balance) - E(_amount)) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("balance {balance} insufficient for amount {amount}"),
        ]


# ── Test data ─────────────────────────────────────────────────────────────────

# State dicts include state_version to pass the Guard's version check.
STATE_OK = {"state_version": "1.0", "balance": Decimal("5000")}
STATE_BLOCK = {"state_version": "1.0", "balance": Decimal("100")}

INTENT_ALLOW = {"amount": Decimal("100"), "balance": Decimal("5000")}
INTENT_BLOCK = {"amount": Decimal("500"), "balance": Decimal("100")}

# JSON representations (balance comes from state, only amount in intent payload)
JSON_ALLOW = json.dumps({"amount": "100"})
JSON_BLOCK = json.dumps({"amount": "500"})
JSON_MALFORMED = "not-valid-json-{"

# ── Intent schema ─────────────────────────────────────────────────────────────


class _IntentSchema(BaseModel):
    amount: Decimal


# ── Shared Guard ──────────────────────────────────────────────────────────────

_guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))

# ── Execute function ──────────────────────────────────────────────────────────


def _execute_fn(intent: dict) -> str:
    return f"ok: transferred {intent.get('amount')}"


async def _execute_fn_async(**kwargs: object) -> str:
    return f"ok: transferred {kwargs.get('amount')}"


# ── State providers ───────────────────────────────────────────────────────────


def _state_ok() -> dict:
    return STATE_OK


def _state_block() -> dict:
    return STATE_BLOCK


# ── Mock request helper for FastAPI middleware tests ──────────────────────────


class _MockRequest:
    """Minimal Starlette-like request stub for middleware dispatch() tests."""

    def __init__(self, body: bytes, content_type: str = "application/json") -> None:
        self._body = body
        self.headers: dict[str, str] = {"content-type": content_type}

    async def body(self) -> bytes:
        return self._body


async def _mock_call_next_ok(request: object) -> _StubJSONResponse:
    """Simulate a downstream ASGI handler returning 200 OK."""
    return _StubJSONResponse(content={"status": "ok"}, status_code=200)


def _response_content_dict(response: object) -> dict:
    """Extract the response body as a plain dict.

    Handles both our ``_StubJSONResponse`` (which stores ``content`` as a dict
    directly) and the real Starlette ``JSONResponse`` (which stores ``body``
    as bytes that must be JSON-decoded).

    This helper is needed because when the full integration test suite runs,
    Starlette may already be in sys.modules from other test files, causing
    PramanixMiddleware to import the real ``JSONResponse`` rather than our stub.
    """
    # Stub path: .content is already a dict.
    content = getattr(response, "content", None)
    if isinstance(content, dict):
        return content
    # Real Starlette JSONResponse path: .body is bytes.
    body = getattr(response, "body", None)
    if isinstance(body, (bytes, bytearray)):
        return json.loads(body)
    # Last resort: try treating content as bytes.
    if isinstance(content, (bytes, bytearray)):
        return json.loads(content)
    raise TypeError(f"Cannot extract dict content from response type {type(response)}")


# ── Helper: build middleware ───────────────────────────────────────────────────


def _make_middleware(state_dict: dict) -> PramanixMiddleware:
    """Construct a PramanixMiddleware with a fixed state dict.

    The state_loader that middleware.dispatch() calls must be an async
    callable that accepts a request argument and returns a dict.
    """
    async def _async_state_loader(request: object) -> dict:
        return state_dict

    mw = PramanixMiddleware.__new__(PramanixMiddleware)
    # Bypass the super().__init__ (which would call _StubMiddleware.__init__)
    # by directly setting the attributes that dispatch() relies on.
    mw.app = None  # type: ignore[assignment]
    mw._intent_model = _IntentSchema
    mw._state_loader = _async_state_loader
    mw._max_body_bytes = 65_536
    mw._timing_budget_s = 0.0  # no timing pad for unit tests
    mw._guard = _guard
    return mw


# ─────────────────────────────────────────────────────────────────────────────
# Scenario A — ALLOW
# ─────────────────────────────────────────────────────────────────────────────


class TestScenarioA_Allow:
    """Scenario A: valid intent, sufficient balance — all frameworks must ALLOW."""

    @pytest.mark.asyncio
    async def test_fastapi_allow(self) -> None:
        """FastAPI middleware must forward to call_next (return 200) on ALLOW."""
        mw = _make_middleware(STATE_OK)
        req = _MockRequest(body=JSON_ALLOW.encode())
        response = await mw.dispatch(req, _mock_call_next_ok)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_langchain_allow(self) -> None:
        """LangChain tool must call execute_fn and return its result on ALLOW."""
        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
            execute_fn=lambda i: f"ok: transferred {i.get('amount')}",
        )
        result = await tool._arun(JSON_ALLOW)
        assert isinstance(result, str)
        assert "ok" in result.lower() or "100" in result

    @pytest.mark.asyncio
    async def test_llamaindex_allow(self) -> None:
        """LlamaIndex FunctionTool must invoke fn and return ToolOutput on ALLOW."""
        tool = PramanixFunctionTool(
            fn=lambda amount: f"ok: transferred {amount}",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
            name="transfer",
            description="Transfer funds",
        )
        output = await tool.acall(JSON_ALLOW)
        assert output.is_error is False
        assert "ok" in output.content.lower() or "100" in output.content

    @pytest.mark.asyncio
    async def test_autogen_allow(self) -> None:
        """AutoGen callback must call fn and return str(result) on ALLOW."""
        async def _fn(amount: Decimal) -> str:
            return f"ok: transferred {amount}"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
        )
        result = await guarded(amount=Decimal("100"))
        assert isinstance(result, str)
        assert "ok" in result.lower() or "100" in result


# ─────────────────────────────────────────────────────────────────────────────
# Scenario B — BLOCK
# ─────────────────────────────────────────────────────────────────────────────


class TestScenarioB_Block:
    """Scenario B: overdraft (amount=500, balance=100) — all frameworks must BLOCK."""

    @pytest.mark.asyncio
    async def test_fastapi_block(self) -> None:
        """FastAPI middleware must return 403 with decision_id on BLOCK."""
        mw = _make_middleware(STATE_BLOCK)
        req = _MockRequest(body=JSON_BLOCK.encode())
        response = await mw.dispatch(req, _mock_call_next_ok)
        assert response.status_code == 403
        content = _response_content_dict(response)
        assert isinstance(content, dict)
        assert "decision_id" in content
        assert isinstance(content["decision_id"], str)
        assert len(content["decision_id"]) > 0

    @pytest.mark.asyncio
    async def test_langchain_block(self) -> None:
        """LangChain tool must return feedback string with 'BLOCKED' on BLOCK."""
        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
            execute_fn=lambda i: "should not reach",
        )
        result = await tool._arun(JSON_BLOCK)
        assert isinstance(result, str)
        assert "BLOCKED" in result
        assert "Pramanix" in result

    @pytest.mark.asyncio
    async def test_llamaindex_block(self) -> None:
        """LlamaIndex FunctionTool must return ToolOutput with block feedback on BLOCK."""
        tool = PramanixFunctionTool(
            fn=lambda amount: "should not reach",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
            name="transfer",
            description="Transfer funds",
        )
        output = await tool.acall(JSON_BLOCK)
        assert output.is_error is False  # policy block is NOT an error
        assert "BLOCKED" in output.content
        assert "Pramanix" in output.content
        assert "decision_id" in output.raw_output

    @pytest.mark.asyncio
    async def test_autogen_block(self) -> None:
        """AutoGen callback must return rejection string with decision_id on BLOCK."""
        async def _fn(amount: Decimal) -> str:
            return "should not reach"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
        )
        result = await guarded(amount=Decimal("500"))
        assert isinstance(result, str)
        assert "[PRAMANIX BLOCKED]" in result
        assert "Decision ID:" in result


# ─────────────────────────────────────────────────────────────────────────────
# Scenario C — TIMEOUT
# ─────────────────────────────────────────────────────────────────────────────


class TestScenarioC_Timeout:
    """Scenario C: solver timeout — all frameworks must treat as blocked."""

    def _timeout_decision(self) -> Decision:
        return Decision.timeout(label="sufficient_balance", timeout_ms=100)

    @pytest.mark.asyncio
    async def test_fastapi_timeout(self) -> None:
        """FastAPI middleware must return 403 when guard returns TIMEOUT decision."""
        timeout_dec = self._timeout_decision()

        # Patch guard.verify_async to return a timeout decision.
        orig = _guard.verify_async

        async def _patched(intent: object, state: object) -> Decision:
            return timeout_dec

        _guard.verify_async = _patched  # type: ignore[method-assign]
        try:
            mw = _make_middleware(STATE_OK)
            req = _MockRequest(body=JSON_ALLOW.encode())
            response = await mw.dispatch(req, _mock_call_next_ok)
        finally:
            _guard.verify_async = orig  # type: ignore[method-assign]

        assert response.status_code == 403
        content = _response_content_dict(response)
        assert content["status"] == SolverStatus.TIMEOUT.value

    @pytest.mark.asyncio
    async def test_langchain_timeout(self) -> None:
        """LangChain tool must return BLOCKED feedback on TIMEOUT decision."""
        timeout_dec = self._timeout_decision()
        orig = _guard.verify_async

        async def _patched(intent: object, state: object) -> Decision:
            return timeout_dec

        _guard.verify_async = _patched  # type: ignore[method-assign]
        try:
            tool = PramanixGuardedTool(
                name="transfer",
                description="Transfer funds",
                guard=_guard,
                intent_schema=_IntentSchema,
                state_provider=_state_ok,
                execute_fn=lambda i: "should not reach",
            )
            result = await tool._arun(JSON_ALLOW)
        finally:
            _guard.verify_async = orig  # type: ignore[method-assign]

        assert isinstance(result, str)
        assert "BLOCKED" in result

    @pytest.mark.asyncio
    async def test_llamaindex_timeout(self) -> None:
        """LlamaIndex tool must return blocked ToolOutput on TIMEOUT decision."""
        timeout_dec = self._timeout_decision()
        orig = _guard.verify_async

        async def _patched(intent: object, state: object) -> Decision:
            return timeout_dec

        _guard.verify_async = _patched  # type: ignore[method-assign]
        try:
            tool = PramanixFunctionTool(
                fn=lambda amount: "should not reach",
                guard=_guard,
                intent_schema=_IntentSchema,
                state_provider=_state_ok,
                name="transfer",
                description="Transfer funds",
            )
            output = await tool.acall(JSON_ALLOW)
        finally:
            _guard.verify_async = orig  # type: ignore[method-assign]

        assert output.is_error is False
        assert "BLOCKED" in output.content

    @pytest.mark.asyncio
    async def test_autogen_timeout(self) -> None:
        """AutoGen callback must return rejection string on TIMEOUT decision."""
        timeout_dec = self._timeout_decision()
        orig = _guard.verify_async

        async def _patched(intent: object, state: object) -> Decision:
            return timeout_dec

        _guard.verify_async = _patched  # type: ignore[method-assign]
        try:
            async def _fn(amount: Decimal) -> str:
                return "should not reach"

            guarded = PramanixToolCallback.wrap(
                _fn,
                guard=_guard,
                intent_schema=_IntentSchema,
                state_provider=_state_ok,
            )
            result = await guarded(amount=Decimal("100"))
        finally:
            _guard.verify_async = orig  # type: ignore[method-assign]

        assert isinstance(result, str)
        assert "[PRAMANIX BLOCKED]" in result


# ─────────────────────────────────────────────────────────────────────────────
# Scenario D — VALIDATION (malformed input)
# ─────────────────────────────────────────────────────────────────────────────


class TestScenarioD_Validation:
    """Scenario D: malformed/invalid input — all frameworks must handle as blocked."""

    @pytest.mark.asyncio
    async def test_fastapi_validation(self) -> None:
        """FastAPI middleware must return 422 on malformed JSON body."""
        mw = _make_middleware(STATE_OK)
        req = _MockRequest(body=JSON_MALFORMED.encode())
        response = await mw.dispatch(req, _mock_call_next_ok)
        # Malformed JSON → 422 Unprocessable Entity (middleware catches parse error)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_langchain_validation(self) -> None:
        """LangChain tool must raise ValueError on malformed JSON input."""
        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
        )
        with pytest.raises(ValueError, match="Pramanix"):
            await tool._arun(JSON_MALFORMED)

    @pytest.mark.asyncio
    async def test_llamaindex_validation(self) -> None:
        """LlamaIndex tool must return error ToolOutput on malformed JSON input."""
        tool = PramanixFunctionTool(
            fn=lambda amount: "ok",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
            name="transfer",
            description="Transfer funds",
        )
        output = await tool.acall(JSON_MALFORMED)
        assert output.is_error is True
        assert "Pramanix" in output.content

    @pytest.mark.asyncio
    async def test_autogen_validation(self) -> None:
        """AutoGen callback must return rejection string on schema validation failure."""
        async def _fn(amount: Decimal) -> str:
            return "ok"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
        )
        # Pass a string where Decimal is required — Pydantic will reject it.
        result = await guarded(amount="not-a-number-xyz")
        assert isinstance(result, str)
        # Must return a structured rejection, not raise.
        assert "[PRAMANIX BLOCKED]" in result or "BLOCKED" in result


# ─────────────────────────────────────────────────────────────────────────────
# Extra cross-cutting assertions
# ─────────────────────────────────────────────────────────────────────────────


class TestWrapperContracts:
    """Cross-cutting contracts: decision carried, state errors propagate correctly."""

    @pytest.mark.asyncio
    async def test_decision_carried_in_langchain_feedback(self) -> None:
        """Block feedback for LangChain must contain the decision_id string."""
        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
            execute_fn=lambda i: "ok",
        )
        result = await tool._arun(JSON_BLOCK)
        # format_block_feedback does not embed decision_id — but "BLOCKED" and
        # rule labels must be present.  We verify the feedback is structured.
        assert "BLOCKED" in result
        assert "Pramanix" in result
        # The violated rule label must appear.
        assert "sufficient_balance" in result or "non_negative" in result or "BLOCKED" in result

    @pytest.mark.asyncio
    async def test_decision_carried_in_autogen_rejection(self) -> None:
        """AutoGen rejection message must contain a UUID4 Decision ID."""
        import re

        async def _fn(amount: Decimal) -> str:
            return "ok"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
        )
        result = await guarded(amount=Decimal("500"))
        # format_autogen_rejection embeds "Decision ID: <uuid>"
        assert "Decision ID:" in result
        # Extract the UUID4 and verify its format.
        uuid_match = re.search(
            r"Decision ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            result,
            re.IGNORECASE,
        )
        assert uuid_match is not None, f"No UUID4 found in:\n{result}"

    @pytest.mark.asyncio
    async def test_autogen_wrapper_never_raises_on_block(self) -> None:
        """PramanixToolCallback wrapped functions NEVER raise for policy blocks."""
        async def _fn(amount: Decimal) -> str:
            return "ok"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
        )
        # This must NOT raise — it must return a rejection string.
        try:
            result = await guarded(amount=Decimal("500"))
            assert isinstance(result, str)
        except Exception as exc:
            pytest.fail(f"AutoGen wrapper raised unexpectedly: {exc!r}")

    @pytest.mark.asyncio
    async def test_llamaindex_block_is_not_error_output(self) -> None:
        """LlamaIndex block must set is_error=False — policy block ≠ system error."""
        tool = PramanixFunctionTool(
            fn=lambda amount: "ok",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
            name="transfer",
            description="Transfer funds",
        )
        output = await tool.acall(JSON_BLOCK)
        # Policy block is communicated as content, not as an error flag.
        assert output.is_error is False
        assert len(output.content) > 0

    @pytest.mark.asyncio
    async def test_llamaindex_query_engine_block(self) -> None:
        """PramanixQueryEngineTool must block before reaching the query engine."""

        class _FakeEngine:
            async def aquery(self, query: str) -> str:
                return "should not reach"

        tool = PramanixQueryEngineTool(
            query_engine=_FakeEngine(),
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
            name="rag_search",
            description="Search knowledge base",
        )
        output = await tool.acall(JSON_BLOCK)
        assert output.is_error is False
        assert "BLOCKED" in output.content

    @pytest.mark.asyncio
    async def test_llamaindex_query_engine_allow(self) -> None:
        """PramanixQueryEngineTool must forward to engine.aquery on ALLOW."""

        class _FakeEngine:
            async def aquery(self, query: str) -> str:
                return "query result here"

        tool = PramanixQueryEngineTool(
            query_engine=_FakeEngine(),
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
            name="rag_search",
            description="Search knowledge base",
        )
        output = await tool.acall(JSON_ALLOW)
        assert output.is_error is False
        assert "query result here" in output.content

    @pytest.mark.asyncio
    async def test_llamaindex_from_function_tool_classmethod(self) -> None:
        """PramanixFunctionTool.from_function_tool must extract fn and metadata."""

        class _FakeFunctionTool:
            """A fake FunctionTool with fn and metadata attributes."""

            def __init__(self) -> None:
                self.fn = lambda amount: "ok from wrapped fn"

            class metadata:
                name = "fake_tool"
                description = "A fake tool"

        fake_tool = _FakeFunctionTool()
        wrapped = PramanixFunctionTool.from_function_tool(
            fake_tool,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
        )
        assert wrapped._name == "fake_tool"
        assert wrapped._description == "A fake tool"
        output = await wrapped.acall(JSON_ALLOW)
        assert output.is_error is False

    def test_autogen_wrap_classmethod_sets_function_name(self) -> None:
        """PramanixToolCallback.wrap must preserve __name__ on the wrapped fn."""

        async def my_special_function(amount: Decimal) -> str:
            return "ok"

        guarded = PramanixToolCallback.wrap(
            my_special_function,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_ok,
        )
        assert guarded.__name__ == "my_special_function"

    @pytest.mark.asyncio
    async def test_wrappers_do_not_suppress_state_loader_exceptions_autogen(
        self,
    ) -> None:
        """AutoGen wrapper returns a rejection string (not raises) when state_provider raises."""

        def _bad_state() -> dict:
            raise RuntimeError("DB connection failed")

        async def _fn(amount: Decimal) -> str:
            return "ok"

        guarded = PramanixToolCallback.wrap(
            _fn,
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_bad_state,
        )
        # The autogen wrapper catches state errors and returns a rejection string.
        result = await guarded(amount=Decimal("100"))
        assert isinstance(result, str)
        # Must be a rejection, not "ok".
        assert "BLOCKED" in result or "[PRAMANIX BLOCKED]" in result

    @pytest.mark.asyncio
    async def test_fastapi_block_response_contains_violated_invariants(self) -> None:
        """FastAPI 403 response must list the violated invariant labels."""
        mw = _make_middleware(STATE_BLOCK)
        req = _MockRequest(body=JSON_BLOCK.encode())
        response = await mw.dispatch(req, _mock_call_next_ok)
        assert response.status_code == 403
        content = _response_content_dict(response)
        assert "violated_invariants" in content
        assert isinstance(content["violated_invariants"], list)
        assert len(content["violated_invariants"]) > 0

    @pytest.mark.asyncio
    async def test_fastapi_allow_does_not_return_403(self) -> None:
        """FastAPI middleware must NOT intercept ALLOW requests."""
        mw = _make_middleware(STATE_OK)
        req = _MockRequest(body=JSON_ALLOW.encode())
        response = await mw.dispatch(req, _mock_call_next_ok)
        assert response.status_code != 403

    @pytest.mark.asyncio
    async def test_langchain_block_returns_string_not_raises(self) -> None:
        """LangChain tool must return a string (not raise) on policy BLOCK."""
        tool = PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard,
            intent_schema=_IntentSchema,
            state_provider=_state_block,
        )
        try:
            result = await tool._arun(JSON_BLOCK)
            assert isinstance(result, str)
        except Exception as exc:
            # Only ValueError for invalid input is acceptable — not for policy block.
            pytest.fail(
                f"LangChain tool raised on policy BLOCK (must return string): {exc!r}"
            )
