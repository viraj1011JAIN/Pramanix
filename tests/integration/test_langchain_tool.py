# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests for PramanixGuardedTool and wrap_tools (9.3).

Uses sys.modules mocking to avoid requiring langchain installation.
The mock makes ``langchain_core.tools.BaseTool`` resolve to ``object`` so that
``PramanixGuardedTool`` inherits from ``object`` — which is perfectly valid
for testing all async/sync paths without Pydantic-v1/v2 compat concerns.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

# ── Mock langchain_core before importing the integration ──────────────────────
# We inject a minimal fake module so the try/except in langchain.py resolves to
# _LANGCHAIN_AVAILABLE = True with _BaseTool = object.

if "langchain_core" not in sys.modules:
    _mock_lc_tools = MagicMock()
    _mock_lc_tools.BaseTool = object  # PramanixGuardedTool will inherit from object
    _mock_lc = MagicMock()
    _mock_lc.tools = _mock_lc_tools
    sys.modules["langchain_core"] = _mock_lc
    sys.modules["langchain_core.tools"] = _mock_lc_tools

# Now import the integration (langchain_core is already mocked above).
# We must reload if it was already imported without the mock.
if "pramanix.integrations.langchain" in sys.modules:
    import importlib
    import pramanix.integrations.langchain as _lc_mod
    importlib.reload(_lc_mod)
    from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools
else:
    from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools

# ── Policy definitions ────────────────────────────────────────────────────────

from pramanix import E, Field, Guard, GuardConfig, Policy

_amount = Field("amount", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount}

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_amount) <= Decimal("10000"))
            .named("under_limit")
            .explain("amount {amount} <= 10000")
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
            .explain("amount must be zero")
        ]


# ── Shared fixtures ───────────────────────────────────────────────────────────

_guard_allow = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
_guard_block = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))

STATE: dict = {"state_version": "1.0"}


class _IntentSchema(BaseModel):
    amount: Decimal


def _state_provider() -> dict:
    return STATE


def _execute_fn(intent: dict) -> str:
    return f"transferred {intent['amount']}"


# ── TestPramanixGuardedToolAllow ──────────────────────────────────────────────


class TestPramanixGuardedToolAllow:
    """ALLOW path: execute_fn is called, result returned as string."""

    def _tool(self) -> PramanixGuardedTool:
        return PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard_allow,
            intent_schema=_IntentSchema,
            state_provider=_state_provider,
            execute_fn=_execute_fn,
        )

    @pytest.mark.asyncio
    async def test_arun_allow_executes_fn(self) -> None:
        tool = self._tool()
        result = await tool._arun('{"amount": "100"}')
        assert "100" in result

    @pytest.mark.asyncio
    async def test_arun_allow_returns_string(self) -> None:
        tool = self._tool()
        result = await tool._arun('{"amount": "50"}')
        assert isinstance(result, str)


# ── TestPramanixGuardedToolBlock ──────────────────────────────────────────────


class TestPramanixGuardedToolBlock:
    """BLOCK path: feedback string returned, no exception raised."""

    def _tool(self) -> PramanixGuardedTool:
        return PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard_block,
            intent_schema=_IntentSchema,
            state_provider=_state_provider,
            execute_fn=_execute_fn,
        )

    @pytest.mark.asyncio
    async def test_arun_block_returns_feedback_string(self) -> None:
        tool = self._tool()
        result = await tool._arun('{"amount": "500"}')
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_arun_block_never_raises(self) -> None:
        tool = self._tool()
        # Should NOT raise — policy block returns a string.
        result = await tool._arun('{"amount": "999"}')
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_block_feedback_contains_violated_rule(self) -> None:
        tool = self._tool()
        result = await tool._arun('{"amount": "500"}')
        # The feedback must reference the violated invariant label.
        assert "must_be_zero" in result or "BLOCKED" in result


# ── TestPramanixGuardedToolInput ──────────────────────────────────────────────


class TestPramanixGuardedToolInput:
    """Input validation: malformed JSON and schema errors raise ValueError."""

    def _tool(self) -> PramanixGuardedTool:
        return PramanixGuardedTool(
            name="transfer",
            description="Transfer funds",
            guard=_guard_allow,
            intent_schema=_IntentSchema,
            state_provider=_state_provider,
        )

    @pytest.mark.asyncio
    async def test_malformed_json_raises_value_error(self) -> None:
        tool = self._tool()
        with pytest.raises(ValueError, match="Pramanix"):
            await tool._arun("this is {not json}")

    def test_run_sync_wrapper_works(self) -> None:
        tool = self._tool()
        result = tool._run('{"amount": "100"}')
        assert isinstance(result, str)


# ── TestWrapTools ─────────────────────────────────────────────────────────────


class TestWrapTools:
    """wrap_tools: batch-wrapping preserves names and descriptions."""

    class _FakeTool:
        def __init__(self, name: str, description: str) -> None:
            self.name = name
            self.description = description

    def _fake_tools(self) -> list:
        return [
            self._FakeTool("tool_a", "Does thing A"),
            self._FakeTool("tool_b", "Does thing B"),
        ]

    def test_wrap_tools_returns_list(self) -> None:
        result = wrap_tools(
            self._fake_tools(),
            guard=_guard_allow,
            intent_schema=_IntentSchema,
            state_provider=_state_provider,
        )
        assert isinstance(result, list)
        assert len(result) == 2

    def test_wrap_tools_preserves_names(self) -> None:
        result = wrap_tools(
            self._fake_tools(),
            guard=_guard_allow,
            intent_schema=_IntentSchema,
            state_provider=_state_provider,
        )
        names = [t.name for t in result]
        assert "tool_a" in names
        assert "tool_b" in names

    def test_wrap_tools_preserves_descriptions(self) -> None:
        result = wrap_tools(
            self._fake_tools(),
            guard=_guard_allow,
            intent_schema=_IntentSchema,
            state_provider=_state_provider,
        )
        descs = {t.name: t.description for t in result}
        assert descs["tool_a"] == "Does thing A"
        assert descs["tool_b"] == "Does thing B"
