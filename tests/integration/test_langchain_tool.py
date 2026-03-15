# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Live integration tests for PramanixGuardedTool.

Uses real langchain-core BaseTool. Zero sys.modules mocking.
Skipped if langchain-core is not installed.
"""
from __future__ import annotations

import json
from decimal import Decimal

import pytest

pytest.importorskip("langchain_core", reason="langchain-core not installed")

from langchain_core.tools import BaseTool  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from pramanix import E, Field, Guard, GuardConfig, Policy  # noqa: E402
from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools  # noqa: E402

# ── Verify real inheritance ───────────────────────────────────────────────────


def test_pramanix_guarded_tool_is_real_basetool_subclass():
    """CRITICAL: Must be a REAL subclass of langchain_core BaseTool."""
    assert issubclass(PramanixGuardedTool, BaseTool), (
        "PramanixGuardedTool must inherit from langchain_core.tools.BaseTool. "
        "If this fails, the LangChain integration is a stub, not a real integration."
    )


# ── Policies ──────────────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount}

    @classmethod
    def invariants(cls):
        return [
            (E(_amount) >= Decimal("0"))
            .named("non_negative")
            .explain("Amount must be non-negative")
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
            .explain("Amount rejected by block policy")
        ]


class _IntentModel(BaseModel):
    amount: Decimal


_STATE = {"state_version": "1.0"}
_guard_allow = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
_guard_block = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))
_execute_log: list[dict] = []


def _execute(intent: dict) -> str:
    _execute_log.append(intent)
    return f"executed amount={intent['amount']}"


# ── Construction tests ────────────────────────────────────────────────────────


class TestPramanixGuardedToolConstruction:
    def test_is_real_basetool_instance(self):
        tool = PramanixGuardedTool(
            name="test",
            description="test desc",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert isinstance(tool, BaseTool)

    def test_name_preserved(self):
        tool = PramanixGuardedTool(
            name="bank_transfer",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert tool.name == "bank_transfer"

    def test_description_preserved(self):
        tool = PramanixGuardedTool(
            name="t",
            description="Transfer funds safely",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert tool.description == "Transfer funds safely"


# ── ALLOW tests ───────────────────────────────────────────────────────────────


class TestPramanixGuardedToolAllow:
    @pytest.mark.asyncio
    async def test_arun_allow_calls_execute_fn(self):
        _execute_log.clear()
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
            execute_fn=_execute,
        )
        await tool._arun(json.dumps({"amount": "100"}))
        assert len(_execute_log) == 1
        assert _execute_log[0]["amount"] == Decimal("100")

    @pytest.mark.asyncio
    async def test_arun_allow_returns_string(self):
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
            execute_fn=lambda i: "transfer complete",
        )
        result = await tool._arun(json.dumps({"amount": "50"}))
        assert isinstance(result, str)
        assert "transfer complete" in result


# ── BLOCK tests ───────────────────────────────────────────────────────────────


class TestPramanixGuardedToolBlock:
    @pytest.mark.asyncio
    async def test_arun_block_returns_string_never_raises(self):
        """CRITICAL: BLOCK must return string, NEVER raise exception."""
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_block,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        result = await tool._arun(json.dumps({"amount": "100"}))
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_arun_block_contains_blocked_signal(self):
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_block,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        result = await tool._arun(json.dumps({"amount": "100"}))
        assert "BLOCKED" in result.upper()

    @pytest.mark.asyncio
    async def test_arun_block_contains_decision_id(self):
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_block,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        result = await tool._arun(json.dumps({"amount": "100"}))
        # decision_id is a UUID — should be in the feedback
        assert "decision_id=" in result or len([p for p in result.split() if len(p) > 30]) > 0

    @pytest.mark.asyncio
    async def test_arun_block_does_not_leak_raw_values(self):
        """SECURITY: feedback must not contain raw input values."""
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_block,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        sentinel = "987654321"
        result = await tool._arun(json.dumps({"amount": sentinel}))
        assert sentinel not in result

    @pytest.mark.asyncio
    async def test_arun_block_execute_fn_never_called(self):
        _execute_log.clear()
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_block,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
            execute_fn=_execute,
        )
        await tool._arun(json.dumps({"amount": "100"}))
        assert len(_execute_log) == 0


# ── Error tests ───────────────────────────────────────────────────────────────


class TestPramanixGuardedToolErrors:
    @pytest.mark.asyncio
    async def test_malformed_json_raises_value_error(self):
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        with pytest.raises(ValueError, match="JSON"):
            await tool._arun("{not valid json{{")

    def test_run_sync_path_returns_string(self):
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
            execute_fn=lambda i: "sync result",
        )
        result = tool._run(json.dumps({"amount": "10"}))
        assert isinstance(result, str)


# ── wrap_tools tests ──────────────────────────────────────────────────────────


class TestWrapTools:
    def test_wrap_tools_returns_pramanix_tools(self):
        mock_tools = [
            type("T", (), {"name": "tool_a", "description": "desc a"})(),
            type("T", (), {"name": "tool_b", "description": "desc b"})(),
        ]
        wrapped = wrap_tools(
            mock_tools,
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert len(wrapped) == 2
        assert all(isinstance(t, PramanixGuardedTool) for t in wrapped)

    def test_wrap_tools_preserves_names(self):
        mock_tools = [type("T", (), {"name": "my_tool", "description": "desc"})()]
        wrapped = wrap_tools(
            mock_tools,
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert wrapped[0].name == "my_tool"

    def test_wrap_tools_preserves_descriptions(self):
        mock_tools = [type("T", (), {"name": "t", "description": "my description"})()]
        wrapped = wrap_tools(
            mock_tools,
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert wrapped[0].description == "my description"
