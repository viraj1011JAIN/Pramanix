# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Live integration tests for PramanixGuardedTool.

Uses real langchain-core BaseTool. Zero sys.modules mocking.
Skipped if langchain-core is not installed.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

pytest.importorskip("langchain_core", reason="langchain-core not installed")

from langchain_core.tools import BaseTool
from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools

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

    def test_wrap_tools_uses_execute_map_when_tool_name_matches(self):
        """execute_map entry for a tool name is used as its execute_fn."""
        _called: list[dict] = []

        def _custom_fn(intent: dict) -> str:
            _called.append(intent)
            return "from_execute_map"

        mock_tools = [type("T", (), {"name": "my_tool", "description": "desc"})()]
        wrapped = wrap_tools(
            mock_tools,
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
            execute_map={"my_tool": _custom_fn},
        )
        assert len(wrapped) == 1
        # Verify the execute_fn stored on the tool is the one from execute_map
        execute_fn = object.__getattribute__(wrapped[0], "_pramanix_execute")
        execute_fn({"amount": Decimal("1")})
        assert len(_called) == 1
        assert _called[0]["amount"] == Decimal("1")

    def test_wrap_tools_uses_orig_run_when_no_execute_map(self):
        """When a tool has _run and no execute_map, _make_default uses _run."""
        _run_calls: list[str] = []

        class _RealTool:
            name = "real_tool"
            description = "has a _run method"

            def _run(self, input_str: str) -> str:
                _run_calls.append(input_str)
                return f"ran:{input_str}"

        wrapped = wrap_tools(
            [_RealTool()],
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert len(wrapped) == 1
        # The default execute_fn should wrap _run
        execute_fn = object.__getattribute__(wrapped[0], "_pramanix_execute")
        result = execute_fn({"amount": 1})
        assert len(_run_calls) == 1
        assert "ran:" in result

    def test_wrap_tools_no_run_uses_json_dumps_default(self):
        """When tool has no _run and no execute_map, default returns JSON."""
        tool_no_run = type("T", (), {"name": "plain", "description": "plain tool"})()
        wrapped = wrap_tools(
            [tool_no_run],
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        assert len(wrapped) == 1
        execute_fn = object.__getattribute__(wrapped[0], "_pramanix_execute")
        result = execute_fn({"amount": 5})
        data = json.loads(result)
        assert "amount" in data


# ── execute_fn=None paths ─────────────────────────────────────────────────────


class TestExecuteFnNone:
    def test_construction_with_no_execute_fn_logs_warning(self, caplog):
        """Constructing without execute_fn emits a warning."""
        import logging

        with caplog.at_level(logging.WARNING, logger="pramanix.integrations.langchain"):
            tool = PramanixGuardedTool(
                name="warn_tool",
                description="no execute_fn",
                guard=_guard_allow,
                intent_schema=_IntentModel,
                state_provider=lambda: _STATE,
            )
        assert tool is not None
        assert any("execute_fn" in rec.message for rec in caplog.records)

    @pytest.mark.asyncio
    async def test_arun_allow_without_execute_fn_raises_configuration_error(self):
        """ALLOW decision with no execute_fn raises ConfigurationError, not crashes."""
        from pramanix.exceptions import ConfigurationError

        tool = PramanixGuardedTool(
            name="no_exec",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
        )
        with pytest.raises(ConfigurationError, match="execute_fn"):
            await tool._arun(json.dumps({"amount": "10"}))


# ── _run inside a running event loop (ThreadPoolExecutor path) ────────────────


class TestRunInsideEventLoop:
    @pytest.mark.asyncio
    async def test_run_called_from_async_context_uses_thread_executor(self):
        """_run dispatches to ThreadPoolExecutor when a loop is already running."""
        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=lambda: _STATE,
            execute_fn=lambda i: "thread_result",
        )
        # asyncio.get_running_loop() succeeds here → ThreadPoolExecutor path
        result = tool._run(json.dumps({"amount": "5"}))
        assert "thread_result" in result


# ── _get_state_async coroutine path ──────────────────────────────────────────


class TestGetStateAsyncCoroutine:
    @pytest.mark.asyncio
    async def test_arun_with_coroutine_returning_state_provider(self):
        """state_provider that returns a coroutine is awaited correctly."""

        async def _async_state() -> dict:
            return {"state_version": "1.0"}

        tool = PramanixGuardedTool(
            name="t",
            description="d",
            guard=_guard_allow,
            intent_schema=_IntentModel,
            state_provider=_async_state,
            execute_fn=lambda i: "coroutine_state_ok",
        )
        result = await tool._arun(json.dumps({"amount": "10"}))
        assert "coroutine_state_ok" in result
