# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real integration tests for PramanixCrewAITool.

Core logic tests run WITHOUT crewai installed (graceful-degradation mode),
so the guard pipeline — which is framework-independent — is always exercised.
The CrewAI-specific hierarchy test at the bottom is skipped when crewai is
not installed.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.crewai import PramanixCrewAITool

# ── Shared policies ──────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")


class _AllowPolicy(Policy):
    """Invariant always satisfied for amount >= 0."""

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
    """Invariant never satisfied for amount > 0."""

    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount}

    @classmethod
    def invariants(cls):
        return [
            (E(_amount) <= Decimal("0"))
            .named("must_be_zero_or_neg")
            .explain("Positive amounts are rejected by policy")
        ]


_ALLOW_GUARD = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
_BLOCK_GUARD = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))
_STATE = {"state_version": "1.0"}


def _make_tool(
    guard: Guard,
    underlying_fn=None,
    block_message: str | None = None,
    name: str = "transfer_funds",
) -> PramanixCrewAITool:
    return PramanixCrewAITool(
        name=name,
        description="Move money between accounts",
        guard=guard,
        intent_builder=lambda inp: {"amount": Decimal(str(inp.get("amount", 0)))},
        state_provider=lambda: _STATE,
        underlying_fn=underlying_fn,
        block_message=block_message,
    )


# ── Allow-path ────────────────────────────────────────────────────────────────


class TestAllowPath:
    def test_allow_calls_underlying_fn_and_returns_result(self):
        executed = []

        def fn(inp):
            executed.append(inp)
            return "transfer_ok"

        result = _make_tool(_ALLOW_GUARD, underlying_fn=fn)({"amount": 100})
        assert result == "transfer_ok"
        assert executed[0]["amount"] == 100

    def test_allow_run_protocol_uses_kwargs(self):
        """`_run(**kwargs)` satisfies CrewAI protocol on the allow path."""
        tool = _make_tool(_ALLOW_GUARD, underlying_fn=lambda inp: f"sent {inp['amount']}")
        assert tool._run(amount=250) == "sent 250"

    @pytest.mark.asyncio
    async def test_allow_arun_protocol(self):
        """`_arun(**kwargs)` satisfies the CrewAI async protocol on the allow path."""
        tool = _make_tool(_ALLOW_GUARD, underlying_fn=lambda inp: "async_ok")
        assert await tool._arun(amount=50) == "async_ok"

    def test_allow_call_merges_dict_and_kwargs(self):
        received = {}

        def fn(inp):
            received.update(inp)
            return "merged_ok"

        _make_tool(_ALLOW_GUARD, underlying_fn=fn)({"amount": 10}, extra_flag=True)
        assert received["amount"] == 10
        assert received["extra_flag"] is True

    def test_allow_none_tool_input_defaults_to_empty_dict(self):
        """Calling with tool_input=None uses amount=0 which satisfies >= 0."""
        tool = _make_tool(_ALLOW_GUARD, underlying_fn=lambda inp: "zero_ok")
        assert tool(None) == "zero_ok"


# ── Block-path ────────────────────────────────────────────────────────────────


class TestBlockPath:
    def test_block_returns_safe_failure_prefix(self):
        result = _make_tool(_BLOCK_GUARD, underlying_fn=lambda inp: "never")({"amount": 500})
        assert result.startswith("[PRAMANIX_BLOCKED]")

    def test_block_does_not_invoke_underlying_fn(self):
        called = []

        def fn(inp):
            called.append(inp)
            return "leaked"

        _make_tool(_BLOCK_GUARD, underlying_fn=fn)({"amount": 500})
        assert not called, "underlying_fn must not be called on a blocked decision"

    def test_block_uses_custom_block_message(self):
        tool = _make_tool(
            _BLOCK_GUARD,
            underlying_fn=lambda inp: "never",
            block_message="Compliance gate: transaction rejected",
        )
        result = tool({"amount": 500})
        assert "[PRAMANIX_BLOCKED]" in result
        assert "Compliance gate" in result

    def test_block_via_run_protocol(self):
        assert _make_tool(_BLOCK_GUARD)._run(amount=999).startswith("[PRAMANIX_BLOCKED]")

    @pytest.mark.asyncio
    async def test_block_via_arun_protocol(self):
        result = await _make_tool(_BLOCK_GUARD)._arun(amount=999)
        assert result.startswith("[PRAMANIX_BLOCKED]")


# ── Edge-cases ────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_no_underlying_fn_raises_not_implemented_error_on_allow(self):
        """No underlying_fn + allowed → NotImplementedError (not silent pass)."""
        with pytest.raises(NotImplementedError, match="underlying_fn"):
            _make_tool(_ALLOW_GUARD)({"amount": 100})

    def test_intent_builder_exception_returns_safe_failure(self):
        """intent_builder crash → safe-failure string, never re-raises."""

        def _bad_intent_builder(inp):
            raise RuntimeError("intent builder exploded")

        tool = PramanixCrewAITool(
            name="bad_intent",
            description="Crash in intent_builder",
            guard=_ALLOW_GUARD,
            intent_builder=_bad_intent_builder,
            state_provider=lambda: _STATE,
        )
        result = tool({"amount": 100})
        assert result.startswith("[PRAMANIX_BLOCKED]")
        assert "Guard error" in result

    def test_state_provider_exception_returns_safe_failure(self):
        """state_provider crash → safe-failure string, never re-raises."""

        def _bad_state_provider():
            raise RuntimeError("state_provider exploded")

        tool = PramanixCrewAITool(
            name="bad_state",
            description="Crash in state_provider",
            guard=_ALLOW_GUARD,
            intent_builder=lambda inp: {"amount": Decimal("50")},
            state_provider=_bad_state_provider,
        )
        result = tool({"amount": 50})
        assert result.startswith("[PRAMANIX_BLOCKED]")

    def test_name_and_description_accessible_as_attributes(self):
        """Attributes must be readable for CrewAI tool discovery."""
        tool = _make_tool(_ALLOW_GUARD, name="audit_tool")
        assert tool.name == "audit_tool"
        assert tool.description == "Move money between accounts"

    def test_different_tool_instances_do_not_share_guard_state(self):
        """Two tool instances must be fully independent."""
        allow_tool = _make_tool(_ALLOW_GUARD, underlying_fn=lambda inp: "allow")
        block_tool = _make_tool(_BLOCK_GUARD, underlying_fn=lambda inp: "never")
        assert allow_tool({"amount": 100}) == "allow"
        assert block_tool({"amount": 100}).startswith("[PRAMANIX_BLOCKED]")


# ── CrewAI framework hierarchy (skipped when crewai not installed) ────────────

import importlib.util as _ilu

_CREWAI_AVAILABLE = _ilu.find_spec("crewai") is not None


@pytest.mark.skipif(not _CREWAI_AVAILABLE, reason="crewai not installed")
class TestCrewAIHierarchy:
    def test_is_subclass_of_base_tool(self):
        """With crewai installed PramanixCrewAITool must be a BaseTool subclass."""
        from crewai.tools import BaseTool

        assert issubclass(PramanixCrewAITool, BaseTool)

    def test_allow_path_with_real_base_tool(self):
        tool = _make_tool(_ALLOW_GUARD, underlying_fn=lambda inp: "crewai_allow")
        assert tool({"amount": 10}) == "crewai_allow"

    def test_block_path_with_real_base_tool(self):
        result = _make_tool(_BLOCK_GUARD, underlying_fn=lambda inp: "never")({"amount": 10})
        assert result.startswith("[PRAMANIX_BLOCKED]")
