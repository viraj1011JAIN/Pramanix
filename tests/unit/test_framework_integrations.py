# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for F-1 — CrewAI and DSPy framework integrations.

Coverage:
- PramanixCrewAITool: blocked → returns [PRAMANIX_BLOCKED] string
- PramanixCrewAITool: allowed → calls underlying_fn and returns its result
- PramanixCrewAITool: __call__ works correctly
- PramanixGuardedModule: blocked → raises GuardViolationError
- PramanixGuardedModule: allowed → delegates to inner_module
- PramanixGuardedModule: __call__ delegates to forward
"""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

from pramanix.decision import Decision
from pramanix.exceptions import GuardViolationError
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Shared test policy ────────────────────────────────────────────────────────


class _SimplePolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) > Decimal("0")).named("positive_amount")]


_CONFIG = GuardConfig(execution_mode="sync")


def _make_guard() -> Guard:
    return Guard(_SimplePolicy, config=_CONFIG)


# ── PramanixCrewAITool ────────────────────────────────────────────────────────


class TestPramanixCrewAIToolBlocked:
    def test_returns_blocked_string_on_violation(self):
        """When guard blocks, _execute must return a [PRAMANIX_BLOCKED] string."""
        from pramanix.integrations.crewai import PramanixCrewAITool, _SAFE_FAILURE_PREFIX

        guard = _make_guard()
        underlying = MagicMock(return_value="success")

        tool = PramanixCrewAITool(
            name="test_tool",
            description="test",
            guard=guard,
            intent_builder=lambda tool_input: {"amount": Decimal("-100")},  # violates
            state_provider=lambda: {},
            underlying_fn=underlying,
        )
        result = tool._execute({"amount": "-100"})
        assert isinstance(result, str)
        assert result.startswith(_SAFE_FAILURE_PREFIX)
        underlying.assert_not_called()

    def test_allowed_calls_underlying_fn(self):
        """When guard allows, _execute must call underlying_fn and return its result."""
        from pramanix.integrations.crewai import PramanixCrewAITool

        guard = _make_guard()
        underlying = MagicMock(return_value="transfer_complete")

        tool = PramanixCrewAITool(
            name="test_tool",
            description="test",
            guard=guard,
            intent_builder=lambda tool_input: {"amount": Decimal("100")},  # passes
            state_provider=lambda: {},
            underlying_fn=underlying,
        )
        result = tool._execute({"amount": "100"})
        assert result == "transfer_complete"
        underlying.assert_called_once()

    def test_call_dunder_delegates_to_execute(self):
        """__call__ should work as an alias for _execute."""
        from pramanix.integrations.crewai import PramanixCrewAITool, _SAFE_FAILURE_PREFIX

        guard = _make_guard()
        tool = PramanixCrewAITool(
            name="test_tool",
            description="test",
            guard=guard,
            intent_builder=lambda tool_input: {"amount": Decimal("-1")},
            state_provider=lambda: {},
        )
        result = tool({"amount": "-1"})
        assert isinstance(result, str)
        assert result.startswith(_SAFE_FAILURE_PREFIX)


# ── PramanixGuardedModule ─────────────────────────────────────────────────────


class TestPramanixGuardedModuleBlocked:
    def test_forward_raises_guard_violation_when_blocked(self):
        """When guard blocks, forward() must raise GuardViolationError."""
        from pramanix.integrations.dspy import PramanixGuardedModule

        guard = _make_guard()
        inner = MagicMock()

        module = PramanixGuardedModule(
            module=inner,
            guard=guard,
            intent_builder=lambda **kw: {"amount": Decimal("-50")},  # violates
            state_provider=lambda: {},
        )
        with pytest.raises(GuardViolationError):
            module.forward(amount="-50")
        inner.forward.assert_not_called()

    def test_forward_delegates_when_allowed(self):
        """When guard allows, forward() must call the inner module."""
        from pramanix.integrations.dspy import PramanixGuardedModule

        guard = _make_guard()
        inner = MagicMock()
        inner.forward.return_value = {"result": "ok"}

        module = PramanixGuardedModule(
            module=inner,
            guard=guard,
            intent_builder=lambda **kw: {"amount": Decimal("200")},  # passes
            state_provider=lambda: {},
        )
        result = module.forward(amount="200")
        assert result == {"result": "ok"}
        inner.forward.assert_called_once()

    def test_call_dunder_delegates_to_forward(self):
        """__call__ should be equivalent to forward."""
        from pramanix.integrations.dspy import PramanixGuardedModule

        guard = _make_guard()
        inner = MagicMock()

        module = PramanixGuardedModule(
            module=inner,
            guard=guard,
            intent_builder=lambda **kw: {"amount": Decimal("-1")},
            state_provider=lambda: {},
        )
        with pytest.raises(GuardViolationError):
            module(amount="-1")
