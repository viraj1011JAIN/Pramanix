# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real integration tests for PramanixPydanticAIValidator.

Without pydantic-ai installed: verifies that __init__ raises ConfigurationError
immediately (fail-fast contract).

With pydantic-ai installed (pytest.importorskip): exercises check(), check_async(),
and guard_tool() with real Guard verifications.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import ConfigurationError, GuardViolationError
from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

# ── Shared policies ──────────────────────────────────────────────────────────

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
            .named("must_be_zero_or_neg")
            .explain("Positive amounts are rejected")
        ]


_STATE = {"state_version": "1.0"}


# ── Fail-fast contract (always runs, even without pydantic-ai) ────────────────


class TestConfigurationErrorWithoutFramework:
    def test_init_raises_configuration_error_when_pydantic_ai_absent(self):
        """If pydantic-ai is not installed PramanixPydanticAIValidator.__init__
        must raise ConfigurationError immediately — before any guard logic runs."""
        try:
            import pydantic_ai  # noqa: F401

            pytest.skip("pydantic-ai is installed; skip absence test")
        except ImportError:
            pass  # expected — proceed with the assertion

        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
        with pytest.raises(ConfigurationError, match="pydantic-ai"):
            PramanixPydanticAIValidator(guard=guard)

    def test_configuration_error_message_contains_install_hint(self):
        """The error message must include the pip install hint so developers can
        self-diagnose immediately."""
        try:
            import pydantic_ai  # noqa: F401

            pytest.skip("pydantic-ai is installed; skip absence test")
        except ImportError:
            pass

        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
        with pytest.raises(ConfigurationError) as exc_info:
            PramanixPydanticAIValidator(guard=guard)
        assert "pip install" in str(exc_info.value)


# ── pydantic-ai present — full functionality tests ────────────────────────────

import importlib.util as _ilu

_PYDANTIC_AI_AVAILABLE = _ilu.find_spec("pydantic_ai") is not None

_skip_without_pydantic_ai = pytest.mark.skipif(
    not _PYDANTIC_AI_AVAILABLE,
    reason="pydantic-ai not installed"
)


@pytest.fixture
def allow_validator():
    guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
    return PramanixPydanticAIValidator(guard=guard)


@pytest.fixture
def block_validator():
    guard = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))
    return PramanixPydanticAIValidator(guard=guard)


@pytest.fixture
def async_allow_validator():
    guard = Guard(_AllowPolicy, GuardConfig(execution_mode="async-thread"))
    return PramanixPydanticAIValidator(guard=guard)


@pytest.fixture
def async_block_validator():
    guard = Guard(_BlockPolicy, GuardConfig(execution_mode="async-thread"))
    return PramanixPydanticAIValidator(guard=guard)


@_skip_without_pydantic_ai
class TestCheckSync:
    def test_allow_returns_decision(self, allow_validator):
        decision = allow_validator.check(
            intent={"amount": Decimal("100")},
            state=_STATE,
        )
        assert decision.allowed

    def test_allow_with_state_fn_fallback(self):
        """state_fn is called when state kwarg is omitted."""
        called = [False]

        def _state_fn():
            called[0] = True
            return _STATE

        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
        v = PramanixPydanticAIValidator(guard=guard, state_fn=_state_fn)
        decision = v.check(intent={"amount": Decimal("10")})
        assert decision.allowed
        assert called[0], "state_fn must be called when state is not provided"

    def test_block_raises_guard_violation_error(self, block_validator):
        with pytest.raises(GuardViolationError) as exc_info:
            block_validator.check(
                intent={"amount": Decimal("500")},
                state=_STATE,
            )
        assert not exc_info.value.decision.allowed

    def test_block_violation_carries_decision_metadata(self, block_validator):
        with pytest.raises(GuardViolationError) as exc_info:
            block_validator.check(
                intent={"amount": Decimal("100")},
                state=_STATE,
            )
        decision = exc_info.value.decision
        assert decision.violated_invariants


@_skip_without_pydantic_ai
class TestCheckAsync:
    @pytest.mark.asyncio
    async def test_allow_async_returns_decision(self, async_allow_validator):
        decision = await async_allow_validator.check_async(
            intent={"amount": Decimal("100")},
            state=_STATE,
        )
        assert decision.allowed

    @pytest.mark.asyncio
    async def test_block_async_raises_guard_violation_error(self, async_block_validator):
        with pytest.raises(GuardViolationError):
            await async_block_validator.check_async(
                intent={"amount": Decimal("500")},
                state=_STATE,
            )

    @pytest.mark.asyncio
    async def test_allow_async_with_state_fn_fallback(self):
        def _state_fn():
            return _STATE

        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="async-thread"))
        v = PramanixPydanticAIValidator(guard=guard, state_fn=_state_fn)
        decision = await v.check_async(intent={"amount": Decimal("10")})
        assert decision.allowed


@_skip_without_pydantic_ai
class TestGuardToolDecorator:
    @pytest.mark.asyncio
    async def test_guard_tool_allows_and_calls_wrapped_fn(self, allow_validator):
        """@guard_tool wraps an async fn: allow path → wrapped fn executes."""
        executed = [False]

        @allow_validator.guard_tool
        async def withdraw(intent: dict, state: dict | None = None) -> str:
            executed[0] = True
            return "withdrawn"

        result = await withdraw(intent={"amount": Decimal("100")}, state=_STATE)
        assert result == "withdrawn"
        assert executed[0]

    @pytest.mark.asyncio
    async def test_guard_tool_blocks_and_does_not_call_fn(self, block_validator):
        """@guard_tool: block path → GuardViolationError raised, fn not called."""
        called = [False]

        @block_validator.guard_tool
        async def transfer(intent: dict, state: dict | None = None) -> str:
            called[0] = True
            return "transferred"

        with pytest.raises(GuardViolationError):
            await transfer(intent={"amount": Decimal("500")}, state=_STATE)
        assert not called[0], "wrapped fn must not be called after a block"

    @pytest.mark.asyncio
    async def test_guard_tool_preserves_fn_metadata(self, allow_validator):
        """@guard_tool must use functools.wraps so __name__ and __doc__ survive."""

        @allow_validator.guard_tool
        async def my_special_tool(intent: dict, state: dict | None = None) -> str:
            """My special tool docstring."""
            return "ok"

        assert my_special_tool.__name__ == "my_special_tool"
        assert "special" in (my_special_tool.__doc__ or "")
