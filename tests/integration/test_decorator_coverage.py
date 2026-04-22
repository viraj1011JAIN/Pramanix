# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests for the @guard decorator (pramanix.decorator).

Coverage targets
----------------
* sync function → TypeError at decoration time
* async function with positional args → ALLOW path (function executes)
* async function with keyword args → ALLOW path (function executes)
* async function → BLOCK path with on_block="raise" → GuardViolationError
* async function → BLOCK path with on_block="return" → returns Decision
* wrapper.__guard__ attribute is set to the Guard instance
* class method decoration works identically to free function
* on_block="return" with less-than-2 positional args (kwargs extraction)
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decorator import guard
from pramanix.exceptions import GuardViolationError

# ═══════════════════════════════════════════════════════════════════════════════
# Minimal schemas and policies
# ═══════════════════════════════════════════════════════════════════════════════


class _SimpleIntent(BaseModel):
    amount: Decimal


class _SimpleState(BaseModel):
    state_version: str
    balance: Decimal


_amount_field = Field("amount", Decimal, "Real")
_balance_field = Field("balance", Decimal, "Real")


class _AllowPolicy(Policy):
    """Policy that always passes: amount <= 10_000."""

    class Meta:
        version = "1.0"
        intent_model = _SimpleIntent
        state_model = _SimpleState

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount_field, "balance": _balance_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [
            (E(_amount_field) <= 10_000)
            .named("under_limit")
            .explain("amount {amount} must be <= 10000"),
        ]


class _BlockPolicy(Policy):
    """Policy that always blocks: amount <= 0 (fails for positive amounts)."""

    class Meta:
        version = "1.0"
        intent_model = _SimpleIntent
        state_model = _SimpleState

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount_field, "balance": _balance_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [
            (E(_amount_field) <= 0).named("must_be_zero").explain("amount {amount} must be zero"),
        ]


_ALLOW_INTENT = {"amount": Decimal("100")}
_BLOCK_INTENT = {"amount": Decimal("500")}
_STATE = {"state_version": "1.0", "balance": Decimal("1000")}


# ═══════════════════════════════════════════════════════════════════════════════
# F-2: sync functions are now supported (no TypeError)
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorSyncFunctionSupport:
    def test_sync_function_does_not_raise_at_decoration(self) -> None:
        """F-2: @guard on a sync function must not raise TypeError."""

        @guard(policy=_AllowPolicy)
        def sync_transfer(intent: dict, state: dict) -> dict:
            return {"status": "ok"}

        assert callable(sync_transfer)

    def test_sync_wrapper_is_not_coroutine(self) -> None:
        import asyncio

        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert not asyncio.iscoroutinefunction(fn)

    def test_sync_allow_executes_function(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {"called": True}

        result = fn(_ALLOW_INTENT, _STATE)
        assert result["called"] is True

    def test_sync_block_raises_guard_violation_error(self) -> None:
        @guard(policy=_BlockPolicy)
        def fn(intent: dict, state: dict) -> dict:
            pytest.fail("should not be reached")

        with pytest.raises(GuardViolationError):
            fn(_BLOCK_INTENT, _STATE)

    def test_sync_block_returns_decision_when_on_block_return(self) -> None:
        from pramanix import Decision

        @guard(policy=_BlockPolicy, on_block="return")
        def fn(intent: dict, state: dict):  # type: ignore[return]
            pytest.fail("should not be reached")

        result = fn(_BLOCK_INTENT, _STATE)
        assert isinstance(result, Decision)
        assert not result.allowed

    def test_sync_wrapper_has_guard_attribute(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert hasattr(fn, "__guard__")
        assert isinstance(fn.__guard__, Guard)


# ═══════════════════════════════════════════════════════════════════════════════
# ALLOW path — positional and keyword args
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorAllowPath:
    @pytest.mark.asyncio
    async def test_allow_with_positional_args_executes_function(self) -> None:
        @guard(policy=_AllowPolicy)
        async def transfer(intent: dict, state: dict) -> dict:
            return {"status": "ok", "amount": intent["amount"]}

        result = await transfer(_ALLOW_INTENT, _STATE)
        assert result == {"status": "ok", "amount": Decimal("100")}

    @pytest.mark.asyncio
    async def test_allow_with_keyword_args_executes_function(self) -> None:
        @guard(policy=_AllowPolicy)
        async def transfer(intent: dict, state: dict) -> dict:
            return {"status": "ok"}

        result = await transfer(intent=_ALLOW_INTENT, state=_STATE)
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_allow_returns_wrapped_function_result(self) -> None:
        sentinel = {"key": "value", "nested": [1, 2, 3]}

        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return sentinel

        result = await fn(_ALLOW_INTENT, _STATE)
        assert result is sentinel

    @pytest.mark.asyncio
    async def test_allow_with_kwargs_only(self) -> None:
        """len(args) < 2 path: intent/state extracted from kwargs."""

        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return {"called": True}

        result = await fn(intent=_ALLOW_INTENT, state=_STATE)
        assert result["called"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK path — on_block="raise" (default)
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorBlockRaise:
    @pytest.mark.asyncio
    async def test_block_raises_guard_violation_error(self) -> None:
        @guard(policy=_BlockPolicy)
        async def transfer(intent: dict, state: dict) -> dict:
            pytest.fail("should not be reached")

        with pytest.raises(GuardViolationError):
            await transfer(_BLOCK_INTENT, _STATE)

    @pytest.mark.asyncio
    async def test_guard_violation_error_contains_decision(self) -> None:
        @guard(policy=_BlockPolicy)
        async def transfer(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError) as exc_info:
            await transfer(_BLOCK_INTENT, _STATE)

        err = exc_info.value
        assert hasattr(err, "decision") or len(err.args) > 0

    @pytest.mark.asyncio
    async def test_block_default_on_block_is_raise(self) -> None:
        @guard(policy=_BlockPolicy)
        async def transfer(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError):
            await transfer(_BLOCK_INTENT, _STATE)

    @pytest.mark.asyncio
    async def test_block_explicit_on_block_raise(self) -> None:
        @guard(policy=_BlockPolicy, on_block="raise")
        async def transfer(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError):
            await transfer(_BLOCK_INTENT, _STATE)


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK path — on_block="return"
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorBlockReturn:
    @pytest.mark.asyncio
    async def test_block_returns_decision_when_on_block_return(self) -> None:
        from pramanix import Decision

        @guard(policy=_BlockPolicy, on_block="return")
        async def transfer(  # type: ignore[return]
            intent: dict, state: dict
        ):
            pytest.fail("should not be reached")

        result = await transfer(_BLOCK_INTENT, _STATE)
        assert isinstance(result, Decision)

    @pytest.mark.asyncio
    async def test_block_return_decision_is_not_allowed(self) -> None:
        @guard(policy=_BlockPolicy, on_block="return")
        async def transfer(  # type: ignore[return]
            intent: dict, state: dict
        ):
            return {}

        result = await transfer(_BLOCK_INTENT, _STATE)
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_block_return_with_kwargs(self) -> None:
        """on_block='return' + keyword-arg extraction (len(args) < 2)."""
        from pramanix import Decision

        @guard(policy=_BlockPolicy, on_block="return")
        async def transfer(  # type: ignore[return]
            intent: dict, state: dict
        ):
            return {}

        result = await transfer(intent=_BLOCK_INTENT, state=_STATE)
        assert isinstance(result, Decision)
        assert not result.allowed


# ═══════════════════════════════════════════════════════════════════════════════
# __guard__ introspection attribute
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorGuardAttribute:
    def test_wrapper_has_guard_attribute(self) -> None:
        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return {}

        assert hasattr(fn, "__guard__")

    def test_guard_attribute_is_guard_instance(self) -> None:
        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return {}

        assert isinstance(fn.__guard__, Guard)

    def test_guard_attribute_is_same_object_every_access(self) -> None:
        """Same Guard instance reused — not re-created per call."""

        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return {}

        assert fn.__guard__ is fn.__guard__

    def test_functools_wraps_preserves_name(self) -> None:
        @guard(policy=_AllowPolicy)
        async def my_special_function(intent: dict, state: dict) -> dict:
            return {}

        assert my_special_function.__name__ == "my_special_function"

    def test_functools_wraps_preserves_doc(self) -> None:
        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            """My docstring."""
            return {}

        assert fn.__doc__ == "My docstring."


# ═══════════════════════════════════════════════════════════════════════════════
# Class method decoration
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorClassMethod:
    @pytest.mark.asyncio
    async def test_class_method_allow(self) -> None:
        class _Service:
            @guard(policy=_AllowPolicy)
            async def transfer(self, intent: dict, state: dict) -> dict:
                return {"from": "method"}

        svc = _Service()
        # Use kwargs to bypass positional-arg extraction ambiguity
        # (self occupies args[0] as a bound method).
        result = await svc.transfer(intent=_ALLOW_INTENT, state=_STATE)
        assert result == {"from": "method"}

    @pytest.mark.asyncio
    async def test_class_method_block_raises(self) -> None:
        class _Service:
            @guard(policy=_BlockPolicy)
            async def transfer(self, intent: dict, state: dict) -> dict:
                return {}

        svc = _Service()
        with pytest.raises(GuardViolationError):
            await svc.transfer(intent=_BLOCK_INTENT, state=_STATE)

    def test_class_method_has_guard_attribute(self) -> None:
        class _Service:
            @guard(policy=_AllowPolicy)
            async def transfer(self, intent: dict, state: dict) -> dict:
                return {}

        assert hasattr(_Service.transfer, "__guard__")
        assert isinstance(_Service.transfer.__guard__, Guard)


# ═══════════════════════════════════════════════════════════════════════════════
# Custom GuardConfig forwarding
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecoratorConfigForwarding:
    def test_custom_config_passed_to_guard(self) -> None:
        cfg = GuardConfig(execution_mode="async-thread", solver_timeout_ms=2000)

        @guard(policy=_AllowPolicy, config=cfg)
        async def fn(intent: dict, state: dict) -> dict:
            return {}

        g: Guard = fn.__guard__
        assert g._config.execution_mode == "async-thread"
        assert g._config.solver_timeout_ms == 2000

    def test_default_config_used_when_none(self) -> None:
        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return {}

        g: Guard = fn.__guard__
        assert g._config is not None
