# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase F-2: Sync @guard decorator.

Gate condition (from engineering plan):
    pytest -k 'sync_decorator'
    # @guard on sync function works. TypeError not raised for any sync function.
    # Existing async decorator tests still pass.

Coverage targets
----------------
* sync function decorated without TypeError
* sync wrapper is NOT a coroutine
* async wrapper IS still a coroutine (no regression)
* sync ALLOW path with positional args — function executes and returns result
* sync ALLOW path with keyword args
* sync BLOCK path on_block="raise" — GuardViolationError raised
* sync BLOCK path on_block="return" — Decision returned
* sync BLOCK with kwargs (len(args) < 2 path)
* __guard__ attribute on sync wrapper is a Guard instance
* functools.wraps preserves __name__ and __doc__
* sync class method decoration — ALLOW path
* sync class method decoration — BLOCK path
* sync class method has __guard__ attribute
* custom GuardConfig forwarded to Guard for sync wrapper
* sync function callable from within a running event loop (blocking, but correct)
"""
from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decorator import guard
from pramanix.exceptions import GuardViolationError

# ═══════════════════════════════════════════════════════════════════════════════
# Minimal schemas and policies (mirrors test_decorator_coverage.py fixtures)
# ═══════════════════════════════════════════════════════════════════════════════


class _Intent(BaseModel):
    amount: Decimal


class _State(BaseModel):
    state_version: str
    balance: Decimal


_amount_field = Field("amount", Decimal, "Real")
_balance_field = Field("balance", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = _Intent
        state_model = _State

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount_field, "balance": _balance_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_amount_field) <= 10_000).named("under_limit")]


class _BlockPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = _Intent
        state_model = _State

    @classmethod
    def fields(cls) -> dict:
        return {"amount": _amount_field, "balance": _balance_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_amount_field) <= 0).named("must_be_zero")]


_ALLOW_INTENT = {"amount": Decimal("100")}
_BLOCK_INTENT = {"amount": Decimal("500")}
_STATE = {"state_version": "1.0", "balance": Decimal("1000")}


# ═══════════════════════════════════════════════════════════════════════════════
# F-2 Gate: basic decoration — no TypeError for sync functions
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorNoTypeError:
    def test_sync_function_decorated_without_error(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert callable(fn)

    def test_sync_wrapper_is_not_a_coroutine_function(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert not asyncio.iscoroutinefunction(fn)

    def test_async_wrapper_is_still_a_coroutine_function(self) -> None:
        """Regression: existing async behavior must be preserved."""

        @guard(policy=_AllowPolicy)
        async def fn(intent: dict, state: dict) -> dict:
            return {}

        assert asyncio.iscoroutinefunction(fn)

    def test_sync_and_async_decorations_produce_different_wrapper_types(self) -> None:
        @guard(policy=_AllowPolicy)
        def sync_fn(intent: dict, state: dict) -> dict:
            return {}

        @guard(policy=_AllowPolicy)
        async def async_fn(intent: dict, state: dict) -> dict:
            return {}

        assert not asyncio.iscoroutinefunction(sync_fn)
        assert asyncio.iscoroutinefunction(async_fn)


# ═══════════════════════════════════════════════════════════════════════════════
# ALLOW path — sync functions execute and return their result
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorAllowPath:
    def test_allow_with_positional_args_executes_function(self) -> None:
        @guard(policy=_AllowPolicy)
        def transfer(intent: dict, state: dict) -> dict:
            return {"status": "ok", "amount": intent["amount"]}

        result = transfer(_ALLOW_INTENT, _STATE)
        assert result == {"status": "ok", "amount": Decimal("100")}

    def test_allow_with_keyword_args_executes_function(self) -> None:
        @guard(policy=_AllowPolicy)
        def transfer(intent: dict, state: dict) -> dict:
            return {"status": "ok"}

        result = transfer(intent=_ALLOW_INTENT, state=_STATE)
        assert result["status"] == "ok"

    def test_allow_returns_wrapped_function_result_identity(self) -> None:
        sentinel = {"key": "value", "nested": [1, 2, 3]}

        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return sentinel

        result = fn(_ALLOW_INTENT, _STATE)
        assert result is sentinel

    def test_allow_kwargs_only_path(self) -> None:
        """len(args) < 2 path: intent/state extracted from kwargs."""

        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {"called": True}

        result = fn(intent=_ALLOW_INTENT, state=_STATE)
        assert result["called"] is True

    def test_allow_does_not_return_decision(self) -> None:
        from pramanix import Decision

        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {"status": "ok"}

        result = fn(_ALLOW_INTENT, _STATE)
        assert not isinstance(result, Decision)


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK path — on_block="raise" (default)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorBlockRaise:
    def test_block_raises_guard_violation_error(self) -> None:
        @guard(policy=_BlockPolicy)
        def transfer(intent: dict, state: dict) -> dict:
            pytest.fail("should not be reached")

        with pytest.raises(GuardViolationError):
            transfer(_BLOCK_INTENT, _STATE)

    def test_guard_violation_error_carries_decision(self) -> None:
        @guard(policy=_BlockPolicy)
        def transfer(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError) as exc_info:
            transfer(_BLOCK_INTENT, _STATE)

        err = exc_info.value
        assert hasattr(err, "decision") or len(err.args) > 0

    def test_block_default_on_block_is_raise(self) -> None:
        @guard(policy=_BlockPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError):
            fn(_BLOCK_INTENT, _STATE)

    def test_block_explicit_on_block_raise(self) -> None:
        @guard(policy=_BlockPolicy, on_block="raise")
        def fn(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError):
            fn(_BLOCK_INTENT, _STATE)

    def test_block_function_body_never_executes(self) -> None:
        body_called = []

        @guard(policy=_BlockPolicy)
        def fn(intent: dict, state: dict) -> dict:
            body_called.append(True)
            return {}

        with pytest.raises(GuardViolationError):
            fn(_BLOCK_INTENT, _STATE)

        assert len(body_called) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK path — on_block="return"
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorBlockReturn:
    def test_block_returns_decision_object(self) -> None:
        from pramanix import Decision

        @guard(policy=_BlockPolicy, on_block="return")
        def fn(intent: dict, state: dict):  # type: ignore[return]
            pytest.fail("should not be reached")

        result = fn(_BLOCK_INTENT, _STATE)
        assert isinstance(result, Decision)

    def test_block_returned_decision_is_not_allowed(self) -> None:
        @guard(policy=_BlockPolicy, on_block="return")
        def fn(intent: dict, state: dict):
            return {}

        result = fn(_BLOCK_INTENT, _STATE)
        assert not result.allowed

    def test_block_return_with_kwargs(self) -> None:
        """len(args) < 2 + on_block='return'."""
        from pramanix import Decision

        @guard(policy=_BlockPolicy, on_block="return")
        def fn(intent: dict, state: dict):  # type: ignore[return]
            return {}

        result = fn(intent=_BLOCK_INTENT, state=_STATE)
        assert isinstance(result, Decision)
        assert not result.allowed

    def test_block_function_body_not_reached_on_return(self) -> None:
        body_called = []

        @guard(policy=_BlockPolicy, on_block="return")
        def fn(intent: dict, state: dict):  # type: ignore[return]
            body_called.append(True)

        fn(_BLOCK_INTENT, _STATE)
        assert len(body_called) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# __guard__ introspection attribute
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorGuardAttribute:
    def test_sync_wrapper_has_guard_attribute(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert hasattr(fn, "__guard__")

    def test_guard_attribute_is_guard_instance(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert isinstance(fn.__guard__, Guard)

    def test_guard_attribute_same_object_every_access(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        assert fn.__guard__ is fn.__guard__

    def test_functools_wraps_preserves_name(self) -> None:
        @guard(policy=_AllowPolicy)
        def my_sync_function(intent: dict, state: dict) -> dict:
            return {}

        assert my_sync_function.__name__ == "my_sync_function"

    def test_functools_wraps_preserves_doc(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            """My sync docstring."""
            return {}

        assert fn.__doc__ == "My sync docstring."


# ═══════════════════════════════════════════════════════════════════════════════
# Class method decoration
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorClassMethod:
    def test_sync_class_method_allow(self) -> None:
        class _Service:
            @guard(policy=_AllowPolicy)
            def transfer(self, intent: dict, state: dict) -> dict:
                return {"from": "sync_method"}

        svc = _Service()
        result = svc.transfer(intent=_ALLOW_INTENT, state=_STATE)
        assert result == {"from": "sync_method"}

    def test_sync_class_method_allow_kwargs(self) -> None:
        """Class methods must use kwargs — positional args[0] would be self."""

        class _Service:
            @guard(policy=_AllowPolicy)
            def transfer(self, intent: dict, state: dict) -> dict:
                return {"called": True}

        svc = _Service()
        result = svc.transfer(intent=_ALLOW_INTENT, state=_STATE)
        assert result["called"] is True

    def test_sync_class_method_block_raises(self) -> None:
        class _Service:
            @guard(policy=_BlockPolicy)
            def transfer(self, intent: dict, state: dict) -> dict:
                return {}

        svc = _Service()
        with pytest.raises(GuardViolationError):
            svc.transfer(intent=_BLOCK_INTENT, state=_STATE)

    def test_sync_class_method_has_guard_attribute(self) -> None:
        class _Service:
            @guard(policy=_AllowPolicy)
            def transfer(self, intent: dict, state: dict) -> dict:
                return {}

        assert hasattr(_Service.transfer, "__guard__")
        assert isinstance(_Service.transfer.__guard__, Guard)


# ═══════════════════════════════════════════════════════════════════════════════
# Custom GuardConfig forwarding
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorConfigForwarding:
    def test_custom_config_passed_to_guard(self) -> None:
        cfg = GuardConfig(solver_timeout_ms=2000)

        @guard(policy=_AllowPolicy, config=cfg)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        g: Guard = fn.__guard__
        assert g._config.solver_timeout_ms == 2000

    def test_default_config_used_when_none(self) -> None:
        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        g: Guard = fn.__guard__
        assert g._config is not None

    def test_sync_and_async_decorators_share_no_state(self) -> None:
        """Two separate decorated functions must have independent Guard instances."""

        @guard(policy=_AllowPolicy)
        def fn1(intent: dict, state: dict) -> dict:
            return {}

        @guard(policy=_AllowPolicy)
        def fn2(intent: dict, state: dict) -> dict:
            return {}

        assert fn1.__guard__ is not fn2.__guard__


# ═══════════════════════════════════════════════════════════════════════════════
# Sync decorator called from within an async context
# ═══════════════════════════════════════════════════════════════════════════════


class TestSyncDecoratorFromAsyncContext:
    @pytest.mark.asyncio
    async def test_sync_decorated_fn_callable_from_async_code(self) -> None:
        """Sync @guard wrapper is callable from async code (blocks the thread)."""

        @guard(policy=_AllowPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {"from": "sync_inside_async"}

        result = fn(_ALLOW_INTENT, _STATE)
        assert result["from"] == "sync_inside_async"

    @pytest.mark.asyncio
    async def test_sync_block_raises_from_async_context(self) -> None:
        @guard(policy=_BlockPolicy)
        def fn(intent: dict, state: dict) -> dict:
            return {}

        with pytest.raises(GuardViolationError):
            fn(_BLOCK_INTENT, _STATE)
