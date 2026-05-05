# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real integration tests for PramanixGuardedModule (DSPy adapter).

Core logic tests run WITHOUT dspy installed (graceful-degradation mode) because
the guard pipeline is framework-independent.  The DSPy hierarchy test is skipped
when dspy is not installed.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import GuardViolationError
from pramanix.integrations.dspy import PramanixGuardedModule

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


_ALLOW_GUARD = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
_BLOCK_GUARD = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))
_STATE = {"state_version": "1.0"}


# ── Stub inner modules ────────────────────────────────────────────────────────


class _ForwardModule:
    """Stub with a forward() method — the standard DSPy pattern."""

    def __init__(self, return_value=None):
        self._return_value = return_value
        self.calls: list[dict] = []

    def forward(self, **kwargs):
        self.calls.append(kwargs)
        return self._return_value or {"result": "forward_ok"}


class _CallableModule:
    """Stub callable without forward() — exercises the __call__ fallback path."""

    def __init__(self):
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return {"result": "callable_ok"}


def _make_module(
    guard: Guard,
    inner_module=None,
    state_override=None,
) -> PramanixGuardedModule:
    inner = inner_module or _ForwardModule()
    state = state_override or _STATE
    return PramanixGuardedModule(
        module=inner,
        guard=guard,
        intent_builder=lambda **kw: {"amount": Decimal(str(kw.get("amount", 0)))},
        state_provider=lambda: state,
    )


# ── Allow-path ────────────────────────────────────────────────────────────────


class TestAllowPath:
    def test_allow_calls_forward_on_inner_module(self):
        """ALLOW + forward() module → inner forward is called, result returned."""
        inner = _ForwardModule(return_value={"result": "allow_forward"})
        module = _make_module(_ALLOW_GUARD, inner_module=inner)
        result = module.forward(amount=Decimal("100"))
        assert result == {"result": "allow_forward"}
        assert len(inner.calls) == 1
        assert inner.calls[0]["amount"] == Decimal("100")

    def test_allow_dunder_call_delegates_to_forward(self):
        """__call__ must delegate to forward() transparently."""
        inner = _ForwardModule(return_value={"result": "call_ok"})
        module = _make_module(_ALLOW_GUARD, inner_module=inner)
        result = module(amount=Decimal("200"))
        assert result == {"result": "call_ok"}

    def test_allow_callable_inner_module_without_forward(self):
        """When inner module has no forward(), __call__ is used as the delegate."""
        inner = _CallableModule()
        module = _make_module(_ALLOW_GUARD, inner_module=inner)
        result = module.forward(amount=Decimal("50"))
        assert result == {"result": "callable_ok"}
        assert inner.calls[0]["amount"] == Decimal("50")

    def test_allow_state_fn_called_each_invocation(self):
        """state_provider must be called fresh on every guard check."""
        call_count = [0]

        def counting_state():
            call_count[0] += 1
            return _STATE

        inner = _ForwardModule()
        module = PramanixGuardedModule(
            module=inner,
            guard=_ALLOW_GUARD,
            intent_builder=lambda **kw: {"amount": Decimal("10")},
            state_provider=counting_state,
        )
        module.forward(amount=Decimal("10"))
        module.forward(amount=Decimal("20"))
        assert call_count[0] == 2, "state_provider must be called once per verification"


# ── Block-path ────────────────────────────────────────────────────────────────


class TestBlockPath:
    def test_block_raises_guard_violation_error(self):
        """BLOCK → GuardViolationError is raised, not a safe-failure string."""
        module = _make_module(_BLOCK_GUARD)
        with pytest.raises(GuardViolationError):
            module.forward(amount=Decimal("500"))

    def test_block_does_not_call_inner_forward(self):
        """Inner module forward() must NOT be called on a blocked decision."""
        inner = _ForwardModule()
        module = _make_module(_BLOCK_GUARD, inner_module=inner)
        with pytest.raises(GuardViolationError):
            module.forward(amount=Decimal("500"))
        assert not inner.calls, "inner.forward() must not be invoked after a block"

    def test_block_via_call_also_raises(self):
        """__call__ also raises GuardViolationError — no bypass through call protocol."""
        module = _make_module(_BLOCK_GUARD)
        with pytest.raises(GuardViolationError):
            module(amount=Decimal("999"))

    def test_guard_violation_error_carries_decision(self):
        """GuardViolationError.decision must be the decision returned by the Guard."""
        module = _make_module(_BLOCK_GUARD)
        with pytest.raises(GuardViolationError) as exc_info:
            module.forward(amount=Decimal("100"))
        err = exc_info.value
        assert err.decision is not None
        assert not err.decision.allowed

    def test_block_with_zero_amount_satisfies_block_policy(self):
        """Boundary condition: amount=0 satisfies both policies; ensure allow fires."""
        allow_module = _make_module(_ALLOW_GUARD)
        inner = _ForwardModule(return_value="zero_ok")
        allow_module = PramanixGuardedModule(
            module=_ForwardModule(return_value="zero_ok"),
            guard=_ALLOW_GUARD,
            intent_builder=lambda **kw: {"amount": Decimal("0")},
            state_provider=lambda: _STATE,
        )
        result = allow_module.forward()
        assert result == "zero_ok"


# ── Edge-cases ────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_multiple_sequential_calls_independent(self):
        """Each forward() call is independently verified — no state leakage."""
        inner = _ForwardModule()
        module = _make_module(_ALLOW_GUARD, inner_module=inner)
        module.forward(amount=Decimal("10"))
        module.forward(amount=Decimal("20"))
        module.forward(amount=Decimal("30"))
        assert len(inner.calls) == 3

    def test_guard_violation_error_message_contains_status(self):
        """GuardViolationError message must reference the decision status."""
        module = _make_module(_BLOCK_GUARD)
        with pytest.raises(GuardViolationError) as exc_info:
            module.forward(amount=Decimal("100"))
        assert "blocked" in str(exc_info.value).lower() or str(exc_info.value)


# ── DSPy framework hierarchy (skipped when dspy not installed) ────────────────

dspy_mod = pytest.importorskip("dspy", reason="dspy not installed")


class TestDSPyHierarchy:
    def test_is_subclass_of_dspy_module(self):
        """With dspy installed PramanixGuardedModule must subclass dspy.Module."""
        import dspy

        assert issubclass(PramanixGuardedModule, dspy.Module)

    def test_allow_path_with_real_dspy_module(self):
        inner = _ForwardModule(return_value={"prediction": "ok"})
        module = _make_module(_ALLOW_GUARD, inner_module=inner)
        result = module.forward(amount=Decimal("100"))
        assert result == {"prediction": "ok"}

    def test_block_path_with_real_dspy_module(self):
        module = _make_module(_BLOCK_GUARD)
        with pytest.raises(GuardViolationError):
            module.forward(amount=Decimal("500"))
