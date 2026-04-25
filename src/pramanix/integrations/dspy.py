# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""DSPy integration for Pramanix — Phase F-1.

Wraps any DSPy ``Module`` so that the forward pass is gated by a
``Guard.verify()`` call before the underlying module executes.  If the guard
blocks the action the module raises a ``PramanixGuardViolationError`` rather
than executing — preserving DSPy's exception-based control flow.

Install: pip install 'pramanix[dspy]'
Requires: dspy-ai >= 2.0  OR  dspy >= 2.5

Usage::

    import dspy
    from pramanix.integrations.dspy import PramanixGuardedModule

    class MyTransferModule(dspy.Module):
        def forward(self, amount: float, recipient: str) -> dspy.Prediction:
            ...

    safe_module = PramanixGuardedModule(
        module=MyTransferModule(),
        guard=Guard(TransferPolicy, config=GuardConfig(execution_mode="sync")),
        intent_builder=lambda kw: {"amount": kw["amount"], ...},
        state_provider=lambda: {"balance": fetch_balance(), ...},
    )

    # DSPy call
    result = safe_module(amount=500.0, recipient="alice")
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.guard import Guard

__all__ = ["PramanixGuardedModule"]

try:
    import dspy as _dspy

    _DSPY_AVAILABLE = True
    _ModuleBase: Any = _dspy.Module
except ImportError:
    _DSPY_AVAILABLE = False
    _ModuleBase = object


class PramanixGuardedModule(_ModuleBase):  # type: ignore[misc]
    """DSPy ``Module`` wrapper with Z3 formal verification gate.

    If DSPy is **not** installed the class functions as a plain callable
    wrapper suitable for testing without the framework installed.

    The verification happens **before** the underlying module's ``forward``
    call.  If the guard blocks, :exc:`~pramanix.exceptions.GuardViolationError`
    is raised — consistent with how DSPy programs handle assertion failures.

    Args:
        module:         A ``dspy.Module`` instance (or any callable with a
                        ``forward`` method).
        guard:          A fully constructed :class:`~pramanix.guard.Guard`.
        intent_builder: Callable ``(**kwargs) → intent dict`` that maps the
                        forward-call keyword arguments to the Guard's intent
                        schema.
        state_provider: Callable ``() → state dict`` that fetches the current
                        system state at call time.
    """

    def __init__(
        self,
        *,
        module: Any,
        guard: Guard,
        intent_builder: Callable[..., dict[str, Any]],
        state_provider: Callable[[], dict[str, Any]],
    ) -> None:
        if _DSPY_AVAILABLE:
            super().__init__()
        # Store via object.__setattr__ to avoid DSPy / Pydantic introspection.
        object.__setattr__(self, "_inner_module", module)
        object.__setattr__(self, "_guard", guard)
        object.__setattr__(self, "_intent_builder", intent_builder)
        object.__setattr__(self, "_state_provider", state_provider)

    def forward(self, **kwargs: Any) -> Any:
        """Verify intent before delegating to the wrapped module.

        Args:
            **kwargs: Keyword arguments forwarded verbatim to the wrapped
                      module's ``forward`` method.

        Returns:
            The result of the wrapped module's ``forward`` call.

        Raises:
            GuardViolationError: Guard blocked the action.
        """
        from pramanix.exceptions import GuardViolationError

        guard: Guard = object.__getattribute__(self, "_guard")
        intent_builder: Callable[..., Any] = object.__getattribute__(self, "_intent_builder")
        state_provider: Callable[..., Any] = object.__getattribute__(self, "_state_provider")
        inner_module: Any = object.__getattribute__(self, "_inner_module")

        intent = intent_builder(**kwargs)
        state = state_provider()
        decision = guard.verify(intent=intent, state=state)

        if not decision.allowed:
            raise GuardViolationError(decision)

        # Delegate to the wrapped module.
        if hasattr(inner_module, "forward"):
            return inner_module.forward(**kwargs)
        return inner_module(**kwargs)

    def __call__(self, **kwargs: Any) -> Any:
        """Allow direct call syntax ``module(...)`` in addition to DSPy's protocol."""
        return self.forward(**kwargs)
