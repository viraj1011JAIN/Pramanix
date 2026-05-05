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


class _PramanixState:
    """Plain-Python container for guard state — invisible to DSPy/Pydantic.

    Storing all non-field attributes here means only a single
    ``object.__setattr__`` bypass is needed (for the container itself),
    rather than one per attribute.
    """

    __slots__ = ("guard", "intent_builder", "state_provider", "inner_module")

    def __init__(
        self,
        guard: Any,
        intent_builder: Any,
        state_provider: Any,
        inner_module: Any,
    ) -> None:
        self.guard = guard
        self.intent_builder = intent_builder
        self.state_provider = state_provider
        self.inner_module = inner_module


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
        # Store all guard state in a single plain-Python container.  One
        # object.__setattr__ bypass is narrower than four separate ones and
        # survives DSPy / Pydantic upstream changes more robustly.
        object.__setattr__(
            self,
            "_pramanix",
            _PramanixState(guard, intent_builder, state_provider, module),
        )

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

        st: _PramanixState = object.__getattribute__(self, "_pramanix")

        intent = st.intent_builder(**kwargs)
        state = st.state_provider()
        decision = st.guard.verify(intent=intent, state=state)

        if not decision.allowed:
            raise GuardViolationError(decision)

        # Delegate to the wrapped module.
        if hasattr(st.inner_module, "forward"):
            return st.inner_module.forward(**kwargs)
        return st.inner_module(**kwargs)

    def __call__(self, **kwargs: Any) -> Any:
        """Allow direct call syntax ``module(...)`` in addition to DSPy's protocol."""
        return self.forward(**kwargs)
