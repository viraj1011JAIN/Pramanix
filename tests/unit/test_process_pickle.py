# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase C-3: ProcessPoolExecutor Pickling Safety.

Gate condition (from engineering plan):
    pytest -k 'process_pickle'
    # Non-picklable object in process mode must return Decision(allowed=False,
    #   reason='unpicklable_intent').
    # PicklingError must never propagate to the caller.
"""
from __future__ import annotations

import threading
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy

# ── Test policy ──────────────────────────────────────────────────────────────

_amt = Field("amount", Decimal, "Real")
_bal = Field("balance", Decimal, "Real")


class _SimplePolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [
            (E(_amt) <= Decimal("10000")).named("max_tx"),
            (E(_bal) - E(_amt) >= 0).named("funds_check"),
        ]


# Non-picklable object: a lock
_NON_PICKLABLE = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
# C-3: process-mode pickling pre-flight
# ═══════════════════════════════════════════════════════════════════════════════


class TestProcessPickleSafety:
    @pytest.fixture
    def process_guard(self) -> Guard:
        return Guard(
            _SimplePolicy,
            GuardConfig(execution_mode="async-process", solver_timeout_ms=5000),
        )

    @pytest.mark.asyncio
    async def test_non_picklable_intent_returns_error_decision(
        self, process_guard: Guard
    ) -> None:
        d = await process_guard.verify_async(
            intent={"amount": _NON_PICKLABLE},
            state={"balance": Decimal("500")},
        )
        assert d.allowed is False
        assert "unpicklable_intent" in d.explanation

    @pytest.mark.asyncio
    async def test_non_picklable_state_returns_error_decision(
        self, process_guard: Guard
    ) -> None:
        d = await process_guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"balance": _NON_PICKLABLE},
        )
        assert d.allowed is False
        assert "unpicklable_intent" in d.explanation

    @pytest.mark.asyncio
    async def test_pickling_error_never_propagates(
        self, process_guard: Guard
    ) -> None:
        """PicklingError must be caught — never bubble up to the caller."""
        try:
            d = await process_guard.verify_async(
                intent={"amount": _NON_PICKLABLE},
                state={"balance": Decimal("500")},
            )
        except Exception as exc:
            pytest.fail(f"PicklingError propagated to caller: {exc}")
        assert d.allowed is False

    @pytest.mark.asyncio
    async def test_error_decision_names_non_picklable_field(
        self, process_guard: Guard
    ) -> None:
        d = await process_guard.verify_async(
            intent={"amount": _NON_PICKLABLE},
            state={"balance": Decimal("500")},
        )
        assert "amount" in d.explanation

    @pytest.mark.asyncio
    async def test_error_decision_has_remediation_hint(
        self, process_guard: Guard
    ) -> None:
        d = await process_guard.verify_async(
            intent={"amount": _NON_PICKLABLE},
            state={"balance": Decimal("500")},
        )
        assert "model_dump" in d.explanation

    @pytest.mark.asyncio
    async def test_picklable_values_are_not_blocked(
        self, process_guard: Guard
    ) -> None:
        """Picklable Decimals must pass through to the solver normally."""
        d = await process_guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        # May be SAFE or any solver outcome — but NOT an unpicklable_intent error.
        assert "unpicklable_intent" not in d.explanation


# ═══════════════════════════════════════════════════════════════════════════════
# C-3: assert_process_safe() diagnostic
# ═══════════════════════════════════════════════════════════════════════════════


class TestAssertProcessSafe:
    def _guard(self) -> Guard:
        return Guard(_SimplePolicy, GuardConfig(solver_timeout_ms=5000))

    def test_no_error_for_picklable_intent(self) -> None:
        g = self._guard()
        g.assert_process_safe({"amount": Decimal("100")})  # must not raise

    def test_raises_for_non_picklable_intent(self) -> None:
        g = self._guard()
        with pytest.raises(ValueError, match="assert_process_safe"):
            g.assert_process_safe({"amount": _NON_PICKLABLE})

    def test_error_names_offending_field(self) -> None:
        g = self._guard()
        with pytest.raises(ValueError, match="amount"):
            g.assert_process_safe({"amount": _NON_PICKLABLE})

    def test_error_contains_remediation_hint(self) -> None:
        g = self._guard()
        with pytest.raises(ValueError, match="model_dump"):
            g.assert_process_safe({"amount": _NON_PICKLABLE})

    def test_no_error_when_all_fields_picklable(self) -> None:
        g = self._guard()
        g.assert_process_safe(
            {"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "1.0"},
        )  # must not raise

    def test_raises_for_non_picklable_state(self) -> None:
        g = self._guard()
        with pytest.raises(ValueError, match="balance"):
            g.assert_process_safe(
                {"amount": Decimal("100")},
                state={"balance": _NON_PICKLABLE},
            )

    def test_multiple_bad_fields_all_listed(self) -> None:
        g = self._guard()
        with pytest.raises(ValueError) as exc_info:
            g.assert_process_safe(
                {"amount": _NON_PICKLABLE, "balance": _NON_PICKLABLE}
            )
        msg = str(exc_info.value)
        assert "amount" in msg
        assert "balance" in msg
