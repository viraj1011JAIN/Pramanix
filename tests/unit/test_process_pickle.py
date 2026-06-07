# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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


@pytest.mark.slow
class TestProcessPickleSafety:
    @pytest.fixture
    def process_guard(self) -> Guard:
        return Guard(
            _SimplePolicy,
            GuardConfig(
                execution_mode="async-process",
                solver_timeout_ms=5000,
                worker_warmup=False,
            ),
        )

    @pytest.mark.asyncio
    async def test_non_picklable_intent_returns_error_decision(self, process_guard: Guard) -> None:
        d = await process_guard.verify_async(
            intent={"amount": _NON_PICKLABLE},
            state={"balance": Decimal("500")},
        )
        assert d.allowed is False
        # Either the type-safety check (ipc_type_violation), the picklability check
        # (unpicklable_intent), or the size-check serialisation failure catches this.
        assert (
            "ipc_type_violation" in d.explanation
            or "unpicklable_intent" in d.explanation
            or "could not be size-checked" in d.explanation
        )

    @pytest.mark.asyncio
    async def test_non_picklable_state_returns_error_decision(self, process_guard: Guard) -> None:
        d = await process_guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"balance": _NON_PICKLABLE},
        )
        assert d.allowed is False
        assert (
            "ipc_type_violation" in d.explanation
            or "unpicklable_intent" in d.explanation
            or "could not be size-checked" in d.explanation
        )

    @pytest.mark.asyncio
    async def test_pickling_error_never_propagates(self, process_guard: Guard) -> None:
        """Non-primitive or unpicklable values must be caught — never bubble up to the caller."""
        try:
            d = await process_guard.verify_async(
                intent={"amount": _NON_PICKLABLE},
                state={"balance": Decimal("500")},
            )
        except Exception as exc:
            pytest.fail(f"Serialization error propagated to caller: {exc}")
        assert d.allowed is False

    @pytest.mark.asyncio
    async def test_error_decision_names_non_picklable_field(self, process_guard: Guard) -> None:
        d = await process_guard.verify_async(
            intent={"amount": _NON_PICKLABLE},
            state={"balance": Decimal("500")},
        )
        # IPC check names the offending field; size-check fires first for non-serialisable values
        assert "amount" in d.explanation or "could not be size-checked" in d.explanation

    @pytest.mark.asyncio
    async def test_error_decision_has_remediation_hint(self, process_guard: Guard) -> None:
        d = await process_guard.verify_async(
            intent={"amount": _NON_PICKLABLE},
            state={"balance": Decimal("500")},
        )
        # IPC check includes model_dump hint; size-check fires first for non-serialisable values
        assert "model_dump" in d.explanation or "could not be size-checked" in d.explanation

    @pytest.mark.asyncio
    async def test_picklable_values_are_not_blocked(self, process_guard: Guard) -> None:
        """Picklable Decimals must pass through to the solver normally."""
        d = await process_guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        # May be SAFE or any solver outcome — but NOT an IPC serialization error.
        assert "ipc_type_violation" not in d.explanation
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
            g.assert_process_safe({"amount": _NON_PICKLABLE, "balance": _NON_PICKLABLE})
        msg = str(exc_info.value)
        assert "amount" in msg
        assert "balance" in msg


# ═══════════════════════════════════════════════════════════════════════════════
# C-3b: _check_ipc_type_safety and _is_ipc_safe_value unit tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestIpcTypeSafetyHelpers:
    """Direct unit tests for _check_ipc_type_safety / _is_ipc_safe_value.

    These functions gate the process-mode dispatch path, rejecting custom
    objects with __reduce__ methods before they reach pickle.  The tests
    cover every branch of the allowlist logic.
    """

    def test_all_primitives_safe(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        safe = {
            "a": Decimal("10"),
            "b": True,
            "c": "hello",
            "d": 42,
            "e": 3.14,
            "f": None,
        }
        assert _check_ipc_type_safety(safe) == []

    def test_nested_list_of_primitives_safe(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        assert _check_ipc_type_safety({"x": [1, Decimal("2"), "three"]}) == []

    def test_nested_dict_of_primitives_safe(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        assert _check_ipc_type_safety({"x": {"y": "z", "n": 0}}) == []

    def test_lock_is_unsafe(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        assert _check_ipc_type_safety({"lock": _NON_PICKLABLE}) == ["lock"]

    def test_custom_object_with_reduce_is_unsafe(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        class Evil:
            def __reduce__(self) -> tuple:
                return (eval, ("1+1",))

        assert _check_ipc_type_safety({"x": Evil()}) == ["x"]

    def test_nested_unsafe_in_list_is_caught(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        assert _check_ipc_type_safety({"x": [_NON_PICKLABLE]}) == ["x"]

    def test_nested_unsafe_in_dict_is_caught(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        assert _check_ipc_type_safety({"x": {"y": _NON_PICKLABLE}}) == ["x"]

    def test_empty_dict_is_safe(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        assert _check_ipc_type_safety({}) == []

    def test_multiple_unsafe_fields_all_returned(self) -> None:
        from pramanix.guard import _check_ipc_type_safety

        unsafe = _check_ipc_type_safety({"a": _NON_PICKLABLE, "b": _NON_PICKLABLE, "c": "ok"})
        assert set(unsafe) == {"a", "b"}

    def test_is_ipc_safe_value_leaf_types(self) -> None:
        from pramanix.guard import _is_ipc_safe_value

        assert _is_ipc_safe_value(Decimal("1"))
        assert _is_ipc_safe_value(True)
        assert _is_ipc_safe_value("hello")
        assert _is_ipc_safe_value(42)
        assert _is_ipc_safe_value(3.14)
        assert _is_ipc_safe_value(None)

    def test_is_ipc_safe_value_rejects_object(self) -> None:
        from pramanix.guard import _is_ipc_safe_value

        assert not _is_ipc_safe_value(_NON_PICKLABLE)

    def test_is_ipc_safe_value_empty_list_safe(self) -> None:
        from pramanix.guard import _is_ipc_safe_value

        assert _is_ipc_safe_value([])

    def test_is_ipc_safe_value_empty_dict_safe(self) -> None:
        from pramanix.guard import _is_ipc_safe_value

        assert _is_ipc_safe_value({})
