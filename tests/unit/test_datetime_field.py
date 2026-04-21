# SPDX-License-Identifier: AGPL-3.0-only
# Phase A-4: Tests for DatetimeField, within_seconds, is_before, is_business_hours
"""Gate: TradeWindowPolicy must ALLOW within-window datetimes and BLOCK outside."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from pramanix.expressions import (
    ConstraintExpr,
    DatetimeField,
    E,
    Field,
)
from pramanix.exceptions import FieldTypeError


UTC = timezone.utc


# ── DatetimeField construction ────────────────────────────────────────────────


class TestDatetimeField:
    def test_produces_field(self) -> None:
        f = DatetimeField("trade_time")
        assert isinstance(f, Field)

    def test_z3_type_is_int(self) -> None:
        f = DatetimeField("trade_time")
        assert f.z3_type == "Int"

    def test_python_type_is_datetime(self) -> None:
        f = DatetimeField("trade_time")
        assert f.python_type is datetime

    def test_name_preserved(self) -> None:
        f = DatetimeField("my_ts")
        assert f.name == "my_ts"


# ── z3_val datetime conversion ────────────────────────────────────────────────


class TestDatetimeConversion:
    def test_aware_datetime_converts(self) -> None:
        from pramanix.transpiler import z3_val
        f = DatetimeField("ts")
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        result = z3_val(f, now)
        import z3
        assert result is not None
        assert int(str(result)) == int(now.timestamp())

    def test_naive_datetime_raises(self) -> None:
        from pramanix.transpiler import z3_val
        f = DatetimeField("ts")
        naive = datetime(2026, 1, 1, 12, 0, 0)
        with pytest.raises(FieldTypeError, match="naive datetime"):
            z3_val(f, naive)

    def test_int_still_works(self) -> None:
        from pramanix.transpiler import z3_val
        f = DatetimeField("ts")
        result = z3_val(f, 1_700_000_000)
        assert result is not None


# ── within_seconds ────────────────────────────────────────────────────────────


class TestWithinSeconds:
    def test_returns_constraint_expr(self) -> None:
        f = DatetimeField("ts")
        expr = E(f).within_seconds(3600)
        assert isinstance(expr, ConstraintExpr)

    def test_negative_duration_raises(self) -> None:
        f = DatetimeField("ts")
        with pytest.raises(Exception, match="non-negative"):
            E(f).within_seconds(-1)

    def test_non_int_raises(self) -> None:
        f = DatetimeField("ts")
        with pytest.raises(Exception):
            E(f).within_seconds(1.5)  # type: ignore[arg-type]

    def test_zero_duration_valid(self) -> None:
        f = DatetimeField("ts")
        expr = E(f).within_seconds(0)
        assert isinstance(expr, ConstraintExpr)


# ── Gate: TradeWindowPolicy — full Guard integration ─────────────────────────


def _make_trade_window_guard(window_seconds: int = 3600) -> Any:
    from pramanix.guard import Guard, GuardConfig
    from pramanix.policy import Policy

    trade_time = DatetimeField("trade_time")

    class TradeWindowPolicy(Policy):
        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return [
                E(trade_time).within_seconds(window_seconds).named("within_window"),
            ]

    return Guard(TradeWindowPolicy, GuardConfig(solver_timeout_ms=5000))


class TestTradeWindowGuardIntegration:
    """Gate: ALLOW within window, BLOCK outside — no pre-computed timestamps."""

    def test_recent_timestamp_allowed(self) -> None:
        guard = _make_trade_window_guard(3600)
        now = datetime.now(UTC)
        recent = now - timedelta(seconds=100)
        d = guard.verify(intent={"trade_time": recent}, state={})
        assert d.allowed is True

    def test_just_at_boundary_allowed(self) -> None:
        guard = _make_trade_window_guard(3600)
        now = datetime.now(UTC)
        boundary = now - timedelta(seconds=3598)  # leave 2s margin for test execution
        d = guard.verify(intent={"trade_time": boundary}, state={})
        assert d.allowed is True

    def test_outside_window_blocked(self) -> None:
        guard = _make_trade_window_guard(3600)
        now = datetime.now(UTC)
        old = now - timedelta(hours=2)
        d = guard.verify(intent={"trade_time": old}, state={})
        assert d.allowed is False

    def test_future_timestamp_blocked(self) -> None:
        guard = _make_trade_window_guard(3600)
        now = datetime.now(UTC)
        future = now + timedelta(seconds=100)
        d = guard.verify(intent={"trade_time": future}, state={})
        assert d.allowed is False

    def test_naive_datetime_blocked(self) -> None:
        guard = _make_trade_window_guard(3600)
        naive = datetime(2026, 1, 1, 12, 0, 0)
        d = guard.verify(intent={"trade_time": naive}, state={})
        assert d.allowed is False

    def test_violated_invariant_reported(self) -> None:
        guard = _make_trade_window_guard(3600)
        old = datetime.now(UTC) - timedelta(hours=3)
        d = guard.verify(intent={"trade_time": old}, state={})
        assert d.allowed is False
        assert "within_window" in d.violated_invariants

    def test_narrow_window(self) -> None:
        guard = _make_trade_window_guard(60)
        now = datetime.now(UTC)
        d = guard.verify(intent={"trade_time": now - timedelta(seconds=30)}, state={})
        assert d.allowed is True
        d2 = guard.verify(intent={"trade_time": now - timedelta(seconds=120)}, state={})
        assert d2.allowed is False


# ── is_before ─────────────────────────────────────────────────────────────────


class TestIsBefore:
    def test_is_before_returns_constraint(self) -> None:
        trade_time = DatetimeField("trade_time")
        expiry = DatetimeField("expiry")
        expr = E(trade_time).is_before(E(expiry))
        assert isinstance(expr, ConstraintExpr)

    def test_is_before_guard_integration(self) -> None:
        from pramanix.guard import Guard, GuardConfig
        from pramanix.policy import Policy

        trade_time = DatetimeField("trade_time")
        expiry = DatetimeField("expiry")

        class ExpiryPolicy(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    E(trade_time).is_before(E(expiry)).named("trade_before_expiry"),
                ]

        guard = Guard(ExpiryPolicy, GuardConfig(solver_timeout_ms=5000))
        now = datetime.now(UTC)
        d = guard.verify(
            intent={"trade_time": now, "expiry": now + timedelta(hours=1)},
            state={},
        )
        assert d.allowed is True

        d2 = guard.verify(
            intent={"trade_time": now + timedelta(hours=2), "expiry": now + timedelta(hours=1)},
            state={},
        )
        assert d2.allowed is False


# ── is_business_hours ─────────────────────────────────────────────────────────


class TestIsBusinessHours:
    def test_returns_constraint(self) -> None:
        trade_time = DatetimeField("trade_time")
        expr = E(trade_time).is_business_hours()
        assert isinstance(expr, ConstraintExpr)

    def test_monday_noon_utc_allowed(self) -> None:
        from pramanix.guard import Guard, GuardConfig
        from pramanix.policy import Policy

        trade_time = DatetimeField("trade_time")

        class BizHoursPolicy(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    E(trade_time).is_business_hours().named("business_hours"),
                ]

        guard = Guard(BizHoursPolicy, GuardConfig(solver_timeout_ms=5000))
        # 2026-04-20 is a Monday; noon UTC is business hours
        monday_noon = datetime(2026, 4, 20, 12, 0, 0, tzinfo=UTC)
        d = guard.verify(intent={"trade_time": monday_noon}, state={})
        assert d.allowed is True

    def test_saturday_blocked(self) -> None:
        from pramanix.guard import Guard, GuardConfig
        from pramanix.policy import Policy

        trade_time = DatetimeField("trade_time")

        class BizHoursPolicy(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    E(trade_time).is_business_hours().named("business_hours"),
                ]

        guard = Guard(BizHoursPolicy, GuardConfig(solver_timeout_ms=5000))
        # 2026-04-18 is a Saturday
        saturday = datetime(2026, 4, 18, 12, 0, 0, tzinfo=UTC)
        d = guard.verify(intent={"trade_time": saturday}, state={})
        assert d.allowed is False

    def test_weekday_outside_hours_blocked(self) -> None:
        from pramanix.guard import Guard, GuardConfig
        from pramanix.policy import Policy

        trade_time = DatetimeField("trade_time")

        class BizHoursPolicy(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    E(trade_time).is_business_hours().named("business_hours"),
                ]

        guard = Guard(BizHoursPolicy, GuardConfig(solver_timeout_ms=5000))
        # Monday at 2am UTC — outside business hours
        monday_2am = datetime(2026, 4, 20, 2, 0, 0, tzinfo=UTC)
        d = guard.verify(intent={"trade_time": monday_2am}, state={})
        assert d.allowed is False
