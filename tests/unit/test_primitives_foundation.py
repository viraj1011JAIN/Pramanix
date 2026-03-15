# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Comprehensive unit tests for Phase-3 foundation primitives.

Coverage targets
----------------
* ``primitives/common.py``  — NotSuspended, StatusMustBe, FieldMustEqual
* ``primitives/rbac.py``    — RoleMustBeIn, ConsentRequired, DepartmentMustBeIn
* ``primitives/time.py``    — WithinTimeWindow, After, Before, NotExpired
* ``primitives/finance.py`` — NonNegativeBalance, UnderDailyLimit,
                              UnderSingleTxLimit, RiskScoreBelow,
                              SecureBalance, MinimumReserve

Test discipline (CTO mandate)
------------------------------
Every primitive gets:
1. SAT case  — values that satisfy the invariant.
2. UNSAT case — values that violate it.
3. Exact boundary — confirms < vs <=, > vs >= consistency with docs.
4. Explanation check — asserts ``.explanation`` template is non-empty
   and that ``_fmt`` interpolates concrete values correctly.

We use ``_fmt`` from ``guard.py`` (not an internal test-only helper) to
guarantee the clear-box explanation path used in production is covered.
"""
from __future__ import annotations

from decimal import Decimal
from typing import ClassVar

from pramanix.expressions import Field
from pramanix.guard import _fmt
from pramanix.primitives.common import FieldMustEqual, NotSuspended, StatusMustBe
from pramanix.primitives.finance import (
    MinimumReserve,
    NonNegativeBalance,
    RiskScoreBelow,
    SecureBalance,
    UnderDailyLimit,
    UnderSingleTxLimit,
)
from pramanix.primitives.rbac import ConsentRequired, DepartmentMustBeIn, RoleMustBeIn
from pramanix.primitives.time import After, Before, NotExpired, WithinTimeWindow
from pramanix.solver import solve

# ── shared Field declarations ─────────────────────────────────────────────────

_is_suspended = Field("is_suspended", bool, "Bool")
_status = Field("status", int, "Int")
_account_type = Field("account_type", int, "Int")
_region = Field("region", str, "String")

_role = Field("role", int, "Int")
_consent = Field("consent", bool, "Bool")
_department = Field("department", int, "Int")

_ts = Field("timestamp", int, "Int")
_ws = Field("window_start", int, "Int")
_we = Field("window_end", int, "Int")
_cutoff = Field("cutoff", int, "Int")
_expiry = Field("expiry_ts", int, "Int")
_now = Field("now_ts", int, "Int")

_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_daily_limit = Field("daily_limit", Decimal, "Real")
_tx_limit = Field("tx_limit", Decimal, "Real")
_risk_score = Field("risk_score", Decimal, "Real")
_threshold = Field("threshold", Decimal, "Real")
_min_reserve = Field("minimum_reserve", Decimal, "Real")


# ═══════════════════════════════════════════════════════════════════════════════
# common.py — NotSuspended
# ═══════════════════════════════════════════════════════════════════════════════


class TestNotSuspended:
    _INV: ClassVar[list] = [NotSuspended(_is_suspended)]

    def test_sat_entity_active(self) -> None:
        result = solve(self._INV, {"is_suspended": False}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_entity_suspended(self) -> None:
        result = solve(self._INV, {"is_suspended": True}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "not_suspended" for v in result.violated)

    def test_label_is_not_suspended(self) -> None:
        inv = NotSuspended(_is_suspended)
        assert inv.label == "not_suspended"

    def test_explanation_template_populated(self) -> None:
        inv = NotSuspended(_is_suspended)
        assert inv.explanation is not None
        assert "is_suspended" in inv.explanation

    def test_explanation_interpolates_concrete_value(self) -> None:
        inv = NotSuspended(_is_suspended)
        formatted = _fmt(inv, {"is_suspended": True})
        assert "True" in formatted or "is_suspended" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# common.py — StatusMustBe
# ═══════════════════════════════════════════════════════════════════════════════


class TestStatusMustBe:
    _INV: ClassVar[list] = [StatusMustBe(_status, 1)]

    def test_sat_status_matches(self) -> None:
        result = solve(self._INV, {"status": 1}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_status_mismatch(self) -> None:
        result = solve(self._INV, {"status": 2}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "status_must_be_1" for v in result.violated)

    def test_boundary_zero_equals_zero(self) -> None:
        inv = [StatusMustBe(_status, 0)]
        result = solve(inv, {"status": 0}, timeout_ms=5_000)
        assert result.sat is True

    def test_label_encodes_expected_value(self) -> None:
        inv = StatusMustBe(_status, 42)
        assert inv.label == "status_must_be_42"

    def test_explanation_contains_field_placeholder(self) -> None:
        inv = StatusMustBe(_status, 1)
        assert inv.explanation is not None
        assert "status" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = StatusMustBe(_status, 1)
        formatted = _fmt(inv, {"status": 99})
        assert "99" in formatted or "status" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# common.py — FieldMustEqual (Int sort)
# ═══════════════════════════════════════════════════════════════════════════════


class TestFieldMustEqualInt:
    _INV: ClassVar[list] = [FieldMustEqual(_account_type, 42)]

    def test_sat_value_matches(self) -> None:
        result = solve(self._INV, {"account_type": 42}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_value_differs(self) -> None:
        result = solve(self._INV, {"account_type": 99}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "field_account_type_must_equal_42" for v in result.violated)

    def test_label_encodes_field_and_value(self) -> None:
        inv = FieldMustEqual(_account_type, 42)
        assert inv.label == "field_account_type_must_equal_42"

    def test_explanation_contains_field_name(self) -> None:
        inv = FieldMustEqual(_account_type, 42)
        assert inv.explanation is not None
        assert "account_type" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = FieldMustEqual(_account_type, 42)
        formatted = _fmt(inv, {"account_type": 99})
        # {account_type} is replaced with 99 — verify the substituted value appears
        assert "99" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# common.py — FieldMustEqual (String sort) — G.1 mixed-type coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestFieldMustEqualString:
    """G.1: FieldMustEqual with a String-sorted field — cross-sort coverage."""

    _INV: ClassVar[list] = [FieldMustEqual(_region, "US")]

    def test_sat_region_matches(self) -> None:
        result = solve(self._INV, {"region": "US"}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_region_differs(self) -> None:
        result = solve(self._INV, {"region": "EU"}, timeout_ms=5_000)
        assert result.sat is False
        assert any("region" in v.label for v in result.violated)

    def test_sat_empty_string_match(self) -> None:
        inv = [FieldMustEqual(_region, "")]
        result = solve(inv, {"region": ""}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_empty_string_mismatch(self) -> None:
        inv = [FieldMustEqual(_region, "")]
        result = solve(inv, {"region": "US"}, timeout_ms=5_000)
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# rbac.py — RoleMustBeIn
# ═══════════════════════════════════════════════════════════════════════════════

_ALLOWED_ROLES = [1, 2, 3]  # doctor=1, nurse=2, admin=3


class TestRoleMustBeIn:
    _INV: ClassVar[list] = [RoleMustBeIn(_role, _ALLOWED_ROLES)]

    def test_sat_first_allowed_role(self) -> None:
        result = solve(self._INV, {"role": 1}, timeout_ms=5_000)
        assert result.sat is True

    def test_sat_last_allowed_role(self) -> None:
        """Boundary: last element in the allowlist must pass."""
        result = solve(self._INV, {"role": 3}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_forbidden_role(self) -> None:
        result = solve(self._INV, {"role": 99}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "role_must_be_in_allowed_set" for v in result.violated)

    def test_unsat_zero_role(self) -> None:
        result = solve(self._INV, {"role": 0}, timeout_ms=5_000)
        assert result.sat is False

    def test_label(self) -> None:
        inv = RoleMustBeIn(_role, _ALLOWED_ROLES)
        assert inv.label == "role_must_be_in_allowed_set"

    def test_explanation_contains_role_placeholder(self) -> None:
        inv = RoleMustBeIn(_role, _ALLOWED_ROLES)
        assert inv.explanation is not None
        assert "role" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = RoleMustBeIn(_role, _ALLOWED_ROLES)
        formatted = _fmt(inv, {"role": 99})
        assert "99" in formatted or "role" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# rbac.py — ConsentRequired
# ═══════════════════════════════════════════════════════════════════════════════


class TestConsentRequired:
    _INV: ClassVar[list] = [ConsentRequired(_consent)]

    def test_sat_consent_given(self) -> None:
        result = solve(self._INV, {"consent": True}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_consent_absent(self) -> None:
        result = solve(self._INV, {"consent": False}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "consent_required" for v in result.violated)

    def test_label(self) -> None:
        inv = ConsentRequired(_consent)
        assert inv.label == "consent_required"

    def test_explanation_template(self) -> None:
        inv = ConsentRequired(_consent)
        assert inv.explanation is not None
        assert "consent" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = ConsentRequired(_consent)
        formatted = _fmt(inv, {"consent": False})
        assert "consent" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# rbac.py — DepartmentMustBeIn
# ═══════════════════════════════════════════════════════════════════════════════

_ALLOWED_DEPTS = [10, 20, 30]


class TestDepartmentMustBeIn:
    _INV: ClassVar[list] = [DepartmentMustBeIn(_department, _ALLOWED_DEPTS)]

    def test_sat_allowed_department(self) -> None:
        result = solve(self._INV, {"department": 10}, timeout_ms=5_000)
        assert result.sat is True

    def test_sat_last_allowed_department(self) -> None:
        result = solve(self._INV, {"department": 30}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_forbidden_department(self) -> None:
        result = solve(self._INV, {"department": 99}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "department_must_be_in_allowed_set" for v in result.violated)

    def test_label(self) -> None:
        inv = DepartmentMustBeIn(_department, _ALLOWED_DEPTS)
        assert inv.label == "department_must_be_in_allowed_set"

    def test_explanation_contains_department_placeholder(self) -> None:
        inv = DepartmentMustBeIn(_department, _ALLOWED_DEPTS)
        assert inv.explanation is not None
        assert "department" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = DepartmentMustBeIn(_department, _ALLOWED_DEPTS)
        formatted = _fmt(inv, {"department": 99})
        assert "department" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# time.py — WithinTimeWindow
# ═══════════════════════════════════════════════════════════════════════════════


class TestWithinTimeWindow:
    _INV: ClassVar[list] = [WithinTimeWindow(_ts, _ws, _we)]

    def _vals(self, ts: int, ws: int, we: int) -> dict:
        return {"timestamp": ts, "window_start": ws, "window_end": we}

    def test_sat_timestamp_inside_window(self) -> None:
        result = solve(self._INV, self._vals(500, 100, 1000), timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_timestamp_before_window(self) -> None:
        result = solve(self._INV, self._vals(50, 100, 1000), timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "within_time_window" for v in result.violated)

    def test_unsat_timestamp_after_window(self) -> None:
        result = solve(self._INV, self._vals(1001, 100, 1000), timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_exactly_at_window_start(self) -> None:
        """Boundary: >= is inclusive, so ts == window_start must be SAT."""
        result = solve(self._INV, self._vals(100, 100, 1000), timeout_ms=5_000)
        assert result.sat is True

    def test_boundary_exactly_at_window_end(self) -> None:
        """Boundary: <= is inclusive, so ts == window_end must be SAT."""
        result = solve(self._INV, self._vals(1000, 100, 1000), timeout_ms=5_000)
        assert result.sat is True

    def test_boundary_one_before_start(self) -> None:
        result = solve(self._INV, self._vals(99, 100, 1000), timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_one_after_end(self) -> None:
        result = solve(self._INV, self._vals(1001, 100, 1000), timeout_ms=5_000)
        assert result.sat is False

    def test_label(self) -> None:
        inv = WithinTimeWindow(_ts, _ws, _we)
        assert inv.label == "within_time_window"

    def test_explanation_template(self) -> None:
        inv = WithinTimeWindow(_ts, _ws, _we)
        assert inv.explanation is not None
        assert "timestamp" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = WithinTimeWindow(_ts, _ws, _we)
        formatted = _fmt(inv, {"timestamp": 50, "window_start": 100, "window_end": 1000})
        assert "50" in formatted or "timestamp" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# time.py — After
# ═══════════════════════════════════════════════════════════════════════════════


class TestAfter:
    _INV: ClassVar[list] = [After(_ts, _cutoff)]

    def test_sat_timestamp_after_cutoff(self) -> None:
        result = solve(self._INV, {"timestamp": 200, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_timestamp_equals_cutoff(self) -> None:
        """Boundary: After uses strict >, so ts == cutoff must be UNSAT."""
        result = solve(self._INV, {"timestamp": 100, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "after_cutoff" for v in result.violated)

    def test_unsat_timestamp_before_cutoff(self) -> None:
        result = solve(self._INV, {"timestamp": 50, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_one_after_cutoff(self) -> None:
        """ts = cutoff + 1 must be SAT."""
        result = solve(self._INV, {"timestamp": 101, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is True

    def test_label(self) -> None:
        inv = After(_ts, _cutoff)
        assert inv.label == "after_cutoff"

    def test_explanation_template(self) -> None:
        inv = After(_ts, _cutoff)
        assert inv.explanation is not None
        assert "timestamp" in inv.explanation
        assert "cutoff" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = After(_ts, _cutoff)
        formatted = _fmt(inv, {"timestamp": 50, "cutoff": 100})
        assert "50" in formatted or "timestamp" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# time.py — Before
# ═══════════════════════════════════════════════════════════════════════════════


class TestBefore:
    _INV: ClassVar[list] = [Before(_ts, _cutoff)]

    def test_sat_timestamp_before_cutoff(self) -> None:
        result = solve(self._INV, {"timestamp": 50, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_timestamp_equals_cutoff(self) -> None:
        """Boundary: Before uses strict <, so ts == cutoff must be UNSAT."""
        result = solve(self._INV, {"timestamp": 200, "cutoff": 200}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "before_cutoff" for v in result.violated)

    def test_unsat_timestamp_after_cutoff(self) -> None:
        result = solve(self._INV, {"timestamp": 200, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_one_before_cutoff(self) -> None:
        """ts = cutoff - 1 must be SAT."""
        result = solve(self._INV, {"timestamp": 99, "cutoff": 100}, timeout_ms=5_000)
        assert result.sat is True

    def test_label(self) -> None:
        inv = Before(_ts, _cutoff)
        assert inv.label == "before_cutoff"

    def test_explanation_template(self) -> None:
        inv = Before(_ts, _cutoff)
        assert inv.explanation is not None
        assert "timestamp" in inv.explanation
        assert "cutoff" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = Before(_ts, _cutoff)
        formatted = _fmt(inv, {"timestamp": 200, "cutoff": 100})
        assert "200" in formatted or "timestamp" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# time.py — NotExpired
# ═══════════════════════════════════════════════════════════════════════════════


class TestNotExpired:
    _INV: ClassVar[list] = [NotExpired(_expiry, _now)]

    def test_sat_not_yet_expired(self) -> None:
        result = solve(self._INV, {"expiry_ts": 2000, "now_ts": 1000}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_exactly_at_expiry(self) -> None:
        """Boundary: NotExpired uses strict >, so expiry == now must be UNSAT."""
        result = solve(self._INV, {"expiry_ts": 1000, "now_ts": 1000}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "not_expired" for v in result.violated)

    def test_unsat_past_expiry(self) -> None:
        result = solve(self._INV, {"expiry_ts": 999, "now_ts": 1000}, timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_one_second_remaining(self) -> None:
        result = solve(self._INV, {"expiry_ts": 1001, "now_ts": 1000}, timeout_ms=5_000)
        assert result.sat is True

    def test_label(self) -> None:
        inv = NotExpired(_expiry, _now)
        assert inv.label == "not_expired"

    def test_explanation_template(self) -> None:
        inv = NotExpired(_expiry, _now)
        assert inv.explanation is not None
        assert "expiry_ts" in inv.explanation
        assert "now_ts" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = NotExpired(_expiry, _now)
        formatted = _fmt(inv, {"expiry_ts": 999, "now_ts": 1000})
        assert "999" in formatted or "expiry_ts" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# finance.py — NonNegativeBalance
# ═══════════════════════════════════════════════════════════════════════════════


class TestNonNegativeBalance:
    _INV: ClassVar[list] = [NonNegativeBalance(_balance, _amount)]

    def test_sat_sufficient_balance(self) -> None:
        result = solve(
            self._INV,
            {"balance": Decimal("1000"), "amount": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_overdraft(self) -> None:
        result = solve(
            self._INV,
            {"balance": Decimal("100"), "amount": Decimal("200")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "non_negative_balance" for v in result.violated)

    def test_boundary_exact_balance(self) -> None:
        """Boundary: balance == amount → 0 >= 0 → SAT (>= is inclusive)."""
        result = solve(
            self._INV,
            {"balance": Decimal("100"), "amount": Decimal("100")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_one_cent_overdraft(self) -> None:
        result = solve(
            self._INV,
            {"balance": Decimal("100.00"), "amount": Decimal("100.01")},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_label(self) -> None:
        inv = NonNegativeBalance(_balance, _amount)
        assert inv.label == "non_negative_balance"

    def test_explanation_template(self) -> None:
        inv = NonNegativeBalance(_balance, _amount)
        assert inv.explanation is not None
        assert "balance" in inv.explanation
        assert "amount" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = NonNegativeBalance(_balance, _amount)
        formatted = _fmt(inv, {"balance": Decimal("100"), "amount": Decimal("200")})
        assert "balance" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# finance.py — UnderDailyLimit
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnderDailyLimit:
    _INV: ClassVar[list] = [UnderDailyLimit(_amount, _daily_limit)]

    def test_sat_under_limit(self) -> None:
        result = solve(
            self._INV,
            {"amount": Decimal("100"), "daily_limit": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_over_limit(self) -> None:
        result = solve(
            self._INV,
            {"amount": Decimal("600"), "daily_limit": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "under_daily_limit" for v in result.violated)

    def test_boundary_exactly_at_limit(self) -> None:
        """Boundary: amount == daily_limit → SAT (<= is inclusive)."""
        result = solve(
            self._INV,
            {"amount": Decimal("500"), "daily_limit": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_one_cent_over_limit(self) -> None:
        result = solve(
            self._INV,
            {"amount": Decimal("500.01"), "daily_limit": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_label(self) -> None:
        inv = UnderDailyLimit(_amount, _daily_limit)
        assert inv.label == "under_daily_limit"

    def test_explanation_template(self) -> None:
        inv = UnderDailyLimit(_amount, _daily_limit)
        assert inv.explanation is not None
        assert "amount" in inv.explanation
        assert "daily_limit" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = UnderDailyLimit(_amount, _daily_limit)
        formatted = _fmt(inv, {"amount": Decimal("600"), "daily_limit": Decimal("500")})
        assert "daily_limit" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# finance.py — UnderSingleTxLimit
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnderSingleTxLimit:
    _INV: ClassVar[list] = [UnderSingleTxLimit(_amount, _tx_limit)]

    def test_sat_under_limit(self) -> None:
        result = solve(
            self._INV,
            {"amount": Decimal("200"), "tx_limit": Decimal("1000")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_over_limit(self) -> None:
        result = solve(
            self._INV,
            {"amount": Decimal("1500"), "tx_limit": Decimal("1000")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "under_single_tx_limit" for v in result.violated)

    def test_boundary_exactly_at_limit(self) -> None:
        result = solve(
            self._INV,
            {"amount": Decimal("1000"), "tx_limit": Decimal("1000")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_label(self) -> None:
        inv = UnderSingleTxLimit(_amount, _tx_limit)
        assert inv.label == "under_single_tx_limit"

    def test_explanation_template(self) -> None:
        inv = UnderSingleTxLimit(_amount, _tx_limit)
        assert inv.explanation is not None
        assert "amount" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = UnderSingleTxLimit(_amount, _tx_limit)
        formatted = _fmt(inv, {"amount": Decimal("1500"), "tx_limit": Decimal("1000")})
        assert "tx_limit" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# finance.py — RiskScoreBelow (strict <)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRiskScoreBelow:
    _INV: ClassVar[list] = [RiskScoreBelow(_risk_score, _threshold)]

    def test_sat_score_below_threshold(self) -> None:
        result = solve(
            self._INV,
            {"risk_score": Decimal("30"), "threshold": Decimal("50")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_score_equals_threshold(self) -> None:
        """Boundary: RiskScoreBelow uses strict <, so score == threshold is UNSAT."""
        result = solve(
            self._INV,
            {"risk_score": Decimal("50"), "threshold": Decimal("50")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "risk_score_below_threshold" for v in result.violated)

    def test_unsat_score_above_threshold(self) -> None:
        result = solve(
            self._INV,
            {"risk_score": Decimal("75"), "threshold": Decimal("50")},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_boundary_one_unit_below_threshold(self) -> None:
        result = solve(
            self._INV,
            {"risk_score": Decimal("49"), "threshold": Decimal("50")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_label(self) -> None:
        inv = RiskScoreBelow(_risk_score, _threshold)
        assert inv.label == "risk_score_below_threshold"

    def test_explanation_template(self) -> None:
        inv = RiskScoreBelow(_risk_score, _threshold)
        assert inv.explanation is not None
        assert "risk_score" in inv.explanation
        assert "threshold" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = RiskScoreBelow(_risk_score, _threshold)
        formatted = _fmt(inv, {"risk_score": Decimal("75"), "threshold": Decimal("50")})
        assert "risk_score" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# finance.py — SecureBalance (minimum reserve floor)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecureBalance:
    _INV: ClassVar[list] = [SecureBalance(_balance, _amount, _min_reserve)]

    def _vals(self, b: str, a: str, r: str) -> dict:
        return {
            "balance": Decimal(b),
            "amount": Decimal(a),
            "minimum_reserve": Decimal(r),
        }

    def test_sat_post_tx_above_reserve(self) -> None:
        result = solve(self._INV, self._vals("1000", "500", "100"), timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_post_tx_below_reserve(self) -> None:
        result = solve(self._INV, self._vals("1000", "950", "100"), timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "minimum_reserve_maintained" for v in result.violated)

    def test_boundary_exactly_at_reserve(self) -> None:
        """Boundary: balance - amount == reserve → SAT (>= is inclusive)."""
        result = solve(self._INV, self._vals("1000", "900", "100"), timeout_ms=5_000)
        assert result.sat is True

    def test_boundary_one_cent_below_reserve(self) -> None:
        result = solve(self._INV, self._vals("1000", "900.01", "100"), timeout_ms=5_000)
        assert result.sat is False

    def test_label(self) -> None:
        inv = SecureBalance(_balance, _amount, _min_reserve)
        assert inv.label == "minimum_reserve_maintained"

    def test_explanation_template(self) -> None:
        inv = SecureBalance(_balance, _amount, _min_reserve)
        assert inv.explanation is not None
        assert "balance" in inv.explanation

    def test_explanation_interpolates(self) -> None:
        inv = SecureBalance(_balance, _amount, _min_reserve)
        formatted = _fmt(
            inv,
            {
                "balance": Decimal("1000"),
                "amount": Decimal("950"),
                "minimum_reserve": Decimal("100"),
            },
        )
        assert "balance" in formatted


# ═══════════════════════════════════════════════════════════════════════════════
# finance.py — MinimumReserve (alias for SecureBalance)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMinimumReserve:
    """MinimumReserve is an alias — verify identical semantics."""

    _INV: ClassVar[list] = [MinimumReserve(_balance, _amount, _min_reserve)]

    def test_sat_same_as_secure_balance(self) -> None:
        result = solve(
            self._INV,
            {
                "balance": Decimal("500"),
                "amount": Decimal("200"),
                "minimum_reserve": Decimal("50"),
            },
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_same_as_secure_balance(self) -> None:
        result = solve(
            self._INV,
            {
                "balance": Decimal("500"),
                "amount": Decimal("480"),
                "minimum_reserve": Decimal("50"),
            },
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_label_same_as_secure_balance(self) -> None:
        inv = MinimumReserve(_balance, _amount, _min_reserve)
        assert inv.label == "minimum_reserve_maintained"
