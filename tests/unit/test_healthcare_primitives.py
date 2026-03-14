# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.primitives.healthcare — 5 HIPAA primitives.

Coverage: SAT pass, UNSAT fail, exact boundary for each primitive.

Primitives under test
---------------------
PHILeastPrivilege, ConsentActive, DosageGradientCheck,
BreakGlassAuth, PediatricDoseBound
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.expressions import Field
from pramanix.primitives.healthcare import (
    BreakGlassAuth,
    ConsentActive,
    DosageGradientCheck,
    PediatricDoseBound,
    PHILeastPrivilege,
)
from pramanix.solver import solve

# ── Field declarations ────────────────────────────────────────────────────────

CLINICIAN = 1
NURSE = 2
ADMIN = 3
AUDITOR = 4
UNKNOWN = 99

_requestor_role = Field("requestor_role", int, "Int")
_consent_given = Field("consent_given", bool, "Bool")
_consent_expiry = Field("consent_expiry", int, "Int")
_new_dose = Field("new_dose", Decimal, "Real")
_current_dose = Field("current_dose", Decimal, "Real")
_emergency_flag = Field("emergency_flag", bool, "Bool")
_approver_id = Field("approver_id", int, "Int")
_dose_per_kg = Field("dose_per_kg", Decimal, "Real")
_weight_kg = Field("weight_kg", Decimal, "Real")

# Shared current time reference for consent tests
_NOW = 1_735_000_000  # 2024-12-24 UTC


# ═══════════════════════════════════════════════════════════════════════════════
# PHILeastPrivilege
# HIPAA 45 CFR § 164.502(b): requestor_role in [CLINICIAN, NURSE]
# ═══════════════════════════════════════════════════════════════════════════════

_INV_PHI = [PHILeastPrivilege(_requestor_role, [CLINICIAN, NURSE])]


class TestPHILeastPrivilege:
    def test_sat_clinician_access(self) -> None:
        result = solve(_INV_PHI, {"requestor_role": CLINICIAN}, timeout_ms=5_000)
        assert result.sat is True

    def test_sat_nurse_access(self) -> None:
        result = solve(_INV_PHI, {"requestor_role": NURSE}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_admin_no_phi_access(self) -> None:
        result = solve(_INV_PHI, {"requestor_role": ADMIN}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "phi_least_privilege" for v in result.violated)

    def test_unsat_unknown_role(self) -> None:
        result = solve(_INV_PHI, {"requestor_role": UNKNOWN}, timeout_ms=5_000)
        assert result.sat is False

    def test_sat_expanded_allowlist(self) -> None:
        """Allow ADMIN when the policy explicitly includes them."""
        inv = [PHILeastPrivilege(_requestor_role, [CLINICIAN, NURSE, ADMIN])]
        result = solve(inv, {"requestor_role": ADMIN}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# ConsentActive
# HIPAA 45 CFR § 164.508: consent_given == True AND consent_expiry > now
# ═══════════════════════════════════════════════════════════════════════════════

_INV_CONSENT = [ConsentActive(_consent_given, _consent_expiry, current_epoch=_NOW)]


class TestConsentActive:
    def test_sat_valid_unexpired_consent(self) -> None:
        result = solve(
            _INV_CONSENT,
            {"consent_given": True, "consent_expiry": _NOW + 86_400},  # expires tomorrow
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_no_consent_on_file(self) -> None:
        result = solve(
            _INV_CONSENT,
            {"consent_given": False, "consent_expiry": _NOW + 86_400},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "consent_active" for v in result.violated)

    def test_unsat_expired_consent(self) -> None:
        result = solve(
            _INV_CONSENT,
            {"consent_given": True, "consent_expiry": _NOW - 1},  # expired 1 second ago
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "consent_active" for v in result.violated)

    def test_unsat_both_conditions_fail(self) -> None:
        result = solve(
            _INV_CONSENT,
            {"consent_given": False, "consent_expiry": _NOW - 86_400},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_boundary_expiry_exactly_at_now_fails(self) -> None:
        """Expiry exactly equal to now — constraint is strictly >, so UNSAT."""
        result = solve(
            _INV_CONSENT,
            {"consent_given": True, "consent_expiry": _NOW},
            timeout_ms=5_000,
        )
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# DosageGradientCheck
# Joint Commission NPSG 03.06.01: (new - current) <= 0.25 * current
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_GRADIENT = Decimal("0.25")
_INV_DOSE_GRADIENT = [DosageGradientCheck(_new_dose, _current_dose, _MAX_GRADIENT)]


class TestDosageGradientCheck:
    def test_sat_small_increase(self) -> None:
        # 10mg → 12mg = 20% increase < 25%
        result = solve(
            _INV_DOSE_GRADIENT,
            {"new_dose": Decimal("12"), "current_dose": Decimal("10")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_excessive_escalation(self) -> None:
        # 10mg → 14mg = 40% increase > 25%
        result = solve(
            _INV_DOSE_GRADIENT,
            {"new_dose": Decimal("14"), "current_dose": Decimal("10")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "dosage_gradient_check" for v in result.violated)

    def test_boundary_exactly_at_gradient_limit(self) -> None:
        # 10mg → 12.5mg = exactly 25% — SAT (<=)
        result = solve(
            _INV_DOSE_GRADIENT,
            {"new_dose": Decimal("12.5"), "current_dose": Decimal("10")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_sat_dose_reduction(self) -> None:
        """Dose reductions always satisfy the increase-cap constraint."""
        result = solve(
            _INV_DOSE_GRADIENT,
            {"new_dose": Decimal("8"), "current_dose": Decimal("10")},
            timeout_ms=5_000,
        )
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# BreakGlassAuth
# HIPAA 45 CFR § 164.312(a)(2)(ii): emergency_flag == True AND approver_id > 0
# ═══════════════════════════════════════════════════════════════════════════════

_INV_BREAK_GLASS = [BreakGlassAuth(_emergency_flag, _approver_id)]


class TestBreakGlassAuth:
    def test_sat_valid_break_glass(self) -> None:
        result = solve(
            _INV_BREAK_GLASS,
            {"emergency_flag": True, "approver_id": 4521},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_flag_set_but_no_approver(self) -> None:
        result = solve(
            _INV_BREAK_GLASS,
            {"emergency_flag": True, "approver_id": 0},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "break_glass_auth" for v in result.violated)

    def test_unsat_approver_set_but_no_emergency(self) -> None:
        """Approver without declared emergency — both conditions required."""
        result = solve(
            _INV_BREAK_GLASS,
            {"emergency_flag": False, "approver_id": 4521},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_unsat_neither_condition(self) -> None:
        result = solve(
            _INV_BREAK_GLASS,
            {"emergency_flag": False, "approver_id": 0},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_boundary_approver_id_exactly_1(self) -> None:
        """Minimum valid approver ID is 1 — exactly at the > 0 boundary."""
        result = solve(
            _INV_BREAK_GLASS,
            {"emergency_flag": True, "approver_id": 1},
            timeout_ms=5_000,
        )
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# PediatricDoseBound
# AAP / FDA PREA: dose_per_kg * weight_kg <= absolute_max
# ═══════════════════════════════════════════════════════════════════════════════

_ABSOLUTE_MAX = Decimal("500")  # 500 mg per dose
_INV_PEDS = [PediatricDoseBound(_dose_per_kg, _weight_kg, _ABSOLUTE_MAX)]


class TestPediatricDoseBound:
    def test_sat_low_dose_light_child(self) -> None:
        # 5 mg/kg × 20 kg = 100 mg ≤ 500 mg
        result = solve(
            _INV_PEDS,
            {"dose_per_kg": Decimal("5"), "weight_kg": Decimal("20")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_high_dose_heavy_child_exceeds_cap(self) -> None:
        # 15 mg/kg × 40 kg = 600 mg > 500 mg
        result = solve(
            _INV_PEDS,
            {"dose_per_kg": Decimal("15"), "weight_kg": Decimal("40")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "pediatric_dose_bound" for v in result.violated)

    def test_boundary_exact_max(self) -> None:
        # 10 mg/kg × 50 kg = 500 mg == 500 mg → SAT (<=)
        result = solve(
            _INV_PEDS,
            {"dose_per_kg": Decimal("10"), "weight_kg": Decimal("50")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_exceeds_by_1mg(self) -> None:
        # 10.1 mg/kg × 50 kg = 505 mg > 500 mg
        result = solve(
            _INV_PEDS,
            {"dose_per_kg": Decimal("10.1"), "weight_kg": Decimal("50")},
            timeout_ms=5_000,
        )
        assert result.sat is False
