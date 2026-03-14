#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
healthcare_phi_access.py — HIPAA-compliant PHI access control via Z3.

Demonstrates three HIPAA primitives working in concert:
  ① PHILeastPrivilege  — 45 CFR § 164.502(b) minimum-necessary rule
  ② ConsentActive      — 45 CFR § 164.508 authorisation expiry check
  ③ BreakGlassAuth     — 45 CFR § 164.312(a)(2)(ii) emergency access

This is the pattern that hospital CTOs recognise immediately: the constraint
labels map 1:1 to HIPAA Technical Safeguard citations.  No NLP, no prompting,
no hallucination risk — every access decision is Z3-verified.

Role encoding (Z3 uses integer sorts, not string sorts)
--------------------------------------------------------
    CLINICIAN = 1   (treating physician)
    NURSE     = 2   (bedside nurse)
    ADMIN     = 3   (billing/scheduling)
    AUDITOR   = 4   (compliance team)
    PATIENT   = 5   (self-access portal)

Run::

    python examples/healthcare_phi_access.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pydantic import BaseModel

from pramanix import Decision, Field, Guard, GuardConfig, Policy
from pramanix.primitives.healthcare import BreakGlassAuth, ConsentActive, PHILeastPrivilege

# ── Role constants ─────────────────────────────────────────────────────────────
CLINICIAN = 1
NURSE = 2
ADMIN = 3
AUDITOR = 4
PATIENT = 5

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Domain models
# ═══════════════════════════════════════════════════════════════════════════════

_NOW = 1_735_000_000  # 2024-12-24 ~00:00 UTC (reference timestamp for this demo)


class PHIAccessIntent(BaseModel):
    """AI agent / care-coordination system's PHI access request."""

    requestor_role: int
    """Integer-encoded clinical role of the requesting user."""

    emergency_flag: bool
    """True when requesting emergency (break-glass) override access."""

    approver_id: int
    """Supervisor employee ID authorising the break-glass event (0 = none)."""


class PatientConsentState(BaseModel):
    """Patient consent record retrieved from the EHR consent registry."""

    state_version: str
    consent_given: bool
    consent_expiry: int
    """UNIX timestamp of authorisation expiry."""


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Policy
# ═══════════════════════════════════════════════════════════════════════════════


class HIPAAAccessPolicy(Policy):
    """HIPAA PHI access control — three concurrent technical safeguards.

    Standard access path (emergency_flag=False):
        ① Role must be in {CLINICIAN, NURSE} (minimum-necessary)
        ② Patient authorisation must be current and unexpired

    Emergency access path (emergency_flag=True):
        ③ Break-glass must be declared AND a supervisor approver_id must be on record
        (HIPAA requires every break-glass event to be logged and audited)

    Note: emergency path REPLACES ①②; both paths cannot be active simultaneously.
    This example uses standard path (invariants ①②) and separately tests ③.
    """

    class Meta:
        version = "0.6"
        intent_model = PHIAccessIntent
        state_model = PatientConsentState

    requestor_role = Field("requestor_role", int, "Int")
    consent_given = Field("consent_given", bool, "Bool")
    consent_expiry = Field("consent_expiry", int, "Int")

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            PHILeastPrivilege(cls.requestor_role, [CLINICIAN, NURSE]),
            ConsentActive(cls.consent_given, cls.consent_expiry, current_epoch=_NOW),
        ]


class BreakGlassPolicy(Policy):
    """Emergency break-glass path — HIPAA 45 CFR § 164.312(a)(2)(ii)."""

    class Meta:
        version = "0.6"
        intent_model = PHIAccessIntent
        state_model = PatientConsentState

    emergency_flag = Field("emergency_flag", bool, "Bool")
    approver_id = Field("approver_id", int, "Int")

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            BreakGlassAuth(cls.emergency_flag, cls.approver_id),
        ]


standard_guard = Guard(HIPAAAccessPolicy, config=GuardConfig(solver_timeout_ms=5_000))
emergency_guard = Guard(BreakGlassPolicy, config=GuardConfig(solver_timeout_ms=5_000))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Print helper
# ═══════════════════════════════════════════════════════════════════════════════


def _print(label: str, d: Decision) -> None:
    symbol = "✓" if d.allowed else "✗"
    print(f"\n{symbol} [{label}]")
    print(f"  allowed  : {d.allowed}")
    print(f"  status   : {d.status.value}")
    if d.violated_invariants:
        print(f"  violated : {sorted(d.violated_invariants)}")
    if d.explanation:
        print(f"  reason   : {d.explanation}")
    print(f"  audit_id : {d.decision_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Standard-path scenarios
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_clinician_valid_consent() -> Decision:
    """Clinician + unexpired consent — standard access granted."""
    return standard_guard.verify(
        intent={"requestor_role": CLINICIAN, "emergency_flag": False, "approver_id": 0},
        state={
            "state_version": "0.6",
            "consent_given": True,
            "consent_expiry": _NOW + 365 * 86_400,  # 1 year from now
        },
    )


def scenario_admin_blocked_no_phi_clearance() -> Decision:
    """Admin role — not in the minimum-necessary allowlist. BLOCKED."""
    return standard_guard.verify(
        intent={"requestor_role": ADMIN, "emergency_flag": False, "approver_id": 0},
        state={
            "state_version": "0.6",
            "consent_given": True,
            "consent_expiry": _NOW + 86_400,
        },
    )


def scenario_nurse_expired_consent() -> Decision:
    """Nurse role + expired patient authorisation. BLOCKED (HIPAA 45 CFR § 164.508)."""
    return standard_guard.verify(
        intent={"requestor_role": NURSE, "emergency_flag": False, "approver_id": 0},
        state={
            "state_version": "0.6",
            "consent_given": True,
            "consent_expiry": _NOW - 86_400,  # expired yesterday
        },
    )


def scenario_double_block_wrong_role_plus_expired() -> Decision:
    """Admin + expired consent — Z3 reports both violations simultaneously."""
    return standard_guard.verify(
        intent={"requestor_role": ADMIN, "emergency_flag": False, "approver_id": 0},
        state={
            "state_version": "0.6",
            "consent_given": False,
            "consent_expiry": _NOW - 86_400,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Break-glass scenarios
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_break_glass_valid() -> Decision:
    """Emergency declared, supervisor approved — break-glass access granted."""
    return emergency_guard.verify(
        intent={"requestor_role": CLINICIAN, "emergency_flag": True, "approver_id": 9_001},
        state={
            "state_version": "0.6",
            "consent_given": False,  # consent irrelevant in emergency path
            "consent_expiry": 0,
        },
    )


def scenario_break_glass_no_approver() -> Decision:
    """Emergency declared but no supervisor on record — HIPAA audit trail missing. BLOCKED."""
    return emergency_guard.verify(
        intent={"requestor_role": CLINICIAN, "emergency_flag": True, "approver_id": 0},
        state={
            "state_version": "0.6",
            "consent_given": False,
            "consent_expiry": 0,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Main
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("PRAMANIX — HIPAA PHI Access Control")
    print("Z3-verified | HIPAA 45 CFR § 164.502(b) + § 164.508 + § 164.312")
    print("=" * 70)
    print("\n── Standard Access Path ──")
    _print("CLINICIAN + valid consent (ALLOWED)", scenario_clinician_valid_consent())
    _print("ADMIN (no PHI clearance) (BLOCKED)", scenario_admin_blocked_no_phi_clearance())
    _print("NURSE + expired consent (BLOCKED)", scenario_nurse_expired_consent())
    _print("ADMIN + no consent — dual violation", scenario_double_block_wrong_role_plus_expired())
    print("\n── Break-Glass Path (45 CFR § 164.312(a)(2)(ii)) ──")
    _print("BREAK-GLASS + supervisor approved (ALLOWED)", scenario_break_glass_valid())
    _print("BREAK-GLASS + no approver (BLOCKED)", scenario_break_glass_no_approver())
    print("\n" + "=" * 70)
    print("Every access decision is logged with a cryptographic audit_id.")
    print("=" * 70)
