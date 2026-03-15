# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""HIPAA / clinical constraint primitives for Pramanix policies.

Each factory returns a :class:`~pramanix.expressions.ConstraintExpr` with
``.named()`` and ``.explain()`` pre-set, ready to include in a Policy's
``invariants()`` list.

Regulatory coverage
-------------------
* ``PHILeastPrivilege``     — HIPAA 45 CFR § 164.502(b) (minimum-necessary rule)
* ``ConsentActive``         — HIPAA 45 CFR § 164.508 (authorisation expiry)
* ``DosageGradientCheck``   — Joint Commission NPSG 03.06.01 (titration safety)
* ``BreakGlassAuth``        — HIPAA 45 CFR § 164.312(a)(2)(ii) (emergency access)
* ``PediatricDoseBound``    — AAP / FDA weight-based paediatric dosing cap

Warning on role encoding
------------------------
Z3 does not support a string sort.  Role codes must be encoded as integers::

    CLINICIAN = 1
    NURSE     = 2
    ADMIN     = 3
    AUDITOR   = 4

Example::

    from pramanix import Policy, Field
    from pramanix.primitives.healthcare import PHILeastPrivilege, ConsentActive

    CLINICIAN, NURSE = 1, 2

    class PHIAccessPolicy(Policy):
        requestor_role = Field("requestor_role", int,  "Int")
        consent_active = Field("consent_active", bool, "Bool")
        consent_expiry = Field("consent_expiry", int,  "Int")

        @classmethod
        def invariants(cls):
            return [
                PHILeastPrivilege(cls.requestor_role, [CLINICIAN, NURSE]),
                ConsentActive(cls.consent_active, cls.consent_expiry, current_epoch=1_735_000_000),
            ]
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pramanix.expressions import E

if TYPE_CHECKING:
    from decimal import Decimal

    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "PHILeastPrivilege",
    "ConsentActive",
    "DosageGradientCheck",
    "BreakGlassAuth",
    "PediatricDoseBound",
]


def PHILeastPrivilege(requestor_role: Field, allowed_roles: list[Any]) -> ConstraintExpr:
    """Enforce HIPAA minimum-necessary access — only permitted roles may access PHI.

    DSL: ``E(requestor_role).is_in(allowed_roles)``

    Roles MUST be integer-encoded (Z3 has no string sort).  Maintain a
    shared constant mapping (e.g. ``CLINICIAN=1, NURSE=2, ADMIN=3``).

    Regulatory: HIPAA 45 CFR § 164.502(b) — covered entities must make
    reasonable efforts to limit PHI access to the minimum necessary to
    accomplish the intended purpose.

    Args:
        requestor_role: Field (int, Int) — integer-encoded caller role.
        allowed_roles:  List of integer role codes permitted to read PHI.
    """
    return (
        E(requestor_role)
        .is_in(allowed_roles)
        .named("phi_least_privilege")
        .explain(
            "PHI access denied: requestor_role ({requestor_role}) is not in "
            "the minimum-necessary access set. (HIPAA 45 CFR § 164.502(b))"
        )
    )


def ConsentActive(
    consent_status: Field,
    consent_expiry_epoch: Field,
    current_epoch: int,
) -> ConstraintExpr:
    """Enforce that a valid, unexpired patient authorisation exists.

    DSL: ``(E(consent_status) == "ACTIVE") & (E(consent_expiry_epoch) > current_epoch)``

    Encoding: ``consent_status`` must be a String-sorted Z3 variable
    (``Field(..., str, "String")``).  Supported states per HIPAA §164.508:

    * ``"ACTIVE"``  — valid written authorisation is on file and unexpired.
    * ``"REVOKED"`` — patient has withdrawn authorisation (HIPAA §164.508(b)(5)).
    * ``"EXPIRED"`` — authorisation lapse date has passed.

    This multi-state encoding prevents a boolean ``True`` from being reused
    after the patient revokes consent — a gap in single-Bool implementations.

    Regulatory: HIPAA 45 CFR § 164.508 — a written authorisation must exist
    and must not have expired before PHI may be used or disclosed for purposes
    beyond Treatment, Payment, and Operations (TPO).

    Args:
        consent_status:       Field (str, String) — authorisation lifecycle
            state.  Must be one of ``"ACTIVE"``, ``"REVOKED"``, ``"EXPIRED"``.
        consent_expiry_epoch: Field (int, Int) — UNIX timestamp of authorisation
            expiry date.
        current_epoch:        Request time as a UNIX timestamp literal (int).
    """
    return (
        ((E(consent_status) == "ACTIVE") & (E(consent_expiry_epoch) > current_epoch))
        .named("consent_active")
        .explain(
            'PHI disclosure blocked: consent_status="{consent_status}", '
            "consent_expiry_epoch={consent_expiry_epoch} — authorisation absent, "
            "revoked, or expired. (HIPAA 45 CFR § 164.508)"
        )
    )


def DosageGradientCheck(
    new_dose: Field,
    current_dose: Field,
    max_increase_pct: Decimal,
) -> ConstraintExpr:
    """Enforce that a dose increase does not exceed a safe titration gradient.

    DSL (reformulated to avoid division):
    ``E(new_dose) - E(current_dose) <= max_increase_pct * E(current_dose)``

    Equivalent to ``(new - current) / current <= max_increase_pct`` when
    ``current > 0``, but expressed as a linear constraint for Z3 efficiency.

    Regulatory: Joint Commission NPSG 03.06.01 / ISMP — dose titration safety
    requires that per-step dose increases not exceed a pre-defined gradient
    (commonly 25-50 % for opioids and narrow-therapeutic-index drugs).

    Args:
        new_dose:         Field (Decimal, Real) — proposed new dose.
        current_dose:     Field (Decimal, Real) — current prescribed dose.
        max_increase_pct: Decimal — maximum fractional increase (e.g., Decimal("0.25")).
    """
    return (
        (E(new_dose) - E(current_dose) <= max_increase_pct * E(current_dose))
        .named("dosage_gradient_check")
        .explain(
            "Dosage escalation rejected: new_dose ({new_dose}) exceeds "
            f"current_dose ({{current_dose}}) by more than {max_increase_pct * 100:.1f}%. "
            "(Joint Commission NPSG 03.06.01 titration safety)"
        )
    )


def BreakGlassAuth(
    emergency_flag: Field,
    approver_id: Field,
) -> ConstraintExpr:
    """Enforce that emergency override access has been properly authorised.

    DSL: ``(E(emergency_flag) == True) & (E(approver_id) > 0)``

    The "break-glass" pattern allows a privileged user to bypass normal access
    controls in a life-threatening emergency, but ONLY when (a) an emergency
    is declared and (b) an approver ID has been recorded for the audit trail.
    An ``approver_id`` of 0 (zero) means no approver has been set.

    Regulatory: HIPAA 45 CFR § 164.312(a)(2)(ii) — emergency access procedures
    must be in place to allow access to ePHI when normal access mechanisms are
    unavailable.  Every break-glass event MUST be logged and reviewed.

    Args:
        emergency_flag: Field (bool, Bool) — True when an emergency override
            has been invoked.
        approver_id:    Field (int, Int) — non-zero employee ID of the approving
            supervisor.  0 = no approver.
    """
    return (
        ((E(emergency_flag) == True) & (E(approver_id) > 0))  # noqa: E712
        .named("break_glass_auth")
        .explain(
            "Break-glass access blocked: emergency_flag={emergency_flag}, "
            "approver_id={approver_id}. Both conditions must hold. "
            "(HIPAA 45 CFR § 164.312(a)(2)(ii))"
        )
    )


def PediatricDoseBound(
    dose_per_kg: Field,
    weight_kg: Field,
    absolute_max: Decimal,
) -> ConstraintExpr:
    """Enforce absolute dosing cap for paediatric patients (weight-based).

    DSL: ``E(dose_per_kg) * E(weight_kg) <= absolute_max``

    Weight-based dosing is standard in paediatrics.  Even when ``dose_per_kg``
    is within range, the *absolute* dose must not exceed a hard ceiling to
    prevent overdose in children at the upper end of normal weight ranges.

    Regulatory: AAP Clinical Practice Guidelines / FDA paediatric labelling
    requirements (PREA, 21 CFR § 314.55) — paediatric drug approvals must
    specify weight-based dosing and absolute dose caps.

    Args:
        dose_per_kg:  Field (Decimal, Real) — dose in mg/kg (or mcg/kg etc.).
        weight_kg:    Field (Decimal, Real) — patient weight in kg.
        absolute_max: Decimal — hard absolute dose ceiling in the same unit as
            ``dose_per_kg x weight_kg`` (e.g., mg).
    """
    return (
        (E(dose_per_kg) * E(weight_kg) <= absolute_max)
        .named("pediatric_dose_bound")
        .explain(
            "Paediatric dose ceiling exceeded: dose_per_kg ({dose_per_kg}) x "
            "weight_kg ({weight_kg}) exceeds absolute maximum of "
            f"{absolute_max}. (AAP / FDA PREA paediatric dosing cap)"
        )
    )
