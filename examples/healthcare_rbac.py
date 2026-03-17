#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Healthcare RBAC example — PHI access control with RoleMustBeIn.

Demonstrates:
* Policy definition using RBAC primitives
* SAT path (doctor accessing PHI with explicit consent)
* UNSAT — wrong role
* UNSAT — consent not granted

Run::

    python examples/healthcare_rbac.py
"""
from __future__ import annotations

from pramanix import Field, Guard, GuardConfig, Policy
from pramanix.primitives.rbac import ConsentRequired, RoleMustBeIn

# Role encoding:  1=doctor, 2=nurse, 3=admin, 99=external
ROLE_DOCTOR = 1
ROLE_NURSE = 2
ROLE_ADMIN = 3

ALLOWED_PHI_ROLES = [ROLE_DOCTOR, ROLE_NURSE, ROLE_ADMIN]


class PHIAccessPolicy(Policy):
    """Policy governing access to Protected Health Information (PHI)."""

    class Meta:
        name = "phi_access"
        version = "1.0"

    # Fields
    role = Field("role", int, "Int")
    consent = Field("consent", bool, "Bool")

    @classmethod
    def invariants(cls) -> list:
        return [
            RoleMustBeIn(cls.role, ALLOWED_PHI_ROLES),
            ConsentRequired(cls.consent),
        ]


guard = Guard(PHIAccessPolicy, GuardConfig(execution_mode="sync"))


def run() -> None:
    print("=== Healthcare RBAC — PHI Access Control ===\n")

    # Scenario A: Doctor with consent → ALLOW
    decision = guard.verify(
        intent={"role": ROLE_DOCTOR},
        state={"consent": True, "state_version": "1.0"},
    )
    print(f"Scenario A (doctor, consent=True):  allowed={decision.allowed} | {decision.status.value}")
    assert decision.allowed, "Expected ALLOW"

    # Scenario B: External role (99) → BLOCK
    decision = guard.verify(
        intent={"role": 99},
        state={"consent": True, "state_version": "1.0"},
    )
    print(f"Scenario B (external, consent=True): allowed={decision.allowed} | {decision.violated_invariants}")
    assert not decision.allowed
    assert "role_must_be_in_allowed_set" in decision.violated_invariants

    # Scenario C: Nurse, no consent → BLOCK
    decision = guard.verify(
        intent={"role": ROLE_NURSE},
        state={"consent": False, "state_version": "1.0"},
    )
    print(f"Scenario C (nurse, consent=False):  allowed={decision.allowed} | {decision.violated_invariants}")
    assert not decision.allowed
    assert "consent_required" in decision.violated_invariants

    print("\n✅ All healthcare RBAC scenarios passed.")


if __name__ == "__main__":
    run()
