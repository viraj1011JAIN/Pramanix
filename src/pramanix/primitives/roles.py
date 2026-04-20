# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Role and permission constants for Pramanix RBAC policies.

Two independent registries are provided:

* :data:`HIPAARole` — clinical roles for healthcare policies (HIPAA §164.312).
* :data:`EnterpriseRole` — tiered system roles for SaaS / enterprise platforms.

Use these constants in ``Policy.invariants()`` to constrain which roles may
perform a given action.

Example::

    from pramanix import E, Field, Policy
    from pramanix.primitives.roles import HIPAARole

    _role = Field("requester_role", int, "Int")
    _target_phi = Field("phi_access_requested", bool, "Bool")

    class PHIAccessPolicy(Policy):
        class Meta:
            version = "1.0"

        @classmethod
        def fields(cls):
            return {"requester_role": _role, "phi_access_requested": _target_phi}

        @classmethod
        def invariants(cls):
            return [
                # Only CLINICIAN or BREAK_GLASS may access PHI
                (
                    (E(_target_phi) == False)  # noqa: E712
                    | (E(_role) == HIPAARole.CLINICIAN)
                    | (E(_role) == HIPAARole.BREAK_GLASS)
                )
                .named("phi_role_gate")
                .explain("PHI access requires CLINICIAN or BREAK_GLASS role"),
            ]
"""
from __future__ import annotations

__all__ = ["EnterpriseRole", "HIPAARole"]


class HIPAARole:
    """Integer role constants for HIPAA-governed clinical systems.

    Role values are stable across policy versions — never renumber existing
    roles.  Add new roles with higher integers.
    """

    #: Licensed clinician — full read/write access to patient records.
    CLINICIAN: int = 1

    #: Registered nurse — read/write within assigned patient context.
    NURSE: int = 2

    #: Healthcare administrator — scheduling, billing, non-clinical ops.
    ADMIN: int = 3

    #: Compliance auditor — read-only access to audit logs and records.
    AUDITOR: int = 4

    #: Approved researcher — de-identified data access under IRB approval.
    RESEARCHER: int = 5

    #: Break-glass emergency override — full access, every use is logged.
    #: Policies MUST emit an audit event when this role is exercised.
    BREAK_GLASS: int = 99


class EnterpriseRole:
    """Integer role constants for SaaS / enterprise system access tiers.

    Tiers are ordered: higher value = broader permissions.  Policies can
    use ``E(role_field) >= EnterpriseRole.OPERATOR`` to express
    "at least operator level".
    """

    #: Read-only access — dashboards, exports, no mutations.
    VIEWER: int = 10

    #: Operational access — run workflows, manage resources within quota.
    OPERATOR: int = 20

    #: System administrator — manage users, configure integrations.
    ADMIN_SYS: int = 30

    #: Superuser — unrestricted access.  Requires MFA + approval workflow.
    SUPERUSER: int = 99
