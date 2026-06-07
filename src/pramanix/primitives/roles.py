# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
                    E(_target_phi).is_false()
                    | (E(_role) == HIPAARole.CLINICIAN)
                    | (E(_role) == HIPAARole.BREAK_GLASS)
                )
                .named("phi_role_gate")
                .explain("PHI access requires CLINICIAN or BREAK_GLASS role"),
            ]
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["EnterpriseRole", "HIPAARole"]


class HIPAARole(IntEnum):
    """Integer role constants for HIPAA-governed clinical systems.

    Values are ``IntEnum`` members — they compare equal to plain ``int``
    literals (``HIPAARole.CLINICIAN == 1`` is True) so Z3 expressions work
    unchanged, while Python code can use ``isinstance(v, HIPAARole)`` to
    enforce namespace separation and prevent cross-registry confusion.

    Role values are stable across policy versions — never renumber existing
    roles.  Add new roles with higher integers.

    .. warning::
        **Do not mix HIPAARole and EnterpriseRole in the same policy.**
        Each registry occupies a disjoint integer range (1–99 vs 100–199)
        so Z3 cannot confuse a HIPAA clinical role with an enterprise tier.
    """

    #: Licensed clinician — full read/write access to patient records.
    CLINICIAN = 1

    #: Registered nurse — read/write within assigned patient context.
    NURSE = 2

    #: Healthcare administrator — scheduling, billing, non-clinical ops.
    ADMIN = 3

    #: Compliance auditor — read-only access to audit logs and records.
    AUDITOR = 4

    #: Approved researcher — de-identified data access under IRB approval.
    RESEARCHER = 5

    #: Break-glass emergency override — full access, every use is logged.
    #: Policies MUST emit an audit event when this role is exercised.
    BREAK_GLASS = 99


class EnterpriseRole(IntEnum):
    """Integer role constants for SaaS / enterprise system access tiers.

    Values are ``IntEnum`` members — they compare equal to plain ``int``
    literals so Z3 expressions work unchanged, while Python code can use
    ``isinstance(v, EnterpriseRole)`` to enforce namespace separation.

    Tiers are ordered: higher value = broader permissions.  Policies can
    use ``E(role_field) >= EnterpriseRole.OPERATOR`` to express
    "at least operator level".

    .. warning::
        **Do not mix HIPAARole and EnterpriseRole in the same policy.**
        EnterpriseRole occupies the 100–199 range; HIPAARole occupies 1–99.
        Mixing them lets Z3 equate roles across registries, potentially
        granting clinical emergency access to enterprise superusers.
    """

    #: Read-only access — dashboards, exports, no mutations.
    VIEWER = 10

    #: Operational access — run workflows, manage resources within quota.
    OPERATOR = 20

    #: System administrator — manage users, configure integrations.
    ADMIN_SYS = 30

    #: Superuser — unrestricted access.  Requires MFA + approval workflow.
    #: Value 100 (not 99) to prevent collision with HIPAARole.BREAK_GLASS=99.
    SUPERUSER = 100
