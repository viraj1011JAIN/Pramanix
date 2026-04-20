# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix primitives library — pre-built, reusable policy constraints.

All primitive factories return a :class:`~pramanix.expressions.ConstraintExpr`
with ``.named()`` and ``.explain()`` pre-configured.

Import by domain::

    from pramanix.primitives.finance     import NonNegativeBalance, UnderDailyLimit
    from pramanix.primitives.rbac        import RoleMustBeIn, ConsentRequired
    from pramanix.primitives.infra       import MinReplicas, MaxReplicas
    from pramanix.primitives.time        import NotExpired, WithinTimeWindow
    from pramanix.primitives.common      import NotSuspended, StatusMustBe
    from pramanix.primitives.fintech     import SufficientBalance, AntiStructuring
    from pramanix.primitives.healthcare  import PHILeastPrivilege, ConsentActive

Or import everything from this module::

    from pramanix.primitives import NonNegativeBalance, RoleMustBeIn, ...
"""
from pramanix.primitives.common import FieldMustEqual, NotSuspended, StatusMustBe
from pramanix.primitives.finance import (
    NonNegativeBalance,
    RiskScoreBelow,
    UnderDailyLimit,
    UnderSingleTxLimit,
)
from pramanix.primitives.fintech import (
    AntiStructuring,
    CollateralHaircut,
    KYCTierCheck,
    MarginRequirement,
    MaxDrawdown,
    SanctionsScreen,
    SufficientBalance,
    TradingWindowCheck,
    VelocityCheck,
    WashSaleDetection,
)
from pramanix.primitives.healthcare import (
    BreakGlassAuth,
    ConsentActive,
    DosageGradientCheck,
    PediatricDoseBound,
    PHILeastPrivilege,
)
from pramanix.primitives.infra import (
    BlastRadiusCheck,
    CircuitBreakerState,
    CPUMemoryGuard,
    MaxReplicas,
    MinReplicas,
    ProdDeployApproval,
    ReplicaBudget,
    WithinCPUBudget,
    WithinMemoryBudget,
)
from pramanix.primitives.rbac import ConsentRequired, DepartmentMustBeIn, RoleMustBeIn
from pramanix.primitives.roles import EnterpriseRole, HIPAARole
from pramanix.primitives.time import After, Before, NotExpired, WithinTimeWindow

__all__ = [
    "After",
    "AntiStructuring",
    "Before",
    # SRE / Infrastructure (phase 8 — 5 primitives)
    "BlastRadiusCheck",
    "BreakGlassAuth",
    "CPUMemoryGuard",
    "CircuitBreakerState",
    "CollateralHaircut",
    "ConsentActive",
    "ConsentRequired",
    "DepartmentMustBeIn",
    "DosageGradientCheck",
    "EnterpriseRole",
    "FieldMustEqual",
    # Role constants
    "HIPAARole",
    "KYCTierCheck",
    "MarginRequirement",
    "MaxDrawdown",
    "MaxReplicas",
    # Infrastructure (phase 4/5)
    "MinReplicas",
    # Finance (phase 4/5)
    "NonNegativeBalance",
    "NotExpired",
    # Common (phase 4/5)
    "NotSuspended",
    # Healthcare / HIPAA (phase 8 — 5 primitives)
    "PHILeastPrivilege",
    "PediatricDoseBound",
    "ProdDeployApproval",
    "ReplicaBudget",
    "RiskScoreBelow",
    # RBAC (phase 4/5)
    "RoleMustBeIn",
    "SanctionsScreen",
    "StatusMustBe",
    # FinTech (phase 8 — 10 primitives)
    "SufficientBalance",
    "TradingWindowCheck",
    "UnderDailyLimit",
    "UnderSingleTxLimit",
    "VelocityCheck",
    "WashSaleDetection",
    "WithinCPUBudget",
    "WithinMemoryBudget",
    # Time (phase 4/5)
    "WithinTimeWindow",
]
