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
from pramanix.primitives.time import After, Before, NotExpired, WithinTimeWindow

__all__ = [
    # Finance (phase 4/5)
    "NonNegativeBalance",
    "UnderDailyLimit",
    "UnderSingleTxLimit",
    "RiskScoreBelow",
    # RBAC (phase 4/5)
    "RoleMustBeIn",
    "ConsentRequired",
    "DepartmentMustBeIn",
    # Infrastructure (phase 4/5)
    "MinReplicas",
    "MaxReplicas",
    "WithinCPUBudget",
    "WithinMemoryBudget",
    # Time (phase 4/5)
    "WithinTimeWindow",
    "After",
    "Before",
    "NotExpired",
    # Common (phase 4/5)
    "NotSuspended",
    "StatusMustBe",
    "FieldMustEqual",
    # FinTech (phase 8 — 10 primitives)
    "SufficientBalance",
    "VelocityCheck",
    "AntiStructuring",
    "WashSaleDetection",
    "CollateralHaircut",
    "MaxDrawdown",
    "SanctionsScreen",
    "KYCTierCheck",
    "TradingWindowCheck",
    "MarginRequirement",
    # Healthcare / HIPAA (phase 8 — 5 primitives)
    "PHILeastPrivilege",
    "ConsentActive",
    "DosageGradientCheck",
    "BreakGlassAuth",
    "PediatricDoseBound",
    # SRE / Infrastructure (phase 8 — 5 primitives)
    "BlastRadiusCheck",
    "CircuitBreakerState",
    "ProdDeployApproval",
    "ReplicaBudget",
    "CPUMemoryGuard",
]
