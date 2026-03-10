# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix primitives library — pre-built, reusable policy constraints.

All primitive factories return a :class:`~pramanix.expressions.ConstraintExpr`
with ``.named()`` and ``.explain()`` pre-configured.

Import by domain::

    from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit
    from pramanix.primitives.rbac    import RoleMustBeIn, ConsentRequired
    from pramanix.primitives.infra   import MinReplicas, MaxReplicas
    from pramanix.primitives.time    import NotExpired, WithinTimeWindow
    from pramanix.primitives.common  import NotSuspended, StatusMustBe

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
from pramanix.primitives.infra import (
    MaxReplicas,
    MinReplicas,
    WithinCPUBudget,
    WithinMemoryBudget,
)
from pramanix.primitives.rbac import ConsentRequired, DepartmentMustBeIn, RoleMustBeIn
from pramanix.primitives.time import After, Before, NotExpired, WithinTimeWindow

__all__ = [
    # Finance
    "NonNegativeBalance",
    "UnderDailyLimit",
    "UnderSingleTxLimit",
    "RiskScoreBelow",
    # RBAC
    "RoleMustBeIn",
    "ConsentRequired",
    "DepartmentMustBeIn",
    # Infrastructure
    "MinReplicas",
    "MaxReplicas",
    "WithinCPUBudget",
    "WithinMemoryBudget",
    # Time
    "WithinTimeWindow",
    "After",
    "Before",
    "NotExpired",
    # Common
    "NotSuspended",
    "StatusMustBe",
    "FieldMustEqual",
]
