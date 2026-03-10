# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Infrastructure and scaling constraint primitives.

Example::

    from pramanix.primitives.infra import MinReplicas, MaxReplicas

    class ScalingPolicy(Policy):
        replicas = Field("replicas", int, "Int")
        min_r    = Field("min_r",    int, "Int")
        max_r    = Field("max_r",    int, "Int")

        @classmethod
        def invariants(cls):
            return [
                MinReplicas(cls.replicas, cls.min_r),
                MaxReplicas(cls.replicas, cls.max_r),
            ]
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pramanix.expressions import E

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "MinReplicas",
    "MaxReplicas",
    "WithinCPUBudget",
    "WithinMemoryBudget",
]


def MinReplicas(replicas: Field, min_replicas: Field) -> ConstraintExpr:
    """Enforce that the replica count is at or above the minimum.

    DSL: ``(E(replicas) >= E(min_replicas))``

    Args:
        replicas:     Field representing the requested replica count.
        min_replicas: Field representing the configured minimum replicas.
    """
    return (
        (E(replicas) >= E(min_replicas))
        .named("min_replicas")
        .explain(
            "Scale-down blocked: replicas ({replicas}) < min_replicas ({min_replicas})."
        )
    )


def MaxReplicas(replicas: Field, max_replicas: Field) -> ConstraintExpr:
    """Enforce that the replica count does not exceed the maximum.

    DSL: ``(E(replicas) <= E(max_replicas))``

    Args:
        replicas:     Field representing the requested replica count.
        max_replicas: Field representing the configured maximum replicas.
    """
    return (
        (E(replicas) <= E(max_replicas))
        .named("max_replicas")
        .explain(
            "Scale-up blocked: replicas ({replicas}) > max_replicas ({max_replicas})."
        )
    )


def WithinCPUBudget(cpu_request: Field, cpu_budget: Field) -> ConstraintExpr:
    """Enforce that the CPU request is within the allocated budget.

    DSL: ``(E(cpu_request) <= E(cpu_budget))``

    Args:
        cpu_request: Field representing the requested CPU (millicores or cores).
        cpu_budget:  Field representing the maximum allowed CPU allocation.
    """
    return (
        (E(cpu_request) <= E(cpu_budget))
        .named("within_cpu_budget")
        .explain(
            "CPU budget exceeded: cpu_request ({cpu_request}) > cpu_budget ({cpu_budget})."
        )
    )


def WithinMemoryBudget(mem_request: Field, mem_budget: Field) -> ConstraintExpr:
    """Enforce that the memory request is within the allocated budget.

    DSL: ``(E(mem_request) <= E(mem_budget))``

    Args:
        mem_request: Field representing the requested memory (MiB or GiB).
        mem_budget:  Field representing the maximum allowed memory allocation.
    """
    return (
        (E(mem_request) <= E(mem_budget))
        .named("within_memory_budget")
        .explain(
            "Memory budget exceeded: mem_request ({mem_request}) "
            "> mem_budget ({mem_budget})."
        )
    )
