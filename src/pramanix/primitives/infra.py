# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Infrastructure, SRE, and reliability constraint primitives.

Phase 4 primitives: MinReplicas, MaxReplicas, WithinCPUBudget, WithinMemoryBudget
Phase 8 SRE primitives: BlastRadiusCheck, CircuitBreakerState, ProdDeployApproval,
    ReplicaBudget, CPUMemoryGuard

Example::

    from pramanix.primitives.infra import MinReplicas, MaxReplicas, BlastRadiusCheck

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

from decimal import Decimal
from typing import TYPE_CHECKING

from pramanix.expressions import E

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "MinReplicas",
    "MaxReplicas",
    "WithinCPUBudget",
    "WithinMemoryBudget",
    # Phase 8 SRE primitives
    "BlastRadiusCheck",
    "CircuitBreakerState",
    "ProdDeployApproval",
    "ReplicaBudget",
    "CPUMemoryGuard",
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


# ── Phase 8: SRE / Production-Safety Primitives ──────────────────────────────


def BlastRadiusCheck(
    affected_instances: Field,
    total_instances: Field,
    max_blast_pct: Decimal,
) -> ConstraintExpr:
    """Enforce that a deployment / change affects at most a fraction of the fleet.

    DSL (reformulated to avoid division):
    ``E(affected) <= max_blast_pct * E(total)``

    Equivalent to ``affected / total <= max_blast_pct`` when ``total > 0``,
    but expressed as a linear (Z3-efficient) constraint.

    SRE principle: Blast radius control limits the customer impact of a bad
    deployment or config change.  Common limits: 5 % for auto-rollout canary,
    20 % for blue/green stage-gate, 100 % for fully-tested releases.

    Args:
        affected_instances: Field (int, Int) — number of instances being changed.
        total_instances:    Field (int, Int) — total fleet size.
        max_blast_pct:      Decimal in (0, 1] — maximum permitted fraction.
    """
    return (
        (E(affected_instances) <= max_blast_pct * E(total_instances))
        .named("blast_radius_check")
        .explain(
            "Blast radius exceeded: {affected_instances} of {total_instances} instances "
            f"(> {max_blast_pct * 100:.1f}% limit). Reduce rollout batch size."
        )
    )


def CircuitBreakerState(circuit_state: Field) -> ConstraintExpr:
    """Block execution when the downstream circuit breaker is open (tripped).

    DSL: ``E(circuit_state) != "OPEN"``

    Encoding: The field must be String-sorted (``Field(..., str, "String")``).
    Supported states follow the standard three-state circuit breaker pattern:

    * ``"CLOSED"``    — healthy; requests flow normally.
    * ``"OPEN"``      — tripped; requests are short-circuited immediately.
    * ``"HALF-OPEN"`` — recovery probe; one request allowed through to test
                        if the downstream has recovered.

    This string-based encoding supports the full ``CLOSED / OPEN / HALF-OPEN``
    lifecycle without separate Bool fields, and is safe to extend with custom
    states (e.g. ``"FORCED-OPEN"`` for maintenance windows).

    SRE principle: Circuit breaker pattern (Fowler) — when an upstream service
    repeatedly fails, trip the breaker to fail fast and protect the downstream,
    rather than allowing cascading timeouts.

    Args:
        circuit_state: Field (str, String) — current circuit breaker state.
            Must be one of ``"CLOSED"``, ``"OPEN"``, or ``"HALF-OPEN"``.
    """
    return (
        (E(circuit_state) != "OPEN")
        .named("circuit_breaker_state")
        .explain(
            'Request blocked: circuit_state="{circuit_state}" — circuit breaker '
            "is OPEN. Downstream service is unhealthy — fail fast."
        )
    )


def ProdDeployApproval(
    deployment_approved: Field,
    approver_count: Field,
    required_approvers: int,
) -> ConstraintExpr:
    """Enforce that a production deployment has required approvals.

    DSL: ``(E(approved) == True) & (E(approver_count) >= required_approvers)``

    Production deployment gates require both a boolean approval flag AND a
    quorum of approvers to prevent single-point-of-failure sign-offs.
    Common requirements: 2 approvers for internal services, 3 for PCI/SOX.

    Args:
        deployment_approved: Field (bool, Bool) — True when approval workflow completed.
        approver_count:      Field (int, Int) — number of unique approvers who signed off.
        required_approvers:  Minimum number of approvers required (literal int).
    """
    return (
        ((E(deployment_approved) == True) & (E(approver_count) >= required_approvers))  # noqa: E712
        .named("prod_deploy_approval")
        .explain(
            "Production deployment blocked: approved={deployment_approved}, "
            f"approver_count={{approver_count}} < required {required_approvers}. "
            "Obtain required change-approval-board sign-offs."
        )
    )


def ReplicaBudget(
    requested_replicas: Field,
    min_replicas: int,
    max_replicas: int,
) -> ConstraintExpr:
    """Enforce that a replica count request falls within the configured budget range.

    DSL: ``(E(replicas) >= min_replicas) & (E(replicas) <= max_replicas)``

    Combines MinReplicas and MaxReplicas into a single atomic constraint with
    literal bounds — useful when min/max are static configuration values rather
    than runtime fields.

    Args:
        requested_replicas: Field (int, Int) — desired replica count.
        min_replicas:       Hard minimum replicas (literal int, for HA floor).
        max_replicas:       Hard maximum replicas (literal int, for cost ceiling).
    """
    return (
        ((E(requested_replicas) >= min_replicas) & (E(requested_replicas) <= max_replicas))
        .named("replica_budget")
        .explain(
            f"Replica count {{requested_replicas}} is outside budget [{min_replicas}–{max_replicas}]. "
            "Adjust HPA/VPA configuration."
        )
    )


def CPUMemoryGuard(
    cpu_millicores: Field,
    mem_mib: Field,
    cpu_limit: int,
    mem_limit: int,
) -> ConstraintExpr:
    """Enforce that a workload's CPU and memory requests are within hard limits.

    DSL: ``(E(cpu_millicores) <= cpu_limit) & (E(mem_mib) <= mem_limit)``

    Kubernetes QoS class Guaranteed requires requests == limits.  This guard
    prevents resource-steal attacks where a container requests more than its
    fair share, degrading co-located workloads.

    Args:
        cpu_millicores: Field (int, Int) — CPU request in millicores (1 CPU = 1000m).
        mem_mib:        Field (int, Int) — Memory request in MiB.
        cpu_limit:      Hard CPU ceiling in millicores (literal int).
        mem_limit:      Hard memory ceiling in MiB (literal int).
    """
    return (
        ((E(cpu_millicores) <= cpu_limit) & (E(mem_mib) <= mem_limit))
        .named("cpu_memory_guard")
        .explain(
            f"Resource limit exceeded: cpu={{cpu_millicores}}m (limit {cpu_limit}m), "
            f"mem={{mem_mib}}MiB (limit {mem_limit}MiB). Reduce resource requests."
        )
    )
