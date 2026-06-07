# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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

from typing import TYPE_CHECKING

from pramanix.expressions import ConstraintExpr, E

if TYPE_CHECKING:
    from decimal import Decimal

    from pramanix.expressions import Field

__all__ = [
    # Phase 8 SRE primitives
    "BlastRadiusCheck",
    "CPUMemoryGuard",
    "CircuitBreakerState",
    "MaxReplicas",
    "MinReplicas",
    "ProdDeployApproval",
    "ReplicaBudget",
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
        .explain("Scale-down blocked: replicas ({replicas}) < min_replicas ({min_replicas}).")
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
        .explain("Scale-up blocked: replicas ({replicas}) > max_replicas ({max_replicas}).")
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
        .explain("CPU budget exceeded: cpu_request ({cpu_request}) > cpu_budget ({cpu_budget}).")
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
            "Memory budget exceeded: mem_request ({mem_request}) " "> mem_budget ({mem_budget})."
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
    ``E(total) > 0 AND E(affected) <= max_blast_pct * E(total)``

    The ``total_instances > 0`` guard prevents vacuous truth: without it,
    ``affected <= max_blast_pct * 0`` would block all non-zero deployments
    (wrong), while an attacker injecting ``total_instances=0`` via state
    could produce a constraint that trivially blocks or allows everything.

    SRE principle: Blast radius control limits the customer impact of a bad
    deployment or config change.  Common limits: 5 % for auto-rollout canary,
    20 % for blue/green stage-gate, 100 % for fully-tested releases.

    Args:
        affected_instances: Field (int, Int) — number of instances being changed.
        total_instances:    Field (int, Int) — total fleet size.  Must be > 0.
        max_blast_pct:      Decimal in (0, 1] — maximum permitted fraction.

    Raises:
        PolicyCompilationError: If ``max_blast_pct`` is not in (0, 1].
    """
    from decimal import Decimal as _D
    from pramanix.exceptions import PolicyCompilationError

    if not (_D("0") < max_blast_pct <= _D("1")):
        raise PolicyCompilationError(
            f"BlastRadiusCheck: max_blast_pct must be in (0, 1], got {max_blast_pct!r}. "
            "Use Decimal('0.05') for 5%, Decimal('1') for 100%."
        )
    return (
        (E(total_instances) > 0)
        & (E(affected_instances) <= max_blast_pct * E(total_instances))
    ).named("blast_radius_check").explain(
        "Blast radius exceeded or fleet size is zero: {affected_instances} of "
        f"{{total_instances}} instances (> {max_blast_pct * 100:.1f}% limit). "
        "Reduce rollout batch size or provide a valid total_instances > 0."
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
    # The circuit state value must be normalised (uppercased) by the state provider
    # before being passed to Guard.verify().  Using a single "OPEN" comparison
    # means "open" (lowercase) or "Open" (mixed-case) from external systems
    # (Redis annotations, K8s labels, API responses) would bypass the guard.
    # The recommended pattern is to normalise in the state provider:
    #   state = {"circuit_state": redis.get("cb:state").decode().upper()}
    # For defence-in-depth, we also match case-insensitively via _InOp membership
    # with all known OPEN variants.
    return (
        E(circuit_state).is_not_in(["OPEN", "open", "Open"])
    ).named("circuit_breaker_state").explain(
        'Request blocked: circuit_state="{circuit_state}" — circuit breaker '
        "is OPEN. Downstream service is unhealthy — fail fast. "
        "Normalise circuit_state to uppercase in your state provider."
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
        required_approvers:  Minimum number of approvers required (literal int, ≥ 1).

    Raises:
        ValueError: If ``required_approvers < 1`` — zero approvers would trivially
            satisfy the quorum check, defeating the deployment gate entirely.
    """
    if required_approvers < 1:
        raise ValueError(
            f"ProdDeployApproval: required_approvers={required_approvers!r} is invalid. "
            "A zero-approver gate is trivially satisfied and provides no protection. "
            "Set required_approvers >= 1 (typically 2 for internal, 3 for PCI/SOX)."
        )
    return (
        (E(deployment_approved).is_true() & (E(approver_count) >= required_approvers))
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

    Raises:
        ValueError: If ``min_replicas > max_replicas`` — the resulting constraint is
            always unsatisfiable, blocking every request with no diagnostic.
    """
    if min_replicas > max_replicas:
        raise ValueError(
            f"ReplicaBudget: min_replicas={min_replicas} > max_replicas={max_replicas}. "
            "This produces an unsatisfiable constraint — every replica request will be "
            "blocked.  Ensure min_replicas <= max_replicas."
        )
    return (
        ((E(requested_replicas) >= min_replicas) & (E(requested_replicas) <= max_replicas))
        .named("replica_budget")
        .explain(
            f"Replica count {{requested_replicas}} is outside budget [{min_replicas}-{max_replicas}]. "
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
