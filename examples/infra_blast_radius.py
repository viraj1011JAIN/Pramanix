#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
infra_blast_radius.py — SRE safety guardrails for production deployments.

Demonstrates three Phase-8 SRE primitives working as a production deployment
gate:
  ① BlastRadiusCheck    — limit fleet exposure to 5% per wave
  ② CircuitBreakerState — halt if a downstream circuit is tripped
  ③ ProdDeployApproval  — require change-approval-board quorum

This is the pattern that SRE leads, platform engineers, and incident
commanders recognise: mathematically verified blast radius + circuit breaker
state + approval chain, checked atomically in microseconds before any
Kubernetes rollout or Terraform apply is initiated.

Run::

    python examples/infra_blast_radius.py
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pydantic import BaseModel

from pramanix import Decision, Field, Guard, GuardConfig, Policy
from pramanix.primitives.infra import (
    BlastRadiusCheck,
    CircuitBreakerState,
    ProdDeployApproval,
)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Domain models
# ═══════════════════════════════════════════════════════════════════════════════


class DeployIntent(BaseModel):
    """AI-initiated or CI/CD pipeline deployment request."""

    affected_instances: int
    """Number of fleet instances the deployment will touch."""

    deployment_approved: bool
    """True when the Change Approval Board workflow has been completed."""

    approver_count: int
    """Number of unique CAB members who signed off."""


class FleetState(BaseModel):
    """Real-time fleet and circuit-breaker state."""

    state_version: str
    total_instances: int
    """Total live fleet size."""

    circuit_open: bool
    """True when any downstream circuit breaker is OPEN (tripped / fault state)."""


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Policy
# ═══════════════════════════════════════════════════════════════════════════════


class ProductionDeployPolicy(Policy):
    """Three-layer production deployment safety gate.

    All three must hold simultaneously before any deployment wave is initiated:

    1. Blast radius ≤ 5% of fleet — limits customer impact per wave
    2. Circuit breaker CLOSED — downstream services are healthy
    3. CAB approval with ≥ 2 approvers — prevents lone-wolf deployments
    """

    class Meta:
        version = "0.6"
        intent_model = DeployIntent
        state_model = FleetState

    affected_instances = Field("affected_instances", int, "Int")
    total_instances = Field("total_instances", int, "Int")
    circuit_open = Field("circuit_open", bool, "Bool")
    deployment_approved = Field("deployment_approved", bool, "Bool")
    approver_count = Field("approver_count", int, "Int")

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            BlastRadiusCheck(cls.affected_instances, cls.total_instances, Decimal("0.05")),
            CircuitBreakerState(cls.circuit_open),
            ProdDeployApproval(cls.deployment_approved, cls.approver_count, required_approvers=2),
        ]


guard = Guard(ProductionDeployPolicy, config=GuardConfig(solver_timeout_ms=5_000))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Print helper
# ═══════════════════════════════════════════════════════════════════════════════


def _print(label: str, d: Decision) -> None:
    symbol = "✓" if d.allowed else "✗"
    print(f"\n{symbol} [{label}]")
    print(f"  allowed  : {d.allowed}")
    print(f"  status   : {d.status.value}")
    if d.violated_invariants:
        print(f"  violated : {sorted(d.violated_invariants)}")
    if d.explanation:
        print(f"  reason   : {d.explanation}")
    print(f"  audit_id : {d.decision_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Scenarios
# ═══════════════════════════════════════════════════════════════════════════════


def scenario_safe_canary_wave() -> Decision:
    """5-instance canary wave on a 200-instance fleet — all gates pass."""
    return guard.verify(
        intent={
            "affected_instances": 5,
            "deployment_approved": True,
            "approver_count": 3,
        },
        state={
            "state_version": "0.6",
            "total_instances": 200,
            "circuit_open": False,
        },
    )


def scenario_blast_radius_exceeded() -> Decision:
    """50-instance wave on 200 = 25% blast radius > 5% limit. BLOCKED."""
    return guard.verify(
        intent={
            "affected_instances": 50,
            "deployment_approved": True,
            "approver_count": 3,
        },
        state={
            "state_version": "0.6",
            "total_instances": 200,
            "circuit_open": False,
        },
    )


def scenario_circuit_breaker_open() -> Decision:
    """Downstream database circuit is OPEN — deployment halted to prevent cascading."""
    return guard.verify(
        intent={
            "affected_instances": 5,
            "deployment_approved": True,
            "approver_count": 3,
        },
        state={
            "state_version": "0.6",
            "total_instances": 200,
            "circuit_open": True,  # ← tripped
        },
    )


def scenario_insufficient_approvers() -> Decision:
    """Only 1 approver — CAB quorum requires 2. BLOCKED."""
    return guard.verify(
        intent={
            "affected_instances": 5,
            "deployment_approved": True,
            "approver_count": 1,  # ← only one person signed off
        },
        state={
            "state_version": "0.6",
            "total_instances": 200,
            "circuit_open": False,
        },
    )


def scenario_friday_chaos_triple_violation() -> Decision:
    """Friday 5pm deployment disaster — all three gates fail simultaneously."""
    return guard.verify(
        intent={
            "affected_instances": 100,  # 50% blast radius
            "deployment_approved": False,  # nobody approved
            "approver_count": 0,
        },
        state={
            "state_version": "0.6",
            "total_instances": 200,
            "circuit_open": True,  # circuit is on fire
        },
    )


def scenario_boundary_exactly_5pct() -> Decision:
    """Exactly 5% blast radius (10/200) — at the boundary, should pass."""
    return guard.verify(
        intent={
            "affected_instances": 10,  # exactly 5%
            "deployment_approved": True,
            "approver_count": 2,
        },
        state={
            "state_version": "0.6",
            "total_instances": 200,
            "circuit_open": False,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Main
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("PRAMANIX — SRE Production Deployment Safety Gate")
    print("Z3-verified blast radius + circuit breaker + approval chain")
    print("=" * 70)

    _print("CANARY WAVE: 5/200 instances (2.5%) — SAFE", scenario_safe_canary_wave())
    _print("BLAST RADIUS: 50/200 = 25% > 5% limit — BLOCKED", scenario_blast_radius_exceeded())
    _print("CIRCUIT BREAKER: OPEN downstream — BLOCKED", scenario_circuit_breaker_open())
    _print("CAB QUORUM: only 1 approver, need 2 — BLOCKED", scenario_insufficient_approvers())
    _print("BOUNDARY: exactly 5% (10/200) — ALLOWED", scenario_boundary_exactly_5pct())
    _print("FRIDAY CHAOS: triple violation — BLOCKED", scenario_friday_chaos_triple_violation())

    print("\n" + "=" * 70)
    print("Z3 identifies ALL violated constraints simultaneously — not sequentially.")
    print("=" * 70)
