# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.primitives.infra — Phase 8 SRE primitives.

Coverage: SAT pass, UNSAT fail, exact boundary for each new primitive.

Primitives under test (Phase 8 additions)
------------------------------------------
BlastRadiusCheck, CircuitBreakerState, ProdDeployApproval,
ReplicaBudget, CPUMemoryGuard
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.expressions import Field
from pramanix.primitives.infra import (
    BlastRadiusCheck,
    CircuitBreakerState,
    CPUMemoryGuard,
    ProdDeployApproval,
    ReplicaBudget,
)
from pramanix.solver import solve

# ── Field declarations ────────────────────────────────────────────────────────

_affected = Field("affected_instances", int, "Int")
_total = Field("total_instances", int, "Int")
_circuit_state = Field("circuit_state", str, "String")
_approved = Field("deployment_approved", bool, "Bool")
_approver_count = Field("approver_count", int, "Int")
_replicas = Field("requested_replicas", int, "Int")
_cpu_milli = Field("cpu_millicores", int, "Int")
_mem_mib = Field("mem_mib", int, "Int")


# ═══════════════════════════════════════════════════════════════════════════════
# BlastRadiusCheck
# SRE blast radius: affected <= max_pct * total
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_BLAST = Decimal("0.05")  # 5% max blast radius
_INV_BLAST = [BlastRadiusCheck(_affected, _total, _MAX_BLAST)]


class TestBlastRadiusCheck:
    def test_sat_small_canary_rollout(self) -> None:
        # 5 of 200 = 2.5% < 5%
        result = solve(_INV_BLAST, {"affected_instances": 5, "total_instances": 200}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_large_rollout_exceeds_blast_limit(self) -> None:
        # 20 of 200 = 10% > 5%
        result = solve(_INV_BLAST, {"affected_instances": 20, "total_instances": 200}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "blast_radius_check" for v in result.violated)

    def test_boundary_exactly_at_limit(self) -> None:
        # 10 of 200 = 5.0% == 5% → SAT (<=)
        result = solve(_INV_BLAST, {"affected_instances": 10, "total_instances": 200}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_one_over_limit(self) -> None:
        # 11 of 200 = 5.5% > 5%
        result = solve(_INV_BLAST, {"affected_instances": 11, "total_instances": 200}, timeout_ms=5_000)
        assert result.sat is False

    def test_sat_single_instance(self) -> None:
        # 1 of 1000 = 0.1% — trivially below any blast limit
        result = solve(_INV_BLAST, {"affected_instances": 1, "total_instances": 1000}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# CircuitBreakerState
# SRE circuit breaker: circuit_state != "OPEN"
# Supports CLOSED / OPEN / HALF-OPEN three-state lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

_INV_CIRCUIT = [CircuitBreakerState(_circuit_state)]


class TestCircuitBreakerState:
    def test_sat_circuit_closed_healthy(self) -> None:
        result = solve(_INV_CIRCUIT, {"circuit_state": "CLOSED"}, timeout_ms=5_000)
        assert result.sat is True

    def test_sat_circuit_half_open_probe(self) -> None:
        """HALF-OPEN allows one probe request through — not blocked."""
        result = solve(_INV_CIRCUIT, {"circuit_state": "HALF-OPEN"}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_circuit_open_tripped(self) -> None:
        result = solve(_INV_CIRCUIT, {"circuit_state": "OPEN"}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "circuit_breaker_state" for v in result.violated)


# ═══════════════════════════════════════════════════════════════════════════════
# ProdDeployApproval
# Change management: approved == True AND approver_count >= 2
# ═══════════════════════════════════════════════════════════════════════════════

_INV_APPROVAL = [ProdDeployApproval(_approved, _approver_count, required_approvers=2)]


class TestProdDeployApproval:
    def test_sat_approved_with_quorum(self) -> None:
        result = solve(
            _INV_APPROVAL,
            {"deployment_approved": True, "approver_count": 3},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_not_approved(self) -> None:
        result = solve(
            _INV_APPROVAL,
            {"deployment_approved": False, "approver_count": 3},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "prod_deploy_approval" for v in result.violated)

    def test_unsat_approved_but_insufficient_approvers(self) -> None:
        result = solve(
            _INV_APPROVAL,
            {"deployment_approved": True, "approver_count": 1},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_boundary_exactly_required_approvers(self) -> None:
        result = solve(
            _INV_APPROVAL,
            {"deployment_approved": True, "approver_count": 2},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_neither_condition_met(self) -> None:
        result = solve(
            _INV_APPROVAL,
            {"deployment_approved": False, "approver_count": 0},
            timeout_ms=5_000,
        )
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# ReplicaBudget
# Kubernetes HPA: min_replicas <= replicas <= max_replicas
# ═══════════════════════════════════════════════════════════════════════════════

_INV_REPLICA = [ReplicaBudget(_replicas, min_replicas=2, max_replicas=10)]


class TestReplicaBudget:
    def test_sat_within_range(self) -> None:
        result = solve(_INV_REPLICA, {"requested_replicas": 5}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_below_minimum(self) -> None:
        result = solve(_INV_REPLICA, {"requested_replicas": 1}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "replica_budget" for v in result.violated)

    def test_unsat_above_maximum(self) -> None:
        result = solve(_INV_REPLICA, {"requested_replicas": 11}, timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_at_minimum(self) -> None:
        result = solve(_INV_REPLICA, {"requested_replicas": 2}, timeout_ms=5_000)
        assert result.sat is True

    def test_boundary_at_maximum(self) -> None:
        result = solve(_INV_REPLICA, {"requested_replicas": 10}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# CPUMemoryGuard
# Kubernetes resource limits: cpu <= 2000m AND mem <= 4096 MiB
# ═══════════════════════════════════════════════════════════════════════════════

_CPU_LIMIT = 2000   # 2 cores in millicores
_MEM_LIMIT = 4096   # 4 GiB in MiB
_INV_RESOURCE = [CPUMemoryGuard(_cpu_milli, _mem_mib, _CPU_LIMIT, _MEM_LIMIT)]


class TestCPUMemoryGuard:
    def test_sat_within_both_limits(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": 500, "mem_mib": 1024},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_cpu_exceeds_limit(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": 2500, "mem_mib": 1024},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "cpu_memory_guard" for v in result.violated)

    def test_unsat_mem_exceeds_limit(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": 500, "mem_mib": 5000},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_unsat_both_exceed_limits(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": 3000, "mem_mib": 8192},
            timeout_ms=5_000,
        )
        assert result.sat is False

    def test_boundary_at_cpu_limit(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": _CPU_LIMIT, "mem_mib": 1024},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_at_mem_limit(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": 500, "mem_mib": _MEM_LIMIT},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_both_at_limits(self) -> None:
        result = solve(
            _INV_RESOURCE,
            {"cpu_millicores": _CPU_LIMIT, "mem_mib": _MEM_LIMIT},
            timeout_ms=5_000,
        )
        assert result.sat is True
