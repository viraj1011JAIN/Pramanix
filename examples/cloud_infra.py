#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Cloud infrastructure scaling policy example.

Demonstrates:
* MinReplicas / MaxReplicas / resource budget constraints
* Policy violations for out-of-bounds scaling requests

Run::

    python examples/cloud_infra.py
"""
from __future__ import annotations

from pramanix import Field, Guard, GuardConfig, Policy
from pramanix.primitives.infra import MaxReplicas, MinReplicas, WithinCPUBudget, WithinMemoryBudget


class ScalingPolicy(Policy):
    """Policy governing Kubernetes replica and resource scaling operations."""

    class Meta:
        name = "k8s_scaling"
        version = "1.0"

    # Intent fields (what the operator wants to set)
    replicas = Field("replicas", int, "Int")
    cpu_request = Field("cpu_request", int, "Int")   # millicores
    mem_request = Field("mem_request", int, "Int")   # MiB

    # State fields (cluster limits)
    min_r = Field("min_r", int, "Int")
    max_r = Field("max_r", int, "Int")
    cpu_budget = Field("cpu_budget", int, "Int")     # millicores
    mem_budget = Field("mem_budget", int, "Int")     # MiB

    @classmethod
    def invariants(cls) -> list:
        return [
            MinReplicas(cls.replicas, cls.min_r),
            MaxReplicas(cls.replicas, cls.max_r),
            WithinCPUBudget(cls.cpu_request, cls.cpu_budget),
            WithinMemoryBudget(cls.mem_request, cls.mem_budget),
        ]


guard = Guard(ScalingPolicy, GuardConfig(execution_mode="sync"))

_CLUSTER_STATE = {
    "min_r": 2,
    "max_r": 20,
    "cpu_budget": 4000,   # 4 cores
    "mem_budget": 8192,   # 8 GiB
    "state_version": "1.0",
}


def run() -> None:
    print("=== Cloud Infrastructure Scaling Policy ===\n")

    # Scenario A: Valid scale-up
    d = guard.verify(
        intent={"replicas": 5, "cpu_request": 1000, "mem_request": 2048},
        state=_CLUSTER_STATE,
    )
    print(f"Scenario A (replicas=5, ok):      allowed={d.allowed} | {d.status.value}")
    assert d.allowed

    # Scenario B: Scale below minimum
    d = guard.verify(
        intent={"replicas": 1, "cpu_request": 500, "mem_request": 512},
        state=_CLUSTER_STATE,
    )
    print(f"Scenario B (replicas=1 < min=2):  allowed={d.allowed} | {d.violated_invariants}")
    assert not d.allowed and "min_replicas" in d.violated_invariants

    # Scenario C: Exceed max replicas
    d = guard.verify(
        intent={"replicas": 50, "cpu_request": 500, "mem_request": 512},
        state=_CLUSTER_STATE,
    )
    print(f"Scenario C (replicas=50 > max=20): allowed={d.allowed} | {d.violated_invariants}")
    assert not d.allowed and "max_replicas" in d.violated_invariants

    # Scenario D: Exceed memory budget
    d = guard.verify(
        intent={"replicas": 3, "cpu_request": 500, "mem_request": 16384},
        state=_CLUSTER_STATE,
    )
    print(f"Scenario D (mem=16GiB > budget=8GiB): allowed={d.allowed} | {d.violated_invariants}")
    assert not d.allowed and "within_memory_budget" in d.violated_invariants

    print("\n✅ All cloud infrastructure scenarios passed.")


if __name__ == "__main__":
    run()
