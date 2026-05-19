# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Coverage tests for guard_pipeline._semantic_post_consensus_check edge cases.

Targets:
  guard_pipeline.py  120->138   dosage present but max_daily_dose is None
  guard_pipeline.py  130-131    non-numeric inner dosage-limit check
  guard_pipeline.py  147->163   replica_count present but max_replicas is None
  guard_pipeline.py  156-157    non-numeric inner replica-limit check
  guard_pipeline.py  175-176    non-numeric CPU check
  guard_pipeline.py  190-191    non-numeric memory check
"""
from __future__ import annotations

import pytest

from pramanix.guard_pipeline import _semantic_post_consensus_check
from pramanix.exceptions import SemanticPolicyViolation


class TestSemanticCheckDosagePaths:
    """Dosage-related branches in _semantic_post_consensus_check."""

    def test_dosage_no_max_daily_dose_skips_inner_check(self) -> None:
        """dosage present but max_daily_dose is None → skip inner try block (120->138)."""
        # No SemanticPolicyViolation raised since max_daily_dose is absent.
        _semantic_post_consensus_check(
            intent_dict={"dosage": "50"},
            state_values={},  # no max_daily_dose or total_daily_dose
        )

    def test_dosage_only_max_daily_dose_no_total_skips_inner_check(self) -> None:
        """max_daily_dose present but total_daily_dose missing → skip inner check."""
        _semantic_post_consensus_check(
            intent_dict={"dosage": "50"},
            state_values={"max_daily_dose": "200"},  # no total_daily_dose
        )

    def test_dosage_inner_non_numeric_exception_path(self) -> None:
        """Non-numeric max_daily_dose in inner check → except path (130-131)."""
        # Both max and total are present but non-numeric → inner except handler fires.
        _semantic_post_consensus_check(
            intent_dict={"dosage": "50"},
            state_values={
                "max_daily_dose": "not-a-number",
                "total_daily_dose": "also-not-a-number",
            },
        )

    def test_dosage_exceeds_remaining_blocks(self) -> None:
        """dosage > remaining daily allowance → SemanticPolicyViolation."""
        with pytest.raises(SemanticPolicyViolation, match="daily dose allowance"):
            _semantic_post_consensus_check(
                intent_dict={"dosage": "200"},
                state_values={"max_daily_dose": "100", "total_daily_dose": "50"},
            )

    def test_dosage_outer_non_numeric_exception_path(self) -> None:
        """Non-numeric dosage → outer except path (134-135)."""
        _semantic_post_consensus_check(
            intent_dict={"dosage": "not-a-number"},
            state_values={"max_daily_dose": "200", "total_daily_dose": "50"},
        )


class TestSemanticCheckReplicaPaths:
    """Replica-related branches in _semantic_post_consensus_check."""

    def test_replicas_no_max_replicas_skips_inner_check(self) -> None:
        """replica_count present but max_replicas absent → skip inner block (147->163)."""
        _semantic_post_consensus_check(
            intent_dict={"replica_count": "3"},
            state_values={},  # no max_replicas
        )

    def test_replicas_inner_non_numeric_exception_path(self) -> None:
        """Non-numeric max_replicas → inner except path (156-157)."""
        _semantic_post_consensus_check(
            intent_dict={"replica_count": "3"},
            state_values={"max_replicas": "not-a-number"},
        )

    def test_replicas_exceeds_max_blocks(self) -> None:
        """requested_replicas > max_replicas → SemanticPolicyViolation."""
        with pytest.raises(SemanticPolicyViolation, match="exceeds cluster max"):
            _semantic_post_consensus_check(
                intent_dict={"requested_replicas": "10"},
                state_values={"max_replicas": "5"},
            )

    def test_replicas_outer_non_numeric_exception_path(self) -> None:
        """Non-numeric replica_count → outer except path (160-161)."""
        _semantic_post_consensus_check(
            intent_dict={"replica_count": "not-a-number"},
            state_values={"max_replicas": "5"},
        )


class TestSemanticCheckCpuMemoryPaths:
    """CPU and memory exception paths in _semantic_post_consensus_check."""

    def test_cpu_non_numeric_request_exception_path(self) -> None:
        """Non-numeric cpu_request → except path (175-176)."""
        _semantic_post_consensus_check(
            intent_dict={"cpu_request": "not-a-cpu-value"},
            state_values={"cpu_limit": "4.0"},
        )

    def test_cpu_non_numeric_limit_exception_path(self) -> None:
        """Non-numeric cpu_limit → except path (175-176)."""
        _semantic_post_consensus_check(
            intent_dict={"cpu_request": "2.0"},
            state_values={"cpu_limit": "not-a-limit"},
        )

    def test_memory_non_numeric_request_exception_path(self) -> None:
        """Non-numeric memory_request → except path (190-191)."""
        _semantic_post_consensus_check(
            intent_dict={"memory_request": "not-a-mem-value"},
            state_values={"memory_limit": "1024"},
        )

    def test_memory_non_numeric_limit_exception_path(self) -> None:
        """Non-numeric memory_limit → except path (190-191)."""
        _semantic_post_consensus_check(
            intent_dict={"memory_request": "512"},
            state_values={"memory_limit": "not-a-limit"},
        )
