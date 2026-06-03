# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Coverage tests for guard_pipeline._semantic_post_consensus_check edge cases.

Targets:
  §4.12/22 — fail-closed non-numeric state injection: every corrupted state
             field must produce SemanticPolicyViolation, never silently pass.
  balance non-numeric: CORRUPTED, {}, NaN
  daily_limit / daily_spent non-numeric state injection
  dosage non-numeric (outer + inner)
  replica_count non-numeric (outer + inner)
  cpu_request / cpu_limit non-numeric
  memory_request / memory_limit non-numeric
"""

from __future__ import annotations

import pytest

from pramanix.exceptions import SemanticPolicyViolation
from pramanix.guard_pipeline import _semantic_post_consensus_check

# ── Balance / minimum-reserve: non-numeric state injection (§4.12/22) ─────────


@pytest.mark.parametrize(
    "corrupted_balance",
    [
        "CORRUPTED",
        {},
        "NaN",
        "not-a-number",
        "∞",
        [],
        object(),
    ],
    ids=[
        "string-CORRUPTED",
        "empty-dict",
        "NaN-string",
        "not-a-number",
        "unicode-infinity",
        "empty-list",
        "arbitrary-object",
    ],
)
def test_balance_non_numeric_raises_semantic_violation(corrupted_balance: object) -> None:
    """Corrupted balance state must produce SemanticPolicyViolation — not pass silently.

    Fail-closed invariant: when state integrity cannot be confirmed, the only
    correct response is DENY.  Silently passing the check creates an injection
    attack surface (§4.12).
    """
    with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
        _semantic_post_consensus_check(
            intent_dict={"amount": "100"},
            state_values={"balance": corrupted_balance, "minimum_reserve": "0"},
        )


def test_balance_none_skips_check() -> None:
    """balance=None is treated as absent — the guard skips the check entirely.

    This is the correct behavior: a missing key is not a corrupted value.
    The caller did not provide balance state, so the balance invariant does
    not apply for this call.
    """
    _semantic_post_consensus_check(
        intent_dict={"amount": "100"},
        state_values={"balance": None, "minimum_reserve": "0"},
    )


def test_balance_corrupted_minimum_reserve_raises_semantic_violation() -> None:
    """Corrupted minimum_reserve with valid balance still produces SemanticPolicyViolation."""
    with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
        _semantic_post_consensus_check(
            intent_dict={"amount": "100"},
            state_values={"balance": "500", "minimum_reserve": "CORRUPTED"},
        )


# ── Daily limit: non-numeric state injection ───────────────────────────────────


@pytest.mark.parametrize(
    ("raw_daily_limit", "raw_daily_spent"),
    [
        ("UNLIMITED", "50"),
        ("500", "NOT_A_NUMBER"),
        ({}, "50"),
        ("500", {}),
    ],
    ids=[
        "daily_limit-corrupted",
        "daily_spent-corrupted",
        "daily_limit-dict",
        "daily_spent-dict",
    ],
)
def test_daily_limit_non_numeric_raises_semantic_violation(
    raw_daily_limit: object,
    raw_daily_spent: object,
) -> None:
    """Corrupted daily_limit or daily_spent must produce SemanticPolicyViolation."""
    with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
        _semantic_post_consensus_check(
            intent_dict={"amount": "100"},
            state_values={
                "balance": "10000",
                "daily_limit": raw_daily_limit,
                "daily_spent": raw_daily_spent,
            },
        )


# ── Dosage: outer and inner non-numeric paths ──────────────────────────────────


class TestSemanticCheckDosagePaths:
    """Dosage-related branches in _semantic_post_consensus_check."""

    def test_dosage_no_max_daily_dose_skips_inner_check(self) -> None:
        """dosage present but max_daily_dose absent → inner block skipped, no violation."""
        _semantic_post_consensus_check(
            intent_dict={"dosage": "50"},
            state_values={},
        )

    def test_dosage_only_max_daily_dose_no_total_skips_inner_check(self) -> None:
        """max_daily_dose present but total_daily_dose missing → skip inner check."""
        _semantic_post_consensus_check(
            intent_dict={"dosage": "50"},
            state_values={"max_daily_dose": "200"},
        )

    def test_dosage_inner_non_numeric_raises_semantic_violation(self) -> None:
        """Non-numeric max_daily_dose in inner check → SemanticPolicyViolation (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
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

    @pytest.mark.parametrize(
        "corrupted_dosage",
        ["MAX", "not-a-number", {}, "∞"],
        ids=["MAX-string", "not-a-number", "empty-dict", "unicode-infinity"],
    )
    def test_dosage_outer_non_numeric_raises_semantic_violation(
        self, corrupted_dosage: object
    ) -> None:
        """Non-numeric dosage → SemanticPolicyViolation — never silently passes (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
            _semantic_post_consensus_check(
                intent_dict={"dosage": corrupted_dosage},
                state_values={"max_daily_dose": "200", "total_daily_dose": "50"},
            )


# ── Replica: outer and inner non-numeric paths ─────────────────────────────────


class TestSemanticCheckReplicaPaths:
    """Replica-related branches in _semantic_post_consensus_check."""

    def test_replicas_no_max_replicas_skips_inner_check(self) -> None:
        """replica_count present but max_replicas absent → inner block skipped."""
        _semantic_post_consensus_check(
            intent_dict={"replica_count": "3"},
            state_values={},
        )

    def test_replicas_inner_non_numeric_raises_semantic_violation(self) -> None:
        """Non-numeric max_replicas → SemanticPolicyViolation (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
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

    @pytest.mark.parametrize(
        "corrupted_replicas",
        ["unlimited", "not-a-number", {}, "∞"],
        ids=["unlimited-string", "not-a-number", "empty-dict", "unicode-infinity"],
    )
    def test_replicas_outer_non_numeric_raises_semantic_violation(
        self, corrupted_replicas: object
    ) -> None:
        """Non-numeric replica_count → SemanticPolicyViolation — never silently passes (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
            _semantic_post_consensus_check(
                intent_dict={"replica_count": corrupted_replicas},
                state_values={"max_replicas": "5"},
            )


# ── CPU and memory: non-numeric paths ─────────────────────────────────────────


class TestSemanticCheckCpuMemoryPaths:
    """CPU and memory exception paths in _semantic_post_consensus_check."""

    def test_cpu_non_numeric_request_raises_semantic_violation(self) -> None:
        """Non-numeric cpu_request → SemanticPolicyViolation (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
            _semantic_post_consensus_check(
                intent_dict={"cpu_request": "not-a-cpu-value"},
                state_values={"cpu_limit": "4.0"},
            )

    def test_cpu_non_numeric_limit_raises_semantic_violation(self) -> None:
        """Non-numeric cpu_limit → SemanticPolicyViolation (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
            _semantic_post_consensus_check(
                intent_dict={"cpu_request": "2.0"},
                state_values={"cpu_limit": "not-a-limit"},
            )

    def test_memory_non_numeric_request_raises_semantic_violation(self) -> None:
        """Non-numeric memory_request → SemanticPolicyViolation (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
            _semantic_post_consensus_check(
                intent_dict={"memory_request": "not-a-mem-value"},
                state_values={"memory_limit": "1024"},
            )

    def test_memory_non_numeric_limit_raises_semantic_violation(self) -> None:
        """Non-numeric memory_limit → SemanticPolicyViolation (§4.12)."""
        with pytest.raises(SemanticPolicyViolation, match="safe-default deny applied"):
            _semantic_post_consensus_check(
                intent_dict={"memory_request": "512"},
                state_values={"memory_limit": "not-a-limit"},
            )
