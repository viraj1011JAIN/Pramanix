# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Adversarial documentation test — T5: TOCTOU awareness contract.

Security threat: T5 — Time-of-Check to Time-of-Use (TOCTOU) between
``verify()`` and action execution.

This is a **documentation/contract test**, NOT a security bypass test.
It demonstrates that:

  1.  ``verify()`` is stateless — each call evaluates the state provided to IT,
      not a stored snapshot.
  2.  Pramanix detects staleness on the *next* ``verify()`` call if
      ``state_version`` is rotated between verification and execution.
  3.  ``Decision.status == STALE_STATE`` is the sentinel that tells the host
      "the world changed — DO NOT execute this action."
  4.  The FAIL-SAFE path: if the host forgets to check ``state_version`` in its
      UPDATE WHERE clause, the *next* verify call will catch the drift.

CTO's note (sledgehammer review):
    An enterprise CISO will reject the SDK if this is not documented as a test.
    This test IS the documentation.  It demonstrates the Optimistic Concurrency
    pattern required of all host integrations.

Optimistic Concurrency Integration Pattern
------------------------------------------
The host MUST execute database mutations under an optimistic lock:

    UPDATE accounts
       SET balance       = balance - :amount,
           state_version = :new_version        -- rotate the version
     WHERE id            = :account_id
       AND state_version = :verified_version;  -- ← the version from verify()

    IF rows_affected == 0:
        -- Another writer changed the row between verify() and execute.
        -- BLOCK the action; re-verify with fresh state if appropriate.
        raise OptimisticLockError(...)

See ``docs/security.md §T5`` for the full threat model entry.
"""
from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

import pytest

from pramanix import E, Field, Guard, Policy
from pramanix.decision import SolverStatus

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr

# ── Shared policy ─────────────────────────────────────────────────────────────


class _TransferPolicy(Policy):
    """Minimal banking policy with version-aware state."""

    class Meta:
        version = "1.0"

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.balance) - E(cls.amount) >= Decimal("0")).named("non_negative_balance")]


_GUARD = Guard(_TransferPolicy)

# Starting state — version "1.0", balance 1 000.
_STATE_V1 = {
    "balance": Decimal("1000.00"),
    "state_version": "1.0",
}

# ── Tests ─────────────────────────────────────────────────────────────────────


class TestTOCTOUContract:
    """Demonstrate TOCTOU detection via state_version rotation."""

    # ── Scenario 1: Clean path — no version drift ──────────────────────────────

    def test_clean_verify_and_execute(self) -> None:
        """Happy path: state version is stable — Decision(allowed=True)."""
        decision = _GUARD.verify(
            intent={"amount": Decimal("500.00")},
            state=_STATE_V1,
        )
        assert decision.allowed is True
        assert decision.status is SolverStatus.SAFE

    # ── Scenario 2: Version drift detected on re-verify ───────────────────────

    def test_stale_state_detected_on_second_verify(self) -> None:
        """
        TOCTOU contract demonstration:

          T1: verify(intent, state_v1) → Decision(allowed=True, state_version="1.0")
          T2: attacker modifies account  → state_version now "2.0", balance drops to 0
          T3: host re-verifies with v1 state → STALE_STATE detected immediately

        The guard CANNOT prevent T2 (OS-level timing gap).  It CAN signal
        staleness on the subsequent call so the host aborts execution.
        """
        # T1: initial check passes on v1 state with 1 000 balance
        first_decision = _GUARD.verify(
            intent={"amount": Decimal("500.00")},
            state=_STATE_V1,
        )
        assert first_decision.allowed is True, "Pre-condition: first verify must pass"

        # T2: account state is mutated externally — version rotated to "2.0"
        # (In production this is the attacker's concurrent transaction completing.)
        mutated_state = {
            "balance": Decimal("0.00"),  # drained
            "state_version": "2.0",  # version rotated by the mutation
        }

        # T3: host re-verifies using the ORIGINAL intent but NEW state — STALE detected
        # (Guard's version check: Policy.Meta.version="1.0" vs state_version="2.0")
        stale_decision = _GUARD.verify(
            intent={"amount": Decimal("500.00")},
            state=mutated_state,
        )
        # The guard detects version mismatch before reaching the Z3 solver.
        assert (
            stale_decision.allowed is False
        ), "TOCTOU contract: Decision must be blocked when state_version changes."
        assert stale_decision.status is SolverStatus.STALE_STATE, (
            f"Expected STALE_STATE but got {stale_decision.status}. "
            "Check Guard.verify() step 4 (version check)."
        )

    def test_stale_state_is_always_blocked(self) -> None:
        """STALE_STATE must always produce allowed=False regardless of Z3 result."""
        stale_decision = _GUARD.verify(
            intent={"amount": Decimal("1.00")},
            state={"balance": Decimal("9999999.00"), "state_version": "99.0"},
        )
        assert stale_decision.allowed is False, (
            "Even a trivially safe intent must be blocked if state_version mismatches. "
            "The guard cannot reason about a state whose provenance is unknown."
        )
        assert stale_decision.status is SolverStatus.STALE_STATE

    # ── Scenario 3: Missing state_version → VALIDATION_FAILURE ────────────────

    def test_missing_state_version_is_blocked(self) -> None:
        """If state_version is absent entirely the request is blocked immediately."""
        decision = _GUARD.verify(
            intent={"amount": Decimal("100.00")},
            state={"balance": Decimal("1000.00")},  # no state_version key
        )
        assert decision.allowed is False
        # status is VALIDATION_FAILURE (missing field) not STALE_STATE (mismatch)
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    # ── Scenario 4: Correct version restores access ───────────────────────────

    def test_updated_state_with_matching_version_passes(self) -> None:
        """After a mutation, if the host RE-PROVISIONS the guard with the new
        Policy.Meta.version, a fresh verify with matching state_version passes."""

        # Note: this test re-creates the guard with version "2.0" to simulate
        # a policy upgrade.  In production the guard is recreated on deploy.
        class _PolicyV2(Policy):
            class Meta:
                version = "2.0"

            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    (E(cls.balance) - E(cls.amount) >= Decimal("0")).named("non_negative_balance")
                ]

        guard_v2 = Guard(_PolicyV2)
        decision = guard_v2.verify(
            intent={"amount": Decimal("50.00")},
            state={"balance": Decimal("500.00"), "state_version": "2.0"},
        )
        assert decision.allowed is True
        assert decision.status is SolverStatus.SAFE

    # ── Scenario 5: Optimistic lock pattern documentation ────────────────────

    def test_optimistic_lock_pattern_illustration(self) -> None:
        """
        Documents the host's responsibility: execute state mutations under
        an optimistic concurrency check.

        This test simulates the database-level enforcement:

            UPDATE accounts
               SET balance       = balance - 500,
                   state_version = 'v2'
             WHERE id            = 'acct-123'
               AND state_version = 'v1';   ← must match verified version

        If rows_affected == 0 (version was already different), the host must
        NOT execute and must re-verify.  Pramanix's ``state_version`` field is
        the token that makes this possible.
        """
        verify_result = _GUARD.verify(
            intent={"amount": Decimal("500.00")},
            state=_STATE_V1,
        )
        verified_version = _STATE_V1["state_version"]  # "1.0"

        assert verify_result.allowed is True
        assert verify_result.status is SolverStatus.SAFE

        # Simulate: SELECT state_version FROM accounts WHERE id = ?
        current_db_version = "1.0"  # no concurrent mutation → still "1.0"

        # Host applies optimistic lock check before executing:
        if current_db_version != verified_version:
            # Version changed between verify and execute — do NOT proceed.
            pytest.fail("Optimistic lock would fire — simulated concurrent mutation.")

        # Safe to execute: verified_version == current_db_version
        # In production: UPDATE ... WHERE state_version = verified_version
        # rows_affected == 1 → commit.

        # This assertion documents the contract: the SDK's Decision.allowed
        # is only actionable if the host confirms the version is still current.
        assert current_db_version == verified_version, (
            "Contract: host must verify state_version equality before executing "
            "any action based on a prior Decision(allowed=True)."
        )
