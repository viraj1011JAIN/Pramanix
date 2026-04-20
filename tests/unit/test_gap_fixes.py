# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for all engineering-gap fixes.

These tests verify every fix applied in the gap-hardening pass:

    G1  Z3Type now includes "String"
    G2  abs() / abs_expr() / __neg__ DSL operators
    G3  Transpiler handles _AbsOp in all tree-walking paths
    G4  Decision.from_dict() round-trip deserialisation
    G5  Decision.__repr__ never exposes sensitive fields
    G6  ExecutionTokenVerifier consumed-set TTL eviction (no unbounded growth)
    G7  GuardConfig raises ConfigurationError for shed_worker_pct out of range
    G8  GuardConfig raises ConfigurationError for shed_latency_threshold_ms <= 0
    G9  Guard max_input_bytes is enforced for Pydantic BaseModel inputs
    G10 FailsafeMode.ALLOW_WITH_AUDIT emits DeprecationWarning
"""
from __future__ import annotations

import secrets
import time
import warnings
from decimal import Decimal
from typing import Any, get_args

import pytest
from pydantic import BaseModel

from pramanix.circuit_breaker import CircuitBreakerConfig, FailsafeMode
from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import ConfigurationError
from pramanix.execution_token import ExecutionTokenSigner, ExecutionTokenVerifier
from pramanix.expressions import (
    E,
    Field,
    Z3Type,
    abs_expr,
)
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy


# -----------------------------------------------------------------------------
# Reusable Field definitions and policies
# -----------------------------------------------------------------------------

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")
_loss = Field("loss", Decimal, "Real")


# -----------------------------------------------------------------------------
# G1  Z3Type includes "String"
# -----------------------------------------------------------------------------


def test_z3type_includes_string() -> None:
    """Z3Type Literal must enumerate 'String' in addition to the numeric sorts."""
    assert "String" in get_args(Z3Type), (
        "Z3Type Literal does not include 'String' - type annotation is incomplete"
    )


def test_z3type_still_includes_numeric_sorts() -> None:
    """Existing sorts must not have been removed."""
    args = get_args(Z3Type)
    for sort in ("Real", "Int", "Bool"):
        assert sort in args, f"Z3Type is missing existing sort '{sort}'"


# -----------------------------------------------------------------------------
# G2 / G3  abs() / abs_expr() / __neg__ DSL operators + transpiler support
# -----------------------------------------------------------------------------


def test_abs_method_returns_expression_node() -> None:
    """ExpressionNode.abs() must return an ExpressionNode."""
    from pramanix.expressions import ExpressionNode

    result = E(_amount).abs()
    assert isinstance(result, ExpressionNode), (
        "ExpressionNode.abs() must return an ExpressionNode"
    )


def test_abs_expr_convenience_returns_expression_node() -> None:
    """abs_expr() module-level function must accept an ExpressionNode."""
    from pramanix.expressions import ExpressionNode

    result = abs_expr(E(_balance))
    assert isinstance(result, ExpressionNode)


def test_neg_operator() -> None:
    """ExpressionNode.__neg__ must return an ExpressionNode."""
    from pramanix.expressions import ExpressionNode

    neg = -E(_amount)
    assert isinstance(neg, ExpressionNode), "__neg__ must return an ExpressionNode"


def test_abs_policy_safe_on_positive() -> None:
    """abs(amount) >= 0 is always SAFE - verify it does not block."""

    class _AbsPolicy(Policy):
        amount = _amount

        @classmethod
        def invariants(cls):
            return [
                (E(cls.amount).abs() >= Decimal("0")).named("abs_nonneg")
            ]

    guard = Guard(_AbsPolicy)
    decision = guard.verify({"amount": 100.0}, {})
    assert decision.allowed, f"Expected SAFE, got: {decision}"


def test_abs_policy_safe_on_negative() -> None:
    """|amount| >= 0 is SAFE even when amount is negative (abs makes it positive)."""

    class _AbsPolicy2(Policy):
        amount = _amount

        @classmethod
        def invariants(cls):
            return [
                (E(cls.amount).abs() >= Decimal("0")).named("abs_nonneg")
            ]

    guard = Guard(_AbsPolicy2)
    decision = guard.verify({"amount": -50.0}, {})
    assert decision.allowed, f"Expected SAFE for negative input: {decision}"


def test_abs_financial_invariant_blocks_large_loss() -> None:
    """|loss| > max_loss must produce UNSAFE when abs(loss) exceeds threshold."""

    class _LossPolicy(Policy):
        loss = _loss

        @classmethod
        def invariants(cls):
            # Allow up to 1000 loss in either direction
            return [
                (abs_expr(E(cls.loss)) <= Decimal("1000")).named("max_loss")
            ]

    guard = Guard(_LossPolicy)

    safe = guard.verify({"loss": -500.0}, {})
    assert safe.allowed, "abs(-500) = 500 <= 1000 - should be SAFE"

    unsafe = guard.verify({"loss": -2000.0}, {})
    assert not unsafe.allowed, "abs(-2000) = 2000 > 1000 - should be UNSAFE"


def test_neg_in_constraint() -> None:
    """Negation operator compiles and produces sensible results."""

    class _NegPolicy(Policy):
        balance = _balance

        @classmethod
        def invariants(cls):
            # -balance <= 0  -  balance >= 0
            return [(-E(cls.balance) <= Decimal("0")).named("nonneg")]

    guard = Guard(_NegPolicy)

    assert guard.verify({"balance": 100.0}, {}).allowed
    assert not guard.verify({"balance": -1.0}, {}).allowed


# -----------------------------------------------------------------------------
# G4  Decision.from_dict() round-trip
# -----------------------------------------------------------------------------


def test_decision_from_dict_round_trip_safe() -> None:
    """A SAFE Decision must round-trip through to_dict() / from_dict()."""
    original = Decision.safe(
        solver_time_ms=3.14,
        intent_dump={"amount": 100},
        state_dump={"balance": 500},
    )
    serialised = original.to_dict()
    restored = Decision.from_dict(serialised)

    assert restored.allowed == original.allowed
    assert restored.status == original.status
    assert restored.decision_id == original.decision_id
    assert restored.violated_invariants == original.violated_invariants
    assert restored.explanation == original.explanation
    assert restored.solver_time_ms == original.solver_time_ms


def test_decision_from_dict_round_trip_unsafe() -> None:
    """An UNSAFE Decision with violated invariants must round-trip correctly."""
    original = Decision.unsafe(
        violated_invariants=("balance_non_negative", "rate_limit"),
        explanation="two invariants failed",
        intent_dump={"tx": 999},
        state_dump={},
    )
    restored = Decision.from_dict(original.to_dict())

    assert not restored.allowed
    assert restored.status == SolverStatus.UNSAFE
    assert set(restored.violated_invariants) == {"balance_non_negative", "rate_limit"}


def test_decision_from_dict_preserves_decision_id() -> None:
    """decision_id must be preserved exactly after round-trip."""
    original = Decision.error(reason="oops")
    d = original.to_dict()
    assert Decision.from_dict(d).decision_id == original.decision_id


def test_decision_from_dict_invalid_status_raises() -> None:
    """from_dict() must raise ValueError for an unrecognised status string."""
    d = Decision.safe().to_dict()
    d["status"] = "not_a_real_status"
    with pytest.raises(ValueError):
        Decision.from_dict(d)


# -----------------------------------------------------------------------------
# G5  Decision.__repr__ never exposes sensitive fields
# -----------------------------------------------------------------------------


def test_decision_repr_excludes_intent_dump() -> None:
    """__repr__ must not contain intent_dump data."""
    d = Decision.safe(intent_dump={"secret_pin": "1234"}, state_dump={"ssn": "***"})
    r = repr(d)
    assert "secret_pin" not in r
    assert "1234" not in r
    assert "ssn" not in r
    assert "***" not in r


def test_decision_repr_includes_key_fields() -> None:
    """__repr__ must include decision_id prefix, allowed, and status."""
    d = Decision.unsafe(violated_invariants=("inv1",))
    r = repr(d)
    assert d.decision_id[:8] in r
    assert "False" in r
    assert "UNSAFE" in r


def test_decision_repr_safe_includes_allowed_true() -> None:
    d = Decision.safe()
    r = repr(d)
    assert "True" in r
    assert "SAFE" in r


# -----------------------------------------------------------------------------
# G6  ExecutionTokenVerifier consumed-set TTL eviction
# -----------------------------------------------------------------------------


def test_evict_expired_reduces_consumed_count() -> None:
    """Expired token IDs must be evicted so consumed_count does not grow forever."""
    key = secrets.token_bytes(32)
    signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=0.05)  # 50 ms TTL
    verifier = ExecutionTokenVerifier(secret_key=key)

    # Mint and consume several tokens with very short TTL
    for _ in range(5):
        safe_decision = Decision.safe(intent_dump={"x": 1})
        token = signer.mint(safe_decision)
        verifier.consume(token)

    assert verifier.consumed_count() == 5

    # Wait for TTL to expire, then force eviction explicitly
    time.sleep(0.1)
    evicted = verifier.evict_expired()
    assert evicted == 5, f"Expected 5 evictions, got {evicted}"
    assert verifier.consumed_count() == 0, "consumed_count should be 0 after full eviction"


def test_consumed_count_lazy_eviction_via_consume() -> None:
    """consume() must trigger lazy eviction so the set stays bounded."""
    key = secrets.token_bytes(32)
    signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=0.05)
    verifier = ExecutionTokenVerifier(secret_key=key)

    # Consume one short-lived token
    t1 = signer.mint(Decision.safe(intent_dump={"a": 1}))
    verifier.consume(t1)
    assert verifier.consumed_count() == 1

    time.sleep(0.1)  # let it expire

    # Consuming a NEW token triggers eviction of the old one
    t2 = signer.mint(Decision.safe(intent_dump={"a": 2}))
    verifier.consume(t2)

    # After eviction + new entry, count should be 1 (not 2)
    assert verifier.consumed_count() == 1


# -----------------------------------------------------------------------------
# G7 / G8  GuardConfig shed_worker_pct and shed_latency_threshold_ms validation
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("bad_pct", [0.0, -1.0, 101.0, 200.0])
def test_guard_config_shed_worker_pct_invalid(bad_pct: float) -> None:
    """shed_worker_pct outside out of range must raise ConfigurationError."""
    with pytest.raises(ConfigurationError):
        GuardConfig(shed_worker_pct=bad_pct)


@pytest.mark.parametrize("good_pct", [0.1, 50.0, 90.0, 100.0])
def test_guard_config_shed_worker_pct_valid(good_pct: float) -> None:
    """shed_worker_pct within in valid range must not raise."""
    cfg = GuardConfig(shed_worker_pct=good_pct)
    assert cfg.shed_worker_pct == good_pct


@pytest.mark.parametrize("bad_ms", [0.0, -1.0, -100.0])
def test_guard_config_shed_latency_threshold_invalid(bad_ms: float) -> None:
    """shed_latency_threshold_ms <= 0 must raise ConfigurationError."""
    with pytest.raises(ConfigurationError):
        GuardConfig(shed_latency_threshold_ms=bad_ms)


def test_guard_config_shed_latency_threshold_valid() -> None:
    """shed_latency_threshold_ms > 0 must not raise."""
    cfg = GuardConfig(shed_latency_threshold_ms=100.0)
    assert cfg.shed_latency_threshold_ms == 100.0


# -----------------------------------------------------------------------------
# G9  Guard max_input_bytes enforced for Pydantic BaseModel inputs
# -----------------------------------------------------------------------------


class _IntentModel(BaseModel):
    payload: str


class _SizeTestPolicy(Policy):
    balance = _balance

    @classmethod
    def invariants(cls):
        # Trivially-true invariant so policy is valid
        return [(E(cls.balance) >= Decimal("-999999")).named("balance_floor")]


def test_max_input_bytes_enforced_for_basemodel_intent() -> None:
    """A large Pydantic BaseModel intent must be rejected when it exceeds the cap."""
    guard = Guard(_SizeTestPolicy, config=GuardConfig(max_input_bytes=50))

    # Create a large payload that definitely exceeds 50 bytes
    large_intent = _IntentModel(payload="x" * 500)
    decision = guard.verify(large_intent, {})

    assert not decision.allowed, (
        "A BaseModel payload exceeding max_input_bytes must be blocked (fail-closed)"
    )
    # Explanation should mention the size limit
    combined = (decision.explanation or "").lower()
    assert "exceed" in combined or "size" in combined or "bytes" in combined, (
        f"Explanation should mention size limit, got: {decision.explanation!r}"
    )


def test_max_input_bytes_passes_for_small_basemodel() -> None:
    """A small Pydantic BaseModel intent within the cap must not be blocked by size check."""
    guard = Guard(_SizeTestPolicy, config=GuardConfig(max_input_bytes=10_000))

    intent = _IntentModel(payload="hello")
    decision = guard.verify(intent, {})
    # Size guard must not block; allowed since no invariants
    assert "exceed" not in (decision.explanation or "").lower(), (
        "Small BaseModel should not be blocked by size guard"
    )


def test_max_input_bytes_zero_disables_check() -> None:
    """max_input_bytes=0 means disabled - even large inputs must not be blocked by size."""
    guard = Guard(_SizeTestPolicy, config=GuardConfig(max_input_bytes=0))

    large = _IntentModel(payload="z" * 10_000)
    decision = guard.verify(large, {})
    # Must not be blocked because of the size check
    assert "exceed" not in (decision.explanation or "").lower(), (
        "max_input_bytes=0 should disable the size check"
    )


# -----------------------------------------------------------------------------
# G10  FailsafeMode.ALLOW_WITH_AUDIT emits DeprecationWarning
# -----------------------------------------------------------------------------


def test_allow_with_audit_emits_deprecation_warning() -> None:
    """CircuitBreakerConfig(failsafe_mode=ALLOW_WITH_AUDIT) must emit DeprecationWarning."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CircuitBreakerConfig(failsafe_mode=FailsafeMode.ALLOW_WITH_AUDIT)

    deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation_warnings, (
        "FailsafeMode.ALLOW_WITH_AUDIT must emit a DeprecationWarning at construction"
    )
    msg = str(deprecation_warnings[0].message).lower()
    assert "deprecated" in msg or "block_all" in msg, (
        f"DeprecationWarning message should mention 'deprecated' or 'BLOCK_ALL', got: {msg!r}"
    )


def test_block_all_does_not_emit_warning() -> None:
    """CircuitBreakerConfig(failsafe_mode=BLOCK_ALL) must NOT emit any DeprecationWarning."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CircuitBreakerConfig(failsafe_mode=FailsafeMode.BLOCK_ALL)

    deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert not deprecation_warnings, (
        "BLOCK_ALL must not trigger a DeprecationWarning"
    )


