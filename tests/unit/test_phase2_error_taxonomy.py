# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Phase 2 — Error Taxonomy: error_domain + stack_trace_hash on Decision.

STOP 2 fix: previously all errors collapsed to Decision.error() with no way
to distinguish PolicyViolation vs ResourceExhaustion vs SystemFault.  These
tests verify the taxonomy is correct, auto-populated, and not spoofable.
"""

from __future__ import annotations

import hashlib

import pytest

from pramanix.decision import Decision, SolverStatus, _ERROR_DOMAIN_MAP


# ── 1. _ERROR_DOMAIN_MAP coverage ─────────────────────────────────────────────


class TestErrorDomainMap:
    def test_map_has_entry_for_every_solver_status(self) -> None:
        for status in SolverStatus:
            assert status.value in _ERROR_DOMAIN_MAP, (
                f"SolverStatus.{status.name} ({status.value!r}) has no entry "
                "in _ERROR_DOMAIN_MAP.  Add it before shipping."
            )

    def test_safe_maps_to_none(self) -> None:
        assert _ERROR_DOMAIN_MAP["safe"] is None

    def test_cache_hit_maps_to_none(self) -> None:
        assert _ERROR_DOMAIN_MAP["cache_hit"] is None

    def test_unsafe_maps_to_policy_violation(self) -> None:
        assert _ERROR_DOMAIN_MAP["unsafe"] == "policy_violation"

    def test_timeout_maps_to_resource_exhaustion(self) -> None:
        assert _ERROR_DOMAIN_MAP["timeout"] == "resource_exhaustion"

    def test_rate_limited_maps_to_resource_exhaustion(self) -> None:
        assert _ERROR_DOMAIN_MAP["rate_limited"] == "resource_exhaustion"

    def test_error_maps_to_system_fault(self) -> None:
        assert _ERROR_DOMAIN_MAP["error"] == "system_fault"

    def test_stale_state_maps_to_state_integrity(self) -> None:
        assert _ERROR_DOMAIN_MAP["stale_state"] == "state_integrity"

    def test_validation_failure_maps_to_state_integrity(self) -> None:
        assert _ERROR_DOMAIN_MAP["validation_failure"] == "state_integrity"

    def test_consensus_failure_maps_to_consensus(self) -> None:
        assert _ERROR_DOMAIN_MAP["consensus_failure"] == "consensus"

    def test_governance_blocked_maps_to_governance(self) -> None:
        assert _ERROR_DOMAIN_MAP["governance_blocked"] == "governance"

    def test_no_unknown_domains_exist(self) -> None:
        known = {None, "policy_violation", "resource_exhaustion", "system_fault",
                 "state_integrity", "consensus", "governance"}
        actual = set(_ERROR_DOMAIN_MAP.values())
        assert actual <= known, f"Unknown domain values: {actual - known}"


# ── 2. Auto-population from status ────────────────────────────────────────────


class TestAutoPopulatedErrorDomain:
    """error_domain is always auto-populated from status in __post_init__."""

    def test_safe_decision_error_domain_is_none(self) -> None:
        d = Decision.safe()
        assert d.error_domain is None

    def test_unsafe_decision_error_domain_is_policy_violation(self) -> None:
        d = Decision.unsafe(violated_invariants=("inv_a",))
        assert d.error_domain == "policy_violation"

    def test_timeout_decision_error_domain_is_resource_exhaustion(self) -> None:
        d = Decision.timeout(label="inv_a", timeout_ms=500)
        assert d.error_domain == "resource_exhaustion"

    def test_error_decision_error_domain_is_system_fault_by_default(self) -> None:
        d = Decision.error(reason="boom")
        assert d.error_domain == "system_fault"

    def test_stale_state_decision_error_domain_is_state_integrity(self) -> None:
        d = Decision.stale_state(expected="v1", actual="v2")
        assert d.error_domain == "state_integrity"

    def test_validation_failure_decision_error_domain_is_state_integrity(self) -> None:
        d = Decision.validation_failure(reason="bad field")
        assert d.error_domain == "state_integrity"

    def test_rate_limited_decision_error_domain_is_resource_exhaustion(self) -> None:
        d = Decision.rate_limited()
        assert d.error_domain == "resource_exhaustion"

    def test_consensus_failure_decision_error_domain_is_consensus(self) -> None:
        d = Decision.consensus_failure()
        assert d.error_domain == "consensus"

    def test_governance_blocked_decision_error_domain_is_governance(self) -> None:
        d = Decision.governance_blocked(reason="scope denied", stage="privilege")
        assert d.error_domain == "governance"

    def test_cache_hit_decision_inherits_base_error_domain(self) -> None:
        base = Decision.safe()
        cached = Decision.cache_hit(base=base)
        assert cached.error_domain is None

    def test_cache_hit_on_unsafe_base_inherits_policy_violation(self) -> None:
        base = Decision.unsafe(violated_invariants=("inv_x",))
        cached = Decision.cache_hit(base=base)
        assert cached.error_domain == "policy_violation"


# ── 3. error_domain override on Decision.error() ──────────────────────────────


class TestErrorDomainOverride:
    """error() factory accepts an explicit error_domain for fine-grained ops routing."""

    def test_circuit_breaker_override_resource_exhaustion(self) -> None:
        d = Decision.error(
            reason="Circuit breaker OPEN",
            error_domain="resource_exhaustion",
        )
        assert d.error_domain == "resource_exhaustion"

    def test_input_validation_override_state_integrity(self) -> None:
        d = Decision.error(
            reason="Input payload too large",
            error_domain="state_integrity",
        )
        assert d.error_domain == "state_integrity"

    def test_explicit_system_fault_stays_system_fault(self) -> None:
        d = Decision.error(
            reason="IPC integrity failure",
            error_domain="system_fault",
        )
        assert d.error_domain == "system_fault"

    def test_none_override_falls_back_to_auto_system_fault(self) -> None:
        d = Decision.error(reason="boom", error_domain=None)
        assert d.error_domain == "system_fault"


# ── 4. stack_trace_hash ────────────────────────────────────────────────────────


class TestStackTraceHash:
    def test_error_without_traceback_str_has_none_hash(self) -> None:
        d = Decision.error(reason="no traceback")
        assert d.stack_trace_hash is None

    def test_error_with_traceback_str_computes_sha256(self) -> None:
        tb = "Traceback (most recent call last):\n  File x.py, line 1\nValueError: bad"
        expected = hashlib.sha256(tb.encode()).hexdigest()
        d = Decision.error(reason="boom", traceback_str=tb)
        assert d.stack_trace_hash == expected

    def test_stack_trace_hash_is_64_char_lowercase_hex(self) -> None:
        import re
        d = Decision.error(reason="fault", traceback_str="some traceback")
        assert d.stack_trace_hash is not None
        assert len(d.stack_trace_hash) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", d.stack_trace_hash)

    def test_same_traceback_same_hash(self) -> None:
        tb = "TypeError: expected int got str"
        d1 = Decision.error(reason="r", traceback_str=tb)
        d2 = Decision.error(reason="different reason", traceback_str=tb)
        assert d1.stack_trace_hash == d2.stack_trace_hash

    def test_different_tracebacks_different_hashes(self) -> None:
        d1 = Decision.error(reason="r", traceback_str="tb A")
        d2 = Decision.error(reason="r", traceback_str="tb B")
        assert d1.stack_trace_hash != d2.stack_trace_hash

    def test_safe_decision_stack_trace_hash_is_none(self) -> None:
        assert Decision.safe().stack_trace_hash is None

    def test_unsafe_decision_stack_trace_hash_is_none(self) -> None:
        assert Decision.unsafe().stack_trace_hash is None

    def test_cache_hit_preserves_stack_trace_hash(self) -> None:
        base = Decision.error(reason="fault", traceback_str="tb content")
        cached = Decision.cache_hit(base=base)
        assert cached.stack_trace_hash == base.stack_trace_hash

    def test_cache_hit_on_safe_base_stack_trace_hash_is_none(self) -> None:
        base = Decision.safe()
        cached = Decision.cache_hit(base=base)
        assert cached.stack_trace_hash is None


# ── 5. Wire format (to_dict / from_dict) ──────────────────────────────────────


class TestWireFormat:
    def test_to_dict_includes_error_domain(self) -> None:
        d = Decision.unsafe(violated_invariants=("inv",))
        wire = d.to_dict()
        assert "error_domain" in wire
        assert wire["error_domain"] == "policy_violation"

    def test_to_dict_includes_stack_trace_hash(self) -> None:
        d = Decision.error(reason="boom", traceback_str="tb")
        wire = d.to_dict()
        assert "stack_trace_hash" in wire
        assert wire["stack_trace_hash"] == d.stack_trace_hash

    def test_to_dict_error_domain_none_for_safe(self) -> None:
        wire = Decision.safe().to_dict()
        assert wire["error_domain"] is None

    def test_to_dict_stack_trace_hash_none_when_no_traceback(self) -> None:
        wire = Decision.error(reason="no tb").to_dict()
        assert wire["stack_trace_hash"] is None

    def test_from_dict_restores_stack_trace_hash(self) -> None:
        tb = "some traceback"
        original = Decision.error(reason="boom", traceback_str=tb)
        restored = Decision.from_dict(original.to_dict())
        assert restored.stack_trace_hash == original.stack_trace_hash

    def test_from_dict_recomputes_error_domain_from_status(self) -> None:
        original = Decision.unsafe(violated_invariants=("inv",))
        wire = original.to_dict()
        # Even if we corrupt error_domain in the wire dict, from_dict re-derives it
        wire["error_domain"] = "corrupted_value"
        restored = Decision.from_dict(wire)
        assert restored.error_domain == "policy_violation"

    def test_from_dict_stack_trace_hash_none_when_missing_from_wire(self) -> None:
        d = Decision.error(reason="no tb")
        wire = d.to_dict()
        del wire["stack_trace_hash"]
        restored = Decision.from_dict(wire)
        assert restored.stack_trace_hash is None

    def test_round_trip_preserves_error_domain_and_hash(self) -> None:
        tb = "RuntimeError: something exploded"
        original = Decision.error(
            reason="exploded",
            traceback_str=tb,
            error_domain="resource_exhaustion",
        )
        restored = Decision.from_dict(original.to_dict())
        assert restored.error_domain == original.error_domain
        assert restored.stack_trace_hash == original.stack_trace_hash


# ── 6. Decision hash stability (error_domain not in canonical hash) ────────────


class TestDecisionHashStability:
    """error_domain and stack_trace_hash must NOT affect decision_hash.

    These are operational metadata — they don't change the policy outcome.
    Adding them to the canonical hash would break audit replay for any decision
    that predates the taxonomy fields.
    """

    def test_same_decision_different_error_domain_has_same_hash(self) -> None:
        d1 = Decision.error(reason="boom", error_domain="system_fault")
        d2 = Decision.error(reason="boom", error_domain="resource_exhaustion")
        assert d1.decision_hash == d2.decision_hash

    def test_same_decision_different_traceback_has_same_hash(self) -> None:
        d1 = Decision.error(reason="boom", traceback_str="tb A")
        d2 = Decision.error(reason="boom", traceback_str="tb B")
        assert d1.decision_hash == d2.decision_hash

    def test_error_domain_not_in_decision_hash_input(self) -> None:
        d_with = Decision.error(reason="x", traceback_str="tb", error_domain="system_fault")
        d_without = Decision.error(reason="x")
        # Both have the same explanation, so hashes match
        assert d_with.decision_hash == d_without.decision_hash


# ── 7. Immutability (frozen dataclass) ────────────────────────────────────────


class TestImmutability:
    def test_error_domain_is_immutable(self) -> None:
        d = Decision.safe()
        with pytest.raises((AttributeError, TypeError)):
            d.error_domain = "policy_violation"  # type: ignore[misc]

    def test_stack_trace_hash_is_immutable(self) -> None:
        d = Decision.error(reason="boom", traceback_str="tb")
        with pytest.raises((AttributeError, TypeError)):
            d.stack_trace_hash = "new_hash"  # type: ignore[misc]


# ── 8. Security: error_domain cannot escalate SAFE to non-None ────────────────


class TestSecurityInvariants:
    def test_safe_decision_error_domain_always_none(self) -> None:
        """SAFE decisions must never carry an error domain — SAFE means no fault."""
        d = Decision.safe()
        assert d.error_domain is None, (
            "SAFE decision must have error_domain=None; "
            "a non-None domain implies a fault occurred."
        )

    def test_all_blocked_statuses_have_non_none_domain(self) -> None:
        """Every BLOCK path must have a domain so ops can route alerts."""
        blocked = [
            Decision.unsafe(violated_invariants=("inv",)),
            Decision.timeout(label="inv", timeout_ms=100),
            Decision.error(reason="boom"),
            Decision.stale_state(expected="v1", actual="v2"),
            Decision.validation_failure(reason="bad"),
            Decision.rate_limited(),
            Decision.consensus_failure(),
            Decision.governance_blocked(reason="denied", stage="privilege"),
        ]
        for d in blocked:
            assert d.error_domain is not None, (
                f"Blocked decision with status={d.status.name} has error_domain=None. "
                "Every blocked decision must have an error domain for ops routing."
            )
