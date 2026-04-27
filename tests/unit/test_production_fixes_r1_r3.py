# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Regression tests for production gap fixes R1-R3.

    R1  DecisionVerifier reads the correct payload fields after N2/N6 fixes:
        - ``policy_hash`` (not the defunct ``policy`` key)
        - ``issued_at`` is always 0 (``iat`` was removed from the signed payload)
    R2  GuardConfig(otel_enabled=True) emits UserWarning when opentelemetry is absent
    R3  MerkleAnchor._build_root is iterative — no RecursionError on large batches
"""
from __future__ import annotations

import warnings
from unittest.mock import patch

import pytest

from pramanix.audit.merkle import MerkleAnchor
from pramanix.audit.signer import DecisionSigner
from pramanix.audit.verifier import DecisionVerifier, VerificationResult
from pramanix.decision import Decision
from pramanix.guard_config import GuardConfig

# ── helpers ───────────────────────────────────────────────────────────────────

_KEY = "x" * 64  # 64-char key — satisfies minimum-length requirement


def _sign(decision: Decision) -> str:
    signer = DecisionSigner(signing_key=_KEY)
    result = signer.sign(decision)
    assert result is not None, "DecisionSigner.sign() returned None — signer broken"
    return result.token


def _verify(token: str) -> VerificationResult:
    return DecisionVerifier(signing_key=_KEY).verify(token)


def _safe_decision() -> Decision:
    return Decision.safe(solver_time_ms=1.5)


def _unsafe_decision() -> Decision:
    return Decision.unsafe(
        violated_invariants=("balance_non_negative",),
        explanation="Overdraft blocked.",
    )


# =============================================================================
# R1 — VerificationResult.policy_hash / issued_at field alignment
# =============================================================================


class TestR1VerifierFieldAlignment:
    """After N2/N6 the signer writes ``policy_hash`` (not ``policy``) and
    removes ``iat`` from the signed payload.  The verifier must read the
    correct keys; the old behaviour silently returned empty strings / epoch.
    """

    def test_result_has_policy_hash_attribute_not_policy(self) -> None:
        """VerificationResult must expose policy_hash, not the defunct policy."""
        result = _verify(_sign(_safe_decision()))
        assert hasattr(result, "policy_hash"), (
            "VerificationResult missing 'policy_hash' field — field rename not applied"
        )
        assert not hasattr(result, "policy"), (
            "VerificationResult still has deprecated 'policy' field"
        )

    def test_policy_hash_is_string(self) -> None:
        result = _verify(_sign(_safe_decision()))
        assert isinstance(result.policy_hash, str)

    def test_valid_token_is_verified(self) -> None:
        token = _sign(_safe_decision())
        result = _verify(token)
        assert result.valid is True
        assert result.error is None

    def test_decision_id_round_trips(self) -> None:
        """decision_id written by signer must be readable by verifier."""
        decision = _safe_decision()
        token = _sign(decision)
        result = _verify(token)
        assert result.decision_id == str(decision.decision_id)

    def test_allowed_round_trips_for_safe_decision(self) -> None:
        result = _verify(_sign(_safe_decision()))
        assert result.allowed is True

    def test_allowed_round_trips_for_unsafe_decision(self) -> None:
        result = _verify(_sign(_unsafe_decision()))
        assert result.allowed is False

    def test_violated_invariants_round_trip(self) -> None:
        decision = _unsafe_decision()
        result = _verify(_sign(decision))
        assert "balance_non_negative" in result.violated_invariants

    def test_issued_at_is_zero_for_current_tokens(self) -> None:
        """iat is not in the signed payload (removed in N6) — must be 0."""
        result = _verify(_sign(_safe_decision()))
        assert result.issued_at == 0, (
            f"issued_at should be 0 (iat not in signed payload) but got {result.issued_at!r}"
        )

    def test_invalid_result_has_policy_hash_empty_string(self) -> None:
        """_invalid() must use policy_hash='', not the defunct policy='' kwarg."""
        result = DecisionVerifier(signing_key=_KEY).verify("bad.token.here")
        assert result.valid is False
        assert hasattr(result, "policy_hash")
        assert result.policy_hash == ""

    def test_tampered_token_fails_verification(self) -> None:
        token = _sign(_safe_decision())
        # flip last char of signature part
        parts = token.split(".")
        parts[2] = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
        tampered = ".".join(parts)
        result = _verify(tampered)
        assert result.valid is False
        assert result.error is not None

    def test_wrong_key_fails_verification(self) -> None:
        token = _sign(_safe_decision())
        wrong_verifier = DecisionVerifier(signing_key="y" * 64)
        result = wrong_verifier.verify(token)
        assert result.valid is False

    def test_malformed_token_returns_invalid(self) -> None:
        result = DecisionVerifier(signing_key=_KEY).verify("notavalidtoken")
        assert result.valid is False
        assert result.decision_id == ""
        assert result.policy_hash == ""
        assert result.issued_at == 0


# =============================================================================
# R2 — GuardConfig(otel_enabled=True) warns when opentelemetry absent
# =============================================================================


class TestR2OtelEnabledWarning:
    """GuardConfig must mirror the metrics_enabled warning pattern for otel_enabled."""

    def test_no_warning_when_otel_disabled(self) -> None:
        """No warning when otel_enabled=False, regardless of availability."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            GuardConfig(otel_enabled=False)
        otel_warnings = [w for w in caught if "opentelemetry" in str(w.message).lower()]
        assert otel_warnings == [], (
            "Unexpected OTel UserWarning raised when otel_enabled=False"
        )

    def test_warning_when_otel_enabled_but_unavailable(self) -> None:
        """When otel_enabled=True and opentelemetry not installed, emit UserWarning."""
        import pramanix.guard_config as _gc

        with patch.object(_gc, "_OTEL_AVAILABLE", False), pytest.warns(UserWarning, match="opentelemetry"):
            GuardConfig(otel_enabled=True)

    def test_warning_message_contains_install_hint(self) -> None:
        """Warning message must guide the user to install the extra."""
        import pramanix.guard_config as _gc

        with patch.object(_gc, "_OTEL_AVAILABLE", False), pytest.warns(UserWarning, match="pramanix\\[otel\\]"):
            GuardConfig(otel_enabled=True)

    def test_no_warning_when_otel_enabled_and_available(self) -> None:
        """No warning when opentelemetry IS installed."""
        import pramanix.guard_config as _gc

        with patch.object(_gc, "_OTEL_AVAILABLE", True), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            GuardConfig(otel_enabled=True)
        otel_warnings = [w for w in caught if "opentelemetry" in str(w.message).lower()]
        assert otel_warnings == [], (
            "Spurious OTel UserWarning raised when opentelemetry IS available"
        )

    def test_otel_available_flag_is_bool(self) -> None:
        """_OTEL_AVAILABLE must be set to a bool in guard_config module."""
        import pramanix.guard_config as _gc

        assert isinstance(_gc._OTEL_AVAILABLE, bool), (  # type: ignore[attr-defined]
            f"_OTEL_AVAILABLE is {type(_gc._OTEL_AVAILABLE).__name__!r}, expected bool"  # type: ignore[attr-defined]
        )


# =============================================================================
# R3 — MerkleAnchor._build_root is iterative (no recursion limit)
# =============================================================================


class TestR3IterativeMerkleRoot:
    """_build_root must be iterative; Python's recursion limit (1000) is hit by
    roughly 2^1000 leaves in the recursive version — trivially exceeded by a
    production log with thousands of decisions.
    """

    def test_single_leaf_returns_leaf(self) -> None:
        anchor = MerkleAnchor()
        leaf = "abc"
        # Access private method directly to test the algorithm
        assert anchor._build_root([leaf]) == leaf  # type: ignore[attr-defined]

    def test_two_leaves_produce_combined_hash(self) -> None:
        import hashlib

        anchor = MerkleAnchor()
        a, b = "leaf_a", "leaf_b"
        # H-07: internal nodes use \x01 prefix
        expected = hashlib.sha256(b"\x01" + (a + b).encode()).hexdigest()
        assert anchor._build_root([a, b]) == expected  # type: ignore[attr-defined]

    def test_odd_leaf_count_duplicates_last(self) -> None:
        """Odd leaf count must pad last leaf with \x01 prefix (H-07 rule)."""
        import hashlib

        anchor = MerkleAnchor()
        a, b, c = "l1", "l2", "l3"
        # level 0: [l1, l2, l3, pad(l3)]  where pad = sha256(\x01 + l3)
        pad_c = hashlib.sha256(b"\x01" + c.encode()).hexdigest()
        ab = hashlib.sha256(b"\x01" + (a + b).encode()).hexdigest()
        cc = hashlib.sha256(b"\x01" + (c + pad_c).encode()).hexdigest()
        root = hashlib.sha256(b"\x01" + (ab + cc).encode()).hexdigest()
        assert anchor._build_root([a, b, c]) == root  # type: ignore[attr-defined]

    def test_power_of_two_leaf_count(self) -> None:
        """4-leaf tree must compute correctly."""
        import hashlib

        anchor = MerkleAnchor()
        leaves = ["d1", "d2", "d3", "d4"]
        # H-07: internal nodes use \x01 prefix
        h01 = hashlib.sha256(
            b"\x01" + (leaves[0] + leaves[1]).encode()
        ).hexdigest()
        h23 = hashlib.sha256(
            b"\x01" + (leaves[2] + leaves[3]).encode()
        ).hexdigest()
        root = hashlib.sha256(b"\x01" + (h01 + h23).encode()).hexdigest()
        assert anchor._build_root(leaves) == root  # type: ignore[attr-defined]

    def test_large_batch_no_recursion_error(self) -> None:
        """5000 decisions must not raise RecursionError."""
        anchor = MerkleAnchor()
        for i in range(5000):
            anchor.add(f"decision-{i}")
        root = anchor.root()
        assert isinstance(root, str)
        assert len(root) == 64  # SHA-256 hexdigest length

    def test_root_deterministic_for_same_leaves(self) -> None:
        """Same leaves in same order must always produce the same root."""
        anchor = MerkleAnchor()
        leaves = [f"leaf_{i}" for i in range(20)]
        r1 = anchor._build_root(leaves[:])  # type: ignore[attr-defined]
        r2 = anchor._build_root(leaves[:])  # type: ignore[attr-defined]
        assert r1 == r2

    def test_root_changes_with_different_leaf(self) -> None:
        anchor = MerkleAnchor()
        r1 = anchor._build_root(["a", "b"])  # type: ignore[attr-defined]
        r2 = anchor._build_root(["a", "c"])  # type: ignore[attr-defined]
        assert r1 != r2

    def test_full_audit_lifecycle_large_batch(self) -> None:
        """Integration: add → root works for a batch that would crash with recursion."""
        anchor = MerkleAnchor()
        for i in range(1500):
            anchor.add(f"audit-decision-{i}")
        root = anchor.root()
        assert isinstance(root, str)
        assert len(root) == 64
        assert root != ""
