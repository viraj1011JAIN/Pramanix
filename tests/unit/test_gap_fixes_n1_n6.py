# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Regression tests for gap fixes N1–N6.

    N1  resolver_registry public singleton wired into Guard (same object)
    N2  DecisionSigner._canonicalize() uses correct to_dict() key names
    N3  MerkleAnchor.add() raises ValueError on duplicate decision_id
    N4  ResolverRegistry.register() logs warning on overwrite
    N5  GuardConfig(metrics_enabled=True) emits UserWarning when prometheus absent
    N6  DecisionSigner produces identical tokens on repeated signing (deterministic)
"""
from __future__ import annotations

import logging
import warnings
from decimal import Decimal
from typing import Any
from unittest.mock import patch

import pytest

from pramanix.audit.merkle import MerkleAnchor, PersistentMerkleAnchor
from pramanix.audit.signer import DecisionSigner
from pramanix.decision import Decision
from pramanix.guard_config import _resolver_registry as _guard_registry
from pramanix.resolvers import ResolverRegistry, resolver_registry


# ── helpers ───────────────────────────────────────────────────────────────────


def _safe_decision() -> Decision:
    return Decision.safe(solver_time_ms=1.0)


def _unsafe_decision() -> Decision:
    return Decision.unsafe(
        violated_invariants=("non_negative_balance",),
        explanation="Overdraft blocked.",
    )


_KEY_64 = "a" * 64


# =============================================================================
# N1 — resolver_registry singleton wired into Guard
# =============================================================================


class TestN1ResolverSingleton:
    def test_guard_registry_is_public_singleton(self) -> None:
        """_resolver_registry in guard_config must be the same object as
        the public resolver_registry in pramanix.resolvers, so that user
        registrations are visible to Guard.verify()'s clear_cache() call."""
        assert _guard_registry is resolver_registry, (
            "guard_config._resolver_registry is a different object from "
            "resolvers.resolver_registry — user-registered resolvers would "
            "be silently ignored by Guard."
        )

    def test_registration_on_public_singleton_is_visible_to_guard_registry(self) -> None:
        """Registering a resolver on the public singleton must be reflected
        in the guard-internal reference."""
        sentinel = lambda: "sentinel_value"  # noqa: E731
        resolver_registry.register("_test_n1_sentinel", sentinel)
        try:
            result = _guard_registry.resolve("_test_n1_sentinel")
            assert result == "sentinel_value"
        finally:
            # Clean up: remove the test registration from internal dict
            _guard_registry._resolvers.pop("_test_n1_sentinel", None)
            _guard_registry.clear_cache()


# =============================================================================
# N2 — DecisionSigner._canonicalize() correct key names
# =============================================================================


class TestN2CanonicalizerKeys:
    def test_canonicalize_uses_policy_hash_not_policy(self) -> None:
        """_canonicalize must read 'policy_hash' (a real to_dict() key),
        not 'policy' (which does not exist at the top level of to_dict())."""
        signer = DecisionSigner(signing_key=_KEY_64)
        decision = Decision.safe(solver_time_ms=5.0)
        canonical = signer._canonicalize(decision)
        assert "policy_hash" in canonical, (
            "_canonicalize must include 'policy_hash' key from to_dict()"
        )
        assert "policy" not in canonical, (
            "_canonicalize must NOT include 'policy' — that key doesn't exist "
            "in to_dict() and would always be empty string"
        )

    def test_canonicalize_excludes_state_version(self) -> None:
        """_canonicalize must not reference 'state_version' which has no
        corresponding key in to_dict()."""
        signer = DecisionSigner(signing_key=_KEY_64)
        decision = _safe_decision()
        canonical = signer._canonicalize(decision)
        assert "state_version" not in canonical, (
            "_canonicalize must NOT include 'state_version' — Decision.to_dict() "
            "has no such top-level key; it always resolves to empty string"
        )

    def test_canonicalize_excludes_iat(self) -> None:
        """_canonicalize must not include 'iat' (non-deterministic timestamp)."""
        signer = DecisionSigner(signing_key=_KEY_64)
        decision = _safe_decision()
        canonical = signer._canonicalize(decision)
        assert "iat" not in canonical, (
            "_canonicalize must NOT include 'iat' — time.time() changes on "
            "every call, making deterministic replay verification impossible"
        )

    def test_canonicalize_preserves_core_fields(self) -> None:
        """Required fields must still be present after the key corrections."""
        signer = DecisionSigner(signing_key=_KEY_64)
        decision = _unsafe_decision()
        canonical = signer._canonicalize(decision)
        for key in ("decision_id", "allowed", "explanation", "status", "violated_invariants"):
            assert key in canonical, f"_canonicalize is missing required field '{key}'"


# =============================================================================
# N6 — DecisionSigner is deterministic (no iat in signed payload)
# =============================================================================


class TestN6DeterministicSigning:
    def test_same_decision_produces_same_token(self) -> None:
        """Signing the same Decision twice must produce an identical JWS token.
        This requires the signed payload to be deterministic (no timestamps)."""
        signer = DecisionSigner(signing_key=_KEY_64)
        decision = _unsafe_decision()
        signed_a = signer.sign(decision)
        signed_b = signer.sign(decision)
        assert signed_a is not None and signed_b is not None
        assert signed_a.token == signed_b.token, (
            "Signing the same Decision twice produced different tokens. "
            "The signed payload must not include any non-deterministic value "
            "such as time.time()."
        )

    def test_different_decisions_produce_different_tokens(self) -> None:
        """Distinct decisions must not collide to the same token."""
        signer = DecisionSigner(signing_key=_KEY_64)
        d_safe = _safe_decision()
        d_unsafe = _unsafe_decision()
        signed_safe = signer.sign(d_safe)
        signed_unsafe = signer.sign(d_unsafe)
        assert signed_safe is not None and signed_unsafe is not None
        assert signed_safe.token != signed_unsafe.token


# =============================================================================
# N3 — MerkleAnchor duplicate detection
# =============================================================================


class TestN3MerkleDuplicateDetection:
    def test_add_duplicate_raises_value_error(self) -> None:
        """Adding the same decision_id twice must raise ValueError."""
        anchor = MerkleAnchor()
        anchor.add("decision-abc-123")
        with pytest.raises(ValueError, match="decision-abc-123"):
            anchor.add("decision-abc-123")

    def test_add_unique_ids_does_not_raise(self) -> None:
        """Distinct decision IDs must all be accepted without error."""
        anchor = MerkleAnchor()
        for i in range(10):
            anchor.add(f"decision-{i}")
        assert anchor.root() is not None

    def test_prove_reflects_correct_leaf_after_dedup(self) -> None:
        """After adding two distinct IDs the proof for each must be valid."""
        anchor = MerkleAnchor()
        anchor.add("id-alpha")
        anchor.add("id-beta")
        proof_alpha = anchor.prove("id-alpha")
        proof_beta = anchor.prove("id-beta")
        assert proof_alpha is not None and proof_alpha.verify()
        assert proof_beta is not None and proof_beta.verify()

    def test_persistent_anchor_also_rejects_duplicates(self) -> None:
        """PersistentMerkleAnchor inherits the duplicate guard via super().add()."""
        checkpoints: list[tuple[str, int]] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=5,
            checkpoint_callback=lambda r, c: checkpoints.append((r, c)),
        )
        anchor.add("dup-id")
        with pytest.raises(ValueError, match="dup-id"):
            anchor.add("dup-id")


# =============================================================================
# N4 — ResolverRegistry.register() warns on overwrite
# =============================================================================


class TestN4ResolverOverwriteWarning:
    def test_first_registration_does_not_warn(self, caplog: pytest.LogCaptureFixture) -> None:
        """Registering a new name for the first time must not emit a warning."""
        reg = ResolverRegistry()
        with caplog.at_level(logging.WARNING, logger="pramanix.resolvers"):
            reg.register("_fresh_name", lambda: 1)
        assert not caplog.records, (
            "First-time registration must not log a warning"
        )

    def test_overwrite_emits_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Re-registering the same name must emit a WARNING-level log."""
        reg = ResolverRegistry()
        reg.register("balance", lambda: 100)
        with caplog.at_level(logging.WARNING, logger="pramanix.resolvers"):
            reg.register("balance", lambda: 200)
        assert any(
            "balance" in r.message and r.levelno == logging.WARNING
            for r in caplog.records
        ), "Expected a WARNING log mentioning the field name 'balance' on overwrite"

    def test_overwrite_still_updates_resolver(self) -> None:
        """After overwriting, the new resolver must be used."""
        reg = ResolverRegistry()
        reg.register("counter", lambda: 1)
        reg.register("counter", lambda: 2)
        assert reg.resolve("counter") == 2

    def test_non_callable_still_raises_type_error(self) -> None:
        """TypeError on non-callable must not be affected by the overwrite fix."""
        reg = ResolverRegistry()
        with pytest.raises(TypeError):
            reg.register("bad", "not_a_callable")  # type: ignore[arg-type]


# =============================================================================
# N5 — GuardConfig warns when metrics_enabled=True but prometheus absent
# =============================================================================


class TestN5MetricsWarning:
    def test_no_warning_when_metrics_disabled(self) -> None:
        """No UserWarning when metrics_enabled=False (default)."""
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            # Must not raise
            from pramanix.guard_config import GuardConfig
            GuardConfig(metrics_enabled=False)

    def test_warning_when_metrics_enabled_and_prometheus_absent(self) -> None:
        """GuardConfig(metrics_enabled=True) must emit UserWarning when
        prometheus_client is not importable."""
        import pramanix.guard_config as _gc

        with patch.object(_gc, "_PROM_AVAILABLE", False):
            with pytest.warns(UserWarning, match="prometheus_client"):
                _gc.GuardConfig(metrics_enabled=True)

    def test_no_warning_when_prometheus_available(self) -> None:
        """When prometheus_client IS available, no UserWarning should be emitted
        even with metrics_enabled=True."""
        import pramanix.guard_config as _gc

        with patch.object(_gc, "_PROM_AVAILABLE", True):
            with warnings.catch_warnings():
                warnings.simplefilter("error", UserWarning)
                # Must not raise
                _gc.GuardConfig(metrics_enabled=True)
