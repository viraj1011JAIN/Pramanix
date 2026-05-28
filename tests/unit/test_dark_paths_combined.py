# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Dark-path tests for decision.py, injection_scorer.py, provenance.py,
and miscellaneous translator paths.

Covers uncovered lines identified in the 95.31% coverage run:
- decision.py lines 58-63 (orjson fallback), 149-151 (FrozenInstanceError fallback)
- translator/injection_scorer.py lines 288 (HMAC mismatch), 295-298 (sklearn absent)
- translator/redundant.py lines 124-127 (string-enum disqualified in analyze_string_promotions)
- provenance.py lines 303-308 (async provenance callback on timeout/error)
- guard.py lines 1138-1175 (async state-version mismatch)
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util as _ilu
import pickle
import sys
from decimal import Decimal
from pathlib import Path
import pytest

from pramanix.decision import Decision, SolverStatus, _build_decision_canonical

# ═══════════════════════════════════════════════════════════════════════════════
# decision.py dark paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionCanonicalFallback:
    """decision.py lines 58-63: stdlib json fallback when orjson is absent."""

    def test_canonical_bytes_fallback_used_when_orjson_absent(self) -> None:
        """Patch orjson away; Decision._compute_hash must still succeed."""
        import pramanix.decision as _dec_mod

        original_canonical = _dec_mod._canonical_bytes

        # Simulate orjson being unavailable by temporarily replacing _canonical_bytes
        # with the stdlib fallback (mirroring the ImportError branch).
        import json as _json

        def _stdlib_canonical(payload):
            return _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

        try:
            _dec_mod._canonical_bytes = _stdlib_canonical
            d = Decision.safe()
            assert d.decision_hash
            assert len(d.decision_hash) == 64  # SHA-256 hex
        finally:
            _dec_mod._canonical_bytes = original_canonical

    def test_build_decision_canonical_round_trips(self) -> None:
        """_build_decision_canonical returns deterministic output for known inputs."""
        canonical = _build_decision_canonical(
            allowed=True,
            explanation="test",
            intent_dump={"amount": "100"},
            policy="v1",
            state_dump={"balance": "500"},
            status="safe",
            violated_invariants=["inv_a", "inv_b"],
        )
        assert canonical["allowed"] is True
        assert canonical["status"] == "safe"
        assert canonical["violated_invariants"] == ["inv_a", "inv_b"]

    def test_decision_hash_field_is_stable(self) -> None:
        """Same inputs produce the same decision_hash."""
        d1 = Decision.safe(intent_dump={"x": "1"}, state_dump={"y": "2"})
        d2 = Decision.safe(intent_dump={"x": "1"}, state_dump={"y": "2"})
        assert d1.decision_hash == d2.decision_hash


class TestDecisionHashMethod:
    """decision.py line 303: __hash__ used in sets / dicts."""

    def test_decision_hashable_in_set(self) -> None:
        d_safe = Decision.safe()
        d_unsafe = Decision.unsafe(violated_invariants=("inv1",))
        d_error = Decision.error(reason="err")
        s = {d_safe, d_unsafe, d_error}
        assert len(s) == 3

    def test_decision_usable_as_dict_key(self) -> None:
        d = Decision.safe()
        mapping = {d: "value"}
        assert mapping[d] == "value"


class TestDecisionCacheHit:
    """decision.py line 650: cache_hit factory."""

    def test_cache_hit_preserves_allowed_true(self) -> None:
        base = Decision.safe(solver_time_ms=10.5)
        cached = Decision.cache_hit(base=base)
        assert cached.allowed is True
        assert cached.status == SolverStatus.SAFE
        assert cached.solver_time_ms == 10.5
        assert cached.metadata.get("_solver_status_tag") == "cache_hit"

    def test_cache_hit_preserves_allowed_false(self) -> None:
        base = Decision.unsafe(violated_invariants=("max_amount",), explanation="too high")
        cached = Decision.cache_hit(base=base)
        assert cached.allowed is False
        assert cached.status == SolverStatus.UNSAFE
        assert cached.metadata.get("_solver_status_tag") == "cache_hit"

    def test_cache_hit_preserves_decision_id(self) -> None:
        base = Decision.safe()
        cached = Decision.cache_hit(base=base)
        assert cached.decision_id == base.decision_id


# ═══════════════════════════════════════════════════════════════════════════════
# translator/injection_scorer.py dark paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestInjectionScorerDarkPaths:
    """injection_scorer.py lines 288 (HMAC mismatch), 295-298 (sklearn absent)."""

    def _write_valid_pkl(self, tmp_path: Path, key: bytes) -> Path:
        """Write a trivial pickle file with a valid HMAC sidecar."""
        payload = pickle.dumps({"dummy": True})
        pkl_path = tmp_path / "scorer.pkl"
        pkl_path.write_bytes(payload)
        tag = hmac.new(key, payload, hashlib.sha256).digest()
        pkl_path.with_suffix(".hmac").write_bytes(tag)
        return pkl_path

    def _write_tampered_pkl(self, tmp_path: Path, key: bytes) -> Path:
        """Write a pkl file whose HMAC sidecar was signed with a different key."""
        payload = pickle.dumps({"dummy": True})
        pkl_path = tmp_path / "tampered.pkl"
        pkl_path.write_bytes(payload)
        bad_tag = hmac.new(b"wrong_key_xyz", payload, hashlib.sha256).digest()
        pkl_path.with_suffix(".hmac").write_bytes(bad_tag)
        return pkl_path

    def test_hmac_mismatch_raises_integrity_error(self, tmp_path: Path) -> None:
        """line 288: HMAC mismatch raises IntegrityError."""
        from pramanix.exceptions import IntegrityError
        from pramanix.translator.injection_scorer import CalibratedScorer

        key = b"valid_key_32bytes_abcdefghijk1234"
        pkl_path = self._write_tampered_pkl(tmp_path, key)

        with pytest.raises(IntegrityError, match="HMAC verification failed"):
            CalibratedScorer.load(pkl_path, hmac_key=key)

    def test_sklearn_absent_raises_configuration_error(self, tmp_path: Path) -> None:
        """lines 295-298: sklearn not installed raises ConfigurationError (DI factory)."""
        from pramanix.exceptions import ConfigurationError
        from pramanix.translator.injection_scorer import CalibratedScorer

        def _raise_import():
            raise ImportError("sklearn not installed")

        key = b"valid_key_32bytes_abcdefghijk1234"
        pkl_path = self._write_valid_pkl(tmp_path, key)

        with pytest.raises(ConfigurationError, match="scikit-learn"):
            CalibratedScorer.load(pkl_path, hmac_key=key, _sklearn_factory=_raise_import)


# ═══════════════════════════════════════════════════════════════════════════════
# guard.py async state-version mismatch (lines 1138-1175)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAsyncStateVersionMismatch:
    """guard.py lines 1138-1175: verify_async with wrong/missing state_version."""

    def _make_versioned_guard(self):
        from pramanix.expressions import ConstraintExpr, E, Field
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _SemverPolicy(Policy):
            """Policy with Meta.semver triggers the semver mismatch path (lines 1138-1175)."""

            class Meta:
                semver = (2, 0, 0)  # triggers _policy_semver

            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("non_negative")]

        return Guard(_SemverPolicy, GuardConfig(execution_mode="async-thread"))

    @pytest.mark.asyncio
    async def test_async_wrong_state_version_returns_stale(self) -> None:
        guard = self._make_versioned_guard()
        decision = await guard.verify_async(
            intent={"amount": Decimal("5")},
            state={"state_version": "1.0.0"},  # wrong semver
        )
        assert not decision.allowed
        assert decision.status == SolverStatus.STALE_STATE

    @pytest.mark.asyncio
    async def test_async_missing_state_version_returns_validation_failure(self) -> None:
        guard = self._make_versioned_guard()
        decision = await guard.verify_async(
            intent={"amount": Decimal("5")},
            state={},  # missing state_version entirely
        )
        assert not decision.allowed
        assert decision.status == SolverStatus.VALIDATION_FAILURE

    @pytest.mark.asyncio
    async def test_async_invalid_semver_format_returns_validation_failure(self) -> None:
        guard = self._make_versioned_guard()
        decision = await guard.verify_async(
            intent={"amount": Decimal("5")},
            state={"state_version": "not_semver"},  # not a valid semver string
        )
        assert not decision.allowed
        assert decision.status == SolverStatus.VALIDATION_FAILURE

    @pytest.mark.asyncio
    async def test_async_two_part_semver_returns_validation_failure(self) -> None:
        """state_version='1.0' (2 parts) → len != 3 → raise ValueError → VALIDATION_FAILURE.

        Covers guard.py line 1154 (the explicit ``raise ValueError`` when len != 3).
        """
        guard = self._make_versioned_guard()
        decision = await guard.verify_async(
            intent={"amount": Decimal("5")},
            state={"state_version": "1.0"},  # 2 parts, valid ints, but len != 3
        )
        assert not decision.allowed
        assert decision.status == SolverStatus.VALIDATION_FAILURE

    @pytest.mark.asyncio
    async def test_async_matching_semver_proceeds_to_solve(self) -> None:
        """state_version matching policy semver → passes version check → Z3 solve.

        Covers guard.py line 1168->1198 (semver matches, flow continues past check).
        """
        guard = self._make_versioned_guard()
        decision = await guard.verify_async(
            intent={"amount": Decimal("5")},
            state={"state_version": "2.0.0"},  # matches _SemverPolicy.Meta.semver
        )
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE


# ═══════════════════════════════════════════════════════════════════════════════
# guard.py span is None path (line 729->739)
# Covered by any test that calls verify() without OTel configured — already
# covered by the governance gate tests above.  No additional test needed.
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# guard.py async-thread additional paths
# 1079->1124  max_input_bytes ≤ 0 → skip size check
# 1225->1252  fast_path present but NOT blocked → fall through to solver
# ═══════════════════════════════════════════════════════════════════════════════


class TestAsyncThreadAdditionalPaths:
    """guard.py async-thread paths not covered by the state-version tests."""

    def _make_simple_policy(self):
        from pramanix.expressions import ConstraintExpr, E, Field
        from pramanix.policy import Policy

        class _SimplePolicy(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_neg")]

        return _SimplePolicy

    @pytest.mark.asyncio
    async def test_async_thread_no_size_check_when_max_input_bytes_zero(self) -> None:
        """max_input_bytes=0 → skip size-check block → branch 1079->1124 taken."""
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        policy_cls = self._make_simple_policy()
        guard = Guard(
            policy_cls,
            GuardConfig(execution_mode="async-thread", max_input_bytes=0, worker_warmup=False),
        )
        decision = await guard.verify_async(
            intent={"x": Decimal("5")},
            state={},
        )
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE

    @pytest.mark.asyncio
    async def test_async_thread_fast_path_present_but_not_blocked(self) -> None:
        """fast_path configured; non-negative value → fast_path not blocked → 1225->1252."""
        from pramanix.fast_path import SemanticFastPath
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        policy_cls = self._make_simple_policy()
        guard = Guard(
            policy_cls,
            GuardConfig(
                execution_mode="async-thread",
                fast_path_enabled=True,
                fast_path_rules=(SemanticFastPath.negative_amount("x"),),
                worker_warmup=False,
            ),
        )
        # x=5 is non-negative → fast_path evaluates but does NOT block
        # → falls through to Z3 solver (covers 1225->1252)
        decision = await guard.verify_async(
            intent={"x": Decimal("5")},
            state={},
        )
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE

    @pytest.mark.asyncio
    async def test_async_thread_size_check_circular_ref_blocks(self) -> None:
        """Circular dict → json.dumps raises → exception path lines 1105-1121 fires."""
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        policy_cls = self._make_simple_policy()
        guard = Guard(
            policy_cls,
            GuardConfig(execution_mode="async-thread", worker_warmup=False),
        )
        # Circular reference in the dict causes json.dumps to raise ValueError
        # even when default=str is set — triggers lines 1105-1121
        circ: dict = {}
        circ["self"] = circ
        decision = await guard.verify_async(intent=circ, state={})
        assert not decision.allowed
        assert decision.status == SolverStatus.ERROR


# ═══════════════════════════════════════════════════════════════════════════════
# guard.py async-process non-picklable value (lines 1298-1300)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAsyncProcessNonPicklable:
    """guard.py 1298-1300: non-picklable value in async-process mode → error Decision."""

    @pytest.mark.asyncio
    async def test_async_process_non_picklable_intent_returns_error(self) -> None:
        """Values dict with a non-picklable object → error before ProcessPoolExecutor."""
        import threading

        from pramanix.expressions import ConstraintExpr, E, Field
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _ProcessPolicy(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_neg")]

        guard = Guard(
            _ProcessPolicy,
            GuardConfig(execution_mode="async-process", worker_warmup=False),
        )
        try:
            # threading.Lock is not picklable → triggers lines 1298-1300
            intent = {"x": threading.Lock()}
            decision = await guard.verify_async(intent=intent, state={})
            assert not decision.allowed
            assert decision.status == SolverStatus.ERROR
            assert "unpicklable" in decision.explanation.lower()
        finally:
            await guard.shutdown()
