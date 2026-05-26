# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Targeted coverage tests — round 3.

Covers:
  guard_config._redact_value — depth>8 early return (line 61)
  guard_config._redact_value — dict value branch (line 63)
  guard_config._gc_prom_register — second call returns cached metric (line 209)
  decision.Decision.is_cache_hit — True path (line 690)
  decision._canonical_bytes — stdlib json fallback (lines 62-67)
  lifecycle/diff.ShadowEvaluator.arecord — async wrapper (line 411)
  audit_sink.InMemoryAuditSink — PRAMANIX_ENV=production guard (lines 122-124)
  crypto.RS256Signer — env-var PEM path (line 488)
  crypto.RS256Verifier — non-RSA public key raises ValueError (line 599)
  crypto.RS256Verifier.verify_decision — unexpected exception re-raises as VerificationError (lines 639-644)
  guard_config._span — OTel fallback (lines 181-187)
"""

from __future__ import annotations

import sys
from decimal import Decimal

import pytest

# ── guard_config._redact_value — depth>8 (line 61) ───────────────────────────


class TestRedactValue:
    def test_depth_gt_8_returns_value_unchanged(self) -> None:
        """Line 61: when depth > 8 the recursion guard returns v unchanged."""
        from pramanix.guard_config import _redact_value

        sentinel = {"password": "should_be_redacted"}
        result = _redact_value(sentinel, depth=9)
        # depth > 8 short-circuits before any redaction
        assert result is sentinel

    def test_dict_value_triggers_recursion(self) -> None:
        """Line 63: when v is a dict the comprehension on line 63 is executed."""
        from pramanix.guard_config import _redact_value

        nested = {"api_key": "secret123"}
        result = _redact_value(nested, depth=0)
        assert isinstance(result, dict)
        assert result["api_key"] == "<redacted>"

    def test_deeply_nested_dict_redacts_secret_keys(self) -> None:
        """Lines 61+63: an 8-level-deep dict is still redacted; depth=9 is not."""
        from pramanix.guard_config import _redact_value

        depth8 = {"k": {"k": {"k": {"k": {"k": {"k": {"k": {"password": "s"}}}}}}}}
        result = _redact_value(depth8)
        # level 8 is within limit — should be redacted
        innermost = result["k"]["k"]["k"]["k"]["k"]["k"]["k"]
        assert innermost.get("password") == "<redacted>"


# ── guard_config._gc_prom_register — cache hit (line 209) ────────────────────


class TestGcPromRegisterCacheHit:
    def test_second_call_returns_cached_metric(self) -> None:
        """Line 209: second registration with same name returns the cached instance."""
        from pramanix.guard_config import _gc_prom_register

        # Use a dummy factory that creates a new object each call (so we can detect caching).
        call_count = [0]

        class _FakeMetric:
            pass

        def _factory(name: str, description: str) -> _FakeMetric:
            call_count[0] += 1
            return _FakeMetric()

        name = "_test_cache_hit_metric_xyzzy"
        first = _gc_prom_register(_factory, name, "test metric")
        second = _gc_prom_register(_factory, name, "test metric")
        # Second call must return the EXACT same object — factory called only once.
        assert first is second
        assert call_count[0] == 1


# ── decision.Decision.is_cache_hit (line 690) ─────────────────────────────────


class TestDecisionIsCacheHit:
    def test_is_cache_hit_true_when_tag_set(self) -> None:
        """Line 690: is_cache_hit() returns True when CACHE_HIT tag is in metadata."""
        from pramanix.decision import Decision, SolverStatus

        base = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="allowed",
        )
        cached = Decision.cache_hit(base=base)
        assert cached.is_cache_hit() is True

    def test_is_cache_hit_false_when_no_tag(self) -> None:
        """is_cache_hit() returns False for a normal (non-cached) decision."""
        from pramanix.decision import Decision, SolverStatus

        d = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="allowed",
        )
        assert d.is_cache_hit() is False

    def test_is_cache_hit_false_when_tag_is_wrong_value(self) -> None:
        """is_cache_hit() returns False when the tag is set to a non-CACHE_HIT value."""
        from pramanix.decision import Decision, SolverStatus

        d = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="allowed",
            metadata={"_solver_status_tag": "some_other_value"},
        )
        assert d.is_cache_hit() is False


# ── decision._canonical_bytes — stdlib json fallback (lines 62-67) ────────────


class TestCanonicalBytesJsonFallback:
    def test_json_fallback_produces_sorted_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 62-67: when orjson is absent, stdlib json is used with sorted keys.

        Uses sys.modules pop+restore instead of importlib.reload to avoid
        mutating the original module's __dict__ in-place, which would corrupt
        SolverStatus identity for all subsequent tests.
        """
        # Save and temporarily evict the original module so a fresh import
        # re-executes module-level code with orjson blocked.
        import pramanix as _pramanix_pkg

        _original = sys.modules.pop("pramanix.decision", None)
        # Also save the package attribute — Python's import machinery sets
        # pramanix.decision = <new module> on every fresh import of the
        # sub-module.  We must restore it so that later tests using
        # `import pramanix.decision as X` (which uses IMPORT_FROM semantics
        # and reads the package attribute, not sys.modules) see the right
        # module object.
        _original_attr = getattr(_pramanix_pkg, "decision", None)
        monkeypatch.setitem(sys.modules, "orjson", None)

        try:
            import pramanix.decision as _fresh_dec  # triggers lines 62-67

            result = _fresh_dec._canonical_bytes({"b": 2, "a": 1})
            assert isinstance(result, bytes)
            decoded = result.decode()
            # stdlib json with sort_keys=True puts "a" before "b"
            assert decoded.index('"a"') < decoded.index('"b"')
        finally:
            # Discard the orjson-less module and restore the original,
            # leaving all pre-existing SolverStatus/Decision references intact.
            sys.modules.pop("pramanix.decision", None)
            if _original is not None:
                sys.modules["pramanix.decision"] = _original
            # Restore the package attribute to keep sys.modules and the
            # package attribute in sync (prevents IMPORT_FROM from returning
            # a stale reference in subsequent tests).
            if _original_attr is not None:
                _pramanix_pkg.decision = _original_attr


# ── lifecycle/diff.ShadowEvaluator.arecord (line 411) ─────────────────────────


class TestShadowEvaluatorARecord:
    @pytest.mark.asyncio
    async def test_arecord_delegates_to_record(self) -> None:
        """Line 411: arecord() offloads synchronous record() to a thread."""
        from pramanix.decision import Decision, SolverStatus
        from pramanix.expressions import E, Field
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.lifecycle.diff import ShadowEvaluator
        from pramanix.policy import Policy

        _amt = Field("amount", Decimal, "Real")

        class _LivePolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls) -> dict:
                return {"amount": _amt}

            @classmethod
            def invariants(cls):
                return [(E(_amt) >= Decimal("0")).named("pos").explain("non-negative")]

        class _ShadowPolicy(Policy):
            class Meta:
                version = "1.0"  # must match state_version in the test state dict

            @classmethod
            def fields(cls) -> dict:
                return {"amount": _amt}

            @classmethod
            def invariants(cls):
                return [(E(_amt) >= Decimal("0")).named("pos").explain("non-negative")]

        cfg = GuardConfig(execution_mode="sync", audit_sinks=[])
        live_guard = Guard(_LivePolicy, cfg)
        shadow_guard = Guard(_ShadowPolicy, cfg)

        evaluator = ShadowEvaluator(live_guard=live_guard, shadow_guard=shadow_guard)

        live_decision = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="allowed",
        )
        intent = {"amount": Decimal("50")}
        state = {"state_version": "1.0"}

        result = await evaluator.arecord(intent, state, live_decision)
        assert result.live_allowed is True
        assert result.shadow_allowed is True  # 50 >= 0
        assert result.diverged is False
        assert result.shadow_error is None


# ── audit_sink.InMemoryAuditSink — PRAMANIX_ENV=production (lines 122-124) ────


class TestInMemoryAuditSinkProductionGuard:
    def test_production_env_raises_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lines 122-124: ConfigurationError when PRAMANIX_ENV=production."""
        from pramanix.audit_sink import InMemoryAuditSink
        from pramanix.exceptions import ConfigurationError

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="InMemoryAuditSink"):
            InMemoryAuditSink()

    def test_non_production_env_emits_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """InMemoryAuditSink in non-production emits a UserWarning only."""
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)
        from pramanix.audit_sink import InMemoryAuditSink

        with pytest.warns(UserWarning, match="testing only"):
            sink = InMemoryAuditSink()
        assert sink is not None


# ── crypto.RS256Signer — env-var PEM path (line 488) ─────────────────────────


class TestRS256SignerEnvVarPath:
    def test_env_var_pem_loads_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Line 488: RS256Signer reads private key PEM from PRAMANIX_RS256_SIGNING_KEY_PEM."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from pramanix.crypto import RS256Signer

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        monkeypatch.setenv("PRAMANIX_RS256_SIGNING_KEY_PEM", pem)
        signer = RS256Signer()  # must load key from env var (line 488)
        assert signer.public_key_pem() is not None
        assert len(signer.key_id()) == 16


# ── crypto.RS256Verifier — non-RSA PEM raises ValueError (line 599) ──────────


class TestRS256VerifierNonRSAPem:
    def test_non_rsa_public_key_raises_value_error(self) -> None:
        """Line 599: ValueError when public key PEM is not RSA."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from pramanix.crypto import RS256Verifier

        # Generate an Ed25519 key (not RSA) and use its public key PEM.
        ed_private = Ed25519PrivateKey.generate()
        ed_public_pem = ed_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(ValueError, match="not an RSA public key"):
            RS256Verifier(public_key_pem=ed_public_pem)


# ── crypto.RS256Verifier.verify_decision — VerificationError wrap (639-644) ───


class TestRS256VerifierDecisionException:
    def test_verify_decision_unexpected_exception_raises_verification_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lines 639-644: non-VerificationError inside verify_decision is wrapped."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from pramanix.crypto import RS256Signer, RS256Verifier
        from pramanix.decision import Decision, SolverStatus
        from pramanix.exceptions import VerificationError

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        signer = RS256Signer(private_key_pem=pem)
        verifier = RS256Verifier(public_key_pem=signer.public_key_pem())

        # Build a decision with a non-empty signature so the early guards pass.
        # __post_init__ computes decision_hash, ensuring recomputed == stored.
        decision = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="ok",
            signature="non_empty_sig_so_early_guard_passes",
        )

        # Patch the verifier's verify() on the instance so it raises an unexpected
        # exception.  Python finds instance attributes before class attributes, so
        # self.verify() inside verify_decision() will call this function.
        def _boom(decision_hash: str, signature: str) -> bool:
            raise RuntimeError("unexpected error — should be wrapped as VerificationError")

        monkeypatch.setattr(verifier, "verify", _boom)

        with pytest.raises(VerificationError, match="RS256 verify_decision"):
            verifier.verify_decision(decision)


# ── guard_config._span — OTel fallback when opentelemetry absent (181-187) ────


class TestGuardConfigOtelFallback:
    def test_otel_fallback_span_is_context_manager(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lines 181-187: when opentelemetry is absent, _span returns nullcontext."""
        import importlib

        # Block opentelemetry so the except ImportError branch in guard_config is taken.
        monkeypatch.setitem(sys.modules, "opentelemetry", None)
        monkeypatch.setitem(sys.modules, "opentelemetry.trace", None)

        import pramanix.guard_config as _gc_mod

        importlib.reload(_gc_mod)
        try:
            span = _gc_mod._span("test-operation")
            # Should be a no-op context manager (nullcontext)
            with span:
                pass
        finally:
            importlib.reload(_gc_mod)
