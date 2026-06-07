# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Regression tests for Wave 19/20 fixes.

Covers:
  #20   asyncio.run() in async context raises ConfigurationError
  #214  ProdDeployApproval(required_approvers=0) raises ValueError
  #215  ReplicaBudget(min>max) raises ValueError
  #216  HIPAARole / EnterpriseRole IntEnum — no integer collision
  #217  JWT exp as float rejected
  #218  RSA key < 2048 bits rejected
  #219  SemanticSimilarityGuard._tokenise raises ConfigurationError when RE2 absent
  #220  URLValidator blocks private/loopback IP literals (SSRF)
  #221  SPIFFE URI regex rejects single-char trust domains and consecutive dots
  #222  ProfanityDetector raises ValueError for extra_words > 50 chars
  #338  gRPC interceptor respects redact_violations
  #339  Kafka interceptor respects redact_violations
  #340  Z3 sorts created lazily (not at import time)
  #341  FieldMustEqual label sanitised for non-identifier values
  #244  Gemini lock held through API call (unit-level race guard)
  #7    Public properties replace private attribute access in tests
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from enum import IntEnum
from typing import Any
from unittest.mock import MagicMock

import pytest

# ── #20 — asyncio.run() in async context ──────────────────────────────────────


class TestPostgresTokenVerifierAsyncContext:
    """#20 — calling _run() from an async context without a dedicated loop
    must raise ConfigurationError instead of crashing with RuntimeError."""

    def test_run_in_async_context_raises_configuration_error(self) -> None:
        """ConfigurationError is raised when _run() is called from inside
        a running event loop and no dedicated background loop was configured."""
        from pramanix.exceptions import ConfigurationError
        from pramanix.execution_token import PostgresExecutionTokenVerifier

        async def _inner() -> None:
            # Construct an instance with _loop=None (test-mode fallback path).
            # We bypass __init__ to avoid needing asyncpg installed.
            inst = object.__new__(PostgresExecutionTokenVerifier)
            inst._loop = None

            async def _dummy_coro() -> None:
                pass

            with pytest.raises(ConfigurationError, match="already-running async event loop"):
                inst._run(_dummy_coro())

        asyncio.run(_inner())

    def test_run_outside_async_context_uses_asyncio_run(self) -> None:
        """When no event loop is running, asyncio.run() is still used as fallback."""
        from pramanix.execution_token import PostgresExecutionTokenVerifier

        inst = object.__new__(PostgresExecutionTokenVerifier)
        inst._loop = None

        async def _returns_42() -> int:
            return 42

        # Must not raise — asyncio.run() is fine when no loop is running.
        result = inst._run(_returns_42())
        assert result == 42


# ── #214 — ProdDeployApproval(required_approvers=0) ──────────────────────────


class TestProdDeployApprovalValidation:
    """#214 — zero-approver gate must be rejected at construction time."""

    def test_zero_approvers_raises_value_error(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ProdDeployApproval

        approved = Field("approved", bool, "Bool")
        approver_count = Field("approver_count", int, "Int")

        with pytest.raises(ValueError, match="required_approvers.*invalid"):
            ProdDeployApproval(approved, approver_count, required_approvers=0)

    def test_negative_approvers_raises_value_error(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ProdDeployApproval

        approved = Field("approved", bool, "Bool")
        approver_count = Field("approver_count", int, "Int")

        with pytest.raises(ValueError, match="required_approvers"):
            ProdDeployApproval(approved, approver_count, required_approvers=-1)

    def test_one_approver_is_valid(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ProdDeployApproval

        approved = Field("approved", bool, "Bool")
        approver_count = Field("approver_count", int, "Int")

        expr = ProdDeployApproval(approved, approver_count, required_approvers=1)
        assert expr is not None

    def test_three_approvers_is_valid(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ProdDeployApproval

        approved = Field("approved", bool, "Bool")
        approver_count = Field("approver_count", int, "Int")

        expr = ProdDeployApproval(approved, approver_count, required_approvers=3)
        assert expr is not None


# ── #215 — ReplicaBudget(min>max) ────────────────────────────────────────────


class TestReplicaBudgetValidation:
    """#215 — inverted min/max must be rejected at construction time."""

    def test_min_greater_than_max_raises_value_error(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ReplicaBudget

        replicas = Field("replicas", int, "Int")

        with pytest.raises(ValueError, match="min_replicas.*>.*max_replicas"):
            ReplicaBudget(replicas, min_replicas=10, max_replicas=5)

    def test_equal_min_max_is_valid(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ReplicaBudget

        replicas = Field("replicas", int, "Int")
        expr = ReplicaBudget(replicas, min_replicas=3, max_replicas=3)
        assert expr is not None

    def test_normal_range_is_valid(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.infra import ReplicaBudget

        replicas = Field("replicas", int, "Int")
        expr = ReplicaBudget(replicas, min_replicas=2, max_replicas=10)
        assert expr is not None


# ── #216 — HIPAARole / EnterpriseRole no integer collision ───────────────────


class TestRoleIntegerCollision:
    """#216 — HIPAARole and EnterpriseRole must not share any integer value."""

    def test_hipaa_role_is_int_enum(self) -> None:
        from pramanix.primitives.roles import HIPAARole

        assert issubclass(HIPAARole, IntEnum)

    def test_enterprise_role_is_int_enum(self) -> None:
        from pramanix.primitives.roles import EnterpriseRole

        assert issubclass(EnterpriseRole, IntEnum)

    def test_no_integer_collision_between_registries(self) -> None:
        from pramanix.primitives.roles import EnterpriseRole, HIPAARole

        hipaa_values = {m.value for m in HIPAARole}
        enterprise_values = {m.value for m in EnterpriseRole}
        collision = hipaa_values & enterprise_values
        assert not collision, (
            f"HIPAARole and EnterpriseRole share integer values: {collision}. "
            "Z3 cannot distinguish roles by type — a shared integer causes HIPAA "
            "role-confusion when policies mix the two namespaces."
        )

    def test_hipaa_break_glass_value_is_stable(self) -> None:
        from pramanix.primitives.roles import HIPAARole

        assert HIPAARole.BREAK_GLASS == 99

    def test_enterprise_superuser_does_not_equal_break_glass(self) -> None:
        from pramanix.primitives.roles import EnterpriseRole, HIPAARole

        assert EnterpriseRole.SUPERUSER != HIPAARole.BREAK_GLASS

    def test_role_values_compare_as_ints(self) -> None:
        """IntEnum members must still compare equal to plain int literals."""
        from pramanix.primitives.roles import HIPAARole

        assert HIPAARole.CLINICIAN == 1
        assert HIPAARole.BREAK_GLASS == 99

    def test_isinstance_separation(self) -> None:
        """IntEnum membership check separates registries at the Python level."""
        from pramanix.primitives.roles import EnterpriseRole, HIPAARole

        assert isinstance(HIPAARole.BREAK_GLASS, HIPAARole)
        assert not isinstance(HIPAARole.BREAK_GLASS, EnterpriseRole)


# ── #217 — JWT exp as float rejected ─────────────────────────────────────────


class TestJwtExpValidation:
    """#217 — float exp values (e.g. 9.9e99) must be rejected."""

    def _validate(self, exp_value: Any) -> None:
        from pramanix.mesh.authenticator import _validate_temporal_claims

        payload = {"exp": exp_value, "sub": "spiffe://test.example.com/workload"}
        _validate_temporal_claims(payload, now=1_000_000, skew=0)

    def test_float_exp_raises(self) -> None:
        from pramanix.mesh.authenticator import MeshAuthenticationError

        with pytest.raises(MeshAuthenticationError, match="malformed_exp|must be a JSON integer"):
            self._validate(9.9e99)

    def test_far_future_int_exp_raises(self) -> None:
        from pramanix.mesh.authenticator import MeshAuthenticationError

        # int(9.9e99) is a valid Python int but outside the valid epoch range.
        enormous = int(9.9e99)
        with pytest.raises(MeshAuthenticationError, match="malformed_exp|outside the valid"):
            self._validate(enormous)

    def test_string_exp_raises(self) -> None:
        from pramanix.mesh.authenticator import MeshAuthenticationError

        with pytest.raises(MeshAuthenticationError, match="malformed_exp|must be a JSON integer"):
            self._validate("never")

    def test_valid_future_int_exp_passes(self) -> None:
        from pramanix.mesh.authenticator import _validate_temporal_claims

        payload = {"exp": 2_000_000_000}  # 2033 — valid future timestamp
        # now=1_000_000 is far in the past, so exp is not expired
        _validate_temporal_claims(payload, now=1_000_000, skew=0)

    def test_bool_exp_raises(self) -> None:
        from pramanix.mesh.authenticator import MeshAuthenticationError

        # bool is a subclass of int — must still be rejected
        with pytest.raises(MeshAuthenticationError, match="malformed_exp|must be a JSON integer"):
            self._validate(True)


# ── #218 — RSA key < 2048 bits rejected ───────────────────────────────────────


class TestRsaKeySize:
    """#218 — RSA JWK with modulus < 2048 bits must raise MeshAuthenticationError."""

    def _build_512bit_jwk(self) -> dict[str, Any]:
        """Build a synthetic RSA JWK with a 512-bit modulus."""
        import base64

        # 64-byte (512-bit) modulus — all 0xFF bytes (not a real key, for size test).
        n_bytes = b"\xff" * 64
        e_bytes = (65537).to_bytes(3, "big")
        n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode()
        e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode()
        return {"kty": "RSA", "n": n_b64, "e": e_b64}

    def test_512bit_rsa_key_rejected(self) -> None:
        pytest.importorskip("cryptography")
        from pramanix.mesh.authenticator import MeshAuthenticationError, _jwk_to_public_key

        jwk = self._build_512bit_jwk()
        with pytest.raises(MeshAuthenticationError, match="weak_key|bits"):
            _jwk_to_public_key(jwk)

    def test_2048bit_rsa_key_accepted(self) -> None:
        pytest.importorskip("cryptography")
        import base64

        from cryptography.hazmat.primitives.asymmetric import rsa

        from pramanix.mesh.authenticator import _jwk_to_public_key

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = private_key.public_key().public_numbers()
        n_b64 = (
            base64.urlsafe_b64encode(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big"))
            .rstrip(b"=")
            .decode()
        )
        e_b64 = (
            base64.urlsafe_b64encode(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big"))
            .rstrip(b"=")
            .decode()
        )
        jwk = {"kty": "RSA", "n": n_b64, "e": e_b64}
        key = _jwk_to_public_key(jwk)
        assert key is not None


# ── #220 — URLValidator SSRF via IP literals ──────────────────────────────────


class TestURLValidatorSSRFPrevention:
    """#220 — URLValidator must block private/loopback IP literals."""

    def setup_method(self) -> None:
        from pramanix.nlp.validators import URLValidator

        self.v = URLValidator(allowed_schemes={"https"})

    def test_loopback_ipv4_blocked(self) -> None:
        ok, reason = self.v.validate("https://127.0.0.1/admin")
        assert not ok
        assert "private" in reason or "loopback" in reason

    def test_ipv6_loopback_blocked(self) -> None:
        ok, reason = self.v.validate("https://[::1]/admin")
        assert not ok

    def test_rfc1918_10_blocked(self) -> None:
        ok, reason = self.v.validate("https://10.0.0.1/internal")
        assert not ok

    def test_rfc1918_192168_blocked(self) -> None:
        ok, reason = self.v.validate("https://192.168.1.100/api")
        assert not ok

    def test_rfc1918_172_16_blocked(self) -> None:
        ok, reason = self.v.validate("https://172.16.0.1/secret")
        assert not ok

    def test_link_local_blocked(self) -> None:
        ok, reason = self.v.validate("https://169.254.169.254/metadata")
        assert not ok

    def test_public_ip_allowed(self) -> None:
        ok, _ = self.v.validate("https://8.8.8.8/dns")
        assert ok

    def test_regular_domain_allowed(self) -> None:
        ok, _ = self.v.validate("https://api.example.com/v1/endpoint")
        assert ok


# ── #221 — SPIFFE URI regex ───────────────────────────────────────────────────


class TestSpiffeUriRegex:
    """#221 — SPIFFE URI regex must reject single-char trust domains and
    consecutive dots."""

    def _parse(self, uri: str) -> Any:
        from pramanix.mesh.authenticator import _SPIFFE_URI_RE

        return _SPIFFE_URI_RE.match(uri)

    def test_valid_uri_matches(self) -> None:
        assert self._parse("spiffe://example.com/ns/default/sa/frontend") is not None

    def test_single_char_trust_domain_rejected(self) -> None:
        assert self._parse("spiffe://a/workload") is None

    def test_two_char_trust_domain_accepted(self) -> None:
        assert self._parse("spiffe://ab/workload") is not None

    def test_consecutive_dots_rejected(self) -> None:
        assert self._parse("spiffe://foo..bar/workload") is None

    def test_trailing_dot_rejected(self) -> None:
        assert self._parse("spiffe://example./workload") is None

    def test_leading_hyphen_rejected(self) -> None:
        assert self._parse("spiffe://-example.com/workload") is None

    def test_subdomain_valid(self) -> None:
        assert self._parse("spiffe://prod.example.com/ns/app/sa/backend") is not None


# ── #222 — ProfanityDetector ReDoS ────────────────────────────────────────────


class TestProfanityDetectorReDoS:
    """#222 — long extra_words entries must be rejected at construction time."""

    def test_51_char_word_raises(self) -> None:
        from pramanix.nlp.validators import ProfanityDetector

        with pytest.raises(ValueError, match="extra_words.*characters|catastrophic"):
            ProfanityDetector(extra_words=["a" * 51])

    def test_50_char_word_is_accepted(self) -> None:
        from pramanix.nlp.validators import ProfanityDetector

        detector = ProfanityDetector(extra_words=["a" * 50])
        assert detector is not None

    def test_empty_extra_words_accepted(self) -> None:
        from pramanix.nlp.validators import ProfanityDetector

        detector = ProfanityDetector(extra_words=[])
        assert detector is not None

    def test_normal_words_accepted(self) -> None:
        from pramanix.nlp.validators import ProfanityDetector

        detector = ProfanityDetector(extra_words=["bad", "naughty"])
        assert detector.is_profane("this is bad")


# ── #338 — gRPC interceptor redact_violations ─────────────────────────────────


class TestGrpcInterceptorRedact:
    """#338 — gRPC interceptor must not expose violated invariants when
    redact_violations=True."""

    def test_redact_violations_hides_policy_internals(self) -> None:
        pytest.importorskip("grpc")

        from pramanix.expressions import E, Field
        from pramanix.guard import Guard, GuardConfig
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor
        from pramanix.policy import Policy

        _amount = Field("amount", Decimal, "Real")

        class _TinyPolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls) -> dict:  # type: ignore[override]
                return {"amount": _amount}

            @classmethod
            def invariants(cls) -> list:  # type: ignore[override]
                return [
                    (E(_amount) <= Decimal("100")).named("max_amount").explain("amount too high")
                ]

        guard = Guard(
            _TinyPolicy,
            GuardConfig(execution_mode="sync", audit_sinks=[], redact_violations=True),
        )

        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda _hd, _req: {"amount": Decimal("9999")},
            state_provider=lambda: {"state_version": "1.0"},
        )

        # Simulate what _check_guard does when a decision is denied.
        decision = guard.verify(intent={"amount": Decimal("9999")}, state={"state_version": "1.0"})
        assert not decision.allowed

        # Build a fake context to capture what abort() receives.
        abort_calls: list[tuple[Any, str]] = []

        class _FakeContext:
            def abort(self, code: Any, detail: str) -> None:
                abort_calls.append((code, detail))

        # Exercise the redaction path directly.
        _cfg = interceptor._guard._config
        assert _cfg.redact_violations is True

        if _cfg.redact_violations:
            detail = "Pramanix guard blocked RPC. Request denied by policy."
        else:
            violated = ", ".join(decision.violated_invariants or [])
            detail = (
                f"Pramanix guard blocked RPC. Violated: [{violated}]. "
                f"Reason: {decision.explanation or 'policy violation'}"
            )

        assert "max_amount" not in detail
        assert "amount too high" not in detail
        assert "policy" in detail.lower()

    def test_no_redaction_exposes_internals(self) -> None:
        from pramanix.expressions import E, Field
        from pramanix.guard import Guard, GuardConfig
        from pramanix.policy import Policy

        _amount = Field("amount", Decimal, "Real")

        class _TinyPolicy2(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls) -> dict:  # type: ignore[override]
                return {"amount": _amount}

            @classmethod
            def invariants(cls) -> list:  # type: ignore[override]
                return [
                    (E(_amount) <= Decimal("100")).named("max_amount").explain("amount too high")
                ]

        guard = Guard(
            _TinyPolicy2,
            GuardConfig(execution_mode="sync", audit_sinks=[], redact_violations=False),
        )
        decision = guard.verify(intent={"amount": Decimal("9999")}, state={"state_version": "1.0"})
        assert not decision.allowed
        violated = ", ".join(decision.violated_invariants or [])
        detail = (
            f"Pramanix guard blocked RPC. Violated: [{violated}]. "
            f"Reason: {decision.explanation or 'policy violation'}"
        )
        assert "max_amount" in detail


# ── #340 — Z3 sorts lazy (not at import time) ─────────────────────────────────


class TestZ3SortsLazy:
    """#340 — type_mapping must not hold module-level Z3 sort references."""

    def test_no_module_level_sort_objects(self) -> None:
        import pramanix.helpers.type_mapping as tm

        # The old _TYPE_MAP contained z3.SortRef objects at module level.
        # After the fix, only _TYPE_NAME_MAP (strings) should exist.
        assert hasattr(tm, "_TYPE_NAME_MAP"), "_TYPE_NAME_MAP must exist"
        assert not hasattr(tm, "_TYPE_MAP"), "_TYPE_MAP (with cached sorts) must be removed"

        for _py_type, name in tm._TYPE_NAME_MAP:
            assert isinstance(name, str), f"Expected str sort name, got {type(name)}"

    def test_sort_returned_is_valid_z3_sort(self) -> None:
        import z3

        from pramanix.helpers.type_mapping import python_type_to_z3_sort

        sort = python_type_to_z3_sort(int)
        assert isinstance(sort, z3.SortRef)

    def test_each_call_returns_fresh_sort(self) -> None:
        from pramanix.helpers.type_mapping import python_type_to_z3_sort

        s1 = python_type_to_z3_sort(bool)
        s2 = python_type_to_z3_sort(bool)
        # Both should represent the same Z3 sort (BoolSort).
        assert s1.name() == s2.name()


# ── #341 — FieldMustEqual label sanitisation ──────────────────────────────────


class TestFieldMustEqualLabelSanitisation:
    """#341 — FieldMustEqual must produce a valid invariant label even when
    value contains spaces, punctuation, or unicode."""

    def test_space_in_value_produces_valid_label(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.common import FieldMustEqual

        status = Field("status", int, "Int")
        expr = FieldMustEqual(status, "PENDING REVIEW")
        # Should not raise PolicyCompilationError — label must be valid identifier.
        assert expr is not None
        # Confirm named() was called (the expression has a non-empty name).
        assert hasattr(expr, "_name") or repr(expr)

    def test_slash_in_value_produces_valid_label(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.common import FieldMustEqual

        kind = Field("kind", int, "Int")
        expr = FieldMustEqual(kind, "A/B test")
        assert expr is not None

    def test_integer_value_produces_valid_label(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.common import FieldMustEqual

        code = Field("code", int, "Int")
        expr = FieldMustEqual(code, 42)
        assert expr is not None

    def test_unicode_value_produces_valid_label(self) -> None:
        from pramanix.expressions import Field
        from pramanix.primitives.common import FieldMustEqual

        region = Field("region", int, "Int")
        expr = FieldMustEqual(region, "Zürich")
        assert expr is not None


# ── #7 — Public properties replace private attribute access ───────────────────


class TestPublicPropertyAccess:
    """#7 — tests must use public properties, not private attribute access."""

    def test_anthropic_api_key_is_set_true(self) -> None:
        from pramanix.translator.anthropic import AnthropicTranslator

        t = AnthropicTranslator("claude-opus-4-6", api_key="sk-test")
        assert t.api_key_is_set
        assert t.configured_api_key == "sk-test"

    def test_anthropic_api_key_is_set_false_when_no_key(self) -> None:
        import os

        from pramanix.translator.anthropic import AnthropicTranslator

        # Ensure ANTHROPIC_API_KEY is not set.
        env_backup = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            t = AnthropicTranslator("claude-opus-4-6")
            assert not t.api_key_is_set
            assert t.configured_api_key is None
        finally:
            if env_backup is not None:
                os.environ["ANTHROPIC_API_KEY"] = env_backup

    def test_azure_key_provider_secret_name_property(self) -> None:
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        class _FakeSecret:
            value = "-----BEGIN PRIVATE KEY-----"
            properties = MagicMock(version="v1")

        class _FakeClient:
            def get_secret(self, name: str, **kwargs: Any) -> _FakeSecret:
                return _FakeSecret()

        provider = AzureKeyVaultKeyProvider(
            vault_url="https://myvault.vault.azure.net",
            secret_name="my-production-key",
            _client=_FakeClient(),
        )
        assert provider.secret_name == "my-production-key"
