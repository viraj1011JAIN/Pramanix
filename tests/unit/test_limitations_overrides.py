# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Known Limitations mitigations.

Covers four production-hardening packages introduced in v0.9.0:

1. TOCTOU gap — state_version binding in ExecutionToken
2. Z3 encoding scope — PolicyAuditor field coverage analysis
3. Z3 crash risk — GuardConfig production-mode warning
4. Z3 string perf — StringEnumField int-backed enumeration

All tests use real objects (no mocks) per the no-mocks policy.
"""
from __future__ import annotations

import warnings
from decimal import Decimal

import pytest

from pramanix import (
    Decision,
    E,
    ExecutionToken,
    ExecutionTokenSigner,
    ExecutionTokenVerifier,
    Field,
    Policy,
    PolicyAuditor,
    StringEnumField,
)
from pramanix.expressions import ConstraintExpr

# ── Helpers ───────────────────────────────────────────────────────────────────

_SECRET = b"test-secret-key-32-bytes-minimum!"
_SIGNER = ExecutionTokenSigner(secret_key=_SECRET, ttl_seconds=30.0)
_VERIFIER = ExecutionTokenVerifier(secret_key=_SECRET)


def _safe_decision() -> Decision:
    return Decision.safe(
        intent_dump={"amount": "100"},
        solver_time_ms=5.0,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. TOCTOU: state_version binding
# ─────────────────────────────────────────────────────────────────────────────


class TestStateVersionToken:
    def test_mint_without_state_version_has_none(self) -> None:
        token = _SIGNER.mint(_safe_decision())
        assert token.state_version is None

    def test_mint_with_state_version_embeds_it(self) -> None:
        token = _SIGNER.mint(_safe_decision(), state_version="etag-v3-abc")
        assert token.state_version == "etag-v3-abc"

    def test_consume_without_version_binding_succeeds(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision())
        assert verifier.consume(token) is True

    def test_consume_with_matching_state_version_succeeds(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision(), state_version="v3-abc")
        assert verifier.consume(token, expected_state_version="v3-abc") is True

    def test_consume_with_stale_state_version_fails(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision(), state_version="v3-abc")
        # State was mutated between verify() and execute() — TOCTOU detected
        assert verifier.consume(token, expected_state_version="v4-mutated") is False

    def test_consume_token_has_version_but_caller_omits_expected_fails(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        # Token bound to "v3-abc"; caller passes None → mismatch → BLOCK
        token = _SIGNER.mint(_safe_decision(), state_version="v3-abc")
        assert verifier.consume(token, expected_state_version=None) is False

    def test_consume_token_no_version_but_caller_passes_one_fails(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        # Token has no version; caller expects one → mismatch → BLOCK
        token = _SIGNER.mint(_safe_decision())
        assert verifier.consume(token, expected_state_version="v3-abc") is False

    def test_tampered_state_version_fails_signature(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision(), state_version="v3-real")
        # Attacker strips the state_version field — dataclass is frozen so we
        # reconstruct: the HMAC body now differs from the minted body.
        forged = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature=token.signature,  # original sig — now invalid for None version
            state_version=None,         # attacker stripped the version
        )
        assert verifier.consume(forged) is False

    def test_state_version_is_included_in_hmac_body(self) -> None:
        from pramanix.execution_token import _token_body

        token_with = _SIGNER.mint(_safe_decision(), state_version="v1")
        token_none = _SIGNER.mint(_safe_decision(), state_version=None)
        # Bodies differ because state_version differs
        assert _token_body(token_with) != _token_body(token_none)

    def test_state_version_token_is_single_use(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision(), state_version="v1")
        assert verifier.consume(token, expected_state_version="v1") is True
        assert verifier.consume(token, expected_state_version="v1") is False

    def test_state_version_survives_round_trip_equality(self) -> None:
        token = _SIGNER.mint(_safe_decision(), state_version="sha256:deadbeef")
        assert token.state_version == "sha256:deadbeef"

    def test_state_version_empty_string_is_valid(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision(), state_version="")
        assert verifier.consume(token, expected_state_version="") is True

    def test_state_version_empty_vs_none_are_distinct(self) -> None:
        verifier = ExecutionTokenVerifier(secret_key=_SECRET)
        token = _SIGNER.mint(_safe_decision(), state_version="")
        # "" != None → BLOCK
        assert verifier.consume(token, expected_state_version=None) is False


# ─────────────────────────────────────────────────────────────────────────────
# 2. Z3 encoding scope: PolicyAuditor
# ─────────────────────────────────────────────────────────────────────────────


class _FullCoveragePolicy(Policy):
    class Meta:
        version = "1.0"

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= 0).named("non_negative"),
        ]


class _PartialCoveragePolicy(Policy):
    class Meta:
        version = "1.0"

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")
    currency = Field("currency", str, "String")  # never used in any invariant

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= 0).named("non_negative"),
        ]


class _EmptyInvariantsPolicy(Policy):
    class Meta:
        version = "1.0"

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return []


class TestPolicyAuditor:
    def test_declared_fields_returns_all_fields(self) -> None:
        fields = PolicyAuditor.declared_fields(_FullCoveragePolicy)
        assert set(fields.keys()) == {"amount", "balance"}

    def test_referenced_fields_finds_used_fields(self) -> None:
        referenced = PolicyAuditor.referenced_fields(_FullCoveragePolicy)
        assert "amount" in referenced
        assert "balance" in referenced

    def test_uncovered_fields_returns_empty_for_full_coverage(self) -> None:
        assert PolicyAuditor.uncovered_fields(_FullCoveragePolicy) == []

    def test_uncovered_fields_detects_unused_field(self) -> None:
        uncovered = PolicyAuditor.uncovered_fields(_PartialCoveragePolicy)
        assert uncovered == ["currency"]

    def test_uncovered_fields_detects_all_fields_when_no_invariants(self) -> None:
        uncovered = PolicyAuditor.uncovered_fields(_EmptyInvariantsPolicy)
        assert uncovered == ["amount"]

    def test_audit_emits_warning_for_uncovered_fields(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = PolicyAuditor.audit(_PartialCoveragePolicy)
        assert len(w) == 1
        assert "currency" in str(w[0].message)
        assert result == ["currency"]

    def test_audit_no_warning_for_full_coverage(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            PolicyAuditor.audit(_FullCoveragePolicy)
        assert len(w) == 0

    def test_audit_raises_when_raise_on_uncovered_true(self) -> None:
        with pytest.raises(ValueError, match="currency"):
            PolicyAuditor.audit(_PartialCoveragePolicy, raise_on_uncovered=True)

    def test_audit_no_raise_for_full_coverage_strict_mode(self) -> None:
        result = PolicyAuditor.audit(_FullCoveragePolicy, raise_on_uncovered=True)
        assert result == []

    def test_referenced_fields_handles_boolean_combinator(self) -> None:
        class _BoolPolicy(Policy):
            class Meta:
                version = "1.0"

            a = Field("a", Decimal, "Real")
            b = Field("b", Decimal, "Real")
            c = Field("c", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [((E(cls.a) > 0) & (E(cls.b) > 0)).named("ab")]

        # c is unreferenced
        assert PolicyAuditor.uncovered_fields(_BoolPolicy) == ["c"]
        assert "a" in PolicyAuditor.referenced_fields(_BoolPolicy)
        assert "b" in PolicyAuditor.referenced_fields(_BoolPolicy)

    def test_referenced_fields_handles_is_in(self) -> None:
        class _InPolicy(Policy):
            class Meta:
                version = "1.0"

            role = Field("role", int, "Int")
            score = Field("score", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [E(cls.role).is_in([1, 2, 3]).named("role_check")]

        assert "role" in PolicyAuditor.referenced_fields(_InPolicy)
        assert PolicyAuditor.uncovered_fields(_InPolicy) == ["score"]

    def test_referenced_fields_handles_abs_expr(self) -> None:
        class _AbsPolicy(Policy):
            class Meta:
                version = "1.0"

            delta = Field("delta", Decimal, "Real")
            limit = Field("limit", Decimal, "Real")
            unused = Field("unused", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.delta).abs() <= E(cls.limit)).named("abs_check")]

        assert "delta" in PolicyAuditor.referenced_fields(_AbsPolicy)
        assert "limit" in PolicyAuditor.referenced_fields(_AbsPolicy)
        assert PolicyAuditor.uncovered_fields(_AbsPolicy) == ["unused"]

    def test_declared_fields_includes_inherited_fields(self) -> None:
        class _Base(Policy):
            class Meta:
                version = "1.0"

            base_field = Field("base_field", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return []

        class _Child(_Base):
            child_field = Field("child_field", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return []

        fields = PolicyAuditor.declared_fields(_Child)
        assert "base_field" in fields
        assert "child_field" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 3. Z3 crash risk: production mode warning
# ─────────────────────────────────────────────────────────────────────────────


class TestProductionModeWarning:
    def _config_with_mode(self, mode: str) -> None:
        from pramanix import GuardConfig

        GuardConfig(execution_mode=mode)

    def test_sync_in_production_emits_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._config_with_mode("sync")
        prod_warnings = [x for x in w if "async-process" in str(x.message)]
        assert len(prod_warnings) == 1
        assert "sync" in str(prod_warnings[0].message)

    def test_async_thread_in_production_emits_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._config_with_mode("async-thread")
        prod_warnings = [x for x in w if "async-process" in str(x.message)]
        assert len(prod_warnings) == 1
        assert "async-thread" in str(prod_warnings[0].message)

    def test_async_process_in_production_no_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._config_with_mode("async-process")
        prod_warnings = [x for x in w if "async-process" in str(x.message) and "not recommended" in str(x.message)]
        assert len(prod_warnings) == 0

    def test_sync_without_production_env_no_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._config_with_mode("sync")
        prod_warnings = [x for x in w if "not recommended" in str(x.message)]
        assert len(prod_warnings) == 0

    def test_production_env_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "PRODUCTION")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._config_with_mode("sync")
        prod_warnings = [x for x in w if "async-process" in str(x.message)]
        assert len(prod_warnings) == 1

    def test_warning_is_userwarning_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self._config_with_mode("sync")
        prod_warnings = [x for x in w if "async-process" in str(x.message)]
        assert prod_warnings[0].category is UserWarning


# ─────────────────────────────────────────────────────────────────────────────
# 4. Z3 string perf: StringEnumField
# ─────────────────────────────────────────────────────────────────────────────


class TestStringEnumField:
    def test_encode_first_value_is_zero(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])
        assert s.encode("CLEAR") == 0

    def test_encode_second_value_is_one(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])
        assert s.encode("PENDING") == 1

    def test_encode_third_value_is_two(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])
        assert s.encode("BLOCKED") == 2

    def test_decode_zero_is_first_value(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])
        assert s.decode(0) == "CLEAR"

    def test_decode_round_trip(self) -> None:
        s = StringEnumField("role", ["admin", "trader", "viewer"])
        for label in s.values:
            assert s.decode(s.encode(label)) == label

    def test_encode_invalid_raises_value_error(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING"])
        with pytest.raises(ValueError, match="UNKNOWN"):
            s.encode("UNKNOWN")

    def test_decode_invalid_raises_value_error(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING"])
        with pytest.raises(ValueError, match="99"):
            s.decode(99)

    def test_empty_values_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            StringEnumField("status", [])

    def test_duplicate_values_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Duplicates"):
            StringEnumField("status", ["CLEAR", "CLEAR", "PENDING"])

    def test_field_has_int_sort(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING"])
        assert s.field.z3_type == "Int"
        assert s.field.name == "status"

    def test_valid_values_constraint_label(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING"])
        constraint = s.valid_values_constraint(s.field)
        assert constraint.label == "status_valid_enum_code"

    def test_is_allowed_constraint_label(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])
        constraint = s.is_allowed_constraint(s.field, ["CLEAR"])
        assert "status" in (constraint.label or "")

    def test_is_allowed_constraint_invalid_label_raises(self) -> None:
        s = StringEnumField("status", ["CLEAR", "PENDING"])
        with pytest.raises(ValueError, match="BLOCKED"):
            s.is_allowed_constraint(s.field, ["BLOCKED"])

    def test_values_property(self) -> None:
        s = StringEnumField("tier", ["LOW", "MEDIUM", "HIGH"])
        assert s.values == ["LOW", "MEDIUM", "HIGH"]

    def test_codes_property(self) -> None:
        s = StringEnumField("tier", ["LOW", "MEDIUM", "HIGH"])
        assert s.codes == [0, 1, 2]

    def test_mapping_property(self) -> None:
        s = StringEnumField("tier", ["LOW", "MEDIUM"])
        assert s.mapping == {"LOW": 0, "MEDIUM": 1}

    def test_repr(self) -> None:
        s = StringEnumField("status", ["A", "B"])
        assert "StringEnumField" in repr(s)
        assert "status" in repr(s)

    def test_full_policy_integration_allow(self) -> None:
        from pramanix import Guard, GuardConfig

        _status = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])

        class _StatusPolicy(Policy):
            status = _status.field

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    _status.valid_values_constraint(cls.status),
                    _status.is_allowed_constraint(cls.status, ["CLEAR"]),
                ]

        guard = Guard(_StatusPolicy, GuardConfig(execution_mode="sync"))
        decision = guard.verify(
            intent={"status": _status.encode("CLEAR")},
            state={},
        )
        assert decision.allowed is True

    def test_full_policy_integration_block(self) -> None:
        from pramanix import Guard, GuardConfig

        _status = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])

        class _StatusPolicy2(Policy):
            status = _status.field

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    _status.valid_values_constraint(cls.status),
                    _status.is_allowed_constraint(cls.status, ["CLEAR"]),
                ]

        guard = Guard(_StatusPolicy2, GuardConfig(execution_mode="sync"))
        decision = guard.verify(
            intent={"status": _status.encode("BLOCKED")},
            state={},
        )
        assert decision.allowed is False
