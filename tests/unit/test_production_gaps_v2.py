# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Production-level tests for the three gaps identified in the v1.0 review.

Gap 1 — audit_sinks=() in production raises ConfigurationError
    GuardConfig(audit_sinks=()) with PRAMANIX_ENV=production must raise
    ConfigurationError, not emit a UserWarning.  PRAMANIX_ALLOW_NO_AUDIT_SINKS=1
    is the explicit opt-out for testing and local dev.

Gap 2 — pramanix doctor audit-sink-reachability is ERROR in production
    The CLI check must be level="ERROR" (not "WARN") so that operators
    cannot miss the requirement and CI pipelines fail loudly.

Gap 3 — StringEnumField auto-coercion via Policy.string_enum_coercions()
    Guard.verify() must transparently encode string values for any field
    registered in Policy.string_enum_coercions(), eliminating the footgun
    where callers forget to call .encode() and receive a cryptic Z3 error.
    The pre-solver string guard must also catch unregistered Int fields that
    receive string values and return a clear Decision.error().

Design rules
------------
* No mocks, no stubs, no unittest.mock imports.
* All guards use real Z3 via real Guard/Policy classes.
* All CLI tests invoke main() with real sys.argv via monkeypatch.
"""
from __future__ import annotations

import json
import sys
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import ConfigurationError
from pramanix.helpers.string_enum import StringEnumField


# ══════════════════════════════════════════════════════════════════════════════
# Gap 1 — audit_sinks ConfigurationError
# ══════════════════════════════════════════════════════════════════════════════


class TestAuditSinksProductionError:
    """GuardConfig raises ConfigurationError when no sinks in production."""

    def test_no_sinks_in_production_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        with pytest.raises(ConfigurationError, match="audit_sinks"):
            GuardConfig()

    def test_error_message_names_remedy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        with pytest.raises(ConfigurationError, match="S3AuditSink|KafkaAuditSink"):
            GuardConfig()

    def test_bypass_env_var_suppresses_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        monkeypatch.setenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", "1")
        # Must not raise — bypass is active.
        cfg = GuardConfig()
        assert cfg.audit_sinks == ()

    def test_bypass_env_var_true_word_suppresses_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        monkeypatch.setenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", "true")
        cfg = GuardConfig()
        assert cfg.audit_sinks == ()

    def test_non_production_env_no_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "staging")
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        # staging is not production — no error.
        cfg = GuardConfig()
        assert cfg.audit_sinks == ()

    def test_no_pramanix_env_no_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        cfg = GuardConfig()
        assert cfg.audit_sinks == ()

    def test_real_sink_in_production_no_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.audit_sink import InMemoryAuditSink

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        # A real sink satisfies the requirement — no error.
        cfg = GuardConfig(audit_sinks=(InMemoryAuditSink(),))
        assert len(cfg.audit_sinks) == 1

    def test_error_type_is_configuration_error_not_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Confirm the type is ConfigurationError, not UserWarning (regression guard)."""
        import warnings

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with pytest.raises(ConfigurationError):
                GuardConfig()
        audit_warnings = [x for x in w if "audit_sinks" in str(x.message)]
        assert len(audit_warnings) == 0, "audit_sinks check must raise, not warn"

    def test_production_uppercase_also_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "PRODUCTION")
        monkeypatch.delenv("PRAMANIX_ALLOW_NO_AUDIT_SINKS", raising=False)
        with pytest.raises(ConfigurationError, match="audit_sinks"):
            GuardConfig()


# ══════════════════════════════════════════════════════════════════════════════
# Gap 2 — doctor audit-sink-reachability level
# ══════════════════════════════════════════════════════════════════════════════


def _run_doctor(
    extra_args: list[str],
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[int, dict]:
    from pramanix.cli import main

    monkeypatch.setattr(sys, "argv", ["pramanix", "doctor", "--json", *extra_args])
    try:
        exit_code = main()
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    return exit_code, json.loads(out)


class TestDoctorAuditSinkCheck:
    """pramanix doctor must report audit-sink-reachability as ERROR in production."""

    def test_audit_sink_is_error_in_production(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        _, data = _run_doctor([], capsys, monkeypatch)
        checks = {c["name"]: c for c in data["checks"]}
        assert "audit-sink-reachability" in checks
        assert checks["audit-sink-reachability"]["level"] == "ERROR"

    def test_audit_sink_check_detail_mentions_sinks(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        _, data = _run_doctor([], capsys, monkeypatch)
        checks = {c["name"]: c for c in data["checks"]}
        detail = checks["audit-sink-reachability"]["detail"]
        assert "AuditSink" in detail or "audit" in detail.lower()

    def test_audit_sink_is_skip_outside_production(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)
        _, data = _run_doctor([], capsys, monkeypatch)
        checks = {c["name"]: c for c in data["checks"]}
        assert "audit-sink-reachability" in checks
        assert checks["audit-sink-reachability"]["level"] == "SKIP"

    def test_production_audit_sink_error_causes_exit_1(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        exit_code, _ = _run_doctor([], capsys, monkeypatch)
        assert exit_code == 1

    def test_audit_sink_check_has_hint(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        _, data = _run_doctor([], capsys, monkeypatch)
        checks = {c["name"]: c for c in data["checks"]}
        # ERROR-level checks must carry a remediation hint.
        assert checks["audit-sink-reachability"].get("hint")


# ══════════════════════════════════════════════════════════════════════════════
# Gap 3 — StringEnumField auto-coercion via Policy.string_enum_coercions()
# ══════════════════════════════════════════════════════════════════════════════

# ── Shared policy fixture ─────────────────────────────────────────────────────

_status_enum = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])
_tier_enum = StringEnumField("risk_tier", ["LOW", "MEDIUM", "HIGH"])


class _StatusPolicy(Policy):
    """Policy with a single StringEnumField ('status') — only CLEAR is allowed."""

    status = _status_enum.field

    @classmethod
    def invariants(cls):
        return [
            _status_enum.is_allowed_constraint(cls.status, ["CLEAR"]),
            _status_enum.valid_values_constraint(cls.status),
        ]

    @classmethod
    def string_enum_coercions(cls):
        return {"status": _status_enum}


class _MultiEnumPolicy(Policy):
    """Policy with two StringEnumFields: status and risk_tier."""

    status = _status_enum.field
    risk_tier = _tier_enum.field

    @classmethod
    def invariants(cls):
        return [
            _status_enum.is_allowed_constraint(cls.status, ["CLEAR"]),
            _status_enum.valid_values_constraint(cls.status),
            _tier_enum.is_allowed_constraint(cls.risk_tier, ["LOW", "MEDIUM"]),
            _tier_enum.valid_values_constraint(cls.risk_tier),
        ]

    @classmethod
    def string_enum_coercions(cls):
        return {"status": _status_enum, "risk_tier": _tier_enum}


class _NoCoercionsIntPolicy(Policy):
    """Policy with an Int field but NO string_enum_coercions() override."""

    status = _status_enum.field

    @classmethod
    def invariants(cls):
        return [
            _status_enum.is_allowed_constraint(cls.status, ["CLEAR"]),
            _status_enum.valid_values_constraint(cls.status),
        ]


def _make_guard(policy_cls: type) -> Guard:
    return Guard(policy_cls, GuardConfig(execution_mode="sync"))


class TestStringEnumAutoCoercion:
    """Guard.verify() transparently encodes string enum values when
    Policy.string_enum_coercions() is declared."""

    def test_string_value_auto_encoded_to_allow(self) -> None:
        guard = _make_guard(_StatusPolicy)
        d = guard.verify(intent={}, state={"status": "CLEAR"})
        assert d.allowed is True

    def test_string_value_blocked_when_not_allowed(self) -> None:
        guard = _make_guard(_StatusPolicy)
        d = guard.verify(intent={}, state={"status": "PENDING"})
        assert d.allowed is False

    def test_pre_encoded_int_still_works(self) -> None:
        guard = _make_guard(_StatusPolicy)
        # Callers who still encode manually must not break.
        d = guard.verify(intent={}, state={"status": _status_enum.encode("CLEAR")})
        assert d.allowed is True

    def test_invalid_string_value_returns_error_not_crash(self) -> None:
        from pramanix.decision import SolverStatus

        guard = _make_guard(_StatusPolicy)
        d = guard.verify(intent={}, state={"status": "NONEXISTENT"})
        assert d.allowed is False
        assert d.status == SolverStatus.ERROR
        assert "NONEXISTENT" in d.explanation or "coercion" in d.explanation.lower()

    def test_multi_enum_policy_both_fields_auto_encoded(self) -> None:
        guard = _make_guard(_MultiEnumPolicy)
        d = guard.verify(intent={}, state={"status": "CLEAR", "risk_tier": "LOW"})
        assert d.allowed is True

    def test_multi_enum_policy_one_blocked_value(self) -> None:
        guard = _make_guard(_MultiEnumPolicy)
        d = guard.verify(intent={}, state={"status": "CLEAR", "risk_tier": "HIGH"})
        assert d.allowed is False

    def test_multi_enum_policy_both_blocked(self) -> None:
        guard = _make_guard(_MultiEnumPolicy)
        d = guard.verify(intent={}, state={"status": "BLOCKED", "risk_tier": "HIGH"})
        assert d.allowed is False

    def test_string_in_intent_dict_auto_encoded(self) -> None:
        """Coercion applies to intent_values as well as state_values."""
        _intent_enum = StringEnumField("action", ["transfer", "query", "cancel"])
        _amount = Field("amount", Decimal, "Real")

        class _IntentEnumPolicy(Policy):
            action = _intent_enum.field
            amount = _amount

            @classmethod
            def invariants(cls):
                return [
                    _intent_enum.is_allowed_constraint(cls.action, ["transfer", "query"]),
                    _intent_enum.valid_values_constraint(cls.action),
                    (E(_amount) > 0).named("positive_amount"),
                ]

            @classmethod
            def string_enum_coercions(cls):
                return {"action": _intent_enum}

        guard = _make_guard(_IntentEnumPolicy)
        d = guard.verify(intent={"action": "transfer", "amount": Decimal("1")}, state={})
        assert d.allowed is True

    def test_mixed_intent_state_coercion(self) -> None:
        """Enum field in intent, non-enum field in state — both handled correctly."""
        _action_enum = StringEnumField("action", ["buy", "sell"])
        _amt = Field("amount", Decimal, "Real")

        class _MixedPolicy(Policy):
            action = _action_enum.field
            amount = _amt

            @classmethod
            def invariants(cls):
                return [
                    _action_enum.is_allowed_constraint(cls.action, ["buy"]),
                    _action_enum.valid_values_constraint(cls.action),
                    (E(_amt) > 0).named("pos_amount"),
                ]

            @classmethod
            def string_enum_coercions(cls):
                return {"action": _action_enum}

        guard = _make_guard(_MixedPolicy)
        d = guard.verify(intent={"action": "buy", "amount": Decimal("100")}, state={})
        assert d.allowed is True


class TestStringEnumIntFieldGuard:
    """When no coercions are registered, Guard must return Decision.error()
    with a clear message instead of letting Z3 crash on a type mismatch."""

    def test_string_in_int_field_without_coercions_returns_error(self) -> None:
        from pramanix.decision import SolverStatus

        guard = _make_guard(_NoCoercionsIntPolicy)
        d = guard.verify(intent={}, state={"status": "CLEAR"})
        assert d.allowed is False
        assert d.status == SolverStatus.ERROR

    def test_error_message_names_the_field(self) -> None:
        guard = _make_guard(_NoCoercionsIntPolicy)
        d = guard.verify(intent={}, state={"status": "CLEAR"})
        assert "status" in d.explanation

    def test_error_message_suggests_remedy(self) -> None:
        guard = _make_guard(_NoCoercionsIntPolicy)
        d = guard.verify(intent={}, state={"status": "CLEAR"})
        assert (
            "encode" in d.explanation.lower()
            or "StringEnumField" in d.explanation
            or "coercion" in d.explanation.lower()
        )

    def test_int_value_in_int_field_still_passes_through(self) -> None:
        guard = _make_guard(_NoCoercionsIntPolicy)
        d = guard.verify(intent={}, state={"status": _status_enum.encode("CLEAR")})
        assert d.allowed is True

    def test_non_int_policy_fields_not_affected(self) -> None:
        """Real-typed fields (Decimal) receiving Decimal values must be unaffected."""
        _amt = Field("amount", Decimal, "Real")

        class _RealPolicy(Policy):
            amount = _amt

            @classmethod
            def invariants(cls):
                return [(E(_amt) > 0).named("positive")]

        guard = _make_guard(_RealPolicy)
        d = guard.verify(intent={"amount": Decimal("5")}, state={})
        assert d.allowed is True


class TestPolicyStringEnumCoercionsDefault:
    """Policy.string_enum_coercions() returns {} by default — no overhead
    when the feature is not used."""

    def test_default_returns_empty_dict(self) -> None:
        _f = Field("x", int, "Int")

        class _Plain(Policy):
            x = _f

            @classmethod
            def invariants(cls):
                return [(E(_f) > 0).named("pos")]

        assert _Plain.string_enum_coercions() == {}

    def test_guard_caches_coercions_at_construction(self) -> None:
        guard = _make_guard(_StatusPolicy)
        assert "status" in guard._string_enum_coercions

    def test_guard_int_field_names_contains_enum_fields(self) -> None:
        guard = _make_guard(_StatusPolicy)
        assert "status" in guard._int_field_names

    def test_guard_int_field_names_excludes_real_fields(self) -> None:
        _amt = Field("amount", Decimal, "Real")
        _st = _status_enum.field

        class _MixedFieldsPolicy(Policy):
            class Meta:
                version = "1.0"

            status = _st
            amount = _amt

            @classmethod
            def invariants(cls):
                return [
                    _status_enum.is_allowed_constraint(cls.status, ["CLEAR"]),
                    _status_enum.valid_values_constraint(cls.status),
                    (E(_amt) > 0).named("pos"),
                ]

            @classmethod
            def string_enum_coercions(cls):
                return {"status": _status_enum}

        guard = _make_guard(_MixedFieldsPolicy)
        assert "status" in guard._int_field_names
        assert "amount" not in guard._int_field_names
