# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for information-flow control (pramanix.ifc).

All tests use real objects — no mocks, no monkeypatching of Pramanix internals.
"""
from __future__ import annotations

import pytest

from pramanix.exceptions import FlowViolationError
from pramanix.ifc import (
    ClassifiedData,
    FlowDecision,
    FlowEnforcer,
    FlowPolicy,
    FlowRule,
    TrustLabel,
)


# ── TrustLabel tests ──────────────────────────────────────────────────────────


class TestTrustLabel:
    def test_ordering(self):
        assert TrustLabel.PUBLIC < TrustLabel.INTERNAL
        assert TrustLabel.INTERNAL < TrustLabel.CUSTOMER
        assert TrustLabel.CUSTOMER < TrustLabel.CONFIDENTIAL
        assert TrustLabel.CONFIDENTIAL < TrustLabel.REGULATED
        assert TrustLabel.REGULATED < TrustLabel.UNTRUSTED

    def test_requires_audit(self):
        assert not TrustLabel.CONFIDENTIAL.requires_audit()
        assert TrustLabel.REGULATED.requires_audit()
        assert TrustLabel.UNTRUSTED.requires_audit()

    def test_requires_authorization(self):
        assert not TrustLabel.CUSTOMER.requires_authorization()
        assert TrustLabel.CONFIDENTIAL.requires_authorization()
        assert TrustLabel.REGULATED.requires_authorization()

    def test_is_tenant_scoped(self):
        assert not TrustLabel.INTERNAL.is_tenant_scoped()
        assert TrustLabel.CUSTOMER.is_tenant_scoped()
        assert TrustLabel.CONFIDENTIAL.is_tenant_scoped()

    def test_all_values_are_distinct(self):
        values = [label.value for label in TrustLabel]
        assert len(values) == len(set(values))

    def test_names(self):
        assert TrustLabel(0).name == "PUBLIC"
        assert TrustLabel(5).name == "UNTRUSTED"


# ── ClassifiedData tests ──────────────────────────────────────────────────────


class TestClassifiedData:
    def _make(self, label: TrustLabel = TrustLabel.INTERNAL) -> ClassifiedData:
        return ClassifiedData(
            data="transfer $500",
            label=label,
            source="user_input",
        )

    def test_frozen(self):
        cd = self._make()
        with pytest.raises((AttributeError, TypeError)):
            cd.data = "modified"  # type: ignore[misc]

    def test_lineage_starts_empty(self):
        cd = self._make()
        assert cd.lineage == ()

    def test_taint_extends_lineage(self):
        cd = self._make()
        cd2 = cd.taint("llm_extractor")
        assert "llm_extractor" in cd2.lineage

    def test_taint_preserves_label(self):
        cd = self._make(TrustLabel.CUSTOMER)
        cd2 = cd.taint("component")
        assert cd2.label == TrustLabel.CUSTOMER

    def test_downgrade_valid(self):
        cd = self._make(TrustLabel.CONFIDENTIAL)
        downgraded = cd.downgrade(TrustLabel.INTERNAL, redactor=lambda d: "[redacted]")
        assert downgraded.label == TrustLabel.INTERNAL
        assert downgraded.data == "[redacted]"

    def test_downgrade_invalid_raises(self):
        cd = self._make(TrustLabel.INTERNAL)
        with pytest.raises(ValueError, match="downgrade"):
            cd.downgrade(TrustLabel.CONFIDENTIAL, redactor=lambda d: d)

    def test_downgrade_same_label_raises(self):
        cd = self._make(TrustLabel.INTERNAL)
        with pytest.raises(ValueError):
            cd.downgrade(TrustLabel.INTERNAL, redactor=lambda d: d)

    def test_upgrade_valid(self):
        cd = self._make(TrustLabel.INTERNAL)
        upgraded = cd.upgrade(TrustLabel.CONFIDENTIAL, reason="contains PII")
        assert upgraded.label == TrustLabel.CONFIDENTIAL
        assert upgraded.data == cd.data  # data payload unchanged

    def test_upgrade_invalid_raises(self):
        cd = self._make(TrustLabel.CONFIDENTIAL)
        with pytest.raises(ValueError, match="upgrade"):
            cd.upgrade(TrustLabel.INTERNAL, reason="downgrade attempt")

    def test_to_audit_dict_excludes_data(self):
        cd = self._make()
        audit = cd.to_audit_dict()
        assert "data" not in audit
        assert "label" in audit
        assert "source" in audit
        assert "lineage" in audit

    def test_created_at_set(self):
        import time
        t0 = time.time()
        cd = self._make()
        assert cd.created_at >= t0


# ── FlowPolicy and FlowRule tests ─────────────────────────────────────────────


class TestFlowPolicy:
    def test_permissive_allows_everything(self):
        policy = FlowPolicy.permissive()
        decision = policy.evaluate(
            TrustLabel.REGULATED, TrustLabel.PUBLIC, "src", "sink"
        )
        assert decision.permitted

    def test_strict_allows_same_label(self):
        policy = FlowPolicy.strict()
        decision = policy.evaluate(
            TrustLabel.INTERNAL, TrustLabel.INTERNAL, "src", "sink"
        )
        assert decision.permitted

    def test_strict_blocks_lower_sink(self):
        policy = FlowPolicy.strict()
        decision = policy.evaluate(
            TrustLabel.CONFIDENTIAL, TrustLabel.PUBLIC, "src", "sink"
        )
        assert not decision.permitted

    def test_regulated_preset_exists(self):
        policy = FlowPolicy.regulated()
        assert policy is not None

    def test_custom_rule_first_match_wins(self):
        # Custom rule: allow CONFIDENTIAL → INTERNAL with redaction.
        # Default deny would block it; explicit rule overrides.
        rule = FlowRule(
            source_label=TrustLabel.CONFIDENTIAL,
            sink_label=TrustLabel.INTERNAL,
            permitted=True,
            requires_redaction=True,
            reason="Redacted confidential to internal",
        )
        policy = FlowPolicy(rules=[rule], default_deny=True)
        decision = policy.evaluate(
            TrustLabel.CONFIDENTIAL, TrustLabel.INTERNAL, None, None
        )
        assert decision.permitted
        assert decision.requires_redaction

    def test_default_deny_blocks_unmatched(self):
        policy = FlowPolicy(rules=[], default_deny=True)
        decision = policy.evaluate(
            TrustLabel.PUBLIC, TrustLabel.INTERNAL, None, None
        )
        assert not decision.permitted

    def test_component_match_narrows_rule(self):
        rule = FlowRule(
            source_label=TrustLabel.INTERNAL,
            sink_label=TrustLabel.INTERNAL,
            source_component="llm",
            permitted=True,
        )
        policy = FlowPolicy(rules=[rule], default_deny=True)
        # Matches component
        d1 = policy.evaluate(TrustLabel.INTERNAL, TrustLabel.INTERNAL, "llm", "db")
        assert d1.permitted
        # Component mismatch — falls through to default deny
        d2 = policy.evaluate(TrustLabel.INTERNAL, TrustLabel.INTERNAL, "other", "db")
        assert not d2.permitted


class TestFlowDecision:
    def test_default_values(self):
        d = FlowDecision(permitted=True)
        assert d.requires_redaction is False
        assert d.matched_rule is None
        assert d.reason == ""


# ── FlowEnforcer tests ────────────────────────────────────────────────────────


class TestFlowEnforcer:
    def _data(
        self,
        label: TrustLabel = TrustLabel.INTERNAL,
        source: str = "agent",
    ) -> ClassifiedData:
        return ClassifiedData(data="some payload", label=label, source=source)

    def test_gate_allowed_returns_data(self):
        enforcer = FlowEnforcer(FlowPolicy.permissive())
        data = self._data(TrustLabel.INTERNAL)
        result = enforcer.gate(data, sink_label=TrustLabel.INTERNAL, sink_component="db")
        assert result.data == data.data

    def test_gate_blocked_raises(self):
        enforcer = FlowEnforcer(FlowPolicy.strict())
        data = self._data(TrustLabel.CONFIDENTIAL)
        with pytest.raises(FlowViolationError):
            enforcer.gate(
                data, sink_label=TrustLabel.PUBLIC, sink_component="log"
            )

    def test_gate_applies_redaction(self):
        rule = FlowRule(
            source_label=TrustLabel.CONFIDENTIAL,
            sink_label=TrustLabel.INTERNAL,
            permitted=True,
            requires_redaction=True,
        )
        enforcer = FlowEnforcer(
            FlowPolicy(rules=[rule], default_deny=True),
        )
        data = ClassifiedData(
            data="secret-value", label=TrustLabel.CONFIDENTIAL, source="src"
        )
        result = enforcer.gate(
            data,
            sink_label=TrustLabel.INTERNAL,
            sink_component="out",
            redactor=lambda d: "[REDACTED]",
        )
        assert result.data == "[REDACTED]"

    def test_gate_no_redactor_raises_when_required(self):
        rule = FlowRule(
            source_label=TrustLabel.CONFIDENTIAL,
            sink_label=TrustLabel.INTERNAL,
            permitted=True,
            requires_redaction=True,
        )
        enforcer = FlowEnforcer(FlowPolicy(rules=[rule], default_deny=True))
        data = ClassifiedData(
            data="secret", label=TrustLabel.CONFIDENTIAL, source="src"
        )
        with pytest.raises((FlowViolationError, ValueError)):
            enforcer.gate(
                data,
                sink_label=TrustLabel.INTERNAL,
                sink_component="out",
                redactor=None,
            )

    def test_check_non_raising(self):
        enforcer = FlowEnforcer(FlowPolicy.strict())
        data = self._data(TrustLabel.INTERNAL)
        assert enforcer.check(data, sink_label=TrustLabel.INTERNAL, sink_component="x") is True
        assert enforcer.check(data, sink_label=TrustLabel.PUBLIC, sink_component="x") is False

    def test_audit_log_populated(self):
        enforcer = FlowEnforcer(FlowPolicy.permissive())
        data = self._data()
        enforcer.gate(data, sink_label=TrustLabel.PUBLIC, sink_component="out")
        log = enforcer.audit_log()
        assert len(log) == 1
        entry = log[0]
        assert "permitted" in entry

    def test_audit_log_is_copy(self):
        enforcer = FlowEnforcer(FlowPolicy.permissive())
        data = self._data()
        enforcer.gate(data, sink_label=TrustLabel.PUBLIC, sink_component="out")
        log1 = enforcer.audit_log()
        log2 = enforcer.audit_log()
        assert log1 is not log2

    def test_clear_audit_log(self):
        enforcer = FlowEnforcer(FlowPolicy.permissive())
        data = self._data()
        enforcer.gate(data, sink_label=TrustLabel.PUBLIC, sink_component="out")
        enforcer.clear_audit_log()
        assert enforcer.audit_log() == []

    def test_violation_error_attributes(self):
        enforcer = FlowEnforcer(FlowPolicy.strict())
        data = self._data(TrustLabel.REGULATED)
        with pytest.raises(FlowViolationError) as exc_info:
            enforcer.gate(
                data, sink_label=TrustLabel.PUBLIC, sink_component="public_api"
            )
        err = exc_info.value
        assert err.source_label == TrustLabel.REGULATED
        assert err.sink_label == TrustLabel.PUBLIC
        assert err.sink_component == "public_api"

    def test_blocked_decision_recorded_in_audit_log(self):
        enforcer = FlowEnforcer(FlowPolicy.strict())
        data = self._data(TrustLabel.CONFIDENTIAL)
        with pytest.raises(FlowViolationError):
            enforcer.gate(
                data, sink_label=TrustLabel.PUBLIC, sink_component="out"
            )
        log = enforcer.audit_log()
        assert any(not e["permitted"] for e in log)

    def test_audit_sink_called_on_gate(self):
        calls: list[tuple] = []
        enforcer = FlowEnforcer(
            FlowPolicy.permissive(),
            audit_sink=lambda data, sink, permitted: calls.append((data, sink, permitted)),
        )
        data = self._data()
        enforcer.gate(data, sink_label=TrustLabel.PUBLIC, sink_component="out")
        assert len(calls) == 1
        assert calls[0][1] == "out"
