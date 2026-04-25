# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for ComplianceReporter (Phase 11.4)."""
from __future__ import annotations

import json
from decimal import Decimal

import pytest

from pramanix.decision import Decision
from pramanix.helpers.compliance import ComplianceReport, ComplianceReporter


def _block(
    violated: tuple,
    explanation: str = "blocked",
    amount: str = "100",
) -> Decision:
    return Decision.unsafe(
        violated_invariants=violated,
        explanation=explanation,
        intent_dump={"amount": amount},
        state_dump={"state_version": "v1"},
        metadata={"policy": "TestPolicy", "policy_version": "1.0"},
    )


def _allow() -> Decision:
    return Decision.safe(
        intent_dump={"amount": "100"},
        state_dump={"state_version": "v1"},
        metadata={"policy": "TestPolicy", "policy_version": "1.0"},
    )


# ── Report generation ─────────────────────────────────────────────────────────


class TestComplianceReportGeneration:
    def test_generates_report_for_blocked_decision(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), "Balance insufficient")
        report = reporter.generate(d)
        assert isinstance(report, ComplianceReport)
        assert report.verdict == "BLOCKED"

    def test_generates_report_for_allowed_decision(self):
        reporter = ComplianceReporter()
        d = _allow()
        report = reporter.generate(d)
        assert report.verdict == "ALLOWED"

    def test_decision_id_preserved(self):
        reporter = ComplianceReporter()
        d = _block(("rule_x",))
        report = reporter.generate(d)
        assert report.decision_id == d.decision_id

    def test_decision_hash_preserved(self):
        reporter = ComplianceReporter()
        d = _block(("rule_x",))
        report = reporter.generate(d)
        assert report.decision_hash == d.decision_hash

    def test_violated_rules_preserved(self):
        reporter = ComplianceReporter()
        d = _block(("rule_a", "rule_b"))
        report = reporter.generate(d)
        assert "rule_a" in report.violated_rules
        assert "rule_b" in report.violated_rules

    def test_explanation_in_rationale(self):
        reporter = ComplianceReporter()
        d = _block(("overdraft",), explanation="Balance 100 insufficient for 500")
        report = reporter.generate(d)
        assert "Balance 100 insufficient" in "\n".join(report.compliance_rationale)


# ── Regulatory references ─────────────────────────────────────────────────────


class TestRegulatoryReferences:
    def test_sufficient_balance_has_basel_ref(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "Basel" in refs_str or "BCBS" in refs_str

    def test_anti_structuring_has_bsa_ref(self):
        reporter = ComplianceReporter()
        d = _block(("anti_structuring",), "Structuring detected")
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "BSA" in refs_str or "CFR" in refs_str

    def test_wash_sale_has_irc_ref(self):
        reporter = ComplianceReporter()
        d = _block(("wash_sale_detection",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "IRC" in refs_str or "1091" in refs_str

    def test_sanctions_has_ofac_ref(self):
        reporter = ComplianceReporter()
        d = _block(("sanctions_screen",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "OFAC" in refs_str or "SDN" in refs_str

    def test_phi_access_has_hipaa_ref(self):
        reporter = ComplianceReporter()
        d = _block(("patient_consent_required",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "HIPAA" in refs_str or "CFR" in refs_str

    def test_unknown_rule_gets_internal_policy_ref(self):
        reporter = ComplianceReporter()
        d = _block(("my_custom_rule_xyz",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "Internal policy" in refs_str or "my_custom_rule_xyz" in refs_str

    def test_custom_rule_registration(self):
        reporter = ComplianceReporter()
        reporter.register_rule("my_rule", ["Company Policy §7.3.2"])
        d = _block(("my_rule",))
        report = reporter.generate(d)
        assert "Company Policy §7.3.2" in report.regulatory_refs

    def test_refs_are_deduplicated(self):
        """Same ref appearing for two rules must only appear once."""
        reporter = ComplianceReporter()
        d = _block(("velocity_check", "within_daily_limit"))
        report = reporter.generate(d)
        assert len(report.regulatory_refs) == len(set(report.regulatory_refs))


# ── Severity classification ───────────────────────────────────────────────────


class TestSeverityClassification:
    def test_high_value_amount_is_critical_prevention(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), amount="500000")
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_sanctions_violation_is_critical_prevention(self):
        reporter = ComplianceReporter()
        d = _block(("sanctions_screen",))
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_phi_violation_is_critical_prevention(self):
        reporter = ComplianceReporter()
        d = _block(("patient_consent_required",))
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_balance_violation_normal_amount_is_high(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), amount="100")
        report = reporter.generate(d)
        assert report.severity in ("HIGH", "CRITICAL_PREVENTION")

    def test_infra_violation_is_medium(self):
        reporter = ComplianceReporter()
        d = _block(("blast_radius_check",))
        report = reporter.generate(d)
        assert report.severity == "MEDIUM"


# ── Serialization ─────────────────────────────────────────────────────────────


class TestComplianceReportSerialization:
    def test_to_json_produces_valid_json(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), "Insufficient balance")
        report = reporter.generate(d)
        parsed = json.loads(report.to_json())
        assert "decision_id" in parsed
        assert "verdict" in parsed
        assert "regulatory_refs" in parsed

    def test_to_json_contains_all_required_fields(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        parsed = json.loads(report.to_json())
        required = [
            "decision_id", "decision_hash", "verdict", "severity",
            "policy_name", "policy_version", "violated_rules",
            "compliance_rationale", "regulatory_refs", "explanation",
        ]
        for f in required:
            assert f in parsed, f"Missing field: {f}"

    def test_to_pdf_returns_bytes(self):
        pytest.importorskip("fpdf", reason="fpdf2 not installed; pip install 'pramanix[pdf]'")
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        pdf = report.to_pdf()
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b"%PDF", "to_pdf() must return a valid PDF binary"

    def test_to_pdf_raises_without_fpdf2(self, monkeypatch):
        """to_pdf() raises ImportError with a helpful message when fpdf2 is absent."""
        import builtins
        real_import = builtins.__import__

        def _block_fpdf(name, *args, **kwargs):  # type: ignore[no-untyped-def]
            if name == "fpdf":
                raise ModuleNotFoundError("No module named 'fpdf'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_fpdf)
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        with pytest.raises(ImportError, match="fpdf2"):
            report.to_pdf()

    def test_report_is_frozen(self):
        reporter = ComplianceReporter()
        d = _block(("rule_x",))
        report = reporter.generate(d)
        with pytest.raises((AttributeError, TypeError)):
            report.verdict = "HACKED"  # type: ignore[misc]


# ── End-to-end via Guard ──────────────────────────────────────────────────────


class TestComplianceReporterEndToEnd:
    def test_via_guard_banking_block(self):
        """End-to-end: real Guard → real Decision → ComplianceReport."""
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _BankingPolicy(Policy):
            class Meta:
                version = "1.0"
                name = "BankingPolicy"

            @classmethod
            def fields(cls):
                return {"amount": _amount, "balance": _balance}

            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sufficient_balance")
                    .explain(
                        "Transfer of {amount} blocked: balance {balance} insufficient"
                    )
                ]

        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        decision = guard.verify(
            intent={"amount": Decimal("5000")},
            state={"balance": Decimal("100"), "state_version": "1.0"},
        )
        assert not decision.allowed

        reporter = ComplianceReporter()
        report = reporter.generate(
            decision,
            policy_meta={"name": "BankingPolicy", "version": "1.0"},
        )

        assert report.verdict == "BLOCKED"
        assert "sufficient_balance" in report.violated_rules
        refs_str = " ".join(report.regulatory_refs)
        assert "Basel" in refs_str or "BCBS" in refs_str
        assert "insufficient" in report.explanation.lower() or \
               "blocked" in report.explanation.lower()
