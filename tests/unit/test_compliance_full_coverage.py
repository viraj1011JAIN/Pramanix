# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Full coverage for helpers/compliance.py.

Uses a proper fake fpdf2 module (NOT a mock) that implements the real FPDF
interface with in-memory recording.  This covers:
  - ComplianceReport.to_pdf() body (lines 189-258)
  - ComplianceReporter.__init__ extra_refs (line 279)
  - _classify_severity() all branches
  - All conditional sections in to_pdf()
"""
from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from pramanix.decision import Decision
from pramanix.helpers.compliance import (
    ComplianceReport,
    ComplianceReporter,
    _classify_severity,
)

# ── Proper fake fpdf2 module (NOT a mock) ─────────────────────────────────────


class _FakePDF:
    """In-memory FPDF implementation that records all operations.

    Implements every method called by ComplianceReport.to_pdf() so the
    method executes real code paths without requiring fpdf2 to be installed.
    """

    def __init__(self) -> None:
        self.l_margin: float = 10.0
        self.r_margin: float = 10.0
        self.w: float = 210.0
        self._y: float = 10.0
        self._text_buffer: list[str] = []

    def set_auto_page_break(self, auto: bool = True, margin: float = 15.0) -> None:
        pass

    def add_page(self) -> None:
        pass

    def set_font(self, family: str, style: str = "", size: int = 10) -> None:
        pass

    def set_fill_color(self, r: int, g: int, b: int) -> None:
        pass

    def set_line_width(self, width: float) -> None:
        pass

    def get_y(self) -> float:
        return self._y

    def line(self, x1: float, y1: float, x2: float, y2: float) -> None:
        pass

    def ln(self, h: float = 10.0) -> None:
        self._y += h

    def cell(
        self,
        w: float,
        h: float = 10.0,
        text: str = "",
        new_x: str = "RIGHT",
        new_y: str = "LAST",
        fill: bool = False,
        align: str = "L",
    ) -> None:
        if text:
            self._text_buffer.append(text)

    def multi_cell(
        self,
        w: float,
        h: float,
        text: str = "",
        new_x: str = "LMARGIN",
        new_y: str = "NEXT",
    ) -> None:
        if text:
            self._text_buffer.append(text)

    def output(self) -> bytearray:
        return bytearray(b"%PDF-1.4 (fake pramanix pdf)")


class _FakeFPDFModule:
    """Drop-in replacement for the ``fpdf`` package."""

    FPDF = _FakePDF


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def fake_fpdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject fake fpdf2 into sys.modules for the duration of the test."""
    monkeypatch.setitem(sys.modules, "fpdf", _FakeFPDFModule())  # type: ignore[arg-type]


def _block(
    violated: tuple[str, ...],
    explanation: str = "blocked",
    amount: str = "100",
    extra_meta: dict[str, Any] | None = None,
) -> Decision:
    meta: dict[str, Any] = {"policy": "TestPolicy", "policy_version": "1.0"}
    if extra_meta:
        meta.update(extra_meta)
    return Decision.unsafe(
        violated_invariants=violated,
        explanation=explanation,
        intent_dump={"amount": amount},
        state_dump={"state_version": "v1"},
        metadata=meta,
    )


def _allow(amount: str = "100") -> Decision:
    return Decision.safe(
        intent_dump={"amount": amount},
        state_dump={"state_version": "v1"},
        metadata={"policy": "TestPolicy", "policy_version": "1.0"},
    )


# ── _classify_severity() ──────────────────────────────────────────────────────


class TestClassifySeverity:
    def test_high_value_amount_triggers_critical_prevention(self) -> None:
        sev = _classify_severity(("sufficient_balance",), {"amount": "100001"})
        assert sev == "CRITICAL_PREVENTION"

    def test_amount_exactly_100k_triggers_critical(self) -> None:
        sev = _classify_severity(("other_rule",), {"amount": "100000"})
        assert sev == "CRITICAL_PREVENTION"

    def test_high_value_rule_triggers_critical(self) -> None:
        sev = _classify_severity(("sanctions_screen",), {"amount": "10"})
        assert sev == "CRITICAL_PREVENTION"

    def test_anti_structuring_triggers_critical(self) -> None:
        sev = _classify_severity(("anti_structuring",), {"amount": "50"})
        assert sev == "CRITICAL_PREVENTION"

    def test_wash_sale_triggers_critical(self) -> None:
        sev = _classify_severity(("wash_sale_detection",), {"amount": "1"})
        assert sev == "CRITICAL_PREVENTION"

    def test_phi_rule_triggers_critical(self) -> None:
        sev = _classify_severity(("phi_least_privilege",), {"amount": "0"})
        assert sev == "CRITICAL_PREVENTION"

    def test_pediatric_dose_triggers_critical(self) -> None:
        sev = _classify_severity(("pediatric_dose_bound",), {"amount": "0"})
        assert sev == "CRITICAL_PREVENTION"

    def test_infra_rule_triggers_medium(self) -> None:
        sev = _classify_severity(("blast_radius_check",), {"amount": "0"})
        assert sev == "MEDIUM"

    def test_circuit_breaker_triggers_medium(self) -> None:
        sev = _classify_severity(("circuit_breaker_state",), {"amount": "0"})
        assert sev == "MEDIUM"

    def test_cpu_memory_guard_triggers_medium(self) -> None:
        sev = _classify_severity(("cpu_memory_guard",), {"amount": "0"})
        assert sev == "MEDIUM"

    def test_default_rule_returns_high(self) -> None:
        sev = _classify_severity(("sufficient_balance",), {"amount": "50"})
        assert sev == "HIGH"

    def test_invalid_amount_falls_through_to_rule_check(self) -> None:
        sev = _classify_severity(("sufficient_balance",), {"amount": "not_a_number"})
        assert sev == "HIGH"

    def test_missing_amount_defaults_to_zero(self) -> None:
        sev = _classify_severity(("sufficient_balance",), {})
        assert sev == "HIGH"


# ── ComplianceReport.to_json() ────────────────────────────────────────────────


class TestComplianceReportToJson:
    def _make_report(self, violated: tuple[str, ...] = (), extra: str = "") -> ComplianceReport:
        return ComplianceReport(
            decision_id="dec-123",
            decision_hash="hash-abc",
            timestamp="2026-04-23T12:00:00",
            verdict="BLOCKED" if violated else "ALLOWED",
            severity="HIGH",
            policy_name="TestPolicy",
            policy_version="1.0",
            violated_rules=violated,
            compliance_rationale=("Reason 1",) if violated else (),
            regulatory_refs=("CFR § 1020",) if violated else (),
            explanation=extra or ("Blocked" if violated else "Allowed"),
        )

    def test_to_json_returns_string(self) -> None:
        r = self._make_report(("balance",))
        assert isinstance(r.to_json(), str)

    def test_to_json_is_valid_json(self) -> None:
        r = self._make_report(("balance",))
        parsed = json.loads(r.to_json())
        assert isinstance(parsed, dict)

    def test_to_json_contains_all_keys(self) -> None:
        r = self._make_report(("balance",))
        parsed = json.loads(r.to_json())
        expected = {
            "decision_id", "decision_hash", "timestamp", "verdict",
            "severity", "policy_name", "policy_version", "violated_rules",
            "compliance_rationale", "regulatory_refs", "explanation",
        }
        assert set(parsed.keys()) == expected

    def test_to_json_allowed_decision(self) -> None:
        r = self._make_report()
        parsed = json.loads(r.to_json())
        assert parsed["verdict"] == "ALLOWED"
        assert parsed["violated_rules"] == []

    def test_to_json_blocked_decision(self) -> None:
        r = self._make_report(("velocity_check",))
        parsed = json.loads(r.to_json())
        assert parsed["verdict"] == "BLOCKED"
        assert "velocity_check" in parsed["violated_rules"]


# ── ComplianceReport.to_pdf() — ImportError path ─────────────────────────────


class TestComplianceReportToPdfImportError:
    def test_to_pdf_raises_import_error_without_fpdf2(self) -> None:
        """to_pdf() raises ImportError with install hint when fpdf2 absent."""
        r = ComplianceReport(
            decision_id="d",
            decision_hash="h",
            timestamp="2026-04-23",
            verdict="BLOCKED",
            severity="HIGH",
            policy_name="P",
            policy_version="1.0",
            violated_rules=("r",),
            compliance_rationale=("rationale",),
            regulatory_refs=("ref",),
            explanation="blocked",
        )
        with pytest.raises(ImportError, match="fpdf2"):
            r.to_pdf()


# ── ComplianceReport.to_pdf() — full generation (fake fpdf2) ─────────────────


@pytest.mark.usefixtures("fake_fpdf")
class TestComplianceReportToPdfGeneration:
    def _report(
        self,
        violated: tuple[str, ...] = (),
        rationale: tuple[str, ...] = (),
        refs: tuple[str, ...] = (),
        explanation: str = "",
    ) -> ComplianceReport:
        return ComplianceReport(
            decision_id="dec-456",
            decision_hash="hash-def",
            timestamp="2026-04-23T00:00:00",
            verdict="BLOCKED" if violated else "ALLOWED",
            severity="HIGH",
            policy_name="BankingPolicy",
            policy_version="1.0",
            violated_rules=violated,
            compliance_rationale=rationale,
            regulatory_refs=refs,
            explanation=explanation,
        )

    def test_to_pdf_returns_bytes(self) -> None:
        r = self._report(("balance",), ("Reason",), ("CFR",), "Blocked")
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_with_violated_rules_section(self) -> None:
        r = self._report(violated=("velocity_check", "anti_structuring"))
        result = r.to_pdf()
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_to_pdf_without_violated_rules(self) -> None:
        r = self._report()
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_with_compliance_rationale(self) -> None:
        r = self._report(rationale=("Per Basel III",), violated=("balance",))
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_without_compliance_rationale(self) -> None:
        r = self._report(violated=("balance",))
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_with_regulatory_refs(self) -> None:
        r = self._report(refs=("31 CFR § 1020",), violated=("balance",))
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_without_regulatory_refs(self) -> None:
        r = self._report(violated=("balance",))
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_with_explanation(self) -> None:
        r = self._report(explanation="The balance was insufficient for the requested amount.")
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_without_explanation(self) -> None:
        r = self._report()
        result = r.to_pdf()
        assert isinstance(result, bytes)

    def test_to_pdf_all_sections_populated(self) -> None:
        r = self._report(
            violated=("sanctions_screen", "kyc_status"),
            rationale=("Sanction list match", "KYC incomplete"),
            refs=("OFAC: 31 CFR § 598", "BSA: 31 CFR § 1020.220"),
            explanation="Transaction blocked: OFAC sanctions match detected.",
        )
        result = r.to_pdf()
        assert isinstance(result, bytes)
        assert b"%PDF" in result


# ── ComplianceReporter ────────────────────────────────────────────────────────


class TestComplianceReporter:
    def test_init_with_no_extra_refs(self) -> None:
        reporter = ComplianceReporter()
        assert "sufficient_balance" in reporter._refs

    def test_init_with_extra_refs_merges(self) -> None:
        """Line 279: extra_refs dict is merged into _refs."""
        extra = {"custom_rule": ["Internal Policy § 3.2"]}
        reporter = ComplianceReporter(extra_refs=extra)
        assert "custom_rule" in reporter._refs
        assert reporter._refs["custom_rule"] == ["Internal Policy § 3.2"]

    def test_extra_refs_do_not_affect_existing_mappings(self) -> None:
        extra = {"custom_rule": ["Custom Ref"]}
        reporter = ComplianceReporter(extra_refs=extra)
        assert "sufficient_balance" in reporter._refs

    def test_extra_refs_override_existing_key(self) -> None:
        extra = {"sufficient_balance": ["Overridden Reference"]}
        reporter = ComplianceReporter(extra_refs=extra)
        assert reporter._refs["sufficient_balance"] == ["Overridden Reference"]

    def test_generate_blocked_decision(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance", "velocity_check"))
        report = reporter.generate(d)
        assert report.verdict == "BLOCKED"
        assert "sufficient_balance" in report.violated_rules

    def test_generate_allowed_decision(self) -> None:
        reporter = ComplianceReporter()
        d = _allow()
        report = reporter.generate(d)
        assert report.verdict == "ALLOWED"
        assert report.violated_rules == ()

    def test_generate_attaches_regulatory_refs(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        assert any("Basel" in r for r in report.regulatory_refs)

    def test_generate_unknown_rule_has_internal_policy_ref(self) -> None:
        """Unknown invariants produce an 'Internal policy rule:' fallback ref."""
        reporter = ComplianceReporter()
        d = _block(("completely_unknown_invariant",))
        report = reporter.generate(d)
        assert len(report.regulatory_refs) == 1
        assert "Internal policy rule: completely_unknown_invariant" in report.regulatory_refs

    def test_generate_critical_prevention_severity_for_large_amount(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("balance",), amount="500000")
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_generate_medium_severity_for_infra_rule(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("blast_radius_check",))
        report = reporter.generate(d)
        assert report.severity == "MEDIUM"

    def test_generate_high_severity_default(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), amount="50")
        report = reporter.generate(d)
        assert report.severity == "HIGH"

    def test_generate_populates_decision_id(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("balance",))
        report = reporter.generate(d)
        assert report.decision_id == d.decision_id

    def test_generate_returns_compliance_report_type(self) -> None:
        reporter = ComplianceReporter()
        d = _allow()
        report = reporter.generate(d)
        assert isinstance(report, ComplianceReport)

    def test_generate_with_extra_refs_produces_custom_ref(self) -> None:
        extra = {"custom_rule": ["My Custom Regulation § 1"]}
        reporter = ComplianceReporter(extra_refs=extra)
        d = _block(("custom_rule",))
        report = reporter.generate(d)
        assert "My Custom Regulation § 1" in report.regulatory_refs

    def test_generate_to_json_round_trip(self) -> None:
        reporter = ComplianceReporter()
        d = _block(("velocity_check",))
        report = reporter.generate(d)
        payload = json.loads(report.to_json())
        assert payload["verdict"] == "BLOCKED"
        assert "velocity_check" in payload["violated_rules"]
