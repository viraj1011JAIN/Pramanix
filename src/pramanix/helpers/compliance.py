# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Compliance report generation for Pramanix Decision objects.

Maps Z3 unsat core labels (violated_invariants) to structured compliance
reports with regulatory citations. Used by banks, hospitals, and cloud
providers to generate audit-ready documentation from Pramanix decisions.

Supported regulatory frameworks:
- BSA/AML (31 CFR § 1020, § 1023, § 1025)
- OFAC/SDN (50 CFR § 598)
- SEC wash sale (IRC § 1091)
- HIPAA Privacy Rule (45 CFR § 164)
- SOX internal controls (15 U.S.C. § 7241)
- Basel III capital adequacy (BCBS 189)

Usage:
    from pramanix.helpers.compliance import ComplianceReporter

    reporter = ComplianceReporter()
    report = reporter.generate(
        decision=decision,
        policy_meta={"name": "BankingPolicy", "version": "1.0"},
    )
    print(report.to_json())
    # → {"decision_id": "...", "verdict": "BLOCKED", "severity": "HIGH",
    #    "compliance_rationale": [...], "regulatory_refs": [...]}
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision


# ── Regulatory reference database ─────────────────────────────────────────────

_REGULATORY_MAP: dict[str, list[str]] = {
    # FinTech / Banking
    "sufficient_balance":    ["Basel III: BCBS 189 §3.1 — Minimum liquidity coverage"],
    "non_negative_balance":  ["Basel III: BCBS 189 §3.1"],
    "velocity_check":        ["BSA/AML: 31 CFR § 1020.320 — Suspicious Activity Reports"],
    "anti_structuring":      ["BSA/AML: 31 CFR § 1020.320(a)(2) — Anti-structuring rule"],
    "wash_sale_detection":   ["IRC § 1091 — Wash sale disallowance rule (30-day window)"],
    "sanctions_screen":      ["OFAC: 31 CFR § 598 — Prohibition on transactions with SDN list"],
    "kyc_status":            ["BSA: 31 CFR § 1020.220 — Customer identification program"],
    "collateral_haircut":    ["Basel III: BCBS 189 — Collateral eligibility and haircuts"],
    "max_drawdown":          ["SEC: 17 CFR § 240.15c3-1 — Net capital requirements"],
    "risk_score_limit":      ["Basel II: BCBS 128 §III — Credit risk internal ratings"],
    "trading_window":        ["SEC: Regulation FD — Material non-public information"],
    "within_daily_limit":    ["BSA/AML: 31 CFR § 1020.320 — Transaction monitoring"],
    "single_tx_cap":         ["SOX: 15 U.S.C. § 7241 — Internal financial controls"],
    "acceptable_risk_score": ["Basel II: BCBS 128 §III — Pillar 2 supervisory review"],
    "positive_amount":       ["SOX: 15 U.S.C. § 7241(a)(4) — Data integrity controls"],
    "account_not_frozen":    ["BSA: 31 CFR § 1010.830 — Frozen accounts enforcement"],
    # Healthcare / HIPAA
    "authorized_role":           ["HIPAA: 45 CFR § 164.502(b) — Minimum necessary standard"],
    "phi_least_privilege":       ["HIPAA: 45 CFR § 164.514(d) — Limited data set requirements"],
    "patient_consent_required":  ["HIPAA: 45 CFR § 164.508 — Authorization requirements"],
    "consent_active":            ["HIPAA: 45 CFR § 164.508(c) — Valid authorization elements"],
    "department_match_required": ["HIPAA: 45 CFR § 164.502(b)(1) — Workforce access control"],
    "dosage_gradient_check":     ["FDA: 21 CFR § 211.68 — Drug dose computation controls"],
    "pediatric_dose_bound":      ["FDA: 21 CFR § 201.57 — Pediatric dosage maximum limits"],
    "break_glass_auth":          ["HIPAA: 45 CFR § 164.312(a)(2)(ii) — Emergency access"],
    "must_be_clinician":         ["HIPAA: 45 CFR § 164.502(b) — Minimum necessary access"],
    "consent_not_expired":       ["HIPAA: 45 CFR § 164.508(b)(5) — Revocation of authorization"],
    # Infrastructure / SRE
    "above_minimum":         ["SRE SLA: Minimum replica count for high availability"],
    "below_maximum":         ["FinOps: Maximum resource budget constraint"],
    "production_ha_minimum": ["SRE: Production HA requires ≥2 replicas"],
    "blast_radius_check":    ["SRE: Blast radius limit for safe deployment"],
    "circuit_breaker_state": ["SRE: Circuit breaker OPEN — downstream service protection"],
    "prod_gate_approval":    ["SOX: Change management approval workflow (ITGC)"],
    "replicas_budget":       ["FinOps: Compute budget constraint"],
    "cpu_memory_guard":      ["SRE: Resource quota enforcement"],
}


# ── Severity classification ────────────────────────────────────────────────────

def _classify_severity(
    violated_invariants: tuple[str, ...],
    intent_dump: dict[str, Any],
) -> str:
    """Classify decision severity based on violated rules and intent context.

    CRITICAL_PREVENTION: High-value financial or PHI access attempts
    HIGH:                Most policy violations in regulated domains
    MEDIUM:              Infrastructure and operational violations
    """
    high_value_rules = {
        "anti_structuring", "sanctions_screen", "wash_sale_detection",
        "patient_consent_required", "phi_least_privilege",
        "pediatric_dose_bound",
    }
    infra_rules = {
        "blast_radius_check", "circuit_breaker_state",
        "replicas_budget", "cpu_memory_guard",
    }

    amount_str = str(intent_dump.get("amount", "0"))
    try:
        amount = Decimal(amount_str)
        if amount >= Decimal("100000"):
            return "CRITICAL_PREVENTION"
    except Exception:
        pass

    violated_set = set(violated_invariants)
    if violated_set & high_value_rules:
        return "CRITICAL_PREVENTION"

    if violated_set & infra_rules:
        return "MEDIUM"

    return "HIGH"


# ── Report dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ComplianceReport:
    """Structured compliance report for a Pramanix Decision.

    Suitable for inclusion in:
    - Regulatory audit submissions (SEC, FDA, OCC)
    - Legal discovery responses
    - Internal compliance dashboards
    - SAR (Suspicious Activity Report) documentation
    """

    decision_id:          str
    decision_hash:        str
    timestamp:            str
    verdict:              str           # "ALLOWED" or "BLOCKED"
    severity:             str           # "CRITICAL_PREVENTION", "HIGH", "MEDIUM"
    policy_name:          str
    policy_version:       str
    violated_rules:       tuple[str, ...]
    compliance_rationale: tuple[str, ...]
    regulatory_refs:      tuple[str, ...]
    explanation:          str

    def to_json(self) -> str:
        """Serialize to JSON string suitable for audit log inclusion."""
        return json.dumps(
            {
                "decision_id":          self.decision_id,
                "decision_hash":        self.decision_hash,
                "timestamp":            self.timestamp,
                "verdict":              self.verdict,
                "severity":             self.severity,
                "policy_name":          self.policy_name,
                "policy_version":       self.policy_version,
                "violated_rules":       list(self.violated_rules),
                "compliance_rationale": list(self.compliance_rationale),
                "regulatory_refs":      list(self.regulatory_refs),
                "explanation":          self.explanation,
            },
            indent=2,
            default=str,
        )

    def to_pdf(self) -> bytes:
        """Generate a PDF compliance report.

        Returns a PDF binary suitable for regulatory submissions, legal
        discovery responses, and compliance dashboards.

        Requires:
            ``pip install 'pramanix[pdf]'`` (``fpdf2 >= 2.7``).

        Raises:
            ImportError: If ``fpdf2`` is not installed.
        """
        try:
            from fpdf import FPDF
        except ImportError as exc:
            raise ImportError(
                "ComplianceReport.to_pdf() requires 'fpdf2'. "
                "Install it: pip install 'pramanix[pdf]'"
            ) from exc

        pdf = FPDF()
        # Regulatory references contain em-dash (—, U+2014, Windows-1252 0x97)
        # and section signs (§, U+00A7).  cp1252 is a strict superset of latin-1
        # that covers all Windows-1252 characters; fpdf2 core fonts encode against
        # this mapping, so setting it avoids FPDFUnicodeEncodingException.
        pdf.core_fonts_encoding = "cp1252"
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # ── Title ────────────────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            0, 12, "PRAMANIX COMPLIANCE REPORT",
            new_x="LMARGIN", new_y="NEXT", align="C",
        )
        pdf.set_line_width(0.5)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(5)

        def _section(title: str) -> None:
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_fill_color(230, 230, 230)
            pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT", fill=True)
            pdf.ln(1)
            pdf.set_font("Helvetica", "", 10)

        def _kv(key: str, value: str) -> None:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(55, 7, key + ":", new_x="RIGHT", new_y="LAST")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 7, value, new_x="LMARGIN", new_y="NEXT")

        def _bullet(text: str) -> None:
            pdf.set_font("Helvetica", "", 10)
            # Helvetica is a Latin-1 core font; U+2022 (BULLET) is not in
            # Latin-1.  U+00B7 (MIDDLE DOT) is at 0xB7 in Latin-1 and
            # renders cleanly as a list marker in all PDF viewers.
            pdf.cell(8, 7, "\u00b7", new_x="RIGHT", new_y="LAST")
            pdf.multi_cell(0, 7, text, new_x="LMARGIN", new_y="NEXT")

        # ── Decision summary ─────────────────────────────────────────────────
        _section("Decision Summary")
        _kv("Decision ID", self.decision_id)
        _kv("Hash", self.decision_hash)
        _kv("Timestamp", self.timestamp or "N/A")
        _kv("Verdict", self.verdict)
        _kv("Severity", self.severity)
        _kv("Policy", f"{self.policy_name}  v{self.policy_version}")
        pdf.ln(4)

        # ── Violated rules ───────────────────────────────────────────────────
        if self.violated_rules:
            _section("Violated Rules")
            for rule in self.violated_rules:
                _bullet(rule)
            pdf.ln(4)

        # ── Compliance rationale ─────────────────────────────────────────────
        if self.compliance_rationale:
            _section("Compliance Rationale")
            for rationale in self.compliance_rationale:
                _bullet(rationale)
            pdf.ln(4)

        # ── Regulatory references ────────────────────────────────────────────
        if self.regulatory_refs:
            _section("Regulatory References")
            for ref in self.regulatory_refs:
                _bullet(ref)
            pdf.ln(4)

        # ── Explanation ──────────────────────────────────────────────────────
        if self.explanation:
            _section("Explanation")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 7, self.explanation, new_x="LMARGIN", new_y="NEXT")

        return bytes(pdf.output())


# ── Reporter ──────────────────────────────────────────────────────────────────


class ComplianceReporter:
    """Generates structured compliance reports from Pramanix Decisions.

    Usage:
        reporter = ComplianceReporter()
        # Or with custom regulatory mappings:
        reporter = ComplianceReporter(extra_refs={"my_rule": ["Internal Policy §3.2"]})
    """

    def __init__(
        self,
        extra_refs: dict[str, list[str]] | None = None,
    ) -> None:
        self._refs: dict[str, list[str]] = dict(_REGULATORY_MAP)
        if extra_refs:
            self._refs.update(extra_refs)

    def generate(
        self,
        decision: Decision,
        policy_meta: dict[str, Any] | None = None,
    ) -> ComplianceReport:
        """Generate a ComplianceReport from a Decision.

        Args:
            decision:    The Decision object from Guard.verify()
            policy_meta: Optional dict with "name" and "version" keys.
                         Falls back to decision.metadata if available.
        """
        meta = dict(policy_meta) if policy_meta else {}
        if not meta and decision.metadata:
            meta = decision.metadata

        policy_name    = meta.get("name") or meta.get("policy") or "UnknownPolicy"
        policy_version = meta.get("version") or meta.get("policy_version") or "unknown"

        timestamp = ""
        if decision.metadata:
            timestamp = str(decision.metadata.get("timestamp_utc", ""))

        verdict  = "ALLOWED" if decision.allowed else "BLOCKED"
        violated = tuple(decision.violated_invariants or ())
        intent_dump = decision.intent_dump or {}

        rationale: list[str] = []
        if decision.explanation:
            rationale.append(decision.explanation)

        refs: list[str] = []
        for rule in violated:
            rule_refs = self._refs.get(rule, [])
            refs.extend(rule_refs)
            if not rule_refs:
                refs.append(f"Internal policy rule: {rule}")

        severity = _classify_severity(violated, intent_dump)

        return ComplianceReport(
            decision_id=str(decision.decision_id),
            decision_hash=str(decision.decision_hash),
            timestamp=timestamp,
            verdict=verdict,
            severity=severity,
            policy_name=policy_name,
            policy_version=policy_version,
            violated_rules=violated,
            compliance_rationale=tuple(rationale),
            regulatory_refs=tuple(dict.fromkeys(refs)),  # deduplicated, ordered
            explanation=str(decision.explanation or ""),
        )

    def register_rule(self, rule_name: str, refs: list[str]) -> None:
        """Register regulatory references for a custom rule label."""
        self._refs[rule_name] = refs
