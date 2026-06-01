# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Phase 4 — Compliance Oracle Hardening: control_id format validation.

STOP 2 fix: without format validation, any arbitrary string could be used as
a control_id, producing attestations that look authoritative but reference
non-existent controls.  These tests verify:

1. Valid canonical control IDs are accepted per framework.
2. Invalid / fabricated control IDs raise ValueError by default.
3. custom_control=True bypasses validation with a UserWarning.
4. The _CONTROL_ID_PATTERNS cover every RegulatoryFramework member.
5. The oracle produces correct attestations with valid control IDs.
"""

from __future__ import annotations

import re
import warnings

import pytest

from pramanix.compliance.oracle import (
    ComplianceOracle,
    ControlMapping,
    RegulatoryFramework,
    _CONTROL_ID_PATTERNS,
)
from pramanix.provenance import ProvenanceRecord


# ── Helpers ────────────────────────────────────────────────────────────────────


def _record(*, allowed: bool = True) -> ProvenanceRecord:
    return ProvenanceRecord(
        decision_id="dec-p4-001",
        policy_hash="abc" * 21 + "d",
        principal_id="spiffe://cluster/ns/payments/svc",
        allowed=allowed,
        metadata={},
    )


def _mapping(
    framework: RegulatoryFramework,
    control_id: str,
    *,
    invariant_label: str = "amount_within_balance",
    custom_control: bool = False,
    description: str = "Test control.",
) -> ControlMapping:
    return ControlMapping(
        framework=framework,
        control_id=control_id,
        control_title="Test Control Title",
        invariant_label=invariant_label,
        description=description,
        custom_control=custom_control,
    )


# ── 1. _CONTROL_ID_PATTERNS completeness ──────────────────────────────────────


class TestControlIdPatternsCompleteness:
    def test_every_framework_has_a_pattern(self) -> None:
        for fw in RegulatoryFramework:
            assert fw.value in _CONTROL_ID_PATTERNS, (
                f"RegulatoryFramework.{fw.name} ({fw.value!r}) has no entry "
                "in _CONTROL_ID_PATTERNS.  Add a regex before shipping."
            )

    def test_all_patterns_are_compiled_regex(self) -> None:
        for key, pat in _CONTROL_ID_PATTERNS.items():
            assert isinstance(pat, re.Pattern), (
                f"_CONTROL_ID_PATTERNS[{key!r}] is not a compiled re.Pattern."
            )


# ── 2. Valid control IDs accepted (one canonical example per framework) ────────


@pytest.mark.parametrize(
    "framework, control_id",
    [
        (RegulatoryFramework.SOC2, "CC6.1"),
        (RegulatoryFramework.SOC2, "CC1.1"),
        (RegulatoryFramework.SOC2, "A1.1"),
        (RegulatoryFramework.SOC2, "PI1.3"),
        (RegulatoryFramework.EU_AI_ACT, "Art.14"),
        (RegulatoryFramework.EU_AI_ACT, "Art.9"),
        (RegulatoryFramework.EU_AI_ACT, "Recital 12"),
        (RegulatoryFramework.HIPAA, "§164.312(a)(1)"),
        (RegulatoryFramework.HIPAA, "§164.308(a)(1)"),
        (RegulatoryFramework.NIST_AI_RMF, "GOVERN-1.1"),
        (RegulatoryFramework.NIST_AI_RMF, "MAP-2.1"),
        (RegulatoryFramework.NIST_AI_RMF, "MEASURE-2.5"),
        (RegulatoryFramework.NIST_AI_RMF, "MANAGE-3.2"),
        (RegulatoryFramework.ISO_42001, "Clause 6.1"),
        (RegulatoryFramework.ISO_42001, "Annex A.6.2.1"),
        (RegulatoryFramework.GDPR, "Art.5"),
        (RegulatoryFramework.GDPR, "Art.25"),
        (RegulatoryFramework.GDPR, "Recital 4"),
    ],
)
def test_valid_canonical_control_ids_accepted(
    framework: RegulatoryFramework, control_id: str
) -> None:
    m = _mapping(framework, control_id)
    assert m.control_id == control_id
    assert m.framework == framework


# ── 3. Fabricated / invalid control IDs rejected ──────────────────────────────


@pytest.mark.parametrize(
    "framework, bad_id",
    [
        (RegulatoryFramework.SOC2, "FAKE_CONTROL_99"),
        (RegulatoryFramework.SOC2, "SOC2_CC6"),
        (RegulatoryFramework.SOC2, "security-control-1"),
        (RegulatoryFramework.EU_AI_ACT, "CC6.1"),
        (RegulatoryFramework.EU_AI_ACT, "eu_ai_act_14"),
        (RegulatoryFramework.HIPAA, "HIPAA-164-312"),
        (RegulatoryFramework.HIPAA, "security_rule"),
        (RegulatoryFramework.NIST_AI_RMF, "CC6.1"),
        (RegulatoryFramework.NIST_AI_RMF, "GOVERN_1_1"),
        (RegulatoryFramework.NIST_AI_RMF, "nist-govern"),
        (RegulatoryFramework.ISO_42001, "CC6.1"),
        (RegulatoryFramework.ISO_42001, "iso42001_6_1"),
        (RegulatoryFramework.GDPR, "CC6.1"),
        (RegulatoryFramework.GDPR, "gdpr_art5"),
    ],
)
def test_fabricated_control_ids_rejected(
    framework: RegulatoryFramework, bad_id: str
) -> None:
    with pytest.raises(ValueError, match="control_id"):
        _mapping(framework, bad_id)


# ── 4. custom_control=True bypasses validation with UserWarning ────────────────


class TestCustomControlBypass:
    def test_custom_control_accepts_nonstandard_id(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            m = _mapping(RegulatoryFramework.SOC2, "INTERNAL-SEC-42", custom_control=True)
        assert m.control_id == "INTERNAL-SEC-42"
        assert m.custom_control is True
        # Warning should be emitted
        assert any(issubclass(x.category, UserWarning) for x in w), (
            "UserWarning expected when custom_control=True and ID is non-canonical."
        )

    def test_custom_control_warning_mentions_framework_and_id(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _mapping(RegulatoryFramework.HIPAA, "INTERNAL-HIPAA-99", custom_control=True)
        msgs = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        assert any("HIPAA" in msg for msg in msgs)
        assert any("INTERNAL-HIPAA-99" in msg for msg in msgs)

    def test_custom_control_true_with_valid_id_emits_no_warning(self) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            m = _mapping(RegulatoryFramework.SOC2, "CC6.1", custom_control=True)
        user_warnings = [x for x in w if issubclass(x.category, UserWarning)]
        assert not user_warnings, (
            "No UserWarning expected when custom_control=True but ID is already valid."
        )
        assert m.custom_control is True

    def test_standard_control_id_with_custom_false_accepted(self) -> None:
        m = _mapping(RegulatoryFramework.NIST_AI_RMF, "GOVERN-1.1")
        assert m.custom_control is False


# ── 5. Error message quality ───────────────────────────────────────────────────


class TestErrorMessageQuality:
    def test_error_mentions_framework_name(self) -> None:
        with pytest.raises(ValueError, match="SOC2"):
            _mapping(RegulatoryFramework.SOC2, "FABRICATED-99")

    def test_error_mentions_bad_id(self) -> None:
        with pytest.raises(ValueError, match="FABRICATED-99"):
            _mapping(RegulatoryFramework.SOC2, "FABRICATED-99")

    def test_error_mentions_custom_control_hint(self) -> None:
        with pytest.raises(ValueError, match="custom_control=True"):
            _mapping(RegulatoryFramework.SOC2, "FABRICATED-99")

    def test_error_mentions_expected_pattern(self) -> None:
        with pytest.raises(ValueError, match=r"pattern:"):
            _mapping(RegulatoryFramework.SOC2, "FABRICATED-99")


# ── 6. Oracle integration: valid controls produce real attestations ────────────


class TestOracleIntegrationWithValidIds:
    def test_soc2_cc61_produces_attestation(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(
            RegulatoryFramework.SOC2,
            _mapping(RegulatoryFramework.SOC2, "CC6.1"),
        )
        rec = _record(allowed=True)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"violated_invariants": [], "evaluated_invariants": ["amount_within_balance"]},
        )
        assert att.total_controls_matched == 1
        assert any(fr.framework == RegulatoryFramework.SOC2 for fr in att.framework_results)

    def test_eu_ai_act_art14_produces_attestation(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(
            RegulatoryFramework.EU_AI_ACT,
            _mapping(RegulatoryFramework.EU_AI_ACT, "Art.14"),
        )
        rec = _record(allowed=False)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"violated_invariants": ["amount_within_balance"]},
        )
        assert att.total_controls_matched == 1
        assert "BLOCKED" in att.summary

    def test_nist_ai_rmf_govern_produces_attestation(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(
            RegulatoryFramework.NIST_AI_RMF,
            _mapping(RegulatoryFramework.NIST_AI_RMF, "GOVERN-1.1"),
        )
        rec = _record(allowed=True)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"violated_invariants": [], "evaluated_invariants": ["amount_within_balance"]},
        )
        assert att.total_controls_matched == 1

    def test_hipaa_produces_attestation(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(
            RegulatoryFramework.HIPAA,
            _mapping(RegulatoryFramework.HIPAA, "§164.312(a)(1)"),
        )
        rec = _record(allowed=True)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"violated_invariants": [], "evaluated_invariants": ["amount_within_balance"]},
        )
        assert att.total_controls_matched == 1

    def test_gdpr_art25_produces_attestation(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(
            RegulatoryFramework.GDPR,
            _mapping(RegulatoryFramework.GDPR, "Art.25"),
        )
        rec = _record(allowed=True)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"violated_invariants": [], "evaluated_invariants": ["amount_within_balance"]},
        )
        assert att.total_controls_matched == 1


# ── 7. Security: fabricated SOC2 control cannot produce attestation ────────────


class TestFabricatedControlRejected:
    def test_fabricated_soc2_control_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError):
            ControlMapping(
                framework=RegulatoryFramework.SOC2,
                control_id="SOC2_APPROVED_EVERYTHING",
                control_title="Fake Control",
                invariant_label="any_invariant",
                description="This should be rejected.",
            )

    def test_fabricated_hipaa_control_rejected(self) -> None:
        with pytest.raises(ValueError):
            ControlMapping(
                framework=RegulatoryFramework.HIPAA,
                control_id="HIPAA_COMPLIANT",
                control_title="Fake HIPAA",
                invariant_label="any_invariant",
                description="Fabricated HIPAA attestation attempt.",
            )

    def test_nist_wrong_format_rejected(self) -> None:
        with pytest.raises(ValueError):
            ControlMapping(
                framework=RegulatoryFramework.NIST_AI_RMF,
                control_id="NIST-1.1",
                control_title="Wrong format",
                invariant_label="any_invariant",
                description="Should use GOVERN-1.1 format.",
            )

    def test_custom_control_still_produces_attestation_with_warning(self) -> None:
        oracle = ComplianceOracle()
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            oracle.register_mapping(
                RegulatoryFramework.SOC2,
                ControlMapping(
                    framework=RegulatoryFramework.SOC2,
                    control_id="INTERNAL-P2-SEC-99",
                    control_title="Internal Control",
                    invariant_label="amount_within_balance",
                    description="Proprietary internal control.",
                    custom_control=True,
                ),
            )
        rec = _record(allowed=True)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"violated_invariants": [], "evaluated_invariants": ["amount_within_balance"]},
        )
        assert att.total_controls_matched == 1
