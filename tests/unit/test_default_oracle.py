# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for the built-in compliance mapping library (P3.1 / default_oracle).

Exercises default_oracle() and _BUILT_IN_MAPPINGS without mocks — all
assertions are against the real ComplianceOracle and real ProvenanceRecords.
"""

from __future__ import annotations

from pramanix.compliance.oracle import (
    _BUILT_IN_MAPPINGS,
    ComplianceOracle,
    ControlMapping,
    RegulatoryFramework,
    default_oracle,
)

# ── _BUILT_IN_MAPPINGS structural checks ──────────────────────────────────────


class TestBuiltInMappingsStructure:
    def test_non_empty(self) -> None:
        assert len(_BUILT_IN_MAPPINGS) >= 20

    def test_all_are_control_mapping_instances(self) -> None:
        for m in _BUILT_IN_MAPPINGS:
            assert isinstance(m, ControlMapping), f"Not a ControlMapping: {m!r}"

    def test_all_have_invariant_label(self) -> None:
        for m in _BUILT_IN_MAPPINGS:
            assert (
                m.invariant_label is not None
            ), f"Built-in mapping {m.control_id} has no invariant_label"

    def test_covers_all_five_frameworks(self) -> None:
        covered = {m.framework for m in _BUILT_IN_MAPPINGS}
        assert RegulatoryFramework.SOC2 in covered
        assert RegulatoryFramework.EU_AI_ACT in covered
        assert RegulatoryFramework.HIPAA in covered
        assert RegulatoryFramework.NIST_AI_RMF in covered
        assert RegulatoryFramework.GDPR in covered

    def test_covers_common_financial_labels(self) -> None:
        labels = {m.invariant_label for m in _BUILT_IN_MAPPINGS}
        assert "amount_limit" in labels
        assert "sufficient_balance" in labels
        assert "velocity_check" in labels

    def test_covers_common_access_labels(self) -> None:
        labels = {m.invariant_label for m in _BUILT_IN_MAPPINGS}
        assert "authorized_role" in labels
        assert "kyc_status" in labels

    def test_covers_healthcare_labels(self) -> None:
        labels = {m.invariant_label for m in _BUILT_IN_MAPPINGS}
        assert "phi_least_privilege" in labels
        assert "patient_consent_required" in labels

    def test_soc2_control_ids_are_valid_format(self) -> None:
        import re

        pattern = re.compile(r"^(CC|A|PI|P|C|CA)\d+\.\d+$")
        for m in _BUILT_IN_MAPPINGS:
            if m.framework == RegulatoryFramework.SOC2:
                assert pattern.match(
                    m.control_id
                ), f"SOC2 control ID {m.control_id!r} does not match pattern"

    def test_eu_ai_act_control_ids_are_valid_format(self) -> None:
        import re

        pattern = re.compile(r"^(Art|Recital|Annex)[\s.]*\d+[a-zA-Z]?")
        for m in _BUILT_IN_MAPPINGS:
            if m.framework == RegulatoryFramework.EU_AI_ACT:
                assert pattern.match(
                    m.control_id
                ), f"EU AI Act control ID {m.control_id!r} does not match pattern"

    def test_hipaa_control_ids_are_valid_format(self) -> None:
        import re

        pattern = re.compile(r"^§\d+\.\d+")
        for m in _BUILT_IN_MAPPINGS:
            if m.framework == RegulatoryFramework.HIPAA:
                assert pattern.match(
                    m.control_id
                ), f"HIPAA control ID {m.control_id!r} does not match pattern"

    def test_nist_ai_rmf_control_ids_are_valid_format(self) -> None:
        import re

        pattern = re.compile(r"^(GOVERN|MAP|MEASURE|MANAGE)-\d+\.\d+$")
        for m in _BUILT_IN_MAPPINGS:
            if m.framework == RegulatoryFramework.NIST_AI_RMF:
                assert pattern.match(
                    m.control_id
                ), f"NIST AI RMF control ID {m.control_id!r} does not match pattern"

    def test_gdpr_control_ids_are_valid_format(self) -> None:
        import re

        pattern = re.compile(r"^(Art|Recital)[\s.]*\d+[a-zA-Z]?")
        for m in _BUILT_IN_MAPPINGS:
            if m.framework == RegulatoryFramework.GDPR:
                assert pattern.match(
                    m.control_id
                ), f"GDPR control ID {m.control_id!r} does not match pattern"

    def test_all_descriptions_non_empty(self) -> None:
        for m in _BUILT_IN_MAPPINGS:
            assert m.description.strip(), f"Empty description in mapping {m.control_id}"

    def test_all_control_titles_non_empty(self) -> None:
        for m in _BUILT_IN_MAPPINGS:
            assert m.control_title.strip(), f"Empty control_title in mapping {m.control_id}"


# ── default_oracle() factory ──────────────────────────────────────────────────


class TestDefaultOracleFactory:
    def test_returns_compliance_oracle(self) -> None:
        oracle = default_oracle()
        assert isinstance(oracle, ComplianceOracle)

    def test_each_call_returns_independent_instance(self) -> None:
        o1 = default_oracle()
        o2 = default_oracle()
        assert o1 is not o2

    def test_oracle_has_all_built_in_frameworks(self) -> None:
        oracle = default_oracle()
        for framework in [
            RegulatoryFramework.SOC2,
            RegulatoryFramework.EU_AI_ACT,
            RegulatoryFramework.HIPAA,
            RegulatoryFramework.NIST_AI_RMF,
            RegulatoryFramework.GDPR,
        ]:
            registered = oracle.get_mappings(framework)
            assert len(registered) > 0, f"default_oracle() has no mappings for {framework.value}"

    def test_oracle_accepts_additional_mappings(self) -> None:
        oracle = default_oracle()
        custom = ControlMapping(
            framework=RegulatoryFramework.SOC2,
            control_id="CC1.1",
            control_title="Integrity and Ethical Values",
            invariant_label="custom_label",
            description="Custom mapping added on top of built-in library.",
        )
        oracle.register_mapping(RegulatoryFramework.SOC2, custom)
        soc2_mappings = oracle.get_mappings(RegulatoryFramework.SOC2)
        assert any(
            m.control_id == "CC1.1" and m.invariant_label == "custom_label" for m in soc2_mappings
        )

    def test_soc2_mappings_include_amount_limit(self) -> None:
        oracle = default_oracle()
        soc2 = oracle.get_mappings(RegulatoryFramework.SOC2)
        labels = {m.invariant_label for m in soc2}
        assert "amount_limit" in labels

    def test_hipaa_mappings_include_phi_least_privilege(self) -> None:
        oracle = default_oracle()
        hipaa = oracle.get_mappings(RegulatoryFramework.HIPAA)
        labels = {m.invariant_label for m in hipaa}
        assert "phi_least_privilege" in labels

    def test_eu_ai_act_mappings_include_human_oversight_controls(self) -> None:
        oracle = default_oracle()
        eu = oracle.get_mappings(RegulatoryFramework.EU_AI_ACT)
        control_ids = {m.control_id for m in eu}
        assert "Art.14" in control_ids

    def test_nist_ai_rmf_has_govern_and_manage(self) -> None:
        oracle = default_oracle()
        nist = oracle.get_mappings(RegulatoryFramework.NIST_AI_RMF)
        control_ids = {m.control_id for m in nist}
        assert any(cid.startswith("GOVERN") for cid in control_ids)
        assert any(cid.startswith("MANAGE") for cid in control_ids)

    def test_gdpr_has_art25_data_minimisation(self) -> None:
        oracle = default_oracle()
        gdpr = oracle.get_mappings(RegulatoryFramework.GDPR)
        control_ids = {m.control_id for m in gdpr}
        assert "Art.25" in control_ids
