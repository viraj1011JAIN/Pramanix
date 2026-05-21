# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Coverage tests for compliance/oracle.py.

Covers: ControlMapping.model_post_init, FrameworkAttestation properties,
ComplianceOracle public API, _evaluate_impl full pipeline, _extract_invariant_sets,
_evaluate_mapping all branches, _build_summary, _no_mappings_attestation,
_error_attestation, and module-level helpers.
"""

from __future__ import annotations

import pytest

from pramanix.compliance.oracle import (
    ComplianceAttestation,
    ComplianceOracle,
    ControlMapping,
    FrameworkAttestation,
    MappingMatchKind,
    RegulatoryFramework,
    _check_invariant_match,
    _check_principal_match,
    _format_violation_prevented,
)
from pramanix.provenance import ProvenanceRecord

# ── Shared helpers ────────────────────────────────────────────────────────────

_FW = RegulatoryFramework.SOC2
_EU = RegulatoryFramework.EU_AI_ACT


def _record(
    *,
    allowed: bool = True,
    principal_id: str = "spiffe://cluster/ns/svc",
    metadata: dict | None = None,
) -> ProvenanceRecord:
    return ProvenanceRecord(
        decision_id="dec-001",
        policy_hash="abc123",
        principal_id=principal_id,
        allowed=allowed,
        metadata=metadata or {},
    )


def _mapping(
    *,
    framework: RegulatoryFramework = _FW,
    control_id: str = "CC6.1",
    control_title: str = "Logical Access",
    invariant_label: str | None = "amount_within_balance",
    principal_pattern: str | None = None,
    require_both: bool = True,
    description: str = "SOC2 CC6.1 logical access.",
) -> ControlMapping:
    return ControlMapping(
        framework=framework,
        control_id=control_id,
        control_title=control_title,
        invariant_label=invariant_label,
        principal_pattern=principal_pattern,
        require_both=require_both,
        description=description,
    )


# ── ControlMapping.model_post_init ────────────────────────────────────────────


class TestControlMappingPostInit:
    def test_both_none_raises(self) -> None:
        """Neither invariant_label nor principal_pattern → ValueError."""
        with pytest.raises(ValueError, match="at least one"):
            ControlMapping(
                framework=_FW,
                control_id="CC6.1",
                control_title="Logical Access",
                description="Test.",
            )

    def test_invariant_only_accepted(self) -> None:
        m = _mapping(invariant_label="inv_a", principal_pattern=None)
        assert m.invariant_label == "inv_a"

    def test_principal_only_accepted(self) -> None:
        m = _mapping(invariant_label=None, principal_pattern="spiffe://*/svc")
        assert m.principal_pattern == "spiffe://*/svc"

    def test_both_provided_accepted(self) -> None:
        m = _mapping(invariant_label="inv_a", principal_pattern="spiffe://*/svc")
        assert m.invariant_label == "inv_a"
        assert m.principal_pattern == "spiffe://*/svc"


# ── FrameworkAttestation properties ──────────────────────────────────────────


class TestFrameworkAttestationProperties:
    def test_total_controls_empty(self) -> None:
        fa = FrameworkAttestation(framework=_FW)
        assert fa.total_controls == 0

    def test_has_findings_false_when_empty(self) -> None:
        fa = FrameworkAttestation(framework=_FW)
        assert fa.has_findings is False

    def test_total_controls_satisfied_only(self) -> None:
        from pramanix.compliance.oracle import ControlSatisfactionResult

        sr = ControlSatisfactionResult(
            control_id="CC6.1",
            control_title="Logical Access",
            description="Test.",
            match_kind=MappingMatchKind.INVARIANT_LABEL,
        )
        fa = FrameworkAttestation(framework=_FW, controls_satisfied=[sr])
        assert fa.total_controls == 1
        assert fa.has_findings is True


# ── ComplianceOracle.__init__ and public API ──────────────────────────────────


class TestComplianceOracleInit:
    def test_empty_oracle_has_zero_mappings(self) -> None:
        oracle = ComplianceOracle()
        assert oracle.mapping_count() == 0

    def test_empty_oracle_no_frameworks(self) -> None:
        oracle = ComplianceOracle()
        assert oracle.registered_frameworks() == []


class TestComplianceOracleRegisterMapping:
    def test_register_raises_on_framework_mismatch(self) -> None:
        oracle = ComplianceOracle()
        m = _mapping(framework=_FW)
        with pytest.raises(ValueError, match="does not match"):
            oracle.register_mapping(_EU, m)

    def test_register_increments_count(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping())
        assert oracle.mapping_count() == 1
        assert oracle.mapping_count(_FW) == 1
        assert oracle.mapping_count(_EU) == 0

    def test_register_multiple_frameworks(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(framework=_FW))
        oracle.register_mapping(_EU, _mapping(framework=_EU))
        assert oracle.mapping_count() == 2
        assert set(oracle.registered_frameworks()) == {_FW, _EU}

    def test_registered_frameworks_sorted(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_EU, _mapping(framework=_EU))
        oracle.register_mapping(_FW, _mapping(framework=_FW))
        fws = oracle.registered_frameworks()
        assert fws == sorted(fws, key=lambda f: f.value)


# ── evaluate_record: no-mappings path ─────────────────────────────────────────


class TestEvaluateRecordNoMappings:
    def test_no_mappings_returns_empty_attestation(self) -> None:
        oracle = ComplianceOracle()
        rec = _record()
        att = oracle.evaluate_record(rec)
        assert isinstance(att, ComplianceAttestation)
        assert att.framework_results == []
        assert att.total_controls_matched == 0
        assert "No compliance mappings" in att.summary

    def test_no_mappings_blocked_record(self) -> None:
        oracle = ComplianceOracle()
        rec = _record(allowed=False)
        att = oracle.evaluate_record(rec)
        assert att.outcome == "BLOCKED"


# ── evaluate_record: exception fallback → _error_attestation ─────────────────


class TestEvaluateRecordErrorFallback:
    def test_exception_in_impl_returns_error_attestation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping())

        def _boom(*a: object, **kw: object) -> None:
            raise RuntimeError("injected failure")

        monkeypatch.setattr(oracle, "_evaluate_impl", _boom)
        rec = _record()
        att = oracle.evaluate_record(rec)
        assert isinstance(att, ComplianceAttestation)
        assert "internal error" in att.summary
        assert att.framework_results == []


# ── _evaluate_impl: full pipeline ─────────────────────────────────────────────


class TestEvaluateImpl:
    def test_allowed_record_produces_satisfaction(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="check_a"))
        rec = _record(
            allowed=True,
            metadata={"evaluated_invariants": ["check_a"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.outcome == "ALLOWED"
        assert len(att.framework_results) == 1
        fa = att.framework_results[0]
        assert fa.total_controls == 1
        assert fa.has_findings is True
        assert len(fa.controls_satisfied) == 1
        assert fa.controls_satisfied[0].control_id == "CC6.1"

    def test_blocked_record_produces_enforcement(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="check_b"))
        rec = _record(
            allowed=False,
            metadata={"violated_invariants": ["check_b"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.outcome == "BLOCKED"
        fa = att.framework_results[0]
        assert len(fa.controls_enforced) == 1
        assert fa.controls_enforced[0].control_id == "CC6.1"

    def test_allowed_with_decision_snapshot_takes_priority(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="snap_inv"))
        rec = _record(allowed=True)
        att = oracle.evaluate_record(
            rec,
            decision_snapshot={"evaluated_invariants": ["snap_inv"]},
        )
        assert att.total_controls_matched == 1

    def test_no_matching_mapping_gives_empty_results(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="other_inv"))
        rec = _record(allowed=True, metadata={"evaluated_invariants": ["diff_inv"]})
        att = oracle.evaluate_record(rec)
        assert att.framework_results == []
        assert att.total_controls_matched == 0

    def test_hmac_tag_from_record_when_stored_empty(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="inv"))
        rec = _record(allowed=True, metadata={"evaluated_invariants": ["inv"]})
        att = oracle.evaluate_record(rec, stored_hmac_tag="")
        assert att.record_hmac_tag  # populated from record.hmac_tag()

    def test_stored_hmac_tag_used_when_provided(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="inv"))
        rec = _record(allowed=True, metadata={"evaluated_invariants": ["inv"]})
        att = oracle.evaluate_record(rec, stored_hmac_tag="fixed-hmac-value")
        assert att.record_hmac_tag == "fixed-hmac-value"


# ── _extract_invariant_sets: inference fallback ────────────────────────────────


class TestExtractInvariantSets:
    def test_allowed_record_infers_evaluated_from_registry(self) -> None:
        """Allowed record with no evaluated_invariants in metadata → inferred."""
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="infer_me"))
        rec = _record(allowed=True)  # no metadata
        att = oracle.evaluate_record(rec)
        # The inferred evaluated set should include "infer_me" → control fires
        assert att.total_controls_matched == 1

    def test_blocked_record_uses_violated_set(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="blocked_inv"))
        rec = _record(
            allowed=False,
            metadata={"violated_invariants": ["blocked_inv"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.total_controls_matched == 1


# ── _evaluate_mapping: require_both and OR branches ──────────────────────────


class TestEvaluateMapping:
    def test_require_both_true_only_fires_when_both_match(self) -> None:
        oracle = ComplianceOracle()
        m = _mapping(
            invariant_label="inv_x",
            principal_pattern="spiffe://*/svc",
            require_both=True,
        )
        oracle.register_mapping(_FW, m)
        # Only invariant matches — principal doesn't (different principal)
        rec = _record(
            allowed=True,
            principal_id="spiffe://other/thing",
            metadata={"evaluated_invariants": ["inv_x"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.total_controls_matched == 0

    def test_require_both_true_fires_when_both_match(self) -> None:
        oracle = ComplianceOracle()
        m = _mapping(
            invariant_label="inv_x",
            principal_pattern="spiffe://cluster/*/svc",
            require_both=True,
        )
        oracle.register_mapping(_FW, m)
        rec = _record(
            allowed=True,
            principal_id="spiffe://cluster/ns/svc",
            metadata={"evaluated_invariants": ["inv_x"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.total_controls_matched == 1
        sr = att.framework_results[0].controls_satisfied[0]
        assert sr.match_kind == MappingMatchKind.BOTH

    def test_require_both_false_fires_on_invariant_only(self) -> None:
        oracle = ComplianceOracle()
        m = _mapping(
            invariant_label="inv_y",
            principal_pattern="spiffe://other/*",
            require_both=False,
        )
        oracle.register_mapping(_FW, m)
        rec = _record(
            allowed=True,
            principal_id="spiffe://cluster/ns/svc",
            metadata={"evaluated_invariants": ["inv_y"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.total_controls_matched == 1
        sr = att.framework_results[0].controls_satisfied[0]
        assert sr.match_kind == MappingMatchKind.INVARIANT_LABEL

    def test_require_both_false_fires_on_principal_only(self) -> None:
        oracle = ComplianceOracle()
        m = _mapping(
            invariant_label="inv_z",
            principal_pattern="spiffe://cluster/*/svc",
            require_both=False,
        )
        oracle.register_mapping(_FW, m)
        # inv_z not in evaluated but principal matches
        rec = _record(
            allowed=True,
            principal_id="spiffe://cluster/ns/svc",
            metadata={"evaluated_invariants": ["different_inv"]},
        )
        att = oracle.evaluate_record(rec)
        assert att.total_controls_matched == 1
        sr = att.framework_results[0].controls_satisfied[0]
        assert sr.match_kind == MappingMatchKind.PRINCIPAL_IDENTITY

    def test_principal_only_mapping_fires(self) -> None:
        oracle = ComplianceOracle()
        m = _mapping(invariant_label=None, principal_pattern="spiffe://cluster/*")
        oracle.register_mapping(_FW, m)
        rec = _record(
            allowed=True,
            principal_id="spiffe://cluster/ns/svc",
        )
        att = oracle.evaluate_record(rec)
        assert att.total_controls_matched == 1
        sr = att.framework_results[0].controls_satisfied[0]
        assert sr.match_kind == MappingMatchKind.PRINCIPAL_IDENTITY


# ── _build_summary: ALLOWED and BLOCKED paths ─────────────────────────────────


class TestBuildSummary:
    def test_allowed_summary_mentions_satisfied(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="inv_a"))
        rec = _record(allowed=True, metadata={"evaluated_invariants": ["inv_a"]})
        att = oracle.evaluate_record(rec)
        assert "ALLOWED" in att.summary
        assert "CC6.1" in att.summary

    def test_blocked_summary_mentions_enforced(self) -> None:
        oracle = ComplianceOracle()
        oracle.register_mapping(_FW, _mapping(invariant_label="inv_b"))
        rec = _record(
            allowed=False,
            metadata={"violated_invariants": ["inv_b"]},
        )
        att = oracle.evaluate_record(rec)
        assert "BLOCKED" in att.summary
        assert "CC6.1" in att.summary


# ── Module-level helpers ───────────────────────────────────────────────────────


class TestCheckInvariantMatch:
    def test_none_label_returns_false(self) -> None:
        m = _mapping(invariant_label=None, principal_pattern="*")
        rec = _record(allowed=True)
        result = _check_invariant_match(m, rec, frozenset(["inv"]), frozenset())
        assert result is False

    def test_allowed_checks_evaluated(self) -> None:
        m = _mapping(invariant_label="inv_a")
        rec = _record(allowed=True)
        assert _check_invariant_match(m, rec, frozenset(["inv_a"]), frozenset()) is True
        assert _check_invariant_match(m, rec, frozenset(["other"]), frozenset()) is False

    def test_blocked_checks_violated(self) -> None:
        m = _mapping(invariant_label="inv_b")
        rec = _record(allowed=False)
        assert _check_invariant_match(m, rec, frozenset(), frozenset(["inv_b"])) is True
        assert _check_invariant_match(m, rec, frozenset(), frozenset()) is False


class TestCheckPrincipalMatch:
    def test_empty_pattern_returns_false(self) -> None:
        m = _mapping(invariant_label="inv", principal_pattern=None)
        rec = _record(principal_id="spiffe://cluster/ns/svc")
        assert _check_principal_match(m, rec) is False

    def test_empty_principal_returns_false(self) -> None:
        m = _mapping(invariant_label=None, principal_pattern="spiffe://*")
        rec = _record(principal_id="")
        assert _check_principal_match(m, rec) is False

    def test_fnmatch_wildcard_matches(self) -> None:
        m = _mapping(invariant_label=None, principal_pattern="spiffe://cluster/*")
        rec = _record(principal_id="spiffe://cluster/ns/svc")
        assert _check_principal_match(m, rec) is True

    def test_fnmatch_no_match(self) -> None:
        m = _mapping(invariant_label=None, principal_pattern="spiffe://other/*")
        rec = _record(principal_id="spiffe://cluster/ns/svc")
        assert _check_principal_match(m, rec) is False


class TestFormatViolationPrevented:
    def test_invariant_only_match_kind(self) -> None:
        m = _mapping(invariant_label="inv_c")
        result = _format_violation_prevented(
            mapping=m,
            violated_invariants=frozenset(["inv_c"]),
            principal_id="spiffe://test",
            match_kind=MappingMatchKind.INVARIANT_LABEL,
        )
        assert "inv_c" in result
        assert "SOC2" in result

    def test_principal_match_kind_includes_principal(self) -> None:
        m = _mapping(
            invariant_label=None,
            principal_pattern="spiffe://*",
        )
        result = _format_violation_prevented(
            mapping=m,
            violated_invariants=frozenset(),
            principal_id="spiffe://cluster/ns/svc",
            match_kind=MappingMatchKind.PRINCIPAL_IDENTITY,
        )
        assert "spiffe://cluster/ns/svc" in result

    def test_both_match_kind_includes_both(self) -> None:
        m = _mapping(
            invariant_label="inv_d",
            principal_pattern="spiffe://*",
        )
        result = _format_violation_prevented(
            mapping=m,
            violated_invariants=frozenset(["inv_d"]),
            principal_id="spiffe://cluster/ns/svc",
            match_kind=MappingMatchKind.BOTH,
        )
        assert "inv_d" in result
        assert "spiffe://cluster/ns/svc" in result
