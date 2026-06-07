# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""End-to-end integration test: Guard.verify() → ProvenanceRecord → ComplianceOracle.

Closes audit gap P15: the compliance oracle was tested in isolation but the
full chain — Guard producing a Decision, wrapping it in a ProvenanceRecord,
and evaluating it through ComplianceOracle.evaluate_record() — had no coverage.

Full chain under test:
  Guard.verify()
    → Decision (allowed, violated_invariants)
    → ProvenanceRecord (decision_id, allowed, metadata)
    → ComplianceOracle.evaluate_record()
    → ComplianceAttestation (framework_results, record_hmac_tag, outcome)
    → ComplianceReporter.generate()
    → ComplianceReport (verdict, violated_rules, regulatory_refs)

No mocks. Real Z3 solver. Real compliance oracle.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.compliance.oracle import (
    ComplianceAttestation,
    ComplianceOracle,
    ControlMapping,
    RegulatoryFramework,
)
from pramanix.helpers.compliance import ComplianceReporter
from pramanix.provenance import ProvenanceRecord

# ── Policy fixture ─────────────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: Decimal
    daily_limit: Decimal


class _AccountState(BaseModel):
    balance: Decimal
    state_version: str


class _TransferPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(cls.amount) >= 0)
            .named("non_negative_amount")
            .explain("Transfer amount must be non-negative"),
            (E(cls.amount) <= E(cls.daily_limit))
            .named("within_daily_limit")
            .explain("Transfer amount must not exceed daily limit"),
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("sufficient_balance")
            .explain("Account balance must cover the transfer amount"),
        ]

    class Meta:
        version = "1.0"
        intent_model = _TransferIntent
        state_model = _AccountState


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(_TransferPolicy, GuardConfig(execution_mode="sync", audit_sinks=[]))


@pytest.fixture(scope="module")
def oracle() -> ComplianceOracle:
    o = ComplianceOracle()
    o.register_mapping(
        RegulatoryFramework.SOC2,
        ControlMapping(
            framework=RegulatoryFramework.SOC2,
            control_id="CC6.1",
            control_title="Logical Access Security",
            invariant_label="within_daily_limit",
            description="SOC2 CC6.1: restrict transfers to authorised daily limits",
        ),
    )
    o.register_mapping(
        RegulatoryFramework.SOC2,
        ControlMapping(
            framework=RegulatoryFramework.SOC2,
            control_id="CC9.1",
            control_title="Risk Mitigation",
            invariant_label="sufficient_balance",
            description="SOC2 CC9.1: prevent overdraft risk",
        ),
    )
    o.register_mapping(
        RegulatoryFramework.NIST_AI_RMF,
        ControlMapping(
            framework=RegulatoryFramework.NIST_AI_RMF,
            control_id="GOVERN-1.1",
            control_title="Policies and Procedures",
            invariant_label="non_negative_amount",
            description="NIST RMF GOVERN-1.1: enforce input validity",
        ),
    )
    return o


_POLICY_INVARIANT_LABELS = [
    "non_negative_amount",
    "within_daily_limit",
    "sufficient_balance",
]


def _make_record(decision: object) -> ProvenanceRecord:
    allowed = bool(getattr(decision, "allowed", False))
    violated = list(getattr(decision, "violated_invariants", []))
    # For ALLOWED decisions all policy invariants were evaluated and passed.
    # Decision.to_dict() does not carry evaluated_invariants, so we populate
    # it from the known policy labels so the compliance oracle can match controls.
    evaluated = _POLICY_INVARIANT_LABELS if allowed else []
    return ProvenanceRecord(
        decision_id=str(getattr(decision, "decision_id", "")),
        policy_hash="sha256-test",
        principal_id="test-agent",
        allowed=allowed,
        metadata={
            "violated_invariants": violated,
            "evaluated_invariants": evaluated,
        },
    )


# ── Scenario 1: ALLOW — attestation must show control satisfaction ────────────


class TestAllowDecisionAttestation:
    def test_allow_produces_attestation(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("100"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert decision.allowed

        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )

        assert isinstance(attestation, ComplianceAttestation)
        assert attestation.outcome == "ALLOWED"

    def test_allow_attestation_has_soc2_framework(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("100"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )

        framework_names = [fa.framework.value for fa in attestation.framework_results]
        assert "SOC2" in framework_names

    def test_allow_attestation_has_record_hmac_tag(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("100"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )

        assert len(attestation.record_hmac_tag) > 0

    def test_allow_attestation_never_raises(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("50"), "daily_limit": Decimal("500")},
            state={"balance": Decimal("200"), "state_version": "1.0"},
        )
        record = _make_record(decision)
        oracle.evaluate_record(record)


# ── Scenario 2: BLOCK — attestation must capture enforcement evidence ─────────


class TestBlockDecisionAttestation:
    def test_block_produces_attestation(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("2000"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert not decision.allowed

        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )

        assert isinstance(attestation, ComplianceAttestation)
        assert attestation.outcome == "BLOCKED"

    def test_block_attestation_maps_violated_controls(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("2000"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert not decision.allowed
        assert "within_daily_limit" in decision.violated_invariants

        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )

        enforced_ids = [
            r.control_id
            for fa in attestation.framework_results
            for r in fa.controls_enforced
        ]
        assert "CC6.1" in enforced_ids

    def test_block_attestation_has_controls_matched(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("9000"), "daily_limit": Decimal("500")},
            state={"balance": Decimal("100"), "state_version": "1.0"},
        )
        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )

        assert attestation.total_controls_matched > 0


# ── Scenario 3: ComplianceReporter integration ────────────────────────────────


class TestComplianceReporter:
    def test_reporter_generates_report_from_allow(self, guard: Guard) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("100"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        reporter = ComplianceReporter()
        report = reporter.generate(
            decision, policy_meta={"name": "TransferPolicy", "version": "1.0"}
        )

        assert report.verdict == "ALLOWED"
        assert report.policy_name == "TransferPolicy"

    def test_reporter_generates_report_from_block(self, guard: Guard) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("2000"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        reporter = ComplianceReporter()
        report = reporter.generate(
            decision, policy_meta={"name": "TransferPolicy", "version": "1.0"}
        )

        assert report.verdict == "BLOCKED"
        assert len(report.violated_rules) > 0

    def test_reporter_includes_regulatory_refs_for_known_invariants(
        self, guard: Guard
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("2000"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        reporter = ComplianceReporter(
            extra_refs={"within_daily_limit": ["SOC2 CC6.1", "Internal Risk §4.2"]}
        )
        report = reporter.generate(decision)

        assert any("SOC2 CC6.1" in ref for ref in report.regulatory_refs)

    def test_reporter_never_raises_on_minimal_decision(self, guard: Guard) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("1"), "daily_limit": Decimal("100")},
            state={"balance": Decimal("50"), "state_version": "1.0"},
        )
        reporter = ComplianceReporter()
        assert reporter.generate(decision) is not None


# ── Scenario 4: Full chain — Guard → ProvenanceRecord → Oracle → Reporter ─────


class TestFullChain:
    def test_full_allow_chain(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("100"), "daily_limit": Decimal("1000")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert decision.allowed

        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )
        reporter = ComplianceReporter()
        report = reporter.generate(
            decision, policy_meta={"name": "TransferPolicy", "version": "1.0"}
        )

        assert len(attestation.record_hmac_tag) > 0
        assert attestation.outcome == "ALLOWED"
        assert report.verdict == "ALLOWED"
        assert report.policy_name == "TransferPolicy"

    def test_full_block_chain(
        self, guard: Guard, oracle: ComplianceOracle
    ) -> None:
        decision = guard.verify(
            intent={"amount": Decimal("9999"), "daily_limit": Decimal("500")},
            state={"balance": Decimal("100"), "state_version": "1.0"},
        )
        assert not decision.allowed

        record = _make_record(decision)
        attestation = oracle.evaluate_record(
            record, decision_snapshot=decision.to_dict()
        )
        reporter = ComplianceReporter()
        report = reporter.generate(
            decision, policy_meta={"name": "TransferPolicy", "version": "1.0"}
        )

        assert attestation.outcome == "BLOCKED"
        assert attestation.total_controls_matched >= 1
        assert report.verdict == "BLOCKED"
        assert len(report.violated_rules) >= 1
