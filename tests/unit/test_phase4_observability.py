# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Phase 4 Items 10 + 11: Policy observability metrics and W006 linter check.

Covers:
  pramanix_guard_decisions_total{policy, outcome} — incremented on every verify()
  pramanix_invariant_violations_total{policy, invariant} — incremented on BLOCK
  W006 lint warning — invariant missing .explain() call
"""

from __future__ import annotations

import json
import sys
import textwrap
from decimal import Decimal
from typing import Any

import pytest

from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Minimal real policy ───────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")


class _ObsPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:  # type: ignore[override]
        return {"amount": _amount}

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [(E(_amount) >= 0).named("non_negative").explain("Amount must be non-negative")]


# ── Prometheus counter helpers ────────────────────────────────────────────────


def _read_counter(metric_base_name: str, labels: dict[str, str]) -> float:
    """Read a labelset's value from the Prometheus registry."""
    from prometheus_client import REGISTRY

    for metric in REGISTRY.collect():
        if metric.name == metric_base_name:
            for sample in metric.samples:
                if sample.name.endswith("_total") and sample.labels == labels:
                    return sample.value
    return 0.0


# ── pramanix_guard_decisions_total ────────────────────────────────────────────


class TestGuardDecisionsCounter:
    """pramanix_guard_decisions_total increments on every verify() call."""

    @pytest.fixture
    def guard(self) -> Guard:
        return Guard(_ObsPolicy, GuardConfig(execution_mode="sync", audit_sinks=[]))

    def test_allow_increments_allow_outcome(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before = _read_counter("pramanix_guard_decisions", {"policy": policy_name, "outcome": "allow"})

        guard.verify(intent={"amount": Decimal("1.00")}, state={"state_version": "1.0"})

        after = _read_counter("pramanix_guard_decisions", {"policy": policy_name, "outcome": "allow"})
        assert after >= before + 1, (
            f"pramanix_guard_decisions_total{{outcome='allow'}} must increment on ALLOW "
            f"(before={before}, after={after})"
        )

    def test_block_increments_block_outcome(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before = _read_counter("pramanix_guard_decisions", {"policy": policy_name, "outcome": "block"})

        guard.verify(intent={"amount": Decimal("-1.00")}, state={"state_version": "1.0"})

        after = _read_counter("pramanix_guard_decisions", {"policy": policy_name, "outcome": "block"})
        assert after >= before + 1, (
            f"pramanix_guard_decisions_total{{outcome='block'}} must increment on BLOCK "
            f"(before={before}, after={after})"
        )

    def test_allow_does_not_increment_block(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before_block = _read_counter(
            "pramanix_guard_decisions", {"policy": policy_name, "outcome": "block"}
        )

        guard.verify(intent={"amount": Decimal("5.00")}, state={"state_version": "1.0"})

        after_block = _read_counter(
            "pramanix_guard_decisions", {"policy": policy_name, "outcome": "block"}
        )
        assert after_block == before_block, "ALLOW decision must not increment block counter"

    def test_multiple_calls_accumulate(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before = _read_counter("pramanix_guard_decisions", {"policy": policy_name, "outcome": "allow"})

        for _ in range(5):
            guard.verify(intent={"amount": Decimal("1.00")}, state={"state_version": "1.0"})

        after = _read_counter("pramanix_guard_decisions", {"policy": policy_name, "outcome": "allow"})
        assert after >= before + 5, (
            f"Counter must accumulate across calls: expected +5, got +{after - before}"
        )


# ── pramanix_invariant_violations_total ───────────────────────────────────────


class TestInvariantViolationsCounter:
    """pramanix_invariant_violations_total increments when an invariant is violated."""

    @pytest.fixture
    def guard(self) -> Guard:
        return Guard(_ObsPolicy, GuardConfig(execution_mode="sync", audit_sinks=[]))

    def test_violation_increments_counter(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before = _read_counter(
            "pramanix_invariant_violations",
            {"policy": policy_name, "invariant": "non_negative"},
        )

        guard.verify(intent={"amount": Decimal("-1.00")}, state={"state_version": "1.0"})

        after = _read_counter(
            "pramanix_invariant_violations",
            {"policy": policy_name, "invariant": "non_negative"},
        )
        assert after >= before + 1, (
            f"pramanix_invariant_violations_total{{invariant='non_negative'}} must increment "
            f"on BLOCK (before={before}, after={after})"
        )

    def test_allow_does_not_increment_violations(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before = _read_counter(
            "pramanix_invariant_violations",
            {"policy": policy_name, "invariant": "non_negative"},
        )

        guard.verify(intent={"amount": Decimal("10.00")}, state={"state_version": "1.0"})

        after = _read_counter(
            "pramanix_invariant_violations",
            {"policy": policy_name, "invariant": "non_negative"},
        )
        assert after == before, "ALLOW must not increment invariant violation counter"

    def test_multiple_violations_accumulate(self, guard: Guard) -> None:
        pytest.importorskip("prometheus_client")
        policy_name = _ObsPolicy.__name__
        before = _read_counter(
            "pramanix_invariant_violations",
            {"policy": policy_name, "invariant": "non_negative"},
        )

        for _ in range(3):
            guard.verify(intent={"amount": Decimal("-5.00")}, state={"state_version": "1.0"})

        after = _read_counter(
            "pramanix_invariant_violations",
            {"policy": policy_name, "invariant": "non_negative"},
        )
        assert after >= before + 3, (
            f"Violation counter must accumulate: expected +3, got +{after - before}"
        )


# ── W006 linter check ─────────────────────────────────────────────────────────


class TestLinterW006:
    """W006 warns when invariants lack .explain() calls."""

    def _lint(self, policy_source: str, *, strict: bool = False) -> list[dict[str, str]]:
        """Run lint-policy on a policy source string and return findings."""
        import importlib
        import importlib.util
        import pathlib
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(policy_source)
            tmp_path = pathlib.Path(tmp.name)

        try:
            from pramanix.cli import _lint_load_python_policy, _lint_policy_class

            findings: list[dict[str, str]] = []

            def _report(code: str, level: str, message: str) -> None:
                findings.append({"code": code, "level": level, "message": message})

            policy_cls = _lint_load_python_policy(tmp_path, None, _report)
            if policy_cls is not None:
                _lint_policy_class(policy_cls, _report)
            return findings
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_w006_emitted_when_explain_missing(self) -> None:
        """Invariant without .explain() must produce W006."""
        source = textwrap.dedent("""
            from decimal import Decimal
            from pramanix import E, Field, Policy

            _amount = Field("amount", Decimal, "Real")

            class TestPolicy(Policy):
                class Meta:
                    version = "1.0"

                @classmethod
                def fields(cls):
                    return {"amount": _amount}

                @classmethod
                def invariants(cls):
                    return [(E(_amount) >= 0).named("non_negative")]
        """)
        findings = self._lint(source)
        w006 = [f for f in findings if f["code"] == "W006"]
        assert w006, "Expected W006 when invariant has no .explain() call"
        assert "non_negative" in w006[0]["message"]
        assert "explain" in w006[0]["message"].lower()

    def test_no_w006_when_explain_present(self) -> None:
        """Invariant with .explain() must NOT produce W006."""
        source = textwrap.dedent("""
            from decimal import Decimal
            from pramanix import E, Field, Policy

            _amount = Field("amount", Decimal, "Real")

            class TestPolicy(Policy):
                class Meta:
                    version = "1.0"

                @classmethod
                def fields(cls):
                    return {"amount": _amount}

                @classmethod
                def invariants(cls):
                    return [
                        (E(_amount) >= 0).named("non_negative").explain("Amount must be >= 0")
                    ]
        """)
        findings = self._lint(source)
        w006 = [f for f in findings if f["code"] == "W006"]
        assert not w006, f"Expected no W006 when .explain() is present, got: {w006}"

    def test_w006_per_invariant(self) -> None:
        """Two invariants without explain: two W006 findings."""
        source = textwrap.dedent("""
            from decimal import Decimal
            from pramanix import E, Field, Policy

            _amount = Field("amount", Decimal, "Real")
            _limit = Field("limit", Decimal, "Real")

            class TestPolicy(Policy):
                class Meta:
                    version = "1.0"

                @classmethod
                def fields(cls):
                    return {"amount": _amount, "limit": _limit}

                @classmethod
                def invariants(cls):
                    return [
                        (E(_amount) >= 0).named("non_negative"),
                        (E(_amount) <= E(_limit)).named("within_limit"),
                    ]
        """)
        findings = self._lint(source)
        w006 = [f for f in findings if f["code"] == "W006"]
        assert len(w006) == 2, f"Expected 2 W006 findings for 2 unexplained invariants, got {len(w006)}"
        labels_mentioned = {f["message"] for f in w006}
        assert any("non_negative" in m for m in labels_mentioned)
        assert any("within_limit" in m for m in labels_mentioned)

    def test_w006_partial_explain(self) -> None:
        """Only invariants without .explain() produce W006; explained ones are clean."""
        source = textwrap.dedent("""
            from decimal import Decimal
            from pramanix import E, Field, Policy

            _amount = Field("amount", Decimal, "Real")
            _limit = Field("limit", Decimal, "Real")

            class TestPolicy(Policy):
                class Meta:
                    version = "1.0"

                @classmethod
                def fields(cls):
                    return {"amount": _amount, "limit": _limit}

                @classmethod
                def invariants(cls):
                    return [
                        (E(_amount) >= 0).named("non_negative").explain("Amount must be >= 0"),
                        (E(_amount) <= E(_limit)).named("within_limit"),
                    ]
        """)
        findings = self._lint(source)
        w006 = [f for f in findings if f["code"] == "W006"]
        assert len(w006) == 1, f"Expected exactly 1 W006 (for within_limit), got {len(w006)}"
        assert "within_limit" in w006[0]["message"]
