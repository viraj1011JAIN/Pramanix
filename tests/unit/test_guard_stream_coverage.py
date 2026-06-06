# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Tests for Guard.verify_stream() (GA-7) and Guard.coverage_report() (GA-13)."""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import AsyncIterator

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.expressions import E, Field
from pramanix.guard import Guard, PolicyCoverageReport
from pramanix.policy import Policy


# ── Minimal test policy ───────────────────────────────────────────────────────


class _AmountPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    limit = Field("limit", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) <= E(cls.limit)).named("within_limit"),
            (E(cls.amount) >= 0).named("non_negative"),
        ]


# ── Helper: async generator from list of strings ─────────────────────────────


async def _token_stream(tokens: list[str]) -> AsyncIterator[str]:
    for t in tokens:
        yield t


# ── verify_stream tests ───────────────────────────────────────────────────────


class TestVerifyStream:
    @pytest.fixture()
    def guard(self) -> Guard:
        return Guard(_AmountPolicy)

    @pytest.mark.asyncio
    async def test_stream_no_violation_yields_allow_at_end(self, guard: Guard) -> None:
        json_tokens = ['{"amount": 50', ', "limit": 100', "}"]
        results: list[tuple[str, Decision | None]] = []
        async for token, decision in guard.verify_stream(
            _token_stream(json_tokens), verify_every_n_tokens=100
        ):
            results.append((token, decision))

        # The final empty-token checkpoint should carry an ALLOW decision
        decisions = [d for _, d in results if d is not None]
        assert decisions, "Expected at least one Decision at stream end"
        assert decisions[-1].allowed

    @pytest.mark.asyncio
    async def test_stream_detects_violation_in_complete_json(self, guard: Guard) -> None:
        # amount > limit → violation
        json_tokens = ['{"amount": 200', ', "limit": 100', "}"]
        all_decisions: list[Decision] = []
        async for _token, decision in guard.verify_stream(
            _token_stream(json_tokens), verify_every_n_tokens=100
        ):
            if decision is not None:
                all_decisions.append(decision)

        assert all_decisions
        assert not all_decisions[-1].allowed
        assert "within_limit" in all_decisions[-1].violated_invariants

    @pytest.mark.asyncio
    async def test_stream_stops_after_block(self, guard: Guard) -> None:
        """Once a BLOCK is yielded the iterator must stop immediately."""
        tokens = ['{"amount": 999', ', "limit": 1', "}"]
        token_count = 0
        stream = guard.verify_stream(
            _token_stream(tokens), verify_every_n_tokens=100
        )
        try:
            async for _token, decision in stream:
                token_count += 1
                if decision is not None and not decision.allowed:
                    break
        finally:
            # Explicitly close the async generator to prevent
            # RuntimeWarning: coroutine 'aclose' was never awaited
            await stream.aclose()
        assert token_count >= 1

    @pytest.mark.asyncio
    async def test_partial_json_yields_none_for_decision(self, guard: Guard) -> None:
        """Incomplete JSON at checkpoint should yield decision=None (deferred)."""
        # Send 20 tokens that don't yet form valid JSON, trigger checkpoint
        tokens = ['{"amount": '] + ["x"] * 19  # 20 tokens, invalid JSON
        decisions = []
        async for _token, decision in guard.verify_stream(
            _token_stream(tokens), verify_every_n_tokens=20
        ):
            if decision is not None:
                decisions.append(decision)
        # All None because JSON is never valid
        assert not decisions

    @pytest.mark.asyncio
    async def test_max_tokens_exceeded_returns_block(self, guard: Guard) -> None:
        """Exceeding max_tokens must yield a blocking Decision and stop."""

        async def _infinite() -> AsyncIterator[str]:
            while True:
                yield "x"

        block_decision = None
        count = 0
        stream = guard.verify_stream(_infinite(), max_tokens=5, verify_every_n_tokens=100)
        try:
            async for _token, decision in stream:
                count += 1
                if decision is not None:
                    block_decision = decision
                    break
        finally:
            await stream.aclose()

        assert block_decision is not None
        assert not block_decision.allowed
        assert count <= 7  # stopped shortly after max

    @pytest.mark.asyncio
    async def test_stream_with_pydantic_state(self, guard: Guard) -> None:
        from pydantic import BaseModel

        class State(BaseModel):
            extra: str = "ok"

        tokens = ['{"amount": 10', ', "limit": 50', "}"]
        decisions = []
        async for _, d in guard.verify_stream(
            _token_stream(tokens), state=State(), verify_every_n_tokens=100
        ):
            if d is not None:
                decisions.append(d)
        assert decisions[-1].allowed

    @pytest.mark.asyncio
    async def test_empty_stream_yields_nothing(self, guard: Guard) -> None:
        results = []
        async for item in guard.verify_stream(_token_stream([]), verify_every_n_tokens=10):
            results.append(item)
        assert results == []


# ── coverage_report tests ─────────────────────────────────────────────────────


class TestCoverageReport:
    @pytest.fixture()
    def guard(self) -> Guard:
        return Guard(_AmountPolicy)

    def _allow(self, guard: Guard) -> None:
        guard.verify(intent={"amount": Decimal("10"), "limit": Decimal("100")}, state={})

    def _block_within_limit(self, guard: Guard) -> None:
        guard.verify(intent={"amount": Decimal("200"), "limit": Decimal("100")}, state={})

    def _block_negative(self, guard: Guard) -> None:
        guard.verify(intent={"amount": Decimal("-1"), "limit": Decimal("100")}, state={})

    def test_initial_report_zero_verifications(self, guard: Guard) -> None:
        report = guard.coverage_report()
        assert report.total_verifications == 0
        assert report.coverage_pct == 0.0

    def test_report_is_policy_coverage_report(self, guard: Guard) -> None:
        report = guard.coverage_report()
        assert isinstance(report, PolicyCoverageReport)

    def test_policy_name_populated(self, guard: Guard) -> None:
        report = guard.coverage_report()
        assert report.policy_name == "_AmountPolicy"

    def test_declared_invariants_listed(self, guard: Guard) -> None:
        report = guard.coverage_report()
        assert "within_limit" in report.declared_invariants
        assert "non_negative" in report.declared_invariants

    def test_total_verifications_increments(self, guard: Guard) -> None:
        self._allow(guard)
        self._allow(guard)
        report = guard.coverage_report()
        assert report.total_verifications == 2

    def test_violation_counted_after_block(self, guard: Guard) -> None:
        self._block_within_limit(guard)
        report = guard.coverage_report()
        assert report.invariant_violations["within_limit"] >= 1

    def test_fields_seen_populated(self, guard: Guard) -> None:
        self._allow(guard)
        report = guard.coverage_report()
        assert "amount" in report.fields_seen
        assert "limit" in report.fields_seen

    def test_coverage_pct_100_when_all_violated(self, guard: Guard) -> None:
        self._block_within_limit(guard)
        self._block_negative(guard)
        report = guard.coverage_report()
        assert report.coverage_pct == 100.0

    def test_coverage_pct_50_when_half_violated(self, guard: Guard) -> None:
        self._block_within_limit(guard)
        # Only 1 of 2 invariants violated
        report = guard.coverage_report()
        assert report.coverage_pct == 50.0

    def test_to_dict_serialisable(self, guard: Guard) -> None:
        import json

        self._allow(guard)
        d = guard.coverage_report().to_dict()
        # Must be JSON-serialisable
        json.dumps(d)
        assert "policy_name" in d
        assert "coverage_pct" in d
        assert "uncovered_invariants" in d
        assert "unseen_fields" in d

    def test_unseen_fields_listed(self, guard: Guard) -> None:
        report = guard.coverage_report()
        # No verifications yet — all fields are unseen
        assert "amount" in report.to_dict()["unseen_fields"]

    def test_allow_does_not_increment_violation_counters(self, guard: Guard) -> None:
        self._allow(guard)
        report = guard.coverage_report()
        for label, count in report.invariant_violations.items():
            assert count == 0, f"Expected zero violations on ALLOW, got {count} for {label}"

    def test_multiple_guards_independent_counters(self) -> None:
        guard_a = Guard(_AmountPolicy)
        guard_b = Guard(_AmountPolicy)

        guard_a.verify(intent={"amount": Decimal("200"), "limit": Decimal("100")}, state={})
        # guard_b untouched
        report_a = guard_a.coverage_report()
        report_b = guard_b.coverage_report()
        assert report_a.total_verifications == 1
        assert report_b.total_verifications == 0

    def test_policy_hash_non_empty(self, guard: Guard) -> None:
        report = guard.coverage_report()
        assert report.policy_hash
        assert len(report.policy_hash) == 64  # SHA-256 hex


# ── translator factory routing (GA-9 / GA-10) ────────────────────────────────


class TestTranslatorFactoryRouting:
    def test_bedrock_prefix_routes_to_bedrock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(__import__("sys").modules, "boto3", None)
        from pramanix.exceptions import ConfigurationError
        from pramanix.translator.redundant import create_translator

        with pytest.raises((ConfigurationError, ImportError)):
            create_translator("bedrock:anthropic.claude-3-5-sonnet-20241022-v2:0")

    def test_vertexai_prefix_routes_to_vertexai(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(__import__("sys").modules, "vertexai", None)
        from pramanix.exceptions import ConfigurationError
        from pramanix.translator.redundant import create_translator

        with pytest.raises((ConfigurationError, ImportError)):
            create_translator("vertexai:gemini-1.5-pro-001")

    def test_unknown_prefix_raises(self) -> None:
        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.redundant import create_translator

        with pytest.raises(ExtractionFailureError, match="Cannot infer"):
            create_translator("unknownprovider:model-x")

    def test_bedrock_in_error_message(self) -> None:
        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.redundant import create_translator

        try:
            create_translator("unsupported:xyz")
        except ExtractionFailureError as exc:
            assert "bedrock:" in str(exc)
            assert "vertexai:" in str(exc)
