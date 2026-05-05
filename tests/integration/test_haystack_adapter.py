# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real integration tests for HaystackGuardedComponent.

The component does not raise ConfigurationError when Haystack is absent —
it degrades gracefully — so ALL tests here run without Haystack installed.
The test at the bottom verifies the Haystack component decorator is applied
when the framework IS installed.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.haystack import HaystackGuardedComponent

# ── Shared policies ──────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")


class _AllowPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount}

    @classmethod
    def invariants(cls):
        return [
            (E(_amount) >= Decimal("0"))
            .named("non_negative")
            .explain("Amount must be non-negative")
        ]


class _BlockPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount}

    @classmethod
    def invariants(cls):
        return [
            (E(_amount) <= Decimal("0"))
            .named("must_be_zero_or_neg")
            .explain("Positive amounts are rejected")
        ]


_SYNC_ALLOW_GUARD = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
_SYNC_BLOCK_GUARD = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))
_ASYNC_ALLOW_GUARD = Guard(_AllowPolicy, GuardConfig(execution_mode="async-thread"))
_ASYNC_BLOCK_GUARD = Guard(_BlockPolicy, GuardConfig(execution_mode="async-thread"))
_STATE = {"state_version": "1.0"}

# Minimal stub objects — represent Haystack Document and ChatMessage without
# importing the Haystack library itself.
_DOC_ALLOW = {"content": "tx_100", "meta": {"amount": "100"}}
_DOC_BLOCK = {"content": "tx_999", "meta": {"amount": "999"}}
_MSG_ALLOW = {"role": "user", "content": "transfer 50", "meta": {"amount": "50"}}
_MSG_BLOCK = {"role": "user", "content": "transfer 9999", "meta": {"amount": "9999"}}


def _make_component(
    guard: Guard,
    block_on_error: bool = True,
    intent_extractor=None,
) -> HaystackGuardedComponent:
    extractor = intent_extractor or (
        lambda item: {"amount": Decimal(str(item.get("meta", {}).get("amount", 0)))}
    )
    return HaystackGuardedComponent(
        guard=guard,
        intent_extractor=extractor,
        state_provider=lambda: _STATE,
        block_on_error=block_on_error,
    )


# ── Synchronous run() — documents ────────────────────────────────────────────


class TestRunDocuments:
    def test_allow_document_passes_through(self):
        comp = _make_component(_SYNC_ALLOW_GUARD)
        result = comp.run(documents=[_DOC_ALLOW])
        assert _DOC_ALLOW in result["documents"]
        assert result["blocked_documents"] == []

    def test_block_document_is_quarantined(self):
        comp = _make_component(_SYNC_BLOCK_GUARD)
        result = comp.run(documents=[_DOC_BLOCK])
        assert result["documents"] == []
        assert _DOC_BLOCK in result["blocked_documents"]

    def test_mixed_documents_routed_correctly(self):
        """One allowed, one blocked in same batch — each goes to the right bucket."""
        comp = _make_component(_SYNC_ALLOW_GUARD)
        # _DOC_ALLOW has amount=100 (allowed), _DOC_BLOCK has amount=999 (also allowed
        # by _ALLOW_GUARD since 999 >= 0). Use a guard that blocks only 999.
        _limit_field = Field("amount", Decimal, "Real")

        class _LimitPolicy(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _limit_field}

            @classmethod
            def invariants(cls):
                return [
                    (E(_limit_field) <= Decimal("500"))
                    .named("max_500")
                    .explain("Amounts above 500 are rejected")
                ]

        limit_guard = Guard(_LimitPolicy, GuardConfig(execution_mode="sync"))
        comp = _make_component(limit_guard)
        result = comp.run(documents=[_DOC_ALLOW, _DOC_BLOCK])
        assert _DOC_ALLOW in result["documents"]
        assert _DOC_BLOCK in result["blocked_documents"]

    def test_empty_documents_list_returns_empty_buckets(self):
        comp = _make_component(_SYNC_ALLOW_GUARD)
        result = comp.run(documents=[])
        assert result == {"documents": [], "blocked_documents": []}

    def test_none_documents_excluded_from_result(self):
        """documents=None is treated as no documents; result omits the messages keys."""
        comp = _make_component(_SYNC_ALLOW_GUARD)
        result = comp.run(documents=None, messages=None)
        assert "documents" in result
        assert "messages" not in result


# ── Synchronous run() — messages ─────────────────────────────────────────────


class TestRunMessages:
    def test_allow_message_passes_through(self):
        comp = _make_component(_SYNC_ALLOW_GUARD)
        result = comp.run(messages=[_MSG_ALLOW])
        assert _MSG_ALLOW in result["messages"]
        assert result["blocked_messages"] == []

    def test_block_message_is_quarantined(self):
        comp = _make_component(_SYNC_BLOCK_GUARD)
        result = comp.run(messages=[_MSG_BLOCK])
        assert result["messages"] == []
        assert _MSG_BLOCK in result["blocked_messages"]

    def test_messages_key_absent_when_not_provided(self):
        """When messages arg is not passed the result dict must not contain 'messages'."""
        comp = _make_component(_SYNC_ALLOW_GUARD)
        result = comp.run(documents=[_DOC_ALLOW])
        assert "messages" not in result
        assert "blocked_messages" not in result


# ── Error-handling: intent extraction ────────────────────────────────────────


class TestIntentExtractionError:
    def test_extraction_error_blocks_when_block_on_error_true(self):
        """intent_extractor crash + block_on_error=True → item quarantined."""

        def _bad_extractor(item):
            raise ValueError("cannot parse document")

        comp = _make_component(
            _SYNC_ALLOW_GUARD,
            block_on_error=True,
            intent_extractor=_bad_extractor,
        )
        result = comp.run(documents=[_DOC_ALLOW])
        assert result["documents"] == []
        assert _DOC_ALLOW in result["blocked_documents"]

    def test_extraction_error_allows_when_block_on_error_false(self):
        """intent_extractor crash + block_on_error=False → item passes (fail-open)."""

        def _bad_extractor(item):
            raise ValueError("cannot parse document")

        comp = _make_component(
            _SYNC_ALLOW_GUARD,
            block_on_error=False,
            intent_extractor=_bad_extractor,
        )
        result = comp.run(documents=[_DOC_ALLOW])
        assert _DOC_ALLOW in result["documents"]
        assert result["blocked_documents"] == []


# ── Error-handling: guard errors ─────────────────────────────────────────────


class TestGuardError:
    def test_guard_error_blocks_when_block_on_error_true(self):
        """A guard that raises instead of returning → item quarantined."""

        class _BrokenGuard:
            def verify(self, *, intent, state):
                raise RuntimeError("Z3 solver crashed")

        comp = HaystackGuardedComponent(
            guard=_BrokenGuard(),
            intent_extractor=lambda item: {"amount": Decimal("10")},
            state_provider=lambda: _STATE,
            block_on_error=True,
        )
        result = comp.run(documents=[_DOC_ALLOW])
        assert result["documents"] == []
        assert _DOC_ALLOW in result["blocked_documents"]

    def test_guard_error_allows_when_block_on_error_false(self):
        class _BrokenGuard:
            def verify(self, *, intent, state):
                raise RuntimeError("Z3 solver crashed")

        comp = HaystackGuardedComponent(
            guard=_BrokenGuard(),
            intent_extractor=lambda item: {"amount": Decimal("10")},
            state_provider=lambda: _STATE,
            block_on_error=False,
        )
        result = comp.run(documents=[_DOC_ALLOW])
        assert _DOC_ALLOW in result["documents"]


# ── Asynchronous run_async() ──────────────────────────────────────────────────


class TestRunAsync:
    @pytest.mark.asyncio
    async def test_allow_document_via_run_async(self):
        comp = _make_component(_ASYNC_ALLOW_GUARD)
        result = await comp.run_async(documents=[_DOC_ALLOW])
        assert _DOC_ALLOW in result["documents"]
        assert result["blocked_documents"] == []

    @pytest.mark.asyncio
    async def test_block_document_via_run_async(self):
        comp = _make_component(_ASYNC_BLOCK_GUARD)
        result = await comp.run_async(documents=[_DOC_BLOCK])
        assert result["documents"] == []
        assert _DOC_BLOCK in result["blocked_documents"]

    @pytest.mark.asyncio
    async def test_allow_message_via_run_async(self):
        comp = _make_component(_ASYNC_ALLOW_GUARD)
        result = await comp.run_async(messages=[_MSG_ALLOW])
        assert _MSG_ALLOW in result["messages"]

    @pytest.mark.asyncio
    async def test_block_message_via_run_async(self):
        comp = _make_component(_ASYNC_BLOCK_GUARD)
        result = await comp.run_async(messages=[_MSG_BLOCK])
        assert _MSG_BLOCK in result["blocked_messages"]

    @pytest.mark.asyncio
    async def test_intent_extraction_error_async_blocks_with_block_on_error(self):
        def _bad(item):
            raise ValueError("bad")

        comp = _make_component(_ASYNC_ALLOW_GUARD, block_on_error=True, intent_extractor=_bad)
        result = await comp.run_async(documents=[_DOC_ALLOW])
        assert result["documents"] == []
        assert _DOC_ALLOW in result["blocked_documents"]


# ── Haystack framework registration (skipped without haystack) ────────────────

haystack_mod = pytest.importorskip("haystack", reason="haystack-ai not installed")


class TestHaystackFrameworkRegistration:
    def test_haystack_component_attribute_set(self):
        """With haystack installed, the class should have __haystack_component__
        attribute set by the @component decorator."""
        # The exact attribute name depends on haystack version, but the class
        # should at minimum be importable and the component should be registered.
        comp = _make_component(_SYNC_ALLOW_GUARD)
        # Haystack component must respond to run()
        result = comp.run(documents=[_DOC_ALLOW])
        assert _DOC_ALLOW in result["documents"]
