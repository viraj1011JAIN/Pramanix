# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real integration tests for PramanixSemanticKernelPlugin.

Without semantic-kernel installed: verifies that __init__ raises
ConfigurationError immediately (fail-fast contract).

With semantic-kernel installed (pytest.importorskip): exercises verify()
and verify_async() with real Guard verifications and JSON response parsing.
"""
from __future__ import annotations

import json
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import ConfigurationError
from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

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


_STATE = {"state_version": "1.0"}
_ALLOW_INTENT = json.dumps({"amount": "100"})
_BLOCK_INTENT = json.dumps({"amount": "500"})
_STATE_JSON = json.dumps(_STATE)


# ── Fail-fast contract (always runs, even without semantic-kernel) ─────────────

class TestConfigurationErrorWithoutFramework:
    def test_init_raises_configuration_error_when_sk_absent(self):
        """If semantic-kernel is not installed PramanixSemanticKernelPlugin.__init__
        must raise ConfigurationError immediately — before any guard logic runs."""
        try:
            import semantic_kernel  # noqa: F401
            pytest.skip("semantic-kernel is installed; skip absence test")
        except ImportError:
            pass

        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
        with pytest.raises(ConfigurationError, match="semantic-kernel"):
            PramanixSemanticKernelPlugin(guard=guard)

    def test_configuration_error_message_contains_install_hint(self):
        """The error message must include the pip install hint for self-diagnosis."""
        try:
            import semantic_kernel  # noqa: F401
            pytest.skip("semantic-kernel is installed; skip absence test")
        except ImportError:
            pass

        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
        with pytest.raises(ConfigurationError) as exc_info:
            PramanixSemanticKernelPlugin(guard=guard)
        assert "pip install" in str(exc_info.value)


# ── semantic-kernel present — full functionality tests ────────────────────────

import importlib.util as _ilu
_SK_AVAILABLE = _ilu.find_spec("semantic_kernel") is not None

_skip_without_sk = pytest.mark.skipif(
    not _SK_AVAILABLE,
    reason="semantic-kernel not installed"
)


@pytest.fixture
def allow_plugin():
    guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
    return PramanixSemanticKernelPlugin(guard=guard)


@pytest.fixture
def block_plugin():
    guard = Guard(_BlockPolicy, GuardConfig(execution_mode="sync"))
    return PramanixSemanticKernelPlugin(guard=guard)


@pytest.fixture
def async_allow_plugin():
    guard = Guard(_AllowPolicy, GuardConfig(execution_mode="async-thread"))
    return PramanixSemanticKernelPlugin(guard=guard)


@pytest.fixture
def async_block_plugin():
    guard = Guard(_BlockPolicy, GuardConfig(execution_mode="async-thread"))
    return PramanixSemanticKernelPlugin(guard=guard)


@_skip_without_sk
class TestVerifySync:
    def test_allow_returns_valid_json(self, allow_plugin):
        """ALLOW path → verify() returns parseable JSON with allowed=True."""
        result_str = allow_plugin.verify(_ALLOW_INTENT, _STATE_JSON)
        result = json.loads(result_str)
        assert result["allowed"] is True

    def test_allow_result_contains_all_required_keys(self, allow_plugin):
        """Response must include allowed, status, explanation, violated_invariants."""
        result = json.loads(allow_plugin.verify(_ALLOW_INTENT, _STATE_JSON))
        assert "allowed" in result
        assert "status" in result
        assert "explanation" in result
        assert "violated_invariants" in result

    def test_allow_violated_invariants_empty_on_allow(self, allow_plugin):
        result = json.loads(allow_plugin.verify(_ALLOW_INTENT, _STATE_JSON))
        assert result["violated_invariants"] == []

    def test_block_returns_valid_json(self, block_plugin):
        """BLOCK path → verify() returns parseable JSON with allowed=False."""
        result_str = block_plugin.verify(_BLOCK_INTENT, _STATE_JSON)
        result = json.loads(result_str)
        assert result["allowed"] is False

    def test_block_violated_invariants_non_empty(self, block_plugin):
        """Blocked decision must carry the names of violated invariants."""
        result = json.loads(block_plugin.verify(_BLOCK_INTENT, _STATE_JSON))
        assert len(result["violated_invariants"]) >= 1

    def test_block_status_reflects_rejection(self, block_plugin):
        result = json.loads(block_plugin.verify(_BLOCK_INTENT, _STATE_JSON))
        # status should be a non-empty string indicating rejection
        assert isinstance(result["status"], str)
        assert result["status"]

    def test_default_state_json_empty_object(self, allow_plugin):
        """state_json defaults to '{}'; verify() must work without explicit state."""
        result = json.loads(allow_plugin.verify(_ALLOW_INTENT))
        assert "allowed" in result

    def test_invalid_intent_json_returns_error_response(self, allow_plugin):
        """Malformed intent JSON → error JSON with allowed=False, no exception raised."""
        result_str = allow_plugin.verify("NOT VALID JSON{{{")
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert "error" in result

    def test_invalid_state_json_returns_error_response(self, allow_plugin):
        """Malformed state JSON → error JSON with allowed=False."""
        result_str = allow_plugin.verify(_ALLOW_INTENT, "BAD STATE JSON")
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert "error" in result

    def test_empty_intent_json_returns_structured_response(self, allow_plugin):
        """Empty intent dict → Guard evaluates against defaults; must return JSON."""
        result_str = allow_plugin.verify("{}", _STATE_JSON)
        result = json.loads(result_str)
        assert "allowed" in result

    def test_custom_plugin_name_stored(self):
        """plugin_name kwarg is stored and accessible."""
        guard = Guard(_AllowPolicy, GuardConfig(execution_mode="sync"))
        plugin = PramanixSemanticKernelPlugin(guard=guard, plugin_name="my_guard")
        assert plugin._plugin_name == "my_guard"

    def test_default_plugin_name(self, allow_plugin):
        assert allow_plugin._plugin_name == "pramanix_guard"


@_skip_without_sk
class TestVerifyAsync:
    @pytest.mark.asyncio
    async def test_allow_async_returns_valid_json(self, async_allow_plugin):
        """verify_async() ALLOW path → parseable JSON with allowed=True."""
        result_str = await async_allow_plugin.verify_async(_ALLOW_INTENT, _STATE_JSON)
        result = json.loads(result_str)
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_block_async_returns_valid_json(self, async_block_plugin):
        """verify_async() BLOCK path → parseable JSON with allowed=False."""
        result_str = await async_block_plugin.verify_async(_BLOCK_INTENT, _STATE_JSON)
        result = json.loads(result_str)
        assert result["allowed"] is False

    @pytest.mark.asyncio
    async def test_async_invalid_json_returns_error(self, async_allow_plugin):
        """verify_async() with malformed JSON → error JSON, no exception raised."""
        result_str = await async_allow_plugin.verify_async("{{INVALID}}")
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_async_violated_invariants_on_block(self, async_block_plugin):
        result = json.loads(await async_block_plugin.verify_async(_BLOCK_INTENT, _STATE_JSON))
        assert len(result["violated_invariants"]) >= 1

    @pytest.mark.asyncio
    async def test_sync_and_async_agree_on_decision(self, allow_plugin, async_allow_plugin):
        """Sync and async paths must produce the same allowed outcome for same input."""
        sync_result = json.loads(allow_plugin.verify(_ALLOW_INTENT, _STATE_JSON))
        async_result = json.loads(await async_allow_plugin.verify_async(_ALLOW_INTENT, _STATE_JSON))
        assert sync_result["allowed"] == async_result["allowed"]


class TestGuardErrorHandling:
    def test_guard_error_returns_error_json(self):
        """When the Guard raises an exception verify() returns error JSON, never re-raises."""
        class _BrokenGuard:
            def verify(self, *, intent, state):
                raise RuntimeError("Z3 solver internal error")

        # Bypass the __init__ framework check by constructing manually
        plugin = object.__new__(PramanixSemanticKernelPlugin)
        plugin._guard = _BrokenGuard()
        plugin._plugin_name = "test"

        result_str = plugin.verify(_ALLOW_INTENT, _STATE_JSON)
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_async_guard_error_returns_error_json(self):
        """verify_async() guard exception → error JSON, never re-raises."""
        class _BrokenGuard:
            async def verify_async(self, *, intent, state):
                raise RuntimeError("async solver crash")

        plugin = object.__new__(PramanixSemanticKernelPlugin)
        plugin._guard = _BrokenGuard()
        plugin._plugin_name = "test"

        result_str = await plugin.verify_async(_ALLOW_INTENT, _STATE_JSON)
        result = json.loads(result_str)
        assert result["allowed"] is False
        assert "error" in result
