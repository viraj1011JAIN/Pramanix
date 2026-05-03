# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for framework adapters: Haystack, SemanticKernel, PydanticAI (F-1).

All tests use real Guard instances from tests.helpers.real_protocols.
The only MagicMock usage is for sys.modules stubs to simulate absent optional
SDK packages (semantic_kernel, pydantic_ai) — these stub the import boundary,
not any Pramanix behaviour.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from pramanix.exceptions import ConfigurationError, GuardViolationError

from tests.helpers.real_protocols import (
    ALLOW_INTENT,
    ALLOW_STATE,
    BLOCK_INTENT,
    make_allow_guard,
    make_block_guard,
)


# ── HaystackGuardedComponent ──────────────────────────────────────────────────


def test_haystack_import_no_haystack(monkeypatch: pytest.MonkeyPatch) -> None:
    """HaystackGuardedComponent can be imported even without haystack-ai."""
    if "pramanix.integrations.haystack" in sys.modules:
        del sys.modules["pramanix.integrations.haystack"]
    monkeypatch.setitem(sys.modules, "haystack", None)
    # Should not raise ConfigurationError — Haystack registration is graceful
    from pramanix.integrations.haystack import HaystackGuardedComponent  # noqa: F401


def test_haystack_run_allows_documents() -> None:
    """Documents pass through when the Guard issues an ALLOW decision."""
    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard = make_allow_guard()
    comp = HaystackGuardedComponent(
        guard=guard,
        intent_extractor=lambda _item: ALLOW_INTENT,
        state_provider=lambda: ALLOW_STATE,
    )
    result = comp.run(documents=["doc1", "doc2"])
    assert "documents" in result
    assert len(result["documents"]) == 2
    assert result.get("blocked_documents", []) == []


def test_haystack_run_blocks_documents_on_violation() -> None:
    """Documents are blocked when the Guard issues a BLOCK decision."""
    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard = make_block_guard()
    comp = HaystackGuardedComponent(
        guard=guard,
        intent_extractor=lambda _item: BLOCK_INTENT,
        state_provider=lambda: ALLOW_STATE,
        block_on_error=True,
    )
    result = comp.run(documents=["doc1"])
    assert result["documents"] == []
    assert len(result["blocked_documents"]) == 1


@pytest.mark.asyncio
async def test_haystack_run_async_allows() -> None:
    """Async run_async passes documents through on ALLOW."""
    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard = make_allow_guard()
    comp = HaystackGuardedComponent(
        guard=guard,
        intent_extractor=lambda _item: ALLOW_INTENT,
        state_provider=lambda: ALLOW_STATE,
    )
    result = await comp.run_async(documents=["doc"])
    assert len(result["documents"]) == 1


# ── PramanixSemanticKernelPlugin ───────────────────────────────────────────────


def test_sk_raises_config_error_without_semantic_kernel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "semantic_kernel", None)
    if "pramanix.integrations.semantic_kernel" in sys.modules:
        del sys.modules["pramanix.integrations.semantic_kernel"]
    with pytest.raises(ConfigurationError, match=r"semantic-kernel"):
        from pramanix.integrations.semantic_kernel import (
            PramanixSemanticKernelPlugin,
        )
        PramanixSemanticKernelPlugin(make_allow_guard())


def test_sk_plugin_verify_returns_json() -> None:
    """verify() returns JSON string with allowed/status/explanation (real Guard)."""
    mock_sk = MagicMock()
    sys.modules.setdefault("semantic_kernel", mock_sk)
    sys.modules.setdefault("semantic_kernel.functions", mock_sk)

    if "pramanix.integrations.semantic_kernel" in sys.modules:
        del sys.modules["pramanix.integrations.semantic_kernel"]

    import json

    from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

    # amount=1 satisfies the allow-guard invariant (amount >= 0)
    plugin = PramanixSemanticKernelPlugin(make_allow_guard())
    result = plugin.verify('{"amount": 1}', '{"state_version": "1.0"}')
    parsed = json.loads(result)
    assert parsed["allowed"] is True
    assert "status" in parsed


@pytest.mark.asyncio
async def test_sk_plugin_verify_async_returns_json() -> None:
    """verify_async() exercises the real async Guard path."""
    import json

    mock_sk = MagicMock()
    sys.modules.setdefault("semantic_kernel", mock_sk)
    sys.modules.setdefault("semantic_kernel.functions", mock_sk)

    if "pramanix.integrations.semantic_kernel" in sys.modules:
        del sys.modules["pramanix.integrations.semantic_kernel"]

    from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

    plugin = PramanixSemanticKernelPlugin(make_allow_guard())
    result = await plugin.verify_async('{"amount": 1}', '{"state_version": "1.0"}')
    parsed = json.loads(result)
    assert parsed["allowed"] is True


# ── PramanixPydanticAIValidator ────────────────────────────────────────────────


def test_pydantic_ai_raises_config_error_without_pydantic_ai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "pydantic_ai", None)
    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]
    with pytest.raises(ConfigurationError, match=r"pydantic-ai"):
        from pramanix.integrations.pydantic_ai import (
            PramanixPydanticAIValidator,
        )
        PramanixPydanticAIValidator(make_allow_guard())


def test_pydantic_ai_check_allowed_returns_decision() -> None:
    """check() returns the Decision on ALLOW (real Guard — Z3 verified)."""
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(make_allow_guard())
    decision = validator.check(ALLOW_INTENT, state=ALLOW_STATE)
    assert decision.allowed is True


def test_pydantic_ai_check_blocked_raises_guard_violation() -> None:
    """check() raises GuardViolationError when Z3 finds a constraint violated."""
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    # BLOCK_INTENT has amount=1, which violates block guard's "amount > 9999"
    validator = PramanixPydanticAIValidator(make_block_guard())
    with pytest.raises(GuardViolationError) as exc_info:
        validator.check(BLOCK_INTENT, state=ALLOW_STATE)
    # Verify the violation is Z3-attributed, not a validation error
    assert exc_info.value.decision.violated_invariants == ("above_threshold",)


@pytest.mark.asyncio
async def test_pydantic_ai_check_async_allowed() -> None:
    """check_async() exercises the real async Guard path with ALLOW result."""
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(make_allow_guard())
    decision = await validator.check_async(ALLOW_INTENT, state=ALLOW_STATE)
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_pydantic_ai_check_async_blocked_raises() -> None:
    """check_async() raises GuardViolationError when Z3 blocks (async path)."""
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(make_block_guard())
    with pytest.raises(GuardViolationError) as exc_info:
        await validator.check_async(BLOCK_INTENT, state=ALLOW_STATE)
    assert exc_info.value.decision.violated_invariants == ("above_threshold",)
