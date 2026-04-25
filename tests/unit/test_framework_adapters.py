# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for framework adapters: Haystack, SemanticKernel, PydanticAI (F-1)."""
from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import ConfigurationError, GuardViolationError


def _allowed_decision() -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="all good",
    )


def _blocked_decision() -> Decision:
    return Decision(
        allowed=False,
        status=SolverStatus.UNSAFE,
        violated_invariants=("overdraft",),
        explanation="overdraft detected",
    )


def _make_mock_guard(allowed: bool = True) -> MagicMock:
    guard = MagicMock()
    decision = _allowed_decision() if allowed else _blocked_decision()
    guard.verify = MagicMock(return_value=decision)
    guard.verify_async = AsyncMock(return_value=decision)
    return guard


# ── HaystackGuardedComponent ──────────────────────────────────────────────────


def test_haystack_import_no_haystack(monkeypatch: pytest.MonkeyPatch) -> None:
    """HaystackGuardedComponent can be imported even without haystack-ai."""
    if "pramanix.integrations.haystack" in sys.modules:
        del sys.modules["pramanix.integrations.haystack"]
    monkeypatch.setitem(sys.modules, "haystack", None)
    # Should not raise ConfigurationError — Haystack registration is graceful
    from pramanix.integrations.haystack import HaystackGuardedComponent  # noqa: F401


def test_haystack_run_allows_documents() -> None:
    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard = _make_mock_guard(allowed=True)
    comp = HaystackGuardedComponent(
        guard=guard,
        intent_extractor=lambda item: {"action": "read"},
        state_provider=lambda: {},
    )
    result = comp.run(documents=["doc1", "doc2"])
    assert "documents" in result
    assert len(result["documents"]) == 2
    assert result.get("blocked_documents", []) == []


def test_haystack_run_blocks_documents_on_violation() -> None:
    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard = _make_mock_guard(allowed=False)
    comp = HaystackGuardedComponent(
        guard=guard,
        intent_extractor=lambda item: {"action": "write"},
        state_provider=lambda: {},
        block_on_error=True,
    )
    result = comp.run(documents=["doc1"])
    assert result["documents"] == []
    assert len(result["blocked_documents"]) == 1


@pytest.mark.asyncio
async def test_haystack_run_async_allows() -> None:
    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard = _make_mock_guard(allowed=True)
    comp = HaystackGuardedComponent(
        guard=guard,
        intent_extractor=lambda item: {},
        state_provider=lambda: {},
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
        PramanixSemanticKernelPlugin(_make_mock_guard())


def test_sk_plugin_verify_returns_json() -> None:
    """verify() returns JSON string with allowed/status/explanation."""
    mock_sk = MagicMock()
    sys.modules.setdefault("semantic_kernel", mock_sk)
    sys.modules.setdefault("semantic_kernel.functions", mock_sk)

    if "pramanix.integrations.semantic_kernel" in sys.modules:
        del sys.modules["pramanix.integrations.semantic_kernel"]

    import json

    from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

    guard = _make_mock_guard(allowed=True)
    plugin = PramanixSemanticKernelPlugin(guard)
    result = plugin.verify('{"action": "read"}', '{}')
    parsed = json.loads(result)
    assert parsed["allowed"] is True


@pytest.mark.asyncio
async def test_sk_plugin_verify_async_returns_json() -> None:
    import json

    mock_sk = MagicMock()
    sys.modules.setdefault("semantic_kernel", mock_sk)
    sys.modules.setdefault("semantic_kernel.functions", mock_sk)

    if "pramanix.integrations.semantic_kernel" in sys.modules:
        del sys.modules["pramanix.integrations.semantic_kernel"]

    from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

    guard = _make_mock_guard(allowed=True)
    plugin = PramanixSemanticKernelPlugin(guard)
    result = await plugin.verify_async('{"action": "read"}', '{}')
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
        PramanixPydanticAIValidator(_make_mock_guard())


def test_pydantic_ai_check_allowed_returns_decision() -> None:
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    guard = _make_mock_guard(allowed=True)
    validator = PramanixPydanticAIValidator(guard)
    decision = validator.check({"action": "read"})
    assert decision.allowed is True


def test_pydantic_ai_check_blocked_raises_guard_violation() -> None:
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    guard = _make_mock_guard(allowed=False)
    validator = PramanixPydanticAIValidator(guard)
    with pytest.raises(GuardViolationError):
        validator.check({"action": "write"})


@pytest.mark.asyncio
async def test_pydantic_ai_check_async_allowed() -> None:
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    guard = _make_mock_guard(allowed=True)
    validator = PramanixPydanticAIValidator(guard)
    decision = await validator.check_async({"action": "read"})
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_pydantic_ai_check_async_blocked_raises() -> None:
    mock_pai = MagicMock()
    sys.modules.setdefault("pydantic_ai", mock_pai)

    if "pramanix.integrations.pydantic_ai" in sys.modules:
        del sys.modules["pramanix.integrations.pydantic_ai"]

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    guard = _make_mock_guard(allowed=False)
    validator = PramanixPydanticAIValidator(guard)
    with pytest.raises(GuardViolationError):
        await validator.check_async({"action": "write"})
