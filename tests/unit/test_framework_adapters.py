# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for framework adapters: Haystack, SemanticKernel, PydanticAI (F-1).

All tests use real Guard instances from tests.helpers.real_protocols.
Optional framework dependencies are gated with pytest.importorskip so these
tests only run against real installed packages.
"""

from __future__ import annotations

import pytest

from pramanix.exceptions import GuardViolationError
from tests.helpers.real_protocols import (
    ALLOW_INTENT,
    ALLOW_STATE,
    BLOCK_INTENT,
    make_allow_guard,
    make_block_guard,
)

# ── HaystackGuardedComponent ──────────────────────────────────────────────────


def test_haystack_run_allows_documents() -> None:
    """Documents pass through when the Guard issues an ALLOW decision."""
    pytest.importorskip("haystack")
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
    pytest.importorskip("haystack")
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
    pytest.importorskip("haystack")
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


def test_sk_plugin_verify_returns_json() -> None:
    """verify() returns JSON string with allowed/status/explanation (real Guard)."""
    pytest.importorskip("semantic_kernel")

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
    pytest.importorskip("semantic_kernel")
    import json

    from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

    plugin = PramanixSemanticKernelPlugin(make_allow_guard())
    result = await plugin.verify_async('{"amount": 1}', '{"state_version": "1.0"}')
    parsed = json.loads(result)
    assert parsed["allowed"] is True


# ── PramanixPydanticAIValidator ────────────────────────────────────────────────


def test_pydantic_ai_check_allowed_returns_decision() -> None:
    """check() returns the Decision on ALLOW (real Guard — Z3 verified)."""
    pytest.importorskip("pydantic_ai")

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(make_allow_guard())
    decision = validator.check(ALLOW_INTENT, state=ALLOW_STATE)
    assert decision.allowed is True


def test_pydantic_ai_check_blocked_raises_guard_violation() -> None:
    """check() raises GuardViolationError when Z3 finds a constraint violated."""
    pytest.importorskip("pydantic_ai")

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
    pytest.importorskip("pydantic_ai")

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(make_allow_guard())
    decision = await validator.check_async(ALLOW_INTENT, state=ALLOW_STATE)
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_pydantic_ai_check_async_blocked_raises() -> None:
    """check_async() raises GuardViolationError when Z3 blocks (async path)."""
    pytest.importorskip("pydantic_ai")

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(make_block_guard())
    with pytest.raises(GuardViolationError) as exc_info:
        await validator.check_async(BLOCK_INTENT, state=ALLOW_STATE)
    assert exc_info.value.decision.violated_invariants == ("above_threshold",)


# ── Optional-adapter import sanity on real dependencies ───────────────────────


def test_dspy_import_with_real_dependency() -> None:
    pytest.importorskip("dspy")
    from pramanix.integrations.dspy import PramanixGuardedModule  # noqa: F401


def test_fastapi_import_with_real_dependency() -> None:
    pytest.importorskip("starlette.middleware.base")
    from pramanix.integrations.fastapi import PramanixMiddleware  # noqa: F401
