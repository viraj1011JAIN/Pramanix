# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for AnthropicTranslator — all API calls mocked.

Coverage targets
----------------
* Success path: valid response with text block → parsed dict
* APIStatusError (4xx/5xx) → ExtractionFailureError
* Retryable timeout (APITimeoutError) exhausted → LLMTimeoutError
* Retryable connection error (APIConnectionError) exhausted → LLMTimeoutError
* No text content in response → ExtractionFailureError
* anthropic package not installed → ImportError
* tenacity package not installed → ImportError
* API key from env var (ANTHROPIC_API_KEY)
* Markdown-wrapped JSON content extracted correctly
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator.anthropic import AnthropicTranslator

# ── Minimal intent schema ─────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: float
    recipient: str


# ── Mock Anthropic SDK helpers ────────────────────────────────────────────────


def _make_content_block(text: str) -> MagicMock:
    block = MagicMock()
    block.text = text
    return block


def _make_anthropic_response(text: str) -> MagicMock:
    """Build a mock anthropic.Message with a single text content block."""
    resp = MagicMock()
    resp.content = [_make_content_block(text)]
    return resp


def _make_anthropic_module(response: MagicMock | None = None) -> MagicMock:
    """Return a mock anthropic module wired for success or customisable failure."""

    mod = MagicMock()

    # Build the AsyncAnthropic client mock
    client = MagicMock()
    client.messages = MagicMock()
    if response is not None:
        client.messages.create = AsyncMock(return_value=response)
    mod.AsyncAnthropic.return_value = client

    # Exception classes — must be real exception types for except clauses
    class _APITimeoutError(Exception):
        pass

    class _APIConnectionError(Exception):
        pass

    class _APIStatusError(Exception):
        def __init__(self, msg: str, *, status_code: int = 400, body: str = "") -> None:
            super().__init__(msg)
            self.status_code = status_code
            self.message = msg

    mod.APITimeoutError = _APITimeoutError
    mod.APIConnectionError = _APIConnectionError
    mod.APIStatusError = _APIStatusError

    return mod


# ═══════════════════════════════════════════════════════════════════════════════
# Construction
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorConstruction:
    def test_default_timeout(self) -> None:
        t = AnthropicTranslator("claude-opus-4-6")
        assert t._timeout == 30.0

    def test_custom_timeout(self) -> None:
        t = AnthropicTranslator("claude-opus-4-6", timeout=60.0)
        assert t._timeout == 60.0

    def test_model_stored(self) -> None:
        t = AnthropicTranslator("claude-opus-4-6")
        assert t.model == "claude-opus-4-6"

    def test_api_key_stored(self) -> None:
        t = AnthropicTranslator("claude-opus-4-6", api_key="sk-test")
        assert t._api_key == "sk-test"


# ═══════════════════════════════════════════════════════════════════════════════
# Missing dependency paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorMissingDeps:
    @pytest.mark.asyncio
    async def test_missing_anthropic_package_raises_import_error(self) -> None:
        t = AnthropicTranslator("claude-opus-4-6")
        # Remove the anthropic package from sys.modules
        with patch.dict("sys.modules", {"anthropic": None}), pytest.raises(ImportError, match="anthropic"):  # type: ignore[dict-item]
            await t.extract("send 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_missing_tenacity_raises_import_error(self) -> None:
        t = AnthropicTranslator("claude-opus-4-6")
        ant_mod = _make_anthropic_module()
        # Block tenacity so the local `from tenacity import …` inside extract()
        # raises ImportError — mirrors production behaviour when the extra is absent.
        blocked: dict = {"tenacity": None}
        with patch.dict("sys.modules", {**blocked, "anthropic": ant_mod}), pytest.raises(ImportError, match="tenacity"):
            await t.extract("send 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Success path
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorSuccess:
    @pytest.mark.asyncio
    async def test_valid_response_returns_parsed_dict(self) -> None:
        import json  # — local import inside test method

        payload = json.dumps({"amount": 200.0, "recipient": "acc_ant"})
        resp = _make_anthropic_response(payload)
        ant_mod = _make_anthropic_module(resp)

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}):
            result = await t.extract("transfer 200 to acc_ant", _TransferIntent)

        assert result == {"amount": 200.0, "recipient": "acc_ant"}

    @pytest.mark.asyncio
    async def test_markdown_json_unwrapped(self) -> None:
        payload = '```json\n{"amount": 50.0, "recipient": "acc_md"}\n```'
        resp = _make_anthropic_response(payload)
        ant_mod = _make_anthropic_module(resp)

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}):
            result = await t.extract("send 50", _TransferIntent)

        assert result["amount"] == 50.0

    @pytest.mark.asyncio
    async def test_context_parameter_accepted(self) -> None:
        import json

        from pramanix.translator.base import TranslatorContext

        payload = json.dumps({"amount": 10.0, "recipient": "acc_ctx"})
        resp = _make_anthropic_response(payload)
        ant_mod = _make_anthropic_module(resp)
        ctx = TranslatorContext(request_id="r1", user_id="u1")

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}):
            result = await t.extract("send 10", _TransferIntent, context=ctx)

        assert result["amount"] == 10.0


# ═══════════════════════════════════════════════════════════════════════════════
# API error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorApiErrors:
    @pytest.mark.asyncio
    async def test_api_status_error_raises_extraction_failure(self) -> None:
        ant_mod = _make_anthropic_module()
        err = ant_mod.APIStatusError("Forbidden", status_code=403)
        ant_mod.AsyncAnthropic.return_value.messages.create = AsyncMock(side_effect=err)

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}), pytest.raises(ExtractionFailureError, match="403"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_no_text_content_block_raises_extraction_failure(self) -> None:
        """Response contains content blocks but none have .text → ExtractionFailureError."""
        resp = MagicMock()
        no_text_block = MagicMock(spec=[])  # no .text attribute
        resp.content = [no_text_block]
        ant_mod = _make_anthropic_module(resp)

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}), pytest.raises(ExtractionFailureError, match="no text content"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_empty_content_list_raises_extraction_failure(self) -> None:
        resp = MagicMock()
        resp.content = []  # empty list → no blocks with text
        ant_mod = _make_anthropic_module(resp)

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}), pytest.raises(ExtractionFailureError, match="no text content"):
            await t.extract("transfer 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Retry / timeout exhaustion paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorRetry:
    @pytest.mark.asyncio
    async def test_timeout_exhausted_raises_llm_timeout_error(self) -> None:
        """APITimeoutError raised on all 3 attempts → LLMTimeoutError."""
        ant_mod = _make_anthropic_module()
        timeout_err = ant_mod.APITimeoutError("Request timed out")
        ant_mod.AsyncAnthropic.return_value.messages.create = AsyncMock(side_effect=timeout_err)

        t = AnthropicTranslator("claude-opus-4-6", timeout=0.001)
        # Use tenacity with 0-second waits to avoid slow tests
        with (
            patch.dict("sys.modules", {"anthropic": ant_mod}),
            patch("tenacity.wait_exponential", return_value=lambda *a, **k: 0),
            pytest.raises(LLMTimeoutError, match="unreachable"),
        ):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_connection_error_exhausted_raises_llm_timeout_error(self) -> None:
        """APIConnectionError raised on all 3 attempts → LLMTimeoutError."""
        ant_mod = _make_anthropic_module()
        conn_err = ant_mod.APIConnectionError("Connection refused")
        ant_mod.AsyncAnthropic.return_value.messages.create = AsyncMock(side_effect=conn_err)

        t = AnthropicTranslator("claude-opus-4-6", timeout=0.001)
        with (
            patch.dict("sys.modules", {"anthropic": ant_mod}),
            patch("tenacity.wait_exponential", return_value=lambda *a, **k: 0),
            pytest.raises(LLMTimeoutError),
        ):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_invalid_inner_json_raises_extraction_failure(self) -> None:
        resp = _make_anthropic_response("not valid json at all")
        ant_mod = _make_anthropic_module(resp)

        t = AnthropicTranslator("claude-opus-4-6")
        with patch.dict("sys.modules", {"anthropic": ant_mod}), pytest.raises(ExtractionFailureError, match="unparseable"):
            await t.extract("transfer 100", _TransferIntent)
