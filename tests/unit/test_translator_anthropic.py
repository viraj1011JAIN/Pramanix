# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for AnthropicTranslator — respx transport-level HTTP interception.

Design principles
-----------------
* No MagicMock, AsyncMock, patch(), or patch.dict() from unittest.mock.

* No fake/stub client classes.  All HTTP calls are intercepted at the
  transport layer by ``respx``, which the Anthropic SDK uses via httpx
  internally.  The SDK parses a real HTTP response, so every code path
  (response deserialization, exception mapping) is exercised with the
  actual SDK implementation.

* For retry exhaustion tests, ``monkeypatch.setattr("tenacity.wait_exponential",
  lambda **kw: wait_none())`` eliminates the 1+2 s inter-retry delays without
  patching retry count or exception routing — only the delay infrastructure is
  changed so the test suite stays sub-second.

* ``monkeypatch.setitem(sys.modules, "anthropic"/"tenacity", None)`` is the
  only way to simulate a missing package and is acceptable for impossible-to-
  reach states (the packages ARE installed in the test env).

Coverage targets
----------------
* Success path: valid response with text block → parsed dict
* APIStatusError (4xx/5xx) → ExtractionFailureError
* Retryable timeout (httpx.TimeoutException) exhausted → LLMTimeoutError
* Retryable connection error (httpx.ConnectError) exhausted → LLMTimeoutError
* No text content in response → ExtractionFailureError
* anthropic package not installed → ImportError
* tenacity package not installed → ImportError
* API key from env var (ANTHROPIC_API_KEY)
* Markdown-wrapped JSON content extracted correctly
"""
from __future__ import annotations

import json
import sys

import httpx
import pytest
import respx
from pydantic import BaseModel
from tenacity import wait_none

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator.anthropic import AnthropicTranslator

# ── Minimal intent schema ─────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: float
    recipient: str


# ── Shared response builder ───────────────────────────────────────────────────

_MESSAGES_URL = "https://api.anthropic.com/v1/messages"


def _ok_response(text: str) -> dict:
    """Return a well-formed Anthropic Messages API response body."""
    return {
        "id": "msg_test_001",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": "claude-opus-4-6",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 100, "output_tokens": 50},
    }


def _empty_content_response() -> dict:
    """Return an Anthropic Messages API response body with no content blocks."""
    return {
        "id": "msg_test_002",
        "type": "message",
        "role": "assistant",
        "content": [],
        "model": "claude-opus-4-6",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 100, "output_tokens": 0},
    }


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
    async def test_missing_anthropic_package_raises_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        t = AnthropicTranslator("claude-opus-4-6")
        monkeypatch.setitem(sys.modules, "anthropic", None)  # type: ignore[arg-type]
        with pytest.raises(ImportError, match="anthropic"):
            await t.extract("send 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_missing_tenacity_raises_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        t = AnthropicTranslator("claude-opus-4-6")
        monkeypatch.setitem(sys.modules, "tenacity", None)  # type: ignore[arg-type]
        with pytest.raises(ImportError, match="tenacity"):
            await t.extract("send 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Success path
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorSuccess:
    @pytest.mark.asyncio
    async def test_valid_response_returns_parsed_dict(self) -> None:
        payload = json.dumps({"amount": 200.0, "recipient": "acc_ant"})
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(200, json=_ok_response(payload))
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            result = await t.extract("transfer 200 to acc_ant", _TransferIntent)

        assert result == {"amount": 200.0, "recipient": "acc_ant"}

    @pytest.mark.asyncio
    async def test_markdown_json_unwrapped(self) -> None:
        payload = '```json\n{"amount": 50.0, "recipient": "acc_md"}\n```'
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(200, json=_ok_response(payload))
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            result = await t.extract("send 50", _TransferIntent)

        assert result["amount"] == 50.0

    @pytest.mark.asyncio
    async def test_context_parameter_accepted(self) -> None:
        from pramanix.translator.base import TranslatorContext

        payload = json.dumps({"amount": 10.0, "recipient": "acc_ctx"})
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(200, json=_ok_response(payload))
            ctx = TranslatorContext(request_id="r1", user_id="u1")
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            result = await t.extract("send 10", _TransferIntent, context=ctx)

        assert result["amount"] == 10.0


# ═══════════════════════════════════════════════════════════════════════════════
# API error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorApiErrors:
    @pytest.mark.asyncio
    async def test_api_status_error_raises_extraction_failure(self) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(
                403, json={"error": {"message": "Forbidden", "type": "permission_error"}}
            )
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            with pytest.raises(ExtractionFailureError, match="403"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_no_text_content_block_raises_extraction_failure(self) -> None:
        """Response with only non-text blocks → ExtractionFailureError."""
        # Use a tool_use-only content block; the SDK will deserialise this as a
        # ToolUseBlock which has no .text attribute, causing the translator to
        # fall through to the "no text content" error path.
        tool_use_response = {
            "id": "msg_test_003",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "tool_abc",
                    "name": "some_tool",
                    "input": {},
                }
            ],
            "model": "claude-opus-4-6",
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 20},
        }
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(200, json=tool_use_response)
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            with pytest.raises(ExtractionFailureError, match="no text content"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_empty_content_list_raises_extraction_failure(self) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(200, json=_empty_content_response())
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            with pytest.raises(ExtractionFailureError, match="no text content"):
                await t.extract("transfer 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Retry / timeout exhaustion paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorRetry:
    @pytest.mark.asyncio
    async def test_timeout_exhausted_raises_llm_timeout_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """httpx.TimeoutException on all 3 attempts → LLMTimeoutError.

        monkeypatch.setattr("tenacity.wait_exponential", ...) eliminates
        the 1+2 s inter-retry delays.  The retry COUNT and exception routing
        remain unchanged — only the delay infrastructure is bypassed.
        """
        monkeypatch.setattr("tenacity.wait_exponential", lambda **kw: wait_none())
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).mock(
                side_effect=httpx.TimeoutException("timed out")
            )
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test", timeout=0.001)
            with pytest.raises(LLMTimeoutError, match="unreachable"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_connection_error_exhausted_raises_llm_timeout_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """httpx.ConnectError on all 3 attempts → LLMTimeoutError."""
        monkeypatch.setattr("tenacity.wait_exponential", lambda **kw: wait_none())
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test", timeout=0.001)
            with pytest.raises(LLMTimeoutError):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_invalid_inner_json_raises_extraction_failure(self) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(_MESSAGES_URL).respond(
                200, json=_ok_response("not valid json at all")
            )
            t = AnthropicTranslator("claude-opus-4-6", api_key="sk-ant-test")
            with pytest.raises(ExtractionFailureError, match="unparseable"):
                await t.extract("transfer 100", _TransferIntent)
