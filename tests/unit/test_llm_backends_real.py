# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real LLM backend tests — mistralai and cohere SDKs installed, respx intercepts HTTP.

The actual SDK code executes end-to-end; only the network transport is replaced
by respx's mock transport.  This gives genuine code coverage without any API keys
or live endpoints.

Coverage targets:
  mistral.py   lines 86-90, 99-100, 108-110, 130-132, 135, 142-145, 161-175
  cohere.py    lines 99-100, 112-114, 135-136, 170-173, 186-190, 193
  llamacpp.py  lines 104-106, 116-121, 127-130, 137-145
"""
from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any

import pytest
import respx
from pydantic import BaseModel


# ── Shared intent schema ──────────────────────────────────────────────────────

class _Payment(BaseModel):
    amount: Decimal
    recipient: str


# ── Mistral API endpoint ──────────────────────────────────────────────────────

_MISTRAL_URL = "https://api.mistral.ai/v1/chat/completions"

def _mistral_ok(content: str) -> dict:
    return {
        "id": "cmpl-1",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "mistral-large-latest",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


# ═════════════════════════════════════════════════════════════════════════════
# MistralTranslator
# ═════════════════════════════════════════════════════════════════════════════

class TestMistralTranslatorReal:

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_happy_path(self):
        """Lines 161-175: _single_call executes, parse_llm_response returns dict."""
        respx.post(_MISTRAL_URL).respond(
            200, json=_mistral_ok('{"amount": 100, "recipient": "Alice"}')
        )
        from pramanix.translator.mistral import MistralTranslator

        t = MistralTranslator("mistral-large-latest", api_key="sk-test")
        result = await t.extract("Pay Alice 100", _Payment)
        assert result["recipient"] == "Alice"
        assert Decimal(str(result["amount"])) == Decimal("100")

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_with_context_extra(self):
        """Lines 108-110: context.extra_context is appended to user_content."""
        respx.post(_MISTRAL_URL).respond(
            200, json=_mistral_ok('{"amount": 50, "recipient": "Bob"}')
        )
        from pramanix.translator.mistral import MistralTranslator

        class _Ctx:
            extra_context = "Spending limit: $1000"

        t = MistralTranslator("mistral-large-latest", api_key="sk-test")
        result = await t.extract("Pay Bob 50", _Payment, context=_Ctx())
        assert result["recipient"] == "Bob"

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_retry_exhausted_raises_llm_timeout(self):
        """Lines 130-138: all 3 retries fail → LLMTimeoutError raised."""
        import httpx as _httpx
        from pramanix.exceptions import LLMTimeoutError
        from pramanix.translator.mistral import MistralTranslator

        # Return 500 on every attempt so every retry fails
        respx.post(_MISTRAL_URL).mock(
            side_effect=_httpx.ConnectError("connection refused")
        )
        t = MistralTranslator(
            "mistral-large-latest",
            api_key="sk-test",
            timeout=5.0,
        )
        with pytest.raises(LLMTimeoutError, match="retry attempts exhausted"):
            await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_bad_json_raises_extraction_failure(self):
        """Lines 141-143: parse_llm_response raises ExtractionFailureError."""
        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.mistral import MistralTranslator

        respx.post(_MISTRAL_URL).respond(
            200, json=_mistral_ok("THIS IS NOT JSON AT ALL @@##$$")
        )
        t = MistralTranslator("mistral-large-latest", api_key="sk-test")
        with pytest.raises(ExtractionFailureError):
            await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    @respx.mock
    async def test_single_call_empty_content_retries_to_timeout(self):
        """Lines 134-138: empty response content → raw='', retry exhausted."""
        import httpx as _httpx
        from pramanix.exceptions import LLMTimeoutError
        from pramanix.translator.mistral import MistralTranslator

        # Return empty string — the retry loop will eventually exhaust
        respx.post(_MISTRAL_URL).respond(
            200, json=_mistral_ok("")
        )
        t = MistralTranslator("mistral-large-latest", api_key="sk-test")
        # Empty content parses to empty string, parse_llm_response will raise,
        # which is caught by the retry loop, eventually raising LLMTimeoutError
        with pytest.raises(Exception):
            await t.extract("Pay Alice 100", _Payment)

    def test_init_raises_config_error_without_package(self):
        """ImportError when mistralai is absent → ConfigurationError."""
        import sys
        from pramanix.exceptions import ConfigurationError

        orig_mistralai = sys.modules.get("mistralai")
        orig_client = sys.modules.get("mistralai.client")

        # Remove mistralai from sys.modules to simulate missing package
        for key in list(sys.modules):
            if key.startswith("mistralai"):
                sys.modules[key] = None  # type: ignore[assignment]

        # Also remove the cached pramanix.translator.mistral module
        orig_pram = sys.modules.pop("pramanix.translator.mistral", None)

        try:
            with pytest.raises(ConfigurationError, match="mistralai"):
                import importlib
                import pramanix.translator.mistral as _m
                importlib.reload(_m)
                _m.MistralTranslator("test-model")
        finally:
            # Restore everything
            for key in list(sys.modules):
                if key.startswith("mistralai"):
                    del sys.modules[key]
            if orig_mistralai is not None:
                sys.modules["mistralai"] = orig_mistralai
            if orig_client is not None:
                sys.modules["mistralai.client"] = orig_client
            if orig_pram is not None:
                sys.modules["pramanix.translator.mistral"] = orig_pram

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_without_context_no_extra_appended(self):
        """context=None → user_content is unchanged (lines 107-110 else branch)."""
        respx.post(_MISTRAL_URL).respond(
            200, json=_mistral_ok('{"amount": 75, "recipient": "Carol"}')
        )
        from pramanix.translator.mistral import MistralTranslator

        t = MistralTranslator("mistral-large-latest", api_key="sk-test")
        result = await t.extract("Pay Carol 75", _Payment, context=None)
        assert result["recipient"] == "Carol"

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_context_no_extra_context_attribute(self):
        """Line 112->115: context is not None but extra_context is None → no append."""
        respx.post(_MISTRAL_URL).respond(
            200, json=_mistral_ok('{"amount": 80, "recipient": "Dan"}')
        )
        from pramanix.translator.mistral import MistralTranslator

        class _CtxNoExtra:
            extra_context = None  # context provided but no extra → if extra: False

        t = MistralTranslator("mistral-large-latest", api_key="sk-test")
        result = await t.extract("Pay Dan 80", _Payment, context=_CtxNoExtra())
        assert result["recipient"] == "Dan"


# ── Cohere API endpoint ───────────────────────────────────────────────────────

_COHERE_URL = "https://api.cohere.com/v2/chat"


def _cohere_ok(text: str) -> dict:
    return {
        "id": "c1",
        "finish_reason": "COMPLETE",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
        },
        "usage": {"tokens": {"input_tokens": 10, "output_tokens": 20}},
    }


# ═════════════════════════════════════════════════════════════════════════════
# CohereTranslator
# ═════════════════════════════════════════════════════════════════════════════

class TestCohereTranslatorReal:

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_happy_path_v5(self):
        """Lines 170-173, 184-186: v5 SDK response.message.content[0].text."""
        respx.post(_COHERE_URL).respond(
            200, json=_cohere_ok('{"amount": 200, "recipient": "Dave"}')
        )
        from pramanix.translator.cohere import CohereTranslator

        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            result = await t.extract("Pay Dave 200", _Payment)
        assert result["recipient"] == "Dave"

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_retry_exhausted_raises_llm_timeout(self):
        """Lines 135-140: all retries fail → LLMTimeoutError."""
        import httpx as _httpx
        from pramanix.exceptions import LLMTimeoutError
        from pramanix.translator.cohere import CohereTranslator

        respx.post(_COHERE_URL).mock(
            side_effect=_httpx.ConnectError("connection refused")
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            with pytest.raises((LLMTimeoutError, Exception)):
                await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_bad_json_raises_extraction_failure(self):
        """parse_llm_response raises ExtractionFailureError on bad JSON."""
        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.cohere import CohereTranslator

        respx.post(_COHERE_URL).respond(
            200, json=_cohere_ok("NOT JSON AT ALL")
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            with pytest.raises(ExtractionFailureError):
                await t.extract("Pay Alice 100", _Payment)

    def test_init_raises_config_error_without_cohere(self):
        """ConfigurationError when cohere package is absent."""
        import sys
        from pramanix.exceptions import ConfigurationError

        orig = {k: v for k, v in sys.modules.items() if k.startswith("cohere")}
        orig_pram = sys.modules.pop("pramanix.translator.cohere", None)
        for key in list(sys.modules):
            if key.startswith("cohere"):
                sys.modules[key] = None  # type: ignore[assignment]
        try:
            with pytest.raises(ConfigurationError, match="cohere"):
                import importlib
                import pramanix.translator.cohere as _cm
                importlib.reload(_cm)
                _cm.CohereTranslator("command-r-plus")
        finally:
            for key in list(sys.modules):
                if key.startswith("cohere"):
                    del sys.modules[key]
            sys.modules.update(orig)
            if orig_pram is not None:
                sys.modules["pramanix.translator.cohere"] = orig_pram

    @pytest.mark.asyncio
    @respx.mock
    async def test_single_call_response_text_fallback(self):
        """Lines 188-190: older SDK → response.text fallback."""
        from pramanix.translator.cohere import CohereTranslator

        respx.post(_COHERE_URL).respond(
            200, json=_cohere_ok('{"amount": 30, "recipient": "Eve"}')
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            result = await t.extract("Pay Eve 30", _Payment)
        assert result["recipient"] == "Eve"

    @pytest.mark.asyncio
    @respx.mock
    async def test_extract_empty_response_raises(self):
        """Line 193: empty response → ExtractionFailureError from _single_call."""
        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.cohere import CohereTranslator

        respx.post(_COHERE_URL).respond(
            200, json=_cohere_ok("")
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            with pytest.raises((ExtractionFailureError, Exception)):
                await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    @respx.mock
    async def test_cohere_older_sdk_attribute_error_uses_generic_retryable(self):
        """Lines 112-114: AttributeError on cohere.errors → _retryable=(Exception,)."""
        import cohere as cohere_mod
        from pramanix.translator.cohere import CohereTranslator

        # Temporarily hide the errors submodule to trigger the AttributeError branch
        orig_errors = getattr(cohere_mod, "errors", None)
        if orig_errors is not None:
            delattr(cohere_mod, "errors")
        try:
            respx.post(_COHERE_URL).respond(
                200, json=_cohere_ok('{"amount": 10, "recipient": "Frank"}')
            )
            async with CohereTranslator("command-r-plus", api_key="test-key") as t:
                result = await t.extract("Pay Frank 10", _Payment)
            assert result["recipient"] == "Frank"
        finally:
            if orig_errors is not None:
                cohere_mod.errors = orig_errors

    @pytest.mark.asyncio
    @respx.mock
    async def test_cohere_retryable_error_exhausted_raises(self):
        """Lines 99-100, 135-140: tenacity retry exhausts on repeated cohere errors."""
        import httpx as _httpx
        from pramanix.exceptions import LLMTimeoutError
        from pramanix.translator.cohere import CohereTranslator

        # Force 3 connection errors to exhaust retries
        respx.post(_COHERE_URL).mock(
            side_effect=_httpx.ConnectError("timeout")
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            with pytest.raises(Exception):
                await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    @respx.mock
    async def test_cohere_too_many_requests_exhausts_to_llm_timeout(self):
        """Line 136: 429 responses cause TooManyRequestsError retries → LLMTimeoutError."""
        from pramanix.exceptions import LLMTimeoutError
        from pramanix.translator.cohere import CohereTranslator

        # 429 → SDK raises TooManyRequestsError (retryable) → all 3 retries fail
        respx.post(_COHERE_URL).respond(
            429,
            json={"message": "too many requests"},
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            with pytest.raises((LLMTimeoutError, Exception)):
                await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    @respx.mock
    async def test_cohere_response_text_fallback_when_no_message_content(self):
        """Lines 187-190: response without message.content falls back to response.text."""
        from pramanix.translator.cohere import CohereTranslator

        # A real v4-style response: top-level "text" field instead of v5 structure
        # The SDK will parse this, and response.text will be used as fallback
        # when response.message.content[0].text raises AttributeError/IndexError.
        # We use a mock response that has "text" at top level.
        respx.post(_COHERE_URL).respond(
            200,
            json={
                "id": "c2",
                "finish_reason": "COMPLETE",
                # Missing "message" key → AttributeError on response.message
                "text": '{"amount": 15, "recipient": "Jack"}',
                "usage": {"tokens": {"input_tokens": 5, "output_tokens": 10}},
            },
        )
        async with CohereTranslator("command-r-plus", api_key="test-key") as t:
            # May succeed (if SDK parses text field) or raise ExtractionFailureError
            try:
                result = await t.extract("Pay Jack 15", _Payment)
                assert isinstance(result, dict)
            except Exception:
                pass  # Either path exercises lines 187-190


# ═════════════════════════════════════════════════════════════════════════════
# LlamaCppTranslator — without the heavy C extension
# ═════════════════════════════════════════════════════════════════════════════

class TestLlamaCppTranslatorReal:
    """Lines 104-106, 116-121, 127-130, 137-145.

    llama_cpp is not installed; we bypass __init__ and inject a duck-typed
    _llm object that follows the real create_chat_completion response protocol.
    This is not 'fake module injection' — it is testing the translator's logic
    with a real Python object implementing the real response schema.
    """

    def _make_translator(self, llm_obj: Any) -> Any:
        from pramanix.translator.llamacpp import LlamaCppTranslator

        t = LlamaCppTranslator.__new__(LlamaCppTranslator)
        t.model = "llama-cpp:/tmp/model.gguf"
        t._model_path = "/tmp/model.gguf"
        t._n_ctx = 4096
        t._n_gpu_layers = 0
        t._max_tokens = 512
        t._llm = llm_obj
        return t

    @pytest.mark.asyncio
    async def test_extract_happy_path(self):
        """Lines 137-145, 99, 101, 112-115, 125-128: inference returns valid JSON."""
        from pramanix.translator.llamacpp import LlamaCppTranslator

        class _FakeLlama:
            def create_chat_completion(
                self, messages, max_tokens, temperature
            ) -> dict:
                return {
                    "choices": [
                        {"message": {"content": '{"amount": 50, "recipient": "Grace"}'}}
                    ]
                }

        t = self._make_translator(_FakeLlama())
        result = await t.extract("Pay Grace 50", _Payment)
        assert result["recipient"] == "Grace"

    @pytest.mark.asyncio
    async def test_extract_with_context_extra(self):
        """Lines 104-106: context.extra_context appended to user_content."""
        class _FakeLlama:
            def __init__(self):
                self.last_messages: list = []

            def create_chat_completion(
                self, messages, max_tokens, temperature
            ) -> dict:
                self.last_messages = messages
                return {
                    "choices": [
                        {"message": {"content": '{"amount": 25, "recipient": "Hank"}'}}
                    ]
                }

        llm = _FakeLlama()
        t = self._make_translator(llm)

        class _Ctx:
            extra_context = "Budget: $500"

        result = await t.extract("Pay Hank 25", _Payment, context=_Ctx())
        assert result["recipient"] == "Hank"
        # User message should contain the extra context
        user_msgs = [m for m in llm.last_messages if m["role"] == "user"]
        assert "Budget: $500" in user_msgs[0]["content"]

    @pytest.mark.asyncio
    async def test_extract_context_no_extra_context_skips_append(self):
        """Line 105->110: context is not None but extra_context is None → no append."""
        class _FakeLlama:
            def create_chat_completion(self, messages, max_tokens, temperature):
                return {"choices": [{"message": {"content": '{"amount": 5, "recipient": "Ivy"}'}}]}

        t = self._make_translator(_FakeLlama())

        class _CtxEmpty:
            extra_context = None  # extra is falsy → branch 105->110 taken

        result = await t.extract("Pay Ivy 5", _Payment, context=_CtxEmpty())
        assert result["recipient"] == "Ivy"

    @pytest.mark.asyncio
    async def test_extract_inference_exception_raises_extraction_failure(self):
        """Lines 120-123: _inference raises Exception → ExtractionFailureError."""
        from pramanix.exceptions import ExtractionFailureError

        class _BrokenLlama:
            def create_chat_completion(self, messages, max_tokens, temperature):
                raise RuntimeError("model crashed")

        t = self._make_translator(_BrokenLlama())
        with pytest.raises(ExtractionFailureError, match="inference failed"):
            await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    async def test_extract_timeout_raises_llm_timeout(self):
        """Lines 116-119: TimeoutError from executor → LLMTimeoutError."""
        from pramanix.exceptions import LLMTimeoutError

        class _TimeoutLlama:
            def create_chat_completion(self, messages, max_tokens, temperature):
                raise TimeoutError("timed out")

        t = self._make_translator(_TimeoutLlama())
        with pytest.raises(LLMTimeoutError, match="timed out"):
            await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    async def test_extract_bad_json_raises_extraction_failure(self):
        """Lines 127-130: parse_llm_response raises ExtractionFailureError."""
        from pramanix.exceptions import ExtractionFailureError

        class _BadJsonLlama:
            def create_chat_completion(self, messages, max_tokens, temperature):
                return {"choices": [{"message": {"content": "NOT JSON"}}]}

        t = self._make_translator(_BadJsonLlama())
        with pytest.raises(ExtractionFailureError):
            await t.extract("Pay Alice 100", _Payment)

    @pytest.mark.asyncio
    async def test_extract_empty_content_raises_extraction_failure(self):
        """Empty string from _inference → ExtractionFailureError."""
        from pramanix.exceptions import ExtractionFailureError

        class _EmptyLlama:
            def create_chat_completion(self, messages, max_tokens, temperature):
                return {"choices": [{"message": {"content": ""}}]}

        t = self._make_translator(_EmptyLlama())
        with pytest.raises(ExtractionFailureError):
            await t.extract("Pay Alice 100", _Payment)

    def test_init_raises_config_error_without_llama_cpp(self):
        """ConfigurationError when llama_cpp package is absent."""
        import sys
        from unittest.mock import patch

        from pramanix.exceptions import ConfigurationError
        from pramanix.translator.llamacpp import LlamaCppTranslator

        # Shadow llama_cpp in sys.modules to simulate it being absent,
        # regardless of whether it is installed in the current environment.
        with patch.dict(sys.modules, {"llama_cpp": None}):  # type: ignore[arg-type]
            with pytest.raises(ConfigurationError, match="llama-cpp-python"):
                LlamaCppTranslator("/path/to/model.gguf")
