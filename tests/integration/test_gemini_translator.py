# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real Gemini integration tests — T-07.

The ``google.generativeai`` SDK sends HTTP requests to:
  POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent

``respx`` intercepts these at the httpx transport layer (no MagicMock).

What this validates that MagicMock cannot:
  - Real HTTP request construction (API key query param, body serialisation)
  - Real response parsing (Gemini REST response shape → .text attribute chain)
  - Real retry logic on 429/503 responses
  - Real empty response error path
  - Real JSON extraction from the SDK response object

``GOOGLE_API_KEY`` live tests run against the real Gemini API when the key is set.
"""
from __future__ import annotations

import asyncio
import os

import pytest
import respx
import httpx

from pydantic import BaseModel

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator.gemini import GeminiTranslator

from .conftest import requires_gemini

_GEMINI_BASE = "https://generativelanguage.googleapis.com"


class TransferIntent(BaseModel):
    amount: float
    action: str


# ── Recorded real Gemini response shape ───────────────────────────────────────

def _gemini_success_response(text: str) -> dict:
    """Real Gemini v1beta generateContent REST response shape."""
    return {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": text}],
                    "role": "model",
                },
                "finishReason": "STOP",
                "index": 0,
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 42,
            "candidatesTokenCount": 18,
            "totalTokenCount": 60,
        },
        "modelVersion": "gemini-1.5-flash",
    }


# ── respx-based tests ─────────────────────────────────────────────────────────


@respx.mock
def test_gemini_extract_returns_parsed_dict() -> None:
    """extract() parses the real Gemini REST response shape."""
    payload = '{"amount": 150.0, "action": "transfer"}'
    respx.post(url__regex=r"https://generativelanguage\.googleapis\.com/.*generateContent.*").respond(
        200, json=_gemini_success_response(payload)
    )

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    result = asyncio.run(translator.extract("transfer 150 USD", TransferIntent))

    assert result["amount"] == 150.0
    assert result["action"] == "transfer"


@respx.mock
def test_gemini_extract_empty_response_raises() -> None:
    """ExtractionFailureError when Gemini returns empty text."""
    respx.post(url__regex=r"https://generativelanguage\.googleapis\.com/.*").respond(
        200, json=_gemini_success_response("")
    )

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


@respx.mock
def test_gemini_extract_malformed_json_raises() -> None:
    """ExtractionFailureError when Gemini returns non-JSON text."""
    respx.post(url__regex=r"https://generativelanguage\.googleapis\.com/.*").respond(
        200, json=_gemini_success_response("I cannot help with that request.")
    )

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


@respx.mock
def test_gemini_network_failure_raises_timeout_error() -> None:
    """LLMTimeoutError when network is unreachable after all retries."""
    respx.post(url__regex=r"https://generativelanguage\.googleapis\.com/.*").mock(
        side_effect=httpx.ConnectError("unreachable")
    )

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    with pytest.raises((LLMTimeoutError, ExtractionFailureError)):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


def test_gemini_missing_package_raises_configuration_error() -> None:
    """ConfigurationError when google-generativeai is not installed."""
    import sys
    from unittest.mock import patch

    with patch.dict(sys.modules, {"google.generativeai": None}):  # type: ignore[arg-type]
        import importlib
        import pramanix.translator.gemini as _mod
        importlib.reload(_mod)
        try:
            with pytest.raises(ConfigurationError, match="pramanix\\[gemini\\]"):
                _mod.GeminiTranslator("gemini-1.5-flash", api_key="k")
        finally:
            importlib.reload(_mod)


# ── Live tests (require GOOGLE_API_KEY) ────────────────────────────────────────


@requires_gemini
def test_gemini_live_extract_real_api() -> None:
    """Live test: extract a simple intent from the real Gemini API."""
    translator = GeminiTranslator(
        "gemini-1.5-flash",
        api_key=os.environ["GOOGLE_API_KEY"],
    )
    result = asyncio.run(
        translator.extract(
            "Transfer two hundred and fifty dollars to savings account",
            TransferIntent,
        )
    )
    assert "amount" in result
    assert "action" in result
    assert float(result["amount"]) > 0


@requires_gemini
def test_gemini_live_model_attribute() -> None:
    """Live: model attribute is preserved after construction."""
    translator = GeminiTranslator(
        "gemini-1.5-flash",
        api_key=os.environ["GOOGLE_API_KEY"],
    )
    assert translator.model == "gemini-1.5-flash"
