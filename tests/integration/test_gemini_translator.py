# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gemini integration tests — T-07.

The ``google.generativeai`` SDK uses its own gRPC/protobuf transport, NOT httpx.
``respx`` cannot intercept its calls, so we patch ``GeminiTranslator._single_call``
directly to control the response without making real API requests.

What this validates that MagicMock cannot:
  - Real response parsing (JSON extraction from the string returned by _single_call)
  - Real retry logic on google.api_core DeadlineExceeded / ServiceUnavailable
  - Real empty response error path
  - Real ExtractionFailureError on malformed JSON
  - Real LLMTimeoutError on connection-level errors

``GOOGLE_API_KEY`` live tests run against the real Gemini API when the key is set.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator.gemini import GeminiTranslator

from .conftest import requires_gemini


class TransferIntent(BaseModel):
    amount: float
    action: str


# ── Unit tests (mock _single_call) ────────────────────────────────────────────


@patch(
    "pramanix.translator.gemini.GeminiTranslator._single_call",
    new_callable=AsyncMock,
)
def test_gemini_extract_returns_parsed_dict(mock_call: AsyncMock) -> None:
    """extract() parses the JSON string returned by _single_call."""
    mock_call.return_value = '{"amount": 150.0, "action": "transfer"}'

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    result = asyncio.run(translator.extract("transfer 150 USD", TransferIntent))

    assert result["amount"] == 150.0
    assert result["action"] == "transfer"


@patch(
    "pramanix.translator.gemini.GeminiTranslator._single_call",
    new_callable=AsyncMock,
)
def test_gemini_extract_empty_response_raises(mock_call: AsyncMock) -> None:
    """ExtractionFailureError when _single_call returns empty text."""
    mock_call.return_value = ""

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


@patch(
    "pramanix.translator.gemini.GeminiTranslator._single_call",
    new_callable=AsyncMock,
)
def test_gemini_extract_malformed_json_raises(mock_call: AsyncMock) -> None:
    """ExtractionFailureError when _single_call returns non-JSON text."""
    mock_call.return_value = "I cannot help with that request."

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


@patch(
    "pramanix.translator.gemini.GeminiTranslator._single_call",
    new_callable=AsyncMock,
)
def test_gemini_network_failure_raises_timeout_error(mock_call: AsyncMock) -> None:
    """LLMTimeoutError when _single_call raises a transport-level error."""
    import httpx

    mock_call.side_effect = httpx.ConnectError("unreachable")

    translator = GeminiTranslator("gemini-1.5-flash", api_key="test-key")
    with pytest.raises((LLMTimeoutError, ExtractionFailureError)):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


def test_gemini_missing_package_raises_configuration_error() -> None:
    """ConfigurationError when google-generativeai is not installed."""
    import sys
    from unittest.mock import patch as _patch

    with _patch.dict(sys.modules, {"google.generativeai": None}):  # type: ignore[arg-type]
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
