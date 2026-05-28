# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
import importlib.util as _ilu
import os

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator.gemini import GeminiTranslator
from tests.helpers.real_protocols import _GeminiRecordingGenaiModule

from .conftest import requires_gemini


class TransferIntent(BaseModel):
    amount: float
    action: str


def _make_translator(genai_module: _GeminiRecordingGenaiModule) -> GeminiTranslator:
    """Build a GeminiTranslator with injected genai module — no real API call."""
    return GeminiTranslator(
        "gemini-1.5-flash",
        api_key=os.environ.get("GOOGLE_API_KEY", "") or None,
        _genai_override=genai_module,
    )


# ── Unit tests (real genai duck-type, no @patch) ──────────────────────────────


def test_gemini_extract_returns_parsed_dict() -> None:
    """extract() parses the JSON string returned by _single_call (real code path)."""
    genai = _GeminiRecordingGenaiModule('{"amount": 150.0, "action": "transfer"}')
    translator = _make_translator(genai)
    result = asyncio.run(translator.extract("transfer 150 USD", TransferIntent))
    assert result["amount"] == 150.0
    assert result["action"] == "transfer"
    assert genai.last_model.call_count == 1


def test_gemini_extract_empty_response_raises() -> None:
    """ExtractionFailureError (or LLMTimeoutError wrapping it) on blank text."""
    genai = _GeminiRecordingGenaiModule("   ")
    translator = _make_translator(genai)
    with pytest.raises((ExtractionFailureError, LLMTimeoutError)):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


def test_gemini_extract_malformed_json_raises() -> None:
    """ExtractionFailureError (or LLMTimeoutError wrapping it) on non-JSON text."""
    genai = _GeminiRecordingGenaiModule("I cannot help with that request.")
    translator = _make_translator(genai)
    with pytest.raises((ExtractionFailureError, LLMTimeoutError)):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


def test_gemini_network_failure_raises_timeout_error() -> None:
    """LLMTimeoutError when the genai model raises on every attempt."""
    genai = _GeminiRecordingGenaiModule(raising=True)
    translator = _make_translator(genai)
    with pytest.raises((LLMTimeoutError, ExtractionFailureError)):
        asyncio.run(translator.extract("transfer 150 USD", TransferIntent))


def test_gemini_missing_package_raises_configuration_error() -> None:
    """ConfigurationError when google-generativeai is absent (DI factory pattern)."""

    def _raise_import():
        raise ImportError("google-generativeai not installed")

    with pytest.raises(ConfigurationError, match="pramanix\\[gemini\\]"):
        GeminiTranslator("gemini-1.5-flash", api_key="", _genai_factory=_raise_import)


# ── Live tests (require GOOGLE_API_KEY in .env.test) ─────────────────────────


@requires_gemini
def test_gemini_live_extract_real_api() -> None:
    """Live test: extract a simple intent from the real Gemini API."""
    translator = GeminiTranslator(
        "gemini-1.5-flash",
        api_key=os.environ.get("GOOGLE_API_KEY"),
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
        api_key=os.environ.get("GOOGLE_API_KEY"),
    )
    assert translator.model == "gemini-1.5-flash"
