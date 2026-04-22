# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for D-2 — Gemini and Cohere LLM backends.

Coverage:
- GeminiTranslator: ConfigurationError when google.generativeai missing
- GeminiTranslator: extract() calls API and returns parsed dict
- GeminiTranslator: model attribute accessible
- CohereTranslator: ConfigurationError when cohere missing
- CohereTranslator: extract() calls API and returns parsed dict
- CohereTranslator: model attribute accessible
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ConfigurationError


class SimpleIntent(BaseModel):
    amount: float
    action: str


# ── GeminiTranslator ──────────────────────────────────────────────────────────


class TestGeminiTranslatorMissingDep:
    def test_raises_configuration_error_when_not_installed(self):
        import sys

        # Temporarily remove google.generativeai from sys.modules
        saved = sys.modules.pop("google.generativeai", None)
        saved_genai = sys.modules.pop("pramanix.translator.gemini", None)
        try:
            with patch.dict(sys.modules, {"google.generativeai": None}):  # type: ignore
                from pramanix.translator.gemini import GeminiTranslator

                with pytest.raises(ConfigurationError, match="pramanix\\[gemini\\]"):
                    GeminiTranslator("gemini-1.5-flash", api_key="test")
        finally:
            if saved is not None:
                sys.modules["google.generativeai"] = saved
            if saved_genai is not None:
                sys.modules["pramanix.translator.gemini"] = saved_genai


class TestGeminiTranslatorExtract:
    def _make_mock_genai(self, response_text: str) -> MagicMock:
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = response_text
        mock_model.generate_content_async = AsyncMock(return_value=mock_response)
        mock_genai.GenerativeModel.return_value = mock_model
        mock_genai.configure = MagicMock()
        return mock_genai

    def test_model_attribute(self):
        mock_genai = self._make_mock_genai('{"amount": 100.0, "action": "transfer"}')
        # Patch google.generativeai so __init__ doesn't raise ConfigurationError
        with patch.dict("sys.modules", {"google.generativeai": mock_genai}):
            from pramanix.translator.gemini import GeminiTranslator
            t = GeminiTranslator("gemini-1.5-flash", api_key="fake-key")
            assert t.model == "gemini-1.5-flash"

    def test_extract_returns_dict(self):
        payload = '{"amount": 100.0, "action": "transfer"}'
        mock_genai = self._make_mock_genai(payload)

        with patch.dict("sys.modules", {"google.generativeai": mock_genai}):
            from pramanix.translator.gemini import GeminiTranslator
            t = GeminiTranslator("gemini-1.5-flash", api_key="fake-key")

            # Bypass the retry/API call by patching _single_call directly
            async def _mock_single_call(*, genai, prompt):  # type: ignore
                return payload

            t._single_call = _mock_single_call  # type: ignore[method-assign]
            result = asyncio.get_event_loop().run_until_complete(
                t.extract("transfer 100 USD", SimpleIntent)
            )
            assert isinstance(result, dict)
            assert result["amount"] == 100.0


# ── CohereTranslator ──────────────────────────────────────────────────────────


class TestCohereTranslatorMissingDep:
    def test_raises_configuration_error_when_not_installed(self):
        import sys

        saved = sys.modules.pop("cohere", None)
        saved_mod = sys.modules.pop("pramanix.translator.cohere", None)
        try:
            with patch.dict(sys.modules, {"cohere": None}):  # type: ignore
                from pramanix.translator.cohere import CohereTranslator

                with pytest.raises(ConfigurationError, match="pramanix\\[cohere\\]"):
                    CohereTranslator("command-r", api_key="test")
        finally:
            if saved is not None:
                sys.modules["cohere"] = saved
            if saved_mod is not None:
                sys.modules["pramanix.translator.cohere"] = saved_mod


class TestCohereTranslatorExtract:
    def _make_mock_cohere(self, response_text: str) -> MagicMock:
        mock_cohere = MagicMock()

        # v5 style response
        mock_content = MagicMock()
        mock_content.text = response_text
        mock_message = MagicMock()
        mock_message.content = [mock_content]
        mock_response = MagicMock()
        mock_response.message = mock_message

        mock_client = MagicMock()
        mock_client.chat = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        mock_cohere.AsyncClientV2 = MagicMock(return_value=mock_client)
        mock_cohere.errors = MagicMock()
        mock_cohere.errors.TooManyRequestsError = Exception
        mock_cohere.errors.ServiceUnavailableError = Exception
        mock_cohere.errors.GatewayTimeoutError = Exception
        return mock_cohere

    def test_model_attribute(self):
        mock_cohere = self._make_mock_cohere('{"amount": 50.0, "action": "pay"}')
        with patch.dict("sys.modules", {"cohere": mock_cohere}):
            import importlib
            import pramanix.translator.cohere as coh

            importlib.reload(coh)
            try:
                t = coh.CohereTranslator("command-r", api_key="fake-key")
                assert t.model == "command-r"
            finally:
                importlib.reload(coh)

    def test_extract_returns_dict(self):
        payload = '{"amount": 50.0, "action": "pay"}'
        mock_cohere = self._make_mock_cohere(payload)

        with patch.dict("sys.modules", {"cohere": mock_cohere}):
            import importlib
            import pramanix.translator.cohere as coh

            importlib.reload(coh)
            try:
                t = coh.CohereTranslator("command-r", api_key="fake-key")
                result = asyncio.get_event_loop().run_until_complete(
                    t.extract("pay 50 USD", SimpleIntent)
                )
                assert isinstance(result, dict)
                assert result["amount"] == 50.0
            finally:
                importlib.reload(coh)
