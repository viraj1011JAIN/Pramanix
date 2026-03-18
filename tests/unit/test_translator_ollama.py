# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for OllamaTranslator — all HTTP paths mocked via unittest.mock.

Coverage targets
----------------
* Success path: valid 200 + JSON response → parsed dict
* Non-200 status → ExtractionFailureError
* httpx.TimeoutException → LLMTimeoutError
* httpx.RequestError (ConnectError) → LLMTimeoutError
* Invalid outer JSON on success 200 → ExtractionFailureError
* Missing ``message.content`` key → ExtractionFailureError
* Bad inner JSON (passes to parse_llm_response) → ExtractionFailureError
* httpx not installed → ImportError
* ``OLLAMA_BASE_URL`` env var fallback
* Custom ``base_url`` constructor arg
* Default model and base_url values
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

pytest.importorskip("httpx", reason="httpx not installed — skipping Ollama translator tests")

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator.ollama import OllamaTranslator

# ── Minimal intent schema for testing ────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: float
    recipient: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_ollama_response(content: str, status_code: int = 200) -> MagicMock:
    """Build a mock httpx.Response with Ollama /api/chat shape."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = f"HTTP {status_code}"
    if status_code == 200:
        resp.json.return_value = {"message": {"role": "assistant", "content": content}}
    else:
        resp.json.side_effect = Exception("non-200 body is not JSON")
    return resp


def _patch_httpx(response: MagicMock) -> patch:
    """Context manager: replace ``httpx.AsyncClient`` so no real network calls are made."""
    client_cm = AsyncMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_cm)
    client_cm.__aexit__ = AsyncMock(return_value=False)
    client_cm.post = AsyncMock(return_value=response)

    return patch("httpx.AsyncClient", return_value=client_cm)


# ═══════════════════════════════════════════════════════════════════════════════
# Construction
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorConstruction:
    def test_default_model_and_url(self) -> None:
        t = OllamaTranslator()
        assert t.model == "llama3.2"
        assert "localhost:11434" in t._base_url

    def test_custom_model(self) -> None:
        t = OllamaTranslator("mistral")
        assert t.model == "mistral"

    def test_custom_base_url_strips_trailing_slash(self) -> None:
        t = OllamaTranslator(base_url="http://my-server:11434/")
        assert t._base_url == "http://my-server:11434"

    def test_env_var_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://env-server:11434")
        t = OllamaTranslator()
        assert "env-server" in t._base_url

    def test_explicit_base_url_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://env-server:11434")
        t = OllamaTranslator(base_url="http://explicit:11434")
        assert "explicit" in t._base_url

    def test_custom_timeout(self) -> None:
        t = OllamaTranslator(timeout=120.0)
        assert t._timeout == 120.0


# ═══════════════════════════════════════════════════════════════════════════════
# Success path
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorSuccess:
    @pytest.mark.asyncio
    async def test_valid_response_returns_parsed_dict(self) -> None:
        payload = json.dumps({"amount": 100.0, "recipient": "acc_123"})
        resp = _make_ollama_response(payload)
        t = OllamaTranslator()

        with _patch_httpx(resp):
            result = await t.extract("transfer 100 to acc_123", _TransferIntent)

        assert result == {"amount": 100.0, "recipient": "acc_123"}

    @pytest.mark.asyncio
    async def test_markdown_wrapped_json_is_extracted(self) -> None:
        """parse_llm_response must unwrap ```json ... ``` fences."""
        payload = '```json\n{"amount": 50.0, "recipient": "acc_456"}\n```'
        resp = _make_ollama_response(payload)
        t = OllamaTranslator()

        with _patch_httpx(resp):
            result = await t.extract("move 50 to acc_456", _TransferIntent)

        assert result["amount"] == 50.0
        assert result["recipient"] == "acc_456"

    @pytest.mark.asyncio
    async def test_context_parameter_accepted(self) -> None:
        """context is accepted but not forwarded to the LLM; extraction must still succeed."""
        from pramanix.translator.base import TranslatorContext

        payload = json.dumps({"amount": 10.0, "recipient": "acc_789"})
        resp = _make_ollama_response(payload)
        ctx = TranslatorContext(request_id="req-1", user_id="user-1")
        t = OllamaTranslator()

        with _patch_httpx(resp):
            result = await t.extract("send 10", _TransferIntent, context=ctx)

        assert result["amount"] == 10.0


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorHttpErrors:
    @pytest.mark.asyncio
    async def test_non_200_raises_extraction_failure(self) -> None:
        resp = _make_ollama_response("Server Error", status_code=500)
        t = OllamaTranslator()

        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="500"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_401_raises_extraction_failure(self) -> None:
        resp = _make_ollama_response("Unauthorized", status_code=401)
        t = OllamaTranslator()

        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="401"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_404_raises_extraction_failure(self) -> None:
        resp = _make_ollama_response("Not Found", status_code=404)
        t = OllamaTranslator()

        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="404"):
            await t.extract("transfer 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Network error paths (ConnectError / TimeoutException)
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorNetworkErrors:
    @pytest.mark.asyncio
    async def test_timeout_raises_llm_timeout_error(self) -> None:
        """httpx.TimeoutException → LLMTimeoutError (fail-safe path)."""
        import httpx

        client_cm = AsyncMock()
        client_cm.__aenter__ = AsyncMock(return_value=client_cm)
        client_cm.__aexit__ = AsyncMock(return_value=False)
        client_cm.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

        t = OllamaTranslator()
        with patch("httpx.AsyncClient", return_value=client_cm), pytest.raises(LLMTimeoutError, match="timed out"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_connect_error_raises_llm_timeout_error(self) -> None:
        """httpx.ConnectError → LLMTimeoutError (connection refused = unreachable)."""
        import httpx

        client_cm = AsyncMock()
        client_cm.__aenter__ = AsyncMock(return_value=client_cm)
        client_cm.__aexit__ = AsyncMock(return_value=False)
        client_cm.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        t = OllamaTranslator()
        with patch("httpx.AsyncClient", return_value=client_cm), pytest.raises(LLMTimeoutError, match="connection failed"):
            await t.extract("transfer 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Malformed response paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorMalformedResponse:
    @pytest.mark.asyncio
    async def test_invalid_outer_json_body_raises_extraction_failure(self) -> None:
        """response.json() raises → ExtractionFailureError."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        resp.json.side_effect = ValueError("not json")

        t = OllamaTranslator()
        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="not valid JSON"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_missing_message_key_raises_extraction_failure(self) -> None:
        """Response shape is wrong — no 'message' key."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        resp.json.return_value = {"unexpected": "shape"}  # no 'message' key

        t = OllamaTranslator()
        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="Unexpected"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_missing_content_key_raises_extraction_failure(self) -> None:
        """message dict exists but has no 'content' key."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        resp.json.return_value = {"message": {"role": "assistant"}}  # no 'content'

        t = OllamaTranslator()
        with _patch_httpx(resp), pytest.raises(ExtractionFailureError):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_invalid_inner_json_raises_extraction_failure(self) -> None:
        """content string is not parseable JSON → parse_llm_response raises."""
        resp = _make_ollama_response("this is not json at all")
        t = OllamaTranslator()

        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="unparseable"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_json_array_instead_of_object_raises(self) -> None:
        """LLM returns a JSON array instead of an object → ExtractionFailureError."""
        resp = _make_ollama_response("[1, 2, 3]")
        t = OllamaTranslator()

        with _patch_httpx(resp), pytest.raises(ExtractionFailureError, match="list"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_partial_json_recovery(self) -> None:
        """Crucial test: partial JSON surrounded by prose — _json.py must extract it."""
        raw_content = 'Here is the extracted data:\n{"amount": 75.0, "recipient": "acc_partial"}\nEnd of response.'
        resp = _make_ollama_response(raw_content)
        t = OllamaTranslator()

        with _patch_httpx(resp):
            result = await t.extract("transfer 75", _TransferIntent)

        assert result["amount"] == 75.0
        assert result["recipient"] == "acc_partial"


# ═══════════════════════════════════════════════════════════════════════════════
# Missing dependency
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorMissingDependency:
    @pytest.mark.asyncio
    async def test_missing_httpx_raises_import_error(self) -> None:
        """If httpx is not installed, extract() must raise ImportError immediately."""
        t = OllamaTranslator()
        with patch.dict("sys.modules", {"httpx": None}), pytest.raises(ImportError, match="httpx"):  # type: ignore[dict-item]
            await t.extract("transfer 100", _TransferIntent)
