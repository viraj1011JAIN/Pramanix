# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for OllamaTranslator — HTTP paths tested via respx transport interception.

Design principles
-----------------
* No AsyncMock, MagicMock, or patch() anywhere in this file.

* respx.mock() intercepts httpx at the TRANSPORT layer — the real httpx
  serialization, response parsing, and exception handling all run.  Only the
  TCP connection is replaced.  This is fundamentally different from patching
  httpx.AsyncClient with a MagicMock.

* Network error side-effects (httpx.TimeoutException, httpx.ConnectError) are
  injected via respx route `.mock(side_effect=...)` — real httpx exception types
  raised by the real transport layer, not fabricated MagicMocks.

* test_missing_httpx_raises_import_error uses monkeypatch.setitem(sys.modules,
  "httpx", None) — the only way to simulate a missing package in a test
  environment where httpx IS installed.  This is an impossible-to-reach state
  through normal API usage, so monkeypatch is acceptable per project discipline.

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
import sys

import httpx
import pytest
import respx
from pydantic import BaseModel

pytest.importorskip("httpx", reason="httpx not installed — skipping Ollama translator tests")

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator.ollama import OllamaTranslator

# ── Minimal intent schema for testing ────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: float
    recipient: str


# ── Shared Ollama API URL ─────────────────────────────────────────────────────

_OLLAMA_URL = "http://localhost:11434/api/chat"


def _ollama_body(content: str) -> dict:
    """Build a real Ollama /api/chat 200 response body."""
    return {"message": {"role": "assistant", "content": content}}


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
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(200, json=_ollama_body(payload))
            result = await t.extract("transfer 100 to acc_123", _TransferIntent)

        assert result == {"amount": 100.0, "recipient": "acc_123"}

    @pytest.mark.asyncio
    async def test_markdown_wrapped_json_is_extracted(self) -> None:
        """parse_llm_response must unwrap ```json ... ``` fences."""
        payload = '```json\n{"amount": 50.0, "recipient": "acc_456"}\n```'
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(200, json=_ollama_body(payload))
            result = await t.extract("move 50 to acc_456", _TransferIntent)

        assert result["amount"] == 50.0
        assert result["recipient"] == "acc_456"

    @pytest.mark.asyncio
    async def test_context_parameter_accepted(self) -> None:
        """context is accepted but not forwarded to the LLM; extraction must still succeed."""
        from pramanix.translator.base import TranslatorContext

        payload = json.dumps({"amount": 10.0, "recipient": "acc_789"})
        ctx = TranslatorContext(request_id="req-1", user_id="user-1")
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(200, json=_ollama_body(payload))
            result = await t.extract("send 10", _TransferIntent, context=ctx)

        assert result["amount"] == 10.0


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorHttpErrors:
    @pytest.mark.asyncio
    async def test_non_200_raises_extraction_failure(self) -> None:
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(500, text="Internal Server Error")
            with pytest.raises(ExtractionFailureError, match="500"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_401_raises_extraction_failure(self) -> None:
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(401, text="Unauthorized")
            with pytest.raises(ExtractionFailureError, match="401"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_404_raises_extraction_failure(self) -> None:
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(404, text="Not Found")
            with pytest.raises(ExtractionFailureError, match="404"):
                await t.extract("transfer 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Network error paths (ConnectError / TimeoutException)
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorNetworkErrors:
    @pytest.mark.asyncio
    async def test_timeout_raises_llm_timeout_error(self) -> None:
        """httpx.TimeoutException → LLMTimeoutError (fail-safe path)."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).mock(
                side_effect=httpx.TimeoutException("timed out")
            )
            with pytest.raises(LLMTimeoutError, match="timed out"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_connect_error_raises_llm_timeout_error(self) -> None:
        """httpx.ConnectError → LLMTimeoutError (connection refused = unreachable)."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(LLMTimeoutError, match="connection failed"):
                await t.extract("transfer 100", _TransferIntent)


# ═══════════════════════════════════════════════════════════════════════════════
# Malformed response paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorMalformedResponse:
    @pytest.mark.asyncio
    async def test_invalid_outer_json_body_raises_extraction_failure(self) -> None:
        """Real httpx response with non-JSON content → response.json() raises."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            # content= sets raw bytes; real httpx.Response.json() will raise JSONDecodeError
            mock.post(_OLLAMA_URL).respond(200, content=b"this is not valid json")
            with pytest.raises(ExtractionFailureError, match="not valid JSON"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_missing_message_key_raises_extraction_failure(self) -> None:
        """Response shape is wrong — no 'message' key."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(200, json={"unexpected": "shape"})
            with pytest.raises(ExtractionFailureError, match="Unexpected"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_missing_content_key_raises_extraction_failure(self) -> None:
        """message dict exists but has no 'content' key."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(
                200, json={"message": {"role": "assistant"}}
            )
            with pytest.raises(ExtractionFailureError):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_invalid_inner_json_raises_extraction_failure(self) -> None:
        """content string is not parseable JSON → parse_llm_response raises."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(
                200, json=_ollama_body("this is not json at all")
            )
            with pytest.raises(ExtractionFailureError, match="unparseable"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_json_array_instead_of_object_raises(self) -> None:
        """LLM returns a JSON array instead of an object → ExtractionFailureError."""
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(200, json=_ollama_body("[1, 2, 3]"))
            with pytest.raises(ExtractionFailureError, match="list"):
                await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_partial_json_recovery(self) -> None:
        """Crucial test: partial JSON surrounded by prose — _json.py must extract it."""
        raw_content = (
            'Here is the extracted data:\n'
            '{"amount": 75.0, "recipient": "acc_partial"}\n'
            'End of response.'
        )
        t = OllamaTranslator()

        with respx.mock(assert_all_called=False) as mock:
            mock.post(_OLLAMA_URL).respond(200, json=_ollama_body(raw_content))
            result = await t.extract("transfer 75", _TransferIntent)

        assert result["amount"] == 75.0
        assert result["recipient"] == "acc_partial"


# ═══════════════════════════════════════════════════════════════════════════════
# Missing dependency
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorMissingDependency:
    @pytest.mark.asyncio
    async def test_missing_httpx_raises_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If httpx is not installed, extract() must raise ImportError immediately.

        monkeypatch.setitem(sys.modules, "httpx", None) is the only way to
        simulate a missing package in a test environment where httpx IS installed.
        This is an impossible-to-reach state through normal API usage.
        """
        t = OllamaTranslator()
        monkeypatch.setitem(sys.modules, "httpx", None)  # type: ignore[arg-type]
        with pytest.raises(ImportError, match="httpx"):
            await t.extract("transfer 100", _TransferIntent)
