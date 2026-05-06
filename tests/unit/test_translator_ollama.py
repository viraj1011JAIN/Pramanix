# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for OllamaTranslator — every test hits a real TCP socket.

Architecture
------------
* No respx, no MagicMock, no patching of httpx internals.

* Success-path tests (TestOllamaTranslatorLive) require Ollama running
  at localhost:11434 with llama3.2 loaded.  They are skipped automatically
  when Ollama is not available.  Run ``ollama serve`` and
  ``ollama pull llama3.2`` before running these tests.

* Error-path tests (TestOllamaTranslatorHttpErrors,
  TestOllamaTranslatorMalformedResponse) use a real local Python HTTP
  server (http.server) on a random port.  These tests always run — they
  do not require Ollama.  The server returns precisely the bytes needed to
  exercise each defensive code path in OllamaTranslator.

* Network-error tests (TestOllamaTranslatorNetworkErrors) use:
    - Wrong port (localhost:11435) → real ConnectionRefusedError
      → LLMTimeoutError
    - Extremely short timeout (0.001 s) → real httpx.TimeoutException
      → LLMTimeoutError

* Construction tests (TestOllamaTranslatorConstruction) and the missing-
  httpx test require no network at all.

Coverage targets
----------------
* Success path: LLM extracts structured intent from natural language
* Non-200 status → ExtractionFailureError
* httpx.TimeoutException → LLMTimeoutError
* httpx.ConnectError → LLMTimeoutError
* Invalid outer JSON → ExtractionFailureError
* Missing message.content key → ExtractionFailureError
* Bad inner JSON → ExtractionFailureError
* JSON array instead of object → ExtractionFailureError
* Partial JSON embedded in prose → successful extraction
* httpx not installed → ImportError
* OLLAMA_BASE_URL env var fallback
* Custom base_url constructor arg
* Default model and base_url values
"""

from __future__ import annotations

import http.server
import json
import sys
import threading
from typing import Any

import pytest

pytest.importorskip(
    "httpx",
    reason="httpx not installed — skipping OllamaTranslator tests",
)

import httpx
from pydantic import BaseModel

from pramanix.exceptions import (
    ExtractionFailureError,
    LLMTimeoutError,
)
from pramanix.translator.ollama import OllamaTranslator

# ── Check Ollama availability ────────────────────────────────────────────────

_OLLAMA_BASE = "http://localhost:11434"
_OLLAMA_AVAILABLE = False
_LLAMA3_AVAILABLE = False
_LLAMA3_WORKS = False  # smoke-tested: model runner actually responds

try:
    _r = httpx.get(f"{_OLLAMA_BASE}/api/version", timeout=2.0)
    if _r.status_code == 200:
        _OLLAMA_AVAILABLE = True
        _tags = httpx.get(f"{_OLLAMA_BASE}/api/tags", timeout=5.0)
        _models = [m["name"] for m in _tags.json().get("models", [])]
        _LLAMA3_AVAILABLE = any("llama3.2" in m for m in _models)
        if _LLAMA3_AVAILABLE:
            # Verify the model runner actually handles requests; it can be listed
            # but the process may have crashed (Ollama returns HTTP 500).
            _probe = httpx.post(
                f"{_OLLAMA_BASE}/api/generate",
                json={"model": "llama3.2", "prompt": "1", "stream": False},
                timeout=20.0,
            )
            _LLAMA3_WORKS = _probe.status_code == 200
except Exception:
    pass

_needs_ollama = pytest.mark.skipif(
    not (_OLLAMA_AVAILABLE and _LLAMA3_AVAILABLE and _LLAMA3_WORKS),
    reason=(
        "Ollama with working llama3.2 not available at localhost:11434 — "
        "start Ollama, run: ollama pull llama3.2, and ensure the runner is healthy"
    ),
)

# ── Minimal intent schema ────────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    amount: float
    recipient: str


# ── Local test HTTP server ───────────────────────────────────────────────────


class _FixedResponseHandler(http.server.BaseHTTPRequestHandler):
    """Serves a single pre-configured response for POST requests."""

    _status: int = 200
    _body: bytes = b""
    _content_type: str = "application/json"

    def do_POST(self) -> None:
        # Read and discard the request body
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(self._status)
        self.send_header("Content-Type", self._content_type)
        self.send_header("Content-Length", str(len(self._body)))
        self.end_headers()
        self.wfile.write(self._body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # Suppress server access logs during tests


def _make_server(
    status: int, body: bytes, content_type: str = "application/json"
) -> tuple[http.server.HTTPServer, str]:
    """Start a single-response HTTP server on a random port.

    Returns (server, base_url).  Caller must call server.shutdown() when done.
    """

    class _Handler(_FixedResponseHandler):
        _status = status
        _body = body
        _content_type = content_type

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def _ollama_json(content: str) -> bytes:
    """Build bytes that look like a real Ollama /api/chat 200 response."""
    return json.dumps(
        {"message": {"role": "assistant", "content": content}}
    ).encode()


# ═══════════════════════════════════════════════════════════════════════════════
# Construction — no network required
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

    def test_explicit_base_url_overrides_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://env-server:11434")
        t = OllamaTranslator(base_url="http://explicit:11434")
        assert "explicit" in t._base_url

    def test_custom_timeout(self) -> None:
        t = OllamaTranslator(timeout=120.0)
        assert t._timeout == 120.0


# ═══════════════════════════════════════════════════════════════════════════════
# Live Ollama tests — skipped when Ollama is not running with llama3.2
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorLive:
    """Tests that require a real Ollama instance with llama3.2."""

    @_needs_ollama
    @pytest.mark.asyncio
    async def test_extract_transfer_intent(self) -> None:
        """Real LLM extracts structured transfer intent from text."""
        t = OllamaTranslator()
        result = await t.extract(
            "Transfer 250 dollars to account acc_789", _TransferIntent
        )
        assert isinstance(result, dict)
        assert "amount" in result
        assert "recipient" in result
        assert isinstance(result["amount"], int | float)

    @_needs_ollama
    @pytest.mark.asyncio
    async def test_extract_with_context(self) -> None:
        """context parameter is accepted; extraction still succeeds."""
        from pramanix.translator.base import TranslatorContext

        ctx = TranslatorContext(request_id="req-live-1", user_id="user-1")
        t = OllamaTranslator()
        result = await t.extract(
            "Send 50 to acc_live", _TransferIntent, context=ctx
        )
        assert isinstance(result, dict)
        assert "amount" in result


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP error paths — local test server, always runs
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorHttpErrors:
    @pytest.mark.asyncio
    async def test_non_200_raises_extraction_failure(self) -> None:
        """Real HTTP 500 from local server → ExtractionFailureError."""
        server, base_url = _make_server(500, b"Internal Server Error")
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="500"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_401_raises_extraction_failure(self) -> None:
        """Real HTTP 401 from local server → ExtractionFailureError."""
        server, base_url = _make_server(401, b"Unauthorized")
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="401"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_404_raises_extraction_failure(self) -> None:
        """Real HTTP 404 from local server → ExtractionFailureError."""
        server, base_url = _make_server(404, b"Not Found")
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="404"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# Network error paths — real connection conditions, always runs
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorNetworkErrors:
    @pytest.mark.asyncio
    async def test_connect_error_raises_llm_timeout_error(self) -> None:
        """Connection refused → real ConnectError → LLMTimeoutError.

        Port 11435 is not listening; httpx raises ConnectError immediately.
        This is a real TCP-level failure — no mocking.
        """
        t = OllamaTranslator(base_url="http://localhost:11435")
        with pytest.raises(LLMTimeoutError, match="connection failed"):
            await t.extract("transfer 100", _TransferIntent)

    @pytest.mark.asyncio
    async def test_timeout_raises_llm_timeout_error(self) -> None:
        """Short timeout (1 ms) → real TimeoutException → LLMTimeoutError.

        A local server that sleeps before responding is not needed — even
        the TCP handshake with localhost cannot complete in 1 ms reliably,
        or the server's keep-alive read triggers the timeout.
        """

        # Start a server that deliberately delays its response
        class _SlowHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                import time

                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                time.sleep(2)  # 2 s delay >> 1 ms timeout
                self.send_response(200)
                self.end_headers()

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), _SlowHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            t = OllamaTranslator(
                base_url=f"http://127.0.0.1:{port}", timeout=0.001
            )
            with pytest.raises(LLMTimeoutError):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# Malformed response paths — local test server, always runs
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorMalformedResponse:
    @pytest.mark.asyncio
    async def test_invalid_outer_json_body_raises_extraction_failure(
        self,
    ) -> None:
        """Local server returns non-JSON bytes — response.json() raises."""
        server, base_url = _make_server(
            200,
            b"this is not valid json",
            content_type="text/plain",
        )
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="not valid JSON"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_missing_message_key_raises_extraction_failure(self) -> None:
        """Local server returns JSON without the 'message' key."""
        body = json.dumps({"unexpected": "shape"}).encode()
        server, base_url = _make_server(200, body)
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="Unexpected"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_missing_content_key_raises_extraction_failure(self) -> None:
        """Local server returns message dict without 'content' key."""
        body = json.dumps({"message": {"role": "assistant"}}).encode()
        server, base_url = _make_server(200, body)
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_invalid_inner_json_raises_extraction_failure(self) -> None:
        """LLM content string that cannot be parsed as JSON."""
        server, base_url = _make_server(
            200, _ollama_json("this is not json at all")
        )
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="unparseable"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_json_array_instead_of_object_raises(self) -> None:
        """LLM returns a JSON array instead of an object."""
        server, base_url = _make_server(200, _ollama_json("[1, 2, 3]"))
        try:
            t = OllamaTranslator(base_url=base_url)
            with pytest.raises(ExtractionFailureError, match="list"):
                await t.extract("transfer 100", _TransferIntent)
        finally:
            server.shutdown()

    @pytest.mark.asyncio
    async def test_partial_json_recovery(self) -> None:
        """JSON in prose is extracted by the _json.py recovery layer."""
        content = (
            "Here is the extracted data:\n"
            '{"amount": 75.0, "recipient": "acc_partial"}\n'
            "End of response."
        )
        server, base_url = _make_server(200, _ollama_json(content))
        try:
            t = OllamaTranslator(base_url=base_url)
            result = await t.extract("transfer 75", _TransferIntent)
            assert result["amount"] == 75.0
            assert result["recipient"] == "acc_partial"
        finally:
            server.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# Missing dependency
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorMissingDependency:
    def test_missing_httpx_raises_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If httpx is not installed, OllamaTranslator() raises ImportError."""
        monkeypatch.setitem(  # type: ignore[arg-type]
            sys.modules, "httpx", None
        )
        with pytest.raises(ImportError, match="httpx"):
            OllamaTranslator()
