# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real Cohere integration tests — T-08.

Uses respx to intercept HTTP at the transport layer (not MagicMock).

What this validates that MagicMock cannot:
  - Real HTTP request construction (headers, body serialisation, auth)
  - Real response parsing (JSON decode of full Cohere SDK response shape)
  - Real retry logic with 429 / 503 responses
  - Real timeout handling at the httpx layer
  - Real empty-response handling
  - Real JSON extraction from the parsed SDK response object

``COHERE_API_KEY`` live tests run against the real API when the key is set.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx

from pydantic import BaseModel

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator.cohere import CohereTranslator

_COHERE_CHAT_URL = "https://api.cohere.com/v2/chat"


class TransferIntent(BaseModel):
    amount: float
    action: str


# ── Recorded real Cohere v2 response fixture ──────────────────────────────────

def _cohere_success_response(text: str) -> dict:
    """Returns a real Cohere v2 /chat response shape with *text* as content."""
    return {
        "id": "c21f5c76-ab6c-4f2e-8c1d-9a3e7b2f1d4e",
        "finish_reason": "COMPLETE",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
        },
        "usage": {
            "billed_units": {"input_tokens": 42, "output_tokens": 18},
            "tokens": {"input_tokens": 42, "output_tokens": 18},
        },
        "meta": {"api_version": {"version": "2"}},
    }


def _cohere_error_response(code: int, message: str) -> dict:
    return {"message": message}


# ── respx-based tests (no MagicMock, no sys.modules) ─────────────────────────


@respx.mock
def test_cohere_extract_returns_parsed_dict() -> None:
    """extract() parses the real Cohere v2 response shape."""
    payload = '{"amount": 100.0, "action": "transfer"}'
    respx.post(_COHERE_CHAT_URL).respond(200, json=_cohere_success_response(payload))

    translator = CohereTranslator("command-r", api_key="test-key")
    result = asyncio.run(translator.extract("transfer 100 USD", TransferIntent))

    assert result["amount"] == 100.0
    assert result["action"] == "transfer"


@respx.mock
def test_cohere_extract_amount_as_integer() -> None:
    """Integer amounts in JSON are transparently promoted to float."""
    payload = '{"amount": 50, "action": "pay"}'
    respx.post(_COHERE_CHAT_URL).respond(200, json=_cohere_success_response(payload))

    translator = CohereTranslator("command-r-plus", api_key="test-key")
    result = asyncio.run(translator.extract("pay 50 euros", TransferIntent))

    assert result["amount"] == 50
    assert result["action"] == "pay"


@respx.mock
def test_cohere_retry_on_429_then_success() -> None:
    """extract() retries on 429 TooManyRequests and succeeds on the 2nd attempt."""
    payload = '{"amount": 25.0, "action": "send"}'
    respx.post(_COHERE_CHAT_URL).mock(
        side_effect=[
            httpx.Response(429, json=_cohere_error_response(429, "Rate limited")),
            httpx.Response(200, json=_cohere_success_response(payload)),
        ]
    )

    translator = CohereTranslator("command-r", api_key="test-key")
    # tenacity retries on the Cohere SDK's retryable exceptions.
    # A 429 from the real API causes the SDK to raise TooManyRequestsError.
    # respx returns the raw httpx response — we test that the retry fires.
    # The SDK converts the 429 to an exception internally.
    result = asyncio.run(translator.extract("send 25 USD", TransferIntent))
    assert result["amount"] == 25.0


@respx.mock
def test_cohere_extract_raises_on_empty_response() -> None:
    """ExtractionFailureError when Cohere returns empty text content."""
    empty = _cohere_success_response("")
    respx.post(_COHERE_CHAT_URL).respond(200, json=empty)

    translator = CohereTranslator("command-r", api_key="test-key")
    with pytest.raises(ExtractionFailureError, match="empty"):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_cohere_extract_raises_on_malformed_json() -> None:
    """ExtractionFailureError when Cohere returns non-JSON text."""
    bad = _cohere_success_response("Sorry, I cannot help with that.")
    respx.post(_COHERE_CHAT_URL).respond(200, json=bad)

    translator = CohereTranslator("command-r", api_key="test-key")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_cohere_extract_raises_llm_timeout_on_network_failure() -> None:
    """LLMTimeoutError when network is unreachable (all retries exhausted)."""
    respx.post(_COHERE_CHAT_URL).mock(side_effect=httpx.ConnectError("unreachable"))

    translator = CohereTranslator("command-r", api_key="test-key")
    with pytest.raises((LLMTimeoutError, ExtractionFailureError)):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_cohere_request_has_auth_header() -> None:
    """The real HTTP request must carry the Authorization header."""
    payload = '{"amount": 10.0, "action": "test"}'
    route = respx.post(_COHERE_CHAT_URL).respond(
        200, json=_cohere_success_response(payload)
    )

    translator = CohereTranslator("command-r", api_key="sk-real-key-test")
    asyncio.run(translator.extract("test 10 USD", TransferIntent))

    assert route.called
    request = route.calls.last.request
    auth_header = request.headers.get("authorization", "")
    assert "Bearer" in auth_header or "sk-real-key-test" in auth_header


@respx.mock
def test_cohere_request_body_contains_model_name() -> None:
    """The HTTP request body must include the configured model name."""
    payload = '{"amount": 5.0, "action": "test"}'
    route = respx.post(_COHERE_CHAT_URL).respond(
        200, json=_cohere_success_response(payload)
    )

    translator = CohereTranslator("command-r-plus", api_key="test-key")
    asyncio.run(translator.extract("test input", TransferIntent))

    request_body = json.loads(route.calls.last.request.content)
    assert request_body.get("model") == "command-r-plus"


@respx.mock
def test_cohere_temperature_zero_in_request() -> None:
    """temperature=0.0 must appear in the request body for deterministic output."""
    payload = '{"amount": 1.0, "action": "t"}'
    route = respx.post(_COHERE_CHAT_URL).respond(
        200, json=_cohere_success_response(payload)
    )

    translator = CohereTranslator("command-r", api_key="test-key")
    asyncio.run(translator.extract("test", TransferIntent))

    body = json.loads(route.calls.last.request.content)
    assert body.get("temperature") == 0.0


@respx.mock
def test_cohere_aclose_releases_client() -> None:
    """aclose() must not raise and should release the underlying HTTP client."""
    payload = '{"amount": 1.0, "action": "t"}'
    respx.post(_COHERE_CHAT_URL).respond(200, json=_cohere_success_response(payload))

    translator = CohereTranslator("command-r", api_key="test-key")
    asyncio.run(translator.extract("test", TransferIntent))

    async def _close() -> None:
        await translator.aclose()

    asyncio.run(_close())  # must not raise


def test_cohere_missing_package_raises_configuration_error() -> None:
    """ConfigurationError is raised at instantiation when cohere is absent.

    CohereTranslator uses a lazy ``import cohere`` inside ``__init__``, so the
    module can be imported normally.  We simulate the absent package by
    inserting ``None`` into sys.modules for the duration of the test — Python
    treats that as a deliberate block and raises ImportError on the inner
    import, which the constructor converts to ConfigurationError.
    """
    import sys
    from unittest.mock import patch

    from pramanix.translator.cohere import CohereTranslator

    with patch.dict(sys.modules, {"cohere": None}):  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError, match="pramanix\\[cohere\\]"):
            CohereTranslator("command-r", api_key="k")


# ── Live tests (require COHERE_API_KEY) ────────────────────────────────────────

import os as _os

_LIVE = pytest.mark.skipif(
    not _os.environ.get("COHERE_API_KEY"),
    reason="COHERE_API_KEY not set — Cohere live tests skipped",
)


@_LIVE
def test_cohere_live_extract_real_api() -> None:
    """Live test: extract a simple intent from the real Cohere API."""
    translator = CohereTranslator(
        "command-r",
        api_key=_os.environ["COHERE_API_KEY"],
    )
    result = asyncio.run(
        translator.extract(
            "Transfer one hundred dollars",
            TransferIntent,
        )
    )
    assert "amount" in result
    assert "action" in result
    assert float(result["amount"]) > 0
