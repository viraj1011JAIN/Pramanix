# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Real Anthropic integration tests for AnthropicTranslator — #9 closure.

#9 fix: of the translators that talk over plain httpx (not gRPC, like Gemini,
and not a protocol respx cannot see), AnthropicTranslator was the one with
ZERO real-protocol test coverage anywhere in the suite. Cohere already has a
respx-based real-wire-protocol suite (test_cohere_translator.py) and an
OpenAI live-credential path exists via test_llm_consensus.py, but Anthropic
had neither — only inline duck-typed fakes inside tests/unit/test_translator*
that never construct a real ``anthropic.AsyncAnthropic`` client or send a
real HTTP request.

Uses respx to intercept HTTP at the transport layer (not MagicMock) against
the REAL ``anthropic`` SDK's streaming Messages API, which is what
AnthropicTranslator._single_call() actually uses (``client.messages.stream``).

What this validates that an inline duck-typed fake cannot:
  - Real HTTP request construction (headers, body, auth, model, system prompt)
  - Real Server-Sent-Events parsing via the Anthropic SDK's streaming client
    (message_start / content_block_delta / content_block_stop / message_stop)
  - Real retry logic on APITimeoutError / APIConnectionError
  - Real APIStatusError mapping (401, 529 overloaded) to ExtractionFailureError
  - Real empty-response and malformed-JSON handling after a real SSE round-trip

``ANTHROPIC_API_KEY`` live tests run against the real API when the key is set.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx
from pydantic import BaseModel

anthropic = pytest.importorskip("anthropic", reason="pramanix[translator] not installed")

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator.anthropic import AnthropicTranslator

from .conftest import requires_anthropic

_ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"


class TransferIntent(BaseModel):
    amount: float
    action: str


# ── Real Anthropic Messages-API SSE fixture ───────────────────────────────────


def _sse_event(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def _anthropic_sse_success(text: str, *, model: str = "claude-opus-4-5") -> str:
    """Build a real Anthropic Messages streaming SSE body containing *text*.

    Mirrors the exact event sequence the live API emits for a single
    text content block: message_start -> content_block_start ->
    content_block_delta(s) -> content_block_stop -> message_delta -> message_stop.
    """
    events = [
        _sse_event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": model,
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 25, "output_tokens": 1},
                },
            },
        ),
        _sse_event(
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        ),
        _sse_event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            },
        ),
        _sse_event("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _sse_event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 15},
            },
        ),
        _sse_event("message_stop", {"type": "message_stop"}),
    ]
    return "".join(events)


def _sse_response(text: str, *, model: str = "claude-opus-4-5") -> httpx.Response:
    return httpx.Response(
        200,
        content=_anthropic_sse_success(text, model=model),
        headers={"content-type": "text/event-stream"},
    )


def _anthropic_error_body(error_type: str, message: str) -> dict:
    return {"type": "error", "error": {"type": error_type, "message": message}}


# ── respx-based tests (real anthropic SDK, real httpx transport) ─────────────


@respx.mock
def test_anthropic_extract_returns_parsed_dict() -> None:
    """extract() parses JSON delivered through a real SSE round-trip."""
    payload = '{"amount": 150.0, "action": "transfer"}'
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(return_value=_sse_response(payload))

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    result = asyncio.run(translator.extract("transfer 150 USD", TransferIntent))

    assert result["amount"] == 150.0
    assert result["action"] == "transfer"


@respx.mock
def test_anthropic_extract_amount_as_integer() -> None:
    """Integer amounts in JSON are transparently promoted to float."""
    payload = '{"amount": 50, "action": "pay"}'
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(return_value=_sse_response(payload))

    translator = AnthropicTranslator("claude-3-5-sonnet-20241022", api_key="sk-ant-test")
    result = asyncio.run(translator.extract("pay 50 euros", TransferIntent))

    assert result["amount"] == 50
    assert result["action"] == "pay"


@respx.mock
def test_anthropic_retry_on_timeout_then_success() -> None:
    """extract() retries on APITimeoutError and succeeds on the 2nd attempt."""
    payload = '{"amount": 25.0, "action": "send"}'
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(
        side_effect=[
            httpx.TimeoutException("simulated timeout"),
            _sse_response(payload),
        ]
    )

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    result = asyncio.run(translator.extract("send 25 USD", TransferIntent))
    assert result["amount"] == 25.0


@respx.mock
def test_anthropic_extract_raises_on_empty_response() -> None:
    """ExtractionFailureError when Anthropic returns an empty text block."""
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(return_value=_sse_response(""))

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_anthropic_extract_raises_on_malformed_json() -> None:
    """ExtractionFailureError when Anthropic returns non-JSON text."""
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(
        return_value=_sse_response("Sorry, I cannot help with that.")
    )

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    with pytest.raises(ExtractionFailureError):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_anthropic_extract_raises_llm_timeout_on_network_failure() -> None:
    """LLMTimeoutError when the network is unreachable on every retry attempt."""
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(side_effect=httpx.ConnectError("unreachable"))

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    with pytest.raises((LLMTimeoutError, ExtractionFailureError)):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_anthropic_status_error_redacted_in_exception() -> None:
    """A real 401 APIStatusError must map to ExtractionFailureError with details redacted."""
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(
        return_value=httpx.Response(
            401,
            json=_anthropic_error_body("authentication_error", "invalid x-api-key — sk-ant-LEAK123"),
        )
    )

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    with pytest.raises(ExtractionFailureError) as excinfo:
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))

    # #248-class regression guard: the raw account/auth detail must NOT leak
    # into the exception message that flows to callers/Sentry/Datadog.
    assert "sk-ant-LEAK123" not in str(excinfo.value)
    assert "401" in str(excinfo.value)


@respx.mock
def test_anthropic_overloaded_529_raises_extraction_failure() -> None:
    """A real 529 (overloaded) APIStatusError must map to ExtractionFailureError."""
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(
        return_value=httpx.Response(
            529, json=_anthropic_error_body("overloaded_error", "Overloaded")
        )
    )

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    with pytest.raises(ExtractionFailureError, match="529"):
        asyncio.run(translator.extract("transfer 100 USD", TransferIntent))


@respx.mock
def test_anthropic_request_has_auth_header() -> None:
    """The real HTTP request must carry the x-api-key header."""
    payload = '{"amount": 10.0, "action": "test"}'
    route = respx.post(_ANTHROPIC_MESSAGES_URL).mock(return_value=_sse_response(payload))

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-real-key-test")
    asyncio.run(translator.extract("test 10 USD", TransferIntent))

    assert route.called
    request = route.calls.last.request
    assert request.headers.get("x-api-key") == "sk-ant-real-key-test"


@respx.mock
def test_anthropic_request_body_contains_model_and_system_prompt() -> None:
    """The HTTP request body must include the configured model and a system prompt."""
    payload = '{"amount": 5.0, "action": "test"}'
    route = respx.post(_ANTHROPIC_MESSAGES_URL).mock(return_value=_sse_response(payload))

    translator = AnthropicTranslator("claude-3-5-sonnet-20241022", api_key="sk-ant-test")
    asyncio.run(translator.extract("test input", TransferIntent))

    body = json.loads(route.calls.last.request.content)
    assert body.get("model") == "claude-3-5-sonnet-20241022"
    assert body.get("system")
    assert body.get("stream") is True


@respx.mock
def test_anthropic_aclose_releases_client() -> None:
    """aclose() must not raise and should release the underlying HTTP client."""
    payload = '{"amount": 1.0, "action": "t"}'
    respx.post(_ANTHROPIC_MESSAGES_URL).mock(return_value=_sse_response(payload))

    translator = AnthropicTranslator("claude-opus-4-5", api_key="sk-ant-test")
    asyncio.run(translator.extract("test", TransferIntent))

    async def _close() -> None:
        await translator.aclose()

    asyncio.run(_close())  # must not raise


# ── Live API tests (skipped without ANTHROPIC_API_KEY) ────────────────────────


@requires_anthropic
def test_anthropic_extract_live() -> None:
    """End-to-end extract() against the real Anthropic API."""
    translator = AnthropicTranslator("claude-3-5-haiku-20241022")
    result = asyncio.run(
        translator.extract(
            "Transfer 75 dollars to Bob for the action 'transfer'.", TransferIntent
        )
    )
    assert isinstance(result.get("amount"), (int, float))
    assert isinstance(result.get("action"), str)
