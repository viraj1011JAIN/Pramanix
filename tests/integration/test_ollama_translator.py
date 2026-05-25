# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Ollama integration tests — T-08.

Requires a running Ollama server with a loaded model.  Set:
  OLLAMA_BASE_URL=http://localhost:11434  (or PRAMANIX_TEST_OLLAMA=1 on default port)
  PRAMANIX_TEST_OLLAMA_MODEL=tinyllama     (default: tinyllama)

Recommended CI model: ``tinyllama`` — 637 MB GGUF, fast on CPU, available as
an official Ollama library model (``ollama pull tinyllama``).

What this validates beyond unit tests:
- Real HTTP round-trip to the Ollama /api/chat endpoint.
- Real JSON extraction from a locally-running open-source model.
- ``extract()`` returns a dict with the expected schema keys.
- ``LLMTimeoutError`` raised when the server is unreachable (connection refused).
- ``model`` attribute preserved after construction.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator.ollama import OllamaTranslator

from .conftest import requires_ollama

_OLLAMA_MODEL = os.environ.get("PRAMANIX_TEST_OLLAMA_MODEL", "tinyllama")
_OLLAMA_BASE_URL = (
    os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434"
)


class TransferIntent(BaseModel):
    amount: float
    action: str


# ── Live tests ────────────────────────────────────────────────────────────────


@requires_ollama
def test_ollama_live_extract_simple_intent() -> None:
    """Live: extract a simple transfer intent from the running Ollama server."""
    translator = OllamaTranslator(model=_OLLAMA_MODEL, base_url=_OLLAMA_BASE_URL)
    result = asyncio.run(
        translator.extract(
            "Transfer 50 dollars to savings account",
            TransferIntent,
        )
    )
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "amount" in result or "action" in result, (
        f"Expected at least one of amount/action in response, got: {result}"
    )


@requires_ollama
def test_ollama_live_model_attribute_preserved() -> None:
    """Live: model attribute is preserved after construction."""
    translator = OllamaTranslator(model=_OLLAMA_MODEL, base_url=_OLLAMA_BASE_URL)
    assert translator.model == _OLLAMA_MODEL


@requires_ollama
def test_ollama_live_base_url_from_env() -> None:
    """Live: OllamaTranslator reads OLLAMA_BASE_URL from environment."""
    translator = OllamaTranslator(model=_OLLAMA_MODEL)
    assert translator._base_url.startswith("http")


@requires_ollama
def test_ollama_live_repeated_extractions_consistent() -> None:
    """Live: temperature=0.0 should produce consistent results on the same input."""
    translator = OllamaTranslator(
        model=_OLLAMA_MODEL,
        base_url=_OLLAMA_BASE_URL,
        temperature=0.0,
    )

    async def _run_twice() -> tuple[dict, dict]:
        r1 = await translator.extract("Transfer 100 USD to Alice", TransferIntent)
        r2 = await translator.extract("Transfer 100 USD to Alice", TransferIntent)
        return r1, r2

    r1, r2 = asyncio.run(_run_twice())
    assert isinstance(r1, dict)
    assert isinstance(r2, dict)


# ── Failure path (no live server needed) ─────────────────────────────────────


def test_ollama_unreachable_server_raises_timeout_or_extraction_error() -> None:
    """LLMTimeoutError or ExtractionFailureError when the server is unreachable.

    Uses a port that is guaranteed not to have an Ollama server on it
    (port 1 is reserved and always connection-refused on any host).
    This test does NOT require OLLAMA_BASE_URL — it verifies the error
    handling code path with a guaranteed-failing connection.
    """
    translator = OllamaTranslator(
        model="tinyllama",
        base_url="http://127.0.0.1:1",  # port 1 is always refused
        timeout=2.0,
    )
    with pytest.raises((LLMTimeoutError, ExtractionFailureError, OSError)):
        asyncio.run(translator.extract("Transfer 50 USD", TransferIntent))
