# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Ollama local-model translator using the native /api/chat endpoint.

Requires the ``pramanix[translator]`` extra (``httpx``).

Unlike the OpenAI-compatible adapter, this speaks Ollama's native JSON API
directly so it works with any Ollama server version and does not require the
``openai`` package.

Example::

    from pramanix.translator.ollama import OllamaTranslator
    from pramanix.translator.redundant import RedundantTranslator

    t = OllamaTranslator("llama3.2")
    # Or pair with a cloud model for consensus:
    redundant = RedundantTranslator(t, OpenAICompatTranslator("gpt-4o"))
"""

from __future__ import annotations
import re

import ipaddress
import os
from urllib.parse import urlparse
from typing import TYPE_CHECKING, Any

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt
from pramanix.translator.base import RedactedSecretsMixin

def _safe_model_tag(model: str) -> str:
    """Return a log-safe version of *model* that cannot inject log lines.

    Strips ASCII control characters (newlines, nulls, ANSI escape sequences)
    so an attacker-controlled model name cannot forge log entries in Splunk,
    Datadog, or CloudWatch by embedding CRLF or ESC[ sequences.
    """
    # x00-x1f are all ASCII control chars (NUL through US, incl newline).
    _s = re.sub("[\x00-\x1f\x7f]", "", str(model))
    # Strip ANSI CSI escape sequences.
    _s = re.sub("\x1b\[[0-9;]*[A-Za-z]", "", _s)
    return _s[:100]


def _validate_translator_url(url: str) -> str:
    """Block link-local metadata IPs in base_url (SSRF, #243).

    169.254.0.0/16 is the cloud metadata service range used by AWS IMDS
    (169.254.169.254), Azure IMDS (169.254.169.254), and GCP metadata
    (169.254.169.254).  Routing Ollama requests there exfiltrates prompts
    to the metadata service.  Localhost and RFC-1918 are NOT blocked so
    that development and on-premise deployments work without configuration.

    Set OLLAMA_SSRF_ALLOW=1 to disable all checks (testing/pentest only).
    """
    if os.environ.get("OLLAMA_SSRF_ALLOW", "").strip() == "1":
        return url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip("[]")
    if not host:
        return url
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_link_local:
            raise ConfigurationError(
                f"OllamaTranslator: base_url {url!r} resolves to a link-local IP "
                f"({addr}) — this is the cloud metadata service range (SSRF risk). "
                "If this is intentional, set OLLAMA_SSRF_ALLOW=1 to override."
            )
    except ValueError:
        pass  # hostname — DNS resolution not validated here
    return url

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["OllamaTranslator"]

_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaTranslator(RedactedSecretsMixin):
    """Translator that calls a local Ollama server via ``/api/chat``.

    Communicates with Ollama using ``httpx.AsyncClient``.  Passes
    ``"format": "json"`` so the model constrains its output to valid JSON.

    Args:
        model:    Ollama model tag (e.g. ``"llama3.2"``, ``"mistral"``).
                  Defaults to ``"llama3.2"`` — the 3 B parameter variant.
        base_url: Ollama server base URL.  Falls back to
                  ``OLLAMA_BASE_URL`` env var, then
                  ``http://localhost:11434``.
        timeout:     Per-request HTTP timeout in seconds (default 60 s —
                     local models can be slow on first-token generation).
        temperature: Sampling temperature (default 0.0 — deterministic
                     output is required for reliable schema extraction).

    Raises:
        ImportError: If ``httpx`` is not installed
                     (``pip install 'pramanix[translator]'``).
    """

    def __init__(
        self,
        model: str = "llama3.2",
        *,
        base_url: str | None = None,
        timeout: float = 60.0,
        temperature: float = 0.0,
        _httpx_factory: Any = None,
    ) -> None:
        try:
            if _httpx_factory is not None:
                httpx = _httpx_factory()
            else:
                import httpx
        except ImportError as exc:
            raise ImportError(
                "httpx is required for OllamaTranslator. "
                "Install it with: pip install 'pramanix[translator]'"
            ) from exc

        self.model = model
        resolved_url = base_url or os.environ.get("OLLAMA_BASE_URL") or _DEFAULT_BASE_URL
        self._base_url = _validate_translator_url(resolved_url.rstrip("/"))
        self._timeout = timeout
        self._temperature = temperature
        self._client = httpx.AsyncClient(timeout=timeout)
        self._httpx = httpx

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* via the Ollama model.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining the expected
                           output.
            context:       Optional host-provided grounding context
                           (unused by the LLM; preserved for protocol
                           compatibility).

        Returns:
            Raw dict from the model; caller should validate against
            *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON
                or the server returned a non-2xx response.
            LLMTimeoutError: Request timed out.
        """
        system_prompt = build_system_prompt(intent_schema)
        url = f"{self._base_url}/api/chat"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": self._temperature},
        }

        try:
            response = await self._client.post(url, json=payload)
        except self._httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                f"Ollama model '{_safe_model_tag(self.model)}' timed out after " f"{self._timeout}s: {exc}",
                model=self.model,
                attempts=1,
            ) from exc
        except self._httpx.RequestError as exc:
            raise LLMTimeoutError(
                f"Ollama model '{_safe_model_tag(self.model)}' connection failed: {exc}",
                model=self.model,
                attempts=1,
            ) from exc

        if response.status_code != 200:
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Ollama server returned HTTP "
                f"{response.status_code}: {response.text[:200]}"
            )

        try:
            data = response.json()
        except Exception as exc:
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Ollama response was not valid JSON: " f"{exc}"
            ) from exc

        # Ollama /api/chat: {"message": {"role": "assistant", "content": "..."}}
        try:
            raw_content: str = data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Unexpected Ollama response shape: {exc}. "
                f"Got: {str(data)[:200]}"
            ) from exc

        return parse_llm_response(raw_content, model_name=self.model)

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

    async def __aenter__(self) -> OllamaTranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
