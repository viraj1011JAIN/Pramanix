# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""OpenAI-compatible translator with exponential-backoff retry.

Works with OpenAI, Azure OpenAI, vLLM, LMStudio, and any service that
exposes the ``/chat/completions`` endpoint.

Requires the ``pramanix[translator]`` extra (``openai``, ``tenacity``).
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

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["OpenAICompatTranslator"]


def _validate_base_url(url: str) -> str:
    """Block link-local metadata IPs in base_url (SSRF, #243).

    API keys are transmitted with every request; routing to 169.254.x.x
    (cloud metadata) exfiltrates credentials. Localhost and RFC-1918 are
    allowed so on-premise vLLM/LMStudio deployments work unchanged.
    Set OPENAI_COMPAT_SSRF_ALLOW=1 to disable (testing/pentest only).
    """
    if os.environ.get("OPENAI_COMPAT_SSRF_ALLOW", "").strip() == "1":
        return url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip("[]")
    if not host:
        return url
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_link_local:
            raise ConfigurationError(
                f"OpenAICompatTranslator: base_url {url!r} resolves to a "
                f"link-local IP ({addr}) — this is the cloud metadata service "
                "range (SSRF/credential leak risk). Set "
                "OPENAI_COMPAT_SSRF_ALLOW=1 to override."
            )
    except ValueError:
        pass  # hostname — DNS resolution not validated here
    return url


class OpenAICompatTranslator(RedactedSecretsMixin):
    """Translator that calls any OpenAI-compatible chat-completion API.

    Retries transient network/timeout errors up to 3 times using
    tenacity exponential backoff (1 s → 2 s → 4 s, capped at 10 s).

    Args:
        model:    Model identifier (e.g. ``"gpt-4o"``, ``"gpt-4-turbo"``).
        api_key:  API key.  Falls back to the ``OPENAI_API_KEY`` env var.
        base_url: Override the API base URL (for vLLM, LMStudio, Azure, …).
        timeout:  Per-request HTTP timeout in seconds (default 30 s).

    Raises:
        ImportError: If ``openai`` or ``tenacity`` are not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
        _openai_factory: Any = None,
    ) -> None:
        try:
            if _openai_factory is not None:
                openai = _openai_factory()
            else:
                import openai
        except ImportError as exc:
            raise ImportError(
                "openai package is required for OpenAICompatTranslator. "
                "Install it with: pip install 'pramanix[translator]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY") or None
        self._base_url = _validate_base_url(base_url) if base_url else base_url
        self._client = openai.AsyncOpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=timeout,
        )
        self._retryable = (openai.APITimeoutError, openai.APIConnectionError)
        self._api_status_error = openai.APIStatusError

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
        *,
        _tenacity_factory: Any = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using the configured model.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining the expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the LLM; caller should validate against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON, or
                an API-level error occurred.
            LLMTimeoutError:        All retry attempts exhausted.
        """
        try:
            if _tenacity_factory is not None:
                AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential = (
                    _tenacity_factory()
                )
            else:
                from tenacity import (
                    AsyncRetrying,
                    retry_if_exception_type,
                    stop_after_attempt,
                    wait_exponential,
                )
        except ImportError as exc:
            raise ImportError(
                "tenacity package is required for retry support. "
                "Install it with: pip install 'pramanix[translator]'"
            ) from exc

        system_prompt = build_system_prompt(intent_schema)
        attempts = 0

        try:
            async for attempt in AsyncRetrying(
                wait=wait_exponential(multiplier=1, min=1, max=10),
                stop=stop_after_attempt(3),
                retry=retry_if_exception_type(self._retryable),
                reraise=True,
            ):
                with attempt:
                    attempts += 1
                    raw = await self._single_call(
                        system_prompt=system_prompt,
                        text=text,
                    )
                    return parse_llm_response(raw, model_name=self.model)

        except self._retryable as exc:
            raise LLMTimeoutError(
                f"OpenAI model '{_safe_model_tag(self.model)}' unreachable after " f"{attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc

        except self._api_status_error as exc:
            import logging as _olog
            _olog.getLogger(__name__).debug(
                "OpenAI API status error for model %s: %s %s",
                _safe_model_tag(self.model), exc.status_code, exc.message,
            )
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] OpenAI API error {exc.status_code}"
                " (details redacted — check DEBUG log)."
            ) from exc
        raise ExtractionFailureError(f"[{_safe_model_tag(self.model)}] Retry loop exited without a result")

    @classmethod
    def _for_testing(
        cls,
        client: Any,
        *,
        model: str = "gpt-test",
        api_key: str = "test-key",
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> "OpenAICompatTranslator":
        """Construct with a pre-built async OpenAI client duck-type for testing.

        Bypasses the openai import and URL validation so tests can exercise
        ``aclose()``, ``extract()``, and other methods with custom mock clients.
        """
        inst = cls.__new__(cls)
        inst.model = model
        inst._timeout = timeout
        inst._api_key = api_key
        inst._base_url = base_url
        inst._client = client
        inst._retryable = (Exception,)
        inst._max_attempts = 3
        return inst

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        # openai SDK ≥1.0 uses close() (coroutine); older builds used aclose().
        # Prefer close() but fall back gracefully for forward compatibility.
        import inspect

        _close = getattr(self._client, "close", None) or getattr(self._client, "aclose", None)
        if _close is not None:
            result = _close()
            if inspect.isawaitable(result):
                await result

    async def __aenter__(self) -> OpenAICompatTranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def _single_call(
        self,
        *,
        system_prompt: str,
        text: str,
    ) -> str:
        """Make a single chat-completion call and return the raw content string."""
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )

        raw_content: str | None = response.choices[0].message.content
        if not raw_content:
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] OpenAI returned an empty response content."
            )
        return raw_content
