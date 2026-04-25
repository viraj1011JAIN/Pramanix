# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Google Gemini translator — Phase D-2.

Requires the ``pramanix[gemini]`` extra (``google-generativeai``, ``tenacity``).
If the package is not installed, instantiation raises
:exc:`~pramanix.exceptions.ConfigurationError` with the exact pip command.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["GeminiTranslator"]

# Temperature 0 ≡ deterministic mode — critical for reproducible consensus.
_TEMPERATURE = 0.0


class GeminiTranslator:
    """Translator that calls the Google Gemini GenerateContent API.

    Uses ``google.generativeai`` (``google-generativeai`` PyPI package).
    Retries transient network errors up to 3 times with exponential backoff
    via ``tenacity`` (1 s → 2 s → 4 s, capped at 10 s).

    Args:
        model:   Gemini model name (e.g. ``"gemini-1.5-pro"``).
        api_key: Google AI Studio API key.  Falls back to ``GOOGLE_API_KEY``
                 env var.
        timeout: Per-request timeout in seconds (default 30 s).

    Raises:
        ConfigurationError: If ``google-generativeai`` is not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        try:
            import google.generativeai  # noqa: F401
        except ImportError as exc:
            raise ConfigurationError(
                "google-generativeai is required for GeminiTranslator. "
                "Install it with: pip install 'pramanix[gemini]'"
            ) from exc

        self.model = model
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY") or None
        self._timeout = timeout

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using Gemini.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON.
            LLMTimeoutError:        All retry attempts exhausted.
            ConfigurationError:     ``google-generativeai`` not installed.
        """
        try:
            import google.generativeai as genai
        except ImportError as exc:  # pragma: no cover
            raise ConfigurationError(
                "google-generativeai is required for GeminiTranslator. "
                "Install it with: pip install 'pramanix[gemini]'"
            ) from exc

        try:
            from tenacity import (
                AsyncRetrying,
                retry_if_exception_type,
                stop_after_attempt,
                wait_exponential,
            )
        except ImportError as exc:
            raise ConfigurationError(
                "tenacity is required for retry support. "
                "Install it with: pip install 'pramanix[gemini]'"
            ) from exc

        if self._api_key:
            genai.configure(api_key=self._api_key)

        system_prompt = build_system_prompt(intent_schema)
        full_prompt = f"{system_prompt}\n\nUser input:\n{text}"

        # google-generativeai raises google.api_core.exceptions.DeadlineExceeded
        # and google.api_core.exceptions.ServiceUnavailable for transient errors.
        # We catch the generic Exception base from google.api_core for robustness.
        try:
            import google.api_core.exceptions as _gapi_exc
            _retryable: tuple[type[Exception], ...] = (
                _gapi_exc.DeadlineExceeded,
                _gapi_exc.ServiceUnavailable,
                _gapi_exc.InternalServerError,
            )
        except ImportError:
            _retryable = (Exception,)

        attempts = 0
        try:
            async for attempt in AsyncRetrying(
                wait=wait_exponential(multiplier=1, min=1, max=10),
                stop=stop_after_attempt(3),
                retry=retry_if_exception_type(_retryable),
                reraise=True,
            ):
                with attempt:
                    attempts += 1
                    raw = await self._single_call(genai=genai, prompt=full_prompt)
                    return parse_llm_response(raw, model_name=self.model)

        except _retryable as exc:
            raise LLMTimeoutError(
                f"Gemini model '{self.model}' unreachable after {attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc

        raise AssertionError("unreachable")  # pragma: no cover

    async def _single_call(self, *, genai: Any, prompt: str) -> str:
        """Make a single GenerateContent call and return the raw text."""
        import asyncio

        client = genai.GenerativeModel(
            model_name=self.model,
            generation_config=genai.GenerationConfig(
                temperature=_TEMPERATURE,
                response_mime_type="application/json",
            ),
        )
        # google-generativeai's Python SDK exposes both sync and async APIs.
        # Use generate_content_async when available; fallback to thread executor.
        if hasattr(client, "generate_content_async"):
            response = await client.generate_content_async(prompt)
        else:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, client.generate_content, prompt)

        raw: str = response.text
        if not raw or not raw.strip():
            raise ExtractionFailureError(
                f"[{self.model}] Gemini returned an empty response."
            )
        return raw
