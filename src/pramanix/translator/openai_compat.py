# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""OpenAI-compatible translator with exponential-backoff retry.

Works with OpenAI, Azure OpenAI, vLLM, LMStudio, and any service that
exposes the ``/chat/completions`` endpoint.

Requires the ``pramanix[translator]`` extra (``openai``, ``tenacity``).
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["OpenAICompatTranslator"]


class OpenAICompatTranslator:
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
    ) -> None:
        try:
            import openai
        except ImportError as exc:
            raise ImportError(
                "openai package is required for OpenAICompatTranslator. "
                "Install it with: pip install 'pramanix[translator]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._client = openai.AsyncOpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY") or None,
            base_url=base_url,
            timeout=timeout,
        )
        self._retryable = (openai.APITimeoutError, openai.APIConnectionError)
        self._api_status_error = openai.APIStatusError

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
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
                f"OpenAI model '{self.model}' unreachable after {attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc

        except self._api_status_error as exc:
            raise ExtractionFailureError(
                f"[{self.model}] OpenAI API error {exc.status_code}: {exc.message}"
            ) from exc

        raise AssertionError("unreachable")  # pragma: no cover

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

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
        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text},
                ],
                response_format={"type": "json_object"},
                temperature=0,
            )
        except self._api_status_error:
            raise  # let extract() handle API errors
        except Exception:
            raise  # let tenacity handle retryable network errors

        raw_content: str | None = response.choices[0].message.content
        if not raw_content:
            raise ExtractionFailureError(
                f"[{self.model}] OpenAI returned an empty response content."
            )
        return raw_content
