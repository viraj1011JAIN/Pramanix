# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Anthropic (Claude) translator with exponential-backoff retry.

Requires the ``pramanix[translator]`` extra (``anthropic``, ``tenacity``).
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

__all__ = ["AnthropicTranslator"]


class AnthropicTranslator:
    """Translator that calls the Anthropic Messages API (Claude models).

    Retries transient network/timeout errors up to 3 times using
    tenacity exponential backoff (1 s → 2 s → 4 s, capped at 10 s).

    Args:
        model:   Model identifier (e.g. ``"claude-opus-4-5"``,
                 ``"claude-3-5-sonnet-20241022"``).
        api_key: Anthropic API key.  Falls back to ``ANTHROPIC_API_KEY``
                 env var.
        timeout: Per-request HTTP timeout in seconds (default 30 s).

    Raises:
        ImportError: If ``anthropic`` or ``tenacity`` are not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required for AnthropicTranslator. "
                "Install it with: pip install 'pramanix[translator]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY") or None,
            timeout=timeout,
        )
        self._retryable = (anthropic.APITimeoutError, anthropic.APIConnectionError)
        self._api_status_error = anthropic.APIStatusError

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using the configured Claude model.

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
                f"Anthropic model '{self.model}' unreachable after "
                f"{attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc

        except self._api_status_error as exc:
            raise ExtractionFailureError(
                f"[{self.model}] Anthropic API error {exc.status_code}: {exc.message}"
            ) from exc

        raise AssertionError("unreachable")  # pragma: no cover

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

    async def __aenter__(self) -> AnthropicTranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def _single_call(
        self,
        *,
        system_prompt: str,
        text: str,
    ) -> str:
        """Make a single Messages API call and return the raw content string.

        Uses ``{"type": "json"}`` extended thinking off — plain text is
        returned which ``parse_llm_response`` then extracts JSON from.
        """
        try:
            response = await self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": text}],
            )
        except self._api_status_error:
            raise  # let extract() handle
        except Exception:
            raise  # let tenacity handle retryable errors

        # Anthropic returns a list of content blocks; grab the first text block.
        for block in response.content:
            text_val: str | None = getattr(block, "text", None)
            if text_val:
                return text_val

        raise ExtractionFailureError(
            f"[{self.model}] Anthropic returned no text content in the response."
        )
