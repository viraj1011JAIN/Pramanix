# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Mistral AI translator — Phase D-2.

Requires the ``pramanix[mistral]`` extra (``mistralai``, ``tenacity``).
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

__all__ = ["MistralTranslator"]

_TEMPERATURE = 0.0


class MistralTranslator:
    """Translator that calls the Mistral AI Chat Completions API.

    Uses the ``mistralai`` Python SDK.  Retries transient errors up to 3 times
    with exponential backoff via ``tenacity`` (1 s → 2 s → 4 s, max 10 s).

    Args:
        model:   Mistral model name (e.g. ``"mistral-large-latest"``,
                 ``"mistral-small-latest"``).
        api_key: Mistral API key.  Falls back to ``MISTRAL_API_KEY`` env var.
        timeout: Per-request timeout in seconds (default 30 s).

    Raises:
        ConfigurationError: If ``mistralai`` is not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        try:
            import mistralai  # noqa: F401
        except ImportError as exc:
            raise ConfigurationError(
                "mistralai is required for MistralTranslator. "
                "Install it with: pip install 'pramanix[mistral]'"
            ) from exc

        self.model = model
        self._api_key = api_key or os.environ.get("MISTRAL_API_KEY") or None
        self._timeout = timeout

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using Mistral.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON.
            LLMTimeoutError:        All retry attempts exhausted.
            ConfigurationError:     ``mistralai`` not installed.
        """
        try:
            from mistralai.client import Mistral  # v2+
        except ImportError:
            try:
                from mistralai import Mistral  # type: ignore[no-redef,assignment]  # v1 fallback
            except ImportError as exc:
                raise ConfigurationError(
                    "mistralai is required for MistralTranslator. "
                    "Install it with: pip install 'pramanix[mistral]'"
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
                "tenacity is required for MistralTranslator retry support. "
                "Install it with: pip install 'pramanix[mistral]'"
            ) from exc

        system_prompt = build_system_prompt(intent_schema)
        user_content = text
        if context is not None:
            extra = getattr(context, "extra_context", None)
            if extra:
                user_content = f"{text}\n\nContext: {extra}"

        last_exc: Exception | None = None

        try:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception_type(Exception),
                wait=wait_exponential(multiplier=1, min=1, max=10),
                stop=stop_after_attempt(3),
                reraise=False,
            ):
                with attempt:
                    raw = await self._single_call(
                        model=self.model,
                        api_key=self._api_key,
                        system_prompt=system_prompt,
                        user_content=user_content,
                        timeout=self._timeout,
                        mistral_cls=Mistral,
                    )
        except Exception as exc:
            last_exc = exc
            raw = None

        if raw is None:
            raise LLMTimeoutError(
                f"MistralTranslator: all retry attempts exhausted for model {self.model!r}. "
                f"Last error: {last_exc}"
            )

        try:
            return parse_llm_response(raw, model_name=self.model)
        except ExtractionFailureError:
            raise
        except Exception as exc:
            raise ExtractionFailureError(
                f"MistralTranslator: failed to parse model response: {exc!r}. "
                f"Raw response: {raw!r}"
            ) from exc

    async def _single_call(
        self,
        *,
        model: str,
        api_key: str | None,
        system_prompt: str,
        user_content: str,
        timeout: float,
        mistral_cls: Any,
    ) -> str:
        """Execute one Mistral API call.  Returns the raw response text."""
        import asyncio

        client = mistral_cls(api_key=api_key or "")
        response = await asyncio.wait_for(
            client.chat.complete_async(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=_TEMPERATURE,
            ),
            timeout=timeout,
        )
        return response.choices[0].message.content or ""
