# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Cohere translator — Phase D-2.

Requires the ``pramanix[cohere]`` extra (``cohere``, ``tenacity``).
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

__all__ = ["CohereTranslator"]

_TEMPERATURE = 0.0


class CohereTranslator:
    """Translator that calls the Cohere Chat API (Command R / Command R+).

    Uses the ``cohere`` Python SDK.  Retries transient errors up to 3 times
    with exponential backoff via ``tenacity`` (1 s → 2 s → 4 s, max 10 s).

    Args:
        model:   Cohere model name (e.g. ``"command-r-plus"``,
                 ``"command-r"``).
        api_key: Cohere API key.  Falls back to ``COHERE_API_KEY`` env var.
        timeout: Per-request timeout in seconds (default 30 s).

    Raises:
        ConfigurationError: If ``cohere`` is not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        try:
            import cohere
        except ImportError as exc:
            raise ConfigurationError(
                "cohere is required for CohereTranslator. "
                "Install it with: pip install 'pramanix[cohere]'"
            ) from exc

        self.model = model
        self._api_key = api_key or os.environ.get("COHERE_API_KEY") or None
        self._timeout = timeout
        self._client: Any = (
            cohere.AsyncClientV2(api_key=self._api_key)
            if hasattr(cohere, "AsyncClientV2")
            else cohere.AsyncClient(api_key=self._api_key)
        )
        self._cohere = cohere
        try:
            self._retryable: tuple[type[Exception], ...] = (
                cohere.errors.TooManyRequestsError,
                cohere.errors.ServiceUnavailableError,
                cohere.errors.GatewayTimeoutError,
            )
        except AttributeError:  # older SDK fallback
            try:
                self._retryable = (cohere.core.api_error.ApiError,)
            except AttributeError:
                _base = getattr(cohere, "CohereError", None)
                self._retryable = (_base,) if _base is not None else (OSError,)

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using Cohere.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON.
            LLMTimeoutError:        All retry attempts exhausted.
            ConfigurationError:     ``cohere`` not installed.
        """
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
                "Install it with: pip install 'pramanix[cohere]'"
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
                f"Cohere model '{self.model}' unreachable after "
                f"{attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc
        except Exception as exc:
            # Wrap httpx transport/timeout errors that are not in _retryable
            # (e.g. httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout).
            try:
                import httpx as _httpx

                if isinstance(exc, (_httpx.TransportError, _httpx.TimeoutException)):
                    raise LLMTimeoutError(
                        f"Cohere model '{self.model}' connection error: {exc}",
                        model=self.model,
                        attempts=attempts,
                    ) from exc
            except ImportError:
                pass
            raise

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        import inspect
        _close = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
        if _close is not None:
            result = _close()
            if inspect.isawaitable(result):
                await result

    async def __aenter__(self) -> CohereTranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def _single_call(
        self,
        *,
        system_prompt: str,
        text: str,
    ) -> str:
        """Make a single Cohere chat call and return the raw text."""
        import asyncio

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text},
        ]

        try:
            response = await self._client.chat(
                model=self.model,
                messages=messages,
                temperature=_TEMPERATURE,
                response_format={"type": "json_object"},
            )
        except TypeError:
            # Older Cohere SDK does not accept response_format kwarg.
            # M-10: use asyncio.get_running_loop() + run_in_executor, not get_event_loop().
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self._cohere.Client(api_key=self._api_key).chat(
                    model=self.model,
                    message=f"{system_prompt}\n\nUser input:\n{text}",
                    temperature=_TEMPERATURE,
                ),
            )

        # Cohere SDK v5: response.message.content[0].text
        # Cohere SDK v4: response.text
        try:
            raw: str = response.message.content[0].text
        except (AttributeError, IndexError, TypeError):
            try:
                raw = response.text
            except AttributeError:
                raw = str(response)

        if not raw or not raw.strip():
            raise ExtractionFailureError(
                f"[{self.model}] Cohere returned an empty response."
            )
        return raw
