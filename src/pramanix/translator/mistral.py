# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Mistral AI translator — Phase D-2.

Requires the ``pramanix[mistral]`` extra (``mistralai``, ``tenacity``).
If the package is not installed, instantiation raises
:exc:`~pramanix.exceptions.ConfigurationError` with the exact pip command.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import TYPE_CHECKING, Any, cast

from pramanix.exceptions import ConfigurationError, LLMTimeoutError
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
        _client_override: Any = None,
        _mistralai_factory: Any = None,
    ) -> None:
        self.model = model
        self._api_key = api_key or os.environ.get("MISTRAL_API_KEY") or None
        self._timeout = timeout

        if _client_override is not None:
            # DI path: tests inject a duck-typed stub to avoid real HTTP clients.
            self._client: Any = _client_override
            return

        _mistral_cls: Any = None
        try:
            if _mistralai_factory is not None:
                _mistral_cls = _mistralai_factory()
            else:
                try:
                    from mistralai.client import Mistral  # v2+

                    _mistral_cls = Mistral
                except ImportError:
                    import mistralai as _mistralai_pkg  # v1 top-level

                    _mistral_cls = cast(Any, _mistralai_pkg).Mistral
        except ImportError as exc:
            raise ConfigurationError(
                "mistralai is required for MistralTranslator. "
                "Install it with: pip install 'pramanix[mistral]'"
            ) from exc

        # M-14: create the client once; reuse across all calls and retries.
        self._client = _mistral_cls(api_key=self._api_key or "")

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
        *,
        _tenacity_factory: Any = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using Mistral.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            LLMTimeoutError:    All retry attempts exhausted.
            ConfigurationError: ``mistralai`` or ``tenacity`` not installed.
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
            raise ConfigurationError(
                "tenacity is required for MistralTranslator retry support. "
                "Install it with: pip install 'pramanix[mistral]'"
            ) from exc

        # M-13: only retry genuine Mistral transport errors, not programmer errors.
        try:
            from mistralai.models import SDKError as _MistralError

            _retryable_base: tuple[type[Exception], ...] = (_MistralError, TimeoutError, OSError)
        except ImportError:
            _retryable_base = (TimeoutError, OSError)

        try:
            import httpx as _httpx

            _http_errors: tuple[type[Exception], ...] = (
                _httpx.ConnectError,
                _httpx.TimeoutException,
                _httpx.ReadTimeout,
            )
        except ImportError:
            _http_errors = ()
        _retryable: tuple[type[Exception], ...] = (*_retryable_base, *_http_errors)

        system_prompt = build_system_prompt(intent_schema)
        user_content = text
        if context is not None:
            extra = getattr(context, "extra_context", None)
            if extra:
                user_content = f"{text}\n\nContext: {extra}"

        attempts = 0
        try:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception_type(_retryable),
                wait=wait_exponential(multiplier=1, min=1, max=10),
                stop=stop_after_attempt(3),
                reraise=True,
            ):
                with attempt:
                    attempts += 1
                    raw = await self._single_call(
                        system_prompt=system_prompt,
                        user_content=user_content,
                    )
        except _retryable as exc:
            raise LLMTimeoutError(
                f"MistralTranslator: all retry attempts exhausted for model {self.model!r} "
                f"after {attempts} attempt(s): {exc}",
            ) from exc

        return parse_llm_response(raw, model_name=self.model)

    async def _single_call(
        self,
        *,
        system_prompt: str,
        user_content: str,
    ) -> str:
        """Execute one Mistral API call using the shared client instance."""
        import asyncio

        response = await asyncio.wait_for(
            self._client.chat.complete_async(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=_TEMPERATURE,
            ),
            timeout=self._timeout,
        )
        return response.choices[0].message.content or ""

    async def aclose(self) -> None:
        """Close the underlying Mistral HTTP client and release resources."""
        import inspect

        # mistralai v2+: client.close() is a coroutine; v1: sync close().
        _close = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
        if _close is not None:
            result = _close()
            if inspect.isawaitable(result):
                await result

    def __del__(self) -> None:
        """Synchronously close the Mistral client on GC to prevent RuntimeWarning."""
        client = getattr(self, "_client", None)
        if client is None:
            return
        # mistralai v2 exposes http_client; close its transport synchronously.
        http_client = getattr(client, "http_client", None)
        transport = getattr(http_client, "_transport", None)
        if transport is not None and hasattr(transport, "close"):
            with contextlib.suppress(OSError, RuntimeError):
                transport.close()
            return
        with contextlib.suppress(RuntimeError):
            asyncio.get_running_loop()
            return
        with contextlib.suppress(RuntimeError, OSError):
            asyncio.run(self.aclose())

    async def __aenter__(self) -> MistralTranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
