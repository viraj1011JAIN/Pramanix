# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Cohere translator — Phase D-2.

Requires the ``pramanix[cohere]`` extra (``cohere``, ``tenacity``).
If the package is not installed, instantiation raises
:exc:`~pramanix.exceptions.ConfigurationError` with the exact pip command.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING, Any

_log = logging.getLogger(__name__)

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
        _cohere_factory: Any = None,
        _client_override: Any = None,
        _cohere_module: Any = None,
    ) -> None:
        self.model = model
        self._api_key = api_key or os.environ.get("COHERE_API_KEY") or None
        self._timeout = timeout

        if _client_override is not None:
            # DI path: caller supplies a duck-typed client (tests only).
            # Bypasses the cohere import entirely so tests can run without the
            # package installed and without __new__() bypasses.
            self._client: Any = _client_override
            self._cohere: Any = _cohere_module
            self._retryable: tuple[type[Exception], ...] = (Exception,)
            return

        try:
            if _cohere_factory is not None:
                cohere = _cohere_factory()
            else:
                import cohere
        except ImportError as exc:
            raise ConfigurationError(
                "cohere is required for CohereTranslator. "
                "Install it with: pip install 'pramanix[cohere]'"
            ) from exc

        self._client = (
            cohere.AsyncClientV2(api_key=self._api_key)
            if hasattr(cohere, "AsyncClientV2")
            else cohere.AsyncClient(api_key=self._api_key)
        )
        self._cohere = cohere
        try:
            self._retryable = (
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
                f"Cohere model '{self.model}' unreachable after " f"{attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc
        except Exception as exc:
            # Wrap httpx transport/timeout errors that are not in _retryable
            # (e.g. httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout).
            try:
                import httpx as _httpx

                if isinstance(exc, _httpx.TransportError | _httpx.TimeoutException):
                    raise LLMTimeoutError(
                        f"Cohere model '{self.model}' connection error: {exc}",
                        model=self.model,
                        attempts=attempts,
                    ) from exc
            except ImportError:
                pass
            raise
        raise ExtractionFailureError(f"[{self.model}] Retry loop exited without a result")

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        import inspect

        _close = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
        if _close is not None:
            result = _close()
            if inspect.isawaitable(result):
                await result

    def __del__(self) -> None:
        """Synchronously close the underlying client on GC to prevent RuntimeWarning.

        httpx.AsyncClient emits ``RuntimeWarning: coroutine 'AsyncClient.aclose'
        was never awaited`` when GC destroys the client without an awaited close.
        We close the underlying transport synchronously here to prevent that.

        Uses bare try/except instead of contextlib.suppress() because __del__ may
        run during interpreter shutdown when module-level globals are set to None.
        """
        client = getattr(self, "_client", None)
        if client is None:
            return
        # httpx.AsyncClient exposes its transport via ._transport; close it sync.
        transport = getattr(client, "_transport", None) or getattr(
            getattr(client, "_base_client", None), "_transport", None
        )
        if transport is not None and hasattr(transport, "close"):
            try:
                transport.close()
            except Exception as _close_exc:
                _log.warning(
                    "CohereTranslator.__del__: error closing httpx transport (resource may leak): %s",
                    _close_exc,
                )
            return
        # Fallback: if no running loop, run aclose() in a fresh loop.
        try:
            asyncio.get_running_loop()
            return  # running loop — can't call asyncio.run(); skip silently
        except RuntimeError:
            pass
        except Exception:
            return  # asyncio module may be None during interpreter shutdown
        try:
            asyncio.run(self.aclose())
        except Exception as _close_exc:
            _log.warning(
                "CohereTranslator.__del__: error during async cleanup (resource may leak): %s",
                _close_exc,
            )

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
            raise ExtractionFailureError(f"[{self.model}] Cohere returned an empty response.")
        return raw
