# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Anthropic (Claude) translator with exponential-backoff retry.

Requires the ``pramanix[translator]`` extra (``anthropic``, ``tenacity``).
"""

from __future__ import annotations
import re

import os
from typing import TYPE_CHECKING, Any, cast

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
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
    # Strip ANSI CSI escape sequences (ESC + literal '[' + params + command).
    _s = re.sub("\x1b" + r"\[[0-9;]*[A-Za-z]", "", _s)
    return _s[:100]

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["AnthropicTranslator"]


class AnthropicTranslator(RedactedSecretsMixin):
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
        _anthropic_factory: Any = None,
    ) -> None:
        try:
            if _anthropic_factory is not None:
                anthropic = _anthropic_factory()
            else:
                import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required for AnthropicTranslator. "
                "Install it with: pip install 'pramanix[translator]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or None
        self._client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            timeout=timeout,
        )
        self._retryable = (anthropic.APITimeoutError, anthropic.APIConnectionError)
        self._api_status_error = anthropic.APIStatusError

    # api_key_is_set / configured_api_key are provided by RedactedSecretsMixin.

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
                f"Anthropic model '{_safe_model_tag(self.model)}' unreachable after "
                f"{attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc

        except self._api_status_error as exc:
            # Redact exc.message — on auth/quota errors it may contain account
            # tier, partial key info, or quota details that should not flow to
            # Sentry/Datadog.  Log the status code only; full message at DEBUG.
            import logging as _alog
            _alog.getLogger(__name__).debug(
                "Anthropic API status error for model %s: %s %s",
                _safe_model_tag(self.model), exc.status_code, exc.message,
            )
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Anthropic API error {exc.status_code}"
                " (details redacted — check DEBUG log)."
            ) from exc
        raise ExtractionFailureError(f"[{_safe_model_tag(self.model)}] Retry loop exited without a result")

    async def aclose(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.close()

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
        """Make a single streaming Messages API call and return the text content.

        Uses the streaming API so that the implementation works with proxy
        environments (such as the VS Code Language Model server) that emit
        Server-Sent Events rather than a monolithic JSON response body.
        Exceptions (``APIStatusError``, ``APITimeoutError``, etc.) propagate
        to ``extract()`` unchanged, where retry and error-mapping logic lives.
        """
        async with self._client.messages.stream(
            model=self.model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": text}],
        ) as stream:
            return cast(str, await stream.get_final_text())
