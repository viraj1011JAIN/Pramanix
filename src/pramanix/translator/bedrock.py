# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""AWS Bedrock translator — Claude, Titan, and Meta Llama models via boto3.

Requires the ``pramanix[bedrock]`` extra::

    pip install "pramanix[bedrock]"

Supported model-ID prefixes
---------------------------
* ``anthropic.claude-*`` — Anthropic Claude models (Bedrock-hosted)
* ``amazon.titan-*``     — Amazon Titan text generation models
* ``meta.llama*``        — Meta Llama text models on Bedrock
* Any other model ID     — Generic Bedrock converse API call

Usage::

    from pramanix.translator.bedrock import BedrockTranslator

    translator = BedrockTranslator(
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        region="us-east-1",
    )
    async with translator:
        result = await translator.extract(text, MyIntentSchema)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING, Any

from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

_log = logging.getLogger(__name__)

__all__ = ["BedrockTranslator"]


class BedrockTranslator:
    """Translator that calls AWS Bedrock foundation models.

    Wraps boto3's synchronous ``bedrock-runtime`` client in an async executor
    so it conforms to the :class:`~pramanix.translator.base.Translator`
    protocol without blocking the event loop.

    Auth is resolved in standard boto3 order:
    1. Explicit keyword arguments (``aws_access_key_id`` etc.)
    2. ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` env vars
    3. ``~/.aws/credentials`` file / IAM instance profile / ECS task role

    Args:
        model:                  Bedrock model ID
                                (e.g. ``"anthropic.claude-3-5-sonnet-20241022-v2:0"``).
        region:                 AWS region (default: ``AWS_DEFAULT_REGION`` env
                                var, or ``"us-east-1"`` if unset).
        aws_access_key_id:      Explicit AWS key ID (optional).
        aws_secret_access_key:  Explicit AWS secret key (optional).
        aws_session_token:      Explicit session token for temporary credentials.
        profile_name:           Named profile from ``~/.aws/config`` (optional).
        timeout:                Per-request timeout in seconds (default 30 s).
        max_tokens:             Maximum tokens to generate (default 1024).

    Raises:
        ImportError: If ``boto3`` is not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        region: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        profile_name: str | None = None,
        timeout: float = 30.0,
        max_tokens: int = 1024,
        _boto3_factory: Any = None,
    ) -> None:
        try:
            if _boto3_factory is not None:
                boto3 = _boto3_factory()
            else:
                import boto3
                import botocore.config
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for BedrockTranslator. "
                "Install it with: pip install 'pramanix[bedrock]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

        _region = (
            region
            or os.environ.get("AWS_DEFAULT_REGION")
            or os.environ.get("AWS_REGION")
            or "us-east-1"
        )

        session_kwargs: dict[str, Any] = {}
        if profile_name:
            session_kwargs["profile_name"] = profile_name

        session = boto3.Session(
            aws_access_key_id=aws_access_key_id or os.environ.get("AWS_ACCESS_KEY_ID") or None,
            aws_secret_access_key=(
                aws_secret_access_key or os.environ.get("AWS_SECRET_ACCESS_KEY") or None
            ),
            aws_session_token=(aws_session_token or os.environ.get("AWS_SESSION_TOKEN") or None),
            **session_kwargs,
        )
        self._client = session.client(
            "bedrock-runtime",
            region_name=_region,
            config=botocore.config.Config(
                read_timeout=int(timeout),
                connect_timeout=10,
                retries={"max_attempts": 0},
            ),
        )

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using the configured Bedrock model.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining the expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller should validate against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON or API error.
            LLMTimeoutError:        Request exceeded the configured timeout.
        """
        system_prompt = build_system_prompt(intent_schema)
        model_lower = self.model.lower()

        if "claude" in model_lower:
            payload = self._build_claude_payload(system_prompt, text)
        elif "titan" in model_lower:
            payload = self._build_titan_payload(system_prompt, text)
        elif "llama" in model_lower:
            payload = self._build_llama_payload(system_prompt, text)
        else:
            # Fallback: use Bedrock Converse API (works for all models)
            return await self._converse(system_prompt, text)

        loop = asyncio.get_event_loop()
        try:
            raw = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._invoke_model(payload)),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise LLMTimeoutError(
                f"Bedrock model '{self.model}' timed out after {self._timeout}s.",
                model=self.model,
                attempts=1,
            ) from exc
        except Exception as exc:
            raise ExtractionFailureError(
                f"[{self.model}] Bedrock invoke_model error: {exc}"
            ) from exc

        return parse_llm_response(raw, model_name=self.model)

    # ── Payload builders ──────────────────────────────────────────────────────

    def _build_claude_payload(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Build an Anthropic Messages API payload for Claude-on-Bedrock."""
        return {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self._max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": text}],
        }

    def _build_titan_payload(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Build an Amazon Titan text-generation payload."""
        combined = f"{system_prompt}\n\nUser: {text}\nAssistant:"
        return {
            "inputText": combined,
            "textGenerationConfig": {
                "maxTokenCount": self._max_tokens,
                "stopSequences": [],
                "temperature": 0.0,
                "topP": 1.0,
            },
        }

    def _build_llama_payload(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Build a Meta Llama chat payload."""
        prompt = f"<s>[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{text} [/INST]"
        return {
            "prompt": prompt,
            "max_gen_len": self._max_tokens,
            "temperature": 0.0,
            "top_p": 1.0,
        }

    # ── Synchronous invocation (runs in executor) ─────────────────────────────

    def _invoke_model(self, payload: dict[str, Any]) -> str:
        """Invoke the Bedrock model synchronously and return the text content."""
        response = self._client.invoke_model(
            modelId=self.model,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        body = json.loads(response["body"].read())

        model_lower = self.model.lower()
        if "claude" in model_lower:
            # Anthropic Messages API response
            content = body.get("content", [])
            if content and isinstance(content, list):
                text = content[0].get("text", "")
            else:
                text = body.get("completion", "")
        elif "titan" in model_lower:
            results = body.get("results", [{}])
            text = results[0].get("outputText", "") if results else ""
        elif "llama" in model_lower:
            text = body.get("generation", "")
        else:
            # Generic fallback
            text = (
                body.get("outputText")
                or body.get("completion")
                or body.get("text")
                or body.get("generation")
                or ""
            )

        if not text:
            raise ExtractionFailureError(
                f"[{self.model}] Bedrock returned an empty response body: {body}"
            )
        return text

    async def _converse(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Use the Bedrock Converse API (model-agnostic) for unsupported models."""
        loop = asyncio.get_event_loop()
        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: self._client.converse(
                        modelId=self.model,
                        system=[{"text": system_prompt}],
                        messages=[{"role": "user", "content": [{"text": text}]}],
                        inferenceConfig={"maxTokens": self._max_tokens, "temperature": 0.0},
                    ),
                ),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise LLMTimeoutError(
                f"Bedrock model '{self.model}' timed out after {self._timeout}s.",
                model=self.model,
                attempts=1,
            ) from exc
        except Exception as exc:
            raise ExtractionFailureError(f"[{self.model}] Bedrock converse error: {exc}") from exc

        output = response.get("output", {})
        message = output.get("message", {})
        content = message.get("content", [])
        raw = content[0].get("text", "") if content else ""
        if not raw:
            raise ExtractionFailureError(
                f"[{self.model}] Bedrock Converse returned empty content: {response}"
            )
        return parse_llm_response(raw, model_name=self.model)

    async def aclose(self) -> None:
        """Close the underlying boto3 client session."""
        try:
            self._client.close()
        except Exception as _close_exc:
            _log.debug(
                "BedrockTranslator.aclose: error closing boto3 client (ignored): %s",
                _close_exc,
                exc_info=True,
            )

    async def __aenter__(self) -> BedrockTranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
