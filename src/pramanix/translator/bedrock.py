# SPDX-License-Identifier: Apache-2.0
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
import re

import asyncio
import json
import logging
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
    # Strip ANSI CSI escape sequences.
    _s = re.sub("\x1b\[[0-9;]*[A-Za-z]", "", _s)
    return _s[:100]

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

_log = logging.getLogger(__name__)

__all__ = ["BedrockTranslator"]


class BedrockTranslator(RedactedSecretsMixin):
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
        # Import boto3 eagerly so a missing install surfaces at construction time.
        try:
            if _boto3_factory is not None:
                self._boto3 = _boto3_factory()
            else:
                import importlib as _importlib

                self._boto3 = _importlib.import_module("boto3")
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for BedrockTranslator. "
                "Install it with: pip install 'pramanix[bedrock]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._region = (
            region
            or os.environ.get("AWS_DEFAULT_REGION")
            or os.environ.get("AWS_REGION")
            or "us-east-1"
        )
        self._aws_access_key_id = aws_access_key_id or os.environ.get("AWS_ACCESS_KEY_ID") or None
        self._aws_secret_access_key = (
            aws_secret_access_key or os.environ.get("AWS_SECRET_ACCESS_KEY") or None
        )
        self._aws_session_token = aws_session_token or os.environ.get("AWS_SESSION_TOKEN") or None
        self._profile_name = profile_name
        # Client is created lazily on first use so that:
        # (a) profile resolution errors surface at call time, not at import/construction time,
        # (b) tests can inject a duck-typed client after construction.
        self._client: Any = None

    def _ensure_client(self) -> None:
        """Create the bedrock-runtime boto3 client if not already created."""
        if self._client is not None:
            return
        import botocore.config

        session_kwargs: dict[str, Any] = {}
        if self._profile_name:
            session_kwargs["profile_name"] = self._profile_name
        session = self._boto3.Session(
            aws_access_key_id=self._aws_access_key_id,
            aws_secret_access_key=self._aws_secret_access_key,
            aws_session_token=self._aws_session_token,
            **session_kwargs,
        )
        # urllib3 rejects read_timeout <= 0; clamp to at least 1 second at the
        # boto3 layer.  asyncio.wait_for enforces the real sub-second timeout.
        read_timeout = max(1, int(self._timeout))
        self._client = session.client(
            "bedrock-runtime",
            region_name=self._region,
            config=botocore.config.Config(
                read_timeout=read_timeout,
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
        self._ensure_client()

        if "claude" in model_lower:
            payload = self._build_claude_payload(system_prompt, text)
        elif "titan" in model_lower:
            payload = self._build_titan_payload(system_prompt, text)
        elif "llama" in model_lower:
            payload = self._build_llama_payload(system_prompt, text)
        else:
            # Fallback: use Bedrock Converse API (works for all models)
            return await self._converse(system_prompt, text)

        loop = asyncio.get_running_loop()
        try:
            raw = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._invoke_model(payload)),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise LLMTimeoutError(
                f"Bedrock model '{_safe_model_tag(self.model)}' timed out after {self._timeout}s.",
                model=self.model,
                attempts=1,
            ) from exc
        except Exception as exc:
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Bedrock invoke_model error: {exc}"
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

    @staticmethod
    def _sanitize_for_titan(text: str) -> str:
        """Strip Titan role-boundary tokens from user-supplied text.

        The Titan format uses ``\\nAssistant:`` as a role boundary.  An attacker
        who includes ``\\nAssistant:`` in their input can inject a fake assistant
        turn and bias the model's extraction.
        """
        return text.replace("\nAssistant:", " ").replace("\r\nAssistant:", " ")

    def _build_titan_payload(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Build an Amazon Titan text-generation payload."""
        safe_text = self._sanitize_for_titan(text)
        combined = f"{system_prompt}\n\nUser: {safe_text}\nAssistant:"
        return {
            "inputText": combined,
            "textGenerationConfig": {
                "maxTokenCount": self._max_tokens,
                "stopSequences": [],
                "temperature": 0.0,
                "topP": 1.0,
            },
        }

    @staticmethod
    def _sanitize_for_llama2(text: str) -> str:
        """Strip Llama 2 instruction-format tokens from user-supplied text.

        An attacker who includes ``[/INST]`` in their input can close the
        instruction block and inject a fabricated assistant response before the
        model generates.  Remove all Llama 2 control tokens from user text.
        """
        for token in ("[/INST]", "[INST]", "<<SYS>>", "<</SYS>>", "<s>", "</s>"):
            text = text.replace(token, " ")
        return text

    def _build_llama_payload(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Build a Meta Llama chat payload."""
        safe_text = self._sanitize_for_llama2(text)
        prompt = f"<s>[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{safe_text} [/INST]"
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
            _body_repr = repr(body)
            _body_snippet = _body_repr[:100] + ("…" if len(_body_repr) > 100 else "")
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Bedrock returned an empty response body: "
                f"{_body_snippet}"
            )
        return cast(str, text)

    async def _converse(self, system_prompt: str, text: str) -> dict[str, Any]:
        """Use the Bedrock Converse API (model-agnostic) for unsupported models."""
        self._ensure_client()
        loop = asyncio.get_running_loop()
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
                f"Bedrock model '{_safe_model_tag(self.model)}' timed out after {self._timeout}s.",
                model=self.model,
                attempts=1,
            ) from exc
        except Exception as exc:
            raise ExtractionFailureError(f"[{_safe_model_tag(self.model)}] Bedrock converse error: {exc}") from exc

        output = response.get("output", {})
        message = output.get("message", {})
        content = message.get("content", [])
        raw = content[0].get("text", "") if content else ""
        if not raw:
            raise ExtractionFailureError(
                f"[{_safe_model_tag(self.model)}] Bedrock Converse returned empty content: {response}"
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
