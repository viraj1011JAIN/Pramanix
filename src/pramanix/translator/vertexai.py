# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Google Vertex AI translator — Gemini and PaLM 2 models via google-cloud-aiplatform.

Requires the ``pramanix[vertexai]`` extra::

    pip install "pramanix[vertexai]"

Unlike :class:`~pramanix.translator.gemini.GeminiTranslator` (AI Studio key),
this translator targets **enterprise Vertex AI** deployments where models run
inside the customer's GCP project.  Supports VPC-SC, private service connect,
Workload Identity Federation, and CMEK — all enforced at the GCP IAM/KMS layer
rather than in this client.

Supported model families
------------------------
* ``gemini-*``        — Vertex AI Gemini (Flash, Pro, Ultra) via GenerativeModel API
* ``text-bison-*``,
  ``text-unicorn-*``  — PaLM 2 text-generation models via TextGenerationModel API
* Any other ID        — Attempted via GenerativeModel (Vertex AI extension models)

Usage::

    from pramanix.translator.vertexai import VertexAITranslator

    translator = VertexAITranslator(
        "gemini-1.5-pro-001",
        project="my-gcp-project",
        location="us-central1",
    )
    async with translator:
        result = await translator.extract(text, MyIntentSchema)
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING, Any, cast

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["VertexAITranslator"]

_TEMPERATURE = 0.0


class VertexAITranslator:
    """Translator that calls Google Vertex AI generative models.

    Wraps the synchronous ``google-cloud-aiplatform`` SDK in an asyncio
    executor so it conforms to the :class:`~pramanix.translator.base.Translator`
    protocol without blocking the event loop.

    Authentication is resolved by Application Default Credentials (ADC):
    1. ``GOOGLE_APPLICATION_CREDENTIALS`` environment variable (service account JSON).
    2. ``gcloud auth application-default login`` user credentials.
    3. Attached service account on GCE / GKE / Cloud Run / Cloud Functions.

    Args:
        model:       Vertex AI model name (e.g. ``"gemini-1.5-pro-001"``,
                     ``"text-bison@001"``).
        project:     GCP project ID (default: ``GOOGLE_CLOUD_PROJECT`` or
                     ``GCLOUD_PROJECT`` env var).
        location:    GCP region (default: ``GOOGLE_CLOUD_LOCATION`` env var,
                     or ``"us-central1"``).
        timeout:     Per-request timeout in seconds (default 30 s).
        max_tokens:  Maximum output tokens (default 1 024).
        credentials: Optional pre-constructed ``google.auth.credentials.Credentials``;
                     when provided, ADC discovery is skipped.

    Raises:
        ConfigurationError: If ``google-cloud-aiplatform`` is not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        project: str | None = None,
        location: str | None = None,
        timeout: float = 30.0,
        max_tokens: int = 1024,
        credentials: Any | None = None,
        _vertexai_factory: Any = None,
    ) -> None:
        try:
            if _vertexai_factory is not None:
                _vertexai_factory()
            else:
                import vertexai  # noqa: F401 — availability probe
        except ImportError as exc:
            raise ConfigurationError(
                "google-cloud-aiplatform is required for VertexAITranslator. "
                "Install it with: pip install 'pramanix[vertexai]'"
            ) from exc

        self.model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

        self._project = (
            project
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCLOUD_PROJECT")
        )
        self._location = (
            location
            or os.environ.get("GOOGLE_CLOUD_LOCATION")
            or os.environ.get("CLOUDSDK_COMPUTE_REGION")
            or "us-central1"
        )
        self._credentials = credentials

        # Initialise vertexai once — subsequent calls with the same project/location are idempotent.
        import vertexai as _vt

        init_kwargs: dict[str, Any] = {"location": self._location}
        if self._project:
            init_kwargs["project"] = self._project
        if self._credentials is not None:
            init_kwargs["credentials"] = self._credentials
        _vt.init(**init_kwargs)

    # ── extract ───────────────────────────────────────────────────────────────

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using the configured Vertex AI model.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining the expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON or API error.
            LLMTimeoutError:        Request exceeded the configured timeout.
        """
        system_prompt = build_system_prompt(intent_schema)
        model_lower = self.model.lower()

        def _invoke_palm() -> str:
            return self._invoke_palm(system_prompt, text)

        def _invoke_gemini() -> str:
            return self._invoke_gemini(system_prompt, text)

        invoke_fn = _invoke_palm if _is_palm(model_lower) else _invoke_gemini

        loop = asyncio.get_event_loop()
        try:
            raw = await asyncio.wait_for(
                loop.run_in_executor(None, invoke_fn),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise LLMTimeoutError(
                f"Vertex AI model '{self.model}' timed out after {self._timeout}s.",
                model=self.model,
                attempts=1,
            ) from exc
        except ExtractionFailureError:
            raise
        except Exception as exc:
            raise ExtractionFailureError(
                f"[{self.model}] Vertex AI API error: {exc}"
            ) from exc

        return parse_llm_response(raw, model_name=self.model)

    # ── Synchronous invocation helpers (run in executor) ─────────────────────

    def _invoke_gemini(self, system_prompt: str, text: str) -> str:
        """Invoke a Gemini model synchronously and return the text response."""
        from vertexai.generative_models import GenerationConfig, GenerativeModel

        genmodel = GenerativeModel(
            model_name=self.model,
            system_instruction=system_prompt,
        )
        response = genmodel.generate_content(
            text,
            generation_config=GenerationConfig(
                max_output_tokens=self._max_tokens,
                temperature=_TEMPERATURE,
            ),
        )
        raw = response.text
        if not raw:
            raise ExtractionFailureError(
                f"[{self.model}] Vertex AI Gemini returned an empty response."
            )
        return cast(str, raw)

    def _invoke_palm(self, system_prompt: str, text: str) -> str:
        """Invoke a PaLM 2 text-generation model synchronously."""
        from vertexai.language_models import TextGenerationModel

        palm_model = TextGenerationModel.from_pretrained(self.model)
        combined_prompt = f"{system_prompt}\n\nUser: {text}\nAssistant:"
        response = palm_model.predict(
            combined_prompt,
            max_output_tokens=self._max_tokens,
            temperature=_TEMPERATURE,
        )
        raw = response.text
        if not raw:
            raise ExtractionFailureError(
                f"[{self.model}] Vertex AI PaLM returned an empty response."
            )
        return cast(str, raw)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def aclose(self) -> None:
        """No-op — the Vertex AI SDK uses per-call connections (no persistent pool)."""

    async def __aenter__(self) -> VertexAITranslator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()


def _is_palm(model_lower: str) -> bool:
    """Return True if the model name matches a PaLM 2 text-generation family."""
    return any(
        model_lower.startswith(prefix)
        for prefix in ("text-bison", "text-unicorn", "text-gecko")
    )
