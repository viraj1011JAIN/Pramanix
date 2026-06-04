# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Google Gemini translator — Phase D-2.

Requires the ``pramanix[gemini]`` extra (``google-generativeai``, ``tenacity``).
If the package is not installed, instantiation raises
:exc:`~pramanix.exceptions.ConfigurationError` with the exact pip command.
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING, Any

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt

from pramanix.translator.base import RedactedSecretsMixin

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["GeminiTranslator"]

# Temperature 0 ≡ deterministic mode — critical for reproducible consensus.
_TEMPERATURE = 0.0

# M-12: serialises genai.configure() calls for older SDK versions that only
# support global key configuration (not per-instance clients).
# threading.Lock (not asyncio.Lock) so it is safe across event-loop boundaries;
# different pytest tests each run with a fresh event loop.
import threading as _thr  # noqa: E402

_GEMINI_CONFIGURE_LOCK = _thr.Lock()
del _thr


class GeminiTranslator(RedactedSecretsMixin):
    """Translator that calls the Google Gemini GenerateContent API.

    Uses ``google.generativeai`` (``google-generativeai`` PyPI package).
    Retries transient network errors up to 3 times with exponential backoff
    via ``tenacity`` (1 s → 2 s → 4 s, capped at 10 s).

    Args:
        model:   Gemini model name (e.g. ``"gemini-1.5-pro"``).
        api_key: Google AI Studio API key.  Falls back to ``GOOGLE_API_KEY``
                 env var.
        timeout: Per-request timeout in seconds (default 30 s).

    Raises:
        ConfigurationError: If ``google-generativeai`` is not installed.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        _genai_override: Any = None,
        _genai_factory: Any = None,
        _protobuf_importer: Any = None,
    ) -> None:
        self.model = model
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY") or None
        self._timeout = timeout

        if _genai_override is not None:
            # DI path: caller supplies a duck-typed genai module (tests only).
            # Skip the google-generativeai import entirely so tests can run
            # without the package installed and without __new__() bypasses.
            self._genai = _genai_override
            self._client: Any = None
            self._retryable: tuple[type[Exception], ...] = (Exception,)
            return

        import warnings as _warnings_mod

        # Scope the google-generativeai deprecation warning suppression to
        # this constructor only.  The previous module-level filterwarnings
        # polluted the global warning filter for every code in the process
        # that imported this module.  Using catch_warnings as a context manager
        # confines the suppression to the google SDK import — the host
        # application's own Google SDK deprecation warnings are unaffected.
        with _warnings_mod.catch_warnings():
            _warnings_mod.filterwarnings(
                "ignore",
                message=r"(?s).*google\.generativeai.*",
                category=FutureWarning,
            )
            _warnings_mod.filterwarnings(
                "ignore",
                message=r"(?s).*google\.generativeai.*",
                category=DeprecationWarning,
            )
            try:
                # proto-plus (a transitive dependency of google-generativeai) accesses
                # ``google.protobuf.__version__`` via the google namespace attribute.
                # Python's import short-circuit (sys.modules hit) skips the setattr
                # that registers subpackages on their parent namespace.  If the google
                # namespace was recreated after google.protobuf was first imported
                # (e.g. a test that temporarily pops sys.modules["google"]), the
                # attribute is absent and proto/message.py raises AttributeError.
                # We force-set the attribute here so the import chain always finds it.
                try:
                    if _protobuf_importer is not None:
                        _protobuf_importer()
                    else:
                        import google as _g
                        import google.protobuf as _gp

                        if not hasattr(_g, "protobuf"):
                            _g.protobuf = _gp
                        del _gp, _g
                except ImportError:
                    pass
                # google.generativeai must be in sys.modules before the
                # genai client is created; this import is the side-effect.
                if _genai_factory is not None:
                    _genai_factory()
                else:
                    import google.generativeai  # noqa: F401 — side-effect only
            except ImportError as exc:
                raise ConfigurationError(
                    "google-generativeai is required for GeminiTranslator. "
                    "Install it with: pip install 'pramanix[gemini]'"
                ) from exc

        # M-12: build a per-instance genai client so two Guard instances with
        # different keys don't overwrite each other via genai.configure().
        import google.generativeai as _genai

        self._genai = _genai
        if self._api_key:
            # genai v0.8+ supports Client(api_key=...) per-instance.
            # Older versions only have global configure(); we use it under a lock
            # (see _single_call) to serialise multi-tenant access.
            _client_cls = getattr(_genai, "Client", None)
            self._client = (
                _client_cls(api_key=self._api_key) if _client_cls is not None else None
            )
        else:
            self._client = None

        try:
            import google.api_core.exceptions as _gapi_exc

            self._retryable = (
                _gapi_exc.DeadlineExceeded,
                _gapi_exc.ServiceUnavailable,
                _gapi_exc.InternalServerError,
            )
        except ImportError:
            self._retryable = (Exception,)

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
        *,
        _tenacity_factory: Any = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using Gemini.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON.
            LLMTimeoutError:        All retry attempts exhausted.
            ConfigurationError:     ``google-generativeai`` not installed.
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
                "tenacity is required for retry support. "
                "Install it with: pip install 'pramanix[gemini]'"
            ) from exc

        system_prompt = build_system_prompt(intent_schema)
        # Use structured contents with system_instruction when the new-client path
        # is available.  For the legacy genai.configure() path the prompt is still
        # assembled as a flat string, but system_instruction is passed separately
        # via GenerativeModel(system_instruction=...) to preserve role separation.
        full_prompt = f"User input:\n{text}"
        # Keep a combined prompt for the legacy path where system_instruction is
        # not supported by the installed SDK version.
        full_prompt_legacy = f"{system_prompt}\n\nUser input:\n{text}"

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
                        prompt=full_prompt,
                        system_prompt=system_prompt,
                        full_prompt_legacy=full_prompt_legacy,
                    )
                    return parse_llm_response(raw, model_name=self.model)

        except self._retryable as exc:
            raise LLMTimeoutError(
                f"Gemini model '{self.model}' unreachable after {attempts} attempt(s): {exc}",
                model=self.model,
                attempts=attempts,
            ) from exc
        except Exception as exc:
            # Wrap httpx transport/timeout errors that are not in _retryable
            # (e.g. httpx.ConnectError when SDK uses httpx transport).
            try:
                import httpx as _httpx

                if isinstance(exc, _httpx.TransportError | _httpx.TimeoutException):
                    raise LLMTimeoutError(
                        f"Gemini model '{self.model}' connection error: {exc}",
                        model=self.model,
                        attempts=attempts,
                    ) from exc
            except ImportError:
                pass
            raise
        raise ExtractionFailureError(f"[{self.model}] Retry loop exited without a result")

    async def _single_call(
        self,
        *,
        prompt: str,
        system_prompt: str = "",
        full_prompt_legacy: str = "",
    ) -> str:
        """Make a single GenerateContent call and return the raw text."""
        genai = self._genai

        # M-12: use the per-instance client if SDK supports it; otherwise fall
        # back to the global configure() path under a module-level lock so
        # concurrent Guard instances with different keys don't race.
        if self._client is not None and hasattr(self._client, "aio"):
            # New-client path: pass system_instruction separately for role
            # separation.  This prevents prompt injection via the user-input
            # portion of the prompt overriding system instructions.
            cfg: dict[str, Any] = {
                "temperature": _TEMPERATURE,
                "response_mime_type": "application/json",
            }
            if system_prompt:
                cfg["system_instruction"] = system_prompt
            response = await self._client.aio.models.generate_content(
                model=self.model,
                contents=[{"role": "user", "parts": [{"text": prompt}]}],
                config=cfg,
            )
            raw_text: str = response.text
        else:
            # Legacy path: pass system_instruction to GenerativeModel constructor
            # when supported, otherwise fall back to flat combined prompt.
            gen_config_kwargs: dict[str, Any] = {
                "temperature": _TEMPERATURE,
                "response_mime_type": "application/json",
            }
            model_kwargs: dict[str, Any] = {
                "model_name": self.model,
                "generation_config": genai.GenerationConfig(**gen_config_kwargs),
            }
            if system_prompt:
                try:
                    model_kwargs["system_instruction"] = system_prompt
                except TypeError:
                    pass  # SDK version does not support system_instruction
            # Try to create the model with system_instruction for role separation.
            # If the installed SDK version does not support it, fall back to the
            # combined prompt (which concatenates system_prompt + user_input).
            effective_prompt = prompt  # user-only
            if self._api_key:
                with _GEMINI_CONFIGURE_LOCK:
                    genai.configure(api_key=self._api_key)
                    try:
                        model_client = genai.GenerativeModel(**model_kwargs)
                    except TypeError:
                        model_kwargs.pop("system_instruction", None)
                        model_client = genai.GenerativeModel(**model_kwargs)
                        effective_prompt = full_prompt_legacy or prompt
            else:
                try:
                    model_client = genai.GenerativeModel(**model_kwargs)
                except TypeError:
                    model_kwargs.pop("system_instruction", None)
                    model_client = genai.GenerativeModel(**model_kwargs)
                    effective_prompt = full_prompt_legacy or prompt
            if hasattr(model_client, "generate_content_async"):
                response = await model_client.generate_content_async(effective_prompt)
            else:
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None, model_client.generate_content, effective_prompt
                )
            raw_text = response.text

        if not raw_text or not raw_text.strip():
            raise ExtractionFailureError(f"[{self.model}] Gemini returned an empty response.")
        return raw_text
