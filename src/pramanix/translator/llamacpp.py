# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""llama-cpp-python translator — Phase D-2.

Local / air-gapped inference from GGUF models via ``llama-cpp-python``.
No network calls, no API keys required.  The model file must be pre-downloaded
and accessible from the filesystem.

Requires the ``pramanix[llamacpp]`` extra (``llama-cpp-python``).
If the package is not installed, instantiation raises
:exc:`~pramanix.exceptions.ConfigurationError` with the exact pip command.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pramanix.exceptions import ConfigurationError, ExtractionFailureError, LLMTimeoutError
from pramanix.translator._json import parse_llm_response
from pramanix.translator._prompt import build_system_prompt

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import TranslatorContext

__all__ = ["LlamaCppTranslator"]

import threading

_TEMPERATURE = 0.0
_DEFAULT_MAX_TOKENS = 512
_DEFAULT_N_CTX = 4096

# L-13: module-level model cache keyed by (model_path, n_ctx, n_gpu_layers).
# Multiple Guard instances sharing the same GGUF model path reuse one loaded
# copy instead of each allocating 4+ GB of RAM independently.
_MODEL_CACHE: dict[tuple[str, int, int], Any] = {}
_MODEL_CACHE_LOCK = threading.Lock()

# Per-model inference lock (#242): llama-cpp-python wraps a C library with no
# Python-level thread safety.  Concurrent create_chat_completion() calls on the
# same Llama object corrupt the KV cache and produce cross-policy contamination.
# Serialise all inference calls for the same model object under a dedicated lock.
_MODEL_INFERENCE_LOCKS: dict[tuple[str, int, int], threading.Lock] = {}
_MODEL_INFERENCE_LOCKS_LOCK = threading.Lock()


def _get_inference_lock(cache_key: tuple[str, int, int]) -> threading.Lock:
    with _MODEL_INFERENCE_LOCKS_LOCK:
        if cache_key not in _MODEL_INFERENCE_LOCKS:
            _MODEL_INFERENCE_LOCKS[cache_key] = threading.Lock()
        return _MODEL_INFERENCE_LOCKS[cache_key]


class LlamaCppTranslator:
    """Translator backed by a local GGUF model via ``llama-cpp-python``.

    Runs inference in-process using CPU (or GPU if llama-cpp-python was built
    with CUDA/Metal support).  All inference is synchronous under the hood;
    this class wraps it in an asyncio executor to avoid blocking the event loop.

    The GGUF model is loaded lazily on the first :meth:`extract` call, not at
    ``__init__`` time, so that Guard construction does not block the main thread
    during a 4+ GB file load.  Multiple instances sharing the same *model_path*,
    *n_ctx*, and *n_gpu_layers* share one loaded model object (module-level cache).

    Args:
        model_path:   Absolute path to a ``.gguf`` model file.
        n_ctx:        Context window in tokens.  Default: 4096.
        n_gpu_layers: Number of layers to offload to GPU.  0 = CPU only.
        max_tokens:   Maximum tokens to generate in one call.  Default: 512.

    Raises:
        ConfigurationError: If ``llama-cpp-python`` is not installed.
    """

    def __init__(
        self,
        model_path: str,
        *,
        n_ctx: int = _DEFAULT_N_CTX,
        n_gpu_layers: int = 0,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        _llamacpp_factory: Any = None,
    ) -> None:
        try:
            if _llamacpp_factory is not None:
                _llamacpp_factory()
            else:
                import importlib as _il

                _il.import_module("llama_cpp")
                del _il
        except ImportError as exc:
            raise ConfigurationError(
                "llama-cpp-python is required for LlamaCppTranslator. "
                "Install it with: pip install 'pramanix[llamacpp]'"
            ) from exc

        self.model = f"llama-cpp:{model_path}"  # used by create_translator routing
        self._model_path = model_path
        self._n_ctx = n_ctx
        self._n_gpu_layers = n_gpu_layers
        self._max_tokens = max_tokens
        self._llm: Any = None  # lazy — loaded on first extract() call

    def _get_llm(self) -> Any:
        """Return the loaded Llama model, loading it on first call (thread-safe)."""
        if self._llm is not None:
            return self._llm
        cache_key = (self._model_path, self._n_ctx, self._n_gpu_layers)
        with _MODEL_CACHE_LOCK:
            if cache_key not in _MODEL_CACHE:
                from llama_cpp import Llama

                _MODEL_CACHE[cache_key] = Llama(
                    model_path=self._model_path,
                    n_ctx=self._n_ctx,
                    n_gpu_layers=self._n_gpu_layers,
                    verbose=False,
                )
            return _MODEL_CACHE[cache_key]

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract structured intent from *text* using the local GGUF model.

        Args:
            text:          Raw user input (treated as untrusted).
            intent_schema: Pydantic model class defining expected output.
            context:       Optional host-provided grounding context.

        Returns:
            Raw dict from the model; caller validates against *intent_schema*.

        Raises:
            ExtractionFailureError: Model returned bad/unparseable JSON.
            LLMTimeoutError:        Inference timed out.
            ConfigurationError:     ``llama-cpp-python`` not installed.
        """
        import asyncio

        system_prompt = build_system_prompt(intent_schema)
        user_content = text
        if context is not None:
            extra = getattr(context, "extra_context", None)
            if extra:
                user_content = f"{text}\n\nContext: {extra}"

        # llama-cpp-python's create_chat_completion is synchronous — run in executor
        # to avoid blocking the asyncio event loop on CPU-bound inference.
        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(
                None,
                lambda: self._inference(system_prompt, user_content),
            )
        except TimeoutError as exc:
            raise LLMTimeoutError(
                f"LlamaCppTranslator: inference timed out: {exc!r}",
                model=self._model_path,
                attempts=1,
            ) from exc
        except Exception as exc:
            raise ExtractionFailureError(f"LlamaCppTranslator: inference failed: {exc!r}") from exc

        try:
            return parse_llm_response(raw, model_name=self._model_path)
        except ExtractionFailureError:
            raise
        except Exception as exc:
            raise ExtractionFailureError(
                f"LlamaCppTranslator: failed to parse model response: {exc!r}. "
                f"Raw response: {raw!r}"
            ) from exc

    def _inference(self, system_prompt: str, user_content: str) -> str:
        """Run synchronous inference under a per-model lock.

        llama-cpp-python wraps a C library with no Python thread safety.
        Concurrent calls on the same Llama object corrupt the KV cache and
        produce cross-policy intent contamination (#242).  The lock serialises
        all inference for the same model file.
        """
        cache_key = (self._model_path, self._n_ctx, self._n_gpu_layers)
        with _get_inference_lock(cache_key):
            return self._inference_locked(system_prompt, user_content)

    def _inference_locked(self, system_prompt: str, user_content: str) -> str:
        """Execute inference (caller must hold the per-model inference lock)."""
        response = self._get_llm().create_chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            max_tokens=self._max_tokens,
            temperature=_TEMPERATURE,
        )
        return response["choices"][0]["message"]["content"] or ""
