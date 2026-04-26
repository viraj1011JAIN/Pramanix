# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real llama-cpp-python integration tests — T-04.

Requires a real GGUF model file.  Set:
  PRAMANIX_TEST_GGUF_PATH=/path/to/model.gguf

Recommended model for CI (380 MB, fast on CPU):
  TinyLlama-1.1B-Chat-v1.0.Q2_K.gguf
  https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF

These tests validate behaviour that _FakeLlama cannot replicate:
  - Real GGUF file loading and memory allocation
  - Real token limit enforcement (max_tokens)
  - Real inference timing (warmup vs cold start)
  - Real JSON output from the actual model
  - Multiple Guard instances sharing one loaded model (module-level cache)
  - Context window limits (n_ctx)
"""
from __future__ import annotations

import asyncio
import os
import time

import pytest

from pydantic import BaseModel

from pramanix.exceptions import ExtractionFailureError
from pramanix.translator.llamacpp import LlamaCppTranslator, _MODEL_CACHE

from .conftest import requires_llamacpp

_GGUF_PATH = os.environ.get("PRAMANIX_TEST_GGUF_PATH", "")


class SimpleIntent(BaseModel):
    action: str
    amount: float


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_llamacpp
def test_llamacpp_translator_loads_and_extracts() -> None:
    """Real GGUF model loads and returns a parseable JSON dict."""
    translator = LlamaCppTranslator(
        _GGUF_PATH,
        n_ctx=512,
        max_tokens=128,
    )
    result = asyncio.run(translator.extract("pay 50 USD", SimpleIntent))
    assert isinstance(result, dict)
    # Model may return different keys but must return a dict
    assert result


@requires_llamacpp
def test_llamacpp_model_cache_shared_across_instances() -> None:
    """Two LlamaCppTranslator instances with the same path share one loaded model.

    L-13: lazy load with module-level cache.  Without sharing, two Guard
    instances would each allocate 4+ GB — exhausting RAM on any real server.
    """
    _MODEL_CACHE.clear()  # start clean

    t1 = LlamaCppTranslator(_GGUF_PATH, n_ctx=512)
    t2 = LlamaCppTranslator(_GGUF_PATH, n_ctx=512)

    # Trigger loading on both
    asyncio.run(t1.extract("test", SimpleIntent))
    asyncio.run(t2.extract("test", SimpleIntent))

    cache_key = (_GGUF_PATH, 512, 0)
    assert cache_key in _MODEL_CACHE, "Model must be cached"
    assert len(_MODEL_CACHE) == 1, "Only one loaded model for the same path+params"


@requires_llamacpp
def test_llamacpp_cold_start_is_slower_than_warm() -> None:
    """First inference (cold) is slower than second (warm, model in memory).

    Real GGUF loading involves mmap and metal/cuda init — a fake cannot measure
    this.  Validates that the cache eliminates redundant loading overhead.
    """
    _MODEL_CACHE.clear()
    translator = LlamaCppTranslator(_GGUF_PATH, n_ctx=256, max_tokens=64)

    t_start = time.perf_counter()
    asyncio.run(translator.extract("test input one", SimpleIntent))
    cold_ms = (time.perf_counter() - t_start) * 1000

    t_start = time.perf_counter()
    asyncio.run(translator.extract("test input two", SimpleIntent))
    warm_ms = (time.perf_counter() - t_start) * 1000

    # Warm inference should be significantly faster (no model loading)
    assert warm_ms < cold_ms, (
        f"Warm inference ({warm_ms:.0f}ms) should be faster than "
        f"cold inference ({cold_ms:.0f}ms)"
    )


@requires_llamacpp
def test_llamacpp_model_attribute_contains_path() -> None:
    """The model attribute includes the GGUF path for routing identification."""
    translator = LlamaCppTranslator(_GGUF_PATH)
    assert _GGUF_PATH in translator.model


@requires_llamacpp
def test_llamacpp_different_n_ctx_different_cache_entries() -> None:
    """Different n_ctx values create separate cache entries — not aliased."""
    _MODEL_CACHE.clear()

    t512 = LlamaCppTranslator(_GGUF_PATH, n_ctx=512)
    t1024 = LlamaCppTranslator(_GGUF_PATH, n_ctx=1024)

    asyncio.run(t512.extract("test", SimpleIntent))
    asyncio.run(t1024.extract("test", SimpleIntent))

    assert (_GGUF_PATH, 512, 0) in _MODEL_CACHE
    assert (_GGUF_PATH, 1024, 0) in _MODEL_CACHE


@requires_llamacpp
def test_llamacpp_extract_is_deterministic_at_temperature_zero() -> None:
    """Two identical prompts at temperature=0 produce the same JSON structure.

    Real LLM inference at temperature=0 is deterministic.  A fake always
    returns the same hardcoded response, masking any temperature bug.
    """
    translator = LlamaCppTranslator(_GGUF_PATH, n_ctx=512, max_tokens=128)
    r1 = asyncio.run(translator.extract("transfer one hundred dollars", SimpleIntent))
    r2 = asyncio.run(translator.extract("transfer one hundred dollars", SimpleIntent))

    # Both should have the same keys (exact values may vary across runs due to
    # system-level floating point, but structure should match)
    assert set(r1.keys()) == set(r2.keys()), (
        f"Deterministic inference should produce same keys: {r1.keys()} vs {r2.keys()}"
    )
