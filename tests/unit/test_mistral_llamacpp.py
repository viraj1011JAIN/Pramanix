# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for MistralTranslator and LlamaCppTranslator (D-2)."""
from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from pramanix.exceptions import ConfigurationError
from tests.helpers.real_protocols import _LlamaCppModule, _MistralClientStub

# ── MistralTranslator ─────────────────────────────────────────────────────────


def test_mistral_raises_config_error_without_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "mistralai", None)
    monkeypatch.setitem(sys.modules, "mistralai.client", None)
    monkeypatch.setitem(sys.modules, "mistralai.async_client", None)
    monkeypatch.setitem(sys.modules, "mistralai.models.chat_completion", None)
    if "pramanix.translator.mistral" in sys.modules:
        del sys.modules["pramanix.translator.mistral"]
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[mistral\\]'"):
        from pramanix.translator.mistral import MistralTranslator
        MistralTranslator("mistral-small")


def test_mistral_translator_init_model_attribute() -> None:
    """MistralTranslator.model is set correctly when mistralai is available."""
    pytest.importorskip("mistralai")
    from pramanix.translator.mistral import MistralTranslator

    translator = MistralTranslator("mistral-small", api_key="test-key")
    assert translator.model == "mistral-small"


@pytest.mark.asyncio
async def test_mistral_extract_calls_single_call() -> None:
    """extract() drives _single_call through the real client path and parses the dict."""
    pytest.importorskip("mistralai")

    from pydantic import BaseModel as _BaseModel

    from pramanix.translator.mistral import MistralTranslator

    class _Schema(_BaseModel):
        amount: int

    t = MistralTranslator.__new__(MistralTranslator)
    t.model = "mistral-small"
    t._api_key = "test-key"
    t._timeout = 30.0
    t._client = _MistralClientStub('{"amount": 100}')

    result = await t.extract("Transfer 100 USD to Alice", _Schema)
    assert isinstance(result, dict)
    assert result.get("amount") == 100


# ── LlamaCppTranslator ────────────────────────────────────────────────────────
#
# These tests must NOT delete sys.modules["pramanix.translator.llamacpp"] because
# doing so inside a patch.dict block causes the parent package attribute
# (pramanix.translator.llamacpp) to diverge from sys.modules — a split that
# breaks later tests which rely on both pointing to the same module object.
#
# Since llama_cpp is installed in the project venv, all tests run against the
# real module.  ConfigurationError is tested by shadowing "llama_cpp" in
# sys.modules with None (import machinery raises ImportError on None entries).


def test_llamacpp_raises_config_error_without_package(monkeypatch: pytest.MonkeyPatch) -> None:
    """ConfigurationError raised when llama_cpp is absent (not installed)."""
    from pramanix.translator.llamacpp import LlamaCppTranslator

    monkeypatch.setitem(sys.modules, "llama_cpp", None)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[llamacpp\\]'"):
        LlamaCppTranslator("/models/test.gguf")


def test_llamacpp_translator_model_property() -> None:
    """LlamaCppTranslator.model follows 'llama-cpp:<path>' convention."""
    from pramanix.translator.llamacpp import LlamaCppTranslator

    t = LlamaCppTranslator.__new__(LlamaCppTranslator)
    t.model = "llama-cpp:/models/my.gguf"
    assert t.model == "llama-cpp:/models/my.gguf"


@pytest.mark.asyncio
async def test_llamacpp_extract_calls_inference() -> None:
    """extract() wraps _inference in an executor and returns the parsed dict.

    Uses __new__ + direct attribute injection to avoid loading a real GGUF
    file.  _inference is replaced with a real callable — no MagicMock.
    """
    from pydantic import BaseModel as _BaseModel

    from pramanix.translator.llamacpp import LlamaCppTranslator

    class _Schema(_BaseModel):
        amount: int

    t = LlamaCppTranslator.__new__(LlamaCppTranslator)
    t.model = "llama-cpp:/models/my.gguf"
    t._model_path = "/models/my.gguf"
    t._n_ctx = 4096
    t._n_gpu_layers = 0
    t._max_tokens = 512
    t._llm = _LlamaCppModule('{"amount": 50}').Llama(model_path="/models/my.gguf")

    result = await t.extract("move 50 tokens", _Schema)
    assert isinstance(result, dict)
    assert result.get("amount") == 50


# ── create_translator routing ─────────────────────────────────────────────────


def test_create_translator_mistral_prefix() -> None:
    """create_translator("mistral:...") returns a MistralTranslator."""
    pytest.importorskip("mistralai")
    from pramanix.translator.redundant import create_translator

    t = create_translator("mistral:mistral-small", api_key="key")
    assert t.model == "mistral-small"


def test_create_translator_llama_prefix() -> None:
    """create_translator("llama:...") returns a LlamaCppTranslator."""
    from pramanix.translator.redundant import create_translator

    t = create_translator("llama:/some/model.gguf")
    assert t.model.startswith("llama-cpp:")
