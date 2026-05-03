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


def test_llamacpp_raises_config_error_without_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "llama_cpp", None)
    if "pramanix.translator.llamacpp" in sys.modules:
        del sys.modules["pramanix.translator.llamacpp"]
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[llamacpp\\]'"):
        from pramanix.translator.llamacpp import LlamaCppTranslator
        LlamaCppTranslator("/models/test.gguf")


def test_llamacpp_translator_model_property() -> None:
    """LlamaCppTranslator.model follows 'llama-cpp:<path>' convention."""
    llama_mod = _LlamaCppModule()
    with patch.dict(sys.modules, {"llama_cpp": llama_mod}):  # type: ignore[arg-type]
        if "pramanix.translator.llamacpp" in sys.modules:
            del sys.modules["pramanix.translator.llamacpp"]
        from pramanix.translator.llamacpp import LlamaCppTranslator

        t = LlamaCppTranslator("/models/my.gguf")
        assert t.model == "llama-cpp:/models/my.gguf"


@pytest.mark.asyncio
async def test_llamacpp_extract_calls_inference() -> None:
    """extract() wraps sync _inference in an executor and returns a parsed dict."""
    from pydantic import BaseModel as _BaseModel

    class _Schema(_BaseModel):
        amount: int

    llama_mod = _LlamaCppModule('{"amount": 50}')
    with patch.dict(sys.modules, {"llama_cpp": llama_mod}):  # type: ignore[arg-type]
        if "pramanix.translator.llamacpp" in sys.modules:
            del sys.modules["pramanix.translator.llamacpp"]
        from pramanix.translator.llamacpp import LlamaCppTranslator

        t = LlamaCppTranslator("/models/my.gguf")
        # Replace _inference with a real function — no patch.object / MagicMock needed.
        t._inference = lambda system_prompt, user_content: '{"amount": 50}'  # type: ignore[method-assign]
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
    llama_mod = _LlamaCppModule()
    with patch.dict(sys.modules, {"llama_cpp": llama_mod}):  # type: ignore[arg-type]
        if "pramanix.translator.llamacpp" in sys.modules:
            del sys.modules["pramanix.translator.llamacpp"]
        from pramanix.translator.redundant import create_translator

        t = create_translator("llama:/some/model.gguf")
        assert t.model.startswith("llama-cpp:")
