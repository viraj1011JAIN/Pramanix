# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for MistralTranslator and LlamaCppTranslator (D-2)."""
from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pramanix.exceptions import ConfigurationError

# ── MistralTranslator ─────────────────────────────────────────────────────────


def test_mistral_raises_config_error_without_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "mistralai", None)
    monkeypatch.setitem(sys.modules, "mistralai.async_client", None)
    monkeypatch.setitem(sys.modules, "mistralai.models.chat_completion", None)
    # Re-import to force ImportError path
    if "pramanix.translator.mistral" in sys.modules:
        del sys.modules["pramanix.translator.mistral"]
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[mistral\\]'"):
        from pramanix.translator.mistral import MistralTranslator
        MistralTranslator("mistral-small")


def test_mistral_translator_init_with_mock() -> None:
    """MistralTranslator initialises correctly when mistralai is available."""
    mock_mistral_pkg = MagicMock()
    mock_client_cls = MagicMock()
    mock_mistral_pkg.MistralAsyncClient = mock_client_cls

    with patch.dict(sys.modules, {"mistralai": mock_mistral_pkg, "mistralai.async_client": mock_mistral_pkg}):
        if "pramanix.translator.mistral" in sys.modules:
            del sys.modules["pramanix.translator.mistral"]
        from pramanix.translator.mistral import MistralTranslator

        translator = MistralTranslator("mistral-small", api_key="test-key")
        assert translator.model == "mistral-small"


@pytest.mark.asyncio
async def test_mistral_extract_calls_single_call() -> None:
    """extract() delegates to _single_call and returns a parsed dict."""
    from unittest.mock import patch as _patch

    from pydantic import BaseModel as _BaseModel

    class _Schema(_BaseModel):
        amount: int

    mock_pkg = MagicMock()
    mock_pkg.MistralAsyncClient.return_value = MagicMock()

    with patch.dict(sys.modules, {"mistralai": mock_pkg, "mistralai.async_client": mock_pkg}):
        if "pramanix.translator.mistral" in sys.modules:
            del sys.modules["pramanix.translator.mistral"]
        from pramanix.translator.mistral import MistralTranslator

        translator = MistralTranslator("mistral-small", api_key="test-key")
        with _patch.object(translator, "_single_call", new=AsyncMock(return_value='{"amount": 100}')):
            result = await translator.extract("Transfer 100 USD to Alice", _Schema)
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
    """LlamaCppTranslator.model follows 'llama:<path>' convention."""
    mock_llama_pkg = MagicMock()
    mock_llama_cls = MagicMock()
    mock_llama_cls.return_value = MagicMock()
    mock_llama_pkg.Llama = mock_llama_cls

    with patch.dict(sys.modules, {"llama_cpp": mock_llama_pkg}):
        if "pramanix.translator.llamacpp" in sys.modules:
            del sys.modules["pramanix.translator.llamacpp"]
        from pramanix.translator.llamacpp import LlamaCppTranslator

        t = LlamaCppTranslator("/models/my.gguf")
        assert t.model == "llama-cpp:/models/my.gguf"


@pytest.mark.asyncio
async def test_llamacpp_extract_calls_inference() -> None:
    """extract() wraps sync _inference call in an executor and returns dict."""
    from unittest.mock import patch as _patch

    from pydantic import BaseModel as _BaseModel

    class _Schema(_BaseModel):
        amount: int

    mock_llama_pkg = MagicMock()
    mock_llm = MagicMock()
    mock_llama_pkg.Llama.return_value = mock_llm

    with patch.dict(sys.modules, {"llama_cpp": mock_llama_pkg}):
        if "pramanix.translator.llamacpp" in sys.modules:
            del sys.modules["pramanix.translator.llamacpp"]
        from pramanix.translator.llamacpp import LlamaCppTranslator

        t = LlamaCppTranslator("/models/my.gguf")
        with _patch.object(t, "_inference", return_value='{"amount": 50}'):
            result = await t.extract("move 50 tokens", _Schema)
    assert isinstance(result, dict)
    assert result.get("amount") == 50


# ── create_translator routing ─────────────────────────────────────────────────


def test_create_translator_mistral_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_pkg = MagicMock()
    mock_pkg.MistralAsyncClient.return_value = MagicMock()
    with patch.dict(sys.modules, {"mistralai": mock_pkg, "mistralai.async_client": mock_pkg}):
        if "pramanix.translator.mistral" in sys.modules:
            del sys.modules["pramanix.translator.mistral"]
        from pramanix.translator.redundant import create_translator
        t = create_translator("mistral:mistral-small", api_key="key")
        assert t.model == "mistral-small"


def test_create_translator_llama_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_pkg = MagicMock()
    mock_pkg.Llama.return_value = MagicMock()
    with patch.dict(sys.modules, {"llama_cpp": mock_pkg}):
        if "pramanix.translator.llamacpp" in sys.modules:
            del sys.modules["pramanix.translator.llamacpp"]
        from pramanix.translator.redundant import create_translator
        t = create_translator("llama:/some/model.gguf")
        assert t.model.startswith("llama-cpp:")
