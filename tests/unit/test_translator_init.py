# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for translator/__init__.py lazy imports and create_translator factory.

Coverage targets
----------------
* ``translator/__init__.py`` — lazy __getattr__ for all three concrete translators
* ``create_translator()``    — routing for gpt-*, claude-*, ollama:*, unknown prefix
"""

from __future__ import annotations

import pytest

from pramanix.exceptions import ExtractionFailureError

# ═══════════════════════════════════════════════════════════════════════════════
# translator/__init__.py — lazy __getattr__ imports
# ═══════════════════════════════════════════════════════════════════════════════


class TestTranslatorLazyImports:
    def test_openai_compat_translator_importable(self) -> None:
        import pramanix.translator as t_pkg

        cls = t_pkg.OpenAICompatTranslator
        assert cls.__name__ == "OpenAICompatTranslator"

    def test_anthropic_translator_importable(self) -> None:
        import pramanix.translator as t_pkg

        cls = t_pkg.AnthropicTranslator
        assert cls.__name__ == "AnthropicTranslator"

    def test_ollama_translator_importable(self) -> None:
        import pramanix.translator as t_pkg

        cls = t_pkg.OllamaTranslator
        assert cls.__name__ == "OllamaTranslator"

    def test_unknown_attribute_raises_attribute_error(self) -> None:
        import pramanix.translator as t_pkg

        with pytest.raises(AttributeError, match="no attribute"):
            _ = t_pkg.NonExistentTranslator  # type: ignore[attr-defined]

    def test_always_importable_exports(self) -> None:
        """Translator and TranslatorContext never require extras."""
        from pramanix.translator import Translator, TranslatorContext

        assert Translator is not None
        assert TranslatorContext is not None

    def test_redundant_translator_directly_importable(self) -> None:
        from pramanix.translator import RedundantTranslator

        assert RedundantTranslator is not None

    def test_create_translator_directly_importable(self) -> None:
        from pramanix.translator import create_translator

        assert callable(create_translator)

    def test_extract_with_consensus_directly_importable(self) -> None:
        from pramanix.translator import extract_with_consensus

        assert callable(extract_with_consensus)


# ═══════════════════════════════════════════════════════════════════════════════
# create_translator() — routing factory
# ═══════════════════════════════════════════════════════════════════════════════


class TestCreateTranslator:
    def test_gpt_prefix_routes_to_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("gpt-4o", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)
        assert t.model == "gpt-4o"

    def test_o1_prefix_routes_to_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("o1-preview", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)

    def test_o3_prefix_routes_to_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("o3-mini", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)

    def test_chatgpt_prefix_routes_to_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("chatgpt-4o-latest", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)

    def test_claude_prefix_routes_to_anthropic(self) -> None:
        from pramanix.translator.anthropic import AnthropicTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("claude-opus-4-6")
        assert isinstance(t, AnthropicTranslator)
        assert t.model == "claude-opus-4-6"

    def test_ollama_prefix_routes_to_ollama(self) -> None:
        from pramanix.translator.ollama import OllamaTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("ollama:mistral")
        assert isinstance(t, OllamaTranslator)
        # The "ollama:" namespace prefix is stripped before passing to OllamaTranslator
        assert t.model == "mistral"

    def test_ollama_with_custom_base_url(self) -> None:
        from pramanix.translator.ollama import OllamaTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("ollama:llama3.2", base_url="http://my-server:11434")
        assert isinstance(t, OllamaTranslator)
        assert "my-server" in t._base_url

    def test_claude_with_api_key(self) -> None:
        from pramanix.translator.anthropic import AnthropicTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("claude-opus-4-6", api_key="sk-test-key")
        assert isinstance(t, AnthropicTranslator)
        assert t._api_key == "sk-test-key"

    def test_gpt_with_custom_timeout(self) -> None:
        from pramanix.translator.redundant import create_translator

        t = create_translator("gpt-4o", api_key="sk-test", timeout=90.0)
        assert t._timeout == 90.0

    def test_unknown_model_prefix_raises_extraction_failure(self) -> None:
        from pramanix.translator.redundant import create_translator

        with pytest.raises(ExtractionFailureError, match="Cannot infer translator"):
            create_translator("llama3.2")  # no recognized prefix

    def test_gemini_prefix_routes_to_gemini_translator(self) -> None:
        """'gemini-*' models must route to GeminiTranslator, not raise.

        This is a routing-only test — we stub google.generativeai in sys.modules
        so the assertion is valid regardless of whether the [gemini] extra is
        installed in the active Python environment.
        """
        import sys
        import types
        from unittest.mock import patch

        from pramanix.translator.gemini import GeminiTranslator
        from pramanix.translator.redundant import create_translator

        # Minimal stub: only the attribute accessed by GeminiTranslator.__init__
        fake_genai = types.ModuleType("google.generativeai")
        fake_genai.Client = None  # type: ignore[attr-defined]
        with patch.dict(sys.modules, {"google.generativeai": fake_genai}):
            t = create_translator("gemini-1.5-pro", api_key="test-key")
        assert isinstance(t, GeminiTranslator)

    def test_text_prefix_routes_to_openai_compat(self) -> None:
        """'text-*' models (legacy OpenAI) must route to OpenAICompatTranslator."""
        from pramanix.translator.openai_compat import OpenAICompatTranslator
        from pramanix.translator.redundant import create_translator

        t = create_translator("text-davinci-003", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)
