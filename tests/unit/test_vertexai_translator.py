# SPDX-License-Identifier: AGPL-3.0-only
"""Production-quality coverage tests for src/pramanix/translator/vertexai.py.

google-cloud-aiplatform (vertexai) is NOT installed in this environment,
so we can only exercise:
  1. ConfigurationError raised in __init__ when vertexai is absent.
  2. The _is_palm() module-level helper function.

These two paths bring vertexai.py from 0% up to the maximum achievable
coverage without installing the SDK.
"""

from __future__ import annotations

import pytest

from pramanix.exceptions import ConfigurationError
from pramanix.translator.vertexai import VertexAITranslator, _is_palm

# ── ConfigurationError path (vertexai not installed) ─────────────────────────


class TestVertexAITranslatorInitFailure:
    def test_raises_configuration_error_when_factory_raises_import_error(self) -> None:
        """Supplying a factory that raises ImportError must raise ConfigurationError."""

        def _bad_factory() -> None:
            raise ImportError("google-cloud-aiplatform not installed")

        with pytest.raises(ConfigurationError, match="google-cloud-aiplatform is required"):
            VertexAITranslator("gemini-1.5-pro", _vertexai_factory=_bad_factory)

    def test_raises_configuration_error_message_contains_install_hint(self) -> None:
        def _bad_factory() -> None:
            raise ImportError("no module named vertexai")

        with pytest.raises(ConfigurationError, match="pramanix\\[vertexai\\]"):
            VertexAITranslator("text-bison@001", _vertexai_factory=_bad_factory)

    def test_error_chains_import_error(self) -> None:
        """The ConfigurationError's __cause__ must be the original ImportError."""
        original = ImportError("no vertexai")

        def _bad_factory() -> None:
            raise original

        with pytest.raises(ConfigurationError) as exc_info:
            VertexAITranslator("gemini-1.5-flash", _vertexai_factory=_bad_factory)

        assert exc_info.value.__cause__ is original


# ── _is_palm() helper ─────────────────────────────────────────────────────────


class TestIsPalmHelper:
    """_is_palm() is a pure function — no SDK required."""

    def test_text_bison_is_palm(self) -> None:
        assert _is_palm("text-bison-001") is True

    def test_text_bison_at_version_is_palm(self) -> None:
        assert _is_palm("text-bison@001") is True

    def test_text_unicorn_is_palm(self) -> None:
        assert _is_palm("text-unicorn-001") is True

    def test_text_gecko_is_palm(self) -> None:
        assert _is_palm("text-gecko-001") is True

    def test_gemini_is_not_palm(self) -> None:
        assert _is_palm("gemini-1.5-pro-001") is False

    def test_gemini_flash_is_not_palm(self) -> None:
        assert _is_palm("gemini-1.5-flash") is False

    def test_llama_is_not_palm(self) -> None:
        assert _is_palm("llama-3-8b") is False

    def test_claude_is_not_palm(self) -> None:
        assert _is_palm("claude-3-5-sonnet") is False

    def test_empty_string_is_not_palm(self) -> None:
        assert _is_palm("") is False

    def test_prefix_substring_is_not_palm(self) -> None:
        # "nottext-bison" does not start with the prefix
        assert _is_palm("nottext-bison-001") is False

    def test_text_bison_uppercase_is_not_palm(self) -> None:
        # The function expects lowercase — callers lower() before calling
        assert _is_palm("TEXT-BISON-001") is False
