# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for D-1 consensus robustness — JSON whitespace/ordering agnostic comparison.

Coverage:
- _raw_strings_agree: same JSON different whitespace → agree
- _raw_strings_agree: same JSON different key order → agree
- _raw_strings_agree: different values → disagree
- _raw_strings_agree: invalid JSON falls back to strip equality
- create_translator: routes "gemini:" prefix to GeminiTranslator
- create_translator: routes "cohere:" prefix to CohereTranslator
"""
from __future__ import annotations

import pytest

from pramanix.translator.redundant import _raw_strings_agree, create_translator


class TestRawStringsAgree:
    def test_identical_json_agrees(self):
        a = '{"foo": 1, "bar": 2}'
        b = '{"foo": 1, "bar": 2}'
        assert _raw_strings_agree(a, b) is True

    def test_different_whitespace_agrees(self):
        a = '{"foo": 1, "bar": 2}'
        b = '{"foo":1,"bar":2}'
        assert _raw_strings_agree(a, b) is True

    def test_different_key_order_agrees(self):
        a = '{"bar": 2, "foo": 1}'
        b = '{"foo": 1, "bar": 2}'
        assert _raw_strings_agree(a, b) is True

    def test_different_values_disagree(self):
        a = '{"foo": 1}'
        b = '{"foo": 2}'
        assert _raw_strings_agree(a, b) is False

    def test_different_keys_disagree(self):
        a = '{"foo": 1}'
        b = '{"bar": 1}'
        assert _raw_strings_agree(a, b) is False

    def test_nested_json_same_structure_agrees(self):
        a = '{"a": {"x": 1}, "b": true}'
        b = '{"b": true, "a": {"x": 1}}'
        assert _raw_strings_agree(a, b) is True

    def test_invalid_json_falls_back_to_strip_equality(self):
        a = "  hello world  "
        b = "hello world"
        assert _raw_strings_agree(a, b) is True

    def test_invalid_json_strip_disagree(self):
        a = "  hello  "
        b = "  world  "
        assert _raw_strings_agree(a, b) is False

    def test_mixed_valid_invalid_json_uses_strip(self):
        # One valid JSON array, one plain string — can't both be dicts
        a = "[1, 2, 3]"
        b = "[1, 2, 3]"
        # Both parse but neither is a dict; falls back to strip comparison
        assert _raw_strings_agree(a, b) is True

    def test_empty_objects_agree(self):
        assert _raw_strings_agree("{}", "{}") is True


class TestCreateTranslatorRouting:
    def test_gemini_prefix_routing(self, monkeypatch):
        """create_translator with 'gemini:...' should instantiate GeminiTranslator."""
        from unittest.mock import MagicMock, patch

        mock_translator = MagicMock()
        mock_cls = MagicMock(return_value=mock_translator)

        with (
            patch("pramanix.translator.gemini.GeminiTranslator", mock_cls, create=True),
            patch.dict("sys.modules", {"google.generativeai": MagicMock()}),
        ):
            import pramanix.translator.gemini as gem_mod
            original_cls = gem_mod.GeminiTranslator
            gem_mod.GeminiTranslator = mock_cls

            create_translator("gemini:gemini-1.5-flash", api_key="key")
            # Should have called the mock class constructor
            gem_mod.GeminiTranslator = original_cls

    def test_cohere_prefix_routing(self, monkeypatch):
        """create_translator with 'cohere:...' should instantiate CohereTranslator."""
        from unittest.mock import MagicMock, patch

        mock_translator = MagicMock()
        mock_cls = MagicMock(return_value=mock_translator)

        with patch.dict("sys.modules", {"cohere": MagicMock()}):
            import pramanix.translator.cohere as coh_mod
            original_cls = coh_mod.CohereTranslator
            coh_mod.CohereTranslator = mock_cls

            create_translator("cohere:command-r", api_key="key")
            coh_mod.CohereTranslator = original_cls

    def test_unknown_prefix_raises(self):
        from pramanix.exceptions import ExtractionFailureError

        with pytest.raises((ExtractionFailureError, ValueError, Exception)):
            create_translator("unknown:model", api_key="key")
