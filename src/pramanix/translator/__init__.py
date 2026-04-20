# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Translator subsystem — optional LLM-based intent extraction.

Public surface
--------------
* :class:`Translator`            — structural protocol all translators satisfy
* :class:`TranslatorContext`     — host-provided grounding context
* :class:`OpenAICompatTranslator`— OpenAI / Azure / vLLM / compatible APIs
* :class:`AnthropicTranslator`   — Anthropic Claude API
* :class:`RedundantTranslator`   — dual-model consensus wrapper
* :func:`extract_with_consensus` — standalone consensus helper
* :func:`create_translator`      — factory: model name → Translator instance

Requires the ``pramanix[translator]`` extra for LLM-backed translators::

    pip install "pramanix[translator]"

The protocol types (:class:`Translator`, :class:`TranslatorContext`) are
always importable without the extra.
"""

from pramanix.translator.base import Translator, TranslatorContext
from pramanix.translator.injection_filter import InjectionFilter
from pramanix.translator.redundant import (
    RedundantTranslator,
    create_translator,
    extract_with_consensus,
)

__all__ = [
    "AnthropicTranslator",
    "InjectionFilter",
    "OllamaTranslator",
    "OpenAICompatTranslator",
    "RedundantTranslator",
    "Translator",
    "TranslatorContext",
    "create_translator",
    "extract_with_consensus",
]


# Lazy imports so that missing optional deps only raise at usage time,
# not at `import pramanix`.
def __getattr__(name: str) -> object:
    if name == "OpenAICompatTranslator":
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        return OpenAICompatTranslator
    if name == "AnthropicTranslator":
        from pramanix.translator.anthropic import AnthropicTranslator

        return AnthropicTranslator
    if name == "OllamaTranslator":
        from pramanix.translator.ollama import OllamaTranslator

        return OllamaTranslator
    raise AttributeError(f"module 'pramanix.translator' has no attribute {name!r}")
