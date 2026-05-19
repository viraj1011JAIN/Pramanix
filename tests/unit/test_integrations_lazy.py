# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for pramanix.integrations.__init__ lazy import machinery.

Covers the __getattr__ branches for the five extension integrations that are
NOT imported by any other test (crewai, dspy, haystack, semantic_kernel,
pydantic_ai):

    integrations/__init__.py  lines 85-103

Also covers the AttributeError fallback (line 104).

Strategy: patch sys.modules so the optional framework packages appear
installed (each replaced by a lightweight stub module). The lazy import
in __getattr__ then imports the pramanix integration sub-module, which
in turn imports the stub. We verify that __getattr__ returns the expected
class/callable without instantiating it.
"""

from __future__ import annotations

import importlib
import sys
import types

import pytest


def _stub_module(name: str) -> types.ModuleType:
    """Return a real types.ModuleType stub for *name*."""
    stub = types.ModuleType(name)
    stub.__name__ = name
    stub.__package__ = name.split(".")[0]
    stub.__spec__ = None
    stub.__loader__ = None
    stub.__path__ = []
    return stub


def _reload_integrations_init() -> types.ModuleType:
    """Force a fresh import of pramanix.integrations to re-run __getattr__."""
    mod_name = "pramanix.integrations"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    return importlib.import_module(mod_name)


class TestIntegrationsLazyImports:
    """Each test exercises one branch of integrations/__init__.__getattr__."""

    def test_crewai_lazy_import(self) -> None:
        """PramanixCrewAITool triggers the crewai branch (lines 85-87)."""
        crewai_stub = _stub_module("crewai")
        crewai_stub.BaseTool = type("BaseTool", (), {})

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "crewai", crewai_stub)
            # Remove any cached integration sub-module so it re-imports with stub
            mp.delitem(sys.modules, "pramanix.integrations.crewai", raising=False)
            mp.delitem(sys.modules, "pramanix.integrations", raising=False)
            integrations = importlib.import_module("pramanix.integrations")
            obj = integrations.PramanixCrewAITool
            assert obj is not None

    def test_dspy_lazy_import(self) -> None:
        """PramanixGuardedModule triggers the dspy branch (lines 89-91)."""
        dspy_stub = _stub_module("dspy")
        dspy_stub.Module = type("Module", (), {})

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "dspy", dspy_stub)
            mp.delitem(sys.modules, "pramanix.integrations.dspy", raising=False)
            mp.delitem(sys.modules, "pramanix.integrations", raising=False)
            integrations = importlib.import_module("pramanix.integrations")
            obj = integrations.PramanixGuardedModule
            assert obj is not None

    def test_haystack_lazy_import(self) -> None:
        """HaystackGuardedComponent triggers the haystack branch (lines 93-95)."""
        haystack_stub = _stub_module("haystack")
        haystack_comp_stub = _stub_module("haystack.components")
        haystack_stub.components = haystack_comp_stub

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "haystack", haystack_stub)
            mp.setitem(sys.modules, "haystack.components", haystack_comp_stub)
            mp.delitem(sys.modules, "pramanix.integrations.haystack", raising=False)
            mp.delitem(sys.modules, "pramanix.integrations", raising=False)
            integrations = importlib.import_module("pramanix.integrations")
            obj = integrations.HaystackGuardedComponent
            assert obj is not None

    def test_semantic_kernel_lazy_import(self) -> None:
        """PramanixSemanticKernelPlugin triggers the sk branch (lines 97-99)."""
        sk_stub = _stub_module("semantic_kernel")
        sk_stub.functions = _stub_module("semantic_kernel.functions")

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "semantic_kernel", sk_stub)
            mp.setitem(sys.modules, "semantic_kernel.functions", sk_stub.functions)
            mp.delitem(sys.modules, "pramanix.integrations.semantic_kernel", raising=False)
            mp.delitem(sys.modules, "pramanix.integrations", raising=False)
            integrations = importlib.import_module("pramanix.integrations")
            obj = integrations.PramanixSemanticKernelPlugin
            assert obj is not None

    def test_pydantic_ai_lazy_import(self) -> None:
        """PramanixPydanticAIValidator triggers the pydantic_ai branch (lines 101-103)."""
        pai_stub = _stub_module("pydantic_ai")
        pai_stub.Agent = type("Agent", (), {})

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "pydantic_ai", pai_stub)
            mp.delitem(sys.modules, "pramanix.integrations.pydantic_ai", raising=False)
            mp.delitem(sys.modules, "pramanix.integrations", raising=False)
            integrations = importlib.import_module("pramanix.integrations")
            obj = integrations.PramanixPydanticAIValidator
            assert obj is not None

    def test_unknown_attribute_raises(self) -> None:
        """Accessing unknown name raises AttributeError (line 104)."""
        import pramanix.integrations as integrations_mod

        with pytest.raises(AttributeError, match="no attribute"):
            _ = integrations_mod.NonExistentThing  # type: ignore[attr-defined]
