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

Strategy: call pramanix.integrations.__getattr__ directly — no sys.modules
manipulation, no stub injection.  This exercises the same code path as lazy
attribute access on the module object.
"""

from __future__ import annotations

import importlib

import pytest


def _integrations_getattr(name: str) -> object:
    """Call the integrations package __getattr__ directly."""
    mod = importlib.import_module("pramanix.integrations")
    return mod.__getattr__(name)


class TestIntegrationsLazyImports:
    """Each test exercises one branch of integrations/__init__.__getattr__."""

    def test_crewai_lazy_import(self) -> None:
        """PramanixCrewAITool triggers the crewai branch."""
        pytest.importorskip("crewai")
        obj = _integrations_getattr("PramanixCrewAITool")
        assert obj is not None

    def test_dspy_lazy_import(self) -> None:
        """PramanixGuardedModule triggers the dspy branch."""
        pytest.importorskip("dspy")
        obj = _integrations_getattr("PramanixGuardedModule")
        assert obj is not None

    def test_haystack_lazy_import(self) -> None:
        """HaystackGuardedComponent triggers the haystack branch."""
        pytest.importorskip("haystack")
        obj = _integrations_getattr("HaystackGuardedComponent")
        assert obj is not None

    def test_semantic_kernel_lazy_import(self) -> None:
        """PramanixSemanticKernelPlugin triggers the sk branch."""
        pytest.importorskip("semantic_kernel")
        obj = _integrations_getattr("PramanixSemanticKernelPlugin")
        assert obj is not None

    def test_pydantic_ai_lazy_import(self) -> None:
        """PramanixPydanticAIValidator triggers the pydantic_ai branch."""
        pytest.importorskip("pydantic_ai")
        obj = _integrations_getattr("PramanixPydanticAIValidator")
        assert obj is not None

    def test_unknown_attribute_raises(self) -> None:
        """Accessing unknown name raises AttributeError (line 104)."""
        import pramanix.integrations as integrations_mod

        with pytest.raises(AttributeError, match="no attribute"):
            _ = integrations_mod.NonExistentThing  # type: ignore[attr-defined]


class TestIntegrationStatus:
    """INTEGRATION_STATUS dict must cover every __all__ entry and have valid labels."""

    def _get_status(self):
        mod = importlib.import_module("pramanix.integrations")
        return mod.INTEGRATION_STATUS

    def test_integration_status_is_dict(self) -> None:
        status = self._get_status()
        assert isinstance(status, dict)

    def test_all_exported_names_have_status(self) -> None:
        import pramanix.integrations as _int

        status = _int.INTEGRATION_STATUS
        non_status = [
            name for name in _int.__all__ if name != "INTEGRATION_STATUS" and name not in status
        ]
        assert non_status == [], (
            f"These exported integrations have no maturity label in INTEGRATION_STATUS: "
            f"{non_status}"
        )

    def test_status_values_are_known_labels(self) -> None:
        valid = {"stable", "beta", "alpha", "deprecated"}
        status = self._get_status()
        bad = {k: v for k, v in status.items() if v not in valid}
        assert not bad, f"Unknown maturity labels: {bad}"

    def test_phase_f1_stubs_are_labeled_beta(self) -> None:
        status = self._get_status()
        stubs = [
            "HaystackGuardedComponent",
            "PramanixCrewAITool",
            "PramanixGuardedModule",
            "PramanixPydanticAIValidator",
            "PramanixSemanticKernelPlugin",
        ]
        for name in stubs:
            assert status.get(name) == "beta", (
                f"Phase F-1 stub {name!r} should be labeled 'beta', "
                f"got {status.get(name)!r}"
            )

    def test_core_integrations_are_labeled_stable(self) -> None:
        status = self._get_status()
        core = [
            "PramanixGuardNode",
            "pramanix_node",
            "PramanixGuardedTool",
            "PramanixMiddleware",
            "PramanixFunctionTool",
        ]
        for name in core:
            assert status.get(name) == "stable", (
                f"Core integration {name!r} should be labeled 'stable', "
                f"got {status.get(name)!r}"
            )
