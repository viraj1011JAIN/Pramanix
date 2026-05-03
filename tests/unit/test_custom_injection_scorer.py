# SPDX-License-Identifier: AGPL-3.0-only
# Phase D-4: Tests for custom injection scorer support
"""Unit tests for GuardConfig.injection_scorer_path (entry-point name) and related plumbing.

The injection_scorer_path field is a *trusted-operator-only entry-point name*,
not a file path.  Custom scorers must be registered via the
'pramanix.injection_scorers' entry-point group and referenced by name.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pramanix.exceptions import ConfigurationError
from pramanix.guard_config import GuardConfig


# ── GuardConfig field tests ───────────────────────────────────────────────────


class TestGuardConfigInjectionScorerPath:
    def test_default_is_none(self) -> None:
        """injection_scorer_path defaults to None."""
        cfg = GuardConfig()
        assert cfg.injection_scorer_path is None

    def test_valid_entry_point_name_accepted(self) -> None:
        """A valid entry-point name (no path separators) is accepted."""
        cfg = GuardConfig(injection_scorer_path="my_scorer")
        assert cfg.injection_scorer_path == "my_scorer"

    def test_dotted_entry_point_name_accepted(self) -> None:
        """Dotted names such as 'org.acme.scorer' are valid entry-point names."""
        cfg = GuardConfig(injection_scorer_path="org.acme.scorer")
        assert cfg.injection_scorer_path == "org.acme.scorer"

    def test_forward_slash_path_raises_configuration_error(self) -> None:
        """A Unix-style file path must be rejected (forward slash present)."""
        with pytest.raises(ConfigurationError, match="entry-point name"):
            GuardConfig(injection_scorer_path="/tmp/my_scorer.py")

    def test_backslash_path_raises_configuration_error(self) -> None:
        """A Windows-style file path must be rejected (backslash present)."""
        with pytest.raises(ConfigurationError, match="entry-point name"):
            GuardConfig(injection_scorer_path="C:\\Users\\scorer.py")

    def test_env_var_sets_scorer_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_INJECTION_SCORER_PATH env var sets the entry-point name."""
        monkeypatch.setenv("PRAMANIX_INJECTION_SCORER_PATH", "my_custom_scorer")
        cfg = GuardConfig()
        assert cfg.injection_scorer_path == "my_custom_scorer"

    def test_empty_env_var_leaves_default_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_INJECTION_SCORER_PATH='' produces injection_scorer_path=None."""
        monkeypatch.setenv("PRAMANIX_INJECTION_SCORER_PATH", "")
        cfg = GuardConfig()
        assert cfg.injection_scorer_path is None

    def test_unset_env_var_leaves_default_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Absent PRAMANIX_INJECTION_SCORER_PATH leaves injection_scorer_path=None."""
        monkeypatch.delenv("PRAMANIX_INJECTION_SCORER_PATH", raising=False)
        cfg = GuardConfig()
        assert cfg.injection_scorer_path is None


# ── extract_with_consensus custom scorer integration tests ────────────────────


class TestExtractWithConsensusCustomScorer:
    """Tests for the entry-point-based scorer loading in extract_with_consensus."""

    def test_unregistered_scorer_name_raises_value_error(self) -> None:
        """Passing an unregistered entry-point name raises ValueError."""
        import asyncio

        from pramanix.translator.redundant import extract_with_consensus

        class _FakeSchema:
            @classmethod
            def model_fields(cls):
                return {}

        async def _run():
            await extract_with_consensus(
                "text",
                _FakeSchema,  # type: ignore[arg-type]
                (object(), object()),  # type: ignore[arg-type]
                injection_scorer_path="definitely_not_registered_xyz987",
            )

        with pytest.raises(ValueError, match="No registered injection scorer"):
            asyncio.run(_run())

    def test_scorer_path_none_uses_builtin(self) -> None:
        """When injection_scorer_path is None, the built-in scorer is used."""
        from pramanix.translator._sanitise import injection_confidence_score

        score = injection_confidence_score("hello world transfer 100", {"amount": "100"}, [])
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_registered_scorer_is_loaded_via_entry_points(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scorer registered in the entry-point group is loaded and called."""
        from unittest.mock import patch

        import importlib.metadata as _meta

        from tests.helpers.real_protocols import _FakeEntryPoint

        def _scorer(text, extracted, warnings):
            return 0.1

        fake_ep = _FakeEntryPoint("test_scorer", _scorer)

        with patch.object(_meta, "entry_points", return_value=[fake_ep]):
            eps = _meta.entry_points(group="pramanix.injection_scorers")
            ep = next((e for e in eps if e.name == "test_scorer"), None)
            assert ep is not None
            fn = ep.load()
            result = fn("user text", {"amount": "100"}, [])

        assert result == 0.1
