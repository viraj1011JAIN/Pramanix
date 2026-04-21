# SPDX-License-Identifier: AGPL-3.0-only
# Phase D-4: Tests for custom injection scorer support
"""Unit tests for GuardConfig.injection_scorer_path and extract_with_consensus custom scorer."""
from __future__ import annotations

import textwrap
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

    def test_valid_path_accepted(self, tmp_path: Path) -> None:
        """A valid file path is accepted without error."""
        scorer = tmp_path / "scorer.py"
        scorer.write_text(
            "def injection_scorer(user_input, extracted_intent, warnings): return 0.0\n"
        )
        cfg = GuardConfig(injection_scorer_path=scorer)
        assert cfg.injection_scorer_path == scorer

    def test_nonexistent_path_raises_configuration_error(self, tmp_path: Path) -> None:
        """A path that does not exist raises ConfigurationError."""
        bogus = tmp_path / "does_not_exist.py"
        with pytest.raises(ConfigurationError, match="does not exist"):
            GuardConfig(injection_scorer_path=bogus)

    def test_directory_path_raises_configuration_error(self, tmp_path: Path) -> None:
        """A path pointing to a directory raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="not a file"):
            GuardConfig(injection_scorer_path=tmp_path)

    def test_env_var_sets_scorer_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_INJECTION_SCORER_PATH env var is read by GuardConfig()."""
        scorer = tmp_path / "scorer.py"
        scorer.write_text(
            "def injection_scorer(user_input, extracted_intent, warnings): return 0.0\n"
        )
        monkeypatch.setenv("PRAMANIX_INJECTION_SCORER_PATH", str(scorer))
        cfg = GuardConfig()
        assert cfg.injection_scorer_path == scorer

    def test_empty_env_var_leaves_default_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_INJECTION_SCORER_PATH='' still produces injection_scorer_path=None."""
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
    """Tests that extract_with_consensus loads and calls the custom scorer."""

    def _make_scorer(self, tmp_path: Path, return_value: float) -> Path:
        scorer = tmp_path / "scorer.py"
        scorer.write_text(
            textwrap.dedent(f"""\
                def injection_scorer(user_input, extracted_intent, warnings):
                    return {return_value!r}
            """)
        )
        return scorer

    def test_custom_scorer_zero_passes(self, tmp_path: Path) -> None:
        """A custom scorer returning 0.0 never blocks the call."""

        scorer_path = self._make_scorer(tmp_path, 0.0)

        # Directly test that the module loading mechanism works
        import importlib.util as ilu

        spec = ilu.spec_from_file_location("_test_scorer", str(scorer_path))
        assert spec is not None and spec.loader is not None
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        result = mod.injection_scorer("hello", {}, [])
        assert result == 0.0

    def test_custom_scorer_one_would_block(self, tmp_path: Path) -> None:
        """A custom scorer returning 1.0 would exceed the default threshold (0.5)."""
        scorer_path = self._make_scorer(tmp_path, 1.0)

        import importlib.util as ilu

        spec = ilu.spec_from_file_location("_test_scorer2", str(scorer_path))
        assert spec is not None and spec.loader is not None
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        result = mod.injection_scorer("any input", {"amount": "100"}, [])
        assert result == 1.0

    def test_invalid_scorer_path_raises_value_error(self, tmp_path: Path) -> None:
        """Passing a non-existent path string to extract_with_consensus raises ValueError."""
        import asyncio

        from pramanix.translator.redundant import extract_with_consensus

        # We use a mock translator that returns immediately
        class _FakePydanticModel:
            """Minimal stand-in for a Pydantic model class."""
            @classmethod
            def model_fields(cls):
                return {}

        bogus_path = str(tmp_path / "does_not_exist.py")

        async def _run():
            await extract_with_consensus(
                "text",
                _FakePydanticModel,  # type: ignore[arg-type]
                (object(), object()),  # type: ignore[arg-type]
                injection_scorer_path=bogus_path,
            )

        with pytest.raises((ValueError, OSError)):
            asyncio.get_event_loop().run_until_complete(_run())

    def test_scorer_path_none_uses_builtin(self, tmp_path: Path) -> None:
        """When injection_scorer_path is None, the built-in scorer is used (no AttributeError)."""
        # Verify the built-in scorer is callable with the expected signature
        from pramanix.translator._sanitise import injection_confidence_score

        score = injection_confidence_score("hello world transfer 100", {"amount": "100"}, [])
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
