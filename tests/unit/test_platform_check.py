# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Gate tests for Phase C-1: Alpine Linux / musl libc detection.

Gate condition (from engineering plan):
    # On Alpine container: ConfigurationError raised at import time.
    # On Debian container: import succeeds.
    # PRAMANIX_SKIP_MUSL_CHECK=1 env var bypasses the check.
"""

from __future__ import annotations

import pytest

from pramanix.exceptions import ConfigurationError


class TestMuslDetection:
    def test_no_error_on_non_musl_platform(self) -> None:
        """check_platform() is a no-op when no musl loader exists."""
        from pramanix._platform import _check_musl

        _check_musl(_glob_fn=lambda *a: [])  # must not raise

    def test_raises_on_musl_loader_present(self) -> None:
        """ConfigurationError when /lib/ld-musl-x86_64.so.1 is found."""
        from pramanix._platform import _check_musl

        with pytest.raises(ConfigurationError, match="musl libc"):
            _check_musl(_glob_fn=lambda *a: ["/lib/ld-musl-x86_64.so.1"])

    def test_error_message_contains_loader_path(self) -> None:
        loader = "/lib/ld-musl-aarch64.so.1"
        from pramanix._platform import _check_musl

        with pytest.raises(ConfigurationError, match="ld-musl-aarch64"):
            _check_musl(_glob_fn=lambda *a: [loader])

    def test_error_message_suggests_debian_image(self) -> None:
        from pramanix._platform import _check_musl

        with pytest.raises(ConfigurationError, match="slim-bookworm"):
            _check_musl(_glob_fn=lambda *a: ["/lib/ld-musl-x86_64.so.1"])

    def test_error_message_mentions_skip_env_var(self) -> None:
        from pramanix._platform import _check_musl

        with pytest.raises(ConfigurationError, match="PRAMANIX_SKIP_MUSL_CHECK"):
            _check_musl(_glob_fn=lambda *a: ["/lib/ld-musl-x86_64.so.1"])


class TestSkipMuslCheck:
    def test_skip_env_var_bypasses_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SKIP_MUSL_CHECK", "1")
        from pramanix._platform import check_platform

        check_platform(_glob_fn=lambda *a: ["/lib/ld-musl-x86_64.so.1"])  # must not raise

    def test_skip_env_var_zero_does_not_bypass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SKIP_MUSL_CHECK", "0")
        from pramanix._platform import check_platform

        with pytest.raises(ConfigurationError, match="musl libc"):
            check_platform(_glob_fn=lambda *a: ["/lib/ld-musl-x86_64.so.1"])

    def test_skip_env_var_absent_does_not_bypass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_SKIP_MUSL_CHECK", raising=False)
        from pramanix._platform import check_platform

        with pytest.raises(ConfigurationError, match="musl libc"):
            check_platform(_glob_fn=lambda *a: ["/lib/ld-musl-x86_64.so.1"])


class TestPlatformCheckIntegration:
    def test_current_platform_does_not_raise(self) -> None:
        """Importing pramanix on a glibc platform (dev/CI) must not raise."""
        from pramanix._platform import check_platform

        check_platform()  # running on Windows/Debian — must succeed

    def test_guard_importable_on_non_musl(self) -> None:
        """Guard import succeeds on non-musl platform."""
        from pramanix import Guard  # noqa: F401 — import is the test

    def test_multiple_musl_loaders_uses_first(self) -> None:
        loaders = ["/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-i386.so.1"]
        from pramanix._platform import _check_musl

        with pytest.raises(ConfigurationError, match="ld-musl-x86_64"):
            _check_musl(_glob_fn=lambda *a: loaders)
