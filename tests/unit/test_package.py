# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Smoke tests — verify the package is importable and well-formed."""

from __future__ import annotations


def test_package_importable() -> None:
    """The pramanix package must be importable without errors."""
    import pramanix

    assert hasattr(pramanix, "__version__")


def test_version_format() -> None:
    """Version string must follow semver (MAJOR.MINOR.PATCH)."""
    import pramanix

    parts = pramanix.__version__.split(".")
    assert len(parts) == 3, f"Expected semver, got {pramanix.__version__}"
    for part in parts:
        assert part.isdigit(), f"Non-numeric version component: {part}"


def test_py_typed_marker_exists() -> None:
    """PEP 561 py.typed marker must exist for type checker support."""
    from pathlib import Path

    import pramanix

    package_dir = Path(pramanix.__file__).parent
    py_typed = package_dir / "py.typed"
    assert py_typed.exists(), f"py.typed marker not found at {py_typed}"
