# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Production-grade smoke tests — verify the package is importable, well-formed,
and satisfies all Phase 0 packaging invariants before any feature code lands."""

from __future__ import annotations

import re
import sys
from importlib.metadata import PackageNotFoundError, metadata
from pathlib import Path
from types import ModuleType

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _import_pramanix() -> ModuleType:
    import pramanix  # noqa: PLC0415
    return pramanix


# ---------------------------------------------------------------------------
# 1. Import & basic attributes
# ---------------------------------------------------------------------------


def test_package_importable() -> None:
    """The pramanix top-level package must import cleanly with no side-effects."""
    pkg = _import_pramanix()
    assert pkg is not None


def test_version_attribute_exists() -> None:
    """__version__ must be defined at the package root."""
    pkg = _import_pramanix()
    assert hasattr(pkg, "__version__"), "pramanix.__version__ is not defined"
    assert isinstance(pkg.__version__, str), "__version__ must be a str"
    assert pkg.__version__, "__version__ must not be empty"


def test_version_format_semver() -> None:
    """Version string must strictly follow MAJOR.MINOR.PATCH semver."""
    pkg = _import_pramanix()
    pattern = re.compile(r"^\d+\.\d+\.\d+$")
    assert pattern.match(pkg.__version__), (
        f"Expected semver (X.Y.Z), got {pkg.__version__!r}"
    )


def test_version_components_non_negative() -> None:
    """Every version component must be a non-negative integer."""
    pkg = _import_pramanix()
    major, minor, patch = pkg.__version__.split(".")
    for label, value in (("major", major), ("minor", minor), ("patch", patch)):
        assert value.isdigit(), f"{label} version component {value!r} is not a digit"
        assert int(value) >= 0, f"{label} version component must be >= 0"


def test_version_matches_package_metadata() -> None:
    """__version__ must match the version declared in pyproject.toml / dist metadata."""
    try:
        meta = metadata("pramanix")
    except PackageNotFoundError:
        pytest.skip("Package not installed in editable/dist mode — skipping metadata check")
    pkg = _import_pramanix()
    assert pkg.__version__ == meta["Version"], (
        f"__version__ ({pkg.__version__!r}) does not match dist metadata ({meta['Version']!r})"
    )


# ---------------------------------------------------------------------------
# 2. PEP 561 — py.typed marker
# ---------------------------------------------------------------------------


def test_py_typed_marker_exists() -> None:
    """PEP 561 py.typed marker must exist so type checkers treat the package as typed."""
    pkg = _import_pramanix()
    package_dir = Path(pkg.__file__).parent  # type: ignore[arg-type]
    py_typed = package_dir / "py.typed"
    assert py_typed.exists(), (
        f"py.typed marker not found at {py_typed}. "
        "Add an empty py.typed file to src/pramanix/."
    )


def test_py_typed_marker_is_empty_file() -> None:
    """py.typed must be an empty file per PEP 561 specification."""
    pkg = _import_pramanix()
    package_dir = Path(pkg.__file__).parent  # type: ignore[arg-type]
    py_typed = package_dir / "py.typed"
    assert py_typed.exists(), (
        f"py.typed marker not found at {py_typed} — cannot check file size. "
        "Add an empty py.typed file to src/pramanix/."
    )
    assert py_typed.stat().st_size == 0, (
        f"py.typed must be empty (size 0), but has {py_typed.stat().st_size} bytes"
    )


# ---------------------------------------------------------------------------
# 3. Public API surface (__all__)
# ---------------------------------------------------------------------------


def test_all_attribute_defined() -> None:
    """__all__ must be explicitly defined to control the public API surface."""
    pkg = _import_pramanix()
    assert hasattr(pkg, "__all__"), "pramanix.__all__ must be defined"


def test_all_is_list_of_strings() -> None:
    """__all__ must be a list and every entry must be a non-empty string."""
    pkg = _import_pramanix()
    assert isinstance(pkg.__all__, list), "__all__ must be a list"
    for name in pkg.__all__:
        assert isinstance(name, str) and name, (
            f"__all__ entry {name!r} must be a non-empty string"
        )


def test_all_exports_are_importable() -> None:
    """Every name declared in __all__ must actually exist in the package namespace."""
    pkg = _import_pramanix()
    missing = [name for name in pkg.__all__ if not hasattr(pkg, name)]
    assert not missing, (
        f"Names in __all__ not found in package namespace: {missing}"
    )


def test_all_contains_no_private_names() -> None:
    """__all__ must not expose private (underscore-prefixed) names."""
    pkg = _import_pramanix()
    private = [name for name in pkg.__all__ if name.startswith("_")]
    assert not private, (
        f"Private names must not appear in __all__: {private}"
    )


# ---------------------------------------------------------------------------
# 4. Package location & structure
# ---------------------------------------------------------------------------


def test_package_file_is_under_src() -> None:
    """The installed package must resolve to a path containing 'pramanix'."""
    pkg = _import_pramanix()
    package_path = Path(pkg.__file__).resolve()  # type: ignore[arg-type]
    assert "pramanix" in package_path.parts, (
        f"Unexpected package location: {package_path}"
    )


def test_package_docstring_exists() -> None:
    """The top-level package must have a module docstring."""
    pkg = _import_pramanix()
    assert pkg.__doc__ and pkg.__doc__.strip(), (
        "pramanix/__init__.py must have a non-empty module docstring"
    )


# ---------------------------------------------------------------------------
# 5. Python version compatibility guard
# ---------------------------------------------------------------------------


def test_minimum_python_version() -> None:
    """The running interpreter must be at least Python 3.10."""
    assert sys.version_info >= (3, 10), (
        f"Pramanix requires Python >= 3.10, running {sys.version}"
    )


def test_maximum_python_version() -> None:
    """The running interpreter must be below Python 3.13.

    pyproject.toml declares python = ">=3.10,<3.13", so 3.13 and above are
    intentionally outside the supported range until z3-solver compatibility
    and CI matrix coverage for 3.13 are confirmed.
    """
    assert sys.version_info < (3, 13), (
        f"Python 3.13+ is not supported (supported range: >=3.10,<3.13); "
        f"running {sys.version}. Switch to Python 3.10, 3.11, or 3.12."
    )
