# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Platform compatibility checks that run at import time.

C-1: z3-solver ships glibc-compiled wheels. Alpine Linux (musl libc) causes
segfaults and 3-10x slowdowns. Detect musl via /lib/ld-musl-*.so.1 and raise
ConfigurationError before any solve attempt can be made.
"""

from __future__ import annotations

import glob as _glob
from collections.abc import Callable
from typing import Any


def is_musl(
    _glob_fn: Callable[[str], list[Any]] | None = None,
    _platform_str: str | None = None,
    _cdll_fn: Callable[[str], Any] | None = None,
) -> bool:
    """Return ``True`` if the current process is running on musl libc.

    Uses two complementary heuristics so both detection paths are consistent
    (L-18):

    1. ``/lib/ld-musl-*.so.1`` dynamic linker glob (fast, filesystem-based).
    2. ``ctypes.CDLL("libc.so.6")`` load failure — musl does not ship
       ``libc.so.6``; failing to load it confirms musl.

    Returns ``False`` on non-Linux systems or when either check is
    inconclusive.

    Args:
        _glob_fn:      Callable replacing ``glob.glob`` — injectable for tests.
        _platform_str: Platform string replacing ``sys.platform`` — injectable.
        _cdll_fn:      Callable replacing ``ctypes.CDLL`` — injectable for tests.
    """
    import sys

    platform = _platform_str if _platform_str is not None else sys.platform
    if platform != "linux":
        return False

    glob_fn = _glob_fn if _glob_fn is not None else _glob.glob
    if glob_fn("/lib/ld-musl-*.so.1"):
        return True

    try:
        import ctypes

        cdll = _cdll_fn if _cdll_fn is not None else ctypes.CDLL
        cdll("libc.so.6")
    except OSError:
        return True

    return False


def _check_musl(_glob_fn: Callable[[str], list[Any]] | None = None) -> None:
    """Raise ConfigurationError if running on musl libc (Alpine Linux).

    Args:
        _glob_fn: Callable replacing ``glob.glob`` — injectable for tests.
    """
    glob_fn = _glob_fn if _glob_fn is not None else _glob.glob
    musl_loaders = glob_fn("/lib/ld-musl-*.so.1")
    if musl_loaders:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "Pramanix detected musl libc (Alpine Linux): "
            f"{musl_loaders[0]!r}. "
            "z3-solver ships glibc-compiled wheels that segfault or run 3-10x "
            "slower on musl. Use a Debian-based image (python:3.13-slim-bookworm) "
            "instead. See Dockerfile.slim in the project root for a reference "
            "image. If you must use Alpine, compile z3 from source against musl "
            "and set PRAMANIX_SKIP_MUSL_CHECK=1 to bypass this guard."
        )


def check_platform(_glob_fn: Callable[[str], list[Any]] | None = None) -> None:
    """Run all platform compatibility checks.

    Called once at Guard import time. Individual checks are no-ops on
    compatible platforms so the overhead is negligible (single glob call).

    Args:
        _glob_fn: Callable replacing ``glob.glob`` — injectable for tests.
    """
    import os

    if os.environ.get("PRAMANIX_SKIP_MUSL_CHECK") == "1":
        return
    _check_musl(_glob_fn=_glob_fn)
