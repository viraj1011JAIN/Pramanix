# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Platform compatibility checks that run at import time.

C-1: z3-solver ships glibc-compiled wheels. Alpine Linux (musl libc) causes
segfaults and 3-10x slowdowns. Detect musl via /lib/ld-musl-*.so.1 and raise
ConfigurationError before any solve attempt can be made.
"""
from __future__ import annotations

import glob as _glob


def is_musl() -> bool:
    """Return ``True`` if the current process is running on musl libc.

    Uses two complementary heuristics so both detection paths are consistent
    (L-18):

    1. ``/lib/ld-musl-*.so.1`` dynamic linker glob (fast, filesystem-based).
    2. ``ctypes.CDLL("libc.so.6")`` load failure — musl does not ship
       ``libc.so.6``; failing to load it confirms musl.

    Returns ``False`` on non-Linux systems or when either check is
    inconclusive.
    """
    import sys

    if sys.platform != "linux":
        return False

    if _glob.glob("/lib/ld-musl-*.so.1"):
        return True

    try:
        import ctypes

        ctypes.CDLL("libc.so.6")
    except OSError:
        return True

    return False


def _check_musl() -> None:
    """Raise ConfigurationError if running on musl libc (Alpine Linux)."""
    musl_loaders = _glob.glob("/lib/ld-musl-*.so.1")
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


def check_platform() -> None:
    """Run all platform compatibility checks.

    Called once at Guard import time. Individual checks are no-ops on
    compatible platforms so the overhead is negligible (single glob call).
    """
    import os

    if os.environ.get("PRAMANIX_SKIP_MUSL_CHECK") == "1":
        return
    _check_musl()
