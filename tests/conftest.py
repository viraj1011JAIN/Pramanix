# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""
Shared test fixtures for the Pramanix test suite.

This file is loaded automatically by pytest. Fixtures defined here are
available to all tests across unit/, integration/, property/, adversarial/,
and perf/ directories.

External-service credentials are loaded from .env.test (gitignored) if present.
Copy .env.test.example → .env.test and fill in real credentials for integration
tests.  Missing credentials cause those tests to be skipped automatically.
"""

from __future__ import annotations

import pathlib

import pytest

# Load .env.test from the repository root, if present.  This is the source of
# all external-service credentials (API keys, connection strings) for tests.
# Never hardcode credentials in test files — put them in .env.test instead.
_env_test = pathlib.Path(__file__).parent.parent / ".env.test"
if _env_test.exists():
    try:
        from dotenv import load_dotenv

        load_dotenv(_env_test, override=False)
    except ImportError:
        pass  # python-dotenv not installed; credentials must be set in env directly


@pytest.fixture
def solver_timeout_ms() -> int:
    """Default solver timeout for tests — generous to avoid CI flakiness."""
    return 500
