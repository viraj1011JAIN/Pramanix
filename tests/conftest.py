# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Shared test fixtures for the Pramanix test suite.

This file is loaded automatically by pytest. Fixtures defined here are
available to all tests across unit/, integration/, property/, adversarial/,
and perf/ directories.

Fixtures will be populated as modules are implemented:
  - Phase 2: sample policies, intents, states, guard instances
  - Phase 3: async guards, worker pool fixtures
  - Phase 4: resolver registry fixtures
  - Phase 5: translator and injection attempt fixtures
"""

from __future__ import annotations

import pytest


@pytest.fixture
def solver_timeout_ms() -> int:
    """Default solver timeout for tests — generous to avoid CI flakiness."""
    return 500
