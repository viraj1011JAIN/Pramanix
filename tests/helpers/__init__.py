# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real protocol implementations for testing.

Every class here is a real implementation — no MagicMock, no AsyncMock,
no unittest.mock anywhere.  These are the approved patterns for Pramanix
test helpers per the enforcement gap principle:

  "A test that passes because a mock swallowed an error provides no safety
   guarantee.  Every ALLOW must prove Z3 satisfiability; every test helper
   must implement the real protocol."
"""
