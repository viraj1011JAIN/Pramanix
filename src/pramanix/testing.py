# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""pramanix.testing — helpers safe to use in test environments only.

These symbols are explicitly NOT part of the stable public API:
they exist to make it easy to write tests against Pramanix without
standing up Redis, Postgres, or SQLite, but they must never be used
in production deployments.

Usage::

    from pramanix.testing import InMemoryExecutionTokenVerifier

    verifier = InMemoryExecutionTokenVerifier(secret_key=b"..." * 32)

Do NOT import from ``pramanix`` directly — ``InMemoryExecutionTokenVerifier``
was removed from the top-level namespace in v1.0.0.  See MIGRATION.md.
"""

from __future__ import annotations

from pramanix.execution_token import InMemoryExecutionTokenVerifier

__all__ = ["InMemoryExecutionTokenVerifier"]
