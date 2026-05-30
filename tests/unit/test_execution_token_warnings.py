# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for InMemoryExecutionTokenVerifier tiered warning/error logic — Issue #16.

Three tiers (evaluated in priority order):
1. PRAMANIX_ENV=production (any)       → ConfigurationError (hard block, highest priority)
2. Multi-worker env vars present       → RuntimeWarning
3. Neither                             → UserWarning
"""

from __future__ import annotations

import secrets

import pytest

from pramanix.exceptions import ConfigurationError
from pramanix.execution_token import InMemoryExecutionTokenVerifier

_SECRET = secrets.token_bytes(32)


class TestInMemoryWarningTiers:
    """Verify the three-tier warning emitted by InMemoryExecutionTokenVerifier."""

    def test_default_emits_user_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No env vars → UserWarning reminding about single-process limitation."""
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)

        with pytest.warns(UserWarning, match="InMemoryExecutionTokenVerifier"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_production_env_raises_configuration_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PRAMANIX_ENV=production (no multi-worker signals) → ConfigurationError hard block."""
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.setenv("PRAMANIX_ENV", "production")

        with pytest.raises(ConfigurationError, match="not permitted when PRAMANIX_ENV=production"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_web_concurrency_emits_runtime_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """WEB_CONCURRENCY=4 → multi-worker RuntimeWarning."""
        monkeypatch.setenv("WEB_CONCURRENCY", "4")
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)

        with pytest.warns(RuntimeWarning, match="multi-worker"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_uvicorn_workers_emits_runtime_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """UVICORN_WORKERS set → multi-worker RuntimeWarning."""
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.setenv("UVICORN_WORKERS", "2")
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)

        with pytest.warns(RuntimeWarning, match="multi-worker"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_production_env_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PRAMANIX_ENV value is normalised to lowercase — 'PRODUCTION' also blocks."""
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.setenv("PRAMANIX_ENV", "PRODUCTION")

        with pytest.raises(ConfigurationError, match="not permitted when PRAMANIX_ENV=production"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_production_env_takes_priority_over_multi_worker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_ENV=production always raises ConfigurationError, even with multi-worker signals.

        Both conditions indicate "not safe for this deployment", but the production
        environment flag is the authoritative hard gate — it must not be bypassed by
        the presence of multi-worker signals.  Prior to this fix, the elif chain meant
        that WEB_CONCURRENCY=N caused only a RuntimeWarning when PRAMANIX_ENV=production,
        silently allowing initialization that should have been blocked.
        """
        monkeypatch.setenv("WEB_CONCURRENCY", "8")
        monkeypatch.setenv("PRAMANIX_ENV", "production")

        with pytest.raises(ConfigurationError, match="not permitted when PRAMANIX_ENV=production"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_web_concurrency_one_is_not_multi_worker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """WEB_CONCURRENCY=1 is treated as single-worker — falls through to UserWarning."""
        monkeypatch.setenv("WEB_CONCURRENCY", "1")
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.delenv("PRAMANIX_ENV", raising=False)

        with pytest.warns(UserWarning, match="InMemoryExecutionTokenVerifier"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)
