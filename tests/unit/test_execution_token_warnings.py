# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for InMemoryExecutionTokenVerifier tiered warning logic — Issue #16.

Three tiers:
1. Multi-worker env vars present  → RuntimeWarning
2. PRAMANIX_ENV=production (no multi-worker vars) → RuntimeWarning
3. Neither                         → UserWarning
"""

from __future__ import annotations

import secrets

import pytest

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

    def test_production_env_emits_runtime_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PRAMANIX_ENV=production (no multi-worker signals) → RuntimeWarning."""
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.setenv("PRAMANIX_ENV", "production")

        with pytest.warns(RuntimeWarning, match="production"):
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
        """PRAMANIX_ENV value is normalised to lowercase before comparison."""
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
        monkeypatch.delenv("UVICORN_WORKERS", raising=False)
        monkeypatch.delenv("HYPERCORN_WORKERS", raising=False)
        monkeypatch.setenv("PRAMANIX_ENV", "PRODUCTION")

        with pytest.warns(RuntimeWarning, match="production"):
            InMemoryExecutionTokenVerifier(secret_key=_SECRET)

    def test_multi_worker_takes_priority_over_production_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Multi-worker signals fire tier-1 RuntimeWarning regardless of PRAMANIX_ENV."""
        monkeypatch.setenv("WEB_CONCURRENCY", "8")
        monkeypatch.setenv("PRAMANIX_ENV", "production")

        with pytest.warns(RuntimeWarning, match="multi-worker"):
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
