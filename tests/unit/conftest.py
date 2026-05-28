# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit-test conftest — provides a real Redis 7-alpine testcontainer.

The ``redis_url`` fixture starts a real Redis 7-alpine instance in Docker for
the duration of the test session and tears it down afterwards.
Tests that declare ``redis_url`` as a fixture parameter are automatically
skipped when Docker is unavailable.
"""

from __future__ import annotations

import warnings
from collections.abc import Generator

import pytest


def pytest_configure(config: pytest.Config) -> None:
    # Cohere SDK v5 uses deprecated Pydantic V1 internal APIs — upstream issue.
    # Scoped to the unit test directory so it does not hide Pydantic v1 usage
    # in Pramanix source code globally.
    try:
        import pydantic.warnings as _pw

        warnings.filterwarnings("ignore", category=_pw.PydanticDeprecatedSince20)
    except (ImportError, AttributeError):
        pass

try:
    import docker as _docker

    _c = _docker.from_env()
    _c.ping()
    _DOCKER_AVAILABLE = True
except Exception:
    _DOCKER_AVAILABLE = False

#: Attach this mark to any test that needs a live Docker daemon.
requires_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker daemon not available")


@pytest.fixture(scope="session")
def redis_url() -> Generator[str, None, None]:
    """Real Redis 7-alpine URL backed by a testcontainer.

    The container is started once per test session and torn down afterwards.
    Tests that use this fixture are automatically skipped when Docker is
    unavailable (``_DOCKER_AVAILABLE == False``).
    """
    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker daemon not available")

    pytest.importorskip("testcontainers")
    from testcontainers.redis import RedisContainer

    with RedisContainer("redis:7-alpine") as redis:
        yield redis.get_connection_url()
