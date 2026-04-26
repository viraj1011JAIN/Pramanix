# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration test fixtures — real Docker containers, no fakes.

All heavy containers (Kafka, Postgres, Redis, Vault, LocalStack) are
session-scoped: started once before any integration test and torn down after
the last.  This makes the full suite fast (< 60 s cold-start overhead) while
still exercising real broker/database behaviour.

Requires:
  - Docker Desktop running (Windows/macOS) or Docker daemon (Linux)
  - pip install -r requirements/integration.txt

Every fixture is annotated with ``@pytest.fixture(scope="session")`` so that
testcontainers only pull images and boot containers once per ``pytest`` run.

Environment overrides (skip the container, use an external service):
  KAFKA_BOOTSTRAP_SERVERS   e.g. "localhost:9092"
  POSTGRES_DSN              e.g. "postgresql://user:pass@localhost:5432/db"
  REDIS_URL                 e.g. "redis://localhost:6379"
  VAULT_ADDR                e.g. "http://localhost:8200"
  VAULT_TOKEN               e.g. "root"
  AWS_ENDPOINT_URL          e.g. "http://localhost:4566"  (LocalStack)
"""
from __future__ import annotations

import os
import time
from typing import Generator

import pytest

# ── Docker availability guard ─────────────────────────────────────────────────
_DOCKER_AVAILABLE: bool = True
try:
    import docker  # type: ignore[import-untyped]
    _client = docker.from_env()
    _client.ping()
except Exception:
    _DOCKER_AVAILABLE = False

requires_docker = pytest.mark.skipif(
    not _DOCKER_AVAILABLE,
    reason="Docker is not available — integration containers cannot start",
)

# ── Kafka ─────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def kafka_bootstrap_servers() -> Generator[str, None, None]:
    """Yield a real Kafka bootstrap server address.

    Uses an external broker if ``KAFKA_BOOTSTRAP_SERVERS`` is set; otherwise
    starts a Redpanda container (fully Kafka-compatible, faster than Kafka).
    """
    external = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
    if external:
        yield external
        return

    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker not available")

    from testcontainers.kafka import KafkaContainer  # type: ignore[import-untyped]

    with KafkaContainer("confluentinc/cp-kafka:7.6.1") as kafka:
        yield kafka.get_bootstrap_server()


# ── Postgres ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def postgres_dsn() -> Generator[str, None, None]:
    """Yield a real asyncpg-compatible DSN to a Postgres 16 container."""
    external = os.environ.get("POSTGRES_DSN")
    if external:
        yield external
        return

    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker not available")

    from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

    with PostgresContainer("postgres:16-alpine") as pg:
        # Convert sqlalchemy DSN (postgresql+psycopg2://) → asyncpg DSN
        raw = pg.get_connection_url()
        dsn = raw.replace("postgresql+psycopg2://", "postgresql://").replace(
            "postgresql://", "postgresql://"
        )
        yield dsn


# ── Redis ─────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def redis_url() -> Generator[str, None, None]:
    """Yield a real Redis 7 URL."""
    external = os.environ.get("REDIS_URL")
    if external:
        yield external
        return

    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker not available")

    from testcontainers.redis import RedisContainer  # type: ignore[import-untyped]

    with RedisContainer("redis:7-alpine") as redis:
        host = redis.get_container_host_ip()
        port = redis.get_exposed_port(6379)
        yield f"redis://{host}:{port}"


# ── HashiCorp Vault ───────────────────────────────────────────────────────────

_VAULT_ROOT_TOKEN = "pramanix-test-root-token"
_VAULT_IMAGE = "hashicorp/vault:1.16"


@pytest.fixture(scope="session")
def vault_addr_and_token() -> Generator[tuple[str, str], None, None]:
    """Yield (vault_addr, root_token) for a real Vault dev container.

    The container runs in ``-dev`` mode with a known root token so tests can
    write and read secrets without a full unseal ceremony.
    """
    external_addr = os.environ.get("VAULT_ADDR")
    external_token = os.environ.get("VAULT_TOKEN")
    if external_addr and external_token:
        yield external_addr, external_token
        return

    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker not available")

    from testcontainers.core.container import DockerContainer  # type: ignore[import-untyped]
    from testcontainers.core.waiting_utils import wait_for_logs  # type: ignore[import-untyped]

    with (
        DockerContainer(_VAULT_IMAGE)
        .with_env("VAULT_DEV_ROOT_TOKEN_ID", _VAULT_ROOT_TOKEN)
        .with_env("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .with_exposed_ports(8200)
        .with_command("server -dev")
    ) as vault:
        wait_for_logs(vault, "Vault server started!", timeout=30)
        host = vault.get_container_host_ip()
        port = vault.get_exposed_port(8200)
        addr = f"http://{host}:{port}"
        # Brief pause — Vault API needs a moment after the log line
        time.sleep(1)
        yield addr, _VAULT_ROOT_TOKEN


# ── LocalStack (S3) ───────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def localstack_endpoint() -> Generator[str, None, None]:
    """Yield a real LocalStack S3 endpoint URL."""
    external = os.environ.get("AWS_ENDPOINT_URL")
    if external:
        yield external
        return

    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker not available")

    from testcontainers.localstack import LocalStackContainer  # type: ignore[import-untyped]

    with LocalStackContainer("localstack/localstack:3.4") as ls:
        yield ls.get_url()


# ── Azure KeyVault (live-gated) ────────────────────────────────────────────────

_AZURE_LIVE = all(
    os.environ.get(k)
    for k in (
        "AZURE_KEYVAULT_URL",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
    )
)

requires_azure = pytest.mark.skipif(
    not _AZURE_LIVE,
    reason=(
        "Azure live tests require AZURE_KEYVAULT_URL, AZURE_TENANT_ID, "
        "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET to be set"
    ),
)


@pytest.fixture(scope="session")
def azure_keyvault_url() -> str:
    """Return the Azure KeyVault URL from the environment."""
    url = os.environ.get("AZURE_KEYVAULT_URL", "")
    if not url:
        pytest.skip("AZURE_KEYVAULT_URL not set")
    return url


# ── Gemini (live-gated) ───────────────────────────────────────────────────────

requires_gemini = pytest.mark.skipif(
    not os.environ.get("GOOGLE_API_KEY"),
    reason="GOOGLE_API_KEY not set — Gemini live tests skipped",
)

# ── LlamaCpp (real GGUF file required) ────────────────────────────────────────

requires_llamacpp = pytest.mark.skipif(
    not os.environ.get("PRAMANIX_TEST_GGUF_PATH"),
    reason=(
        "PRAMANIX_TEST_GGUF_PATH not set — "
        "set to a local .gguf file path to enable llamacpp integration tests"
    ),
)
