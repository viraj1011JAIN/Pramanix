# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
import warnings
from collections.abc import Generator

import pytest

# ── Integration-suite warning filters ────────────────────────────────────────
# These warnings originate in upstream SDK internals that we do not control.
# They are scoped to the integration tests directory (not globally) so that
# any Pydantic v1 API usage in our own source code remains visible.


def pytest_configure(config: pytest.Config) -> None:
    # Cohere SDK v5 uses deprecated Pydantic V1 internal APIs — upstream issue.
    # Scoped here so it does not hide Pydantic v1 usage in Pramanix source.
    warnings.filterwarnings(
        "ignore",
        category=DeprecationWarning,
        message=r".*PydanticDeprecatedSince20.*",
    )
    try:
        import pydantic.warnings as _pw

        warnings.filterwarnings("ignore", category=_pw.PydanticDeprecatedSince20)
    except (ImportError, AttributeError):
        pass
    # google-generativeai emits FutureWarning about its own deprecation.
    # GeminiTranslator.__init__ suppresses it locally during import, but the
    # SDK may also emit it during individual generate_content() calls.
    warnings.filterwarnings(
        "ignore",
        message=r"(?s).*google\.generativeai.*",
        category=FutureWarning,
    )
    warnings.filterwarnings(
        "ignore",
        message=r"(?s).*google\.generativeai.*",
        category=DeprecationWarning,
    )

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


# ── GCP Secret Manager (live-gated) ───────────────────────────────────────────
#
# #8 fix: GcpKmsKeyProvider previously had zero real-API test coverage — only
# the duck-typed `_FakeSecretsManagerClient`-style stub in test_kms_provider.py.
# Unlike AWS (LocalStack) there is no widely-available local GCP Secret
# Manager emulator, so this follows the same env-gated live-credential
# pattern already established for Azure above. Skip reason is intentionally
# generic (not enumerating exact required env var names) to avoid the #326
# anti-pattern of leaking expected-credential names into CI artifact XML.

_GCP_LIVE = bool(os.environ.get("GCP_PROJECT_ID")) and bool(
    os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or os.environ.get("GCP_ADC_AVAILABLE")
)

requires_gcp = pytest.mark.skipif(
    not _GCP_LIVE,
    reason="GCP Secret Manager live tests require a configured project and credentials",
)


@pytest.fixture(scope="session")
def gcp_project_id() -> str:
    """Return the GCP project ID from the environment."""
    project_id = os.environ.get("GCP_PROJECT_ID", "")
    if not project_id:
        pytest.skip("GCP_PROJECT_ID not set")
    return project_id


# ── OpenAI (live-gated) ───────────────────────────────────────────────────────

requires_openai = pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason=(
        "OPENAI_API_KEY not set — OpenAI live tests skipped. "
        "These tests MUST pass before any release that touches "
        "translator/redundant.py or translator/openai_compat.py."
    ),
)

# ── Anthropic (live-gated) ────────────────────────────────────────────────────
#
# #9 fix: AnthropicTranslator previously had zero real-protocol test coverage
# anywhere in the suite (Cohere/Gemini/Ollama/LlamaCpp already had real or
# respx-based coverage). See test_anthropic_translator.py.

requires_anthropic = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason=(
        "ANTHROPIC_API_KEY not set — Anthropic live tests skipped. "
        "These tests MUST pass before any release that touches "
        "translator/anthropic.py."
    ),
)

# ── Gemini (live-gated) ───────────────────────────────────────────────────────

requires_gemini = pytest.mark.skipif(
    not os.environ.get("GOOGLE_API_KEY"),
    reason=(
        "GOOGLE_API_KEY not set — Gemini live tests skipped. "
        "These tests MUST pass before any release that touches "
        "translator/gemini.py."
    ),
)

# ── Ollama (local server required) ───────────────────────────────────────────

requires_ollama = pytest.mark.skipif(
    not os.environ.get("OLLAMA_BASE_URL") and not os.environ.get("PRAMANIX_TEST_OLLAMA"),
    reason=(
        "Ollama live tests require a running Ollama server. "
        "Set OLLAMA_BASE_URL (e.g. 'http://localhost:11434') or "
        "PRAMANIX_TEST_OLLAMA=1 to enable. "
        "These tests MUST pass before any release that touches "
        "translator/ollama.py."
    ),
)

# ── LlamaCpp (real GGUF file required) ────────────────────────────────────────

requires_llamacpp = pytest.mark.skipif(
    not os.environ.get("PRAMANIX_TEST_GGUF_PATH"),
    reason=(
        "PRAMANIX_TEST_GGUF_PATH not set — "
        "set to a local .gguf file path to enable llamacpp integration tests. "
        "These tests MUST pass before any release that touches "
        "translator/llamacpp.py."
    ),
)
