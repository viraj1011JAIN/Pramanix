# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Real AWS Secrets Manager integration tests for AwsKmsKeyProvider via LocalStack — T-03.

GA-16 closure: these tests cover transport-layer behaviour that boto3 module stubs
in tests/helpers/real_protocols.py cannot replicate:
  - Real HTTP request/response cycle to LocalStack's secretsmanager API
  - Real ClientError (ResourceNotFoundException) for a missing secret
  - Real secret storage + retrieval lifecycle (create → get → verify)
  - Cache invalidation: second call within TTL should not make a second API call
  - public_key_pem() derives a valid Ed25519 public key from a LocalStack-fetched key

Requires: Docker + LocalStack (testcontainers[localstack]) + boto3
  pip install 'pramanix[aws]' 'testcontainers[localstack]'
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

boto3 = pytest.importorskip("boto3", reason="boto3 not installed")  # type: ignore[assignment]

from pramanix.key_provider import AwsKmsKeyProvider

from .conftest import requires_docker


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_sm_client(endpoint: str) -> Any:
    """Build a real boto3 Secrets Manager client pointed at LocalStack."""
    return boto3.client(
        "secretsmanager",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _generate_test_pem() -> bytes:
    """Generate a fresh Ed25519 private key PEM for testing."""
    from pramanix.crypto import PramanixSigner

    signer = PramanixSigner.generate()
    return signer.private_key_pem()


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_docker
def test_aws_kms_provider_fetches_pem_from_localstack(localstack_endpoint: str) -> None:
    """AwsKmsKeyProvider retrieves a real PEM from LocalStack Secrets Manager."""
    sm = _make_sm_client(localstack_endpoint)
    pem = _generate_test_pem()
    secret_name = "pramanix/test/ed25519-key"

    # Store the PEM in LocalStack
    sm.create_secret(Name=secret_name, SecretString=pem.decode())

    provider = AwsKmsKeyProvider(
        secret_name,
        _client=sm,
    )
    fetched = provider.private_key_pem()
    assert fetched == pem, f"Fetched PEM does not match stored PEM"


@requires_docker
def test_aws_kms_provider_derives_public_key(localstack_endpoint: str) -> None:
    """public_key_pem() derives a valid Ed25519 public key from LocalStack-fetched private key."""
    sm = _make_sm_client(localstack_endpoint)
    pem = _generate_test_pem()
    secret_name = "pramanix/test/ed25519-pubkey"
    sm.create_secret(Name=secret_name, SecretString=pem.decode())

    provider = AwsKmsKeyProvider(secret_name, _client=sm)
    pub = provider.public_key_pem()
    assert b"PUBLIC KEY" in pub, f"Expected PUBLIC KEY in derived PEM, got: {pub[:60]!r}"


@requires_docker
def test_aws_kms_provider_missing_secret_raises_runtime_error(localstack_endpoint: str) -> None:
    """A missing secret ARN must raise RuntimeError (wrapping ClientError), never hang."""
    sm = _make_sm_client(localstack_endpoint)
    provider = AwsKmsKeyProvider(
        "arn:aws:secretsmanager:us-east-1:000000000000:secret:does-not-exist",
        _client=sm,
    )
    # LocalStack returns a real ResourceNotFoundException which AwsKmsKeyProvider
    # wraps in RuntimeError.  This exercises the real HTTP error path.
    with pytest.raises(RuntimeError, match="failed to fetch secret"):
        provider.private_key_pem()


@requires_docker
def test_aws_kms_provider_key_version_from_localstack(localstack_endpoint: str) -> None:
    """key_version() returns a non-empty version string from the LocalStack VersionId."""
    sm = _make_sm_client(localstack_endpoint)
    pem = _generate_test_pem()
    secret_name = "pramanix/test/ed25519-version"
    sm.create_secret(Name=secret_name, SecretString=pem.decode())

    provider = AwsKmsKeyProvider(secret_name, _client=sm)
    version = provider.key_version()
    assert isinstance(version, str) and len(version) > 0, (
        f"Expected non-empty version string, got: {version!r}"
    )


@requires_docker
def test_aws_kms_provider_cache_avoids_second_api_call(localstack_endpoint: str) -> None:
    """Second private_key_pem() call within TTL must not make a second HTTP request."""
    sm = _make_sm_client(localstack_endpoint)
    pem = _generate_test_pem()
    secret_name = "pramanix/test/ed25519-cache"
    sm.create_secret(Name=secret_name, SecretString=pem.decode())

    call_count = 0
    original_get = sm.get_secret_value

    def _counting_get(**kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        return original_get(**kwargs)

    sm.get_secret_value = _counting_get

    provider = AwsKmsKeyProvider(secret_name, _client=sm)
    provider.private_key_pem()  # first call — fetches from LocalStack
    provider.private_key_pem()  # second call — must use cache
    assert call_count == 1, (
        f"Expected exactly 1 API call due to cache, got {call_count}"
    )


@requires_docker
def test_aws_kms_provider_secret_binary_fetches_correctly(localstack_endpoint: str) -> None:
    """AwsKmsKeyProvider handles binary secrets (SecretBinary) from LocalStack."""
    sm = _make_sm_client(localstack_endpoint)
    pem = _generate_test_pem()
    secret_name = "pramanix/test/ed25519-binary"
    sm.create_secret(Name=secret_name, SecretBinary=pem)

    provider = AwsKmsKeyProvider(secret_name, _client=sm)
    fetched = provider.private_key_pem()
    assert fetched == pem, f"Binary secret fetch mismatch"


@requires_docker
def test_aws_kms_provider_thread_safe_concurrent_reads(localstack_endpoint: str) -> None:
    """Concurrent reads from multiple threads must all return the same PEM.

    Verifies that the threading.Lock() in AwsKmsKeyProvider prevents
    concurrent _refresh_cache() races under real IO latency from LocalStack.
    """
    sm = _make_sm_client(localstack_endpoint)
    pem = _generate_test_pem()
    secret_name = "pramanix/test/ed25519-threads"
    sm.create_secret(Name=secret_name, SecretString=pem.decode())

    provider = AwsKmsKeyProvider(secret_name, _client=sm)
    results: list[bytes] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def _fetch() -> None:
        try:
            p = provider.private_key_pem()
            with lock:
                results.append(p)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=_fetch) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"Concurrent reads raised: {errors}"
    assert len(results) == 8, f"Expected 8 results, got {len(results)}"
    assert all(r == pem for r in results), "Concurrent reads returned inconsistent PEM values"
