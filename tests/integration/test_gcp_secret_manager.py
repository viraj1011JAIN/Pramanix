# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Real GCP Secret Manager integration tests for GcpKmsKeyProvider — #8 closure.

#8 fix: GcpKmsKeyProvider previously had zero real-API test coverage anywhere
in the suite — only the duck-typed `_FakeSecretManagerServiceClient`-style stub
in tests/unit/test_kms_provider.py / tests/unit/test_misc_coverage_gaps.py.
None of those fakes implement the real google-cloud-secret-manager error model,
real gRPC transport, or real secret-version lifecycle, so GcpKmsKeyProvider was
the one cloud provider audited in FLAW_AUDIT.md #8 with no real-protocol cover
at all (AWS already had LocalStack coverage; Azure already had a live-gated
suite — see test_aws_kms_provider.py, test_azure_keyvault.py).

There is no widely-available local Secret Manager emulator (unlike LocalStack
for AWS), so this follows the same env-gated live-credential pattern already
established for Azure: skipped automatically unless a real GCP project and
Application Default Credentials are configured.

These tests validate behaviour the fake cannot replicate:
  - Real gRPC request/response cycle to secretmanager.googleapis.com
  - Real secret + secret-version create -> access -> verify lifecycle
  - Real NotFound error for a missing secret version
  - Cache invalidation: second call within TTL must not re-fetch
  - public_key_pem() derives a valid Ed25519 public key from a live-fetched key
  - rotate_key() picks up a newly-added "latest" version

Requires: google-cloud-secret-manager + a real GCP project
  pip install 'pramanix[gcp]'

Run locally:
  GCP_PROJECT_ID=my-test-project \
  GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json \
  pytest tests/integration/test_gcp_secret_manager.py -v

The service account needs: Secret Manager Admin (or Secret Manager Secret
Version Adder + Accessor + Secret Manager Viewer) on the test project. A
dedicated project/secret namespace is recommended -- these tests create and
delete real secrets prefixed "pramanix-test-".
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Any

import pytest

secretmanager = pytest.importorskip(
    "google.cloud.secretmanager",
    reason="google-cloud-secret-manager not installed; run: pip install 'pramanix[gcp]'",
)

from pramanix.exceptions import ConfigurationError
from pramanix.key_provider import GcpKmsKeyProvider

from .conftest import gcp_project_id, requires_gcp  # noqa: F401  (gcp_project_id is a fixture)

# ── Helpers ────────────────────────────────────────────────────────────────────


def _real_client() -> Any:
    """Build a real SecretManagerServiceClient using Application Default Credentials."""
    return secretmanager.SecretManagerServiceClient()


def _generate_test_pem() -> bytes:
    """Generate a fresh Ed25519 private key PEM for testing."""
    from pramanix.crypto import PramanixSigner

    signer = PramanixSigner.generate()
    return signer.private_key_pem()


@pytest.fixture
def gcp_secret(gcp_project_id: str) -> Generator[tuple[Any, str], None, None]:
    """Create a real, uniquely-named secret; yield (client, secret_id); delete on teardown."""
    client = _real_client()
    secret_id = f"pramanix-test-{uuid.uuid4().hex[:12]}"
    parent = f"projects/{gcp_project_id}"

    client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
    )
    try:
        yield client, secret_id
    finally:
        secret_name = f"{parent}/secrets/{secret_id}"
        try:
            client.delete_secret(request={"name": secret_name})
        except Exception:
            # Best-effort cleanup — do not fail the test run on teardown errors.
            pass


def _add_version(client: Any, project_id: str, secret_id: str, payload: bytes) -> None:
    client.add_secret_version(
        request={
            "parent": f"projects/{project_id}/secrets/{secret_id}",
            "payload": {"data": payload},
        }
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_gcp
def test_gcp_kms_provider_fetches_pem_from_secret_manager(
    gcp_project_id: str,
    gcp_secret: tuple[Any, str],
) -> None:
    """GcpKmsKeyProvider retrieves a real PEM from a real Secret Manager secret version."""
    client, secret_id = gcp_secret
    pem = _generate_test_pem()
    _add_version(client, gcp_project_id, secret_id, pem)

    provider = GcpKmsKeyProvider(gcp_project_id, secret_id, _client=client)
    fetched = provider.private_key_pem()
    assert fetched == pem, "Fetched PEM does not match stored PEM"


@requires_gcp
def test_gcp_kms_provider_derives_public_key(
    gcp_project_id: str,
    gcp_secret: tuple[Any, str],
) -> None:
    """public_key_pem() derives a valid Ed25519 public key from a live-fetched private key."""
    client, secret_id = gcp_secret
    pem = _generate_test_pem()
    _add_version(client, gcp_project_id, secret_id, pem)

    provider = GcpKmsKeyProvider(gcp_project_id, secret_id, _client=client)
    pub = provider.public_key_pem()
    assert b"PUBLIC KEY" in pub, f"Expected PUBLIC KEY in derived PEM, got: {pub[:60]!r}"


@requires_gcp
def test_gcp_kms_provider_missing_secret_raises_configuration_error(
    gcp_project_id: str,
) -> None:
    """A missing secret must raise ConfigurationError (wrapping the real NotFound error)."""
    client = _real_client()
    provider = GcpKmsKeyProvider(
        gcp_project_id,
        f"pramanix-test-does-not-exist-{uuid.uuid4().hex[:8]}",
        _client=client,
    )
    # Secret Manager returns a real google.api_core.exceptions.NotFound,
    # which GcpKmsKeyProvider wraps in ConfigurationError (#22 fix).
    with pytest.raises(ConfigurationError, match="failed to fetch secret"):
        provider.private_key_pem()


@requires_gcp
def test_gcp_kms_provider_cache_avoids_second_api_call(
    gcp_project_id: str,
    gcp_secret: tuple[Any, str],
) -> None:
    """Second private_key_pem() call within TTL must not make a second gRPC call."""
    client, secret_id = gcp_secret
    pem = _generate_test_pem()
    _add_version(client, gcp_project_id, secret_id, pem)

    call_count = 0
    original_access = client.access_secret_version

    def _counting_access(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        return original_access(*args, **kwargs)

    client.access_secret_version = _counting_access

    provider = GcpKmsKeyProvider(gcp_project_id, secret_id, _client=client)
    provider.private_key_pem()  # first call — fetches from Secret Manager
    provider.private_key_pem()  # second call — must use cache
    assert call_count == 1, f"Expected exactly 1 API call due to cache, got {call_count}"


@requires_gcp
def test_gcp_kms_provider_rotate_key_picks_up_new_version(
    gcp_project_id: str,
    gcp_secret: tuple[Any, str],
) -> None:
    """rotate_key() must fetch the newest 'latest' secret version after rotation."""
    client, secret_id = gcp_secret
    old_pem = _generate_test_pem()
    _add_version(client, gcp_project_id, secret_id, old_pem)

    provider = GcpKmsKeyProvider(gcp_project_id, secret_id, version_id="1", _client=client)
    assert provider.private_key_pem() == old_pem

    new_pem = _generate_test_pem()
    _add_version(client, gcp_project_id, secret_id, new_pem)

    provider.rotate_key()
    assert provider.private_key_pem() == new_pem, "rotate_key() did not pick up the new version"
    assert provider.key_version() == "latest"
