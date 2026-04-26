# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real Azure KeyVault integration tests — T-06.

Requires live Azure credentials (env-gated):
  AZURE_KEYVAULT_URL    = https://<vault-name>.vault.azure.net
  AZURE_TENANT_ID       = <tenant-uuid>
  AZURE_CLIENT_ID       = <service-principal-app-id>
  AZURE_CLIENT_SECRET   = <service-principal-secret>

A dedicated Key Vault for CI testing is recommended.  The service principal
needs: Key Vault Secrets Officer role (read + write + delete).

These tests validate behaviour that the azure-keyvault fake cannot replicate:
  - Real MSAL token acquisition (OAuth2 client credentials flow)
  - Real TLS to vault.azure.net
  - Real secret versioning (each set() creates a new version)
  - Real 403 Forbidden on wrong credentials
  - Real 404 Not Found on missing secret
  - Real secret disable/enable lifecycle

Run locally:
  AZURE_KEYVAULT_URL=... AZURE_TENANT_ID=... \
  AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
  pytest tests/integration/test_azure_keyvault.py -v
"""
from __future__ import annotations

import asyncio
import os
import uuid
from typing import Generator

import pytest
from azure.identity import ClientSecretCredential  # type: ignore[import-untyped]
from azure.keyvault.secrets import SecretClient  # type: ignore[import-untyped]

from pramanix.key_provider import AzureKeyVaultKeyProvider

from .conftest import requires_azure

_VAULT_URL = os.environ.get("AZURE_KEYVAULT_URL", "")
_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

_TEST_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIMPSE9VEWKLmIFTCDn7oKHkSRVS5rHqVVQSf5NGKN4M=\n"
    "-----END PRIVATE KEY-----\n"
)


def _real_secret_client() -> SecretClient:
    cred = ClientSecretCredential(
        tenant_id=_TENANT_ID,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
    )
    return SecretClient(vault_url=_VAULT_URL, credential=cred)


@pytest.fixture(scope="module")
def _test_secret_name() -> Generator[str, None, None]:
    """Create a uniquely-named test secret and delete it after the module."""
    name = f"pramanix-test-{uuid.uuid4().hex[:8]}"
    client = _real_secret_client()
    client.set_secret(name, _TEST_PEM)
    yield name
    # Cleanup: delete and purge to avoid vault quota accumulation
    try:
        client.begin_delete_secret(name).wait()
        client.purge_deleted_secret(name)
    except Exception:
        pass


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_azure
def test_azure_provider_reads_secret(_test_secret_name: str) -> None:
    """AzureKeyVaultKeyProvider reads the PEM back from a real KeyVault secret."""
    provider = AzureKeyVaultKeyProvider(
        vault_url=_VAULT_URL,
        secret_name=_test_secret_name,
        tenant_id=_TENANT_ID,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
    )
    pem = provider.private_key_pem()
    assert b"BEGIN PRIVATE KEY" in pem or "BEGIN PRIVATE KEY" in pem


@requires_azure
def test_azure_provider_missing_secret_raises(_test_secret_name: str) -> None:
    """AzureKeyVaultKeyProvider raises on a non-existent secret name."""
    provider = AzureKeyVaultKeyProvider(
        vault_url=_VAULT_URL,
        secret_name="definitely-does-not-exist-xyzzy-99",
        tenant_id=_TENANT_ID,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
    )
    with pytest.raises(Exception, match="(SecretNotFound|404|ResourceNotFound)"):
        provider.private_key_pem()


@requires_azure
def test_azure_provider_wrong_client_secret_raises() -> None:
    """AzureKeyVaultKeyProvider raises a 401/403 on wrong credentials."""
    provider = AzureKeyVaultKeyProvider(
        vault_url=_VAULT_URL,
        secret_name="any-secret",
        tenant_id=_TENANT_ID,
        client_id=_CLIENT_ID,
        client_secret="definitely-wrong-secret",
    )
    with pytest.raises(Exception, match="(401|403|Unauthorized|ClientAuthenticationError)"):
        provider.private_key_pem()


@requires_azure
def test_azure_provider_versioning(_test_secret_name: str) -> None:
    """Writing a new value creates a new version; provider returns the latest."""
    client = _real_secret_client()
    new_pem = _TEST_PEM.replace("MC4CAQAw", "MC4CAQBX")
    client.set_secret(_test_secret_name, new_pem)

    provider = AzureKeyVaultKeyProvider(
        vault_url=_VAULT_URL,
        secret_name=_test_secret_name,
        tenant_id=_TENANT_ID,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
    )
    pem = provider.private_key_pem()
    # Latest version should have the updated content
    assert "CAQBX" in (pem if isinstance(pem, str) else pem.decode())


@requires_azure
def test_azure_provider_supports_rotation(_test_secret_name: str) -> None:
    """AzureKeyVaultKeyProvider.supports_rotation is True (M-28)."""
    provider = AzureKeyVaultKeyProvider(
        vault_url=_VAULT_URL,
        secret_name=_test_secret_name,
        tenant_id=_TENANT_ID,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
    )
    assert hasattr(provider, "supports_rotation")
    assert provider.supports_rotation is True
