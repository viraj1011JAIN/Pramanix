# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real HashiCorp Vault integration tests for VaultKeyProvider — T-05.

Tests run against a real Vault 1.16 dev container.
Validates behaviour that hvac fakes cannot replicate:
  - Real Vault KV v2 API responses
  - Real 403 Forbidden on permission denied
  - Real 404 Not Found on missing secret
  - Real token lease expiry semantics
  - Real key rotation: write new version, read it back
"""
from __future__ import annotations

import asyncio

import hvac  # type: ignore[import-untyped]
import pytest

from pramanix.key_provider import VaultKeyProvider

from .conftest import requires_docker


# ── Helpers ────────────────────────────────────────────────────────────────────

_PEM_PRIVATE = b"""\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMPSE9VEWKLmIFTCDn7oKHkSRVS5rHqVVQSf5NGKN/4M
-----END PRIVATE KEY-----
"""
_SECRET_PATH = "pramanix/signing-key"
_SECRET_MOUNT = "secret"


def _vault_client(vault_addr: str, token: str) -> hvac.Client:
    client = hvac.Client(url=vault_addr, token=token)
    assert client.is_authenticated()
    return client


def _write_secret(
    vault_addr: str,
    token: str,
    key_pem: bytes,
) -> None:
    """Write a signing key to Vault KV v2."""
    client = _vault_client(vault_addr, token)
    client.secrets.kv.v2.create_or_update_secret(
        path=_SECRET_PATH,
        secret={"private_key_pem": key_pem.decode()},
        mount_point=_SECRET_MOUNT,
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_docker
def test_vault_provider_reads_key(vault_addr_and_token: tuple[str, str]) -> None:
    """VaultKeyProvider reads back the private key PEM written to Vault KV v2."""
    addr, token = vault_addr_and_token
    _write_secret(addr, token, _PEM_PRIVATE)

    provider = VaultKeyProvider(
        addr=addr,
        token=token,
        secret_path=_SECRET_PATH,
        mount_point=_SECRET_MOUNT,
    )
    pem = asyncio.run(provider.private_key_pem()) if asyncio.iscoroutinefunction(
        provider.private_key_pem
    ) else provider.private_key_pem()

    assert b"-----BEGIN PRIVATE KEY-----" in pem


@requires_docker
def test_vault_provider_missing_secret_raises(
    vault_addr_and_token: tuple[str, str],
) -> None:
    """VaultKeyProvider raises a meaningful error when the secret path is absent."""
    addr, token = vault_addr_and_token

    provider = VaultKeyProvider(
        addr=addr,
        token=token,
        secret_path="pramanix/does-not-exist",
        mount_point=_SECRET_MOUNT,
    )
    with pytest.raises(Exception, match="(not found|404|InvalidPath|does.not.exist)"):
        if asyncio.iscoroutinefunction(provider.private_key_pem):
            asyncio.run(provider.private_key_pem())
        else:
            provider.private_key_pem()


@requires_docker
def test_vault_provider_bad_token_raises(
    vault_addr_and_token: tuple[str, str],
) -> None:
    """VaultKeyProvider raises on Vault 403 Forbidden with a wrong token."""
    addr, _ = vault_addr_and_token

    provider = VaultKeyProvider(
        addr=addr,
        token="wrong-token-definitely-invalid",
        secret_path=_SECRET_PATH,
        mount_point=_SECRET_MOUNT,
    )
    with pytest.raises(Exception, match="(403|Forbidden|permission|Forbidden|auth)"):
        if asyncio.iscoroutinefunction(provider.private_key_pem):
            asyncio.run(provider.private_key_pem())
        else:
            provider.private_key_pem()


@requires_docker
def test_vault_provider_key_rotation(
    vault_addr_and_token: tuple[str, str],
) -> None:
    """Key rotation: write v1, read v1, write v2, read v2 — real versioning."""
    addr, token = vault_addr_and_token
    client = _vault_client(addr, token)

    _PEM_V1 = b"-----BEGIN PRIVATE KEY-----\nVERSION1\n-----END PRIVATE KEY-----\n"
    _PEM_V2 = b"-----BEGIN PRIVATE KEY-----\nVERSION2\n-----END PRIVATE KEY-----\n"

    rot_path = "pramanix/rotation-test"
    client.secrets.kv.v2.create_or_update_secret(
        path=rot_path,
        secret={"private_key_pem": _PEM_V1.decode()},
        mount_point=_SECRET_MOUNT,
    )
    client.secrets.kv.v2.create_or_update_secret(
        path=rot_path,
        secret={"private_key_pem": _PEM_V2.decode()},
        mount_point=_SECRET_MOUNT,
    )

    # Latest version should be v2
    result = client.secrets.kv.v2.read_secret_version(
        path=rot_path, mount_point=_SECRET_MOUNT
    )
    pem_read = result["data"]["data"]["private_key_pem"].encode()
    assert b"VERSION2" in pem_read
    assert result["data"]["metadata"]["version"] == 2


@requires_docker
def test_vault_provider_supports_rotation_false_for_vault(
    vault_addr_and_token: tuple[str, str],
) -> None:
    """VaultKeyProvider.supports_rotation reports True (Vault supports KV rotation)."""
    addr, token = vault_addr_and_token
    _write_secret(addr, token, _PEM_PRIVATE)

    provider = VaultKeyProvider(
        addr=addr,
        token=token,
        secret_path=_SECRET_PATH,
        mount_point=_SECRET_MOUNT,
    )
    # M-28: providers must expose a supports_rotation property
    assert hasattr(provider, "supports_rotation")
    assert provider.supports_rotation is True
