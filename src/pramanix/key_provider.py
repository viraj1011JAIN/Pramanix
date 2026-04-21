# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""KeyProvider — pluggable Ed25519 key sourcing for PramanixSigner.

Phase E-3: abstracts key management from PramanixSigner so institutional
deployments can source keys from HSMs, cloud KMS services, or secret vaults
without changing application code.

Built-in providers
------------------
- :class:`PemKeyProvider`  — inline PEM bytes/str (original behaviour)
- :class:`EnvKeyProvider`  — reads PEM from an environment variable
- :class:`FileKeyProvider` — reads PEM from a file path on disk

Cloud KMS stubs (raise ImportError if SDK not installed)
---------------------------------------------------------
- :class:`AwsKmsKeyProvider`         — requires ``boto3``
- :class:`AzureKeyVaultKeyProvider`  — requires ``azure-keyvault-keys``
- :class:`GcpKmsKeyProvider`         — requires ``google-cloud-kms``
- :class:`HashiCorpVaultKeyProvider` — requires ``hvac``

Usage::

    from pramanix.key_provider import FileKeyProvider
    from pramanix.crypto import PramanixSigner

    provider = FileKeyProvider("/run/secrets/pramanix-ed25519.pem")
    signer = PramanixSigner.from_provider(provider)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "AwsKmsKeyProvider",
    "AzureKeyVaultKeyProvider",
    "EnvKeyProvider",
    "FileKeyProvider",
    "GcpKmsKeyProvider",
    "HashiCorpVaultKeyProvider",
    "KeyProvider",
    "PemKeyProvider",
]


@runtime_checkable
class KeyProvider(Protocol):
    """Protocol for Ed25519 key providers.

    Implementors must supply ``private_key_pem()`` and ``public_key_pem()``
    returning PEM-encoded bytes.  Key rotation is optional — providers that
    do not support it should raise :exc:`NotImplementedError`.
    """

    def private_key_pem(self) -> bytes:
        """Return the PEM-encoded Ed25519 private key."""
        ...

    def public_key_pem(self) -> bytes:
        """Return the PEM-encoded Ed25519 public key."""
        ...

    def key_version(self) -> str:
        """Return an opaque string identifying the current key version.

        Embedded in Decision metadata so historical signatures remain
        verifiable after key rotation.
        """
        ...

    def rotate_key(self) -> None:
        """Rotate to a new key.

        Raises:
            NotImplementedError: If the provider does not support rotation.
        """
        ...


# ── Built-in providers ────────────────────────────────────────────────────────


class PemKeyProvider:
    """Provide a key from inline PEM bytes or string.

    This wraps the existing ``PramanixSigner(private_key_pem=...)`` usage,
    giving it a ``KeyProvider`` interface for uniform treatment.

    Args:
        private_pem: PEM-encoded Ed25519 private key (bytes or str).
        version:     Opaque key version label (default ``"inline-1"``).
    """

    def __init__(
        self,
        private_pem: bytes | str,
        *,
        version: str = "inline-1",
    ) -> None:
        raw = private_pem.encode() if isinstance(private_pem, str) else private_pem
        self._private_pem = raw
        self._version = version
        self._public_pem: bytes | None = None

    def private_key_pem(self) -> bytes:
        return self._private_pem

    def public_key_pem(self) -> bytes:
        if self._public_pem is None:
            self._public_pem = _derive_public_pem(self._private_pem)
        return self._public_pem

    def key_version(self) -> str:
        return self._version

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "PemKeyProvider does not support rotation — supply a new PEM to rotate."
        )


class EnvKeyProvider:
    """Provide a key from an environment variable containing PEM.

    Args:
        env_var: Name of the environment variable (default
                 ``PRAMANIX_SIGNING_KEY_PEM``).
        version: Opaque key version label (default ``"env-1"``).

    Raises:
        RuntimeError: If the environment variable is not set.
    """

    _DEFAULT_ENV = "PRAMANIX_SIGNING_KEY_PEM"

    def __init__(
        self,
        env_var: str = _DEFAULT_ENV,
        *,
        version: str = "env-1",
    ) -> None:
        self._env_var = env_var
        self._version = version

    def private_key_pem(self) -> bytes:
        pem = os.environ.get(self._env_var, "")
        if not pem:
            raise RuntimeError(
                f"EnvKeyProvider: environment variable {self._env_var!r} is not set. "
                "Set it to a PEM-encoded Ed25519 private key."
            )
        return pem.encode()

    def public_key_pem(self) -> bytes:
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        return self._version

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "EnvKeyProvider does not support rotation — update the environment variable to rotate."
        )


class FileKeyProvider:
    """Provide a key from a PEM file on disk.

    Args:
        path:    Path to the PEM file.
        version: Opaque key version label.  If ``None`` (default), uses the
                 file modification time as the version string.

    Raises:
        FileNotFoundError: If the key file does not exist at the time
                           :meth:`private_key_pem` is called.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        version: str | None = None,
    ) -> None:
        self._path = Path(path)
        self._explicit_version = version

    def private_key_pem(self) -> bytes:
        if not self._path.exists():
            raise FileNotFoundError(
                f"FileKeyProvider: key file not found: {self._path}"
            )
        return self._path.read_bytes()

    def public_key_pem(self) -> bytes:
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        if self._explicit_version is not None:
            return self._explicit_version
        try:
            mtime = self._path.stat().st_mtime
            return f"file-mtime-{mtime:.0f}"
        except OSError:
            return "file-unknown"

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "FileKeyProvider does not support in-place rotation — "
            "replace the file contents and create a new FileKeyProvider."
        )


# ── Cloud KMS stubs ──────────────────────────────────────────────────────────


def _cloud_stub(provider_name: str, package: str) -> type:
    """Factory for cloud KMS stub classes that raise ImportError."""

    class _Stub:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                f"{provider_name} requires the '{package}' package. "
                f"Install it: pip install '{package}'"
            )

        def private_key_pem(self) -> bytes:  # pragma: no cover
            raise NotImplementedError

        def public_key_pem(self) -> bytes:  # pragma: no cover
            raise NotImplementedError

        def key_version(self) -> str:  # pragma: no cover
            raise NotImplementedError

        def rotate_key(self) -> None:  # pragma: no cover
            raise NotImplementedError

    _Stub.__name__ = provider_name
    _Stub.__qualname__ = provider_name
    return _Stub


AwsKmsKeyProvider: type = _cloud_stub("AwsKmsKeyProvider", "boto3")
AzureKeyVaultKeyProvider: type = _cloud_stub("AzureKeyVaultKeyProvider", "azure-keyvault-keys")
GcpKmsKeyProvider: type = _cloud_stub("GcpKmsKeyProvider", "google-cloud-kms")
HashiCorpVaultKeyProvider: type = _cloud_stub("HashiCorpVaultKeyProvider", "hvac")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _derive_public_pem(private_pem: bytes) -> bytes:
    """Derive the public key PEM from a private key PEM."""
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_private_key,
        )
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "The 'cryptography' package is required. "
            "Install it: pip install 'pramanix[crypto]'"
        ) from exc

    key = load_pem_private_key(private_pem, password=None)
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
