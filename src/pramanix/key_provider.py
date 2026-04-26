# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""KeyProvider — pluggable Ed25519 key sourcing for PramanixSigner.

Phase E-3: abstracts key management from PramanixSigner so institutional
deployments can source keys from HSMs, cloud secret stores, or secret vaults
without changing application code.

Built-in providers (no extra deps)
-----------------------------------
- :class:`PemKeyProvider`  — inline PEM bytes/str (original behaviour)
- :class:`EnvKeyProvider`  — reads PEM from an environment variable
- :class:`FileKeyProvider` — reads PEM from a file path on disk

Cloud secret-store providers (require optional extras)
------------------------------------------------------
- :class:`AwsKmsKeyProvider`         — AWS Secrets Manager; requires ``pip install 'pramanix[aws]'``
- :class:`AzureKeyVaultKeyProvider`  — Azure Key Vault Secrets; requires ``pip install 'pramanix[azure]'``
- :class:`GcpKmsKeyProvider`         — GCP Secret Manager; requires ``pip install 'pramanix[gcp]'``
- :class:`HashiCorpVaultKeyProvider` — HashiCorp Vault KV v2; requires ``pip install 'pramanix[vault]'``

Usage::

    from pramanix.key_provider import FileKeyProvider, AwsKmsKeyProvider
    from pramanix.crypto import PramanixSigner

    # Local file
    provider = FileKeyProvider("/run/secrets/pramanix-ed25519.pem")
    signer = PramanixSigner.from_provider(provider)

    # AWS Secrets Manager (requires pip install 'pramanix[aws]')
    provider = AwsKmsKeyProvider("arn:aws:secretsmanager:us-east-1:123:secret:pramanix-key")
    signer = PramanixSigner.from_provider(provider)
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

_DEFAULT_KEY_CACHE_TTL: float = 300.0

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

    @property
    def supports_rotation(self) -> bool:
        """Return ``True`` if this provider supports :meth:`rotate_key`."""
        ...

    def rotate_key(self) -> None:
        """Rotate to a new key.

        Raises:
            NotImplementedError: If the provider does not support rotation.
                                 Check :attr:`supports_rotation` first.
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

    @property
    def supports_rotation(self) -> bool:
        return False

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

    @property
    def supports_rotation(self) -> bool:
        return False

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

    @property
    def supports_rotation(self) -> bool:
        return False

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "FileKeyProvider does not support in-place rotation — "
            "replace the file contents and create a new FileKeyProvider."
        )


# ── Cloud secret-store providers ─────────────────────────────────────────────


class AwsKmsKeyProvider:
    """Fetch an Ed25519 private key PEM from AWS Secrets Manager.

    The private key PEM must be stored as a plaintext secret
    (``SecretString``) or binary secret (``SecretBinary``) in AWS Secrets
    Manager.  This provider retrieves it on each call to
    :meth:`private_key_pem`.

    Args:
        secret_arn:    ARN or name of the Secrets Manager secret that
                       contains the PEM-encoded Ed25519 private key.
        region_name:   AWS region (default ``"us-east-1"``).
        version_stage: Secret version stage label (default
                       ``"AWSCURRENT"``).
        version:       Opaque version label for :meth:`key_version`.
                       If ``None``, the Secrets Manager ``VersionId`` is
                       used.
        _client:       Pre-built boto3 ``secretsmanager`` client.
                       Injected for testing; not part of the public API.

    Requires:
        ``pip install 'pramanix[aws]'`` (``boto3 >= 1.34``).
    """

    def __init__(
        self,
        secret_arn: str,
        *,
        region_name: str = "us-east-1",
        version_stage: str = "AWSCURRENT",
        version: str | None = None,
        _client: Any = None,
    ) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "AwsKmsKeyProvider requires 'boto3'. "
                "Install it: pip install 'pramanix[aws]'"
            ) from exc
        self._secret_arn = secret_arn
        self._version_stage = version_stage
        self._explicit_version = version
        self._client = _client or boto3.client(
            "secretsmanager", region_name=region_name
        )
        # H-12: cache fetched key PEM and version to avoid redundant API calls.
        self._cache_lock = threading.Lock()
        self._cached_pem: bytes | None = None
        self._cached_version: str | None = None
        self._cache_expires: float = 0.0

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        resp = self._client.get_secret_value(
            SecretId=self._secret_arn,
            VersionStage=self._version_stage,
        )
        value: str | bytes = resp.get("SecretString") or resp.get("SecretBinary", b"")
        self._cached_pem = value.encode() if isinstance(value, str) else value
        if self._explicit_version:
            self._cached_version = self._explicit_version
        else:
            version_id: str = resp.get("VersionId", "aws-unknown")
            self._cached_version = version_id
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_pem  # type: ignore[return-value]

    def public_key_pem(self) -> bytes:
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_version or "aws-unknown"

    @property
    def supports_rotation(self) -> bool:
        return True

    def rotate_key(self) -> None:
        """Trigger automatic rotation of the Secrets Manager secret."""
        self._client.rotate_secret(SecretId=self._secret_arn)
        with self._cache_lock:
            self._cache_expires = 0.0  # invalidate cache after rotation


class AzureKeyVaultKeyProvider:
    """Fetch an Ed25519 private key PEM from Azure Key Vault Secrets.

    The private key PEM must be stored as a Key Vault Secret value.  This
    provider retrieves it on each call to :meth:`private_key_pem`.

    Args:
        vault_url:      Full URL of the Key Vault, e.g.
                        ``"https://my-vault.vault.azure.net"``.
        secret_name:    Name of the Key Vault Secret that contains the PEM.
        secret_version: Specific secret version (default: latest).
        credential:     Azure credential object (default:
                        ``DefaultAzureCredential()``).
        _client:        Pre-built ``SecretClient`` instance.
                        Injected for testing; not part of the public API.

    Requires:
        ``pip install 'pramanix[azure]'``
        (``azure-keyvault-secrets >= 4.7``, ``azure-identity >= 1.15``).
    """

    def __init__(
        self,
        vault_url: str,
        secret_name: str,
        *,
        secret_version: str | None = None,
        credential: Any = None,
        _client: Any = None,
    ) -> None:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:
            raise ImportError(
                "AzureKeyVaultKeyProvider requires 'azure-keyvault-secrets' and "
                "'azure-identity'. Install them: pip install 'pramanix[azure]'"
            ) from exc
        self._secret_name = secret_name
        self._secret_version = secret_version
        self._client = _client or SecretClient(
            vault_url=vault_url,
            credential=credential or DefaultAzureCredential(),
        )
        # H-12: cache fetched key PEM and version to avoid redundant API calls.
        self._cache_lock = threading.Lock()
        self._cached_pem: bytes | None = None
        self._cached_version: str | None = None
        self._cache_expires: float = 0.0

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        secret = self._client.get_secret(
            self._secret_name, version=self._secret_version
        )
        value: str | bytes = secret.value or ""
        self._cached_pem = value.encode() if isinstance(value, str) else value
        self._cached_version = str(secret.properties.version or "azure-unknown")
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_pem  # type: ignore[return-value]

    def public_key_pem(self) -> bytes:
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_version or "azure-unknown"

    @property
    def supports_rotation(self) -> bool:
        return False

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "AzureKeyVaultKeyProvider does not support automatic rotation. "
            "Upload a new secret version via the Azure portal or CLI, then "
            "create a new AzureKeyVaultKeyProvider pointing at the new version."
        )


class GcpKmsKeyProvider:
    """Fetch an Ed25519 private key PEM from GCP Secret Manager.

    The private key PEM must be stored as a Secret Manager secret.  This
    provider retrieves it on each call to :meth:`private_key_pem`.

    Args:
        project_id:  GCP project ID.
        secret_id:   ID of the Secret Manager secret containing the PEM.
        version_id:  Secret version (default ``"latest"``).
        _client:     Pre-built ``SecretManagerServiceClient`` instance.
                     Injected for testing; not part of the public API.

    Requires:
        ``pip install 'pramanix[gcp]'``
        (``google-cloud-secret-manager >= 2.16``).
    """

    def __init__(
        self,
        project_id: str,
        secret_id: str,
        *,
        version_id: str = "latest",
        _client: Any = None,
    ) -> None:
        try:
            from google.cloud import secretmanager
        except ImportError as exc:
            raise ImportError(
                "GcpKmsKeyProvider requires 'google-cloud-secret-manager'. "
                "Install it: pip install 'pramanix[gcp]'"
            ) from exc
        self._project_id = project_id
        self._secret_id = secret_id
        self._version_id = version_id
        self._client = _client or secretmanager.SecretManagerServiceClient()
        # H-12: cache fetched key PEM to avoid redundant API calls.
        self._cache_lock = threading.Lock()
        self._cached_pem: bytes | None = None
        self._cache_expires: float = 0.0

    def _version_name(self) -> str:
        return (
            f"projects/{self._project_id}/secrets/{self._secret_id}"
            f"/versions/{self._version_id}"
        )

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        response = self._client.access_secret_version(name=self._version_name())
        payload: bytes | str = response.payload.data
        self._cached_pem = payload if isinstance(payload, bytes) else payload.encode()
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_pem  # type: ignore[return-value]

    def public_key_pem(self) -> bytes:
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        return self._version_id

    @property
    def supports_rotation(self) -> bool:
        return False

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "GcpKmsKeyProvider does not support automatic rotation. "
            "Add a new secret version via the GCP console or gcloud CLI, then "
            "create a new GcpKmsKeyProvider pointing at the new version."
        )


class HashiCorpVaultKeyProvider:
    """Fetch an Ed25519 private key PEM from HashiCorp Vault KV v2.

    The private key PEM must be stored as a field in a Vault KV v2 secret.
    This provider retrieves it on each call to :meth:`private_key_pem`.

    Args:
        url:          Vault server URL, e.g.
                      ``"https://vault.example.com:8200"``.
        secret_path:  Path to the KV v2 secret (relative to ``mount_point``),
                      e.g. ``"pramanix/signing-key"``.
        field:        Field name within the secret data (default
                      ``"private_key_pem"``).
        token:        Vault token for authentication.  If ``None``, hvac
                      reads ``VAULT_TOKEN`` from the environment.
        mount_point:  KV v2 mount point (default ``"secret"``).
        _client:      Pre-built ``hvac.Client`` instance.
                      Injected for testing; not part of the public API.

    Requires:
        ``pip install 'pramanix[vault]'`` (``hvac >= 2.0``).
    """

    def __init__(
        self,
        url: str,
        secret_path: str,
        *,
        field: str = "private_key_pem",
        token: str | None = None,
        mount_point: str = "secret",
        _client: Any = None,
    ) -> None:
        try:
            import hvac
        except ImportError as exc:
            raise ImportError(
                "HashiCorpVaultKeyProvider requires 'hvac'. "
                "Install it: pip install 'pramanix[vault]'"
            ) from exc
        self._secret_path = secret_path
        self._field = field
        self._mount_point = mount_point
        self._client = _client or hvac.Client(url=url, token=token)
        # H-12: cache fetched key PEM and version to avoid redundant API calls.
        self._cache_lock = threading.Lock()
        self._cached_pem: bytes | None = None
        self._cached_version: str | None = None
        self._cache_expires: float = 0.0

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        resp = self._client.secrets.kv.v2.read_secret_version(
            path=self._secret_path,
            mount_point=self._mount_point,
        )
        value: str | bytes = resp["data"]["data"][self._field]
        self._cached_pem = value.encode() if isinstance(value, str) else value
        self._cached_version = str(resp["data"]["metadata"]["version"])
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_pem  # type: ignore[return-value]

    def public_key_pem(self) -> bytes:
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_version or "vault-unknown"

    @property
    def supports_rotation(self) -> bool:
        return False

    def rotate_key(self) -> None:
        raise NotImplementedError(
            "HashiCorpVaultKeyProvider does not support automatic rotation. "
            "Write a new secret version via the vault CLI or API, then "
            "create a new HashiCorpVaultKeyProvider pointing at the latest version."
        )


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
