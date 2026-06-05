# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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

import contextlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

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
        """Return the inline PEM-encoded private key bytes."""
        return self._private_pem

    def public_key_pem(self) -> bytes:
        """Derive and return the PEM-encoded public key from the private key."""
        if self._public_pem is None:
            self._public_pem = _derive_public_pem(self._private_pem)
        return self._public_pem

    def key_version(self) -> str:
        """Return the opaque key version label."""
        return self._version

    @property
    def supports_rotation(self) -> bool:
        """True — generates a new Ed25519 key in-place."""
        return True

    def rotate_key(self) -> None:
        """Generate a new Ed25519 key and replace the in-memory PEM.

        The previous key is discarded.  Callers that need the new public key
        for distribution must call :meth:`public_key_pem` after rotation.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        new_key = Ed25519PrivateKey.generate()
        self._private_pem = new_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        self._public_pem = None


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
        """Read and return the PEM key from the configured environment variable."""
        pem = os.environ.get(self._env_var, "")
        if not pem:
            raise RuntimeError(
                f"EnvKeyProvider: environment variable {self._env_var!r} is not set. "
                "Set it to a PEM-encoded Ed25519 private key."
            )
        return pem.encode()

    def public_key_pem(self) -> bytes:
        """Derive and return the public key from the environment-sourced private key."""
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        """Return the opaque key version label."""
        return self._version

    @property
    def supports_rotation(self) -> bool:
        """Always False — update the environment variable to rotate."""
        return False

    def rotate_key(self) -> None:
        """Not supported; raises NotImplementedError."""
        raise NotImplementedError(
            "EnvKeyProvider does not support rotation — update the environment variable to rotate."
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        env_var: str = "PRAMANIX_SIGNING_KEY_PEM",
        version: str = "env-1",
    ) -> "EnvKeyProvider":
        """Construct without requiring the env var to be set.

        Useful when a test only needs to inspect supports_rotation or
        key_version without actually calling private_key_pem().
        """
        inst = cls.__new__(cls)
        inst._env_var = env_var
        inst._version = version
        return inst


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
        """Read and return the PEM key from the configured file path."""
        if not self._path.exists():
            raise FileNotFoundError(f"FileKeyProvider: key file not found: {self._path}")
        return self._path.read_bytes()

    def public_key_pem(self) -> bytes:
        """Derive and return the public key from the file-sourced private key."""
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        """Return the file mtime as a version string, or the explicit version if set."""
        if self._explicit_version is not None:
            return self._explicit_version
        try:
            mtime = self._path.stat().st_mtime
            return f"file-mtime-{mtime:.0f}"
        except OSError:
            return "file-unknown"

    @property
    def supports_rotation(self) -> bool:
        """True — generates a new Ed25519 key and writes it atomically to disk."""
        return True

    def rotate_key(self) -> None:
        """Generate a new Ed25519 key and write it atomically to :attr:`_path`.

        Uses a sibling temp file + ``os.replace()`` so readers never observe
        a partially-written key file.  The previous key is overwritten.
        """
        import tempfile

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        new_key = Ed25519PrivateKey.generate()
        new_pem = new_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        parent = self._path.parent
        fd, tmp_path = tempfile.mkstemp(dir=parent, suffix=".pem.tmp")
        try:
            os.write(fd, new_pem)
            os.close(fd)
            os.replace(tmp_path, self._path)
        except Exception:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise


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
        _boto3_factory: Any = None,
    ) -> None:
        try:
            if _boto3_factory is not None:
                _boto3 = _boto3_factory()
            else:
                import importlib as _importlib

                _boto3 = _importlib.import_module("boto3")
        except ImportError as exc:
            raise ImportError(
                "AwsKmsKeyProvider requires 'boto3'. " "Install it: pip install 'pramanix[aws]'"
            ) from exc
        self._secret_arn = secret_arn
        self._version_stage = version_stage
        self._explicit_version = version
        self._client = _client or _boto3.client("secretsmanager", region_name=region_name)
        # H-12: cache fetched key PEM and version to avoid redundant API calls.
        self._cache_lock = threading.Lock()
        self._cached_pem: bytes | None = None
        self._cached_version: str | None = None
        self._cache_expires: float = 0.0

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        try:
            resp = self._client.get_secret_value(
                SecretId=self._secret_arn,
                VersionStage=self._version_stage,
            )
        except Exception as exc:
            raise RuntimeError(
                f"AwsKmsKeyProvider: failed to fetch secret {self._secret_arn!r} "
                f"from AWS Secrets Manager — KMS may be unreachable or credentials "
                f"are invalid. Underlying error: {type(exc).__name__}: {exc}"
            ) from exc
        value: str | bytes = resp.get("SecretString") or resp.get("SecretBinary", b"")
        self._cached_pem = value.encode() if isinstance(value, str) else value
        if self._explicit_version:
            self._cached_version = self._explicit_version
        else:
            version_id: str = resp.get("VersionId", "aws-unknown")
            self._cached_version = version_id
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        """Fetch and return the PEM key from AWS Secrets Manager."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            if self._cached_pem is None:
                raise RuntimeError(
                    "_refresh_cache() completed without setting _cached_pem — "
                    "this is an internal invariant violation."
                )
            return self._cached_pem

    def public_key_pem(self) -> bytes:
        """Derive and return the public key from the AWS-sourced private key."""
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        """Return the Secrets Manager VersionId as the key version."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_version or "aws-unknown"

    @property
    def supports_rotation(self) -> bool:
        """True — rotation is delegated to AWS Secrets Manager."""
        return True

    def rotate_key(self) -> None:
        """Trigger automatic rotation of the Secrets Manager secret.

        Cache is invalidated *before* triggering rotation so no concurrent
        reader can observe a stale key between the API call and expiry reset.
        """
        with self._cache_lock:
            self._cache_expires = 0.0
        self._client.rotate_secret(SecretId=self._secret_arn)


    @classmethod
    def _for_testing(
        cls,
        client: Any,
        *,
        secret_arn: str = "arn:aws:secretsmanager:us-east-1:000000000000:secret:test",
        version_stage: str = "AWSCURRENT",
        cached_pem: bytes | None = None,
    ) -> "AwsKmsKeyProvider":
        """Construct with a pre-built Secrets Manager client for unit testing."""
        inst = cls.__new__(cls)
        inst._secret_arn = secret_arn
        inst._version_stage = version_stage
        inst._explicit_version = None
        inst._client = client
        inst._cache_lock = threading.Lock()
        inst._cached_pem = cached_pem
        inst._cached_version = "test-version" if cached_pem else None
        inst._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL if cached_pem else 0.0
        return inst


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
        _azure_factory: Any = None,
    ) -> None:
        try:
            if _azure_factory is not None:
                DefaultAzureCredential, SecretClient = _azure_factory()
            else:
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
        try:
            secret = self._client.get_secret(self._secret_name, version=self._secret_version)
        except Exception as exc:
            raise RuntimeError(
                f"AzureKeyVaultKeyProvider: failed to fetch secret {self._secret_name!r} "
                f"from Azure Key Vault — the vault may be unreachable, the secret may "
                f"not exist, or credentials are invalid. "
                f"Underlying error: {type(exc).__name__}: {exc}"
            ) from exc
        value: str | bytes = secret.value or ""
        self._cached_pem = value.encode() if isinstance(value, str) else value
        self._cached_version = str(secret.properties.version or "azure-unknown")
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        """Fetch and return the PEM key from Azure Key Vault."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            if self._cached_pem is None:
                raise RuntimeError(
                    "_refresh_cache() completed without setting _cached_pem — "
                    "this is an internal invariant violation."
                )
            return self._cached_pem

    def public_key_pem(self) -> bytes:
        """Derive and return the public key from the Azure-sourced private key."""
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        """Return the Key Vault secret version as the key version."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_version or "azure-unknown"

    @property
    def supports_rotation(self) -> bool:
        """True — rotation fetches the latest unversioned secret from Azure Key Vault."""
        return True

    def rotate_key(self) -> None:
        """Rotate by fetching the latest secret version from Azure Key Vault.

        Invalidates the local cache and re-fetches with ``version=None``
        so the next call to :meth:`private_key_pem` picks up whatever new
        PEM the operator has uploaded to the vault.

        Raises:
            RuntimeError: If the Azure Key Vault fetch fails.
        """
        with self._cache_lock:
            # Force re-fetch on next access by expiring the cache and clearing
            # the pinned version so the latest version is always used.
            self._cache_expires = 0.0
            self._cached_pem = None
            self._cached_version = None
            _pinned = self._secret_version
            self._secret_version = None  # fetch latest version
            try:
                self._refresh_cache()
            except Exception:
                self._secret_version = _pinned  # restore on failure
                raise

    @classmethod
    def _for_testing(
        cls,
        client: Any,
        *,
        secret_name: str = "test-key",
        secret_version: str | None = None,
        cached_pem: bytes | None = None,
    ) -> "AzureKeyVaultKeyProvider":
        """Construct an instance with a pre-built client for unit testing.

        Accepts an already-constructed SecretClient duck-type so tests can
        inject fakes without requiring Azure SDK or real vault credentials.
        If *cached_pem* is provided the cache is pre-warmed, skipping the
        initial ``_refresh_cache()`` call.
        """
        inst = cls.__new__(cls)
        inst._secret_name = secret_name
        inst._secret_version = secret_version
        inst._client = client
        inst._cache_lock = threading.Lock()
        inst._cached_pem = cached_pem
        inst._cached_version = secret_version
        inst._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL if cached_pem else 0.0
        return inst


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
        _gcp_factory: Any = None,
    ) -> None:
        try:
            if _gcp_factory is not None:
                secretmanager = _gcp_factory()
            else:
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
            f"projects/{self._project_id}/secrets/{self._secret_id}" f"/versions/{self._version_id}"
        )

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        try:
            response = self._client.access_secret_version(name=self._version_name())
        except Exception as exc:
            raise RuntimeError(
                f"GcpKmsKeyProvider: failed to fetch secret "
                f"projects/{self._project_id}/secrets/{self._secret_id}/"
                f"versions/{self._version_id} from GCP Secret Manager — "
                f"the project may be unreachable or credentials are invalid. "
                f"Underlying error: {type(exc).__name__}: {exc}"
            ) from exc
        payload: bytes | str = response.payload.data
        self._cached_pem = payload if isinstance(payload, bytes) else payload.encode()
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        """Fetch and return the PEM key from GCP Secret Manager."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            if self._cached_pem is None:
                raise RuntimeError(
                    "_refresh_cache() completed without setting _cached_pem — "
                    "this is an internal invariant violation."
                )
            return self._cached_pem

    def public_key_pem(self) -> bytes:
        """Derive and return the public key from the GCP-sourced private key."""
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        """Return the GCP secret version ID as the key version."""
        return self._version_id

    @property
    def supports_rotation(self) -> bool:
        """True — rotation re-fetches the 'latest' version from GCP Secret Manager."""
        return True

    def rotate_key(self) -> None:
        """Rotate by fetching the latest secret version from GCP Secret Manager.

        Invalidates the local cache and sets ``version_id`` to ``"latest"``
        so the next :meth:`private_key_pem` call picks up the newest secret
        version the operator has added to GCP Secret Manager.

        Raises:
            RuntimeError: If the GCP Secret Manager fetch fails.
        """
        with self._cache_lock:
            _pinned = self._version_id
            self._version_id = "latest"
            self._cache_expires = 0.0
            self._cached_pem = None
            try:
                self._refresh_cache()
            except Exception:
                self._version_id = _pinned
                raise


    @classmethod
    def _for_testing(
        cls,
        client: Any,
        *,
        project_id: str = "test-project",
        secret_id: str = "test-secret",
        version_id: str = "latest",
        cached_pem: bytes | None = None,
    ) -> "GcpKmsKeyProvider":
        """Construct with a pre-built SecretManagerServiceClient for unit testing."""
        inst = cls.__new__(cls)
        inst._project_id = project_id
        inst._secret_id = secret_id
        inst._version_id = version_id
        inst._client = client
        inst._cache_lock = threading.Lock()
        inst._cached_pem = cached_pem
        inst._cached_version = version_id if cached_pem else None
        inst._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL if cached_pem else 0.0
        return inst


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
        _hvac_factory: Any = None,
    ) -> None:
        try:
            if _hvac_factory is not None:
                _hvac = _hvac_factory()
            else:
                import importlib as _importlib

                _hvac = _importlib.import_module("hvac")
        except ImportError as exc:
            raise ImportError(
                "HashiCorpVaultKeyProvider requires 'hvac'. "
                "Install it: pip install 'pramanix[vault]'"
            ) from exc
        self._secret_path = secret_path
        self._field = field
        self._mount_point = mount_point
        self._client = _client or _hvac.Client(url=url, token=token)
        # H-12: cache fetched key PEM and version to avoid redundant API calls.
        self._cache_lock = threading.Lock()
        self._cached_pem: bytes | None = None
        self._cached_version: str | None = None
        self._cache_expires: float = 0.0

    def _cache_valid(self) -> bool:
        return time.monotonic() < self._cache_expires

    def _refresh_cache(self) -> None:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=self._secret_path,
                mount_point=self._mount_point,
            )
        except Exception as exc:
            raise RuntimeError(
                f"HashiCorpVaultKeyProvider: failed to read secret {self._secret_path!r} "
                f"(mount={self._mount_point!r}) from HashiCorp Vault — "
                f"the Vault server may be sealed/unreachable or the token is invalid. "
                f"Underlying error: {type(exc).__name__}: {exc}"
            ) from exc
        try:
            value: str | bytes = resp["data"]["data"][self._field]
        except KeyError:
            from pramanix.exceptions import ConfigurationError

            available = list(resp.get("data", {}).get("data", {}).keys())
            raise ConfigurationError(
                f"HashiCorpVaultKeyProvider: field {self._field!r} not found in secret "
                f"{self._secret_path!r} (mount={self._mount_point!r}). "
                f"Available fields: {available}"
            ) from None
        self._cached_pem = value.encode() if isinstance(value, str) else value
        self._cached_version = str(resp["data"]["metadata"]["version"])
        self._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL

    def private_key_pem(self) -> bytes:
        """Fetch and return the PEM key from HashiCorp Vault KV v2."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            if self._cached_pem is None:
                raise RuntimeError(
                    "_refresh_cache() completed without setting _cached_pem — "
                    "this is an internal invariant violation."
                )
            return self._cached_pem

    def public_key_pem(self) -> bytes:
        """Derive and return the public key from the Vault-sourced private key."""
        return _derive_public_pem(self.private_key_pem())

    def key_version(self) -> str:
        """Return the Vault secret version number as the key version."""
        with self._cache_lock:
            if not self._cache_valid():
                self._refresh_cache()
            return self._cached_version or "vault-unknown"

    @property
    def supports_rotation(self) -> bool:
        """True — rotation re-fetches the latest version from HashiCorp Vault KV v2."""
        return True

    def rotate_key(self) -> None:
        """Rotate by fetching the latest secret version from HashiCorp Vault KV v2.

        Invalidates the local PEM cache and calls
        ``secrets.kv.v2.read_secret_version()`` without a version pin so that
        the most recently written version is returned.  Call this after
        writing a new PEM to the Vault secret path to complete zero-downtime
        key rotation.

        Raises:
            RuntimeError: If the Vault fetch fails (sealed, unreachable, token expired).
        """
        with self._cache_lock:
            self._cache_expires = 0.0
            self._cached_pem = None
            self._cached_version = None
            self._refresh_cache()

    @classmethod
    def _for_testing(
        cls,
        client: Any,
        *,
        vault_url: str = "http://localhost:8200",
        secret_path: str = "pramanix/signing-key",
        mount_point: str = "secret",
        cached_pem: bytes | None = None,
    ) -> "HashiCorpVaultKeyProvider":
        """Construct with a pre-built hvac client for unit testing.

        Accepts an already-constructed hvac.Client duck-type so tests can
        inject fakes without requiring a real Vault server.
        """
        inst = cls.__new__(cls)
        inst._vault_url = vault_url
        inst._secret_path = secret_path
        inst._mount_point = mount_point
        inst._client = client
        inst._cache_lock = threading.Lock()
        inst._cached_pem = cached_pem
        inst._cached_version = "test-version" if cached_pem else None
        inst._cache_expires = time.monotonic() + _DEFAULT_KEY_CACHE_TTL if cached_pem else 0.0
        return inst


# ── Helpers ───────────────────────────────────────────────────────────────────


def _derive_public_pem(private_pem: bytes, *, _crypto_factory: Any = None) -> bytes:
    """Derive the public key PEM from a private key PEM."""
    try:
        if _crypto_factory is not None:
            Encoding, PublicFormat, load_pem_private_key = _crypto_factory()
        else:
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
                load_pem_private_key,
            )
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required. " "Install it: pip install 'pramanix[crypto]'"
        ) from exc

    key = load_pem_private_key(private_pem, password=None)
    return cast(
        bytes, key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
