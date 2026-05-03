# SPDX-License-Identifier: AGPL-3.0-only
# Phase E-3: Tests for KeyProvider implementations and PramanixSigner.from_provider()
"""Verifies KeyProvider protocol, built-in providers, and signer factory."""
from __future__ import annotations

from pathlib import Path

import pytest

from pramanix.key_provider import (
    AwsKmsKeyProvider,
    AzureKeyVaultKeyProvider,
    EnvKeyProvider,
    FileKeyProvider,
    GcpKmsKeyProvider,
    HashiCorpVaultKeyProvider,
    KeyProvider,
    PemKeyProvider,
)

# ── Shared test key fixture ───────────────────────────────────────────────────

def _generate_test_pem() -> bytes:
    """Generate a fresh Ed25519 private key PEM for testing."""
    from pramanix.crypto import PramanixSigner
    signer = PramanixSigner.generate()
    return signer.private_key_pem()


@pytest.fixture(scope="module")
def test_pem() -> bytes:
    return _generate_test_pem()


# ── PemKeyProvider ────────────────────────────────────────────────────────────


class TestPemKeyProvider:
    def test_private_key_pem_roundtrip(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem)
        assert provider.private_key_pem() == test_pem

    def test_str_pem_accepted(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem.decode())
        assert provider.private_key_pem() == test_pem

    def test_public_key_pem_derived(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem)
        pub = provider.public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_default_version(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem)
        assert provider.key_version() == "inline-1"

    def test_custom_version(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem, version="v2")
        assert provider.key_version() == "v2"

    def test_rotate_raises(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem)
        with pytest.raises(NotImplementedError):
            provider.rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        provider = PemKeyProvider(test_pem)
        assert isinstance(provider, KeyProvider)


# ── EnvKeyProvider ────────────────────────────────────────────────────────────


class TestEnvKeyProvider:
    def test_reads_from_env_var(self, test_pem: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_SIGNING_KEY", test_pem.decode())
        provider = EnvKeyProvider("TEST_SIGNING_KEY")
        assert provider.private_key_pem() == test_pem

    def test_missing_env_var_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_TEST_MISSING_KEY", raising=False)
        provider = EnvKeyProvider("PRAMANIX_TEST_MISSING_KEY")
        with pytest.raises(RuntimeError, match="is not set"):
            provider.private_key_pem()

    def test_public_key_derived(self, test_pem: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_SIGNING_KEY2", test_pem.decode())
        provider = EnvKeyProvider("TEST_SIGNING_KEY2")
        pub = provider.public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_default_version(self, test_pem: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY_PEM", test_pem.decode())
        provider = EnvKeyProvider()
        assert provider.key_version() == "env-1"

    def test_rotate_raises(self) -> None:
        provider = EnvKeyProvider()
        with pytest.raises(NotImplementedError):
            provider.rotate_key()

    def test_satisfies_protocol(self) -> None:
        assert isinstance(EnvKeyProvider(), KeyProvider)


# ── FileKeyProvider ───────────────────────────────────────────────────────────


class TestFileKeyProvider:
    def test_reads_pem_from_file(self, test_pem: bytes, tmp_path: Path) -> None:
        key_file = tmp_path / "signing.pem"
        key_file.write_bytes(test_pem)
        provider = FileKeyProvider(key_file)
        assert provider.private_key_pem() == test_pem

    def test_str_path_accepted(self, test_pem: bytes, tmp_path: Path) -> None:
        key_file = tmp_path / "signing2.pem"
        key_file.write_bytes(test_pem)
        provider = FileKeyProvider(str(key_file))
        assert provider.private_key_pem() == test_pem

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        provider = FileKeyProvider(tmp_path / "does_not_exist.pem")
        with pytest.raises(FileNotFoundError):
            provider.private_key_pem()

    def test_public_key_derived(self, test_pem: bytes, tmp_path: Path) -> None:
        key_file = tmp_path / "signing3.pem"
        key_file.write_bytes(test_pem)
        provider = FileKeyProvider(key_file)
        pub = provider.public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_explicit_version(self, test_pem: bytes, tmp_path: Path) -> None:
        key_file = tmp_path / "signing4.pem"
        key_file.write_bytes(test_pem)
        provider = FileKeyProvider(key_file, version="prod-2025-01")
        assert provider.key_version() == "prod-2025-01"

    def test_auto_version_uses_mtime(self, test_pem: bytes, tmp_path: Path) -> None:
        key_file = tmp_path / "signing5.pem"
        key_file.write_bytes(test_pem)
        provider = FileKeyProvider(key_file)
        version = provider.key_version()
        assert version.startswith("file-mtime-")

    def test_rotate_raises(self, tmp_path: Path) -> None:
        provider = FileKeyProvider(tmp_path / "any.pem")
        with pytest.raises(NotImplementedError):
            provider.rotate_key()

    def test_satisfies_protocol(self, tmp_path: Path) -> None:
        provider = FileKeyProvider(tmp_path / "any.pem")
        assert isinstance(provider, KeyProvider)


# ── PramanixSigner.from_provider() ───────────────────────────────────────────


class TestSignerFromProvider:
    def test_from_pem_provider_signs(self, test_pem: bytes) -> None:
        from pramanix.crypto import PramanixSigner
        from pramanix.decision import Decision

        provider = PemKeyProvider(test_pem)
        signer = PramanixSigner.from_provider(provider)
        decision = Decision.safe(solver_time_ms=1.0)
        sig = signer.sign(decision)
        assert sig != ""

    def test_from_file_provider_signs(self, test_pem: bytes, tmp_path: Path) -> None:
        from pramanix.crypto import PramanixSigner
        from pramanix.decision import Decision

        key_file = tmp_path / "key.pem"
        key_file.write_bytes(test_pem)
        provider = FileKeyProvider(key_file)
        signer = PramanixSigner.from_provider(provider)
        decision = Decision.safe(solver_time_ms=1.0)
        sig = signer.sign(decision)
        assert sig != ""

    def test_signature_verifiable(self, test_pem: bytes) -> None:
        from pramanix.crypto import PramanixSigner, PramanixVerifier
        from pramanix.decision import Decision

        provider = PemKeyProvider(test_pem)
        signer = PramanixSigner.from_provider(provider)
        decision = Decision.safe(solver_time_ms=1.0)
        sig = signer.sign(decision)

        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=decision.decision_hash, signature=sig)

    def test_key_rotation_produces_new_signer(self, test_pem: bytes) -> None:
        """New PemKeyProvider with different key produces different signer."""
        from pramanix.crypto import PramanixSigner

        pem1 = test_pem
        pem2 = PramanixSigner.generate().private_key_pem()
        signer1 = PramanixSigner.from_provider(PemKeyProvider(pem1))
        signer2 = PramanixSigner.from_provider(PemKeyProvider(pem2))
        # Different keys produce different key IDs
        assert signer1.key_id() != signer2.key_id()


# ── Cloud KMS providers — missing SDK raises ImportError ─────────────────────
# These tests verify that each provider raises ImportError when its optional
# SDK is not installed.  They are skipped when the SDK *is* present.

import importlib

from tests.helpers.real_protocols import (
    _AwsSecretsClient,
    _AzureSecretClient,
    _GcpSecretClient,
    _HvacClient,
)


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ModuleNotFoundError, ValueError):
        return False


_HAS_BOTO3 = _has_module("boto3")
_HAS_AZURE = _has_module("azure.keyvault.secrets") and _has_module("azure.identity")
_HAS_GCP   = _has_module("google.cloud.secretmanager")
_HAS_HVAC  = _has_module("hvac")


class TestCloudKmsImportGuard:
    """Provider constructors raise ImportError when the SDK is absent."""

    @pytest.mark.skipif(_HAS_BOTO3, reason="boto3 is installed")
    def test_aws_kms_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="boto3"):
            AwsKmsKeyProvider("arn:aws:secretsmanager:us-east-1:123:secret:k")

    @pytest.mark.skipif(_HAS_AZURE, reason="azure-keyvault-secrets is installed")
    def test_azure_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="azure"):
            AzureKeyVaultKeyProvider("https://vault.azure.net", "my-secret")

    @pytest.mark.skipif(_HAS_GCP, reason="google-cloud-secret-manager is installed")
    def test_gcp_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="google-cloud-secret-manager"):
            GcpKmsKeyProvider("my-project", "my-secret")

    @pytest.mark.skipif(_HAS_HVAC, reason="hvac is installed")
    def test_vault_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="hvac"):
            HashiCorpVaultKeyProvider("https://vault.example.com", "pramanix/key")


# ── AwsKmsKeyProvider — behaviour with injected mock client ──────────────────


class TestAwsKmsKeyProviderBehavior:
    """Tests AwsKmsKeyProvider logic with an injected real _AwsSecretsClient.

    Uses ``__new__`` + attribute injection to bypass the SDK import check so
    these tests run regardless of whether boto3 is installed in CI.
    """

    _ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:pramanix-key"

    def _provider(
        self,
        client: _AwsSecretsClient,
        *,
        explicit_version: str | None = None,
    ) -> AwsKmsKeyProvider:
        import threading
        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = client
        p._secret_arn = self._ARN
        p._version_stage = "AWSCURRENT"
        p._explicit_version = explicit_version
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        return p

    def test_private_key_pem_from_secret_string(self, test_pem: bytes) -> None:
        client = _AwsSecretsClient(test_pem.decode())
        assert self._provider(client).private_key_pem() == test_pem

    def test_private_key_pem_from_secret_binary(self, test_pem: bytes) -> None:
        client = _AwsSecretsClient(secret_binary=test_pem)
        assert self._provider(client).private_key_pem() == test_pem

    def test_public_key_derived(self, test_pem: bytes) -> None:
        client = _AwsSecretsClient(test_pem.decode())
        pub = self._provider(client).public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_key_version_from_describe_secret(self) -> None:
        client = _AwsSecretsClient("PLACEHOLDER_PEM", version_id="ver-abc-123")
        assert self._provider(client).key_version() == "ver-abc-123"

    def test_explicit_version_skips_describe(self) -> None:
        client = _AwsSecretsClient("PLACEHOLDER_PEM")
        p = self._provider(client, explicit_version="pinned-v2")
        assert p.key_version() == "pinned-v2"

    def test_key_version_fallback_when_stage_absent(self) -> None:
        # No version_id → get_secret_value returns no "VersionId" key → "aws-unknown"
        client = _AwsSecretsClient("PLACEHOLDER_PEM")
        assert self._provider(client).key_version() == "aws-unknown"

    def test_rotate_calls_rotate_secret(self) -> None:
        client = _AwsSecretsClient()
        self._provider(client).rotate_key()
        assert client.rotate_secret_calls == [self._ARN]

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        client = _AwsSecretsClient(test_pem.decode())
        assert isinstance(self._provider(client), KeyProvider)


# ── AzureKeyVaultKeyProvider — behaviour with injected mock client ────────────


class TestAzureKeyVaultKeyProviderBehavior:
    """Tests AzureKeyVaultKeyProvider logic with an injected real _AzureSecretClient."""

    def _provider(self, client: _AzureSecretClient) -> AzureKeyVaultKeyProvider:
        import threading
        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        p._client = client
        p._secret_name = "pramanix-signing-key"
        p._secret_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        return p

    def test_private_key_pem_returns_value(self, test_pem: bytes) -> None:
        assert self._provider(_AzureSecretClient(test_pem.decode())).private_key_pem() == test_pem

    def test_public_key_derived(self, test_pem: bytes) -> None:
        pub = self._provider(_AzureSecretClient(test_pem.decode())).public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_key_version_from_properties(self, test_pem: bytes) -> None:
        client = _AzureSecretClient(test_pem.decode(), version_id="v20260401")
        assert self._provider(client).key_version() == "v20260401"

    def test_rotate_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            self._provider(_AzureSecretClient("")).rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        assert isinstance(self._provider(_AzureSecretClient(test_pem.decode())), KeyProvider)


# ── GcpKmsKeyProvider — behaviour with injected mock client ──────────────────


class TestGcpKmsKeyProviderBehavior:
    """Tests GcpKmsKeyProvider logic with an injected real _GcpSecretClient."""

    def _provider(
        self,
        client: _GcpSecretClient,
        *,
        version_id: str = "latest",
    ) -> GcpKmsKeyProvider:
        import threading
        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._client = client
        p._project_id = "my-project"
        p._secret_id = "pramanix-signing-key"
        p._version_id = version_id
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cache_expires = 0.0
        return p

    def test_private_key_pem_from_payload(self, test_pem: bytes) -> None:
        assert self._provider(_GcpSecretClient(test_pem)).private_key_pem() == test_pem

    def test_private_key_pem_from_string_payload(self, test_pem: bytes) -> None:
        assert self._provider(_GcpSecretClient(test_pem, as_str=True)).private_key_pem() == test_pem

    def test_version_name_construction(self) -> None:
        p = self._provider(_GcpSecretClient(b""), version_id="42")
        assert p._version_name() == "projects/my-project/secrets/pramanix-signing-key/versions/42"

    def test_key_version_returns_version_id(self) -> None:
        assert self._provider(_GcpSecretClient(b""), version_id="7").key_version() == "7"

    def test_rotate_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            self._provider(_GcpSecretClient(b"")).rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        assert isinstance(self._provider(_GcpSecretClient(test_pem)), KeyProvider)


# ── HashiCorpVaultKeyProvider — behaviour with injected mock client ───────────


class TestHashiCorpVaultKeyProviderBehavior:
    """Tests HashiCorpVaultKeyProvider logic with an injected real _HvacClient."""

    def _provider(self, client: _HvacClient) -> HashiCorpVaultKeyProvider:
        import threading
        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._client = client
        p._secret_path = "pramanix/signing-key"
        p._field = "private_key_pem"
        p._mount_point = "secret"
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0
        return p

    def test_private_key_pem_from_kv(self, test_pem: bytes) -> None:
        assert self._provider(_HvacClient(test_pem)).private_key_pem() == test_pem

    def test_public_key_derived(self, test_pem: bytes) -> None:
        pub = self._provider(_HvacClient(test_pem)).public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_key_version_from_metadata(self, test_pem: bytes) -> None:
        assert self._provider(_HvacClient(test_pem, version=7)).key_version() == "7"

    def test_rotate_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            self._provider(_HvacClient(b"PLACEHOLDER")).rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        assert isinstance(self._provider(_HvacClient(_generate_test_pem())), KeyProvider)
