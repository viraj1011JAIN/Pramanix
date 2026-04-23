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
import sys
from unittest.mock import MagicMock, PropertyMock


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
    """Tests AwsKmsKeyProvider logic with an injected mock boto3 client.

    Uses ``__new__`` + attribute injection to bypass the SDK import check so
    these tests run regardless of whether boto3 is installed in CI.
    """

    _ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:pramanix-key"

    def _provider(
        self,
        mock_client: MagicMock,
        *,
        explicit_version: str | None = None,
    ) -> AwsKmsKeyProvider:
        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._client = mock_client
        p._secret_arn = self._ARN
        p._version_stage = "AWSCURRENT"
        p._explicit_version = explicit_version
        return p

    def test_private_key_pem_from_secret_string(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret_value.return_value = {"SecretString": test_pem.decode()}
        assert self._provider(mc).private_key_pem() == test_pem

    def test_private_key_pem_from_secret_binary(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret_value.return_value = {"SecretBinary": test_pem}
        assert self._provider(mc).private_key_pem() == test_pem

    def test_public_key_derived(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret_value.return_value = {"SecretString": test_pem.decode()}
        pub = self._provider(mc).public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_key_version_from_describe_secret(self) -> None:
        mc = MagicMock()
        mc.describe_secret.return_value = {
            "VersionIdsToStages": {"ver-abc-123": ["AWSCURRENT"]}
        }
        assert self._provider(mc).key_version() == "ver-abc-123"

    def test_explicit_version_skips_describe(self) -> None:
        mc = MagicMock()
        assert self._provider(mc, explicit_version="pinned-v2").key_version() == "pinned-v2"
        mc.describe_secret.assert_not_called()

    def test_key_version_fallback_when_stage_absent(self) -> None:
        mc = MagicMock()
        mc.describe_secret.return_value = {
            "VersionIdsToStages": {"ver-old": ["AWSPREVIOUS"]}
        }
        assert self._provider(mc).key_version() == "aws-unknown"

    def test_rotate_calls_rotate_secret(self) -> None:
        mc = MagicMock()
        self._provider(mc).rotate_key()
        mc.rotate_secret.assert_called_once_with(SecretId=self._ARN)

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret_value.return_value = {"SecretString": test_pem.decode()}
        assert isinstance(self._provider(mc), KeyProvider)


# ── AzureKeyVaultKeyProvider — behaviour with injected mock client ────────────


class TestAzureKeyVaultKeyProviderBehavior:
    """Tests AzureKeyVaultKeyProvider logic with an injected mock SecretClient."""

    def _provider(self, mock_client: MagicMock) -> AzureKeyVaultKeyProvider:
        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        p._client = mock_client
        p._secret_name = "pramanix-signing-key"
        p._secret_version = None
        return p

    def _mock_secret(self, pem: bytes, version: str = "abc123def") -> MagicMock:
        secret = MagicMock()
        secret.value = pem.decode()
        secret.properties.version = version
        return secret

    def test_private_key_pem_returns_value(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret.return_value = self._mock_secret(test_pem)
        assert self._provider(mc).private_key_pem() == test_pem

    def test_public_key_derived(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret.return_value = self._mock_secret(test_pem)
        pub = self._provider(mc).public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_key_version_from_properties(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret.return_value = self._mock_secret(test_pem, version="v20260401")
        assert self._provider(mc).key_version() == "v20260401"

    def test_rotate_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            self._provider(MagicMock()).rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.get_secret.return_value = self._mock_secret(test_pem)
        assert isinstance(self._provider(mc), KeyProvider)


# ── GcpKmsKeyProvider — behaviour with injected mock client ──────────────────


class TestGcpKmsKeyProviderBehavior:
    """Tests GcpKmsKeyProvider logic with an injected mock SecretManagerClient."""

    def _provider(
        self,
        mock_client: MagicMock,
        *,
        version_id: str = "latest",
    ) -> GcpKmsKeyProvider:
        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._client = mock_client
        p._project_id = "my-project"
        p._secret_id = "pramanix-signing-key"
        p._version_id = version_id
        return p

    def test_private_key_pem_from_payload(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.access_secret_version.return_value.payload.data = test_pem
        assert self._provider(mc).private_key_pem() == test_pem

    def test_private_key_pem_from_string_payload(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.access_secret_version.return_value.payload.data = test_pem.decode()
        assert self._provider(mc).private_key_pem() == test_pem

    def test_version_name_construction(self) -> None:
        mc = MagicMock()
        p = self._provider(mc, version_id="42")
        assert p._version_name() == "projects/my-project/secrets/pramanix-signing-key/versions/42"

    def test_key_version_returns_version_id(self) -> None:
        assert self._provider(MagicMock(), version_id="7").key_version() == "7"

    def test_rotate_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            self._provider(MagicMock()).rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.access_secret_version.return_value.payload.data = test_pem
        assert isinstance(self._provider(mc), KeyProvider)


# ── HashiCorpVaultKeyProvider — behaviour with injected mock client ───────────


class TestHashiCorpVaultKeyProviderBehavior:
    """Tests HashiCorpVaultKeyProvider logic with an injected mock hvac.Client."""

    def _provider(self, mock_client: MagicMock) -> HashiCorpVaultKeyProvider:
        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._client = mock_client
        p._secret_path = "pramanix/signing-key"
        p._field = "private_key_pem"
        p._mount_point = "secret"
        return p

    def _kv_response(self, pem: bytes, version: int = 3) -> dict:  # type: ignore[type-arg]
        return {
            "data": {
                "data": {"private_key_pem": pem.decode()},
                "metadata": {"version": version},
            }
        }

    def test_private_key_pem_from_kv(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.secrets.kv.v2.read_secret_version.return_value = self._kv_response(test_pem)
        assert self._provider(mc).private_key_pem() == test_pem

    def test_public_key_derived(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.secrets.kv.v2.read_secret_version.return_value = self._kv_response(test_pem)
        pub = self._provider(mc).public_key_pem()
        assert b"PUBLIC KEY" in pub

    def test_key_version_from_metadata(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.secrets.kv.v2.read_secret_version.return_value = self._kv_response(test_pem, version=7)
        assert self._provider(mc).key_version() == "7"

    def test_rotate_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            self._provider(MagicMock()).rotate_key()

    def test_satisfies_protocol(self, test_pem: bytes) -> None:
        mc = MagicMock()
        mc.secrets.kv.v2.read_secret_version.return_value = self._kv_response(
            _generate_test_pem()
        )
        assert isinstance(self._provider(mc), KeyProvider)
