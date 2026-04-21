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


# ── Cloud KMS stubs raise ImportError ────────────────────────────────────────


class TestCloudKmsStubs:
    def test_aws_kms_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="boto3"):
            AwsKmsKeyProvider()  # type: ignore[call-arg]

    def test_azure_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="azure-keyvault-keys"):
            AzureKeyVaultKeyProvider()  # type: ignore[call-arg]

    def test_gcp_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="google-cloud-kms"):
            GcpKmsKeyProvider()  # type: ignore[call-arg]

    def test_vault_raises_import_error(self) -> None:
        with pytest.raises(ImportError, match="hvac"):
            HashiCorpVaultKeyProvider()  # type: ignore[call-arg]
