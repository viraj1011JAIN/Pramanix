"""Tests for RS256 and ES256 asymmetric JWT-compatible signers (Issue #15)."""
from __future__ import annotations

import pytest

from pramanix.crypto import ES256Signer, ES256Verifier, RS256Signer, RS256Verifier


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rs256_signer() -> RS256Signer:
    return RS256Signer.generate()


@pytest.fixture(scope="module")
def es256_signer() -> ES256Signer:
    return ES256Signer.generate()


@pytest.fixture(scope="module")
def mock_decision(rs256_signer: RS256Signer):
    """Return a minimal Decision-like object for signing tests."""
    from pramanix.decision import Decision, SolverStatus

    d = Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="test decision",
    )
    return d


# ── RS256 tests ───────────────────────────────────────────────────────────────


class TestRS256Signer:
    def test_generate_returns_signer(self) -> None:
        signer = RS256Signer.generate()
        assert isinstance(signer, RS256Signer)

    def test_generate_minimum_key_size(self) -> None:
        with pytest.raises(ValueError, match="2048"):
            RS256Signer.generate(key_size=1024)

    def test_public_key_pem_is_bytes(self, rs256_signer: RS256Signer) -> None:
        pem = rs256_signer.public_key_pem()
        assert isinstance(pem, bytes)
        assert b"PUBLIC KEY" in pem

    def test_key_id_is_16_hex_chars(self, rs256_signer: RS256Signer) -> None:
        kid = rs256_signer.key_id()
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_sign_returns_nonempty_string(self, rs256_signer: RS256Signer, mock_decision) -> None:
        sig = rs256_signer.sign(mock_decision)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_sign_verify_roundtrip(self, rs256_signer: RS256Signer, mock_decision) -> None:
        sig = rs256_signer.sign(mock_decision)
        assert mock_decision.decision_hash is not None
        assert rs256_signer.verify(decision_hash=mock_decision.decision_hash, signature=sig)

    def test_verify_wrong_signature_fails(self, rs256_signer: RS256Signer, mock_decision) -> None:
        assert not rs256_signer.verify(
            decision_hash=mock_decision.decision_hash or "hash",
            signature="invalidsig",
        )

    def test_force_ephemeral(self) -> None:
        signer = RS256Signer(force_ephemeral=True)
        assert isinstance(signer, RS256Signer)

    def test_no_key_raises_runtime_error(self, monkeypatch) -> None:
        monkeypatch.delenv("PRAMANIX_RS256_SIGNING_KEY_PEM", raising=False)
        with pytest.raises(RuntimeError, match="No RS256 signing key"):
            RS256Signer()

    def test_algorithm_constant(self) -> None:
        assert RS256Signer._ALGORITHM == "RS256"


class TestRS256Verifier:
    def test_verify_valid_signature(self, rs256_signer: RS256Signer, mock_decision) -> None:
        sig = rs256_signer.sign(mock_decision)
        verifier = RS256Verifier(public_key_pem=rs256_signer.public_key_pem())
        assert verifier.verify(decision_hash=mock_decision.decision_hash, signature=sig)

    def test_verify_tampered_hash_fails(self, rs256_signer: RS256Signer, mock_decision) -> None:
        sig = rs256_signer.sign(mock_decision)
        verifier = RS256Verifier(public_key_pem=rs256_signer.public_key_pem())
        assert not verifier.verify(decision_hash="tampered_hash", signature=sig)

    def test_verify_wrong_key_fails(self, mock_decision) -> None:
        signer_a = RS256Signer.generate()
        signer_b = RS256Signer.generate()
        sig = signer_a.sign(mock_decision)
        verifier_b = RS256Verifier(public_key_pem=signer_b.public_key_pem())
        assert not verifier_b.verify(
            decision_hash=mock_decision.decision_hash, signature=sig
        )

    def test_non_rsa_public_key_raises(self) -> None:
        es_signer = ES256Signer.generate()
        with pytest.raises(ValueError, match="not an RSA public key"):
            RS256Verifier(public_key_pem=es_signer.public_key_pem())

    def test_verify_decision_valid(
        self, rs256_signer: RS256Signer, mock_decision
    ) -> None:
        import dataclasses

        from pramanix.decision import Decision, SolverStatus

        d = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="test",
        )
        sig = rs256_signer.sign(d)
        d = dataclasses.replace(d, signature=sig)
        verifier = RS256Verifier(public_key_pem=rs256_signer.public_key_pem())
        assert verifier.verify_decision(d)

    def test_verify_decision_empty_sig_fails(
        self, rs256_signer: RS256Signer
    ) -> None:
        from pramanix.decision import Decision, SolverStatus

        d = Decision(
            allowed=False,
            status=SolverStatus.UNSAFE,
            violated_invariants=(),
            explanation="test",
        )
        verifier = RS256Verifier(public_key_pem=rs256_signer.public_key_pem())
        assert not verifier.verify_decision(d)


# ── ES256 tests ───────────────────────────────────────────────────────────────


class TestES256Signer:
    def test_generate_returns_signer(self) -> None:
        signer = ES256Signer.generate()
        assert isinstance(signer, ES256Signer)

    def test_public_key_pem_is_bytes(self, es256_signer: ES256Signer) -> None:
        pem = es256_signer.public_key_pem()
        assert isinstance(pem, bytes)
        assert b"PUBLIC KEY" in pem

    def test_key_id_is_16_hex_chars(self, es256_signer: ES256Signer) -> None:
        kid = es256_signer.key_id()
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_sign_returns_nonempty_string(self, es256_signer: ES256Signer, mock_decision) -> None:
        sig = es256_signer.sign(mock_decision)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_sign_verify_roundtrip(self, es256_signer: ES256Signer, mock_decision) -> None:
        sig = es256_signer.sign(mock_decision)
        assert es256_signer.verify(decision_hash=mock_decision.decision_hash, signature=sig)

    def test_verify_wrong_signature_fails(self, es256_signer: ES256Signer, mock_decision) -> None:
        assert not es256_signer.verify(
            decision_hash=mock_decision.decision_hash or "hash",
            signature="invalidsig",
        )

    def test_force_ephemeral(self) -> None:
        signer = ES256Signer(force_ephemeral=True)
        assert isinstance(signer, ES256Signer)

    def test_no_key_raises_runtime_error(self, monkeypatch) -> None:
        monkeypatch.delenv("PRAMANIX_ES256_SIGNING_KEY_PEM", raising=False)
        with pytest.raises(RuntimeError, match="No ES256 signing key"):
            ES256Signer()

    def test_algorithm_constant(self) -> None:
        assert ES256Signer._ALGORITHM == "ES256"

    def test_p384_key_rejected(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        key = generate_private_key(SECP384R1())
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        with pytest.raises(ValueError, match="secp256r1"):
            ES256Signer(private_key_pem=pem)


class TestES256Verifier:
    def test_verify_valid_signature(self, es256_signer: ES256Signer, mock_decision) -> None:
        sig = es256_signer.sign(mock_decision)
        verifier = ES256Verifier(public_key_pem=es256_signer.public_key_pem())
        assert verifier.verify(decision_hash=mock_decision.decision_hash, signature=sig)

    def test_verify_tampered_hash_fails(self, es256_signer: ES256Signer, mock_decision) -> None:
        sig = es256_signer.sign(mock_decision)
        verifier = ES256Verifier(public_key_pem=es256_signer.public_key_pem())
        assert not verifier.verify(decision_hash="tampered_hash", signature=sig)

    def test_verify_wrong_key_fails(self, mock_decision) -> None:
        signer_a = ES256Signer.generate()
        signer_b = ES256Signer.generate()
        sig = signer_a.sign(mock_decision)
        verifier_b = ES256Verifier(public_key_pem=signer_b.public_key_pem())
        assert not verifier_b.verify(
            decision_hash=mock_decision.decision_hash, signature=sig
        )

    def test_non_ec_public_key_raises(self) -> None:
        rs_signer = RS256Signer.generate()
        with pytest.raises(ValueError, match="not an EC public key"):
            ES256Verifier(public_key_pem=rs_signer.public_key_pem())

    def test_verify_decision_valid(self, es256_signer: ES256Signer) -> None:
        import dataclasses

        from pramanix.decision import Decision, SolverStatus

        d = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="test",
        )
        sig = es256_signer.sign(d)
        d = dataclasses.replace(d, signature=sig)
        verifier = ES256Verifier(public_key_pem=es256_signer.public_key_pem())
        assert verifier.verify_decision(d)


# ── Cross-algorithm rejection ─────────────────────────────────────────────────


class TestCrossAlgorithmRejection:
    """RS256 and ES256 signatures must not verify across algorithms."""

    def test_rs256_sig_fails_es256_verify(self, rs256_signer: RS256Signer, mock_decision) -> None:
        rs_sig = rs256_signer.sign(mock_decision)
        es_signer = ES256Signer.generate()
        es_verifier = ES256Verifier(public_key_pem=es_signer.public_key_pem())
        assert not es_verifier.verify(
            decision_hash=mock_decision.decision_hash, signature=rs_sig
        )

    def test_es256_sig_fails_rs256_verify(self, es256_signer: ES256Signer, mock_decision) -> None:
        es_sig = es256_signer.sign(mock_decision)
        rs_signer = RS256Signer.generate()
        rs_verifier = RS256Verifier(public_key_pem=rs_signer.public_key_pem())
        assert not rs_verifier.verify(
            decision_hash=mock_decision.decision_hash, signature=es_sig
        )
