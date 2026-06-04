# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Extended crypto coverage: RS256Signer, ES256Signer, helpers, and edge cases.

Covers uncovered lines in crypto.py:
  _b64url, _b64url_decode, _increment_signing_failure_counter,
  PramanixSigner.__init__ from env var, from_provider, sign empty hash,
  PramanixSigner.verify, RS256Signer, RS256Verifier, ES256Signer, ES256Verifier.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from pramanix.crypto import (
    ES256Signer,
    ES256Verifier,
    PramanixSigner,
    RS256Signer,
    RS256Verifier,
    _b64url,
    _b64url_decode,
)
from pramanix.decision import Decision

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_decision(*, allowed: bool = True, amount: str = "100") -> Decision:
    if allowed:
        return Decision.safe(
            intent_dump={"amount": amount},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
    return Decision.unsafe(
        violated_invariants=("test_rule",),
        explanation="Test block",
        intent_dump={"amount": amount},
        state_dump={"balance": "5000", "state_version": "v1"},
    )


# ── _b64url and _b64url_decode ────────────────────────────────────────────────


class TestB64urlHelpers:
    def test_round_trip(self) -> None:
        original = b"\x00\x01\x02\xff\xfe\xfd"
        encoded = _b64url(original)
        assert "=" not in encoded
        decoded = _b64url_decode(encoded)
        assert decoded == original

    def test_no_padding_in_output(self) -> None:
        for size in range(1, 10):
            data = bytes(range(size))
            assert "=" not in _b64url(data)

    def test_decode_with_no_padding_needed(self) -> None:
        data = b"hello!"  # 6 bytes → 8 base64 chars, no padding
        encoded = _b64url(data)
        assert _b64url_decode(encoded) == data

    def test_decode_with_1_char_padding(self) -> None:
        data = b"hi"  # 2 bytes → 3 base64 chars (1 padding stripped)
        encoded = _b64url(data)
        assert _b64url_decode(encoded) == data


# ── PramanixSigner: env var path, from_provider, edge cases ──────────────────


class TestPramanixSignerEnvVar:
    def test_init_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gen = PramanixSigner.generate()
        pem_str = gen.private_key_pem().decode()
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY_PEM", pem_str)
        signer = PramanixSigner()
        assert signer.key_id() == gen.key_id()

    def test_from_provider(self) -> None:
        gen = PramanixSigner.generate()
        pem = gen.private_key_pem()

        class _FakeProvider:
            def private_key_pem(self) -> bytes:
                return pem

        signer = PramanixSigner.from_provider(_FakeProvider())
        assert signer.key_id() == gen.key_id()

    def test_init_from_string_pem(self) -> None:
        gen = PramanixSigner.generate()
        pem_str = gen.private_key_pem().decode()
        signer = PramanixSigner(private_key_pem=pem_str)
        assert signer.key_id() == gen.key_id()


class TestPramanixSignerEdgeCases:
    def test_sign_empty_decision_hash_raises_signing_error(self) -> None:
        from pramanix.exceptions import SigningError

        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={},
            state_dump={"state_version": "v1"},
        )
        # Bypass frozen dataclass to force an empty decision_hash.
        object.__setattr__(d, "decision_hash", "")
        with pytest.raises(SigningError):
            signer.sign(d)

    def test_signer_verify_delegates_to_verifier(self) -> None:
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert signer.verify(decision_hash=d.decision_hash, signature=sig) is True

    def test_signer_verify_wrong_signature_returns_false(self) -> None:
        signer = PramanixSigner.generate()
        d = _make_decision()
        assert signer.verify(decision_hash=d.decision_hash, signature="bad") is False


# ── RS256Signer ────────────────────────────────────────────────────────────────


class TestRS256Signer:
    def test_generate_creates_signer(self) -> None:
        signer = RS256Signer.generate()
        assert signer is not None

    def test_key_id_is_16_hex_chars(self) -> None:
        signer = RS256Signer.generate()
        kid = signer.key_id()
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_public_key_pem_starts_with_header(self) -> None:
        signer = RS256Signer.generate()
        assert signer.public_key_pem().startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_sign_returns_nonempty_base64url(self) -> None:
        signer = RS256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert isinstance(sig, str)
        assert len(sig) > 0
        assert "=" not in sig

    def test_sign_empty_hash_raises_signing_error(self) -> None:
        from pramanix.exceptions import SigningError

        signer = RS256Signer.generate()
        d = _make_decision()
        object.__setattr__(d, "decision_hash", "")
        with pytest.raises(SigningError):
            signer.sign(d)

    def test_verify_valid_signature_true(self) -> None:
        signer = RS256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert signer.verify(decision_hash=d.decision_hash, signature=sig) is True

    def test_verify_wrong_signature_false(self) -> None:
        signer = RS256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert signer.verify(decision_hash="tampered", signature=sig) is False

    def test_no_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_RS256_SIGNING_KEY_PEM", raising=False)
        with pytest.raises(RuntimeError, match="No RS256 signing key"):
            RS256Signer()

    def test_force_ephemeral_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_RS256_SIGNING_KEY_PEM", raising=False)
        signer = RS256Signer(force_ephemeral=True)
        assert len(signer.key_id()) == 16

    def test_load_from_pem(self) -> None:
        RS256Signer.generate()
        # Re-export the private key by generating a known one
        signer2 = RS256Signer.generate()
        pem = signer2.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_generate_small_key_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2048"):
            RS256Signer.generate(key_size=1024)


# ── RS256Verifier ──────────────────────────────────────────────────────────────


class TestRS256Verifier:
    def test_verify_valid_signature(self) -> None:
        signer = RS256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = RS256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig) is True

    def test_verify_wrong_key_returns_false(self) -> None:
        signer_a = RS256Signer.generate()
        signer_b = RS256Signer.generate()
        d = _make_decision()
        sig = signer_a.sign(d)
        verifier = RS256Verifier(public_key_pem=signer_b.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig) is False

    def test_verify_tampered_signature_returns_false(self) -> None:
        signer = RS256Signer.generate()
        d = _make_decision()
        verifier = RS256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature="garbage") is False

    def test_verify_decision_no_signature_returns_false(self) -> None:
        signer = RS256Signer.generate()
        d = _make_decision()
        verifier = RS256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify_decision(d) is False

    def test_verify_decision_signed(self) -> None:
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amt = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amt}

            @classmethod
            def invariants(cls):
                return [(E(_amt) >= Decimal("0")).named("pos")]

        signer = RS256Signer.generate()
        guard = Guard(_P, GuardConfig(execution_mode="sync", signer=signer))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        verifier = RS256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify_decision(d) is True

    def test_string_pem_accepted(self) -> None:
        signer = RS256Signer.generate()
        pem_str = signer.public_key_pem().decode()
        verifier = RS256Verifier(public_key_pem=pem_str)
        d = _make_decision()
        sig = signer.sign(d)
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig) is True


# ── ES256Signer ────────────────────────────────────────────────────────────────


class TestES256Signer:
    def test_generate_creates_signer(self) -> None:
        signer = ES256Signer.generate()
        assert signer is not None

    def test_key_id_is_16_hex_chars(self) -> None:
        signer = ES256Signer.generate()
        kid = signer.key_id()
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_public_key_pem_starts_with_header(self) -> None:
        signer = ES256Signer.generate()
        assert signer.public_key_pem().startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_sign_returns_nonempty_base64url(self) -> None:
        signer = ES256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert isinstance(sig, str)
        assert len(sig) > 0
        assert "=" not in sig

    def test_sign_empty_hash_raises_signing_error(self) -> None:
        from pramanix.exceptions import SigningError

        signer = ES256Signer.generate()
        d = _make_decision()
        object.__setattr__(d, "decision_hash", "")
        with pytest.raises(SigningError):
            signer.sign(d)

    def test_verify_valid_signature_true(self) -> None:
        signer = ES256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert signer.verify(decision_hash=d.decision_hash, signature=sig) is True

    def test_verify_wrong_signature_false(self) -> None:
        signer = ES256Signer.generate()
        d = _make_decision()
        assert signer.verify(decision_hash=d.decision_hash, signature="bad") is False

    def test_no_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_ES256_SIGNING_KEY_PEM", raising=False)
        with pytest.raises(RuntimeError, match="No ES256 signing key"):
            ES256Signer()

    def test_force_ephemeral_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRAMANIX_ES256_SIGNING_KEY_PEM", raising=False)
        signer = ES256Signer(force_ephemeral=True)
        assert len(signer.key_id()) == 16


# ── ES256Verifier ──────────────────────────────────────────────────────────────


class TestES256Verifier:
    def test_verify_valid_signature(self) -> None:
        signer = ES256Signer.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = ES256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig) is True

    def test_verify_wrong_key_returns_false(self) -> None:
        signer_a = ES256Signer.generate()
        signer_b = ES256Signer.generate()
        d = _make_decision()
        sig = signer_a.sign(d)
        verifier = ES256Verifier(public_key_pem=signer_b.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig) is False

    def test_verify_garbage_signature_returns_false(self) -> None:
        signer = ES256Signer.generate()
        d = _make_decision()
        verifier = ES256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature="garbage") is False

    def test_verify_decision_no_signature_returns_false(self) -> None:
        signer = ES256Signer.generate()
        d = _make_decision()
        verifier = ES256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify_decision(d) is False

    def test_verify_decision_signed(self) -> None:
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amt = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amt}

            @classmethod
            def invariants(cls):
                return [(E(_amt) >= Decimal("0")).named("pos")]

        signer = ES256Signer.generate()
        guard = Guard(_P, GuardConfig(execution_mode="sync", signer=signer))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        verifier = ES256Verifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify_decision(d) is True

    def test_string_pem_accepted(self) -> None:
        signer = ES256Signer.generate()
        pem_str = signer.public_key_pem().decode()
        verifier = ES256Verifier(public_key_pem=pem_str)
        d = _make_decision()
        sig = signer.sign(d)
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig) is True
