# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Ed25519 cryptographic signing (Phase 11.2).

Critical properties verified:
1. Signatures are valid (signer produces, verifier accepts)
2. Wrong key fails verification (key binding)
3. Tampered hash fails verification (integrity)
4. Tampered signature fails verification
5. 1000 sign-verify cycles all pass (reliability)
6. Signing is deterministic (same hash = same signature for Ed25519)
"""
from __future__ import annotations

from decimal import Decimal

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from pramanix.crypto import PramanixSigner, PramanixVerifier
from pramanix.decision import Decision


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_decision(allowed: bool = True, amount: str = "100") -> Decision:
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


# ── PramanixSigner ────────────────────────────────────────────────────────────


class TestPramanixSigner:
    def test_generate_creates_signer(self):
        signer = PramanixSigner.generate()
        assert signer is not None

    def test_key_id_is_16_hex_chars(self):
        signer = PramanixSigner.generate()
        kid = signer.key_id()
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_public_key_pem_starts_with_pem_header(self):
        signer = PramanixSigner.generate()
        pem = signer.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_private_key_pem_starts_with_pem_header(self):
        signer = PramanixSigner.generate()
        pem = signer.private_key_pem()
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_sign_returns_nonempty_string(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_sign_returns_base64url_encoded(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        # base64url: no + / = characters
        assert "+" not in sig
        assert "/" not in sig
        assert "=" not in sig

    def test_ed25519_signature_is_deterministic(self):
        """Ed25519 signing is deterministic — same hash always same sig."""
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig1 = signer.sign(d)
        sig2 = signer.sign(d)
        assert sig1 == sig2

    def test_two_different_decisions_produce_different_signatures(self):
        signer = PramanixSigner.generate()
        d1 = _make_decision(amount="100")
        d2 = _make_decision(amount="200")
        assert signer.sign(d1) != signer.sign(d2)

    def test_key_loaded_from_pem_produces_same_key_id(self):
        signer1 = PramanixSigner.generate()
        pem = signer1.private_key_pem()
        signer2 = PramanixSigner(private_key_pem=pem)
        assert signer1.key_id() == signer2.key_id()

    def test_different_generated_keys_have_different_key_ids(self):
        s1 = PramanixSigner.generate()
        s2 = PramanixSigner.generate()
        assert s1.key_id() != s2.key_id()


# ── PramanixVerifier ──────────────────────────────────────────────────────────


class TestPramanixVerifier:
    def test_verify_valid_signature_returns_true(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig)

    def test_verify_wrong_key_returns_false(self):
        signer_a = PramanixSigner.generate()
        signer_b = PramanixSigner.generate()
        d = _make_decision()
        sig = signer_a.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer_b.public_key_pem())
        assert not verifier.verify(decision_hash=d.decision_hash, signature=sig)

    def test_verify_tampered_hash_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        tampered_hash = d.decision_hash[:-1] + (
            "0" if d.decision_hash[-1] != "0" else "1"
        )
        assert not verifier.verify(decision_hash=tampered_hash, signature=sig)

    def test_verify_tampered_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        tampered_sig = sig[:-4] + "AAAA"
        assert not verifier.verify(decision_hash=d.decision_hash, signature=tampered_sig)

    def test_verify_empty_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert not verifier.verify(decision_hash=d.decision_hash, signature="")

    def test_verify_garbage_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert not verifier.verify(
            decision_hash=d.decision_hash,
            signature="not_a_real_signature_at_all",
        )

    def test_verify_decision_full_pipeline(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        object.__setattr__(d, "signature", sig)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify_decision(d)

    def test_verify_decision_missing_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()  # No signature set
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert not verifier.verify_decision(d)


# ── Reliability: 1000 sign-verify cycles ─────────────────────────────────────


class TestSignVerifyReliability:
    def test_1000_sign_verify_cycles_all_pass(self):
        """All 1000 sign-verify cycles must succeed with correct key."""
        signer = PramanixSigner.generate()
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())

        failures = []
        for i in range(1000):
            d = _make_decision(
                allowed=(i % 2 == 0),
                amount=str(i + 1),
            )
            sig = signer.sign(d)
            ok = verifier.verify(decision_hash=d.decision_hash, signature=sig)
            if not ok:
                failures.append(i)

        assert len(failures) == 0, (
            f"Sign-verify failed for {len(failures)} out of 1000 decisions: "
            f"indices {failures[:10]}"
        )

    def test_1000_cycles_with_wrong_key_all_fail(self):
        """All 1000 sign-verify cycles must FAIL with wrong key."""
        signer = PramanixSigner.generate()
        wrong_signer = PramanixSigner.generate()
        verifier = PramanixVerifier(public_key_pem=wrong_signer.public_key_pem())

        wrong_passes = []
        for i in range(1000):
            d = _make_decision(amount=str(i + 1))
            sig = signer.sign(d)
            ok = verifier.verify(decision_hash=d.decision_hash, signature=sig)
            if ok:
                wrong_passes.append(i)

        assert len(wrong_passes) == 0, (
            f"Wrong-key verification PASSED for {len(wrong_passes)} decisions. "
            "This is a critical security failure."
        )


# ── Guard integration ─────────────────────────────────────────────────────────


class TestGuardSigningIntegration:
    def test_guard_signs_decision_when_signer_configured(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0")).named("pos").explain("Positive")
                ]

        signer = PramanixSigner.generate()
        guard = Guard(_P, GuardConfig(execution_mode="sync", signer=signer))

        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.signature is not None
        assert len(d.signature) > 0
        assert d.public_key_id == signer.key_id()

    def test_guard_does_not_sign_when_no_signer(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0")).named("pos").explain("Positive")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.signature is None

    def test_guard_signed_decision_verifies(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount, "balance": _balance}

            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sb")
                    .explain("Insufficient")
                ]

        signer = PramanixSigner.generate()
        guard = Guard(_P, GuardConfig(execution_mode="sync", signer=signer))

        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )

        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(
            decision_hash=d.decision_hash,
            signature=d.signature,
        )
