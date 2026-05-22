# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""RS256 and ES256 asymmetric JWT verification tests.

Requires: pip install pramanix[crypto]  (cryptography>=41.0)
Skipped automatically when 'cryptography' is not installed.

Properties verified:
1. RS256 linker accepts a token signed with the configured private key.
2. RS256 linker rejects a token signed with a different private key.
3. ES256 linker accepts a token signed with the configured private key.
4. ES256 linker rejects a token signed with a different private key.
5. RS256 linker rejects a tampered payload (signature no longer matches).
6. ES256 linker rejects a tampered payload.
7. RS256 expiry / nbf enforcement still applies.
8. ES256 extracts correct IdentityClaims (sub, roles, exp, iat).
9. PEM string input (str) works as well as bytes input for public_key_pem.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from unittest.mock import patch

import pytest

pytest.importorskip(
    "cryptography", reason="cryptography not installed — skipping asymmetric JWT tests"
)

import redis.asyncio as aioredis
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1

from pramanix.identity.linker import (
    JWTAlgorithm,
    JWTExpiredError,
    JWTIdentityLinker,
    JWTVerificationError,
)
from pramanix.identity.redis_loader import RedisStateLoader

# ── Key-pair fixtures (module-scoped — generate once per test session) ─────────


@pytest.fixture(scope="module")
def rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


@pytest.fixture(scope="module")
def rsa_alt_key_pair():
    """A second, independent RSA key pair for wrong-key rejection tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


@pytest.fixture(scope="module")
def ec_key_pair():
    private_key = ec.generate_private_key(SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


@pytest.fixture(scope="module")
def ec_alt_key_pair():
    """A second, independent EC key pair for wrong-key rejection tests."""
    private_key = ec.generate_private_key(SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


# ── JWT token builders ─────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_rs256_token(payload: dict, private_key) -> str:
    header_b64 = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"


def _make_es256_token(payload: dict, private_key) -> str:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    header_b64 = _b64url(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    # cryptography produces DER; JWT ES256 requires raw R||S (RFC 7515 §A.3)
    sig_der = private_key.sign(signing_input, ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header_b64}.{payload_b64}.{_b64url(sig_raw)}"


def _valid_payload(sub: str = "user-asymmetric", exp_offset: int = 3600) -> dict:
    now = int(time.time())
    return {"sub": sub, "roles": ["agent"], "iat": now, "exp": now + exp_offset}


def _make_noop_loader() -> RedisStateLoader:
    # These tests never call load() — a placeholder URL is sufficient
    return RedisStateLoader(
        redis_client=aioredis.from_url("redis://127.0.0.1:6379/0"), key_prefix="pramanix:state:"
    )


# ── TestRS256Linker ────────────────────────────────────────────────────────────


class TestRS256Linker:
    """RS256: real RSA-2048 key generation, signing, and verification."""

    def test_accepts_valid_rs256_token(self, rsa_key_pair) -> None:
        private_key, public_pem = rsa_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
        )
        token = _make_rs256_token(_valid_payload(sub="alice"), private_key)
        claims = linker._verify_token(token)
        assert claims.sub == "alice"
        assert claims.roles == ["agent"]

    def test_rejects_token_signed_with_different_key(self, rsa_key_pair, rsa_alt_key_pair) -> None:
        _private_key, public_pem = rsa_key_pair
        alt_private, _alt_public = rsa_alt_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
        )
        # Signed with the *alternative* key — should be rejected
        token = _make_rs256_token(_valid_payload(), alt_private)
        with pytest.raises(JWTVerificationError, match="RS256 signature"):
            linker._verify_token(token)

    def test_rejects_tampered_payload(self, rsa_key_pair) -> None:
        private_key, public_pem = rsa_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
        )
        token = _make_rs256_token(_valid_payload(sub="alice"), private_key)
        header_b64, payload_b64, sig_b64 = token.split(".")
        # Replace payload with a tampered version (different sub)
        tampered_payload = _b64url(json.dumps(_valid_payload(sub="attacker")).encode())
        tampered_token = f"{header_b64}.{tampered_payload}.{sig_b64}"
        with pytest.raises(JWTVerificationError, match="RS256 signature"):
            linker._verify_token(tampered_token)

    def test_rejects_expired_token(self, rsa_key_pair) -> None:
        private_key, public_pem = rsa_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
            clock_skew_seconds=0,
        )
        token = _make_rs256_token(_valid_payload(exp_offset=-7200), private_key)
        with pytest.raises(JWTExpiredError, match="expired"):
            linker._verify_token(token)

    def test_accepts_public_key_as_string(self, rsa_key_pair) -> None:
        private_key, public_pem_bytes = rsa_key_pair
        # Pass PEM as str — both bytes and str are supported
        public_pem_str = public_pem_bytes.decode("utf-8")
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem_str,
            algorithm=JWTAlgorithm.RS256,
        )
        token = _make_rs256_token(_valid_payload(sub="str-pem-user"), private_key)
        claims = linker._verify_token(token)
        assert claims.sub == "str-pem-user"

    def test_claims_populated_correctly(self, rsa_key_pair) -> None:
        private_key, public_pem = rsa_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
        )
        payload = _valid_payload(sub="detailed-user")
        payload["custom"] = "extra"
        token = _make_rs256_token(payload, private_key)
        claims = linker._verify_token(token)
        assert claims.sub == "detailed-user"
        assert claims.roles == ["agent"]
        assert claims.raw["custom"] == "extra"
        assert claims.exp > 0
        assert claims.iat > 0

    def test_empty_sub_rejected(self, rsa_key_pair) -> None:
        private_key, public_pem = rsa_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
        )
        payload = _valid_payload()
        payload["sub"] = ""  # empty sub
        token = _make_rs256_token(payload, private_key)
        with pytest.raises(JWTVerificationError, match="sub"):
            linker._verify_token(token)

    def test_malformed_pem_raises_at_construction(self) -> None:
        with pytest.raises(ValueError, match="Invalid public key PEM"):
            JWTIdentityLinker(
                state_loader=_make_noop_loader(),
                public_key_pem=b"not a valid pem",
                algorithm=JWTAlgorithm.RS256,
            )


# ── TestES256Linker ────────────────────────────────────────────────────────────


class TestES256Linker:
    """ES256: real EC P-256 key generation, signing, and verification."""

    def test_accepts_valid_es256_token(self, ec_key_pair) -> None:
        private_key, public_pem = ec_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.ES256,
        )
        token = _make_es256_token(_valid_payload(sub="ec-user"), private_key)
        claims = linker._verify_token(token)
        assert claims.sub == "ec-user"
        assert claims.roles == ["agent"]

    def test_rejects_token_signed_with_different_ec_key(self, ec_key_pair, ec_alt_key_pair) -> None:
        _private_key, public_pem = ec_key_pair
        alt_private, _alt_public = ec_alt_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.ES256,
        )
        token = _make_es256_token(_valid_payload(), alt_private)
        with pytest.raises(JWTVerificationError, match="ES256 signature"):
            linker._verify_token(token)

    def test_rejects_tampered_payload(self, ec_key_pair) -> None:
        private_key, public_pem = ec_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.ES256,
        )
        token = _make_es256_token(_valid_payload(sub="alice"), private_key)
        header_b64, _payload_b64, sig_b64 = token.split(".")
        tampered_payload = _b64url(json.dumps(_valid_payload(sub="attacker")).encode())
        tampered_token = f"{header_b64}.{tampered_payload}.{sig_b64}"
        with pytest.raises(JWTVerificationError, match="ES256 signature"):
            linker._verify_token(tampered_token)

    def test_rejects_expired_token(self, ec_key_pair) -> None:
        private_key, public_pem = ec_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.ES256,
            clock_skew_seconds=0,
        )
        token = _make_es256_token(_valid_payload(exp_offset=-3600), private_key)
        with pytest.raises(JWTExpiredError, match="expired"):
            linker._verify_token(token)

    def test_accepts_public_key_as_string(self, ec_key_pair) -> None:
        private_key, public_pem_bytes = ec_key_pair
        public_pem_str = public_pem_bytes.decode("utf-8")
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem_str,
            algorithm=JWTAlgorithm.ES256,
        )
        token = _make_es256_token(_valid_payload(sub="str-ec-user"), private_key)
        claims = linker._verify_token(token)
        assert claims.sub == "str-ec-user"

    def test_nbf_not_yet_valid_rejected(self, ec_key_pair) -> None:
        private_key, public_pem = ec_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.ES256,
            clock_skew_seconds=0,
        )
        payload = _valid_payload()
        payload["nbf"] = int(time.time()) + 7200  # valid only in 2h
        token = _make_es256_token(payload, private_key)
        with pytest.raises(JWTVerificationError, match="not yet valid"):
            linker._verify_token(token)

    def test_malformed_pem_raises_at_construction(self) -> None:
        with pytest.raises(ValueError, match="Invalid public key PEM"):
            JWTIdentityLinker(
                state_loader=_make_noop_loader(),
                public_key_pem=b"-----BEGIN PUBLIC KEY-----\nbaddata\n-----END PUBLIC KEY-----\n",
                algorithm=JWTAlgorithm.ES256,
            )


# ── ImportError coverage (cryptography package absent) ────────────────────────


class TestCryptographyImportErrors:
    """Cover ImportError handler paths in linker.py.

    Uses sys.modules patching to simulate 'cryptography' being absent at the
    point where the import is attempted, without actually uninstalling the package.
    Exercises lines 269-272 (_verify_rs256), 285-288 (_verify_es256), and
    311-315 (_load_and_validate_public_key).
    """

    def test_verify_rs256_raises_on_missing_cryptography(self, rsa_key_pair) -> None:
        private_key, public_pem = rsa_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.RS256,
        )
        with (
            patch.dict(sys.modules, {"cryptography.exceptions": None}),
            pytest.raises(ImportError, match="RS256 requires the 'cryptography' package"),
        ):
            linker._verify_rs256(b"header.payload", "AAAA")

    def test_verify_es256_raises_on_missing_cryptography(self, ec_key_pair) -> None:
        private_key, public_pem = ec_key_pair
        linker = JWTIdentityLinker(
            state_loader=_make_noop_loader(),
            public_key_pem=public_pem,
            algorithm=JWTAlgorithm.ES256,
        )
        with (
            patch.dict(sys.modules, {"cryptography.exceptions": None}),
            pytest.raises(ImportError, match="ES256 requires the 'cryptography' package"),
        ):
            linker._verify_es256(b"header.payload", "AAAA")

    def test_load_and_validate_raises_on_missing_cryptography(self) -> None:
        with (
            patch.dict(
                sys.modules,
                {"cryptography.hazmat.primitives.serialization": None},
            ),
            pytest.raises(ImportError, match="requires the 'cryptography' package"),
        ):
            JWTIdentityLinker._load_and_validate_public_key(
                JWTAlgorithm.RS256,
                b"-----BEGIN PUBLIC KEY-----\ndummy\n-----END PUBLIC KEY-----\n",
            )
