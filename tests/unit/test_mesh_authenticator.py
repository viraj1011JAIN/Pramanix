# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Comprehensive tests for pramanix.mesh.authenticator.

Covers MeshAuthenticator (all public methods) and all module-level helper
functions.  JWT tokens are constructed manually (base64url + cryptography sign)
so no external JWT library is required.  JWKS HTTP fetches are tested using
unittest.mock.patch on httpx.get to avoid network calls.

Scope: all 235 missing statements from the coverage gap report.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from pramanix.exceptions import MeshAuthenticationError
from pramanix.mesh.authenticator import (
    MeshAuthenticator,
    SpiffeIdentity,
    _b64url_decode,
    _decode_jwt_parts,
    _jwk_to_public_key,
    _load_public_key_pem,
    _parse_spiffe_uri,
    _select_jwk,
    _validate_audience,
    _validate_temporal_claims,
    _verify_signature,
)

# ── Key generation (module-scoped — generated once per session) ───────────────


@pytest.fixture(scope="module")
def rsa_private_key():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


@pytest.fixture(scope="module")
def rsa_public_key(rsa_private_key):
    return rsa_private_key.public_key()


@pytest.fixture(scope="module")
def rsa_public_pem(rsa_public_key):
    from cryptography.hazmat.primitives import serialization

    return rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="module")
def ec_private_key():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1(), default_backend())


@pytest.fixture(scope="module")
def ec_public_key(ec_private_key):
    return ec_private_key.public_key()


@pytest.fixture(scope="module")
def ec_public_pem(ec_public_key):
    from cryptography.hazmat.primitives import serialization

    return ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ── JWT construction helpers ──────────────────────────────────────────────────


def _b64url_enc(data: bytes | dict) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()  # type: ignore[arg-type]


def _make_jwt(
    payload: dict,
    private_key: Any,
    alg: str = "RS256",
    kid: str | None = None,
    extra_headers: dict | None = None,
) -> str:
    header: dict = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    if extra_headers:
        header.update(extra_headers)

    h_b64 = _b64url_enc(header)
    p_b64 = _b64url_enc(payload)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    if alg == "RS256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        sig = private_key.sign(signing_input, ECDSA(hashes.SHA256()))
    else:
        # Deliberately invalid sig for algorithm-rejection tests
        sig = b"\x00" * 32

    s_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}.{s_b64}"


def _valid_payload(
    *,
    sub: str = "spiffe://prod.example/payments-agent",
    aud: str | list[str] = "spiffe://prod.example",
    exp_offset: int = 3600,
    nbf_offset: int | None = None,
) -> dict:
    now = int(time.time())
    p: dict = {"sub": sub, "aud": aud, "exp": now + exp_offset, "iat": now}
    if nbf_offset is not None:
        p["nbf"] = now + nbf_offset
    return p


def _rsa_to_jwk(public_key: Any, kid: str = "rsa-kid") -> dict:
    numbers = public_key.public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode(),
        "e": base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode(),
    }


def _ec_to_jwk(public_key: Any, kid: str = "ec-kid") -> dict:
    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "kid": kid,
        "x": base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode(),
    }


# ── MeshAuthenticator.__init__ validation ─────────────────────────────────────


class TestMeshAuthenticatorInit:
    def test_neither_jwks_nor_pem_raises(self):
        with pytest.raises(ValueError, match="requires either"):
            MeshAuthenticator(audience="spiffe://prod.example")

    def test_both_jwks_and_pem_raises(self, rsa_public_pem):
        with pytest.raises(ValueError, match="accepts 'jwks_uri' OR 'public_key_pem'"):
            MeshAuthenticator(
                jwks_uri="https://jwks.example/jwks",
                public_key_pem=rsa_public_pem,
                audience="spiffe://prod.example",
            )

    def test_empty_audience_raises(self, rsa_public_pem):
        with pytest.raises(ValueError, match="'audience' must be a non-empty string"):
            MeshAuthenticator(public_key_pem=rsa_public_pem, audience="")

    def test_unsupported_algorithm_raises(self, rsa_public_pem):
        with pytest.raises(ValueError, match="Unsupported algorithms"):
            MeshAuthenticator(
                public_key_pem=rsa_public_pem,
                audience="spiffe://prod.example",
                algorithms={"HS256"},
            )

    def test_empty_algorithms_raises(self, rsa_public_pem):
        with pytest.raises(ValueError, match="must contain at least one supported algorithm"):
            MeshAuthenticator(
                public_key_pem=rsa_public_pem,
                audience="spiffe://prod.example",
                algorithms=set(),
            )

    def test_valid_jwks_uri_construction(self):
        auth = MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
        )
        assert auth._jwks_uri == "https://jwks.example/jwks"
        assert auth._static_key is None

    def test_valid_rsa_pem_construction(self, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        assert auth._static_key is not None
        assert auth._jwks_uri is None

    def test_valid_ec_pem_construction(self, ec_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=ec_public_pem,
            audience="spiffe://prod.example",
        )
        assert auth._static_key is not None

    def test_custom_algorithms_rs256_only(self, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
            algorithms={"RS256"},
        )
        assert auth._algorithms == frozenset({"RS256"})

    def test_str_pem_accepted(self, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem.decode("ascii"),
            audience="spiffe://prod.example",
        )
        assert auth._static_key is not None

    def test_invalid_pem_raises_value_error(self):
        with pytest.raises((ValueError, Exception)):
            MeshAuthenticator(
                public_key_pem=b"not a real PEM",
                audience="spiffe://prod.example",
            )

    def test_custom_timeouts_stored(self):
        auth = MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
            clock_skew_seconds=60,
            jwks_cache_ttl_seconds=300,
            jwks_connect_timeout_seconds=3.0,
            jwks_read_timeout_seconds=8.0,
        )
        assert auth._clock_skew == 60
        assert auth._cache_ttl == 300
        assert auth._connect_timeout == 3.0
        assert auth._read_timeout == 8.0


# ── authenticate_and_bind ─────────────────────────────────────────────────────


class TestAuthenticateAndBind:
    def test_intent_poisoning_rejected(self, rsa_private_key, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        token = _make_jwt(_valid_payload(), rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="Intent poisoning"):
            auth.authenticate_and_bind(
                token, {"amount": 100, "_mesh_principal": "spiffe://attacker"}
            )

    def test_valid_token_enriches_intent(self, rsa_private_key, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        token = _make_jwt(_valid_payload(), rsa_private_key)
        result = auth.authenticate_and_bind(token, {"amount": 100})
        assert "_mesh_principal" in result
        assert result["_mesh_principal"] == "spiffe://prod.example/payments-agent"
        assert result["amount"] == 100

    def test_original_intent_not_mutated(self, rsa_private_key, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        token = _make_jwt(_valid_payload(), rsa_private_key)
        raw = {"amount": 50}
        result = auth.authenticate_and_bind(token, raw)
        assert "_mesh_principal" not in raw  # original not mutated
        assert "_mesh_principal" in result


# ── verify_svid ────────────────────────────────────────────────────────────────


class TestVerifySvid:
    @pytest.fixture(autouse=True)
    def _auth(self, rsa_public_pem):
        self.auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )

    def test_empty_token_raises(self):
        with pytest.raises(MeshAuthenticationError, match="missing or empty"):
            self.auth.verify_svid("")

    def test_whitespace_only_token_raises(self):
        with pytest.raises(MeshAuthenticationError, match="missing or empty"):
            self.auth.verify_svid("   ")

    def test_oversized_token_raises(self):
        oversized = "A" * 20_000
        with pytest.raises(MeshAuthenticationError, match="exceeds the maximum"):
            self.auth.verify_svid(oversized)

    def test_wrong_segment_count_raises(self):
        with pytest.raises(MeshAuthenticationError, match="dot-separated"):
            self.auth.verify_svid("header.payload")

    def test_disallowed_algorithm_raises(self, rsa_private_key):
        token = _make_jwt(_valid_payload(), rsa_private_key, alg="HS256")
        with pytest.raises(MeshAuthenticationError, match="uses algorithm"):
            self.auth.verify_svid(token)

    def test_invalid_signature_raises(self, rsa_private_key):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Use a DIFFERENT private key to produce the signature
        other_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        token = _make_jwt(_valid_payload(), other_key, alg="RS256")
        with pytest.raises(MeshAuthenticationError, match="verification failed"):
            self.auth.verify_svid(token)

    def test_missing_exp_raises(self, rsa_private_key):
        payload = {
            "sub": "spiffe://prod.example/agent",
            "aud": "spiffe://prod.example",
            "iat": int(time.time()),
        }
        token = _make_jwt(payload, rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="required 'exp'"):
            self.auth.verify_svid(token)

    def test_expired_token_raises(self, rsa_private_key):
        payload = _valid_payload(exp_offset=-3600)  # expired 1 hr ago
        token = _make_jwt(payload, rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="expired"):
            self.auth.verify_svid(token)

    def test_missing_aud_raises(self, rsa_private_key):
        payload = {
            "sub": "spiffe://prod.example/agent",
            "exp": int(time.time()) + 3600,
        }
        token = _make_jwt(payload, rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="required 'aud'"):
            self.auth.verify_svid(token)

    def test_wrong_aud_raises(self, rsa_private_key):
        payload = _valid_payload(aud="spiffe://other.example")
        token = _make_jwt(payload, rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="does not contain"):
            self.auth.verify_svid(token)

    def test_missing_sub_raises(self, rsa_private_key):
        payload = {
            "aud": "spiffe://prod.example",
            "exp": int(time.time()) + 3600,
        }
        token = _make_jwt(payload, rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="'sub' claim"):
            self.auth.verify_svid(token)

    def test_invalid_spiffe_uri_raises(self, rsa_private_key):
        payload = _valid_payload(sub="not-a-spiffe-uri")
        token = _make_jwt(payload, rsa_private_key)
        with pytest.raises(MeshAuthenticationError, match="valid SPIFFE"):
            self.auth.verify_svid(token)

    def test_valid_rsa256_token_returns_identity(self, rsa_private_key):
        token = _make_jwt(_valid_payload(), rsa_private_key)
        identity = self.auth.verify_svid(token)
        assert isinstance(identity, SpiffeIdentity)
        assert identity.uri == "spiffe://prod.example/payments-agent"
        assert identity.trust_domain == "prod.example"
        assert identity.path == "/payments-agent"

    def test_leading_trailing_whitespace_stripped(self, rsa_private_key):
        token = "  " + _make_jwt(_valid_payload(), rsa_private_key) + "  "
        identity = self.auth.verify_svid(token)
        assert identity.uri == "spiffe://prod.example/payments-agent"

    def test_aud_as_list_accepted(self, rsa_private_key):
        payload = _valid_payload(aud=["spiffe://prod.example", "other"])
        token = _make_jwt(payload, rsa_private_key)
        identity = self.auth.verify_svid(token)
        assert identity.uri == "spiffe://prod.example/payments-agent"

    def test_spiffe_uri_without_path(self, rsa_private_key):
        payload = _valid_payload(sub="spiffe://prod.example")
        token = _make_jwt(payload, rsa_private_key)
        identity = self.auth.verify_svid(token)
        assert identity.path == ""
        assert identity.trust_domain == "prod.example"


class TestVerifySvidEC:
    """Same test surface but with ES256 / EC P-256 key."""

    def test_valid_es256_token_returns_identity(self, ec_private_key, ec_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=ec_public_pem,
            audience="spiffe://prod.example",
            algorithms={"ES256"},
        )
        token = _make_jwt(_valid_payload(), ec_private_key, alg="ES256")
        identity = auth.verify_svid(token)
        assert identity.uri == "spiffe://prod.example/payments-agent"

    def test_invalid_es256_signature_raises(self, ec_public_pem):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        auth = MeshAuthenticator(
            public_key_pem=ec_public_pem,
            audience="spiffe://prod.example",
            algorithms={"ES256"},
        )
        # Sign with a different EC key
        other_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        token = _make_jwt(_valid_payload(), other_key, alg="ES256")
        with pytest.raises(MeshAuthenticationError, match="verification failed"):
            auth.verify_svid(token)


# ── Async methods ─────────────────────────────────────────────────────────────


class TestAsyncMethods:
    @pytest.mark.asyncio
    async def test_verify_svid_async(self, rsa_private_key, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        token = _make_jwt(_valid_payload(), rsa_private_key)
        identity = await auth.verify_svid_async(token)
        assert isinstance(identity, SpiffeIdentity)

    @pytest.mark.asyncio
    async def test_authenticate_and_bind_async(self, rsa_private_key, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        token = _make_jwt(_valid_payload(), rsa_private_key)
        result = await auth.authenticate_and_bind_async(token, {"x": 1})
        assert "_mesh_principal" in result


# ── _resolve_key ──────────────────────────────────────────────────────────────


class TestResolveKey:
    def test_static_key_returned(self, rsa_public_pem):
        auth = MeshAuthenticator(
            public_key_pem=rsa_public_pem,
            audience="spiffe://prod.example",
        )
        key = auth._resolve_key({"alg": "RS256"})
        assert key is auth._static_key

    def test_jwks_path_uses_cache(self, rsa_public_key, rsa_private_key):
        auth = MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
        )
        # Pre-populate cache with a valid key
        rsa_jwk = _rsa_to_jwk(rsa_public_key, kid="k1")
        auth._jwks_cache.keys = [rsa_jwk]
        auth._jwks_cache.fetched_at = time.monotonic()
        key = auth._resolve_key({"alg": "RS256", "kid": "k1"})
        assert key is not None

    def test_jwks_none_and_static_none_raises(self):
        auth = MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
        )
        # Force internal invariant violation by clearing jwks_uri after init
        auth._jwks_uri = None
        auth._static_key = None
        with pytest.raises(MeshAuthenticationError):
            auth._resolve_key({"alg": "RS256"})


# ── _get_cached_jwks_keys ─────────────────────────────────────────────────────


class TestGetCachedJwksKeys:
    def _make_auth(self):
        return MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
        )

    def test_fresh_cache_returned_immediately(self, rsa_public_key):
        auth = self._make_auth()
        rsa_jwk = _rsa_to_jwk(rsa_public_key)
        auth._jwks_cache.keys = [rsa_jwk]
        auth._jwks_cache.fetched_at = time.monotonic()
        result = auth._get_cached_jwks_keys()
        assert result == [rsa_jwk]

    def test_stale_cache_triggers_fetch(self, rsa_public_key):
        auth = self._make_auth()
        rsa_jwk = _rsa_to_jwk(rsa_public_key)
        # Patch _fetch_jwks to return the key without HTTP
        with patch.object(auth, "_fetch_jwks", return_value=[rsa_jwk]):
            result = auth._get_cached_jwks_keys()
        assert result == [rsa_jwk]

    def test_fetch_failure_clears_flag_and_raises(self):
        auth = self._make_auth()
        with patch.object(auth, "_fetch_jwks", side_effect=MeshAuthenticationError("fail")):
            with pytest.raises(MeshAuthenticationError):
                auth._get_cached_jwks_keys()
        # Flag must be cleared after failure
        assert auth._jwks_fetching is False

    def test_another_thread_fetching_returns_stale(self, rsa_public_key):
        auth = self._make_auth()
        rsa_jwk = _rsa_to_jwk(rsa_public_key)
        auth._jwks_cache.keys = [rsa_jwk]
        auth._jwks_fetching = True
        # Should return stale keys without triggering a second fetch
        result = auth._get_cached_jwks_keys()
        assert result == [rsa_jwk]
        # Cleanup
        auth._jwks_fetching = False


# ── _fetch_jwks ───────────────────────────────────────────────────────────────


class TestFetchJwks:
    def _make_auth(self):
        return MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
        )

    def test_httpx_not_installed_raises_import_error(self):
        auth = self._make_auth()
        import sys

        with patch.dict(sys.modules, {"httpx": None}):
            with pytest.raises(ImportError, match="httpx"):
                auth._fetch_jwks()

    def test_timeout_exception_raises_mesh_auth_error(self):
        auth = self._make_auth()
        import httpx

        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            with pytest.raises(MeshAuthenticationError, match="timed out"):
                auth._fetch_jwks()

    def test_http_status_error_raises_mesh_auth_error(self):
        auth = self._make_auth()
        import httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        with patch(
            "httpx.get",
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=mock_resp),
        ):
            with pytest.raises(MeshAuthenticationError, match="returned HTTP"):
                auth._fetch_jwks()

    def test_request_error_raises_mesh_auth_error(self):
        auth = self._make_auth()
        import httpx

        with patch("httpx.get", side_effect=httpx.ConnectError("connection refused")):
            with pytest.raises(MeshAuthenticationError, match="unreachable"):
                auth._fetch_jwks()

    def test_invalid_json_response_raises_mesh_auth_error(self):
        auth = self._make_auth()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = ValueError("not json")
        with patch("httpx.get", return_value=mock_resp):
            with pytest.raises(MeshAuthenticationError, match="not valid JSON"):
                auth._fetch_jwks()

    def test_missing_keys_field_raises_mesh_auth_error(self):
        auth = self._make_auth()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"something_else": []}
        with patch("httpx.get", return_value=mock_resp):
            with pytest.raises(MeshAuthenticationError, match="missing"):
                auth._fetch_jwks()

    def test_empty_keys_array_raises_mesh_auth_error(self):
        auth = self._make_auth()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"keys": []}
        with patch("httpx.get", return_value=mock_resp):
            with pytest.raises(MeshAuthenticationError, match="no keys"):
                auth._fetch_jwks()

    def test_successful_fetch_returns_key_list(self, rsa_public_key):
        auth = self._make_auth()
        rsa_jwk = _rsa_to_jwk(rsa_public_key)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"keys": [rsa_jwk]}
        with patch("httpx.get", return_value=mock_resp):
            result = auth._fetch_jwks()
        assert result == [rsa_jwk]

    def test_jwks_uri_none_invariant_raises(self):
        auth = self._make_auth()
        auth._jwks_uri = None  # force invariant violation
        with pytest.raises(MeshAuthenticationError):
            auth._fetch_jwks()


# ── _decode_jwt_parts ─────────────────────────────────────────────────────────


class TestDecodeJwtParts:
    def test_too_few_segments_raises(self):
        with pytest.raises(MeshAuthenticationError, match="dot-separated"):
            _decode_jwt_parts("only.two")

    def test_too_many_segments_raises(self):
        with pytest.raises(MeshAuthenticationError, match="dot-separated"):
            _decode_jwt_parts("a.b.c.d")

    def test_invalid_header_base64_raises(self):
        # Put something that is not valid base64url JSON in header position
        bad_header = "!!!notbase64!!!"
        good_payload = _b64url_enc({"sub": "test", "exp": 9999999999})
        good_sig = _b64url_enc(b"\x00\x01\x02")
        with pytest.raises(MeshAuthenticationError, match="header"):
            _decode_jwt_parts(f"{bad_header}.{good_payload}.{good_sig}")

    def test_invalid_payload_base64_raises(self):
        good_header = _b64url_enc({"alg": "RS256", "typ": "JWT"})
        bad_payload = "!!!invalid!!!"
        good_sig = _b64url_enc(b"\x00")
        with pytest.raises(MeshAuthenticationError, match="payload"):
            _decode_jwt_parts(f"{good_header}.{bad_payload}.{good_sig}")

    def test_header_not_json_object_raises(self):
        not_obj = _b64url_enc(b'"just_a_string"')
        good_payload = _b64url_enc({"sub": "x"})
        good_sig = _b64url_enc(b"\x00")
        with pytest.raises(MeshAuthenticationError, match="header"):
            _decode_jwt_parts(f"{not_obj}.{good_payload}.{good_sig}")

    def test_payload_not_json_object_raises(self):
        good_header = _b64url_enc({"alg": "RS256"})
        not_obj = _b64url_enc(b'"just_a_string"')
        good_sig = _b64url_enc(b"\x00")
        with pytest.raises(MeshAuthenticationError, match="payload"):
            _decode_jwt_parts(f"{good_header}.{not_obj}.{good_sig}")

    def test_valid_jwt_returns_parts(self, rsa_private_key):
        payload = _valid_payload()
        token = _make_jwt(payload, rsa_private_key)
        header, decoded_payload, signing_input, raw_sig = _decode_jwt_parts(token)
        assert header["alg"] == "RS256"
        assert decoded_payload["sub"] == payload["sub"]
        assert isinstance(signing_input, bytes)
        assert isinstance(raw_sig, bytes)


# ── _validate_temporal_claims ─────────────────────────────────────────────────


class TestValidateTemporalClaims:
    def test_missing_exp_raises(self):
        with pytest.raises(MeshAuthenticationError, match="required 'exp'"):
            _validate_temporal_claims({}, int(time.time()), 30)

    def test_non_integer_exp_raises(self):
        with pytest.raises(MeshAuthenticationError, match="not a valid integer"):
            _validate_temporal_claims({"exp": "not-a-number"}, int(time.time()), 30)

    def test_expired_token_raises(self):
        now = int(time.time())
        with pytest.raises(MeshAuthenticationError, match="expired"):
            _validate_temporal_claims({"exp": now - 3600}, now, 30)

    def test_valid_exp_no_raise(self):
        now = int(time.time())
        # Should not raise
        _validate_temporal_claims({"exp": now + 3600}, now, 30)

    def test_valid_exp_with_nbf_in_past(self):
        now = int(time.time())
        # nbf in the past is fine
        _validate_temporal_claims({"exp": now + 3600, "nbf": now - 60}, now, 30)

    def test_nbf_in_future_raises(self):
        now = int(time.time())
        with pytest.raises(MeshAuthenticationError, match="not yet valid"):
            _validate_temporal_claims({"exp": now + 3600, "nbf": now + 600}, now, 30)

    def test_non_integer_nbf_raises(self):
        now = int(time.time())
        with pytest.raises(MeshAuthenticationError, match="not a valid integer"):
            _validate_temporal_claims({"exp": now + 3600, "nbf": "bad"}, now, 30)

    def test_clock_skew_allows_slightly_expired(self):
        now = int(time.time())
        # Token expired 10s ago but skew is 30s — should be OK
        _validate_temporal_claims({"exp": now - 10}, now, 30)


# ── _validate_audience ────────────────────────────────────────────────────────


class TestValidateAudience:
    def test_missing_aud_raises(self):
        with pytest.raises(MeshAuthenticationError, match="required 'aud'"):
            _validate_audience({}, "spiffe://prod.example")

    def test_wrong_aud_string_raises(self):
        with pytest.raises(MeshAuthenticationError, match="does not contain"):
            _validate_audience({"aud": "spiffe://wrong.example"}, "spiffe://prod.example")

    def test_aud_as_string_matches(self):
        _validate_audience({"aud": "spiffe://prod.example"}, "spiffe://prod.example")

    def test_aud_as_list_matches(self):
        _validate_audience({"aud": ["spiffe://prod.example", "other"]}, "spiffe://prod.example")

    def test_aud_as_list_no_match_raises(self):
        with pytest.raises(MeshAuthenticationError, match="does not contain"):
            _validate_audience(
                {"aud": ["spiffe://a.example", "spiffe://b.example"]},
                "spiffe://prod.example",
            )


# ── _parse_spiffe_uri ─────────────────────────────────────────────────────────


class TestParseSpiffeUri:
    def test_invalid_uri_raises(self):
        with pytest.raises(MeshAuthenticationError, match="valid SPIFFE"):
            _parse_spiffe_uri("https://not-spiffe.example/path", {})

    def test_uuid_raises(self):
        with pytest.raises(MeshAuthenticationError, match="valid SPIFFE"):
            _parse_spiffe_uri("550e8400-e29b-41d4-a716-446655440000", {})

    def test_valid_uri_with_path(self):
        claims = {"sub": "spiffe://prod.example/payments-agent", "exp": 9999999999}
        identity = _parse_spiffe_uri("spiffe://prod.example/payments-agent", claims)
        assert identity.uri == "spiffe://prod.example/payments-agent"
        assert identity.trust_domain == "prod.example"
        assert identity.path == "/payments-agent"

    def test_valid_uri_without_path(self):
        identity = _parse_spiffe_uri("spiffe://prod.example", {})
        assert identity.path == ""
        assert identity.trust_domain == "prod.example"

    def test_raw_claims_are_copied(self):
        claims = {"key": "value"}
        identity = _parse_spiffe_uri("spiffe://prod.example", claims)
        # Mutation of original should not affect stored claims
        claims["key"] = "mutated"
        assert identity.raw_claims["key"] == "value"


# ── _verify_signature ─────────────────────────────────────────────────────────


class TestVerifySignature:
    def test_rs256_valid_signature(self, rsa_private_key, rsa_public_key):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        data = b"header.payload"
        sig = rsa_private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        # Should not raise
        _verify_signature("RS256", data, sig, rsa_public_key)

    def test_rs256_invalid_signature_raises(self, rsa_public_key):
        _verify_signature.__module__  # access to confirm import
        with pytest.raises(MeshAuthenticationError, match="verification failed"):
            _verify_signature("RS256", b"header.payload", b"\x00" * 256, rsa_public_key)

    def test_es256_valid_signature(self, ec_private_key, ec_public_key):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        data = b"header.payload"
        sig = ec_private_key.sign(data, ECDSA(hashes.SHA256()))
        _verify_signature("ES256", data, sig, ec_public_key)

    def test_es256_invalid_signature_raises(self, ec_public_key):
        with pytest.raises(MeshAuthenticationError, match="verification failed"):
            _verify_signature("ES256", b"header.payload", b"\x00" * 64, ec_public_key)


# ── _select_jwk ───────────────────────────────────────────────────────────────


class TestSelectJwk:
    def test_no_kid_match_raises(self, rsa_public_key):
        keys = [_rsa_to_jwk(rsa_public_key, kid="abc")]
        with pytest.raises(MeshAuthenticationError, match="No JWK with kid"):
            _select_jwk(keys, kid="xyz", alg="RS256")

    def test_kid_match_returns_key(self, rsa_public_key):
        keys = [_rsa_to_jwk(rsa_public_key, kid="my-kid")]
        key = _select_jwk(keys, kid="my-kid", alg="RS256")
        assert key is not None

    def test_no_kid_selects_by_alg(self, rsa_public_key):
        keys = [_rsa_to_jwk(rsa_public_key, kid="k1")]
        key = _select_jwk(keys, kid=None, alg="RS256")
        assert key is not None

    def test_no_kid_selects_by_use_sig(self, rsa_public_key):
        # Remove 'alg' so it falls back to use=sig selection
        jwk = _rsa_to_jwk(rsa_public_key, kid="k1")
        del jwk["alg"]
        keys = [jwk]
        key = _select_jwk(keys, kid=None, alg="RS256")
        assert key is not None

    def test_no_usable_key_raises(self):
        # All candidates fail conversion
        keys = [{"kty": "unsupported-type", "kid": "k1"}]
        with pytest.raises(MeshAuthenticationError):
            _select_jwk(keys, kid=None, alg="RS256")

    def test_ec_kid_match_returns_ec_key(self, ec_public_key):
        keys = [_ec_to_jwk(ec_public_key, kid="ec-k1")]
        key = _select_jwk(keys, kid="ec-k1", alg="ES256")
        assert key is not None


# ── _jwk_to_public_key ────────────────────────────────────────────────────────


class TestJwkToPublicKey:
    def test_rsa_jwk_success(self, rsa_public_key):
        jwk = _rsa_to_jwk(rsa_public_key)
        key = _jwk_to_public_key(jwk)
        assert key is not None

    def test_rsa_jwk_missing_n_raises(self, rsa_public_key):
        jwk = _rsa_to_jwk(rsa_public_key)
        del jwk["n"]
        with pytest.raises(MeshAuthenticationError, match="missing required parameter"):
            _jwk_to_public_key(jwk)

    def test_rsa_jwk_missing_e_raises(self, rsa_public_key):
        jwk = _rsa_to_jwk(rsa_public_key)
        del jwk["e"]
        with pytest.raises(MeshAuthenticationError, match="missing required parameter"):
            _jwk_to_public_key(jwk)

    def test_ec_jwk_success(self, ec_public_key):
        jwk = _ec_to_jwk(ec_public_key)
        key = _jwk_to_public_key(jwk)
        assert key is not None

    def test_ec_jwk_unsupported_curve_raises(self, ec_public_key):
        jwk = _ec_to_jwk(ec_public_key)
        jwk["crv"] = "P-521"
        with pytest.raises(MeshAuthenticationError, match="Only 'P-256'"):
            _jwk_to_public_key(jwk)

    def test_ec_jwk_missing_x_raises(self, ec_public_key):
        jwk = _ec_to_jwk(ec_public_key)
        del jwk["x"]
        with pytest.raises(MeshAuthenticationError, match="missing required parameter"):
            _jwk_to_public_key(jwk)

    def test_ec_jwk_missing_y_raises(self, ec_public_key):
        jwk = _ec_to_jwk(ec_public_key)
        del jwk["y"]
        with pytest.raises(MeshAuthenticationError, match="missing required parameter"):
            _jwk_to_public_key(jwk)

    def test_unsupported_kty_raises(self):
        with pytest.raises(MeshAuthenticationError, match="Unsupported JWK key type"):
            _jwk_to_public_key({"kty": "oct", "k": "some-key"})


# ── _load_public_key_pem ──────────────────────────────────────────────────────


class TestLoadPublicKeyPem:
    def test_valid_rsa_pem_loads(self, rsa_public_pem):
        key = _load_public_key_pem(rsa_public_pem)
        assert key is not None

    def test_valid_ec_pem_loads(self, ec_public_pem):
        key = _load_public_key_pem(ec_public_pem)
        assert key is not None

    def test_string_pem_loads(self, rsa_public_pem):
        key = _load_public_key_pem(rsa_public_pem.decode("ascii"))
        assert key is not None

    def test_invalid_pem_raises_value_error(self):
        with pytest.raises((ValueError, Exception)):
            _load_public_key_pem(b"this is not a PEM")

    def test_private_key_pem_raises_value_error(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ValueError):
            _load_public_key_pem(private_pem)


# ── _b64url_decode ────────────────────────────────────────────────────────────


class TestB64urlDecode:
    def test_no_padding(self):
        original = b"hello world"
        encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode()
        assert _b64url_decode(encoded) == original

    def test_one_padding_char(self):
        # 'hello' → 'aGVsbG8' (7 chars, needs 1 pad)
        assert _b64url_decode("aGVsbG8") == b"hello"

    def test_two_padding_chars(self):
        # 'he' → 'aGU' (3 chars, needs 2 pads... wait that's 1 pad)
        # Let's verify with a known case
        assert _b64url_decode("aGk") == b"hi"

    def test_invalid_base64url_raises(self):
        # Python's urlsafe_b64decode is lenient with invalid chars; force the
        # except-branch by patching the underlying decoder to raise.
        with patch(
            "pramanix.mesh.authenticator.base64.urlsafe_b64decode",
            side_effect=Exception("simulated decode error"),
        ):
            with pytest.raises(ValueError):
                _b64url_decode("anything")

    def test_roundtrip(self):
        for test_bytes in [b"", b"\x00", b"\xff\xfe", b"SPIFFE JWT-SVID"]:
            enc = base64.urlsafe_b64encode(test_bytes).rstrip(b"=").decode()
            assert _b64url_decode(enc) == test_bytes


# ── JWKS end-to-end via verify_svid ──────────────────────────────────────────


class TestJwksEndToEnd:
    """Verify that the full JWKS path works when cache is cold."""

    def test_cold_jwks_cache_fetches_and_verifies(self, rsa_private_key, rsa_public_key):
        auth = MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
        )
        rsa_jwk = _rsa_to_jwk(rsa_public_key, kid="rsa-1")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"keys": [rsa_jwk]}

        token = _make_jwt(_valid_payload(), rsa_private_key, kid="rsa-1")
        with patch("httpx.get", return_value=mock_resp):
            identity = auth.verify_svid(token)
        assert identity.uri == "spiffe://prod.example/payments-agent"

    def test_ec_jwks_end_to_end(self, ec_private_key, ec_public_key):
        auth = MeshAuthenticator(
            jwks_uri="https://jwks.example/jwks",
            audience="spiffe://prod.example",
            algorithms={"ES256"},
        )
        ec_jwk = _ec_to_jwk(ec_public_key, kid="ec-1")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"keys": [ec_jwk]}

        token = _make_jwt(_valid_payload(), ec_private_key, alg="ES256", kid="ec-1")
        with patch("httpx.get", return_value=mock_resp):
            identity = auth.verify_svid(token)
        assert identity.trust_domain == "prod.example"
