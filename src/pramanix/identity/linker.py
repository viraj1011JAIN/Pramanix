# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Zero-Trust JWT Identity Linker — HS256, RS256, ES256.

Architecture:
    Request → Extract Bearer token → Verify JWT signature →
    Extract (sub, roles) → Fetch state(sub) from StateLoader →
    Return (claims, state)

The caller's request body state is NEVER used. JWT sub claim is the
ONLY state lookup key. This is the zero-trust boundary.

Security guarantees:
1. JWT signature verified before ANY claims are trusted.
2. Algorithm confusion attacks prevented: token ``alg`` header MUST match
   the algorithm the linker was constructed with — any mismatch (including
   ``"none"``) is rejected before any cryptographic work is done.
3. RS256 / ES256 for K8s multi-replica deployments: public-key verification
   eliminates shared-secret key distribution risk across pods.
4. Token expiry (``exp``) and not-before (``nbf``) enforced with configurable
   clock-skew allowance.
5. Empty ``sub`` rejected — no empty-identity spoofing.
6. Public key PEM validated eagerly at construction — malformed keys fail
   fast, not at the first incoming request.
7. Caller-provided state in the request body is IGNORED.
"""
from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class JWTAlgorithm(enum.Enum):
    """Supported JWT signature algorithms.

    Choose HS256 for single-node / development environments where a shared
    secret is acceptable.  Choose RS256 or ES256 for production K8s
    multi-replica deployments — the public key can be distributed freely
    without any shared-secret risk.
    """

    HS256 = "HS256"
    RS256 = "RS256"
    ES256 = "ES256"


@dataclass(frozen=True)
class IdentityClaims:
    """Parsed and validated JWT claims for a bearer token."""

    sub: str
    roles: list[str]
    exp: int
    iat: int
    raw: dict[str, Any]


class StateLoader(Protocol):
    """Protocol for loading application state keyed by verified identity claims."""

    async def load(self, claims: IdentityClaims) -> dict[str, Any]:
        """Return a state dict for the given verified identity claims."""
        ...


class StateLoadError(Exception):
    """Raised when application state cannot be loaded for the given claims."""


class JWTVerificationError(Exception):
    """Raised when a JWT has an invalid signature or is structurally malformed."""


class JWTExpiredError(Exception):
    """Raised when a JWT token has passed its expiry time (exp claim)."""


class JWTIdentityLinker:
    """Zero-Trust JWT Identity Linker supporting HS256, RS256, and ES256.

    HS256 (symmetric — single-node / dev)::

        linker = JWTIdentityLinker(state_loader=..., jwt_secret="<min 32 chars>")
        # Or via env: PRAMANIX_JWT_SECRET=<secret>

    RS256 (asymmetric RSA — K8s multi-replica / production)::

        linker = JWTIdentityLinker(
            state_loader=RedisStateLoader(...),
            public_key_pem=Path("/run/secrets/jwt_public.pem").read_bytes(),
            algorithm=JWTAlgorithm.RS256,
        )

    ES256 (asymmetric EC P-256 — K8s / production, smaller keys)::

        linker = JWTIdentityLinker(
            state_loader=RedisStateLoader(...),
            public_key_pem=Path("/run/secrets/jwt_ec_public.pem").read_bytes(),
            algorithm=JWTAlgorithm.ES256,
        )

    RS256/ES256 requires ``cryptography>=41.0``::

        pip install pramanix[crypto]

    Algorithm confusion attack prevention:
        The ``alg`` field in the JWT header MUST exactly match the ``algorithm``
        configured at construction time.  Tokens presenting ``"none"`` or a
        different algorithm are rejected before any cryptographic work is done.

    Usage with FastAPI::

        @app.post("/transfer")
        async def transfer(request: Request):
            claims, state = await linker.extract_and_load(request)
            decision = await guard.verify_async(intent=intent, state=state)
    """

    _JWT_ENV_VAR = "PRAMANIX_JWT_SECRET"
    _MIN_SECRET_LENGTH = 32

    def __init__(
        self,
        state_loader: StateLoader,
        jwt_secret: str | None = None,
        public_key_pem: bytes | str | None = None,
        algorithm: JWTAlgorithm = JWTAlgorithm.HS256,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._algorithm = algorithm
        self._loader = state_loader
        self._skew = clock_skew_seconds
        # _secret is set for HS256; _public_key is set for RS256/ES256.
        self._secret: bytes | None = None
        self._public_key: Any = None  # RSAPublicKey | EllipticCurvePublicKey

        if algorithm is JWTAlgorithm.HS256:
            raw = jwt_secret or os.environ.get(self._JWT_ENV_VAR, "")
            if not raw or len(raw) < self._MIN_SECRET_LENGTH:
                raise ValueError(
                    f"JWT secret must be >= {self._MIN_SECRET_LENGTH} characters. "
                    f"Set {self._JWT_ENV_VAR} environment variable."
                )
            self._secret = raw.encode()
        else:
            if public_key_pem is None:
                raise ValueError(
                    f"public_key_pem is required for algorithm {algorithm.value}. "
                    "Pass the PEM bytes of your public key."
                )
            # Validate eagerly — fail at construction, not at the first request.
            self._public_key = self._load_and_validate_public_key(algorithm, public_key_pem)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def extract_and_load(self, request: Any) -> tuple[IdentityClaims, dict[str, Any]]:
        """Extract verified claims and load state.

        Returns (claims, state) on success.  The returned state comes
        EXCLUSIVELY from the StateLoader using claims.sub — never from
        the request body.

        Raises:
            JWTVerificationError: Signature invalid, algorithm mismatch, or
                                  structural malformation.
            JWTExpiredError:      Token has passed its ``exp`` claim.
            StateLoadError:       StateLoader failed for the verified subject.
        """
        auth_header = request.headers.get("Authorization", "")
        token = self._extract_bearer(auth_header)
        claims = self._verify_token(token)
        state = await self._loader.load(claims)
        return claims, state

    # ── Internal — extraction ──────────────────────────────────────────────────

    def _extract_bearer(self, auth_header: str) -> str:
        if not auth_header.startswith("Bearer "):
            raise JWTVerificationError("Authorization header must be: Bearer <token>")
        token = auth_header[7:].strip()
        if not token:
            raise JWTVerificationError("Bearer token is empty")
        return token

    def _verify_token(self, token: str) -> IdentityClaims:
        """Verify JWT signature. Claims decoded ONLY after signature passes."""
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTVerificationError("JWT must have exactly 3 parts")

        header_b64, payload_b64, sig_b64 = parts

        # BUG-10: validate alg BEFORE computing any signature — algorithm
        # confusion attack prevention (CVE-2015-9235 family).
        try:
            header = json.loads(self._b64url_decode(header_b64))
        except Exception as e:
            raise JWTVerificationError(f"JWT header decode failed: {e}") from e

        alg = header.get("alg")
        if alg != self._algorithm.value:
            raise JWTVerificationError(
                f"Algorithm mismatch: token has {alg!r}, "
                f"linker configured for {self._algorithm.value!r}"
            )

        signing_input = f"{header_b64}.{payload_b64}".encode()

        if self._algorithm is JWTAlgorithm.HS256:
            self._verify_hs256(signing_input, sig_b64)
        elif self._algorithm is JWTAlgorithm.RS256:
            self._verify_rs256(signing_input, sig_b64)
        else:
            self._verify_es256(signing_input, sig_b64)

        try:
            payload = json.loads(self._b64url_decode(payload_b64))
        except Exception as e:
            raise JWTVerificationError(f"JWT payload decode failed: {e}") from e

        now = int(time.time())

        # BUG-11: enforce nbf (not-before) claim.
        nbf = payload.get("nbf")
        if nbf is not None and now < int(nbf) - self._skew:
            raise JWTVerificationError(f"JWT not yet valid (nbf={nbf}, now={now})")

        exp = payload.get("exp", 0)
        if exp and now > exp + self._skew:
            raise JWTExpiredError(f"JWT expired at {exp}, current time {now}")

        # BUG-12: reject missing or empty sub to prevent empty-identity spoofing.
        sub = payload.get("sub")
        if not sub:
            raise JWTVerificationError("JWT 'sub' claim is required and must be non-empty")

        return IdentityClaims(
            sub=str(sub),
            roles=list(payload.get("roles", [])),
            exp=int(payload.get("exp", 0)),
            iat=int(payload.get("iat", 0)),
            raw=payload,
        )

    # ── Internal — per-algorithm verification ─────────────────────────────────

    def _verify_hs256(self, signing_input: bytes, sig_b64: str) -> None:
        assert self._secret is not None  # invariant: set in __init__ for HS256
        expected_sig = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(sig_b64.encode(), self._b64url(expected_sig).encode()):
            raise JWTVerificationError("JWT signature verification failed")

    def _verify_rs256(self, signing_input: bytes, sig_b64: str) -> None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError as exc:
            raise ImportError(
                "RS256 requires the 'cryptography' package: pip install pramanix[crypto]"
            ) from exc

        sig = self._b64url_decode(sig_b64)
        try:
            self._public_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise JWTVerificationError("JWT RS256 signature verification failed") from exc

    def _verify_es256(self, signing_input: bytes, sig_b64: str) -> None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        except ImportError as exc:
            raise ImportError(
                "ES256 requires the 'cryptography' package: pip install pramanix[crypto]"
            ) from exc

        sig = self._b64url_decode(sig_b64)
        try:
            self._public_key.verify(sig, signing_input, ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise JWTVerificationError("JWT ES256 signature verification failed") from exc

    # ── Internal — key loading ─────────────────────────────────────────────────

    @staticmethod
    def _load_and_validate_public_key(
        algorithm: JWTAlgorithm,
        pem: bytes | str,
    ) -> Any:
        """Load and type-validate a PEM public key for RS256 or ES256.

        Raises:
            ImportError:  ``cryptography`` package not installed.
            ValueError:   Malformed PEM or key type mismatch for algorithm.
        """
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
        except ImportError as exc:
            raise ImportError(
                f"{algorithm.value} requires the 'cryptography' package: "
                "pip install pramanix[crypto]"
            ) from exc

        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        try:
            key = load_pem_public_key(pem_bytes)
        except Exception as exc:
            raise ValueError(f"Invalid public key PEM for {algorithm.value}: {exc}") from exc

        if algorithm is JWTAlgorithm.RS256:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
            if not isinstance(key, RSAPublicKey):
                raise ValueError(
                    "RS256 requires an RSA public key; "
                    f"got {type(key).__name__}"
                )
        else:  # ES256
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
            if not isinstance(key, EllipticCurvePublicKey):
                raise ValueError(
                    "ES256 requires an EC (elliptic curve) public key; "
                    f"got {type(key).__name__}"
                )
        return key

    # ── Internal — base64url helpers ───────────────────────────────────────────

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)
