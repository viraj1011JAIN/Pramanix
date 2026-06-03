# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Pillar 2 — Zero-Trust Agent Mesh: SPIFFE JWT-SVID Authenticator.

Architecture
------------
Every agent-to-agent call carries an ``Authorization: Bearer <token>`` header
whose value is a SPIFFE JWT-SVID (SPIFFE Verifiable Identity Document
encoded as a JWT).  The :class:`MeshAuthenticator` validates that token and
injects the caller's SPIFFE URI into the intent dictionary before it reaches
``Guard.verify()``::

    # Agent B receives a call from Agent A
    enriched_intent = auth.authenticate_and_bind(bearer_token, raw_intent)
    decision        = guard.verify(intent=enriched_intent, state=state)

The ``_mesh_principal`` key injected into the intent is reserved.  Z3 policies
can reference it like any other field::

    class AgentPolicy(Policy):
        caller = Field("_mesh_principal", str, "String")

        @classmethod
        def invariants(cls):
            return [
                (E(cls.caller) == "spiffe://prod.example/payments-agent")
                .named("trusted_caller"),
            ]

Security guarantees
-------------------
1. **Algorithm whitelist** — only RS256 and ES256 are accepted.  The ``"none"``
   algorithm and HS256 are unconditionally rejected *before* any cryptographic
   work, regardless of what the JWT header claims.  This prevents algorithm
   confusion and "none"-bypass attacks.

2. **Signature first** — all three of exp/nbf/aud validation occur *after* the
   cryptographic signature is verified.  An attacker cannot craft a
   plausible-looking but unsigned token and observe timing differences.

3. **Strict expiry** — the ``exp`` claim is *required* for JWT-SVIDs.  Tokens
   without ``exp`` are rejected.  ``nbf`` is enforced when present.

4. **Audience** — the ``aud`` claim (string or array per RFC 7519 §4.1.3) must
   contain the configured audience.  Missing ``aud`` is rejected.

5. **SPIFFE URI** — the ``sub`` claim must be a syntactically valid
   ``spiffe://`` URI.  UUIDs, e-mail addresses, URIs with ports, userinfo,
   query strings, or fragments are all rejected.

6. **Intent-poisoning prevention** — if ``_mesh_principal`` already exists in
   the caller-supplied intent, the call is rejected immediately.  Callers
   cannot pre-inject a principal to bypass or spoof authentication.

7. **Fail-closed** — every failure path raises
   :exc:`~pramanix.exceptions.MeshAuthenticationError`.  The method never
   returns an unbound intent.

8. **Token size limit** — tokens exceeding 16 KiB are rejected before parsing
   to prevent resource exhaustion attacks.

9. **JWKS caching** — the JWKS document is cached with a configurable TTL
   (default: 600 s) to avoid a per-request HTTP round-trip.  Cache refresh is
   thread-safe via a :class:`threading.Lock`.

10. **No dynamic code** — no ``eval``, no ``exec``, no ``pickle`` in this
    module.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Final

from pramanix.exceptions import MeshAuthenticationError

__all__ = [
    "MeshAuthenticator",
    "SpiffeIdentity",
]

# ── Module-level constants ────────────────────────────────────────────────────

#: Only RS256 (RSA + SHA-256) and ES256 (ECDSA P-256 + SHA-256) are permitted.
#: HS256 is excluded: JWT-SVIDs are verified by third parties that cannot hold
#: a shared symmetric secret.  ``"none"`` is always excluded.
_ALLOWED_ALGORITHMS: Final[frozenset[str]] = frozenset({"RS256", "ES256"})

#: Reserved intent key injected by the authenticator after successful
#: validation.  Its presence in the caller-supplied intent is rejected.
_MESH_PRINCIPAL_KEY: Final[str] = "_mesh_principal"

#: SPIFFE URI regular expression.
#:
#: Trust domain rules (SPIFFE spec §2):
#:   - Non-empty DNS-like label(s); max 255 chars total.
#:   - No port (``:``) — rejects ``spiffe://host:8080/path``.
#:   - No userinfo (``@``) — rejects ``spiffe://user@host/path``.
#:   - Case-insensitive for the trust domain portion.
#:
#: Path rules:
#:   - Optional; when present, starts with ``/``.
#:   - No query strings (``?``) or fragments (``#``).
#:   - No whitespace.
_SPIFFE_URI_RE: Final[re.Pattern[str]] = re.compile(
    r"^spiffe://"
    r"(?P<trust_domain>[A-Za-z0-9][A-Za-z0-9\-\.]{0,253})"
    r"(?P<path>/[^\s#?]*)?"
    r"$"
)

#: Maximum JWT token size in bytes.  SPIFFE JWT-SVIDs are always small
#: (typically < 1 KiB); an oversized token indicates a malformed or
#: adversarial request and is rejected before any parsing occurs.
_MAX_TOKEN_BYTES: Final[int] = 16_384  # 16 KiB

# Type alias for a JWK dictionary parsed from a JWKS document.
_JwkDict = dict[str, Any]


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SpiffeIdentity:
    """A validated SPIFFE identity extracted from a JWT-SVID.

    All fields are set by :meth:`MeshAuthenticator.verify_svid` after
    cryptographic verification succeeds.  Instances are immutable.

    Attributes:
        uri:          Full SPIFFE URI, e.g. ``"spiffe://prod.example/payments-agent"``.
        trust_domain: Authority component, e.g. ``"prod.example"``.
        path:         Path component (empty string when absent), e.g.
                      ``"/payments-agent"``.
        raw_claims:   Snapshot of the full decoded JWT payload (read-only copy).
    """

    uri: str
    trust_domain: str
    path: str
    raw_claims: dict[str, Any]


@dataclass
class _JwksCache:
    """Thread-guarded JWKS document cache (internal use only)."""

    keys: list[_JwkDict] = field(default_factory=list)
    fetched_at: float = 0.0  # monotonic clock timestamp of last successful fetch


# ── MeshAuthenticator ─────────────────────────────────────────────────────────


class MeshAuthenticator:
    """SPIFFE JWT-SVID authenticator for the Pramanix Zero-Trust Agent Mesh.

    Validates an inbound ``Authorization: Bearer <token>`` JWT-SVID,
    extracts the caller's SPIFFE URI from the ``sub`` claim, and injects it
    into the intent dictionary under the key ``_mesh_principal`` so that Z3
    policies can reference the caller's identity.

    Construction modes
    ------------------
    **JWKS endpoint** (recommended for production — supports key rotation)::

        auth = MeshAuthenticator(
            jwks_uri="https://spiffe.prod.example/jwks",
            audience="spiffe://prod.example",
        )

    **Static PEM key** (for testing or air-gapped deployments)::

        from pathlib import Path
        auth = MeshAuthenticator(
            public_key_pem=Path("/run/secrets/svid_public.pem").read_bytes(),
            audience="spiffe://prod.example",
        )

    Usage::

        enriched = auth.authenticate_and_bind(bearer_token, raw_intent)
        decision  = guard.verify(intent=enriched, state=state)

    Parameters
    ----------
    jwks_uri:
        HTTPS URL of the JWKS endpoint.  Mutually exclusive with
        ``public_key_pem``.
    public_key_pem:
        PEM-encoded RSA or EC public key bytes (or ASCII string).  Mutually
        exclusive with ``jwks_uri``.
    audience:
        Required ``aud`` claim value.  The JWT ``aud`` claim must contain this
        string.  SPIFFE trust domain URIs are the typical value, e.g.
        ``"spiffe://prod.example"``.
    algorithms:
        Algorithm whitelist.  Must be a subset of ``{"RS256", "ES256"}``.
        Defaults to both algorithms.
    clock_skew_seconds:
        Seconds of leeway for ``exp`` and ``nbf`` claim clock-drift.
        Default: 30.
    jwks_cache_ttl_seconds:
        How long a fetched JWKS document is cached before a re-fetch is
        attempted.  Default: 600 (10 minutes).  Ignored for static-PEM
        authenticators.
    jwks_connect_timeout_seconds:
        HTTP connect timeout for JWKS endpoint requests.  Default: 5.0.
    jwks_read_timeout_seconds:
        HTTP read timeout for JWKS endpoint requests.  Default: 10.0.

    Raises
    ------
    ValueError
        If both or neither of ``jwks_uri``/``public_key_pem`` are supplied;
        if ``algorithms`` contains unsupported values; if ``audience`` is
        empty; or if the PEM key cannot be parsed.
    ImportError
        If ``cryptography`` is not installed when ``public_key_pem`` is
        provided.
    """

    def __init__(
        self,
        *,
        jwks_uri: str | None = None,
        public_key_pem: bytes | str | None = None,
        audience: str,
        algorithms: frozenset[str] | set[str] | None = None,
        clock_skew_seconds: int = 30,
        jwks_cache_ttl_seconds: int = 600,
        jwks_connect_timeout_seconds: float = 5.0,
        jwks_read_timeout_seconds: float = 10.0,
    ) -> None:
        # ── Parameter validation ──────────────────────────────────────────────
        if jwks_uri is None and public_key_pem is None:
            raise ValueError("MeshAuthenticator requires either 'jwks_uri' or 'public_key_pem'.")
        if jwks_uri is not None and public_key_pem is not None:
            raise ValueError("MeshAuthenticator accepts 'jwks_uri' OR 'public_key_pem', not both.")
        if not audience:
            raise ValueError("'audience' must be a non-empty string.")

        effective_algos: frozenset[str] = (
            frozenset(algorithms) if algorithms is not None else _ALLOWED_ALGORITHMS
        )
        unsupported = effective_algos - _ALLOWED_ALGORITHMS
        if unsupported:
            raise ValueError(
                f"Unsupported algorithms: {sorted(unsupported)!r}. "
                f"Only {sorted(_ALLOWED_ALGORITHMS)!r} are permitted for JWT-SVIDs."
            )
        if not effective_algos:
            raise ValueError("'algorithms' must contain at least one supported algorithm.")

        self._algorithms: frozenset[str] = effective_algos
        self._audience: str = audience
        self._clock_skew: int = clock_skew_seconds
        self._cache_ttl: int = jwks_cache_ttl_seconds
        self._connect_timeout: float = jwks_connect_timeout_seconds
        self._read_timeout: float = jwks_read_timeout_seconds

        # ── Key material ──────────────────────────────────────────────────────
        self._jwks_uri: str | None = jwks_uri
        self._static_key: Any = None
        if public_key_pem is not None:
            # Eagerly load and validate the PEM key so errors surface at
            # construction time rather than at the first token verification.
            self._static_key = _load_public_key_pem(public_key_pem)

        # ── JWKS cache (only relevant when jwks_uri is set) ───────────────────
        self._jwks_cache: _JwksCache = _JwksCache()
        self._jwks_lock: threading.Lock = threading.Lock()
        # Prevents concurrent threads from issuing duplicate JWKS fetches when
        # the cache is expired.  Checked and set atomically under _jwks_lock.
        self._jwks_fetching: bool = False

    # ── Public API ────────────────────────────────────────────────────────────

    def authenticate_and_bind(
        self,
        token: str,
        raw_intent: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate a SPIFFE JWT-SVID and inject the caller identity.

        This is the primary entrypoint for the Zero-Trust Agent Mesh layer.
        It must be called **before** ``Guard.verify()``::

            enriched = auth.authenticate_and_bind(bearer_token, raw_intent)
            decision  = guard.verify(intent=enriched, state=state)

        The method is fail-closed: every error path raises
        :exc:`~pramanix.exceptions.MeshAuthenticationError`.  It never
        returns an unbound intent.

        Parameters
        ----------
        token:
            Raw JWT-SVID string (the value after ``Authorization: Bearer``).
            Leading/trailing whitespace is stripped.
        raw_intent:
            Caller-supplied intent dictionary.  **Must not** contain the key
            ``_mesh_principal``; its presence implies an intent-poisoning
            attempt and causes an immediate
            :exc:`~pramanix.exceptions.MeshAuthenticationError`.

        Returns
        -------
        dict[str, Any]
            A shallow copy of ``raw_intent`` with ``_mesh_principal`` set to
            the verified SPIFFE URI.  The original ``raw_intent`` dict is
            never mutated.

        Raises
        ------
        MeshAuthenticationError
            On any authentication failure: missing/empty token, malformed
            structure, disallowed algorithm, expired or not-yet-valid token,
            invalid audience, signature verification failure, invalid SPIFFE
            URI in ``sub``, or ``_mesh_principal`` already present in
            ``raw_intent``.
        """
        # ── Intent-poisoning guard ────────────────────────────────────────────
        if _MESH_PRINCIPAL_KEY in raw_intent:
            raise MeshAuthenticationError(
                f"Intent poisoning rejected: '{_MESH_PRINCIPAL_KEY}' must not be present "
                "in the caller-supplied intent dictionary. "
                "Only MeshAuthenticator may set this key.",
                reason="intent_poisoning",
            )

        identity = self.verify_svid(token)

        enriched = dict(raw_intent)
        enriched[_MESH_PRINCIPAL_KEY] = identity.uri
        return enriched

    def verify_svid(self, token: str) -> SpiffeIdentity:
        """Verify a SPIFFE JWT-SVID and return the validated identity.

        A lower-level method exposed for testing and introspection.  Production
        callers should use :meth:`authenticate_and_bind` instead, which also
        handles intent-poisoning detection and principal injection.

        Parameters
        ----------
        token:
            Raw JWT-SVID string.

        Returns
        -------
        SpiffeIdentity
            Validated identity with ``uri``, ``trust_domain``, ``path``, and
            ``raw_claims``.

        Raises
        ------
        MeshAuthenticationError
            On any verification failure (see class docstring for the full list).
        """
        token = (token or "").strip()

        # ── Size guard ────────────────────────────────────────────────────────
        if not token:
            raise MeshAuthenticationError(
                "JWT-SVID token is missing or empty.",
                reason="missing_token",
            )
        if len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
            raise MeshAuthenticationError(
                f"JWT-SVID token exceeds the maximum size of {_MAX_TOKEN_BYTES} bytes. "
                "Oversized tokens are rejected to prevent resource exhaustion.",
                reason="token_too_large",
                token_preview=token[:16],
            )

        # ── Structural decode ─────────────────────────────────────────────────
        header, payload, signing_input, raw_sig = _decode_jwt_parts(token)

        # ── Algorithm enforcement (before any key lookup) ─────────────────────
        alg: str = header.get("alg", "")
        if alg not in self._algorithms:
            raise MeshAuthenticationError(
                f"JWT-SVID uses algorithm {alg!r}; "
                f"only {sorted(self._algorithms)!r} are permitted. "
                "The 'none' algorithm and HS256 are unconditionally rejected.",
                reason="disallowed_algorithm",
                token_preview=token[:16],
            )

        # ── Key resolution ────────────────────────────────────────────────────
        public_key = self._resolve_key(header)

        # ── Cryptographic signature verification ──────────────────────────────
        # Claims are only trusted after the signature passes.
        _verify_signature(alg, signing_input, raw_sig, public_key, token_preview=token[:16])

        # ── Temporal claims ───────────────────────────────────────────────────
        now = int(time.time())
        _validate_temporal_claims(payload, now, self._clock_skew, token_preview=token[:16])

        # ── Audience ──────────────────────────────────────────────────────────
        _validate_audience(payload, self._audience, token_preview=token[:16])

        # ── Subject / SPIFFE URI ──────────────────────────────────────────────
        sub: str = payload.get("sub", "")
        if not sub:
            raise MeshAuthenticationError(
                "JWT-SVID 'sub' claim is missing or empty. "
                "SPIFFE JWT-SVIDs must carry a non-empty SPIFFE URI as the subject.",
                reason="missing_sub",
                token_preview=token[:16],
            )

        return _parse_spiffe_uri(str(sub), payload)

    async def authenticate_and_bind_async(
        self,
        token: str,
        raw_intent: dict[str, Any],
    ) -> dict[str, Any]:
        """Async variant of :meth:`authenticate_and_bind`.

        Offloads the synchronous JWKS HTTP fetch and cryptographic work to the
        default thread-pool executor so the calling event loop is not blocked.

        See :meth:`authenticate_and_bind` for the full contract and error
        semantics.
        """
        return await asyncio.to_thread(self.authenticate_and_bind, token, raw_intent)

    async def verify_svid_async(self, token: str) -> SpiffeIdentity:
        """Async variant of :meth:`verify_svid`.

        Offloads to the thread-pool executor — safe to call from an async
        handler without blocking the event loop.
        """
        return await asyncio.to_thread(self.verify_svid, token)

    # ── Internal — key resolution ─────────────────────────────────────────────

    def _resolve_key(self, header: dict[str, Any]) -> Any:
        """Return the public key to use for signature verification.

        For static-PEM authenticators, returns the pre-loaded key object.
        For JWKS-backed authenticators, fetches/caches the JWKS document and
        selects the key that matches the JWT ``kid`` header.

        Parameters
        ----------
        header:
            Decoded JWT header dictionary.

        Returns
        -------
        Any
            A ``cryptography`` public key object.
        """
        if self._static_key is not None:
            return self._static_key

        # JWKS path
        if self._jwks_uri is None:
            raise MeshAuthenticationError(
                "_select_verification_key called without static_key or jwks_uri — "
                "this is an internal invariant violation enforced by __init__."
            )
        jwks_keys = self._get_cached_jwks_keys()
        return _select_jwk(jwks_keys, kid=header.get("kid"), alg=header.get("alg", ""))

    def _get_cached_jwks_keys(self) -> list[_JwkDict]:
        """Return the cached JWKS key list, refreshing from the endpoint if expired.

        Thread-safe via double-checked locking with a ``_jwks_fetching`` flag:

        1. Read the cache under ``_jwks_lock``.  Return immediately on a hit.
        2. If the cache is cold/expired and another thread is already fetching
           (``_jwks_fetching=True``), return stale keys if any exist — the
           caller gets slightly stale data for one request rather than issuing
           a duplicate HTTP fetch.  On a cold cache with no stale keys the
           thread joins the fetch (rare cold-start scenario; both fetches are
           idempotent).
        3. Claim the fetch slot atomically by setting ``_jwks_fetching=True``
           inside the lock, then fetch outside the lock.
        4. Store the result and clear the flag atomically under the lock.
        """
        with self._jwks_lock:
            age = time.monotonic() - self._jwks_cache.fetched_at
            if age < self._cache_ttl and self._jwks_cache.keys:
                return list(self._jwks_cache.keys)
            if self._jwks_fetching and self._jwks_cache.keys:
                # Another thread is refreshing; serve stale keys rather than
                # issuing a duplicate HTTP request.
                return list(self._jwks_cache.keys)
            # Claim the fetch slot (atomic because we're under the lock).
            self._jwks_fetching = True

        try:
            fresh_keys = self._fetch_jwks()
        except Exception:
            with self._jwks_lock:
                self._jwks_fetching = False
            raise

        with self._jwks_lock:
            self._jwks_cache.keys = fresh_keys
            self._jwks_cache.fetched_at = time.monotonic()
            self._jwks_fetching = False

        return fresh_keys

    def _fetch_jwks(self) -> list[_JwkDict]:
        """Perform an HTTP GET to the JWKS endpoint and return the key list.

        Raises
        ------
        MeshAuthenticationError
            If the endpoint is unreachable, returns a non-2xx status, the
            response body is not valid JSON, or the ``keys`` array is absent
            or empty.
        ImportError
            If ``httpx`` is not installed.
        """
        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "JWKS endpoint support requires the 'httpx' package: " "pip install httpx"
            ) from exc

        if self._jwks_uri is None:
            raise MeshAuthenticationError(
                "_fetch_jwks called without jwks_uri — "
                "this is an internal invariant violation enforced by __init__."
            )

        try:
            response = httpx.get(
                self._jwks_uri,
                timeout=httpx.Timeout(
                    connect=self._connect_timeout,
                    read=self._read_timeout,
                    write=5.0,
                    pool=5.0,
                ),
                follow_redirects=False,
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise MeshAuthenticationError(
                f"JWKS endpoint timed out: {self._jwks_uri!r}",
                reason="jwks_timeout",
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise MeshAuthenticationError(
                f"JWKS endpoint returned HTTP {exc.response.status_code}: " f"{self._jwks_uri!r}",
                reason="jwks_http_error",
            ) from exc
        except httpx.RequestError as exc:
            raise MeshAuthenticationError(
                f"JWKS endpoint unreachable: {self._jwks_uri!r} — {exc}",
                reason="jwks_unreachable",
            ) from exc

        try:
            jwks: Any = response.json()
        except Exception as exc:
            raise MeshAuthenticationError(
                f"JWKS endpoint response is not valid JSON: {self._jwks_uri!r}",
                reason="jwks_invalid_json",
            ) from exc

        if not isinstance(jwks, dict) or "keys" not in jwks:
            raise MeshAuthenticationError(
                f"JWKS document from {self._jwks_uri!r} is missing the 'keys' array.",
                reason="jwks_missing_keys",
            )

        keys: list[_JwkDict] = jwks["keys"]
        if not isinstance(keys, list) or len(keys) == 0:
            raise MeshAuthenticationError(
                f"JWKS document from {self._jwks_uri!r} contains no keys.",
                reason="jwks_empty",
            )

        return keys


# ── Module-level helpers ───────────────────────────────────────────────────────


def _decode_jwt_parts(
    token: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split and base64url-decode a compact JWT into its constituent parts.

    Parameters
    ----------
    token:
        Raw JWT string in compact serialisation (three dot-delimited segments).

    Returns
    -------
    tuple of (header_dict, payload_dict, signing_input_bytes, raw_signature_bytes)
        ``signing_input_bytes`` is the ``header_b64url.payload_b64url`` ASCII
        bytes that were signed.  ``raw_signature_bytes`` is the decoded
        (non-base64url) signature.

    Raises
    ------
    MeshAuthenticationError
        If the token does not have exactly three segments, or any segment
        cannot be decoded as base64url or parsed as a JSON object.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise MeshAuthenticationError(
            f"JWT-SVID has {len(parts)} dot-separated segment(s); "
            "expected exactly 3 (header.payload.signature).",
            reason="malformed_token",
            token_preview=token[:16],
        )

    header_b64, payload_b64, sig_b64 = parts
    signing_input: bytes = f"{header_b64}.{payload_b64}".encode("ascii")

    try:
        header: Any = json.loads(_b64url_decode(header_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise MeshAuthenticationError(
            f"JWT-SVID header segment could not be decoded: {exc}",
            reason="malformed_header",
            token_preview=token[:16],
        ) from exc

    try:
        payload: Any = json.loads(_b64url_decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise MeshAuthenticationError(
            f"JWT-SVID payload segment could not be decoded: {exc}",
            reason="malformed_payload",
            token_preview=token[:16],
        ) from exc

    if not isinstance(header, dict):
        raise MeshAuthenticationError(
            "JWT-SVID header is not a JSON object.",
            reason="malformed_header",
            token_preview=token[:16],
        )
    if not isinstance(payload, dict):
        raise MeshAuthenticationError(
            "JWT-SVID payload is not a JSON object.",
            reason="malformed_payload",
            token_preview=token[:16],
        )

    try:
        raw_sig: bytes = _b64url_decode(sig_b64)
    except ValueError as exc:
        raise MeshAuthenticationError(
            f"JWT-SVID signature segment could not be decoded: {exc}",
            reason="malformed_signature",
            token_preview=token[:16],
        ) from exc

    return header, payload, signing_input, raw_sig


def _validate_temporal_claims(
    payload: dict[str, Any],
    now: int,
    skew: int,
    *,
    token_preview: str = "",
) -> None:
    """Enforce the ``exp`` (expiration) and ``nbf`` (not-before) claims.

    The ``exp`` claim is *required* for SPIFFE JWT-SVIDs per the SPIFFE
    specification.  ``nbf`` is enforced when present.

    Parameters
    ----------
    payload:
        Decoded JWT payload dictionary.
    now:
        Current UNIX timestamp in seconds.
    skew:
        Clock-skew tolerance in seconds applied symmetrically to both claims.
    token_preview:
        First 16 chars of the raw token, included in error messages for
        log correlation without exposing credentials.

    Raises
    ------
    MeshAuthenticationError
        If ``exp`` is absent, not an integer, or the token is expired.
        If ``nbf`` is present, not an integer, or the token is not yet valid.
    """
    exp = payload.get("exp")
    if exp is None:
        raise MeshAuthenticationError(
            "JWT-SVID is missing the required 'exp' claim. "
            "SPIFFE JWT-SVIDs must always carry an expiration time.",
            reason="missing_exp",
            token_preview=token_preview,
        )
    try:
        exp_int = int(exp)
    except (TypeError, ValueError) as exc:
        raise MeshAuthenticationError(
            f"JWT-SVID 'exp' claim is not a valid integer: {exp!r}",
            reason="malformed_exp",
            token_preview=token_preview,
        ) from exc

    if now > exp_int + skew:
        raise MeshAuthenticationError(
            f"JWT-SVID has expired (exp={exp_int}, now={now}, skew=±{skew}s). "
            "Request a fresh token from the SPIFFE Workload API.",
            reason="expired",
            token_preview=token_preview,
        )

    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf_int = int(nbf)
        except (TypeError, ValueError) as exc:
            raise MeshAuthenticationError(
                f"JWT-SVID 'nbf' claim is not a valid integer: {nbf!r}",
                reason="malformed_nbf",
                token_preview=token_preview,
            ) from exc

        if now < nbf_int - skew:
            raise MeshAuthenticationError(
                f"JWT-SVID is not yet valid (nbf={nbf_int}, now={now}, skew=±{skew}s). "
                "The token's not-before time has not been reached.",
                reason="not_yet_valid",
                token_preview=token_preview,
            )


def _validate_audience(
    payload: dict[str, Any],
    required_audience: str,
    *,
    token_preview: str = "",
) -> None:
    """Verify that the required audience is present in the JWT ``aud`` claim.

    Per RFC 7519 §4.1.3, ``aud`` may be a single string or an array of
    strings.  Both forms are accepted.

    Parameters
    ----------
    payload:
        Decoded JWT payload dictionary.
    required_audience:
        The audience string that must appear in the ``aud`` claim.
    token_preview:
        First 16 chars of the raw token for log correlation.

    Raises
    ------
    MeshAuthenticationError
        If the ``aud`` claim is absent or does not contain ``required_audience``.
    """
    aud = payload.get("aud")
    if aud is None:
        raise MeshAuthenticationError(
            "JWT-SVID is missing the required 'aud' claim. "
            f"Expected audience: {required_audience!r}.",
            reason="missing_aud",
            token_preview=token_preview,
        )
    audiences: list[str] = [aud] if isinstance(aud, str) else list(aud)
    if required_audience not in audiences:
        raise MeshAuthenticationError(
            f"JWT-SVID audience {audiences!r} does not contain "
            f"the required value {required_audience!r}.",
            reason="audience_mismatch",
            token_preview=token_preview,
        )


def _parse_spiffe_uri(
    sub: str,
    raw_claims: dict[str, Any],
) -> SpiffeIdentity:
    """Parse and validate a SPIFFE URI from the JWT ``sub`` claim.

    Parameters
    ----------
    sub:
        The raw ``sub`` claim string from the verified JWT payload.
    raw_claims:
        The full decoded JWT payload; stored as a copy in the returned
        :class:`SpiffeIdentity`.

    Returns
    -------
    SpiffeIdentity

    Raises
    ------
    MeshAuthenticationError
        If ``sub`` is not a syntactically valid SPIFFE URI.
    """
    match = _SPIFFE_URI_RE.match(sub)
    if match is None:
        raise MeshAuthenticationError(
            f"JWT-SVID 'sub' claim {sub!r} is not a valid SPIFFE URI. "
            "Expected format: spiffe://<trust-domain>[/<path>]. "
            "URIs with ports, userinfo, query strings, or fragments are rejected. "
            "Plain UUIDs and e-mail addresses are not valid SPIFFE identities.",
            reason="bad_spiffe_uri",
        )

    return SpiffeIdentity(
        uri=sub,
        trust_domain=match.group("trust_domain"),
        path=match.group("path") or "",
        raw_claims=dict(raw_claims),  # defensive copy; SpiffeIdentity is frozen
    )


def _verify_signature(
    alg: str,
    signing_input: bytes,
    raw_sig: bytes,
    public_key: Any,
    *,
    token_preview: str = "",
) -> None:
    """Verify a JWT signature using the given algorithm and public key.

    Only RS256 and ES256 are supported.  This function should only be called
    after the algorithm has already been validated against the whitelist in
    :meth:`MeshAuthenticator.verify_svid`.

    Parameters
    ----------
    alg:
        Algorithm identifier: ``"RS256"`` or ``"ES256"``.
    signing_input:
        The ``header_b64url.payload_b64url`` ASCII bytes that were signed.
    raw_sig:
        Decoded (non-base64url) signature bytes.
    public_key:
        A ``cryptography`` RSA or EC public key object.
    token_preview:
        First 16 chars of the raw token for log correlation.

    Raises
    ------
    MeshAuthenticationError
        If the cryptographic signature verification fails.
    ImportError
        If the ``cryptography`` package is not installed.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise ImportError(
            "JWT-SVID signature verification requires the 'cryptography' package: "
            "pip install pramanix[crypto]"
        ) from exc

    if alg == "RS256":
        try:
            from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        except ImportError as exc:
            raise ImportError("'cryptography' package is required for RS256 verification.") from exc

        try:
            public_key.verify(
                raw_sig,
                signing_input,
                asym_padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise MeshAuthenticationError(
                "JWT-SVID RS256 signature verification failed. "
                "The token may have been tampered with or signed by an unknown key.",
                reason="invalid_signature",
                token_preview=token_preview,
            ) from exc

    elif alg == "ES256":
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        except ImportError as exc:
            raise ImportError("'cryptography' package is required for ES256 verification.") from exc

        try:
            public_key.verify(raw_sig, signing_input, ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise MeshAuthenticationError(
                "JWT-SVID ES256 signature verification failed. "
                "The token may have been tampered with or signed by an unknown key.",
                reason="invalid_signature",
                token_preview=token_preview,
            ) from exc

    else:
        # This branch is unreachable under normal operation because the
        # algorithm whitelist is enforced before _verify_signature is called.
        raise MeshAuthenticationError(
            f"Internal error: unhandled algorithm {alg!r} reached signature verification.",
            reason="disallowed_algorithm",
            token_preview=token_preview,
        )


def _select_jwk(
    keys: list[_JwkDict],
    *,
    kid: str | None,
    alg: str,
) -> Any:
    """Find the matching JWK in a JWKS key list and return a public key object.

    Matching strategy
    -----------------
    1. If the JWT ``kid`` header is present, select keys whose ``kid``
       matches exactly.  A ``kid`` mismatch is a hard error.
    2. If ``kid`` is absent, prefer keys whose ``alg`` matches, then keys
       with ``use="sig"``, then any key as a last resort.  Key construction
       is attempted for each candidate in order; the first that succeeds is
       returned.

    Parameters
    ----------
    keys:
        List of JWK dictionaries from a JWKS document.
    kid:
        The ``kid`` value from the JWT header, or ``None``.
    alg:
        The ``alg`` value from the JWT header (e.g. ``"RS256"``).

    Returns
    -------
    Any
        A ``cryptography`` public key object.

    Raises
    ------
    MeshAuthenticationError
        If no matching JWK is found, or no candidate can be converted to a
        usable public key.
    """
    if kid is not None:
        candidates = [k for k in keys if k.get("kid") == kid]
        if not candidates:
            raise MeshAuthenticationError(
                f"No JWK with kid={kid!r} found in the JWKS. "
                "The signing key may have been rotated; the JWKS cache will "
                "refresh automatically when it expires.",
                reason="unknown_kid",
            )
    else:
        # No kid — prefer keys matching the algorithm, then use=sig, then all.
        by_alg = [k for k in keys if k.get("alg") == alg]
        candidates = by_alg or [k for k in keys if k.get("use") == "sig"] or list(keys)

    last_exc: MeshAuthenticationError | None = None
    for jwk in candidates:
        try:
            return _jwk_to_public_key(jwk)
        except MeshAuthenticationError as exc:
            last_exc = exc
            continue

    raise last_exc or MeshAuthenticationError(
        f"No usable JWK found in the JWKS for algorithm {alg!r}. "
        "Ensure the JWKS endpoint exposes a key compatible with RS256 or ES256.",
        reason="no_usable_key",
    )


def _jwk_to_public_key(jwk: _JwkDict) -> Any:
    """Convert a JWK dictionary to a ``cryptography`` public key object.

    Supported key types
    -------------------
    * ``kty="RSA"`` — constructs an RSA public key from the ``n`` (modulus)
      and ``e`` (exponent) base64url parameters.
    * ``kty="EC"`` with ``crv="P-256"`` — constructs an EC public key from
      the ``x`` and ``y`` base64url point coordinates.

    Parameters
    ----------
    jwk:
        A JWK dictionary (one element of the ``keys`` array in a JWKS document).

    Returns
    -------
    Any
        An RSA or EC public key object from ``cryptography``.

    Raises
    ------
    MeshAuthenticationError
        If the JWK has an unsupported ``kty``, unsupported EC curve, or is
        missing required parameters.
    ImportError
        If the ``cryptography`` package is not installed.
    ValueError
        Propagated from ``cryptography`` when numeric parameters are invalid.
    """
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError as exc:
        raise ImportError(
            "JWK-to-key conversion requires the 'cryptography' package: "
            "pip install pramanix[crypto]"
        ) from exc

    kty: str = jwk.get("kty", "")

    if kty == "RSA":
        n_b64 = jwk.get("n")
        e_b64 = jwk.get("e")
        if not n_b64 or not e_b64:
            raise MeshAuthenticationError(
                "RSA JWK is missing required parameter(s) 'n' and/or 'e'.",
                reason="malformed_jwk",
            )
        n = int.from_bytes(_b64url_decode(n_b64), "big")
        e = int.from_bytes(_b64url_decode(e_b64), "big")
        return rsa.RSAPublicNumbers(e=e, n=n).public_key(default_backend())

    if kty == "EC":
        crv: str = jwk.get("crv", "")
        if crv != "P-256":
            raise MeshAuthenticationError(
                f"EC JWK curve {crv!r} is not supported. " "Only 'P-256' (ES256) is accepted.",
                reason="unsupported_curve",
            )
        x_b64 = jwk.get("x")
        y_b64 = jwk.get("y")
        if not x_b64 or not y_b64:
            raise MeshAuthenticationError(
                "EC JWK is missing required parameter(s) 'x' and/or 'y'.",
                reason="malformed_jwk",
            )
        x = int.from_bytes(_b64url_decode(x_b64), "big")
        y = int.from_bytes(_b64url_decode(y_b64), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        return pub_numbers.public_key(default_backend())

    raise MeshAuthenticationError(
        f"Unsupported JWK key type {kty!r}. Supported types: 'RSA', 'EC'.",
        reason="unsupported_kty",
    )


def _load_public_key_pem(pem: bytes | str) -> Any:
    """Load and validate a PEM-encoded RSA or EC public key.

    Parameters
    ----------
    pem:
        PEM-encoded public key as bytes or ASCII string.

    Returns
    -------
    Any
        A ``cryptography`` RSAPublicKey or EllipticCurvePublicKey object.

    Raises
    ------
    ImportError
        If the ``cryptography`` package is not installed.
    ValueError
        If the PEM is malformed or contains a key type that is not RSA or EC
        (e.g. a private key, a DSA key, or a certificate).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:
        raise ImportError(
            "PEM key loading requires the 'cryptography' package: " "pip install pramanix[crypto]"
        ) from exc

    pem_bytes: bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
    try:
        key = load_pem_public_key(pem_bytes)
    except Exception as exc:
        raise ValueError(f"Failed to load public key PEM: {exc}") from exc

    if not isinstance(key, RSAPublicKey | EllipticCurvePublicKey):
        raise ValueError(
            f"PEM contains a {type(key).__name__} key. "
            "MeshAuthenticator requires an RSA (RS256) or EC (ES256) public key."
        )

    return key


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url-encoded string, accepting input with or without padding.

    This is the same decoding logic used by
    :class:`~pramanix.identity.linker.JWTIdentityLinker`, extracted here for
    use in the mesh layer.

    Parameters
    ----------
    s:
        Base64url-encoded string (the ``=`` padding characters are optional).

    Returns
    -------
    bytes

    Raises
    ------
    ValueError
        If the string contains characters outside the base64url alphabet or
        has invalid length.
    """
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    try:
        return base64.urlsafe_b64decode(s)
    except Exception as exc:
        raise ValueError(f"Invalid base64url data: {s[:40]!r}") from exc
