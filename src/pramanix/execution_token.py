# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Sealed Execution Token — HMAC-SHA256 single-use intent binding.

Problem
-------
Without execution tokens, an attacker who can replay a ``Decision.safe()``
JSON record (or steal a decision object in memory) can re-use an *already-
verified* ALLOW to trigger the guarded action a second time, or pass a
fabricated SAFE decision to the executor without ever calling ``Guard.verify()``.

This is the **TOCTOU / Execution Gap**: the time between Guard.verify() and
the actual execution.

Solution
--------
``ExecutionTokenSigner.mint()`` consumes a ``Decision`` and produces an
``ExecutionToken`` — a compact, HMAC-SHA256 signed record that embeds:

* ``decision_id``  — ties the token to a specific Guard call
* ``intent_dump``  — what was verified (binds token to exact payload)
* ``policy_hash``  — which policy produced the decision
* ``expires_at``   — short TTL (default 30 s) defeats replay after expiry
* ``token_id``     — a unique nonce per mint, so identical decisions cannot
                     share a token
* ``signature``    — HMAC-SHA256 over the canonical token body

``ExecutionTokenVerifier.consume()`` checks the signature, expiry, and
consumes the ``token_id`` from a local single-use registry.  A token can
only be consumed **once** — subsequent calls return ``False`` even with a
valid signature.

Thread safety
-------------
``ExecutionTokenVerifier`` uses a ``threading.Lock`` around the consumed-set
mutation, making ``consume()`` safe to call from multiple threads.

Usage::

    from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier
    import secrets

    # At startup — share the same secret_key securely
    secret = secrets.token_bytes(32)
    signer = ExecutionTokenSigner(secret_key=secret, ttl_seconds=15.0)
    verifier = ExecutionTokenVerifier(secret_key=secret)

    # After Guard.verify():
    decision = guard.verify(intent=..., state=...)
    if decision.allowed:
        token = signer.mint(decision)

    # In the executor — only proceed if token is valid and unconsumed:
    if verifier.consume(token):
        execute_action(token.intent_dump)
    else:
        raise RuntimeError("Execution token invalid, expired, or already used.")

.. warning::
    The ``ExecutionTokenVerifier`` consumed-set is **in-memory only**.
    In a multi-process deployment each process has its own registry;
    a token minted in process A can be consumed once in process A and
    once in process B.  For distributed single-use enforcement, back
    the registry with Redis (SETNX) or a transactional database.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision

__all__ = ["ExecutionToken", "ExecutionTokenSigner", "ExecutionTokenVerifier"]


# ── Token dataclass ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutionToken:
    """HMAC-signed single-use record binding a verified decision to execution.

    Attributes:
        decision_id:  UUID4 from the originating ``Decision``.
        allowed:      Must be ``True`` — mint() refuses UNSAFE/ERROR decisions.
        intent_dump:  JSON-safe copy of the verified intent values.
        policy_hash:  SHA-256 fingerprint of the policy (may be ``None`` if
                      ``GuardConfig.expected_policy_hash`` was not set).
        expires_at:   Unix timestamp after which the token is invalid.
        token_id:     Random 16-byte hex nonce — unique per ``mint()`` call.
        signature:    Hex-encoded HMAC-SHA256 over the canonical body.
    """

    decision_id: str
    allowed: bool
    intent_dump: dict[str, Any]
    policy_hash: str | None
    expires_at: float
    token_id: str
    signature: str

    # ── Convenience predicates ────────────────────────────────────────────────

    def is_expired(self) -> bool:
        """Return ``True`` if the token TTL has elapsed."""
        return time.time() > self.expires_at

    def is_allowed(self) -> bool:
        """Return ``True`` iff the token carries an ALLOW decision."""
        return self.allowed


# ── Canonical serialisation (shared by signer + verifier) ─────────────────────


def _token_body(token: ExecutionToken) -> bytes:
    """Deterministic canonical bytes for HMAC computation.

    Excludes ``signature`` (obviously).  Uses sorted-key JSON so the output is
    identical regardless of insertion order.
    """
    body: dict[str, Any] = {
        "allowed": token.allowed,
        "decision_id": token.decision_id,
        "expires_at": token.expires_at,
        "intent_dump": token.intent_dump,
        "policy_hash": token.policy_hash,
        "token_id": token.token_id,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


# ── Signer ────────────────────────────────────────────────────────────────────


class ExecutionTokenSigner:
    """Mints HMAC-SHA256 signed ``ExecutionToken`` objects from verified Decisions.

    Args:
        secret_key:   Shared symmetric secret (at least 32 bytes recommended).
                      Keep this secret — anyone with the key can mint valid tokens.
        ttl_seconds:  Token lifetime in seconds from mint time.  Default: 30 s.
                      Keep this short; it is the window in which a stolen token
                      can be replayed before expiry saves you.

    Example::

        signer = ExecutionTokenSigner(secret_key=secrets.token_bytes(32))
        token = signer.mint(decision)
    """

    def __init__(self, secret_key: bytes, ttl_seconds: float = 30.0) -> None:
        if len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes.")
        self._key = secret_key
        self._ttl = ttl_seconds

    def mint(self, decision: Decision) -> ExecutionToken:
        """Create a signed, single-use token from a ``Decision``.

        Args:
            decision: A ``Decision`` returned by ``Guard.verify()``.

        Returns:
            A signed ``ExecutionToken`` ready to pass to the executor.

        Raises:
            ValueError: If ``decision.allowed`` is ``False``.  Only SAFE
                        decisions may be tokenised — mint() is fail-closed.
        """
        if not decision.allowed:
            raise ValueError(
                "ExecutionTokenSigner.mint() requires decision.allowed=True. "
                f"Received status={decision.status.value!r}. "
                "Do not tokenise blocked decisions."
            )
        token_id = secrets.token_hex(16)
        expires_at = time.time() + self._ttl

        # Build unsigned token first so _token_body() can serialise it.
        unsigned = ExecutionToken(
            decision_id=decision.decision_id,
            allowed=True,
            intent_dump=dict(decision.intent_dump),
            policy_hash=getattr(decision, "policy_hash", None),
            expires_at=expires_at,
            token_id=token_id,
            signature="",  # placeholder — replaced below
        )
        body = _token_body(unsigned)
        sig = hmac.new(self._key, body, hashlib.sha256).hexdigest()

        # Return the final frozen token with real signature.
        return ExecutionToken(
            decision_id=unsigned.decision_id,
            allowed=unsigned.allowed,
            intent_dump=unsigned.intent_dump,
            policy_hash=unsigned.policy_hash,
            expires_at=unsigned.expires_at,
            token_id=unsigned.token_id,
            signature=sig,
        )


# ── Verifier ──────────────────────────────────────────────────────────────────


class ExecutionTokenVerifier:
    """Verifies and single-use-consumes ``ExecutionToken`` objects.

    Args:
        secret_key: Must match the key used by the corresponding
                    ``ExecutionTokenSigner``.

    Thread safety:
        ``consume()`` is safe to call concurrently from multiple threads.
        The consumed-set mutation is protected by a ``threading.Lock``.

    .. warning::
        The consumed-set is in-memory only.  Restart loses it.
        For distributed deployments, swap out ``_consumed`` for a
        Redis SETNX or similar transactional store.

    Example::

        verifier = ExecutionTokenVerifier(secret_key=secret)
        if verifier.consume(token):
            execute_action(token.intent_dump)
        else:
            abort("Token invalid, expired, or already used.")
    """

    def __init__(self, secret_key: bytes) -> None:
        if len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes.")
        self._key = secret_key
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def consume(self, token: ExecutionToken) -> bool:
        """Verify and consume a token.  Returns ``True`` iff:

        1. The HMAC signature is correct (token was minted by our signer).
        2. The token has not expired.
        3. The token has not been consumed before (single-use).

        All three checks must pass.  The token_id is recorded as consumed
        atomically — even if the caller later fails, the token cannot be
        reused.

        Args:
            token: The ``ExecutionToken`` to verify.

        Returns:
            ``True`` if the token is valid, unexpired, and newly consumed.
            ``False`` in all other cases (invalid sig, expired, replayed).
        """
        # ── 1. Signature check (constant-time) ───────────────────────────────
        # Recompute expected HMAC over unsigned body (sig="" placeholder).
        unsigned = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature="",
        )
        expected_sig = hmac.new(self._key, _token_body(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            return False

        # ── 2. Expiry check ───────────────────────────────────────────────────
        if token.is_expired():
            return False

        # ── 3. Single-use check (atomic) ──────────────────────────────────────
        with self._lock:
            if token.token_id in self._consumed:
                return False
            self._consumed.add(token.token_id)

        return True

    def consumed_count(self) -> int:
        """Return the number of token IDs in the consumed registry."""
        with self._lock:
            return len(self._consumed)


# ── Redis-backed distributed verifier ─────────────────────────────────────────


class RedisExecutionTokenVerifier:
    """Distributed single-use token verifier backed by Redis SETNX.

    Drop-in replacement for :class:`ExecutionTokenVerifier` in multi-server
    deployments.  Uses Redis ``SET ... NX EX`` (SETNX with TTL) so that a
    token consumed on **Server A** is immediately invisible to **Server B** —
    preventing cross-node replay attacks without any shared application state.

    How it works
    ------------
    1. Verify HMAC-SHA256 signature (same as the in-memory verifier).
    2. Check local expiry.
    3. ``SET pramanix:token:<token_id> 1 NX EX <remaining_seconds>``

       * If the key did **not** exist → SETNX succeeds → token is consumed globally.
       * If the key **already** exists → another server consumed it → return False.

    Tokens expire from Redis automatically when their TTL elapses — no manual
    cleanup is required.

    Thread safety
    -------------
    Redis operations are atomic at the server level.  Multiple threads (or
    processes, or servers) calling ``consume()`` concurrently on the same
    token are safe: exactly one will receive ``True``.

    Requirements
    ------------
    ``pip install redis``  — or ``pip install redis[hiredis]`` for better throughput.

    Args:
        secret_key:   HMAC-SHA256 key — must match :class:`ExecutionTokenSigner`.
        redis_client: A connected ``redis.Redis`` (sync) instance.
        key_prefix:   Redis key namespace.  Default: ``"pramanix:token:"``.
                      Use per-environment prefixes (``"prod:token:"`` vs
                      ``"staging:token:"``) to prevent cross-env collisions.

    Raises:
        TypeError:  If ``redis_client`` is not Redis-compatible
                    (must have ``set`` and ``scan`` methods).
        ValueError: If ``secret_key`` is shorter than 16 bytes.

    Example::

        import redis
        from pramanix import ExecutionTokenSigner, RedisExecutionTokenVerifier
        import secrets

        secret = secrets.token_bytes(32)
        signer   = ExecutionTokenSigner(secret_key=secret, ttl_seconds=30.0)
        r        = redis.Redis(host="redis.internal", port=6379, ssl=True,
                               decode_responses=True)
        verifier = RedisExecutionTokenVerifier(secret_key=secret, redis_client=r)

        # After Guard.verify():
        token = signer.mint(decision)

        # In the executor (any server — one wins, rest lose):
        if verifier.consume(token):
            execute_action(token.intent_dump)
        else:
            abort("Token already used or invalid.")

    .. warning::
        If the Redis connection is unavailable, ``consume()`` raises
        ``redis.RedisError``.  Callers **must** treat connection failures as
        BLOCK — never fall back to the in-memory verifier for a token that
        has already been attempted against Redis.
    """

    def __init__(
        self,
        secret_key: bytes,
        redis_client: Any,
        key_prefix: str = "pramanix:token:",
    ) -> None:
        if len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes.")
        if not (hasattr(redis_client, "set") and hasattr(redis_client, "scan")):
            raise TypeError(
                "redis_client must be a redis.Redis-compatible client "
                "(requires .set() and .scan() methods)."
            )
        self._key = secret_key
        self._redis = redis_client
        self._prefix = key_prefix

    def consume(self, token: ExecutionToken) -> bool:
        """Verify and atomically consume a token via Redis SETNX.

        Args:
            token: The :class:`ExecutionToken` to verify and consume.

        Returns:
            ``True`` if the token is valid, unexpired, and was not previously
            consumed on **any** server sharing this Redis instance.
            ``False`` in all other cases.

        Raises:
            redis.RedisError: If the Redis connection fails.  The caller must
                treat this as a BLOCK — never silently allow on Redis failure.
        """
        # ── 1. Signature check (constant-time) ───────────────────────────────
        unsigned = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature="",
        )
        expected_sig = hmac.new(
            self._key, _token_body(unsigned), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            return False

        # ── 2. Expiry check ───────────────────────────────────────────────────
        if token.is_expired():
            return False

        # ── 3. Atomic SETNX with TTL = remaining token lifetime ───────────────
        # max(1, ...) ensures the key gets at least 1 second TTL even if the
        # token is about to expire — so Redis doesn't reject the SET.
        remaining_s = max(1, int(token.expires_at - time.time()))
        redis_key = f"{self._prefix}{token.token_id}"
        result = self._redis.set(redis_key, "1", nx=True, ex=remaining_s)
        return bool(result)

    def consumed_count(self) -> int:
        """Count active (not yet expired) consumed token keys in Redis.

        Uses ``SCAN`` to iterate the keyspace — O(N) on large keyspaces.
        Use for monitoring dashboards only, not on hot paths.

        Returns:
            Number of unconsumed-TTL token keys in Redis under this prefix.
        """
        cursor = 0
        count = 0
        while True:
            cursor, keys = self._redis.scan(
                cursor, match=f"{self._prefix}*", count=100
            )
            count += len(keys)
            if cursor == 0:
                break
        return count
