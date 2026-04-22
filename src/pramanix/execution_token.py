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

__all__ = [
    "ExecutionToken",
    "ExecutionTokenSigner",
    "ExecutionTokenVerifier",
    "InMemoryExecutionTokenVerifier",
    "SQLiteExecutionTokenVerifier",
]


# ── Token dataclass ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutionToken:
    """HMAC-signed single-use record binding a verified decision to execution.

    Attributes:
        decision_id:    UUID4 from the originating ``Decision``.
        allowed:        Must be ``True`` — mint() refuses UNSAFE/ERROR decisions.
        intent_dump:    JSON-safe copy of the verified intent values.
        policy_hash:    SHA-256 fingerprint of the policy (may be ``None`` if
                        ``GuardConfig.expected_policy_hash`` was not set).
        expires_at:     Unix timestamp after which the token is invalid.
        token_id:       Random 16-byte hex nonce — unique per ``mint()`` call.
        signature:      Hex-encoded HMAC-SHA256 over the canonical body.
        state_version:  Caller-supplied state version/ETag at verify time.
                        If present, ``consume()`` will reject tokens whose
                        ``expected_state_version`` argument does not match —
                        detecting concurrent state mutations between
                        ``Guard.verify()`` and the actual execution (TOCTOU).
                        ``None`` means no state-version binding was requested.
    """

    decision_id: str
    allowed: bool
    intent_dump: dict[str, Any]
    policy_hash: str | None
    expires_at: float
    token_id: str
    signature: str
    state_version: str | None = None

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
    identical regardless of insertion order.  ``state_version`` is included so
    that a token minted with a specific state version cannot be detached from
    that binding by an attacker who replays a stripped token.
    """
    body: dict[str, Any] = {
        "allowed": token.allowed,
        "decision_id": token.decision_id,
        "expires_at": token.expires_at,
        "intent_dump": token.intent_dump,
        "policy_hash": token.policy_hash,
        "state_version": token.state_version,
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

    def mint(
        self,
        decision: Decision,
        *,
        state_version: str | None = None,
    ) -> ExecutionToken:
        """Create a signed, single-use token from a ``Decision``.

        Args:
            decision:      A ``Decision`` returned by ``Guard.verify()``.
            state_version: Optional state version/ETag string captured at
                           verify time.  When supplied, the token binds the
                           decision to the exact state snapshot that was
                           evaluated.  ``ExecutionTokenVerifier.consume()``
                           will reject the token if the caller supplies a
                           different ``expected_state_version`` — detecting
                           concurrent mutations between verify and execute
                           (TOCTOU gap mitigation).

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
            state_version=state_version,
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
            state_version=unsigned.state_version,
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

    Memory management:
        The in-memory registry is automatically pruned on every ``consume()``
        call: any entry whose token TTL has already elapsed is evicted.
        This bounds memory to ``O(unique unexpired tokens)`` rather than growing
        unboundedly over the lifetime of the process.

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
        # {token_id: expires_at} — stores expiry alongside the ID so that
        # entries can be evicted once the TTL elapses, bounding memory usage.
        self._consumed: dict[str, float] = {}
        self._lock = threading.Lock()

    def _evict_expired(self) -> None:
        """Prune consumed entries whose TTL has elapsed.  Called under lock."""
        now = time.time()
        expired = [tid for tid, exp in self._consumed.items() if exp < now]
        for tid in expired:
            del self._consumed[tid]

    def consume(
        self,
        token: ExecutionToken,
        *,
        expected_state_version: str | None = None,
    ) -> bool:
        """Verify and consume a token.  Returns ``True`` iff:

        1. The HMAC signature is correct (token was minted by our signer).
        2. The token has not expired.
        3. The token has not been consumed before (single-use).
        4. If ``expected_state_version`` is provided, it matches the version
           embedded in the token at mint time (TOCTOU guard).

        All checks must pass.  The token_id is recorded as consumed
        atomically — even if the caller later fails, the token cannot be
        reused.

        Args:
            token:                  The ``ExecutionToken`` to verify.
            expected_state_version: The current state version/ETag at execution
                                    time.  If the token was minted with a
                                    ``state_version`` and this argument differs,
                                    ``consume()`` returns ``False`` — indicating
                                    that the state was mutated between verify
                                    and execute.  Pass ``None`` to skip this
                                    check (default, backward-compatible).

        Returns:
            ``True`` if all checks pass.
            ``False`` in all other cases (invalid sig, expired, replayed,
            or state version mismatch).
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
            state_version=token.state_version,
        )
        expected_sig = hmac.new(self._key, _token_body(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            return False

        # ── 2. Expiry check ───────────────────────────────────────────────────
        if token.is_expired():
            return False

        # ── 3. State version check (TOCTOU guard) ─────────────────────────────
        # If either the token or the caller supplied a state_version, both must
        # agree.  A token minted with version "v3" and consumed with "v4" means
        # the state changed between verify() and execute — block the execution.
        if (
            token.state_version is not None or expected_state_version is not None
        ) and token.state_version != expected_state_version:
            return False

        # ── 4. Single-use check (atomic) ──────────────────────────────────────
        with self._lock:
            self._evict_expired()  # prune stale entries to bound memory growth
            if token.token_id in self._consumed:
                return False
            self._consumed[token.token_id] = token.expires_at

        return True

    def consumed_count(self) -> int:
        """Return the number of token IDs currently in the consumed registry.

        Note: entries are lazily evicted on ``consume()`` calls.  The count
        may include tokens whose TTL has elapsed if ``consume()`` has not been
        called recently.  Use :meth:`evict_expired` to force immediate pruning.
        """
        with self._lock:
            return len(self._consumed)

    def evict_expired(self) -> int:
        """Force eviction of all expired token entries.  Returns the count evicted.

        Normally this is unnecessary — eviction runs automatically on every
        ``consume()`` call.  Call this explicitly if the service is idle for a
        long period and you want to reclaim memory proactively.
        """
        with self._lock:
            before = len(self._consumed)
            self._evict_expired()
            return before - len(self._consumed)


# ── E-1: InMemoryExecutionTokenVerifier ───────────────────────────────────────


class InMemoryExecutionTokenVerifier(ExecutionTokenVerifier):
    """Explicit in-memory single-use token verifier for single-process deployments.

    Drop-in replacement for :class:`ExecutionTokenVerifier` with an explicit
    name that signals intent: this backend is *not* safe for multi-process or
    multi-server deployments.  For distributed enforcement, use
    :class:`RedisExecutionTokenVerifier` or :class:`SQLiteExecutionTokenVerifier`.

    Identical to :class:`ExecutionTokenVerifier` in all respects — provided
    as a named variant so that code using the explicit backend name is
    searchable and the intent is self-documenting.

    Args:
        secret_key: Must match the key used by :class:`ExecutionTokenSigner`.
    """

    # Inherit all methods from ExecutionTokenVerifier unchanged.


# ── E-1: SQLiteExecutionTokenVerifier ─────────────────────────────────────────


class SQLiteExecutionTokenVerifier:
    """SQLite-backed single-use token verifier for small production deployments.

    Uses WAL-mode SQLite so that concurrent reads do not block writes.  A
    UNIQUE constraint on ``token_id`` provides atomic single-use enforcement —
    the second ``consume()`` call for the same token_id will violate the
    constraint and return ``False`` without any race window.

    Thread-safe: multiple threads in the same process can call ``consume()``
    concurrently.  Not suitable for multi-process or multi-server deployments
    where processes cannot share the same SQLite file on the same host.

    Args:
        secret_key: Must match the key used by :class:`ExecutionTokenSigner`.
        db_path:    Path to the SQLite database file.  Use ``':memory:'`` for
                    testing (not thread-safe across Python threads — prefer a
                    real file path in multi-threaded tests).

    Example::

        verifier = SQLiteExecutionTokenVerifier(
            secret_key=secret, db_path="/var/lib/pramanix/tokens.db"
        )
        if verifier.consume(token):
            execute_action(token.intent_dump)
        else:
            abort("Token invalid, expired, or already used.")
    """

    def __init__(self, secret_key: bytes, db_path: str = ":memory:") -> None:
        import sqlite3

        if len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes.")
        self._key = secret_key
        self._db_path = db_path
        # check_same_thread=False: we serialise access with a threading.Lock below.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        import sqlite3

        with self._lock:
            cur = self._conn.cursor()
            # WAL mode for better concurrent read performance.
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute(
                "CREATE TABLE IF NOT EXISTS consumed_tokens ("
                "  token_id  TEXT NOT NULL PRIMARY KEY,"
                "  expires_at REAL NOT NULL"
                ")"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires ON consumed_tokens(expires_at)"
            )
            self._conn.commit()

    def _evict_expired(self) -> None:
        """Delete expired rows.  Must be called under self._lock."""
        cur = self._conn.cursor()
        cur.execute("DELETE FROM consumed_tokens WHERE expires_at < ?", (time.time(),))
        self._conn.commit()

    def consume(
        self,
        token: ExecutionToken,
        *,
        expected_state_version: str | None = None,
    ) -> bool:
        """Verify and single-use-consume a token.

        Returns ``True`` iff all four checks pass:
        1. HMAC signature is valid.
        2. Token has not expired.
        3. ``expected_state_version`` matches (when provided).
        4. Token has not been consumed before (UNIQUE constraint).
        """
        import sqlite3

        # ── 1. Signature check ────────────────────────────────────────────────
        unsigned = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature="",
            state_version=token.state_version,
        )
        expected_sig = hmac.new(self._key, _token_body(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            return False

        # ── 2. Expiry check ───────────────────────────────────────────────────
        if token.is_expired():
            return False

        # ── 3. State version check ────────────────────────────────────────────
        if (
            token.state_version is not None or expected_state_version is not None
        ) and token.state_version != expected_state_version:
            return False

        # ── 4. Single-use (atomic INSERT — UNIQUE constraint) ─────────────────
        with self._lock:
            self._evict_expired()
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "INSERT INTO consumed_tokens (token_id, expires_at) VALUES (?, ?)",
                    (token.token_id, token.expires_at),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                # UNIQUE constraint violation — token already consumed.
                return False

        return True

    def consumed_count(self) -> int:
        """Return the number of non-expired token IDs in the database."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM consumed_tokens WHERE expires_at >= ?",
                (time.time(),),
            )
            row = cur.fetchone()
            return row[0] if row else 0

    def evict_expired(self) -> int:
        """Force eviction of expired entries.  Returns the count removed."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM consumed_tokens WHERE expires_at < ?", (time.time(),))
            row = cur.fetchone()
            count = row[0] if row else 0
            self._evict_expired()
            return count

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()


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

    def consume(
        self,
        token: ExecutionToken,
        *,
        expected_state_version: str | None = None,
    ) -> bool:
        """Verify and atomically consume a token via Redis SETNX.

        Args:
            token:                  The :class:`ExecutionToken` to verify and consume.
            expected_state_version: Current state version/ETag at execution time.
                                    If the token carries a ``state_version`` and
                                    this argument differs, returns ``False``
                                    (TOCTOU state-mutation guard).

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
            state_version=token.state_version,
        )
        expected_sig = hmac.new(
            self._key, _token_body(unsigned), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            return False

        # ── 2. Expiry check ───────────────────────────────────────────────────
        if token.is_expired():
            return False

        # ── 3. State version check (TOCTOU guard) ─────────────────────────────
        if (
            token.state_version is not None or expected_state_version is not None
        ) and token.state_version != expected_state_version:
            return False

        # ── 4. Atomic SETNX with TTL = remaining token lifetime ───────────────
        # max(1, ...) ensures the key gets at least 1 second TTL even if the
        # token is about to expire — so Redis doesn't reject the SET.
        # Fail-safe: any Redis error → deny (False), never allow.
        remaining_s = max(1, int(token.expires_at - time.time()))
        redis_key = f"{self._prefix}{token.token_id}"
        try:
            result = self._redis.set(redis_key, "1", nx=True, ex=remaining_s)
        except Exception:
            return False
        return bool(result)

    def consumed_count(self) -> int:
        """Count active (not yet expired) consumed token keys in Redis.

        Uses ``SCAN`` to iterate the keyspace — O(N) on large keyspaces.
        Use for monitoring dashboards only, not on hot paths.

        Returns:
            Number of unconsumed-TTL token keys in Redis under this prefix.
            Returns 0 if Redis is unreachable (fail-safe default).
        """
        cursor = 0
        count = 0
        try:
            while True:
                cursor, keys = self._redis.scan(
                    cursor, match=f"{self._prefix}*", count=100
                )
                count += len(keys)
                if cursor == 0:
                    break
        except Exception:
            return 0
        return count


# ── E-1: Postgres-backed distributed verifier ─────────────────────────────────


class PostgresExecutionTokenVerifier:
    """Postgres-backed single-use token verifier using ``asyncpg``.

    Suitable for multi-server deployments where Redis is unavailable or a
    relational audit trail is preferred.  Uses a ``consumed_tokens`` table with
    a ``UNIQUE`` constraint on ``token_id`` to guarantee atomicity — two
    concurrent ``consume()`` calls for the same token will result in exactly one
    ``True`` return and one ``False`` return, with no race window.

    Token IDs are stored with their expiry time so expired entries can be
    evicted periodically without scanning all rows.

    Implementation note
    -------------------
    ``asyncpg`` is async-only; this class wraps all operations with
    ``asyncio.run()`` so the public API remains synchronous (consistent with
    :class:`SQLiteExecutionTokenVerifier` and :class:`RedisExecutionTokenVerifier`).
    If you are already in an async context, call the ``_async_*`` helpers directly.

    Requires: ``pip install 'pramanix[postgres]'`` (``asyncpg``).

    Args:
        secret_key:  Must match the key used by :class:`ExecutionTokenSigner`.
        dsn:         asyncpg connection DSN, e.g.
                     ``"postgresql://user:pass@host/db"``.
        key_prefix:  Not used for table lookups but kept for API symmetry.
                     Default: ``"pramanix:token:"``.

    Raises:
        ConfigurationError: If ``asyncpg`` is not installed.
        ValueError:          If ``secret_key`` is shorter than 16 bytes.

    Example::

        verifier = PostgresExecutionTokenVerifier(
            secret_key=secret,
            dsn="postgresql://app_user:hunter2@db.prod/pramanix",
        )
        if verifier.consume(token):
            execute_action(token.intent_dump)
        else:
            abort("Token already used or invalid.")
    """

    def __init__(
        self,
        secret_key: bytes,
        dsn: str,
        key_prefix: str = "pramanix:token:",
    ) -> None:
        try:
            import asyncpg  # noqa: F401
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "asyncpg is required for PostgresExecutionTokenVerifier. "
                "Install it with: pip install 'pramanix[postgres]'"
            ) from exc

        if len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes.")
        self._key = secret_key
        self._dsn = dsn
        self._prefix = key_prefix  # for API symmetry only

    def _run(self, coro: Any) -> Any:
        """Run *coro* synchronously, creating an event loop if necessary."""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We are inside an async context (e.g., running under pytest-asyncio).
                # Use a new thread with its own event loop to avoid nesting.
                import concurrent.futures
                import threading

                result: list[Any] = []
                exc_container: list[BaseException] = []

                def _run_in_thread() -> None:
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        result.append(new_loop.run_until_complete(coro))
                    except BaseException as e:
                        exc_container.append(e)
                    finally:
                        new_loop.close()

                t = threading.Thread(target=_run_in_thread)
                t.start()
                t.join()
                if exc_container:
                    raise exc_container[0]
                return result[0]
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    async def _ensure_table(self, conn: Any) -> None:
        """Create the consumed_tokens table if it does not exist."""
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS consumed_tokens (
                token_id   TEXT    NOT NULL PRIMARY KEY,
                expires_at DOUBLE PRECISION NOT NULL
            )
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ct_expires
            ON consumed_tokens(expires_at)
        """)

    async def _async_consume(
        self,
        token: ExecutionToken,
        expected_state_version: str | None,
    ) -> bool:
        import asyncpg  # type: ignore[import-untyped]

        # ── 1. Signature check ────────────────────────────────────────────────
        unsigned = ExecutionToken(
            decision_id=token.decision_id,
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature="",
            state_version=token.state_version,
        )
        expected_sig = hmac.new(self._key, _token_body(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            return False

        # ── 2. Expiry check ───────────────────────────────────────────────────
        if token.is_expired():
            return False

        # ── 3. State version check ────────────────────────────────────────────
        if (
            token.state_version is not None or expected_state_version is not None
        ) and token.state_version != expected_state_version:
            return False

        # ── 4. Atomic INSERT with UNIQUE constraint ───────────────────────────
        conn: Any = await asyncpg.connect(self._dsn)
        try:
            await self._ensure_table(conn)
            try:
                await conn.execute(
                    "INSERT INTO consumed_tokens (token_id, expires_at) VALUES ($1, $2)",
                    token.token_id,
                    token.expires_at,
                )
                return True
            except asyncpg.UniqueViolationError:
                # Token already consumed — single-use enforced.
                return False
        finally:
            await conn.close()

    def consume(
        self,
        token: ExecutionToken,
        *,
        expected_state_version: str | None = None,
    ) -> bool:
        """Verify and single-use-consume a token against Postgres.

        Returns:
            ``True`` iff all four checks pass and the INSERT succeeded.
            ``False`` if the token is invalid, expired, state-version-mismatched,
            or has already been consumed.
        """
        return self._run(self._async_consume(token, expected_state_version))

    async def _async_evict_expired(self) -> int:
        import asyncpg  # type: ignore[import-untyped]

        conn: Any = await asyncpg.connect(self._dsn)
        try:
            await self._ensure_table(conn)
            result = await conn.execute(
                "DELETE FROM consumed_tokens WHERE expires_at < $1",
                time.time(),
            )
            # asyncpg returns "DELETE N" as a string.
            parts = result.split()
            return int(parts[1]) if len(parts) == 2 else 0
        finally:
            await conn.close()

    def evict_expired(self) -> int:
        """Delete expired token records from Postgres.

        Returns:
            Number of rows deleted.
        """
        return self._run(self._async_evict_expired())

    async def _async_consumed_count(self) -> int:
        import asyncpg  # type: ignore[import-untyped]

        conn: Any = await asyncpg.connect(self._dsn)
        try:
            await self._ensure_table(conn)
            row = await conn.fetchrow(
                "SELECT COUNT(*) AS n FROM consumed_tokens WHERE expires_at >= $1",
                time.time(),
            )
            return row["n"] if row else 0
        finally:
            await conn.close()

    def consumed_count(self) -> int:
        """Count non-expired consumed tokens in Postgres.

        Returns:
            Number of active (not yet expired) consumed token entries.
        """
        return self._run(self._async_consumed_count())
