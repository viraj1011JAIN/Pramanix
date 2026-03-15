# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Intent extraction cache for Pramanix NLP mode.

Caches LLM extraction results to eliminate repeated API calls for
identical natural-language inputs. Only the extraction step is cached.
Pydantic validation and Z3 verification always run on every request.

SECURITY INVARIANTS (enforced by tests):
1. Z3 solver is ALWAYS called — cache hit does NOT bypass Z3
2. Pydantic validation is ALWAYS called — malformed cache entries are rejected
3. State is NEVER part of the cache key — same input, different state = different Z3 result
4. Cache is disabled by default (PRAMANIX_INTENT_CACHE_ENABLED must be "true")
5. Cache stores only the raw extracted dict — not a Decision, not allowed/blocked status

Enabled via:
    PRAMANIX_INTENT_CACHE_ENABLED=true
    PRAMANIX_INTENT_CACHE_TTL_SECONDS=300   (default)
    PRAMANIX_INTENT_CACHE_MAX_SIZE=1024     (in-process LRU, default)
    PRAMANIX_INTENT_CACHE_REDIS_URL=...     (optional Redis backend)
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import time
import unicodedata
from threading import Lock
from typing import Any


def _normalize_key(text: str) -> str:
    """Produce a deterministic, collision-resistant cache key.

    Steps:
    1. NFKC Unicode normalization (handles full-width digits, etc.)
    2. Strip leading/trailing whitespace
    3. Lowercase
    4. SHA-256 hash (64 hex chars)

    The hash ensures:
    - Constant-time key comparison (no timing oracle on input length)
    - No accidental key collision from Unicode variants
    - Fixed key size regardless of input length
    """
    normalized = unicodedata.normalize("NFKC", text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class _CacheEntry:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: dict[str, Any], ttl_seconds: float) -> None:
        self.value = value
        self.expires_at = time.monotonic() + ttl_seconds

    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at


class _InProcessLRUCache:
    """Thread-safe in-process LRU cache with TTL."""

    def __init__(self, maxsize: int = 1024, ttl_seconds: float = 300.0) -> None:
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._store: dict[str, _CacheEntry] = {}
        self._lock = Lock()

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.is_expired():
                del self._store[key]
                return None
            # Update LRU order
            del self._store[key]
            self._store[key] = entry
            return dict(entry.value)  # Return copy — never expose mutable ref

    def set(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            if key in self._store:
                del self._store[key]
            elif len(self._store) >= self._maxsize:
                # Evict oldest (first) entry
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[key] = _CacheEntry(dict(value), self._ttl)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)


class _RedisCache:
    """Redis-backed intent cache. Requires redis package."""

    def __init__(
        self,
        redis_client: Any,
        ttl_seconds: int = 300,
        key_prefix: str = "pramanix:intent:",
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._prefix = key_prefix

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            import json

            raw = self._redis.get(f"{self._prefix}{key}")
            if raw is None:
                return None
            return dict(json.loads(raw))
        except Exception:
            return None  # Redis failure → cache miss (safe)

    def set(self, key: str, value: dict[str, Any]) -> None:
        try:
            import json

            self._redis.setex(
                f"{self._prefix}{key}",
                self._ttl,
                json.dumps(value, default=str),
            )
        except Exception:
            pass  # Redis failure → silent (cache is best-effort)

    def invalidate(self, key: str) -> None:
        with contextlib.suppress(Exception):
            self._redis.delete(f"{self._prefix}{key}")

    def clear(self) -> None:
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=f"{self._prefix}*", count=100)
                if keys:
                    self._redis.delete(*keys)
                if cursor == 0:
                    break
        except Exception:
            pass


class IntentCache:
    """Intent extraction cache for Pramanix NLP mode.

    Wraps either an in-process LRU cache or a Redis backend.
    The backend is transparent to the caller.

    Usage:
        cache = IntentCache.from_env()
        if cache.enabled:
            result = cache.get(user_text)
            ...
            cache.set(user_text, extracted_dict)
    """

    _ENV_ENABLED = "PRAMANIX_INTENT_CACHE_ENABLED"
    _ENV_TTL = "PRAMANIX_INTENT_CACHE_TTL_SECONDS"
    _ENV_MAX_SIZE = "PRAMANIX_INTENT_CACHE_MAX_SIZE"
    _ENV_REDIS = "PRAMANIX_INTENT_CACHE_REDIS_URL"

    def __init__(
        self,
        *,
        enabled: bool = False,
        backend: _InProcessLRUCache | _RedisCache | None = None,
    ) -> None:
        self._enabled = enabled
        self._backend = backend
        self._hits = 0
        self._misses = 0

    @classmethod
    def from_env(cls) -> IntentCache:
        """Create an IntentCache configured from environment variables.

        Disabled by default — must explicitly set
        PRAMANIX_INTENT_CACHE_ENABLED=true to activate.
        """
        enabled = os.environ.get(cls._ENV_ENABLED, "false").lower() == "true"
        if not enabled:
            return cls(enabled=False)

        ttl = float(os.environ.get(cls._ENV_TTL, "300"))
        redis_url = os.environ.get(cls._ENV_REDIS, "")

        if redis_url:
            try:
                import redis

                r = redis.from_url(redis_url)
                r.ping()  # Verify connectivity at startup
                backend: _RedisCache | _InProcessLRUCache = _RedisCache(
                    redis_client=r, ttl_seconds=int(ttl)
                )
            except Exception:
                # Redis unavailable → fall back to in-process LRU
                maxsize = int(os.environ.get(cls._ENV_MAX_SIZE, "1024"))
                backend = _InProcessLRUCache(maxsize=maxsize, ttl_seconds=ttl)
        else:
            maxsize = int(os.environ.get(cls._ENV_MAX_SIZE, "1024"))
            backend = _InProcessLRUCache(maxsize=maxsize, ttl_seconds=ttl)

        return cls(enabled=True, backend=backend)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self._enabled,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": (
                self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0.0
            ),
        }

    def get(self, user_text: str) -> dict[str, Any] | None:
        """Return cached extraction dict, or None on miss.

        Never raises. Cache failure returns None (safe degradation).
        """
        if not self._enabled or not self._backend:
            return None
        try:
            key = _normalize_key(user_text)
            result = self._backend.get(key)
            if result is None:
                self._misses += 1
            else:
                self._hits += 1
            return result
        except Exception:
            self._misses += 1
            return None

    def set(self, user_text: str, extracted: dict[str, Any]) -> None:
        """Store extraction result for user_text.

        Never raises. Cache failure is silently ignored.
        """
        if not self._enabled or not self._backend:
            return
        try:
            key = _normalize_key(user_text)
            self._backend.set(key, dict(extracted))  # Store copy
        except Exception:
            pass

    def invalidate(self, user_text: str) -> None:
        """Explicitly invalidate a cache entry."""
        if not self._enabled or not self._backend:
            return
        try:
            key = _normalize_key(user_text)
            self._backend.invalidate(key)
        except Exception:
            pass

    def clear(self) -> None:
        """Clear all cache entries."""
        if not self._enabled or not self._backend:
            return
        with contextlib.suppress(Exception):
            self._backend.clear()
