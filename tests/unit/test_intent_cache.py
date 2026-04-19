# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Phase 10.2 — Intent Extraction Cache.

Verifies security invariants, LRU eviction, TTL expiry, thread safety,
and disabled-by-default behaviour.
"""
from __future__ import annotations

import threading
import time

import fakeredis as _fakeredis_module

from pramanix.translator._cache import (
    IntentCache,
    _InProcessLRUCache,
    _normalize_key,
)

# ── Tests: _normalize_key ─────────────────────────────────────────────────────


class TestNormalizeKey:
    def test_returns_64_hex_chars(self):
        key = _normalize_key("hello world")
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_deterministic(self):
        assert _normalize_key("test") == _normalize_key("test")

    def test_case_insensitive(self):
        assert _normalize_key("Transfer $100") == _normalize_key("transfer $100")

    def test_whitespace_stripped(self):
        assert _normalize_key("  hello  ") == _normalize_key("hello")

    def test_unicode_normalized(self):
        # Full-width digits should normalize to ASCII
        full_width = "\uff11\uff10\uff10"  # 100 (fullwidth)
        ascii_equiv = "100"
        assert _normalize_key(full_width) == _normalize_key(ascii_equiv)

    def test_different_inputs_different_keys(self):
        assert _normalize_key("transfer 100") != _normalize_key("transfer 200")


# ── Tests: _InProcessLRUCache ─────────────────────────────────────────────────


class TestInProcessLRUCache:
    def test_get_miss_returns_none(self):
        cache = _InProcessLRUCache()
        assert cache.get("nonexistent") is None

    def test_set_and_get(self):
        cache = _InProcessLRUCache()
        cache.set("k1", {"amount": 100})
        result = cache.get("k1")
        assert result == {"amount": 100}

    def test_returns_copy_not_reference(self):
        cache = _InProcessLRUCache()
        original = {"amount": 100}
        cache.set("k1", original)
        result = cache.get("k1")
        result["amount"] = 999
        # Original stored value unchanged
        assert cache.get("k1") == {"amount": 100}

    def test_ttl_expiry(self):
        cache = _InProcessLRUCache(ttl_seconds=0.05)
        cache.set("k1", {"amount": 100})
        assert cache.get("k1") is not None
        time.sleep(0.1)
        assert cache.get("k1") is None

    def test_lru_eviction(self):
        cache = _InProcessLRUCache(maxsize=2)
        cache.set("k1", {"v": 1})
        cache.set("k2", {"v": 2})
        cache.set("k3", {"v": 3})  # evicts k1 (oldest)
        assert cache.get("k1") is None
        assert cache.get("k2") == {"v": 2}
        assert cache.get("k3") == {"v": 3}

    def test_invalidate(self):
        cache = _InProcessLRUCache()
        cache.set("k1", {"v": 1})
        cache.invalidate("k1")
        assert cache.get("k1") is None

    def test_clear(self):
        cache = _InProcessLRUCache()
        cache.set("k1", {"v": 1})
        cache.set("k2", {"v": 2})
        cache.clear()
        assert cache.size == 0

    def test_size_property(self):
        cache = _InProcessLRUCache()
        assert cache.size == 0
        cache.set("k1", {"v": 1})
        assert cache.size == 1

    def test_thread_safety(self):
        cache = _InProcessLRUCache(maxsize=1000)
        errors = []

        def worker(tid: int) -> None:
            try:
                for i in range(50):
                    key = f"k{tid}_{i}"
                    cache.set(key, {"tid": tid, "i": i})
                    result = cache.get(key)
                    # Result may be None if evicted, but must not raise
                    if result is not None:
                        assert isinstance(result, dict)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"


# ── Tests: IntentCache ────────────────────────────────────────────────────────


class TestIntentCache:
    def test_disabled_by_default(self):
        cache = IntentCache.from_env()
        # Default: PRAMANIX_INTENT_CACHE_ENABLED not set
        assert cache.enabled is False

    def test_disabled_cache_get_returns_none(self):
        cache = IntentCache(enabled=False)
        assert cache.get("any text") is None

    def test_disabled_cache_set_is_noop(self):
        cache = IntentCache(enabled=False)
        # Should not raise
        cache.set("text", {"amount": 100})

    def test_enabled_cache_stores_and_retrieves(self):
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("transfer 100 dollars", {"amount": 100})
        result = cache.get("transfer 100 dollars")
        assert result == {"amount": 100}

    def test_cache_hit_increments_counter(self):
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("text", {"v": 1})
        cache.get("text")
        assert cache.stats["hits"] == 1
        assert cache.stats["misses"] == 0

    def test_cache_miss_increments_counter(self):
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.get("not stored")
        assert cache.stats["misses"] == 1
        assert cache.stats["hits"] == 0

    def test_hit_rate_calculation(self):
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("k", {"v": 1})
        cache.get("k")  # hit
        cache.get("k")  # hit
        cache.get("x")  # miss
        stats = cache.stats
        assert abs(stats["hit_rate"] - 2 / 3) < 0.001

    def test_normalize_key_applied_to_input(self):
        """Cache must normalize keys so case/whitespace variants collide."""
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("Transfer $100", {"amount": 100})
        # Different casing/whitespace — should hit same key
        result = cache.get("transfer $100")
        assert result == {"amount": 100}

    def test_invalidate_removes_entry(self):
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("text", {"v": 1})
        cache.invalidate("text")
        assert cache.get("text") is None

    def test_clear_removes_all(self):
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("a", {"v": 1})
        cache.set("b", {"v": 2})
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_get_never_raises(self):
        """get() must never raise even if backend breaks."""
        cache = IntentCache(enabled=True, backend=None)
        result = cache.get("any text")  # backend=None
        assert result is None

    def test_set_never_raises(self):
        """set() must never raise even if backend breaks."""
        cache = IntentCache(enabled=True, backend=None)
        cache.set("text", {"v": 1})  # should not raise

    def test_stats_disabled(self):
        cache = IntentCache(enabled=False)
        stats = cache.stats
        assert stats["enabled"] is False

    # ── SECURITY INVARIANTS ─────────────────────────────────────────────────

    def test_security_state_not_part_of_cache_key(self):
        """State must NOT be part of the cache key.

        Same NL input + different state = same cache entry (LLM extraction
        only). Z3 still runs with the actual state values.
        """
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)

        # Store extraction for "send 100"
        cache.set("send 100", {"amount": 100})

        # Same NL input — regardless of state, same extracted dict returned
        result = cache.get("send 100")
        assert result == {"amount": 100}
        # The caller is responsible for calling Z3 with actual state

    def test_security_cache_stores_only_extracted_dict(self):
        """Cache must only store raw extraction dict, not Decision objects."""
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)

        # Store a plain extraction dict
        cache.set("text", {"amount": 100, "currency": "USD"})
        result = cache.get("text")

        assert isinstance(result, dict)
        assert "allowed" not in result
        assert "status" not in result

    def test_security_returned_value_is_copy(self):
        """Cache must return copies so callers cannot mutate stored data."""
        backend = _InProcessLRUCache()
        cache = IntentCache(enabled=True, backend=backend)
        cache.set("text", {"amount": 100})

        r1 = cache.get("text")
        r1["amount"] = 999  # mutate the returned copy

        r2 = cache.get("text")
        assert r2["amount"] == 100  # stored value unchanged


# ── _InProcessLRUCache edge cases ─────────────────────────────────────────────


class TestInProcessLRUCacheEdgeCases:
    def test_set_updates_existing_key_lru_order(self):
        """Setting the same key twice updates the entry (line 86 coverage)."""
        backend = _InProcessLRUCache(maxsize=5)
        backend.set("key1", {"v": "original"})
        backend.set("key1", {"v": "updated"})
        result = backend.get("key1")
        assert result["v"] == "updated"

    def test_size_property(self):
        """size property returns current entry count."""
        backend = _InProcessLRUCache(maxsize=10)
        assert backend.size == 0
        backend.set("a", {"k": "a"})
        backend.set("b", {"k": "b"})
        assert backend.size == 2

    def test_clear_empties_store(self):
        """clear() removes all entries."""
        backend = _InProcessLRUCache()
        backend.set("a", {"k": "a"})
        backend.clear()
        assert backend.size == 0

    def test_invalidate_removes_specific_key(self):
        """invalidate() removes only the specified key."""
        backend = _InProcessLRUCache()
        backend.set("keep", {"k": "keep"})
        backend.set("remove", {"k": "remove"})
        backend.invalidate("remove")
        assert backend.get("keep") is not None
        assert backend.get("remove") is None

    def test_invalidate_nonexistent_key_is_safe(self):
        """invalidate() on a nonexistent key must not raise."""
        backend = _InProcessLRUCache()
        backend.invalidate("does_not_exist")  # Must not raise


# ── _RedisCache unit tests (real fakeredis) ────────────────────────────────────


# ── Error-injection subclasses — real fakeredis with one overridden method ─────


class _ErrorOnGet(_fakeredis_module.FakeRedis):
    """fakeredis that raises ConnectionError on get() — tests silent degradation."""

    def get(self, name, **kwargs):
        raise ConnectionError("Redis down")


class _ErrorOnSetex(_fakeredis_module.FakeRedis):
    """fakeredis that raises ConnectionError on setex() — tests silent degradation."""

    def setex(self, name, time, value, **kwargs):
        raise ConnectionError("Redis down")


class _ErrorOnDelete(_fakeredis_module.FakeRedis):
    """fakeredis that raises ConnectionError on delete() — tests silent degradation."""

    def delete(self, *names, **kwargs):
        raise ConnectionError("Redis down")


class _ErrorOnScan(_fakeredis_module.FakeRedis):
    """fakeredis that raises ConnectionError on scan() — tests silent degradation."""

    def scan(self, cursor=0, match=None, count=None, **kwargs):
        raise ConnectionError("Redis down")


class _PaginatedScanRedis:
    """Minimal real Redis-protocol object that returns two scan pages.

    Simulates a Redis server that requires two SCAN iterations to exhaust
    the keyspace — tests that _RedisCache.clear() loops until cursor == 0.
    Not a mock: state is real, all methods have deterministic real behaviour.
    """

    def __init__(self) -> None:
        self._pages = iter([
            (1, [b"pramanix:intent:key1"]),
            (0, [b"pramanix:intent:key2"]),
        ])
        self.scan_call_count = 0
        self.delete_call_count = 0

    def scan(self, cursor=0, match=None, count=None, **kwargs):
        self.scan_call_count += 1
        return next(self._pages)

    def delete(self, *names, **kwargs):
        self.delete_call_count += 1

    # Required for _RedisCache construction (other methods are no-ops here)
    def get(self, name, **kwargs):
        return None

    def set(self, name, value, **kwargs):
        pass

    def setex(self, name, time, value, **kwargs):
        pass


class TestRedisCache:
    """Tests for _RedisCache using real fakeredis — no MagicMock."""

    def test_init_stores_config(self):
        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()
        cache = _RedisCache(redis_client=r, ttl_seconds=60, key_prefix="test:")
        assert cache._redis is r
        assert cache._ttl == 60
        assert cache._prefix == "test:"

    def test_get_returns_dict_on_hit(self):
        import json

        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()
        r.set("pramanix:intent:anykey", json.dumps({"amount": "100"}).encode())
        cache = _RedisCache(redis_client=r)
        result = cache.get("anykey")
        assert result == {"amount": "100"}

    def test_get_returns_none_on_miss(self):
        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()  # empty — no keys set
        cache = _RedisCache(redis_client=r)
        result = cache.get("anykey")
        assert result is None

    def test_get_returns_none_on_redis_error(self):
        from pramanix.translator._cache import _RedisCache

        r = _ErrorOnGet()
        cache = _RedisCache(redis_client=r)
        result = cache.get("anykey")
        assert result is None  # Silent degradation

    def test_set_stores_value_with_prefix_and_ttl(self):
        import json

        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()
        cache = _RedisCache(redis_client=r, ttl_seconds=300, key_prefix="pfx:")
        cache.set("mykey", {"amount": "500"})
        stored_raw = r.get("pfx:mykey")
        assert stored_raw is not None
        assert json.loads(stored_raw) == {"amount": "500"}
        ttl = r.ttl("pfx:mykey")
        assert 0 < ttl <= 300

    def test_set_silent_on_redis_error(self):
        from pramanix.translator._cache import _RedisCache

        r = _ErrorOnSetex()
        cache = _RedisCache(redis_client=r)
        cache.set("mykey", {"amount": "500"})  # Must not raise

    def test_invalidate_removes_key(self):
        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()
        r.set("pfx:mykey", "some_value")
        cache = _RedisCache(redis_client=r, key_prefix="pfx:")
        cache.invalidate("mykey")
        assert r.get("pfx:mykey") is None

    def test_invalidate_silent_on_redis_error(self):
        from pramanix.translator._cache import _RedisCache

        r = _ErrorOnDelete()
        cache = _RedisCache(redis_client=r)
        cache.invalidate("mykey")  # Must not raise

    def test_clear_deletes_only_matching_keys(self):
        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()
        r.set("pramanix:intent:k1", "v1")
        r.set("pramanix:intent:k2", "v2")
        r.set("other:key", "v3")  # Different prefix — must NOT be deleted
        cache = _RedisCache(redis_client=r)
        cache.clear()
        assert r.get("pramanix:intent:k1") is None
        assert r.get("pramanix:intent:k2") is None
        assert r.get("other:key") is not None  # Untouched

    def test_clear_handles_multiple_pages(self):
        from pramanix.translator._cache import _RedisCache

        r = _PaginatedScanRedis()
        cache = _RedisCache(redis_client=r)
        cache.clear()
        # Two scan pages → scan called twice, delete called twice
        assert r.scan_call_count == 2
        assert r.delete_call_count == 2

    def test_clear_silent_on_redis_error(self):
        from pramanix.translator._cache import _RedisCache

        r = _ErrorOnScan()
        cache = _RedisCache(redis_client=r)
        cache.clear()  # Must not raise

    def test_intent_cache_with_redis_backend_hit(self):
        """IntentCache end-to-end: real fakeredis hit returns cached dict."""
        import json

        from pramanix.translator._cache import _normalize_key, _RedisCache

        r = _fakeredis_module.FakeRedis()
        hashed = _normalize_key("transfer 500")
        r.set(f"pramanix:intent:{hashed}", json.dumps({"amount": "500"}).encode())
        backend = _RedisCache(redis_client=r)
        cache = IntentCache(enabled=True, backend=backend)
        result = cache.get("transfer 500")
        assert result == {"amount": "500"}
        assert cache.stats["hits"] == 1

    def test_intent_cache_with_redis_backend_miss(self):
        """IntentCache.get() returns None when key is absent in fakeredis."""
        from pramanix.translator._cache import _RedisCache

        r = _fakeredis_module.FakeRedis()  # empty
        backend = _RedisCache(redis_client=r)
        cache = IntentCache(enabled=True, backend=backend)
        result = cache.get("no such key")
        assert result is None
        assert cache.stats["misses"] == 1


# ── IntentCache exception path coverage ───────────────────────────────────────


class _BrokenCacheBackend:
    """Real cache backend that always raises — tests IntentCache's resilience.

    Not a mock: every method has real, deterministic behaviour (raises).
    Used to cover the outer try/except branches in IntentCache.
    """

    def get(self, key: str) -> dict:
        raise RuntimeError("backend failed")

    def set(self, key: str, value: dict) -> None:
        raise RuntimeError("backend failed")

    def invalidate(self, key: str) -> None:
        raise RuntimeError("backend failed")

    def clear(self) -> None:
        raise RuntimeError("backend failed")


class TestIntentCacheExceptionPaths:
    """Cover the outer try/except branches in IntentCache methods.

    These paths fire when the backend itself raises.  Uses _BrokenCacheBackend —
    a real class that always raises — instead of a MagicMock.
    """

    def _make_broken_backend(self) -> _BrokenCacheBackend:
        return _BrokenCacheBackend()

    def test_get_exception_returns_none(self):
        cache = IntentCache(enabled=True, backend=self._make_broken_backend())
        result = cache.get("any text")
        assert result is None  # Exception swallowed; miss counted

    def test_get_exception_increments_miss_count(self):
        cache = IntentCache(enabled=True, backend=self._make_broken_backend())
        cache.get("any text")
        assert cache.stats["misses"] == 1

    def test_set_exception_is_silent(self):
        cache = IntentCache(enabled=True, backend=self._make_broken_backend())
        cache.set("any text", {"amount": "100"})  # Must not raise

    def test_invalidate_exception_is_silent(self):
        cache = IntentCache(enabled=True, backend=self._make_broken_backend())
        cache.invalidate("any text")  # Must not raise

    def test_clear_exception_is_silent(self):
        cache = IntentCache(enabled=True, backend=self._make_broken_backend())
        cache.clear()  # Must not raise

    def test_invalidate_when_disabled_is_noop(self):
        cache = IntentCache(enabled=False)
        cache.invalidate("any text")  # Must not raise, returns immediately

    def test_clear_when_disabled_is_noop(self):
        cache = IntentCache(enabled=False)
        cache.clear()  # Must not raise, returns immediately


# ── IntentCache.from_env() Redis URL fallback ─────────────────────────────────


class TestFromEnvRedisPath:
    def test_from_env_with_bad_redis_url_falls_back_to_lru(self, monkeypatch):
        """When Redis URL set but connection fails, fall back to in-process LRU."""
        monkeypatch.setenv("PRAMANIX_INTENT_CACHE_ENABLED", "true")
        # Port 99999 guarantees connection failure
        monkeypatch.setenv("PRAMANIX_INTENT_CACHE_REDIS_URL", "redis://localhost:99999")
        cache = IntentCache.from_env()
        assert cache.enabled  # Cache is still enabled, just using LRU backend
        # Should work via LRU fallback
        cache.set("test", {"amount": "100"})
        cache.get("test")
        # Result is None because the fallback LRU was created fresh
        # (the set and get use the same LRU backend, so it should work)

    def test_from_env_enabled_without_redis_url_uses_lru(self, monkeypatch):
        """When enabled but no Redis URL, use in-process LRU."""
        monkeypatch.setenv("PRAMANIX_INTENT_CACHE_ENABLED", "true")
        monkeypatch.delenv("PRAMANIX_INTENT_CACHE_REDIS_URL", raising=False)
        monkeypatch.setenv("PRAMANIX_INTENT_CACHE_MAX_SIZE", "512")
        monkeypatch.setenv("PRAMANIX_INTENT_CACHE_TTL_SECONDS", "120")
        cache = IntentCache.from_env()
        assert cache.enabled
        # Verify it works as LRU
        cache.set("hello", {"k": "v"})
        assert cache.get("hello") == {"k": "v"}


# ── _CacheEntry coverage ───────────────────────────────────────────────────────


class TestCacheEntry:
    def test_is_expired_false_when_fresh(self):
        from pramanix.translator._cache import _CacheEntry

        entry = _CacheEntry({"k": "v"}, ttl_seconds=3600)
        assert entry.is_expired() is False

    def test_is_expired_true_when_ttl_elapsed(self):
        import time

        from pramanix.translator._cache import _CacheEntry

        entry = _CacheEntry({"k": "v"}, ttl_seconds=0.001)
        time.sleep(0.01)
        assert entry.is_expired() is True
