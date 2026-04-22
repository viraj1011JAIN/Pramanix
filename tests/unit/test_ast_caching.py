# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for InvariantASTCache (C-2)."""
from __future__ import annotations

import threading

import pytest

from pramanix.transpiler import InvariantASTCache, InvariantMeta


def _make_meta(name: str) -> list[InvariantMeta]:
    return [
        InvariantMeta(
            label=name,
            explain_template="",
            field_refs=frozenset({"amount"}),
            tree_repr="",
            has_literal=False,
        )
    ]


# ── Basic get/put ─────────────────────────────────────────────────────────────


def test_cache_miss_returns_none() -> None:
    InvariantASTCache.clear()

    class Dummy:
        pass

    assert InvariantASTCache.get(Dummy, "abc") is None


def test_cache_hit_returns_same_object() -> None:
    InvariantASTCache.clear()

    class MyPolicy:
        pass

    meta = _make_meta("inv1")
    InvariantASTCache.put(MyPolicy, "hash1", meta)
    result = InvariantASTCache.get(MyPolicy, "hash1")
    assert result is meta


def test_cache_size_increments() -> None:
    InvariantASTCache.clear()

    class P1:
        pass

    class P2:
        pass

    InvariantASTCache.put(P1, "h1", _make_meta("a"))
    InvariantASTCache.put(P2, "h2", _make_meta("b"))
    assert InvariantASTCache.size() == 2


def test_cache_update_in_place() -> None:
    InvariantASTCache.clear()

    class Upd:
        pass

    meta1 = _make_meta("first")
    meta2 = _make_meta("second")
    InvariantASTCache.put(Upd, "key", meta1)
    InvariantASTCache.put(Upd, "key", meta2)
    result = InvariantASTCache.get(Upd, "key")
    assert result is meta2
    assert InvariantASTCache.size() == 1  # no duplicate entries


# ── Clear ─────────────────────────────────────────────────────────────────────


def test_clear_all() -> None:
    InvariantASTCache.clear()

    class C1:
        pass

    class C2:
        pass

    InvariantASTCache.put(C1, "h1", _make_meta("x"))
    InvariantASTCache.put(C2, "h2", _make_meta("y"))
    InvariantASTCache.clear()
    assert InvariantASTCache.size() == 0


def test_clear_specific_class() -> None:
    InvariantASTCache.clear()

    class Keep:
        pass

    class Remove:
        pass

    InvariantASTCache.put(Keep, "h1", _make_meta("k"))
    InvariantASTCache.put(Remove, "h2", _make_meta("r"))
    InvariantASTCache.clear(Remove)
    assert InvariantASTCache.size() == 1
    assert InvariantASTCache.get(Keep, "h1") is not None
    assert InvariantASTCache.get(Remove, "h2") is None


# ── LRU eviction ─────────────────────────────────────────────────────────────


def test_lru_eviction() -> None:
    """Least recently used entry is evicted when at max capacity."""
    InvariantASTCache.clear()
    original_max = InvariantASTCache._max_size
    InvariantASTCache._max_size = 3

    try:
        classes = [type(f"Cls{i}", (), {}) for i in range(4)]
        for i, cls in enumerate(classes[:3]):
            InvariantASTCache.put(cls, "h", _make_meta(f"m{i}"))

        # Access first entry to make it MRU
        InvariantASTCache.get(classes[0], "h")

        # Insert 4th — should evict LRU (classes[1])
        InvariantASTCache.put(classes[3], "h", _make_meta("m3"))

        assert InvariantASTCache.size() == 3
        assert InvariantASTCache.get(classes[1], "h") is None  # evicted
        assert InvariantASTCache.get(classes[0], "h") is not None  # MRU kept
    finally:
        InvariantASTCache._max_size = original_max


# ── Thread-safety thrash test ─────────────────────────────────────────────────


def test_concurrent_access_is_safe() -> None:
    """Multiple threads putting/getting should not raise."""
    InvariantASTCache.clear()
    errors: list[Exception] = []

    classes = [type(f"TCls{i}", (), {}) for i in range(10)]

    def worker(cls: type, idx: int) -> None:
        try:
            for _ in range(50):
                InvariantASTCache.put(cls, f"hash{idx}", _make_meta(f"m{idx}"))
                InvariantASTCache.get(cls, f"hash{idx}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(cls, i)) for i, cls in enumerate(classes)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread safety errors: {errors}"
