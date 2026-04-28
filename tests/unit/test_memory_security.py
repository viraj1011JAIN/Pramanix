# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for secure scoped memory (pramanix.memory).

All tests use real objects — no mocks, no monkeypatching of Pramanix internals.
"""
from __future__ import annotations

import threading

import pytest

from pramanix.exceptions import MemoryViolationError
from pramanix.ifc import TrustLabel
from pramanix.memory import (
    MemoryEntry,
    ScopedMemoryPartition,
    SecureMemoryStore,
)


# ── MemoryEntry tests ─────────────────────────────────────────────────────────


class TestMemoryEntry:
    def _make(self) -> MemoryEntry:
        return MemoryEntry(
            key="goal",
            value={"step": 1},
            label=TrustLabel.INTERNAL,
            source="planner",
            workflow_id="run-001",
            tenant_id="acme",
        )

    def test_frozen(self):
        entry = self._make()
        with pytest.raises((AttributeError, TypeError)):
            entry.value = "modified"  # type: ignore[misc]

    def test_entry_id_is_unique(self):
        e1 = self._make()
        e2 = self._make()
        assert e1.entry_id != e2.entry_id

    def test_to_audit_dict_excludes_value(self):
        entry = self._make()
        audit = entry.to_audit_dict()
        assert "value" not in audit
        assert "entry_id" in audit
        assert "label" in audit
        assert "source" in audit

    def test_to_audit_dict_label_is_name(self):
        entry = self._make()
        assert entry.to_audit_dict()["label"] == "INTERNAL"

    def test_lineage_is_tuple(self):
        entry = MemoryEntry(
            key="k", value=1, label=TrustLabel.PUBLIC,
            source="src", lineage=("a", "b"),
        )
        assert entry.lineage == ("a", "b")


# ── ScopedMemoryPartition tests ───────────────────────────────────────────────


class TestScopedMemoryPartition:
    def _partition(
        self,
        min_label: TrustLabel = TrustLabel.PUBLIC,
    ) -> ScopedMemoryPartition:
        return ScopedMemoryPartition("acme", "run-001", min_label=min_label)

    def test_write_and_retrieve(self):
        p = self._partition()
        entry = p.write(
            "goal", value="book flight", label=TrustLabel.INTERNAL, source="planner"
        )
        retrieved = p.retrieve("goal")
        assert len(retrieved) == 1
        assert retrieved[0].entry_id == entry.entry_id

    def test_retrieve_all_keys(self):
        p = self._partition()
        p.write("a", value=1, label=TrustLabel.INTERNAL, source="s")
        p.write("b", value=2, label=TrustLabel.INTERNAL, source="s")
        all_entries = p.retrieve()
        assert len(all_entries) == 2

    def test_retrieve_key_filter(self):
        p = self._partition()
        p.write("a", value=1, label=TrustLabel.INTERNAL, source="s")
        p.write("b", value=2, label=TrustLabel.INTERNAL, source="s")
        a_only = p.retrieve("a")
        assert all(e.key == "a" for e in a_only)

    def test_retrieve_max_label_filter(self):
        p = self._partition()
        p.write("pub", value=1, label=TrustLabel.PUBLIC, source="s")
        p.write("conf", value=2, label=TrustLabel.CONFIDENTIAL, source="s")
        visible = p.retrieve(max_label=TrustLabel.INTERNAL)
        assert any(e.key == "pub" for e in visible)
        assert not any(e.key == "conf" for e in visible)

    def test_retrieve_min_label_filter(self):
        p = self._partition()
        p.write("pub", value=1, label=TrustLabel.PUBLIC, source="s")
        p.write("conf", value=2, label=TrustLabel.CONFIDENTIAL, source="s")
        high_only = p.retrieve(min_label=TrustLabel.CONFIDENTIAL)
        assert not any(e.key == "pub" for e in high_only)
        assert any(e.key == "conf" for e in high_only)

    def test_latest_returns_newest(self):
        p = self._partition()
        p.write("goal", value="v1", label=TrustLabel.INTERNAL, source="s")
        p.write("goal", value="v2", label=TrustLabel.INTERNAL, source="s")
        latest = p.latest("goal")
        assert latest is not None
        assert latest.value == "v2"

    def test_latest_returns_none_for_missing(self):
        p = self._partition()
        assert p.latest("nonexistent") is None

    def test_untrusted_blocked_in_confidential_partition(self):
        p = self._partition(min_label=TrustLabel.CONFIDENTIAL)
        with pytest.raises(MemoryViolationError) as exc_info:
            p.write("k", value="tainted", label=TrustLabel.UNTRUSTED, source="user")
        err = exc_info.value
        assert "UNTRUSTED" in str(err)
        assert err.operation == "write"

    def test_untrusted_allowed_in_public_partition(self):
        p = self._partition(min_label=TrustLabel.PUBLIC)
        # UNTRUSTED is allowed when partition floor < CONFIDENTIAL
        entry = p.write("k", value="tainted", label=TrustLabel.UNTRUSTED, source="user")
        assert entry.label == TrustLabel.UNTRUSTED

    def test_size(self):
        p = self._partition()
        assert p.size() == 0
        p.write("a", value=1, label=TrustLabel.PUBLIC, source="s")
        assert p.size() == 1

    def test_clear(self):
        p = self._partition()
        p.write("a", value=1, label=TrustLabel.PUBLIC, source="s")
        p.write("b", value=2, label=TrustLabel.PUBLIC, source="s")
        removed = p.clear()
        assert removed == 2
        assert p.size() == 0

    def test_max_entries_evicts_oldest(self):
        p = ScopedMemoryPartition("t", "w", max_entries=3)
        for i in range(5):
            p.write(f"k{i}", value=i, label=TrustLabel.PUBLIC, source="s")
        assert p.size() == 3
        # Oldest (k0, k1) should be gone
        remaining_keys = {e.key for e in p.retrieve()}
        assert "k0" not in remaining_keys
        assert "k4" in remaining_keys

    def test_lineage_stored(self):
        p = self._partition()
        p.write("k", value=1, label=TrustLabel.INTERNAL,
                source="s", lineage=("a", "b"))
        entry = p.retrieve("k")[0]
        assert entry.lineage == ("a", "b")

    def test_thread_safety(self):
        p = self._partition()
        errors: list[Exception] = []

        def writer(i: int) -> None:
            try:
                for j in range(10):
                    p.write(f"k{i}{j}", value=i * j,
                            label=TrustLabel.PUBLIC, source="t")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert p.size() == 50


# ── SecureMemoryStore tests ───────────────────────────────────────────────────


class TestSecureMemoryStore:
    def test_write_creates_partition(self):
        store = SecureMemoryStore()
        store.write("acme", "run-001", "goal",
                    value="book flight", label=TrustLabel.INTERNAL, source="s")
        assert store.partition_count() == 1

    def test_retrieve_empty_for_unknown_partition(self):
        store = SecureMemoryStore()
        entries = store.retrieve("no-tenant", "no-run")
        assert entries == []

    def test_cross_tenant_isolation(self):
        store = SecureMemoryStore()
        store.write("acme", "run-001", "secret",
                    value="ACME secret", label=TrustLabel.CONFIDENTIAL, source="a")
        store.write("beta", "run-001", "secret",
                    value="BETA secret", label=TrustLabel.CONFIDENTIAL, source="b")
        acme = store.retrieve("acme", "run-001", "secret")
        beta = store.retrieve("beta", "run-001", "secret")
        assert acme[0].value == "ACME secret"
        assert beta[0].value == "BETA secret"
        # ACME entries not visible to BETA partition
        beta_all = store.retrieve("beta", "run-001")
        assert all(e.value != "ACME secret" for e in beta_all)

    def test_latest_convenience(self):
        store = SecureMemoryStore()
        store.write("t", "w", "k", value="v1", label=TrustLabel.PUBLIC, source="s")
        store.write("t", "w", "k", value="v2", label=TrustLabel.PUBLIC, source="s")
        latest = store.latest("t", "w", "k")
        assert latest is not None
        assert latest.value == "v2"

    def test_latest_unknown_partition_returns_none(self):
        store = SecureMemoryStore()
        assert store.latest("x", "y", "k") is None

    def test_drop_partition(self):
        store = SecureMemoryStore()
        store.write("t", "w", "k", value=1, label=TrustLabel.PUBLIC, source="s")
        assert store.drop_partition("t", "w") is True
        assert store.partition_count() == 0

    def test_drop_unknown_partition_returns_false(self):
        store = SecureMemoryStore()
        assert store.drop_partition("nobody", "nothing") is False

    def test_partition_ids_sorted(self):
        store = SecureMemoryStore()
        store.write("b", "1", "k", value=1, label=TrustLabel.PUBLIC, source="s")
        store.write("a", "2", "k", value=2, label=TrustLabel.PUBLIC, source="s")
        ids = store.partition_ids()
        assert ids == sorted(ids)

    def test_get_partition_create_false(self):
        store = SecureMemoryStore()
        assert store.get_partition("x", "y", create=False) is None

    def test_get_partition_create_true(self):
        store = SecureMemoryStore()
        p = store.get_partition("x", "y", create=True)
        assert p is not None
        assert p.tenant_id == "x"

    def test_write_violation_propagated(self):
        store = SecureMemoryStore(default_min_label=TrustLabel.CONFIDENTIAL)
        with pytest.raises(MemoryViolationError):
            store.write("t", "w", "k",
                        value="tainted", label=TrustLabel.UNTRUSTED, source="user")
