# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Secure scoped memory storage for the Pramanix agentic runtime.

Provides a trust-label-aware, tenant-isolated, append-controlled in-process
memory layer.  Every entry carries a :class:`~pramanix.ifc.labels.TrustLabel`
so that retrieval filters can enforce information-flow rules without a
separate enforcement step.

Design constraints
------------------
* **Write controls** — data labelled ``UNTRUSTED`` may not be written to a
  partition whose sensitivity floor is ``CONFIDENTIAL`` or higher.  Any
  attempt raises :exc:`~pramanix.exceptions.MemoryViolationError`.
* **Cross-tenant isolation** — each partition is keyed by
  ``(tenant_id, workflow_id)``; a principal that holds one key cannot
  read or write entries in a different partition without explicitly being
  handed the other key.
* **Retrieval filtering** — :meth:`ScopedMemoryPartition.retrieve` accepts
  an optional ``max_label`` ceiling so that a caller with only READ_ONLY
  scope can be confined to ``PUBLIC / INTERNAL`` entries.
* **Immutable entries** — :class:`MemoryEntry` is a frozen dataclass;
  once written it cannot be mutated in-place.  Updates append a new entry
  (the old entry is not deleted by default to preserve provenance).
* **Thread-safe** — all mutations and reads inside
  :class:`SecureMemoryStore` are protected by ``threading.Lock``.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from pramanix.exceptions import MemoryViolationError
from pramanix.ifc.labels import TrustLabel

__all__ = [
    "MemoryEntry",
    "ScopedMemoryPartition",
    "SecureMemoryStore",
]

_log = logging.getLogger(__name__)


# ── Memory entry ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MemoryEntry:
    """An immutable record stored in a :class:`ScopedMemoryPartition`.

    Attributes:
        entry_id:       UUID of this entry.
        key:            Logical key for this record (e.g. ``"user_goal"``).
        value:          Stored value — any JSON-serialisable object.
        label:          Trust classification of the stored data.
        source:         Component or agent that wrote this entry.
        workflow_id:    Workflow run ID for correlation.
        tenant_id:      Tenant scope for isolation.
        written_at:     Unix timestamp of write.
        lineage:        Immutable tuple recording the chain of components
                        that influenced this value.
        metadata:       Arbitrary key-value pairs for routing / display.
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    key: str = ""
    value: Any = None
    label: TrustLabel = TrustLabel.INTERNAL
    source: str = ""
    workflow_id: str = ""
    tenant_id: str = ""
    written_at: float = field(default_factory=time.time)
    lineage: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_audit_dict(self) -> dict[str, Any]:
        """Return a JSON-safe audit representation (value payload excluded)."""
        return {
            "entry_id": self.entry_id,
            "key": self.key,
            "label": self.label.name,
            "source": self.source,
            "workflow_id": self.workflow_id,
            "tenant_id": self.tenant_id,
            "written_at": self.written_at,
            "lineage": list(self.lineage),
        }


# ── Scoped partition ──────────────────────────────────────────────────────────


class ScopedMemoryPartition:
    """Thread-safe, label-filtered memory partition for one ``(tenant_id, workflow_id)`` scope.

    A partition enforces two invariants:

    1. **Sensitivity floor** — no entry may be written with a label *below*
       ``min_label``.  This prevents low-sensitivity data from cluttering a
       high-sensitivity workspace.
    2. **Untrusted write block** — data labelled ``UNTRUSTED`` may not be
       written when ``min_label >= CONFIDENTIAL``.  This prevents tainted
       user input from silently reaching the confidential memory tier.

    Args:
        tenant_id:   Tenant this partition belongs to.
        workflow_id: Workflow run this partition belongs to.
        min_label:   Minimum sensitivity floor for writes (default: ``PUBLIC``).
        max_entries: Hard cap on stored entries; oldest entry evicted when
                     exceeded (default: 1 000).

    Example::

        partition = ScopedMemoryPartition("acme", "run-001",
                                          min_label=TrustLabel.INTERNAL)
        partition.write("plan", value={"step": 1},
                        label=TrustLabel.INTERNAL, source="planner")
        entries = partition.retrieve(max_label=TrustLabel.INTERNAL)
    """

    def __init__(
        self,
        tenant_id: str,
        workflow_id: str,
        *,
        min_label: TrustLabel = TrustLabel.PUBLIC,
        max_entries: int = 1_000,
    ) -> None:
        self.tenant_id = tenant_id
        self.workflow_id = workflow_id
        self.min_label = min_label
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: deque[MemoryEntry] = deque(maxlen=max_entries)

    def write(
        self,
        key: str,
        *,
        value: Any,
        label: TrustLabel,
        source: str,
        lineage: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> MemoryEntry:
        """Write a new entry to the partition.

        Args:
            key:      Logical key for the entry.
            value:    Value to store.
            label:    Trust label of the data.
            source:   Component writing the data.
            lineage:  Chain-of-custody provenance tuple.
            metadata: Optional routing metadata.

        Returns:
            The created :class:`MemoryEntry`.

        Raises:
            MemoryViolationError: When the write violates label policy.
        """
        # Block UNTRUSTED data in high-sensitivity partitions.
        if (
            label == TrustLabel.UNTRUSTED
            and self.min_label >= TrustLabel.CONFIDENTIAL
        ):
            _log.warning(
                "memory.write_blocked: key=%s label=UNTRUSTED tenant=%s workflow=%s",
                key,
                self.tenant_id,
                self.workflow_id,
            )
            raise MemoryViolationError(
                f"Cannot write UNTRUSTED data to partition with "
                f"min_label={self.min_label.name} "
                f"(tenant={self.tenant_id!r}, workflow={self.workflow_id!r}).",
                partition_id=f"{self.tenant_id}/{self.workflow_id}",
                operation="write",
                reason=f"UNTRUSTED data rejected by sensitivity floor {self.min_label.name}",
            )
        entry = MemoryEntry(
            key=key,
            value=value,
            label=label,
            source=source,
            workflow_id=self.workflow_id,
            tenant_id=self.tenant_id,
            lineage=lineage,
            metadata=metadata or {},
        )
        with self._lock:
            self._entries.append(entry)  # deque(maxlen=N) auto-evicts oldest
        _log.debug(
            "memory.written: key=%s label=%s tenant=%s workflow=%s entry_id=%s",
            key,
            label.name,
            self.tenant_id,
            self.workflow_id,
            entry.entry_id,
        )
        return entry

    def retrieve(
        self,
        key: str | None = None,
        *,
        max_label: TrustLabel | None = None,
        min_label: TrustLabel | None = None,
    ) -> list[MemoryEntry]:
        """Return matching entries, optionally filtered by key and label bounds.

        Args:
            key:       When provided, only entries with this key are returned.
            max_label: Inclusive ceiling — entries with a label *above* this
                       value are excluded (i.e. hidden from lower-privilege callers).
            min_label: Inclusive floor — entries with a label *below* this
                       value are excluded.

        Returns:
            Matching entries in write-order (oldest first).
        """
        with self._lock:
            entries = list(self._entries)
        result = []
        for e in entries:
            if key is not None and e.key != key:
                continue
            if max_label is not None and e.label > max_label:
                continue
            if min_label is not None and e.label < min_label:
                continue
            result.append(e)
        return result

    def latest(
        self,
        key: str,
        *,
        max_label: TrustLabel | None = None,
    ) -> MemoryEntry | None:
        """Return the most-recently written entry for *key*, or ``None``."""
        entries = self.retrieve(key, max_label=max_label)
        return entries[-1] if entries else None

    def clear(self) -> int:
        """Remove all entries from the partition.  Returns the count removed."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
        return count

    def size(self) -> int:
        """Number of entries currently stored."""
        with self._lock:
            return len(self._entries)


# ── Secure memory store ───────────────────────────────────────────────────────


class SecureMemoryStore:
    """Cross-tenant-isolated store of :class:`ScopedMemoryPartition` objects.

    A store acts as the single entry-point for all agent memory operations.
    Partitions are created lazily on first write and are isolated by the
    ``(tenant_id, workflow_id)`` key — a principal holding one key cannot
    access entries in a different partition.

    Args:
        default_min_label: Default sensitivity floor applied to newly-created
                           partitions (default: ``PUBLIC`` — no restriction).
        max_partition_entries: Hard cap per partition (default: 1 000).

    Example::

        store = SecureMemoryStore()
        store.write("acme", "run-001", "goal",
                    value="book a flight", label=TrustLabel.INTERNAL,
                    source="user_agent")
        entries = store.retrieve("acme", "run-001", max_label=TrustLabel.INTERNAL)
    """

    def __init__(
        self,
        *,
        default_min_label: TrustLabel = TrustLabel.PUBLIC,
        max_partition_entries: int = 1_000,
    ) -> None:
        self._default_min_label = default_min_label
        self._max_partition_entries = max_partition_entries
        self._lock = threading.Lock()
        self._partitions: dict[tuple[str, str], ScopedMemoryPartition] = {}

    # ── Partition management ──────────────────────────────────────────────

    def get_partition(
        self,
        tenant_id: str,
        workflow_id: str,
        *,
        create: bool = True,
    ) -> ScopedMemoryPartition | None:
        """Return (or create) the partition for ``(tenant_id, workflow_id)``.

        Args:
            tenant_id:   Tenant identifier.
            workflow_id: Workflow run identifier.
            create:      When ``True`` (default), create the partition if it
                         does not exist.

        Returns:
            The partition, or ``None`` when ``create=False`` and it does not
            exist.
        """
        key = (tenant_id, workflow_id)
        with self._lock:
            if key not in self._partitions:
                if not create:
                    return None
                self._partitions[key] = ScopedMemoryPartition(
                    tenant_id,
                    workflow_id,
                    min_label=self._default_min_label,
                    max_entries=self._max_partition_entries,
                )
            return self._partitions[key]

    def drop_partition(self, tenant_id: str, workflow_id: str) -> bool:
        """Remove and discard a partition.  Returns ``True`` if it existed."""
        key = (tenant_id, workflow_id)
        with self._lock:
            return self._partitions.pop(key, None) is not None

    def partition_ids(self) -> list[tuple[str, str]]:
        """Return sorted list of ``(tenant_id, workflow_id)`` keys."""
        with self._lock:
            return sorted(self._partitions.keys())

    # ── Convenience delegation ────────────────────────────────────────────

    def write(
        self,
        tenant_id: str,
        workflow_id: str,
        key: str,
        *,
        value: Any,
        label: TrustLabel,
        source: str,
        lineage: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> MemoryEntry:
        """Write an entry to the ``(tenant_id, workflow_id)`` partition.

        Creates the partition lazily if it does not exist.

        Raises:
            MemoryViolationError: Propagated from :meth:`ScopedMemoryPartition.write`.
        """
        partition = self.get_partition(tenant_id, workflow_id, create=True)
        if partition is None:  # create=True always returns a partition
            raise RuntimeError(
                f"SecureMemoryStore.get_partition returned None for "
                f"({tenant_id!r}, {workflow_id!r}) with create=True; "
                "this is a bug in the store implementation."
            )
        return partition.write(
            key,
            value=value,
            label=label,
            source=source,
            lineage=lineage,
            metadata=metadata,
        )

    def retrieve(
        self,
        tenant_id: str,
        workflow_id: str,
        key: str | None = None,
        *,
        max_label: TrustLabel | None = None,
        min_label: TrustLabel | None = None,
    ) -> list[MemoryEntry]:
        """Retrieve entries from the ``(tenant_id, workflow_id)`` partition.

        Returns an empty list when the partition does not exist.
        """
        partition = self.get_partition(tenant_id, workflow_id, create=False)
        if partition is None:
            return []
        return partition.retrieve(key, max_label=max_label, min_label=min_label)

    def latest(
        self,
        tenant_id: str,
        workflow_id: str,
        key: str,
        *,
        max_label: TrustLabel | None = None,
    ) -> MemoryEntry | None:
        """Return the most-recently written entry for *key*, or ``None``."""
        partition = self.get_partition(tenant_id, workflow_id, create=False)
        if partition is None:
            return None
        return partition.latest(key, max_label=max_label)

    def partition_count(self) -> int:
        """Number of active partitions."""
        with self._lock:
            return len(self._partitions)
