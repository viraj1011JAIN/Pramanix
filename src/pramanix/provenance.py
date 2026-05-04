# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Runtime provenance and chain-of-custody for Pramanix decisions.

Every :class:`~pramanix.decision.Decision` can be wrapped in a
:class:`ProvenanceRecord` that cryptographically binds the decision to the
policy version, model version, input classification labels, and the set of
tools active at runtime.  A :class:`ProvenanceChain` threads these records
together so that an auditor can reconstruct the full lineage of any action.

Design constraints
------------------
* **Tamper-evident** — each :class:`ProvenanceRecord` carries an HMAC-SHA256
  tag over all its fields.  The :meth:`ProvenanceRecord.verify` method
  re-computes the tag from the stored fields and compares it with
  :func:`hmac.compare_digest` to detect silent modification.
* **Chain integrity** — :class:`ProvenanceChain` links records via
  ``prev_hash`` (SHA-256 of the previous record's HMAC tag) so that
  deletion or re-ordering of any record breaks the chain.
* **Non-repudiation** — the record captures ``policy_hash`` (the
  SHA-256 of the compiled policy) so that the exact policy under which
  a decision was made is permanently bound to the record.
* **Label propagation** — ``input_labels`` records the
  :class:`~pramanix.ifc.labels.TrustLabel` assigned to every input
  field, so information-flow analysis can be performed post-hoc.
* **Tool manifest** — ``tool_manifest`` records the set of tool names
  that were active (e.g. from the capability manifest) at decision time.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from pramanix.exceptions import ProvenanceError

__all__ = [
    "ProvenanceChain",
    "ProvenanceRecord",
]

_log = logging.getLogger(__name__)

# ── Per-process HMAC key ──────────────────────────────────────────────────────

_PROVENANCE_KEY: bytes | None = None
_KEY_LOCK = threading.Lock()


def _provenance_key() -> bytes:
    """Return the stable per-process HMAC key."""
    global _PROVENANCE_KEY
    if _PROVENANCE_KEY is None:
        with _KEY_LOCK:
            if _PROVENANCE_KEY is None:
                _PROVENANCE_KEY = os.urandom(32)
    return _PROVENANCE_KEY


# ── Provenance record ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProvenanceRecord:
    """Tamper-evident chain-of-custody record for a single decision.

    Attributes:
        record_id:      UUID of this record.
        decision_id:    UUID of the :class:`~pramanix.decision.Decision`.
        policy_hash:    SHA-256 of the compiled policy (or ``""`` if unavailable).
        model_version:  Version string of the LLM model used for extraction
                        (or ``""`` for direct-dict calls with no translator).
        input_labels:   Mapping of field name → trust-label name for each
                        input field (e.g. ``{"amount": "INTERNAL"}``).
        tool_manifest:  Frozenset of tool names active at decision time.
        principal_id:   Identity of the agent or service that called verify().
        allowed:        Whether the decision was ALLOW or BLOCK.
        created_at:     Unix timestamp of record creation.
        prev_hash:      HMAC tag of the previous record in the chain,
                        or ``""`` for the genesis record.
        metadata:       Arbitrary key-value pairs for routing / display.
    """

    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str = ""
    policy_hash: str = ""
    model_version: str = ""
    input_labels: dict[str, str] = field(default_factory=dict)
    tool_manifest: frozenset[str] = field(default_factory=frozenset)
    principal_id: str = ""
    allowed: bool = False
    created_at: float = field(default_factory=time.time)
    prev_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── HMAC integrity ────────────────────────────────────────────────────

    def hmac_tag(self, signing_key: bytes | None = None) -> str:
        """Compute and return the HMAC-SHA256 tag for this record.

        The tag is computed over a canonical byte string of all identifying
        fields.  It is *not* stored in the frozen dataclass — callers compute
        it on demand to keep the dataclass value type pure.

        Args:
            signing_key: HMAC key.  Defaults to the stable per-process key.
        """
        key = signing_key or _provenance_key()
        payload = (
            f"{self.record_id}|"
            f"{self.decision_id}|"
            f"{self.policy_hash}|"
            f"{self.model_version}|"
            f"{sorted(self.input_labels.items())}|"
            f"{sorted(self.tool_manifest)}|"
            f"{self.principal_id}|"
            f"{self.allowed}|"
            f"{self.created_at}|"
            f"{self.prev_hash}"
        ).encode()
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    def verify(self, stored_tag: str, signing_key: bytes | None = None) -> bool:
        """Return ``True`` when the record has not been tampered with.

        Args:
            stored_tag:  The HMAC tag produced when the record was first created.
            signing_key: The key used at creation time.
        """
        return hmac.compare_digest(self.hmac_tag(signing_key), stored_tag)

    def to_dict(self, signing_key: bytes | None = None) -> dict[str, Any]:
        """Return a JSON-safe audit representation including the HMAC tag."""
        return {
            "record_id": self.record_id,
            "decision_id": self.decision_id,
            "policy_hash": self.policy_hash,
            "model_version": self.model_version,
            "input_labels": dict(self.input_labels),
            "tool_manifest": sorted(self.tool_manifest),
            "principal_id": self.principal_id,
            "allowed": self.allowed,
            "created_at": self.created_at,
            "prev_hash": self.prev_hash,
            "metadata": dict(self.metadata),
            "hmac_tag": self.hmac_tag(signing_key),
        }

    @classmethod
    def from_decision(
        cls,
        decision: Any,
        *,
        model_version: str = "",
        input_labels: dict[str, str] | None = None,
        tool_manifest: frozenset[str] | None = None,
        principal_id: str = "",
        prev_hash: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> "ProvenanceRecord":
        """Build a record from a :class:`~pramanix.decision.Decision`.

        Args:
            decision:       The decision object.
            model_version:  LLM model version used for extraction (if any).
            input_labels:   Trust labels for input fields.
            tool_manifest:  Active tool names from the capability manifest.
            principal_id:   Agent or service identity.
            prev_hash:      HMAC tag of the preceding chain record.
            metadata:       Arbitrary metadata for correlation.
        """
        return cls(
            decision_id=str(getattr(decision, "decision_id", "") or ""),
            policy_hash=str(getattr(decision, "policy_hash", "") or ""),
            model_version=model_version,
            input_labels=input_labels or {},
            tool_manifest=tool_manifest or frozenset(),
            principal_id=principal_id,
            allowed=bool(getattr(decision, "allowed", False)),
            prev_hash=prev_hash,
            metadata=metadata or {},
        )


# ── Provenance chain ──────────────────────────────────────────────────────────


class ProvenanceChain:
    """Thread-safe, append-only chain of :class:`ProvenanceRecord` objects.

    Each appended record's ``prev_hash`` is set to the HMAC tag of the
    previous record so that:

    * Deletion of any record breaks the chain.
    * Re-ordering of any two records breaks the chain.
    * Modification of any record breaks both its own tag and the next
      record's ``prev_hash`` link.

    Args:
        signing_key: HMAC key for all records in this chain.
                     Defaults to the stable per-process key.
        max_records: Hard cap on retained records; oldest evicted when
                     exceeded (default: 100 000).

    Example::

        chain = ProvenanceChain()
        record = ProvenanceRecord.from_decision(decision)
        chain.append(record)
        assert chain.verify_integrity()
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        *,
        max_records: int = 100_000,
    ) -> None:
        self._key = signing_key or _provenance_key()
        self._max_records = max_records
        self._lock = threading.Lock()
        self._records: deque[ProvenanceRecord] = deque(maxlen=max_records)
        self._tags: deque[str] = deque(maxlen=max_records)

    def append(self, record: ProvenanceRecord) -> str:
        """Append *record* to the chain, rewriting ``prev_hash`` if needed.

        The record's ``prev_hash`` field is *not* re-used from the input;
        the chain always overwrites it with the actual previous tag to
        maintain integrity.  A new :class:`ProvenanceRecord` with the
        correct ``prev_hash`` is created and stored.

        Returns:
            The HMAC tag of the appended record.

        Raises:
            ProvenanceError: If the record's ``decision_id`` is empty.
        """
        if not record.decision_id:
            raise ProvenanceError(
                "ProvenanceRecord must have a non-empty decision_id before appending to a chain.",
                decision_id="",
                reason="empty decision_id",
            )
        with self._lock:
            prev_tag = self._tags[-1] if self._tags else ""
            # Rebuild record with authoritative prev_hash.
            linked: ProvenanceRecord = ProvenanceRecord(
                record_id=record.record_id,
                decision_id=record.decision_id,
                policy_hash=record.policy_hash,
                model_version=record.model_version,
                input_labels=record.input_labels,
                tool_manifest=record.tool_manifest,
                principal_id=record.principal_id,
                allowed=record.allowed,
                created_at=record.created_at,
                prev_hash=prev_tag,
                metadata=record.metadata,
            )
            tag = linked.hmac_tag(self._key)
            self._records.append(linked)  # deque(maxlen=N) auto-evicts oldest
            self._tags.append(tag)
        _log.debug(
            "provenance.appended: decision_id=%s tag=%s",
            record.decision_id,
            tag[:12] + "…",
        )
        return tag

    def verify_integrity(self) -> bool:
        """Return ``True`` when every record's HMAC tag is internally consistent.

        Checks:
        1. Each record's computed tag matches the stored tag.
        2. Each record's ``prev_hash`` matches the stored tag of the preceding record.

        Note: When ``max_records`` eviction has occurred, the first record's
        ``prev_hash`` may reference a record that is no longer in memory.
        The check skips the ``prev_hash`` link for the first retained record.
        """
        with self._lock:
            records = list(self._records)
            tags = list(self._tags)

        for i, (rec, stored_tag) in enumerate(zip(records, tags)):
            computed = rec.hmac_tag(self._key)
            if not hmac.compare_digest(computed, stored_tag):
                _log.error(
                    "provenance.integrity_failure: index=%d decision_id=%s",
                    i,
                    rec.decision_id,
                )
                return False
            if i > 0 and not hmac.compare_digest(rec.prev_hash, tags[i - 1]):
                _log.error(
                    "provenance.chain_broken: index=%d decision_id=%s",
                    i,
                    rec.decision_id,
                )
                return False
        return True

    def records(self) -> list[ProvenanceRecord]:
        """Return an ordered copy of all retained records."""
        with self._lock:
            return list(self._records)

    def tags(self) -> list[str]:
        """Return an ordered copy of all HMAC tags."""
        with self._lock:
            return list(self._tags)

    def length(self) -> int:
        """Number of records currently in the chain."""
        with self._lock:
            return len(self._records)

    def head_tag(self) -> str | None:
        """Return the HMAC tag of the most-recently appended record, or ``None``."""
        with self._lock:
            return self._tags[-1] if self._tags else None
