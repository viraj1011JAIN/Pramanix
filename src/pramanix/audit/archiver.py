# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""E-2: Merkle Anchor Pruning & Archival.

MerkleArchiver wraps the in-memory Merkle accumulation with segment-based
archival so that the active chain never grows past PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES.

Archive format
--------------
Each archive is a newline-delimited JSON file (.merkle.archive.YYYYMMDD):

    {"type":"header","date":"20250401","entry_count":50000,
     "root_hash":"abc123...","archived_at":1712000000.0}
    {"type":"leaf","decision_id":"...","leaf_hash":"...","ts":1712000000.0}
    ...

The root_hash in the header is the Merkle root of *all leaf_hash values* in the
archive, in order.  Running MerkleArchiver.verify_archive(path) recomputes the
root and compares it to the header — a mismatch means the archive was tampered.

Checkpoint entry
----------------
After archival, a single checkpoint leaf is prepended to the active chain:

    __checkpoint__{YYYYMMDD}__{root_hash_first8}

This leaf's SHA-256 hash (like any other leaf) becomes the leftmost leaf of the
next accumulation window.  The checkpoint binds the archived segment root hash
into the ongoing proof chain cryptographically.

Environment variables
---------------------
PRAMANIX_MERKLE_SEGMENT_DAYS      : int, default 30  — archive entries older than N days
PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES: int, default 100000 — trigger archival at this threshold
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)


@dataclass
class _Leaf:
    decision_id: str
    leaf_hash: str
    ts: float


@dataclass
class ArchiveResult:
    """Result returned by MerkleArchiver.archive()."""

    archive_path: Path
    entry_count: int
    root_hash: str
    checkpoint_id: str


class MerkleArchiver:
    """Merkle accumulator with automatic segment-based archival.

    Entries accumulate in memory.  When ``len(active_entries) >=
    max_active_entries`` (configurable via env var or constructor argument),
    the oldest segment (entries older than ``segment_days`` days, or half the
    active entries if all are fresh) is flushed to an archive file and replaced
    with a single checkpoint leaf.

    Args:
        base_path:          Directory for archive files.  Default: current dir.
        segment_days:       Archive entries older than N days.  Default: env
                            ``PRAMANIX_MERKLE_SEGMENT_DAYS`` or 30.
        max_active_entries: Trigger archival when active count reaches N.
                            Default: env ``PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES``
                            or 100,000.

    Usage::

        archiver = MerkleArchiver(base_path="/var/lib/pramanix/merkle")
        for decision in stream:
            archiver.add(decision.decision_id)
        archiver.flush_archive()   # archive remaining entries at shutdown
    """

    DEFAULT_SEGMENT_DAYS = 30
    DEFAULT_MAX_ACTIVE_ENTRIES = 100_000

    def __init__(
        self,
        base_path: str | Path = ".",
        segment_days: int | None = None,
        max_active_entries: int | None = None,
    ) -> None:
        self._base_path = Path(base_path)
        self._segment_days: int = (
            segment_days
            if segment_days is not None
            else int(os.environ.get("PRAMANIX_MERKLE_SEGMENT_DAYS", self.DEFAULT_SEGMENT_DAYS))
        )
        self._max_active: int = (
            max_active_entries
            if max_active_entries is not None
            else int(
                os.environ.get(
                    "PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES",
                    self.DEFAULT_MAX_ACTIVE_ENTRIES,
                )
            )
        )
        self._active: list[_Leaf] = []
        _log.warning(
            "MerkleArchiver: archive files are written in PLAINTEXT. "
            "For compliance regimes requiring encryption at rest "
            "(SOC 2, PCI DSS, HIPAA), encrypt the archive directory "
            "or implement a custom archiver with AES-256-GCM."
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def add(self, decision_id: str, *, timestamp: float | None = None) -> ArchiveResult | None:
        """Add a decision ID to the active chain.

        Triggers archival automatically when the active count reaches
        ``max_active_entries``.

        Args:
            decision_id: UUID or other unique ID from a Decision.
            timestamp:   Unix timestamp for the entry.  Defaults to now.

        Returns:
            An :class:`ArchiveResult` if archival was triggered, else ``None``.
        """
        ts = timestamp if timestamp is not None else time.time()
        leaf_hash = hashlib.sha256(decision_id.encode()).hexdigest()
        self._active.append(_Leaf(decision_id=decision_id, leaf_hash=leaf_hash, ts=ts))

        if len(self._active) >= self._max_active:
            return self._archive_segment()
        return None

    def archive(self) -> ArchiveResult | None:
        """Manually trigger archival of the oldest segment.

        Returns ``None`` if there are no entries to archive.
        """
        if not self._active:
            return None
        return self._archive_segment()

    def flush_archive(self) -> ArchiveResult | None:
        """Archive all remaining active entries (call at shutdown).

        Returns ``None`` if there are no entries.
        """
        return self.archive()

    def active_count(self) -> int:
        """Return the number of entries currently in the active chain."""
        return len(self._active)

    def root(self) -> str | None:
        """Return the Merkle root of all active leaves, or ``None`` if empty."""
        if not self._active:
            return None
        return _build_root([leaf.leaf_hash for leaf in self._active])

    def active_leaves(self) -> list[_Leaf]:
        """Return a copy of the active leaf list (for testing/inspection)."""
        return list(self._active)

    @classmethod
    def verify_archive(cls, archive_path: str | Path) -> bool:
        """Verify the integrity of an archive file.

        Recomputes the Merkle root of all leaf hashes in the file and
        compares it to the header root_hash.

        Args:
            archive_path: Path to a ``.merkle.archive.*`` file.

        Returns:
            ``True`` if the archive is intact, ``False`` if tampered.
        """
        path = Path(archive_path)
        if not path.exists():
            return False

        header: dict[str, Any] | None = None
        leaf_hashes: list[str] = []

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False
            rec_type = record.get("type")
            if rec_type == "header":
                header = record
            elif rec_type == "leaf":
                lh = record.get("leaf_hash")
                if not lh:
                    return False
                leaf_hashes.append(lh)

        if header is None or not leaf_hashes:
            return False

        expected_root = header.get("root_hash")
        if not expected_root:
            return False

        computed = _build_root(leaf_hashes)
        result: bool = computed == expected_root
        return result

    # ── Internal ───────────────────────────────────────────────────────────────

    def _archive_segment(self) -> ArchiveResult | None:
        """Archive the oldest segment and replace with a checkpoint leaf."""
        cutoff_ts = time.time() - self._segment_days * 86_400
        # Entries older than segment_days go to archive.
        to_archive = [leaf for leaf in self._active if leaf.ts <= cutoff_ts]

        # If nothing is old enough (all entries are fresh), archive the oldest half.
        if not to_archive:
            split = max(1, len(self._active) // 2)
            to_archive = self._active[:split]

        if not to_archive:
            return None

        archive_date = time.strftime("%Y%m%d", time.gmtime(to_archive[0].ts))
        archive_path = self._base_path / f".merkle.archive.{archive_date}"

        root_hash = _build_root([leaf.leaf_hash for leaf in to_archive])
        checkpoint_id = f"__checkpoint__{archive_date}__{root_hash[:8]}"

        # Write archive file.
        lines: list[str] = [
            json.dumps(
                {
                    "type": "header",
                    "date": archive_date,
                    "entry_count": len(to_archive),
                    "root_hash": root_hash,
                    "archived_at": time.time(),
                },
                separators=(",", ":"),
            )
        ]
        for leaf in to_archive:
            lines.append(
                json.dumps(
                    {
                        "type": "leaf",
                        "decision_id": leaf.decision_id,
                        "leaf_hash": leaf.leaf_hash,
                        "ts": leaf.ts,
                    },
                    separators=(",", ":"),
                )
            )
        self._base_path.mkdir(parents=True, exist_ok=True)
        # H-06: atomic write — write to temp file, fsync, then os.replace().
        # A crash mid-write produces an orphaned .tmp file, never a corrupt
        # archive.  os.replace() is atomic on POSIX; on Windows it is atomic
        # if src and dst are on the same filesystem (they always are here).
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=self._base_path, prefix=".merkle.tmp.", suffix=".partial"
        )
        try:
            content = "\n".join(lines) + "\n"
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        os.replace(tmp_path, archive_path)

        # Replace archived entries with a checkpoint leaf in the active chain.
        archived_ids = {leaf.decision_id for leaf in to_archive}
        remaining = [leaf for leaf in self._active if leaf.decision_id not in archived_ids]

        checkpoint_leaf = _Leaf(
            decision_id=checkpoint_id,
            leaf_hash=hashlib.sha256(checkpoint_id.encode()).hexdigest(),
            ts=time.time(),
        )
        self._active = [checkpoint_leaf, *remaining]

        return ArchiveResult(
            archive_path=archive_path,
            entry_count=len(to_archive),
            root_hash=root_hash,
            checkpoint_id=checkpoint_id,
        )


def _build_root(leaf_hashes: list[str]) -> str:
    """Compute Merkle root using \x01-prefixed internal nodes (H-07 safe)."""
    level = leaf_hashes[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            padded = hashlib.sha256(b"\x01" + level[-1].encode()).hexdigest()
            level.append(padded)
        level = [
            hashlib.sha256(
                b"\x01" + (level[i] + level[i + 1]).encode()
            ).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]
