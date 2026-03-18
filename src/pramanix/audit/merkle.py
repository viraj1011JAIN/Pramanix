# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Merkle tree anchoring for Pramanix Decision batches.

Allows proving any single decision was part of an unaltered batch
without replaying all decisions. Store only the root hash in your
audit log. Provide the MerkleProof to any auditor on demand.

Two implementations
-------------------
* :class:`MerkleAnchor`           — In-memory only.  Fast, no dependencies.
* :class:`PersistentMerkleAnchor` — Same API + a ``checkpoint_callback`` that
  fires every *N* additions so the caller can write the root hash to a durable
  store (database, append-only file, S3, etc.).

Usage (basic)::

    anchor = MerkleAnchor()
    for decision in decisions:
        anchor.add(decision.decision_id)
    root = anchor.root()
    proof = anchor.prove(decision_id)
    assert proof.verify()

Usage (persistent checkpointing)::

    def save_root(root: str, count: int) -> None:
        db.execute("INSERT INTO merkle_checkpoints VALUES (?, ?, ?)",
                   (root, count, datetime.utcnow().isoformat()))

    anchor = PersistentMerkleAnchor(
        checkpoint_every=500,
        checkpoint_callback=save_root,
    )
    for decision in stream:
        anchor.add(decision.decision_id)
    # Flush any remaining leaves that haven't triggered a checkpoint:
    anchor.flush()
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class MerkleProof:
    leaf_hash: str
    root_hash: str
    proof_path: list[tuple[str, str]]  # (sibling_hash, "left"|"right")

    def verify(self) -> bool:
        current = self.leaf_hash
        for sibling, direction in self.proof_path:
            combined = sibling + current if direction == "left" else current + sibling
            current = hashlib.sha256(combined.encode()).hexdigest()
        return current == self.root_hash


class MerkleAnchor:
    """In-memory Merkle tree anchoring for a batch of Decision IDs.

    .. note::
        **In-memory only.** The tree is not persisted across restarts. To use
        this for auditability, call ``root()`` after processing a batch and
        store the root hash in an external durable log (database, append-only
        file, blockchain anchor, etc.). Losing the process loses the tree.
    """

    def __init__(self) -> None:
        self._leaves: list[str] = []

    def add(self, decision_id: str) -> None:
        self._leaves.append(hashlib.sha256(decision_id.encode()).hexdigest())

    def root(self) -> str | None:
        if not self._leaves:
            return None
        return self._build_root(self._leaves[:])

    def prove(self, decision_id: str) -> MerkleProof | None:
        target = hashlib.sha256(decision_id.encode()).hexdigest()
        try:
            idx = self._leaves.index(target)
        except ValueError:
            return None

        proof_path: list[tuple[str, str]] = []
        current_level = self._leaves[:]
        current_idx = idx

        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])
            if current_idx % 2 == 0:
                proof_path.append((current_level[current_idx + 1], "right"))
            else:
                proof_path.append((current_level[current_idx - 1], "left"))
            next_level = [
                hashlib.sha256((current_level[i] + current_level[i + 1]).encode()).hexdigest()
                for i in range(0, len(current_level), 2)
            ]
            current_idx //= 2
            current_level = next_level

        return MerkleProof(
            leaf_hash=target,
            root_hash=current_level[0],
            proof_path=proof_path,
        )

    def _build_root(self, leaves: list[str]) -> str:
        if len(leaves) == 1:
            return leaves[0]
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        next_level = [
            hashlib.sha256((leaves[i] + leaves[i + 1]).encode()).hexdigest()
            for i in range(0, len(leaves), 2)
        ]
        return self._build_root(next_level)


class PersistentMerkleAnchor(MerkleAnchor):
    """Merkle anchor that checkpoints its root hash to a durable store.

    Extends :class:`MerkleAnchor` with a ``checkpoint_callback`` hook that is
    called automatically every *checkpoint_every* additions.  This solves the
    **Merkle Volatility** gap: the in-memory ``MerkleAnchor`` is lost on
    restart, making post-mortem audits impossible unless the root is persisted.

    The callback receives ``(root_hash: str, leaf_count: int)`` so the caller
    can store the root alongside its positional index for replay auditing.

    Args:
        checkpoint_every:    Trigger a checkpoint after every N ``add()`` calls.
                             Default: 100.
        checkpoint_callback: Callable invoked as
                             ``callback(root_hash, leaf_count)`` when the
                             threshold is reached and on explicit ``flush()``.
                             Runs synchronously in the caller's thread.

    Example::

        import sqlite3

        conn = sqlite3.connect("audit.db")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS checkpoints "
            "(root TEXT, count INTEGER, ts TEXT)"
        )

        def save(root: str, count: int) -> None:
            conn.execute(
                "INSERT INTO checkpoints VALUES (?,?,datetime('now'))",
                (root, count),
            )
            conn.commit()

        anchor = PersistentMerkleAnchor(checkpoint_every=500, checkpoint_callback=save)
        for d in decisions:
            anchor.add(d.decision_id)
        anchor.flush()  # persist any trailing decisions
    """

    def __init__(
        self,
        checkpoint_every: int = 100,
        checkpoint_callback: Callable[[str, int], None] | None = None,
    ) -> None:
        super().__init__()
        if checkpoint_every < 1:
            raise ValueError("checkpoint_every must be >= 1.")
        self._checkpoint_every = checkpoint_every
        self._callback = checkpoint_callback
        self._last_checkpoint_count: int = 0

    def add(self, decision_id: str) -> None:
        """Add a decision ID and checkpoint if the interval threshold is reached."""
        super().add(decision_id)
        count = len(self._leaves)
        if count % self._checkpoint_every == 0:
            self._do_checkpoint(count)
            self._last_checkpoint_count = count

    def flush(self) -> None:
        """Force a checkpoint for any leaves added since the last checkpoint.

        Call this at shutdown or end-of-batch to ensure no trailing decisions
        are lost between periodic checkpoints.
        """
        count = len(self._leaves)
        if count > self._last_checkpoint_count and count > 0:
            self._do_checkpoint(count)
            self._last_checkpoint_count = count

    def _do_checkpoint(self, count: int) -> None:
        root = self.root()
        if root is not None and self._callback is not None:
            self._callback(root, count)
