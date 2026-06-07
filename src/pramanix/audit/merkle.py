# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Merkle tree anchoring for Pramanix Decision batches.

Allows proving any single decision was part of an unaltered batch
without replaying all decisions. Store only the root hash in your
audit log. Provide the MerkleProof to any auditor on demand.

Two implementations
-------------------
* :class:`MerkleAnchor`           — In-memory only.  Fast, no dependencies.
* :class:`PersistentMerkleAnchor` — Same API + ``checkpoint_callback`` and
  ``leaves_checkpoint_callback`` hooks that fire every *N* additions so the
  caller can write the root hash and full leaf list to a durable store.

Usage (basic)::

    anchor = MerkleAnchor()
    for decision in decisions:
        anchor.add(decision.decision_id)
    root = anchor.root()
    proof = anchor.prove(decision_id)
    assert proof.verify()

Usage (persistent checkpointing with cross-restart proof validity)::

    import json, sqlite3

    conn = sqlite3.connect("audit.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS checkpoints "
        "(root TEXT, count INTEGER, leaves TEXT, ts TEXT)"
    )

    def save_root(root: str, count: int) -> None:
        conn.execute(
            "INSERT INTO checkpoints(root,count,ts) VALUES(?,?,datetime('now'))",
            (root, count),
        )
        conn.commit()

    def save_leaves(leaves: list[str]) -> None:
        conn.execute(
            "UPDATE checkpoints SET leaves=? WHERE rowid=last_insert_rowid()",
            (json.dumps(leaves),),
        )
        conn.commit()

    anchor = PersistentMerkleAnchor(
        checkpoint_every=500,
        checkpoint_callback=save_root,
        leaves_checkpoint_callback=save_leaves,
    )
    for decision in stream:
        anchor.add(decision.decision_id)
    anchor.flush()  # persist any trailing decisions

    # --- After restart, restore from last checkpoint ---
    row = conn.execute(
        "SELECT root, leaves FROM checkpoints ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    if row:
        stored_root, stored_leaves = row
        anchor = PersistentMerkleAnchor(
            checkpoint_every=500,
            checkpoint_callback=save_root,
            leaves_checkpoint_callback=save_leaves,
            initial_leaves=json.loads(stored_leaves),
            expected_root=stored_root,   # raises ValueError on corruption
        )
        proof = anchor.prove(some_decision_id)
        assert proof is not None and proof.verify()
"""

from __future__ import annotations

import atexit
import hashlib
import hmac
import threading
import weakref
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class MerkleProof:
    """Inclusion proof for a single Decision ID in a MerkleAnchor batch."""

    leaf_hash: str
    root_hash: str
    proof_path: list[tuple[str, str]]  # (sibling_hash, "left"|"right")

    def verify(self) -> bool:
        """Return True if the proof path reconstructs the expected Merkle root.

        .. warning::
            This method only verifies the structural integrity of the proof path
            (i.e. that the leaf_hash is included in the tree with the given root).
            It does NOT verify that ``leaf_hash`` was derived from any specific
            ``decision_id``.  Use :meth:`verify_for_decision` when you have the
            original decision_id and want end-to-end integrity.
        """
        current = self.leaf_hash
        for sibling, direction in self.proof_path:
            combined = sibling + current if direction == "left" else current + sibling
            # H-07: internal nodes use \x01 prefix (matches _build_root)
            current = hashlib.sha256(b"\x01" + combined.encode()).hexdigest()
        return current == self.root_hash

    def verify_for_decision(self, decision_id: str) -> bool:
        """End-to-end verification: recompute the leaf hash from *decision_id*
        and confirm it matches ``leaf_hash``, then verify the proof path.

        This is the correct way to prove that a specific decision_id is included
        in the Merkle tree anchored at ``root_hash``.  Calling :meth:`verify`
        alone does not bind the proof to any particular decision — an attacker
        who can control ``leaf_hash`` in a deserialized proof could pass
        :meth:`verify` with an arbitrary proof path.

        Args:
            decision_id: The original decision UUID string as passed to
                :meth:`MerkleAnchor.add`.

        Returns:
            ``True`` only when:
            1. The leaf hash recomputed from *decision_id* matches
               ``self.leaf_hash`` (the proof is bound to this decision).
            2. The proof path correctly reconstructs ``self.root_hash``
               (the decision is structurally included in the tree).
        """
        expected_leaf = hashlib.sha256(b"\x00" + decision_id.encode()).hexdigest()
        if not hmac.compare_digest(expected_leaf, self.leaf_hash):
            return False
        return self.verify()


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
        self._ids: set[str] = set()  # O(1) duplicate guard
        self._lock = threading.Lock()  # guards _leaves and _ids (#170)

    def add(self, decision_id: str) -> None:
        """Hash and add decision_id as a leaf; raises ValueError on duplicates."""
        leaf_hash = hashlib.sha256(b"\x00" + decision_id.encode()).hexdigest()
        with self._lock:
            if decision_id in self._ids:
                raise ValueError(
                    f"Duplicate decision_id {decision_id!r} already anchored in this MerkleAnchor. "
                    "Each decision_id must be unique within a single audit batch."
                )
            self._ids.add(decision_id)
            # H-07: prefix real leaf nodes with \x00 to distinguish them from
            # duplicated padding nodes (which use \x01 prefix).  This prevents
            # the Bitcoin-CVE-2012-style second-preimage attack.
            self._leaves.append(leaf_hash)

    def root(self) -> str | None:
        """Return the current Merkle root hash, or None if no leaves have been added."""
        with self._lock:
            if not self._leaves:
                return None
            return self._build_root(self._leaves[:])

    def prove(self, decision_id: str) -> MerkleProof | None:
        """Return an inclusion proof for decision_id, or None if not in this tree."""
        # H-07: use the same \x00 prefix as add() to locate the leaf
        target = hashlib.sha256(b"\x00" + decision_id.encode()).hexdigest()
        with self._lock:
            try:
                idx = self._leaves.index(target)
            except ValueError:
                return None
            # Take a snapshot under the lock so concurrent add() calls cannot
            # mutate _leaves mid-traversal (data race #170).
            leaves_snapshot = self._leaves[:]

        proof_path: list[tuple[str, str]] = []
        current_level = leaves_snapshot
        current_idx = idx

        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                # H-07: pad with \x01-prefixed copy of the last node, not a
                # plain duplicate, so odd-length sequences produce distinct roots.
                padded = hashlib.sha256(b"\x01" + current_level[-1].encode()).hexdigest()
                current_level.append(padded)
            if current_idx % 2 == 0:
                proof_path.append((current_level[current_idx + 1], "right"))
            else:
                proof_path.append((current_level[current_idx - 1], "left"))
            next_level = [
                hashlib.sha256(
                    b"\x01" + (current_level[i] + current_level[i + 1]).encode()
                ).hexdigest()
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
        # Iterative implementation avoids Python's default recursion limit.
        # H-07: use \x01 prefix for all internal (parent) nodes, distinguishing
        # them from the \x00-prefixed leaf nodes to prevent the duplication attack.
        level = leaves[:]
        while len(level) > 1:
            if len(level) % 2 == 1:
                padded = hashlib.sha256(b"\x01" + level[-1].encode()).hexdigest()
                level.append(padded)
            level = [
                hashlib.sha256(b"\x01" + (level[i] + level[i + 1]).encode()).hexdigest()
                for i in range(0, len(level), 2)
            ]
        return level[0]


class PersistentMerkleAnchor(MerkleAnchor):
    """Merkle anchor that checkpoints its root hash and leaf hashes to a durable store.

    Extends :class:`MerkleAnchor` with checkpoint hooks that fire automatically
    every *checkpoint_every* additions.  Solves two gaps:

    * **Merkle Volatility** — root hash is never silently dropped; written to a
      durable store via ``checkpoint_callback``.
    * **Cross-restart proof validity (#34)** — the full leaf-hash list is emitted
      via ``leaves_checkpoint_callback`` so callers can persist it alongside the
      root.  On restart, pass ``initial_leaves`` to restore the tree so that
      ``prove()`` and ``verify()`` work across process boundaries.

    Args:
        checkpoint_every:           Trigger a checkpoint after every N ``add()``
                                    calls.  Default: 100.
        checkpoint_callback:        Callable invoked as
                                    ``callback(root_hash, leaf_count)`` on each
                                    periodic checkpoint and on ``flush()``.
                                    Runs synchronously in the caller's thread.
        leaves_checkpoint_callback: Callable invoked as
                                    ``callback(leaf_hashes)`` immediately after
                                    ``checkpoint_callback`` on each checkpoint.
                                    Receives a snapshot of the full leaf-hash
                                    list (SHA-256 hex strings, **not** raw
                                    decision IDs).  Persist this list to the
                                    same durable store as the root hash.
        initial_leaves:             Leaf-hash list to restore from a previous
                                    session's ``leaves_checkpoint_callback``.
                                    Enables ``prove()``/``verify()`` across
                                    process restarts.
        expected_root:              Expected root hash after restoring
                                    ``initial_leaves``.  If the recomputed root
                                    does not match, ``__init__`` raises
                                    ``ValueError`` — use this to detect truncated
                                    or corrupted leaf stores at startup.

    .. note::
        ``initial_leaves`` does **not** restore duplicate-detection state.
        Decision IDs added before the restart will not be caught as duplicates
        in the new process; duplicates added *within* the new session are still
        caught normally.
    """

    def __init__(
        self,
        checkpoint_every: int = 100,
        checkpoint_callback: Callable[[str, int], None] | None = None,
        leaves_checkpoint_callback: Callable[[list[str]], None] | None = None,
        initial_leaves: list[str] | None = None,
        expected_root: str | None = None,
    ) -> None:
        super().__init__()
        if checkpoint_every < 1:
            raise ValueError("checkpoint_every must be >= 1.")
        self._checkpoint_every = checkpoint_every
        self._callback = checkpoint_callback
        self._leaves_callback = leaves_checkpoint_callback
        self._last_checkpoint_count: int = 0

        # Cross-restart leaf restore (#34): repopulate the in-memory leaf list
        # from a previously persisted snapshot so prove()/verify() work again.
        if initial_leaves is not None:
            with self._lock:
                self._leaves = list(initial_leaves)
            if expected_root is not None:
                actual = self.root()
                if actual != expected_root:
                    raise ValueError(
                        f"Restored leaf hashes produce root {actual!r} but "
                        f"expected_root is {expected_root!r}. "
                        "The leaf store may be corrupted or incomplete."
                    )
            self._last_checkpoint_count = len(self._leaves)

        # Auto-flush at process exit so trailing leaves added since the last
        # periodic checkpoint are never silently dropped. A weak reference is
        # used so the anchor can still be garbage-collected normally during the
        # program's lifetime; at interpreter shutdown the object is still alive
        # and _ref() returns it for the final flush.
        _ref: weakref.ref[PersistentMerkleAnchor] = weakref.ref(self)

        def _atexit_flush(_r: weakref.ref[PersistentMerkleAnchor] = _ref) -> None:
            anchor = _r()
            if anchor is not None:
                import contextlib

                with contextlib.suppress(OSError, RuntimeError):
                    anchor.flush()

        atexit.register(_atexit_flush)
        self._atexit_flush = _atexit_flush  # keep reference alive for testing

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
        if root is not None:
            if self._callback is not None:
                self._callback(root, count)
            if self._leaves_callback is not None:
                with self._lock:
                    leaves_snapshot = self._leaves[:]
                self._leaves_callback(leaves_snapshot)
