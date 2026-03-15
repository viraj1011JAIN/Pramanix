# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Merkle tree anchoring for Pramanix Decision batches.

Allows proving any single decision was part of an unaltered batch
without replaying all decisions. Store only the root hash in your
audit log. Provide the MerkleProof to any auditor on demand.

Usage:
    anchor = MerkleAnchor()
    for decision in decisions:
        anchor.add(decision.decision_id)
    root = anchor.root()
    proof = anchor.prove(decision_id)
    assert proof.verify()
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


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
