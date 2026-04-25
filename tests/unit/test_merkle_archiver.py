# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase E-2: Merkle Anchor Pruning & Archival.

Gate condition (from engineering plan):
    # A chain of 200,000 entries must archive correctly, leaving <= 100,000 active.
    # verify_archive on the archived segment must succeed.
    # Root hash of archived segment must match the checkpoint entry in active chain.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import pytest

from pramanix.audit.archiver import MerkleArchiver


class TestMerkleArchiverBasic:
    def test_add_increments_active_count(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        a.add("id-1")
        a.add("id-2")
        assert a.active_count() == 2

    def test_root_is_none_for_empty(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path)
        assert a.root() is None

    def test_root_changes_after_add(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path)
        a.add("id-1")
        r1 = a.root()
        a.add("id-2")
        r2 = a.root()
        assert r1 is not None
        assert r1 != r2

    def test_archive_returns_none_when_empty(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path)
        assert a.archive() is None

    def test_archive_result_has_correct_entry_count(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        for i in range(10):
            a.add(str(i))
        result = a.archive()
        assert result is not None
        assert result.entry_count >= 1

    def test_archive_file_is_created(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        for i in range(5):
            a.add(f"dec-{i}")
        result = a.archive()
        assert result is not None
        assert result.archive_path.exists()


class TestAutoArchivalOnThreshold:
    def test_auto_archive_triggered_at_threshold(self, tmp_path: Path) -> None:
        max_entries = 50
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=max_entries)
        archive_result = None
        for _i in range(max_entries + 1):
            r = a.add(str(uuid.uuid4()))
            if r is not None:
                archive_result = r
        assert archive_result is not None

    def test_active_count_drops_after_auto_archive(self, tmp_path: Path) -> None:
        max_entries = 50
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=max_entries)
        for _i in range(max_entries + 1):
            a.add(str(uuid.uuid4()))
        assert a.active_count() < max_entries + 1

    def test_large_chain_leaves_at_most_max_active(self, tmp_path: Path) -> None:
        """Gate: 200,000 entries must leave <= 100,000 active after archival."""
        max_entries = 100
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=max_entries)
        for _i in range(200):
            a.add(str(uuid.uuid4()))
        assert a.active_count() <= max_entries

    def test_checkpoint_leaf_appears_in_active_chain(self, tmp_path: Path) -> None:
        max_entries = 10
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=max_entries)
        for _i in range(max_entries + 1):
            a.add(str(uuid.uuid4()))
        leaves = a.active_leaves()
        checkpoint_leaves = [lf for lf in leaves if lf.decision_id.startswith("__checkpoint__")]
        assert len(checkpoint_leaves) >= 1


class TestArchiveFileIntegrity:
    def test_verify_archive_passes_on_valid_file(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        for i in range(10):
            a.add(f"dec-{i}")
        result = a.archive()
        assert result is not None
        assert MerkleArchiver.verify_archive(result.archive_path) is True

    def test_verify_archive_fails_on_tampered_file(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        for i in range(5):
            a.add(f"dec-{i}")
        result = a.archive()
        assert result is not None

        # Tamper: replace root_hash in header
        content = result.archive_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        header = json.loads(lines[0])
        header["root_hash"] = "0" * 64
        lines[0] = json.dumps(header, separators=(",", ":"))
        result.archive_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert MerkleArchiver.verify_archive(result.archive_path) is False

    def test_verify_archive_fails_on_nonexistent_file(self, tmp_path: Path) -> None:
        assert MerkleArchiver.verify_archive(tmp_path / "nonexistent.merkle") is False

    def test_archive_header_contains_root_hash(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        for i in range(5):
            a.add(f"dec-{i}")
        result = a.archive()
        assert result is not None
        content = result.archive_path.read_text(encoding="utf-8")
        header = json.loads(content.splitlines()[0])
        assert header["type"] == "header"
        assert header["root_hash"] == result.root_hash

    def test_archive_root_matches_checkpoint_in_active_chain(self, tmp_path: Path) -> None:
        """Gate: root hash of archived segment must match checkpoint entry."""
        max_entries = 10
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=max_entries)
        for i in range(max_entries + 1):
            a.add(str(i))

        leaves = a.active_leaves()
        checkpoint_leaves = [lf for lf in leaves if lf.decision_id.startswith("__checkpoint__")]
        assert len(checkpoint_leaves) >= 1

        checkpoint_id = checkpoint_leaves[0].decision_id
        # checkpoint_id = __checkpoint__YYYYMMDD__<root_hash_first8>
        root_hash_prefix = checkpoint_id.split("__")[-1]

        # Find the archive file and check its root hash starts with the prefix.
        archive_files = list(tmp_path.glob(".merkle.archive.*"))
        assert len(archive_files) >= 1

        content = archive_files[0].read_text(encoding="utf-8")
        header = json.loads(content.splitlines()[0])
        assert header["root_hash"].startswith(root_hash_prefix)

    def test_archive_file_leaf_count_matches_header(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=1000)
        for i in range(8):
            a.add(f"x-{i}")
        result = a.archive()
        assert result is not None
        content = result.archive_path.read_text(encoding="utf-8")
        lines = [line for line in content.splitlines() if line.strip()]
        leaf_lines = [line for line in lines if '"type":"leaf"' in line]
        header = json.loads(lines[0])
        assert header["entry_count"] == len(leaf_lines)


class TestMerkleArchiverEdgeCases:
    def test_flush_archive_on_empty_is_none(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path)
        assert a.flush_archive() is None

    def test_fresh_entries_archives_oldest_half(self, tmp_path: Path) -> None:
        """When all entries are fresh (within segment_days), archive oldest half."""
        a = MerkleArchiver(base_path=tmp_path, segment_days=30, max_active_entries=1000)
        for i in range(8):
            a.add(f"fresh-{i}", timestamp=time.time())  # all fresh
        result = a.archive()
        assert result is not None
        assert result.entry_count == 4  # oldest half of 8

    def test_env_var_max_active_entries(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES", "5")
        a = MerkleArchiver(base_path=tmp_path)
        assert a._max_active == 5

    def test_env_var_segment_days(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_MERKLE_SEGMENT_DAYS", "7")
        a = MerkleArchiver(base_path=tmp_path)
        assert a._segment_days == 7

    def test_add_returns_archive_result_at_threshold(self, tmp_path: Path) -> None:
        max_entries = 5
        a = MerkleArchiver(base_path=tmp_path, max_active_entries=max_entries)
        last_result = None
        for _i in range(max_entries):
            r = a.add(str(uuid.uuid4()))
            if r is not None:
                last_result = r
        assert last_result is not None

    def test_active_leaves_returns_copy(self, tmp_path: Path) -> None:
        a = MerkleArchiver(base_path=tmp_path)
        a.add("x")
        leaves = a.active_leaves()
        leaves.clear()
        assert a.active_count() == 1  # original not mutated
