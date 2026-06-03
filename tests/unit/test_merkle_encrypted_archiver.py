# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Unit tests for EncryptedArchiveWriter, ArchiveKeySet,
RotatingKeyArchiveWriter, and MerkleArchiver.verify_encrypted_archive.

All tests use real cryptography (no mocks).  Each test is self-contained via
tmp_path; no shared state between tests.
"""

from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path

import pytest

from pramanix.audit.archiver import (
    ArchiveKeySet,
    EncryptedArchiveWriter,
    MerkleArchiver,
    RotatingKeyArchiveWriter,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_NDJSON = (
    b'{"type":"header","date":"20260101",'
    b'"entry_count":2,"root_hash":"aabbcc","archived_at":0}\n'
    b'{"type":"leaf","decision_id":"d1","leaf_hash":"h1","ts":0}\n'
    b'{"type":"leaf","decision_id":"d2","leaf_hash":"h2","ts":0}\n'
)


def _valid_archive_bytes() -> bytes:
    """Return a minimal valid NDJSON archive with a correct Merkle root."""
    import hashlib

    h1 = hashlib.sha256(b"d1").hexdigest()
    h2 = hashlib.sha256(b"d2").hexdigest()

    pair = hashlib.sha256(b"\x01" + (h1 + h2).encode()).hexdigest()

    header = json.dumps(
        {
            "type": "header",
            "date": "20260101",
            "entry_count": 2,
            "root_hash": pair,
            "archived_at": 0.0,
        },
        separators=(",", ":"),
    )
    leaf1 = json.dumps(
        {"type": "leaf", "decision_id": "d1", "leaf_hash": h1, "ts": 0.0},
        separators=(",", ":"),
    )
    leaf2 = json.dumps(
        {"type": "leaf", "decision_id": "d2", "leaf_hash": h2, "ts": 0.0},
        separators=(",", ":"),
    )
    return (header + "\n" + leaf1 + "\n" + leaf2 + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# EncryptedArchiveWriter
# ---------------------------------------------------------------------------


class TestEncryptedArchiveWriter:
    def test_round_trip(self, tmp_path: Path) -> None:
        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg.merkle.archive.20260101"
        writer(base, _SAMPLE_NDJSON)

        enc_path = base.with_suffix(".enc")
        assert enc_path.exists()

        plaintext = EncryptedArchiveWriter.decrypt(key, enc_path)
        assert plaintext == _SAMPLE_NDJSON

    def test_wrong_key_raises(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)

        wrong_key = secrets.token_bytes(32)
        with pytest.raises(InvalidTag):
            EncryptedArchiveWriter.decrypt(wrong_key, base.with_suffix(".enc"))

    def test_tampered_ciphertext_raises(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)

        enc_path = base.with_suffix(".enc")
        raw = bytearray(enc_path.read_bytes())
        raw[-1] ^= 0xFF  # flip last byte (in GCM tag region)
        enc_path.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            EncryptedArchiveWriter.decrypt(key, enc_path)

    def test_atomic_write(self, tmp_path: Path) -> None:
        """Confirm no .partial files remain after a successful write."""
        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)
        assert list(tmp_path.glob("*.partial")) == []

    def test_bad_key_length_raises(self) -> None:
        with pytest.raises(ValueError, match="32-byte"):
            EncryptedArchiveWriter(secrets.token_bytes(16))

    def test_decrypt_bad_key_length_raises(self, tmp_path: Path) -> None:
        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)
        with pytest.raises(ValueError, match="32-byte"):
            EncryptedArchiveWriter.decrypt(b"short", base.with_suffix(".enc"))

    def test_generate_key(self) -> None:
        k = EncryptedArchiveWriter.generate_key()
        assert isinstance(k, bytes)
        assert len(k) == 32

    def test_different_nonce_each_write(self, tmp_path: Path) -> None:
        """Two encryptions of the same plaintext produce different ciphertext."""
        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base1 = tmp_path / "seg1"
        base2 = tmp_path / "seg2"
        writer(base1, _SAMPLE_NDJSON)
        writer(base2, _SAMPLE_NDJSON)
        ct1 = base1.with_suffix(".enc").read_bytes()
        ct2 = base2.with_suffix(".enc").read_bytes()
        assert ct1 != ct2


# ---------------------------------------------------------------------------
# ArchiveKeySet
# ---------------------------------------------------------------------------


class TestArchiveKeySet:
    def test_add_and_get(self) -> None:
        ks = ArchiveKeySet()
        key = secrets.token_bytes(32)
        ks.add("k1", key)
        assert ks.get("k1") == key

    def test_add_bad_length_raises(self) -> None:
        ks = ArchiveKeySet()
        with pytest.raises(ValueError, match="32 bytes"):
            ks.add("k1", b"tooshort")

    def test_get_missing_raises(self) -> None:
        ks = ArchiveKeySet()
        with pytest.raises(KeyError):
            ks.get("nonexistent")

    def test_set_active_and_active_key(self) -> None:
        ks = ArchiveKeySet()
        key = secrets.token_bytes(32)
        ks.add("k1", key)
        ks.set_active("k1")
        assert ks.active_key_id == "k1"
        assert ks.active_key == key

    def test_set_active_missing_raises(self) -> None:
        ks = ArchiveKeySet()
        with pytest.raises(KeyError):
            ks.set_active("missing")

    def test_active_key_id_before_set_raises(self) -> None:
        ks = ArchiveKeySet()
        with pytest.raises(RuntimeError, match="no active key"):
            _ = ks.active_key_id

    def test_remove(self) -> None:
        ks = ArchiveKeySet()
        key = secrets.token_bytes(32)
        ks.add("k1", key)
        ks.add("k2", secrets.token_bytes(32))
        ks.set_active("k2")
        ks.remove("k1")
        with pytest.raises(KeyError):
            ks.get("k1")

    def test_remove_active_raises(self) -> None:
        ks = ArchiveKeySet()
        ks.add("k1", secrets.token_bytes(32))
        ks.set_active("k1")
        with pytest.raises(ValueError, match="Cannot remove active"):
            ks.remove("k1")

    def test_remove_missing_raises(self) -> None:
        ks = ArchiveKeySet()
        with pytest.raises(KeyError):
            ks.remove("ghost")

    def test_rotate(self) -> None:
        ks = ArchiveKeySet()
        k1 = secrets.token_bytes(32)
        k2 = secrets.token_bytes(32)
        ks.add("k1", k1)
        ks.set_active("k1")
        old_id = ks.rotate("k2", k2)
        assert old_id == "k1"
        assert ks.active_key_id == "k2"
        assert ks.get("k1") == k1  # old key still accessible

    def test_rotate_before_set_active_raises(self) -> None:
        ks = ArchiveKeySet()
        with pytest.raises(RuntimeError, match="active key was set"):
            ks.rotate("k2", secrets.token_bytes(32))

    def test_key_ids(self) -> None:
        ks = ArchiveKeySet()
        ks.add("a", secrets.token_bytes(32))
        ks.add("b", secrets.token_bytes(32))
        assert set(ks.key_ids()) == {"a", "b"}

    def test_overwrite_existing_key(self) -> None:
        ks = ArchiveKeySet()
        k1 = secrets.token_bytes(32)
        k2 = secrets.token_bytes(32)
        ks.add("k1", k1)
        ks.add("k1", k2)  # overwrite
        assert ks.get("k1") == k2


# ---------------------------------------------------------------------------
# RotatingKeyArchiveWriter
# ---------------------------------------------------------------------------


class TestRotatingKeyArchiveWriter:
    def _make_key_set(self, key_id: str = "k1") -> tuple[ArchiveKeySet, bytes]:
        ks = ArchiveKeySet()
        key = secrets.token_bytes(32)
        ks.add(key_id, key)
        ks.set_active(key_id)
        return ks, key

    def test_round_trip(self, tmp_path: Path) -> None:
        ks, _ = self._make_key_set()
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)
        enc_path = base.with_suffix(".enc")
        assert enc_path.exists()
        plaintext = RotatingKeyArchiveWriter.decrypt(ks, enc_path)
        assert plaintext == _SAMPLE_NDJSON

    def test_magic_header(self, tmp_path: Path) -> None:
        ks, _ = self._make_key_set()
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)
        raw = base.with_suffix(".enc").read_bytes()
        assert raw[:4] == b"RPMK"

    def test_wrong_key_raises(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        ks, _ = self._make_key_set("k1")
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)

        wrong_ks = ArchiveKeySet()
        wrong_ks.add("k1", secrets.token_bytes(32))  # same id, different key
        wrong_ks.set_active("k1")

        enc = base.with_suffix(".enc")
        with pytest.raises(InvalidTag):
            RotatingKeyArchiveWriter.decrypt(wrong_ks, enc)

    def test_missing_key_id_in_set_raises(self, tmp_path: Path) -> None:
        ks, _ = self._make_key_set("key-jan")
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)

        empty_ks = ArchiveKeySet()
        enc = base.with_suffix(".enc")
        with pytest.raises(KeyError):
            RotatingKeyArchiveWriter.decrypt(empty_ks, enc)

    def test_decrypt_non_rpmk_raises(self, tmp_path: Path) -> None:
        ks, _ = self._make_key_set()
        enc_path = tmp_path / "bad.enc"
        enc_path.write_bytes(b"\x00" * 20)  # not RPMK magic
        with pytest.raises(ValueError, match="RPMK"):
            RotatingKeyArchiveWriter.decrypt(ks, enc_path)

    def test_tampered_ciphertext_raises(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        ks, _ = self._make_key_set()
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)
        enc_path = base.with_suffix(".enc")
        raw = bytearray(enc_path.read_bytes())
        raw[-1] ^= 0xFF
        enc_path.write_bytes(bytes(raw))
        with pytest.raises(InvalidTag):
            RotatingKeyArchiveWriter.decrypt(ks, enc_path)

    def test_key_rotation_decryptable_after_rotate(self, tmp_path: Path) -> None:
        """Archives written with key-A remain decryptable after rotating to key-B."""
        ks = ArchiveKeySet()
        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)
        ks.add("key-a", key_a)
        ks.set_active("key-a")

        writer = RotatingKeyArchiveWriter(ks)
        base_old = tmp_path / "old_seg"
        writer(base_old, _SAMPLE_NDJSON)

        ks.rotate("key-b", key_b)

        base_new = tmp_path / "new_seg"
        writer(base_new, _SAMPLE_NDJSON)

        # Old archive still decryptable (key-a retained after rotate)
        old_enc = base_old.with_suffix(".enc")
        old_plain = RotatingKeyArchiveWriter.decrypt(ks, old_enc)
        assert old_plain == _SAMPLE_NDJSON

        # New archive decryptable with key-b
        new_enc = base_new.with_suffix(".enc")
        new_plain = RotatingKeyArchiveWriter.decrypt(ks, new_enc)
        assert new_plain == _SAMPLE_NDJSON

        # Confirm new archive embeds key-b
        raw = new_enc.read_bytes()
        offset = 4
        kid_len = int.from_bytes(raw[offset:offset + 2], "big")
        kid = raw[offset + 2:offset + 2 + kid_len].decode()
        assert kid == "key-b"

    def test_remove_old_key_breaks_decryption(self, tmp_path: Path) -> None:
        ks = ArchiveKeySet()
        ks.add("ka", secrets.token_bytes(32))
        ks.set_active("ka")
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _SAMPLE_NDJSON)

        ks.rotate("kb", secrets.token_bytes(32))
        ks.remove("ka")  # purge old key

        enc = base.with_suffix(".enc")
        with pytest.raises(KeyError):
            RotatingKeyArchiveWriter.decrypt(ks, enc)

    def test_atomic_no_partials(self, tmp_path: Path) -> None:
        ks, _ = self._make_key_set()
        writer = RotatingKeyArchiveWriter(ks)
        writer(tmp_path / "seg", _SAMPLE_NDJSON)
        assert list(tmp_path.glob("*.partial")) == []


# ---------------------------------------------------------------------------
# MerkleArchiver.verify_encrypted_archive
# ---------------------------------------------------------------------------


class TestVerifyEncryptedArchive:
    def test_single_key_valid_archive(self, tmp_path: Path) -> None:
        key = secrets.token_bytes(32)
        content = _valid_archive_bytes()
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, content)
        enc = base.with_suffix(".enc")
        assert MerkleArchiver.verify_encrypted_archive(enc, key=key) is True

    def test_single_key_tampered_archive(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        key = secrets.token_bytes(32)
        content = _valid_archive_bytes()
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, content)
        enc_path = base.with_suffix(".enc")
        raw = bytearray(enc_path.read_bytes())
        raw[-1] ^= 0xFF
        enc_path.write_bytes(bytes(raw))
        with pytest.raises(InvalidTag):
            MerkleArchiver.verify_encrypted_archive(enc_path, key=key)

    def test_single_key_merkle_root_tampered(self, tmp_path: Path) -> None:
        """Decrypt succeeds but root_hash mismatch -> verify returns False."""
        key = secrets.token_bytes(32)
        bad_content = (
            b'{"type":"header","date":"20260101","entry_count":1,'
            b'"root_hash":"deadbeef","archived_at":0}\n'
            b'{"type":"leaf","decision_id":"x","leaf_hash":"aaa","ts":0}\n'
        )
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, bad_content)
        enc = base.with_suffix(".enc")
        assert MerkleArchiver.verify_encrypted_archive(enc, key=key) is False

    def test_key_set_valid_archive(self, tmp_path: Path) -> None:
        ks = ArchiveKeySet()
        ks.add("k1", secrets.token_bytes(32))
        ks.set_active("k1")
        content = _valid_archive_bytes()
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, content)
        enc = base.with_suffix(".enc")
        assert MerkleArchiver.verify_encrypted_archive(enc, key_set=ks) is True

    def test_key_set_wrong_key(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        ks = ArchiveKeySet()
        ks.add("k1", secrets.token_bytes(32))
        ks.set_active("k1")
        writer = RotatingKeyArchiveWriter(ks)
        base = tmp_path / "seg"
        writer(base, _valid_archive_bytes())

        bad_ks = ArchiveKeySet()
        bad_ks.add("k1", secrets.token_bytes(32))
        bad_ks.set_active("k1")

        enc = base.with_suffix(".enc")
        with pytest.raises(InvalidTag):
            MerkleArchiver.verify_encrypted_archive(enc, key_set=bad_ks)

    def test_both_supplied_raises(self, tmp_path: Path) -> None:
        key = secrets.token_bytes(32)
        ks = ArchiveKeySet()
        ks.add("k1", secrets.token_bytes(32))
        ks.set_active("k1")
        dummy = tmp_path / "dummy.enc"
        dummy.write_bytes(b"x")
        with pytest.raises(ValueError, match="exactly one"):
            MerkleArchiver.verify_encrypted_archive(dummy, key=key, key_set=ks)

    def test_neither_supplied_raises(self, tmp_path: Path) -> None:
        dummy = tmp_path / "dummy.enc"
        dummy.write_bytes(b"x")
        with pytest.raises(ValueError, match="exactly one"):
            MerkleArchiver.verify_encrypted_archive(dummy)

    def test_no_tmp_files_left(self, tmp_path: Path) -> None:
        """Temp files are cleaned up after verify_encrypted_archive."""
        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        base = tmp_path / "seg"
        writer(base, _valid_archive_bytes())
        enc = base.with_suffix(".enc")
        tmpdir = Path(tempfile.gettempdir())
        before = set(tmpdir.iterdir())
        MerkleArchiver.verify_encrypted_archive(enc, key=key)
        after = set(tmpdir.iterdir())
        new_files = {
            f for f in (after - before) if "pramanix.verify" in f.name
        }
        assert new_files == set()


# ---------------------------------------------------------------------------
# Integration: MerkleArchiver + EncryptedArchiveWriter end-to-end
# ---------------------------------------------------------------------------


class TestMerkleArchiverEncryptedIntegration:
    def test_archive_and_verify_encrypted(self, tmp_path: Path) -> None:
        key = secrets.token_bytes(32)
        writer = EncryptedArchiveWriter(key)
        archiver = MerkleArchiver(
            base_path=tmp_path,
            max_active_entries=5,
            segment_days=0,
            archive_writer=writer,
        )
        for i in range(5):
            archiver.add(f"decision-{i}", timestamp=float(i))

        enc_files = list(tmp_path.glob("*.enc"))
        assert len(enc_files) == 1, f"expected 1 .enc file, got {enc_files}"
        assert MerkleArchiver.verify_encrypted_archive(
            enc_files[0], key=key
        ) is True

    def test_archive_and_verify_rotating_key(self, tmp_path: Path) -> None:
        ks = ArchiveKeySet()
        ks.add("key-2026-01", secrets.token_bytes(32))
        ks.set_active("key-2026-01")
        writer = RotatingKeyArchiveWriter(ks)
        archiver = MerkleArchiver(
            base_path=tmp_path,
            max_active_entries=3,
            segment_days=0,
            archive_writer=writer,
        )
        for i in range(3):
            archiver.add(f"d-{i}", timestamp=float(i))

        enc_files = list(tmp_path.glob("*.enc"))
        assert len(enc_files) == 1
        assert MerkleArchiver.verify_encrypted_archive(
            enc_files[0], key_set=ks
        ) is True

    def test_plaintext_verify_still_works(self, tmp_path: Path) -> None:
        archiver = MerkleArchiver(
            base_path=tmp_path,
            max_active_entries=3,
            segment_days=0,
        )
        for i in range(3):
            archiver.add(f"d-{i}", timestamp=float(i))

        plain_files = [
            f for f in tmp_path.iterdir()
            if "archive" in f.name and not f.name.endswith(".enc")
        ]
        assert len(plain_files) == 1
        assert MerkleArchiver.verify_archive(plain_files[0]) is True

    def test_env_var_auto_encrypt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_MERKLE_ARCHIVE_KEY env var auto-enables encryption."""
        key = secrets.token_bytes(32)
        monkeypatch.setenv("PRAMANIX_MERKLE_ARCHIVE_KEY", key.hex())
        monkeypatch.setenv("PRAMANIX_MERKLE_ARCHIVE_PLAINTEXT_OK", "false")
        archiver = MerkleArchiver(
            base_path=tmp_path,
            max_active_entries=3,
            segment_days=0,
        )
        for i in range(3):
            archiver.add(f"ev-{i}", timestamp=float(i))

        enc_files = list(tmp_path.glob("*.enc"))
        assert len(enc_files) == 1
        assert MerkleArchiver.verify_encrypted_archive(
            enc_files[0], key=key
        ) is True
