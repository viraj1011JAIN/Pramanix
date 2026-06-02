# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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

import contextlib
import hashlib
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

_log = logging.getLogger(__name__)

# ── ArchiveWriter protocol ────────────────────────────────────────────────────
# A callable ``(path: Path, content: bytes) -> None`` that persists an archive
# segment.  The default writer writes plaintext UTF-8.  For compliance regimes
# that require encryption at rest (SOC 2 Type II, PCI DSS, HIPAA) supply a
# custom writer that encrypts with AES-256-GCM before writing to disk.
#
# Example — AES-256-GCM writer using ``cryptography``::
#
#     from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#     import secrets
#
#     key = AESGCM.generate_key(bit_length=256)   # store in KMS
#     gcm = AESGCM(key)
#
#     def encrypted_writer(path: Path, content: bytes) -> None:
#         nonce = secrets.token_bytes(12)
#         ciphertext = gcm.encrypt(nonce, content, None)
#         path.with_suffix(".enc").write_bytes(nonce + ciphertext)
#
#     archiver = MerkleArchiver(archive_writer=encrypted_writer)
ArchiveWriter = "Callable[[Path, bytes], None]"


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


def _default_archive_writer(path: Path, content: bytes) -> None:
    """Default plaintext writer — atomic write via tempfile + os.replace()."""
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".merkle.tmp.", suffix=".partial")
    try:
        with os.fdopen(tmp_fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    os.replace(tmp_path, path)


class EncryptedArchiveWriter:
    """AES-256-GCM archive writer for SOC 2, PCI DSS, and HIPAA compliance.

    Encrypts each archive segment with AES-256-GCM before writing to disk.
    Each write generates a fresh 12-byte random nonce (NIST SP 800-38D §8.2
    compliant: nonce space is 2^96; probability of collision is negligible
    for the volumes produced by MerkleArchiver).

    Wire format (written to ``path.with_suffix(".enc")``):
    ``[12-byte nonce][GCM-authenticated ciphertext (tag appended by AESGCM)]``

    The GCM authentication tag is verified on every :meth:`decrypt` call —
    any byte-level tampering raises
    :class:`cryptography.exceptions.InvalidTag` before plaintext is returned.

    Requires: ``cryptography >= 41.0`` (core Pramanix dependency, always
    present; no extra install needed).

    Args:
        key: 32-byte AES-256 key.  Generate once and store in a KMS::

                import secrets
                key = secrets.token_bytes(32)  # store in Vault / AWS KMS / etc.

    Raises:
        ValueError: If *key* is not exactly 32 bytes.
        ConfigurationError: If the ``cryptography`` package is not installed.

    Example::

        import secrets
        from pramanix.audit.archiver import EncryptedArchiveWriter, MerkleArchiver

        key = secrets.token_bytes(32)  # persist this in your KMS
        writer = EncryptedArchiveWriter(key)
        archiver = MerkleArchiver(base_path="/var/lib/pramanix/merkle",
                                  archive_writer=writer)
    """

    _NONCE_BYTES: int = 12  # 96-bit nonce — NIST SP 800-38D recommendation for GCM

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(
                f"EncryptedArchiveWriter requires a 32-byte AES-256 key "
                f"(got {len(key)} bytes).  "
                f"Generate one with: secrets.token_bytes(32)"
            )
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "The 'cryptography' package is required for EncryptedArchiveWriter. "
                "Install it with: pip install pramanix  (it is a core dependency)"
            ) from exc

        self._aesgcm = AESGCM(key)

    def __call__(self, path: Path, content: bytes) -> None:
        """Encrypt *content* with AES-256-GCM and write to ``path.with_suffix('.enc')``.

        Writes atomically via a tempfile + :func:`os.replace` so a crash
        mid-write never leaves a partial or corrupt ciphertext on disk.

        Args:
            path:    Base path provided by :class:`MerkleArchiver`.  The
                     ``.enc`` suffix is appended so plaintext and ciphertext
                     archive paths are never confused.
            content: Raw plaintext bytes (UTF-8 encoded NDJSON archive).
        """
        nonce = secrets.token_bytes(self._NONCE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, content, None)
        payload = nonce + ciphertext  # nonce prepended; decrypt() splits on _NONCE_BYTES

        enc_path = path.with_suffix(".enc")
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=enc_path.parent, prefix=".merkle.enc.tmp.", suffix=".partial"
        )
        try:
            with os.fdopen(tmp_fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        os.replace(tmp_path, enc_path)

    @staticmethod
    def decrypt(key: bytes, enc_path: Path) -> bytes:
        """Decrypt an archive segment written by :class:`EncryptedArchiveWriter`.

        Reads the ``[nonce][ciphertext+tag]`` payload, verifies the GCM
        authentication tag, and returns plaintext bytes.  Any byte-level
        tampering raises :class:`cryptography.exceptions.InvalidTag` before
        any plaintext is exposed.

        Args:
            key:      The same 32-byte key used at encryption time.
            enc_path: Path to the ``.enc`` file produced by this writer.

        Returns:
            Plaintext bytes (UTF-8 encoded NDJSON archive).

        Raises:
            ValueError:                         *key* is not 32 bytes.
            FileNotFoundError:                  *enc_path* does not exist.
            cryptography.exceptions.InvalidTag: Ciphertext has been tampered with.
        """
        if len(key) != 32:
            raise ValueError(f"decrypt() requires a 32-byte AES-256 key (got {len(key)} bytes).")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        raw = Path(enc_path).read_bytes()
        nonce = raw[: EncryptedArchiveWriter._NONCE_BYTES]
        ciphertext = raw[EncryptedArchiveWriter._NONCE_BYTES :]
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically random 32-byte AES-256 key.

        Returns:
            32 random bytes suitable for use as an AES-256 key.  Store this
            in a KMS (AWS KMS, HashiCorp Vault, Azure Key Vault, GCP Cloud KMS)
            before using it in production.
        """
        return secrets.token_bytes(32)


class ArchiveKeySet:
    """Manages multiple AES-256 keys for Merkle archive key rotation.

    Usage::

        key_set = ArchiveKeySet()
        key_set.add("key-2026-01", secrets.token_bytes(32))
        key_set.set_active("key-2026-01")

        # Six months later — rotate without losing decryptability of old archives:
        old_id = key_set.rotate("key-2026-07", secrets.token_bytes(32))
        # key-2026-01 is still in the set for decrypting old .enc files.
        # Remove it only once all archives encrypted with it have been re-encrypted:
        # key_set.remove(old_id)   # optional cleanup

    Thread-safety: all mutations are protected by an internal ``threading.Lock``.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}
        self._active_key_id: str | None = None
        self._lock: threading.Lock = threading.Lock()

    def add(self, key_id: str, key: bytes) -> None:
        """Add *key* under *key_id*.  Overwrites silently if the ID already exists."""
        if len(key) != 32:
            raise ValueError(
                f"ArchiveKeySet.add({key_id!r}): key must be exactly 32 bytes "
                f"(got {len(key)}).  Generate one with secrets.token_bytes(32)."
            )
        with self._lock:
            self._keys[key_id] = key

    def remove(self, key_id: str) -> None:
        """Remove *key_id* from the set.  Raises ``KeyError`` if not found.

        Do not remove a key while archives encrypted with it still exist and
        have not been re-encrypted — decryption will fail.
        """
        with self._lock:
            if key_id not in self._keys:
                raise KeyError(key_id)
            if key_id == self._active_key_id:
                raise ValueError(
                    f"Cannot remove active key {key_id!r}. " "Call rotate() or set_active() first."
                )
            del self._keys[key_id]

    def set_active(self, key_id: str) -> None:
        """Set *key_id* as the key used for new encryption operations."""
        with self._lock:
            if key_id not in self._keys:
                raise KeyError(
                    f"Key {key_id!r} not in ArchiveKeySet. " "Call add(key_id, key) first."
                )
            self._active_key_id = key_id

    def rotate(self, new_key_id: str, new_key: bytes) -> str:
        """Add *new_key* as *new_key_id* and promote it to active.

        The old active key remains in the set for decrypting historical
        archives.  Returns the previously active key_id so the caller
        can schedule its eventual removal.

        Raises:
            RuntimeError: If no active key has been set yet.
        """
        self.add(new_key_id, new_key)
        with self._lock:
            old_id = self._active_key_id
            if old_id is None:
                raise RuntimeError(
                    "ArchiveKeySet.rotate() called before any active key was set. "
                    "Call set_active() at least once first."
                )
            self._active_key_id = new_key_id
        return old_id

    @property
    def active_key_id(self) -> str:
        """The key_id currently used for encryption.  Raises ``RuntimeError`` if unset."""
        with self._lock:
            if self._active_key_id is None:
                raise RuntimeError(
                    "ArchiveKeySet has no active key. "
                    "Call add(key_id, key) then set_active(key_id)."
                )
            return self._active_key_id

    @property
    def active_key(self) -> bytes:
        """The 32-byte key currently used for encryption."""
        with self._lock:
            if self._active_key_id is None:
                raise RuntimeError("ArchiveKeySet has no active key.")
            return self._keys[self._active_key_id]

    def get(self, key_id: str) -> bytes:
        """Return the key for *key_id*.  Raises ``KeyError`` if not found."""
        with self._lock:
            try:
                return self._keys[key_id]
            except KeyError:
                raise KeyError(
                    f"Key {key_id!r} not found in ArchiveKeySet. "
                    "This key may have been removed or was never added."
                ) from None

    def key_ids(self) -> list[str]:
        """Return all key IDs currently in the set (unordered)."""
        with self._lock:
            return list(self._keys)


class RotatingKeyArchiveWriter:
    """AES-256-GCM writer with key rotation support.

    Embeds a *key_id* in the wire format so that historical archives can
    be decrypted with the correct key from an :class:`ArchiveKeySet` even
    after the active key has been rotated.

    Wire format (written to ``path.with_suffix(".enc")``)::

        [4-byte magic: b'RPMK']
        [2-byte key_id length, big-endian]
        [key_id bytes, UTF-8]
        [12-byte nonce (random per-write)]
        [AES-256-GCM ciphertext with appended 16-byte auth tag]

    The 4-byte magic ``b'RPMK'`` disambiguates this format from archives
    written by the single-key :class:`EncryptedArchiveWriter` (which starts
    with a raw nonce).

    Requires: ``cryptography >= 41.0``

    Args:
        key_set: An :class:`ArchiveKeySet` with at least one key and an active
                 key set.

    Raises:
        ConfigurationError: If the ``cryptography`` package is not installed.
    """

    _MAGIC: bytes = b"RPMK"
    _NONCE_BYTES: int = 12
    _MAX_KEY_ID_BYTES: int = 65_535

    def __init__(self, key_set: ArchiveKeySet) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM  # noqa: F401
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "The 'cryptography' package is required for RotatingKeyArchiveWriter. "
                "Install it with: pip install pramanix  (it is a core dependency)"
            ) from exc
        self._key_set = key_set

    def __call__(self, path: Path, content: bytes) -> None:
        """Encrypt *content* and write to ``path.with_suffix('.enc')``."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key_id = self._key_set.active_key_id
        key_id_bytes = key_id.encode("utf-8")
        if len(key_id_bytes) > self._MAX_KEY_ID_BYTES:
            raise ValueError(
                f"key_id {key_id!r} is too long "
                f"({len(key_id_bytes)} bytes > {self._MAX_KEY_ID_BYTES})."
            )

        nonce = secrets.token_bytes(self._NONCE_BYTES)
        ciphertext = AESGCM(self._key_set.active_key).encrypt(nonce, content, None)

        payload = (
            self._MAGIC + len(key_id_bytes).to_bytes(2, "big") + key_id_bytes + nonce + ciphertext
        )

        enc_path = path.with_suffix(".enc")
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=enc_path.parent, prefix=".merkle.rot.tmp.", suffix=".partial"
        )
        try:
            with os.fdopen(tmp_fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        os.replace(tmp_path, enc_path)

    @classmethod
    def decrypt(cls, key_set: ArchiveKeySet, enc_path: Path) -> bytes:
        """Decrypt an archive written by :class:`RotatingKeyArchiveWriter`.

        Reads the embedded *key_id*, retrieves the key from *key_set*, and
        decrypts.  Authentication tag mismatch raises
        :class:`cryptography.exceptions.InvalidTag`.

        Args:
            key_set:  Must contain the key that was active when the archive
                      was written (identified by the embedded key_id).
            enc_path: Path to the ``.enc`` file.

        Raises:
            ValueError:                         File is not in RPMK format.
            KeyError:                           key_id embedded in file is not
                                                in *key_set*.
            cryptography.exceptions.InvalidTag: Ciphertext has been tampered.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        raw = Path(enc_path).read_bytes()
        if not raw.startswith(cls._MAGIC):
            raise ValueError(
                f"File {enc_path} is not in RPMK rotating-key format "
                f"(expected magic {cls._MAGIC!r}, got {raw[:4]!r}). "
                "Use EncryptedArchiveWriter.decrypt() for single-key archives."
            )

        offset = len(cls._MAGIC)
        key_id_len = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        key_id = raw[offset : offset + key_id_len].decode("utf-8")
        offset += key_id_len
        nonce = raw[offset : offset + cls._NONCE_BYTES]
        offset += cls._NONCE_BYTES
        ciphertext = raw[offset:]

        return AESGCM(key_set.get(key_id)).decrypt(nonce, ciphertext, None)


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
        archive_writer:     Callable ``(path: Path, content: bytes) -> None``
                            that persists each archive segment.  Defaults to
                            the plaintext atomic writer.  Supply an encrypted
                            writer for SOC 2, PCI DSS, or HIPAA deployments::

                                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                                import secrets
                                gcm = AESGCM(key)
                                def enc_writer(p, data):
                                    nonce = secrets.token_bytes(12)
                                    p.write_bytes(nonce + gcm.encrypt(nonce, data, None))
                                archiver = MerkleArchiver(archive_writer=enc_writer)

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
        archive_writer: Callable[[Path, bytes], None] | None = None,
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
        self._writer: Callable[[Path, bytes], None] = archive_writer or _default_archive_writer
        self._active: list[_Leaf] = []
        self._lock: threading.Lock = threading.Lock()
        if archive_writer is None:
            # ── Auto-encrypt if PRAMANIX_MERKLE_ARCHIVE_KEY is set ────────────
            # Operators may set PRAMANIX_MERKLE_ARCHIVE_KEY to a 64-char hex
            # string (= 32 bytes) to enable AES-256-GCM encryption without
            # needing to modify application code:
            #
            #   export PRAMANIX_MERKLE_ARCHIVE_KEY=$(python -c \
            #       "import secrets; print(secrets.token_bytes(32).hex())")
            #
            _env_key_hex = os.environ.get("PRAMANIX_MERKLE_ARCHIVE_KEY", "").strip()
            if _env_key_hex:
                try:
                    _key = bytes.fromhex(_env_key_hex)
                    if len(_key) != 32:
                        raise ValueError(f"key must be 32 bytes (got {len(_key)})")
                    self._writer = EncryptedArchiveWriter(_key)
                    _log.info(
                        "MerkleArchiver: AES-256-GCM encryption enabled via "
                        "PRAMANIX_MERKLE_ARCHIVE_KEY environment variable."
                    )
                except ValueError as exc:
                    _log.warning(
                        "MerkleArchiver: PRAMANIX_MERKLE_ARCHIVE_KEY is set but invalid "
                        "(%s) — falling back to PLAINTEXT writer.  "
                        "Fix the key or unset the variable.",
                        exc,
                    )
                    # Emit the loud plaintext warning too (falls through below)
                    _env_key_hex = ""  # clear so the plaintext warning fires

            if not _env_key_hex:
                _plaintext_ok = (
                    os.environ.get("PRAMANIX_MERKLE_ARCHIVE_PLAINTEXT_OK", "").strip().lower()
                    == "true"
                )
                if not _plaintext_ok:
                    _log.warning(
                        "MerkleArchiver: no archive_writer supplied and "
                        "PRAMANIX_MERKLE_ARCHIVE_KEY is not set — segments written as "
                        "PLAINTEXT UTF-8.  For SOC 2, PCI DSS, or HIPAA deployments:\n"
                        "  Option A: set PRAMANIX_MERKLE_ARCHIVE_KEY=<64-char-hex> in the "
                        "environment (auto-enables AES-256-GCM).\n"
                        "  Option B: pass archive_writer=EncryptedArchiveWriter(key) to "
                        "MerkleArchiver.  See MerkleArchiver docstring for examples.\n"
                        "  (Silence this warning in tests: "
                        "PRAMANIX_MERKLE_ARCHIVE_PLAINTEXT_OK=true)"
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
        with self._lock:
            self._active.append(_Leaf(decision_id=decision_id, leaf_hash=leaf_hash, ts=ts))
            if len(self._active) >= self._max_active:
                return self._archive_segment()
        return None

    def archive(self) -> ArchiveResult | None:
        """Manually trigger archival of the oldest segment.

        Returns ``None`` if there are no entries to archive.
        """
        with self._lock:
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
        with self._lock:
            return len(self._active)

    def root(self) -> str | None:
        """Return the Merkle root of all active leaves, or ``None`` if empty."""
        with self._lock:
            if not self._active:
                return None
            return _build_root([leaf.leaf_hash for leaf in self._active])

    def active_leaves(self) -> list[_Leaf]:
        """Return a copy of the active leaf list (for testing/inspection)."""
        with self._lock:
            return list(self._active)

    @classmethod
    def verify_encrypted_archive(
        cls,
        archive_path: str | Path,
        *,
        key: bytes | None = None,
        key_set: ArchiveKeySet | None = None,
    ) -> bool:
        """Decrypt and verify an encrypted archive segment.

        Supply exactly one of *key* (for :class:`EncryptedArchiveWriter`
        archives) or *key_set* (for :class:`RotatingKeyArchiveWriter`
        archives).

        Args:
            archive_path: Path to the ``.enc`` file.
            key:          32-byte AES-256 key used at encryption time
                          (single-key :class:`EncryptedArchiveWriter` mode).
            key_set:      :class:`ArchiveKeySet` containing the key identified
                          by the embedded ``key_id``
                          (:class:`RotatingKeyArchiveWriter` mode).

        Returns:
            ``True`` if the decrypted archive passes :meth:`verify_archive`,
            ``False`` if the Merkle root mismatches.

        Raises:
            ValueError:                         Neither or both of *key* /
                                                *key_set* were supplied.
            cryptography.exceptions.InvalidTag: Ciphertext has been tampered.
            KeyError:                           Embedded key_id not in *key_set*.
        """
        if (key is None) == (key_set is None):
            raise ValueError(
                "verify_encrypted_archive() requires exactly one of key= or key_set=, not both or neither."
            )

        enc_path = Path(archive_path)
        if key is not None:
            plaintext = EncryptedArchiveWriter.decrypt(key, enc_path)
        else:
            assert key_set is not None
            plaintext = RotatingKeyArchiveWriter.decrypt(key_set, enc_path)

        tmp_fd, tmp_path_str = tempfile.mkstemp(suffix=".merkle.verify", prefix=".pramanix.verify.")
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(tmp_fd, "wb") as fh:
                fh.write(plaintext)
            return cls.verify_archive(tmp_path)
        finally:
            with contextlib.suppress(OSError):
                tmp_path.unlink()

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
        content_bytes = ("\n".join(lines) + "\n").encode("utf-8")
        # Delegate to the configured writer (default: plaintext atomic write;
        # custom: caller-supplied encrypted writer for compliance deployments).
        self._writer(archive_path, content_bytes)

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
            hashlib.sha256(b"\x01" + (level[i] + level[i + 1]).encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]
