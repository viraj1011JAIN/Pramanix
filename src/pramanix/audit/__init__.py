# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Cryptographic audit trail for Pramanix decisions.

Exports: DecisionSigner, DecisionVerifier, MerkleAnchor, PersistentMerkleAnchor,
         MerkleArchiver (E-2: pruning/archival), EncryptedArchiveWriter (AES-256-GCM),
         ArchiveKeySet, RotatingKeyArchiveWriter (key-rotation support)
"""

from pramanix.audit.archiver import (
    ArchiveKeySet,
    EncryptedArchiveWriter,
    MerkleArchiver,
    RotatingKeyArchiveWriter,
)
from pramanix.audit.merkle import MerkleAnchor, PersistentMerkleAnchor
from pramanix.audit.signer import DecisionSigner
from pramanix.audit.verifier import DecisionVerifier

__all__ = [
    "ArchiveKeySet",
    "DecisionSigner",
    "DecisionVerifier",
    "EncryptedArchiveWriter",
    "MerkleAnchor",
    "MerkleArchiver",
    "PersistentMerkleAnchor",
    "RotatingKeyArchiveWriter",
]
