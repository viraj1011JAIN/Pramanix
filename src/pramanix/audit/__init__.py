# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Cryptographic audit trail for Pramanix decisions.

Exports: DecisionSigner, DecisionVerifier, MerkleAnchor, PersistentMerkleAnchor,
         MerkleArchiver (E-2: pruning/archival), EncryptedArchiveWriter (AES-256-GCM)
"""

from pramanix.audit.archiver import EncryptedArchiveWriter, MerkleArchiver
from pramanix.audit.merkle import MerkleAnchor, PersistentMerkleAnchor
from pramanix.audit.signer import DecisionSigner
from pramanix.audit.verifier import DecisionVerifier

__all__ = [
    "DecisionSigner",
    "DecisionVerifier",
    "EncryptedArchiveWriter",
    "MerkleAnchor",
    "MerkleArchiver",
    "PersistentMerkleAnchor",
]
