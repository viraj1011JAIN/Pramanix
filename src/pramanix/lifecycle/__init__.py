# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Policy lifecycle management: structural diffs and shadow evaluation."""

from pramanix.lifecycle.diff import (
    FieldChange,
    InvariantChange,
    PolicyDiff,
    ShadowEvaluator,
    ShadowResult,
)

__all__ = [
    "FieldChange",
    "InvariantChange",
    "PolicyDiff",
    "ShadowEvaluator",
    "ShadowResult",
]
