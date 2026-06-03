# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Pillar 3 — Compliance Oracle: regulatory attestation engine.

Exposes the public API of :mod:`pramanix.compliance.oracle` at the package level
so that callers only need a single import:

.. code-block:: python

    from pramanix.compliance import (
        ComplianceAttestation,
        ComplianceOracle,
        ControlEnforcementResult,
        ControlMapping,
        ControlSatisfactionResult,
        FrameworkAttestation,
        MappingMatchKind,
        RegulatoryFramework,
    )

See :mod:`pramanix.compliance.oracle` for full documentation.
"""

from __future__ import annotations

from pramanix.compliance.oracle import (
    ComplianceAttestation,
    ComplianceOracle,
    ControlEnforcementResult,
    ControlMapping,
    ControlSatisfactionResult,
    FrameworkAttestation,
    MappingMatchKind,
    RegulatoryFramework,
    default_oracle,
)

__all__ = [
    "ComplianceAttestation",
    "ComplianceOracle",
    "ControlEnforcementResult",
    "ControlMapping",
    "ControlSatisfactionResult",
    "FrameworkAttestation",
    "MappingMatchKind",
    "RegulatoryFramework",
    "default_oracle",
]
