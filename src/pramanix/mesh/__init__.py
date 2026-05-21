# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Pillar 2 — Zero-Trust Agent Mesh.

Provides SPIFFE JWT-SVID authentication and principal binding for agent-to-agent
calls within the Pramanix Neuro-Symbolic Policy Engine.  The authenticator sits
*before* ``Guard.verify()`` and cryptographically validates every inbound bearer
token before the intent is admitted into the policy pipeline.

Public surface
--------------
* :class:`~pramanix.mesh.authenticator.MeshAuthenticator` — SPIFFE JWT-SVID
  validator with JWKS endpoint support and static-PEM fallback.
* :class:`~pramanix.mesh.authenticator.SpiffeIdentity` — frozen dataclass
  holding the validated SPIFFE URI, trust domain, and raw JWT claims.
* :exc:`~pramanix.exceptions.MeshAuthenticationError` — fail-closed exception
  raised on any authentication failure (re-exported for convenience).
"""

from pramanix.exceptions import MeshAuthenticationError
from pramanix.mesh.authenticator import MeshAuthenticator, SpiffeIdentity

__all__ = [
    "MeshAuthenticationError",
    "MeshAuthenticator",
    "SpiffeIdentity",
]
