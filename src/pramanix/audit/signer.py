# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""JWS signing for Pramanix Decision objects.

The signing key is loaded from PRAMANIX_SIGNING_KEY environment variable.
Minimum key length: 32 characters.
Generate a production key:
    python -c "import secrets; print(secrets.token_hex(64))"

Token format: base64url(header).base64url(payload).base64url(sig)
Algorithm: HMAC-SHA256
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision


@dataclass(frozen=True)
class SignedDecision:
    token: str  # Full JWS compact serialization
    decision_id: str  # Copied from Decision for fast lookup
    issued_at: int  # Unix timestamp (ms)


class DecisionSigner:
    _ALG = "HS256"
    _TYP = "PRAMANIX-PROOF"
    _ENV_KEY = "PRAMANIX_SIGNING_KEY"
    _MIN_KEY_LENGTH = 32

    def __init__(self, signing_key: str | None = None) -> None:
        raw = signing_key or os.environ.get(self._ENV_KEY, "")
        if raw and len(raw) >= self._MIN_KEY_LENGTH:
            self._key: bytes | None = raw.encode()
        else:
            self._key = None

    @property
    def is_active(self) -> bool:
        return self._key is not None

    def sign(self, decision: Decision) -> SignedDecision | None:
        """Sign a Decision and return a JWS compact token.

        Returns None if no signing key is configured.
        Never raises — signing failures return None.
        """
        if not self._key:
            return None
        try:
            header = self._b64url(
                json.dumps(
                    {"alg": self._ALG, "typ": self._TYP},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            )
            payload_dict = self._canonicalize(decision)
            payload = self._b64url(
                json.dumps(
                    payload_dict,
                    separators=(",", ":"),
                    sort_keys=True,
                    default=str,
                ).encode()
            )
            signing_input = f"{header}.{payload}"
            sig = hmac.new(
                self._key,
                signing_input.encode(),
                hashlib.sha256,
            ).digest()
            token = f"{signing_input}.{self._b64url(sig)}"
            return SignedDecision(
                token=token,
                decision_id=decision.decision_id,
                issued_at=int(time.time() * 1000),
            )
        except Exception:
            return None

    def _canonicalize(self, decision: Decision) -> dict[str, Any]:
        """Produce a deterministic canonical dict from a Decision."""
        d = decision.to_dict()
        return {
            "decision_id": str(d.get("decision_id", "")),
            "allowed": bool(d.get("allowed", False)),
            "explanation": str(d.get("explanation", "")),
            "iat": int(time.time()),
            "policy": str(d.get("policy", "")),
            "solver_time_ms": float(d.get("solver_time_ms", 0)),
            "state_version": str(d.get("state_version", "")),
            "status": str(d.get("status", "")),
            "violated_invariants": sorted(str(v) for v in d.get("violated_invariants", [])),
        }

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
