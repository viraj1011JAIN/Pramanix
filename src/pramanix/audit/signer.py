# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
import logging
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision

_log = logging.getLogger(__name__)

_signing_failure_counter_lock = __import__("threading").Lock()
_signing_failure_counter: Any = None


def _inc_signing_failure() -> None:
    """Increment pramanix_signing_failures_total Prometheus counter."""
    global _signing_failure_counter
    try:
        from prometheus_client import Counter

        with _signing_failure_counter_lock:
            if _signing_failure_counter is None:
                try:
                    _signing_failure_counter = Counter(
                        "pramanix_signing_failures_total",
                        "Total Decision signing failures (exception or missing key)",
                    )
                except ValueError:
                    return
        _signing_failure_counter.inc()
    except ImportError:
        pass
    except Exception:
        pass


@dataclass(frozen=True)
class SignedDecision:
    """A Decision augmented with a compact JWS token for tamper-evident audit."""

    token: str  # Full JWS compact serialization
    decision_id: str  # Copied from Decision for fast lookup
    issued_at: int  # Unix timestamp (ms)


class DecisionSigner:
    """Signs Decision objects with HMAC-SHA-256 for verifiable audit trails."""

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
        """True if a valid signing key is configured."""
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
        except Exception as exc:
            _log.error(
                "pramanix.audit.signer: sign() failed for decision_id=%s — "
                "no signed token produced (audit trail integrity gap): %s",
                getattr(decision, "decision_id", "<unknown>"),
                exc,
                exc_info=True,
            )
            _inc_signing_failure()
            return None

    def _canonicalize(self, decision: Decision) -> dict[str, Any]:
        """Produce a deterministic canonical dict from a Decision.

        Uses the exact key names returned by ``decision.to_dict()``.
        ``iat`` is intentionally excluded from the signed payload — it is
        non-deterministic (changes on every call) and is already captured
        in ``SignedDecision.issued_at`` outside the HMAC boundary.  Including
        it would make deterministic replay verification impossible.
        """
        d = decision.to_dict()
        return {
            "decision_id": str(d.get("decision_id", "")),
            "allowed": bool(d.get("allowed", False)),
            "explanation": str(d.get("explanation", "")),
            "policy_hash": str(d.get("policy_hash", "")),
            "solver_time_ms": float(d.get("solver_time_ms", 0)),
            "status": str(d.get("status", "")),
            "violated_invariants": sorted(str(v) for v in d.get("violated_invariants", [])),
        }

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
