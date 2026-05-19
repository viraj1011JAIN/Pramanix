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
    """Signs Decision objects with HMAC-SHA-256 for verifiable audit trails.

    A valid signing key (≥ 32 characters) is required at construction time.
    Constructing a ``DecisionSigner`` without a key raises
    :exc:`~pramanix.exceptions.ConfigurationError` immediately — a signer that
    cannot sign is not a signer; it is a misconfiguration waiting to produce
    silent audit-trail gaps.

    For deployments that intentionally operate without decision signing, do not
    instantiate this class.  Use ``DecisionSigner.optional()`` to get a signer
    instance only when a key is present::

        signer = DecisionSigner.optional()   # returns None if no key configured
        if signer:
            signed = signer.sign(decision)

    Generate a production key::

        python -c "import secrets; print(secrets.token_hex(64))"

    Store it in the ``PRAMANIX_SIGNING_KEY`` environment variable or pass it
    directly as ``signing_key``.

    Migration note (v0.9 → v1.0):
        Previously, constructing ``DecisionSigner()`` without a key silently
        set ``self._key = None`` and ``sign()`` returned ``None``.  This
        allowed misconfigured deployments to produce unsigned decision records
        without any error signal.  The new behaviour raises
        ``ConfigurationError`` immediately, surfacing misconfiguration at
        startup rather than silently at audit-review time.
    """

    _ALG = "HS256"
    _TYP = "PRAMANIX-PROOF"
    _ENV_KEY = "PRAMANIX_SIGNING_KEY"
    _MIN_KEY_LENGTH = 32

    def __init__(self, signing_key: str | None = None) -> None:
        from pramanix.exceptions import ConfigurationError

        raw = signing_key or os.environ.get(self._ENV_KEY, "")
        if not raw:
            raise ConfigurationError(
                "DecisionSigner requires a signing key. "
                f"Set the {self._ENV_KEY!r} environment variable to a "
                f"hex string of at least {self._MIN_KEY_LENGTH} characters, "
                "or pass signing_key= explicitly. "
                "Generate a key: python -c \"import secrets; print(secrets.token_hex(64))\". "
                "To operate without signing, do not instantiate DecisionSigner "
                "(or use DecisionSigner.optional() which returns None when no key is set)."
            )
        if len(raw) < self._MIN_KEY_LENGTH:
            raise ConfigurationError(
                f"DecisionSigner signing key is too short "
                f"({len(raw)} chars, minimum {self._MIN_KEY_LENGTH}). "
                "Short keys are cryptographically weak. "
                "Generate a secure key: "
                "python -c \"import secrets; print(secrets.token_hex(64))\""
            )
        self._key: bytes = raw.encode()

    @classmethod
    def optional(cls, signing_key: str | None = None) -> "DecisionSigner | None":
        """Return a ``DecisionSigner`` if a key is configured, or ``None``.

        Use this in application code that should function with or without
        decision signing::

            signer = DecisionSigner.optional()
            token = signer.sign(decision) if signer else None

        Returns ``None`` when no key is set rather than raising, making
        "signing is optional" an explicit, readable design choice instead of
        a misconfiguration that silently does nothing.
        """
        raw = signing_key or os.environ.get(cls._ENV_KEY, "")
        if not raw or len(raw) < cls._MIN_KEY_LENGTH:
            return None
        return cls(signing_key=raw)

    @property
    def is_active(self) -> bool:
        """Always True — a DecisionSigner with a valid key is always active."""
        return True

    def sign(self, decision: Decision) -> SignedDecision | None:
        """Sign a Decision and return a JWS compact token.

        Returns a :class:`SignedDecision` on success, or ``None`` if an
        internal signing error occurs (logged at ERROR with full traceback).
        Never raises — callers must treat ``None`` as a signing failure and
        alert accordingly (e.g. emit a metric, skip the audit record, retry).
        """
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
