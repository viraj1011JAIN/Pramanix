# SPDX-License-Identifier: Apache-2.0
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
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision

_log = logging.getLogger(__name__)

_signing_failure_counter_lock = threading.Lock()
_signing_failure_counter: Any = None


def _sort_dict(d: Any) -> Any:
    """Recursively sort dict keys for deterministic JSON serialisation."""
    if isinstance(d, dict):
        return {k: _sort_dict(v) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return [_sort_dict(i) for i in d]
    return d


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
    except Exception as _exc:
        _log.warning(
            "pramanix.audit.signer: unexpected error incrementing "
            "pramanix_signing_failures_total counter — metric may be stale. "
            "Error: %s",
            _exc,
            exc_info=True,
        )


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
            try:
                signed = signer.sign(decision)
            except SigningError:
                log.error("audit token signing failed")

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
                'Generate a key: python -c "import secrets; print(secrets.token_hex(64))". '
                "To operate without signing, do not instantiate DecisionSigner "
                "(or use DecisionSigner.optional() which returns None when no key is set)."
            )
        if len(raw) < self._MIN_KEY_LENGTH:
            raise ConfigurationError(
                f"DecisionSigner signing key is too short "
                f"({len(raw)} chars, minimum {self._MIN_KEY_LENGTH}). "
                "Short keys are cryptographically weak. "
                "Generate a secure key: "
                'python -c "import secrets; print(secrets.token_hex(64))"'
            )
        self._key: bytes = raw.encode()

    @classmethod
    def optional(cls, signing_key: str | None = None) -> DecisionSigner | None:
        """Return a ``DecisionSigner`` if a key is configured, or ``None``.

        Use this in application code that should function with or without
        decision signing::

            signer = DecisionSigner.optional()
            if signer:
                try:
                    signed = signer.sign(decision)
                except SigningError:
                    log.error("audit token signing failed")
                    signed = None

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

    def sign(self, decision: Decision) -> SignedDecision:
        """Sign a Decision and return a JWS compact token.

        Returns a :class:`SignedDecision` on success.

        Raises:
            SigningError: If the signing operation fails for any reason.
                Callers must never silently swallow this — a signing failure
                means the audit trail's chain-of-custody guarantee is broken.
        """
        from pramanix.exceptions import SigningError

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
        except SigningError:
            raise
        except Exception as exc:
            _log.error(
                "pramanix.audit.signer: sign() failed for decision_id=%s — "
                "audit trail integrity gap: %s",
                getattr(decision, "decision_id", "<unknown>"),
                exc,
                exc_info=True,
            )
            _inc_signing_failure()
            raise SigningError(
                f"DecisionSigner.sign() failed for decision_id="
                f"{getattr(decision, 'decision_id', '<unknown>')}: {exc}"
            ) from exc

    def _canonicalize(self, decision: Decision) -> dict[str, Any]:
        """Produce a deterministic canonical dict from a Decision.

        Covers all 17 security-relevant fields from ``decision.to_dict()``.
        ``iat`` is intentionally excluded — it is non-deterministic (changes
        on every call) and is captured in ``SignedDecision.issued_at`` outside
        the HMAC boundary; including it would make replay verification impossible.

        ``metadata``, ``intent_dump``, and ``state_dump`` are JSON-sorted so
        the canonical form is stable regardless of insertion order.
        """
        d = decision.to_dict()
        return {
            "allowed": bool(d.get("allowed", False)),
            "decision_hash": str(d.get("decision_hash") or ""),
            "decision_id": str(d.get("decision_id", "")),
            "error_domain": str(d.get("error_domain") or ""),
            "explanation": str(d.get("explanation", "")),
            "hash_alg": str(d.get("hash_alg") or ""),
            "intent_dump": _sort_dict(d.get("intent_dump") or {}),
            "metadata": _sort_dict(d.get("metadata") or {}),
            "policy_hash": str(d.get("policy_hash") or ""),
            "policy_name": str(d.get("policy_name") or ""),
            "public_key_id": str(d.get("public_key_id") or ""),
            "signature": str(d.get("signature") or ""),
            "solver_time_ms": float(d.get("solver_time_ms", 0)),
            "stack_trace_hash": str(d.get("stack_trace_hash") or ""),
            "state_dump": _sort_dict(d.get("state_dump") or {}),
            "status": str(d.get("status", "")),
            "violated_invariants": sorted(str(v) for v in d.get("violated_invariants", [])),
        }

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
