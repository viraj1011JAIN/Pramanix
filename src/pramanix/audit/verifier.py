# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Standalone JWS verifier for Pramanix Decision proofs.

This file is intentionally self-contained — stdlib only.
An auditor can copy this single file and verify tokens offline.

Usage:
    verifier = DecisionVerifier(signing_key="<key>")
    result = verifier.verify(token)
    if result.valid:
        print(f"VALID: decision {result.decision_id}, allowed={result.allowed}")
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a SignedDecision token produced by DecisionSigner."""

    valid: bool
    decision_id: str
    allowed: bool
    status: str
    violated_invariants: list[str]
    explanation: str
    policy_hash: str
    """SHA-256 fingerprint of the policy that produced this decision."""
    issued_at: int
    """Unix timestamp (milliseconds) of signing.  Always ``0`` for tokens
    produced by the current SDK — ``iat`` was removed from the signed payload
    to make signing deterministic (replay-verifiable).
    """
    # Extended fields (added in v1.0 — all security-relevant Decision fields now signed)
    policy_name: str = ""
    decision_hash: str = ""
    hash_alg: str = ""
    signature: str = ""
    public_key_id: str = ""
    error_domain: str = ""
    stack_trace_hash: str = ""
    solver_time_ms: float = 0.0
    metadata: dict[str, object] | None = None
    intent_dump: dict[str, object] | None = None
    state_dump: dict[str, object] | None = None
    error: str | None = None


class DecisionVerifier:
    """Verifies SignedDecision tokens for tamper-evident audit log validation."""

    _MIN_KEY_LENGTH = 32

    def __init__(self, signing_key: str | None = None) -> None:
        raw = signing_key or os.environ.get("PRAMANIX_SIGNING_KEY", "")
        if not raw or len(raw) < self._MIN_KEY_LENGTH:
            raise ValueError(
                f"Signing key must be >= {self._MIN_KEY_LENGTH} characters. "
                'Generate one: python -c "import secrets; print(secrets.token_hex(64))"'
            )
        self._key = raw.encode()

    def verify(self, token: str) -> VerificationResult:
        """Verify a JWS compact token. Never raises."""
        try:
            parts = token.strip().split(".")
            if len(parts) != 3:
                return self._invalid("Token must have exactly 3 parts (header.payload.signature)")

            header_b64, payload_b64, sig_b64 = parts

            signing_input = f"{header_b64}.{payload_b64}"
            expected_sig = hmac.new(
                self._key,
                signing_input.encode(),
                hashlib.sha256,
            ).digest()
            expected_b64 = self._b64url(expected_sig)

            if not hmac.compare_digest(sig_b64.encode(), expected_b64.encode()):
                return self._invalid("Signature verification failed — token tampered or wrong key")

            payload_bytes = self._b64url_decode(payload_b64)
            payload = json.loads(payload_bytes)

            # Use strict identity check for `allowed` — `bool(truthy_non_bool)`
            # such as bool([1]) or bool({"x": 1}) would return True, allowing a
            # crafted token with a non-boolean `allowed` field to be accepted as
            # ALLOW.  The signed payload must contain the Python literal True.
            raw_allowed = payload.get("allowed")
            if raw_allowed is not True and raw_allowed is not False:
                return self._invalid(
                    f"Token 'allowed' field must be boolean true or false, "
                    f"got {type(raw_allowed).__name__!r}: {raw_allowed!r}"
                )
            return VerificationResult(
                valid=True,
                decision_id=str(payload.get("decision_id", "")),
                allowed=raw_allowed,
                status=str(payload.get("status", "")),
                violated_invariants=list(payload.get("violated_invariants", [])),
                explanation=str(payload.get("explanation", "")),
                policy_hash=str(payload.get("policy_hash", "")),
                issued_at=int(payload.get("iat", 0)),
                policy_name=str(payload.get("policy_name", "")),
                decision_hash=str(payload.get("decision_hash", "")),
                hash_alg=str(payload.get("hash_alg", "")),
                signature=str(payload.get("signature", "")),
                public_key_id=str(payload.get("public_key_id", "")),
                error_domain=str(payload.get("error_domain", "")),
                stack_trace_hash=str(payload.get("stack_trace_hash", "")),
                solver_time_ms=float(payload.get("solver_time_ms", 0.0)),
                metadata=dict(payload["metadata"]) if isinstance(payload.get("metadata"), dict) else None,
                intent_dump=dict(payload["intent_dump"]) if isinstance(payload.get("intent_dump"), dict) else None,
                state_dump=dict(payload["state_dump"]) if isinstance(payload.get("state_dump"), dict) else None,
            )
        except Exception as exc:
            return self._invalid(str(exc))

    @staticmethod
    def _invalid(error: str) -> VerificationResult:
        return VerificationResult(
            valid=False,
            decision_id="",
            allowed=False,
            status="",
            violated_invariants=[],
            explanation="",
            policy_hash="",
            issued_at=0,
            error=error,
        )


    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)
