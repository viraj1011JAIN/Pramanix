# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
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
    """SHA-256 fingerprint of the policy that produced this decision.

    Previously named ``policy`` (which was always empty because the signed
    payload used the wrong key name).  Corrected in v0.5.x to read the
    actual ``policy_hash`` field written by :class:`~pramanix.audit.signer.DecisionSigner`.
    """
    issued_at: int
    """Unix timestamp (milliseconds) of signing.  Always ``0`` for tokens
    produced by the current SDK — ``iat`` was removed from the signed payload
    in v0.5.x to make signing deterministic (replay-verifiable).  The
    timestamp is available on :attr:`~pramanix.audit.signer.SignedDecision.issued_at`
    when the token is produced, but is NOT embedded in the JWS body.
    """
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

            return VerificationResult(
                valid=True,
                decision_id=str(payload.get("decision_id", "")),
                allowed=bool(payload.get("allowed", False)),
                status=str(payload.get("status", "")),
                violated_invariants=list(payload.get("violated_invariants", [])),
                explanation=str(payload.get("explanation", "")),
                # "policy_hash" is the correct key written by DecisionSigner._canonicalize().
                # The old key "policy" was a bug — it never existed in to_dict() and
                # always resolved to "".  "iat" was removed from the signed payload in
                # v0.5.x (N6 fix) to make signing deterministic; it is therefore always 0.
                policy_hash=str(payload.get("policy_hash", "")),
                issued_at=int(payload.get("iat", 0)),
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
