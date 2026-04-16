# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Ed25519 cryptographic signing for Pramanix Decision objects.

Every Decision produced by a Guard with a configured PramanixSigner
carries an Ed25519 signature over its decision_hash. This signature
can be verified offline by any holder of the public key — no Pramanix
SDK installation required, only the Python cryptography library.

Key management:
    Production:  Load private key from AWS KMS, HashiCorp Vault, or
                 Kubernetes Secret. Never store private key in source code.
    Development: Set PRAMANIX_SIGNING_KEY_PEM env var to PEM-encoded key.
    Fallback:    Ephemeral key generated at startup (warns on stderr).

Key generation:
    from pramanix.crypto import PramanixSigner
    signer = PramanixSigner.generate()
    # Save private key PEM to your secrets manager
    print(signer.private_key_pem().decode())
    # Publish public key PEM (safe to share)
    print(signer.public_key_pem().decode())

Rotation:
    Old public keys must be ARCHIVED — decisions signed with old keys
    remain verifiable indefinitely using the archived public key.
    New key_id appears in all new decisions, indicating which key to use.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    from pramanix.decision import Decision

log = logging.getLogger(__name__)

_ENV_KEY_PEM = "PRAMANIX_SIGNING_KEY_PEM"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


class PramanixSigner:
    """Ed25519 signer for Pramanix Decision objects.

    Usage:
        # Production: load from secrets manager
        signer = PramanixSigner(private_key_pem=vault.get_secret("pramanix-key"))

        # Development: load from environment
        signer = PramanixSigner()  # reads PRAMANIX_SIGNING_KEY_PEM

        # Wire into Guard
        guard = Guard(policy, GuardConfig(signer=signer))

        # Verify a decision
        decision = guard.verify(intent=..., state=...)
        assert decision.signature  # Present when signer is configured

        # Offline verification (no Guard needed)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision)
    """

    _private_key: Ed25519PrivateKey
    _public_key: Ed25519PublicKey

    def __init__(
        self,
        private_key_pem: bytes | str | None = None,
        *,
        force_ephemeral: bool = False,
    ) -> None:
        """Initialize with an Ed25519 private key.

        Priority:
        1. ``private_key_pem`` parameter (bytes or str)
        2. ``PRAMANIX_SIGNING_KEY_PEM`` environment variable
        3. Ephemeral key — ONLY when ``force_ephemeral=True`` is explicitly set

        Raises:
            RuntimeError: If no key is provided and ``force_ephemeral=False``.
                          This prevents the distributed ephemeral-key trap: in a
                          multi-pod deployment each instance would generate a
                          different key, making the entire audit trail
                          unverifiable.  The error is raised at startup so the
                          misconfiguration is caught immediately, not when an
                          auditor discovers months of unsigned decisions.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
                load_pem_private_key,
            )
        except ImportError as e:  # pragma: no cover
            raise ImportError(  # pragma: no cover
                "The 'cryptography' package is required for Ed25519 signing. "
                "Install it: pip install 'pramanix[crypto]'"
            ) from e

        if private_key_pem is not None:
            raw = (
                private_key_pem.encode()
                if isinstance(private_key_pem, str)
                else private_key_pem
            )
            self._private_key: Ed25519PrivateKey = load_pem_private_key(raw, password=None)  # type: ignore[assignment]
            if not isinstance(self._private_key, Ed25519PrivateKey):
                raise ValueError(
                    "PEM key is not an Ed25519 private key. "
                    "Pramanix requires Ed25519 for deterministic signing."
                )
        else:
            env_pem = os.environ.get(_ENV_KEY_PEM, "")
            if env_pem:
                self._private_key = load_pem_private_key(env_pem.encode(), password=None)  # type: ignore[assignment]
                if not isinstance(self._private_key, Ed25519PrivateKey):
                    raise ValueError(
                        "PRAMANIX_SIGNING_KEY_PEM is not an Ed25519 private key."
                    )
            elif force_ephemeral:
                # Ephemeral key — development only, warn loudly
                self._private_key = Ed25519PrivateKey.generate()
                log.warning(
                    "PRAMANIX_SIGNING_KEY_PEM not set and force_ephemeral=True. "
                    "Using ephemeral Ed25519 key — signatures will NOT verify "
                    "across restarts or across pods. "
                    "Set PRAMANIX_SIGNING_KEY_PEM for production."
                )
            else:
                raise RuntimeError(
                    "No Ed25519 signing key configured. "
                    "PramanixSigner requires one of:\n"
                    "  1. private_key_pem argument\n"
                    "  2. PRAMANIX_SIGNING_KEY_PEM environment variable\n"
                    "  3. force_ephemeral=True (development/testing only)\n"
                    "In a multi-pod deployment, omitting a persistent key causes each "
                    "instance to generate a different ephemeral key, making the entire "
                    "audit trail unverifiable."
                )

        self._public_key: Ed25519PublicKey = self._private_key.public_key()

        # Cache PEM exports
        self._private_pem = self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        self._public_pem = self._public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = hashlib.sha256(self._public_pem).hexdigest()[:16]

    @classmethod
    def generate(cls) -> PramanixSigner:
        """Generate a new Ed25519 keypair.

        Use for key generation scripts only. Never call in application code.
        Store the private key PEM in a secrets manager immediately.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return cls(private_key_pem=pem)

    def sign(self, decision: Decision) -> str:
        """Sign decision.decision_hash with Ed25519.

        Returns base64url-encoded signature (86 chars, 64 raw bytes).
        Never raises — signing failures log ERROR and return empty string.
        """
        try:
            if not decision.decision_hash:
                log.error("Cannot sign Decision with empty decision_hash")
                return ""
            sig_bytes = self._private_key.sign(
                decision.decision_hash.encode("utf-8")
            )
            return _b64url(sig_bytes)
        except Exception as e:  # pragma: no cover
            log.error("Decision signing failed: %s", e)  # pragma: no cover
            return ""  # pragma: no cover

    def public_key_pem(self) -> bytes:
        """Return public key in PEM format. Safe to log and publish."""
        return self._public_pem

    def private_key_pem(self) -> bytes:
        """Return private key in PEM format. NEVER LOG THIS."""
        return self._private_pem

    def key_id(self) -> str:
        """Return 16-char hex key ID (SHA-256[:16] of public key PEM).

        Used to identify which public key was used to sign a Decision,
        enabling key rotation without breaking audit trail verification.
        """
        return self._key_id

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Verify a signature against a decision_hash using this signer's public key.

        Convenience method. For offline verification, use PramanixVerifier.
        """
        verifier = PramanixVerifier(public_key_pem=self._public_pem)
        return verifier.verify(decision_hash=decision_hash, signature=signature)


class PramanixVerifier:
    """Ed25519 signature verifier for Pramanix Decision proofs.

    This class is intentionally usable WITHOUT a PramanixSigner.
    An external auditor needs only the public key PEM and this class
    to verify the entire audit log. No private key, no SDK internals.

    Standalone usage (auditor script):
        from pramanix.crypto import PramanixVerifier

        with open("pramanix_public_key.pem", "rb") as f:
            public_key_pem = f.read()

        verifier = PramanixVerifier(public_key_pem=public_key_pem)

        with open("audit_log.jsonl") as f:
            for line in f:
                record = json.loads(line)
                ok = verifier.verify(
                    decision_hash=record["decision_hash"],
                    signature=record["signature"],
                )
                print("VALID" if ok else "INVALID", record["decision_id"])
    """

    def __init__(self, public_key_pem: bytes | str) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                load_pem_public_key,
            )
        except ImportError as e:  # pragma: no cover
            raise ImportError(  # pragma: no cover
                "The 'cryptography' package is required for verification. "
                "pip install cryptography"
            ) from e

        raw = (
            public_key_pem.encode()
            if isinstance(public_key_pem, str)
            else public_key_pem
        )
        loaded_pub = load_pem_public_key(raw)
        if not isinstance(loaded_pub, Ed25519PublicKey):
            raise ValueError(
                "PEM key is not an Ed25519 public key. "
                "Pramanix requires Ed25519 for decision verification."
            )
        self._public_key: Ed25519PublicKey = loaded_pub

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Verify that decision_hash was signed with the corresponding private key.

        Returns True if signature is valid. Returns False for any failure.
        Never raises.
        """
        try:
            sig_bytes = _b64url_decode(signature)
            self._public_key.verify(
                sig_bytes,
                decision_hash.encode("utf-8"),
            )
            return True
        except Exception:
            return False

    def verify_decision(self, decision: Decision) -> bool:
        """Verify a Decision object's signature against its hash.

        Recomputes decision_hash from decision fields and verifies
        that the stored signature matches.

        Returns True only if:
        - decision.signature is present
        - decision.decision_hash matches recomputed hash (tamper check)
        - Ed25519 signature is valid against decision_hash
        """
        try:
            if not decision.signature:
                return False
            if not decision.decision_hash:
                return False

            # Tamper check: recompute hash from fields
            recomputed = decision._compute_hash()
            if recomputed != decision.decision_hash:
                return False  # Fields were modified after signing

            return self.verify(
                decision_hash=decision.decision_hash,
                signature=decision.signature,
            )
        except Exception:
            return False
