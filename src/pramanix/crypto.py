# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    from pramanix.decision import Decision

log = logging.getLogger(__name__)

_ENV_KEY_PEM = "PRAMANIX_SIGNING_KEY_PEM"

# Module-level cache avoids re-registration ValueError on repeated imports and
# removes the need to reach into prometheus_client's private _names_to_collectors.
_signing_failure_counter: Any = None
_signing_failure_counter_lock = __import__("threading").Lock()


_COUNTER_DISABLED = object()  # sentinel: collision detected, counter permanently disabled


def _increment_signing_failure_counter() -> None:
    """Increment pramanix_signing_failure_total Prometheus counter (M-49).

    Silent no-op when prometheus_client is not installed or a metric-name
    collision is detected.  Logs a one-time warning on first collision.
    """
    global _signing_failure_counter
    try:
        from prometheus_client import Counter

        with _signing_failure_counter_lock:
            if _signing_failure_counter is None:
                try:
                    _signing_failure_counter = Counter(
                        "pramanix_signing_failure_total",
                        "Total decision signing failures",
                    )
                except ValueError as e:
                    # Counter already registered by external code.  Don't reach into
                    # prometheus_client's private internals — set a sentinel so we
                    # don't spam warnings on every subsequent signing failure.
                    log.warning(
                        "pramanix.crypto: Prometheus counter registration conflict: %s — "
                        "pramanix_signing_failure_total will not be counted "
                        "(ensure metric names are unique across your application).",
                        e,
                    )
                    _signing_failure_counter = _COUNTER_DISABLED
                    return
            if _signing_failure_counter is _COUNTER_DISABLED:
                return
        _signing_failure_counter.inc()  # type: ignore[union-attr]
    except ImportError:
        pass
    except Exception:
        pass


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
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
                load_pem_private_key,
            )
        except ImportError as e:
            raise ImportError(
                "The 'cryptography' package is required for Ed25519 signing. "
                "Install it: pip install 'pramanix[crypto]'"
            ) from e

        if private_key_pem is not None:
            raw = (
                private_key_pem.encode()
                if isinstance(private_key_pem, str)
                else private_key_pem
            )
            self._private_key: Ed25519PrivateKey = cast("Ed25519PrivateKey", load_pem_private_key(raw, password=None))
            if not isinstance(self._private_key, Ed25519PrivateKey):
                raise ValueError(
                    "PEM key is not an Ed25519 private key. "
                    "Pramanix requires Ed25519 for deterministic signing."
                )
        else:
            env_pem = os.environ.get(_ENV_KEY_PEM, "")
            if env_pem:
                self._private_key = cast("Ed25519PrivateKey", load_pem_private_key(env_pem.encode(), password=None))
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

        # Cache PEM exports.
        # SECURITY: _private_pem holds unencrypted PKCS8 PEM in process memory.
        # This is unavoidable for a software signer — the key must be in memory
        # to sign.  Callers MUST NOT log, serialize, or transmit this value.
        # Use private_key_pem() only for key backup/export to a secrets manager.
        # For HSM-backed deployments, replace PramanixSigner with an
        # HSM-resident signer that never exposes the private key bytes.
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

    @classmethod
    def from_provider(cls, provider: Any) -> PramanixSigner:
        """Create a :class:`PramanixSigner` from a :class:`~pramanix.key_provider.KeyProvider`.

        This is the recommended factory for institutional deployments using
        cloud KMS, HSM, or secret-vault key sources.

        Args:
            provider: Any object implementing the
                      :class:`~pramanix.key_provider.KeyProvider` protocol.

        Returns:
            A :class:`PramanixSigner` initialised with the private key PEM
            loaded from *provider*.

        Example::

            from pramanix.key_provider import FileKeyProvider
            signer = PramanixSigner.from_provider(
                FileKeyProvider("/run/secrets/pramanix-ed25519.pem")
            )
        """
        return cls(private_key_pem=provider.private_key_pem())

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
        except Exception as e:
            log.error("Decision signing failed: %s", e, exc_info=True)
            _increment_signing_failure_counter()
            return ""

    def public_key_pem(self) -> bytes:
        """Return public key in PEM format. Safe to log and publish."""
        return self._public_pem

    def private_key_pem(self) -> bytes:
        """Return private key in PEM format.

        WARNING: NEVER log, print, transmit, or store this value in plaintext.
        Use only to export the key to a secrets manager (AWS KMS, HashiCorp
        Vault, Kubernetes Secret, etc.) immediately after generation.
        """
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
        except ImportError as e:
            raise ImportError(
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


# ── RS256 / ES256 asymmetric JWT-compatible signers ────────────────────────────


class RS256Signer:
    """RSA-PKCS1v15-SHA256 (RS256) signer for Pramanix Decision objects.

    Drop-in replacement for :class:`PramanixSigner` when RSA signing is required.
    Signatures are base64url-encoded without padding (same format as JWT).

    Args:
        private_key_pem: PEM-encoded RSA private key.  Minimum 2048-bit key.
        force_ephemeral: Generate a 2048-bit key at startup for dev use only.

    Env var fallback: ``PRAMANIX_RS256_SIGNING_KEY_PEM`` (PEM string or path).
    """

    _ENV_KEY = "PRAMANIX_RS256_SIGNING_KEY_PEM"
    _ALGORITHM = "RS256"

    def __init__(
        self,
        private_key_pem: bytes | str | None = None,
        *,
        force_ephemeral: bool = False,
    ) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
                load_pem_private_key,
            )
        except ImportError as exc:
            raise ImportError(
                "The 'cryptography' package is required for RS256 signing. "
                "Install it: pip install 'pramanix[crypto]'"
            ) from exc

        raw: bytes | None = None
        if private_key_pem is not None:
            raw = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
        else:
            env_pem = os.environ.get(self._ENV_KEY, "")
            if env_pem:
                raw = env_pem.encode()
            elif force_ephemeral:
                _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                log.warning(
                    "%s not set and force_ephemeral=True. "
                    "Using ephemeral RSA-2048 key — NOT suitable for production.",
                    self._ENV_KEY,
                )
                raw = _key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            else:
                raise RuntimeError(
                    "No RS256 signing key configured. Provide private_key_pem, "
                    f"set {self._ENV_KEY}, or use force_ephemeral=True."
                )

        _loaded = load_pem_private_key(raw, password=None)  # type: ignore[arg-type]
        if not isinstance(_loaded, RSAPrivateKey):
            raise ValueError("PEM key is not an RSA private key.")
        if _loaded.key_size < 2048:
            raise ValueError(
                f"RSA key size {_loaded.key_size} bits is too small. "
                "Minimum 2048 bits required."
            )
        self._private_key: RSAPrivateKey = _loaded
        self._public_key_obj = self._private_key.public_key()
        self._public_pem = self._public_key_obj.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = hashlib.sha256(self._public_pem).hexdigest()[:16]

    @classmethod
    def generate(cls, key_size: int = 2048) -> "RS256Signer":
        """Generate a new RSA key pair for development use."""
        if key_size < 2048:
            raise ValueError("key_size must be at least 2048 bits.")
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return cls(private_key_pem=pem)

    def sign(self, decision: "Decision") -> str:
        """Sign ``decision.decision_hash`` with RSA-PKCS1v15-SHA256.

        Returns a base64url-encoded signature.  Never raises; failures log ERROR.
        """
        try:
            if not decision.decision_hash:
                log.error("Cannot sign Decision with empty decision_hash")
                return ""
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            sig_bytes = self._private_key.sign(
                decision.decision_hash.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return _b64url(sig_bytes)
        except Exception as exc:
            log.error("RS256 signing failed: %s", exc, exc_info=True)
            _increment_signing_failure_counter()
            return ""

    def public_key_pem(self) -> bytes:
        """Return RSA public key in PEM (SubjectPublicKeyInfo) format."""
        return self._public_pem

    def key_id(self) -> str:
        """Return 16-char hex key ID derived from SHA-256 of public key PEM."""
        return self._key_id

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Verify a base64url-encoded RS256 signature."""
        return RS256Verifier(public_key_pem=self._public_pem).verify(
            decision_hash=decision_hash, signature=signature
        )


class RS256Verifier:
    """RSA-PKCS1v15-SHA256 signature verifier.

    Args:
        public_key_pem: PEM-encoded RSA public key.
    """

    def __init__(self, public_key_pem: bytes | str) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
        except ImportError as exc:
            raise ImportError(
                "The 'cryptography' package is required for RS256 verification."
            ) from exc

        raw = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        loaded = load_pem_public_key(raw)
        if not isinstance(loaded, RSAPublicKey):
            raise ValueError("PEM key is not an RSA public key.")
        self._public_key: RSAPublicKey = loaded

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Return ``True`` if *signature* is a valid RS256 signature over *decision_hash*."""
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            sig_bytes = _b64url_decode(signature)
            self._public_key.verify(
                sig_bytes,
                decision_hash.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def verify_decision(self, decision: "Decision") -> bool:
        """Verify a Decision object's RS256 signature."""
        try:
            if not decision.signature or not decision.decision_hash:
                return False
            recomputed = decision._compute_hash()
            if recomputed != decision.decision_hash:
                return False
            return self.verify(
                decision_hash=decision.decision_hash,
                signature=decision.signature,
            )
        except Exception:
            return False


class ES256Signer:
    """ECDSA-P256-SHA256 (ES256) signer for Pramanix Decision objects.

    Uses NIST P-256 (secp256r1) with RFC 6979 deterministic k-generation.
    Smaller keys and faster operations than RS256 with equivalent 128-bit security.
    Preferred over RS256 for new deployments.

    Args:
        private_key_pem: PEM-encoded EC private key on P-256 curve.
        force_ephemeral: Generate a P-256 key at startup for dev use only.

    Env var fallback: ``PRAMANIX_ES256_SIGNING_KEY_PEM``.
    """

    _ENV_KEY = "PRAMANIX_ES256_SIGNING_KEY_PEM"
    _ALGORITHM = "ES256"

    def __init__(
        self,
        private_key_pem: bytes | str | None = None,
        *,
        force_ephemeral: bool = False,
    ) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                SECP256R1,
                EllipticCurvePrivateKey,
                generate_private_key,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
                load_pem_private_key,
            )
        except ImportError as exc:
            raise ImportError(
                "The 'cryptography' package is required for ES256 signing. "
                "Install it: pip install 'pramanix[crypto]'"
            ) from exc

        raw: bytes | None = None
        if private_key_pem is not None:
            raw = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
        else:
            env_pem = os.environ.get(self._ENV_KEY, "")
            if env_pem:
                raw = env_pem.encode()
            elif force_ephemeral:
                _key = generate_private_key(SECP256R1())
                log.warning(
                    "%s not set and force_ephemeral=True. "
                    "Using ephemeral ES256 P-256 key — NOT suitable for production.",
                    self._ENV_KEY,
                )
                raw = _key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            else:
                raise RuntimeError(
                    "No ES256 signing key configured. Provide private_key_pem, "
                    f"set {self._ENV_KEY}, or use force_ephemeral=True."
                )

        _loaded = load_pem_private_key(raw, password=None)  # type: ignore[arg-type]
        if not isinstance(_loaded, EllipticCurvePrivateKey):
            raise ValueError("PEM key is not an EC private key.")
        _curve = _loaded.curve
        if not isinstance(_curve, SECP256R1):
            raise ValueError(
                f"ES256Signer requires P-256 (secp256r1), got {type(_curve).__name__}."
            )
        self._private_key: EllipticCurvePrivateKey = _loaded
        self._public_key_obj = self._private_key.public_key()
        self._public_pem = self._public_key_obj.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = hashlib.sha256(self._public_pem).hexdigest()[:16]

    @classmethod
    def generate(cls) -> "ES256Signer":
        """Generate a new P-256 key pair for development use."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            generate_private_key,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        key = generate_private_key(SECP256R1())
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return cls(private_key_pem=pem)

    def sign(self, decision: "Decision") -> str:
        """Sign ``decision.decision_hash`` with ECDSA-P256-SHA256.

        Returns a base64url-encoded DER-encoded signature.  Never raises; failures log ERROR.
        """
        try:
            if not decision.decision_hash:
                log.error("Cannot sign Decision with empty decision_hash")
                return ""
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

            sig_bytes = self._private_key.sign(
                decision.decision_hash.encode("utf-8"),
                ECDSA(hashes.SHA256()),
            )
            return _b64url(sig_bytes)
        except Exception as exc:
            log.error("ES256 signing failed: %s", exc, exc_info=True)
            _increment_signing_failure_counter()
            return ""

    def public_key_pem(self) -> bytes:
        """Return EC public key in PEM (SubjectPublicKeyInfo) format."""
        return self._public_pem

    def key_id(self) -> str:
        """Return 16-char hex key ID derived from SHA-256 of public key PEM."""
        return self._key_id

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Verify a base64url-encoded ES256 signature."""
        return ES256Verifier(public_key_pem=self._public_pem).verify(
            decision_hash=decision_hash, signature=signature
        )


class ES256Verifier:
    """ECDSA-P256-SHA256 signature verifier.

    Args:
        public_key_pem: PEM-encoded P-256 public key.
    """

    def __init__(self, public_key_pem: bytes | str) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                SECP256R1,
                EllipticCurvePublicKey,
            )
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
        except ImportError as exc:
            raise ImportError(
                "The 'cryptography' package is required for ES256 verification."
            ) from exc

        raw = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        loaded = load_pem_public_key(raw)
        if not isinstance(loaded, EllipticCurvePublicKey):
            raise ValueError("PEM key is not an EC public key.")
        if not isinstance(loaded.curve, SECP256R1):
            raise ValueError(
                f"ES256Verifier requires P-256, got {type(loaded.curve).__name__}."
            )
        self._public_key: EllipticCurvePublicKey = loaded

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Return ``True`` if *signature* is a valid ES256 signature over *decision_hash*."""
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

            sig_bytes = _b64url_decode(signature)
            self._public_key.verify(
                sig_bytes,
                decision_hash.encode("utf-8"),
                ECDSA(hashes.SHA256()),
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def verify_decision(self, decision: "Decision") -> bool:
        """Verify a Decision object's ES256 signature."""
        try:
            if not decision.signature or not decision.decision_hash:
                return False
            recomputed = decision._compute_hash()
            if recomputed != decision.decision_hash:
                return False
            return self.verify(
                decision_hash=decision.decision_hash,
                signature=decision.signature,
            )
        except Exception:
            return False
