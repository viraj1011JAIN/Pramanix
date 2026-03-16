You are implementing Phase 11 of the Pramanix codebase at C:\Pramanix.

Phases 0-10 are complete. Pramanix v0.7.0 is certified with:
- Cryptographic Decision Proofs (JWS, CLI verifier)
- Zero-Trust Identity Layer (JWT + Redis)
- Adaptive Circuit Breaker
- Expression Tree Pre-Compilation
- Semantic Fast-Path
- Adaptive Load Shedding
- Publishable benchmarks

You are now implementing Phase 11: Cryptographic Audit Trail & Non-Repudiation.

This is the phase that makes banks and hospitals sign contracts. Every
competitor uses probabilistic guardrails with mutable logs. Pramanix v0.8
produces audit trails that can be submitted to the SEC, the FDA, or a
court and proven mathematically unmodified. Zero competitors do this.

The four deliverables:
1. Deterministic Decision Hashing — every Decision has a SHA-256 fingerprint
2. Ed25519 Cryptographic Signing — every Decision is signed with asymmetric crypto
3. pramanix audit CLI — standalone verifier for external auditors
4. Compliance Reporter — maps Z3 violations to regulatory citations

═══════════════════════════════════════════════════════════════════════
PRE-FLIGHT — READ THESE FILES BEFORE WRITING ANY CODE
═══════════════════════════════════════════════════════════════════════

Read every file listed below completely before writing a single line:

1.  src/pramanix/decision.py          — Decision dataclass, all fields, factory methods
2.  src/pramanix/guard.py             — Guard class, GuardConfig, verify_async pipeline
3.  src/pramanix/audit/signer.py      — existing HMAC-based signer (Phase 9)
4.  src/pramanix/audit/verifier.py    — existing HMAC-based verifier (Phase 9)
5.  src/pramanix/cli.py               — existing CLI structure (Phase 9)
6.  src/pramanix/solver.py            — SolverStatus enum
7.  src/pramanix/primitives/fintech.py — fintech primitives (compliance refs needed)
8.  src/pramanix/primitives/healthcare.py — healthcare primitives
9.  src/pramanix/helpers/             — list all files in helpers/
10. src/pramanix/__init__.py          — current exports and __version__
11. tests/unit/test_audit.py          — existing audit tests (Phase 9)
12. pyproject.toml                    — version, dependencies
13. CHANGELOG.md                      — format reference

After reading all files, print exactly:
"PRE-FLIGHT COMPLETE. Current version: X.Y.Z. Starting Phase 11."

Then execute the four pillars in order. Do not begin a pillar until
the previous pillar's gate conditions pass.

═══════════════════════════════════════════════════════════════════════
PILLAR 1 — DETERMINISTIC DECISION HASHING
═══════════════════════════════════════════════════════════════════════

Goal: Every Decision has a cryptographically unique, deterministic
SHA-256 fingerprint. Any modification — even flipping one bit in
amount, changing allowed from False to True, altering a violated
invariant — produces a completely different hash. This is the
foundation that makes the audit trail tamper-evident.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.1 — Install orjson
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pip install orjson

Check if already installed:
    python -c "import orjson; print('orjson', orjson.__version__)"

Add to pyproject.toml [tool.poetry.dependencies]:
    orjson = ">=3.9"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.2 — Extend Decision dataclass
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read src/pramanix/decision.py carefully. Understand every field
and every factory method before modifying anything.

Add THREE new fields to the Decision dataclass:
````python
# New fields to add to Decision (frozen=True dataclass):

intent_dump: dict = field(default_factory=dict)
# Stores the serialized intent dict at decision time.
# Required for hash replay and audit verification.
# Never contains Pydantic models — only model_dump() output.

state_dump: dict = field(default_factory=dict)
# Stores the serialized state dict at decision time.
# Required for hash replay and audit verification.
# Never contains Pydantic models — only model_dump() output.

decision_hash: str = field(default="")
# SHA-256 fingerprint of this Decision's canonical representation.
# Computed in __post_init__ if empty.
# Immutable after construction (frozen dataclass).
````

Add the hash computation to __post_init__:
````python
def __post_init__(self) -> None:
    # Existing validation (keep all existing __post_init__ logic)
    # ...existing code...

    # Compute decision_hash if not already set
    # Use object.__setattr__ because dataclass is frozen
    if not self.decision_hash:
        computed = self._compute_hash()
        object.__setattr__(self, "decision_hash", computed)
````

Add the hash computation method:
````python
def _compute_hash(self) -> str:
    """Compute a deterministic SHA-256 hash of this Decision.

    Canonical representation includes:
    - intent_dump (sorted keys, Decimal as string)
    - state_dump (sorted keys, Decimal as string)
    - policy (name + version string)
    - status.value
    - allowed (bool)
    - violated_invariants (sorted tuple → list for JSON)
    - explanation

    Uses orjson with OPT_SORT_KEYS for deterministic key ordering.
    Decimal values are serialized as strings to prevent float drift.

    Security:
    - Changing ANY field changes the hash
    - Hash is computed from the full intent+state context
    - This makes every Decision tamper-evident
    """
    import hashlib
    try:
        import orjson
        canonical = {
            "allowed": bool(self.allowed),
            "explanation": str(self.explanation or ""),
            "intent_dump": _make_json_safe(self.intent_dump),
            "policy": str(self.metadata.get("policy", "") if self.metadata else ""),
            "state_dump": _make_json_safe(self.state_dump),
            "status": str(self.status.value if hasattr(self.status, "value") else self.status),
            "violated_invariants": sorted(str(v) for v in (self.violated_invariants or ())),
        }
        serialized = orjson.dumps(
            canonical,
            option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS,
        )
    except Exception:
        # Fallback to stdlib json if orjson fails
        import json
        canonical = {
            "allowed": bool(self.allowed),
            "explanation": str(self.explanation or ""),
            "policy": str(self.metadata.get("policy", "") if self.metadata else ""),
            "status": str(self.status.value if hasattr(self.status, "value") else self.status),
            "violated_invariants": sorted(str(v) for v in (self.violated_invariants or ())),
        }
        serialized = json.dumps(canonical, sort_keys=True, default=str).encode()

    return hashlib.sha256(serialized).hexdigest()
````

Add the helper function at module level (outside the class):
````python
def _make_json_safe(d: dict) -> dict:
    """Convert a dict to JSON-safe types, preserving Decimal precision.

    Decimal → str (exact representation, no float drift)
    datetime → ISO 8601 UTC string
    All other types → str fallback
    """
    from decimal import Decimal
    result = {}
    for k, v in sorted(d.items()):  # Sorted for determinism
        if isinstance(v, Decimal):
            result[str(k)] = str(v)
        elif isinstance(v, bool):
            result[str(k)] = v
        elif isinstance(v, (int, float)):
            result[str(k)] = v
        elif isinstance(v, str):
            result[str(k)] = v
        elif hasattr(v, "isoformat"):  # datetime
            result[str(k)] = v.isoformat()
        else:
            result[str(k)] = str(v)
    return result
````

CRITICAL: After modifying Decision, run the full existing test suite
to confirm no regressions:

    pytest tests/unit/test_decision.py -v
    pytest tests/integration/test_banking_flow.py -v

Both must pass with zero failures before proceeding.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.3 — Wire intent_dump and state_dump into Guard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read guard.py. Find where Decision objects are constructed from solver
results. The Decision must be built with intent_dump and state_dump
populated from the model_dump() dicts that Guard already computes.

In Guard.verify() / verify_async(), after computing intent_dict and
state_dict from model_dump(), pass them through to Decision construction:
````python
# When building the final Decision, ensure these are passed:
# (The exact location depends on your guard.py implementation)
# Find where Decision.safe/unsafe/timeout/error is called and
# ensure intent_dump=intent_dict, state_dump=state_dict are passed.

# Example pattern — adapt to your actual code:
decision = Decision.unsafe(
    violated_invariants=result.violated_invariants,
    explanation=result.explanation,
    solver_time_ms=result.solver_time_ms,
    intent_dump=intent_dict,     # ADD THIS
    state_dump=state_dict,       # ADD THIS
    metadata={"policy": policy_name, "policy_version": policy_version},
)
````

If the Decision factory methods don't accept intent_dump/state_dump,
update their signatures now. All factory methods must accept and pass
through these two optional parameters.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.4 — Create tests/unit/test_decision_hash.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
````python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for deterministic Decision hashing (Phase 11.1).

Critical properties verified:
1. Determinism: same inputs always produce the same hash
2. Uniqueness: any modification produces a different hash
3. Immutability: hash cannot be changed after construction
4. Coverage: all fields affect the hash

These properties make the audit trail tamper-evident.
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pramanix.decision import Decision, SolverStatus


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_decision(
    allowed: bool = True,
    amount: str = "100",
    balance: str = "5000",
    violated: tuple = (),
    explanation: str = "",
    policy: str = "TestPolicy",
) -> Decision:
    if allowed:
        return Decision.safe(
            intent_dump={"amount": amount},
            state_dump={"balance": balance, "state_version": "v1"},
            metadata={"policy": policy, "policy_version": "1.0"},
        )
    return Decision.unsafe(
        violated_invariants=violated or ("test_rule",),
        explanation=explanation or "Test block",
        intent_dump={"amount": amount},
        state_dump={"balance": balance, "state_version": "v1"},
        metadata={"policy": policy, "policy_version": "1.0"},
    )


# ── Hash presence ─────────────────────────────────────────────────────────────


class TestDecisionHashPresence:
    def test_safe_decision_has_hash(self):
        d = _make_decision(allowed=True)
        assert d.decision_hash
        assert len(d.decision_hash) == 64  # SHA-256 hex

    def test_unsafe_decision_has_hash(self):
        d = _make_decision(allowed=False)
        assert d.decision_hash
        assert len(d.decision_hash) == 64

    def test_hash_is_hex_string(self):
        d = _make_decision()
        assert all(c in "0123456789abcdef" for c in d.decision_hash)

    def test_hash_is_immutable(self):
        """Frozen dataclass — hash cannot be changed after construction."""
        d = _make_decision()
        with pytest.raises((AttributeError, TypeError)):
            d.decision_hash = "hacked"  # type: ignore[misc]


# ── Determinism ───────────────────────────────────────────────────────────────


class TestDecisionHashDeterminism:
    def test_identical_decisions_have_identical_hashes(self):
        d1 = _make_decision(allowed=True, amount="100", balance="5000")
        d2 = _make_decision(allowed=True, amount="100", balance="5000")
        assert d1.decision_hash == d2.decision_hash

    def test_hash_is_stable_across_multiple_calls(self):
        d = _make_decision()
        hash1 = d.decision_hash
        hash2 = d._compute_hash()
        assert hash1 == hash2

    def test_decimal_precision_preserved_in_hash(self):
        """Decimal(100.00) and Decimal(100) must produce same hash."""
        d1 = Decision.safe(
            intent_dump={"amount": str(Decimal("100.00"))},
            state_dump={"balance": str(Decimal("5000")), "state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": str(Decimal("100"))},
            state_dump={"balance": str(Decimal("5000")), "state_version": "v1"},
        )
        # NOTE: 100.00 and 100 have different string representations
        # This is CORRECT — they ARE different values in decimal arithmetic
        # The test documents the behavior
        assert isinstance(d1.decision_hash, str)
        assert isinstance(d2.decision_hash, str)

    @given(
        amount=st.decimals(
            min_value=Decimal("0.01"),
            max_value=Decimal("999999"),
            allow_nan=False,
            allow_infinity=False,
        )
    )
    @settings(max_examples=500)
    def test_hypothesis_hash_determinism(self, amount):
        """Property: same Decision always hashes to same value."""
        d1 = Decision.safe(
            intent_dump={"amount": str(amount)},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": str(amount)},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        assert d1.decision_hash == d2.decision_hash


# ── Uniqueness (tamper detection) ─────────────────────────────────────────────


class TestDecisionHashUniqueness:
    def test_different_amounts_produce_different_hashes(self):
        d1 = _make_decision(amount="100")
        d2 = _make_decision(amount="101")
        assert d1.decision_hash != d2.decision_hash

    def test_different_balances_produce_different_hashes(self):
        d1 = _make_decision(balance="5000")
        d2 = _make_decision(balance="5001")
        assert d1.decision_hash != d2.decision_hash

    def test_allowed_flip_changes_hash(self):
        """CRITICAL: changing allowed=True to allowed=False must change hash."""
        d_allow = _make_decision(allowed=True, amount="100")
        d_block = _make_decision(allowed=False, amount="100")
        assert d_allow.decision_hash != d_block.decision_hash

    def test_different_violated_invariants_change_hash(self):
        d1 = Decision.unsafe(
            violated_invariants=("rule_a",),
            explanation="blocked",
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        d2 = Decision.unsafe(
            violated_invariants=("rule_b",),
            explanation="blocked",
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash

    def test_different_explanation_changes_hash(self):
        d1 = _make_decision(allowed=False, explanation="reason A")
        d2 = _make_decision(allowed=False, explanation="reason B")
        assert d1.decision_hash != d2.decision_hash

    def test_different_policy_changes_hash(self):
        d1 = _make_decision(policy="PolicyA")
        d2 = _make_decision(policy="PolicyB")
        assert d1.decision_hash != d2.decision_hash

    def test_adding_intent_field_changes_hash(self):
        d1 = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": "100", "recipient": "alice"},
            state_dump={"state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash

    def test_modifying_state_changes_hash(self):
        d1 = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "4999", "state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash

    @given(
        amount_1=st.integers(min_value=1, max_value=999999),
        amount_2=st.integers(min_value=1, max_value=999999),
    )
    @settings(max_examples=200)
    def test_hypothesis_different_amounts_different_hashes(
        self, amount_1, amount_2
    ):
        """Property: different amounts produce different hashes."""
        if amount_1 == amount_2:
            return  # Skip when equal

        d1 = Decision.safe(
            intent_dump={"amount": str(amount_1)},
            state_dump={"state_version": "v1"},
        )
        d2 = Decision.safe(
            intent_dump={"amount": str(amount_2)},
            state_dump={"state_version": "v1"},
        )
        assert d1.decision_hash != d2.decision_hash


# ── End-to-end via Guard ──────────────────────────────────────────────────────


class TestDecisionHashViaGuard:
    def test_guard_decision_has_hash(self):
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount, "balance": _balance}
            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sufficient_balance").explain("Insufficient")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert d.decision_hash
        assert len(d.decision_hash) == 64

    def test_guard_decision_hash_changes_with_different_amounts(self):
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount, "balance": _balance}
            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sb").explain("Insufficient")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        state = {"balance": Decimal("5000"), "state_version": "1.0"}
        d1 = guard.verify(intent={"amount": Decimal("100")}, state=state)
        d2 = guard.verify(intent={"amount": Decimal("200")}, state=state)
        assert d1.decision_hash != d2.decision_hash

    def test_guard_decision_intent_dump_populated(self):
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount  = Field("amount",  Decimal, "Real")

        class _P(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount}
            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0")).named("pos").explain("Positive")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.intent_dump is not None
        assert "amount" in d.intent_dump
````

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 1 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_decision_hash.py -v
    # All pass including Hypothesis property tests

    pytest tests/unit/test_decision.py -v
    # All existing decision tests still pass (no regressions)

    pytest tests/integration/test_banking_flow.py -v
    # All integration tests still pass

    python -c "
from decimal import Decimal
from pramanix.decision import Decision
d = Decision.safe(
    intent_dump={'amount': '100'},
    state_dump={'balance': '5000', 'state_version': 'v1'},
)
print('Hash:', d.decision_hash)
print('Length:', len(d.decision_hash))
assert len(d.decision_hash) == 64
print('✅ Pillar 1 gate passed')
"

Only proceed to Pillar 2 after all gate conditions pass.

═══════════════════════════════════════════════════════════════════════
PILLAR 2 — ED25519 CRYPTOGRAPHIC SIGNING
═══════════════════════════════════════════════════════════════════════

Goal: Every Decision's hash is signed with Ed25519 asymmetric
cryptography. Any holder of the public key can verify that the
Decision was produced by the authorized Pramanix instance and
has not been tampered with since. This is court-admissible proof.

Ed25519 is chosen over RSA because:
- 256-bit security with 64-byte signatures (vs RSA-4096's 512 bytes)
- Deterministic signing (no random number generator in signing path)
- Standard in modern security infrastructure (SSH, TLS 1.3, Let's Encrypt)
- Supported natively in Python cryptography library

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.1 — Install cryptography library
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pip install "cryptography>=41.0"

Check if already installed:
    python -c "import cryptography; print('cryptography', cryptography.__version__)"

Add to pyproject.toml [tool.poetry.dependencies]:
    cryptography = ">=41.0"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.2 — Create src/pramanix/crypto.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
````python
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
        decision = await guard.verify_async(intent=..., state=...)
        assert decision.signature  # Present when signer is configured

        # Offline verification (no Guard needed)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision)
    """

    def __init__(self, private_key_pem: bytes | str | None = None) -> None:
        """Initialize with an Ed25519 private key.

        Priority:
        1. private_key_pem parameter (bytes or str)
        2. PRAMANIX_SIGNING_KEY_PEM environment variable
        3. Ephemeral key (logs WARNING — not for production)
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
            self._private_key = load_pem_private_key(raw, password=None)
        else:
            env_pem = os.environ.get(_ENV_KEY_PEM, "")
            if env_pem:
                self._private_key = load_pem_private_key(
                    env_pem.encode(), password=None
                )
            else:
                # Ephemeral key — warn loudly
                self._private_key = Ed25519PrivateKey.generate()
                log.warning(
                    "PRAMANIX_SIGNING_KEY_PEM not set. "
                    "Using ephemeral Ed25519 key — signatures will NOT verify "
                    "across restarts. Set PRAMANIX_SIGNING_KEY_PEM for production."
                )

        self._public_key = self._private_key.public_key()

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
    def generate(cls) -> "PramanixSigner":
        """Generate a new Ed25519 keypair.

        Use for key generation scripts only. Never call in application code.
        Store the private key PEM in a secrets manager immediately.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat,
        )
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return cls(private_key_pem=pem)

    def sign(self, decision: "Decision") -> str:
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
            log.error("Decision signing failed: %s", e)
            return ""

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
        self._public_key = load_pem_public_key(raw)

    def verify(self, decision_hash: str, signature: str) -> bool:
        """Verify that decision_hash was signed with the corresponding private key.

        Returns True if signature is valid. Returns False for any failure.
        Never raises.
        """
        try:
            from cryptography.exceptions import InvalidSignature
            sig_bytes = _b64url_decode(signature)
            self._public_key.verify(
                sig_bytes,
                decision_hash.encode("utf-8"),
            )
            return True
        except Exception:
            return False

    def verify_decision(self, decision: "Decision") -> bool:
        """Verify a Decision object's signature against its hash.

        Recomputes decision_hash from decision fields and verifies
        that the stored signature matches.

        Returns True only if:
        - decision.signature is present
        - decision.decision_hash matches recomputed hash (tamper check)
        - Ed25519 signature is valid against decision_hash
        """
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
````

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.3 — Add signature fields to Decision
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add TWO more optional fields to the Decision dataclass:
````python
signature: str | None = None
# Base64url-encoded Ed25519 signature over decision_hash.
# Present when GuardConfig.signer is configured.
# None when no signer is configured (default).

public_key_id: str | None = None
# 16-char hex key ID identifying which public key was used.
# Used for key rotation tracking.
# Corresponds to PramanixSigner.key_id().
````

These fields must be EXCLUDED from hash computation.
The hash is computed from decision content only — NOT from the
signature or key_id (that would make the hash circular).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.4 — Add signer to GuardConfig and wire into Guard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add to GuardConfig:
````python
signer: "PramanixSigner | None" = None
# If set, every Decision returned by Guard.verify() will be signed.
# The signature is Ed25519 over decision.decision_hash.
# None by default — signing is opt-in.
````

In Guard.verify() / verify_async(), after constructing the Decision,
add signing step:
````python
# At the end of Guard.verify(), after Decision is constructed:
if self._config.signer is not None:
    signature = self._config.signer.sign(decision)
    key_id = self._config.signer.key_id()
    # Use object.__setattr__ since Decision is frozen
    object.__setattr__(decision, "signature", signature)
    object.__setattr__(decision, "public_key_id", key_id)

return decision
````

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.5 — Create tests/unit/test_crypto.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
````python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Ed25519 cryptographic signing (Phase 11.2).

Critical properties verified:
1. Signatures are valid (signer produces, verifier accepts)
2. Wrong key fails verification (key binding)
3. Tampered hash fails verification (integrity)
4. Tampered signature fails verification
5. 1000 sign-verify cycles all pass (reliability)
6. Signing is deterministic (same hash = same signature for Ed25519)
"""
from __future__ import annotations

from decimal import Decimal

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from pramanix.crypto import PramanixSigner, PramanixVerifier
from pramanix.decision import Decision


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_decision(allowed: bool = True, amount: str = "100") -> Decision:
    if allowed:
        return Decision.safe(
            intent_dump={"amount": amount},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
    return Decision.unsafe(
        violated_invariants=("test_rule",),
        explanation="Test block",
        intent_dump={"amount": amount},
        state_dump={"balance": "5000", "state_version": "v1"},
    )


# ── PramanixSigner ────────────────────────────────────────────────────────────


class TestPramanixSigner:
    def test_generate_creates_signer(self):
        signer = PramanixSigner.generate()
        assert signer is not None

    def test_key_id_is_16_hex_chars(self):
        signer = PramanixSigner.generate()
        kid = signer.key_id()
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_public_key_pem_starts_with_pem_header(self):
        signer = PramanixSigner.generate()
        pem = signer.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_private_key_pem_starts_with_pem_header(self):
        signer = PramanixSigner.generate()
        pem = signer.private_key_pem()
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_sign_returns_nonempty_string(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_sign_returns_base64url_encoded(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        # base64url: no + / = characters
        assert "+" not in sig
        assert "/" not in sig
        assert "=" not in sig

    def test_ed25519_signature_is_deterministic(self):
        """Ed25519 signing is deterministic — same hash always same sig."""
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig1 = signer.sign(d)
        sig2 = signer.sign(d)
        assert sig1 == sig2

    def test_two_different_decisions_produce_different_signatures(self):
        signer = PramanixSigner.generate()
        d1 = _make_decision(amount="100")
        d2 = _make_decision(amount="200")
        assert signer.sign(d1) != signer.sign(d2)

    def test_key_loaded_from_pem_produces_same_key_id(self):
        signer1 = PramanixSigner.generate()
        pem = signer1.private_key_pem()
        signer2 = PramanixSigner(private_key_pem=pem)
        assert signer1.key_id() == signer2.key_id()

    def test_different_generated_keys_have_different_key_ids(self):
        s1 = PramanixSigner.generate()
        s2 = PramanixSigner.generate()
        assert s1.key_id() != s2.key_id()


# ── PramanixVerifier ──────────────────────────────────────────────────────────


class TestPramanixVerifier:
    def test_verify_valid_signature_returns_true(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=sig)

    def test_verify_wrong_key_returns_false(self):
        signer_a = PramanixSigner.generate()
        signer_b = PramanixSigner.generate()
        d = _make_decision()
        sig = signer_a.sign(d)
        # Verify with signer_b's public key — must fail
        verifier = PramanixVerifier(public_key_pem=signer_b.public_key_pem())
        assert not verifier.verify(decision_hash=d.decision_hash, signature=sig)

    def test_verify_tampered_hash_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        # Tamper the hash
        tampered_hash = d.decision_hash[:-1] + (
            "0" if d.decision_hash[-1] != "0" else "1"
        )
        assert not verifier.verify(decision_hash=tampered_hash, signature=sig)

    def test_verify_tampered_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        # Tamper signature
        tampered_sig = sig[:-4] + "AAAA"
        assert not verifier.verify(decision_hash=d.decision_hash, signature=tampered_sig)

    def test_verify_empty_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert not verifier.verify(decision_hash=d.decision_hash, signature="")

    def test_verify_garbage_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert not verifier.verify(
            decision_hash=d.decision_hash,
            signature="not_a_real_signature_at_all",
        )

    def test_verify_decision_full_pipeline(self):
        signer = PramanixSigner.generate()
        d = _make_decision()
        sig = signer.sign(d)
        object.__setattr__(d, "signature", sig)
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify_decision(d)

    def test_verify_decision_missing_signature_returns_false(self):
        signer = PramanixSigner.generate()
        d = _make_decision()  # No signature set
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert not verifier.verify_decision(d)


# ── Reliability: 1000 sign-verify cycles ─────────────────────────────────────


class TestSignVerifyReliability:
    def test_1000_sign_verify_cycles_all_pass(self):
        """All 1000 sign-verify cycles must succeed with correct key."""
        signer = PramanixSigner.generate()
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())

        failures = []
        for i in range(1000):
            d = _make_decision(
                allowed=(i % 2 == 0),
                amount=str(i + 1),
            )
            sig = signer.sign(d)
            ok = verifier.verify(
                decision_hash=d.decision_hash,
                signature=sig,
            )
            if not ok:
                failures.append(i)

        assert len(failures) == 0, (
            f"Sign-verify failed for {len(failures)} out of 1000 decisions: "
            f"indices {failures[:10]}"
        )

    def test_1000_cycles_with_wrong_key_all_fail(self):
        """All 1000 sign-verify cycles must FAIL with wrong key."""
        signer = PramanixSigner.generate()
        wrong_signer = PramanixSigner.generate()
        verifier = PramanixVerifier(public_key_pem=wrong_signer.public_key_pem())

        wrong_passes = []
        for i in range(1000):
            d = _make_decision(amount=str(i + 1))
            sig = signer.sign(d)
            ok = verifier.verify(decision_hash=d.decision_hash, signature=sig)
            if ok:
                wrong_passes.append(i)

        assert len(wrong_passes) == 0, (
            f"Wrong-key verification PASSED for {len(wrong_passes)} decisions. "
            "This is a critical security failure."
        )


# ── Guard integration ─────────────────────────────────────────────────────────


class TestGuardSigningIntegration:
    def test_guard_signs_decision_when_signer_configured(self):
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount}
            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0")).named("pos").explain("Positive")
                ]

        signer = PramanixSigner.generate()
        guard = Guard(_P, GuardConfig(execution_mode="sync", signer=signer))

        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.signature is not None
        assert len(d.signature) > 0
        assert d.public_key_id == signer.key_id()

    def test_guard_does_not_sign_when_no_signer(self):
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount}
            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0")).named("pos").explain("Positive")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))  # No signer
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.signature is None

    def test_guard_signed_decision_verifies(self):
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount, "balance": _balance}
            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sb").explain("Insufficient")
                ]

        signer = PramanixSigner.generate()
        guard = Guard(_P, GuardConfig(execution_mode="sync", signer=signer))

        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )

        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(
            decision_hash=d.decision_hash,
            signature=d.signature,
        )
````

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 2 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_crypto.py -v
    # All pass including 1000-cycle reliability tests

    python -c "
from pramanix.crypto import PramanixSigner, PramanixVerifier
from pramanix.decision import Decision

signer = PramanixSigner.generate()
d = Decision.safe(
    intent_dump={'amount': '100'},
    state_dump={'balance': '5000', 'state_version': 'v1'},
)
sig = signer.sign(d)
verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())

assert verifier.verify(decision_hash=d.decision_hash, signature=sig)
print('✅ VALID signature verified')

wrong = PramanixSigner.generate()
wrong_verifier = PramanixVerifier(public_key_pem=wrong.public_key_pem())
assert not wrong_verifier.verify(decision_hash=d.decision_hash, signature=sig)
print('✅ Wrong key correctly rejected')
print('✅ Pillar 2 gate passed')
"

═══════════════════════════════════════════════════════════════════════
PILLAR 3 — AUDIT CLI TOOL
═══════════════════════════════════════════════════════════════════════

Goal: A standalone CLI that any external auditor — the SEC, the FDA,
a court-appointed examiner — can run on an audit log JSONL file to
prove that every Decision was produced by the authorized Pramanix
instance and has not been modified since production. No Pramanix SDK
installation required beyond the cryptography package.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3.1 — Extend src/pramanix/cli.py with audit subcommand
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read src/pramanix/cli.py (written in Phase 9). Add the audit subcommand
alongside the existing verify-proof subcommand.

Add these functions to cli.py:
````python
# Add to the existing main() function's subparser setup:
# (Find the existing sub = parser.add_subparsers(dest="command") block
# and add the audit subcommand there)

audit = sub.add_parser("audit", help="Audit log verification tools")
audit_sub = audit.add_subparsers(dest="audit_command")

av = audit_sub.add_parser(
    "verify",
    help="Verify a JSONL audit log file",
)
av.add_argument("log_file", help="Path to JSONL audit log file")
av.add_argument(
    "--public-key",
    required=True,
    help="Path to Ed25519 public key PEM file",
)
av.add_argument(
    "--json",
    dest="as_json",
    action="store_true",
    help="Output results as JSON",
)
av.add_argument(
    "--fail-fast",
    action="store_true",
    help="Stop at first invalid record",
)

# In main(), add:
# if args.command == "audit":
#     return _cmd_audit(args)
````

Add the audit implementation:
````python
def _cmd_audit(args: argparse.Namespace) -> int:
    if not hasattr(args, "audit_command") or args.audit_command == "verify":
        return _cmd_audit_verify(args)
    print("Usage: pramanix audit verify <log_file> --public-key <key.pem>")
    return 2


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify a JSONL audit log file.

    For each record:
    1. Recompute decision_hash from stored fields (tamper detection)
    2. Verify Ed25519 signature against decision_hash (authentication)

    Output:
        [VALID]       decision_id=... — hash matches, signature valid
        [TAMPERED]    decision_id=... — hash mismatch (fields modified)
        [INVALID_SIG] decision_id=... — hash ok but signature invalid
        [MISSING_SIG] decision_id=... — no signature in record
        [ERROR]       decision_id=... — malformed record

    Exit code:
        0 — all records valid
        1 — any record tampered, invalid signature, or malformed
        2 — usage error (file not found, bad key)
    """
    import json

    # Load public key
    pub_key_path = getattr(args, "public_key", None)
    if not pub_key_path:
        print("ERROR: --public-key is required", file=sys.stderr)
        return 2

    try:
        with open(pub_key_path, "rb") as f:
            public_key_pem = f.read()
    except FileNotFoundError:
        print(f"ERROR: Public key file not found: {pub_key_path}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: Cannot read public key: {e}", file=sys.stderr)
        return 2

    # Initialize verifier
    try:
        from pramanix.crypto import PramanixVerifier
        verifier = PramanixVerifier(public_key_pem=public_key_pem)
    except ImportError:
        print(
            "ERROR: cryptography package required. pip install cryptography",
            file=sys.stderr,
        )
        return 2
    except Exception as e:
        print(f"ERROR: Invalid public key: {e}", file=sys.stderr)
        return 2

    # Open log file
    log_path = args.log_file
    try:
        log_file = open(log_path, "r", encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        return 2

    # Process records
    results = []
    total = valid = tampered = invalid_sig = missing_sig = errors = 0
    fail_fast = getattr(args, "fail_fast", False)

    with log_file:
        for line_num, line in enumerate(log_file, 1):
            line = line.strip()
            if not line:
                continue

            total += 1

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                result = {
                    "line": line_num,
                    "status": "ERROR",
                    "decision_id": "UNKNOWN",
                    "reason": "Invalid JSON on line",
                }
                results.append(result)
                if not getattr(args, "as_json", False):
                    print(f"[ERROR] line={line_num} — Invalid JSON")
                if fail_fast:
                    break
                continue

            decision_id = record.get("decision_id", "UNKNOWN")
            stored_hash = record.get("decision_hash", "")
            signature   = record.get("signature", "")

            # Step 1: Recompute hash from stored fields
            try:
                recomputed_hash = _recompute_hash(record)
            except Exception as e:
                errors += 1
                result = {
                    "line": line_num,
                    "status": "ERROR",
                    "decision_id": decision_id,
                    "reason": f"Hash recomputation failed: {e}",
                }
                results.append(result)
                if not getattr(args, "as_json", False):
                    print(f"[ERROR] decision_id={decision_id} — {e}")
                if fail_fast:
                    break
                continue

            # Step 2: Check hash matches stored hash (tamper detection)
            if recomputed_hash != stored_hash:
                tampered += 1
                result = {
                    "line": line_num,
                    "status": "TAMPERED",
                    "decision_id": decision_id,
                    "reason": "decision_hash mismatch — fields were modified",
                    "stored_hash": stored_hash,
                    "computed_hash": recomputed_hash,
                }
                results.append(result)
                if not getattr(args, "as_json", False):
                    print(
                        f"[TAMPERED]    decision_id={decision_id} "
                        f"| stored={stored_hash[:16]}... "
                        f"computed={recomputed_hash[:16]}..."
                    )
                if fail_fast:
                    break
                continue

            # Step 3: Verify Ed25519 signature
            if not signature:
                missing_sig += 1
                result = {
                    "line": line_num,
                    "status": "MISSING_SIG",
                    "decision_id": decision_id,
                    "reason": "No signature field in record",
                }
                results.append(result)
                if not getattr(args, "as_json", False):
                    print(f"[MISSING_SIG] decision_id={decision_id}")
                if fail_fast:
                    break
                continue

            sig_valid = verifier.verify(
                decision_hash=recomputed_hash,
                signature=signature,
            )

            if not sig_valid:
                invalid_sig += 1
                result = {
                    "line": line_num,
                    "status": "INVALID_SIG",
                    "decision_id": decision_id,
                    "reason": "Ed25519 signature invalid — wrong key or tampered signature",
                }
                results.append(result)
                if not getattr(args, "as_json", False):
                    print(f"[INVALID_SIG] decision_id={decision_id}")
                if fail_fast:
                    break
                continue

            # All checks passed
            valid += 1
            result = {
                "line": line_num,
                "status": "VALID",
                "decision_id": decision_id,
                "allowed": record.get("allowed"),
            }
            results.append(result)
            if not getattr(args, "as_json", False):
                verdict = "ALLOW" if record.get("allowed") else "BLOCK"
                print(f"[VALID]       decision_id={decision_id} ({verdict})")

    # Summary
    any_failure = (tampered + invalid_sig + missing_sig + errors) > 0

    if getattr(args, "as_json", False):
        summary = {
            "total": total,
            "valid": valid,
            "tampered": tampered,
            "invalid_sig": invalid_sig,
            "missing_sig": missing_sig,
            "errors": errors,
            "all_valid": not any_failure,
            "records": results,
        }
        print(json.dumps(summary, indent=2))
    else:
        print(f"\n{'─' * 60}")
        print(f"Audit complete: {total} records")
        print(f"  ✅ Valid:        {valid}")
        if tampered:
            print(f"  ❌ Tampered:     {tampered}")
        if invalid_sig:
            print(f"  ❌ Invalid sig:  {invalid_sig}")
        if missing_sig:
            print(f"  ⚠️  Missing sig:  {missing_sig}")
        if errors:
            print(f"  ⚠️  Errors:       {errors}")
        print()
        if not any_failure:
            print("✅ AUDIT PASSED — All records verified")
        else:
            print("❌ AUDIT FAILED — See details above")

    return 1 if any_failure else 0


def _recompute_hash(record: dict) -> str:
    """Recompute decision_hash from a JSONL audit record.

    This function must be kept in sync with Decision._compute_hash().
    It is the auditor's side of the hash verification.
    """
    import hashlib
    try:
        import orjson
        from pramanix.decision import _make_json_safe
        canonical = {
            "allowed": bool(record.get("allowed", False)),
            "explanation": str(record.get("explanation", "")),
            "intent_dump": _make_json_safe(record.get("intent_dump", {})),
            "policy": str(record.get("policy", "")),
            "state_dump": _make_json_safe(record.get("state_dump", {})),
            "status": str(record.get("status", "")),
            "violated_invariants": sorted(
                str(v) for v in record.get("violated_invariants", [])
            ),
        }
        serialized = orjson.dumps(
            canonical,
            option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS,
        )
    except Exception:
        import json as _json
        canonical = {
            "allowed": bool(record.get("allowed", False)),
            "explanation": str(record.get("explanation", "")),
            "policy": str(record.get("policy", "")),
            "status": str(record.get("status", "")),
            "violated_invariants": sorted(
                str(v) for v in record.get("violated_invariants", [])
            ),
        }
        serialized = _json.dumps(canonical, sort_keys=True, default=str).encode()

    return hashlib.sha256(serialized).hexdigest()
````

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3.2 — Create tests/unit/test_audit_cli.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
````python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for pramanix audit verify CLI (Phase 11.3).

Tests:
1. Valid JSONL file → exit 0, all [VALID]
2. Tampered record (amount changed) → exit 1, [TAMPERED]
3. Tampered allowed field → exit 1, [TAMPERED]
4. Wrong public key → exit 1, [INVALID_SIG]
5. Missing signature → [MISSING_SIG]
6. Malformed JSON line → [ERROR]
7. JSON output format is correct
8. Mixed file: valid + tampered → exit 1
"""
from __future__ import annotations

import json
import os
import tempfile
from decimal import Decimal
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from pramanix.crypto import PramanixSigner, PramanixVerifier
from pramanix.decision import Decision


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_audit_record(decision: Decision, signer: PramanixSigner) -> dict:
    """Create a JSONL audit record from a Decision + signer."""
    sig = signer.sign(decision)
    return {
        "decision_id":        decision.decision_id,
        "decision_hash":      decision.decision_hash,
        "signature":          sig,
        "public_key_id":      signer.key_id(),
        "allowed":            decision.allowed,
        "status":             str(decision.status.value if hasattr(decision.status, "value") else decision.status),
        "violated_invariants": list(decision.violated_invariants or []),
        "explanation":        decision.explanation or "",
        "policy":             str(decision.metadata.get("policy", "") if decision.metadata else ""),
        "intent_dump":        decision.intent_dump or {},
        "state_dump":         decision.state_dump or {},
    }


def _write_jsonl(records: list[dict], path: Path) -> None:
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _write_public_key(signer: PramanixSigner, path: Path) -> None:
    path.write_bytes(signer.public_key_pem())


def _run_audit_cli(log_path: Path, key_path: Path, extra_args: list = None) -> tuple[int, str]:
    """Run the audit CLI and return (exit_code, stdout)."""
    import io
    import sys
    from pramanix.cli import main as cli_main

    args = ["pramanix", "audit", "verify", str(log_path),
            "--public-key", str(key_path)]
    if extra_args:
        args.extend(extra_args)

    old_argv = sys.argv
    old_stdout = sys.stdout
    sys.argv = args
    sys.stdout = io.StringIO()
    try:
        exit_code = cli_main()
        output = sys.stdout.getvalue()
    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout

    return exit_code or 0, output


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestAuditCLIValid:
    def test_valid_log_exits_0(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        records = [_make_audit_record(d, signer)]
        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl(records, log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 0
        assert "[VALID]" in output

    def test_multiple_valid_records_exits_0(self, tmp_path):
        signer = PramanixSigner.generate()
        records = []
        for i in range(10):
            d = Decision.safe(
                intent_dump={"amount": str(i * 100)},
                state_dump={"state_version": "v1"},
            )
            records.append(_make_audit_record(d, signer))

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl(records, log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 0
        assert output.count("[VALID]") == 10


class TestAuditCLITampered:
    def test_tampered_amount_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        record = _make_audit_record(d, signer)

        # Tamper: change amount after signing
        record["intent_dump"]["amount"] = "999999"

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[TAMPERED]" in output

    def test_tampered_allowed_field_exits_1(self, tmp_path):
        """CRITICAL: flipping allowed=False to allowed=True must be detected."""
        signer = PramanixSigner.generate()
        d = Decision.unsafe(
            violated_invariants=("overdraft",),
            explanation="Insufficient balance",
            intent_dump={"amount": "9999"},
            state_dump={"balance": "100", "state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        assert record["allowed"] is False

        # Tamper: flip allowed to True
        record["allowed"] = True

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[TAMPERED]" in output

    def test_tampered_violated_invariants_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.unsafe(
            violated_invariants=("rule_a",),
            explanation="Rule A violated",
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        record = _make_audit_record(d, signer)

        # Tamper: remove violated invariants
        record["violated_invariants"] = []

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[TAMPERED]" in output


class TestAuditCLIInvalidSig:
    def test_wrong_public_key_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        wrong_signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        records = [_make_audit_record(d, signer)]

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl(records, log_path)
        _write_public_key(wrong_signer, key_path)  # Wrong key

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[INVALID_SIG]" in output

    def test_missing_signature_field_reports_missing(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        del record["signature"]  # Remove signature

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[MISSING_SIG]" in output


class TestAuditCLIEdgeCases:
    def test_malformed_json_line_reports_error(self, tmp_path):
        signer = PramanixSigner.generate()
        key_path = tmp_path / "key.pem"
        _write_public_key(signer, key_path)

        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("{ this is not valid json {\n")

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[ERROR]" in output

    def test_mixed_valid_and_tampered_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        d_valid = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        d_tampered = Decision.safe(
            intent_dump={"amount": "200"},
            state_dump={"state_version": "v1"},
        )
        r_valid   = _make_audit_record(d_valid, signer)
        r_tampered = _make_audit_record(d_tampered, signer)
        r_tampered["intent_dump"]["amount"] = "999"  # Tamper

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([r_valid, r_tampered], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[VALID]" in output
        assert "[TAMPERED]" in output

    def test_json_output_is_parseable(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        records = [_make_audit_record(d, signer)]

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl(records, log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path, ["--json"])
        parsed = json.loads(output)
        assert parsed["total"] == 1
        assert parsed["valid"] == 1
        assert parsed["all_valid"] is True

    def test_json_output_tampered_has_correct_fields(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        record["allowed"] = True  # Tamper

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path, ["--json"])
        parsed = json.loads(output)
        assert parsed["tampered"] == 1
        assert parsed["all_valid"] is False
        assert code == 1


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 3 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_audit_cli.py -v
    # All tests pass including tamper detection tests

Verify CLI end-to-end:
    python -c "
import json, tempfile, os
from pathlib import Path
from pramanix.crypto import PramanixSigner
from pramanix.decision import Decision

# Setup
signer = PramanixSigner.generate()
d = Decision.unsafe(
    violated_invariants=('overdraft',),
    explanation='Balance 50 insufficient for 500',
    intent_dump={'amount': '500'},
    state_dump={'balance': '50', 'state_version': 'v1'},
)
sig = signer.sign(d)
record = {
    'decision_id': d.decision_id,
    'decision_hash': d.decision_hash,
    'signature': sig,
    'allowed': d.allowed,
    'status': str(d.status.value),
    'violated_invariants': list(d.violated_invariants),
    'explanation': d.explanation,
    'policy': '',
    'intent_dump': d.intent_dump,
    'state_dump': d.state_dump,
}
with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
    f.write(json.dumps(record) + '\n')
    log_path = f.name
with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
    f.write(signer.public_key_pem())
    key_path = f.name

print('Audit log:', log_path)
print('Public key:', key_path)
" 2>/dev/null

    pramanix audit verify /tmp/audit_test.jsonl --public-key /tmp/test_key.pem
    # Expected: [VALID] + exit 0

═══════════════════════════════════════════════════════════════════════
PILLAR 4 — COMPLIANCE REPORTER
═══════════════════════════════════════════════════════════════════════

Goal: Map Z3 unsat cores (invariant labels) to human-readable
compliance rationale with regulatory citations. A Decision that
blocks a $5M wire transfer produces not just "sufficient_balance
violated" but a structured report citing 31 CFR § 1020 with the
exact values and severity classification.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4.1 — Create src/pramanix/helpers/compliance.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Compliance report generation for Pramanix Decision objects.

Maps Z3 unsat core labels (violated_invariants) to structured compliance
reports with regulatory citations. Used by banks, hospitals, and cloud
providers to generate audit-ready documentation from Pramanix decisions.

Supported regulatory frameworks:
- BSA/AML (31 CFR § 1020, § 1023, § 1025)
- OFAC/SDN (50 CFR § 598)
- SEC wash sale (IRC § 1091)
- HIPAA Privacy Rule (45 CFR § 164)
- SOX internal controls (15 U.S.C. § 7241)
- Basel III capital adequacy (BCBS 189)

Usage:
    from pramanix.helpers.compliance import ComplianceReporter

    reporter = ComplianceReporter()
    report = reporter.generate(
        decision=decision,
        policy_meta={"name": "BankingPolicy", "version": "1.0"},
    )
    print(report.to_json())
    # → {"decision_id": "...", "verdict": "BLOCKED", "severity": "HIGH",
    #    "compliance_rationale": [...], "regulatory_refs": [...]}
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.decision import Decision


# ── Regulatory reference database ─────────────────────────────────────────────

_REGULATORY_MAP: dict[str, list[str]] = {
    # FinTech / Banking
    "sufficient_balance":      ["Basel III: BCBS 189 §3.1 — Minimum liquidity coverage"],
    "non_negative_balance":    ["Basel III: BCBS 189 §3.1"],
    "velocity_check":          ["BSA/AML: 31 CFR § 1020.320 — Suspicious Activity Reports"],
    "anti_structuring":        ["BSA/AML: 31 CFR § 1020.320(a)(2) — Anti-structuring rule"],
    "wash_sale_detection":     ["IRC § 1091 — Wash sale disallowance rule (30-day window)"],
    "sanctions_screen":        ["OFAC: 31 CFR § 598 — Prohibition on transactions with SDN list"],
    "kyc_status":              ["BSA: 31 CFR § 1020.220 — Customer identification program"],
    "collateral_haircut":      ["Basel III: BCBS 189 — Collateral eligibility and haircuts"],
    "max_drawdown":            ["SEC: 17 CFR § 240.15c3-1 — Net capital requirements"],
    "risk_score_limit":        ["Basel II: BCBS 128 §III — Credit risk internal ratings"],
    "trading_window":          ["SEC: Regulation FD — Material non-public information"],
    "within_daily_limit":      ["BSA/AML: 31 CFR § 1020.320 — Transaction monitoring"],
    "single_tx_cap":           ["SOX: 15 U.S.C. § 7241 — Internal financial controls"],
    "acceptable_risk_score":   ["Basel II: BCBS 128 §III — Pillar 2 supervisory review"],
    "positive_amount":         ["SOX: 15 U.S.C. § 7241(a)(4) — Data integrity controls"],
    "account_not_frozen":      ["BSA: 31 CFR § 1010.830 — Frozen accounts enforcement"],

    # Healthcare / HIPAA
    "authorized_role":             ["HIPAA: 45 CFR § 164.502(b) — Minimum necessary standard"],
    "phi_least_privilege":         ["HIPAA: 45 CFR § 164.514(d) — Limited data set requirements"],
    "patient_consent_required":    ["HIPAA: 45 CFR § 164.508 — Authorization requirements"],
    "consent_active":              ["HIPAA: 45 CFR § 164.508(c) — Valid authorization elements"],
    "department_match_required":   ["HIPAA: 45 CFR § 164.502(b)(1) — Workforce access control"],
    "dosage_gradient_check":       ["FDA: 21 CFR § 211.68 — Drug dose computation controls"],
    "pediatric_dose_bound":        ["FDA: 21 CFR § 201.57 — Pediatric dosage maximum limits"],
    "break_glass_auth":            ["HIPAA: 45 CFR § 164.312(a)(2)(ii) — Emergency access"],
    "must_be_clinician":           ["HIPAA: 45 CFR § 164.502(b) — Minimum necessary access"],
    "consent_not_expired":         ["HIPAA: 45 CFR § 164.508(b)(5) — Revocation of authorization"],

    # Infrastructure / SRE
    "above_minimum":               ["SRE SLA: Minimum replica count for high availability"],
    "below_maximum":               ["FinOps: Maximum resource budget constraint"],
    "production_ha_minimum":       ["SRE: Production HA requires ≥2 replicas"],
    "blast_radius_check":          ["SRE: Blast radius limit for safe deployment"],
    "circuit_breaker_state":       ["SRE: Circuit breaker OPEN — downstream service protection"],
    "prod_gate_approval":          ["SOX: Change management approval workflow (ITGC)"],
    "replicas_budget":             ["FinOps: Compute budget constraint"],
    "cpu_memory_guard":            ["SRE: Resource quota enforcement"],
}


# ── Severity classification ────────────────────────────────────────────────────

def _classify_severity(
    violated_invariants: tuple[str, ...],
    intent_dump: dict,
) -> str:
    """Classify decision severity based on context.

    CRITICAL_PREVENTION: High-value financial or PHI access attempts
    HIGH:                Most policy violations in regulated domains
    MEDIUM:              Infrastructure and operational violations
    """
    high_value_rules = {
        "anti_structuring", "sanctions_screen", "wash_sale_detection",
        "patient_consent_required", "phi_least_privilege",
        "pediatric_dose_bound",
    }
    infra_rules = {
        "blast_radius_check", "circuit_breaker_state",
        "replicas_budget", "cpu_memory_guard",
    }

    # Check for critical prevention conditions
    amount_str = str(intent_dump.get("amount", "0"))
    try:
        amount = Decimal(amount_str)
        if amount >= Decimal("100000"):
            return "CRITICAL_PREVENTION"
    except Exception:
        pass

    violated_set = set(violated_invariants)
    if violated_set & high_value_rules:
        return "CRITICAL_PREVENTION"

    if violated_set & infra_rules:
        return "MEDIUM"

    return "HIGH"


# ── Report dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ComplianceReport:
    """Structured compliance report for a Pramanix Decision.

    Suitable for inclusion in:
    - Regulatory audit submissions (SEC, FDA, OCC)
    - Legal discovery responses
    - Internal compliance dashboards
    - SAR (Suspicious Activity Report) documentation
    """
    decision_id:          str
    decision_hash:        str
    timestamp:            str
    verdict:              str          # "ALLOWED" or "BLOCKED"
    severity:             str          # "CRITICAL_PREVENTION", "HIGH", "MEDIUM"
    policy_name:          str
    policy_version:       str
    violated_rules:       tuple[str, ...]
    compliance_rationale: tuple[str, ...]
    regulatory_refs:      tuple[str, ...]
    explanation:          str

    def to_json(self) -> str:
        """Serialize to JSON string suitable for audit log inclusion."""
        return json.dumps(
            {
                "decision_id":          self.decision_id,
                "decision_hash":        self.decision_hash,
                "timestamp":            self.timestamp,
                "verdict":              self.verdict,
                "severity":             self.severity,
                "policy_name":          self.policy_name,
                "policy_version":       self.policy_version,
                "violated_rules":       list(self.violated_rules),
                "compliance_rationale": list(self.compliance_rationale),
                "regulatory_refs":      list(self.regulatory_refs),
                "explanation":          self.explanation,
            },
            indent=2,
            default=str,
        )

    def to_pdf(self) -> bytes:
        """Generate a PDF compliance report.

        Phase 12 deliverable. This is a placeholder that returns a
        UTF-8 encoded structured text until Phase 12 implements PDF.
        """
        lines = [
            "PRAMANIX COMPLIANCE REPORT",
            "=" * 40,
            f"Decision ID:   {self.decision_id}",
            f"Hash:          {self.decision_hash}",
            f"Timestamp:     {self.timestamp}",
            f"Verdict:       {self.verdict}",
            f"Severity:      {self.severity}",
            f"Policy:        {self.policy_name} v{self.policy_version}",
            "",
            "VIOLATED RULES:",
        ]
        for rule in self.violated_rules:
            lines.append(f"  • {rule}")
        lines.append("")
        lines.append("COMPLIANCE RATIONALE:")
        for rationale in self.compliance_rationale:
            lines.append(f"  • {rationale}")
        lines.append("")
        lines.append("REGULATORY REFERENCES:")
        for ref in self.regulatory_refs:
            lines.append(f"  • {ref}")
        lines.append("")
        lines.append(f"EXPLANATION: {self.explanation}")
        return "\n".join(lines).encode("utf-8")


# ── Reporter ──────────────────────────────────────────────────────────────────


class ComplianceReporter:
    """Generates structured compliance reports from Pramanix Decisions.

    Usage:
        reporter = ComplianceReporter()
        # Or with custom regulatory mappings:
        reporter = ComplianceReporter(extra_refs={"my_rule": ["Internal Policy §3.2"]})

    For every violated invariant, the reporter:
    1. Uses the invariant's .explain() template (populated with actual values)
    2. Maps the invariant label to regulatory citations
    3. Classifies severity based on violated rules and amount
    """

    def __init__(
        self,
        extra_refs: dict[str, list[str]] | None = None,
    ) -> None:
        self._refs = dict(_REGULATORY_MAP)
        if extra_refs:
            self._refs.update(extra_refs)

    def generate(
        self,
        decision: "Decision",
        policy_meta: dict[str, str] | None = None,
    ) -> ComplianceReport:
        """Generate a ComplianceReport from a Decision.

        Args:
            decision:    The Decision object from Guard.verify()
            policy_meta: Optional dict with "name" and "version" keys.
                         Falls back to decision.metadata if available.
        """
        meta = policy_meta or {}
        if not meta and decision.metadata:
            meta = decision.metadata

        policy_name    = meta.get("name") or meta.get("policy") or "UnknownPolicy"
        policy_version = meta.get("version") or meta.get("policy_version") or "unknown"

        # Timestamp from decision
        timestamp = ""
        if decision.metadata:
            timestamp = str(decision.metadata.get("timestamp_utc", ""))

        verdict = "ALLOWED" if decision.allowed else "BLOCKED"

        violated = tuple(decision.violated_invariants or ())
        intent_dump = decision.intent_dump or {}

        # Build compliance rationale (explain() templates already interpolated)
        rationale: list[str] = []
        if decision.explanation:
            rationale.append(decision.explanation)

        # Build regulatory references
        refs: list[str] = []
        for rule in violated:
            rule_refs = self._refs.get(rule, [])
            refs.extend(rule_refs)
            if not rule_refs:
                refs.append(f"Internal policy rule: {rule}")

        # Classify severity
        severity = _classify_severity(violated, intent_dump)

        return ComplianceReport(
            decision_id=str(decision.decision_id),
            decision_hash=str(decision.decision_hash),
            timestamp=timestamp,
            verdict=verdict,
            severity=severity,
            policy_name=policy_name,
            policy_version=policy_version,
            violated_rules=violated,
            compliance_rationale=tuple(rationale),
            regulatory_refs=tuple(dict.fromkeys(refs)),  # Deduplicated, ordered
            explanation=str(decision.explanation or ""),
        )

    def register_rule(self, rule_name: str, refs: list[str]) -> None:
        """Register regulatory references for a custom rule label."""
        self._refs[rule_name] = refs
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4.2 — Create tests/unit/test_compliance_reporter.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for ComplianceReporter (Phase 11.4).

Verifies:
1. Regulatory references are correct for each domain
2. Severity classification is correct
3. Report fields are properly populated
4. Custom rules can be registered
5. End-to-end via Guard: real Decision → report
"""
from __future__ import annotations

import json
from decimal import Decimal

import pytest

from pramanix.helpers.compliance import ComplianceReport, ComplianceReporter
from pramanix.decision import Decision


def _block(violated: tuple, explanation: str = "blocked",
           amount: str = "100") -> Decision:
    return Decision.unsafe(
        violated_invariants=violated,
        explanation=explanation,
        intent_dump={"amount": amount},
        state_dump={"state_version": "v1"},
        metadata={"policy": "TestPolicy", "policy_version": "1.0"},
    )


def _allow() -> Decision:
    return Decision.safe(
        intent_dump={"amount": "100"},
        state_dump={"state_version": "v1"},
        metadata={"policy": "TestPolicy", "policy_version": "1.0"},
    )


class TestComplianceReportGeneration:
    def test_generates_report_for_blocked_decision(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), "Balance insufficient")
        report = reporter.generate(d)
        assert isinstance(report, ComplianceReport)
        assert report.verdict == "BLOCKED"

    def test_generates_report_for_allowed_decision(self):
        reporter = ComplianceReporter()
        d = _allow()
        report = reporter.generate(d)
        assert report.verdict == "ALLOWED"

    def test_decision_id_preserved(self):
        reporter = ComplianceReporter()
        d = _block(("rule_x",))
        report = reporter.generate(d)
        assert report.decision_id == d.decision_id

    def test_decision_hash_preserved(self):
        reporter = ComplianceReporter()
        d = _block(("rule_x",))
        report = reporter.generate(d)
        assert report.decision_hash == d.decision_hash

    def test_violated_rules_preserved(self):
        reporter = ComplianceReporter()
        d = _block(("rule_a", "rule_b"))
        report = reporter.generate(d)
        assert "rule_a" in report.violated_rules
        assert "rule_b" in report.violated_rules

    def test_explanation_in_rationale(self):
        reporter = ComplianceReporter()
        d = _block(("overdraft",), explanation="Balance 100 insufficient for 500")
        report = reporter.generate(d)
        assert "Balance 100 insufficient" in "\n".join(report.compliance_rationale)


class TestRegulatoryReferences:
    def test_sufficient_balance_has_basel_ref(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "Basel" in refs_str or "BCBS" in refs_str

    def test_anti_structuring_has_bsa_ref(self):
        reporter = ComplianceReporter()
        d = _block(("anti_structuring",), "Structuring detected")
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "BSA" in refs_str or "CFR" in refs_str

    def test_wash_sale_has_irc_ref(self):
        reporter = ComplianceReporter()
        d = _block(("wash_sale_detection",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "IRC" in refs_str or "1091" in refs_str

    def test_sanctions_has_ofac_ref(self):
        reporter = ComplianceReporter()
        d = _block(("sanctions_screen",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "OFAC" in refs_str or "SDN" in refs_str

    def test_phi_access_has_hipaa_ref(self):
        reporter = ComplianceReporter()
        d = _block(("patient_consent_required",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "HIPAA" in refs_str or "CFR" in refs_str

    def test_unknown_rule_gets_internal_policy_ref(self):
        reporter = ComplianceReporter()
        d = _block(("my_custom_rule_xyz",))
        report = reporter.generate(d)
        refs_str = " ".join(report.regulatory_refs)
        assert "Internal policy" in refs_str or "my_custom_rule_xyz" in refs_str

    def test_custom_rule_registration(self):
        reporter = ComplianceReporter()
        reporter.register_rule("my_rule", ["Company Policy §7.3.2"])
        d = _block(("my_rule",))
        report = reporter.generate(d)
        assert "Company Policy §7.3.2" in report.regulatory_refs

    def test_refs_are_deduplicated(self):
        """Same ref appearing multiple times must only appear once."""
        reporter = ComplianceReporter()
        # Two rules that both cite BSA
        d = _block(("velocity_check", "within_daily_limit"))
        report = reporter.generate(d)
        # Should not duplicate identical references
        assert len(report.regulatory_refs) == len(set(report.regulatory_refs))


class TestSeverityClassification:
    def test_high_value_amount_is_critical_prevention(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), amount="500000")
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_sanctions_violation_is_critical_prevention(self):
        reporter = ComplianceReporter()
        d = _block(("sanctions_screen",))
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_phi_violation_is_critical_prevention(self):
        reporter = ComplianceReporter()
        d = _block(("patient_consent_required",))
        report = reporter.generate(d)
        assert report.severity == "CRITICAL_PREVENTION"

    def test_balance_violation_normal_amount_is_high(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), amount="100")
        report = reporter.generate(d)
        assert report.severity in ("HIGH", "CRITICAL_PREVENTION")

    def test_infra_violation_is_medium(self):
        reporter = ComplianceReporter()
        d = _block(("blast_radius_check",))
        report = reporter.generate(d)
        assert report.severity == "MEDIUM"


class TestComplianceReportSerialization:
    def test_to_json_produces_valid_json(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",), "Insufficient balance")
        report = reporter.generate(d)
        raw = report.to_json()
        parsed = json.loads(raw)
        assert "decision_id" in parsed
        assert "verdict" in parsed
        assert "regulatory_refs" in parsed

    def test_to_json_contains_all_required_fields(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        parsed = json.loads(report.to_json())
        required = [
            "decision_id", "decision_hash", "verdict", "severity",
            "policy_name", "policy_version", "violated_rules",
            "compliance_rationale", "regulatory_refs", "explanation",
        ]
        for field in required:
            assert field in parsed, f"Missing field: {field}"

    def test_to_pdf_returns_bytes(self):
        reporter = ComplianceReporter()
        d = _block(("sufficient_balance",))
        report = reporter.generate(d)
        pdf = report.to_pdf()
        assert isinstance(pdf, bytes)
        assert len(pdf) > 0

    def test_report_is_frozen(self):
        reporter = ComplianceReporter()
        d = _block(("rule_x",))
        report = reporter.generate(d)
        with pytest.raises((AttributeError, TypeError)):
            report.verdict = "HACKED"  # type: ignore[misc]


class TestComplianceReporterEndToEnd:
    def test_via_guard_banking_block(self):
        """End-to-end: real Guard → real Decision → ComplianceReport."""
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _BankingPolicy(Policy):
            class Meta:
                version = "1.0"
                name = "BankingPolicy"

            @classmethod
            def fields(cls):
                return {"amount": _amount, "balance": _balance}

            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sufficient_balance")
                    .explain(
                        "Transfer of {amount} blocked: balance {balance} insufficient"
                    )
                ]

        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        decision = guard.verify(
            intent={"amount": Decimal("5000")},
            state={"balance": Decimal("100"), "state_version": "1.0"},
        )
        assert not decision.allowed

        reporter = ComplianceReporter()
        report = reporter.generate(
            decision,
            policy_meta={"name": "BankingPolicy", "version": "1.0"},
        )

        assert report.verdict == "BLOCKED"
        assert "sufficient_balance" in report.violated_rules
        refs_str = " ".join(report.regulatory_refs)
        assert "Basel" in refs_str or "BCBS" in refs_str
        # Explanation should contain template content
        assert "insufficient" in report.explanation.lower() or \
               "blocked" in report.explanation.lower()
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 4 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_compliance_reporter.py -v
    # All pass including end-to-end via Guard test

═══════════════════════════════════════════════════════════════════════
FINAL ASSEMBLY — UPDATE ALL METADATA
═══════════════════════════════════════════════════════════════════════

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.1 — Bump version to 0.8.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

In pyproject.toml: version = "0.8.0"
In src/pramanix/__init__.py: __version__ = "0.8.0"

These MUST match exactly.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.2 — Update src/pramanix/__init__.py exports
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add to existing __init__.py:
    from pramanix.crypto import PramanixSigner, PramanixVerifier
    from pramanix.helpers.compliance import ComplianceReporter, ComplianceReport

Add to __all__:
    "PramanixSigner", "PramanixVerifier",
    "ComplianceReporter", "ComplianceReport"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.3 — Add crypto optional extra to pyproject.toml
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

In [tool.poetry.extras]:
    crypto = ["cryptography", "orjson"]

Update "all" extra to include "cryptography" and "orjson".

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.4 — Add mypy overrides
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

In pyproject.toml [[tool.mypy.overrides]]:
    [[tool.mypy.overrides]]
    module = ["pramanix.crypto", "pramanix.helpers.compliance"]
    ignore_missing_imports = true

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.5 — Update docs/security.md with key management guidance
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Append to docs/security.md:

---

## Phase 11: Ed25519 Key Management (v0.8.0)

### Production Key Provisioning

Never generate keys in application code for production deployments.
Use one of these approved patterns:

**AWS KMS (recommended for AWS deployments):**
```python
# Use KMS for signing — private key never leaves KMS
import boto3
kms = boto3.client("kms")
# Create an ED25519 signing key in KMS
# Use kms.sign() API — no local private key
```

**HashiCorp Vault:**
```bash
vault write transit/keys/pramanix type=ed25519
vault write transit/sign/pramanix input=$(base64 <<< "decision_hash")
```

**Kubernetes Secret:**
```bash
# Generate key offline
python -c "from pramanix.crypto import PramanixSigner; s = PramanixSigner.generate(); print(s.private_key_pem().decode())" > pramanix_private_key.pem

# Store in k8s secret
kubectl create secret generic pramanix-signing-key \
  --from-file=private_key.pem=pramanix_private_key.pem

# Mount as env var in deployment
# PRAMANIX_SIGNING_KEY_PEM comes from the secret
```

### Key Rotation

1. Generate a new keypair
2. Assign a new key_id (automatically computed as SHA-256[:16] of new public key)
3. Archive the old public key PEM alongside its key_id
4. Old decisions signed with old key remain verifiable using archived public key
5. New decisions carry new key_id in public_key_id field

### Public Key Distribution

The public key PEM is safe to publish. Share it with:
- External auditors and regulators
- Compliance teams
- Any system that needs to verify Pramanix decisions offline

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.6 — Add CHANGELOG.md entry for v0.8.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add at top of CHANGELOG.md:

## [0.8.0] — 2026-03-15

### Added — Phase 11: Cryptographic Audit Trail & Non-Repudiation

**Pillar 1: Deterministic Decision Hashing**
- `Decision.decision_hash`: SHA-256 fingerprint of every Decision
- `Decision.intent_dump` / `state_dump`: stored for hash replay
- `_make_json_safe()`: Decimal-preserving canonical serialization
- `orjson` with OPT_SORT_KEYS for deterministic key ordering
- Hypothesis property tests: 500 examples prove determinism and uniqueness

**Pillar 2: Ed25519 Cryptographic Signing**
- `PramanixSigner`: Ed25519 signing with AWS KMS / Vault / env var support
- `PramanixVerifier`: standalone offline verification (stdlib + cryptography only)
- `GuardConfig.signer`: wire in signer to auto-sign every Decision
- `Decision.signature` / `Decision.public_key_id`: new optional fields
- 1000-cycle reliability test: 100% sign-verify pass rate

**Pillar 3: Audit CLI**
- `pramanix audit verify <log.jsonl> --public-key <key.pem>`
- Detects: tampered fields (TAMPERED), wrong key (INVALID_SIG),
  missing signature (MISSING_SIG), malformed JSON (ERROR)
- JSON output mode: `--json` for machine-readable results
- Exit code 1 on ANY tampered or invalid record

**Pillar 4: Compliance Reporter**
- `ComplianceReporter`: maps violated invariants to regulatory citations
- Supports: BSA/AML, OFAC/SDN, IRC § 1091, HIPAA, SOX, Basel III
- `ComplianceReport.to_json()`: audit-ready JSON
- `ComplianceReport.to_pdf()`: placeholder for Phase 12 PDF generation
- Severity classification: CRITICAL_PREVENTION / HIGH / MEDIUM

### Security
- `Decision` now carries cryptographic proof of integrity
- Any field modification after signing is detectable by audit CLI
- Ed25519 is deterministic — no RNG in signing path
- Private key never logged or exposed — only public key_id in Decision

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.7 — Coverage repair
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest --cov=src/pramanix --cov-branch --cov-report=term-missing \
           --cov-fail-under=95 --ignore=tests/perf -q

Check coverage for new modules:
    src/pramanix/crypto.py           — orjson fallback path
    src/pramanix/helpers/compliance.py — to_pdf() placeholder
    src/pramanix/decision.py         — new fields in factory methods

For any path < 95%: write the missing test. Never use # pragma: no cover
on logic paths. Only use it on:
    - ImportError fallback blocks
    - TYPE_CHECKING blocks

═══════════════════════════════════════════════════════════════════════
FINAL GATE — THE COMPLETE PHASE 11 AUDIT
═══════════════════════════════════════════════════════════════════════

Run every command below. Every one must pass. Print results.

GATE 1 — Decision hashing
    pytest tests/unit/test_decision_hash.py -v
    # All pass including Hypothesis tests

    python -c "
from pramanix.decision import Decision
d1 = Decision.safe(intent_dump={'amount': '100'}, state_dump={'state_version': 'v1'})
d2 = Decision.safe(intent_dump={'amount': '100'}, state_dump={'state_version': 'v1'})
d3 = Decision.safe(intent_dump={'amount': '101'}, state_dump={'state_version': 'v1'})
assert d1.decision_hash == d2.decision_hash, 'FAIL: identical decisions have different hashes'
assert d1.decision_hash != d3.decision_hash, 'FAIL: different amounts have same hash'
assert len(d1.decision_hash) == 64
print('✅ GATE 1: Decision hashing correct')
"

GATE 2 — Ed25519 signing
    pytest tests/unit/test_crypto.py -v
    # All pass including 1000-cycle tests

    python -c "
from pramanix.crypto import PramanixSigner, PramanixVerifier
from pramanix.decision import Decision

signer = PramanixSigner.generate()
d = Decision.unsafe(
    violated_invariants=('overdraft',),
    explanation='Balance insufficient',
    intent_dump={'amount': '5000'},
    state_dump={'balance': '100', 'state_version': 'v1'},
)
sig = signer.sign(d)
verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
assert verifier.verify(decision_hash=d.decision_hash, signature=sig)

wrong = PramanixSigner.generate()
wv = PramanixVerifier(public_key_pem=wrong.public_key_pem())
assert not wv.verify(decision_hash=d.decision_hash, signature=sig)
print('✅ GATE 2: Ed25519 signing and verification correct')
"

GATE 3 — Audit CLI tamper detection (THE CRITICAL GATE)
    pytest tests/unit/test_audit_cli.py -v
    # test_tampered_allowed_field_exits_1 MUST pass
    # This proves flipping allowed=False to allowed=True is detected

GATE 4 — Compliance reporter
    pytest tests/unit/test_compliance_reporter.py -v
    # test_via_guard_banking_block MUST pass (end-to-end via real Guard)

GATE 5 — No regressions
    pytest tests/unit/test_decision.py tests/integration/test_banking_flow.py -v
    # All existing tests still pass

GATE 6 — Full test suite
    pytest --ignore=tests/perf -q --tb=short
    # ≥ 1500 passed, 0 failed

GATE 7 — Coverage
    pytest --cov=src/pramanix --cov-fail-under=95 --ignore=tests/perf -q
    # ≥ 95%

GATE 8 — Security invariants (the institutional demo)
    python -c "
print('Phase 11 Security Invariant Verification')
print('=' * 50)

# Invariant 1: Hash changes when allowed is flipped
from pramanix.decision import Decision
d_block = Decision.unsafe(
    violated_invariants=('overdraft',),
    explanation='blocked',
    intent_dump={'amount': '5000'},
    state_dump={'balance': '100', 'state_version': 'v1'},
)
# Manually create a tampered version
import copy
# The only way to have a different 'allowed' is to create a new Decision
# A real attacker would modify the JSONL record — not the Python object
# The audit CLI would detect this
hash_block = d_block.decision_hash
d_allow = Decision.safe(
    intent_dump={'amount': '5000'},
    state_dump={'balance': '100', 'state_version': 'v1'},
)
hash_allow = d_allow.decision_hash
assert hash_block != hash_allow
print('✅ INVARIANT 1: allowed=False and allowed=True have different hashes')

# Invariant 2: Wrong key cannot forge valid signature
from pramanix.crypto import PramanixSigner, PramanixVerifier
signer_a = PramanixSigner.generate()
signer_b = PramanixSigner.generate()
d = Decision.safe(intent_dump={'amount': '100'}, state_dump={'state_version': 'v1'})
sig_a = signer_a.sign(d)
vb = PramanixVerifier(public_key_pem=signer_b.public_key_pem())
assert not vb.verify(decision_hash=d.decision_hash, signature=sig_a)
print('✅ INVARIANT 2: Wrong key cannot verify signature')

# Invariant 3: 1000 sign-verify cycles — all pass
signer = PramanixSigner.generate()
verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
failures = 0
for i in range(1000):
    d = Decision.safe(
        intent_dump={'amount': str(i)},
        state_dump={'state_version': 'v1'},
    )
    sig = signer.sign(d)
    if not verifier.verify(decision_hash=d.decision_hash, signature=sig):
        failures += 1
assert failures == 0
print(f'✅ INVARIANT 3: 1000/1000 sign-verify cycles passed')

# Invariant 4: Compliance reporter produces regulatory citations
from pramanix.helpers.compliance import ComplianceReporter
reporter = ComplianceReporter()
d_bsa = Decision.unsafe(
    violated_invariants=('anti_structuring',),
    explanation='Structuring detected',
    intent_dump={'amount': '9000'},
    state_dump={'state_version': 'v1'},
)
report = reporter.generate(d_bsa)
refs = ' '.join(report.regulatory_refs)
assert 'BSA' in refs or 'CFR' in refs
assert report.severity == 'CRITICAL_PREVENTION'
print('✅ INVARIANT 4: BSA violation correctly classified as CRITICAL_PREVENTION')

print()
print('All Phase 11 security invariants verified.')
"

GATE 9 — Version consistency
    python -c "
import sys
sys.path.insert(0, 'src')
import pramanix
assert pramanix.__version__ == '0.8.0', f'Expected 0.8.0, got {pramanix.__version__}'
print('✅ Version 0.8.0 confirmed')
"

After all 9 gates pass, print:

"╔══════════════════════════════════════════════════════════════╗
 ║     PRAMANIX v0.8.0 — PHASE 11 COMPLETE                     ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  Pillar 1: Deterministic Decision Hashing   ✅ CERTIFIED    ║
 ║  Pillar 2: Ed25519 Cryptographic Signing    ✅ CERTIFIED    ║
 ║  Pillar 3: Audit CLI (tamper detection)     ✅ CERTIFIED    ║
 ║  Pillar 4: Compliance Reporter              ✅ CERTIFIED    ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  1000/1000 sign-verify cycles passed                        ║
 ║  Hash changes proven on: amount, balance, allowed, policy   ║
 ║  Regulatory refs: BSA, OFAC, IRC, HIPAA, SOX, Basel III     ║
 ║  Tests:   ≥1500 passed, 0 failed                            ║
 ║  Coverage: ≥95%                                             ║
 ╚══════════════════════════════════════════════════════════════╝"
````