# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Adversarial tests — ExecutionToken replay, tampering, and expiry attacks.

Verifies that the HMAC-signed single-use execution token protocol correctly
prevents all replay and forgery attack vectors.

INVARIANT: A consumed token can NEVER be consumed again within the same
           verifier's scope, regardless of timing or concurrent callers.

Attack vectors covered:
  R1  Direct replay               — consume() a valid token twice → second fails
  R2  Expired token replay        — token past TTL is rejected before HMAC check
  R3  Tampered decision_id        — HMAC mismatch → rejected
  R4  Tampered intent_dump        — HMAC mismatch → rejected
  R5  Tampered signature          — explicit bad sig → rejected
  R6  Wrong verifier key          — HMAC mismatch → rejected
  R7  State-version mismatch      — stale state version → rejected (TOCTOU)
  R8  BLOCK decision tokenisation — mint() refuses non-ALLOW decisions
  R9  Concurrent replay           — thread-safe single-use under contention
  R10 Cross-process replay note   — in-memory verifier documented limitation
  R11 Merkle atexit flush         — PersistentMerkleAnchor flushes on exit
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import replace

import pytest

from pramanix.decision import Decision
from pramanix.execution_token import ExecutionToken, ExecutionTokenSigner, ExecutionTokenVerifier

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_key() -> bytes:
    return secrets.token_bytes(32)


def _safe_decision(intent: dict | None = None) -> Decision:
    """Return a minimal Decision with allowed=True."""
    return Decision.safe(
        intent_dump=intent or {"amount": 100.0},
    )


def _blocked_decision() -> Decision:
    """Return a Decision with allowed=False (UNSAFE)."""
    return Decision.unsafe(
        intent_dump={"amount": -1.0},
        violated_invariants=("non_negative",),
        explanation="negative amount",
    )


def _signer_and_verifier(
    ttl: float = 30.0,
    key: bytes | None = None,
) -> tuple[ExecutionTokenSigner, ExecutionTokenVerifier]:
    k = key or _make_key()
    signer = ExecutionTokenSigner(secret_key=k, ttl_seconds=ttl)
    verifier = ExecutionTokenVerifier(secret_key=k)
    return signer, verifier


# ── R1: Direct replay ─────────────────────────────────────────────────────────


class TestDirectReplay:
    def test_R1_first_consume_succeeds(self) -> None:
        """First consume() of a valid token returns True."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision())
        assert verifier.consume(token) is True

    def test_R1_second_consume_always_fails(self) -> None:
        """Replaying the same token always returns False — single-use invariant."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision())
        assert verifier.consume(token) is True
        assert verifier.consume(token) is False

    def test_R1_many_replays_all_fail(self) -> None:
        """100 replay attempts after first consume all return False."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision())
        verifier.consume(token)
        for _ in range(100):
            assert verifier.consume(token) is False

    def test_R1_two_distinct_tokens_same_decision_are_independent(self) -> None:
        """mint() generates a unique token_id per call — two tokens are independent."""
        signer, verifier = _signer_and_verifier()
        decision = _safe_decision()
        t1 = signer.mint(decision)
        t2 = signer.mint(decision)
        assert t1.token_id != t2.token_id
        assert verifier.consume(t1) is True
        assert verifier.consume(t2) is True


# ── R2: Expired token ─────────────────────────────────────────────────────────


class TestExpiredTokenReplay:
    def test_R2_token_with_past_expiry_rejected(self) -> None:
        """A token whose expires_at is in the past is always rejected."""
        key = _make_key()
        frozen_past = time.time() - 60.0
        signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=1.0, clock=lambda: frozen_past)
        verifier = ExecutionTokenVerifier(secret_key=key)
        token = signer.mint(_safe_decision())
        assert token.is_expired()
        assert verifier.consume(token) is False

    def test_R2_expired_token_not_added_to_consumed_set(self) -> None:
        """Expired tokens never enter the consumed registry — no state pollution."""
        key = _make_key()
        past = time.time() - 60.0
        signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=1.0, clock=lambda: past)
        verifier = ExecutionTokenVerifier(secret_key=key)
        token = signer.mint(_safe_decision())
        verifier.consume(token)
        assert token.token_id not in verifier._consumed

    def test_R2_valid_token_not_expired(self) -> None:
        """A freshly minted token with 30s TTL is not expired."""
        signer, verifier = _signer_and_verifier(ttl=30.0)
        token = signer.mint(_safe_decision())
        assert not token.is_expired()
        assert verifier.consume(token) is True


# ── R3/R4/R5: Tampered token fields ──────────────────────────────────────────


class TestTamperedToken:
    def _make_valid_token(self) -> tuple[ExecutionToken, ExecutionTokenVerifier]:
        signer, verifier = _signer_and_verifier()
        return signer.mint(_safe_decision({"amount": 500.0})), verifier

    def test_R3_tampered_decision_id_rejected(self) -> None:
        """Changing decision_id invalidates the HMAC signature."""
        token, verifier = self._make_valid_token()
        tampered = replace(token, decision_id="00000000-0000-0000-0000-000000000000")
        assert verifier.consume(tampered) is False

    def test_R4_tampered_intent_dump_rejected(self) -> None:
        """Changing intent_dump field invalidates the HMAC signature."""
        token, verifier = self._make_valid_token()
        tampered = replace(token, intent_dump={"amount": 9_999_999.0})
        assert verifier.consume(tampered) is False

    def test_R5_explicit_bad_signature_rejected(self) -> None:
        """An explicitly forged signature is rejected."""
        token, verifier = self._make_valid_token()
        tampered = replace(token, signature="a" * 64)
        assert verifier.consume(tampered) is False

    def test_R5_truncated_signature_rejected(self) -> None:
        """Truncated signature string is rejected."""
        token, verifier = self._make_valid_token()
        tampered = replace(token, signature=token.signature[:32])
        assert verifier.consume(tampered) is False

    def test_R5_empty_signature_rejected(self) -> None:
        """Empty signature string is rejected."""
        token, verifier = self._make_valid_token()
        tampered = replace(token, signature="")
        assert verifier.consume(tampered) is False

    def test_tampered_expires_at_rejected(self) -> None:
        """Pushing expires_at far into the future doesn't bypass HMAC check."""
        token, verifier = self._make_valid_token()
        tampered = replace(token, expires_at=time.time() + 86400.0)
        assert verifier.consume(tampered) is False

    def test_tampered_allowed_flag_rejected(self) -> None:
        """Flipping allowed=False to allowed=True doesn't bypass HMAC check."""
        # Mint normally (allowed=True), then flip to False — sig mismatch
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision())
        tampered = replace(token, allowed=False)
        assert verifier.consume(tampered) is False


# ── R6: Wrong verifier key ────────────────────────────────────────────────────


class TestWrongVerifierKey:
    def test_R6_wrong_key_rejects_token(self) -> None:
        """A token signed with key A cannot be consumed by a verifier with key B."""
        key_a = _make_key()
        key_b = _make_key()
        signer = ExecutionTokenSigner(secret_key=key_a)
        verifier = ExecutionTokenVerifier(secret_key=key_b)
        token = signer.mint(_safe_decision())
        assert verifier.consume(token) is False

    def test_R6_correct_key_accepts_token(self) -> None:
        """Sanity check: same key signs and verifies correctly."""
        key = _make_key()
        signer = ExecutionTokenSigner(secret_key=key)
        verifier = ExecutionTokenVerifier(secret_key=key)
        token = signer.mint(_safe_decision())
        assert verifier.consume(token) is True


# ── R7: State-version binding (TOCTOU mitigation) ────────────────────────────


class TestStateVersionBinding:
    def test_R7_matching_state_version_accepted(self) -> None:
        """Token minted with state_version='v1' accepted when v1 matches."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision(), state_version="v1")
        assert verifier.consume(token, expected_state_version="v1") is True

    def test_R7_mismatched_state_version_rejected(self) -> None:
        """Token minted at v1 rejected when executor sees v2 — concurrent mutation."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision(), state_version="v1")
        assert verifier.consume(token, expected_state_version="v2") is False

    def test_R7_token_without_binding_accepted_with_no_expected_version(self) -> None:
        """Token with no state_version accepted when caller also passes None."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision(), state_version=None)
        # Unbound token + no expected_version → version check skipped → accept
        assert verifier.consume(token, expected_state_version=None) is True

    def test_R7_token_without_binding_rejected_when_caller_expects_version(self) -> None:
        """Unbound token is rejected if executor supplies an expected_state_version.

        Contract: if either side sets a state_version, both must agree.
        An unbound token (state_version=None) never agrees with a non-None expected.
        """
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision(), state_version=None)
        assert verifier.consume(token, expected_state_version="v1") is False

    def test_R7_bound_token_rejected_when_no_version_supplied(self) -> None:
        """Token bound to v1 rejected when executor passes no expected version."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision(), state_version="v1")
        assert verifier.consume(token, expected_state_version=None) is False


# ── R8: BLOCK decision tokenisation attempt ───────────────────────────────────


class TestBlockDecisionTokenisation:
    def test_R8_mint_raises_on_blocked_decision(self) -> None:
        """mint() raises ValueError for any decision with allowed=False."""
        signer, _ = _signer_and_verifier()
        blocked = _blocked_decision()
        assert not blocked.allowed
        with pytest.raises(ValueError, match="allowed=True"):
            signer.mint(blocked)

    def test_R8_error_decision_cannot_be_minted(self) -> None:
        """Decision.error() produces allowed=False — mint() must reject it."""
        signer, _ = _signer_and_verifier()
        error_dec = Decision.error(
            reason="z3 crash during verification",
        )
        assert not error_dec.allowed
        with pytest.raises(ValueError):
            signer.mint(error_dec)

    def test_R8_short_key_rejected_at_signer_construction(self) -> None:
        """ExecutionTokenSigner requires at least 16 bytes — short key raises."""
        with pytest.raises(ValueError, match="16 bytes"):
            ExecutionTokenSigner(secret_key=b"tooshort")

    def test_R8_short_key_rejected_at_verifier_construction(self) -> None:
        """ExecutionTokenVerifier requires at least 16 bytes."""
        with pytest.raises(ValueError, match="16 bytes"):
            ExecutionTokenVerifier(secret_key=b"short")


# ── R9: Concurrent replay (thread-safety) ────────────────────────────────────


class TestConcurrentReplay:
    def test_R9_only_one_thread_wins_concurrent_consume(self) -> None:
        """Under concurrent consume() calls for the same token, exactly one wins."""
        signer, verifier = _signer_and_verifier()
        token = signer.mint(_safe_decision())

        results: list[bool] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def _consume() -> None:
            try:
                result = verifier.consume(token)
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=_consume) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Exceptions in threads: {errors}"
        assert results.count(True) == 1, f"Expected exactly 1 True, got: {results}"
        assert results.count(False) == 19, f"Expected 19 False, got: {results}"


# ── R10: Cross-process replay documentation ───────────────────────────────────


class TestCrossProcessReplayLimitation:
    def test_R10_in_memory_verifier_warns_about_multiprocess_gap(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """ExecutionTokenVerifier.__init__ must emit a log about the multi-process gap."""
        import logging

        key = _make_key()
        with caplog.at_level(logging.WARNING, logger="pramanix.execution_token"):
            ExecutionTokenVerifier(secret_key=key)
        assert any(
            "multi-process" in r.message.lower() or "in-memory" in r.message.lower()
            for r in caplog.records
        ), "ExecutionTokenVerifier must warn operators about the in-memory consumed-set limitation"


# ── R11: PersistentMerkleAnchor auto-flush at process exit ────────────────────


class TestMerkleAtexitFlush:
    def test_R11_atexit_handler_registered_on_construction(self) -> None:
        """PersistentMerkleAnchor registers an atexit flush handler at construction."""
        from pramanix.audit.merkle import PersistentMerkleAnchor

        anchor = PersistentMerkleAnchor(checkpoint_every=10)
        assert hasattr(anchor, "_atexit_flush"), "atexit flush handler must be stored on anchor"
        assert callable(anchor._atexit_flush)

    def test_R11_atexit_flush_calls_callback_for_pending_leaves(self) -> None:
        """Simulating process exit flushes leaves not yet checkpointed."""
        from pramanix.audit.merkle import PersistentMerkleAnchor

        flushed: list[tuple[str, int]] = []

        def _callback(root: str, count: int) -> None:
            flushed.append((root, count))

        anchor = PersistentMerkleAnchor(checkpoint_every=100, checkpoint_callback=_callback)
        for i in range(7):
            anchor.add(f"decision-{i:04d}")

        assert not flushed, "No checkpoint yet (7 < 100)"
        anchor._atexit_flush()  # simulate process exit
        assert len(flushed) == 1, "Exactly one checkpoint should fire at exit"
        assert flushed[0][1] == 7, f"Expected leaf count 7, got {flushed[0][1]}"

    def test_R11_atexit_flush_is_idempotent(self) -> None:
        """Calling atexit flush twice does not produce duplicate checkpoints."""
        from pramanix.audit.merkle import PersistentMerkleAnchor

        flushed: list[tuple[str, int]] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=100, checkpoint_callback=lambda r, c: flushed.append((r, c))
        )
        for i in range(5):
            anchor.add(f"id-{i}")

        anchor._atexit_flush()
        anchor._atexit_flush()
        assert len(flushed) == 1, "Second atexit call must not duplicate the checkpoint"

    def test_R11_atexit_flush_noop_when_no_pending_leaves(self) -> None:
        """flush() is a no-op when all leaves are already checkpointed."""
        from pramanix.audit.merkle import PersistentMerkleAnchor

        flushed: list[tuple[str, int]] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=2, checkpoint_callback=lambda r, c: flushed.append((r, c))
        )
        anchor.add("id-0")
        anchor.add("id-1")  # triggers periodic checkpoint (2 == checkpoint_every)
        before = len(flushed)
        anchor._atexit_flush()  # nothing pending
        assert len(flushed) == before, "No extra checkpoint when leaves are already saved"

    def test_R11_atexit_flush_survives_callback_exception(self) -> None:
        """atexit flush suppresses callback exceptions — never propagates to shutdown."""
        from pramanix.audit.merkle import PersistentMerkleAnchor

        def _bad_callback(root: str, count: int) -> None:
            raise RuntimeError("DB connection lost")

        anchor = PersistentMerkleAnchor(checkpoint_every=100, checkpoint_callback=_bad_callback)
        anchor.add("id-0")
        anchor._atexit_flush()  # must not raise
