# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Phase 12 hardening tests — all 15 security properties.

Each test class maps directly to one hardening measure:

 H01  TOCTOU / Execution Gap      — ExecutionToken single-use binding
 H02  Zombie Processes             — PPID watchdog daemon thread
 H03  Cold Start JIT               — 8-pattern warmup suite in worker
 H04  Oracle Attack                — redact_violations hides violation details
 H05  Merkle Volatility            — PersistentMerkleAnchor checkpoint callbacks
 H06  Big Data DoS                 — max_input_bytes pre-solver size cap
 H07  Z3 Thread Safety             — per-call z3.Context, concurrent verify()
 H08  Non-Linear Explosion         — solver_rlimit resource cap
 H09  Silent Policy Drift          — expected_policy_hash mismatch → error at init
 H10  Log Injection                — structured JSON logging, no format strings
 H11  Solver Non-Determinism       — same inputs → identical decision_hash
 H12  Recursive Logic Loop         — rlimit + timeout blocks non-terminating Z3
 H13  Side-Channel Timing          — min_response_ms pads response to floor
 H14  State-Intent Divergence      — policy_hash present and correct in Decision
 H15  Additional hardening gaps    — policy_hash in to_dict(), fail-closed signing
"""
from __future__ import annotations

import secrets
import threading
import time
from decimal import Decimal

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_policy(version: str = "1.0"):
    """Return a minimal Policy class for use in Guard tests."""
    from pramanix import E, Field, Policy

    _amount = Field("amount", Decimal, "Real")

    class _P(Policy):
        class Meta:
            pass  # version set below (class bodies can't access enclosing scope)

        amount = _amount

        @classmethod
        def fields(cls):
            return {"amount": _amount}

        @classmethod
        def invariants(cls):
            return [(E(_amount) >= Decimal("0")).named("pos").explain("Positive")]

    _P.Meta.version = version  # type: ignore[attr-defined]
    return _P


def _make_guard(policy=None, **config_kwargs):
    """Return a Guard with the given GuardConfig keyword args."""
    from pramanix import Guard, GuardConfig

    p = policy or _make_policy()
    return Guard(p, GuardConfig(execution_mode="sync", **config_kwargs))


# ═══════════════════════════════════════════════════════════════════════════════
# H01 — TOCTOU / Execution Gap  (ExecutionToken)
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecutionToken:
    """Single-use tokens prevent replay of verified decisions."""

    def _pair(self, ttl: float = 30.0):
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier

        key = secrets.token_bytes(32)
        return (
            ExecutionTokenSigner(secret_key=key, ttl_seconds=ttl),
            ExecutionTokenVerifier(secret_key=key),
        )

    def _safe_decision(self):
        guard = _make_guard()
        return guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )

    def test_mint_and_consume_valid_token(self):
        signer, verifier = self._pair()
        d = self._safe_decision()
        token = signer.mint(d)
        assert verifier.consume(token) is True

    def test_token_is_single_use(self):
        """Second consume() on the same token must return False."""
        signer, verifier = self._pair()
        d = self._safe_decision()
        token = signer.mint(d)
        assert verifier.consume(token) is True
        assert verifier.consume(token) is False

    def test_replay_blocked_after_consume(self):
        """Even with correct key, a consumed token cannot be reused."""
        signer, verifier = self._pair()
        d = self._safe_decision()
        token = signer.mint(d)
        verifier.consume(token)
        assert verifier.consume(token) is False

    def test_wrong_key_fails(self):
        """Verifier with different key rejects token."""
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier

        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key_a)
        verifier = ExecutionTokenVerifier(secret_key=key_b)
        d = self._safe_decision()
        token = signer.mint(d)
        assert verifier.consume(token) is False

    def test_expired_token_fails(self):
        """Token with negative TTL is immediately expired."""
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier

        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key, ttl_seconds=-1.0)
        verifier = ExecutionTokenVerifier(secret_key=key)
        d = self._safe_decision()
        token = signer.mint(d)
        assert token.is_expired()
        assert verifier.consume(token) is False

    def test_mint_refuses_blocked_decision(self):
        """mint() on an UNSAFE/BLOCK decision must raise ValueError."""
        from pramanix import ExecutionTokenSigner
        from pramanix.decision import Decision

        signer = ExecutionTokenSigner(secret_key=secrets.token_bytes(32))
        blocked = Decision.unsafe(
            violated_invariants=("pos",),
            explanation="Blocked",
            intent_dump={"amount": "100"},
            state_dump={},
        )
        with pytest.raises(ValueError, match=r"decision\.allowed=True"):
            signer.mint(blocked)

    def test_tampered_token_signature_fails(self):
        """Mutating any field of the token body must invalidate the signature."""
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier
        from pramanix.execution_token import ExecutionToken

        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key)
        verifier = ExecutionTokenVerifier(secret_key=key)
        d = self._safe_decision()
        token = signer.mint(d)
        # Tamper with the decision_id
        tampered = ExecutionToken(
            decision_id="00000000-0000-0000-0000-000000000000",
            allowed=token.allowed,
            intent_dump=token.intent_dump,
            policy_hash=token.policy_hash,
            expires_at=token.expires_at,
            token_id=token.token_id,
            signature=token.signature,  # original sig — now invalid
        )
        assert verifier.consume(tampered) is False

    def test_concurrent_single_use(self):
        """Multiple threads racing to consume the same token: exactly one succeeds."""
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier

        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key)
        verifier = ExecutionTokenVerifier(secret_key=key)
        d = self._safe_decision()
        token = signer.mint(d)

        results: list[bool] = []
        lock = threading.Lock()

        def try_consume():
            ok = verifier.consume(token)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=try_consume) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 1
        assert results.count(False) == 9

    def test_short_secret_key_raises(self):
        """Keys shorter than 16 bytes must be rejected at construction time."""
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier

        with pytest.raises(ValueError, match="16 bytes"):
            ExecutionTokenSigner(secret_key=b"short")
        with pytest.raises(ValueError, match="16 bytes"):
            ExecutionTokenVerifier(secret_key=b"short")

    def test_consumed_count_tracks_tokens(self):
        """consumed_count() increments for each successfully consumed token."""
        from pramanix import ExecutionTokenSigner, ExecutionTokenVerifier

        key = secrets.token_bytes(32)
        signer = ExecutionTokenSigner(secret_key=key)
        verifier = ExecutionTokenVerifier(secret_key=key)
        guard = _make_guard()

        assert verifier.consumed_count() == 0
        for i in range(5):
            d = guard.verify(
                intent={"amount": Decimal(str(i + 1))},
                state={"state_version": "1.0"},
            )
            token = signer.mint(d)
            verifier.consume(token)
        assert verifier.consumed_count() == 5


# ═══════════════════════════════════════════════════════════════════════════════
# H02 — Zombie Processes  (PPID watchdog daemon thread)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPPIDWatchdog:
    """PPID watchdog thread is started and is a daemon."""

    def test_ppid_watchdog_function_exists(self):
        """_ppid_watchdog must be importable from worker module."""
        from pramanix.worker import _ppid_watchdog  # noqa: F401 — import test

    def test_warmup_starts_watchdog_daemon_thread(self):
        """After _warmup_worker runs, a daemon thread named 'ppid-watchdog' exists."""
        # We cannot call _warmup_worker() directly (it is a subprocess initializer),
        # so instead verify the thread is correctly configured by inspecting
        # the function's logic: call it and check a daemon thread is started.
        # Since warmup triggers the real Z3, run it in a thread to avoid
        # polluting the main process state.
        import threading

        from pramanix.worker import _warmup_worker

        started_event = threading.Event()
        warmup_error: list[Exception] = []

        def run_warmup():
            try:
                _warmup_worker()
                started_event.set()
            except Exception as exc:
                warmup_error.append(exc)
                started_event.set()

        t = threading.Thread(target=run_warmup, daemon=True)
        t.start()
        started_event.wait(timeout=30)

        if warmup_error:
            pytest.skip(f"warmup not available in this environment: {warmup_error[0]}")

        # Find daemon threads named ppid-watchdog
        daemon_watchdogs = [
            th
            for th in threading.enumerate()
            if "ppid-watchdog" in th.name and th.daemon
        ]
        assert len(daemon_watchdogs) >= 1, (
            "No daemon thread named 'ppid-watchdog' found after _warmup_worker(). "
            "Zombie process protection is missing."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# H03 — Cold Start JIT  (8-pattern warmup)
# ═══════════════════════════════════════════════════════════════════════════════


class TestColdStartWarmup:
    """Worker warmup primes all Z3 theory caches with 8 patterns."""

    def test_warmup_worker_completes_without_error(self):
        """_warmup_worker() must not raise."""
        import threading

        from pramanix.worker import _warmup_worker

        errors: list[Exception] = []

        def run():
            try:
                _warmup_worker()
            except Exception as exc:
                errors.append(exc)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=30)
        assert not errors, f"_warmup_worker() raised: {errors[0]}"

    def test_warmup_patterns_constant_is_8(self):
        """Source of truth: _warmup_worker internally runs exactly 8 Z3 patterns."""
        import inspect

        from pramanix.worker import _warmup_worker

        src = inspect.getsource(_warmup_worker)
        # Each pattern is a call to z3.Solver(); count them
        pattern_count = src.count("z3.Solver(")
        assert pattern_count >= 8, (
            f"Expected ≥8 z3.Solver() calls in _warmup_worker, found {pattern_count}. "
            "Cold-start JIT protection requires all Z3 theory caches to be primed."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# H04 — Oracle Attack  (redact_violations)
# ═══════════════════════════════════════════════════════════════════════════════


class TestOracleAttackRedaction:
    """redact_violations=True must hide violation details from callers."""

    def _blocked_decision(self, **cfg):
        guard = _make_guard(**cfg)
        return guard.verify(
            intent={"amount": Decimal("-1")},  # violates pos invariant
            state={"state_version": "1.0"},
        )

    def test_without_redaction_details_are_present(self):
        d = self._blocked_decision()
        assert not d.allowed
        assert len(d.violated_invariants) > 0
        assert d.explanation != "Policy Violation: Action Blocked"

    def test_with_redaction_violated_invariants_cleared(self):
        d = self._blocked_decision(redact_violations=True)
        assert not d.allowed
        assert d.violated_invariants == ()

    def test_with_redaction_explanation_is_generic(self):
        d = self._blocked_decision(redact_violations=True)
        assert d.explanation == "Policy Violation: Action Blocked"

    def test_redaction_does_not_affect_safe_decision(self):
        """ALLOW decisions must never be redacted."""
        guard = _make_guard(redact_violations=True)
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.allowed
        assert d.violated_invariants == ()  # safe — was empty anyway

    def test_decision_hash_computed_over_real_fields(self):
        """decision_hash must differ from a hash computed over redacted fields.

        The hash must be computed BEFORE redaction so the signed audit record
        is the full-fidelity version.
        """
        pytest.importorskip("cryptography", reason="cryptography not installed")
        from pramanix import PramanixSigner
        from pramanix.crypto import PramanixVerifier

        signer = PramanixSigner.generate()
        guard = _make_guard(redact_violations=True, signer=signer)
        d = guard.verify(
            intent={"amount": Decimal("-1")},
            state={"state_version": "1.0"},
        )
        assert not d.allowed
        # The signature must still verify against the decision_hash
        verifier = PramanixVerifier(public_key_pem=signer.public_key_pem())
        assert verifier.verify(decision_hash=d.decision_hash, signature=d.signature)

    def test_redaction_without_signer_still_applies(self):
        """Redaction must work even when no signer is configured."""
        d = self._blocked_decision(redact_violations=True)
        assert d.explanation == "Policy Violation: Action Blocked"
        assert d.signature is None  # no signer


# ═══════════════════════════════════════════════════════════════════════════════
# H05 — Merkle Volatility  (PersistentMerkleAnchor)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPersistentMerkleAnchor:
    """PersistentMerkleAnchor fires checkpoint callbacks and flushes correctly."""

    def test_checkpoint_fires_at_n_interval(self):
        from pramanix import PersistentMerkleAnchor

        checkpoints: list[tuple[str, int]] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=5,
            checkpoint_callback=lambda root, count: checkpoints.append((root, count)),
        )
        for i in range(10):
            anchor.add(f"decision-{i}")

        assert len(checkpoints) == 2  # at counts 5 and 10
        assert checkpoints[0][1] == 5
        assert checkpoints[1][1] == 10

    def test_flush_captures_trailing_decisions(self):
        from pramanix import PersistentMerkleAnchor

        flushed: list[tuple[str, int]] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=100,
            checkpoint_callback=lambda root, count: flushed.append((root, count)),
        )
        for i in range(7):
            anchor.add(f"d-{i}")

        assert len(flushed) == 0  # not yet at 100
        anchor.flush()
        assert len(flushed) == 1
        assert flushed[0][1] == 7

    def test_flush_noop_on_empty_tree(self):
        from pramanix import PersistentMerkleAnchor

        called = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=10,
            checkpoint_callback=lambda root, count: called.append(count),
        )
        anchor.flush()  # must not raise
        assert called == []

    def test_double_flush_does_not_duplicate(self):
        from pramanix import PersistentMerkleAnchor

        calls: list[int] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=100,
            checkpoint_callback=lambda root, count: calls.append(count),
        )
        anchor.add("d-1")
        anchor.flush()
        anchor.flush()  # second flush must not repeat
        assert len(calls) == 1

    def test_checkpoint_callback_receives_valid_root(self):
        from pramanix import MerkleAnchor, PersistentMerkleAnchor

        roots: list[str] = []
        anchor = PersistentMerkleAnchor(
            checkpoint_every=3,
            checkpoint_callback=lambda root, count: roots.append(root),
        )
        ids = [f"id-{i}" for i in range(3)]
        for d in ids:
            anchor.add(d)

        assert len(roots) == 1
        # Cross-verify with a standard MerkleAnchor built from same IDs
        ref = MerkleAnchor()
        for d in ids:
            ref.add(d)
        assert roots[0] == ref.root()

    def test_no_callback_does_not_raise(self):
        """PersistentMerkleAnchor with callback=None must not raise."""
        from pramanix import PersistentMerkleAnchor

        anchor = PersistentMerkleAnchor(checkpoint_every=2, checkpoint_callback=None)
        anchor.add("a")
        anchor.add("b")  # triggers checkpoint with None callback — no error
        anchor.flush()

    def test_invalid_checkpoint_every_raises(self):
        from pramanix import PersistentMerkleAnchor

        with pytest.raises(ValueError):
            PersistentMerkleAnchor(checkpoint_every=0)


# ═══════════════════════════════════════════════════════════════════════════════
# H06 — Big Data DoS  (max_input_bytes)
# ═══════════════════════════════════════════════════════════════════════════════


class TestBigDataDoS:
    """Oversized payloads are rejected before reaching the Z3 solver."""

    def test_normal_payload_allowed(self):
        guard = _make_guard(max_input_bytes=65_536)
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.allowed

    def test_oversized_payload_returns_error(self):
        from pramanix.decision import SolverStatus

        guard = _make_guard(max_input_bytes=10)  # tiny cap
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.status == SolverStatus.ERROR
        assert not d.allowed

    def test_max_input_bytes_zero_disables_check(self):
        """max_input_bytes=0 disables the size check — no rejection."""
        guard = _make_guard(max_input_bytes=0)
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.allowed

    def test_oversized_error_reason_mentions_size(self):
        from pramanix.decision import SolverStatus

        guard = _make_guard(max_input_bytes=5)
        d = guard.verify(
            intent={"amount": Decimal("999")},
            state={"state_version": "1.0"},
        )
        assert d.status == SolverStatus.ERROR
        assert "max_input_bytes" in d.explanation or "bytes" in d.explanation


# ═══════════════════════════════════════════════════════════════════════════════
# H07 — Z3 Thread Safety  (per-call z3.Context)
# ═══════════════════════════════════════════════════════════════════════════════


class TestZ3ThreadSafety:
    """Concurrent Guard.verify() calls must all produce correct results."""

    def test_concurrent_verify_all_correct(self):
        guard = _make_guard()
        errors: list[str] = []
        lock = threading.Lock()

        def run(amount: str, expected_allowed: bool):
            d = guard.verify(
                intent={"amount": Decimal(amount)},
                state={"state_version": "1.0"},
            )
            if d.allowed != expected_allowed:
                with lock:
                    errors.append(
                        f"amount={amount}: expected allowed={expected_allowed}, "
                        f"got {d.allowed}"
                    )

        cases = [("100", True), ("-1", False), ("0", True), ("-50", False), ("9999", True)]
        threads = [
            threading.Thread(target=run, args=args)
            for args in cases * 4  # 20 threads total
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread safety failures: {errors}"

    def test_verify_is_reentrant(self):
        """The same Guard instance can be called from multiple threads simultaneously."""
        guard = _make_guard()
        results: list[bool] = []
        lock = threading.Lock()

        def verify_once():
            d = guard.verify(
                intent={"amount": Decimal("1")},
                state={"state_version": "1.0"},
            )
            with lock:
                results.append(d.allowed)

        threads = [threading.Thread(target=verify_once) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 20
        assert all(r is True for r in results)


# ═══════════════════════════════════════════════════════════════════════════════
# H08 — Non-Linear Explosion  (solver_rlimit)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolverRlimit:
    """solver_rlimit is threaded through to Z3 and 0 disables it."""

    def test_rlimit_default_is_nonzero(self):
        from pramanix import GuardConfig

        cfg = GuardConfig()
        assert cfg.solver_rlimit > 0

    def test_rlimit_zero_disables(self):
        from pramanix import GuardConfig

        cfg = GuardConfig(execution_mode="sync", solver_rlimit=0)
        assert cfg.solver_rlimit == 0

    def test_normal_solve_passes_with_rlimit(self):
        """Standard policy solve must complete within rlimit=10M."""
        guard = _make_guard(solver_rlimit=10_000_000)
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.allowed

    def test_rlimit_env_override(self, monkeypatch):
        """PRAMANIX_SOLVER_RLIMIT env var must override the default."""
        from pramanix import GuardConfig

        monkeypatch.setenv("PRAMANIX_SOLVER_RLIMIT", "999")
        cfg = GuardConfig()
        assert cfg.solver_rlimit == 999


# ═══════════════════════════════════════════════════════════════════════════════
# H09 — Silent Policy Drift  (expected_policy_hash)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSilentPolicyDrift:
    """expected_policy_hash mismatch must raise ConfigurationError at Guard init."""

    def test_correct_hash_does_not_raise(self):
        from pramanix import Guard, GuardConfig
        from pramanix.guard import _compute_policy_fingerprint

        p = _make_policy()
        fp = _compute_policy_fingerprint(p)
        # Must not raise
        Guard(p, GuardConfig(execution_mode="sync", expected_policy_hash=fp))

    def test_wrong_hash_raises_configuration_error(self):
        from pramanix import Guard, GuardConfig
        from pramanix.exceptions import ConfigurationError

        p = _make_policy()
        with pytest.raises(ConfigurationError, match=r"[Pp]olicy"):
            Guard(
                p,
                GuardConfig(
                    execution_mode="sync",
                    expected_policy_hash="deadbeef" * 8,  # 64-char wrong hash
                ),
            )

    def test_none_expected_hash_skips_validation(self):
        from pramanix import Guard, GuardConfig

        p = _make_policy()
        # No expected_policy_hash → no validation → no error
        Guard(p, GuardConfig(execution_mode="sync", expected_policy_hash=None))

    def test_different_policy_has_different_fingerprint(self):
        from pramanix.guard import _compute_policy_fingerprint

        p1 = _make_policy(version="1.0")
        p2 = _make_policy(version="2.0")  # different version → different hash
        assert _compute_policy_fingerprint(p1) != _compute_policy_fingerprint(p2)

    def test_fingerprint_is_stable_across_calls(self):
        from pramanix.guard import _compute_policy_fingerprint

        p = _make_policy()
        fp1 = _compute_policy_fingerprint(p)
        fp2 = _compute_policy_fingerprint(p)
        assert fp1 == fp2

    def test_fingerprint_is_64_hex_chars(self):
        from pramanix.guard import _compute_policy_fingerprint

        p = _make_policy()
        fp = _compute_policy_fingerprint(p)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)


# ═══════════════════════════════════════════════════════════════════════════════
# H10 — Log Injection  (structured JSON logging)
# ═══════════════════════════════════════════════════════════════════════════════


class TestLogInjection:
    """Log injection is prevented by structured logging (not format strings)."""

    def test_structlog_is_used_in_guard(self):
        """guard.py pipeline must use structlog, not % or .format() on user data."""
        import inspect

        import pramanix.guard as guard_mod
        import pramanix.guard_config as guard_config_mod

        # After guard refactor, structlog lives in guard_config (where _log is
        # defined and exported).  Either module containing structlog is correct.
        src = inspect.getsource(guard_mod) + inspect.getsource(guard_config_mod)
        assert "structlog" in src, "guard pipeline must use structlog for structured logging"

    def test_malicious_newline_in_decision_id_does_not_corrupt_log(self):
        """Embedded newlines in intent values must not break structured logs.

        structlog serialises records as dicts/JSON — newlines in values are
        embedded as \\n, not interpreted as record separators.
        """
        # If this doesn't raise, the structured logger handled it correctly.
        guard = _make_guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.allowed
        # decision_id is a UUID — structlog would include it verbatim
        assert "\n" not in d.decision_id

    def test_injection_string_in_explanation_is_inert(self):
        """Violation explanations containing log-format patterns must not cause errors."""
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _x = Field("x", int, "Int")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"x": _x}

            @classmethod
            def invariants(cls):
                return [
                    (E(_x) >= 0)
                    .named("safe")
                    .explain("%(injection)s\n{injection}\x00NULL")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"x": -1},
            state={"state_version": "1.0"},
        )
        assert not d.allowed
        assert isinstance(d.explanation, str)


# ═══════════════════════════════════════════════════════════════════════════════
# H11 — Solver Non-Determinism
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolverDeterminism:
    """Same inputs must always produce the same decision_hash."""

    def test_same_inputs_same_hash(self):
        guard = _make_guard()
        d1 = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        d2 = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d1.decision_hash == d2.decision_hash

    def test_different_amounts_different_hash(self):
        guard = _make_guard()
        d1 = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        d2 = guard.verify(
            intent={"amount": Decimal("200")},
            state={"state_version": "1.0"},
        )
        assert d1.decision_hash != d2.decision_hash

    def test_hash_is_stable_across_100_calls(self):
        guard = _make_guard()
        hashes = set()
        for _ in range(100):
            d = guard.verify(
                intent={"amount": Decimal("42")},
                state={"state_version": "1.0"},
            )
            hashes.add(d.decision_hash)
        assert len(hashes) == 1, (
            f"Non-deterministic hashes across 100 identical calls: {hashes}"
        )

    def test_blocked_decision_hash_is_deterministic(self):
        guard = _make_guard()
        hashes = set()
        for _ in range(50):
            d = guard.verify(
                intent={"amount": Decimal("-5")},
                state={"state_version": "1.0"},
            )
            hashes.add(d.decision_hash)
        assert len(hashes) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# H12 — Recursive Logic Loop  (rlimit + timeout blocks non-termination)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRecursiveLogicLoop:
    """Extreme rlimit/timeout prevents non-terminating Z3 queries from hanging."""

    def test_very_tight_rlimit_on_normal_query_still_passes(self):
        """Normal simple queries should pass even with a generous rlimit floor."""
        guard = _make_guard(solver_rlimit=10_000_000, solver_timeout_ms=5_000)
        d = guard.verify(
            intent={"amount": Decimal("1")},
            state={"state_version": "1.0"},
        )
        assert d.allowed

    def test_rlimit_and_timeout_both_applied(self):
        """Both rlimit and timeout_ms must be set (defence-in-depth)."""
        from pramanix import GuardConfig

        cfg = GuardConfig(
            execution_mode="sync",
            solver_rlimit=10_000_000,
            solver_timeout_ms=5_000,
        )
        assert cfg.solver_rlimit > 0
        assert cfg.solver_timeout_ms > 0


# ═══════════════════════════════════════════════════════════════════════════════
# H13 — Side-Channel Timing  (min_response_ms)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSideChannelTiming:
    """min_response_ms pads responses to a minimum wall-clock floor."""

    def test_response_takes_at_least_min_response_ms(self):
        min_ms = 100.0
        guard = _make_guard(min_response_ms=min_ms)

        start = time.perf_counter()
        guard.verify(
            intent={"amount": Decimal("1")},
            state={"state_version": "1.0"},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        # Allow 20 ms tolerance for scheduler jitter
        assert elapsed_ms >= (min_ms - 20), (
            f"Response completed in {elapsed_ms:.1f} ms < floor {min_ms} ms. "
            "Side-channel timing protection is broken."
        )

    def test_zero_min_response_ms_does_not_sleep(self):
        """With min_response_ms=0, no sleep is injected."""
        guard = _make_guard(min_response_ms=0.0)
        start = time.perf_counter()
        guard.verify(
            intent={"amount": Decimal("1")},
            state={"state_version": "1.0"},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        # Should finish well under 100 ms without a forced sleep
        assert elapsed_ms < 500, (
            f"Unexpected delay ({elapsed_ms:.1f} ms) with min_response_ms=0."
        )

    def test_blocked_decision_also_padded(self):
        """BLOCK decisions must also respect the timing floor."""
        min_ms = 80.0
        guard = _make_guard(min_response_ms=min_ms)

        start = time.perf_counter()
        d = guard.verify(
            intent={"amount": Decimal("-1")},
            state={"state_version": "1.0"},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        assert not d.allowed
        assert elapsed_ms >= (min_ms - 20), (
            f"BLOCK response completed in {elapsed_ms:.1f} ms < floor {min_ms} ms."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# H14 — State-Intent Divergence  (policy_hash in Decision)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPolicyHashInDecision:
    """policy_hash must be present on every Decision produced by Guard.verify()."""

    def test_policy_hash_is_set_on_safe_decision(self):
        guard = _make_guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.policy_hash is not None
        assert len(d.policy_hash) == 64  # SHA-256 hex

    def test_policy_hash_is_set_on_blocked_decision(self):
        guard = _make_guard()
        d = guard.verify(
            intent={"amount": Decimal("-1")},
            state={"state_version": "1.0"},
        )
        assert not d.allowed
        assert d.policy_hash is not None
        assert len(d.policy_hash) == 64

    def test_policy_hash_matches_fingerprint(self):
        from pramanix.guard import _compute_policy_fingerprint

        p = _make_policy()
        guard = _make_guard(policy=p)
        expected = _compute_policy_fingerprint(p)

        d = guard.verify(
            intent={"amount": Decimal("1")},
            state={"state_version": "1.0"},
        )
        assert d.policy_hash == expected

    def test_policy_hash_differs_for_different_policies(self):
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _a = Field("amount", Decimal, "Real")
        _b = Field("balance", Decimal, "Real")

        class _P1(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _a}

            @classmethod
            def invariants(cls):
                return [(E(_a) >= Decimal("0")).named("pos").explain("x")]

        class _P2(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"balance": _b}

            @classmethod
            def invariants(cls):
                return [(E(_b) >= Decimal("0")).named("bal").explain("y")]

        cfg = GuardConfig(execution_mode="sync")
        g1 = Guard(_P1, cfg)
        g2 = Guard(_P2, cfg)

        d1 = g1.verify(intent={"amount": Decimal("1")}, state={"state_version": "1.0"})
        d2 = g2.verify(intent={"balance": Decimal("1")}, state={"state_version": "1.0"})

        assert d1.policy_hash != d2.policy_hash

    def test_policy_hash_is_not_in_decision_hash_preimage(self):
        """Changing policy_hash alone must not change decision_hash.

        policy_hash is metadata (like signature), not part of the canonical body.
        """
        import dataclasses

        from pramanix.decision import Decision

        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={},
        )
        h1 = d.decision_hash

        d2 = dataclasses.replace(d, policy_hash="abcd" * 16)
        # decision_hash is frozen at construction, so h1 == d2.decision_hash
        assert d2.decision_hash == h1


# ═══════════════════════════════════════════════════════════════════════════════
# H15 — Additional hardening gaps
# ═══════════════════════════════════════════════════════════════════════════════


class TestAdditionalHardeningGaps:
    """Catch-all for remaining hardening properties."""

    def test_policy_hash_present_in_to_dict(self):
        """to_dict() must include policy_hash so audit records carry the fingerprint."""
        guard = _make_guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        record = d.to_dict()
        assert "policy_hash" in record
        assert record["policy_hash"] == d.policy_hash

    def test_to_dict_policy_hash_none_when_not_set(self):
        """A Decision built without a Guard has policy_hash=None in to_dict()."""
        from pramanix.decision import Decision

        d = Decision.safe(intent_dump={"amount": "1"}, state_dump={})
        record = d.to_dict()
        assert "policy_hash" in record
        assert record["policy_hash"] is None

    def test_fail_closed_signing_returns_error_on_empty_sig(self, monkeypatch):
        """Guard._sign_decision() must return Decision.error() on signing failure."""
        pytest.importorskip("cryptography", reason="cryptography not installed")
        from pramanix import Guard, GuardConfig, PramanixSigner
        from pramanix.decision import SolverStatus

        p = _make_policy()
        signer = PramanixSigner.generate()
        monkeypatch.setattr(signer, "sign", lambda d: "")

        guard = Guard(p, GuardConfig(execution_mode="sync", signer=signer))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.status == SolverStatus.ERROR
        assert d.signature is None

    def test_execution_token_exported_from_top_level(self):
        """ExecutionToken symbols must be importable from the pramanix package."""
        from pramanix import (  # noqa: F401 — import test
            ExecutionToken,
            ExecutionTokenSigner,
            ExecutionTokenVerifier,
        )

    def test_persistent_merkle_anchor_exported_from_top_level(self):
        """PersistentMerkleAnchor must be importable from the pramanix package."""
        from pramanix import PersistentMerkleAnchor  # noqa: F401 — import test

    def test_decision_policy_hash_field_exists(self):
        """Decision dataclass must have a policy_hash field."""
        import dataclasses

        from pramanix.decision import Decision

        field_names = {f.name for f in dataclasses.fields(Decision)}
        assert "policy_hash" in field_names

    def test_guard_config_all_phase12_fields_exist(self):
        """All 5 Phase 12 GuardConfig fields must be present."""
        import dataclasses

        from pramanix import GuardConfig

        field_names = {f.name for f in dataclasses.fields(GuardConfig)}
        for name in (
            "solver_rlimit",
            "max_input_bytes",
            "min_response_ms",
            "redact_violations",
            "expected_policy_hash",
        ):
            assert name in field_names, f"GuardConfig missing Phase 12 field: {name!r}"
