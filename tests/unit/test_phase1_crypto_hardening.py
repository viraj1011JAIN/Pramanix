# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Phase 1 architectural hardening tests: STOP 1 (seal-key injection) and
STOP 3 (timing side-channel protection).

Verifies:
1. GuardConfig raises ConfigurationError for undersized result_seal_key.
2. GuardConfig raises ConfigurationError in production + async-process when
   result_seal_key is None (cross-pod key isolation bug).
3. GuardConfig raises ConfigurationError in production when min_response_ms==0
   and allow_insecure_timing_leaks is False.
4. allow_insecure_timing_leaks=True suppresses the timing ConfigurationError.
5. _unseal_decision accepts and correctly uses an injected seal_key.
6. _unseal_decision rejects an envelope signed with a different key.
7. WorkerPool defaults seal_key to the module-level _RESULT_SEAL_KEY.bytes.
8. WorkerPool uses an explicitly injected seal_key end-to-end.
9. Nonce replay is still rejected even when seal_key is injected.

Design rules
------------
* No mocks, no stubs, no unittest.mock imports.
* IPC sealing tested via the public functions directly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets

import pytest

from pramanix.exceptions import ConfigurationError


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════


def _make_audit_sink():
    """Return a StdoutAuditSink — not InMemory, safe for production config."""
    from pramanix.audit_sink import StdoutAuditSink

    return StdoutAuditSink()


def _production_base_kwargs(**overrides):
    """Minimum kwargs that pass all other production checks so we can test
    the one we care about in isolation."""
    defaults = {
        "audit_sinks": (_make_audit_sink(),),
        "min_response_ms": 5.0,
        "execution_mode": "sync",
    }
    defaults.update(overrides)
    return defaults


# ══════════════════════════════════════════════════════════════════════════════
# 1. result_seal_key length validation (always enforced, not prod-only)
# ══════════════════════════════════════════════════════════════════════════════


class TestResultSealKeyValidation:
    """GuardConfig validates result_seal_key length unconditionally."""

    def test_key_below_32_bytes_raises(self) -> None:
        from pramanix.guard_config import GuardConfig

        short_key = secrets.token_bytes(16)
        with pytest.raises(ConfigurationError, match="32 bytes"):
            GuardConfig(result_seal_key=short_key)

    def test_key_exactly_1_byte_raises(self) -> None:
        from pramanix.guard_config import GuardConfig

        with pytest.raises(ConfigurationError, match="32 bytes"):
            GuardConfig(result_seal_key=b"\x00")

    def test_key_exactly_32_bytes_accepted(self) -> None:
        from pramanix.guard_config import GuardConfig

        key = secrets.token_bytes(32)
        cfg = GuardConfig(result_seal_key=key)
        assert cfg.result_seal_key == key

    def test_key_64_bytes_accepted(self) -> None:
        from pramanix.guard_config import GuardConfig

        key = secrets.token_bytes(64)
        cfg = GuardConfig(result_seal_key=key)
        assert cfg.result_seal_key == key

    def test_none_key_accepted_in_non_production(self) -> None:
        from pramanix.guard_config import GuardConfig

        cfg = GuardConfig(result_seal_key=None)
        assert cfg.result_seal_key is None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Production + async-process requires result_seal_key (STOP 1)
# ══════════════════════════════════════════════════════════════════════════════


class TestProductionSealKeyRequired:
    """In production, async-process mode requires an explicit seal key."""

    def test_async_process_production_no_key_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="result_seal_key"):
            GuardConfig(
                **_production_base_kwargs(
                    execution_mode="async-process",
                    result_seal_key=None,
                )
            )

    def test_error_message_names_remedy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="secrets manager|KMS|Vault"):
            GuardConfig(
                **_production_base_kwargs(
                    execution_mode="async-process",
                    result_seal_key=None,
                )
            )

    def test_async_process_production_with_key_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        key = secrets.token_bytes(32)
        cfg = GuardConfig(
            **_production_base_kwargs(
                execution_mode="async-process",
                result_seal_key=key,
            )
        )
        assert cfg.result_seal_key == key

    def test_sync_mode_production_no_key_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Seal key is only required for async-process mode."""
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        cfg = GuardConfig(
            **_production_base_kwargs(
                execution_mode="sync",
                result_seal_key=None,
            )
        )
        assert cfg.result_seal_key is None

    def test_async_thread_production_no_key_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """async-thread uses shared memory — no cross-process seal needed."""
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        cfg = GuardConfig(
            **_production_base_kwargs(
                execution_mode="async-thread",
                result_seal_key=None,
            )
        )
        assert cfg.result_seal_key is None

    def test_non_production_async_process_no_key_accepted(self) -> None:
        """Non-production never requires a seal key."""
        from pramanix.guard_config import GuardConfig

        cfg = GuardConfig(execution_mode="async-process", result_seal_key=None)
        assert cfg.result_seal_key is None


# ══════════════════════════════════════════════════════════════════════════════
# 3 & 4. Timing side-channel: min_response_ms in production (STOP 3)
# ══════════════════════════════════════════════════════════════════════════════


class TestProductionTimingProtection:
    """Production requires min_response_ms > 0 unless allow_insecure_timing_leaks."""

    def test_zero_min_response_production_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="min_response_ms"):
            GuardConfig(
                **_production_base_kwargs(
                    execution_mode="sync",
                    min_response_ms=0.0,
                    allow_insecure_timing_leaks=False,
                )
            )

    def test_error_message_describes_attack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.raises(ConfigurationError, match="timing"):
            GuardConfig(
                **_production_base_kwargs(
                    execution_mode="sync",
                    min_response_ms=0.0,
                )
            )

    def test_nonzero_min_response_production_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        cfg = GuardConfig(
            **_production_base_kwargs(
                execution_mode="sync",
                min_response_ms=5.0,
            )
        )
        assert cfg.min_response_ms == 5.0

    def test_allow_insecure_timing_leaks_bypasses_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit opt-in flag suppresses the timing ConfigurationError."""
        from pramanix.guard_config import GuardConfig

        monkeypatch.setenv("PRAMANIX_ENV", "production")
        cfg = GuardConfig(
            **_production_base_kwargs(
                execution_mode="sync",
                min_response_ms=0.0,
                allow_insecure_timing_leaks=True,
            )
        )
        assert cfg.allow_insecure_timing_leaks is True

    def test_zero_min_response_non_production_accepted(self) -> None:
        """Non-production never enforces the timing floor."""
        from pramanix.guard_config import GuardConfig

        cfg = GuardConfig(min_response_ms=0.0)
        assert cfg.min_response_ms == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 5 & 6. _unseal_decision with injected seal_key
# ══════════════════════════════════════════════════════════════════════════════


class TestUnsealDecisionInjectedKey:
    """_unseal_decision correctly uses an injected seal_key."""

    def _build_envelope(self, payload_dict: dict, key: bytes, nonce: str) -> dict:
        """Build a correctly signed envelope using *key*."""
        payload_dict["_nonce"] = nonce
        payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode()
        tag = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return {"_p": payload.decode(), "_t": tag, "_n": nonce}

    def test_injected_key_verifies_own_envelope(self) -> None:
        from pramanix.worker import _unseal_decision

        key = secrets.token_bytes(32)
        nonce = secrets.token_hex(16)
        envelope = self._build_envelope({"allowed": True, "status": "safe"}, key, nonce)
        result = _unseal_decision(envelope, expected_nonce=nonce, seal_key=key)
        assert result["allowed"] is True
        assert "_nonce" not in result

    def test_wrong_injected_key_raises_value_error(self) -> None:
        from pramanix.worker import _unseal_decision

        signing_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        nonce = secrets.token_hex(16)
        envelope = self._build_envelope(
            {"allowed": True, "status": "safe"}, signing_key, nonce
        )
        with pytest.raises(ValueError, match="HMAC mismatch"):
            _unseal_decision(envelope, expected_nonce=nonce, seal_key=wrong_key)

    def test_nonce_mismatch_raises_even_with_correct_key(self) -> None:
        from pramanix.worker import _unseal_decision

        key = secrets.token_bytes(32)
        nonce = secrets.token_hex(16)
        envelope = self._build_envelope({"allowed": True, "status": "safe"}, key, nonce)
        with pytest.raises(ValueError, match="nonce mismatch|replay"):
            _unseal_decision(envelope, expected_nonce="wrong_nonce", seal_key=key)

    def test_none_seal_key_falls_back_to_module_key(self) -> None:
        """seal_key=None falls back to _RESULT_SEAL_KEY — verified round-trip."""
        from pramanix.worker import (
            _RESULT_SEAL_KEY,
            _unseal_decision,
            _worker_solve_sealed,
        )
        from pramanix.policy import Policy
        from pramanix.expressions import E, Field, ConstraintExpr
        from decimal import Decimal

        class _TrivialPolicy(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_neg")]

        nonce = secrets.token_hex(16)
        # Sign with module-level key
        envelope = _worker_solve_sealed(
            _TrivialPolicy,
            {"x": "1"},
            5000,
            _RESULT_SEAL_KEY.bytes,
            0,
            nonce,
        )
        # Verify with seal_key=None (uses module-level key)
        result = _unseal_decision(envelope, expected_nonce=nonce, seal_key=None)
        assert "allowed" in result


# ══════════════════════════════════════════════════════════════════════════════
# 7. WorkerPool.seal_key default
# ══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolSealKeyDefault:
    """WorkerPool defaults seal_key to the module-level _RESULT_SEAL_KEY.bytes."""

    def test_default_seal_key_matches_module_key(self) -> None:
        from pramanix.worker import WorkerPool, _RESULT_SEAL_KEY

        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=100,
            warmup=False,
        )
        assert pool.seal_key == _RESULT_SEAL_KEY.bytes

    def test_explicit_seal_key_overrides_default(self) -> None:
        from pramanix.worker import WorkerPool, _RESULT_SEAL_KEY

        custom_key = secrets.token_bytes(32)
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=100,
            warmup=False,
            seal_key=custom_key,
        )
        assert pool.seal_key == custom_key
        assert pool.seal_key != _RESULT_SEAL_KEY.bytes


# ══════════════════════════════════════════════════════════════════════════════
# 8. Guard passes result_seal_key to WorkerPool
# ══════════════════════════════════════════════════════════════════════════════


class TestGuardSealKeyPropagation:
    """Guard forwards GuardConfig.result_seal_key to its WorkerPool."""

    def test_async_thread_pool_gets_injected_key(self) -> None:
        from decimal import Decimal

        from pramanix import E, Field, Guard, GuardConfig, Policy
        from pramanix.expressions import ConstraintExpr

        class _P(Policy):
            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("n")]

        custom_key = secrets.token_bytes(32)
        guard = Guard(
            _P,
            GuardConfig(
                execution_mode="async-thread",
                result_seal_key=custom_key,
                worker_warmup=False,
            ),
        )
        try:
            assert guard._pool is not None
            assert guard._pool.seal_key == custom_key
        finally:
            import asyncio

            asyncio.run(guard.shutdown())

    def test_sync_mode_pool_is_none(self) -> None:
        from decimal import Decimal

        from pramanix import E, Field, Guard, GuardConfig, Policy
        from pramanix.expressions import ConstraintExpr

        class _P2(Policy):
            y = Field("y", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.y) >= 0).named("n")]

        guard = Guard(_P2, GuardConfig(execution_mode="sync"))
        assert guard._pool is None
