# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Adversarial tests — DistributedCircuitBreaker backend failure scenarios.

Uses only real implementations: real Guard+Policy, real InMemoryDistributedBackend
with direct state injection, and real RedisDistributedBackend pointed at an
unreachable port for genuine connection-failure paths.

INVARIANT: A distributed backend failure can NEVER cause the circuit breaker
           to silently ALLOW traffic. Failures produce conservative OPEN
           outcomes (fail-safe) or are logged and local state prevails.

Failure scenarios:
  CB-1  Backend unreachable (get_state raises)  → fail-safe OPEN, guard not called
  CB-2  Corrupted state from backend            → unknown state → fail-safe OPEN
  CB-3  No explicit backend at construction     → ConfigurationError raised
  CB-4  OPEN state pre-seeded                   → guard not invoked
  CB-5  ISOLATED state pre-seeded               → guard not invoked
  CB-6  CLOSED baseline                         → guard invoked normally
  CB-7  Pressure accumulation                   → real Z3 solve time exceeds threshold
  CB-8  State isolation across namespaces        → two breakers don't interfere
"""

from __future__ import annotations

import socket
from decimal import Decimal

import pytest

from pramanix.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitState,
    DistributedCircuitBreaker,
    InMemoryDistributedBackend,
    _DistributedState,
)
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Shared real policy + guard ────────────────────────────────────────────────


class _SimplePolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative_amount")]


_GUARD = Guard(_SimplePolicy, GuardConfig(execution_mode="async-thread"))
_ALLOW_INTENT = {"amount": Decimal("50")}
_BLOCK_INTENT = {"amount": Decimal("-1")}
_STATE = {}


def _find_free_port() -> int:
    """Bind to port 0 and immediately close — returns a port that was free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_breaker(
    backend: object,
    *,
    namespace: str,
    pressure_threshold_ms: float = 10_000.0,
    consecutive: int = 3,
) -> DistributedCircuitBreaker:
    config = CircuitBreakerConfig(
        namespace=namespace,
        pressure_threshold_ms=pressure_threshold_ms,
        consecutive_pressure_count=consecutive,
    )
    return DistributedCircuitBreaker(_GUARD, config=config, backend=backend)


# ── CB-1: Backend unreachable → fail-safe OPEN ────────────────────────────────


class TestBackendUnreachable:
    def _unreachable_backend(self) -> object:
        """Real RedisDistributedBackend with a pre-configured client pointed at an
        unused port — produces a genuine ConnectionRefusedError on first use."""
        import redis.asyncio as aioredis

        from pramanix.circuit_breaker import RedisDistributedBackend

        port = _find_free_port()
        client = aioredis.from_url(
            f"redis://127.0.0.1:{port}",
            decode_responses=True,
            socket_connect_timeout=0.05,
            socket_timeout=0.05,
        )
        return RedisDistributedBackend(redis_client=client)

    @pytest.mark.asyncio
    async def test_CB1_get_state_failure_returns_block_decision(self) -> None:
        """When Redis is unreachable, verify_async returns BLOCK (fail-safe OPEN)."""
        breaker = _make_breaker(self._unreachable_backend(), namespace="cb1_fail_ns")
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        assert not decision.allowed, "Backend failure must produce fail-safe BLOCK"

    @pytest.mark.asyncio
    async def test_CB1_multiple_failures_all_block(self) -> None:
        """Repeated backend failures always return BLOCK — never ALLOW."""
        breaker = _make_breaker(self._unreachable_backend(), namespace="cb1_multi_ns")
        for _ in range(3):
            decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
            assert not decision.allowed

    @pytest.mark.asyncio
    async def test_CB1_backend_failure_logged_as_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Backend failure emits an ERROR log mentioning the namespace."""
        import logging

        breaker = _make_breaker(self._unreachable_backend(), namespace="cb1_log_ns")
        with caplog.at_level(logging.ERROR, logger="pramanix.circuit_breaker"):
            await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)

        assert any(
            r.levelno >= logging.ERROR for r in caplog.records
        ), "Backend unreachable must log at ERROR level"


# ── CB-2: Corrupted state from backend → fail-safe OPEN ───────────────────────


class TestCorruptedBackendState:
    @pytest.mark.asyncio
    async def test_CB2_unknown_state_string_treated_as_open(self) -> None:
        """Corrupted state string not in CircuitState enum → fail-safe OPEN."""
        ns = "cb2_corrupt_ns"
        InMemoryDistributedBackend.clear(ns)
        # Directly inject a state that is not a valid CircuitState value.
        InMemoryDistributedBackend._store[ns] = _DistributedState(
            circuit_state="CORRUPTED_STATE_INJECTION",
            failure_count=0,
        )
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        InMemoryDistributedBackend.clear(ns)
        assert (
            not decision.allowed
        ), "Unknown state value must fail-safe to OPEN — never allow traffic"

    @pytest.mark.asyncio
    async def test_CB2_corrupted_state_logged_as_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Corrupted backend state emits a WARNING so operators can investigate."""
        import logging

        ns = "cb2_warn_ns"
        InMemoryDistributedBackend.clear(ns)
        InMemoryDistributedBackend._store[ns] = _DistributedState(
            circuit_state="TOTALLY_INVALID",
            failure_count=0,
        )
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)
        with caplog.at_level(logging.WARNING, logger="pramanix.circuit_breaker"):
            await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        InMemoryDistributedBackend.clear(ns)
        assert any(
            "unknown" in r.message.lower() for r in caplog.records if r.levelno >= logging.WARNING
        ), "Corrupted state must generate a WARNING or ERROR log"


# ── CB-3: No explicit backend raises ConfigurationError ───────────────────────


class TestMissingBackend:
    def test_CB3_none_backend_raises_configuration_error(self) -> None:
        """Omitting backend= raises ConfigurationError at construction time."""
        from pramanix.exceptions import ConfigurationError

        config = CircuitBreakerConfig(namespace="no_backend_ns")
        with pytest.raises(ConfigurationError, match="explicit backend"):
            DistributedCircuitBreaker(_GUARD, config=config, backend=None)


# ── CB-4: OPEN state pre-seeded → guard not invoked ───────────────────────────


class TestOpenStateBlocks:
    @pytest.mark.asyncio
    async def test_CB4_open_state_returns_block_without_guard(self) -> None:
        """OPEN state in backend blocks immediately — guard is never invoked."""
        ns = "cb4_open_ns"
        InMemoryDistributedBackend.clear(ns)
        await InMemoryDistributedBackend.set_state(
            ns,
            _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=5),
        )
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)

        # Track whether verify_async on the real guard is ever called by
        # checking the guard's coverage counter before and after.
        before = _GUARD.coverage_report().total_verifications
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        after = _GUARD.coverage_report().total_verifications
        InMemoryDistributedBackend.clear(ns)

        assert not decision.allowed
        assert after == before, "Guard.verify_async must not be called when circuit is OPEN"

    @pytest.mark.asyncio
    async def test_CB4_open_decision_has_meaningful_error_message(self) -> None:
        """The OPEN block decision includes the namespace so operators can identify it."""
        ns = "cb4_msg_ns"
        InMemoryDistributedBackend.clear(ns)
        await InMemoryDistributedBackend.set_state(
            ns, _DistributedState(circuit_state=CircuitState.OPEN.value)
        )
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        InMemoryDistributedBackend.clear(ns)
        assert not decision.allowed
        assert ns in (
            decision.explanation or ""
        ), f"OPEN decision explanation must mention namespace {ns!r}"


# ── CB-5: ISOLATED state pre-seeded → guard not invoked ───────────────────────


class TestIsolatedStateBlocks:
    @pytest.mark.asyncio
    async def test_CB5_isolated_state_returns_block_without_guard(self) -> None:
        """ISOLATED state blocks immediately — manual reset required."""
        ns = "cb5_isolated_ns"
        InMemoryDistributedBackend.clear(ns)
        await InMemoryDistributedBackend.set_state(
            ns,
            _DistributedState(circuit_state=CircuitState.ISOLATED.value, failure_count=20),
        )
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)

        before = _GUARD.coverage_report().total_verifications
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        after = _GUARD.coverage_report().total_verifications
        InMemoryDistributedBackend.clear(ns)

        assert not decision.allowed
        assert after == before, "Guard must not run when circuit is ISOLATED"


# ── CB-6: CLOSED baseline — guard invoked normally ────────────────────────────


class TestClosedBaselinePath:
    @pytest.mark.asyncio
    async def test_CB6_closed_state_invokes_guard_and_allows(self) -> None:
        """In CLOSED state, verify_async delegates to the real Guard — ALLOW returned.

        An ALLOW decision can ONLY originate from the Guard (the circuit breaker
        itself only ever blocks). So decision.allowed=True proves the Guard ran.
        """
        ns = "cb6_closed_ns"
        InMemoryDistributedBackend.clear(ns)
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        InMemoryDistributedBackend.clear(ns)

        assert decision.allowed, (
            "CLOSED breaker + valid intent must produce ALLOW — "
            "only the guard can grant ALLOW, so this proves the guard ran"
        )

    @pytest.mark.asyncio
    async def test_CB6_closed_state_blocks_invalid_intent(self) -> None:
        """In CLOSED state, the real Guard blocks invalid intent."""
        ns = "cb6_block_ns"
        InMemoryDistributedBackend.clear(ns)
        breaker = _make_breaker(InMemoryDistributedBackend, namespace=ns)
        decision = await breaker.verify_async(intent=_BLOCK_INTENT, state=_STATE)
        InMemoryDistributedBackend.clear(ns)
        assert not decision.allowed, "Negative amount must be blocked by real Z3 policy"


# ── CB-7: Pressure accumulation → real Z3 solve drives state ──────────────────


class TestPressureAccumulation:
    @pytest.mark.asyncio
    async def test_CB7_threshold_zero_trips_after_consecutive_solves(self) -> None:
        """With pressure_threshold_ms=0.0 every real Z3 solve registers as pressure."""
        ns = "cb7_pressure_ns"
        InMemoryDistributedBackend.clear(ns)
        # threshold=0.0 means every solve exceeds the threshold; 2 consecutive trips OPEN
        config = CircuitBreakerConfig(
            namespace=ns,
            pressure_threshold_ms=0.0,
            consecutive_pressure_count=2,
        )
        breaker = DistributedCircuitBreaker(
            _GUARD, config=config, backend=InMemoryDistributedBackend
        )
        # Two solves always take > 0ms → both register as pressure
        await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        # Third call should see OPEN state
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        InMemoryDistributedBackend.clear(ns)
        assert not decision.allowed, "After consecutive pressure solves, circuit must trip to OPEN"


# ── CB-8: State isolation across namespaces ───────────────────────────────────


class TestNamespaceIsolation:
    @pytest.mark.asyncio
    async def test_CB8_open_in_ns_a_does_not_affect_ns_b(self) -> None:
        """OPEN state in namespace A must not bleed into namespace B."""
        ns_a = "cb8_ns_a"
        ns_b = "cb8_ns_b"
        InMemoryDistributedBackend.clear(ns_a)
        InMemoryDistributedBackend.clear(ns_b)

        await InMemoryDistributedBackend.set_state(
            ns_a, _DistributedState(circuit_state=CircuitState.OPEN.value)
        )

        breaker_a = _make_breaker(InMemoryDistributedBackend, namespace=ns_a)
        breaker_b = _make_breaker(InMemoryDistributedBackend, namespace=ns_b)

        d_a = await breaker_a.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        d_b = await breaker_b.verify_async(intent=_ALLOW_INTENT, state=_STATE)

        InMemoryDistributedBackend.clear(ns_a)
        InMemoryDistributedBackend.clear(ns_b)

        assert not d_a.allowed, "Namespace A must be OPEN (was set)"
        assert d_b.allowed, "Namespace B must be CLOSED and allow traffic"
