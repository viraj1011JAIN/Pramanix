# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Adaptive Circuit Breaker for Z3 solver pressure management.

State machine:
    CLOSED → OPEN → HALF_OPEN → CLOSED (recovery)
    3 consecutive OPEN episodes → ISOLATED (manual reset required)

CLOSED:    Normal operation. Z3 solves normally.
OPEN:      Pressure detected. Returns failsafe Decision.
           Emits Prometheus gauge: pramanix_circuit_state{state="open"} 1
HALF_OPEN: Probe mode. One test solve after recovery_seconds.
           Success → CLOSED. Failure → OPEN.
ISOLATED:  Manual reset() required. All requests BLOCK.
           Emits Prometheus gauge: pramanix_circuit_state{state="isolated"} 1

Usage:
    breaker = AdaptiveCircuitBreaker(
        guard=guard,
        config=CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            namespace="banking",
        )
    )
    decision = await breaker.verify_async(intent=intent, state=state)
    # Prometheus: pramanix_circuit_state{namespace="banking", state="closed"} 1
"""
from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from pramanix.decision import Decision

log = logging.getLogger(__name__)


class CircuitState(enum.StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"
    ISOLATED = "isolated"


class FailsafeMode(enum.StrEnum):
    BLOCK_ALL = "block_all"
    ALLOW_WITH_AUDIT = "allow_with_audit"
    """.. deprecated::
        ``ALLOW_WITH_AUDIT`` is an alias for ``BLOCK_ALL`` and will be removed
        in a future version.  The circuit breaker is **always fail-closed** —
        returning ``allowed=True`` without Z3 verification would violate the
        SDK's core safety contract.  Setting this mode emits a
        :exc:`DeprecationWarning` at :class:`CircuitBreakerConfig` construction
        time.  Migrate to ``FailsafeMode.BLOCK_ALL``.
    """


@dataclass
class CircuitBreakerConfig:
    pressure_threshold_ms: float = 40.0
    consecutive_pressure_count: int = 5
    recovery_seconds: float = 30.0
    isolation_threshold: int = 3
    failsafe_mode: FailsafeMode = FailsafeMode.BLOCK_ALL
    namespace: str = "default"

    def __post_init__(self) -> None:
        if self.failsafe_mode is FailsafeMode.ALLOW_WITH_AUDIT:
            import warnings

            warnings.warn(
                "CircuitBreakerConfig.failsafe_mode=ALLOW_WITH_AUDIT is deprecated "
                "and behaves identically to BLOCK_ALL.  The circuit breaker is "
                "always fail-closed — allowing requests without Z3 verification "
                "would violate Pramanix's core safety contract.  "
                "Migrate to FailsafeMode.BLOCK_ALL.",
                DeprecationWarning,
                stacklevel=2,
            )


@dataclass
class CircuitBreakerStatus:
    state: CircuitState
    consecutive_pressure: int
    open_episodes: int
    last_transition: float
    namespace: str


class AdaptiveCircuitBreaker:
    """Wraps Guard with adaptive Z3 pressure management.

    The circuit breaker monitors solver_time_ms on every decision.
    When pressure is detected (consecutive slow solves), it opens
    and returns a failsafe Decision without invoking Z3. This gives
    the solver time to recover while keeping the system responsive.

    All state transitions emit Prometheus metrics if prometheus_client
    is installed. If not installed, metrics are silently skipped.
    """

    def __init__(
        self,
        guard: Any,
        config: CircuitBreakerConfig | None = None,
    ) -> None:
        self._guard = guard
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._consecutive_pressure = 0
        self._open_episodes = 0
        self._last_transition = time.monotonic()
        self._lock = asyncio.Lock()
        self._metrics_available = False
        self._state_gauge: Any = None
        self._pressure_counter: Any = None
        self._register_metrics()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def status(self) -> CircuitBreakerStatus:
        return CircuitBreakerStatus(
            state=self._state,
            consecutive_pressure=self._consecutive_pressure,
            open_episodes=self._open_episodes,
            last_transition=self._last_transition,
            namespace=self._config.namespace,
        )

    def verify_sync(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Decision:
        """Blocking synchronous wrapper around :meth:`verify_async`.

        Use this only in synchronous (non-async) codebases.  If called from
        within a running asyncio event loop, raises
        :exc:`~pramanix.exceptions.ConfigurationError` directing the caller
        to use :meth:`verify_async` instead.

        Args:
            intent: Intent dict passed to the underlying Guard.
            state:  State dict passed to the underlying Guard.

        Returns:
            :class:`~pramanix.decision.Decision` from the underlying Guard.

        Raises:
            ConfigurationError: If called from within a running event loop.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "AdaptiveCircuitBreaker.verify_sync() cannot be called from within "
                "a running asyncio event loop.  Use verify_async() instead."
            )
        return asyncio.run(self.verify_async(intent=intent, state=state))

    async def verify_async(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Decision:
        """Verify with circuit breaker protection.

        CLOSED:    delegates to guard.verify_async
        OPEN:      returns failsafe Decision, guard NOT called
        HALF_OPEN: one probe, success → CLOSED, failure → OPEN
        ISOLATED:  always BLOCK, requires manual reset()
        """
        async with self._lock:
            current_state = self._state

        if current_state == CircuitState.ISOLATED:
            return self._make_isolated_decision()

        if current_state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_transition
            if elapsed >= self._config.recovery_seconds:
                async with self._lock:
                    if self._state == CircuitState.OPEN:
                        self._transition(CircuitState.HALF_OPEN)
            else:
                return self._make_open_decision()

        t0 = time.monotonic()
        decision = await self._guard.verify_async(intent=intent, state=state)
        solve_ms = (time.monotonic() - t0) * 1000

        async with self._lock:
            self._record_solve(solve_ms)

        return decision  # type: ignore[no-any-return]

    def reset(self) -> None:
        """Manual reset from ISOLATED. Requires human acknowledgment."""
        self._state = CircuitState.CLOSED
        self._consecutive_pressure = 0
        self._open_episodes = 0
        self._last_transition = time.monotonic()
        self._update_prometheus()
        log.warning(
            "Circuit breaker manually reset from ISOLATED",
            extra={"namespace": self._config.namespace},
        )

    def _record_solve(self, solve_ms: float) -> None:
        """Update state machine. Called under lock."""
        threshold = self._config.pressure_threshold_ms

        if self._state == CircuitState.HALF_OPEN:
            if solve_ms <= threshold:
                self._transition(CircuitState.CLOSED)
                log.info("Circuit breaker recovered: HALF_OPEN → CLOSED")
            else:
                self._open_episodes += 1
                self._consecutive_pressure = 0
                if self._open_episodes >= self._config.isolation_threshold:
                    self._transition(CircuitState.ISOLATED)
                    log.critical(
                        "Circuit breaker ISOLATED after %d open episodes", self._open_episodes
                    )
                else:
                    self._transition(CircuitState.OPEN)
                    log.error("Circuit breaker probe failed: HALF_OPEN → OPEN")
            return

        if solve_ms > threshold:
            self._consecutive_pressure += 1
            self._increment_pressure_metric()
            log.warning(
                "Z3 pressure: solve_ms=%.1f threshold=%.1f consecutive=%d",
                solve_ms,
                threshold,
                self._consecutive_pressure,
            )
            if self._consecutive_pressure >= self._config.consecutive_pressure_count:
                self._open_episodes += 1
                self._consecutive_pressure = 0
                if self._open_episodes >= self._config.isolation_threshold:
                    self._transition(CircuitState.ISOLATED)
                    log.critical("Circuit breaker ISOLATED")
                else:
                    self._transition(CircuitState.OPEN)
                    log.error(
                        "Circuit breaker OPEN after %d pressure events",
                        self._config.consecutive_pressure_count,
                    )
        else:
            if self._consecutive_pressure > 0:
                log.info("Z3 pressure resolved, resetting counter")
            self._consecutive_pressure = 0

    def _transition(self, new_state: CircuitState) -> None:
        old = self._state
        self._state = new_state
        self._last_transition = time.monotonic()
        self._update_prometheus()
        log.info(
            "Circuit breaker: %s → %s (namespace=%s)",
            old.value,
            new_state.value,
            self._config.namespace,
        )

    def _make_open_decision(self) -> Decision:
        from pramanix.decision import Decision

        return Decision.error(
            reason=(
                f"Circuit breaker OPEN (namespace={self._config.namespace}). "
                f"Z3 solver under pressure. "
                f"Failsafe: {self._config.failsafe_mode.value}. "
                "Auto-recovery in progress. Request blocked."
            )
        )

    def _make_isolated_decision(self) -> Decision:
        from pramanix.decision import Decision

        return Decision.error(
            reason=(
                f"Circuit breaker ISOLATED (namespace={self._config.namespace}). "
                "All requests blocked. Operator must call reset() to resume."
            )
        )

    def _register_metrics(self) -> None:
        try:
            from prometheus_client import Counter, Gauge

            self._state_gauge = Gauge(
                "pramanix_circuit_state",
                "Circuit breaker state (1=active for this state)",
                ["namespace", "state"],
            )
            self._pressure_counter = Counter(
                "pramanix_circuit_pressure_events_total",
                "Z3 pressure events (solve_ms > threshold)",
                ["namespace"],
            )
            self._metrics_available = True
            self._update_prometheus()
        except ImportError:  # pragma: no cover
            self._metrics_available = False
        except ValueError:
            # Metrics already registered (e.g., multiple instances in same process).
            # Retrieve existing metrics from registry.
            try:
                from prometheus_client import REGISTRY

                self._state_gauge = REGISTRY._names_to_collectors.get(  # pyright: ignore[reportAttributeAccessIssue]
                    "pramanix_circuit_state"
                )
                self._pressure_counter = REGISTRY._names_to_collectors.get(  # pyright: ignore[reportAttributeAccessIssue]
                    "pramanix_circuit_pressure_events_total"
                )
                self._metrics_available = (
                    self._state_gauge is not None and self._pressure_counter is not None
                )
                if self._metrics_available:
                    self._update_prometheus()
            except Exception:
                self._metrics_available = False

    def _update_prometheus(self) -> None:
        if not self._metrics_available:
            return  # pragma: no cover
        try:
            for s in CircuitState:
                self._state_gauge.labels(
                    namespace=self._config.namespace,
                    state=s.value,
                ).set(1 if self._state == s else 0)
        except Exception:
            pass

    def _increment_pressure_metric(self) -> None:
        if not self._metrics_available:
            return  # pragma: no cover
        with contextlib.suppress(Exception):
            self._pressure_counter.labels(namespace=self._config.namespace).inc()


# ── Phase C-5: Distributed Circuit Breaker ───────────────────────────────────


@dataclass
class _DistributedState:
    """Shared state record stored in the distributed backend."""

    circuit_state: str = CircuitState.CLOSED.value
    failure_count: int = 0
    last_failure_time: float = 0.0
    open_episode_count: int = 0


class InMemoryDistributedBackend:
    """In-process distributed backend for testing.

    All instances sharing the same *namespace* see the same state, simulating
    multiple replicas within a single process.  Thread-safe via a module-level
    :class:`threading.Lock`.

    Use :meth:`clear` to reset all namespaces between tests.
    """

    import threading as _threading

    _store: ClassVar[dict[str, _DistributedState]] = {}
    _lock: ClassVar[Any] = _threading.Lock()

    @classmethod
    async def get_state(cls, namespace: str) -> _DistributedState:
        with cls._lock:
            return cls._store.get(namespace, _DistributedState())

    @classmethod
    async def set_state(cls, namespace: str, state: _DistributedState) -> None:
        with cls._lock:
            existing = cls._store.get(namespace, _DistributedState())
            # Conservative merge: escalate to most severe state across replicas.
            # If either the incoming or existing state is more severe, keep it.
            severity = {
                CircuitState.CLOSED.value: 0,
                CircuitState.HALF_OPEN.value: 1,
                CircuitState.OPEN.value: 2,
                CircuitState.ISOLATED.value: 3,
            }
            new_severity = severity.get(state.circuit_state, 0)
            existing_severity = severity.get(existing.circuit_state, 0)
            merged_state = state.circuit_state if new_severity >= existing_severity else existing.circuit_state
            cls._store[namespace] = _DistributedState(
                circuit_state=merged_state,
                failure_count=existing.failure_count + state.failure_count,
                last_failure_time=max(existing.last_failure_time, state.last_failure_time),
                open_episode_count=max(existing.open_episode_count, state.open_episode_count),
            )

    @classmethod
    def clear(cls, namespace: str | None = None) -> None:
        """Clear stored state. Pass namespace to clear one namespace, or None to clear all."""
        with cls._lock:
            if namespace is None:
                cls._store.clear()
            else:
                cls._store.pop(namespace, None)


class DistributedCircuitBreaker:
    """Circuit breaker with distributed state synchronization.

    A drop-in replacement for :class:`AdaptiveCircuitBreaker` that shares
    state across multiple replicas via a pluggable backend.  The aggregation
    rule is conservative (fail-safe): if ANY replica is OPEN, all replicas
    report OPEN.  Failure counts are summed across replicas.

    Args:
        guard:            The :class:`~pramanix.guard.Guard` to wrap.
        config:           :class:`CircuitBreakerConfig` (same as single-node).
        backend:          Distributed state backend.  Defaults to
                          :class:`InMemoryDistributedBackend` (single-process
                          testing).  Use a Redis-backed backend in production.

    Usage::

        # Single-process simulation (testing)
        breaker1 = DistributedCircuitBreaker(guard, namespace="trade")
        breaker2 = DistributedCircuitBreaker(guard, namespace="trade")
        # breaker1 and breaker2 share state via InMemoryDistributedBackend.

    """

    def __init__(
        self,
        guard: Any,
        config: CircuitBreakerConfig | None = None,
        backend: Any = None,
    ) -> None:
        self._guard = guard
        self._config = config or CircuitBreakerConfig()
        self._backend = backend or InMemoryDistributedBackend()
        self._local_state = CircuitState.CLOSED
        self._local_failure_count = 0
        self._last_transition = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._local_state

    async def _sync_state(self) -> CircuitState:
        """Pull current aggregate state from backend and update local view."""
        agg = await self._backend.get_state(self._config.namespace)
        try:
            synced = CircuitState(agg.circuit_state)
        except ValueError:
            synced = CircuitState.CLOSED
        self._local_state = synced
        self._local_failure_count = agg.failure_count
        return synced

    async def _push_state(self, new_state: CircuitState, delta_failures: int = 0) -> None:
        """Write local state to backend (backend merges conservatively)."""
        self._local_state = new_state
        now = time.monotonic()
        self._last_transition = now
        await self._backend.set_state(
            self._config.namespace,
            _DistributedState(
                circuit_state=new_state.value,
                failure_count=delta_failures,
                last_failure_time=now if delta_failures > 0 else 0.0,
                open_episode_count=1 if new_state == CircuitState.OPEN else 0,
            ),
        )

    async def verify_async(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Decision:
        """Verify with distributed circuit breaker protection.

        Syncs state from the backend on each call.  If the aggregate state is
        OPEN, returns a failsafe :class:`~pramanix.decision.Decision` without
        invoking Z3.  Otherwise delegates to the underlying Guard.
        """
        async with self._lock:
            current = await self._sync_state()

        if current in (CircuitState.OPEN, CircuitState.ISOLATED):
            return self._make_open_decision(current)

        t0 = time.monotonic()
        decision = await self._guard.verify_async(intent=intent, state=state)
        solve_ms = (time.monotonic() - t0) * 1000

        async with self._lock:
            if solve_ms > self._config.pressure_threshold_ms:
                self._local_failure_count += 1
                if self._local_failure_count >= self._config.consecutive_pressure_count:
                    await self._push_state(CircuitState.OPEN, delta_failures=self._local_failure_count)
                    self._local_failure_count = 0
                    log.error(
                        "DistributedCircuitBreaker: OPEN (namespace=%s)",
                        self._config.namespace,
                    )
                else:
                    await self._push_state(CircuitState.CLOSED, delta_failures=1)
            else:
                self._local_failure_count = 0

        return decision  # type: ignore[no-any-return]

    def verify_sync(self, *, intent: dict[str, Any], state: dict[str, Any]) -> Decision:
        """Blocking synchronous wrapper (sync callers only).

        Raises :exc:`~pramanix.exceptions.ConfigurationError` if called from
        within a running asyncio event loop.  Use :meth:`verify_async` in
        async code.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "DistributedCircuitBreaker.verify_sync() cannot be called from within "
                "a running asyncio event loop.  Use verify_async() instead."
            )
        return asyncio.run(self.verify_async(intent=intent, state=state))

    def reset(self) -> None:
        """Clear distributed state for this namespace."""
        self._local_state = CircuitState.CLOSED
        self._local_failure_count = 0
        self._backend.clear(self._config.namespace)

    def _make_open_decision(self, current: CircuitState) -> Decision:
        from pramanix.decision import Decision

        label = "OPEN" if current == CircuitState.OPEN else "ISOLATED"
        return Decision.error(
            reason=(
                f"DistributedCircuitBreaker {label} (namespace={self._config.namespace}). "
                "Aggregate replica state indicates Z3 solver pressure. Request blocked."
            )
        )
