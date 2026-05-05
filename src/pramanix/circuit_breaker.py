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
    """State machine states for the adaptive circuit breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"
    ISOLATED = "isolated"


class FailsafeMode(enum.StrEnum):
    """Failsafe behaviour when the circuit breaker is open."""

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
    """Configuration for AdaptiveCircuitBreaker thresholds and recovery timing."""

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
    """Point-in-time snapshot of circuit breaker state for observability."""

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
        """Current circuit state."""
        return self._state

    @property
    def status(self) -> CircuitBreakerStatus:
        """Full status snapshot of the circuit breaker."""
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
        # M-05: acquire the lock for the full state-check + routing decision so
        # two coroutines cannot simultaneously read CLOSED and both proceed into
        # the guard when one of them should have triggered the transition to OPEN.
        async with self._lock:
            current_state = self._state

            if current_state == CircuitState.ISOLATED:
                return self._make_isolated_decision()

            if current_state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_transition
                if elapsed >= self._config.recovery_seconds:
                    self._transition(CircuitState.HALF_OPEN)
                else:
                    return self._make_open_decision()
            # Lock released before the blocking verify_async call so other
            # coroutines can check/update state concurrently during the solve.

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
        except ImportError:
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
            return
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
            return
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
        """Fetch the current circuit state from the distributed store."""
        with cls._lock:
            return cls._store.get(namespace, _DistributedState())

    @classmethod
    async def set_state(cls, namespace: str, state: _DistributedState) -> None:
        """Persist a state transition to the distributed store."""
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
        # M-04: Prometheus metrics — same set as AdaptiveCircuitBreaker.
        self._metrics_available = False
        self._state_gauge: Any = None
        self._pressure_counter: Any = None
        self._register_metrics()

    @property
    def state(self) -> CircuitState:
        return self._local_state

    async def _sync_state(self) -> CircuitState:
        """Pull current aggregate state from backend and update local view."""
        agg = await self._backend.get_state(self._config.namespace)
        try:
            synced = CircuitState(agg.circuit_state)
        except ValueError:
            # H-04: unknown/corrupted state → fail-safe OPEN, never CLOSED.
            # Mapping an unknown value to CLOSED would allow traffic through
            # a potentially broken circuit.  Operators must restore Redis
            # connectivity to resume normal operation.
            log.warning(
                "DistributedCircuitBreaker: unknown circuit state %r for "
                "namespace=%r — failing SAFE (OPEN). Restore backend to resume.",
                agg.circuit_state,
                self._config.namespace,
            )
            synced = CircuitState.OPEN
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

    def _register_metrics(self) -> None:
        """Register Prometheus metrics (same set as AdaptiveCircuitBreaker)."""
        try:
            from prometheus_client import Counter, Gauge

            self._state_gauge = Gauge(
                "pramanix_distributed_circuit_state",
                "Distributed circuit breaker state (1=active for this state)",
                ["namespace", "state"],
            )
            self._pressure_counter = Counter(
                "pramanix_distributed_circuit_pressure_events_total",
                "Distributed Z3 pressure events (solve_ms > threshold)",
                ["namespace"],
            )
            self._metrics_available = True
            self._update_prometheus()
        except ImportError:
            self._metrics_available = False
        except ValueError:
            try:
                from prometheus_client import REGISTRY

                self._state_gauge = REGISTRY._names_to_collectors.get(  # pyright: ignore[reportAttributeAccessIssue]
                    "pramanix_distributed_circuit_state"
                )
                self._pressure_counter = REGISTRY._names_to_collectors.get(  # pyright: ignore[reportAttributeAccessIssue]
                    "pramanix_distributed_circuit_pressure_events_total"
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
            return
        try:
            for s in CircuitState:
                self._state_gauge.labels(
                    namespace=self._config.namespace,
                    state=s.value,
                ).set(1 if self._local_state == s else 0)
        except Exception:
            pass


# ── C-5: Redis distributed backend ───────────────────────────────────────────


class RedisDistributedBackend:
    """Distributed state backend using ``redis.asyncio``.

    All replicas pointing at the same Redis instance and namespace will share
    circuit-breaker state.  The aggregation rule is conservative: the most
    severe state stored in Redis wins (ISOLATED > OPEN > HALF_OPEN > CLOSED).

    A per-namespace Redis Hash is used.  Each entry stores the four
    :class:`_DistributedState` fields as string-encoded hash fields.
    The key TTL prevents stale OPEN entries from locking out a recovered
    system indefinitely.

    Requires: ``pip install 'pramanix[redis]'`` (``redis[asyncio]``).

    Args:
        redis_url:            Redis connection URL (e.g.
                              ``"redis://localhost:6379/0"``).
        sync_interval_seconds: Minimum interval between Redis reads in
                               :meth:`get_state`.  Default: 1.0 s.
        key_prefix:           Redis key prefix for all namespaces.
                              Default: ``"pramanix:cb:"``.
        ttl_seconds:          TTL for each namespace Hash key.  Default: 300 s.

    Raises:
        ConfigurationError: If ``redis[asyncio]`` is not installed.
    """

    # Conservative severity ordering (higher = worse = takes priority).
    _SEVERITY: ClassVar[dict[str, int]] = {
        CircuitState.CLOSED.value: 0,
        CircuitState.HALF_OPEN.value: 1,
        CircuitState.OPEN.value: 2,
        CircuitState.ISOLATED.value: 3,
    }

    def __init__(
        self,
        redis_url: str,
        *,
        sync_interval_seconds: float = 1.0,
        key_prefix: str = "pramanix:cb:",
        ttl_seconds: int = 300,
    ) -> None:
        try:
            import redis.asyncio  # noqa: F401
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "redis[asyncio] is required for RedisDistributedBackend. "
                "Install it with: pip install 'pramanix[redis]'"
            ) from exc

        self._redis_url = redis_url
        self._sync_interval = sync_interval_seconds
        self._prefix = key_prefix
        self._ttl = ttl_seconds
        self._client: Any = None

    async def _get_client(self) -> Any:
        """Lazily create and cache the async Redis client."""
        if self._client is None:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(self._redis_url, decode_responses=True)
        return self._client

    async def close(self) -> None:
        """Close the underlying Redis connection."""
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    def __del__(self) -> None:
        if getattr(self, "_client", None) is not None:
            log.warning(
                "RedisDistributedBackend GC'd with an open Redis connection — "
                "call close() explicitly to release the connection cleanly."
            )

    def _key(self, namespace: str) -> str:
        return f"{self._prefix}{namespace}"

    async def get_state(self, namespace: str) -> _DistributedState:
        """Fetch state from Redis for *namespace*.

        Returns a default :class:`_DistributedState` (CLOSED) if the key does
        not exist yet.
        """
        try:
            client = await self._get_client()
            data: dict[str, str] = await client.hgetall(self._key(namespace))
        except Exception as exc:
            # Redis is unavailable — fail SAFE by returning OPEN state so all
            # replicas block requests rather than silently appearing healthy.
            # An operator must restore Redis connectivity to resume normal operation.
            log.error(
                "circuit_breaker: Redis unavailable for namespace=%r — failing SAFE "
                "(OPEN state returned). Distributed state sync is down: %s",
                namespace,
                exc,
            )
            return _DistributedState(circuit_state=CircuitState.OPEN.value)

        if not data:
            return _DistributedState()

        try:
            return _DistributedState(
                circuit_state=data.get("circuit_state", CircuitState.CLOSED.value),
                failure_count=int(data.get("failure_count", 0)),
                last_failure_time=float(data.get("last_failure_time", 0.0)),
                open_episode_count=int(data.get("open_episode_count", 0)),
            )
        except (ValueError, KeyError):
            return _DistributedState()

    async def set_state(self, namespace: str, state: _DistributedState) -> None:
        """Merge *state* into the Redis Hash for *namespace* (conservative merge).

        Conservative merge means:
        - ``circuit_state`` escalates to the most severe value.
        - ``failure_count`` is summed with the existing count.
        - ``last_failure_time`` takes the maximum.
        - ``open_episode_count`` takes the maximum.
        """
        try:
            client = await self._get_client()
            key = self._key(namespace)

            # Fetch existing state for conservative merge.
            existing = await self.get_state(namespace)

            # Severity-wins merge for circuit_state.
            new_severity = self._SEVERITY.get(state.circuit_state, 0)
            existing_severity = self._SEVERITY.get(existing.circuit_state, 0)
            merged_circuit_state = (
                state.circuit_state
                if new_severity >= existing_severity
                else existing.circuit_state
            )

            merged = {
                "circuit_state": merged_circuit_state,
                "failure_count": str(existing.failure_count + state.failure_count),
                "last_failure_time": str(
                    max(existing.last_failure_time, state.last_failure_time)
                ),
                "open_episode_count": str(
                    max(existing.open_episode_count, state.open_episode_count)
                ),
            }

            # Use a pipeline for atomicity: HSET + EXPIRE in one round-trip.
            async with client.pipeline(transaction=True) as pipe:
                await pipe.hset(key, mapping=merged)
                await pipe.expire(key, self._ttl)
                await pipe.execute()
        except Exception as exc:
            # State-sync failures are non-fatal — local state still governs,
            # but we must surface this so operators know distributed view is stale.
            log.error(
                "circuit_breaker: Redis state sync failed for namespace=%r; "
                "local state still governs but distributed view may be stale: %s",
                namespace,
                exc,
            )

    async def clear_async(self, namespace: str | None = None) -> None:
        """Async-native clear — preferred in async contexts (tests, FastAPI)."""
        await self._async_clear(namespace)

    def clear(self, namespace: str | None = None) -> None:
        """Synchronously clear Redis state.

        Safe to call from both sync and async contexts.  In async contexts,
        prefer :meth:`clear_async` to avoid potential event-loop conflicts.
        """
        import asyncio

        try:
            # If there is already a running loop (e.g. inside pytest-asyncio,
            # FastAPI, or any async framework), run_until_complete would raise
            # RuntimeError.  Use asyncio.run() which always creates a fresh loop.
            asyncio.get_running_loop()
            # We ARE inside a running loop — schedule as a fire-and-forget task.
            # The caller in async code should use await clear_async() instead.
            log.warning(
                "RedisDistributedBackend.clear() called from within a running "
                "event loop.  Use 'await clear_async()' in async code to avoid "
                "scheduling issues.  Scheduling as background task."
            )
            asyncio.ensure_future(self._async_clear(namespace))
        except RuntimeError:
            # No running loop — safe to use asyncio.run().
            asyncio.run(self._async_clear(namespace))

    async def _async_clear(self, namespace: str | None) -> None:
        try:
            client = await self._get_client()
            if namespace is None:
                # Delete all keys matching the prefix pattern.
                keys = await client.keys(f"{self._prefix}*")
                if keys:
                    await client.delete(*keys)
            else:
                await client.delete(self._key(namespace))
        except Exception:
            pass


# ── TranslatorCircuitBreaker ──────────────────────────────────────────────────


class TranslatorCircuitBreaker:
    """Lightweight circuit breaker for individual LLM translator calls.

    Unlike :class:`AdaptiveCircuitBreaker` which wraps a full Guard for Z3
    pressure management, this class wraps a single translator's ``extract()``
    call and trips open on consecutive ``ExtractionFailureError`` /
    ``LLMTimeoutError`` failures.

    State machine:
        CLOSED → OPEN (after *failure_threshold* consecutive failures)
        OPEN   → HALF_OPEN (after *recovery_seconds*)
        HALF_OPEN → CLOSED (probe succeeds) or OPEN (probe fails)

    Args:
        model:             Translator model name — used for logging and metrics.
        failure_threshold: Consecutive failures before tripping open.
        recovery_seconds:  Seconds before allowing a probe from OPEN state.

    Thread / async safety: all state is guarded by an :class:`asyncio.Lock`.
    """

    def __init__(
        self,
        model: str,
        *,
        failure_threshold: int = 5,
        recovery_seconds: float = 30.0,
    ) -> None:
        self.model = model
        self._failure_threshold = failure_threshold
        self._recovery_seconds = recovery_seconds
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state

    async def call(
        self,
        coro_factory: Any,
    ) -> Any:
        """Execute *coro_factory()* (a coroutine) through circuit breaker logic.

        Args:
            coro_factory: Zero-argument callable that returns a coroutine —
                          typically ``lambda: translator.extract(...)``.

        Returns:
            The coroutine's result on success.

        Raises:
            ExtractionFailureError: If the circuit is OPEN (model is degraded).
            Any exception raised by the coroutine.
        """
        from pramanix.exceptions import ExtractionFailureError, LLMTimeoutError

        async with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - (self._opened_at or 0.0)
                if elapsed < self._recovery_seconds:
                    raise ExtractionFailureError(
                        f"Translator circuit breaker OPEN for model {self.model!r}. "
                        f"Retry in {self._recovery_seconds - elapsed:.1f}s."
                    )
                # Probe window — transition to HALF_OPEN
                self._state = CircuitState.HALF_OPEN
                log.info(
                    "pramanix.translator_cb.half_open: model=%r probing after %.1fs",
                    self.model,
                    elapsed,
                )

        try:
            result = await coro_factory()
        except (ExtractionFailureError, LLMTimeoutError) as exc:
            async with self._lock:
                self._consecutive_failures += 1
                if self._state == CircuitState.HALF_OPEN or (
                    self._consecutive_failures >= self._failure_threshold
                ):
                    self._state = CircuitState.OPEN
                    self._opened_at = time.monotonic()
                    log.warning(
                        "pramanix.translator_cb.opened: model=%r failures=%d",
                        self.model,
                        self._consecutive_failures,
                    )
            raise
        except Exception:
            raise
        else:
            async with self._lock:
                if self._consecutive_failures > 0 or self._state != CircuitState.CLOSED:
                    log.info(
                        "pramanix.translator_cb.recovered: model=%r state=%s→closed",
                        self.model,
                        self._state,
                    )
                self._consecutive_failures = 0
                self._opened_at = None
                self._state = CircuitState.CLOSED
            return result

    def reset(self) -> None:
        """Manually reset the circuit to CLOSED (operator use)."""
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = None
        log.info("pramanix.translator_cb.reset: model=%r", self.model)
