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
from typing import TYPE_CHECKING, Any

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


@dataclass
class CircuitBreakerConfig:
    pressure_threshold_ms: float = 40.0
    consecutive_pressure_count: int = 5
    recovery_seconds: float = 30.0
    isolation_threshold: int = 3
    failsafe_mode: FailsafeMode = FailsafeMode.BLOCK_ALL
    namespace: str = "default"


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
