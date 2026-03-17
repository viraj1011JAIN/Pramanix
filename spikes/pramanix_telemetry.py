# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Pramanix — Red-Flag Telemetry Emitter
=======================================
Tracks three security red flags in a rolling time window and exposes a
snapshot for dashboard rendering.

Red flags
---------
1. **injection_score_spikes**    — high-confidence injection attempts (score ≥ 0.5).
                                   Many of these in a short window indicate an
                                   automated attack campaign.
2. **consensus_mismatches**      — dual-model extraction disagreements; a rising
                                   rate suggests adversarial model-probing.
3. **z3_timeouts**               — Z3 subprocess timeouts; a sustained rate
                                   indicates deliberate constraint-complexity DoS.

Thread-safe.  Never raises — telemetry must never affect the hot transaction path.

Usage
-----
::

    from pramanix_telemetry import get_telemetry, emit_snapshot

    tel = get_telemetry()
    tel.record_injection_score(0.7)           # spike recorded
    tel.record_consensus_attempt(matched=False)
    tel.record_z3_evaluation(timed_out=True)

    print(emit_snapshot())                     # dashboard point-in-time dict

    # Optional: push every red-flag event to a log aggregator
    from pramanix_telemetry import StructuredLogEmitter
    tel.add_red_flag_listener(StructuredLogEmitter())
"""
from __future__ import annotations

import contextlib
import json
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "INJECTION_SPIKE_THRESHOLD",
    "PramaniXTelemetry",
    "RedFlagMetric",
    "StructuredLogEmitter",
    "emit_snapshot",
    "get_telemetry",
]

# Score at-or-above which an injection evaluation is counted as a spike.
# Mirrors the block threshold in pramanix_llm_hardened.injection_confidence_score.
INJECTION_SPIKE_THRESHOLD: float = 0.5


# ---------------------------------------------------------------------------
# Internal rolling-window counter
# ---------------------------------------------------------------------------


class _RollingCounter:
    """Thread-safe event counter constrained to a sliding time window."""

    __slots__ = ("_window_s", "_events", "_total", "_lock")

    def __init__(self, window_s: float) -> None:
        self._window_s = window_s
        self._events: deque[float] = deque()
        self._total: int = 0
        self._lock = threading.Lock()

    def record(self) -> None:
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            self._total += 1
            self._evict(now)

    def _evict(self, now: float) -> None:
        cutoff = now - self._window_s
        while self._events and self._events[0] < cutoff:
            self._events.popleft()

    @property
    def window_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            return len(self._events)

    @property
    def total(self) -> int:
        with self._lock:
            return self._total


class _RedFlagCounter:
    """Tracks *events* (numerator) and *attempts* (denominator) separately."""

    def __init__(self, window_s: float) -> None:
        self._events   = _RollingCounter(window_s)
        self._attempts = _RollingCounter(window_s)

    def record_attempt(self) -> None:
        self._attempts.record()

    def record_event(self) -> None:
        """Record both an event occurrence AND an attempt."""
        self._events.record()
        self._attempts.record()

    def snapshot(self) -> RedFlagMetric:
        events   = self._events.window_count
        attempts = self._attempts.window_count
        rate     = events / attempts if attempts > 0 else 0.0
        return RedFlagMetric(
            window_count   = events,
            total_events   = self._events.total,
            total_attempts = self._attempts.total,
            window_rate    = round(rate, 4),
        )


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedFlagMetric:
    """Immutable point-in-time snapshot for one red-flag counter pair."""

    window_count:   int    # matching events inside the rolling window
    total_events:   int    # all-time matching events
    total_attempts: int    # all-time total opportunities recorded
    window_rate:    float  # window_count / window_attempts  (0.0 if no attempts)


# ---------------------------------------------------------------------------
# Core telemetry class
# ---------------------------------------------------------------------------


class PramaniXTelemetry:
    """Thread-safe telemetry store for the three Pramanix security red flags.

    Obtain the module-level singleton via :func:`get_telemetry`.
    Register alert listeners with :meth:`add_red_flag_listener` to receive a
    callback on every red-flag event (e.g. push metrics to Grafana or Datadog).

    Args:
        window_s: Rolling time window in seconds.  Default: 300 (5 minutes).
    """

    def __init__(self, window_s: float = 300.0) -> None:
        self._window_s             = window_s
        self.injection_spikes      = _RedFlagCounter(window_s)
        self.consensus_mismatches  = _RedFlagCounter(window_s)
        self.z3_timeouts           = _RedFlagCounter(window_s)
        self._listeners: list[Callable[[str, dict[str, Any]], None]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Recording API
    # ------------------------------------------------------------------

    def record_injection_score(self, score: float) -> None:
        """Record one injection-score evaluation.

        Increments **injection_spikes** when *score* ≥
        :data:`INJECTION_SPIKE_THRESHOLD`; fires ``"injection_spike"`` listener
        event with ``{"score": <float>}`` payload.
        """
        if score >= INJECTION_SPIKE_THRESHOLD:
            self.injection_spikes.record_event()
            self._fire("injection_spike", {"score": round(score, 4)})
        else:
            self.injection_spikes.record_attempt()

    def record_consensus_attempt(self, matched: bool) -> None:
        """Record one dual-model consensus check.

        Increments **consensus_mismatches** when *matched* is ``False``; fires
        ``"consensus_mismatch"`` listener event.
        """
        if not matched:
            self.consensus_mismatches.record_event()
            self._fire("consensus_mismatch", {})
        else:
            self.consensus_mismatches.record_attempt()

    def record_z3_evaluation(self, *, timed_out: bool) -> None:
        """Record one Z3 evaluation attempt.

        Increments **z3_timeouts** when *timed_out* is ``True``; fires
        ``"z3_timeout"`` listener event.
        """
        if timed_out:
            self.z3_timeouts.record_event()
            self._fire("z3_timeout", {})
        else:
            self.z3_timeouts.record_attempt()

    # ------------------------------------------------------------------
    # Listener / dashboard API
    # ------------------------------------------------------------------

    def add_red_flag_listener(
        self,
        fn: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Register *fn* to be called on every red-flag event.

        Signature: ``fn(event_type: str, payload: dict) -> None``

        *event_type* is one of: ``"injection_spike"``,
        ``"consensus_mismatch"``, ``"z3_timeout"``.

        Exceptions raised by *fn* are silently swallowed — telemetry must
        never crash the transaction path.
        """
        with self._lock:
            self._listeners.append(fn)

    def snapshot(self) -> dict[str, Any]:
        """Return a point-in-time dict of all three red-flag metrics.

        Suitable for JSON serialisation and dashboard rendering.

        Example::

            {
                "window_s": 300,
                "injection_spikes":     {"window_count": 2, "window_rate": 0.4, ...},
                "consensus_mismatches": {"window_count": 0, "window_rate": 0.0, ...},
                "z3_timeouts":          {"window_count": 0, "window_rate": 0.0, ...}
            }
        """
        return {
            "window_s":             self._window_s,
            "injection_spikes":     _metric_to_dict(self.injection_spikes.snapshot()),
            "consensus_mismatches": _metric_to_dict(self.consensus_mismatches.snapshot()),
            "z3_timeouts":          _metric_to_dict(self.z3_timeouts.snapshot()),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fire(self, event_type: str, payload: dict[str, Any]) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for fn in listeners:
            with contextlib.suppress(Exception):
                fn(event_type, payload)


def _metric_to_dict(m: RedFlagMetric) -> dict[str, Any]:
    return {
        "window_count":   m.window_count,
        "window_rate":    m.window_rate,
        "total_events":   m.total_events,
        "total_attempts": m.total_attempts,
    }


# ---------------------------------------------------------------------------
# Structured-log emitter (optional listener) — JSON lines to a stream
# ---------------------------------------------------------------------------


class StructuredLogEmitter:
    """Listener that writes one JSON-lines record per red-flag event.

    Attach to a :class:`PramaniXTelemetry` instance via
    :meth:`~PramaniXTelemetry.add_red_flag_listener`.  Output is written to
    *stream* (default: ``sys.stdout``) as machine-parseable JSON lines.  Log
    aggregators (Grafana Loki, Datadog, Elastic) can ingest this directly.

    Args:
        stream: Writable text stream.  Defaults to ``sys.stdout``.
        prefix: Prepended to ``event_type`` in the ``"event"`` field.
    """

    def __init__(
        self,
        stream: Any = None,
        prefix: str = "pramanix_redflag",
    ) -> None:
        self._stream = stream or sys.stdout
        self._prefix = prefix

    def __call__(self, event_type: str, payload: dict[str, Any]) -> None:
        record: dict[str, Any] = {
            "event":   f"{self._prefix}.{event_type}",
            "ts_mono": round(time.monotonic(), 3),
            **payload,
        }
        try:
            self._stream.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._stream.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Module-level singleton + convenience wrappers
# ---------------------------------------------------------------------------

_GLOBAL_TELEMETRY: PramaniXTelemetry = PramaniXTelemetry()


def get_telemetry() -> PramaniXTelemetry:
    """Return the module-level :class:`PramaniXTelemetry` singleton."""
    return _GLOBAL_TELEMETRY


def emit_snapshot() -> dict[str, Any]:
    """Return a point-in-time snapshot of all red-flag metrics.

    Convenience wrapper over :meth:`PramaniXTelemetry.snapshot` on the
    global singleton.
    """
    return _GLOBAL_TELEMETRY.snapshot()
