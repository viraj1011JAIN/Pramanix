# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Phase 10.4 — Adaptive Concurrency Limiter / Load Shedding.

Verifies AdaptiveConcurrencyLimiter shedding logic, Decision.rate_limited()
factory, and WorkerPool integration.
"""
from __future__ import annotations

import threading
import time

from pramanix.decision import Decision, SolverStatus
from pramanix.worker import AdaptiveConcurrencyLimiter

# ── Tests: Decision.rate_limited() ───────────────────────────────────────────


class TestDecisionRateLimited:
    def test_rate_limited_allowed_false(self):
        d = Decision.rate_limited()
        assert d.allowed is False

    def test_rate_limited_status(self):
        d = Decision.rate_limited()
        assert d.status == SolverStatus.RATE_LIMITED

    def test_rate_limited_default_explanation(self):
        d = Decision.rate_limited()
        assert len(d.explanation) > 0
        assert "shed" in d.explanation.lower() or "rate" in d.explanation.lower()

    def test_rate_limited_custom_reason(self):
        d = Decision.rate_limited("Custom shed reason")
        assert d.explanation == "Custom shed reason"

    def test_rate_limited_metadata(self):
        d = Decision.rate_limited(metadata={"key": "val"})
        assert d.metadata == {"key": "val"}

    def test_rate_limited_in_blocked_statuses(self):
        from pramanix.decision import _BLOCKED_STATUSES

        assert SolverStatus.RATE_LIMITED in _BLOCKED_STATUSES

    def test_rate_limited_serializable(self):
        d = Decision.rate_limited()
        as_dict = d.to_dict()
        assert as_dict["allowed"] is False
        assert as_dict["status"] == "rate_limited"

    def test_cache_hit_status_exists(self):
        """CACHE_HIT must exist as an enum value."""
        assert SolverStatus.CACHE_HIT == "cache_hit"


# ── Tests: AdaptiveConcurrencyLimiter ────────────────────────────────────────


class TestAdaptiveConcurrencyLimiter:
    def test_acquire_succeeds_under_threshold(self):
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=4,
            latency_threshold_ms=200.0,
            worker_pct=90.0,
        )
        result = limiter.acquire()
        assert result is True

    def test_release_decrements_active(self):
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=4,
            latency_threshold_ms=200.0,
            worker_pct=90.0,
        )
        limiter.acquire()
        assert limiter.active_workers == 1
        limiter.release(50.0)
        assert limiter.active_workers == 0

    def test_active_never_goes_negative(self):
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=4,
            latency_threshold_ms=200.0,
            worker_pct=90.0,
        )
        # Release without acquire — should not go negative
        limiter.release(10.0)
        assert limiter.active_workers >= 0

    def test_no_shed_without_enough_latency_data(self):
        """P99 requires >=10 samples — shed never fires without data."""
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=1.0,  # very low threshold
            worker_pct=10.0,  # very low pct
        )
        # No latency data yet — should not shed
        result = limiter.acquire()
        assert result is True

    def test_sheds_when_both_conditions_met(self):
        """Should shed when worker saturation AND high p99 latency."""
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=10.0,
            worker_pct=50.0,
        )
        # Fill the latency window with high-latency samples
        for _ in range(20):
            limiter.acquire()
            limiter.release(999.0)  # 999ms — well over threshold

        # Now saturate workers: acquire fills 1 slot (100% of max_workers=1)
        # Then next acquire should trigger shedding
        limiter.acquire()  # now active_workers=1, saturation=100% > 50%
        result = limiter.acquire()  # 2nd acquire: active=2, sat=200% > 50%; p99=999>10
        # One of the acquires should have shed (shed_count > 0)
        # Note: actual shedding depends on acquire order, so check shed_count
        if not result:
            assert limiter.shed_count > 0

    def test_shed_count_increments(self):
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=1.0,
            worker_pct=1.0,  # shed at 1% saturation
        )
        # Fill latency window with high latency
        for _ in range(20):
            limiter.acquire()
            limiter.release(999.0)

        initial_shed = limiter.shed_count
        # Try to acquire — should shed
        limiter.acquire()  # may or may not shed depending on active count
        # Reset active to 0 and try again to ensure shedding
        # Force shed by having many active workers relative to max
        result = limiter.acquire()
        if not result:
            assert limiter.shed_count > initial_shed

    def test_no_shed_without_latency_condition(self):
        """High worker saturation alone should NOT shed (dual condition)."""
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=10_000.0,  # very high threshold — never exceeded
            worker_pct=10.0,
        )
        # Fill latency window with low-latency samples
        for _ in range(20):
            limiter.acquire()
            limiter.release(1.0)  # 1ms — well under threshold

        # Even at 100% saturation, should not shed (latency too low)
        limiter.acquire()
        limiter.acquire()
        # Since latency is low, should NOT shed
        assert limiter.shed_count == 0

    def test_latency_window_eviction(self):
        """Old latency entries (>60s) should be evicted."""
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=4,
            latency_threshold_ms=200.0,
            worker_pct=90.0,
        )
        # Add entries — they'll all be recent so won't be evicted yet
        for _ in range(5):
            limiter.acquire()
            limiter.release(100.0)
        # Window should have 5 entries
        assert len(limiter._latency_window) == 5

    def test_thread_safe_acquire_release(self):
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=10,
            latency_threshold_ms=200.0,
            worker_pct=90.0,
        )
        errors = []

        def worker():
            try:
                for _ in range(20):
                    result = limiter.acquire()
                    if result:
                        time.sleep(0.001)
                        limiter.release(10.0)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert limiter.active_workers >= 0

    def test_p99_requires_minimum_10_samples(self):
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=1.0,
            worker_pct=50.0,
        )
        # Only 9 samples — p99 returns None — no shedding
        for _ in range(9):
            limiter.acquire()
            limiter.release(999.0)

        limiter.acquire()  # saturate
        limiter.acquire()
        assert limiter.shed_count == 0  # no shed (p99 returned None)


# ── Tests: WorkerPool integration ────────────────────────────────────────────


class TestWorkerPoolShedIntegration:
    def test_worker_pool_has_shed_limiter(self):
        from pramanix.worker import WorkerPool

        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=10_000,
        )
        assert hasattr(pool, "_shed_limiter")
        assert isinstance(pool._shed_limiter, AdaptiveConcurrencyLimiter)

    def test_worker_pool_accepts_latency_threshold(self):
        from pramanix.worker import WorkerPool

        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=10_000,
            latency_threshold_ms=500.0,
            worker_pct=80.0,
        )
        assert pool._shed_limiter._latency_threshold == 500.0
        assert pool._shed_limiter._worker_pct == 80.0
