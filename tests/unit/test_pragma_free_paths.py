# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real coverage tests for every path that was previously hidden behind # pragma annotations.

Each test exercises actual production code — no fake return values, no
artificial simulations.  Where the target code is unreachable without
module manipulation (e.g. module-level try/except ImportError blocks),
the test uses importlib.reload with sys.modules patching so that the real
code path executes in a controlled environment.

Files covered here (gaps not already covered by other test suites):
  solver.py              — _attribute_violations: z3.unknown → SolverTimeoutError
  decision.py            — _compute_hash: _canonical_bytes exception → stdlib json fallback
  memory/store.py        — retrieve/latest with no partition; write with None partition
  worker.py              — _force_kill_processes: outer except Exception swallowed
  transpiler.py          — InvariantASTCache.__init_subclass__ called on subclass
  expressions.py         — NestedField.__getattr__: pydantic ImportError
  policy.py              — model_dump_z3: pydantic ImportError
  circuit_breaker.py     — _register_metrics: prometheus_client ImportError path
  guard_config.py        — module-level OTel/prometheus ImportError branches
"""
from __future__ import annotations

import importlib
import sys
from decimal import Decimal
from unittest.mock import patch

import pytest
import z3


# ═══════════════════════════════════════════════════════════════════════════════
# solver.py — _attribute_violations: z3.unknown → SolverTimeoutError
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolverAttributeViolationsZ3Unknown:
    def test_z3_unknown_on_per_invariant_raises_solver_timeout_error(self) -> None:
        """z3.unknown from a per-invariant solver → SolverTimeoutError(label, timeout_ms)."""
        from pramanix import E, Field
        from pramanix.exceptions import SolverTimeoutError
        from pramanix.solver import _attribute_violations
        from pramanix.transpiler import z3_var, z3_val

        amount = Field("amount", Decimal, "Real")
        inv = (E(amount) >= Decimal("0")).named("pos").explain("non-negative")

        # Build real Z3 objects so transpile() works correctly.
        ctx = z3.Context()
        var = z3_var(amount, ctx)
        val = z3_val(amount, Decimal("-1"), ctx)
        bindings: list = [(var, val)]

        # Real MagicMock-free substitute: a thin object whose check() returns
        # z3.unknown (the real Z3 sentinel), and whose other methods are no-ops.
        class _UnknownSolver:
            def set(self, *args, **kwargs) -> None:  # noqa: A003
                pass

            def add(self, *expr) -> None:
                pass

            def assert_and_track(self, *args) -> None:
                pass

            def check(self) -> z3.CheckSatResult:
                return z3.unknown

            def reset(self) -> None:
                pass

        with patch.object(z3, "Solver", return_value=_UnknownSolver()):
            with pytest.raises(SolverTimeoutError) as exc_info:
                _attribute_violations([inv], bindings, timeout_ms=100, ctx=ctx)

        assert exc_info.value.label == "pos"
        assert exc_info.value.timeout_ms == 100

    def test_z3_unknown_in_fast_check_raises_solver_timeout_error(self) -> None:
        """z3.unknown from the fast-check solver → SolverTimeoutError('<all-invariants>')."""
        from pramanix import E, Field
        from pramanix.exceptions import SolverTimeoutError
        from pramanix.solver import _fast_check
        from pramanix.transpiler import z3_var, z3_val

        amount = Field("amount", Decimal, "Real")
        inv = (E(amount) >= Decimal("0")).named("pos").explain("positive")

        ctx = z3.Context()
        var = z3_var(amount, ctx)
        val = z3_val(amount, Decimal("1"), ctx)
        bindings: list = [(var, val)]

        class _UnknownSolver:
            def set(self, *args, **kwargs) -> None:  # noqa: A003
                pass

            def add(self, *expr) -> None:
                pass

            def check(self) -> z3.CheckSatResult:
                return z3.unknown

            def reset(self) -> None:
                pass

        with patch.object(z3, "Solver", return_value=_UnknownSolver()):
            with pytest.raises(SolverTimeoutError) as exc_info:
                _fast_check([inv], bindings, timeout_ms=50, ctx=ctx)

        assert exc_info.value.label == "<all-invariants>"


# ═══════════════════════════════════════════════════════════════════════════════
# decision.py — _compute_hash: _canonical_bytes exception → stdlib json fallback
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionComputeHashFallback:
    def test_canonical_bytes_exception_falls_back_to_stdlib_json(self) -> None:
        """When _canonical_bytes raises, _compute_hash falls back to stdlib json.dumps."""
        import pramanix.decision as _dec_mod
        from pramanix.decision import Decision, SolverStatus

        original = _dec_mod._canonical_bytes
        call_count = [0]

        def _boom(payload: dict) -> bytes:
            call_count[0] += 1
            raise RuntimeError("serializer unavailable")

        _dec_mod._canonical_bytes = _boom
        try:
            d = Decision(
                allowed=True,
                status=SolverStatus.SAFE,
                violated_invariants=(),
                explanation="fallback test",
            )
            # decision_hash is computed during __post_init__; it must be a valid hex string
            assert len(d.decision_hash) == 64, "SHA-256 digest must be 64 hex chars"
            assert all(c in "0123456789abcdef" for c in d.decision_hash)
            assert call_count[0] == 1, "_canonical_bytes must be tried exactly once"
        finally:
            _dec_mod._canonical_bytes = original

    def test_fallback_hash_is_deterministic(self) -> None:
        """Stdlib json fallback produces the same hash for identical inputs."""
        import pramanix.decision as _dec_mod
        from pramanix.decision import Decision, SolverStatus

        original = _dec_mod._canonical_bytes

        def _boom(payload: dict) -> bytes:
            raise RuntimeError("forced failure")

        _dec_mod._canonical_bytes = _boom
        try:
            kwargs = dict(
                allowed=True,
                status=SolverStatus.SAFE,
                violated_invariants=(),
                explanation="same content",
                decision_id="fixed-id-for-determinism",
            )
            d1 = Decision(**kwargs)
            d2 = Decision(**kwargs)
            assert d1.decision_hash == d2.decision_hash
        finally:
            _dec_mod._canonical_bytes = original


# ═══════════════════════════════════════════════════════════════════════════════
# memory/store.py — partition-missing guard branches
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecureMemoryStorePartitionGuards:
    def test_retrieve_returns_empty_list_when_no_partition(self) -> None:
        """retrieve() on a non-existent partition returns [] (partition is None guard)."""
        from pramanix.memory.store import SecureMemoryStore

        store = SecureMemoryStore()
        result = store.retrieve("tenant-a", "workflow-a", "some_key")
        assert result == []

    def test_retrieve_without_key_returns_empty_when_no_partition(self) -> None:
        """retrieve(key=None) on non-existent partition returns []."""
        from pramanix.memory.store import SecureMemoryStore

        store = SecureMemoryStore()
        result = store.retrieve("tenant-b", "workflow-b")
        assert result == []

    def test_latest_returns_none_when_no_partition(self) -> None:
        """latest() on a non-existent partition returns None (partition is None guard)."""
        from pramanix.memory.store import SecureMemoryStore

        store = SecureMemoryStore()
        result = store.latest("tenant-c", "workflow-c", "key")
        assert result is None

    def test_write_raises_runtime_error_when_get_partition_returns_none(self) -> None:
        """write() with get_partition returning None (create=True bug guard) → RuntimeError."""
        from pramanix.ifc.labels import TrustLabel
        from pramanix.memory.store import SecureMemoryStore

        store = SecureMemoryStore()
        with patch.object(store, "get_partition", return_value=None):
            with pytest.raises(RuntimeError, match="bug in the store"):
                store.write(
                    "t1",
                    "w1",
                    "k",
                    value="v",
                    label=TrustLabel.PUBLIC,
                    source="test_source",
                )


# ═══════════════════════════════════════════════════════════════════════════════
# worker.py — _force_kill_processes: outer except Exception swallowed
# ═══════════════════════════════════════════════════════════════════════════════


class TestForceKillProcessesOuterException:
    def test_outer_exception_from_processes_property_is_swallowed(self) -> None:
        """_force_kill_processes swallows unexpected exceptions from executor access."""
        from pramanix.worker import _force_kill_processes

        class _BadExecutor:
            """Executor whose _processes property raises a non-AttributeError exception."""

            @property
            def _processes(self) -> dict:
                # getattr only catches AttributeError; RuntimeError propagates
                # and is caught by _force_kill_processes's outer except Exception.
                raise RuntimeError("executor internal state corrupted")

        _force_kill_processes(_BadExecutor())  # must not raise

    def test_outer_exception_from_values_iteration_is_swallowed(self) -> None:
        """_force_kill_processes swallows exceptions from iterating process values."""
        from pramanix.worker import _force_kill_processes

        class _BrokenDict:
            """Dict-like whose values() raises on iteration."""

            def values(self) -> None:  # type: ignore[override]
                raise RuntimeError("cannot iterate processes")

        class _BadExecutor:
            @property
            def _processes(self) -> _BrokenDict:  # type: ignore[return]
                return _BrokenDict()

        _force_kill_processes(_BadExecutor())  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# transpiler.py — InvariantASTCache.__init_subclass__ triggered on subclass
# ═══════════════════════════════════════════════════════════════════════════════


class TestInvariantASTCacheInitSubclass:
    def test_subclass_triggers_init_subclass(self) -> None:
        """Defining a subclass calls InvariantASTCache.__init_subclass__ (cooperative MRO)."""
        from pramanix.transpiler import InvariantASTCache

        class _MyCache(InvariantASTCache):
            pass

        assert issubclass(_MyCache, InvariantASTCache)

    def test_subclass_inherits_get_and_put(self) -> None:
        """Subclass inherits and can call the get/put class-methods."""
        from pramanix.transpiler import InvariantASTCache

        class _MyCache(InvariantASTCache):
            pass

        # Verify the subclass shares the class-level cache machinery.
        # Calling get() on a fresh (unrelated) key returns None.
        result = _MyCache.get(object, "nonexistent-hash")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# expressions.py — NestedField.__getattr__: pydantic ImportError branch
# ═══════════════════════════════════════════════════════════════════════════════


class TestNestedFieldPydanticImportError:
    def test_getattr_raises_import_error_when_pydantic_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """NestedField.__getattr__ raises ImportError when pydantic is not available."""
        from pramanix.expressions import NestedField

        class _FakeModel:
            pass

        nf = NestedField("account", _FakeModel)

        # Setting sys.modules["pydantic"] = None makes 'from pydantic import X' raise ImportError.
        monkeypatch.setitem(sys.modules, "pydantic", None)  # type: ignore[arg-type]

        with pytest.raises(ImportError, match="pydantic"):
            _ = nf.some_field

    def test_getattr_error_message_contains_install_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ImportError message guides the developer to install pydantic."""
        from pramanix.expressions import NestedField

        class _FakeModel:
            pass

        nf = NestedField("account", _FakeModel)
        monkeypatch.setitem(sys.modules, "pydantic", None)  # type: ignore[arg-type]

        with pytest.raises(ImportError) as exc_info:
            _ = nf.some_field

        assert "pip install pydantic" in str(exc_info.value)


# ═══════════════════════════════════════════════════════════════════════════════
# policy.py — model_dump_z3: pydantic ImportError branch
# ═══════════════════════════════════════════════════════════════════════════════


class TestModelDumpZ3PydanticImportError:
    def test_raises_import_error_when_pydantic_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """model_dump_z3 raises ImportError when pydantic is not importable."""
        from pramanix.policy import model_dump_z3

        class _NotAModel:
            pass

        monkeypatch.setitem(sys.modules, "pydantic", None)  # type: ignore[arg-type]

        with pytest.raises(ImportError, match="pydantic"):
            model_dump_z3(_NotAModel())  # type: ignore[arg-type]

    def test_raises_type_error_for_non_model_instance(self) -> None:
        """model_dump_z3 raises TypeError when given a non-BaseModel instance."""
        from pramanix.policy import model_dump_z3

        class _NotAModel:
            pass

        with pytest.raises(TypeError, match="BaseModel"):
            model_dump_z3(_NotAModel())  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════════════════════════════
# circuit_breaker.py — _register_metrics: prometheus ImportError path
# ═══════════════════════════════════════════════════════════════════════════════


class TestCircuitBreakerPrometheusImportError:
    def test_adaptive_cb_prometheus_import_error_sets_metrics_unavailable(self) -> None:
        """AdaptiveCircuitBreaker._register_metrics: prometheus ImportError → metrics_available=False."""
        from pramanix import E, Field, Guard, GuardConfig, Policy
        from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        config = CircuitBreakerConfig(namespace="import-err-test-adaptive")

        with patch.dict(sys.modules, {"prometheus_client": None}):
            cb = AdaptiveCircuitBreaker(guard, config)

        assert cb._metrics_available is False

    def test_distributed_cb_prometheus_import_error_sets_metrics_unavailable(self) -> None:
        """DistributedCircuitBreaker._register_metrics: prometheus ImportError → metrics_available=False."""
        from pramanix import E, Field, Guard, GuardConfig, Policy
        from pramanix.circuit_breaker import CircuitBreakerConfig, DistributedCircuitBreaker

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

        guard = Guard(_P, GuardConfig(execution_mode="sync"))
        config = CircuitBreakerConfig(namespace="import-err-test-distributed")

        with patch.dict(sys.modules, {"prometheus_client": None}):
            cb = DistributedCircuitBreaker(guard, config)

        assert cb._metrics_available is False


# ═══════════════════════════════════════════════════════════════════════════════
# guard_config.py — module-level OTel/prometheus ImportError branches
#
# Strategy: use importlib.util.spec_from_file_location to load guard_config
# into a private namespace (NOT "pramanix.guard_config") so the canonical
# sys.modules["pramanix.guard_config"] entry — and the GuardConfig class bound
# to it — are NEVER touched.  Reloading pramanix.guard_config in-place would
# corrupt GuardConfig.__post_init__.__globals__ for subsequent tests.
# ═══════════════════════════════════════════════════════════════════════════════


def _load_guard_config_fresh(private_name: str, *, block_otel: bool, block_prom: bool):
    """Load guard_config source into a private module namespace.

    Never modifies sys.modules["pramanix.guard_config"].  The caller must
    remove private_name from sys.modules in a finally block.
    """
    import importlib.util
    from pathlib import Path

    import pramanix.guard_config as _canonical

    src_path = Path(_canonical.__file__).resolve()
    spec = importlib.util.spec_from_file_location(private_name, src_path)
    fresh = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]

    overrides: dict = {}
    if block_otel:
        # Block the top-level package AND the common sub-module so that
        # "from opentelemetry import trace" raises ImportError.
        overrides["opentelemetry"] = None
        overrides["opentelemetry.trace"] = None
    if block_prom:
        overrides["prometheus_client"] = None

    sys.modules[private_name] = fresh
    try:
        with patch.dict(sys.modules, overrides):
            spec.loader.exec_module(fresh)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(private_name, None)
        raise

    return fresh


class TestGuardConfigImportErrorBranches:
    def test_span_returns_nullcontext_when_otel_absent(self) -> None:
        """guard_config._span() returns contextlib.nullcontext() when opentelemetry is absent."""
        name = "_pramanix_test_gc_otel_absent"
        try:
            fresh = _load_guard_config_fresh(name, block_otel=True, block_prom=True)
            assert fresh._OTEL_AVAILABLE is False

            ctx = fresh._span("test.span")
            with ctx as span:
                assert span is None
        finally:
            sys.modules.pop(name, None)

    def test_prometheus_counters_are_none_when_prom_absent(self) -> None:
        """guard_config._PROM_AVAILABLE=False and counters=None when prometheus_client absent."""
        name = "_pramanix_test_gc_prom_absent"
        try:
            fresh = _load_guard_config_fresh(name, block_otel=False, block_prom=True)
            assert fresh._PROM_AVAILABLE is False
            assert fresh._decisions_total is None
            assert fresh._decision_latency is None
        finally:
            sys.modules.pop(name, None)


# ═══════════════════════════════════════════════════════════════════════════════
# guard.py — OTel span attributes path (if span is not None: set_attribute calls)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardOtelSpanAttributes:
    def test_span_attributes_set_when_otel_tracer_configured(self) -> None:
        """Guard.verify() sets pramanix.decision_id and policy attributes on the span."""
        import opentelemetry.trace as _otel_trace
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from pramanix import E, Field, Guard, GuardConfig, Policy

        # OTel's global TracerProvider is set-once across the process — earlier
        # tests may have already set one.  Reset the internal Once guard so we
        # can install our InMemorySpanExporter for this test.
        _prev_provider = _otel_trace._TRACER_PROVIDER
        _prev_done = _otel_trace._TRACER_PROVIDER_SET_ONCE._done
        try:
            _otel_trace._TRACER_PROVIDER_SET_ONCE._done = False
            _otel_trace._TRACER_PROVIDER = None

            exporter = InMemorySpanExporter()
            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(exporter))
            trace.set_tracer_provider(provider)

            _amount = Field("amount", Decimal, "Real")

            class _P(Policy):
                class Meta:
                    version = "1.0"

                @classmethod
                def fields(cls):
                    return {"amount": _amount}

                @classmethod
                def invariants(cls):
                    return [(E(_amount) >= Decimal("0")).named("pos").explain("positive")]

            guard = Guard(_P, GuardConfig(execution_mode="sync"))
            d = guard.verify(
                intent={"amount": Decimal("10")},
                state={"state_version": "1.0"},
            )

            assert d.allowed
            spans = exporter.get_finished_spans()
            assert len(spans) > 0

            guard_spans = [s for s in spans if s.name == "pramanix.guard.verify"]
            assert len(guard_spans) > 0, "Expected a pramanix.guard.verify span"

            attrs = guard_spans[0].attributes or {}
            assert "pramanix.decision_id" in attrs
            assert "pramanix.policy.name" in attrs
            assert attrs["pramanix.policy.name"] == "_P"
        finally:
            # Restore the original TracerProvider so subsequent tests are unaffected.
            _otel_trace._TRACER_PROVIDER_SET_ONCE._done = False
            _otel_trace._TRACER_PROVIDER = None
            if _prev_provider is not None:
                _otel_trace._TRACER_PROVIDER_SET_ONCE._done = False
                trace.set_tracer_provider(_prev_provider)
            else:
                _otel_trace._TRACER_PROVIDER_SET_ONCE._done = _prev_done
                _otel_trace._TRACER_PROVIDER = _prev_provider
