# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Reusable SolverProtocol-compliant stubs for unit tests.

These classes are real implementations of the ``SolverProtocol`` interface —
they are NOT mocks or unittest.mock objects.  Each stub exercises a specific
failure/edge-case mode of the Z3 solver surface, enabling deterministic tests
without patching the Z3 C extension or any ``pramanix.guard`` internal.

Available stubs
---------------
- ``RaisingSolverStub`` — ``check()`` raises a configurable exception;
  covers Z3Exception, MemoryError, TranspileError, RuntimeError,
  KeyboardInterrupt, and any other type Guard must handle.
- ``TimeoutSolverStub``  — ``check()`` returns ``z3.unknown`` →
  ``SolverTimeoutError``; simulates SMT budget exhaustion.
- ``FailingSolverStub``  — ``check()`` raises ``RuntimeError``; kept for
  backwards-compatibility with existing tests.
- ``SlowSolverStub``     — ``check()`` raises ``TimeoutError``; legacy alias.
- ``UnsatSolverStub``    — ``check()`` returns ``z3.unsat``; ``unsat_core()``
  returns the tracked formula labels.
- ``SatSolverStub``      — ``check()`` always returns ``z3.sat``.
"""

from __future__ import annotations

from typing import Any

import z3 as _z3


# ── Primary stubs ────────────────────────────────────────────────────────────


class RaisingSolverStub:
    """Solver stub that raises a configurable exception from ``check()``.

    Replaces ``monkeypatch.setattr(_guard_mod, "solve", _raise)`` in
    fail-safe tests.  Pass the exception instance you want the solver to
    raise; ``Guard.verify()`` must catch it and return ``allowed=False``.

    Args:
        exc: Any ``BaseException`` instance — including ``KeyboardInterrupt``
             for tests that verify non-``Exception`` errors propagate.
    """

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        raise self._exc

    def unsat_core(self) -> list[Any]:
        return []

    def reset(self) -> None:
        pass


class TimeoutSolverStub:
    """Solver stub whose ``check()`` returns ``z3.unknown``.

    ``solver.py`` converts ``unknown`` into ``SolverTimeoutError``
    (Budget exhausted / resource limit hit).  Use to verify Guard returns
    ``Decision.timeout()`` — always ``allowed=False`` — without sleeping.
    """

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        return _z3.unknown

    def unsat_core(self) -> list[Any]:
        return []

    def reset(self) -> None:
        pass


# ── Backwards-compatible stubs ───────────────────────────────────────────────


class FailingSolverStub:
    """Solver stub whose ``check()`` always raises ``RuntimeError``.

    Equivalent to ``RaisingSolverStub(RuntimeError(...))``; kept for
    backwards-compatibility with existing callers.
    """

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        raise RuntimeError("FailingSolverStub: solver failure for testing.")

    def unsat_core(self) -> list[Any]:
        return []

    def reset(self) -> None:
        pass


class SlowSolverStub:
    """Solver stub whose ``check()`` raises ``TimeoutError``.

    Legacy alias; prefer ``TimeoutSolverStub`` for new tests (it exercises
    the real ``SolverTimeoutError`` path via ``z3.unknown``).
    """

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        raise TimeoutError("SlowSolverStub: SMT timeout injected for testing.")

    def unsat_core(self) -> list[Any]:
        return []

    def reset(self) -> None:
        pass


class UnsatSolverStub:
    """Solver stub that always returns ``z3.unsat``.

    Accumulates formula labels passed to ``assert_and_track()`` and returns
    them from ``unsat_core()``, enabling assertions on which invariants were
    tracked.
    """

    def __init__(self) -> None:
        self._labels: list[str] = []

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        self._labels.append(label)

    def check(self) -> Any:
        return _z3.unsat

    def unsat_core(self) -> list[Any]:
        return list(self._labels)

    def reset(self) -> None:
        self._labels.clear()


class SatSolverStub:
    """Solver stub that always returns ``z3.sat`` (all invariants satisfied).

    Use to verify that ``Guard.verify()`` returns an ``ALLOWED`` decision
    when the solver confirms satisfiability.
    """

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        return _z3.sat

    def unsat_core(self) -> list[Any]:
        return []

    def reset(self) -> None:
        pass
