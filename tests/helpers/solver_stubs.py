# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Reusable SolverProtocol-compliant stubs for unit tests.

These classes are real implementations of the ``SolverProtocol`` interface —
they are NOT mocks or unittest.mock objects.  Each stub exercises a specific
failure/edge-case mode of the Z3 solver surface, enabling deterministic tests
without patching the Z3 C extension.

Available stubs
---------------
- ``FailingSolverStub``  — ``check()`` raises ``RuntimeError`` immediately.
- ``SlowSolverStub``     — ``check()`` raises ``TimeoutError``; simulates SMT
  timeout without touching ``time.sleep``.
- ``UnsatSolverStub``    — ``check()`` returns a ``_UnsatResult`` sentinel;
  ``unsat_core()`` returns the tracked formula labels.
- ``SatSolverStub``      — ``check()`` always returns a ``_SatResult`` sentinel.
"""

from __future__ import annotations

from typing import Any

# ── Result sentinels (no z3 dependency required) ─────────────────────────────


class _SatResult:
    """Lightweight SAT sentinel — str-compares as ``"sat"``."""

    def __str__(self) -> str:
        return "sat"

    def __repr__(self) -> str:
        return "_SatResult()"


class _UnsatResult:
    """Lightweight UNSAT sentinel — str-compares as ``"unsat"``."""

    def __str__(self) -> str:
        return "unsat"

    def __repr__(self) -> str:
        return "_UnsatResult()"


_SAT = _SatResult()
_UNSAT = _UnsatResult()


# ── Stubs ─────────────────────────────────────────────────────────────────────


class FailingSolverStub:
    """Solver stub whose ``check()`` always raises ``RuntimeError``.

    Use to verify that ``Guard.verify()`` converts solver errors into a
    ``BLOCKED`` decision via the fail-safe path — not an unhandled exception.
    """

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        raise RuntimeError("FailingSolverStub: solver failure injected for testing.")

    def unsat_core(self) -> list[Any]:
        return []


class SlowSolverStub:
    """Solver stub whose ``check()`` raises ``TimeoutError``.

    Simulates SMT solver timeout without calling ``time.sleep``.  Confirms
    that the Guard's timeout-error path returns ``BLOCKED``.
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


class UnsatSolverStub:
    """Solver stub that always returns UNSAT.

    Accumulates formula labels passed to ``assert_and_track()`` and returns
    them from ``unsat_core()``, enabling tests to assert which invariants
    were tracked.
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
        return _UNSAT

    def unsat_core(self) -> list[Any]:
        return list(self._labels)


class SatSolverStub:
    """Solver stub that always returns SAT (all invariants satisfied).

    Use to verify that ``Guard.verify()`` returns an ``ALLOWED`` decision when
    the solver confirms satisfiability.
    """

    def set(self, key: str, value: Any) -> None:
        pass

    def add(self, *formulas: Any) -> None:
        pass

    def assert_and_track(self, formula: Any, label: str) -> None:
        pass

    def check(self) -> Any:
        return _SAT

    def unsat_core(self) -> list[Any]:
        return []
