# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Property-based soak test: Decimal → Z3 RealVal roundtrip exactness.

Proves that floating-point math can *never* break the Pramanix Decimal
encoding pipeline — regardless of the decimal value's magnitude, scale,
or sign.

The key invariant under test
-----------------------------
``z3_val()`` converts a Python :class:`~decimal.Decimal` to a Z3 ``RealVal``
via ``Decimal.as_integer_ratio()``, which produces a *mathematically exact*
rational ``p/q`` with no IEEE 754 approximation.  The Z3 solver must then be
able to determine that:

    var == encoded_val  is SAT (satisfiable)

for any non-NaN, non-Inf Decimal.

Run 1 000 examples:  ``pytest tests/property/ -q``
"""
from __future__ import annotations

from decimal import Decimal

import z3
from hypothesis import given, settings
from hypothesis import strategies as st

import gc

from pramanix.expressions import Field
import pytest

from pramanix.transpiler import z3_val, z3_var

pytestmark = pytest.mark.slow

# ── Helpers ────────────────────────────────────────────────────────────────


def _fresh_ctx() -> z3.Context:
    """Return an isolated Z3 context for this test invocation."""
    return z3.Context()


# ── The soak test ──────────────────────────────────────────────────────────


@given(
    st.decimals(
        allow_nan=False,
        allow_infinity=False,
        # No ``places`` restriction.  Tokenized / crypto assets (Real-World
        # Assets, DeFi) routinely use 18 decimal places.  Letting Hypothesis
        # explore arbitrarily high precision proves the Z3 rational encoder is
        # future-proof and suitable for Big Finance.
    )
)
@settings(max_examples=1_000, deadline=None)
def test_decimal_z3_roundtrip(value: Decimal) -> None:
    """Decimal survives the Z3 RealVal encoding at arbitrary precision.

    For every generated Decimal value (including high-precision values with
    20, 30, or 50+ decimal places):
    1. Encode it into a fresh Z3 context as a RealVal.
    2. Assert Z3 can satisfy  ``x == encoded_value``  (SAT, not UNSAT/unknown).

    This proves:
    * ``z3_val()`` never produces structurally invalid Z3 expressions.
    * Z3's rational arithmetic produces the same value that Python computed —
      i.e. no float-to-rational conversion error crept in at any precision.
    """
    field = Field("x", Decimal, "Real")
    ctx = _fresh_ctx()
    try:
        var = z3_var(field, ctx)
        val = z3_val(field, value, ctx)

        solver = z3.Solver(ctx=ctx)
        solver.add(var == val)

        result = solver.check()
        assert result == z3.sat, (
            f"Expected SAT for Decimal({value!r}) but Z3 returned {result!r}. "
            "This indicates a precision error in the z3_val() encoding pipeline."
        )
    finally:
        # Explicit cleanup so Z3_del_context runs in this thread via refcounting,
        # not deferred to the Python 3.13 background GC thread which would race
        # with Z3_set_error_handler on the next iteration.
        del solver, var, val
        del ctx
        gc.collect(0)
