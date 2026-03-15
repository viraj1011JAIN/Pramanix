#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Expression tree pre-compilation spike.

Proves the optimization is valid BEFORE touching production code.
Must print: EQUIVALENCE CHECK: PASSED
"""
from __future__ import annotations

import sys
import time
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import z3
from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.transpiler import compile_policy, collect_fields, transpile, InvariantMeta

# ── Minimal banking policy ─────────────────────────────────────────────────────

_amount  = Field("amount",    Decimal, "Real")
_balance = Field("balance",   Decimal, "Real")
_frozen  = Field("is_frozen", bool,    "Bool")
_limit   = Field("daily_limit", Decimal, "Real")
_risk    = Field("risk_score",  float,  "Real")


class BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount, "balance": _balance, "is_frozen": _frozen,
            "daily_limit": _limit, "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance")
                .explain("Balance insufficient"),
            (E(_frozen) == False)
                .named("account_not_frozen")
                .explain("Account is frozen"),
            (E(_amount) <= E(_limit))
                .named("within_daily_limit")
                .explain("Amount exceeds daily limit"),
            (E(_risk) <= 0.8)
                .named("acceptable_risk")
                .explain("Risk score too high"),
            (E(_amount) > Decimal("0"))
                .named("positive_amount")
                .explain("Amount must be positive"),
        ]


# ── Compile metadata (walks tree once) ────────────────────────────────────────

invariants = BankingPolicy.invariants()
meta_list = compile_policy(invariants)

print(f"Compiled {len(meta_list)} invariants:")
for m in meta_list:
    print(f"  - {m.label}: fields={sorted(m.field_refs)}, has_literal={m.has_literal}")

# ── Equivalence check ─────────────────────────────────────────────────────────

def check_equivalence():
    """Verify compiled metadata matches full tree-walk for each invariant."""
    for i, (inv, meta) in enumerate(zip(invariants, meta_list)):
        # Check label matches
        if inv.label != meta.label:
            return False, f"Label mismatch: {inv.label} != {meta.label}"

        # Check field_refs match
        full_fields = set(collect_fields(inv.node).keys())
        if full_fields != meta.field_refs:
            return False, f"Field refs mismatch for '{meta.label}': {full_fields} != {meta.field_refs}"

        # Check tree_repr is deterministic
        from pramanix.transpiler import _tree_repr
        repr1 = _tree_repr(inv)
        repr2 = _tree_repr(inv)
        if repr1 != repr2:
            return False, f"tree_repr not deterministic for '{meta.label}'"

    return True, "All checks passed"


passed, msg = check_equivalence()
print(f"\nEQUIVALENCE CHECK: {'PASSED' if passed else 'FAILED — ' + msg}")

# ── Performance comparison ────────────────────────────────────────────────────

N = 10_000

# Full tree-walk (baseline)
t0 = time.monotonic()
for _ in range(N):
    for inv in invariants:
        _ = collect_fields(inv.node)
full_walk_s = time.monotonic() - t0

# Cached metadata access (optimized)
t0 = time.monotonic()
for _ in range(N):
    for meta in meta_list:
        _ = meta.field_refs
cached_s = time.monotonic() - t0

speedup = full_walk_s / max(cached_s, 1e-9)
print(f"\nFull walk: {full_walk_s*1000:.2f}ms for {N} iterations")
print(f"Cached access: {cached_s*1000:.2f}ms for {N} iterations")
print(f"WALK speedup: {speedup:.1f}x faster than full re-walk")

if speedup >= 1.3:
    print("SPEEDUP GATE: PASSED")
else:
    print(f"SPEEDUP GATE: FAILED (expected >= 1.3x, got {speedup:.1f}x)")

sys.exit(0 if passed else 1)
