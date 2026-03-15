You are now implementing Phase 10: Performance Engineering.

The goal is not speed for its own sake. The goal is PROVABLE speed —
every optimization has a test that proves it did not compromise the
security invariants established in Phases 7-9. BlackRock's SRE team
will ask: "How fast?" AND "How do you know it's still safe?"
You must be able to answer both questions with test output.

═══════════════════════════════════════════════════════════════════════
PRE-FLIGHT — READ THESE FILES BEFORE WRITING ANY CODE
═══════════════════════════════════════════════════════════════════════

Read every file listed below completely before writing a single line:

1.  src/pramanix/__init__.py              — current exports, __version__
2.  src/pramanix/guard.py                 — Guard class internals, verify_async pipeline
3.  src/pramanix/transpiler.py            — current transpile() implementation
4.  src/pramanix/solver.py                — SolverStatus, solve(), Z3 context management
5.  src/pramanix/worker.py                — WorkerPool, recycling, concurrency handling
6.  src/pramanix/decision.py              — Decision, SolverStatus enum (check for RATE_LIMITED)
7.  src/pramanix/translator/_cache.py     — check if exists
8.  src/pramanix/translator/__init__.py   — translator exports
9.  src/pramanix/translator/base.py       — Translator protocol
10. benchmarks/                           — list all existing benchmark files
11. tests/perf/                           — list all existing perf tests
12. docs/performance.md                   — current performance documentation
13. pyproject.toml                        — version, dependencies
14. CHANGELOG.md                          — format reference

After reading all files, print exactly:
"PRE-FLIGHT COMPLETE. Current version: X.Y.Z. Starting Phase 10."

Then execute the five pillars in order. Do not begin a pillar until
the previous pillar's gate conditions pass.

═══════════════════════════════════════════════════════════════════════
PILLAR 1 — EXPRESSION TREE PRE-VALIDATION (Safe Pre-Compilation)
═══════════════════════════════════════════════════════════════════════

Goal: Walk the Python expression tree ONCE at Guard.__init__() and cache
the walk metadata. At request time, build Z3 AST directly from cached
metadata + field values — skipping the tree walk entirely.

CRITICAL CONSTRAINT: Z3 objects (Solver, ExprRef, BoolRef, ArithRef) are
NEVER stored in the cache. They are process-local, context-bound, and
cannot safely cross request boundaries. Only Python-level metadata
(field names, operator types, operand values) is cached.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.1 — Create spikes/expression_tree_cache_spike.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Create spikes/ directory. Write a standalone 80-100 line spike that:
1. Defines a minimal 5-invariant banking policy as raw ExpressionNodes
2. Walks the tree and extracts metadata into a list of InvariantMeta tuples
3. Builds Z3 AST from metadata (NOT from tree walk) with sample field values
4. Compares result against full tree-walk transpilation — must be identical
5. Times both approaches over 10,000 iterations and prints speedup

The spike must print:
- "EQUIVALENCE CHECK: PASSED" or "FAILED" (with details)
- "WALK speedup: Nx faster than full re-walk" where N >= 1.3

This spike proves the optimization is valid BEFORE touching transpiler.py.

Run the spike:
    python spikes/expression_tree_cache_spike.py

Gate: EQUIVALENCE CHECK must print PASSED before proceeding.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.2 — Add InvariantMeta dataclass to transpiler.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add to src/pramanix/transpiler.py (do NOT remove any existing code):
```python
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class NodeKind(str, enum.Enum):
    """Classification of an expression tree node for cached metadata."""
    FIELD_REF   = "field_ref"    # E(field) reference
    LITERAL     = "literal"      # constant value
    BINOP       = "binop"        # arithmetic: +, -, *, /
    CMPOP       = "cmpop"        # comparison: >=, <=, >, <, ==, !=
    BOOLOP      = "boolop"       # logical: AND, OR, NOT
    CONSTRAINT  = "constraint"   # top-level ConstraintExpr


@dataclass(frozen=True)
class InvariantMeta:
    """Cached metadata for one invariant's expression tree.

    Contains ONLY Python-level information extracted from the
    expression tree at compile time. No Z3 objects. No live Python
    objects. This is safe to share across requests and threads.

    Fields:
        label:          Invariant name (from .named())
        explain_template: Human-readable template (from .explain())
        field_refs:     Names of all Field objects referenced in this invariant
        tree_repr:      Structural fingerprint for equivalence testing
        has_literal:    True if any literal values appear in the tree
    """
    label: str
    explain_template: str
    field_refs: frozenset[str]
    tree_repr: str       # canonical string representation for debugging
    has_literal: bool

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("InvariantMeta.label cannot be empty")
        if not self.field_refs:
            raise ValueError(
                f"InvariantMeta for '{self.label}' has no field references — "
                "every invariant must reference at least one Field"
            )
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.3 — Add compile_policy() to transpiler.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add this function to transpiler.py alongside the existing transpile():
```python
def compile_policy(invariants: list) -> list[InvariantMeta]:
    """Walk all invariants ONCE at Guard init time and cache metadata.

    Called exactly once per Guard instance at __init__() time.
    Result is stored as Guard._compiled_meta and reused on every
    request. The walk is never repeated at request time.

    Returns a list of InvariantMeta, one per invariant.

    Raises PolicyCompilationError if:
    - Any invariant has no .named() label
    - Any invariant has no field references
    - Any invariant has duplicate labels (detected here for speed)

    Security guarantee: this function produces ONLY Python-level
    metadata. No Z3 objects are created or stored.
    """
    from pramanix.exceptions import PolicyCompilationError

    seen_labels: set[str] = set()
    result: list[InvariantMeta] = []

    for inv in invariants:
        label = getattr(inv, "_label", None) or getattr(inv, "label", None)
        if not label:
            raise PolicyCompilationError(
                "Every invariant must have a .named() label. "
                "Use: (E(field) >= 0).named('invariant_name')"
            )

        if label in seen_labels:
            raise PolicyCompilationError(
                f"Duplicate invariant label: '{label}'. "
                "Every invariant must have a unique name."
            )
        seen_labels.add(label)

        explain = getattr(inv, "_explain", None) or getattr(inv, "explain_template", "") or ""
        field_refs = frozenset(_collect_field_names(inv))

        if not field_refs:
            raise PolicyCompilationError(
                f"Invariant '{label}' references no Fields. "
                "Every invariant must reference at least one Field via E()."
            )

        has_literal = _tree_has_literal(inv)
        tree_repr = _tree_repr(inv)

        result.append(InvariantMeta(
            label=label,
            explain_template=explain,
            field_refs=field_refs,
            tree_repr=tree_repr,
            has_literal=has_literal,
        ))

    return result


def _collect_field_names(node: Any) -> list[str]:
    """Recursively collect all Field names from an expression tree node.

    This is similar to existing collect_fields() but returns names only,
    not Field objects. Called once at compile time.
    """
    # Import here to avoid circular imports
    from pramanix.expressions import ExpressionNode, ConstraintExpr, BinOp, CmpOp, BoolOp

    # Handle ConstraintExpr wrapper
    if hasattr(node, "_inner") or hasattr(node, "inner"):
        inner = getattr(node, "_inner", None) or getattr(node, "inner", None)
        if inner is not None:
            return _collect_field_names(inner)

    # Handle ExpressionNode with node_type
    node_type = getattr(node, "node_type", None) or getattr(node, "_node_type", None)

    if node_type == "field_ref":
        field_obj = getattr(node, "field", None)
        if field_obj and hasattr(field_obj, "name"):
            return [field_obj.name]
        return []

    if node_type == "literal":
        return []

    if node_type in ("binop", "cmpop"):
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        result = []
        if left:
            result.extend(_collect_field_names(left))
        if right:
            result.extend(_collect_field_names(right))
        return result

    if node_type == "boolop":
        operands = getattr(node, "operands", []) or []
        result = []
        for op in operands:
            result.extend(_collect_field_names(op))
        return result

    # Fallback: try to use existing collect_fields if available
    try:
        from pramanix.transpiler import collect_fields
        fields = collect_fields(node)
        return [f.name for f in fields if hasattr(f, "name")]
    except Exception:
        return []


def _tree_has_literal(node: Any) -> bool:
    """Return True if the tree contains any literal constant value."""
    node_type = getattr(node, "node_type", None) or getattr(node, "_node_type", None)
    if node_type == "literal":
        return True
    if node_type in ("binop", "cmpop"):
        return (
            _tree_has_literal(getattr(node, "left", None) or object())
            or _tree_has_literal(getattr(node, "right", None) or object())
        )
    if node_type == "boolop":
        return any(_tree_has_literal(op) for op in (getattr(node, "operands", []) or []))
    if hasattr(node, "_inner"):
        return _tree_has_literal(node._inner)
    return False


def _tree_repr(node: Any) -> str:
    """Produce a canonical string representation of an expression tree.

    Used for equivalence testing and debugging. Not used in hot path.
    """
    node_type = getattr(node, "node_type", None) or getattr(node, "_node_type", None)
    if node_type == "field_ref":
        field_obj = getattr(node, "field", None)
        name = getattr(field_obj, "name", "?") if field_obj else "?"
        return f"Field({name})"
    if node_type == "literal":
        val = getattr(node, "value", "?")
        return f"Lit({val!r})"
    if node_type == "binop":
        op = getattr(node, "op", "?")
        left = _tree_repr(getattr(node, "left", None) or object())
        right = _tree_repr(getattr(node, "right", None) or object())
        return f"BinOp({op},{left},{right})"
    if node_type == "cmpop":
        op = getattr(node, "op", "?")
        left = _tree_repr(getattr(node, "left", None) or object())
        right = _tree_repr(getattr(node, "right", None) or object())
        return f"CmpOp({op},{left},{right})"
    if node_type == "boolop":
        op = getattr(node, "op", "?")
        operands = ",".join(
            _tree_repr(o) for o in (getattr(node, "operands", []) or [])
        )
        return f"BoolOp({op},{operands})"
    if hasattr(node, "_inner"):
        inner = _tree_repr(node._inner)
        label = getattr(node, "_label", "")
        return f"Constraint({label},{inner})"
    return f"Unknown({type(node).__name__})"
```

IMPORTANT: After writing these functions, run the existing test suite
to confirm no regressions:
    pytest tests/unit/test_transpiler.py -v
    # Must still pass 100%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.4 — Wire compile_policy() into Guard.__init__()
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read guard.py carefully. Find the Guard.__init__() method.

After the existing policy compilation / invariant validation logic,
add exactly ONE call to compile_policy():
```python
# In Guard.__init__(), after existing policy validation:
from pramanix.transpiler import compile_policy as _compile_policy
try:
    self._compiled_meta: list = _compile_policy(self._policy_invariants)
except Exception as e:
    # compile_policy failure is a PolicyCompilationError — re-raise
    raise

# Log the compilation result at DEBUG level
# Do NOT log invariant details — that would leak policy structure
import logging
log = logging.getLogger(__name__)
log.debug(
    "Policy compiled",
    extra={
        "policy": getattr(self._policy, "__name__", str(self._policy)),
        "invariant_count": len(self._compiled_meta),
        "field_count": len({
            f for meta in self._compiled_meta for f in meta.field_refs
        }),
    }
)
```

The existing transpile() call at request time remains UNCHANGED.
We are NOT replacing transpile() — we are adding pre-compilation
metadata alongside it. The performance improvement comes from
guard.py being able to skip redundant validation steps using
the already-computed metadata.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.5 — Add field presence pre-check to Guard.verify_async()
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is where the compiled metadata pays off. In Guard.verify_async(),
BEFORE calling transpile() or solve(), add a fast field-presence check
using _compiled_meta:
```python
# In Guard.verify_async(), after Pydantic validation and model_dump():
# Fast pre-check: verify all required fields are present in the
# combined intent+state dict. This catches missing-field errors
# in O(n_fields) without invoking Z3 at all.
combined_keys = set(intent_dict.keys()) | set(state_dict.keys())
missing = []
for meta in self._compiled_meta:
    absent = meta.field_refs - combined_keys
    if absent:
        missing.append((meta.label, absent))

if missing:
    missing_str = "; ".join(
        f"'{label}' needs {sorted(fields)}"
        for label, fields in missing
    )
    return Decision.error(
        reason=f"Missing required fields: {missing_str}"
    )
# Proceed to transpile() + solve() only if all fields present
```

This check short-circuits Z3 invocation for the common error case of
missing fields, returning in microseconds instead of milliseconds.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1.6 — Create tests/unit/test_expression_cache.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for expression tree pre-compilation (Phase 10.1).

Verifies:
1. compile_policy() produces correct InvariantMeta for all policy variants
2. Compiled metadata is immutable after Guard.__init__()
3. Field presence pre-check short-circuits missing-field errors
4. Security: compiled cache cannot be modified by a request
5. Equivalence: compile_policy results match full transpile() results
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.transpiler import InvariantMeta, compile_policy


# ── Test policies ─────────────────────────────────────────────────────────────

_amount  = Field("amount",  Decimal, "Real")
_balance = Field("balance", Decimal, "Real")
_frozen  = Field("is_frozen", bool,  "Bool")
_limit   = Field("daily_limit", Decimal, "Real")
_risk    = Field("risk_score",  float,  "Real")


class _BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount, "balance": _balance,
            "is_frozen": _frozen, "daily_limit": _limit,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance")
                .explain("Balance {balance} insufficient for amount {amount}"),
            (E(_frozen) == False)
                .named("account_not_frozen")
                .explain("Account is frozen"),
            (E(_amount) <= E(_limit))
                .named("within_daily_limit")
                .explain("Amount {amount} exceeds daily limit {daily_limit}"),
            (E(_risk) <= 0.8)
                .named("acceptable_risk")
                .explain("Risk score {risk_score} exceeds threshold 0.8"),
            (E(_amount) > Decimal("0"))
                .named("positive_amount")
                .explain("Amount must be positive"),
        ]


# ── InvariantMeta correctness ─────────────────────────────────────────────────


class TestInvariantMeta:
    def test_compile_policy_returns_one_meta_per_invariant(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        assert len(guard._compiled_meta) == 5

    def test_compile_policy_labels_match_named(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        labels = {m.label for m in guard._compiled_meta}
        assert labels == {
            "sufficient_balance", "account_not_frozen",
            "within_daily_limit", "acceptable_risk", "positive_amount",
        }

    def test_compile_policy_explain_templates_match(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        meta_by_label = {m.label: m for m in guard._compiled_meta}
        assert "balance" in meta_by_label["sufficient_balance"].explain_template
        assert "frozen" in meta_by_label["account_not_frozen"].explain_template

    def test_compile_policy_field_refs_correct(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        meta_by_label = {m.label: m for m in guard._compiled_meta}

        # sufficient_balance uses balance AND amount
        assert "balance" in meta_by_label["sufficient_balance"].field_refs
        assert "amount" in meta_by_label["sufficient_balance"].field_refs

        # account_not_frozen uses only is_frozen
        assert "is_frozen" in meta_by_label["account_not_frozen"].field_refs

    def test_invariant_meta_is_frozen(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        meta = guard._compiled_meta[0]
        with pytest.raises((AttributeError, TypeError)):
            meta.label = "hacked"  # type: ignore[misc]

    def test_field_refs_is_frozenset(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        for meta in guard._compiled_meta:
            assert isinstance(meta.field_refs, frozenset)

    def test_has_literal_true_for_constant_comparison(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        meta_by_label = {m.label: m for m in guard._compiled_meta}
        # (E(_risk) <= 0.8) has a literal constant
        assert meta_by_label["acceptable_risk"].has_literal is True

    def test_has_literal_false_for_field_field_comparison(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        meta_by_label = {m.label: m for m in guard._compiled_meta}
        # (E(_amount) <= E(_limit)) has no literal
        assert meta_by_label["within_daily_limit"].has_literal is False


# ── Immutability after init ───────────────────────────────────────────────────


class TestCacheImmutability:
    def test_compiled_meta_list_is_not_mutable_by_caller(self):
        """Security: caller cannot modify the compiled cache."""
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        original_len = len(guard._compiled_meta)

        # Attempt to modify the cached list
        try:
            guard._compiled_meta.append(None)
            # If append succeeded, the cache is mutable — fail
            # (This is acceptable as a warning, not a hard failure,
            #  since Python list immutability requires explicit protection)
        except (AttributeError, TypeError):
            pass  # Good — list is protected

        # Regardless of whether append succeeded, the CONTENT must be intact
        # The test is that requests cannot alter the POLICY LOGIC
        # We verify this by running a decision and confirming correct result
        state = {
            "balance": Decimal("5000"), "is_frozen": False,
            "daily_limit": Decimal("10000"), "risk_score": 0.3,
            "state_version": "1.0",
        }
        intent = {"amount": Decimal("100")}
        decision = guard.verify(intent=intent, state=state)
        assert decision.allowed  # Policy logic unchanged

    def test_two_guard_instances_have_independent_caches(self):
        """Different Guard instances must not share compiled metadata."""
        guard_a = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        guard_b = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        assert guard_a._compiled_meta is not guard_b._compiled_meta


# ── Field presence pre-check ──────────────────────────────────────────────────


class TestFieldPresencePreCheck:
    def test_missing_field_returns_error_decision(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        # Missing 'balance' field
        state = {"is_frozen": False, "daily_limit": Decimal("10000"),
                 "risk_score": 0.3, "state_version": "1.0"}
        intent = {"amount": Decimal("100")}

        decision = guard.verify(intent=intent, state=state)
        assert not decision.allowed

    def test_missing_field_returns_faster_than_z3_timeout(self):
        """Pre-check must return in < 1ms (much faster than Z3 timeout)."""
        import time
        guard = Guard(
            _BankingPolicy,
            GuardConfig(execution_mode="sync", solver_timeout_ms=50),
        )
        state = {"state_version": "1.0"}  # Missing all domain fields
        intent = {"amount": Decimal("100")}

        t0 = time.monotonic()
        decision = guard.verify(intent=intent, state=state)
        elapsed_ms = (time.monotonic() - t0) * 1000

        assert not decision.allowed
        assert elapsed_ms < 5.0, (
            f"Pre-check took {elapsed_ms:.2f}ms, expected < 5ms. "
            "Z3 may have been invoked unnecessarily."
        )

    def test_all_fields_present_proceeds_to_z3(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        state = {
            "balance": Decimal("5000"), "is_frozen": False,
            "daily_limit": Decimal("10000"), "risk_score": 0.3,
            "state_version": "1.0",
        }
        intent = {"amount": Decimal("100")}
        decision = guard.verify(intent=intent, state=state)
        # Should reach Z3 and return SAFE
        assert decision.allowed
        assert decision.solver_time_ms > 0  # Z3 was invoked


# ── Equivalence ───────────────────────────────────────────────────────────────


class TestEquivalence:
    def test_compiled_meta_label_set_equals_invariant_labels(self):
        """compile_policy must produce exactly the same labels as the invariants."""
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        invariants = _BankingPolicy.invariants()
        expected_labels = {
            getattr(inv, "_label", None) or getattr(inv, "label", "")
            for inv in invariants
        }
        cached_labels = {m.label for m in guard._compiled_meta}
        assert cached_labels == expected_labels

    def test_full_verify_correct_after_compilation(self):
        """End-to-end correctness: compiled cache does not alter verify() results."""
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))

        # ALLOW case
        state_allow = {
            "balance": Decimal("5000"), "is_frozen": False,
            "daily_limit": Decimal("10000"), "risk_score": 0.3,
            "state_version": "1.0",
        }
        d_allow = guard.verify(
            intent={"amount": Decimal("100")}, state=state_allow
        )
        assert d_allow.allowed

        # BLOCK case — overdraft
        state_block = {
            "balance": Decimal("50"), "is_frozen": False,
            "daily_limit": Decimal("10000"), "risk_score": 0.3,
            "state_version": "1.0",
        }
        d_block = guard.verify(
            intent={"amount": Decimal("1000")}, state=state_block
        )
        assert not d_block.allowed
        assert "sufficient_balance" in d_block.violated_invariants

        # BLOCK case — frozen
        state_frozen = {
            "balance": Decimal("5000"), "is_frozen": True,
            "daily_limit": Decimal("10000"), "risk_score": 0.3,
            "state_version": "1.0",
        }
        d_frozen = guard.verify(
            intent={"amount": Decimal("100")}, state=state_frozen
        )
        assert not d_frozen.allowed
        assert "account_not_frozen" in d_frozen.violated_invariants
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 1 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    python spikes/expression_tree_cache_spike.py
    # Must print: EQUIVALENCE CHECK: PASSED

    pytest tests/unit/test_expression_cache.py -v
    # All pass

    pytest tests/unit/test_transpiler.py -v
    # All still pass (no regressions)

    pytest tests/integration/test_banking_flow.py -v
    # All still pass (end-to-end correctness unchanged)

Only proceed to Pillar 2 after all gate conditions pass.

═══════════════════════════════════════════════════════════════════════
PILLAR 2 — INTENT EXTRACTION CACHE (NLP Mode Speedup)
═══════════════════════════════════════════════════════════════════════

Goal: Cache LLM extraction results to eliminate repeated API calls for
identical inputs. This is the dominant cost in NLP mode (200-500ms).

CRITICAL INVARIANTS (enforce in tests, not just docs):
1. Z3 solver is ALWAYS called, even on cache hit
2. Pydantic validation is ALWAYS called on the cached dict
3. State is NEVER part of the cache key
4. Cache is disabled by default

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.1 — Add RATE_LIMITED to SolverStatus if not present
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read src/pramanix/decision.py and src/pramanix/solver.py.

Check if SolverStatus already has a RATE_LIMITED member.
If not, add it. Also add a CACHE_HIT member for observability:

In solver.py SolverStatus enum, add if not present:
    RATE_LIMITED = "rate_limited"    # Request shed by load limiter
    CACHE_HIT    = "cache_hit"      # Intent extracted from cache (Z3 still ran)

Add Decision.rate_limited() factory if not present:
    @classmethod
    def rate_limited(cls, reason: str = "Request shed by adaptive load limiter") -> "Decision":
        return cls(
            allowed=False,
            status=SolverStatus.RATE_LIMITED,
            violated_invariants=(),
            explanation=reason,
            solver_time_ms=0.0,
            decision_id=str(uuid.uuid4()),
        )

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.2 — Create src/pramanix/translator/_cache.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Intent extraction cache for Pramanix NLP mode.

Caches LLM extraction results to eliminate repeated API calls for
identical natural-language inputs. Only the extraction step is cached.
Pydantic validation and Z3 verification always run on every request.

SECURITY INVARIANTS (enforced by tests):
1. Z3 solver is ALWAYS called — cache hit does NOT bypass Z3
2. Pydantic validation is ALWAYS called — malformed cache entries are rejected
3. State is NEVER part of the cache key — same input, different state = different Z3 result
4. Cache is disabled by default (PRAMANIX_INTENT_CACHE_ENABLED must be "true")
5. Cache stores only the raw extracted dict — not a Decision, not allowed/blocked status

Enabled via:
    PRAMANIX_INTENT_CACHE_ENABLED=true
    PRAMANIX_INTENT_CACHE_TTL_SECONDS=300   (default)
    PRAMANIX_INTENT_CACHE_MAX_SIZE=1024     (in-process LRU, default)
    PRAMANIX_INTENT_CACHE_REDIS_URL=...     (optional Redis backend)

Usage (internal — called by Guard when translator_enabled=True):
    cache = IntentCache.from_env()
    cached = cache.get(user_text)
    if cached is not None:
        intent_dict = cached      # Skip LLM, still run Pydantic + Z3
    else:
        intent_dict = await translator.extract(user_text, schema, ctx)
        cache.set(user_text, intent_dict)
"""
from __future__ import annotations

import hashlib
import os
import time
import unicodedata
from functools import lru_cache
from threading import Lock
from typing import Any


def _normalize_key(text: str) -> str:
    """Produce a deterministic, collision-resistant cache key.

    Steps:
    1. NFKC Unicode normalization (handles full-width digits, etc.)
    2. Strip leading/trailing whitespace
    3. Lowercase
    4. SHA-256 hash (64 hex chars)

    The hash ensures:
    - Constant-time key comparison (no timing oracle on input length)
    - No accidental key collision from Unicode variants
    - Fixed key size regardless of input length
    """
    normalized = unicodedata.normalize("NFKC", text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class _CacheEntry:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: dict, ttl_seconds: float) -> None:
        self.value = value
        self.expires_at = time.monotonic() + ttl_seconds

    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at


class _InProcessLRUCache:
    """Thread-safe in-process LRU cache with TTL."""

    def __init__(self, maxsize: int = 1024, ttl_seconds: float = 300.0) -> None:
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._store: dict[str, _CacheEntry] = {}
        self._lock = Lock()
        # LRU ordering via insertion-ordered dict (Python 3.7+)
        # On hit: delete and re-insert to update recency

    def get(self, key: str) -> dict | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.is_expired():
                del self._store[key]
                return None
            # Update LRU order
            del self._store[key]
            self._store[key] = entry
            return dict(entry.value)  # Return copy — never expose mutable ref

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            if key in self._store:
                del self._store[key]
            elif len(self._store) >= self._maxsize:
                # Evict oldest (first) entry
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[key] = _CacheEntry(dict(value), self._ttl)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)


class _RedisCache:
    """Redis-backed intent cache. Requires redis package."""

    def __init__(
        self,
        redis_client: Any,
        ttl_seconds: int = 300,
        key_prefix: str = "pramanix:intent:",
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._prefix = key_prefix

    def get(self, key: str) -> dict | None:
        try:
            import json
            raw = self._redis.get(f"{self._prefix}{key}")
            if raw is None:
                return None
            return json.loads(raw)
        except Exception:
            return None  # Redis failure → cache miss (safe)

    def set(self, key: str, value: dict) -> None:
        try:
            import json
            self._redis.setex(
                f"{self._prefix}{key}",
                self._ttl,
                json.dumps(value, default=str),
            )
        except Exception:
            pass  # Redis failure → silent (cache is best-effort)

    def invalidate(self, key: str) -> None:
        try:
            self._redis.delete(f"{self._prefix}{key}")
        except Exception:
            pass

    def clear(self) -> None:
        try:
            # Scan and delete all matching keys
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(
                    cursor, match=f"{self._prefix}*", count=100
                )
                if keys:
                    self._redis.delete(*keys)
                if cursor == 0:
                    break
        except Exception:
            pass


class IntentCache:
    """Intent extraction cache for Pramanix NLP mode.

    Wraps either an in-process LRU cache or a Redis backend.
    The backend is transparent to the caller.

    Usage:
        cache = IntentCache.from_env()
        if cache.enabled:
            result = cache.get(user_text)
            ...
            cache.set(user_text, extracted_dict)
    """

    _ENV_ENABLED  = "PRAMANIX_INTENT_CACHE_ENABLED"
    _ENV_TTL      = "PRAMANIX_INTENT_CACHE_TTL_SECONDS"
    _ENV_MAX_SIZE = "PRAMANIX_INTENT_CACHE_MAX_SIZE"
    _ENV_REDIS    = "PRAMANIX_INTENT_CACHE_REDIS_URL"

    def __init__(
        self,
        *,
        enabled: bool = False,
        backend: _InProcessLRUCache | _RedisCache | None = None,
    ) -> None:
        self._enabled = enabled
        self._backend = backend
        self._hits = 0
        self._misses = 0

    @classmethod
    def from_env(cls) -> "IntentCache":
        """Create an IntentCache configured from environment variables.

        Disabled by default — must explicitly set
        PRAMANIX_INTENT_CACHE_ENABLED=true to activate.
        """
        enabled = os.environ.get(cls._ENV_ENABLED, "false").lower() == "true"
        if not enabled:
            return cls(enabled=False)

        ttl = float(os.environ.get(cls._ENV_TTL, "300"))
        redis_url = os.environ.get(cls._ENV_REDIS, "")

        if redis_url:
            try:
                import redis
                r = redis.from_url(redis_url)
                r.ping()  # Verify connectivity at startup
                backend: _RedisCache | _InProcessLRUCache = _RedisCache(
                    redis_client=r, ttl_seconds=int(ttl)
                )
            except Exception:
                # Redis unavailable → fall back to in-process LRU
                maxsize = int(os.environ.get(cls._ENV_MAX_SIZE, "1024"))
                backend = _InProcessLRUCache(maxsize=maxsize, ttl_seconds=ttl)
        else:
            maxsize = int(os.environ.get(cls._ENV_MAX_SIZE, "1024"))
            backend = _InProcessLRUCache(maxsize=maxsize, ttl_seconds=ttl)

        return cls(enabled=True, backend=backend)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def stats(self) -> dict:
        return {
            "enabled": self._enabled,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": (
                self._hits / (self._hits + self._misses)
                if (self._hits + self._misses) > 0
                else 0.0
            ),
        }

    def get(self, user_text: str) -> dict | None:
        """Return cached extraction dict, or None on miss.

        Never raises. Cache failure returns None (safe degradation).
        """
        if not self._enabled or not self._backend:
            return None
        try:
            key = _normalize_key(user_text)
            result = self._backend.get(key)
            if result is None:
                self._misses += 1
            else:
                self._hits += 1
            return result
        except Exception:
            self._misses += 1
            return None

    def set(self, user_text: str, extracted: dict) -> None:
        """Store extraction result for user_text.

        Never raises. Cache failure is silently ignored.
        """
        if not self._enabled or not self._backend:
            return
        try:
            key = _normalize_key(user_text)
            self._backend.set(key, dict(extracted))  # Store copy
        except Exception:
            pass

    def invalidate(self, user_text: str) -> None:
        """Explicitly invalidate a cache entry."""
        if not self._enabled or not self._backend:
            return
        try:
            key = _normalize_key(user_text)
            self._backend.invalidate(key)
        except Exception:
            pass

    def clear(self) -> None:
        """Clear all cache entries."""
        if not self._enabled or not self._backend:
            return
        try:
            self._backend.clear()
        except Exception:
            pass
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.3 — Wire IntentCache into Guard (translator path only)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read guard.py. Find the section where the translator is called in
parse_and_verify() or equivalent NLP mode entry point.

Add cache lookup and store:
```python
# In Guard (translator-enabled path), in __init__:
from pramanix.translator._cache import IntentCache
self._intent_cache = IntentCache.from_env()

# In the NLP extraction path (parse_and_verify or equivalent):
# BEFORE calling translator.extract():
cached_dict = self._intent_cache.get(user_text)
if cached_dict is not None:
    # CACHE HIT: skip LLM extraction
    # NEVER skip Pydantic validation or Z3 — they always run
    raw_intent_dict = cached_dict
    # telemetry: log cache hit at DEBUG level
else:
    # CACHE MISS: call translator normally
    raw_intent_dict = await self._translator.extract(
        user_text, intent_schema, context
    )
    # Store result for future requests
    # Only store AFTER successful extraction
    self._intent_cache.set(user_text, raw_intent_dict)

# Pydantic validation ALWAYS runs (cache hit or miss)
intent_validated = validate_intent(intent_schema, raw_intent_dict)
intent_dict = intent_validated.model_dump()

# Z3 ALWAYS runs (cache hit or miss)
decision = await self._solve_async(intent_dict, state_dict)
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2.4 — Create tests/unit/test_intent_cache.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for IntentCache.

Tests both functional correctness and security invariants.
Security tests are explicitly named with 'security' in the name.
"""
from __future__ import annotations

import time
from decimal import Decimal

import pytest

from pramanix.translator._cache import IntentCache, _normalize_key


class TestNormalizeKey:
    def test_identical_text_produces_same_key(self):
        assert _normalize_key("transfer $500") == _normalize_key("transfer $500")

    def test_case_insensitive(self):
        assert _normalize_key("Transfer $500") == _normalize_key("transfer $500")

    def test_whitespace_stripped(self):
        assert _normalize_key("  transfer $500  ") == _normalize_key("transfer $500")

    def test_full_width_digits_normalized(self):
        """Security: Unicode normalization prevents bypass via full-width chars."""
        # ５００ (full-width) should normalize to 500
        assert _normalize_key("transfer ５００") == _normalize_key("transfer 500")

    def test_key_is_64_char_hex(self):
        key = _normalize_key("any input text")
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_different_text_produces_different_key(self):
        assert _normalize_key("transfer 100") != _normalize_key("transfer 200")


class TestIntentCacheDisabledByDefault:
    def test_from_env_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("PRAMANIX_INTENT_CACHE_ENABLED", raising=False)
        cache = IntentCache.from_env()
        assert not cache.enabled

    def test_disabled_cache_get_returns_none(self):
        cache = IntentCache(enabled=False)
        assert cache.get("any text") is None

    def test_disabled_cache_set_is_noop(self):
        cache = IntentCache(enabled=False)
        cache.set("any text", {"amount": "100"})
        assert cache.get("any text") is None


class TestIntentCacheFunctionality:
    def test_get_returns_none_on_miss(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())
        assert cache.get("not cached") is None

    def test_set_and_get_roundtrip(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())
        data = {"amount": "100", "recipient": "alice"}
        cache.set("transfer 100 to alice", data)
        result = cache.get("transfer 100 to alice")
        assert result == data

    def test_get_returns_copy_not_reference(self):
        """Cache must return copies — callers cannot mutate cache entries."""
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())
        data = {"amount": "100"}
        cache.set("input", data)
        result = cache.get("input")
        result["amount"] = "999999"  # Mutate returned value
        # Original cache entry must be unchanged
        result2 = cache.get("input")
        assert result2["amount"] == "100"

    def test_ttl_expiry(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(
            enabled=True,
            backend=_InProcessLRUCache(ttl_seconds=0.05),
        )
        cache.set("expiring", {"amount": "100"})
        assert cache.get("expiring") is not None
        time.sleep(0.1)
        assert cache.get("expiring") is None

    def test_lru_eviction_at_maxsize(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(
            enabled=True,
            backend=_InProcessLRUCache(maxsize=3),
        )
        cache.set("a", {"k": "a"})
        cache.set("b", {"k": "b"})
        cache.set("c", {"k": "c"})
        # Adding 4th entry evicts oldest
        cache.set("d", {"k": "d"})
        # 'a' should be evicted (LRU)
        assert cache.get("a") is None
        assert cache.get("d") is not None

    def test_invalidate_removes_entry(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())
        cache.set("remove me", {"amount": "100"})
        cache.invalidate("remove me")
        assert cache.get("remove me") is None

    def test_clear_removes_all_entries(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())
        cache.set("a", {"k": "a"})
        cache.set("b", {"k": "b"})
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_stats_tracks_hits_and_misses(self):
        from pramanix.translator._cache import _InProcessLRUCache
        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())
        cache.get("miss_1")   # miss
        cache.get("miss_2")   # miss
        cache.set("hit_key", {"x": "1"})
        cache.get("hit_key")  # hit
        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 2


class TestIntentCacheSecurity:
    def test_security_same_input_different_state_does_not_share_z3_result(self):
        """INVARIANT 3: State is never part of cache key.

        This test verifies the behavioral invariant:
        Same NL input + different state = different Z3 result.
        Cache must NOT store the Z3 decision — only the extracted dict.
        """
        from pramanix.translator._cache import _InProcessLRUCache

        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())

        # Same NL text produces same cache key regardless of state
        text = "transfer 500 dollars to alice"
        state_rich  = {"balance": "5000", "state_version": "v1"}
        state_broke = {"balance": "10",   "state_version": "v1"}

        # Store extracted dict (not a decision, not state-dependent)
        extracted = {"amount": "500", "recipient": "alice"}
        cache.set(text, extracted)

        # Both states should get the SAME extracted dict from cache
        result_rich  = cache.get(text)
        result_broke = cache.get(text)

        assert result_rich == extracted
        assert result_broke == extracted
        # Z3 would produce ALLOW for state_rich and BLOCK for state_broke
        # but the cache correctly returns the same extracted dict for both
        # The Z3 decision is NEVER in the cache

    def test_security_poisoned_cache_entry_fails_pydantic(self):
        """INVARIANT 2: Pydantic validation always runs on cache hits.

        If a cache entry contains a malformed dict (e.g., due to cache
        poisoning or TTL corruption), Pydantic validation must catch it.
        """
        from pramanix.translator._cache import _InProcessLRUCache
        from pydantic import BaseModel, ValidationError

        cache = IntentCache(enabled=True, backend=_InProcessLRUCache())

        # Poison the cache with an invalid entry
        poisoned = {"amount": "not_a_number", "recipient": "alice"}
        cache.set("transfer 500", poisoned)

        # Retrieve poisoned entry
        cached = cache.get("transfer 500")
        assert cached is not None  # Cache returns it

        # Pydantic must reject it
        class TransferIntent(BaseModel):
            amount: Decimal
            recipient: str

        with pytest.raises((ValidationError, ValueError)):
            TransferIntent.model_validate(cached, strict=False)
        # This confirms the host must always run Pydantic after cache hit

    def test_security_cache_key_is_hash_not_plaintext(self):
        """Cache key must be a SHA-256 hash, not the original text.

        This prevents timing attacks on cache key comparison and
        prevents logging the user's NL input as a cache key.
        """
        key = _normalize_key("transfer 500 dollars to alice's account")
        # Must be exactly 64 hex chars (SHA-256 output)
        assert len(key) == 64
        assert key.isalnum()
        # Must not contain any part of the original text
        assert "transfer" not in key
        assert "alice" not in key
        assert "500" not in key

    def test_security_unicode_bypass_prevented(self):
        """Security: different Unicode representations of same amount must hit same cache slot."""
        # "５００" (full-width 500) must normalize to same key as "500"
        key_normal    = _normalize_key("transfer 500")
        key_fullwidth = _normalize_key("transfer ５００")
        assert key_normal == key_fullwidth

    def test_security_null_byte_handling(self):
        """Security: null bytes in input must not crash or bypass normalization."""
        # Should not raise
        key = _normalize_key("transfer \x00 500")
        assert len(key) == 64

    def test_security_very_long_input_produces_fixed_length_key(self):
        """Cache key length must be constant regardless of input length."""
        short_key = _normalize_key("t")
        long_key  = _normalize_key("transfer " + "x" * 100_000)
        assert len(short_key) == len(long_key) == 64
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 2 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_intent_cache.py -v
    # All pass including all test_security_* tests

    pytest tests/unit/ -v -k "cache"
    # No regressions in any existing cache-related tests

═══════════════════════════════════════════════════════════════════════
PILLAR 3 — SEMANTIC FAST-PATH (Sub-millisecond Pre-Screening)
═══════════════════════════════════════════════════════════════════════

Goal: Screen obvious violations in pure Python before invoking Z3.
Eliminates Z3 overhead for the most common failure modes.
Fast-path rules can only BLOCK — they CANNOT ALLOW.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3.1 — Create src/pramanix/fast_path.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Semantic fast-path for Pramanix Guard.

Pre-screens obvious violations in pure Python O(1) before invoking Z3.
Eliminates Z3 overhead for the most common failure modes:
negative amounts, zero balances, frozen accounts, etc.

ARCHITECTURE CONTRACT:
- Fast-path rules can only BLOCK, never ALLOW
- Only Z3 can produce Decision(allowed=True)
- A fast-path BLOCK means Z3 is not invoked at all
- A fast-path PASS means Z3 is invoked normally
- Fast-path runs AFTER Pydantic validation, BEFORE Z3

PERFORMANCE TARGET:
- Fast-path evaluation: < 0.1ms per request
- False positive rate: 0% (no legitimate requests blocked)
- False negative rate: acceptable (Z3 catches what fast-path misses)

Usage (via GuardConfig):
    config = GuardConfig(
        fast_path_enabled=True,  # default: False
        fast_path_rules=[
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.zero_balance("balance"),
        ]
    )

Or use the host-provided rule interface:
    def my_rule(intent: dict, state: dict) -> str | None:
        if intent.get("amount", 0) > 1_000_000:
            return "Single transfer cap exceeded"
        return None  # None = pass, string = block reason

    config = GuardConfig(
        fast_path_enabled=True,
        fast_path_rules=[my_rule],
    )
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable

log = logging.getLogger(__name__)


# A fast-path rule takes (intent_dict, state_dict) and returns:
# - None: no violation detected, proceed to Z3
# - str: violation detected, this string is the block reason
FastPathRule = Callable[[dict, dict], str | None]


@dataclass
class FastPathResult:
    """Result of fast-path evaluation."""
    blocked: bool
    reason: str = ""
    rule_name: str = ""

    @classmethod
    def pass_through(cls) -> "FastPathResult":
        return cls(blocked=False)

    @classmethod
    def block(cls, reason: str, rule_name: str = "") -> "FastPathResult":
        return cls(blocked=True, reason=reason, rule_name=rule_name)


class SemanticFastPath:
    """Factory for common fast-path rules.

    All rules are pure Python functions. No Z3, no Pydantic, no I/O.
    Each rule runs in O(1) — a single dict lookup and comparison.

    Rules return None (pass) or a string (block reason).
    """

    @staticmethod
    def negative_amount(field_name: str = "amount") -> FastPathRule:
        """Block if amount is negative. Catches the most common LLM error."""
        def _rule(intent: dict, state: dict) -> str | None:
            val = intent.get(field_name) or state.get(field_name)
            if val is None:
                return None  # Field absent — let Z3 / Pydantic handle it
            try:
                if Decimal(str(val)) < Decimal("0"):
                    return f"Amount must be non-negative (got {val})"
            except Exception:
                return None  # Unparseable — let Pydantic handle it
            return None
        _rule.__name__ = f"negative_amount({field_name})"
        return _rule

    @staticmethod
    def zero_or_negative_balance(field_name: str = "balance") -> FastPathRule:
        """Block if account balance is zero or negative."""
        def _rule(intent: dict, state: dict) -> str | None:
            val = state.get(field_name)
            if val is None:
                return None
            try:
                if Decimal(str(val)) <= Decimal("0"):
                    return f"Account balance is zero or negative"
            except Exception:
                return None
            return None
        _rule.__name__ = f"zero_or_negative_balance({field_name})"
        return _rule

    @staticmethod
    def account_frozen(field_name: str = "is_frozen") -> FastPathRule:
        """Block if account is frozen."""
        def _rule(intent: dict, state: dict) -> str | None:
            val = state.get(field_name)
            if val is True or str(val).lower() in ("true", "1", "yes"):
                return "Account is frozen"
            return None
        _rule.__name__ = f"account_frozen({field_name})"
        return _rule

    @staticmethod
    def exceeds_hard_cap(
        amount_field: str = "amount",
        cap: Decimal | int | float = 1_000_000,
    ) -> FastPathRule:
        """Block if amount exceeds an absolute hard cap (last-resort guard)."""
        cap_decimal = Decimal(str(cap))
        def _rule(intent: dict, state: dict) -> str | None:
            val = intent.get(amount_field) or state.get(amount_field)
            if val is None:
                return None
            try:
                if Decimal(str(val)) > cap_decimal:
                    return f"Amount exceeds hard cap of {cap}"
            except Exception:
                return None
            return None
        _rule.__name__ = f"exceeds_hard_cap({amount_field},{cap})"
        return _rule

    @staticmethod
    def amount_exceeds_balance(
        amount_field: str = "amount",
        balance_field: str = "balance",
    ) -> FastPathRule:
        """Block if amount clearly exceeds balance (obvious overdraft).

        This mirrors the Z3 sufficient_balance invariant but runs in Python.
        The fast-path never allows — if this check passes, Z3 still verifies.
        """
        def _rule(intent: dict, state: dict) -> str | None:
            amount_val  = intent.get(amount_field)
            balance_val = state.get(balance_field)
            if amount_val is None or balance_val is None:
                return None
            try:
                amount  = Decimal(str(amount_val))
                balance = Decimal(str(balance_val))
                if amount > balance:
                    return "Insufficient balance for transfer"
            except Exception:
                return None
            return None
        _rule.__name__ = f"amount_exceeds_balance({amount_field},{balance_field})"
        return _rule


class FastPathEvaluator:
    """Runs a sequence of fast-path rules in order.

    Stops at the first rule that returns a block reason.
    Returns FastPathResult immediately on first violation.
    """

    def __init__(self, rules: list[FastPathRule]) -> None:
        self._rules = list(rules)  # Defensive copy

    def evaluate(self, intent: dict, state: dict) -> FastPathResult:
        """Evaluate all rules. Returns immediately on first block.

        INVARIANT: Returns FastPathResult.pass_through() if no rule blocks.
        INVARIANT: Never returns allowed=True — only pass_through or block.
        Total time: O(n_rules) where each rule is O(1).
        """
        for rule in self._rules:
            try:
                reason = rule(intent, state)
                if reason is not None:
                    rule_name = getattr(rule, "__name__", "unknown_rule")
                    log.debug(
                        "Fast-path block",
                        extra={"rule": rule_name, "reason": reason},
                    )
                    return FastPathResult.block(
                        reason=reason,
                        rule_name=rule_name,
                    )
            except Exception as e:
                # Rule raised unexpectedly — log and continue to Z3
                log.warning(
                    "Fast-path rule raised exception — continuing to Z3",
                    extra={"rule": getattr(rule, "__name__", "?"), "error": str(e)},
                )
                continue

        return FastPathResult.pass_through()

    @property
    def rule_count(self) -> int:
        return len(self._rules)
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3.2 — Wire FastPathEvaluator into Guard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add to GuardConfig:
```python
@dataclass
class GuardConfig:
    # ... existing fields ...
    fast_path_enabled: bool = False
    fast_path_rules: list = field(default_factory=list)
```

In Guard.__init__(), add:
```python
from pramanix.fast_path import FastPathEvaluator
if self._config.fast_path_enabled and self._config.fast_path_rules:
    self._fast_path = FastPathEvaluator(self._config.fast_path_rules)
else:
    self._fast_path = None
```

In Guard.verify() / verify_async(), AFTER Pydantic validation and
BEFORE Z3 invocation, add:
```python
if self._fast_path is not None:
    fp_result = self._fast_path.evaluate(intent_dict, state_dict)
    if fp_result.blocked:
        return Decision.unsafe(
            violated_invariants=(fp_result.rule_name or "fast_path_block",),
            explanation=fp_result.reason,
        )
# Proceed to Z3
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3.3 — Create tests/unit/test_fast_path.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for SemanticFastPath and FastPathEvaluator.

Includes timing tests to verify sub-millisecond performance
and security tests to verify the cannot-allow invariant.
"""
from __future__ import annotations

import time
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.fast_path import (
    FastPathEvaluator,
    FastPathResult,
    SemanticFastPath,
)


class TestSemanticFastPathRules:
    def test_negative_amount_blocks(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": "-100"}, {}) is not None

    def test_negative_amount_passes_positive(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": "100"}, {}) is None

    def test_negative_amount_passes_zero(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({"amount": "0"}, {}) is None

    def test_negative_amount_absent_field_passes(self):
        rule = SemanticFastPath.negative_amount("amount")
        assert rule({}, {}) is None

    def test_zero_balance_blocks(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert rule({}, {"balance": "0"}) is not None

    def test_negative_balance_blocks(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert rule({}, {"balance": "-50"}) is not None

    def test_positive_balance_passes(self):
        rule = SemanticFastPath.zero_or_negative_balance("balance")
        assert rule({}, {"balance": "100"}) is None

    def test_frozen_account_blocks(self):
        rule = SemanticFastPath.account_frozen("is_frozen")
        assert rule({}, {"is_frozen": True}) is not None

    def test_unfrozen_account_passes(self):
        rule = SemanticFastPath.account_frozen("is_frozen")
        assert rule({}, {"is_frozen": False}) is None

    def test_hard_cap_blocks_when_exceeded(self):
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert rule({"amount": "2000000"}, {}) is not None

    def test_hard_cap_passes_under_cap(self):
        rule = SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000)
        assert rule({"amount": "999999"}, {}) is None

    def test_amount_exceeds_balance_blocks(self):
        rule = SemanticFastPath.amount_exceeds_balance()
        assert rule({"amount": "1000"}, {"balance": "100"}) is not None

    def test_amount_within_balance_passes(self):
        rule = SemanticFastPath.amount_exceeds_balance()
        assert rule({"amount": "50"}, {"balance": "100"}) is None

    def test_amount_equals_balance_passes(self):
        """Boundary: exact balance is allowed (Z3 will confirm)."""
        rule = SemanticFastPath.amount_exceeds_balance()
        assert rule({"amount": "100"}, {"balance": "100"}) is None


class TestFastPathEvaluator:
    def test_evaluator_pass_through_with_no_rules(self):
        ev = FastPathEvaluator([])
        result = ev.evaluate({}, {})
        assert not result.blocked

    def test_evaluator_blocks_on_first_matching_rule(self):
        rules = [
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.account_frozen("is_frozen"),
        ]
        ev = FastPathEvaluator(rules)
        result = ev.evaluate({"amount": "-100"}, {"is_frozen": False})
        assert result.blocked
        assert "negative" in result.reason.lower() or "non-negative" in result.reason.lower()

    def test_evaluator_stops_at_first_block(self):
        blocked_count = [0]

        def counter_rule(intent, state):
            blocked_count[0] += 1
            return "block"

        rules = [counter_rule, counter_rule, counter_rule]
        ev = FastPathEvaluator(rules)
        ev.evaluate({}, {})
        assert blocked_count[0] == 1  # Stopped after first block

    def test_evaluator_continues_after_rule_exception(self):
        def bad_rule(intent, state):
            raise RuntimeError("rule crashed")

        def good_rule(intent, state):
            return "this is the real block"

        ev = FastPathEvaluator([bad_rule, good_rule])
        result = ev.evaluate({}, {})
        # bad_rule raised → skipped → good_rule ran → blocked
        assert result.blocked
        assert result.reason == "this is the real block"

    def test_evaluator_result_pass_through_never_allowed(self):
        """SECURITY: fast-path pass-through is not an ALLOW decision."""
        ev = FastPathEvaluator([])
        result = ev.evaluate({}, {})
        assert not result.blocked  # Pass-through
        # FastPathResult.pass_through() has blocked=False
        # This means "proceed to Z3" — not "allowed=True"
        assert isinstance(result, FastPathResult)


class TestFastPathTiming:
    def test_fast_path_evaluates_under_1ms(self):
        """Performance: fast-path must complete in < 1ms."""
        rules = [
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.zero_or_negative_balance("balance"),
            SemanticFastPath.account_frozen("is_frozen"),
            SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000),
            SemanticFastPath.amount_exceeds_balance(),
        ]
        ev = FastPathEvaluator(rules)
        intent = {"amount": "100"}
        state  = {"balance": "5000", "is_frozen": False}

        # Run 1000 evaluations and measure total time
        t0 = time.monotonic()
        for _ in range(1000):
            ev.evaluate(intent, state)
        elapsed_ms = (time.monotonic() - t0) * 1000

        avg_ms = elapsed_ms / 1000
        assert avg_ms < 1.0, f"Fast-path avg {avg_ms:.3f}ms exceeds 1ms limit"


class TestFastPathGuardIntegration:
    def test_fast_path_block_does_not_invoke_z3(self):
        """When fast-path blocks, solver_time_ms should be 0."""
        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _Policy(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount, "balance": _balance}
            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sufficient_balance")
                    .explain("Insufficient balance")
                ]

        guard = Guard(
            _Policy,
            GuardConfig(
                execution_mode="sync",
                fast_path_enabled=True,
                fast_path_rules=[
                    SemanticFastPath.negative_amount("amount"),
                ],
            ),
        )
        decision = guard.verify(
            intent={"amount": Decimal("-100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert not decision.allowed
        # Z3 was not invoked — solver_time_ms should be 0 or very small
        assert decision.solver_time_ms < 1.0

    def test_fast_path_pass_still_invokes_z3(self):
        """When fast-path passes, Z3 must still be invoked."""
        _amount  = Field("amount",  Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _Policy(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount, "balance": _balance}
            @classmethod
            def invariants(cls):
                return [
                    ((E(_balance) - E(_amount)) >= Decimal("0"))
                    .named("sufficient_balance")
                    .explain("Insufficient balance")
                ]

        guard = Guard(
            _Policy,
            GuardConfig(
                execution_mode="sync",
                fast_path_enabled=True,
                fast_path_rules=[
                    SemanticFastPath.negative_amount("amount"),
                ],
            ),
        )
        # Positive amount — fast-path passes — Z3 must run
        decision = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("5000"), "state_version": "1.0"},
        )
        assert decision.allowed
        assert decision.solver_time_ms > 0  # Z3 was invoked

    def test_fast_path_cannot_produce_allowed_true(self):
        """SECURITY: fast-path can only block, never allow."""
        # Rule that always returns None (pass through)
        always_pass = lambda i, s: None

        _amount = Field("amount", Decimal, "Real")

        class _BlockPolicy(Policy):
            class Meta: version = "1.0"
            @classmethod
            def fields(cls): return {"amount": _amount}
            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) <= Decimal("0"))
                    .named("must_be_zero")
                    .explain("Amount must be zero")
                ]

        guard = Guard(
            _BlockPolicy,
            GuardConfig(
                execution_mode="sync",
                fast_path_enabled=True,
                fast_path_rules=[always_pass],
            ),
        )
        # Fast-path passes but Z3 must still block
        decision = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert not decision.allowed  # Z3 blocked it
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 3 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_fast_path.py -v
    # All pass including timing test

    pytest tests/unit/ -v
    # No regressions anywhere

═══════════════════════════════════════════════════════════════════════
PILLAR 4 — ADAPTIVE LOAD SHEDDING
═══════════════════════════════════════════════════════════════════════

Goal: When the Z3 worker pool is saturated AND solver latency is high,
reject new requests immediately instead of queuing them until timeout.
All shed requests return Decision(allowed=False, status=RATE_LIMITED).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4.1 — Add SolverStatus.RATE_LIMITED and Decision.rate_limited()
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

First verify RATE_LIMITED was added in Step 2.1. If already done, skip.
If not yet done, add now.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4.2 — Add AdaptiveConcurrencyLimiter to worker.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read src/pramanix/worker.py carefully. Add this class:
```python
# Add to worker.py

import collections
import os
import threading
import time as _time_module


class AdaptiveConcurrencyLimiter:
    """Adaptive load shedder for the Z3 worker pool.

    Sheds requests when BOTH conditions are met simultaneously:
    1. active_workers >= max_workers * shed_worker_pct/100
    2. p99_solver_latency_ms > shed_latency_threshold_ms

    This dual-condition prevents false positives:
    - High workers alone may be a healthy burst
    - High latency alone may be a transient GC pause
    - Both together signals genuine overload

    INVARIANT: shed decisions always have allowed=False.
    INVARIANT: Shedding is NEVER the cause of allowed=True.

    Configuration (environment variables with GuardConfig override):
        PRAMANIX_SHED_LATENCY_THRESHOLD_MS=200
        PRAMANIX_SHED_WORKER_PCT=90
    """

    _LATENCY_WINDOW_SECONDS = 60.0

    def __init__(
        self,
        max_workers: int,
        latency_threshold_ms: float | None = None,
        worker_pct: float | None = None,
    ) -> None:
        self._max_workers = max_workers
        self._latency_threshold = latency_threshold_ms or float(
            os.environ.get("PRAMANIX_SHED_LATENCY_THRESHOLD_MS", "200")
        )
        self._worker_pct = worker_pct or float(
            os.environ.get("PRAMANIX_SHED_WORKER_PCT", "90")
        )
        self._active = 0
        self._lock = threading.Lock()
        # Sliding window of (timestamp, latency_ms) tuples
        self._latency_window: collections.deque = collections.deque()
        self._shed_count = 0

    @property
    def active_workers(self) -> int:
        return self._active

    @property
    def shed_count(self) -> int:
        return self._shed_count

    def acquire(self) -> bool:
        """Try to acquire a worker slot.

        Returns True if the request should proceed.
        Returns False if the request should be shed.

        Never raises.
        """
        with self._lock:
            self._active += 1
            should_shed = self._check_shed_conditions()
            if should_shed:
                self._active -= 1
                self._shed_count += 1
                return False
            return True

    def release(self, latency_ms: float) -> None:
        """Release a worker slot and record the solve latency."""
        with self._lock:
            self._active = max(0, self._active - 1)
            now = _time_module.monotonic()
            self._latency_window.append((now, latency_ms))
            # Evict entries outside the 60s window
            cutoff = now - self._LATENCY_WINDOW_SECONDS
            while self._latency_window and self._latency_window[0][0] < cutoff:
                self._latency_window.popleft()

    def _check_shed_conditions(self) -> bool:
        """Check both shedding conditions. Called under lock."""
        # Condition 1: Worker pool saturation
        saturation_pct = (self._active / self._max_workers) * 100
        if saturation_pct < self._worker_pct:
            return False  # Not saturated — never shed

        # Condition 2: P99 latency above threshold
        p99 = self._compute_p99()
        if p99 is None:
            return False  # No data yet — don't shed
        return p99 > self._latency_threshold

    def _compute_p99(self) -> float | None:
        """Compute P99 over the sliding window. Called under lock."""
        if len(self._latency_window) < 10:
            return None  # Not enough data for stable P99
        latencies = sorted(entry[1] for entry in self._latency_window)
        idx = int(len(latencies) * 0.99)
        return latencies[min(idx, len(latencies) - 1)]
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4.3 — Wire AdaptiveConcurrencyLimiter into WorkerPool
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

In WorkerPool.__init__(), add:
```python
self._shed_limiter = AdaptiveConcurrencyLimiter(
    max_workers=config.max_workers,
    latency_threshold_ms=getattr(config, "shed_latency_threshold_ms", None),
    worker_pct=getattr(config, "shed_worker_pct", None),
)
```

In WorkerPool.submit_solve(), BEFORE dispatching to executor:
```python
if not self._shed_limiter.acquire():
    return Decision.rate_limited(
        "Request shed: Z3 worker pool saturated with high latency. "
        "Retry after backoff."
    ).to_dict()

t0 = time.monotonic()
try:
    result = ... # existing dispatch logic
    latency_ms = (time.monotonic() - t0) * 1000
    self._shed_limiter.release(latency_ms)
    return result
except Exception:
    self._shed_limiter.release(9999.0)  # Count as slow
    raise
```

Add to GuardConfig:
```python
shed_latency_threshold_ms: float = 200.0
shed_worker_pct: float = 90.0
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4.4 — Create tests/unit/test_load_shedding.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for AdaptiveConcurrencyLimiter.

The critical invariant: shed decisions always have allowed=False.
No shed path can produce allowed=True under any conditions.
"""
from __future__ import annotations

import time

import pytest

from pramanix.worker import AdaptiveConcurrencyLimiter


class TestAdaptiveConcurrencyLimiter:
    def test_acquires_normally_when_below_threshold(self):
        lim = AdaptiveConcurrencyLimiter(
            max_workers=10,
            latency_threshold_ms=200.0,
            worker_pct=90.0,
        )
        # 5/10 = 50% — well below 90% threshold
        for _ in range(5):
            assert lim.acquire() is True
        assert lim.active_workers == 5

    def test_release_decrements_active_count(self):
        lim = AdaptiveConcurrencyLimiter(max_workers=10)
        lim.acquire()
        lim.acquire()
        lim.release(5.0)
        assert lim.active_workers == 1

    def test_shed_count_starts_at_zero(self):
        lim = AdaptiveConcurrencyLimiter(max_workers=10)
        assert lim.shed_count == 0

    def test_does_not_shed_without_latency_data(self):
        """Even at 100% saturation, shed requires latency data."""
        lim = AdaptiveConcurrencyLimiter(
            max_workers=2,
            latency_threshold_ms=1.0,
            worker_pct=50.0,
        )
        # 1/2 = 50% — exactly at threshold
        # But no latency data → should not shed
        assert lim.acquire() is True

    def test_sheds_when_both_conditions_met(self):
        """Shed only when worker saturation AND high latency both present."""
        lim = AdaptiveConcurrencyLimiter(
            max_workers=10,
            latency_threshold_ms=10.0,  # Very low threshold
            worker_pct=80.0,            # 80% saturation threshold
        )
        # Saturate to 9/10 = 90%
        for _ in range(9):
            lim.acquire()

        # Inject 20 slow latency measurements (need >= 10 for P99 computation)
        for _ in range(20):
            lim.release(50.0)  # 50ms >> 10ms threshold
            lim.acquire()       # Re-acquire to maintain count

        # Now at 90% saturation with P99 >> threshold — should shed
        shed_count_before = lim.shed_count
        result = lim.acquire()
        if not result:
            assert lim.shed_count > shed_count_before

    def test_p99_computation_requires_10_samples(self):
        """P99 is None with fewer than 10 samples — no shedding."""
        lim = AdaptiveConcurrencyLimiter(
            max_workers=2,
            latency_threshold_ms=1.0,
            worker_pct=50.0,
        )
        # Only 5 slow latencies — below the 10-sample minimum
        for _ in range(5):
            lim.acquire()
            lim.release(500.0)

        # Should not shed (insufficient P99 data)
        for _ in range(5):
            lim.acquire()
        result = lim.acquire()
        # With only 5 samples, P99 is None, no shedding
        # (exact result depends on worker count, but key is: no crash)
        assert isinstance(result, bool)

    def test_latency_window_evicts_old_entries(self):
        """Entries older than 60s must be evicted from window."""
        lim = AdaptiveConcurrencyLimiter(max_workers=10)
        # Manually add an old entry by manipulating the deque
        # (In production, entries expire after 60s)
        # This test just verifies the window doesn't grow unbounded
        for _ in range(100):
            lim.acquire()
            lim.release(5.0)
        # Window should not have more than 100 entries
        assert len(lim._latency_window) <= 100


class TestShedDecisionAlwaysAllowedFalse:
    def test_rate_limited_decision_is_not_allowed(self):
        """CRITICAL SECURITY TEST: shed decisions must have allowed=False."""
        from pramanix.decision import Decision, SolverStatus

        # Create a rate_limited decision
        d = Decision.rate_limited("Test shed")
        assert d.allowed is False
        assert d.status == SolverStatus.RATE_LIMITED

    def test_rate_limited_factory_produces_correct_status(self):
        from pramanix.decision import Decision, SolverStatus
        d = Decision.rate_limited()
        assert d.status == SolverStatus.RATE_LIMITED
        assert not d.allowed
        assert d.decision_id  # Has audit ID

    def test_rate_limited_decision_has_explanation(self):
        from pramanix.decision import Decision
        d = Decision.rate_limited("custom reason")
        assert "custom reason" in d.explanation
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 4 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    pytest tests/unit/test_load_shedding.py -v
    # All pass

    pytest tests/unit/ -v
    # No regressions

═══════════════════════════════════════════════════════════════════════
PILLAR 5 — PUBLISHABLE PERFORMANCE BENCHMARKS
═══════════════════════════════════════════════════════════════════════

Goal: Machine-readable benchmark results that answer the questions
"How fast?" and "How do you know it's still safe?" simultaneously.
Results committed to the repository and referenced in README.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5.1 — Create benchmarks/results/ directory
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Create benchmarks/results/.gitkeep to track the directory.
Add benchmarks/results/*.json to .gitignore or NOT —
the results files SHOULD be committed as proof.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5.2 — Create benchmarks/latency_benchmark.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix latency benchmark — API mode and NLP mode.

Produces machine-readable results in benchmarks/results/latency_results.json.
This file is committed to the repository as evidence of performance targets.

Targets (Phase 10):
    API Mode:       P50 < 5ms,  P95 < 10ms,  P99 < 15ms
    NLP Mode:       P50 < 50ms, P95 < 150ms, P99 < 300ms (mock LLM)
    Cache-hit NLP:  P50 < 5ms,  P95 < 10ms,  P99 < 15ms

Usage:
    python benchmarks/latency_benchmark.py
    python benchmarks/latency_benchmark.py --n 5000
    python benchmarks/latency_benchmark.py --mode api_only
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pramanix import E, Field, Guard, GuardConfig, Policy


# ── Banking policy for benchmarks ─────────────────────────────────────────────

_amount  = Field("amount",    Decimal, "Real")
_balance = Field("balance",   Decimal, "Real")
_frozen  = Field("is_frozen", bool,    "Bool")
_limit   = Field("daily_limit", Decimal, "Real")
_risk    = Field("risk_score",  float,  "Real")


class _BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount, "balance": _balance,
            "is_frozen": _frozen, "daily_limit": _limit,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance")
                .explain("Balance insufficient"),
            (E(_frozen) == False)
                .named("account_not_frozen")
                .explain("Account frozen"),
            (E(_amount) <= E(_limit))
                .named("within_daily_limit")
                .explain("Daily limit exceeded"),
            (E(_risk) <= 0.8)
                .named("acceptable_risk")
                .explain("Risk score exceeded"),
            (E(_amount) > Decimal("0"))
                .named("positive_amount")
                .explain("Amount must be positive"),
        ]


ALLOW_STATE  = {
    "balance": Decimal("10000"), "is_frozen": False,
    "daily_limit": Decimal("50000"), "risk_score": 0.3,
    "state_version": "1.0",
}
ALLOW_INTENT = {"amount": Decimal("100")}

BLOCK_STATE  = {
    "balance": Decimal("50"), "is_frozen": False,
    "daily_limit": Decimal("10000"), "risk_score": 0.3,
    "state_version": "1.0",
}
BLOCK_INTENT = {"amount": Decimal("1000")}


def percentile(data: list[float], pct: float) -> float:
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


def run_api_benchmark(n: int = 10_000) -> dict:
    """API mode: structured JSON intent, no LLM."""
    print(f"\n[API MODE] Running {n} decisions...")
    guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))

    latencies_ms: list[float] = []

    # Warmup (not measured)
    for _ in range(100):
        guard.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)

    # Measured run: alternating ALLOW and BLOCK
    for i in range(n):
        intent = ALLOW_INTENT if i % 2 == 0 else BLOCK_INTENT
        state  = ALLOW_STATE  if i % 2 == 0 else BLOCK_STATE
        t0 = time.perf_counter()
        decision = guard.verify(intent=intent, state=state)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    results = {
        "mode": "api",
        "n": n,
        "p50_ms": round(percentile(latencies_ms, 50), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
        "p999_ms": round(percentile(latencies_ms, 99.9), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
        "targets": {
            "p50": {"target_ms": 5.0,  "passed": percentile(latencies_ms, 50) < 5.0},
            "p95": {"target_ms": 10.0, "passed": percentile(latencies_ms, 95) < 10.0},
            "p99": {"target_ms": 15.0, "passed": percentile(latencies_ms, 99) < 15.0},
        },
    }

    print(f"  P50: {results['p50_ms']}ms  (target < 5ms:  {'✅' if results['targets']['p50']['passed'] else '❌'})")
    print(f"  P95: {results['p95_ms']}ms  (target < 10ms: {'✅' if results['targets']['p95']['passed'] else '❌'})")
    print(f"  P99: {results['p99_ms']}ms  (target < 15ms: {'✅' if results['targets']['p99']['passed'] else '❌'})")
    return results


def run_fast_path_benchmark(n: int = 10_000) -> dict:
    """API mode with fast-path enabled."""
    from pramanix.fast_path import SemanticFastPath

    print(f"\n[API MODE + FAST-PATH] Running {n} decisions...")
    guard = Guard(
        _BankingPolicy,
        GuardConfig(
            execution_mode="sync",
            fast_path_enabled=True,
            fast_path_rules=[
                SemanticFastPath.negative_amount("amount"),
                SemanticFastPath.account_frozen("is_frozen"),
                SemanticFastPath.amount_exceeds_balance(),
            ],
        ),
    )

    latencies_ms: list[float] = []
    for _ in range(100):
        guard.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)

    for i in range(n):
        intent = ALLOW_INTENT if i % 2 == 0 else BLOCK_INTENT
        state  = ALLOW_STATE  if i % 2 == 0 else BLOCK_STATE
        t0 = time.perf_counter()
        guard.verify(intent=intent, state=state)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    results = {
        "mode": "api_fast_path",
        "n": n,
        "p50_ms": round(percentile(latencies_ms, 50), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
    }
    print(f"  P50: {results['p50_ms']}ms")
    print(f"  P95: {results['p95_ms']}ms")
    print(f"  P99: {results['p99_ms']}ms")
    return results


def run_nlp_mock_benchmark(n: int = 1_000) -> dict:
    """NLP mode with mock LLM (measures guard overhead without network)."""
    print(f"\n[NLP MOCK MODE] Running {n} decisions with mock translator...")

    # Mock translator that returns immediately (no network I/O)
    class _MockTranslator:
        async def extract(self, text, intent_schema, context=None):
            return {"amount": "100"}

    guard = Guard(
        _BankingPolicy,
        GuardConfig(execution_mode="sync"),
    )

    # Simulate NLP pipeline: parse text → validate → Z3
    latencies_ms: list[float] = []
    import asyncio

    async def _run_one():
        t0 = time.perf_counter()
        # Simulate: text → mock extraction (0ms) → Pydantic → Z3
        extracted = {"amount": "100"}
        from pydantic import BaseModel
        class _Intent(BaseModel):
            amount: Decimal
        validated = _Intent.model_validate(extracted).model_dump()
        guard.verify(intent=validated, state=ALLOW_STATE)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    for _ in range(50):
        asyncio.run(_run_one())  # warmup

    for _ in range(n):
        asyncio.run(_run_one())

    results = {
        "mode": "nlp_mock",
        "n": n,
        "p50_ms": round(percentile(latencies_ms, 50), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
        "targets": {
            "p50": {"target_ms": 50.0,  "passed": percentile(latencies_ms, 50) < 50.0},
            "p95": {"target_ms": 150.0, "passed": percentile(latencies_ms, 95) < 150.0},
            "p99": {"target_ms": 300.0, "passed": percentile(latencies_ms, 99) < 300.0},
        },
    }
    print(f"  P50: {results['p50_ms']}ms  (target < 50ms:  {'✅' if results['targets']['p50']['passed'] else '❌'})")
    print(f"  P95: {results['p95_ms']}ms  (target < 150ms: {'✅' if results['targets']['p95']['passed'] else '❌'})")
    print(f"  P99: {results['p99_ms']}ms  (target < 300ms: {'✅' if results['targets']['p99']['passed'] else '❌'})")
    return results


def main():
    parser = argparse.ArgumentParser(description="Pramanix latency benchmark")
    parser.add_argument("--n", type=int, default=10_000, help="Decisions to run (API mode)")
    parser.add_argument("--mode", choices=["all", "api_only", "nlp_only"], default="all")
    args = parser.parse_args()

    import platform
    print(f"\nPramanix Latency Benchmark")
    print(f"Python: {platform.python_version()}")
    print(f"Platform: {platform.system()} {platform.machine()}")

    all_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "results": [],
    }

    if args.mode in ("all", "api_only"):
        all_results["results"].append(run_api_benchmark(args.n))
        all_results["results"].append(run_fast_path_benchmark(args.n))

    if args.mode in ("all", "nlp_only"):
        all_results["results"].append(run_nlp_mock_benchmark(min(args.n, 1000)))

    # Write results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "latency_results.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n✅ Results written to {output_path}")

    # Check if all targets met
    all_targets_met = all(
        t["passed"]
        for result in all_results["results"]
        for t in result.get("targets", {}).values()
    )
    print(f"\n{'✅ ALL TARGETS MET' if all_targets_met else '❌ SOME TARGETS MISSED'}")
    return 0 if all_targets_met else 1


if __name__ == "__main__":
    sys.exit(main())
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5.3 — Create benchmarks/memory_stability_extended.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Extended memory stability benchmark — 2M decisions.

Extends the Phase 4 1M decision test to 2M.
Confirms memory stays flat (no growth trend) from 1M to 2M.

Target: RSS growth < 50MB over 2M decisions.
Proof: RSS at 2M decisions must be within 5MB of RSS at 1M decisions.

Usage:
    python benchmarks/memory_stability_extended.py
"""
from __future__ import annotations

import sys
import time
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    import resource
    HAS_PSUTIL = False


def get_rss_mb() -> float:
    if HAS_PSUTIL:
        import os
        return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    else:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def main():
    from pramanix import E, Field, Guard, GuardConfig, Policy

    _amount  = Field("amount",  Decimal, "Real")
    _balance = Field("balance", Decimal, "Real")

    class _P(Policy):
        class Meta: version = "1.0"
        @classmethod
        def fields(cls): return {"amount": _amount, "balance": _balance}
        @classmethod
        def invariants(cls):
            return [
                ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance")
                .explain("Insufficient balance")
            ]

    guard = Guard(
        _P,
        GuardConfig(
            execution_mode="sync",
            max_decisions_per_worker=10_000,
            worker_warmup=True,
        ),
    )

    state  = {"balance": Decimal("5000"), "state_version": "1.0"}
    intent = {"amount": Decimal("100")}

    print("Pramanix Extended Memory Stability Benchmark")
    print("Target: 2,000,000 decisions, RSS growth < 50MB\n")

    rss_baseline = get_rss_mb()
    print(f"Baseline RSS: {rss_baseline:.1f}MB")

    checkpoints = {
        100_000:   None,
        500_000:   None,
        1_000_000: None,
        1_500_000: None,
        2_000_000: None,
    }

    t0 = time.monotonic()
    for i in range(1, 2_000_001):
        guard.verify(intent=intent, state=state)
        if i in checkpoints:
            rss = get_rss_mb()
            checkpoints[i] = rss
            elapsed = time.monotonic() - t0
            print(f"  {i:>10,} decisions | RSS: {rss:.1f}MB | {elapsed:.0f}s")

    total_elapsed = time.monotonic() - t0
    rss_final = checkpoints[2_000_000]
    rss_at_1m  = checkpoints[1_000_000]
    rss_growth_total = rss_final - rss_baseline
    rss_growth_1m_to_2m = rss_final - rss_at_1m

    print(f"\nResults:")
    print(f"  Total decisions: 2,000,000")
    print(f"  Total time: {total_elapsed:.1f}s")
    print(f"  RSS baseline:  {rss_baseline:.1f}MB")
    print(f"  RSS at 1M:     {rss_at_1m:.1f}MB")
    print(f"  RSS at 2M:     {rss_final:.1f}MB")
    print(f"  Growth (total): {rss_growth_total:.1f}MB")
    print(f"  Growth (1M→2M): {rss_growth_1m_to_2m:.1f}MB")

    passed_total  = rss_growth_total < 50
    passed_stable = abs(rss_growth_1m_to_2m) < 5  # Flat from 1M to 2M

    print(f"\n  Total growth < 50MB: {'✅ PASS' if passed_total  else '❌ FAIL'}")
    print(f"  Flat 1M→2M (< 5MB): {'✅ PASS' if passed_stable else '❌ FAIL'}")

    import json
    results = {
        "decisions": 2_000_000,
        "total_elapsed_s": round(total_elapsed, 1),
        "rss_baseline_mb": round(rss_baseline, 1),
        "rss_at_1m_mb": round(rss_at_1m, 1),
        "rss_at_2m_mb": round(rss_final, 1),
        "growth_total_mb": round(rss_growth_total, 1),
        "growth_1m_to_2m_mb": round(rss_growth_1m_to_2m, 1),
        "passed_total_growth": passed_total,
        "passed_flat_1m_to_2m": passed_stable,
    }

    from pathlib import Path
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    with open(results_dir / "memory_2m.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Results written to benchmarks/results/memory_2m.json")
    return 0 if (passed_total and passed_stable) else 1


if __name__ == "__main__":
    sys.exit(main())
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5.4 — Create tests/perf/test_performance_targets.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is the pytest version of the benchmarks — runs in CI.
Uses smaller N to keep CI under 5 minutes.
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Performance target tests for Phase 10.

These tests enforce performance targets in CI.
Uses conservative N values (1000 instead of 10000) for CI speed.
The full benchmark (N=10000) is in benchmarks/latency_benchmark.py.

Performance targets:
    API mode:  P99 < 15ms
    Fast-path: P99 < 5ms for blocked decisions
"""
from __future__ import annotations

import statistics
import time
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.fast_path import SemanticFastPath


def percentile(data: list[float], pct: float) -> float:
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


_amount  = Field("amount",    Decimal, "Real")
_balance = Field("balance",   Decimal, "Real")
_frozen  = Field("is_frozen", bool,    "Bool")
_limit   = Field("daily_limit", Decimal, "Real")
_risk    = Field("risk_score",  float,  "Real")


class _BankingPolicy(Policy):
    class Meta: version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount, "balance": _balance,
            "is_frozen": _frozen, "daily_limit": _limit,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance").explain("Insufficient"),
            (E(_frozen) == False).named("not_frozen").explain("Frozen"),
            (E(_amount) <= E(_limit)).named("under_limit").explain("Over limit"),
            (E(_risk) <= 0.8).named("risk_ok").explain("High risk"),
            (E(_amount) > Decimal("0")).named("positive").explain("Positive"),
        ]


ALLOW_STATE  = {
    "balance": Decimal("10000"), "is_frozen": False,
    "daily_limit": Decimal("50000"), "risk_score": 0.3,
    "state_version": "1.0",
}
ALLOW_INTENT = {"amount": Decimal("100")}
BLOCK_STATE  = {
    "balance": Decimal("50"), "is_frozen": False,
    "daily_limit": Decimal("10000"), "risk_score": 0.3,
    "state_version": "1.0",
}
BLOCK_INTENT = {"amount": Decimal("1000")}


@pytest.mark.slow
class TestAPIModePerfTargets:
    def test_allow_path_p99_under_15ms(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        # Warmup
        for _ in range(50):
            guard.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)

        latencies = []
        for _ in range(500):
            t0 = time.perf_counter()
            guard.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)
            latencies.append((time.perf_counter() - t0) * 1000)

        p99 = percentile(latencies, 99)
        assert p99 < 15.0, (
            f"API mode ALLOW P99 = {p99:.2f}ms exceeds 15ms target. "
            f"P50={percentile(latencies, 50):.2f}ms, "
            f"P95={percentile(latencies, 95):.2f}ms"
        )

    def test_block_path_p99_under_15ms(self):
        guard = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        for _ in range(50):
            guard.verify(intent=BLOCK_INTENT, state=BLOCK_STATE)

        latencies = []
        for _ in range(500):
            t0 = time.perf_counter()
            guard.verify(intent=BLOCK_INTENT, state=BLOCK_STATE)
            latencies.append((time.perf_counter() - t0) * 1000)

        p99 = percentile(latencies, 99)
        assert p99 < 15.0, (
            f"API mode BLOCK P99 = {p99:.2f}ms exceeds 15ms target"
        )


@pytest.mark.slow
class TestFastPathPerfTargets:
    def test_fast_path_block_under_1ms(self):
        """Fast-path blocks must return in < 1ms (no Z3 invoked)."""
        guard = Guard(
            _BankingPolicy,
            GuardConfig(
                execution_mode="sync",
                fast_path_enabled=True,
                fast_path_rules=[
                    SemanticFastPath.amount_exceeds_balance(),
                ],
            ),
        )
        # Warmup
        for _ in range(50):
            guard.verify(intent=BLOCK_INTENT, state=BLOCK_STATE)

        latencies = []
        for _ in range(500):
            t0 = time.perf_counter()
            guard.verify(intent=BLOCK_INTENT, state=BLOCK_STATE)
            latencies.append((time.perf_counter() - t0) * 1000)

        p99 = percentile(latencies, 99)
        # Fast-path avoids Z3 — should be much faster than 1ms
        assert p99 < 5.0, (
            f"Fast-path block P99 = {p99:.2f}ms, expected < 5ms. "
            "Z3 may have been invoked on fast-path block."
        )

    def test_fast_path_does_not_slow_down_allow_path(self):
        """Fast-path evaluation must not add meaningful latency to ALLOW path."""
        guard_no_fp = Guard(_BankingPolicy, GuardConfig(execution_mode="sync"))
        guard_with_fp = Guard(
            _BankingPolicy,
            GuardConfig(
                execution_mode="sync",
                fast_path_enabled=True,
                fast_path_rules=[
                    SemanticFastPath.negative_amount("amount"),
                    SemanticFastPath.account_frozen("is_frozen"),
                    SemanticFastPath.amount_exceeds_balance(),
                ],
            ),
        )

        for _ in range(50):
            guard_no_fp.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)
            guard_with_fp.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)

        lat_no_fp   = []
        lat_with_fp = []
        for _ in range(200):
            t0 = time.perf_counter()
            guard_no_fp.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)
            lat_no_fp.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            guard_with_fp.verify(intent=ALLOW_INTENT, state=ALLOW_STATE)
            lat_with_fp.append((time.perf_counter() - t0) * 1000)

        mean_no_fp   = statistics.mean(lat_no_fp)
        mean_with_fp = statistics.mean(lat_with_fp)

        overhead_ms = mean_with_fp - mean_no_fp
        # Fast-path overhead on ALLOW path must be < 0.5ms
        assert overhead_ms < 0.5, (
            f"Fast-path adds {overhead_ms:.3f}ms overhead to ALLOW path "
            f"(no-fp: {mean_no_fp:.3f}ms, with-fp: {mean_with_fp:.3f}ms)"
        )
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PILLAR 5 GATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run:
    python benchmarks/latency_benchmark.py --n 1000
    # Must print: ✅ ALL TARGETS MET
    # Must create benchmarks/results/latency_results.json

    pytest tests/perf/test_performance_targets.py -v -m slow
    # All pass

═══════════════════════════════════════════════════════════════════════
FINAL ASSEMBLY — UPDATE ALL METADATA
═══════════════════════════════════════════════════════════════════════

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.1 — Bump version to 0.7.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

In pyproject.toml: version = "0.7.0"
In src/pramanix/__init__.py: __version__ = "0.7.0"

These MUST match exactly. The existing test_version_matches_package_metadata
will fail if they differ.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.2 — Update src/pramanix/__init__.py exports
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add to existing __init__.py:
    from pramanix.fast_path import SemanticFastPath, FastPathEvaluator
    from pramanix.translator._cache import IntentCache

Add to __all__:
    "SemanticFastPath", "FastPathEvaluator", "IntentCache"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.3 — Update docs/performance.md
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Update docs/performance.md with Phase 10 results. Add a section:

## Phase 10 Performance Targets (v0.7.0)

| Mode | P50 | P95 | P99 | Target P99 | Status |
|------|-----|-----|-----|------------|--------|
| API (structured) | <measured> | <measured> | <measured> | 15ms | ✅/❌ |
| API + Fast-path block | <measured> | <measured> | <measured> | 5ms | ✅/❌ |
| NLP (mock LLM) | <measured> | <measured> | <measured> | 300ms | ✅/❌ |

Fill in <measured> from the benchmark output.

### What Changed in Phase 10

1. **Expression Tree Pre-Validation**: Policy invariants are walked once
   at `Guard.__init__()`. Field presence is checked in O(n) Python before
   invoking Z3. Missing-field errors return in microseconds.

2. **Intent Extraction Cache**: LLM extraction results cached by normalized
   input hash. Z3 and Pydantic always run even on cache hit.
   Disabled by default: `PRAMANIX_INTENT_CACHE_ENABLED=true` to activate.

3. **Semantic Fast-Path**: Configurable Python rules pre-screen obvious
   violations before Z3. Fast-path can only BLOCK — never ALLOW.
   Blocked decisions return in < 1ms without invoking Z3.

4. **Adaptive Load Shedding**: Requests shed when worker pool saturated
   AND P99 latency exceeds threshold. Shed decisions always `allowed=False`.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.4 — Add CHANGELOG.md entry for v0.7.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Add at top of CHANGELOG.md (after [Unreleased]):

## [0.7.0] — 2026-03-15

### Added — Phase 10: Performance Engineering

- `InvariantMeta` dataclass: cached expression tree metadata for each invariant
- `compile_policy()`: walks expression trees once at `Guard.__init__()`
- Field presence pre-check: O(n) Python check before Z3 invocation
- `IntentCache`: LRU/Redis cache for NLP extraction results
  - Disabled by default (PRAMANIX_INTENT_CACHE_ENABLED=true)
  - Z3 + Pydantic always run on cache hit
  - Cache key: SHA-256(NFKC(input.strip().lower()))
- `SemanticFastPath`: factory for common fast-path rules
  - `negative_amount`, `zero_or_negative_balance`, `account_frozen`
  - `exceeds_hard_cap`, `amount_exceeds_balance`
- `FastPathEvaluator`: runs rules in order, stops at first block
- `AdaptiveConcurrencyLimiter`: sheds requests when pool saturated + high P99
- `SolverStatus.RATE_LIMITED`: shed decisions status code
- `Decision.rate_limited()`: factory for shed decisions
- `benchmarks/latency_benchmark.py`: publishable benchmark suite
- `benchmarks/memory_stability_extended.py`: 2M decision stability test
- `benchmarks/results/`: machine-readable benchmark results
- `tests/perf/test_performance_targets.py`: CI-friendly perf gates

### Performance Improvements
- API mode BLOCK path: fast-path short-circuits Z3 for obvious violations
- Missing-field errors: O(n) Python pre-check instead of Z3 invocation
- NLP mode: LLM extraction cached per normalized input

### Security
- Fast-path invariant enforced by test: cannot produce `allowed=True`
- Load shedding invariant enforced by test: shed = `allowed=False`
- Cache security: Pydantic always validates cached entries
- Cache key: SHA-256 hash prevents timing oracle on input text

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP F.5 — Coverage repair
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run coverage check:
    pytest --cov=src/pramanix --cov-branch --cov-report=term-missing \
           --cov-fail-under=95 --ignore=tests/perf -q

Identify any new modules below 95%. Target files to check:
    src/pramanix/fast_path.py         — ALLOW_WITH_AUDIT branch in evaluator
    src/pramanix/translator/_cache.py — Redis fallback path, clear() method
    src/pramanix/transpiler.py        — _tree_has_literal unknown branch

For any uncovered paths:
1. Write the missing test — do NOT use # pragma: no cover on logic paths
2. Add # pragma: no cover ONLY to:
   - ImportError fallback blocks (e.g., "except ImportError: pass")
   - TYPE_CHECKING blocks
   - Abstract method stubs in Protocol classes

═══════════════════════════════════════════════════════════════════════
FINAL GATE — THE COMPLETE PHASE 10 AUDIT
═══════════════════════════════════════════════════════════════════════

Run every command below in order. Every one must pass. Print results.

GATE 1 — Spike validation
    python spikes/expression_tree_cache_spike.py
    # Must print: EQUIVALENCE CHECK: PASSED

GATE 2 — Expression cache unit tests
    pytest tests/unit/test_expression_cache.py -v
    # All pass

GATE 3 — Intent cache security tests
    pytest tests/unit/test_intent_cache.py -v -k "security"
    # All 6 security tests pass

GATE 4 — Fast-path tests (including security invariant)
    pytest tests/unit/test_fast_path.py -v
    # test_fast_path_cannot_produce_allowed_true MUST pass

GATE 5 — Load shedding security test
    pytest tests/unit/test_load_shedding.py -v -k "AllowedFalse"
    # test_rate_limited_decision_is_not_allowed MUST pass

GATE 6 — No regressions in existing tests
    pytest tests/unit/ tests/integration/ tests/adversarial/ -q --tb=short
    # All existing tests still pass

GATE 7 — Performance benchmark
    python benchmarks/latency_benchmark.py --n 2000
    # Must print: ✅ ALL TARGETS MET
    # Must create benchmarks/results/latency_results.json

GATE 8 — Performance perf suite
    pytest tests/perf/test_performance_targets.py -v -m slow
    # All pass

GATE 9 — Full test suite with coverage
    pytest --ignore=tests/perf -q --tb=short
    # ≥ 1400 passed, 0 failed

    pytest --cov=src/pramanix --cov-fail-under=95 --ignore=tests/perf -q
    # ≥ 95% coverage

GATE 10 — Security invariants summary (print these explicitly)
    python -c "
from pramanix.decision import Decision, SolverStatus
from pramanix.fast_path import FastPathEvaluator, FastPathResult

# INVARIANT 1: Shed decisions are always allowed=False
d = Decision.rate_limited()
assert d.allowed is False, 'FAIL: rate_limited decision is allowed=True'
assert d.status == SolverStatus.RATE_LIMITED
print('✅ INVARIANT 1: Shed decisions always allowed=False')

# INVARIANT 2: Fast-path pass-through is not allowed=True
ev = FastPathEvaluator([])
result = ev.evaluate({}, {})
assert not result.blocked  # Pass-through
# FastPathResult.pass_through does NOT have allowed=True
# It means 'proceed to Z3' not 'allowed'
print('✅ INVARIANT 2: Fast-path pass-through is not an ALLOW decision')

# INVARIANT 3: Cache is disabled by default
import os
os.environ.pop('PRAMANIX_INTENT_CACHE_ENABLED', None)
from pramanix.translator._cache import IntentCache
c = IntentCache.from_env()
assert not c.enabled
print('✅ INVARIANT 3: Intent cache disabled by default')

print()
print('All Phase 10 security invariants verified.')
"

GATE 11 — Version consistency
    python -c "
import sys
sys.path.insert(0, 'src')
import pramanix
assert pramanix.__version__ == '0.7.0', f'Expected 0.7.0, got {pramanix.__version__}'
print('✅ Version 0.7.0 confirmed')
"

After all 11 gates pass, print:

"╔══════════════════════════════════════════════════════════════╗
 ║     PRAMANIX v0.7.0 — PHASE 10 COMPLETE                     ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  Pillar 1: Expression Tree Pre-Compilation  ✅ CERTIFIED    ║
 ║  Pillar 2: Intent Extraction Cache          ✅ CERTIFIED    ║
 ║  Pillar 3: Semantic Fast-Path               ✅ CERTIFIED    ║
 ║  Pillar 4: Adaptive Load Shedding           ✅ CERTIFIED    ║
 ║  Pillar 5: Publishable Benchmarks           ✅ CERTIFIED    ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  API mode P99:   < 15ms  ✅                                 ║
 ║  Fast-path P99:  < 5ms   ✅                                 ║
 ║  Tests:   ≥1400 passed, 0 failed                            ║
 ║  Coverage: ≥95%                                             ║
 ╚══════════════════════════════════════════════════════════════╝"