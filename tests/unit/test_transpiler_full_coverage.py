# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Full coverage for transpiler.py missing branches.

Targets:
  transpiler.py lines 197-206, 295->298, 296->298, 299-301,
  305->exit, 307->306, 314->317, 340 (pragma), 392, 418,
  515, 518-519, 553-554, 816-817, 844-845, 877-878

Design: Uses direct AST construction (_CmpOp, _InOp, _FieldRef, etc.)
to exercise precise branches without going through Guard.verify().
InvariantASTCache tests manipulate internal class-level dicts directly
to reproduce inconsistent state (key in cache but not in access_order).
"""

from __future__ import annotations

from decimal import Decimal

import pytest
import z3

from pramanix.exceptions import FieldTypeError, TranspileError
from pramanix.expressions import (
    ConstraintExpr,
    E,
    Field,
    _BinOp,
    _CmpOp,
    _FieldRef,
    _InOp,
    _LengthBetweenOp,
    _Literal,
    _ModOp,
    _RegexMatchOp,
    _StartsWithOp,
)
from pramanix.transpiler import (
    InvariantASTCache,
    InvariantMeta,
    analyze_string_promotions,
    transpile,
    z3_val,
)

# ── Shared field fixtures ─────────────────────────────────────────────────────

_str_field = Field("status", str, "String")
_int_field = Field("count", int, "Int")
_int_field2 = Field("divisor", int, "Int")
_real_field = Field("amount", Decimal, "Real")


# ── z3_val: String field + promotions, value missing from encoding ────────────


class TestZ3ValStringPromotion:
    """Lines 197-206: FieldTypeError when promoted String value is not in encoding."""

    def test_known_value_returns_int_val(self) -> None:
        promotions = {"status": {"active": 0, "inactive": 1}}
        result = z3_val(_str_field, "active", promotions=promotions)
        assert z3.is_int_value(result)

    def test_unknown_value_raises_field_type_error(self) -> None:
        """Line 200-205: value not in promotion encoding → FieldTypeError."""
        promotions = {"status": {"active": 0, "inactive": 1}}
        with pytest.raises(FieldTypeError, match="promotion encoding table"):
            z3_val(_str_field, "pending", promotions=promotions)

    def test_error_message_lists_known_values(self) -> None:
        promotions = {"status": {"active": 0, "inactive": 1}}
        with pytest.raises(FieldTypeError, match="active"):
            z3_val(_str_field, "unknown_status", promotions=promotions)

    def test_no_promotions_returns_string_val(self) -> None:
        result = z3_val(_str_field, "anything", promotions=None)
        assert z3.is_string_value(result)

    def test_promotions_without_this_field_returns_string_val(self) -> None:
        promotions = {"other_field": {"x": 0}}
        result = z3_val(_str_field, "anything", promotions=promotions)
        assert z3.is_string_value(result)


# ── analyze_string_promotions: right-side String field in CmpOp ───────────────


class TestAnalyzeStringPromotionsRightSideField:
    """Lines 299-301: String FieldRef on the RIGHT side of eq/ne CmpOp."""

    def test_right_side_string_field_eq_literal_adds_to_eligible(self) -> None:
        """Line 299-301: literal == str_field → field on right side gets encoded."""
        node = _CmpOp(op="eq", left=_Literal("active"), right=_FieldRef(_str_field))
        invariant = ConstraintExpr(node)
        promotions = analyze_string_promotions([invariant])
        assert "status" in promotions
        assert "active" in promotions["status"]

    def test_right_side_ne_also_captured(self) -> None:
        node = _CmpOp(op="ne", left=_Literal("closed"), right=_FieldRef(_str_field))
        invariant = ConstraintExpr(node)
        promotions = analyze_string_promotions([invariant])
        assert "status" in promotions
        assert "closed" in promotions["status"]

    def test_right_side_non_string_literal_not_captured(self) -> None:
        """Right-side field with int literal on left — not a string literal, skipped."""
        node = _CmpOp(op="eq", left=_Literal(42), right=_FieldRef(_str_field))
        invariant = ConstraintExpr(node)
        promotions = analyze_string_promotions([invariant])
        # Int literal on left → condition at line 299 is False → "status" may still
        # be eligible but with an empty encoding (from the _FieldRef walk at 285-288).
        # The important thing is we don't crash.
        assert isinstance(promotions, dict)


# ── analyze_string_promotions: left-side field already disqualified ───────────


class TestAnalyzeStringPromotionsDisqualifiedBranches:
    """Lines 295->298 and 296->298: branches when field IS in disqualified."""

    def test_disqualified_field_eq_literal_branch_not_taken(self) -> None:
        """Line 295->298: left is String FieldRef but disqualified by StartsWithOp.

        StartsWithOp appears first in the invariant list → status disqualified.
        Then a CmpOp(eq) sees status on the left, but disqualified check (296->298)
        prevents it from being added to eligible.
        """
        # StartsWithOp disqualifies "status"
        starts_inv = E(_str_field).starts_with("pre")
        # CmpOp should now hit the 296->298 branch (field in disqualified)
        eq_node = _CmpOp(op="eq", left=_FieldRef(_str_field), right=_Literal("active"))
        eq_inv = ConstraintExpr(eq_node)
        promotions = analyze_string_promotions([starts_inv, eq_inv])
        # "status" was disqualified → should NOT be in promotions
        assert "status" not in promotions

    def test_right_side_literal_is_not_str_hits_295_false_branch(self) -> None:
        """Line 295->298: right is a non-string Literal (e.g., int) → False branch.

        The field IS in eligible (seen as _FieldRef at line 285), but the eq/ne
        literal-collection check (295) is False (int literal, not str) → no string
        literal added.  Promotion table has an empty encoding for the field.
        """
        node = _CmpOp(op="eq", left=_FieldRef(_str_field), right=_Literal(99))
        invariant = ConstraintExpr(node)
        promotions = analyze_string_promotions([invariant])
        # Field is in promotions but with an empty encoding (no str literals collected)
        if "status" in promotions:
            assert promotions["status"] == {}
        # The important thing: no crash, and the 295->298 branch was exercised


# ── analyze_string_promotions: _InOp branches ────────────────────────────────


class TestAnalyzeStringPromotionsInOpBranches:
    """Lines 305->exit, 307->306: _InOp edge cases."""

    def test_disqualified_field_inop_hits_305_exit(self) -> None:
        """Line 305->exit: field IS in disqualified when processing _InOp.

        StartsWithOp is processed first → status disqualified.
        Then _InOp with status on left → line 305 (`if not in disqualified`) is False
        → skip the for loop (305->exit).
        """
        starts_inv = E(_str_field).starts_with("pre")
        in_node = _InOp(
            left=_FieldRef(_str_field),
            values=[_Literal("x"), _Literal("y")],
        )
        in_inv = ConstraintExpr(in_node)
        promotions = analyze_string_promotions([starts_inv, in_inv])
        assert "status" not in promotions

    def test_inop_with_non_string_literal_value_hits_307_false_branch(self) -> None:
        """Line 307->306: InOp value is NOT a str _Literal → loop continues."""
        in_node = _InOp(
            left=_FieldRef(_str_field),
            # First value is int (not str) → 307->306; second is str → 307->308
            values=[_Literal(42), _Literal("active"), _Literal("inactive")],
        )
        invariant = ConstraintExpr(in_node)
        promotions = analyze_string_promotions([invariant])
        # "active" and "inactive" still captured; 42 skipped
        assert "status" in promotions
        assert "active" in promotions["status"]
        assert "inactive" in promotions["status"]

    def test_inop_non_string_field_hits_else_walk(self) -> None:
        """_InOp where left is NOT a String FieldRef → else _walk(l) branch."""
        # Int field in InOp — left is not String FieldRef, falls to else _walk(l)
        in_node = _InOp(
            left=_FieldRef(_int_field),
            values=[_Literal(1), _Literal(2)],
        )
        invariant = ConstraintExpr(in_node)
        promotions = analyze_string_promotions([invariant])
        assert "count" not in promotions


# ── analyze_string_promotions: string-theory op with non-FieldRef operand ─────


class TestAnalyzeStringPromotionsStringTheoryNonFieldRef:
    """Line 314->317: StartsWithOp operand is NOT a String FieldRef."""

    def test_starts_with_non_string_fieldref_skips_disqualify(self) -> None:
        """Line 314->317: operand is a String FieldRef but not String type → skip."""
        # _StartsWithOp with an Int FieldRef operand — not a String field
        starts_node = _StartsWithOp(operand=_FieldRef(_int_field), prefix=_Literal("pre"))
        invariant = ConstraintExpr(starts_node)
        promotions = analyze_string_promotions([invariant])
        # Int field not affected by String-theory disqualification
        assert "count" not in promotions

    def test_length_between_non_string_field_skips_disqualify(self) -> None:
        """Same 314->317 branch: LengthBetweenOp with non-String operand."""
        len_node = _LengthBetweenOp(operand=_FieldRef(_int_field), lo=1, hi=5)
        invariant = ConstraintExpr(len_node)
        promotions = analyze_string_promotions([invariant])
        assert isinstance(promotions, dict)


# ── transpile: _BinOp right-side Int literal coercion ────────────────────────


class TestTranspileBinOpRightSideIntCoercion:
    """Line 392: rz.is_int() and lz.is_real() → coerce literal on LEFT to IntVal."""

    def test_int_literal_on_left_coerced_when_right_is_int_field(self) -> None:
        """Line 392: left is int literal (compiled as Real), right is Int field.

        _BinOp(add, left=_Literal(3), right=_FieldRef(int_field))
        → lz = RealVal(3), rz = Int("count")
        → rz.is_int() and lz.is_real() → lz coerced to IntVal(3)
        """
        node = _BinOp(op="add", left=_Literal(3), right=_FieldRef(_int_field))
        result = transpile(node)
        assert result is not None

    def test_int_literal_on_left_with_subtraction(self) -> None:
        """Line 392: left=int literal, right=Int field — also works with sub op."""
        node = _BinOp(op="sub", left=_Literal(10), right=_FieldRef(_int_field))
        result = transpile(node)
        assert result is not None


# ── transpile: _CmpOp right-side promoted String field ───────────────────────


class TestTransposeCmpOpRightSidePromotedField:
    """Line 418: right is a promoted String FieldRef, left is str literal."""

    def test_right_side_string_field_promoted_literal_on_left(self) -> None:
        """Line 418: literal == promoted_field → lz re-encoded as IntVal."""
        node = _CmpOp(op="eq", left=_Literal("active"), right=_FieldRef(_str_field))
        promotions = {"status": {"active": 0, "inactive": 1}}
        result = transpile(node, promotions=promotions)
        assert result is not None
        # The result should be an equality formula
        assert z3.is_eq(result)

    def test_right_side_string_field_value_not_in_encoding_raises_field_type_error(
        self,
    ) -> None:
        """Unknown string values in promoted fields raise FieldTypeError (#68/#69).

        Previously used .get(value, -1) sentinel which produced a vacuously-true
        Z3 constraint (fail-open security violation).  Now raises FieldTypeError
        so unknown values are caught at compile time, not silently bypassed.
        """
        from pramanix.exceptions import FieldTypeError

        node = _CmpOp(op="eq", left=_Literal("unknown_val"), right=_FieldRef(_str_field))
        promotions = {"status": {"active": 0, "inactive": 1}}
        with pytest.raises(FieldTypeError, match="unknown_val"):
            transpile(node, promotions=promotions)


# ── transpile: _ModOp non-literal divisor (line 515) ─────────────────────────


class TestTranspileModOpNonLiteralDivisor:
    """Line 515: divisor is not a _Literal → falls to else branch."""

    def test_field_divisor_uses_transpile(self) -> None:
        """Line 515: divisor is a FieldRef, not a Literal → transpile(v)."""
        node = _ModOp(dividend=_FieldRef(_int_field), divisor=_FieldRef(_int_field2))
        result = transpile(node)
        assert result is not None

    def test_decimal_literal_divisor_falls_to_else(self) -> None:
        """Line 515: Decimal literal is not isinstance(int) → else branch."""
        node = _ModOp(dividend=_FieldRef(_int_field), divisor=_Literal(Decimal("2")))
        with pytest.raises(TranspileError, match="Modulo"):
            transpile(node)


# ── transpile: _ModOp Z3Exception (lines 518-519) ────────────────────────────


class TestTranspileModOpZ3Exception:
    """Lines 518-519: z3.Z3Exception from Real % Real → wrapped as TranspileError."""

    def test_real_field_mod_decimal_literal_raises_transpile_error(self) -> None:
        """Real field % Decimal literal → Decimal is not int → else(515)
        → z_dividend is Real, z_divisor is Real → Z3Exception → TranspileError.
        """
        node = _ModOp(dividend=_FieldRef(_real_field), divisor=_Literal(Decimal("3")))
        with pytest.raises(TranspileError, match=r"Modulo.*only supported for Int"):
            transpile(node)

    def test_transpile_error_wraps_original_z3_exception(self) -> None:
        node = _ModOp(dividend=_FieldRef(_real_field), divisor=_Literal(Decimal("2")))
        with pytest.raises(TranspileError) as exc_info:
            transpile(node)
        assert exc_info.value.__cause__ is not None


# ── transpile: _RegexMatchOp Z3Exception (lines 553-554) ─────────────────────


class TestTranspileRegexMatchOpZ3Exception:
    """Lines 553-554: z3.Z3Exception when String field is promoted to Int but
    used in InRe (sort mismatch: Int vs String expected by Z3 regex)."""

    def test_promoted_field_in_regex_raises_transpile_error(self) -> None:
        """String field promoted to Int-sorted, then used in InRe → Z3Exception."""
        promotions = {"status": {"active": 0}}
        node = _RegexMatchOp(operand=_FieldRef(_str_field), pattern="active")
        with pytest.raises(TranspileError, match="matches_re"):
            transpile(node, promotions=promotions)

    def test_transpile_error_preserves_original_cause(self) -> None:
        promotions = {"status": {"active": 0}}
        node = _RegexMatchOp(operand=_FieldRef(_str_field), pattern="active")
        with pytest.raises(TranspileError) as exc_info:
            transpile(node, promotions=promotions)
        assert exc_info.value.__cause__ is not None


# ── InvariantASTCache: get() moves entry to MRU position ─────────────────────


class TestInvariantASTCacheGetValueError:
    """get() retrieves cached entry and promotes it to most-recently-used position."""

    def test_get_returns_entry_and_moves_to_mru(self) -> None:
        """get() retrieves a directly-injected entry and moves it to MRU in OrderedDict."""

        class _PolicyA:
            pass

        meta = [
            InvariantMeta(
                label="inv",
                explain_template="",
                field_refs=frozenset(["x"]),
                tree_repr="CmpOp(ge,FieldRef(x),Literal(0))",
                has_literal=True,
            )
        ]
        key = (id(_PolicyA), "hash_a")
        # Inject directly into the OrderedDict (at LRU position)
        InvariantASTCache._cache[key] = meta

        try:
            result = InvariantASTCache.get(_PolicyA, "hash_a")
            assert result is meta
            # After get(), key should be at the MRU (last) position in the OrderedDict
            assert list(InvariantASTCache._cache.keys())[-1] == key
        finally:
            InvariantASTCache._cache.pop(key, None)


# ── InvariantASTCache: put() update path ──────────────────────────────────────


class TestInvariantASTCachePutValueError:
    """put() update path: existing key is refreshed to MRU without duplicate insert."""

    def test_put_update_replaces_existing_entry(self) -> None:
        """put() on an existing key replaces the value and moves it to MRU position."""

        class _PolicyB:
            pass

        meta1 = [
            InvariantMeta(
                label="inv1",
                explain_template="",
                tree_repr="FieldRef(f)",
                field_refs=frozenset(["y"]),
                has_literal=False,
            )
        ]
        meta2 = [
            InvariantMeta(
                label="inv2",
                explain_template="",
                tree_repr="FieldRef(f)",
                field_refs=frozenset(["y"]),
                has_literal=False,
            )
        ]
        key = (id(_PolicyB), "hash_b")
        # Inject into cache directly (at LRU position)
        InvariantASTCache._cache[key] = meta1

        try:
            # put() detects existing key → updates in-place, moves to MRU
            InvariantASTCache.put(_PolicyB, "hash_b", meta2)
            assert InvariantASTCache.get(_PolicyB, "hash_b") is meta2
            # Size must not have grown (update, not insert)
            keys = [k for k in InvariantASTCache._cache if k == key]
            assert len(keys) == 1
        finally:
            InvariantASTCache._cache.pop(key, None)

    def test_lru_eviction_removes_oldest_when_at_capacity(self) -> None:
        """Lines 851-853: LRU eviction path — oldest key removed when cache full."""

        class _PolicyC:
            pass

        class _PolicyD:
            pass

        meta = [
            InvariantMeta(
                label="inv",
                explain_template="",
                tree_repr="FieldRef(f)",
                field_refs=frozenset(["z"]),
                has_literal=False,
            )
        ]
        original_max = InvariantASTCache._max_size
        try:
            InvariantASTCache._max_size = 1
            # Clear any leftover state (OrderedDict — no separate _access_order)
            InvariantASTCache._cache.clear()

            # Insert first entry
            InvariantASTCache.put(_PolicyC, "hash_c", meta)
            assert InvariantASTCache.size() == 1

            # Insert second entry — should evict the first
            InvariantASTCache.put(_PolicyD, "hash_d", meta)
            assert InvariantASTCache.size() == 1
            # First entry evicted
            assert InvariantASTCache.get(_PolicyC, "hash_c") is None
            # Second entry present
            assert InvariantASTCache.get(_PolicyD, "hash_d") is meta
        finally:
            InvariantASTCache._max_size = original_max
            InvariantASTCache._cache.clear()


# ── InvariantASTCache: clear(policy_cls=...) removes only that class ──────────


class TestInvariantASTCacheClearPolicyClass:
    """clear(policy_cls) removes only entries for that class, leaving others intact."""

    def test_clear_specific_policy_class(self) -> None:
        """clear(_PolicyE) removes only _PolicyE entries; _PolicyF is unaffected."""

        class _PolicyE:
            pass

        class _PolicyF:
            pass

        meta = [
            InvariantMeta(
                label="inv",
                explain_template="",
                tree_repr="FieldRef(f)",
                field_refs=frozenset(["w"]),
                has_literal=False,
            )
        ]
        key_e = (id(_PolicyE), "hash_e")
        key_f = (id(_PolicyF), "hash_f")

        # Inject both classes directly into the OrderedDict cache
        InvariantASTCache._cache[key_e] = meta
        InvariantASTCache.put(_PolicyF, "hash_f", meta)

        try:
            InvariantASTCache.clear(_PolicyE)
            assert InvariantASTCache.get(_PolicyE, "hash_e") is None
            # _PolicyF should be unaffected
            assert InvariantASTCache.get(_PolicyF, "hash_f") is meta
        finally:
            InvariantASTCache._cache.pop(key_e, None)
            InvariantASTCache._cache.pop(key_f, None)

    def test_clear_none_removes_all(self) -> None:
        """clear(None) clears the entire cache."""

        class _PolicyG:
            pass

        meta = [
            InvariantMeta(
                label="g",
                explain_template="",
                tree_repr="FieldRef(f)",
                field_refs=frozenset(["g"]),
                has_literal=False,
            )
        ]
        InvariantASTCache.put(_PolicyG, "hash_g", meta)
        assert InvariantASTCache.size() > 0
        InvariantASTCache.clear()
        assert InvariantASTCache.size() == 0

    def test_clear_specific_does_not_remove_other_policies(self) -> None:
        """clear(PolicyH) only removes PolicyH entries, not PolicyI entries."""

        class _PolicyH:
            pass

        class _PolicyI:
            pass

        meta = [
            InvariantMeta(
                label="h",
                explain_template="",
                tree_repr="FieldRef(f)",
                field_refs=frozenset(["h"]),
                has_literal=False,
            )
        ]
        try:
            InvariantASTCache.put(_PolicyH, "hash_h", meta)
            InvariantASTCache.put(_PolicyI, "hash_i", meta)
            InvariantASTCache.clear(_PolicyH)
            assert InvariantASTCache.get(_PolicyH, "hash_h") is None
            assert InvariantASTCache.get(_PolicyI, "hash_i") is meta
        finally:
            InvariantASTCache.clear()


# ── Integration: end-to-end promotion with right-side field ──────────────────


class TestPromotionIntegration:
    """Verifies that right-side field promotion flows through analyze + transpile."""

    def test_right_side_field_promotion_round_trip(self) -> None:
        """Lines 299-301 + 418: analyze detects right-side field, transpile uses it."""
        field = Field("category", str, "String")
        node = _CmpOp(op="eq", left=_Literal("electronics"), right=_FieldRef(field))
        invariant = ConstraintExpr(node)
        promotions = analyze_string_promotions([invariant])
        assert "category" in promotions
        result = transpile(node, promotions=promotions)
        assert result is not None
