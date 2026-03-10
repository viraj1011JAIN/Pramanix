# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.helpers.type_mapping — python_type_to_z3_sort().

Coverage targets:
- bool → BoolSort (checked BEFORE int due to bool ⊂ int in Python)
- int → IntSort
- float → RealSort
- Decimal → RealSort
- Unsupported types raise PolicyCompilationError: str, list, dict, set, tuple,
  bytes, object, None (NoneType)
- z3_type_hint consistency check: matching hint accepted, mismatched raises
- Return types are z3.SortRef instances
"""
from __future__ import annotations

from decimal import Decimal

import pytest
import z3

from pramanix.exceptions import PolicyCompilationError
from pramanix.helpers.type_mapping import python_type_to_z3_sort

# ═══════════════════════════════════════════════════════════════════════════════
# Supported type mappings
# ═══════════════════════════════════════════════════════════════════════════════


class TestSupportedTypeMappings:
    """Every supported Python type must map to its documented Z3 sort."""

    def test_bool_maps_to_bool_sort(self) -> None:
        sort = python_type_to_z3_sort(bool)
        assert isinstance(sort, z3.BoolSortRef)

    def test_int_maps_to_int_sort(self) -> None:
        sort = python_type_to_z3_sort(int)
        assert isinstance(sort, z3.ArithSortRef)
        assert sort == z3.IntSort()

    def test_float_maps_to_real_sort(self) -> None:
        sort = python_type_to_z3_sort(float)
        assert isinstance(sort, z3.ArithSortRef)
        assert sort == z3.RealSort()

    def test_decimal_maps_to_real_sort(self) -> None:
        sort = python_type_to_z3_sort(Decimal)
        assert isinstance(sort, z3.ArithSortRef)
        assert sort == z3.RealSort()

    def test_bool_before_int_ordering(self) -> None:
        """bool must map to BoolSort, NOT IntSort (bool ⊂ int in Python)."""
        bool_sort = python_type_to_z3_sort(bool)
        int_sort = python_type_to_z3_sort(int)
        assert bool_sort != int_sort  # BoolSort ≠ IntSort

    def test_returns_z3_sort_ref_instance(self) -> None:
        for py_type in (bool, int, float, Decimal):
            sort = python_type_to_z3_sort(py_type)
            assert isinstance(sort, z3.SortRef), f"{py_type} did not return SortRef"


# ═══════════════════════════════════════════════════════════════════════════════
# Unsupported types raise PolicyCompilationError
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnsupportedTypes:
    @pytest.mark.parametrize(
        "unsupported_type",
        [
            str,
            list,
            dict,
            set,
            tuple,
            bytes,
            object,
            type(None),
        ],
    )
    def test_unsupported_type_raises_policy_compilation_error(
        self, unsupported_type: type
    ) -> None:
        with pytest.raises(PolicyCompilationError):
            python_type_to_z3_sort(unsupported_type)

    def test_error_message_mentions_supported_types(self) -> None:
        try:
            python_type_to_z3_sort(str)
        except PolicyCompilationError as err:
            msg = str(err)
            assert "bool" in msg or "int" in msg or "Decimal" in msg
        else:
            pytest.fail("PolicyCompilationError not raised for str")


# ═══════════════════════════════════════════════════════════════════════════════
# z3_type_hint consistency check
# ═══════════════════════════════════════════════════════════════════════════════


class TestZ3TypeHintConsistency:
    """An explicit z3_type_hint is validated against the resolved sort."""

    def test_bool_with_correct_hint_accepted(self) -> None:
        sort = python_type_to_z3_sort(bool, z3_type_hint="Bool")
        assert isinstance(sort, z3.BoolSortRef)

    def test_int_with_correct_hint_accepted(self) -> None:
        sort = python_type_to_z3_sort(int, z3_type_hint="Int")
        assert sort == z3.IntSort()

    def test_float_with_correct_hint_accepted(self) -> None:
        sort = python_type_to_z3_sort(float, z3_type_hint="Real")
        assert sort == z3.RealSort()

    def test_decimal_with_correct_hint_accepted(self) -> None:
        sort = python_type_to_z3_sort(Decimal, z3_type_hint="Real")
        assert sort == z3.RealSort()

    def test_bool_with_wrong_hint_raises(self) -> None:
        """Declaring bool as 'Int' is a type mismatch and must raise."""
        with pytest.raises(PolicyCompilationError, match="mismatch"):
            python_type_to_z3_sort(bool, z3_type_hint="Int")

    def test_int_with_wrong_hint_raises(self) -> None:
        with pytest.raises(PolicyCompilationError, match="mismatch"):
            python_type_to_z3_sort(int, z3_type_hint="Bool")

    def test_decimal_with_wrong_hint_raises(self) -> None:
        with pytest.raises(PolicyCompilationError, match="mismatch"):
            python_type_to_z3_sort(Decimal, z3_type_hint="Int")

    def test_no_hint_always_accepted_for_supported_types(self) -> None:
        for py_type in (bool, int, float, Decimal):
            sort = python_type_to_z3_sort(py_type, z3_type_hint=None)
            assert isinstance(sort, z3.SortRef)
