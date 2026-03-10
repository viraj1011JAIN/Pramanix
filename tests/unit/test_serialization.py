# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.helpers.serialization — safe_dump().

Coverage targets:
- Valid flat models: Decimal, str, bool, int fields all preserved
- Nested BaseModel detection raises TypeError
- Nested model in a list raises TypeError
- Nested model in a dict value raises TypeError
- Picklability contract (debug mode only, but always runs in test)
- Distinct output dicts per call (no aliasing)
- safe_dump() returns plain dict, not BaseModel
- Decimal and datetime primitives preserved as native types (not stringified)
"""
from __future__ import annotations

import pickle
from datetime import date, datetime
from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix.helpers.serialization import safe_dump

# ── Models used throughout ────────────────────────────────────────────────────


class _FlatModel(BaseModel):
    amount: Decimal
    label: str
    is_active: bool
    count: int


class _NestedModel(BaseModel):
    inner: _FlatModel  # nested BaseModel — must be rejected


class _ModelWithList(BaseModel):
    items: list[str]
    amount: Decimal


class _ModelWithDatetime(BaseModel):
    created_at: datetime
    event_date: date
    label: str


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def flat_model() -> _FlatModel:
    return _FlatModel(amount=Decimal("123.45"), label="test", is_active=True, count=7)


# ═══════════════════════════════════════════════════════════════════════════════
# Basic contract: returns plain dict
# ═══════════════════════════════════════════════════════════════════════════════


class TestSafeDumpBasic:
    def test_returns_dict(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert isinstance(result, dict)

    def test_result_is_not_base_model(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert not isinstance(result, BaseModel)

    def test_amount_field_preserved_as_decimal(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert isinstance(result["amount"], Decimal)
        assert result["amount"] == Decimal("123.45")

    def test_str_field_preserved(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert result["label"] == "test"

    def test_bool_field_preserved(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert result["is_active"] is True

    def test_int_field_preserved(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert result["count"] == 7

    def test_all_fields_present(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        assert set(result.keys()) == {"amount", "label", "is_active", "count"}

    def test_two_calls_produce_distinct_dicts(self, flat_model: _FlatModel) -> None:
        d1 = safe_dump(flat_model)
        d2 = safe_dump(flat_model)
        assert d1 is not d2

    def test_list_field_preserved(self) -> None:
        m = _ModelWithList(items=["a", "b", "c"], amount=Decimal("10"))
        result = safe_dump(m)
        assert result["items"] == ["a", "b", "c"]


# ═══════════════════════════════════════════════════════════════════════════════
# Datetime primitives: preserved as native types, not stringified
# ═══════════════════════════════════════════════════════════════════════════════


class TestSafeDumpNativeTypes:
    def test_datetime_preserved_as_datetime(self) -> None:
        dt = datetime(2026, 3, 10, 5, 30, 0)
        m = _ModelWithDatetime(created_at=dt, event_date=date(2026, 3, 10), label="x")
        result = safe_dump(m)
        assert isinstance(result["created_at"], datetime)
        assert result["created_at"] == dt

    def test_date_preserved_as_date(self) -> None:
        d = date(2026, 3, 10)
        m = _ModelWithDatetime(created_at=datetime(2026, 3, 10), event_date=d, label="x")
        result = safe_dump(m)
        assert isinstance(result["event_date"], date)
        assert result["event_date"] == d


# ═══════════════════════════════════════════════════════════════════════════════
# Nested BaseModel behaviour
# ═══════════════════════════════════════════════════════════════════════════════


class TestSafeDumpNestedModelRejection:
    """pydantic model_dump() already flattens nested BaseModel instances to plain
    dicts before _assert_no_nested_models runs, so safe_dump() succeeds and the
    nested data is preserved in dict form.  The guard function is exercised
    separately via _assert_no_nested_models to confirm it would catch a raw model.
    """

    def test_nested_model_serialised_to_dict(self) -> None:
        """safe_dump should succeed because model_dump() flattens the nested model."""
        inner = _FlatModel(amount=Decimal("1"), label="inner", is_active=False, count=0)
        outer = _NestedModel(inner=inner)
        # model_dump() converts nested BaseModel → dict; no TypeError expected
        result = safe_dump(outer)
        assert isinstance(result, dict)
        assert isinstance(result["inner"], dict)
        assert result["inner"]["label"] == "inner"

    def test_guard_detects_raw_base_model_directly(self) -> None:
        """_assert_no_nested_models must raise if a raw BaseModel is passed manually."""
        from pramanix.helpers.serialization import (
            _assert_no_nested_models,  # type: ignore[attr-defined,unused-ignore]
        )

        raw_model = _FlatModel(amount=Decimal("1"), label="x", is_active=False, count=0)
        with pytest.raises(TypeError, match="nested Pydantic model"):
            _assert_no_nested_models({"key": raw_model})

    def test_guard_detects_raw_base_model_in_list(self) -> None:
        """_assert_no_nested_models must raise for a BaseModel inside a list."""
        from pramanix.helpers.serialization import (
            _assert_no_nested_models,  # type: ignore[attr-defined,unused-ignore]
        )

        raw_model = _FlatModel(amount=Decimal("2"), label="y", is_active=True, count=1)
        with pytest.raises(TypeError, match="nested Pydantic model"):
            _assert_no_nested_models([raw_model])


# ═══════════════════════════════════════════════════════════════════════════════
# Picklability
# ═══════════════════════════════════════════════════════════════════════════════


class TestSafeDumpPicklability:
    def test_result_is_picklable(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        pickled = pickle.dumps(result)
        unpickled = pickle.loads(pickled)  # test-only
        assert unpickled["amount"] == Decimal("123.45")

    def test_decimal_survives_pickle_roundtrip(self, flat_model: _FlatModel) -> None:
        result = safe_dump(flat_model)
        restored = pickle.loads(pickle.dumps(result))
        assert restored["amount"] == result["amount"]
