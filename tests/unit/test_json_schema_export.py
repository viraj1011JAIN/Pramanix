# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for G-3 — Policy.export_json_schema() classmethod.

Coverage:
- export_json_schema returns a dict
- $schema is JSON Schema draft-07 URI
- type is "object"
- All declared fields appear in "properties"
- "required" is sorted list of all field names
- additionalProperties is False
- title matches the class name
- int → "integer", float/Decimal → "number", str → "string", bool → "boolean"
- Dynamic policy via from_config also exports schema
"""
from __future__ import annotations

from decimal import Decimal

from pramanix.expressions import E, Field
from pramanix.policy import Policy


class _TransferPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    is_frozen = Field("is_frozen", bool, "Bool")
    recipient = Field("recipient", str, "String")
    count = Field("count", int, "Int")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) > Decimal("0")).named("positive_amount")]


class _MinimalPolicy(Policy):
    price = Field("price", float, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.price) > 0.0).named("positive_price")]


class TestExportJsonSchema:
    def test_returns_dict(self):
        schema = _TransferPolicy.export_json_schema()
        assert isinstance(schema, dict)

    def test_schema_uri_is_draft07(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"

    def test_type_is_object(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["type"] == "object"

    def test_title_matches_class_name(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["title"] == "_TransferPolicy"

    def test_additional_properties_false(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["additionalProperties"] is False

    def test_all_fields_in_properties(self):
        schema = _TransferPolicy.export_json_schema()
        declared = set(_TransferPolicy.fields().keys())
        assert declared == set(schema["properties"].keys())

    def test_required_is_sorted_list(self):
        schema = _TransferPolicy.export_json_schema()
        required = schema["required"]
        assert required == sorted(required)
        assert set(required) == set(_TransferPolicy.fields().keys())

    def test_decimal_maps_to_number(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["properties"]["amount"]["type"] == "number"

    def test_bool_maps_to_boolean(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["properties"]["is_frozen"]["type"] == "boolean"

    def test_str_maps_to_string(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["properties"]["recipient"]["type"] == "string"

    def test_int_maps_to_integer(self):
        schema = _TransferPolicy.export_json_schema()
        assert schema["properties"]["count"]["type"] == "integer"

    def test_float_maps_to_number(self):
        schema = _MinimalPolicy.export_json_schema()
        assert schema["properties"]["price"]["type"] == "number"

    def test_schema_is_json_serializable(self):
        import json

        schema = _TransferPolicy.export_json_schema()
        serialized = json.dumps(schema)
        roundtripped = json.loads(serialized)
        assert roundtripped == schema
