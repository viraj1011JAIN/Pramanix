# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Security tests for feedback formatters.

Verifies that raw field values from intent/state are never
included in block feedback strings.
"""
from pramanix.decision import Decision
from pramanix.integrations._feedback import format_autogen_rejection, format_block_feedback


def _make_block_decision():
    return Decision.unsafe(
        violated_invariants=("rule_one", "rule_two"),
        explanation="Transfer blocked: amount exceeds balance.",
    )


def test_format_block_feedback_never_includes_raw_amount():
    d = _make_block_decision()
    intent = {"amount": "123456789", "balance": "9988776655"}
    result = format_block_feedback(d, intent)
    # Strip decision_id before checking: UUID hex can coincidentally contain digits
    result_without_id = result.replace(d.decision_id, "<id>")
    assert "123456789" not in result_without_id
    assert "9988776655" not in result_without_id


def test_format_block_feedback_never_includes_field_names_not_in_explain():
    d = _make_block_decision()
    intent = {"secret_field": "secret_value", "amount": "999"}
    result = format_block_feedback(d, intent)
    assert "secret_value" not in result
    assert "secret_field" not in result
    assert "999" not in result


def test_format_block_feedback_includes_decision_id():
    d = _make_block_decision()
    result = format_block_feedback(d, {})
    assert d.decision_id in result


def test_format_block_feedback_includes_violated_invariants():
    d = _make_block_decision()
    result = format_block_feedback(d, {})
    assert "rule_one" in result
    assert "rule_two" in result


def test_format_autogen_rejection_never_includes_raw_values():
    d = _make_block_decision()
    intent = {"amount": "777888999", "balance": "444555666"}
    result = format_autogen_rejection(d, intent)
    assert "777888999" not in result
    assert "444555666" not in result


def test_format_autogen_rejection_includes_decision_id():
    d = _make_block_decision()
    result = format_autogen_rejection(d, {})
    assert d.decision_id in result


def test_format_autogen_rejection_includes_revise_guidance():
    d = _make_block_decision()
    result = format_autogen_rejection(d, {})
    assert "revise" in result.lower()
