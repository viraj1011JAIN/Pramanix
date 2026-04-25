# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for transparent String→Int promotion in transpiler and solver."""
from __future__ import annotations

from pramanix import Guard, GuardConfig
from pramanix.expressions import E, Field
from pramanix.policy import Policy
from pramanix.transpiler import analyze_string_promotions

# ── Minimal policies ──────────────────────────────────────────────────────────


class RolePolicy(Policy):
    """Policy that uses a String field in equality only — promotable."""
    role = Field("role", str, "String")
    amount = Field("amount", float, "Real")

    @classmethod
    def invariants(cls):
        return [
            E(cls.role).is_in(["admin", "manager"]).named("valid_role"),
            (E(cls.amount) <= 1000).named("within_limit"),
        ]


class RolePolicyWithEq(Policy):
    """Policy that uses String field only via == — promotable."""
    status = Field("status", str, "String")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.status) == "active").named("must_be_active"),
        ]


class MixedStringPolicy(Policy):
    """Policy with a String field used in startswith — NOT promotable."""
    name = Field("name", str, "String")

    @classmethod
    def invariants(cls):
        return [
            E(cls.name).starts_with("Dr.").named("must_be_doctor"),
        ]


class TwoStringPolicy(Policy):
    """Two String fields: one promotable, one not."""
    role = Field("role", str, "String")
    notes = Field("notes", str, "String")

    @classmethod
    def invariants(cls):
        return [
            E(cls.role).is_in(["admin", "viewer"]).named("valid_role"),
            E(cls.notes).starts_with("NOTE:").named("has_prefix"),
        ]


# ── analyze_string_promotions unit tests ──────────────────────────────────────


def test_analyze_promotions_returns_dict_for_is_in_field() -> None:
    invs = RolePolicy.invariants()
    result = analyze_string_promotions(invs)
    assert "role" in result


def test_analyze_promotions_encodes_sorted_alphabetically() -> None:
    invs = RolePolicy.invariants()
    result = analyze_string_promotions(invs)
    # "admin" < "manager" alphabetically → codes 0, 1
    assert result["role"]["admin"] == 0
    assert result["role"]["manager"] == 1


def test_analyze_promotions_eq_field_is_promoted() -> None:
    invs = RolePolicyWithEq.invariants()
    result = analyze_string_promotions(invs)
    assert "status" in result
    assert result["status"]["active"] == 0


def test_analyze_promotions_startswith_field_not_promoted() -> None:
    invs = MixedStringPolicy.invariants()
    result = analyze_string_promotions(invs)
    assert "name" not in result


def test_analyze_promotions_only_promotable_field_included() -> None:
    invs = TwoStringPolicy.invariants()
    result = analyze_string_promotions(invs)
    assert "role" in result
    assert "notes" not in result


def test_analyze_promotions_empty_invariants() -> None:
    result = analyze_string_promotions([])
    assert result == {}


def test_analyze_promotions_non_string_field_not_included() -> None:
    invs = RolePolicy.invariants()
    result = analyze_string_promotions(invs)
    assert "amount" not in result


# ── End-to-end: Guard.verify with promoted String field ──────────────────────


def _make_guard(policy_cls) -> Guard:
    config = GuardConfig(
        solver_timeout_ms=5000,
        fast_path_enabled=False,
    )
    return Guard(policy_cls, config)


def test_string_promotion_allows_valid_role() -> None:
    guard = _make_guard(RolePolicy)
    decision = guard.verify({"role": "admin", "amount": 500}, {})
    assert decision.allowed is True


def test_string_promotion_blocks_invalid_role() -> None:
    guard = _make_guard(RolePolicy)
    decision = guard.verify({"role": "intern", "amount": 500}, {})
    assert decision.allowed is False


def test_string_promotion_allows_all_listed_values() -> None:
    guard = _make_guard(RolePolicy)
    for role in ("admin", "manager"):
        d = guard.verify({"role": role, "amount": 100}, {})
        assert d.allowed is True, f"role={role!r} should be allowed"


def test_string_promotion_blocks_value_outside_list() -> None:
    guard = _make_guard(RolePolicy)
    for role in ("guest", "root", ""):
        d = guard.verify({"role": role, "amount": 100}, {})
        assert d.allowed is False, f"role={role!r} should be blocked"


def test_string_promotion_with_eq_allows_active() -> None:
    guard = _make_guard(RolePolicyWithEq)
    d = guard.verify({"status": "active"}, {})
    assert d.allowed is True


def test_string_promotion_with_eq_blocks_inactive() -> None:
    guard = _make_guard(RolePolicyWithEq)
    d = guard.verify({"status": "inactive"}, {})
    assert d.allowed is False


def test_non_promotable_string_field_still_works() -> None:
    """A starts_with field is NOT promoted — ensure it still evaluates correctly."""
    guard = _make_guard(MixedStringPolicy)
    d = guard.verify({"name": "Dr. Smith"}, {})
    assert d.allowed is True
    d2 = guard.verify({"name": "Mr. Jones"}, {})
    assert d2.allowed is False


def test_two_string_policy_correct_decisions() -> None:
    guard = _make_guard(TwoStringPolicy)
    # Valid role + valid prefix → allowed
    d = guard.verify({"role": "admin", "notes": "NOTE: test"}, {})
    assert d.allowed is True
    # Invalid role → blocked
    d2 = guard.verify({"role": "hacker", "notes": "NOTE: test"}, {})
    assert d2.allowed is False
    # Invalid prefix → blocked
    d3 = guard.verify({"role": "admin", "notes": "no prefix"}, {})
    assert d3.allowed is False
