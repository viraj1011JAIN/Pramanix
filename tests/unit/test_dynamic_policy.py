# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase B-2: Policy.from_config() dynamic factory.

Gate condition (from engineering plan):
    Policy.from_config({'balance': ('Real', Decimal), 'amount': ('Real', Decimal)}, ...)
    must produce a valid, verifiable policy.
    100 different tenant configs must compile without error in < 1s total.
"""
from __future__ import annotations

import time
from decimal import Decimal

import pytest

from pramanix.exceptions import ConfigurationError, InvariantLabelError, PolicyError
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.policy import Policy, _DYNAMIC_POLICY_CACHE


# ── Helpers ───────────────────────────────────────────────────────────────────


def _funds_check_inv(f: dict[str, Field]) -> ConstraintExpr:
    return (E(f["balance"]) - E(f["amount"]) >= 0).named("funds_check")


def _limit_inv(f: dict[str, Field]) -> ConstraintExpr:
    return (E(f["amount"]) <= Decimal("10000")).named("max_tx")


_BASE_FIELDS: dict[str, tuple[str, type]] = {
    "balance": ("Real", Decimal),
    "amount": ("Real", Decimal),
}


# ── Basic construction ────────────────────────────────────────────────────────


class TestFromConfigBasic:
    def test_returns_policy_subclass(self) -> None:
        cls = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        assert issubclass(cls, Policy)

    def test_class_has_invariants(self) -> None:
        cls = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        invs = cls.invariants()
        assert len(invs) == 1
        assert invs[0].label == "funds_check"

    def test_class_has_field_attributes(self) -> None:
        cls = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        fields = cls.fields()
        assert "balance" in fields
        assert "amount" in fields
        assert isinstance(fields["balance"], Field)
        assert fields["balance"].z3_type == "Real"

    def test_multiple_invariant_lambdas(self) -> None:
        cls = Policy.from_config(_BASE_FIELDS, [_funds_check_inv, _limit_inv])
        invs = cls.invariants()
        assert len(invs) == 2
        labels = {inv.label for inv in invs}
        assert labels == {"funds_check", "max_tx"}

    def test_lambda_returning_list_is_flattened(self) -> None:
        def multi_inv(f: dict[str, Field]) -> list[ConstraintExpr]:
            return [
                (E(f["balance"]) >= 0).named("non_neg_balance"),
                (E(f["amount"]) >= 0).named("non_neg_amount"),
            ]

        cls = Policy.from_config(_BASE_FIELDS, [multi_inv])
        invs = cls.invariants()
        assert len(invs) == 2

    def test_all_z3_types_accepted(self) -> None:
        fields = {
            "price": ("Real", Decimal),
            "count": ("Int", int),
            "active": ("Bool", bool),
            "name": ("String", str),
        }

        def inv(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["active"]) == True).named("active_check")  # noqa: E712

        cls = Policy.from_config(fields, [inv])
        assert cls.fields()["price"].z3_type == "Real"
        assert cls.fields()["count"].z3_type == "Int"
        assert cls.fields()["active"].z3_type == "Bool"
        assert cls.fields()["name"].z3_type == "String"

    def test_validate_passes_on_dynamic_policy(self) -> None:
        cls = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        cls.validate()  # must not raise

    def test_class_name_is_deterministic(self) -> None:
        cls1 = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        # Same fields → same schema hash → same class name prefix
        assert cls1.__name__.startswith("_DynamicPolicy_")


# ── Caching ───────────────────────────────────────────────────────────────────


class TestFromConfigCaching:
    def test_same_config_returns_same_class(self) -> None:
        cls1 = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        cls2 = Policy.from_config(_BASE_FIELDS, [_funds_check_inv])
        assert cls1 is cls2

    def test_different_fields_returns_different_class(self) -> None:
        fields_a = {"amount": ("Real", Decimal)}
        fields_b = {"balance": ("Real", Decimal)}

        def inv_a(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["amount"]) >= 0).named("pos_amount")

        def inv_b(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["balance"]) >= 0).named("pos_balance")

        cls_a = Policy.from_config(fields_a, [inv_a])
        cls_b = Policy.from_config(fields_b, [inv_b])
        assert cls_a is not cls_b

    def test_different_invariant_functions_returns_different_class(self) -> None:
        def inv1(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["balance"]) >= 0).named("check1")

        def inv2(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["balance"]) >= 0).named("check2")

        cls1 = Policy.from_config({"balance": ("Real", Decimal)}, [inv1])
        cls2 = Policy.from_config({"balance": ("Real", Decimal)}, [inv2])
        assert cls1 is not cls2


# ── Guard round-trip ──────────────────────────────────────────────────────────


class TestFromConfigGuardRoundTrip:
    def _make_guard(self, allow: bool):
        from pramanix.guard import Guard, GuardConfig

        def inv(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["balance"]) - E(f["amount"]) >= 0).named("funds_check")

        cls = Policy.from_config(_BASE_FIELDS, [inv])
        return Guard(cls, GuardConfig(solver_timeout_ms=5000))

    def test_allow_when_invariant_satisfied(self) -> None:
        guard = self._make_guard(allow=True)
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        assert d.allowed is True

    def test_block_when_invariant_violated(self) -> None:
        guard = self._make_guard(allow=False)
        d = guard.verify(
            intent={"amount": Decimal("1000")},
            state={"balance": Decimal("100")},
        )
        assert d.allowed is False
        assert "funds_check" in d.violated_invariants

    def test_block_with_zero_balance(self) -> None:
        guard = self._make_guard(allow=False)
        d = guard.verify(
            intent={"amount": Decimal("0.01")},
            state={"balance": Decimal("0")},
        )
        assert d.allowed is False

    def test_allow_with_exact_balance(self) -> None:
        guard = self._make_guard(allow=True)
        d = guard.verify(
            intent={"amount": Decimal("500")},
            state={"balance": Decimal("500")},
        )
        assert d.allowed is True

    def test_multiple_invariants_all_must_pass(self) -> None:
        from pramanix.guard import Guard, GuardConfig

        def combined_inv(f: dict[str, Field]) -> list[ConstraintExpr]:
            return [
                (E(f["balance"]) - E(f["amount"]) >= 0).named("funds_check"),
                (E(f["amount"]) <= Decimal("10000")).named("max_tx"),
            ]

        cls = Policy.from_config(_BASE_FIELDS, [combined_inv])
        guard = Guard(cls, GuardConfig(solver_timeout_ms=5000))

        # Violates max_tx only
        d = guard.verify(
            intent={"amount": Decimal("20000")},
            state={"balance": Decimal("50000")},
        )
        assert d.allowed is False
        assert "max_tx" in d.violated_invariants

    def test_invariants_compiled_at_construction_not_per_call(self) -> None:
        """Invariant lambdas are called once — not on each verify()."""
        call_count = 0

        def counting_inv(f: dict[str, Field]) -> ConstraintExpr:
            nonlocal call_count
            call_count += 1
            return (E(f["balance"]) >= 0).named("non_neg")

        Policy.from_config({"balance": ("Real", Decimal)}, [counting_inv])
        # Lambda was called once during from_config
        assert call_count == 1

        # Calling from_config again with the same lambda doesn't re-evaluate (cache hit)
        Policy.from_config({"balance": ("Real", Decimal)}, [counting_inv])
        assert call_count == 1  # still 1 — cache hit, lambda not called again


# ── Error paths ───────────────────────────────────────────────────────────────


class TestFromConfigErrors:
    def test_empty_fields_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="fields"):
            Policy.from_config({}, [_funds_check_inv])

    def test_empty_invariants_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="invariants"):
            Policy.from_config(_BASE_FIELDS, [])

    def test_invalid_z3_type_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="z3_type"):
            Policy.from_config(
                {"amount": ("Complex", Decimal)},
                [lambda f: (E(f["amount"]) >= 0).named("x")],
            )

    def test_malformed_spec_tuple_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="2-tuple"):
            Policy.from_config(
                {"amount": "Real"},  # type: ignore[dict-item]  # wrong: string not tuple
                [lambda f: (E(f["amount"]) >= 0).named("x")],
            )

    def test_spec_wrong_length_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="2-tuple"):
            Policy.from_config(
                {"amount": ("Real", Decimal, "extra")},  # type: ignore[dict-item]
                [lambda f: (E(f["amount"]) >= 0).named("x")],
            )

    def test_lambda_that_raises_wraps_in_configuration_error(self) -> None:
        def bad_inv(f: dict[str, Field]) -> ConstraintExpr:
            raise ValueError("intentional error in lambda")

        with pytest.raises(ConfigurationError, match="intentional error"):
            Policy.from_config({"balance": ("Real", Decimal)}, [bad_inv])

    def test_lambda_accessing_missing_field_raises_configuration_error(self) -> None:
        def bad_inv(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["nonexistent"]) >= 0).named("x")  # KeyError

        with pytest.raises((ConfigurationError, KeyError)):
            Policy.from_config({"balance": ("Real", Decimal)}, [bad_inv])

    def test_unlabelled_invariant_raises_on_validate(self) -> None:
        def unlabelled(f: dict[str, Field]) -> ConstraintExpr:
            return E(f["amount"]) >= 0  # no .named()

        cls = Policy.from_config({"amount": ("Real", Decimal)}, [unlabelled])
        with pytest.raises(InvariantLabelError):
            cls.validate()

    def test_duplicate_labels_raises_on_validate(self) -> None:
        def dup1(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["amount"]) >= 0).named("same_label")

        def dup2(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["amount"]) <= 100).named("same_label")

        cls = Policy.from_config({"amount": ("Real", Decimal)}, [dup1, dup2])
        with pytest.raises(InvariantLabelError, match="same_label"):
            cls.validate()


# ── Scale gate: 100 tenant configs in < 1s ───────────────────────────────────


class TestFromConfigScale:
    def test_hundred_unique_configs_compile_under_1s(self) -> None:
        """Gate: 100 distinct tenant schemas must compile in under 1 second total."""
        start = time.perf_counter()

        for i in range(100):
            field_name = f"field_{i}"
            fields = {field_name: ("Real", Decimal)}

            # Use a fresh lambda each iteration so cache won't hit
            # (different invariant function identity per tenant)
            def make_inv(name: str):
                def inv(f: dict[str, Field]) -> ConstraintExpr:
                    return (E(f[name]) >= 0).named(f"pos_{name}")
                return inv

            Policy.from_config(fields, [make_inv(field_name)])

        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"100 tenant configs took {elapsed:.3f}s — must be < 1.0s. "
            "Policy.from_config() is too slow."
        )

    def test_hundred_cached_configs_under_100ms(self) -> None:
        """Cached lookups for identical configs must be near-instant."""
        # Warm the cache with one config
        def inv(f: dict[str, Field]) -> ConstraintExpr:
            return (E(f["balance"]) >= 0).named("pos")

        Policy.from_config({"balance": ("Real", Decimal)}, [inv])

        # Time 100 cache lookups
        start = time.perf_counter()
        for _ in range(100):
            Policy.from_config({"balance": ("Real", Decimal)}, [inv])
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, (
            f"100 cached lookups took {elapsed:.3f}s — must be < 0.1s."
        )
