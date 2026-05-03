# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Semantic fast-path for Pramanix Guard.

Pre-screens obvious violations in pure Python O(1) before invoking Z3.
Eliminates Z3 overhead for the most common failure modes.

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
        fast_path_enabled=True,
        fast_path_rules=(
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.zero_or_negative_balance("balance"),
        )
    )
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)


# A fast-path rule takes (intent_dict, state_dict) and returns:
# - None: no violation detected, proceed to Z3
# - str: violation detected, this string is the block reason
FastPathRule = Callable[[dict[str, Any], dict[str, Any]], "str | None"]


@dataclass
class FastPathResult:
    """Result of fast-path evaluation."""

    blocked: bool
    reason: str = ""
    rule_name: str = ""

    @classmethod
    def pass_through(cls) -> FastPathResult:
        """Return a FastPathResult indicating the request should proceed to Z3."""
        return cls(blocked=False)

    @classmethod
    def block(cls, reason: str, rule_name: str = "") -> FastPathResult:
        """Return a FastPathResult indicating the request is blocked before Z3."""
        return cls(blocked=True, reason=reason, rule_name=rule_name)


class SemanticFastPath:
    """Factory for common fast-path rules.

    All rules are pure Python functions. No Z3, no Pydantic, no I/O.
    Each rule runs in O(1) — a single dict lookup and comparison.

    Rules return None (pass) or a string (block reason).
    """

    @staticmethod
    def negative_amount(field_name: str = "amount") -> FastPathRule:
        """Block if amount is negative."""

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            val = intent.get(field_name) or state.get(field_name)
            if val is None:
                return None
            try:
                if Decimal(str(val)) < Decimal("0"):
                    return f"Amount must be non-negative (got {val})"
            except Exception:
                return None
            return None

        _rule.__name__ = f"negative_amount({field_name})"
        return _rule

    @staticmethod
    def zero_or_negative_balance(field_name: str = "balance") -> FastPathRule:
        """Block if account balance is zero or negative."""

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            val = state.get(field_name)
            if val is None:
                return None
            try:
                if Decimal(str(val)) <= Decimal("0"):
                    return "Account balance is zero or negative"
            except Exception:
                return None
            return None

        _rule.__name__ = f"zero_or_negative_balance({field_name})"
        return _rule

    @staticmethod
    def account_frozen(field_name: str = "is_frozen") -> FastPathRule:
        """Block if account is frozen."""

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
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
        """Block if amount exceeds an absolute hard cap."""
        cap_decimal = Decimal(str(cap))

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
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

        The fast-path never allows — if this check passes, Z3 still verifies.
        """

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            amount_val = intent.get(amount_field)
            balance_val = state.get(balance_field)
            if amount_val is None or balance_val is None:
                return None
            try:
                amount = Decimal(str(amount_val))
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
    """

    def __init__(self, rules: list[Any] | tuple[Any, ...]) -> None:
        self._rules = list(rules)  # Defensive copy

    def evaluate(self, intent: dict[str, Any], state: dict[str, Any]) -> FastPathResult:
        """Evaluate all rules. Returns immediately on first block.

        INVARIANT: Returns FastPathResult.pass_through() if no rule blocks.
        INVARIANT: Never returns allowed=True — only pass_through or block.
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
                log.warning(
                    "Fast-path rule raised exception — continuing to Z3",
                    extra={"rule": getattr(rule, "__name__", "?"), "error": str(e)},
                )
                continue

        return FastPathResult.pass_through()

    @property
    def rule_count(self) -> int:
        """Return the number of fast-path rules registered on this instance."""
        return len(self._rules)
