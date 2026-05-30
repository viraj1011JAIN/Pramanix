# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
import threading
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)

_PARSE_FAILURE_COUNTER: Any = None
_PARSE_FAILURE_COUNTER_LOCK = threading.Lock()


def _inc_parse_failure(rule_name: str) -> None:
    """Increment pramanix_fast_path_parse_failure_total for the given rule."""
    global _PARSE_FAILURE_COUNTER
    if _PARSE_FAILURE_COUNTER is None:
        with _PARSE_FAILURE_COUNTER_LOCK:
            if _PARSE_FAILURE_COUNTER is None:
                try:
                    from prometheus_client import Counter as _Counter

                    _PARSE_FAILURE_COUNTER = _Counter(
                        "pramanix_fast_path_parse_failure_total",
                        "Fast-path Decimal parse failures by rule; non-zero means "
                        "malformed numeric inputs were passed through to Z3",
                        ["rule"],
                    )
                except Exception:
                    _PARSE_FAILURE_COUNTER = False
    try:
        if _PARSE_FAILURE_COUNTER:
            _PARSE_FAILURE_COUNTER.labels(rule=rule_name).inc()
    except Exception as _e:
        log.debug("pramanix.fast_path: metrics increment failed: %s", _e)


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
        _rule_name = f"negative_amount({field_name})"

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            val = intent.get(field_name) or state.get(field_name)
            if val is None:
                return None
            try:
                d = Decimal(str(val))
                if not d.is_finite():
                    return f"Non-finite {field_name!r} value {val!r} is not a valid amount"
                if d < Decimal("0"):
                    return f"Amount must be non-negative (got {val})"
            except Exception as _exc:
                _inc_parse_failure(_rule_name)
                log.warning(
                    "fast_path.negative_amount: could not parse %r as Decimal"
                    " — blocking as fail-safe (%s: %s)",
                    val,
                    type(_exc).__name__,
                    _exc,
                )
                return f"Malformed {field_name!r} value:" f" {val!r} is not a valid number"
            return None

        _rule.__name__ = _rule_name
        return _rule

    @staticmethod
    def zero_or_negative_balance(field_name: str = "balance") -> FastPathRule:
        """Block if account balance is zero or negative."""
        _rule_name = f"zero_or_negative_balance({field_name})"

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            val = state.get(field_name)
            if val is None:
                return None
            try:
                d = Decimal(str(val))
                if not d.is_finite():
                    return f"Non-finite {field_name!r} balance {val!r} is not a valid amount"
                if d <= Decimal("0"):
                    return "Account balance is zero or negative"
            except Exception as _exc:
                _inc_parse_failure(_rule_name)
                log.warning(
                    "fast_path.zero_or_negative_balance:"
                    " could not parse %r as Decimal"
                    " — blocking as fail-safe (%s: %s)",
                    val,
                    type(_exc).__name__,
                    _exc,
                )
                return f"Malformed {field_name!r} balance:" f" {val!r} is not a valid number"
            return None

        _rule.__name__ = _rule_name
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
        _rule_name = f"exceeds_hard_cap({amount_field},{cap})"

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            val = intent.get(amount_field) or state.get(amount_field)
            if val is None:
                return None
            try:
                d = Decimal(str(val))
                if not d.is_finite():
                    return f"Non-finite {amount_field!r} value {val!r} is not a valid amount"
                if d > cap_decimal:
                    return f"Amount exceeds hard cap of {cap}"
            except Exception as _exc:
                _inc_parse_failure(_rule_name)
                log.warning(
                    "fast_path.exceeds_hard_cap: could not parse %r as Decimal"
                    " — blocking as fail-safe (%s: %s)",
                    val,
                    type(_exc).__name__,
                    _exc,
                )
                return f"Malformed {amount_field!r} value:" f" {val!r} is not a valid number"
            return None

        _rule.__name__ = _rule_name
        return _rule

    @staticmethod
    def amount_exceeds_balance(
        amount_field: str = "amount",
        balance_field: str = "balance",
    ) -> FastPathRule:
        """Block if amount clearly exceeds balance (obvious overdraft).

        The fast-path never allows — if this check passes, Z3 still verifies.
        """

        _rule_name = f"amount_exceeds_balance({amount_field},{balance_field})"

        def _rule(intent: dict[str, Any], state: dict[str, Any]) -> str | None:
            amount_val = intent.get(amount_field)
            balance_val = state.get(balance_field)
            if amount_val is None or balance_val is None:
                return None
            try:
                amount = Decimal(str(amount_val))
                balance = Decimal(str(balance_val))
                if not amount.is_finite():
                    return f"Non-finite {amount_field!r} value {amount_val!r} is not a valid amount"
                if not balance.is_finite():
                    return (
                        f"Non-finite {balance_field!r} value {balance_val!r} is not a valid balance"
                    )
                if amount > balance:
                    return "Insufficient balance for transfer"
            except Exception as _exc:
                _inc_parse_failure(_rule_name)
                log.warning(
                    "fast_path.amount_exceeds_balance: could not parse"
                    " amount=%r or balance=%r as Decimal"
                    " — blocking as fail-safe (%s: %s)",
                    amount_val,
                    balance_val,
                    type(_exc).__name__,
                    _exc,
                )
                return (
                    f"Malformed {amount_field!r} or {balance_field!r}:"
                    " non-numeric value cannot be verified"
                )
            return None

        _rule.__name__ = _rule_name
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
                rule_name = getattr(rule, "__name__", "unknown_rule")
                log.warning(
                    "Fast-path rule raised exception — blocking fail-closed (rule=%s, error=%s)",
                    rule_name,
                    e,
                )
                return FastPathResult.block(
                    reason=f"Fast-path rule error (fail-closed): rule={rule_name}",
                    rule_name=rule_name,
                )

        return FastPathResult.pass_through()

    @property
    def rule_count(self) -> int:
        """Return the number of fast-path rules registered on this instance."""
        return len(self._rules)
