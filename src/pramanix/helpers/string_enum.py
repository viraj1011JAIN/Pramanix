# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""StringEnumField — Int-backed string enumeration for Z3 performance.

Z3's ``"String"`` sort uses sequence theory, which is decidable but
significantly slower than linear-integer arithmetic.  For fields that are
string-typed enumerations (status codes, roles, risk tiers, etc.), there is no
need to pay the string-theory penalty — the values are finite and known upfront.

:class:`StringEnumField` maps each string label to a deterministic integer code
and exposes a ``"Int"``-sorted :class:`~pramanix.expressions.Field`.  The
string-to-int mapping is deterministic (insertion-order index), reproducible,
and fully encoded in the HMAC-signed ``ExecutionToken`` intent dump.

Benchmark context
-----------------
A 5-invariant policy with one ``"String"`` sort field: ~12 ms P50.
The same policy with the string field replaced by :class:`StringEnumField`:
~5 ms P50.  For policies with multiple string enumerations the speedup
compounds.

Usage::

    from pramanix.helpers.string_enum import StringEnumField
    from pramanix import Policy, Field, E, Guard, GuardConfig

    _status = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])

    class AccountPolicy(Policy):
        class Meta:
            version = "1.0"

        status = _status.field          # Int field, not String

        @classmethod
        def invariants(cls):
            return [
                # Only CLEAR accounts may transact
                _status.is_allowed_constraint(cls.status, ["CLEAR"]),
                # All encoded values must be in the valid set
                _status.valid_values_constraint(cls.status),
            ]

    # Encode at call time — before passing to Guard.verify():
    decision = guard.verify(
        intent={},
        state={"status": _status.encode("CLEAR")},   # encode "CLEAR" → 0
    )

    # Decode for display or logging:
    label = _status.decode(0)   # → "CLEAR"
"""
from __future__ import annotations

from pramanix.expressions import ConstraintExpr, E, Field

__all__ = ["StringEnumField"]


class StringEnumField:
    """Maps a fixed string enumeration to a Z3 ``Int`` field.

    Each string label is assigned a deterministic integer code based on its
    position in the *values* list (0, 1, 2, …).  The underlying
    :attr:`field` is a ``"Int"``-sorted :class:`~pramanix.expressions.Field`
    that Z3 solves with linear-integer arithmetic instead of sequence theory.

    Args:
        name:   The field name — must match the key used in ``Guard.verify()``
                intent/state dicts and the ``Field`` name in the policy class.
        values: Ordered list of string labels.  Must be non-empty and unique.
                Ordering is stable: "CLEAR" is always 0, "PENDING" always 1,
                etc., so serialised codes remain meaningful across restarts.

    Raises:
        ValueError: If *values* is empty or contains duplicates.

    Example::

        risk_tier = StringEnumField("risk_tier", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        risk_tier.encode("HIGH")   # → 2
        risk_tier.decode(2)        # → "HIGH"
    """

    def __init__(self, name: str, values: list[str]) -> None:
        if not values:
            raise ValueError(
                f"StringEnumField({name!r}): values list must not be empty."
            )
        if len(values) != len(set(values)):
            dupes = [v for v in values if values.count(v) > 1]
            raise ValueError(
                f"StringEnumField({name!r}): values must be unique. "
                f"Duplicates found: {list(dict.fromkeys(dupes))!r}"
            )
        self._name = name
        self._mapping: dict[str, int] = {v: i for i, v in enumerate(values)}
        self._reverse: dict[int, str] = {i: v for i, v in enumerate(values)}
        self.field = Field(name, int, "Int")

    # ── Encoding / decoding ───────────────────────────────────────────────────

    def encode(self, value: str) -> int:
        """Encode a string label to its integer code.

        Args:
            value: A string label from the enumeration.

        Returns:
            The integer code for *value*.

        Raises:
            ValueError: If *value* is not in the enumeration.
        """
        try:
            return self._mapping[value]
        except KeyError:
            raise ValueError(
                f"StringEnumField({self._name!r}): {value!r} is not a valid "
                f"enum label.  Valid labels: {self.values!r}"
            ) from None

    def decode(self, code: int) -> str:
        """Decode an integer code back to its string label.

        Args:
            code: An integer code previously returned by :meth:`encode`.

        Returns:
            The string label for *code*.

        Raises:
            ValueError: If *code* is not a valid code for this enumeration.
        """
        try:
            return self._reverse[code]
        except KeyError:
            raise ValueError(
                f"StringEnumField({self._name!r}): {code!r} is not a valid "
                f"enum code.  Valid codes: {self.codes!r}"
            ) from None

    # ── Constraint factories ──────────────────────────────────────────────────

    def valid_values_constraint(self, field_ref: Field) -> ConstraintExpr:
        """Return a constraint asserting *field_ref* holds a valid enum code.

        This is a catch-all that prevents out-of-range integers from being
        accepted.  Include it in every policy that uses this field.

        Args:
            field_ref: The ``Field`` attribute from the policy class
                       (typically ``cls.<attr_name>``).

        Returns:
            A named :class:`~pramanix.expressions.ConstraintExpr`.
        """
        return E(field_ref).is_in(self.codes).named(
            f"{self._name}_valid_enum_code"
        )

    def is_allowed_constraint(
        self,
        field_ref: Field,
        allowed_values: list[str],
    ) -> ConstraintExpr:
        """Return a constraint asserting *field_ref* is one of *allowed_values*.

        Args:
            field_ref:      The ``Field`` attribute from the policy class.
            allowed_values: Subset of string labels that are permitted.

        Returns:
            A named :class:`~pramanix.expressions.ConstraintExpr`.

        Raises:
            ValueError: If any label in *allowed_values* is not in the enum.
        """
        codes = [self.encode(v) for v in allowed_values]
        return E(field_ref).is_in(codes).named(
            f"{self._name}_in_{'+'.join(allowed_values)}"
        )

    # ── Inspection ────────────────────────────────────────────────────────────

    @property
    def values(self) -> list[str]:
        """All string labels in definition order."""
        return list(self._mapping.keys())

    @property
    def codes(self) -> list[int]:
        """All integer codes in definition order."""
        return list(self._reverse.keys())

    @property
    def mapping(self) -> dict[str, int]:
        """Read-only string→int mapping."""
        return dict(self._mapping)

    def __repr__(self) -> str:
        return f"StringEnumField({self._name!r}, {self.values!r})"
