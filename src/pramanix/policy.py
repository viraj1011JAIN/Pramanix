# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Policy base class — container for Field declarations and invariants.

A :class:`Policy` subclass is the primary authoring surface for Pramanix
users.  It combines three things:

1. **Schema** — class-level :class:`~pramanix.expressions.Field` attributes
   that describe the typed inputs the Guard will receive.
2. **Invariants** — a :meth:`invariants` classmethod that returns a list of
   named :class:`~pramanix.expressions.ConstraintExpr` objects that the
   Z3 solver will verify against every incoming fact.
3. **Meta** — an optional inner class that configures version pinning and
   Pydantic model associations for intent/state validation.

Typical usage::

    from decimal import Decimal
    from pydantic import BaseModel
    from pramanix.expressions import E, Field
    from pramanix.policy import Policy

    class TransferIntent(BaseModel):
        amount: Decimal

    class AccountState(BaseModel):
        state_version: str
        balance: Decimal
        daily_limit: Decimal
        is_frozen: bool

    class TradePolicy(Policy):
        class Meta:
            version = "1.0"
            intent_model = TransferIntent
            state_model = AccountState

        amount      = Field("amount",      Decimal, "Real")
        balance     = Field("balance",     Decimal, "Real")
        daily_limit = Field("daily_limit", Decimal, "Real")
        is_frozen   = Field("is_frozen",   bool,    "Bool")

        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return [
                (E(cls.balance) - E(cls.amount) >= 0)
                .named("non_negative_balance")
                .explain("Overdraft: balance={balance}, amount={amount}"),

                (E(cls.amount) <= E(cls.daily_limit))
                .named("within_daily_limit")
                .explain("Exceeds daily limit: amount={amount}, limit={daily_limit}"),

                (E(cls.is_frozen) == False)        # noqa: E712
                .named("account_not_frozen")
                .explain("Account is frozen; no transactions permitted"),
            ]

Meta inner class
----------------
Declare a ``Meta`` inner class on your :class:`Policy` subclass to enable
advanced Guard features:

``version``
    A string identifier for this policy's expected state schema version.
    ``Guard.verify()`` compares ``state.state_version`` against this value
    and returns ``Decision.stale_state()`` if they differ.

``intent_model``
    A :class:`pydantic.BaseModel` subclass describing the structure of the
    *intent* data.  ``Guard.verify()`` validates the intent dict against this
    model in strict mode before proceeding to Z3.

``state_model``
    A :class:`pydantic.BaseModel` subclass describing the structure of the
    *state* data.  Must include a ``state_version: str`` field.
    ``Guard.verify()`` validates the state dict against this model in strict
    mode before comparing versions.

Call :meth:`Policy.validate` (or let :class:`~pramanix.guard.Guard` do it
automatically at construction) to assert that all labels are present and
unique before verification begins.
"""
from __future__ import annotations

from typing import Any, Callable, cast

from pramanix.exceptions import ConfigurationError, InvariantLabelError, PolicyError
from pramanix.expressions import ConstraintExpr, Field, Z3Type

__all__ = ["Policy"]

# ── B-2: Dynamic policy cache — keyed by (fields_schema, invariant_ids) ──────
_DYNAMIC_POLICY_CACHE: dict[tuple[Any, ...], type["Policy"]] = {}


class Policy:
    """Base class for all Pramanix policies.

    Subclass, declare :class:`~pramanix.expressions.Field` class attributes,
    and override :meth:`invariants` to return the constraint list.  Optionally
    declare a ``Meta`` inner class to enable Pydantic validation and version
    pinning.

    **Field discovery** — :meth:`fields` introspects ``vars(cls)`` and
    returns every attribute that is a :class:`~pramanix.expressions.Field`
    instance.  Inherited fields are *not* included (they belong to the
    parent class); call ``super().fields()`` explicitly if you need them.

    **Validation** — :meth:`validate` checks:

    * At least one invariant is declared.
    * Every invariant has a non-empty ``.named()`` label.
    * All labels are unique within the policy.

    :class:`~pramanix.guard.Guard` calls :meth:`validate` at construction
    time so policy authoring errors surface immediately, not at
    request-handling time.

    **Meta inner class** (optional)::

        class MyPolicy(Policy):
            class Meta:
                version = "2.0"
                intent_model = MyIntentModel   # pydantic BaseModel
                state_model  = MyStateModel    # pydantic BaseModel (needs state_version)

    Meta attributes are read by ``Guard.__init__`` via
    :meth:`meta_version`, :meth:`meta_intent_model`, and
    :meth:`meta_state_model`.
    """

    # ── Field discovery ───────────────────────────────────────────────────────

    @classmethod
    def fields(cls) -> dict[str, Field]:
        """Return all :class:`~pramanix.expressions.Field` class attributes.

        Only attributes declared directly on *this* class are returned
        (``vars(cls)``, not ``dir(cls)``).  Override if you need to merge
        fields from a parent policy.

        Returns:
            A ``{name: Field}`` mapping preserving declaration order
            (Python 3.7+ dict insertion order guarantee).
        """
        return {k: v for k, v in vars(cls).items() if isinstance(v, Field)}

    # ── Invariant declaration ─────────────────────────────────────────────────

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        """Return the list of named :class:`~pramanix.expressions.ConstraintExpr` invariants.

        Every expression **must** carry a unique ``.named()`` label.
        Labels are used by the solver for exact violation attribution and
        appear verbatim in :attr:`~pramanix.decision.Decision.violated_invariants`.

        Raises:
            NotImplementedError: If the subclass does not override this method.
        """
        raise NotImplementedError(
            f"{cls.__name__} must override Policy.invariants() and return "
            "a non-empty list of named ConstraintExpr objects."
        )

    # ── Compile-time validation ───────────────────────────────────────────────

    @classmethod
    def validate(cls) -> None:
        """Assert that all invariants are well-formed.

        Checks (in order):

        1. ``invariants()`` returns a non-empty list.
        2. Every invariant carries a non-empty ``.named()`` label.
        3. All labels are unique within the policy.

        Raises:
            PolicyError:         If ``invariants()`` returns an empty list.
            InvariantLabelError: If any invariant is missing a label, or if
                two invariants share the same label.
        """
        invs = cls.invariants()

        if not invs:
            raise PolicyError(
                f"{cls.__name__}.invariants() returned an empty list. "
                "At least one named ConstraintExpr is required."
            )

        seen: set[str] = set()
        for i, inv in enumerate(invs):
            if not inv.label:
                raise InvariantLabelError(
                    f"{cls.__name__}.invariants()[{i}] has no .named() label. "
                    "Call .named('unique_label') on every invariant."
                )
            if inv.label in seen:
                raise InvariantLabelError(
                    f"{cls.__name__}: duplicate invariant label '{inv.label}'. "
                    "Labels must be unique within a policy."
                )
            seen.add(inv.label)

    # ── B-2: Dynamic policy factory ──────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        fields: dict[str, tuple[str, type]],
        invariants: list[Callable[[dict[str, Field]], "ConstraintExpr | list[ConstraintExpr]"]],
    ) -> "type[Policy]":
        """Create a sealed :class:`Policy` subclass from a runtime field configuration.

        Useful for multi-tenant deployments where each tenant has a distinct field
        schema.  The invariant lambdas are evaluated **once at construction time**
        (not per ``verify()`` call), so the returned class carries pre-built
        :class:`~pramanix.expressions.ConstraintExpr` objects.

        Args:
            fields: Mapping of ``field_name → (z3_type, python_type)`` where
                ``z3_type`` is one of ``"Real"``, ``"Int"``, ``"Bool"``, ``"String"``
                and ``python_type`` is the corresponding Python type (e.g. ``Decimal``).
            invariants: List of callables ``f → ConstraintExpr | list[ConstraintExpr]``
                where ``f`` is a ``dict[str, Field]`` keyed by field name.  Each
                callable is called once with the constructed field dict.

        Returns:
            A new :class:`Policy` subclass with the given fields and invariants.
            Identical ``(fields, invariant-function-ids)`` combinations are cached
            and return the same class object.

        Raises:
            ConfigurationError: If *fields* is empty, any field spec is malformed,
                an unsupported ``z3_type`` is used, or any invariant lambda raises.
        """
        _VALID_Z3 = {"Bool", "Int", "Real", "String"}

        if not fields:
            raise ConfigurationError("Policy.from_config: 'fields' must be a non-empty dict.")
        if not invariants:
            raise ConfigurationError("Policy.from_config: 'invariants' must be a non-empty list.")

        # ── Validate field spec and build Field instances ─────────────────────
        field_instances: dict[str, Field] = {}
        for name, spec in fields.items():
            if not isinstance(spec, tuple) or len(spec) != 2:
                raise ConfigurationError(
                    f"Policy.from_config: field '{name}' spec must be a 2-tuple "
                    f"(z3_type, python_type), got {spec!r}."
                )
            z3_type, python_type = spec
            if z3_type not in _VALID_Z3:
                raise ConfigurationError(
                    f"Policy.from_config: field '{name}' z3_type must be one of "
                    f"{sorted(_VALID_Z3)}, got {z3_type!r}."
                )
            field_instances[name] = Field(name, python_type, cast(Z3Type, z3_type))

        # ── Check cache before evaluating lambdas ────────────────────────────
        fields_key = tuple(
            sorted((n, z3t, getattr(pt, "__name__", repr(pt))) for n, (z3t, pt) in fields.items())
        )
        # Use actual function objects (not id()) so they stay alive as long as the
        # cache entry exists — prevents id reuse after GC causing stale cache hits.
        inv_key = tuple(invariants)
        cache_key = (fields_key, inv_key)
        if cache_key in _DYNAMIC_POLICY_CACHE:
            return _DYNAMIC_POLICY_CACHE[cache_key]

        # ── Evaluate invariant lambdas once (compile-time, not per-request) ──
        realized: list[ConstraintExpr] = []
        for i, inv_fn in enumerate(invariants):
            try:
                result = inv_fn(field_instances)
            except Exception as exc:
                raise ConfigurationError(
                    f"Policy.from_config: invariants[{i}] raised during evaluation: {exc}"
                ) from exc
            if isinstance(result, list):
                realized.extend(result)
            else:
                realized.append(result)

        # ── Build the dynamic class ───────────────────────────────────────────
        schema_hash = abs(hash(fields_key)) % 10**8
        class_name = f"_DynamicPolicy_{schema_hash:08d}"
        _realized_copy = list(realized)

        @classmethod  # type: ignore[misc]
        def _inv_method(_cls: type) -> list[ConstraintExpr]:
            return list(_realized_copy)

        namespace: dict[str, Any] = dict(field_instances)
        namespace["invariants"] = _inv_method

        dynamic_cls: type[Policy] = type(class_name, (cls,), namespace)
        _DYNAMIC_POLICY_CACHE[cache_key] = dynamic_cls
        return dynamic_cls

    # ── Meta accessors ────────────────────────────────────────────────────────

    @classmethod
    def meta_version(cls) -> str | None:
        """Return ``Meta.version`` if declared, otherwise ``None``."""
        meta = vars(cls).get("Meta")
        if meta is None:
            return None
        return getattr(meta, "version", None)

    @classmethod
    def meta_intent_model(cls) -> type | None:
        """Return ``Meta.intent_model`` if declared, otherwise ``None``."""
        meta = vars(cls).get("Meta")
        if meta is None:
            return None
        return getattr(meta, "intent_model", None)

    @classmethod
    def meta_state_model(cls) -> type | None:
        """Return ``Meta.state_model`` if declared, otherwise ``None``."""
        meta = vars(cls).get("Meta")
        if meta is None:
            return None
        return getattr(meta, "state_model", None)
