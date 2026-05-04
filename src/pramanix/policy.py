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

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from pramanix.exceptions import (
    ConfigurationError,
    InvariantLabelError,
    PolicyCompilationError,
    PolicyError,
)
from pramanix.expressions import ConstraintExpr, Field, Z3Type

if TYPE_CHECKING:
    from pydantic import BaseModel

__all__ = ["Policy", "invariant_mixin", "model_dump_z3"]

# Type alias for a mixin function: receives the policy's field dict and returns
# one or more ConstraintExpr objects.
_MixinFn = Callable[[dict[str, Field]], "ConstraintExpr | list[ConstraintExpr]"]


def invariant_mixin(fn: _MixinFn) -> _MixinFn:
    """Mark a callable as a reusable policy invariant mixin.

    A mixin function accepts a ``dict[str, Field]`` (the receiving policy's
    field set) and returns a :class:`~pramanix.expressions.ConstraintExpr` or
    a ``list[ConstraintExpr]``.  Every returned constraint **must** carry a
    unique ``.named()`` label.

    Compose mixins into a :class:`Policy` subclass via the ``mixins`` keyword
    argument at class definition time::

        @invariant_mixin
        def AccountSafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [
                (E(fields["balance"]) >= 0).named("non_neg_balance"),
                (E(fields["is_frozen"]) == False).named("account_not_frozen"),  # noqa: E712
            ]

        class TradePolicy(Policy, mixins=[AccountSafetyMixin]):
            balance   = Field("balance",   Decimal, "Real")
            is_frozen = Field("is_frozen", bool,    "Bool")
            amount    = Field("amount",    Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("max_tx")]

    Missing fields are detected at :class:`~pramanix.guard.Guard` construction
    time via :meth:`Policy.validate`, not at ``verify()`` time.

    Args:
        fn: A callable ``(fields: dict[str, Field]) → ConstraintExpr |
            list[ConstraintExpr]``.

    Returns:
        The same callable, with ``._is_invariant_mixin = True`` set for
        introspection.
    """
    fn._is_invariant_mixin = True  # type: ignore[attr-defined]
    return fn


# ── B-2: Dynamic policy cache — keyed by (fields_schema, invariant_ids) ──────
_DYNAMIC_POLICY_CACHE: dict[tuple[Any, ...], type[Policy]] = {}


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

    # ── B-3: Subclass hook — mixin composition ────────────────────────────────

    def __init_subclass__(
        cls,
        mixins: list[_MixinFn] | None = None,
        **kwargs: Any,
    ) -> None:
        """Hook applied whenever a :class:`Policy` is subclassed.

        If *mixins* is provided, each callable is woven into the class's
        :meth:`invariants` return value.  Mixin functions are **evaluated
        lazily** — on the first :meth:`invariants` call, which happens at
        :class:`~pramanix.guard.Guard` construction time via
        :meth:`validate`.  This means missing-field errors surface when you
        instantiate ``Guard(MyPolicy)``, not when the class is defined.

        Args:
            mixins: List of :func:`invariant_mixin`-decorated callables.
                Each receives ``dict[str, Field]`` (this class's fields) and
                must return a :class:`~pramanix.expressions.ConstraintExpr`
                or ``list[ConstraintExpr]``.

        Raises:
            PolicyCompilationError: At ``Guard.__init__`` time if a mixin
                accesses a field not declared in this policy, or if a mixin
                is not callable.
        """
        super().__init_subclass__(**kwargs)
        if not mixins:
            return

        _raw_mixins: list[_MixinFn] = list(mixins)

        # Snapshot THIS class's own invariants method (may be None if the
        # class body didn't override invariants).  We do NOT call it here —
        # evaluation is deferred to the first invariants() call.
        _own_inv: Any = cls.__dict__.get("invariants")

        @classmethod  # type: ignore[misc]
        def _merged(_cls: type) -> list[ConstraintExpr]:
            # Step 1: get the policy's own (non-mixin) invariants.
            if _own_inv is not None:
                own: list[ConstraintExpr] = _own_inv.__func__(_cls)
            else:
                # This class didn't define invariants() — walk the MRO to
                # find the first ancestor that did.
                own = []
                for ancestor in _cls.__mro__[1:]:
                    ancestor_inv = vars(ancestor).get("invariants")
                    if ancestor_inv is not None:
                        try:
                            if hasattr(ancestor_inv, "__func__"):
                                own = ancestor_inv.__func__(_cls)
                            else:
                                own = ancestor_inv(_cls)
                        except NotImplementedError as exc:
                            import logging as _logging
                            _logging.getLogger(__name__).warning(
                                "policy '%s': ancestor '%s' raised NotImplementedError "
                                "from invariants() — this policy will have zero inherited "
                                "invariants, which may silently disable the guard. "
                                "Fix the parent class. Error: %s",
                                _cls.__name__,
                                ancestor.__name__,
                                exc,
                            )
                            raise PolicyCompilationError(
                                f"Policy '{_cls.__name__}': ancestor '{ancestor.__name__}' "
                                f"raised NotImplementedError from invariants(). "
                                "Define invariants() properly in every policy ancestor."
                            ) from exc
                        break

            # Step 2: evaluate each mixin with this class's field dict.
            fields = _cls.fields()  # type: ignore[attr-defined]
            extra: list[ConstraintExpr] = []
            for mixin_fn in _raw_mixins:
                if not callable(mixin_fn):
                    raise PolicyCompilationError(
                        f"Each mixin must be callable, got "
                        f"{type(mixin_fn).__name__!r} in policy '{_cls.__name__}'. "
                        "Decorate your mixin function with @invariant_mixin."
                    )
                try:
                    result = mixin_fn(fields)
                except KeyError as key_e:
                    mixin_name = getattr(mixin_fn, "__name__", repr(mixin_fn))
                    raise PolicyCompilationError(
                        f"Mixin '{mixin_name}' requires field {key_e!s} which is "
                        f"not declared in '{_cls.__name__}'. "
                        f"Declared fields: {sorted(fields.keys())}. "
                        f"Add the missing field to {_cls.__name__} or remove "
                        "the mixin."
                    ) from key_e
                if isinstance(result, list):
                    extra.extend(result)
                else:
                    extra.append(result)

            return own + extra

        cls.invariants = _merged  # type: ignore[method-assign, assignment]

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

    # ── StringEnumField coercion registry ────────────────────────────────────

    @classmethod
    def string_enum_coercions(cls) -> dict[str, Any]:
        """Return a mapping of field name to :class:`~pramanix.helpers.string_enum.StringEnumField`.

        Override this method in policies that use
        :class:`~pramanix.helpers.string_enum.StringEnumField` to enable
        transparent string-to-integer encoding in :meth:`~pramanix.guard.Guard.verify`
        without requiring callers to call ``.encode()`` manually.

        When a field name is registered here, :class:`~pramanix.guard.Guard`
        automatically encodes any ``str`` values for that field to their
        integer codes before the Z3 solver runs.  Values already supplied
        as integers (already encoded) are passed through unchanged.

        Returns:
            ``{}`` by default.  Override to return
            ``{"field_name": string_enum_field_instance, ...}``.

        Example::

            _status = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])

            class AccountPolicy(Policy):
                status = _status.field

                @classmethod
                def invariants(cls):
                    return [
                        _status.is_allowed_constraint(cls.status, ["CLEAR"]),
                        _status.valid_values_constraint(cls.status),
                    ]

                @classmethod
                def string_enum_coercions(cls):
                    return {"status": _status}

            # Guard.verify() now auto-encodes — no manual .encode() needed:
            guard.verify(intent={}, state={"status": "CLEAR"})
        """
        return {}

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

    # ── G-3: JSON Schema export ───────────────────────────────────────────────

    @classmethod
    def export_json_schema(cls) -> dict[str, Any]:
        """Export a JSON Schema draft-07 representation of this policy's fields.

        Returns:
            A ``dict`` that is a valid JSON Schema (draft-07) document
            describing all declared fields, their JSON types, and the title
            of the policy class.

        Example::

            schema = TransferPolicy.export_json_schema()
            # {
            #   "$schema": "http://json-schema.org/draft-07/schema#",
            #   "title": "TransferPolicy",
            #   "type": "object",
            #   "properties": {
            #       "amount": {"type": "number"},
            #       "is_frozen": {"type": "boolean"},
            #   },
            #   "required": ["amount", "is_frozen"],
            #   "additionalProperties": False,
            # }
        """
        from decimal import Decimal as _Decimal

        _type_map: dict[type, str] = {
            int: "integer",
            float: "number",
            str: "string",
            bool: "boolean",
            _Decimal: "number",
        }

        properties: dict[str, Any] = {}
        required: list[str] = []

        for field_name, field in cls.fields().items():
            json_type = _type_map.get(field.python_type, "string")
            properties[field_name] = {"type": json_type}
            required.append(field_name)

        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": cls.__name__,
            "type": "object",
            "properties": properties,
            "required": sorted(required),
            "additionalProperties": False,
        }

    # ── B-2: Dynamic policy factory ──────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        fields: dict[str, tuple[str, type]],
        invariants: list[Callable[[dict[str, Field]], ConstraintExpr | list[ConstraintExpr]]],
    ) -> type[Policy]:
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
        _valid_z3 = {"Bool", "Int", "Real", "String"}

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
            if z3_type not in _valid_z3:
                raise ConfigurationError(
                    f"Policy.from_config: field '{name}' z3_type must be one of "
                    f"{sorted(_valid_z3)}, got {z3_type!r}."
                )
            field_instances[name] = Field(name, python_type, cast("Z3Type", z3_type))

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
    def _get_meta(cls) -> type | None:
        """Walk the MRO to find the nearest declared ``Meta`` inner class.

        ``vars(cls).get("Meta")`` only searches the class's own ``__dict__``,
        causing subclasses that inherit ``Meta`` without redeclaring it to
        silently drop all meta attributes.  MRO traversal fixes this.
        """
        for klass in cls.__mro__:
            meta = vars(klass).get("Meta")
            if meta is not None:
                return meta
        return None

    @classmethod
    def meta_version(cls) -> str | None:
        """Return ``Meta.version`` if declared, otherwise ``None``.

        When ``Meta.semver`` is also declared, the semver string
        representation is returned (e.g. ``"1.2.0"``).  Plain
        ``Meta.version`` strings are returned as-is for backward
        compatibility.
        """
        semver = cls.meta_semver()
        if semver is not None:
            return "{}.{}.{}".format(*semver)
        meta = cls._get_meta()
        if meta is None:
            return None
        return getattr(meta, "version", None)

    @classmethod
    def meta_semver(cls) -> tuple[int, int, int] | None:
        """Return ``Meta.semver`` if declared, otherwise ``None``.

        ``Meta.semver`` must be a 3-tuple of non-negative ints:
        ``(major, minor, patch)``.  Validation happens at
        :class:`~pramanix.guard.Guard` construction time.

        Returns:
            The semver tuple or ``None`` if not declared.
        """
        meta = cls._get_meta()
        if meta is None:
            return None
        return getattr(meta, "semver", None)

    @classmethod
    def meta_intent_model(cls) -> type | None:
        """Return ``Meta.intent_model`` if declared, otherwise ``None``."""
        meta = cls._get_meta()
        if meta is None:
            return None
        return getattr(meta, "intent_model", None)

    @classmethod
    def meta_state_model(cls) -> type | None:
        """Return ``Meta.state_model`` if declared, otherwise ``None``."""
        meta = cls._get_meta()
        if meta is None:
            return None
        return getattr(meta, "state_model", None)


# ── B-1: Nested Pydantic model_dump_z3 ───────────────────────────────────────


def model_dump_z3(
    model: BaseModel,
    prefix: str = "",
    *,
    max_nesting_depth: int = 5,
    _seen: frozenset[type] | None = None,
) -> dict[str, Any]:
    """Recursively flatten a nested Pydantic model to dotted-path keys.

    Converts a Pydantic ``BaseModel`` instance (potentially with nested
    model fields) to a flat dict whose keys are dot-separated field paths.
    The resulting dict can be passed directly to :meth:`Guard.verify` as
    the ``state=`` or ``intent=`` argument.

    Example::

        class Address(BaseModel):
            street: str
            city: str

        class Customer(BaseModel):
            name: str
            address: Address
            balance: Decimal

        c = Customer(name="Alice", address=Address(street="1 Main", city="NYC"),
                     balance=Decimal("1000.00"))
        flat = model_dump_z3(c)
        # {
        #   "name":            "Alice",
        #   "address.street":  "1 Main",
        #   "address.city":    "NYC",
        #   "balance":         Decimal("1000.00"),
        # }

    Args:
        model:             A Pydantic ``BaseModel`` instance.
        prefix:            Dot-separated key prefix prepended to all keys.
                           Used internally for recursion; callers typically
                           leave this as the default ``""``.
        max_nesting_depth: Maximum recursion depth.  Nested models beyond
                           this limit are serialised as raw dicts via
                           ``model.model_dump()``.  Default: 5.
        _seen:             Circular-reference guard (internal).  A
                           ``frozenset`` of already-visited model types in
                           the current call stack.  Do **not** pass this
                           argument; it is managed automatically.

    Returns:
        Flat ``dict[str, Any]`` with dotted-path keys.

    Raises:
        TypeError: If *model* is not a Pydantic ``BaseModel`` instance.
    """
    try:
        from pydantic import BaseModel as _BaseModel
    except ImportError as exc:  # pragma: no cover
        raise ImportError("pydantic is required for model_dump_z3") from exc

    if not isinstance(model, _BaseModel):
        raise TypeError(
            f"model_dump_z3 expects a pydantic.BaseModel instance, got {type(model)!r}."
        )

    if _seen is None:
        _seen = frozenset()

    result: dict[str, Any] = {}

    for field_name, value in model.model_dump().items():
        full_key = f"{prefix}{field_name}" if not prefix else f"{prefix}.{field_name}"

        # Attempt to get the actual nested model instance (model_dump gave us a dict).
        raw_value = getattr(model, field_name, value)

        if (
            isinstance(raw_value, _BaseModel)
            and max_nesting_depth > 0
            and type(raw_value) not in _seen
        ):
            nested = model_dump_z3(
                raw_value,
                prefix=full_key,
                max_nesting_depth=max_nesting_depth - 1,
                _seen=_seen | {type(model)},
            )
            result.update(nested)
        else:
            result[full_key] = value

    return result
