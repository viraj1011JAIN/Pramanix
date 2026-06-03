# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""YAML / TOML policy DSL loader — compile a declarative file into a live Policy subclass.

This module lets teams write Pramanix policies in structured YAML or TOML
rather than Python, useful for:

* Non-engineer stakeholders (compliance, legal) who write policy intent in a
  human-readable format reviewed through a normal code-review process.
* Configuration-management systems (Helm values, Ansible vars) that inject
  policy parameters at deploy time.
* Multi-language systems where the policy definition must be consumed by both
  Python (Pramanix) and another language (e.g. Go, Java).

**Security invariant**: The expression parser is a safe AST visitor — it
never calls ``eval()`` or ``exec()``.  Only a strict whitelist of Python AST
node types is accepted.  Any unrecognised node raises
:exc:`~pramanix.exceptions.PolicySyntaxError`.

YAML format
-----------
.. code-block:: yaml

    meta:
      name: BankingPolicy          # Python class name (required)
      version: "1.0"               # Policy.Meta.version  (optional)
      description: "Transfer limits"

    fields:
      amount:
        z3_type: Real              # Real | Int | Bool | String (required)
        type: Decimal              # Python type hint (optional)
      balance:
        z3_type: Real
      daily_limit:
        z3_type: Real
      is_frozen:
        z3_type: Bool
        type: bool

    invariants:
      - name: non_negative_balance
        expr: "balance - amount >= 0"
        explain: "Overdraft: balance={balance}, amount={amount}"
      - name: within_daily_limit
        expr: "amount <= daily_limit"
      - name: account_not_frozen
        expr: "not is_frozen"

TOML format
-----------
.. code-block:: toml

    [meta]
    name = "BankingPolicy"
    version = "1.0"

    [fields.amount]
    z3_type = "Real"

    [fields.balance]
    z3_type = "Real"

    [[invariants]]
    name = "non_negative_balance"
    expr = "balance - amount >= 0"

Usage::

    from pramanix.natural_policy.yaml_loader import load_policy_file, load_policy_yaml

    # From a YAML or TOML file:
    BankingPolicy = load_policy_file("banking_policy.yaml")
    guard = Guard(BankingPolicy)

    # From an in-memory YAML string:
    policy_cls = load_policy_yaml(yaml_content)
"""

from __future__ import annotations

import ast as _ast
import pathlib
import re
from datetime import datetime as _datetime
from decimal import Decimal as _Decimal
from typing import TYPE_CHECKING, Any, NoReturn, cast

from pramanix.exceptions import PolicySyntaxError
from pramanix.expressions import (
    ConstraintExpr,
    ExpressionNode,
    Field,
    Z3Type,
    _FieldRef,
    _Literal,
)

if TYPE_CHECKING:
    from pramanix.policy import Policy

__all__ = [
    "load_policy_file",
    "load_policy_string",
    "load_policy_yaml",
    "load_policy_toml",
]

# ── Type-name → Python type mapping ──────────────────────────────────────────

_PYTHON_TYPES: dict[str, type] = {
    "Decimal": _Decimal,
    "float": float,
    "int": int,
    "bool": bool,
    "str": str,
    "string": str,
    "datetime": _datetime,
}

# ── Safe expression parser ────────────────────────────────────────────────────


def _raise_unexpected_operand(op_name: str, invariant_name: str) -> NoReturn:
    """Raise PolicySyntaxError for an unexpected operand type.

    Extracted from the defensive guards in _visit() so the branches are
    directly testable without needing to bypass the type invariants of _visit.
    """
    raise PolicySyntaxError(
        f"Invariant {invariant_name!r}: {op_name!r} applied to unexpected node type"
    )


def _raise_unhandled_ast_node(node: Any, invariant_name: str) -> NoReturn:
    """Raise PolicySyntaxError for an AST node type that passed the allow-list
    but is not handled by any isinstance branch in _visit().

    Extracted so the branch is directly testable: pass _ast.Not() which IS
    in _ALLOWED_NODES but is never the subject of an isinstance(node, ...) check.
    """
    raise PolicySyntaxError(
        f"Invariant {invariant_name!r}: unhandled AST node {type(node).__name__!r}"
    )


# Only these AST node types are allowed in invariant expressions.
# Anything not in this set raises PolicySyntaxError immediately.
_ALLOWED_NODES = frozenset(
    {
        _ast.Expression,
        _ast.Constant,
        _ast.Name,
        _ast.UnaryOp,
        _ast.Not,
        _ast.USub,
        _ast.UAdd,
        _ast.BinOp,
        _ast.Add,
        _ast.Sub,
        _ast.Mult,
        _ast.Div,
        _ast.Compare,
        _ast.Eq,
        _ast.NotEq,
        _ast.Lt,
        _ast.LtE,
        _ast.Gt,
        _ast.GtE,
        _ast.BoolOp,
        _ast.And,
        _ast.Or,
    }
)


def _parse_expr(
    source: str,
    fields: dict[str, ExpressionNode],
    invariant_name: str,
) -> ConstraintExpr:
    """Parse *source* into a :class:`~pramanix.expressions.ConstraintExpr`.

    Uses Python's ``ast.parse()`` with mode ``"eval"`` so only a single
    expression is accepted.  Only AST node types in ``_ALLOWED_NODES`` are
    translated; anything else (calls, subscripts, lambdas, …) raises
    :exc:`~pramanix.exceptions.PolicySyntaxError`.

    Args:
        source:         Expression string (e.g. ``"balance - amount >= 0"``).
        fields:         Mapping of field name → ``ExpressionNode`` wrapping
                        the declared :class:`~pramanix.expressions.Field`.
        invariant_name: Name used in error messages.

    Returns:
        A :class:`~pramanix.expressions.ConstraintExpr`.

    Raises:
        PolicySyntaxError: If the expression is syntactically invalid or
                           uses disallowed constructs.
    """
    try:
        tree = _ast.parse(source.strip(), mode="eval")
    except SyntaxError as exc:
        raise PolicySyntaxError(
            f"Invariant {invariant_name!r}: syntax error in expression " f"{source!r}: {exc}"
        ) from exc

    result = _visit(tree.body, fields, source, invariant_name)

    if isinstance(result, ConstraintExpr):
        return result

    # Top-level ExpressionNode that is not already a ConstraintExpr — this
    # means the expression reduces to an arithmetic value, not a boolean
    # constraint (e.g. the user wrote "balance - amount" without a comparison).
    raise PolicySyntaxError(
        f"Invariant {invariant_name!r}: expression {source!r} does not "
        "produce a boolean constraint.  Add a comparison operator "
        "(>=, <=, >, <, ==, !=) or wrap the boolean field directly."
    )


def _visit(
    node: _ast.expr,
    fields: dict[str, ExpressionNode],
    source: str,
    invariant_name: str,
) -> ExpressionNode | ConstraintExpr:
    """Recursively translate an AST node to an ExpressionNode or ConstraintExpr."""
    if type(node) not in _ALLOWED_NODES:
        raise PolicySyntaxError(
            f"Invariant {invariant_name!r}: disallowed expression node "
            f"{type(node).__name__!r} in {source!r}.  "
            "Only arithmetic (+, -, *, /), comparisons (>=, <=, >, <, ==, !=), "
            "and boolean operators (and, or, not) are permitted."
        )

    # ── Literal constant ──────────────────────────────────────────────────────
    if isinstance(node, _ast.Constant):
        v = node.value
        if not isinstance(v, int | float | bool | str):
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: literal {v!r} has unsupported "
                f"type {type(v).__name__!r}.  Supported: int, float, bool, str."
            )
        return ExpressionNode(_Literal(v))

    # ── Field reference ───────────────────────────────────────────────────────
    if isinstance(node, _ast.Name):
        name = node.id
        # Special Boolean literals
        if name in ("True", "true"):
            return ExpressionNode(_Literal(True))
        if name in ("False", "false"):
            return ExpressionNode(_Literal(False))
        if name not in fields:
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: field {name!r} is not "
                f"declared.  Declared fields: {sorted(fields)}"
            )
        return fields[name]

    # ── Unary operators ───────────────────────────────────────────────────────
    if isinstance(node, _ast.UnaryOp):
        operand = _visit(node.operand, fields, source, invariant_name)
        if isinstance(node.op, _ast.Not):
            # `not x` on a Bool field → ConstraintExpr via is_false()
            # `not expr` on a ConstraintExpr → ~constraint
            if isinstance(operand, ConstraintExpr):
                return ~operand
            if isinstance(operand, ExpressionNode):
                # Bool field wrapped in ExpressionNode — use .is_false()
                return operand.is_false()
            _raise_unexpected_operand("not", invariant_name)
        if isinstance(node.op, _ast.USub):
            if isinstance(operand, ExpressionNode):
                return -operand
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: unary minus applied to "
                "a boolean constraint, not a numeric expression"
            )
        if isinstance(node.op, _ast.UAdd):
            return operand  # +x === x; no-op
        raise PolicySyntaxError(
            f"Invariant {invariant_name!r}: unsupported unary operator "
            f"{type(node.op).__name__!r} in {source!r}"
        )

    # ── Binary arithmetic ─────────────────────────────────────────────────────
    if isinstance(node, _ast.BinOp):
        left = _visit(node.left, fields, source, invariant_name)
        right = _visit(node.right, fields, source, invariant_name)
        if isinstance(left, ConstraintExpr) or isinstance(right, ConstraintExpr):
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: arithmetic operators cannot be "
                "applied to boolean constraints in {source!r}"
            )
        left = left  # guaranteed ExpressionNode from here
        if isinstance(node.op, _ast.Add):
            return left + right
        if isinstance(node.op, _ast.Sub):
            return left - right
        if isinstance(node.op, _ast.Mult):
            return left * right
        if isinstance(node.op, _ast.Div):
            return left / right
        raise PolicySyntaxError(
            f"Invariant {invariant_name!r}: unsupported binary operator "
            f"{type(node.op).__name__!r}.  Allowed: +, -, *, /"
        )

    # ── Comparison ────────────────────────────────────────────────────────────
    if isinstance(node, _ast.Compare):
        if len(node.comparators) != 1:
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: chained comparisons "
                f"(e.g. a < b < c) are not supported.  "
                "Rewrite as two separate invariants."
            )
        left = _visit(node.left, fields, source, invariant_name)
        right = _visit(node.comparators[0], fields, source, invariant_name)
        op = node.ops[0]
        if isinstance(left, ConstraintExpr):
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: left-hand side of comparison "
                "is a boolean constraint; wrap in parentheses or restructure."
            )
        if isinstance(right, ConstraintExpr):
            raise PolicySyntaxError(
                f"Invariant {invariant_name!r}: right-hand side of comparison "
                "is a boolean constraint; wrap in parentheses or restructure."
            )
        if isinstance(op, _ast.GtE):
            return left >= right
        if isinstance(op, _ast.LtE):
            return left <= right
        if isinstance(op, _ast.Gt):
            return left > right
        if isinstance(op, _ast.Lt):
            return left < right
        if isinstance(op, _ast.Eq):
            return cast("ConstraintExpr", left == right)
        if isinstance(op, _ast.NotEq):
            return cast("ConstraintExpr", left != right)
        raise PolicySyntaxError(
            f"Invariant {invariant_name!r}: unsupported comparison op " f"{type(op).__name__!r}"
        )

    # ── Boolean operators ─────────────────────────────────────────────────────
    if isinstance(node, _ast.BoolOp):
        operands = [_visit(v, fields, source, invariant_name) for v in node.values]
        # Promote ExpressionNode Bool fields to ConstraintExpr via is_true()
        promoted: list[ConstraintExpr] = []
        for op_node in operands:
            if isinstance(op_node, ConstraintExpr):
                promoted.append(op_node)
            elif isinstance(op_node, ExpressionNode):
                promoted.append(op_node.is_true())
            else:
                _raise_unexpected_operand(
                    f"BoolOp with unexpected operand type {type(op_node).__name__!r}",
                    invariant_name,
                )
        result = promoted[0]
        for operand in promoted[1:]:
            result = (result & operand) if isinstance(node.op, _ast.And) else (result | operand)
        return result

    _raise_unhandled_ast_node(node, invariant_name)


# ── Policy builder ────────────────────────────────────────────────────────────


def _build_policy_class(spec: dict[str, Any]) -> type[Policy]:
    """Compile a parsed policy spec dict into a live :class:`~pramanix.policy.Policy` subclass.

    Args:
        spec: Normalised dict with keys ``meta``, ``fields``, ``invariants``.

    Returns:
        A dynamically-created :class:`~pramanix.policy.Policy` subclass ready
        for use with :class:`~pramanix.guard.Guard`.

    Raises:
        PolicySyntaxError: If the spec is structurally invalid or an invariant
                           expression cannot be parsed.
    """
    from pramanix.policy import Policy

    meta = spec.get("meta") or {}
    policy_name = meta.get("name") or "DynamicPolicy"
    policy_version = str(meta.get("version", "")) or None

    # Validate the class name (must be a valid Python identifier)
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", policy_name):
        raise PolicySyntaxError(f"meta.name {policy_name!r} is not a valid Python identifier.")

    # ── Build Field objects ───────────────────────────────────────────────────
    raw_fields: dict[str, Any] = spec.get("fields") or {}
    if not raw_fields:
        raise PolicySyntaxError("Policy must declare at least one field under 'fields:'")

    _valid_z3_types = {"Real", "Int", "Bool", "String"}
    field_objects: dict[str, Field] = {}

    for field_name, field_spec in raw_fields.items():
        if not isinstance(field_spec, dict):
            raise PolicySyntaxError(
                f"Field {field_name!r} spec must be a mapping; got "
                f"{type(field_spec).__name__!r}"
            )
        z3_type = field_spec.get("z3_type") or field_spec.get("z3type")
        if not z3_type:
            raise PolicySyntaxError(
                f"Field {field_name!r} is missing required 'z3_type' key.  "
                f"Valid values: {sorted(_valid_z3_types)}"
            )
        z3_type = str(z3_type).strip()
        if z3_type not in _valid_z3_types:
            raise PolicySyntaxError(
                f"Field {field_name!r} has invalid z3_type={z3_type!r}.  "
                f"Valid values: {sorted(_valid_z3_types)}"
            )
        python_type_name = str(field_spec.get("type", "")).strip()
        python_type = _PYTHON_TYPES.get(python_type_name, object)
        # Fall back to sensible defaults when python_type is not declared
        if python_type is object:
            python_type = {
                "Real": _Decimal,
                "Int": int,
                "Bool": bool,
                "String": str,
            }[z3_type]
        field_objects[field_name] = Field(field_name, python_type, cast(Z3Type, z3_type))

    # ── Wrap each Field in an ExpressionNode for expression parsing ───────────
    expr_nodes: dict[str, ExpressionNode] = {
        name: ExpressionNode(_FieldRef(f)) for name, f in field_objects.items()
    }

    # ── Build ConstraintExpr list ─────────────────────────────────────────────
    raw_invariants: list[Any] = spec.get("invariants") or []
    if not raw_invariants:
        raise PolicySyntaxError("Policy must declare at least one invariant under 'invariants:'")

    constraints: list[ConstraintExpr] = []
    seen_names: set[str] = set()

    for idx, inv_spec in enumerate(raw_invariants):
        if not isinstance(inv_spec, dict):
            raise PolicySyntaxError(
                f"Invariant #{idx + 1} must be a mapping; got {type(inv_spec).__name__!r}"
            )
        inv_name = str(inv_spec.get("name") or f"invariant_{idx + 1}").strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", inv_name):
            raise PolicySyntaxError(f"Invariant name {inv_name!r} is not a valid identifier.")
        if inv_name in seen_names:
            raise PolicySyntaxError(
                f"Duplicate invariant name {inv_name!r} — all names must be unique."
            )
        seen_names.add(inv_name)

        expr_src = str(inv_spec.get("expr") or "").strip()
        if not expr_src:
            raise PolicySyntaxError(f"Invariant {inv_name!r} is missing 'expr' key.")

        constraint = _parse_expr(expr_src, expr_nodes, inv_name).named(inv_name)

        explain = str(inv_spec.get("explain") or inv_spec.get("explanation") or "").strip()
        if explain:
            constraint = constraint.explain(explain)

        constraints.append(constraint)

    # ── Freeze the constraint list in a closure for invariants() ─────────────
    _frozen_constraints = tuple(constraints)

    def _invariants(cls: Any) -> list[ConstraintExpr]:
        return list(_frozen_constraints)

    # ── Build Meta inner class ────────────────────────────────────────────────
    meta_attrs: dict[str, Any] = {}
    if policy_version:
        meta_attrs["version"] = policy_version

    DynamicMeta = type("Meta", (), meta_attrs)

    # ── Assemble the Policy subclass ──────────────────────────────────────────
    class_attrs: dict[str, Any] = {"Meta": DynamicMeta}
    class_attrs.update(field_objects)
    class_attrs["invariants"] = classmethod(_invariants)

    policy_cls: type[Policy] = type(policy_name, (Policy,), class_attrs)
    return policy_cls


# ── Public loaders ────────────────────────────────────────────────────────────


def load_policy_yaml(content: str) -> type[Policy]:
    """Compile a YAML string into a Policy subclass.

    Args:
        content: YAML string containing the policy definition.

    Returns:
        A dynamically-created :class:`~pramanix.policy.Policy` subclass.

    Raises:
        ImportError:      If ``PyYAML`` (``pyyaml``) is not installed.
        PolicySyntaxError: If the YAML is structurally invalid or an
                           expression cannot be parsed.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "pyyaml is required for YAML policy loading. " "Install it with: pip install pyyaml"
        ) from exc

    try:
        spec = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise PolicySyntaxError(f"YAML parse error: {exc}") from exc

    if not isinstance(spec, dict):
        raise PolicySyntaxError(
            "YAML policy must be a top-level mapping (dict); " f"got {type(spec).__name__!r}"
        )
    return _build_policy_class(spec)


def load_policy_toml(content: str) -> type[Policy]:
    """Compile a TOML string into a Policy subclass.

    Uses the stdlib ``tomllib`` (Python 3.11+) or falls back to ``tomli``.

    Args:
        content: TOML string containing the policy definition.

    Returns:
        A dynamically-created :class:`~pramanix.policy.Policy` subclass.

    Raises:
        ImportError:       If neither stdlib ``tomllib`` nor ``tomli`` is available.
        PolicySyntaxError: If the TOML is structurally invalid or an expression
                           cannot be parsed.
    """
    try:
        import tomllib as _tomllib  # stdlib 3.11+
    except ImportError:
        try:
            import importlib as _importlib

            _tomllib = _importlib.import_module("tomli")
        except ImportError as exc:
            raise ImportError(
                "TOML policy loading requires Python 3.11+ (stdlib tomllib) "
                "or the 'tomli' package: pip install tomli"
            ) from exc

    try:
        spec = _tomllib.loads(content)
    except Exception as exc:
        raise PolicySyntaxError(f"TOML parse error: {exc}") from exc

    return _build_policy_class(spec)


def load_policy_string(content: str, *, fmt: str = "yaml") -> type[Policy]:
    """Compile a YAML or TOML string into a Policy subclass.

    Args:
        content: Policy definition string.
        fmt:     Format hint — ``"yaml"`` (default) or ``"toml"``.

    Returns:
        A dynamically-created :class:`~pramanix.policy.Policy` subclass.

    Raises:
        ValueError:        If *fmt* is not ``"yaml"`` or ``"toml"``.
        PolicySyntaxError: On parse or compilation errors.
    """
    fmt = fmt.lower().strip()
    if fmt == "yaml":
        return load_policy_yaml(content)
    if fmt == "toml":
        return load_policy_toml(content)
    raise ValueError(f"Unknown format {fmt!r}.  Supported values: 'yaml', 'toml'.")


def load_policy_file(path: str | pathlib.Path) -> type[Policy]:
    """Compile a ``.yaml`` / ``.yml`` / ``.toml`` policy file into a Policy subclass.

    The file format is inferred from the file extension.

    Args:
        path: Path to the policy definition file.

    Returns:
        A dynamically-created :class:`~pramanix.policy.Policy` subclass.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError:        If the file extension is not ``.yaml``, ``.yml``,
                           or ``.toml``.
        PolicySyntaxError: On parse or compilation errors.
    """
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")

    suffix = p.suffix.lower()
    content = p.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        return load_policy_yaml(content)
    if suffix == ".toml":
        return load_policy_toml(content)
    raise ValueError(
        f"Cannot infer policy format from extension {p.suffix!r}.  "
        "Supported extensions: .yaml, .yml, .toml"
    )
