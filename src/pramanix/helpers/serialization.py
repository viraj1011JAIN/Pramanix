# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Serialisation helpers for safe cross-boundary data transfer.

The critical invariant for async process-pool mode (M2) is:

    **Every value that crosses a ``ProcessPoolExecutor`` boundary must be
    picklable.**

Pydantic ``BaseModel`` instances are *not* reliably picklable in all
configurations (custom validators, computed fields, private attributes).
:func:`safe_dump` converts models to plain Python dicts before any boundary
crossing, and verifies that the result contains no nested Pydantic instances.

Public API
----------
* :func:`safe_dump` — serialize a ``BaseModel`` to a plain, pickle-safe dict

Design notes
------------
* ``model_dump()`` is used (not ``model_dump(mode="json")``) so that
  ``Decimal``, ``datetime``, and other native Python types are preserved
  exactly rather than being stringified.  Both are picklable.
* Nested ``BaseModel`` detection uses recursive traversal.  Dicts, lists,
  tuples, and sets are all inspected.
* A pre-flight ``pickle.dumps`` is performed in debug mode (when
  ``__debug__`` is ``True``) to surface subtle pickling failures early.
"""
from __future__ import annotations

import pickle
from typing import Any

from pydantic import BaseModel

__all__ = ["flatten_model", "safe_dump"]

# ── Internal helpers ──────────────────────────────────────────────────────────


def _assert_no_nested_models(value: Any, path: str = "root") -> None:
    """Recursively assert that *value* contains no nested ``BaseModel`` instances.

    Raises:
        TypeError: If a nested ``BaseModel`` instance is found anywhere in
            the data structure, with a dotted path to aid debugging.
    """
    if isinstance(value, BaseModel):
        raise TypeError(
            f"safe_dump: nested Pydantic model found at '{path}'. "
            "Nested BaseModel instances are not supported in v0.1. "
            "Flatten the model or call model_dump() on the nested model first."
        )
    if isinstance(value, dict):
        for k, v in value.items():
            _assert_no_nested_models(v, path=f"{path}.{k}")
    elif isinstance(value, list | tuple | set | frozenset):
        for i, item in enumerate(value):
            _assert_no_nested_models(item, path=f"{path}[{i}]")


# ── B-1: Nested model flattening ─────────────────────────────────────────────


def flatten_model(
    model: BaseModel,
    *,
    max_depth: int = 5,
    _prefix: str = "",
    _depth: int = 0,
    _seen: frozenset[type] | None = None,
) -> dict[str, Any]:
    """Recursively flatten *model* to a plain dict with dotted-path keys.

    Nested :class:`pydantic.BaseModel` fields are traversed and their sub-fields
    are emitted as ``"parent.child.leaf"`` keys.  All other Python types (Decimal,
    datetime, int, str, …) are preserved exactly — no JSON coercion.

    Args:
        model:     Any :class:`pydantic.BaseModel` instance.
        max_depth: Maximum nesting depth before raising (default 5).

    Returns:
        A flat ``dict[str, Any]`` with dotted-path keys, pickle-safe.

    Raises:
        PolicyCompilationError: If nesting depth exceeds *max_depth* or a
            circular model-type reference is detected.
    """
    from pramanix.exceptions import PolicyCompilationError

    seen: frozenset[type] = _seen if _seen is not None else frozenset()

    if _depth > max_depth:
        raise PolicyCompilationError(
            f"Nested model depth exceeds max_nesting_depth={max_depth} "
            f"at prefix '{_prefix}'."
        )
    model_type = type(model)
    if model_type in seen:
        raise PolicyCompilationError(
            f"Circular model reference detected: {model_type.__name__!r} "
            f"appears recursively at prefix '{_prefix}'."
        )
    seen = seen | {model_type}

    result: dict[str, Any] = {}
    for field_name in type(model).model_fields:
        value = getattr(model, field_name)
        key = f"{_prefix}.{field_name}" if _prefix else field_name
        if isinstance(value, BaseModel):
            nested = flatten_model(
                value,
                max_depth=max_depth,
                _prefix=key,
                _depth=_depth + 1,
                _seen=seen,
            )
            result.update(nested)
        else:
            result[key] = value
    return result


# ── Public API ────────────────────────────────────────────────────────────────


def safe_dump(model: BaseModel) -> dict[str, Any]:
    """Serialise *model* to a plain, pickle-safe Python dict.

    Calls ``model.model_dump()`` and then verifies:

    1. No nested :class:`pydantic.BaseModel` instances remain in the result.
    2. The result is picklable (checked in debug builds only to avoid the
       cost in production).

    The returned dict preserves exact Python types:  ``Decimal``, ``datetime``,
    ``date``, ``UUID``, etc. are kept as-is (not converted to strings).

    Args:
        model: Any :class:`pydantic.BaseModel` instance.

    Returns:
        A ``dict[str, Any]`` that is safe to pass across a
        ``ProcessPoolExecutor`` boundary.

    Raises:
        TypeError: If any nested ``BaseModel`` instance is found in the dump,
            or if the result is not picklable (debug mode only).
    """
    result = model.model_dump()

    # ── Guard: no nested Pydantic models ──────────────────────────────────────
    _assert_no_nested_models(result)

    # ── Guard: picklability — always checked, not only in debug builds ─────────
    # M-27: __debug__ is False in production (-O flag), so we always run this.
    try:
        pickle.dumps(result)
    except Exception as exc:  # broad catch: pickle raises many error types
        raise TypeError(
            f"safe_dump: model_dump() result is not picklable. "
            f"Exception type: {type(exc).__name__}: {exc}"
        ) from exc

    return result
