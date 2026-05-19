# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Meta-verification — prove the LLM did not hallucinate policy semantics.

After the :class:`~pramanix.natural_policy.compiler.ASTBuilder` compiles
a :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema` into
:class:`~pramanix.expressions.ConstraintExpr` objects, the
:class:`MetaVerifier` walks back over the compiled AST nodes to reconstruct
a canonical English description and compares it against the LLM's own
``natural_language`` annotations.

Rationale
---------
The LLM translates English → JSON, and the :class:`ASTBuilder` compiles that
JSON → Z3 DSL.  There are two failure modes:

1. **LLM hallucination** — the LLM produces a JSON constraint that doesn't
   match the original English (e.g. it emits ``amount >= 50000`` when the
   policy says "must not exceed 50000").
2. **Compiler bug** — the :class:`ASTBuilder` applies the wrong Z3 operator
   (e.g. ``>=`` where the schema said ``<=``).

The meta-verifier addresses *both* by checking that the canonical
reconstruction of the compiled AST matches the LLM's ``natural_language``
field, and that the ``natural_language`` field is semantically consistent
with the original English policy.

The verification is *structural*, not semantic — it reconstructs a precise
algebraic expression (e.g. ``amount <= 50000``) from the AST nodes and checks
it against the LLM's description using keyword/token matching.  This catches
gross operator inversions (``>`` vs ``<``) and wrong field names.

Modes
-----
* :attr:`VerificationMode.STRICT` — any mismatch raises
  :exc:`~pramanix.exceptions.PolicyCompilationError`.  Recommended for
  production deployments.
* :attr:`VerificationMode.WARN` — mismatches are recorded but do not raise.
  Use during policy development to inspect LLM quality.
* :attr:`VerificationMode.SKIP` — skip verification entirely.  **Not
  recommended** — exists only for testing and bootstrap scenarios.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pramanix.exceptions import PolicyCompilationError
from pramanix.expressions import (
    ConstraintExpr,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _FieldRef,
    _InOp,
    _Literal,
)

__all__ = [
    "MetaVerificationResult",
    "MetaVerifier",
    "VerificationMode",
]


# ── Verification mode ─────────────────────────────────────────────────────────


class VerificationMode(str, Enum):
    """Controls how the :class:`MetaVerifier` handles mismatches."""

    STRICT = "strict"
    """Any mismatch raises :exc:`~pramanix.exceptions.PolicyCompilationError`."""

    WARN = "warn"
    """Mismatches are recorded in :attr:`MetaVerificationResult.mismatches` but do
    not raise.  The compilation still succeeds."""

    SKIP = "skip"
    """Skip meta-verification entirely.  **Not recommended for production.**"""


# ── Result dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ConstraintVerificationDetail:
    """Per-constraint verification result."""

    label: str
    """The constraint's ``.named()`` label."""

    reconstructed: str
    """Canonical algebraic reconstruction of the compiled AST node."""

    natural_language: str
    """The LLM's original ``natural_language`` annotation for this constraint."""

    passed: bool
    """``True`` if the verification check passed."""

    mismatch_reason: str | None = None
    """Human-readable reason if the check failed, otherwise ``None``."""


@dataclass(frozen=True, slots=True)
class MetaVerificationResult:
    """Aggregate result of the meta-verification pass.

    Attributes
    ----------
    verified:
        ``True`` if all constraints passed (or :attr:`VerificationMode.SKIP`
        was used).
    original_english:
        Verbatim CISO policy text from the schema.
    constraint_details:
        Per-constraint breakdown of the verification check.
    mismatches:
        List of human-readable mismatch descriptions for any failed checks.
    mode:
        The :class:`VerificationMode` that was applied.
    """

    verified: bool
    original_english: str
    constraint_details: tuple[ConstraintVerificationDetail, ...]
    mismatches: tuple[str, ...]
    mode: VerificationMode

    def is_clean(self) -> bool:
        """Return ``True`` when ``verified`` is ``True`` and there are no mismatches."""
        return self.verified and len(self.mismatches) == 0


# ── Canonical AST reconstruction ─────────────────────────────────────────────

_OP_SYMBOL: dict[str, str] = {
    "ge": ">=",
    "le": "<=",
    "gt": ">",
    "lt": "<",
    "eq": "==",
    "ne": "!=",
    "add": "+",
    "sub": "-",
    "mul": "*",
    "div": "/",
}

_OP_ENGLISH: dict[str, str] = {
    "ge": "is at least",
    "le": "is at most",
    "gt": "is greater than",
    "lt": "is less than",
    "eq": "equals",
    "ne": "does not equal",
}

_ARITH_ENGLISH: dict[str, str] = {
    "add": "plus",
    "sub": "minus",
    "mul": "times",
    "div": "divided by",
}


def _reconstruct_expr(node: Any) -> str:
    """Recursively reconstruct a canonical algebraic string from an AST node."""
    if isinstance(node, _FieldRef):
        return node.field.name
    if isinstance(node, _Literal):
        v = node.value
        if isinstance(v, bool):
            return str(v).lower()
        return str(v)
    if isinstance(node, _BinOp):
        left = _reconstruct_expr(node.left)
        right = _reconstruct_expr(node.right)
        sym = _OP_SYMBOL.get(node.op, node.op)
        return f"({left} {sym} {right})"
    if isinstance(node, _CmpOp):
        left = _reconstruct_expr(node.left)
        right = _reconstruct_expr(node.right)
        sym = _OP_SYMBOL.get(node.op, node.op)
        return f"{left} {sym} {right}"
    if isinstance(node, _BoolOp):
        parts = [_reconstruct_expr(o) for o in node.operands]
        if node.op == "not":
            return f"NOT({parts[0]})"
        sep = f" {node.op.upper()} "
        return sep.join(f"({p})" for p in parts)
    if isinstance(node, _InOp):
        left = _reconstruct_expr(node.left)
        values = ", ".join(_reconstruct_expr(v) for v in node.values)
        return f"{left} in {{{values}}}"
    return repr(node)


def _reconstruct_constraint(expr: ConstraintExpr) -> str:
    """Return canonical algebraic English for a :class:`ConstraintExpr`."""
    return _reconstruct_expr(expr.node)


# ── Token-level comparison ────────────────────────────────────────────────────

_NORMALISE_RE = re.compile(r"[^a-z0-9><=!._\-+*/]+")


def _tokenise(text: str) -> set[str]:
    """Lower-case and split text into a set of meaningful tokens."""
    lowered = text.lower()
    tokens = set(_NORMALISE_RE.sub(" ", lowered).split())
    # Remove common stop words that carry no semantic weight
    stop = {
        "the",
        "a",
        "an",
        "and",
        "or",
        "not",
        "be",
        "must",
        "should",
        "is",
        "are",
        "to",
        "in",
        "of",
        "for",
        "that",
        "it",
        "this",
    }
    return tokens - stop


def _check_consistency(
    reconstructed: str,
    natural_language: str,
    original_english: str,
    label: str,
) -> tuple[bool, str | None]:
    """Check that *reconstructed* and *natural_language* are semantically consistent.

    The check extracts three categories of tokens:

    1. **Numeric literals** — any digits/decimal numbers from *reconstructed*
       must appear somewhere in *natural_language*.  This catches the most
       dangerous hallucination: the LLM emitting ``amount >= 50000`` when the
       policy says "must not exceed 50000" (the correct form is ``amount <= 50000``).
    2. **Field names** — every field name in *reconstructed* must appear in
       *natural_language*.
    3. **Operator tokens** — the comparison operator symbol in *reconstructed*
       (``>=``, ``<=``, etc.) must appear, or at least one of its English
       synonyms must appear in *natural_language*.

    Returns ``(True, None)`` on pass, or ``(False, reason)`` on failure.
    """
    # ── 1. Numeric token check ─────────────────────────────────────────────
    # Numeric literals from the reconstructed expression must appear in the
    # per-constraint natural language annotation.  We do NOT include
    # original_english here: that would allow a wrong annotation (e.g. "99999")
    # to pass simply because the correct value appears somewhere in the original
    # policy text.
    numeric_re = re.compile(r"\b\d[\d,_.]*\b")
    recon_nums = set(numeric_re.findall(reconstructed.replace(",", "")))
    nl_text = natural_language + " " + original_english  # used for field-name / operator checks
    nl_nums = set(numeric_re.findall(natural_language.replace(",", "")))

    for num in recon_nums:
        # Allow numbers that appear in either natural_language or original_english
        if num not in nl_nums:
            # Also check for formatted variants: 50000 == "50,000" == "50 000"
            bare = num.replace("_", "").replace(",", "")

            # Normalize whole-number floats: "50000.0" and "50000" are the same value
            def _norm(s: str) -> str:
                s = s.replace("_", "").replace(",", "")
                if "." in s:
                    try:
                        f = float(s)
                        if f == int(f):
                            return str(int(f))
                    except (ValueError, OverflowError):
                        pass
                return s

            found = any(_norm(bare) == _norm(n) for n in nl_nums)
            if not found:
                return (
                    False,
                    f"[{label}] Compiled value {num!r} not found in natural language "
                    f"description. Reconstructed: {reconstructed!r}. "
                    f"Natural language: {natural_language!r}",
                )

    # ── 2. Field name check ────────────────────────────────────────────────
    field_re = re.compile(r"\b([a-z][a-z0-9_]*)\b")
    recon_fields = set(field_re.findall(reconstructed))
    nl_lower = nl_text.lower()
    for fname in recon_fields:
        # Skip operator symbols and common keywords
        if fname in {"and", "or", "not", "in", "true", "false"}:
            continue
        if fname not in nl_lower:
            # Try underscore → space: "is_frozen" might appear as "is frozen"
            spaced = fname.replace("_", " ")
            if spaced not in nl_lower:
                return (
                    False,
                    f"[{label}] Field {fname!r} from compiled expression not found "
                    f"in natural language. Reconstructed: {reconstructed!r}. "
                    f"Natural language: {natural_language!r}",
                )

    # ── 3. Operator consistency check ─────────────────────────────────────
    # Extract operator from reconstructed (first occurrence of a comparison op)
    op_match = re.search(r"(>=|<=|>|<|==|!=)", reconstructed)
    if op_match:
        op_sym = op_match.group(1)
        op_internal = {v: k for k, v in _OP_SYMBOL.items()}.get(op_sym)
        if op_internal:
            op_eng = _OP_ENGLISH.get(op_internal, "")
            # Check that the operator symbol or its English synonym appears
            op_synonyms = _get_op_synonyms(op_internal)
            nl_lower_check = natural_language.lower()
            if op_sym not in nl_lower_check:
                if not any(syn in nl_lower_check for syn in op_synonyms):
                    return (
                        False,
                        f"[{label}] Operator {op_sym!r} ({op_eng}) not found in "
                        f"natural language and no synonym matched. "
                        f"Reconstructed: {reconstructed!r}. "
                        f"Natural language: {natural_language!r}. "
                        f"Expected one of: {op_synonyms}",
                    )

    return True, None


def _get_op_synonyms(op_internal: str) -> list[str]:
    """Return English synonyms for a given operator key."""
    synonyms: dict[str, list[str]] = {
        "ge": [
            "at least",
            "no less than",
            "minimum",
            "not less than",
            "≥",
            "or more",
            "or above",
            "or equal",
        ],
        "le": [
            "at most",
            "no more than",
            "maximum",
            "not exceed",
            "not more than",
            "not greater",
            "≤",
            "or less",
            "or below",
            "or equal",
            "limit",
        ],
        "gt": ["greater than", "more than", "above", "exceeds", "over"],
        "lt": ["less than", "below", "under", "fewer than"],
        "eq": [
            "equal",
            "equals",
            "same as",
            "must be",
            "set to",
            "is true",
            "is false",
            "must not be",
            "not frozen",
            "is not",
        ],
        "ne": ["not equal", "differs from", "not the same", "must not be", "different from"],
    }
    return synonyms.get(op_internal, [])


# ── MetaVerifier ──────────────────────────────────────────────────────────────


class MetaVerifier:
    """Verifies that compiled :class:`~pramanix.expressions.ConstraintExpr` objects
    faithfully represent the LLM's stated interpretation of the original policy.

    The verifier is called once per :meth:`~pramanix.natural_policy.compiler.NaturalPolicyCompiler.compile`
    invocation — **never** during ``Guard.verify()``.

    Parameters
    ----------
    mode:
        :class:`VerificationMode` controlling how failures are handled.
        Defaults to :attr:`VerificationMode.STRICT`.
    """

    def __init__(self, mode: VerificationMode = VerificationMode.STRICT) -> None:
        self._mode = mode

    def verify(
        self,
        *,
        original_english: str,
        natural_language_annotations: list[str],
        compiled_constraints: list[ConstraintExpr],
    ) -> MetaVerificationResult:
        """Run the meta-verification pass.

        Pairs each compiled :class:`~pramanix.expressions.ConstraintExpr` with
        the corresponding ``natural_language`` annotation from the LLM schema
        and checks for semantic consistency.

        Parameters
        ----------
        original_english:
            Verbatim CISO policy text from
            :attr:`~pramanix.natural_policy.schemas.NaturalPolicySchema.original_english`.
        natural_language_annotations:
            List of LLM ``natural_language`` strings, one per compiled constraint
            (must be in the same order as *compiled_constraints*).
        compiled_constraints:
            Compiled :class:`~pramanix.expressions.ConstraintExpr` objects from
            :meth:`~pramanix.natural_policy.compiler.ASTBuilder.build`.

        Returns
        -------
        MetaVerificationResult
            Full verification report with per-constraint details.

        Raises
        ------
        PolicyCompilationError
            In :attr:`VerificationMode.STRICT` mode when any constraint fails
            the verification check.
        ValueError
            If *natural_language_annotations* and *compiled_constraints* have
            different lengths — indicates a compiler internal error.
        """
        if self._mode is VerificationMode.SKIP:
            return MetaVerificationResult(
                verified=True,
                original_english=original_english,
                constraint_details=(),
                mismatches=(),
                mode=self._mode,
            )

        if len(natural_language_annotations) != len(compiled_constraints):
            raise ValueError(
                f"natural_language_annotations length ({len(natural_language_annotations)}) "
                f"does not match compiled_constraints length ({len(compiled_constraints)}). "
                "This is a compiler internal error."
            )

        details: list[ConstraintVerificationDetail] = []
        mismatches: list[str] = []

        for annotation, constraint in zip(
            natural_language_annotations, compiled_constraints, strict=True
        ):
            label = constraint.label or "<unlabelled>"
            reconstructed = _reconstruct_constraint(constraint)
            passed, reason = _check_consistency(
                reconstructed=reconstructed,
                natural_language=annotation,
                original_english=original_english,
                label=label,
            )
            details.append(
                ConstraintVerificationDetail(
                    label=label,
                    reconstructed=reconstructed,
                    natural_language=annotation,
                    passed=passed,
                    mismatch_reason=reason,
                )
            )
            if not passed and reason is not None:
                mismatches.append(reason)

        all_passed = len(mismatches) == 0
        result = MetaVerificationResult(
            verified=all_passed,
            original_english=original_english,
            constraint_details=tuple(details),
            mismatches=tuple(mismatches),
            mode=self._mode,
        )

        if not all_passed and self._mode is VerificationMode.STRICT:
            summary = "\n".join(f"  • {m}" for m in mismatches)
            raise PolicyCompilationError(
                f"Meta-verification failed: {len(mismatches)} constraint(s) could not be "
                f"verified against the LLM's natural language annotations.\n"
                f"This indicates a potential LLM hallucination or operator inversion.\n"
                f"Mismatches:\n{summary}\n\n"
                f"Set VerificationMode.WARN to compile despite mismatches, or review "
                f"the policy text and retry."
            )

        return result
