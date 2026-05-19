# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Natural-language policy compiler — compile-time only, never in the hot path.

This subpackage provides a translation layer that allows a CISO to write a
policy in plain English.  The pipeline is:

1. **LLM parse** — an LLM-backed :class:`~pramanix.translator.Translator`
   converts the English description into a structured
   :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema` JSON object.
2. **Pydantic validation** — the JSON is validated against strict Pydantic
   models before any DSL code touches it.
3. **AST compilation** — :class:`~pramanix.natural_policy.compiler.ASTBuilder`
   maps each Pydantic node to a ``pramanix.expressions`` call, producing
   :class:`~pramanix.expressions.ConstraintExpr` objects.
4. **Meta-verification** — :class:`~pramanix.natural_policy.verifier.MetaVerifier`
   reconstructs canonical English from the compiled AST and compares it to
   the LLM's own ``natural_language`` annotations to detect hallucinations.

**Security invariant**: The LLM is called *only* inside
:meth:`~pramanix.natural_policy.compiler.NaturalPolicyCompiler.compile`.
It is *never* called during ``Guard.verify()``.  The compiled
:class:`~pramanix.expressions.ConstraintExpr` objects are pure-Python /
Z3 data structures with zero LLM involvement at verification time.

Typical usage::

    from pramanix.translator import create_translator
    from pramanix.natural_policy import NaturalPolicyCompiler

    compiler = NaturalPolicyCompiler(translator=create_translator("gpt-4o"))
    result = await compiler.compile(
        \"\"\"
        The transaction amount must not exceed 50 000 USD.
        The account balance after the transfer must remain non-negative.
        The account must not be frozen.
        \"\"\"
    )

    # result.fields  — dict[str, Field]  — use as Policy class attributes
    # result.constraints  — list[ConstraintExpr]  — return from Policy.invariants()
    # result.verification — MetaVerificationResult — audit proof of no hallucination
"""

from pramanix.natural_policy.compiler import ASTBuilder, CompiledPolicy, NaturalPolicyCompiler
from pramanix.natural_policy.schemas import (
    AndConstraintNode,
    ArithmeticLHS,
    ArithOp,
    ComparisonConstraintNode,
    ComparisonOp,
    CompositeConstraintNode,
    FieldDeclaration,
    FieldLHS,
    NaturalPolicySchema,
    NotConstraintNode,
    OrConstraintNode,
    Z3TypeEnum,
)
from pramanix.natural_policy.verifier import MetaVerificationResult, MetaVerifier, VerificationMode

__all__ = [
    "ASTBuilder",
    "AndConstraintNode",
    "ArithOp",
    "ArithmeticLHS",
    "CompiledPolicy",
    "ComparisonConstraintNode",
    "ComparisonOp",
    "CompositeConstraintNode",
    "FieldDeclaration",
    "FieldLHS",
    "MetaVerificationResult",
    "MetaVerifier",
    "NaturalPolicyCompiler",
    "NaturalPolicySchema",
    "NotConstraintNode",
    "OrConstraintNode",
    "VerificationMode",
    "Z3TypeEnum",
]
