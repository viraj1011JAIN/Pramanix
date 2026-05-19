# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix NLP validation layer.

Provides zero-dependency (stdlib-only) text classifiers that can gate policy
decisions based on the *content* of natural-language fields — complementing
the structural Z3 constraints that guard numeric/enum/boolean fields.

Exports
-------
PIIDetector
    Regex-based detector for SSN, credit cards, email addresses, phone
    numbers, and passport-style identifiers.

ToxicityScorer
    Keyword-density scorer returning a ``[0.0, 1.0]`` float.  Higher values
    indicate more toxic content.

RegexClassifier
    Configurable list of ``(pattern, label)`` pairs; returns all matching
    labels for a given text.

SemanticSimilarityGuard
    Lightweight Jaccard/word-overlap similarity check between input text and
    operator-defined anchor phrases.  No external ML libraries required.

Usage::

    from pramanix.nlp import PIIDetector, ToxicityScorer

    pii = PIIDetector()
    matches = pii.detect("Call me at 555-867-5309 or email bob@example.com")
    # → [PIIMatch(label='phone', value='555-867-5309'), PIIMatch(label='email', ...)]

    scorer = ToxicityScorer()
    score = scorer.score("I will destroy everything you care about")
    # → 0.6  (rough heuristic; tune threshold per deployment)

All classes are usable as drop-in ``ConstraintExpr`` wrappers via the
``FieldMatchesNLPGuard`` primitive when you need to block policy decisions
that contain PII or toxic content in a text field.
"""

from pramanix.nlp.validators import (
    PIIDetector,
    PIIMatch,
    RegexClassifier,
    SemanticSimilarityGuard,
    ToxicityScorer,
)

__all__ = [
    "PIIDetector",
    "PIIMatch",
    "RegexClassifier",
    "SemanticSimilarityGuard",
    "ToxicityScorer",
]
