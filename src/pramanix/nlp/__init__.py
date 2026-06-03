# SPDX-License-Identifier: Apache-2.0
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
    Keyword-density scorer returning a ``[0.0, 1.0]`` float.

RegexClassifier
    Configurable list of ``(pattern, label)`` pairs; returns all matching
    labels for a given text.

SemanticSimilarityGuard
    Lightweight Jaccard/word-overlap similarity check against anchor phrases.

StringLengthValidator
    Validates that a string's character length is within a declared range.

NumericRangeValidator
    Validates that a numeric value is within a declared [min, max] range.

DateValidator
    Validates ISO 8601 date/datetime strings with optional temporal constraints.

URLValidator
    Validates URL format with scheme allowlist and domain allow/block lists.

EmailValidator
    RFC 5321 email address validator backed by google-re2.

JSONSchemaValidator
    Validates a dict or JSON string against a JSON Schema definition.

ProfanityDetector
    Keyword-based profanity detector with whole-word matching; zero ML deps.
"""

from pramanix.nlp.validators import (
    DateValidator,
    EmailValidator,
    JSONSchemaValidator,
    NumericRangeValidator,
    PIIDetector,
    PIIMatch,
    ProfanityDetector,
    RegexClassifier,
    SemanticSimilarityGuard,
    StringLengthValidator,
    ToxicityScorer,
    URLValidator,
)

__all__ = [
    "DateValidator",
    "EmailValidator",
    "JSONSchemaValidator",
    "NumericRangeValidator",
    "PIIDetector",
    "PIIMatch",
    "ProfanityDetector",
    "RegexClassifier",
    "SemanticSimilarityGuard",
    "StringLengthValidator",
    "ToxicityScorer",
    "URLValidator",
]
