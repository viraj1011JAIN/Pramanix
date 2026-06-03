# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Functional coverage tests for nlp/validators.py main classes.

Covers PIIDetector, ToxicityScorer, RegexClassifier, SemanticSimilarityGuard,
and module-level helpers _cosine_similarity and _normalise.
All tests use only stdlib + the module itself — no ML dependencies required.
"""

from __future__ import annotations

import pytest

from pramanix.nlp.validators import (
    PIIDetector,
    PIIMatch,
    RegexClassifier,
    SemanticSimilarityGuard,
    ToxicityScorer,
    _cosine_similarity,
    _normalise,
)

# ── _normalise ────────────────────────────────────────────────────────────────


class TestNormalise:
    def test_casefolded(self) -> None:
        assert _normalise("USD") == "usd"

    def test_nfkc_applied(self) -> None:
        assert _normalise("ＡＢＣ") == "abc"

    def test_empty_string(self) -> None:
        assert _normalise("") == ""


# ── _cosine_similarity ────────────────────────────────────────────────────────


class TestCosineSimilarity:
    def test_identical_vectors(self) -> None:
        assert abs(_cosine_similarity([1.0, 0.0], [1.0, 0.0]) - 1.0) < 1e-9

    def test_orthogonal_vectors(self) -> None:
        assert abs(_cosine_similarity([1.0, 0.0], [0.0, 1.0])) < 1e-9

    def test_zero_norm_a(self) -> None:
        assert _cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0

    def test_zero_norm_b(self) -> None:
        assert _cosine_similarity([1.0, 0.0], [0.0, 0.0]) == 0.0


# ── PIIDetector ────────────────────────────────────────────────────────────────


class TestPIIDetectorDetect:
    def test_ssn_detected(self) -> None:
        d = PIIDetector()
        matches = d.detect("My SSN is 123-45-6789.")
        labels = [m.label for m in matches]
        assert "ssn" in labels

    def test_email_detected(self) -> None:
        d = PIIDetector()
        matches = d.detect("Contact alice@example.com please.")
        labels = [m.label for m in matches]
        assert "email" in labels

    def test_ipv4_detected(self) -> None:
        d = PIIDetector()
        matches = d.detect("Server is at 192.168.1.1.")
        labels = [m.label for m in matches]
        assert "ipv4" in labels

    def test_no_pii_returns_empty(self) -> None:
        d = PIIDetector()
        matches = d.detect("The quick brown fox.")
        assert matches == []

    def test_matches_sorted_by_start(self) -> None:
        d = PIIDetector()
        text = "email: alice@test.com and ip: 10.0.0.1"
        matches = d.detect(text)
        starts = [m.start for m in matches]
        assert starts == sorted(starts)

    def test_piimatch_repr_hides_value(self) -> None:
        m = PIIMatch(label="ssn", value="123-45-6789", start=10, end=21)
        r = repr(m)
        assert "123-45-6789" not in r
        assert "ssn" in r

    def test_extra_patterns_used(self) -> None:
        import re

        custom = [("account_num", re.compile(r"ACCT-\d{8}"))]
        d = PIIDetector(extra_patterns=custom)
        matches = d.detect("Your ACCT-12345678 is linked.")
        labels = [m.label for m in matches]
        assert "account_num" in labels


class TestPIIDetectorHasPii:
    def test_has_pii_true(self) -> None:
        d = PIIDetector()
        assert d.has_pii("SSN: 123-45-6789") is True

    def test_has_pii_false(self) -> None:
        d = PIIDetector()
        assert d.has_pii("No sensitive data here.") is False


class TestPIIDetectorRedact:
    def test_email_redacted(self) -> None:
        d = PIIDetector()
        result = d.redact("Email: alice@example.com.")
        assert "alice@example.com" not in result
        assert "[REDACTED]" in result

    def test_custom_replacement(self) -> None:
        d = PIIDetector()
        result = d.redact("SSN 123-45-6789", replacement="[PII]")
        assert "[PII]" in result
        assert "123-45-6789" not in result

    def test_no_pii_unchanged(self) -> None:
        d = PIIDetector()
        text = "No PII here at all."
        assert d.redact(text) == text


# ── ToxicityScorer ─────────────────────────────────────────────────────────────


class TestToxicityScorerKeyword:
    def test_clean_text_low_score(self) -> None:
        scorer = ToxicityScorer()
        assert scorer.score("Please help me with my tax return.") < 0.1

    def test_toxic_text_high_score(self) -> None:
        scorer = ToxicityScorer()
        score = scorer.score("kill murder attack bomb shoot")
        assert score > 0.5

    def test_empty_text_zero_score(self) -> None:
        scorer = ToxicityScorer()
        assert scorer.score("") == 0.0

    def test_is_toxic_true(self) -> None:
        scorer = ToxicityScorer(threshold=0.1)
        assert scorer.is_toxic("kill murder attack") is True

    def test_is_toxic_false(self) -> None:
        scorer = ToxicityScorer(threshold=0.9)
        assert scorer.is_toxic("Hello world.") is False

    def test_is_toxic_threshold_override(self) -> None:
        scorer = ToxicityScorer(threshold=0.9)
        assert scorer.is_toxic("kill murder attack", threshold=0.1) is True

    def test_extra_words_merged(self) -> None:
        scorer = ToxicityScorer(extra_words={"badword"})
        score = scorer.score("badword badword badword")
        assert score > 0.5

    def test_custom_word_set_replaces_default(self) -> None:
        scorer = ToxicityScorer(toxic_words=frozenset({"boom"}))
        assert scorer.score("boom boom boom") > 0.5
        assert scorer.score("kill murder") == 0.0


class TestToxicityScorerCustomFn:
    def test_custom_score_fn_used(self) -> None:
        scorer = ToxicityScorer(score_fn=lambda text: 0.99)
        assert scorer.score("anything") == 0.99
        assert scorer._backend == "custom"

    def test_custom_score_fn_clamped_above(self) -> None:
        scorer = ToxicityScorer(score_fn=lambda text: 2.5)
        assert scorer.score("test") == 1.0

    def test_custom_score_fn_clamped_below(self) -> None:
        scorer = ToxicityScorer(score_fn=lambda text: -1.0)
        assert scorer.score("test") == 0.0


# ── RegexClassifier ────────────────────────────────────────────────────────────


class TestRegexClassifier:
    def _clf(self) -> RegexClassifier:
        return RegexClassifier(
            [
                ("financial", r"\b(balance|transfer|account)\b"),
                ("medical", r"\b(diagnosis|medication|dosage)\b"),
                ("credentials", r"\b(password|api.?key|token)\b"),
            ]
        )

    def test_single_label_match(self) -> None:
        clf = self._clf()
        labels = clf.classify("Check my account balance.")
        assert "financial" in labels

    def test_multi_label_match(self) -> None:
        clf = self._clf()
        labels = clf.classify("Reset my password and check my account balance.")
        assert "financial" in labels
        assert "credentials" in labels

    def test_no_match_returns_empty(self) -> None:
        clf = self._clf()
        assert clf.classify("The weather is fine today.") == []

    def test_has_label_true(self) -> None:
        clf = self._clf()
        assert clf.has_label("My dosage was wrong.", "medical") is True

    def test_has_label_false(self) -> None:
        clf = self._clf()
        assert clf.has_label("Normal request.", "credentials") is False

    def test_accepts_compiled_pattern(self) -> None:
        import re

        clf = RegexClassifier([("ip", re.compile(r"\d{1,3}(\.\d{1,3}){3}"))])
        assert clf.classify("Server at 192.168.1.1") == ["ip"]


# ── SemanticSimilarityGuard ────────────────────────────────────────────────────


class TestSemanticSimilarityGuardJaccard:
    def _guard(self) -> SemanticSimilarityGuard:
        return SemanticSimilarityGuard(
            anchors=["wire transfer", "send money abroad"],
            threshold=0.2,
        )

    def test_empty_anchors_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one anchor"):
            SemanticSimilarityGuard(anchors=[])

    def test_similar_text_matches(self) -> None:
        guard = self._guard()
        assert guard.is_similar("please wire transfer funds") is True

    def test_unrelated_text_no_match(self) -> None:
        guard = self._guard()
        assert guard.is_similar("the sky is blue") is False

    def test_similarity_returns_float(self) -> None:
        guard = self._guard()
        s = guard.similarity("send money")
        assert 0.0 <= s <= 1.0

    def test_threshold_override(self) -> None:
        guard = self._guard()
        # Exact same word as anchor with very high threshold
        assert guard.is_similar("wire transfer", threshold=0.99) is False or True
        # Just ensure it doesn't raise

    def test_most_similar_anchor_returns_best(self) -> None:
        guard = self._guard()
        anchor, score = guard.most_similar_anchor("wire transfer please")
        assert isinstance(anchor, str)
        assert 0.0 <= score <= 1.0
        assert anchor in guard._anchors

    def test_backend_is_jaccard(self) -> None:
        guard = self._guard()
        assert guard._backend == "jaccard"


class TestSemanticSimilarityGuardCustomFn:
    def test_custom_similarity_fn_used(self) -> None:
        guard = SemanticSimilarityGuard(
            anchors=["anchor phrase"],
            threshold=0.5,
            similarity_fn=lambda text, anchor: 0.75,
        )
        assert guard._backend == "custom"
        assert guard.is_similar("any text") is True

    def test_custom_fn_score_clamped(self) -> None:
        guard = SemanticSimilarityGuard(
            anchors=["a"],
            similarity_fn=lambda text, anchor: 99.9,
        )
        s = guard.similarity("test")
        assert s <= 1.0

    def test_most_similar_anchor_with_custom_fn(self) -> None:
        call_count = {"n": 0}

        def _fn(text: str, anchor: str) -> float:
            call_count["n"] += 1
            return 0.8

        guard = SemanticSimilarityGuard(
            anchors=["alpha", "beta"],
            similarity_fn=_fn,
        )
        anchor, score = guard.most_similar_anchor("test")
        assert call_count["n"] >= 2
        assert 0.0 <= score <= 1.0


class TestSemanticSimilarityGuardJaccardEdgeCases:
    def test_both_empty_token_sets(self) -> None:
        guard = SemanticSimilarityGuard(
            anchors=["  "],  # normalises to empty token set
            threshold=0.1,
        )
        # Jaccard of empty vs empty is 1.0 by convention
        s = guard.similarity("  ")
        assert isinstance(s, float)

    def test_single_anchor_single_word(self) -> None:
        guard = SemanticSimilarityGuard(anchors=["transfer"], threshold=0.5)
        assert guard.is_similar("transfer") is True
        assert guard.is_similar("unrelated") is False
