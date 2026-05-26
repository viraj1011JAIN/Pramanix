# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""NLP validators — zero external-dependency text classification utilities.

Design goals
------------
* **No heavy ML dependencies at import time.**  All classifiers work with
  stdlib ``re`` and built-in Python.  Optional sentence-transformers / sklearn
  integrations are imported lazily and only when explicitly requested.
* **Deterministic.**  Given the same input and the same configuration the same
  result is always produced.  No model downloads, no RNG, no network calls.
* **Composable.**  Every classifier is a lightweight dataclass or class that
  can be configured in ``GuardConfig`` and composed with Z3 constraints via
  the policy layer.
"""

from __future__ import annotations

import contextlib
import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

_log = logging.getLogger(__name__)


class SecurityWarning(UserWarning):
    """Security advisory (not a Python built-in — defined here for all versions)."""


# ── RE2 engine (linear-time, ReDoS-immune) ────────────────────────────────────
# google-re2 guarantees O(n) matching.  All PII patterns below are written to
# avoid lookbehind assertions (not supported by RE2).  The phone pattern uses
# \b (word boundary) instead of the stdlib lookbehind — functionally equivalent
# for the corpus of natural-language text this module targets.
#
# re2 is an optional security extra (pramanix[security]).  We do NOT raise at
# module-import time so that tests and code paths that don't use PII detection
# can still import pramanix normally.  ConfigurationError is raised lazily in
# PIIDetector.__init__() and _re_ci()/_re_ci_ml() when re2 is absent.
_RE2_AVAILABLE = False
_re_engine: Any = None
_re2_import_error: ImportError | None = None
try:
    import re2 as _re2

    _re_engine = _re2
    _RE2_AVAILABLE = True
except ImportError as _re2_err:
    _re2_import_error = _re2_err


def _require_re2() -> None:
    """Raise ConfigurationError if google-re2 is not installed."""
    if not _RE2_AVAILABLE:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "pramanix.nlp.validators: google-re2 is required but not installed. "
            "ReDoS via crafted PII patterns is a critical security risk without it. "
            "Install with: pip install 'pramanix[security]'"
        ) from _re2_import_error


def _re_ci(pattern: str) -> Any:
    _require_re2()
    opts = _re_engine.Options()
    opts.case_sensitive = False
    return _re_engine.compile(pattern, opts)


def _re_ci_ml(pattern: str) -> Any:
    _require_re2()
    opts = _re_engine.Options()
    opts.case_sensitive = False
    opts.one_line = False
    return _re_engine.compile(pattern, opts)


# ── ML backend detection (lazy, zero import-time cost) ────────────────────────

# Prometheus gauges for NLP model availability (set at module load time).
# Operators can alert on pramanix_nlp_model_available{model="..."} == 0.
_NLP_GAUGE: Any = None  # set below after load attempts
_NLP_GAUGE_LOCK = __import__("threading").Lock()

# Counter for NLP scorer degradation events (fallback to keyword/Jaccard).
# Operators can alert on pramanix_nlp_degradation_total{scorer=...,fallback=...}.
_NLP_DEGRADATION_COUNTER: Any = None
_NLP_DEGRADATION_COUNTER_LOCK = __import__("threading").Lock()


def _get_nlp_degradation_counter() -> Any:
    """Return (or lazily create) the pramanix_nlp_degradation_total counter."""
    global _NLP_DEGRADATION_COUNTER
    if _NLP_DEGRADATION_COUNTER is not None:
        return _NLP_DEGRADATION_COUNTER
    with _NLP_DEGRADATION_COUNTER_LOCK:
        if _NLP_DEGRADATION_COUNTER is not None:
            return _NLP_DEGRADATION_COUNTER
        try:
            from prometheus_client import Counter

            _NLP_DEGRADATION_COUNTER = Counter(
                "pramanix_nlp_degradation_total",
                "NLP scorer degradation events — how often a fallback backend was selected",
                ["scorer", "fallback"],
            )
        except Exception as _e:
            _log.debug("pramanix.nlp.validators: degradation counter setup failed: %s", _e)
    return _NLP_DEGRADATION_COUNTER


def _get_nlp_gauge() -> Any:
    """Return (or lazily create) the pramanix_nlp_model_available gauge."""
    global _NLP_GAUGE
    if _NLP_GAUGE is not None:
        return _NLP_GAUGE
    with _NLP_GAUGE_LOCK:
        if _NLP_GAUGE is not None:
            return _NLP_GAUGE
        try:
            from prometheus_client import Gauge

            _NLP_GAUGE = Gauge(
                "pramanix_nlp_model_available",
                "1 if the named NLP safety model loaded successfully, 0 if degraded",
                ["model"],
            )
        except Exception as _e:
            _log.debug("pramanix.nlp.validators: gauge setup failed: %s", _e)
    return _NLP_GAUGE


def _try_detoxify_scorer() -> Any:
    """Return a Detoxify-backed score function, or None if unavailable.

    On failure, emits a WARNING log and sets the
    ``pramanix_nlp_model_available{model="detoxify"}`` gauge to 0 so
    operators can alert before the first request reaches the safety scorer.
    """
    try:
        from detoxify import Detoxify

        _model = Detoxify("original")

        def _score(text: str) -> float:
            results = _model.predict(text)
            return float(results.get("toxicity", 0.0))

        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(Exception):
                g.labels(model="detoxify").set(1)
        return _score
    except Exception as _exc:
        _log.warning(
            "pramanix.nlp.validators: Detoxify model failed to load (%s: %s) — "
            "toxicity scoring is DISABLED. Injection attacks and toxic prompts "
            "will NOT be caught by this safety layer. "
            "Fix: ensure 'detoxify' is installed and GPU/CPU resources are sufficient.",
            type(_exc).__name__,
            _exc,
        )
        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(Exception):
                g.labels(model="detoxify").set(0)
        return None


def _try_sentence_transformer() -> Any:
    """Return a SentenceTransformer model, or None if unavailable.

    On failure, emits a WARNING log and sets the
    ``pramanix_nlp_model_available{model="sentence_transformer"}`` gauge to 0.
    """
    try:
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer("all-MiniLM-L6-v2")
        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(Exception):
                g.labels(model="sentence_transformer").set(1)
        return model
    except Exception as _exc:
        _log.warning(
            "pramanix.nlp.validators: SentenceTransformer model failed to load (%s: %s) — "
            "semantic injection detection is DISABLED. Prompt-injection attacks that "
            "alter intent semantically will NOT be detected by this safety layer. "
            "Fix: ensure 'sentence-transformers' is installed and model files are present.",
            type(_exc).__name__,
            _exc,
        )
        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(Exception):
                g.labels(model="sentence_transformer").set(0)
        return None


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return float(dot / (norm_a * norm_b))


# ── Helpers ────────────────────────────────────────────────────────────────────


def _normalise(text: str) -> str:
    """NFKC-normalise and lower-case *text* for pattern matching."""
    return unicodedata.normalize("NFKC", text).casefold()


# ── PIIDetector ────────────────────────────────────────────────────────────────


def _build_pii_patterns() -> list[tuple[str, Any]]:
    """Build compiled PII patterns. Returns [] when google-re2 is absent."""
    if not _RE2_AVAILABLE:
        return []
    return [
        # US Social Security Number  (xxx-xx-xxxx)
        ("ssn", _re_engine.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        # Credit / debit card — 13-19 digit groups separated by spaces or dashes.
        # Covers Visa (13/16), MC (16), Amex (15), Discover (16), UnionPay (16-19).
        ("credit_card", _re_engine.compile(r"\b(?:\d[ -]?){13,19}\b")),
        # Email addresses (RFC 5321 simplified)
        ("email", _re_ci(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
        # Phone numbers — US/international formats.
        # Uses \b instead of (?<!\d)/(?!\d) lookbehind for RE2 compatibility.
        (
            "phone",
            _re_engine.compile(
                r"\b"
                r"(?:\+?1[\s\-.]?)?"
                r"(?:\(?\d{3}\)?[\s\-.]?)"
                r"\d{3}[\s\-.]?"
                r"\d{4}"
                r"\b",
            ),
        ),
        # IPv4 addresses
        (
            "ipv4",
            _re_engine.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}" r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            ),
        ),
        # US passport number (A followed by 8 digits)
        ("passport_us", _re_engine.compile(r"\b[A-Z]\d{8}\b")),
        # UK National Insurance number (XX 99 99 99 X)
        ("nino_uk", _re_ci(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[ABCD]\b")),
        # Driver's licence — common North American pattern (1-2 letters + 5-14 digits)
        ("drivers_licence", _re_engine.compile(r"\b[A-Z]{1,2}\d{5,14}\b")),
    ]


_PII_PATTERNS: list[tuple[str, Any]] = _build_pii_patterns()


@dataclass(frozen=True, slots=True)
class PIIMatch:
    """A single PII hit found by :class:`PIIDetector`.

    Attributes
    ----------
    label:  PII category (``ssn``, ``email``, ``phone``, ``credit_card``, …).
    value:  The exact substring that matched (redacted in log output).
    start:  Character offset of the match start in the original text.
    end:    Character offset of the match end (exclusive).
    """

    label: str
    value: str
    start: int
    end: int

    def __repr__(self) -> str:
        # Never expose the matched value in repr/logs.
        return f"PIIMatch(label={self.label!r}, start={self.start}, end={self.end})"


class PIIDetector:
    """Regex-based PII detector.

    Detects SSNs, credit card numbers, email addresses, phone numbers, IPv4
    addresses, US passport numbers, UK NINOs, and driver's licence numbers.

    Args:
        extra_patterns: Optional list of ``(label, compiled_pattern)`` tuples
                        appended to the built-in set.  Use this to add custom
                        PII patterns without subclassing.

    Example::

        detector = PIIDetector()
        matches = detector.detect("SSN 123-45-6789 or email alice@example.com")
        for m in matches:
            print(m.label, m.start, m.end)  # value is NOT printed
    """

    def __init__(
        self,
        extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        _require_re2()
        self._patterns: list[tuple[str, re.Pattern[str]]] = list(_PII_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def detect(self, text: str) -> list[PIIMatch]:
        """Return all PII matches found in *text*.

        Overlapping matches from different pattern categories are all
        returned.  Within a single pattern, only non-overlapping matches are
        returned (left-to-right, first match wins).

        Args:
            text: Raw input string to scan.

        Returns:
            List of :class:`PIIMatch` objects, sorted by start offset.
        """
        results: list[PIIMatch] = []
        for label, pattern in self._patterns:
            for m in pattern.finditer(text):
                results.append(PIIMatch(label=label, value=m.group(), start=m.start(), end=m.end()))
        results.sort(key=lambda m: m.start)
        return results

    def has_pii(self, text: str) -> bool:
        """Return ``True`` if *text* contains at least one PII match."""
        return any(pattern.search(text) for _label, pattern in self._patterns)

    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        """Return a copy of *text* with all PII replaced by *replacement*.

        Replacements are applied right-to-left so that character offsets
        remain valid after each substitution.

        Args:
            text:        Original text to redact.
            replacement: String to substitute for each PII span.

        Returns:
            Redacted copy of *text*.
        """
        matches = self.detect(text)
        # Deduplicate / sort descending by start so we can splice right-to-left.
        matches_sorted = sorted(set(matches), key=lambda m: m.start, reverse=True)
        result = text
        for m in matches_sorted:
            result = result[: m.start] + replacement + result[m.end :]
        return result


# ── ToxicityScorer ─────────────────────────────────────────────────────────────

# Default keyword set.  Deliberately minimal — the goal is a fast,
# configurable heuristic for policy gating, NOT a substitute for a trained
# toxicity model.  Operators MUST tune the ``threshold`` per deployment and
# can supply custom ``toxic_words`` tailored to their domain.
_DEFAULT_TOXIC_WORDS: frozenset[str] = frozenset(
    {
        # Threats / violence
        "kill",
        "murder",
        "attack",
        "bomb",
        "shoot",
        "stab",
        "assault",
        "threaten",
        "destroy",
        "annihilate",
        "eliminate",
        "slaughter",
        "execute",
        "detonate",
        # Harassment
        "hate",
        "harass",
        "bully",
        "intimidate",
        "stalk",
        "blackmail",
        # Explicit sexual content signals
        "rape",
        "molest",
        "grope",
        "fondle",
        # Self-harm
        "suicide",
        "self-harm",
        "overdose",
        # Racial / ethnic slurs — common derogatory stems
        # This list covers the most-flagged categories in content moderation
        # research (Fortuna & Nunes 2018; Davidson et al. 2017).  It is NOT
        # exhaustive; operators MUST extend via extra_words for their domain.
        # Stems are chosen to match the root form across inflections.
        "nigger",
        "nigga",
        "chink",
        "spic",
        "wetback",
        "kike",
        "gook",
        "zipperhead",
        "coon",
        "beaner",
        "cracker",
        "honky",
        "redskin",
        "towelhead",
        "raghead",
        "camel jockey",
        # Homophobic / transphobic slurs
        "faggot",
        "fag",
        "dyke",
        "tranny",
        "shemale",
        "homo",
        # Ableist slurs
        "retard",
        "spastic",
        "cripple",
        # Religious / national slurs
        "infidel",
        "kafir",
        "jap",
        "kraut",
        "frog",
        "limey",
    }
)


class ToxicityScorer:
    """Keyword-density heuristic toxicity scorer.

    Returns a ``[0.0, 1.0]`` float where higher values indicate more toxic
    content.  The score is computed as:

    .. math::

        \\text{score} = \\frac{\\text{toxic token count}}{\\max(1, \\text{total token count})}

    capped at ``1.0``.

    This is intentionally a rough heuristic suitable for policy gating.  For
    production deployments requiring high-accuracy toxicity classification,
    integrate an external model (e.g. ``detoxify``, Perspective API) by
    subclassing or passing a custom ``score_fn``.

    Args:
        toxic_words:  Custom replacement for the built-in toxic word set.
                      When ``None``, the built-in set is used.
        extra_words:  Additional toxic words *merged* with the built-in set.
        threshold:    Convenience attribute — operators may compare
                      ``scorer.score(text) >= scorer.threshold`` in policy
                      callbacks.  Default: ``0.3``.
        score_fn:     Optional callable ``(text: str) -> float`` that
                      completely overrides the keyword-density logic.  Use
                      this to plug in an external model while keeping the
                      same interface.

    Example::

        scorer = ToxicityScorer(threshold=0.2)
        if scorer.score(user_message) >= scorer.threshold:
            raise PolicyViolation("Toxic content detected")
    """

    def __init__(
        self,
        toxic_words: frozenset[str] | set[str] | None = None,
        extra_words: frozenset[str] | set[str] | None = None,
        threshold: float = 0.3,
        score_fn: Any | None = None,  # Callable[[str], float] | None
    ) -> None:
        base = toxic_words if toxic_words is not None else _DEFAULT_TOXIC_WORDS
        if extra_words:
            base = frozenset(base) | frozenset(w.casefold() for w in extra_words)
        self._words: frozenset[str] = frozenset(w.casefold() for w in base)
        self.threshold: float = threshold

        if score_fn is not None:
            self._score_fn = score_fn
            self._backend = "custom"
        else:
            _detoxify = _try_detoxify_scorer()
            if _detoxify is not None:
                self._score_fn = _detoxify
                self._backend = "detoxify"
                _log.debug("ToxicityScorer: using detoxify 'original' model backend")
            else:
                self._score_fn = None
                self._backend = "keyword"
                _log.warning(
                    "ToxicityScorer: using keyword-density fallback — "
                    "install 'detoxify' for production-grade toxicity scoring: "
                    "pip install 'pramanix[nlp]'"
                )
                _c = _get_nlp_degradation_counter()
                if _c is not None:
                    with contextlib.suppress(Exception):
                        _c.labels(scorer="ToxicityScorer", fallback="keyword").inc()

    def score(self, text: str) -> float:
        """Compute a toxicity score for *text*.

        Args:
            text: Raw input string.

        Returns:
            Float in ``[0.0, 1.0]`` — higher means more toxic.
        """
        if self._score_fn is not None:
            result = float(self._score_fn(text))
            return max(0.0, min(1.0, result))

        tokens = _normalise(text).split()
        if not tokens:
            return 0.0

        toxic_count = sum(1 for t in tokens if t.strip(".,!?;:'\"") in self._words)
        return min(1.0, toxic_count / len(tokens))

    def is_toxic(self, text: str, threshold: float | None = None) -> bool:
        """Return ``True`` if the toxicity score meets or exceeds *threshold*.

        Args:
            text:       Input to evaluate.
            threshold:  Override the instance threshold for this call.

        Returns:
            ``True`` when ``score(text) >= threshold``.
        """
        thr = threshold if threshold is not None else self.threshold
        return self.score(text) >= thr


# ── RegexClassifier ────────────────────────────────────────────────────────────


class RegexClassifier:
    """Multi-label regex-based text classifier.

    Maps a list of ``(label, pattern)`` pairs to all labels whose pattern
    matches the input text.  Useful for classifying request intent, detecting
    sensitive topics, or routing text to the appropriate policy branch.

    Args:
        rules: List of ``(label, pattern_or_str)`` tuples.  Strings are
               compiled with ``re.IGNORECASE | re.MULTILINE``.

    Example::

        clf = RegexClassifier([
            ("financial",    r"\\b(balance|transfer|account|wire)\\b"),
            ("medical",      r"\\b(diagnosis|medication|dosage|patient)\\b"),
            ("credentials",  r"\\b(password|api.?key|token|secret)\\b"),
        ])
        labels = clf.classify("Please reset my password and check my account balance")
        # → ["financial", "credentials"]
    """

    def __init__(
        self,
        rules: list[tuple[str, str | re.Pattern[str]]],
    ) -> None:
        self._rules: list[tuple[str, re.Pattern[str]]] = []
        for label, pat in rules:
            if isinstance(pat, str):
                compiled = _re_ci_ml(pat)
            else:
                compiled = pat
            self._rules.append((label, compiled))

    def classify(self, text: str) -> list[str]:
        """Return all labels whose pattern matches *text*.

        Args:
            text: Input string to classify.

        Returns:
            List of matching labels in rule definition order.
        """
        return [label for label, pat in self._rules if pat.search(text)]

    def has_label(self, text: str, label: str) -> bool:
        """Return ``True`` if the given *label* matches *text*."""
        return label in self.classify(text)


# ── SemanticSimilarityGuard ────────────────────────────────────────────────────


class SemanticSimilarityGuard:
    """Word-overlap (Jaccard) similarity guard with no external ML dependencies.

    Compares the *token set* of input text against one or more anchor phrases
    using Jaccard similarity.  If the maximum similarity across all anchors
    meets the threshold, the guard considers the text semantically related to
    the anchor topics.

    .. math::

        J(A, B) = \\frac{|A \\cap B|}{|A \\cup B|}

    For higher-accuracy semantic similarity, pass a ``similarity_fn`` that
    uses sentence-transformers or another embedding model.

    Args:
        anchors:       List of reference phrases that represent the
                       protected topic (e.g. ``["wire transfer", "send money"]``).
        threshold:     Minimum Jaccard similarity to trigger a match.
                       Default: ``0.3``.
        similarity_fn: Optional callable ``(text: str, anchor: str) -> float``
                       overriding the built-in Jaccard logic.  Must return a
                       value in ``[0.0, 1.0]``.

    Example::

        guard = SemanticSimilarityGuard(
            anchors=["execute wire transfer", "send funds abroad"],
            threshold=0.4,
        )
        if guard.is_similar("Please transfer $50 000 to overseas account"):
            raise PolicyViolation("Potential wire fraud detected")
    """

    def __init__(
        self,
        anchors: list[str],
        threshold: float = 0.3,
        similarity_fn: Any | None = None,  # Callable[[str, str], float] | None
    ) -> None:
        if not anchors:
            raise ValueError("SemanticSimilarityGuard requires at least one anchor phrase.")
        self._anchors: list[str] = list(anchors)
        self.threshold: float = threshold

        if similarity_fn is not None:
            self._similarity_fn = similarity_fn
            self._st_model = None
            self._backend = "custom"
        else:
            _st = _try_sentence_transformer()
            if _st is not None:
                self._st_model = _st
                # Pre-encode anchors for fast inference
                self._anchor_embeddings: list[list[float]] = [
                    _st.encode(a, convert_to_tensor=False).tolist() for a in self._anchors
                ]
                self._similarity_fn = None
                self._backend = "sentence-transformers"
                _log.debug(
                    "SemanticSimilarityGuard: using sentence-transformers "
                    "'all-MiniLM-L6-v2' backend"
                )
            else:
                self._st_model = None
                self._similarity_fn = None
                self._backend = "jaccard"
                _log.warning(
                    "SemanticSimilarityGuard: using Jaccard word-overlap fallback — "
                    "install 'sentence-transformers' for production-grade semantic "
                    "similarity: pip install 'pramanix[nlp]'"
                )
                _c = _get_nlp_degradation_counter()
                if _c is not None:
                    with contextlib.suppress(Exception):
                        _c.labels(scorer="SemanticSimilarityGuard", fallback="jaccard").inc()

        # Pre-tokenise anchors for the Jaccard fallback path.
        self._anchor_tokens: list[frozenset[str]] = [self._tokenise(a) for a in self._anchors]

    @staticmethod
    def _tokenise(text: str) -> frozenset[str]:
        """Lower-case, NFKC-normalise, and split on non-alphanumeric chars."""
        norm = _normalise(text)
        return frozenset(_re_engine.split(r"\W+", norm)) - {""}

    def _jaccard(self, a: frozenset[str], b: frozenset[str]) -> float:
        if not a and not b:
            return 1.0
        union = a | b
        return len(a & b) / len(union)

    def similarity(self, text: str) -> float:
        """Return the maximum similarity of *text* against all anchors.

        Args:
            text: Input text to compare.

        Returns:
            Float in ``[0.0, 1.0]`` — highest similarity across all anchors.
        """
        scores: list[float] = []

        if self._similarity_fn is not None:
            for anchor in self._anchors:
                s = float(self._similarity_fn(text, anchor))
                scores.append(max(0.0, min(1.0, s)))
        elif self._st_model is not None:
            text_emb = self._st_model.encode(text, convert_to_tensor=False).tolist()
            for anc_emb in self._anchor_embeddings:
                s = _cosine_similarity(text_emb, anc_emb)
                scores.append(max(0.0, min(1.0, s)))
        else:
            text_tokens = self._tokenise(text)
            for i in range(len(self._anchors)):
                scores.append(self._jaccard(text_tokens, self._anchor_tokens[i]))

        return max(scores) if scores else 0.0

    def is_similar(self, text: str, threshold: float | None = None) -> bool:
        """Return ``True`` if ``similarity(text) >= threshold``.

        Args:
            text:       Input to evaluate.
            threshold:  Override the instance threshold for this call.

        Returns:
            ``True`` when the text is semantically similar to any anchor.
        """
        thr = threshold if threshold is not None else self.threshold
        return self.similarity(text) >= thr

    def most_similar_anchor(self, text: str) -> tuple[str, float]:
        """Return the ``(anchor, similarity_score)`` pair with highest score.

        Useful for debugging which topic the input text most closely matched.

        Args:
            text: Input text.

        Returns:
            ``(anchor_phrase, score)`` tuple.
        """
        best_anchor = self._anchors[0]
        best_score = 0.0

        if self._similarity_fn is not None:
            for anchor in self._anchors:
                s = max(0.0, min(1.0, float(self._similarity_fn(text, anchor))))
                if s > best_score:
                    best_score = s
                    best_anchor = anchor
        elif self._st_model is not None:
            text_emb = self._st_model.encode(text, convert_to_tensor=False).tolist()
            for anchor, anc_emb in zip(self._anchors, self._anchor_embeddings, strict=False):
                s = max(0.0, min(1.0, _cosine_similarity(text_emb, anc_emb)))
                if s > best_score:
                    best_score = s
                    best_anchor = anchor
        else:
            text_tokens = self._tokenise(text)
            for i, anchor in enumerate(self._anchors):
                s = max(0.0, min(1.0, self._jaccard(text_tokens, self._anchor_tokens[i])))
                if s > best_score:
                    best_score = s
                    best_anchor = anchor

        return best_anchor, best_score
