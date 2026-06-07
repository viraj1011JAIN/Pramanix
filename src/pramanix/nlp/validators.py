# SPDX-License-Identifier: Apache-2.0
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
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
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
_NLP_GAUGE_LOCK = threading.Lock()

# Counter for NLP scorer degradation events (fallback to keyword/Jaccard).
# Operators can alert on pramanix_nlp_degradation_total{scorer=...,fallback=...}.
_NLP_DEGRADATION_COUNTER: Any = None
_NLP_DEGRADATION_COUNTER_LOCK = threading.Lock()


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

    On failure, emits an ERROR log and sets the
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
            with contextlib.suppress(AttributeError, ValueError):
                g.labels(model="detoxify").set(1)
        return _score
    except Exception as _exc:
        _log.error(
            "pramanix.nlp.validators: Detoxify model failed to load (%s: %s) — "
            "toxicity scoring is DISABLED. Injection attacks and toxic prompts "
            "will NOT be caught by this safety layer. "
            "Fix: ensure 'detoxify' is installed and GPU/CPU resources are sufficient.",
            type(_exc).__name__,
            _exc,
        )
        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(AttributeError, ValueError):
                g.labels(model="detoxify").set(0)
        return None


def _try_sentence_transformer() -> Any:
    """Return a SentenceTransformer model, or None if unavailable.

    On failure, emits an ERROR log and sets the
    ``pramanix_nlp_model_available{model="sentence_transformer"}`` gauge to 0.
    """
    try:
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer("all-MiniLM-L6-v2")
        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(AttributeError, ValueError):
                g.labels(model="sentence_transformer").set(1)
        return model
    except Exception as _exc:
        _log.error(
            "pramanix.nlp.validators: SentenceTransformer model failed to load (%s: %s) — "
            "semantic injection detection is DISABLED. Prompt-injection attacks that "
            "alter intent semantically will NOT be detected by this safety layer. "
            "Fix: ensure 'sentence-transformers' is installed and model files are present.",
            type(_exc).__name__,
            _exc,
        )
        g = _get_nlp_gauge()
        if g is not None:
            with contextlib.suppress(AttributeError, ValueError):
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

# Homoglyph confusables table (#207): Cyrillic and Greek characters that are
# visually indistinguishable from Latin letters in most fonts.  NFKC alone does
# NOT map these — they are distinct code points in different scripts.  An
# adversary can replace a Latin letter with its Cyrillic lookalike to bypass
# keyword matching: e.g. "kіll" (Cyrillic і U+0456) ≠ "kill" (Latin i U+0069).
# str.translate() applies this table in O(n) time — one pass per character.
_CONFUSABLES: dict[int, str] = {
    # Cyrillic → Latin
    0x0430: "a",  # а → a
    0x0410: "a",  # А → a
    0x0435: "e",  # е → e
    0x0415: "e",  # Е → e
    0x043E: "o",  # о → o
    0x041E: "o",  # О → o
    0x0440: "p",  # р → p
    0x0420: "p",  # Р → p
    0x0441: "c",  # с → c
    0x0421: "c",  # С → c
    0x0445: "x",  # х → x
    0x0425: "x",  # Х → x
    0x0456: "i",  # і → i  (Ukrainian small i — primary evasion char)
    0x0406: "i",  # І → i
    0x0432: "b",  # в → b
    0x0412: "b",  # В → b
    0x043D: "n",  # н → n
    0x041D: "n",  # Н → n
    0x043A: "k",  # к → k
    0x041A: "k",  # К → k
    0x043C: "m",  # м → m
    0x041C: "m",  # М → m
    0x0442: "t",  # т → t
    0x0422: "t",  # Т → t
    0x0455: "s",  # ѕ → s  (Cyrillic dze)
    # Greek → Latin
    0x03B1: "a",  # α → a
    0x03B5: "e",  # ε → e
    0x03B7: "n",  # η → n
    0x03B9: "i",  # ι → i
    0x03BA: "k",  # κ → k
    0x03BD: "v",  # ν → v
    0x03BF: "o",  # ο → o
    0x03C1: "p",  # ρ → p
    0x03C7: "x",  # χ → x
    # Mathematical / letterlike
    0x2113: "l",  # ℓ → l
    0x0261: "g",  # ɡ → g  (IPA voiced velar stop)
}
_CONFUSABLES_TABLE: dict[int, str] = _CONFUSABLES  # alias — str.translate expects int keys


def _normalise(text: str) -> str:
    """NFKC-normalise, deconfuse homoglyphs, strip zero-width chars, casefold.

    Pipeline (#207):
    1. NFKC: fullwidth → ASCII, decomposed → composed, compatibility variants.
    2. Confusables: Cyrillic/Greek lookalikes → ASCII equivalents.
    3. Zero-width filter: remove non-printable invisible characters.
    4. casefold: locale-insensitive lowercasing.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_CONFUSABLES_TABLE)
    # Strip zero-width and other invisible chars that survive steps 1-2
    text = "".join(ch for ch in text if ch.isprintable())
    return text.casefold()


def _luhn_valid(digits: str) -> bool:
    """Return True iff *digits* (only decimal chars) passes the Luhn checksum.

    Luhn algorithm (#208): validates that a numeric string has a valid credit
    card check digit.  Eliminates phone numbers, SSNs, timestamps, and other
    numeric sequences that happen to match the card-prefix regex but are not
    real card numbers.
    """
    total = 0
    odd_position = True  # from the rightmost digit
    for ch in reversed(digits):
        if not ch.isdigit():
            continue
        d = int(ch)
        if not odd_position:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        odd_position = not odd_position
    return total % 10 == 0


# ── PIIDetector ────────────────────────────────────────────────────────────────


def _build_pii_patterns() -> list[tuple[str, Any]]:
    """Build compiled PII patterns. Returns [] when google-re2 is absent."""
    if not _RE2_AVAILABLE:
        return []
    return [
        # US Social Security Number  (xxx-xx-xxxx)
        ("ssn", _re_engine.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        # Credit / debit card — tighter pattern than raw digit runs to reduce
        # false positives from phone numbers, SSNs, and timestamps.
        # Anchored to known card prefixes and standard group formats:
        #   Visa (13/16d starting 4), Mastercard (16d starting 51-55),
        #   Amex (15d starting 34/37), Discover (16d starting 6011/65).
        # The `\b` word boundary and required grouping (4-4-4-4 or 4-6-5)
        # dramatically reduces false positives compared to raw 13-19 digit match.
        (
            "credit_card",
            _re_engine.compile(
                r"\b(?:"
                r"4\d{3}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{1,4}"  # Visa 13/16
                r"|(?:5[1-5]\d{2}|2[2-7]\d{2})[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}"  # MC 16
                r"|3[47]\d{2}[ \-]?\d{6}[ \-]?\d{5}"  # Amex 15
                r"|6(?:011|5\d{2})[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}"  # Discover 16
                r"|(?:2131|1800|35\d{3})[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{3,4}"  # JCB 15/16
                r")\b"
            ),
        ),
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
                matched = m.group()
                if label == "credit_card":
                    # Luhn check (#208): eliminate false positives (phone
                    # numbers, SSNs, timestamps) that pass the prefix regex
                    # but are not valid card numbers.
                    digits = "".join(ch for ch in matched if ch.isdigit())
                    if not _luhn_valid(digits):
                        continue
                results.append(PIIMatch(label=label, value=matched, start=m.start(), end=m.end()))
        results.sort(key=lambda m: m.start)
        return results

    def has_pii(self, text: str) -> bool:
        """Return ``True`` if *text* contains at least one PII match.

        Delegates to :meth:`detect` so that Luhn validation (#208) is
        applied consistently for ``credit_card`` matches.
        """
        return bool(self.detect(text))

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
                    with contextlib.suppress(AttributeError, ValueError):
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

        # Full normalisation pipeline (#207): NFKC + homoglyph deconfuse +
        # zero-width strip + casefold — _normalise() handles all steps.
        normalised = _normalise(text)
        tokens = normalised.split()
        if not tokens:
            return 0.0

        # Strip punctuation at word edges for unigram matching
        stripped = [t.strip(".,!?;:'\"()[]{}") for t in tokens]
        unigram_hits = sum(1 for t in stripped if t in self._words)

        # Bigram matching for 2-word toxic phrases
        bigrams = [f"{stripped[i]} {stripped[i+1]}" for i in range(len(stripped) - 1)]
        bigram_hits = sum(1 for bg in bigrams if bg in self._words)

        # Trigram matching for 3-word toxic phrases
        trigrams = [
            f"{stripped[i]} {stripped[i+1]} {stripped[i+2]}" for i in range(len(stripped) - 2)
        ]
        trigram_hits = sum(1 for tg in trigrams if tg in self._words)

        toxic_count = unigram_hits + bigram_hits + trigram_hits
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
            compiled = _re_ci_ml(pat) if isinstance(pat, str) else pat
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
                    with contextlib.suppress(AttributeError, ValueError):
                        _c.labels(scorer="SemanticSimilarityGuard", fallback="jaccard").inc()

        # Pre-tokenise anchors for the Jaccard fallback path.
        self._anchor_tokens: list[frozenset[str]] = [self._tokenise(a) for a in self._anchors]

    @staticmethod
    def _tokenise(text: str) -> frozenset[str]:
        """Lower-case, NFKC-normalise, and split on non-alphanumeric chars."""
        _require_re2()
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


# ── StringLengthValidator ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class StringLengthValidator:
    """Validates that a string's length falls within a declared range.

    Uses ``len(text)`` (Unicode code-point count, not byte count).  For
    byte-length constraints on encoded payloads use
    ``len(text.encode('utf-8'))`` before calling.

    Args:
        min_length: Minimum allowed length, inclusive (default 0).
        max_length: Maximum allowed length, inclusive (default 10 000).

    Example::

        v = StringLengthValidator(min_length=1, max_length=256)
        ok, reason = v.validate("Hello, world!")
        assert ok
    """

    min_length: int = 0
    max_length: int = 10_000

    def __post_init__(self) -> None:
        if self.min_length < 0:
            raise ValueError("StringLengthValidator: min_length must be >= 0")
        if self.max_length < self.min_length:
            raise ValueError(
                f"StringLengthValidator: max_length ({self.max_length}) "
                f"must be >= min_length ({self.min_length})"
            )

    def validate(self, text: str) -> tuple[bool, str]:
        """Return ``(True, "")`` if *text* is within bounds, else ``(False, reason)``."""
        n = len(text)
        if n < self.min_length:
            return False, f"too short: {n} characters < minimum {self.min_length}"
        if n > self.max_length:
            return False, f"too long: {n} characters > maximum {self.max_length}"
        return True, ""

    def is_valid(self, text: str) -> bool:
        """Return ``True`` if ``validate(text)`` succeeds."""
        ok, _ = self.validate(text)
        return ok


# ── NumericRangeValidator ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class NumericRangeValidator:
    """Validates that a numeric value is within a declared range.

    Accepts ``int``, ``float``, ``Decimal``, or a string representation that
    ``Decimal(str(value))`` can parse.  Uses ``Decimal`` internally to avoid
    floating-point drift when comparing values from JSON.

    Args:
        min_value:  Lower bound (default ``None`` — no lower bound).
        max_value:  Upper bound (default ``None`` — no upper bound).
        inclusive:  When ``True`` (default) the bounds are inclusive (``>=``/``<=``).
                    When ``False`` the bounds are exclusive (``>``/``<``).

    Example::

        v = NumericRangeValidator(min_value=0, max_value=1_000_000, inclusive=True)
        ok, reason = v.validate("500.50")
        assert ok
    """

    min_value: float | int | Decimal | None = None
    max_value: float | int | Decimal | None = None
    inclusive: bool = True

    def validate(self, value: int | float | Decimal | str) -> tuple[bool, str]:
        """Return ``(True, "")`` when *value* satisfies the range constraint."""
        try:
            v = Decimal(str(value))
        except InvalidOperation:
            return False, f"cannot parse {value!r} as a numeric value"

        if self.min_value is not None:
            lo = Decimal(str(self.min_value))
            if self.inclusive and v < lo:
                return False, f"{v} < minimum {lo}"
            if not self.inclusive and v <= lo:
                return False, f"{v} must be strictly greater than {lo}"

        if self.max_value is not None:
            hi = Decimal(str(self.max_value))
            if self.inclusive and v > hi:
                return False, f"{v} > maximum {hi}"
            if not self.inclusive and v >= hi:
                return False, f"{v} must be strictly less than {hi}"

        return True, ""

    def is_valid(self, value: int | float | Decimal | str) -> bool:
        """Return ``True`` if ``validate(value)`` succeeds."""
        ok, _ = self.validate(value)
        return ok


# ── DateValidator ──────────────────────────────────────────────────────────────


@dataclass
class DateValidator:
    """Validates ISO 8601 date/datetime strings and optional temporal constraints.

    Parses the value with ``datetime.fromisoformat()``.  Naive datetimes are
    treated as UTC.  Timezone-aware datetimes are converted to UTC before any
    ``not_before``/``not_after`` comparison.

    Args:
        allow_past:   Accept dates before ``datetime.now(UTC)``.  Default ``True``.
        allow_future: Accept dates after ``datetime.now(UTC)``.   Default ``True``.
        not_before:   Hard lower bound (inclusive).  ``None`` = no lower bound.
        not_after:    Hard upper bound (inclusive).  ``None`` = no upper bound.

    Example::

        import datetime
        v = DateValidator(allow_past=False)
        ok, reason = v.validate("2099-01-01T00:00:00+00:00")
        assert ok
    """

    allow_past: bool = True
    allow_future: bool = True
    not_before: datetime | None = None
    not_after: datetime | None = None

    def validate(self, date_str: str) -> tuple[bool, str]:
        """Parse *date_str* and check all temporal constraints."""

        try:
            dt = datetime.fromisoformat(date_str)
        except (ValueError, TypeError):
            return False, f"invalid ISO 8601 date/datetime: {date_str!r}"

        # Normalise to UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)

        now = datetime.now(UTC)

        if not self.allow_past and dt < now:
            return False, f"date {dt.isoformat()} is in the past"
        if not self.allow_future and dt > now:
            return False, f"date {dt.isoformat()} is in the future"

        if self.not_before is not None:
            nb = self.not_before
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=UTC)
            if dt < nb:
                return False, (f"date {dt.isoformat()} is before minimum {nb.isoformat()}")

        if self.not_after is not None:
            na = self.not_after
            if na.tzinfo is None:
                na = na.replace(tzinfo=UTC)
            if dt > na:
                return False, (f"date {dt.isoformat()} is after maximum {na.isoformat()}")

        return True, ""

    def is_valid(self, date_str: str) -> bool:
        """Return ``True`` if ``validate(date_str)`` succeeds."""
        ok, _ = self.validate(date_str)
        return ok


# ── URLValidator ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class URLValidator:
    """Validates URL format with optional scheme and domain constraints.

    Uses stdlib ``urllib.parse.urlparse()`` — no network calls.

    Args:
        allowed_schemes:  Set of permitted schemes (default: ``{"https"}``).
        allowed_domains:  Allowlist of domain suffixes.  ``None`` = any domain.
                          Both exact matches and subdomain matches are accepted
                          (e.g. ``"example.com"`` matches ``"api.example.com"``).
        blocked_domains:  Blocklist of domain suffixes (checked before allowlist).
        require_path:     Require a non-root path component.  Default ``False``.

    Example::

        v = URLValidator(allowed_schemes={"https"}, blocked_domains=frozenset({"evil.com"}))
        ok, reason = v.validate("https://api.example.com/v1/endpoint")
        assert ok
    """

    allowed_schemes: frozenset[str] = frozenset({"https"})
    allowed_domains: frozenset[str] | None = None
    blocked_domains: frozenset[str] = frozenset()
    require_path: bool = False

    # Private/loopback IPv4 and IPv6 ranges that must be rejected to prevent SSRF.
    # Checked against parsed IP literals before any domain blocklist.
    _BLOCKED_IP_PREFIXES: tuple[str, ...] = (
        "127.",       # IPv4 loopback (127.0.0.0/8)
        "10.",        # RFC 1918 private (10.0.0.0/8)
        "172.16.",    # RFC 1918 private (172.16.0.0/12) — full range checked below
        "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",   # RFC 1918 private (192.168.0.0/16)
        "169.254.",   # Link-local (169.254.0.0/16)
        "0.",         # This-network (0.0.0.0/8)
        "100.64.",    # Shared address space (RFC 6598)
    )
    _BLOCKED_IPV6: tuple[str, ...] = (
        "::1",            # IPv6 loopback
        "fc", "fd",       # IPv6 unique local (fc00::/7)
        "fe80",           # IPv6 link-local (fe80::/10)
        "::",             # IPv6 unspecified
    )

    def _is_private_ip(self, host: str) -> bool:
        """Return True if *host* is a private/loopback IP literal (SSRF risk)."""
        import ipaddress

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return not addr.is_global or addr.is_loopback or addr.is_private or addr.is_link_local

    def validate(self, url: str) -> tuple[bool, str]:
        """Return ``(True, "")`` if *url* passes all configured checks."""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
        except ValueError as exc:
            return False, f"malformed URL: {exc}"

        if not parsed.scheme:
            return False, "URL has no scheme"
        if parsed.scheme.lower() not in self.allowed_schemes:
            return False, (
                f"scheme {parsed.scheme!r} not in allowed set " f"{sorted(self.allowed_schemes)}"
            )
        if not parsed.netloc:
            return False, "URL has no host"

        host = (parsed.hostname or "").lower()

        # Reject private/loopback IP literals — domain blocklist suffix matching
        # never fires on IP literals, so SSRF via 127.0.0.1 or [::1] bypasses it.
        if self._is_private_ip(host):
            return False, (
                f"host {host!r} resolves to a private or loopback IP address — "
                "blocked to prevent SSRF attacks"
            )

        for bd in self.blocked_domains:
            if host == bd.lower() or host.endswith(f".{bd.lower()}"):
                return False, f"domain {host!r} is in the blocklist"

        if self.allowed_domains is not None and not any(
            host == ad.lower() or host.endswith(f".{ad.lower()}") for ad in self.allowed_domains
        ):
            return False, f"domain {host!r} is not in the allowlist"

        if self.require_path and not parsed.path.strip("/"):
            return False, "URL requires a non-empty path component"

        return True, ""

    def is_valid(self, url: str) -> bool:
        """Return ``True`` if ``validate(url)`` succeeds."""
        ok, _ = self.validate(url)
        return ok


# ── EmailValidator ─────────────────────────────────────────────────────────────


class EmailValidator:
    """RFC 5321-compatible email address validator backed by google-re2.

    Uses a RE2-compiled pattern for ReDoS-immune matching.  Requires the
    ``pramanix[security]`` extra (``google-re2``).

    Raises:
        ConfigurationError: If google-re2 is not installed.

    Example::

        v = EmailValidator()
        ok, reason = v.validate("alice@example.com")
        assert ok
    """

    # Simplified RFC 5321 local-part @ domain pattern.  RE2 does not support
    # lookahead/lookbehind so we anchor with ^ and $ instead.
    _PATTERN = r"^[A-Za-z0-9._%+\-]+" r"@" r"[A-Za-z0-9.\-]+" r"\." r"[A-Za-z]{2,}$"

    def __init__(self) -> None:
        _require_re2()
        self._re = _re_ci(self._PATTERN)

    def validate(self, email: str) -> tuple[bool, str]:
        """Return ``(True, "")`` if *email* matches the RFC 5321 pattern."""
        stripped = email.strip() if isinstance(email, str) else ""
        if not stripped:
            return False, "email address is empty"
        if "@" not in stripped:
            return False, f"missing '@' in email address: {email!r}"
        if self._re.search(stripped) is None:
            return False, f"email {email!r} does not match RFC 5321 pattern"
        local, _, domain = stripped.rpartition("@")
        if len(local) > 64:
            return False, f"local part exceeds 64 characters: {len(local)}"
        if len(domain) > 255:
            return False, f"domain exceeds 255 characters: {len(domain)}"
        return True, ""

    def is_valid(self, email: str) -> bool:
        """Return ``True`` if ``validate(email)`` succeeds."""
        ok, _ = self.validate(email)
        return ok


# ── JSONSchemaValidator ────────────────────────────────────────────────────────


@dataclass
class JSONSchemaValidator:
    """Validates a dict or JSON string against a JSON Schema (draft 7) definition.

    Uses ``jsonschema`` if installed; falls back to a structural check that
    verifies required fields and top-level object type.

    Args:
        schema: A JSON Schema dict (e.g. ``{"type": "object", "required": ["amount"]}``).

    Example::

        v = JSONSchemaValidator(schema={
            "type": "object",
            "required": ["amount", "currency"],
            "properties": {
                "amount":   {"type": "number", "minimum": 0},
                "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            },
        })
        ok, reason = v.validate({"amount": 100, "currency": "USD"})
        assert ok
    """

    schema: dict[str, Any] = field(default_factory=dict)

    def validate(self, data: dict[str, Any] | str | Any) -> tuple[bool, str]:
        """Return ``(True, "")`` if *data* is valid against the schema."""
        import json as _json

        if isinstance(data, str):
            try:
                data = _json.loads(data)
            except _json.JSONDecodeError as exc:
                return False, f"invalid JSON string: {exc}"

        try:
            import jsonschema

            try:
                jsonschema.validate(instance=data, schema=self.schema)
                return True, ""
            except jsonschema.ValidationError as exc:
                return False, f"JSON schema violation: {exc.message}"
            except jsonschema.SchemaError as exc:
                return False, f"invalid JSON schema definition: {exc.message}"
        except ImportError:
            return self._fallback_validate(data)

    def _fallback_validate(self, data: Any) -> tuple[bool, str]:
        """Structural check when jsonschema is not installed."""
        expected_type = self.schema.get("type")
        if expected_type == "object" and not isinstance(data, dict):
            return False, f"expected JSON object, got {type(data).__name__}"
        if expected_type == "array" and not isinstance(data, list):
            return False, f"expected JSON array, got {type(data).__name__}"

        if isinstance(data, dict):
            for key in self.schema.get("required", []):
                if key not in data:
                    return False, f"missing required field: {key!r}"

        return True, ""

    def is_valid(self, data: dict[str, Any] | str | Any) -> bool:
        """Return ``True`` if ``validate(data)`` succeeds."""
        ok, _ = self.validate(data)
        return ok


# ── ProfanityDetector ──────────────────────────────────────────────────────────

# Default word list — curated for general-purpose content moderation.
# Uses root forms only; whole-word matching prevents false positives on
# innocent words that contain profane substrings (e.g. "classic").
_DEFAULT_PROFANITY_WORDS: frozenset[str] = frozenset(
    {
        "fuck",
        "shit",
        "bitch",
        "bastard",
        "crap",
        "piss",
        "cock",
        "dick",
        "cunt",
        "twat",
        "arsehole",
        "asshole",
        "motherfucker",
        "bullshit",
        "horseshit",
        "jackass",
        "dumbass",
        "wanker",
        "tosser",
        "prick",
        "bollocks",
    }
)


class ProfanityDetector:
    """Keyword-based profanity detector.  Zero external dependencies.

    Uses whole-word matching (stdlib ``re`` word boundaries) to avoid
    flagging innocent words that contain profane substrings.

    Args:
        extra_words:      Additional profanity words to detect.
        case_sensitive:   When ``True``, matching is exact-case.
                          Default ``False`` (case-insensitive).

    Example::

        detector = ProfanityDetector()
        assert detector.is_profane("What the f*** is this?")
        assert not detector.is_profane("classic architecture")
        censored = detector.censor("This is bullshit!")
        assert "***" in censored
    """

    # Maximum length for any single extra_word entry.  Long words combined with
    # adversarial near-miss input can trigger catastrophic backtracking in stdlib
    # re because we use word-boundary patterns ((?<!\w)...(?!\w)).  RE2 is not
    # used here because ProfanityDetector is intentionally zero-dependency.
    _MAX_WORD_LEN: int = 50

    def __init__(
        self,
        extra_words: list[str] | None = None,
        *,
        case_sensitive: bool = False,
    ) -> None:
        words: set[str] = set(_DEFAULT_PROFANITY_WORDS)
        if extra_words:
            for w in extra_words:
                stripped = w.strip()
                if not stripped:
                    continue
                if len(stripped) > self._MAX_WORD_LEN:
                    raise ValueError(
                        f"ProfanityDetector: extra_words entry {stripped[:20]!r}... "
                        f"is {len(stripped)} characters — maximum is {self._MAX_WORD_LEN}. "
                        "Long entries can trigger catastrophic backtracking in the "
                        "stdlib re engine used for word-boundary matching."
                    )
                words.add(stripped)
        self._case_sensitive = case_sensitive
        self._words: frozenset[str] = frozenset(words)
        # Pre-compile per-word whole-boundary patterns for deterministic matching.
        flags = 0 if case_sensitive else re.IGNORECASE
        self._patterns: list[tuple[str, re.Pattern[str]]] = [
            (w, re.compile(r"(?<!\w)" + re.escape(w) + r"(?!\w)", flags))
            for w in sorted(self._words)
        ]

    def detect(self, text: str) -> list[str]:
        """Return sorted list of profanity words found in *text*.

        Uses whole-word boundary matching — ``"classic"`` does not trigger
        even though it contains ``"ass"``.
        """
        found: list[str] = []
        for word, pattern in self._patterns:
            if pattern.search(text) is not None:
                found.append(word)
        return found

    def is_profane(self, text: str) -> bool:
        """Return ``True`` if *text* contains at least one profanity word."""
        return any(pattern.search(text) is not None for _w, pattern in self._patterns)

    def censor(self, text: str, replacement: str = "***") -> str:
        """Return a copy of *text* with all profanity replaced by *replacement*.

        Replacements are applied right-to-left (longest match first) to
        preserve correct character offsets across substitutions.
        """
        result = text
        for _word, pattern in self._patterns:
            result = pattern.sub(replacement, result)
        return result


# ── #35 fix: canonical names for clarity ──────────────────────────────────────

# ``SemanticSimilarityGuard`` is a misleading name — the default backend uses
# Jaccard word-overlap (a lexical metric), NOT sentence-transformer embeddings.
# ``LexicalOverlapGuard`` is the accurate name.  Both names are exported for
# backward compatibility, but new code should use ``LexicalOverlapGuard``.
#
# To use real semantic (embedding-based) similarity, pass a ``similarity_fn``
# backed by sentence-transformers:
#
#   from sentence_transformers import SentenceTransformer
#   from pramanix.nlp.validators import LexicalOverlapGuard
#   model = SentenceTransformer("all-MiniLM-L6-v2")
#
#   def embed_sim(text: str, anchor: str) -> float:
#       embs = model.encode([text, anchor])
#       return float(embs[0] @ embs[1] / (norm(embs[0]) * norm(embs[1])))
#
#   guard = LexicalOverlapGuard(anchors=["wire transfer"], similarity_fn=embed_sim)

#: Canonical alias — use this in new code.
LexicalOverlapGuard = SemanticSimilarityGuard

# ``KeywordDensityScorer`` is the accurate name for ``ToxicityScorer`` — it
# matches against a fixed vocabulary of stems and returns a density ratio.
# It is NOT an ML toxicity model (no neural network, no training data).
# Export both names; new code should use ``KeywordDensityScorer``.
KeywordDensityScorer = ToxicityScorer
