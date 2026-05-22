# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Hypothesis property tests for injection_confidence_score and sanitise_user_input.

Properties verified for injection_confidence_score:
P-1. Score always in [0.0, 1.0] regardless of all signal combinations.
P-2. Score is a Python float (not int or Decimal).
P-3. Empty warnings list never contributes injection-pattern points.
P-4. Explicit injection-pattern warning always drives score >= 0.6.
P-5. Score for benign conditions is 0.0.

Properties verified for sanitise_user_input:
S-1. Short inputs (after NFKC) never raise.
S-2. Output contains no C0 control characters in the stripped range.
S-3. Output is a (str, list[str]) tuple.
S-4. Inputs longer than max_length (after NFKC) always raise InputTooLongError.
S-5. NFKC normalisation never produces output longer than max_length when
     input is sufficiently short (unicode_normalised warning correlates).

Edge-case unit tests (excluded from Hypothesis by strategy design):
E-1. Empty string does not raise; returns ("", []).
E-2. Single character does not raise.
E-3. Whitespace-only string does not raise.
E-4. Two-character injection prefix does not raise.
E-5. 512-char input does not raise (at the default limit).
E-6. 513-char input raises InputTooLongError.
E-7. 1024-char input raises InputTooLongError.
E-8. Empty string scores 0.0 (no short-input signal for len == 0).
E-9. Single ASCII char scores >= 0.2 (short-input signal fires for 1 <= len < 10).
E-10. Whitespace-only string scores 0.0 (stripped = empty, no short-input signal).
"""

from __future__ import annotations

import re
import unicodedata
from datetime import timedelta
from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pramanix.exceptions import InputTooLongError
from pramanix.translator._sanitise import (
    injection_confidence_score,
    sanitise_user_input,
)

# ── Strategies ────────────────────────────────────────────────────────────────

# Amount values: strings, numbers, and values that cause Decimal() to raise.
_amount_values = st.one_of(
    st.decimals(allow_nan=True, allow_infinity=True),
    st.integers(min_value=-(10**18), max_value=10**18),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=30),
    st.none(),
    st.just({}),
    st.just([]),
)

# ID-like field names that trigger the non-word-char signal.
_ID_SUFFIXES = [
    "_id",
    "_key",
    "_token",
    "_ref",
    "_number",
    "_code",
    "_account",
    "_address",
]


@st.composite
def _extracted_intent(draw: st.DrawFn) -> dict:
    """Build a dict that may or may not include 'amount' and ID-like fields."""
    d: dict = {}
    if draw(st.booleans()):
        d["amount"] = draw(_amount_values)
    if draw(st.booleans()):
        suffix = draw(st.sampled_from(_ID_SUFFIXES))
        prefix = draw(
            st.text(
                min_size=1,
                max_size=10,
                alphabet=st.characters(whitelist_categories=("Ll", "Lu")),
            )
        )
        d[prefix + suffix] = draw(st.text(max_size=40))
    return d


@st.composite
def _warnings(draw: st.DrawFn) -> list[str]:
    """Build a warnings list that may include real or synthetic warning strings."""
    base = draw(st.lists(st.text(max_size=50), max_size=4))
    if draw(st.booleans()):
        base.append("injection_patterns_detected: ['something']")
    return base


_sub_penny_threshold = st.decimals(
    min_value=Decimal("0"),
    max_value=Decimal("10"),
    allow_nan=False,
    allow_infinity=False,
    places=8,
)

# Strategy for P-3: non-ASCII text guaranteed not to be stripped by .strip().
# Excludes surrogates (Cs) and Unicode separator categories (Zs, Zl, Zp)
# so that strip() never reduces the string below min_size.
_non_ascii_non_whitespace = st.text(
    min_size=10,
    max_size=200,
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Lo", "Mn", "Nd", "No"),
        blacklist_characters="".join(chr(i) for i in range(0x80)),
    ),
)

# Strategies for S-1/S-2/S-5: max_size=100 stays well below the 512-char
# default limit even with aggressive NFKC expansion (factor <= 3 in practice).
_short_text = st.text(max_size=100)

# ── P-1 / P-2: Score always in [0.0, 1.0] and is a float ────────────────────


@given(
    user_input=st.text(max_size=300),
    extracted_intent=_extracted_intent(),
    warnings=_warnings(),
    sub_penny_threshold=_sub_penny_threshold,
)
@settings(max_examples=500, deadline=timedelta(milliseconds=500))
def test_score_always_in_unit_interval(
    user_input: str,
    extracted_intent: dict,
    warnings: list[str],
    sub_penny_threshold: Decimal,
) -> None:
    """P-1+P-2: score in [0.0, 1.0] for every possible combination of signals."""
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=sub_penny_threshold,
    )
    assert isinstance(score, float), f"expected float, got {type(score)}"
    assert 0.0 <= score <= 1.0, f"score {score} out of [0.0, 1.0]"


# ── P-3: Empty warnings never contribute injection-pattern points ─────────────


@given(
    user_input=_non_ascii_non_whitespace,
    extracted_intent=st.just({}),
    sub_penny_threshold=_sub_penny_threshold,
)
@settings(max_examples=200, deadline=timedelta(milliseconds=500))
def test_empty_warnings_no_injection_pattern_signal(
    user_input: str,
    extracted_intent: dict,
    sub_penny_threshold: Decimal,
) -> None:
    """P-3: Non-ASCII text with empty warnings and empty intent scores 0.0.

    The strategy generates only non-whitespace, non-ASCII chars so:
    - len(user_input.strip()) >= 10 (no Unicode whitespace to strip)
    - No ASCII chars, so the high-entropy regex [A-Za-z0-9+/]{20,} cannot match
    - extracted_intent is empty, so no amount or ID-field signals
    - Empty warnings means no injection-pattern signal
    Result: all signals at 0 → score == 0.0.
    """
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        [],
        sub_penny_threshold=sub_penny_threshold,
    )
    assert score == 0.0


# ── P-4: Injection-pattern warning always drives score >= 0.6 ────────────────


@given(
    user_input=st.text(max_size=300),
    extracted_intent=_extracted_intent(),
    extra_warnings=st.lists(st.text(max_size=50), max_size=3),
    sub_penny_threshold=_sub_penny_threshold,
)
@settings(max_examples=300, deadline=timedelta(milliseconds=500))
def test_injection_pattern_warning_drives_score_to_at_least_0_6(
    user_input: str,
    extracted_intent: dict,
    extra_warnings: list[str],
    sub_penny_threshold: Decimal,
) -> None:
    """P-4: Any warnings list containing 'injection_patterns_detected' → >= 0.6."""
    warnings = [*extra_warnings, "injection_patterns_detected: test"]
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=sub_penny_threshold,
    )
    assert score >= 0.6, f"expected >= 0.6 with injection warning, got {score}"


# ── P-5: Score for fully benign conditions is exactly 0.0 ────────────────────


def test_score_is_zero_for_fully_benign_input() -> None:
    """P-5: A clearly benign input with no signals scores 0.0."""
    score = injection_confidence_score(
        "Pay Alice one hundred dollars.",
        {},
        [],
        sub_penny_threshold=Decimal("0.10"),
    )
    assert score == 0.0


# ── Bounds stress test: worst-case simultaneous signals ──────────────────────


def test_four_signals_simultaneously_capped_at_1_0() -> None:
    """Four signals fire at once: result must be exactly 1.0 (not > 1.0)."""
    user_input = "AAAAAAAAAAAAAAAAAAAAAA"  # 22 chars → +0.2 high-entropy
    extracted_intent = {
        "amount": {},  # dict → Decimal raises → +0.4
        "user_id": "x!/y",  # non-word char → +0.3
    }
    warnings = ["injection_patterns_detected: ['jailbreak']"]  # +0.6
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=Decimal("0.10"),
    )
    assert score == 1.0  # 0.6 + 0.4 + 0.3 + 0.2 = 1.5 → capped


def test_sub_penny_and_injection_capped_at_1_0() -> None:
    """Sub-penny + injection warning + ID field + high-entropy → 1.4 → 1.0."""
    user_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAA"  # > 20 chars → +0.2
    extracted_intent = {
        "amount": "0.001",  # 0 < 0.001 < 0.10 → +0.3
        "account_id": "x;y",  # non-word char → +0.3
    }
    warnings = ["injection_patterns_detected: ['ignore all']"]  # +0.6
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=Decimal("0.10"),
    )
    assert score == 1.0  # 0.6 + 0.3 + 0.3 + 0.2 = 1.4 → capped


# ── sanitise_user_input property tests ───────────────────────────────────────


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@given(raw=_short_text)
@settings(max_examples=500, deadline=timedelta(milliseconds=500))
def test_sanitise_short_input_never_raises(raw: str) -> None:
    """S-1+S-3: inputs short enough after NFKC never raise; return is (str, list).

    max_size=100 keeps the NFKC-normalised length well below the 512-char
    default limit (a 100-char string would need > 5x NFKC expansion to hit
    the limit, which does not occur for any known Unicode block).
    """
    cleaned, warnings = sanitise_user_input(raw)
    assert isinstance(cleaned, str)
    assert isinstance(warnings, list)
    assert all(isinstance(w, str) for w in warnings)


@given(raw=_short_text)
@settings(max_examples=500, deadline=timedelta(milliseconds=500))
def test_sanitise_output_has_no_stripped_control_chars(raw: str) -> None:
    """S-2: Output never contains C0 control codes in the stripped range."""
    cleaned, _ = sanitise_user_input(raw)
    assert (
        _CONTROL_RE.search(cleaned) is None
    ), f"Control char found in sanitised output: {cleaned!r}"


@given(raw=st.text(min_size=2, max_size=50))
@settings(max_examples=300, deadline=timedelta(milliseconds=500))
def test_sanitise_raises_for_over_limit_input(raw: str) -> None:
    """S-4: Inputs longer than max_length (after NFKC) raise InputTooLongError.

    min_size=2 ensures the NFKC-normalised form always has at least one
    character, so tiny_limit = len(normalised) - 1 is always strictly less
    than len(normalised) and the over-limit condition always fires.
    """
    normalised = unicodedata.normalize("NFKC", raw)
    tiny_limit = max(0, len(normalised) - 1)
    if tiny_limit >= len(normalised):
        return  # degenerate: normalised is empty; skip without assume()
    with pytest.raises(InputTooLongError):
        sanitise_user_input(raw, max_length=tiny_limit)


@given(raw=st.text(max_size=200))
@settings(max_examples=300, deadline=timedelta(milliseconds=500))
def test_sanitise_unicode_normalised_warning_iff_nfkc_changes_text(
    raw: str,
) -> None:
    """S-5: 'unicode_normalised' in warnings iff NFKC changes the text."""
    normalised = unicodedata.normalize("NFKC", raw)
    if len(normalised) > 511:
        return  # NFKC expansion pushed over limit; skip without assume()
    _cleaned, warnings = sanitise_user_input(raw)
    nfkc_changed = normalised != raw
    warning_present = any("unicode_normalised" in w for w in warnings)
    assert nfkc_changed == warning_present, (
        f"NFKC changed={nfkc_changed} but " f"unicode_normalised warning present={warning_present}"
    )


# ── Edge-case unit tests for inputs excluded by strategy bounds (#32) ────────


class TestSanitiseEdgeCases:
    """Explicit unit tests for inputs excluded from property-test strategies.

    These cover the security-relevant boundaries that Hypothesis cannot
    reach when the strategy uses max_size constraints to avoid InputTooLongError.
    """

    def test_empty_string_does_not_raise(self) -> None:
        """E-1: sanitise_user_input('') returns ('', []) without raising."""
        cleaned, warnings = sanitise_user_input("")
        assert cleaned == ""
        assert warnings == []

    def test_single_char_does_not_raise(self) -> None:
        """E-2: single-character input sanitises without raising."""
        cleaned, _ = sanitise_user_input("A")
        assert isinstance(cleaned, str)

    def test_whitespace_only_does_not_raise(self) -> None:
        """E-3: whitespace-only input sanitises without raising."""
        cleaned, _ = sanitise_user_input("   \t\n")
        assert isinstance(cleaned, str)

    def test_two_char_injection_prefix_does_not_raise(self) -> None:
        """E-4: a 2-char injection prefix ('ig') does not raise."""
        cleaned, _ = sanitise_user_input("ig")
        assert isinstance(cleaned, str)

    def test_512_char_boundary_does_not_raise(self) -> None:
        """E-5: exactly 512 ASCII chars (the default limit) does not raise."""
        cleaned, _ = sanitise_user_input("A" * 512)
        assert len(cleaned) <= 512

    def test_513_char_raises(self) -> None:
        """E-6: 513 ASCII chars (one over the default limit) raises."""
        with pytest.raises(InputTooLongError):
            sanitise_user_input("A" * 513)

    def test_1024_char_raises(self) -> None:
        """E-7: 1024-char input (double the limit) raises InputTooLongError."""
        with pytest.raises(InputTooLongError):
            sanitise_user_input("A" * 1024)


class TestScoreEdgeCases:
    """Explicit unit tests for score inputs excluded by assume() in P-3 (#32).

    The short-input signal fires for 1 <= len(stripped) < 10.
    Empty and whitespace-only strings strip to "" (len == 0) so they do NOT
    trigger the short-input signal and must score 0.0.
    """

    def test_empty_string_scores_zero(self) -> None:
        """E-8: empty string has no short-input signal (0 is not in 1..9)."""
        score = injection_confidence_score("", {}, [], sub_penny_threshold=Decimal("0.10"))
        assert score == 0.0

    def test_single_char_triggers_short_input_signal(self) -> None:
        """E-9: 1-char input (len == 1, in 1..9) → short-input signal (+0.2)."""
        score = injection_confidence_score("A", {}, [], sub_penny_threshold=Decimal("0.10"))
        assert score >= 0.2

    def test_whitespace_only_scores_zero(self) -> None:
        """E-10: whitespace-only input strips to '' → no short-input signal."""
        score = injection_confidence_score("     ", {}, [], sub_penny_threshold=Decimal("0.10"))
        assert score == 0.0

    def test_nine_char_input_triggers_short_input_signal(self) -> None:
        """Boundary: 9 chars is still < 10, so short-input signal fires."""
        score = injection_confidence_score("AAAAAAAAA", {}, [], sub_penny_threshold=Decimal("0.10"))
        assert score >= 0.2

    def test_ten_char_input_does_not_trigger_short_input_signal(self) -> None:
        """Boundary: 10 chars is NOT < 10, so no short-input signal."""
        score = injection_confidence_score(
            "AAAAAAAAAA",  # 10 chars, no injection keywords
            {},
            [],
            sub_penny_threshold=Decimal("0.10"),
        )
        assert score == 0.0
