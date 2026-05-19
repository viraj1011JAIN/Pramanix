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
"""
from __future__ import annotations

import re
import unicodedata
from decimal import Decimal

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from pramanix.exceptions import InputTooLongError
from pramanix.translator._sanitise import injection_confidence_score, sanitise_user_input

# ── Strategies ────────────────────────────────────────────────────────────────

# Amount values: strings, numbers, and values that cause Decimal() to raise.
_amount_values = st.one_of(
    st.decimals(allow_nan=True, allow_infinity=True),
    st.integers(min_value=-10**18, max_value=10**18),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=30),
    st.none(),
    st.just({}),
    st.just([]),
)

# ID-like field names that trigger the non-word-char signal.
_ID_SUFFIXES = ["_id", "_key", "_token", "_ref", "_number", "_code", "_account", "_address"]


@st.composite
def _extracted_intent(draw: st.DrawFn) -> dict:
    """Build a dict that may or may not include 'amount' and ID-like fields."""
    d: dict = {}
    if draw(st.booleans()):
        d["amount"] = draw(_amount_values)
    if draw(st.booleans()):
        # Add an ID-like field — may contain non-word chars to trigger the +0.3 signal
        suffix = draw(st.sampled_from(_ID_SUFFIXES))
        field_name = draw(st.text(min_size=1, max_size=10, alphabet=st.characters(
            whitelist_categories=("Ll", "Lu")
        ))) + suffix
        d[field_name] = draw(st.text(max_size=40))
    return d


@st.composite
def _warnings(draw: st.DrawFn) -> list[str]:
    """Build a warnings list that may include real or synthetic warning strings."""
    base = draw(st.lists(st.text(max_size=50), max_size=4))
    # Occasionally inject the real injection-pattern warning tag
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

# ── P-1 / P-2: Score always in [0.0, 1.0] and is a float ─────────────────────


@given(
    user_input=st.text(max_size=300),
    extracted_intent=_extracted_intent(),
    warnings=_warnings(),
    sub_penny_threshold=_sub_penny_threshold,
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_score_always_in_unit_interval(
    user_input: str,
    extracted_intent: dict,
    warnings: list[str],
    sub_penny_threshold: Decimal,
) -> None:
    """P-1 + P-2: score ∈ [0.0, 1.0] for every possible combination of signals."""
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=sub_penny_threshold,
    )
    assert isinstance(score, float), f"expected float, got {type(score)}"
    assert 0.0 <= score <= 1.0, f"score {score} out of [0.0, 1.0]"


# ── P-3: Empty warnings never contribute injection-pattern points ──────────────


@given(
    user_input=st.text(min_size=10, max_size=200, alphabet=st.characters(
        # Exclude ASCII (avoids injection keywords and high-entropy token pattern)
        blacklist_categories=("Cs",),
        blacklist_characters="".join(chr(i) for i in range(0x80)),
    )),
    extracted_intent=st.just({}),
    sub_penny_threshold=_sub_penny_threshold,
)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_empty_warnings_no_injection_pattern_signal(
    user_input: str,
    extracted_intent: dict,
    sub_penny_threshold: Decimal,
) -> None:
    """P-3: With empty warnings and no ASCII (so no high-entropy regex match),
    extracted_intent={}, and input length >=10 AFTER stripping, score must be 0.0.

    Some non-ASCII characters (e.g. U+00A0 NO-BREAK SPACE) are Unicode whitespace
    and are removed by str.strip(), which can shrink a 10-char string below the
    threshold.  We use assume() to skip such edge-case inputs.
    """
    assume(len(user_input.strip()) >= 10)
    score = injection_confidence_score(
        user_input, extracted_intent, [], sub_penny_threshold=sub_penny_threshold
    )
    # With no warnings, no amount, strip-len>=10, and non-ASCII text the score is 0.0.
    # (The high-entropy regex [A-Za-z0-9+/]{20,} won't match all-Unicode text.)
    assert score == 0.0


# ── P-4: Injection-pattern warning always drives score >= 0.6 ─────────────────


@given(
    user_input=st.text(max_size=300),
    extracted_intent=_extracted_intent(),
    extra_warnings=st.lists(st.text(max_size=50), max_size=3),
    sub_penny_threshold=_sub_penny_threshold,
)
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_injection_pattern_warning_drives_score_to_at_least_0_6(
    user_input: str,
    extracted_intent: dict,
    extra_warnings: list[str],
    sub_penny_threshold: Decimal,
) -> None:
    """P-4: Any warnings list that contains 'injection_patterns_detected' must
    yield a score >= 0.6 (the base weight of that signal)."""
    warnings = extra_warnings + ["injection_patterns_detected: test"]
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=sub_penny_threshold,
    )
    assert score >= 0.6, f"expected >= 0.6 with injection warning, got {score}"


# ── P-5: Score for fully benign conditions is exactly 0.0 ─────────────────────


def test_score_is_zero_for_fully_benign_input() -> None:
    """P-5: A clearly benign input with no signals scores 0.0."""
    score = injection_confidence_score(
        "Pay Alice one hundred dollars.",  # > 10 chars, no injection keywords
        {},                                 # no amount, no ID fields
        [],                                 # no warnings
        sub_penny_threshold=Decimal("0.10"),
    )
    assert score == 0.0


# ── Bounds stress test: worst-case simultaneous signals ───────────────────────


def test_all_signals_simultaneously_capped_at_1_0() -> None:
    """All six signals fire at once: result must be exactly 1.0 (not > 1.0)."""
    # injection_patterns: +0.6 via warning
    # short input: +0.2 via len < 10 (but high-entropy needs 20+ chars — tested separately)
    # unparseable amount: +0.4 via exception path (takes priority over sub-penny)
    # non-word ID field: +0.3 via '!' in user_id
    # high-entropy: +0.2 via base64-like token in user_input
    user_input = "AAAAAAAAAAAAAAAAAAAAAA"  # 22 chars, matches [A-Za-z0-9+/]{20,}
    extracted_intent = {
        "amount": {},           # dict → str({}) → Decimal raises → +0.4
        "user_id": "x!/y",      # non-word char → +0.3
    }
    warnings = ["injection_patterns_detected: ['jailbreak']"]
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=Decimal("0.10"),
    )
    # 0.6 + 0.4 + 0.3 + 0.2 = 1.5, capped → 1.0
    assert score == 1.0


def test_sub_penny_and_injection_capped_at_1_0() -> None:
    """Sub-penny + injection warning + ID field + high-entropy token = 1.4 → 1.0."""
    user_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAA"  # > 20 chars base64-like → +0.2
    extracted_intent = {
        "amount": "0.001",    # 0 < 0.001 < 0.10 → +0.3
        "account_id": "x;y",  # non-word char → +0.3
    }
    warnings = ["injection_patterns_detected: ['ignore all']"]  # +0.6
    score = injection_confidence_score(
        user_input,
        extracted_intent,
        warnings,
        sub_penny_threshold=Decimal("0.10"),
    )
    # 0.6 + 0.3 + 0.3 + 0.2 = 1.4 → capped at 1.0
    assert score == 1.0


# ── sanitise_user_input property tests ────────────────────────────────────────


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@given(raw=st.text(max_size=400))
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_sanitise_short_input_never_raises(raw: str) -> None:
    """S-1 + S-3: inputs short enough after NFKC never raise; return is (str, list)."""
    normalised = unicodedata.normalize("NFKC", raw)
    assume(len(normalised) <= 512)
    cleaned, warnings = sanitise_user_input(raw)
    assert isinstance(cleaned, str)
    assert isinstance(warnings, list)
    assert all(isinstance(w, str) for w in warnings)


@given(raw=st.text(max_size=400))
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_sanitise_output_has_no_stripped_control_chars(raw: str) -> None:
    """S-2: Output never contains C0 control codes in the stripped range."""
    normalised = unicodedata.normalize("NFKC", raw)
    assume(len(normalised) <= 512)
    cleaned, _ = sanitise_user_input(raw)
    assert _CONTROL_RE.search(cleaned) is None, (
        f"Control char found in sanitised output: {cleaned!r}"
    )


@given(raw=st.text(min_size=1, max_size=50))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_sanitise_raises_for_over_limit_input(raw: str) -> None:
    """S-4: Inputs longer than max_length (after NFKC) always raise InputTooLongError."""
    normalised = unicodedata.normalize("NFKC", raw)
    # Use a very small max_length that the normalised text is sure to exceed
    tiny_limit = max(0, len(normalised) - 1)
    assume(tiny_limit < len(normalised))  # skip degenerate case where limit == len
    with pytest.raises(InputTooLongError):
        sanitise_user_input(raw, max_length=tiny_limit)


@given(raw=st.text(max_size=200))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_sanitise_unicode_normalised_warning_iff_nfkc_changes_text(raw: str) -> None:
    """S-5: 'unicode_normalised' appears in warnings iff NFKC changes the text."""
    normalised = unicodedata.normalize("NFKC", raw)
    assume(len(normalised) <= 512)
    _cleaned, warnings = sanitise_user_input(raw)
    nfkc_changed = (normalised != raw)
    warning_present = any("unicode_normalised" in w for w in warnings)
    assert nfkc_changed == warning_present, (
        f"NFKC changed={nfkc_changed} but unicode_normalised warning present={warning_present}"
    )
