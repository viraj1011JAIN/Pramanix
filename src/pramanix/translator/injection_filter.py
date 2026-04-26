# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""System 1 fast-path injection filter.

A sub-millisecond regex scanner that kills obviously malicious prompts
*before* they consume any LLM API budget.  This is the zeroth gate in
Pramanix's 5-layer prompt-injection defence pipeline — it runs before
:func:`~pramanix.translator._sanitise.sanitise_user_input` forwards the
text to any LLM.

Design goals
------------
* **Speed** — single pre-compiled alternation regex; target < 1 ms on
  prompts up to 1 000 characters.
* **No external dependencies** — stdlib ``re`` only.
* **Fail-open** — any internal error returns ``(False, "filter_error:...")``.
  The LLM + consensus + post-scoring layers still apply; the filter is an
  optimisation, not a single point of failure.
* **Auditable** — :meth:`InjectionFilter.scan_all` returns every matched
  pattern with its label and matched text, suitable for structured logging.

Usage::

    from pramanix.translator.injection_filter import InjectionFilter
    from pramanix.exceptions import InjectionBlockedError

    _filter = InjectionFilter()

    blocked, reason = _filter.is_injection(prompt)
    if blocked:
        raise InjectionBlockedError(reason)
"""
from __future__ import annotations

import re

__all__ = ["INJECTION_PATTERNS", "InjectionFilter"]


# ── Injection pattern registry ─────────────────────────────────────────
#
# Each entry is (regex_pattern, label).  Labels appear in block-reason
# strings and structured audit logs.  Compiled with re.IGNORECASE.
#
# Coverage:
#   - Classic override / jailbreak phrases (GPT-4, Claude, Gemini)
#   - Open-source model instruction tokens (Llama 2/3, Mistral, ChatML)
#   - Embedded role-escalation JSON
#   - Persona and capability override phrases
#   - Prompt / system-prompt extraction attempts
#   - Direct compliance coercion ("you must comply")
#
from pramanix.translator._injection_patterns import INJECTION_PATTERNS

# Combined alternation compiled once at import time.
_COMBINED_RE: re.Pattern[str] = re.compile(
    "|".join(f"(?:{pat})" for pat, _ in INJECTION_PATTERNS),
    re.IGNORECASE,
)

# Individual patterns compiled for reason attribution (on a hit only).
_INDIVIDUAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pat, re.IGNORECASE), label)
    for pat, label in INJECTION_PATTERNS
]


class InjectionFilter:
    """System 1 fast-path injection filter.

    Scans user input with a single pre-compiled alternation regex designed
    to run in sub-millisecond time on typical prompt lengths (< 1 000 chars).

    Call :meth:`is_injection` before dispatching to any LLM.  When it
    returns ``True`` the caller should raise
    :exc:`~pramanix.exceptions.InjectionBlockedError` immediately — no
    LLM API call should be made.

    The filter is *deliberately conservative*: it blocks on regex match
    regardless of surrounding context.  False positives are acceptable
    because the cost is a clear error message asking the user to rephrase;
    the cost of a missed jailbreak is a compromised guardrail.

    Example::

        f = InjectionFilter()
        blocked, reason = f.is_injection(user_text)
        if blocked:
            raise InjectionBlockedError(reason)
    """

    def is_injection(self, text: str) -> tuple[bool, str]:
        """Scan *text* for injection / jailbreak patterns.

        Uses the combined alternation regex for a single-pass scan.  On a
        hit, walks the individual patterns to produce a precise label for
        the block-reason string.

        Args:
            text: User-supplied prompt.  Should be Unicode-NFKC-normalised
                  before calling (see
                  :func:`~pramanix.translator._sanitise.sanitise_user_input`),
                  but this is not required — the filter is still effective
                  on raw input.

        Returns:
            ``(True, reason)`` if an injection pattern is detected, where
            *reason* is a human-readable string suitable for
            :exc:`~pramanix.exceptions.InjectionBlockedError`.
            ``(False, "")`` if the input appears benign.

        Never raises — any internal error returns
        ``(False, "filter_error:<exc>")``.
        """
        try:
            if not _COMBINED_RE.search(text):
                return False, ""

            # Combined regex hit — find the specific pattern for logging.
            for pattern, label in _INDIVIDUAL_PATTERNS:
                m = pattern.search(text)
                if m:
                    return (
                        True,
                        f"injection_pattern_detected label={label!r} "
                        f"matched={m.group()!r}",
                    )

            # Fallback: combined matched but no individual did.
            return True, "injection_pattern_detected label='unknown'"

        except Exception as exc:
            # Fail-open: never block legitimate requests on a filter bug.
            return False, f"filter_error:{exc}"

    def scan_all(self, text: str) -> list[tuple[str, str]]:
        """Return *all* injection patterns matched in *text*.

        Unlike :meth:`is_injection` which short-circuits on the first
        match, this method walks every individual pattern and collects all
        hits.  Intended for structured audit logging when a complete
        picture of why a prompt was blocked is required.

        Args:
            text: User-supplied prompt.

        Returns:
            List of ``(label, matched_text)`` tuples, ordered by pattern
            registry position.  Empty list if no patterns match.
        """
        results: list[tuple[str, str]] = []
        try:
            for pattern, label in _INDIVIDUAL_PATTERNS:
                m = pattern.search(text)
                if m:
                    results.append((label, m.group()))
        except Exception:  # pragma: no cover
            pass
        return results
