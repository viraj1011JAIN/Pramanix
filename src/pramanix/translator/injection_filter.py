# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
* **Fail-closed** — any internal error (e.g. catastrophic regex backtracking
  on a crafted payload) blocks the request and logs ``ERROR``.  An input that
  crashes the regex engine is anomalous by definition and must not proceed.
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

import logging
from typing import Any

_log = logging.getLogger(__name__)

class SecurityWarning(UserWarning):
    """Security advisory (not a Python built-in — defined here for all versions)."""


__all__ = ["INJECTION_PATTERNS", "InjectionFilter"]

# ── RE2 engine (linear-time, ReDoS-immune) ────────────────────────────────────
# google-re2 guarantees O(n) matching.  Absence is detected at import time but
# the error is raised lazily at instantiation so that the module can be imported
# without google-re2 installed (e.g. in environments that only use the Z3 core).
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
    if not _RE2_AVAILABLE:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "pramanix.translator.injection_filter: google-re2 is required but not installed. "
            "ReDoS via crafted injection patterns is a critical security risk without it. "
            "Install with: pip install 'pramanix[security]'"
        ) from _re2_import_error


def _re_ci(pattern: str) -> Any:
    opts = _re_engine.Options()
    opts.case_sensitive = False
    return _re_engine.compile(pattern, opts)


# ── Injection pattern registry ─────────────────────────────────────────
#
# Each entry is (regex_pattern, label).  Labels appear in block-reason
# strings and structured audit logs.  Compiled with IGNORECASE.
#
# Coverage:
#   - Classic override / jailbreak phrases (GPT-4, Claude, Gemini)
#   - Open-source model instruction tokens (Llama 2/3, Mistral, ChatML)
#   - Embedded role-escalation JSON
#   - Persona and capability override phrases
#   - Prompt / system-prompt extraction attempts
#   - Direct compliance coercion ("you must comply")
#
from pramanix.translator._injection_patterns import INJECTION_PATTERNS  # noqa: E402


def _build_injection_compiled() -> tuple[Any, list[tuple[Any, str]]]:
    if not _RE2_AVAILABLE:
        return None, []
    combined = _re_ci(
        "|".join(f"(?:{pat})" for pat, _ in INJECTION_PATTERNS),
    )
    individual = [(_re_ci(pat), label) for pat, label in INJECTION_PATTERNS]
    return combined, individual


# Combined alternation and individual patterns compiled once at import time
# (returns (None, []) when re2 is absent — guarded at instantiation).
_COMBINED_RE: Any
_INDIVIDUAL_PATTERNS: list[tuple[Any, str]]
_COMBINED_RE, _INDIVIDUAL_PATTERNS = _build_injection_compiled()


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

    def __init__(self) -> None:
        _require_re2()

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
                        f"injection_pattern_detected label={label!r} " f"matched={m.group()!r}",
                    )

            # Fallback: combined matched but no individual did.
            return True, "injection_pattern_detected label='unknown'"

        except Exception as exc:
            # Fail-CLOSED: an anomalous input that crashes the regex engine is
            # by definition suspicious.  Blocking is the only safe response.
            # Log at ERROR so operators can investigate and fix the pattern.
            _log.error(
                "pramanix.injection_filter: is_injection() raised unexpectedly — "
                "input blocked as a precaution (fail-closed): %s",
                exc,
            )
            return True, f"filter_internal_error:{type(exc).__name__}"

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
        except Exception as _exc:
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "injection_filter: pattern matching error (partial results returned): %s",
                _exc,
            )
        return results
