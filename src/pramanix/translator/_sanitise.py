# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pre-LLM input sanitisation and injection confidence scoring.

This module implements Pramanix's hardened input pipeline, providing two
complementary defences applied *before* any LLM is consulted:

1. **Unicode NFKC normalisation** — collapses full-width digits and homoglyphs
   (e.g. ``Ａ`` → ``A``, ``５`` → ``5``) to defeat encoding-based evasion.
2. **Input truncation** — prevents prompt-length denial-of-service.
3. **Control-character stripping** — removes NUL bytes and C0 control codes
   that could be used for terminal injection or parser confusion.
4. **Injection pattern detection** — regex scan covering known jailbreak and
   steering phrases used across GPT-*, Claude, and open-source model families.
5. **Injection confidence scoring** — a heuristic ``[0, 1]`` float that
   combines the sanitisation signals with extracted-intent anomalies.
   Scores ≥ 0.5 block the request before any LLM call is made.

Security design note
--------------------
This scorer is a *last-resort* defence-in-depth layer.  The primary defences
are: compiled DSL unreachable from user input, extraction-only prompt design,
Pydantic strict schema validation, and dual-model consensus.  The scorer adds
pre-call blocking for inputs that are obviously adversarial, reducing LLM API
costs and latency for attack traffic.

The false-positive rate for legitimate low-value transactions is intentionally
low — the threshold (0.5) was chosen to block only high-confidence attacks.
"""
from __future__ import annotations

import re
import unicodedata
from decimal import Decimal
from typing import Any

__all__ = [
    "sanitise_user_input",
    "injection_confidence_score",
]

# ── Injection pattern registry ────────────────────────────────────────────────
#
# Covers known jailbreak / steering patterns for GPT-*, Claude, Llama-2/3,
# Mistral, and generic adversarial prompt-injection payloads.
#
_INJECTION_RE = re.compile(
    # Classic overrides
    r"ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?|context)"
    r"|ignore\s+all"
    r"|jailbreak"
    r"|developer\s+mode"
    # Instruction tokens used by open-source model families
    r"|\[INST\]"  # Llama 2
    r"|\<\<SYS\>\>"  # Llama 2 system block
    r"|<\|im_start\|>"  # ChatML (Mistral/OpenChat)
    r"|<\|eot_id\|>"  # Llama 3
    r"|<\|begin_of_text\|>"  # Llama 3 BOS
    # Fake system-message injection
    r"|system\s*:\s*(?=[A-Za-z])"  # "SYSTEM: do X"
    r"|\{\s*[\"']role[\"']\s*:\s*[\"']system[\"']"  # embedded JSON role
    # Persona / override phrases
    r"|override\s+safety"
    r"|pretend\s+you\s+are"
    r"|you\s+are\s+now"
    r"|act\s+as\s+an?\s+(admin|root|superuser|god|oracle|unrestricted)"
    r"|unlock.{0,20}mode"
    # Markdown-fenced / structured instruction injection
    r"|\\n\\n\s*###\s*(instruction|system|prompt)"
    # RL/RLHF gaming
    r"|reward\s+hack"
    r"|prompt\s+injection",
    re.IGNORECASE,
)

# Allow: HT (\x09), LF (\x0a), CR (\x0d) — normal whitespace
# Strip:  NUL (\x00) and other C0 control codes that serve no legitimate purpose
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_MAX_INPUT_LENGTH: int = 512


# ── Public API ────────────────────────────────────────────────────────────────


def sanitise_user_input(
    raw: str,
    max_length: int = _MAX_INPUT_LENGTH,
) -> tuple[str, list[str]]:
    """Sanitise *raw* user input before forwarding it to an LLM.

    Applies four transforms in order:

    1. **Unicode NFKC** — ``"Ｓend ５０ dollars"`` → ``"Send 50 dollars"``
    2. **Truncation** — clip to *max_length* characters.
    3. **Control-char strip** — remove NUL bytes and other C0 control codes.
    4. **Injection pattern scan** — record warning if adversarial phrases found.

    The original string is never modified in-place; a cleaned copy is returned.

    Args:
        raw:        Raw user-supplied string (untrusted).
        max_length: Maximum character count; input is clipped if longer.

    Returns:
        ``(cleaned_text, warnings)`` where *warnings* is a list of string
        tags describing what was found or modified.  An empty list means the
        input appears benign.
    """
    warnings: list[str] = []

    # Step 1: Unicode NFKC normalisation — homograph / full-width digit collapse
    normalised = unicodedata.normalize("NFKC", raw)
    if normalised != raw:
        warnings.append("unicode_normalised")
    text = normalised

    # Step 2: Truncate
    if len(text) > max_length:
        text = text[:max_length]
        warnings.append(f"input_truncated_to_{max_length}_chars")

    # Step 3: Strip control characters
    cleaned = _CONTROL_RE.sub("", text)
    if cleaned != text:
        warnings.append("control_characters_stripped")
    text = cleaned

    # Step 4: Injection pattern scan
    matches = _INJECTION_RE.findall(text)
    if matches:
        warnings.append(f"injection_patterns_detected: {matches}")

    return text, warnings


def injection_confidence_score(
    user_input: str,
    extracted_intent: dict[str, Any],
    warnings: list[str],
    *,
    sub_penny_threshold: Decimal = Decimal("0.10"),
) -> float:
    """Heuristic injection-confidence score in *[0, 1]*.

    Combines sanitisation signals with extracted-intent anomalies.  Values
    ≥ 0.5 indicate a probable adversarial attempt and should be blocked by
    the caller before any LLM is consulted or consensus is returned.

    Scoring table (additive, capped at 1.0):

    +--------------------------------------------------+-------+
    | Signal                                           | Score |
    +==================================================+=======+
    | Injection pattern detected during sanitisation   |  +0.6 |
    | Input length < 10 chars (evasion probe)          |  +0.2 |
    | Sub-threshold amount (0 < amount < threshold)    |  +0.3 |
    | Non-alphanumeric chars in recipient_id           |  +0.3 |
    | Unparseable / missing amount field               |  +0.4 |
    | High-entropy token ≥ 20 chars (base64/hex probe) |  +0.2 |
    +--------------------------------------------------+-------+

    Args:
        user_input:           Original (possibly sanitised) user text.
        extracted_intent:     Dict returned by one of the LLM translators.
        warnings:             Warning list from :func:`sanitise_user_input`.
        sub_penny_threshold:  Amounts strictly between zero and this value
                              trigger the +0.3 sub-penny signal.  Defaults
                              to ``Decimal("0.10")`` (USD/EUR standard).
                              Override for legitimate micro-transaction
                              domains — e.g. ``Decimal("0.001")`` for KWD/BHD
                              (3-decimal currencies), ``Decimal("0.0001")``
                              for crypto, or ``Decimal("0")`` to disable the
                              signal entirely.

    Returns:
        Float in *[0.0, 1.0]*.
    """
    score = 0.0

    # Injection patterns found during sanitisation
    if any("injection_patterns_detected" in w for w in warnings):
        score += 0.6

    # Very short inputs are suspicious (fuzzing / evasion probes)
    if len(user_input.strip()) < 10:
        score += 0.2

    # Sub-threshold amounts are anomalous for most financial transactions.
    # The threshold is domain-specific; callers must override for currencies
    # with legitimate micro-transaction semantics (crypto, zero-decimal, etc.).
    try:
        amt = Decimal(str(extracted_intent.get("amount", "1")))
        if Decimal("0") < amt < sub_penny_threshold:
            score += 0.3
    except Exception:
        score += 0.4  # unparseable amount is itself a suspicious anomaly

    # Non-alphanumeric recipient IDs may be path-traversal / code-injection
    rid = str(extracted_intent.get("recipient_id", ""))
    if rid and re.search(r"[^a-zA-Z0-9_\-]", rid):
        score += 0.3

    # High-entropy token — possible base64, hex or encoded payload embedded
    if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", user_input):
        score += 0.2

    return min(score, 1.0)
