# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Pramanix — LLM Hardening Utilities
====================================
Standalone module supplying the LLM-integration hardening surface:

* ``sanitise_user_input``       — Unicode NFKC normalisation + regex injection detection.
* ``injection_confidence_score`` — Additive risk scorer evaluated after consensus extraction.
* ``validate_consensus``         — Normalised string-compare of two extraction results.
* ``_normalise_for_comparison``  — Canonical JSON serialisation for deterministic diffs.

All functions are pure (no side effects) and import-safe for both the core
library and for standalone test runners.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from typing import Any

# ---------------------------------------------------------------------------
# Prompt-injection pattern library
# Compatible with GPT-4o, Claude 3.x, Llama-2 / Llama-3, Mistral, Gemini
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[str] = [
    # ---- Universal role-escalation / system-override tokens ----
    r"\bsystem\s*:.*ignore",
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompt|context|rules?)",
    r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompt|context|rules?)",
    r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompt|context|rules?)",
    r"override\s+(instructions?|prompt|system|context|rules?)",
    r"you\s+are\s+now\s+(a|an|the)\s+\w+",
    r"act\s+as\s+(a|an|the)?\s*\w+\s+(without\s+restrictions?|freely|unfiltered)",
    r"jailbreak",
    r"do\s+anything\s+now",
    r"\bdan\b",                               # "Do Anything Now" variant
    # ---- Special tokens (Llama-2 / Llama-3 / Mistral / Gemini) ----
    r"<\|?system\|?>",
    r"<\|?user\|?>",
    r"<\|?assistant\|?>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<\s*sys\s*>>",
    # ---- Exfil / extraction attempts ----
    r"print\s+(your\s+)?(instructions?|system\s+prompt|prompt|rules)",
    r"reveal\s+(your\s+)?(instructions?|system\s+prompt|prompt|rules)",
    r"output\s+(your\s+)?(instructions?|system\s+prompt|prompt|rules)",
    # ---- Code execution tokens ----
    r"```\s*(python|bash|sh|powershell|cmd|javascript|js|ruby|perl)",
    r"<script[\s>]",
    r"eval\(",
    r"exec\(",
    # ---- Semantic manipulation ----
    r"translate\s+to\s+(base64|hex|rot13|pig.latin)",
    r"encode\s+(the\s+)?(following|input)\s+(in|as|to)\s+(base64|hex)",
    r"hypothetically\s+(speaking)?,?\s+(what\s+if|if\s+you)",
    r"pretend\s+(that\s+)?you\s+(are|were|have\s+no)",
    r"roleplay\s+as",
]

_INJECTION_RE = re.compile(
    "|".join(f"(?:{p})" for p in _INJECTION_PATTERNS),
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Pre-LLM sanitisation
# ---------------------------------------------------------------------------

_CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitise_user_input(
    raw: str,
    *,
    max_length: int = 512,
) -> tuple[str, list[str]]:
    """Sanitise *raw* user text before forwarding to an LLM.

    Steps applied in order:
    1. Unicode NFKC normalisation (collapse homoglyphs / width variants).
    2. Truncate to *max_length* characters.
    3. Strip C0 control characters (except \\n and \\t which are harmless).
    4. Scan for known injection patterns — log but do NOT strip (preserves
       transparency; scoring happens separately in ``injection_confidence_score``).

    Args:
        raw:        Raw string from the user.
        max_length: Hard upper bound on returned string length.

    Returns:
        ``(sanitised_text, warnings)`` where *warnings* is a list of
        human-readable strings (may be empty).
    """
    warnings: list[str] = []

    # Step 1 — Unicode NFKC normalisation
    text = unicodedata.normalize("NFKC", raw)

    # Step 2 — Truncate
    if len(text) > max_length:
        warnings.append(
            f"input_truncated: original length {len(text)}, truncated to {max_length}"
        )
        text = text[:max_length]

    # Step 3 — Strip C0 control characters (except \n \t)
    cleaned = _CTRL_CHAR_RE.sub("", text)
    if cleaned != text:
        warnings.append("control_chars_stripped")
    text = cleaned

    # Step 4 — Injection pattern scan (record, do not strip)
    match = _INJECTION_RE.search(text)
    if match:
        warnings.append(f"injection_pattern_detected: matched «{match.group(0)!r}»")

    return text, warnings


# ---------------------------------------------------------------------------
# Injection confidence scorer (post-consensus)
# ---------------------------------------------------------------------------

_HIGH_ENTROPY_THRESHOLD = 20   # characters — long opaque tokens are suspicious
_MIN_NORMAL_LENGTH      = 10   # very short inputs are suspicious

# ---- Per-currency sub-penny thresholds (minimum meaningful transfer amount) ----
# Two-decimal currencies (USD, EUR, GBP, ...): default 0.01.
# Zero-decimal currencies (JPY, KRW, ...): threshold is 1.
# Three-decimal currencies (KWD, OMR, ...): threshold is 0.001.
# Crypto (BTC, ETH): 0.0001 is a normal micro-payment floor.
_PENNY_THRESHOLDS: dict[str, Decimal] = {
    # Zero-decimal ISO 4217 currencies
    "JPY": Decimal("1"), "KRW": Decimal("1"), "VND": Decimal("1"),
    "CLP": Decimal("1"), "ISK": Decimal("1"), "HUF": Decimal("1"),
    "UGX": Decimal("1"), "RWF": Decimal("1"), "GNF": Decimal("1"),
    "XAF": Decimal("1"), "XOF": Decimal("1"), "XPF": Decimal("1"),
    # Three-decimal currencies
    "KWD": Decimal("0.001"), "BHD": Decimal("0.001"), "OMR": Decimal("0.001"),
    "IQD": Decimal("0.001"), "TND": Decimal("0.001"), "JOD": Decimal("0.001"),
    "LYD": Decimal("0.001"),
    # Crypto — four-decimal minimum for standard payments
    "BTC": Decimal("0.0001"), "ETH": Decimal("0.0001"),
}
_DEFAULT_PENNY_THRESHOLD: Decimal = Decimal("0.01")  # two-decimal fallback

# ---- Dangerous-character blocklist for recipient_id scoring ----
# Uses a BLOCKLIST (not an allowlist) so that legitimate separators such as
# hyphens (-), dots (.), and plus signs (+) do NOT incur a false-positive
# penalty.  Shell metacharacters, path chars, and quote/template injectors
# still raise the risk score.
_DANGEROUS_RECIPIENT_CHARS_RE = re.compile(
    r"[;|()\\/\x27\x22`<>&$%#{}\x00-\x1f\x7f]"
    # shell:  ;|()   path: \/   quotes: '" `   template: <>&$%#{}   ctrl
)


def _is_high_entropy_token(s: str) -> bool:
    """Heuristic: long string with low whitespace / punctuation density."""
    if len(s) < _HIGH_ENTROPY_THRESHOLD:
        return False
    non_word = sum(1 for c in s if not c.isalnum())
    ratio = non_word / len(s)
    return ratio < 0.1    # < 10 % separators → likely dense b64/hex payload


def injection_confidence_score(
    user_input: str,
    extracted_intent: str,
    warnings: list[str],
    currency: str = "USD",
    penny_thresholds: "dict[str, Decimal] | None" = None,
) -> float:
    """Return a [0.0, 1.0] injection confidence score.

    A score **≥ 0.5** should be treated as a definitive block.  The additive
    model is intentionally conservative — individual weak signals cannot alone
    breach the threshold.

    Signals evaluated
    -----------------
    * ``+0.60`` — injection regex matched (patterns in *warnings* or fresh scan).
    * ``+0.20`` — input suspiciously short (< 10 chars).
    * ``+0.30`` — sub-penny amount for the effective currency (configurable per
                   currency; default 0.01 for two-decimal currencies).
    * ``+0.30`` — dangerous characters in ``recipient_id`` (shell metacharacters,
                   path separators, quote injectors).  Common separators such as
                   hyphens, dots, and plus signs are explicitly permitted.
    * ``+0.40`` — ``amount`` field cannot be parsed as a positive Decimal.
    * ``+0.20`` — high-entropy token detected in *extracted_intent*.

    Args:
        user_input:        Original (post-sanitise) user string.
        extracted_intent:  JSON string of the LLM-extracted intent.
        warnings:          List returned by :func:`sanitise_user_input`.
        currency:          ISO 4217 code of the transaction currency (used when
                           the extracted intent does not contain a currency field).
                           Defaults to ``"USD"``.
        penny_thresholds:  Override the built-in :data:`_PENNY_THRESHOLDS` map.
                           ``None`` uses the module default.

    Returns:
        Float in ``[0.0, 1.0]``.  Recorded in telemetry automatically.
    """
    score = 0.0

    # Pattern detection (either already flagged by sanitise, or fresh scan here)
    has_pattern_warning = any("injection_pattern_detected" in w for w in warnings)
    if has_pattern_warning or _INJECTION_RE.search(user_input):
        score += 0.60

    # Suspicious length
    if len(user_input.strip()) < _MIN_NORMAL_LENGTH:
        score += 0.20

    # Parse the extracted intent for semantic anomalies
    try:
        intent: dict[str, Any] = json.loads(extracted_intent)

        # Sub-penny amount check — threshold is configurable per currency.
        # The effective currency is taken from the extracted intent when present,
        # falling back to the *currency* argument (default: USD).
        effective_currency = intent.get("currency", currency).upper()
        thresholds = penny_thresholds if penny_thresholds is not None else _PENNY_THRESHOLDS
        penny_threshold = thresholds.get(effective_currency, _DEFAULT_PENNY_THRESHOLD)

        amount_raw = intent.get("amount")
        if amount_raw is not None:
            try:
                amount = Decimal(str(amount_raw))
                if amount > 0 and amount < penny_threshold:
                    score += 0.30
            except (InvalidOperation, ValueError):
                # Unparseable amount field
                score += 0.40

        # Dangerous-character detection in recipient_id.
        # Uses a BLOCKLIST so legitimate separators (-, ., +) are never penalised.
        # Shell metacharacters, path-traversal chars, and quote injectors
        # (;, |, \, /, ', ", `, <, >, &, $, %, #, {, }) raise the score.
        recipient = intent.get("recipient_id", "")
        if recipient and _DANGEROUS_RECIPIENT_CHARS_RE.search(str(recipient)):
            score += 0.30

    except (json.JSONDecodeError, AttributeError):
        # Cannot parse the intent at all — treat as unparseable amount
        score += 0.40

    # High-entropy token in extracted intent string
    for token in re.split(r"\s+", extracted_intent):
        if _is_high_entropy_token(token):
            score += 0.20
            break

    score = min(score, 1.0)
    # Optional telemetry hook — silently ignored if pramanix_telemetry is absent.
    try:
        from pramanix_telemetry import get_telemetry
        get_telemetry().record_injection_score(score)
    except Exception:
        pass
    return score


# ---------------------------------------------------------------------------
# Consensus validation
# ---------------------------------------------------------------------------

_EXTRACTION_SYSTEM_PROMPT = """You are a transaction extraction assistant.
Extract intent fields as JSON: amount (decimal string), recipient_id (alphanumeric),
currency (ISO 4217 three-letter code), memo (optional string ≤128 chars).
Output ONLY the JSON object — no prose, no code fences."""

_SYSTEM_PROMPT_HASH: str = hashlib.sha256(
    _EXTRACTION_SYSTEM_PROMPT.encode("utf-8")
).hexdigest()


def _verify_prompt_integrity() -> bool:
    """Return True iff the system prompt has not been tampered with."""
    current = hashlib.sha256(_EXTRACTION_SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    return current == _SYSTEM_PROMPT_HASH


def _normalise_for_comparison(intent: dict) -> str:
    """Return a canonical JSON string of *intent* suitable for byte-level comparison.

    Normalisation applied:
    * All keys sorted alphabetically.
    * ``amount`` value converted to a canonical Decimal string (e.g. ``"100.00"``
      and ``"1e2"`` are both normalised to ``"100"``).
    * All other values left as-is.
    """
    normalised: dict[str, Any] = {}
    for k in sorted(intent.keys()):
        v = intent[k]
        if k == "amount":
            try:
                v = str(Decimal(str(v)).normalize())
            except (InvalidOperation, ValueError):
                pass   # leave raw value — scorer will catch it later
        normalised[k] = v
    return json.dumps(normalised, sort_keys=True, separators=(",", ":"))


def validate_consensus(
    intent_a: dict | None,
    intent_b: dict | None,
    required_fields: tuple[str, ...] = ("amount", "recipient_id", "currency"),
) -> dict | None:
    """Validate that two independently extracted intents agree.

    *None* is returned (consensus failed) if any of the following hold:
    * Either intent is ``None``.
    * Any field in *required_fields* is missing from either intent.
    * The normalised representations differ.

    Args:
        intent_a:       Dict extracted by model A.
        intent_b:       Dict extracted by model B.
        required_fields: Fields that must be present and matching.

    Returns:
        The validated intent dict (from *intent_a*) if consensus passes,
        otherwise ``None``.
    """
    if intent_a is None or intent_b is None:
        return None

    for field in required_fields:
        if field not in intent_a or field not in intent_b:
            return None

    norm_a = _normalise_for_comparison(intent_a)
    norm_b = _normalise_for_comparison(intent_b)

    if norm_a != norm_b:
        return None

    return intent_a
