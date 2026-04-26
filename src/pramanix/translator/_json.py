# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Internal JSON cleaning and parsing utilities.

This module has no external dependencies — it is always importable.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pramanix.exceptions import ExtractionFailureError

# Not re-exported; this is an internal helper module.
__all__: list[str] = []


def _extract_first_json(s: str) -> str | None:
    """Return the first valid JSON object ``{…}`` or array ``[…}`` in *s*.

    Uses :meth:`json.JSONDecoder.raw_decode` to locate and parse the first
    JSON value starting from the earliest ``{`` or ``[`` in the string.
    This is faster and more correct than a manual character walk.

    Returns ``None`` if no complete JSON object or array is found.
    """
    decoder = json.JSONDecoder()
    for i, ch in enumerate(s):
        if ch not in ("{", "["):
            continue
        try:
            value, end = decoder.raw_decode(s, i)
            if isinstance(value, (dict, list)):
                return s[i:end]
        except json.JSONDecodeError:
            continue
    return None


def _clean_json(raw: str) -> str:
    """Strip markdown code fences and surrounding prose from LLM output.

    LLMs frequently wrap JSON in triple backticks, prepend "Here is the
    JSON:" or append trailing commentary.  This function pulls out the
    bare JSON object or JSON array so the caller can hand it to
    ``json.loads``.

    Args:
        raw: Raw LLM response string (may contain markdown / prose).

    Returns:
        A string that should be parseable by ``json.loads``.  If no JSON
        object or array is found, the stripped raw string is returned as-is.
    """
    # Remove opening/closing triple-backtick fences (with optional "json" tag)
    stripped = re.sub(r"```(?:json)?\s*", "", raw, flags=re.IGNORECASE).strip()
    stripped = stripped.rstrip("`").strip()

    # Extract the FIRST balanced JSON object or array (handles nesting)
    first = _extract_first_json(stripped)
    if first is not None:
        return first
    return stripped


def parse_llm_response(raw: str, *, model_name: str = "") -> dict[str, Any]:
    """Parse raw LLM text into a ``dict``.

    Args:
        raw:        Raw LLM response string.
        model_name: Optional model identifier for clearer error messages.

    Returns:
        Parsed JSON object as a Python ``dict``.

    Raises:
        ExtractionFailureError: The response is not valid JSON, or the
            top-level value is not a JSON object (dict).
    """
    cleaned = _clean_json(raw)
    prefix = f"[{model_name}] " if model_name else ""

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ExtractionFailureError(
            f"{prefix}LLM returned unparseable JSON: {exc}. "
            f"Raw response (first 300 chars): {raw[:300]!r}"
        ) from exc

    if not isinstance(parsed, dict):
        raise ExtractionFailureError(
            f"{prefix}LLM returned a JSON {type(parsed).__name__} — "
            "expected a JSON object (dict)."
        )

    return parsed
