# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Translator protocol and host-context dataclass.

Both types are pure-Python with no optional dependencies so they can be
imported unconditionally even when *openai* / *anthropic* are not installed.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pydantic import BaseModel

__all__ = ["Translator", "TranslatorContext"]


@runtime_checkable
class Translator(Protocol):
    """Structural protocol for all Pramanix LLM-backed translators.

    A ``Translator`` converts a natural-language string into a structured
    intent dict that can be validated by Pydantic and fed into
    ``Guard.verify()``.

    **Security contract**: All text received via *text* is UNTRUSTED user
    input.  A translator is a text parser, never a policy decision-maker.
    The Z3 engine — not the LLM — makes all allow/block decisions.
    """

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Extract a structured intent dict from natural-language *text*.

        Args:
            text:          Raw user input (treat as untrusted).
            intent_schema: Pydantic model class whose fields define the
                           expected JSON output structure.
            context:       Optional host-provided context (account IDs,
                           user identifier, locale, etc.) that may help
                           ground the extraction.

        Returns:
            A ``dict`` whose keys and values correspond to the fields of
            *intent_schema*.  The caller is responsible for Pydantic
            validation of this dict before passing it to the solver.

        Raises:
            ExtractionFailureError: LLM response was not valid JSON or did
                not satisfy the schema.
            LLMTimeoutError:        All retry attempts were exhausted.
        """
        ...


@dataclass
class TranslatorContext:
    """Host-provided context passed to every :meth:`Translator.extract` call.

    The translator *may* surface these values inside the system prompt to
    help the LLM ground its extraction (e.g., listing the user's available
    account names so the model does not hallucinate IDs).

    **Security contract**: ``TranslatorContext`` values are informational
    only.  The translator must never use them to make policy decisions.

    Attributes:
        request_id:         Caller-assigned trace ID (defaults to UUID4).
        user_id:            Opaque user identifier used for logging only.
        available_accounts: Names/IDs the user may legally reference.
        extra:              Arbitrary additional key/value pairs (e.g.
                            locale, currency, session metadata).
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    available_accounts: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
