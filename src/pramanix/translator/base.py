# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Translator protocol and host-context dataclass.

Both types are pure-Python with no optional dependencies so they can be
imported unconditionally even when *openai* / *anthropic* are not installed.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pydantic import BaseModel

__all__ = ["Translator", "TranslatorContext", "RedactedSecretsMixin"]

# ── Secret-redaction mixin ────────────────────────────────────────────────────

#: Attribute names that contain credentials and must never appear in
#: repr(), pickle, or crash dumps (#237).
_SECRET_ATTRS = frozenset(
    {
        "_api_key",
        "_aws_access_key_id",
        "_aws_secret_access_key",
        "_aws_session_token",
        "_vertex_credentials",
    }
)


class RedactedSecretsMixin:
    """Mixin that prevents API keys from leaking via repr / pickle / heap dumps.

    Translators that store credentials as instance attributes should inherit
    from this mixin.  It overrides ``__repr__`` to show ``***`` for secret
    fields and ``__getstate__`` to exclude them from pickle output.

    Also provides :attr:`configured_api_key` / :attr:`api_key_is_set` —
    public, stable accessors for the conventional ``self._api_key`` attribute
    (#6/#7 closure: previously each translator either lacked a public
    accessor entirely, forcing tests to read ``t._api_key`` directly, or
    duplicated an identical property body per-class). Translators that do not
    use ``_api_key`` (e.g. AWS/Vertex translators with multi-part credentials)
    simply see ``None`` / ``False`` here, which is correct and harmless.
    """

    @property
    def api_key_is_set(self) -> bool:
        """Return True if ``self._api_key`` was configured (arg or env var)."""
        return bool(getattr(self, "_api_key", None))

    @property
    def configured_api_key(self) -> str | None:
        """Return the resolved ``self._api_key`` (for tests/diagnostics only)."""
        return getattr(self, "_api_key", None)

    def __repr__(self) -> str:
        safe = {
            k: "***" if k in _SECRET_ATTRS else v
            for k, v in vars(self).items()
            if not k.startswith("__")
        }
        return f"{type(self).__name__}({safe!r})"

    def __getstate__(self) -> dict[str, Any]:
        state = dict(vars(self))
        for attr in _SECRET_ATTRS:
            state.pop(attr, None)
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        # Restore secret attrs as None so the object is usable (callers will
        # get clear AttributeError / auth failures rather than silent wrong-key).
        for attr in _SECRET_ATTRS:
            if attr not in self.__dict__:
                self.__dict__[attr] = None


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

    request_id: str = field(
        default_factory=lambda: str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
    )
    user_id: str = ""
    available_accounts: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
