# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Haystack integration for Pramanix — Phase F-1.

Wraps a Pramanix :class:`~pramanix.guard.Guard` as a Haystack pipeline
:class:`~haystack.component.Component` so that every pipeline document or
message can be gated by Z3 formal verification before downstream processing.

Install: pip install 'pramanix[haystack]'
Requires: haystack-ai >= 2.0

Usage::

    from pramanix.integrations.haystack import HaystackGuardedComponent

    guard_component = HaystackGuardedComponent(
        guard=Guard(MyPolicy, config=GuardConfig(execution_mode="async-thread")),
        intent_extractor=lambda doc: {"amount": doc.meta["amount"]},
        state_provider=lambda: {"balance": fetch_balance()},
    )

    pipeline = Pipeline()
    pipeline.add_component("guard", guard_component)
    pipeline.connect("retriever.documents", "guard.documents")
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.guard import Guard

__all__ = ["HaystackGuardedComponent"]

_log = logging.getLogger(__name__)

# M-21: register the class as a Haystack component at definition time,
# not per-instance in __init__.
try:
    from haystack import component as _haystack_component  # type: ignore[import-untyped]

    _HAYSTACK_AVAILABLE = True
except ImportError:
    _HAYSTACK_AVAILABLE = False
    _haystack_component = None


class HaystackGuardedComponent:
    """Haystack pipeline component that gates document processing via a Guard.

    Passes only documents/messages that are allowed by the configured Guard.
    Blocked documents are collected in ``blocked_documents`` for audit.

    If Haystack is not installed, the component degrades gracefully to a
    plain callable that applies the same guard logic.

    Args:
        guard:           A fully constructed :class:`~pramanix.guard.Guard`.
        intent_extractor: Callable ``(doc_or_message) → intent dict``.
        state_provider:  Callable ``() → state dict`` providing current state.
        block_on_error:  If ``True`` (default), treat guard errors as BLOCK.

    Raises:
        ConfigurationError: If the guard is not properly configured.
    """

    def __init__(
        self,
        guard: Guard,
        intent_extractor: Callable[[Any], dict[str, Any]],
        state_provider: Callable[[], dict[str, Any]],
        *,
        block_on_error: bool = True,
    ) -> None:
        self._guard = guard
        self._intent_extractor = intent_extractor
        self._state_provider = state_provider
        self._block_on_error = block_on_error
        self._haystack_available = _HAYSTACK_AVAILABLE

    def run(
        self,
        documents: list[Any] | None = None,
        messages: list[Any] | None = None,
    ) -> dict[str, list[Any]]:
        """Process a list of documents or messages through the Guard.

        Args:
            documents: List of Haystack Document objects (or any dicts).
            messages:  List of ChatMessage objects (or any dicts).

        Returns:
            A dict with keys ``"documents"`` and ``"blocked_documents"``
            (and ``"messages"`` / ``"blocked_messages"`` if messages were given).
        """

        allowed_docs: list[Any] = []
        blocked_docs: list[Any] = []
        allowed_msgs: list[Any] = []
        blocked_msgs: list[Any] = []

        items_and_targets = []
        if documents:
            items_and_targets.extend([(d, "doc") for d in documents])
        if messages:
            items_and_targets.extend([(m, "msg") for m in messages])

        state = self._state_provider()

        for item, kind in items_and_targets:
            try:
                intent = self._intent_extractor(item)
            except Exception as exc:
                _log.error("pramanix.haystack.intent_extraction_error: %s", exc, exc_info=True)
                if self._block_on_error:
                    (blocked_docs if kind == "doc" else blocked_msgs).append(item)
                else:
                    (allowed_docs if kind == "doc" else allowed_msgs).append(item)
                continue

            try:
                # Use sync verify for synchronous pipeline components.
                decision = self._guard.verify(intent=intent, state=state)
            except Exception as exc:
                _log.error("pramanix.haystack.guard_error: %s", exc, exc_info=True)
                if self._block_on_error:
                    (blocked_docs if kind == "doc" else blocked_msgs).append(item)
                else:
                    (allowed_docs if kind == "doc" else allowed_msgs).append(item)
                continue

            if decision.allowed:
                (allowed_docs if kind == "doc" else allowed_msgs).append(item)
            else:
                (blocked_docs if kind == "doc" else blocked_msgs).append(item)

        result: dict[str, list[Any]] = {
            "documents": allowed_docs,
            "blocked_documents": blocked_docs,
        }
        if messages is not None:
            result["messages"] = allowed_msgs
            result["blocked_messages"] = blocked_msgs
        return result

    async def run_async(
        self,
        documents: list[Any] | None = None,
        messages: list[Any] | None = None,
    ) -> dict[str, list[Any]]:
        """Async variant of :meth:`run` for async pipeline contexts."""
        allowed_docs: list[Any] = []
        blocked_docs: list[Any] = []
        allowed_msgs: list[Any] = []
        blocked_msgs: list[Any] = []

        items_and_targets = []
        if documents:
            items_and_targets.extend([(d, "doc") for d in documents])
        if messages:
            items_and_targets.extend([(m, "msg") for m in messages])

        state = self._state_provider()

        for item, kind in items_and_targets:
            try:
                intent = self._intent_extractor(item)
            except Exception as exc:
                _log.error("pramanix.haystack.intent_extraction_error: %s", exc, exc_info=True)
                if self._block_on_error:
                    (blocked_docs if kind == "doc" else blocked_msgs).append(item)
                else:
                    (allowed_docs if kind == "doc" else allowed_msgs).append(item)
                continue

            try:
                decision = await self._guard.verify_async(intent=intent, state=state)
            except Exception as exc:
                _log.error("pramanix.haystack.guard_error: %s", exc, exc_info=True)
                if self._block_on_error:
                    (blocked_docs if kind == "doc" else blocked_msgs).append(item)
                else:
                    (allowed_docs if kind == "doc" else allowed_msgs).append(item)
                continue

            if decision.allowed:
                (allowed_docs if kind == "doc" else allowed_msgs).append(item)
            else:
                (blocked_docs if kind == "doc" else blocked_msgs).append(item)

        result: dict[str, list[Any]] = {
            "documents": allowed_docs,
            "blocked_documents": blocked_docs,
        }
        if messages is not None:
            result["messages"] = allowed_msgs
            result["blocked_messages"] = blocked_msgs
        return result


# M-21: register at class-definition time, not per-instance.
if _HAYSTACK_AVAILABLE and _haystack_component is not None:
    try:
        _haystack_component(HaystackGuardedComponent)
    except Exception:
        pass
