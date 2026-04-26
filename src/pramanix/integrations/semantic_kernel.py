# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Microsoft Semantic Kernel integration for Pramanix — Phase F-1.

Exposes a Pramanix :class:`~pramanix.guard.Guard` as a Semantic Kernel native
function plugin.  The plugin's ``verify`` function can be invoked from SK
agents and planners, returning a structured verification result.

Install: pip install 'pramanix[semantic-kernel]'
Requires: semantic-kernel >= 0.9

Usage::

    from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

    plugin = PramanixSemanticKernelPlugin(guard=guard)
    kernel.add_plugin(plugin, plugin_name="pramanix_guard")
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from pramanix.exceptions import ConfigurationError

if TYPE_CHECKING:
    from pramanix.guard import Guard

__all__ = ["PramanixSemanticKernelPlugin"]

_log = logging.getLogger(__name__)


class PramanixSemanticKernelPlugin:
    """Semantic Kernel plugin that wraps a Pramanix Guard as a native function.

    When added to a kernel, this plugin exposes a ``verify`` function that can
    be called by SK agents and planners.  The function accepts an intent JSON
    string and state JSON string, calls the Guard, and returns a structured
    JSON result.

    Args:
        guard:        A fully constructed :class:`~pramanix.guard.Guard`.
        plugin_name:  Name shown in SK function metadata.  Default:
                      ``"pramanix_guard"``.

    Raises:
        ConfigurationError: If ``semantic-kernel`` is not installed.
    """

    def __init__(
        self,
        guard: Guard,
        plugin_name: str = "pramanix_guard",
    ) -> None:
        self._guard = guard
        self._plugin_name = plugin_name

        # Validate presence of semantic-kernel — warn but don't hard-fail
        # so tests can mock this without installing the full package.
        try:
            import semantic_kernel  # noqa: F401
        except ImportError as exc:
            raise ConfigurationError(
                "semantic-kernel is required for PramanixSemanticKernelPlugin. "
                "Install it with: pip install 'pramanix[semantic-kernel]'"
            ) from exc

    def verify(
        self,
        intent_json: str,
        state_json: str = "{}",
    ) -> str:
        """Verify an intent against the Guard and return a JSON result.

        This is the SK native function entry point.  SK planners call this
        by name when the plugin is registered on the kernel.

        Args:
            intent_json: JSON string of the intent dict.
            state_json:  JSON string of the current state dict.  Default ``{}``.

        Returns:
            JSON string with keys ``allowed``, ``status``, ``explanation``,
            ``violated_invariants``.
        """
        try:
            intent = json.loads(intent_json)
            state = json.loads(state_json)
        except json.JSONDecodeError as exc:
            _log.error("pramanix.sk.json_parse_error: %s", exc, exc_info=True)
            return json.dumps({"error": "Invalid JSON input.", "allowed": False})

        try:
            decision = self._guard.verify(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.sk.guard_error: %s", exc, exc_info=True)
            return json.dumps({"error": "Guard error — action blocked", "allowed": False})

        return json.dumps({
            "allowed": decision.allowed,
            "status": str(decision.status),
            "explanation": decision.explanation,
            "violated_invariants": list(decision.violated_invariants),
        })

    async def verify_async(
        self,
        intent_json: str,
        state_json: str = "{}",
    ) -> str:
        """Async variant for use with async SK kernels.

        Same interface as :meth:`verify` but uses ``verify_async`` on the Guard.
        """
        try:
            intent = json.loads(intent_json)
            state = json.loads(state_json)
        except json.JSONDecodeError as exc:
            _log.error("pramanix.sk.json_parse_error: %s", exc, exc_info=True)
            return json.dumps({"error": "Invalid JSON input.", "allowed": False})

        try:
            decision = await self._guard.verify_async(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.sk.guard_error: %s", exc, exc_info=True)
            return json.dumps({"error": "Guard error — action blocked", "allowed": False})

        return json.dumps({
            "allowed": decision.allowed,
            "status": str(decision.status),
            "explanation": decision.explanation,
            "violated_invariants": list(decision.violated_invariants),
        })
