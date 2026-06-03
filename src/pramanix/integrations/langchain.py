# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""LangChain integration for Pramanix.

Install: pip install 'pramanix[langchain]'
Requires: langchain-core >= 0.1
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import logging
import weakref
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pramanix.guard import Guard
from pramanix.integrations._feedback import format_block_feedback

_log = logging.getLogger(__name__)


class _BaseToolFallback:
    """Raises ConfigurationError when langchain-core is not installed."""

    name: str = ""
    description: str = ""

    def __init__(self, *, name: str = "", description: str = "", **kwargs: Any) -> None:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "LangChain integration requires 'langchain-core': " "pip install 'pramanix[langchain]'"
        )

    def _run(self, tool_input: str, **kwargs: Any) -> str:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "LangChain integration requires 'langchain-core': " "pip install 'pramanix[langchain]'"
        )

    async def _arun(self, tool_input: str, **kwargs: Any) -> str:
        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            "LangChain integration requires 'langchain-core': " "pip install 'pramanix[langchain]'"
        )


_LANGCHAIN_AVAILABLE: bool = False

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool
else:
    try:
        from langchain_core.tools import BaseTool

        _LANGCHAIN_AVAILABLE = True
    except ImportError:
        BaseTool = _BaseToolFallback


# Build model_config at module level to avoid polluting the class namespace
# (Pydantic would treat an in-class `from pydantic import ConfigDict` as a field)
_PRAMANIX_MODEL_CONFIG: Any = None
try:
    from pydantic import ConfigDict as _ConfigDict

    _PRAMANIX_MODEL_CONFIG = _ConfigDict(arbitrary_types_allowed=True)
except ImportError:
    pass

__all__ = ["PramanixGuardedTool", "wrap_tools"]


class PramanixGuardedTool(BaseTool):
    """LangChain BaseTool with Z3 formal verification gate.

    When langchain-core is installed, this IS a proper BaseTool subclass.
    When it is absent, the stub BaseTool raises ConfigurationError at
    __init__ time — never at import time, so the module stays importable.

    Private guard state is stored via object.__setattr__ with underscore
    prefix names to avoid Pydantic schema exposure. This is safe because
    these fields are behavioral config, not domain data.
    """

    name: str = ""
    description: str = ""

    if _LANGCHAIN_AVAILABLE and _PRAMANIX_MODEL_CONFIG is not None:
        model_config = _PRAMANIX_MODEL_CONFIG

    def __init__(
        self,
        *,
        name: str,
        description: str,
        guard: Guard,
        intent_schema: type,
        state_provider: Callable[[], Any],
        execute_fn: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "LangChain integration requires 'langchain-core': "
                "pip install 'pramanix[langchain]'"
            )
        try:
            super().__init__(name=name, description=description)
        except Exception:
            # Pydantic v1/v2 edge case — set directly
            object.__setattr__(self, "name", name)
            object.__setattr__(self, "description", description)

        if execute_fn is None:
            _log.warning(
                "PramanixGuardedTool '%s': execute_fn is None — "
                "ALLOW decisions raise ConfigurationError. "
                "Pass execute_fn= to configure the guarded action.",
                name,
            )
        # Store private behavioral state bypassing Pydantic schema
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pramanix-langchain"
        )
        object.__setattr__(self, "_pramanix_guard", guard)
        object.__setattr__(self, "_pramanix_schema", intent_schema)
        object.__setattr__(self, "_pramanix_state", state_provider)
        object.__setattr__(self, "_pramanix_execute", execute_fn)
        # H-13: one shared executor — created once, never per-call.
        object.__setattr__(self, "_pramanix_executor", executor)
        # Register leak-detection finalizer to replace __del__ anti-pattern.
        object.__setattr__(
            self,
            "_pramanix_finalizer",
            weakref.finalize(self, PramanixGuardedTool._shutdown_executor, executor),
        )

    def _run(self, tool_input: str, **kwargs: Any) -> str:
        """Sync path — wraps async logic in a dedicated thread pool."""
        try:
            asyncio.get_running_loop()
            executor = object.__getattribute__(self, "_pramanix_executor")
            future = executor.submit(asyncio.run, self._arun(tool_input, **kwargs))
            return str(future.result(timeout=30))
        except RuntimeError:
            return asyncio.run(self._arun(tool_input, **kwargs))

    @staticmethod
    def _shutdown_executor(executor: concurrent.futures.ThreadPoolExecutor) -> None:
        with contextlib.suppress(RuntimeError, OSError):
            executor.shutdown(wait=False)

    def close(self) -> None:
        """Shut down the shared thread pool executor."""
        finalizer = object.__getattribute__(self, "_pramanix_finalizer")
        if finalizer.alive:
            finalizer.detach()
        executor = object.__getattribute__(self, "_pramanix_executor")
        executor.shutdown(wait=False)

    async def _arun(self, tool_input: str, **kwargs: Any) -> str:
        guard = object.__getattribute__(self, "_pramanix_guard")
        schema = object.__getattribute__(self, "_pramanix_schema")
        state_provider = object.__getattribute__(self, "_pramanix_state")
        execute_fn = object.__getattribute__(self, "_pramanix_execute")

        try:
            raw = json.loads(tool_input)
        except json.JSONDecodeError as e:
            raise ValueError(f"Pramanix: tool_input must be valid JSON: {e}") from e

        try:
            intent = schema.model_validate(raw).model_dump()
        except Exception as e:
            raise ValueError(f"Pramanix: intent validation failed: {e}") from e

        state = await self._get_state_async(state_provider)
        decision = await guard.verify_async(intent=intent, state=state)

        if decision.allowed:
            if execute_fn is None:
                from pramanix.exceptions import ConfigurationError

                raise ConfigurationError(
                    f"PramanixGuardedTool '{self.name}': decision is ALLOW but no "
                    "execute_fn was supplied at construction time. "
                    "Pass execute_fn=<callable> when creating the tool."
                )
            result = execute_fn(intent)
            if asyncio.iscoroutine(result):
                result = await result
            return str(result)
        else:
            return format_block_feedback(decision, intent)

    @staticmethod
    async def _get_state_async(provider: Callable[[], Any]) -> dict[str, Any]:
        result = provider()
        if asyncio.iscoroutine(result):
            return dict(await result)
        return dict(result)


def wrap_tools(
    tools: list[Any],
    *,
    guard: Guard,
    intent_schema: type,
    state_provider: Callable[[], Any],
    execute_map: dict[str, Callable[[dict[str, Any]], Any]] | None = None,
) -> list[PramanixGuardedTool]:
    """Batch-wrap existing tools with Pramanix verification."""
    result = []
    em = execute_map or {}
    for tool in tools:
        _orig = getattr(tool, "_run", None)

        def _make_default(
            _t: Any,
        ) -> Callable[[dict[str, Any]], Any]:
            if _t is not None:
                return lambda i: _t(json.dumps(i))
            return lambda i: json.dumps(i)

        _default_fn: Callable[[dict[str, Any]], Any] = (
            em[tool.name] if tool.name in em else _make_default(_orig)
        )
        result.append(
            PramanixGuardedTool(
                name=tool.name,
                description=tool.description,
                guard=guard,
                intent_schema=intent_schema,
                state_provider=state_provider,
                execute_fn=_default_fn,
            )
        )
    return result
