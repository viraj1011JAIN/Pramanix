# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""LangChain integration for Pramanix — PramanixGuardedTool.

Install: pip install 'pramanix[langchain]'

Provides:

* :class:`PramanixGuardedTool` — a LangChain-compatible tool that runs a
  Pramanix guard before executing the underlying action.  Works with both
  LangChain v0.1 (Pydantic v1 via ``pydantic.v1``) and langchain-core >= 0.3
  (Pydantic v2).

* :func:`wrap_tools` — batch-wrap a list of existing BaseTool-like objects
  with a shared Guard.

Security note: if the Guard blocks, the tool returns a human-readable feedback
string rather than raising an exception.  This prevents the LLM orchestration
layer from treating a policy block as a retriable error.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Callable

from pramanix.integrations._feedback import format_block_feedback

__all__ = ["PramanixGuardedTool", "wrap_tools"]

# ── Optional LangChain dependency ─────────────────────────────────────────────

try:
    from langchain_core.tools import BaseTool as _BaseTool  # type: ignore[import-not-found]

    _LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    try:
        from langchain.tools import BaseTool as _BaseTool  # type: ignore[no-redef,import-not-found]

        _LANGCHAIN_AVAILABLE = True
    except ImportError:
        _LANGCHAIN_AVAILABLE = False

        class _BaseTool:  # type: ignore[no-redef]
            """Minimal stub used when neither langchain-core nor langchain is installed."""

            name: str = ""
            description: str = ""

            def run(self, tool_input: str, **kwargs: Any) -> str:  # noqa: ARG002
                raise NotImplementedError

            async def arun(self, tool_input: str, **kwargs: Any) -> str:  # noqa: ARG002
                raise NotImplementedError


# ── PramanixGuardedTool ───────────────────────────────────────────────────────


class PramanixGuardedTool(_BaseTool):  # type: ignore[misc]
    """LangChain-compatible tool that gates execution behind a Pramanix policy.

    For each invocation:

    1. The ``tool_input`` JSON string is parsed and validated against
       ``intent_schema``.
    2. The current state is retrieved from ``state_provider``.
    3. :meth:`~pramanix.guard.Guard.verify_async` is called.
    4. If ALLOW: ``execute_fn(intent)`` is called and its result returned.
    5. If BLOCK: a human-readable feedback string is returned — no exception.

    Args:
        name:            LangChain tool name (shown to the LLM).
        description:     LangChain tool description (shown to the LLM).
        guard:           A pre-constructed :class:`~pramanix.guard.Guard`.
        intent_schema:   Pydantic model class for input validation.
        state_provider:  Zero-argument callable returning ``dict`` or a coroutine.
        execute_fn:      Optional callable ``(intent_dict) -> Any`` to run on
                         ALLOW.  Defaults to a no-op returning ``"OK"``.

    Raises:
        ImportError: If LangChain is not installed and you instantiate this class.
    """

    # Pydantic v1/v2 compat: declare as class-level annotations only.
    # Private guard/schema attrs are set directly on the instance via
    # object.__setattr__ to bypass Pydantic's field machinery on both versions.
    name: str = ""
    description: str = ""

    class Config:
        arbitrary_types_allowed = True

    def __init__(
        self,
        *,
        name: str,
        description: str,
        guard: Any,
        intent_schema: Any,
        state_provider: Callable[[], Any],
        execute_fn: Callable[[dict[str, Any]], Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:  # pragma: no cover
            raise ImportError(
                "LangChain is required: pip install 'pramanix[langchain]'"
            )
        # Pydantic v1/v2 compat — try super().__init__ with Pydantic fields,
        # fall back to direct assignment if the parent raises.
        try:
            super().__init__(name=name, description=description, **kwargs)
        except Exception:
            # BaseTool is a MagicMock or uses an incompatible init — set directly.
            object.__setattr__(self, "name", name)
            object.__setattr__(self, "description", description)

        # Store private attrs bypassing Pydantic's descriptor machinery.
        object.__setattr__(self, "_guard", guard)
        object.__setattr__(self, "_intent_schema", intent_schema)
        object.__setattr__(self, "_state_provider", state_provider)
        object.__setattr__(
            self, "_execute_fn", execute_fn if execute_fn is not None else lambda i: "OK"
        )

    # ── Async run (canonical implementation) ──────────────────────────────────

    async def _arun(self, tool_input: str, **kwargs: Any) -> str:  # noqa: ARG002
        """Execute the tool asynchronously through the Pramanix guard.

        Returns a human-readable BLOCK message if the policy blocks — never
        raises for a policy violation so the LLM agent can handle it gracefully.

        Args:
            tool_input: JSON-encoded intent string from the LLM.

        Returns:
            A string: the execute_fn result on ALLOW, or a block-feedback
            string on BLOCK.

        Raises:
            ValueError: If ``tool_input`` is not valid JSON or fails
                        ``intent_schema`` validation.
        """
        # ── Parse and validate ────────────────────────────────────────────────
        try:
            raw: dict[str, Any] = json.loads(tool_input)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Pramanix: malformed tool input (not valid JSON): {exc}") from exc

        try:
            intent: dict[str, Any] = (
                self._intent_schema.model_validate(raw, strict=False).model_dump()
            )
        except Exception as exc:
            raise ValueError(f"Pramanix: malformed tool input: {exc}") from exc

        # ── Load state ────────────────────────────────────────────────────────
        state = await self._get_state()

        # ── Guard verify ──────────────────────────────────────────────────────
        decision = await self._guard.verify_async(intent=intent, state=state)

        if decision.allowed:
            result = self._execute_fn(intent)
            if asyncio.iscoroutine(result):
                result = await result
            return str(result)

        # BLOCK — return feedback string (never raise for policy violations).
        return format_block_feedback(decision, intent)

    async def _get_state(self) -> dict[str, Any]:
        """Retrieve current state, awaiting if the provider is a coroutine."""
        result = self._state_provider()
        if asyncio.iscoroutine(result):
            result = await result
        return result  # type: ignore[return-value]

    # ── Sync run (calls async run in a new event loop or thread) ──────────────

    def _run(self, tool_input: str, **kwargs: Any) -> str:
        """Synchronous wrapper around :meth:`_arun`.

        If no event loop is running, uses ``asyncio.run()``.  If an event
        loop is already running (e.g., inside a Jupyter notebook or async
        framework), offloads to a dedicated thread with its own event loop.

        Args:
            tool_input: JSON-encoded intent string from the LLM.

        Returns:
            Same as :meth:`_arun`.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — safe to use asyncio.run().
            return asyncio.run(self._arun(tool_input, **kwargs))

        # Already inside an async context — run in a fresh thread.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, self._arun(tool_input, **kwargs))
            return future.result()


# ── wrap_tools ────────────────────────────────────────────────────────────────


def wrap_tools(
    tools: list[Any],
    *,
    guard: Any,
    intent_schema: Any,
    state_provider: Callable[[], Any],
    execute_map: dict[str, Callable[[dict[str, Any]], Any]] | None = None,
) -> list[PramanixGuardedTool]:
    """Batch-wrap a list of existing BaseTool-like objects with a shared Guard.

    Each wrapped tool preserves the original tool's ``name`` and ``description``
    and gates execution through the provided Guard.

    Args:
        tools:          List of tool objects with ``name`` and ``description``
                        attributes (e.g., existing LangChain ``BaseTool`` instances).
        guard:          A pre-constructed :class:`~pramanix.guard.Guard` to share
                        across all wrapped tools.
        intent_schema:  Pydantic model class for input validation (shared).
        state_provider: Zero-argument callable returning ``dict`` or a coroutine.
        execute_map:    Optional ``{tool_name: execute_fn}`` mapping.  If a tool's
                        name is present, that function is used as its ``execute_fn``;
                        otherwise the default no-op (``lambda i: "OK"``) is used.

    Returns:
        A list of :class:`PramanixGuardedTool` instances in the same order as
        *tools*.
    """
    _execute_map: dict[str, Callable[[dict[str, Any]], Any]] = execute_map or {}
    wrapped: list[PramanixGuardedTool] = []
    for tool in tools:
        tool_name: str = getattr(tool, "name", str(tool))
        tool_desc: str = getattr(tool, "description", "")
        execute_fn = _execute_map.get(tool_name)
        wrapped.append(
            PramanixGuardedTool(
                name=tool_name,
                description=tool_desc,
                guard=guard,
                intent_schema=intent_schema,
                state_provider=state_provider,
                execute_fn=execute_fn,
            )
        )
    return wrapped
