# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""LlamaIndex integration for Pramanix — PramanixFunctionTool and PramanixQueryEngineTool.

Install: pip install 'pramanix[llamaindex]'

Usage::

    from pramanix.integrations.llamaindex import PramanixFunctionTool

    async def execute_transfer(amount: Decimal, recipient: str) -> str:
        return f"Transferred {amount} to {recipient}"

    tool = PramanixFunctionTool(
        fn=execute_transfer,
        guard=guard,
        intent_schema=TransferIntent,
        state_provider=lambda: get_account_state(),
        name="transfer",
        description="Transfer funds between accounts",
    )
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import logging
import weakref
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from pramanix.guard import Guard
from pramanix.integrations._feedback import format_block_feedback

_log = logging.getLogger(__name__)

__all__ = ["PramanixFunctionTool", "PramanixQueryEngineTool"]

# ── Optional LlamaIndex dependency ────────────────────────────────────────────
# M-24: Do NOT export stub types when llama_index is absent — callers who
# type-check against ToolMetadata/ToolOutput would silently get the fake.
# Raise ImportError on import so the dependency requirement is clear.

# Fallback stubs defined unconditionally so they can be used as assignments
# in the except block without triggering [no-redef].
_llama_import_exc: BaseException | None = None


class _ToolMetadataFallback:
    """Raises ImportError when llama-index-core is not installed."""

    def __init__(
        self,
        *,
        name: str = "",
        description: str = "",
        **kwargs: Any,
    ) -> None:
        raise ImportError(
            "LlamaIndex integration requires 'llama-index-core': "
            "pip install 'pramanix[llamaindex]'"
        ) from _llama_import_exc


class _ToolOutputFallback:
    """Raises ImportError when llama-index-core is not installed."""

    def __init__(
        self,
        *,
        content: str = "",
        tool_name: str = "",
        raw_input: dict[str, Any] | None = None,
        raw_output: dict[str, Any] | None = None,
        is_error: bool = False,
        **kwargs: Any,
    ) -> None:
        raise ImportError(
            "LlamaIndex integration requires 'llama-index-core': "
            "pip install 'pramanix[llamaindex]'"
        ) from _llama_import_exc


_LLAMA_AVAILABLE: bool = False

if TYPE_CHECKING:
    from llama_index.core.tools.types import ToolMetadata, ToolOutput
else:
    try:
        from llama_index.core.tools.types import ToolMetadata, ToolOutput

        _LLAMA_AVAILABLE = True
    except ImportError as _exc:
        # Python deletes `except ... as` bindings at block end — capture it so the
        # fallback constructors can chain the error.
        _llama_import_exc = _exc
        ToolMetadata = _ToolMetadataFallback
        ToolOutput = _ToolOutputFallback


# ── PramanixFunctionTool ──────────────────────────────────────────────────────


class PramanixFunctionTool:
    """LlamaIndex-compatible function tool gated by a Pramanix policy.

    NOT a subclass of ``FunctionTool`` — this avoids a hard dependency on
    ``llama-index-core`` in the Pramanix core package.  Instead, this class
    implements the same interface (``acall``, ``call``, ``metadata`` property)
    so it is a drop-in replacement wherever a LlamaIndex tool is expected.

    For each invocation:

    1. The ``input`` JSON string is parsed and validated against
       ``intent_schema``.
    2. The current state is retrieved from ``state_provider``.
    3. :meth:`~pramanix.guard.Guard.verify_async` is called.
    4. If ALLOW: ``fn(**intent)`` is called and its result returned.
    5. If BLOCK: a human-readable feedback ``ToolOutput`` is returned — no
       exception is raised for a policy violation.

    Args:
        fn:             Callable (sync or async) to execute on ALLOW.
        guard:          A pre-constructed :class:`~pramanix.guard.Guard`.
        intent_schema:  Pydantic model class for input validation.
        state_provider: Zero-argument callable returning ``dict`` (or coroutine).
        name:           Tool name shown to the LLM agent.
        description:    Tool description shown to the LLM agent.
    """

    def __init__(
        self,
        *,
        fn: Callable[..., Any],
        guard: Guard,
        intent_schema: Any,
        state_provider: Callable[[], Any],
        name: str = "",
        description: str = "",
    ) -> None:
        if not _LLAMA_AVAILABLE:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "llama_index is not installed. " "Run: pip install 'pramanix[llamaindex]'"
            )
        self._fn = fn
        self._guard = guard
        self._intent_schema = intent_schema
        self._state_provider = state_provider
        self._name = name
        self._description = description
        # H-13: one shared executor — created once, never per-call.
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pramanix-llamaindex"
        )
        # Leak-detection finalizer replaces __del__ anti-pattern.
        self._finalizer = weakref.finalize(
            self, PramanixFunctionTool._shutdown_executor, self._executor
        )

    @staticmethod
    def _shutdown_executor(executor: concurrent.futures.ThreadPoolExecutor) -> None:
        with contextlib.suppress(RuntimeError, OSError):
            executor.shutdown(wait=False)

    # ── metadata property ────────────────────────────────────────────────────

    @property
    def metadata(self) -> ToolMetadata:
        """Return ``ToolMetadata`` compatible with LlamaIndex's tool interface."""
        return ToolMetadata(name=self._name, description=self._description)

    # ── Async call (canonical) ────────────────────────────────────────────────

    async def acall(self, input: str, **kwargs: Any) -> ToolOutput:
        """Execute the tool asynchronously through the Pramanix guard.

        Returns a ``ToolOutput`` with ``is_error=False`` even when the guard
        blocks — policy violations are surfaced as content, never as errors,
        so the orchestrating agent can understand and adapt gracefully.

        Args:
            input: JSON-encoded intent string from the LLM agent.

        Returns:
            A ``ToolOutput`` with the function result on ALLOW, or a block
            feedback message on BLOCK.
        """
        # ── 1. Parse input JSON ────────────────────────────────────────────────
        try:
            raw: dict[str, Any] = json.loads(input)
        except (json.JSONDecodeError, ValueError) as exc:
            return ToolOutput(
                content=f"Pramanix: invalid input: {exc}",
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={},
                is_error=True,
            )

        # ── 2. Validate intent against schema ──────────────────────────────────
        try:
            from pydantic import ValidationError as _PydanticValidationError

            intent: dict[str, Any] = self._intent_schema.model_validate(raw).model_dump()
        except _PydanticValidationError as exc:
            return ToolOutput(
                content=f"Pramanix: invalid input: {exc}",
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={},
                is_error=True,
            )

        # ── 3. Load state ──────────────────────────────────────────────────────
        state = await self._get_state()

        # ── 4. Guard verify ────────────────────────────────────────────────────
        try:
            decision = await self._guard.verify_async(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.llamaindex.verify_error: %s", exc, exc_info=True)
            from pramanix.decision import Decision

            error_decision = Decision.error(reason=f"Guard verification error: {exc}")
            return ToolOutput(
                content=format_block_feedback(error_decision, intent),
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={},
                is_error=True,
            )

        # ── 5. ALLOW path — call fn and return result ─────────────────────────
        if decision.allowed:
            result = self._fn(**intent)
            if asyncio.iscoroutine(result):
                result = await result
            result_str = str(result)
            return ToolOutput(
                content=result_str,
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={"result": result_str},
                is_error=False,
            )

        # ── 6. BLOCK path — return feedback, never raise ───────────────────────
        feedback = format_block_feedback(decision, intent)
        return ToolOutput(
            content=feedback,
            tool_name=self._name,
            raw_input={"input": input},
            raw_output={
                "decision_id": decision.decision_id,
                "status": decision.status.value,
                "violated_invariants": list(decision.violated_invariants),
            },
            is_error=False,
        )

    # ── Sync wrapper ──────────────────────────────────────────────────────────

    def call(self, input: str, **kwargs: Any) -> ToolOutput:
        """Synchronous wrapper around :meth:`acall`.

        If no event loop is running, uses ``asyncio.run()``.  If an event loop
        is already running (e.g., inside a Jupyter notebook or async framework),
        offloads to a dedicated thread with its own event loop.

        Args:
            input: JSON-encoded intent string from the LLM agent.

        Returns:
            Same as :meth:`acall`.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — safe to use asyncio.run().
            return asyncio.run(self.acall(input, **kwargs))

        # Already inside an async context — reuse the shared executor.
        # Use a lambda so the coroutine is created in the worker thread's own
        # event loop, not the calling loop (which would raise "attached to a
        # different loop" on Python 3.10+).
        future = self._executor.submit(lambda: asyncio.run(self.acall(input, **kwargs)))
        return future.result()

    def close(self) -> None:
        """Shut down the shared thread pool executor."""
        if self._finalizer.alive:
            self._finalizer.detach()
        self._executor.shutdown(wait=False)

    # ── State retrieval ───────────────────────────────────────────────────────

    async def _get_state(self) -> dict[str, Any]:
        """Retrieve current state, awaiting if the provider is a coroutine."""
        result = self._state_provider()
        if asyncio.iscoroutine(result):
            result = await result
        return cast(dict[str, Any], result)

    # ── Class method factory ──────────────────────────────────────────────────

    @classmethod
    def from_function_tool(
        cls,
        tool: Any,
        guard: Guard,
        intent_schema: Any,
        state_provider: Callable[[], Any],
    ) -> PramanixFunctionTool:
        """Wrap an existing LlamaIndex ``FunctionTool`` with a Pramanix guard.

        Extracts the underlying callable and metadata from the existing tool
        and creates a new ``PramanixFunctionTool`` that gates execution through
        the provided Guard.

        Args:
            tool:           An existing LlamaIndex ``FunctionTool`` instance.
            guard:          A pre-constructed :class:`~pramanix.guard.Guard`.
            intent_schema:  Pydantic model class for input validation.
            state_provider: Zero-argument callable returning ``dict``.

        Returns:
            A :class:`PramanixFunctionTool` wrapping the original tool's fn.
        """
        # Extract the underlying callable from the FunctionTool.
        fn = getattr(tool, "fn", None) or getattr(tool, "_fn", None) or tool
        # Extract name and description from metadata if available.
        meta = getattr(tool, "metadata", None)
        name = getattr(meta, "name", "") if meta is not None else getattr(tool, "name", "")
        description = (
            getattr(meta, "description", "")
            if meta is not None
            else getattr(tool, "description", "")
        )
        return cls(
            fn=fn,
            guard=guard,
            intent_schema=intent_schema,
            state_provider=state_provider,
            name=name,
            description=description,
        )


# ── PramanixQueryEngineTool ───────────────────────────────────────────────────


class PramanixQueryEngineTool:
    """LlamaIndex-compatible query engine tool gated by a Pramanix policy.

    Wraps any object with an ``aquery(str) -> str`` method (or a synchronous
    ``query(str) -> str`` fallback) and gates each query through the Pramanix
    guard before forwarding to the underlying engine.

    NOT a subclass of ``QueryEngineTool`` — implements the same interface
    (``acall``, ``call``, ``metadata`` property) without the hard dependency.

    For each invocation:

    1. The ``input`` JSON string is parsed and validated against
       ``intent_schema``.
    2. The current state is retrieved from ``state_provider``.
    3. :meth:`~pramanix.guard.Guard.verify_async` is called.
    4. If BLOCK: a blocked ``ToolOutput`` is returned immediately.
    5. If ALLOW: ``query_engine.aquery(input)`` (or ``.query(input)``) is
       called and its result returned.

    Args:
        query_engine:   An object with ``aquery(str)`` or ``query(str)`` method.
        guard:          A pre-constructed :class:`~pramanix.guard.Guard`.
        intent_schema:  Pydantic model class for input validation.
        state_provider: Zero-argument callable returning ``dict`` (or coroutine).
        name:           Tool name shown to the LLM agent.
        description:    Tool description shown to the LLM agent.
    """

    def __init__(
        self,
        *,
        query_engine: Any,
        guard: Guard,
        intent_schema: Any,
        state_provider: Callable[[], Any],
        name: str = "",
        description: str = "",
    ) -> None:
        if not _LLAMA_AVAILABLE:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "llama_index is not installed. " "Run: pip install 'pramanix[llamaindex]'"
            )
        self._engine = query_engine
        self._guard = guard
        self._intent_schema = intent_schema
        self._state_provider = state_provider
        self._name = name
        self._description = description
        # H-13: one shared executor — created once at construction, never per-call.
        # Creating a new ThreadPoolExecutor per call() invocation exhausts OS
        # thread handles under agent-loop load.
        import concurrent.futures as _cf
        import weakref as _wr
        self._executor = _cf.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pramanix-llamaindex-qe"
        )
        _wr.finalize(self, _cf.ThreadPoolExecutor.shutdown, self._executor, wait=False)

    # ── metadata property ────────────────────────────────────────────────────

    @property
    def metadata(self) -> ToolMetadata:
        """Return ``ToolMetadata`` compatible with LlamaIndex's tool interface."""
        return ToolMetadata(name=self._name, description=self._description)

    # ── Async call (canonical) ────────────────────────────────────────────────

    async def acall(self, input: str, **kwargs: Any) -> ToolOutput:
        """Execute the query engine asynchronously through the Pramanix guard.

        Returns a ``ToolOutput`` with ``is_error=False`` even when the guard
        blocks — policy violations are surfaced as content, never as errors.

        Args:
            input: The query string (also used as the JSON intent for guard
                   verification if parseable as JSON).

        Returns:
            A ``ToolOutput`` with the query result on ALLOW, or a block
            feedback message on BLOCK.
        """
        # ── 1. Parse input JSON ────────────────────────────────────────────────
        try:
            raw: dict[str, Any] = json.loads(input)
        except (json.JSONDecodeError, ValueError) as exc:
            return ToolOutput(
                content=f"Pramanix: invalid input: {exc}",
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={},
                is_error=True,
            )

        # ── 2. Validate intent against schema ──────────────────────────────────
        try:
            from pydantic import ValidationError as _PydanticValidationError

            intent: dict[str, Any] = self._intent_schema.model_validate(raw).model_dump()
        except _PydanticValidationError as exc:
            return ToolOutput(
                content=f"Pramanix: invalid input: {exc}",
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={},
                is_error=True,
            )

        # ── 3. Load state ──────────────────────────────────────────────────────
        state = await self._get_state()

        # ── 4. Guard verify ────────────────────────────────────────────────────
        try:
            decision = await self._guard.verify_async(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.llamaindex.query_verify_error: %s", exc, exc_info=True)
            from pramanix.decision import Decision

            error_decision = Decision.error(reason=f"Guard verification error: {exc}")
            return ToolOutput(
                content=format_block_feedback(error_decision, intent),
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={},
                is_error=True,
            )

        # ── 5. BLOCK path ──────────────────────────────────────────────────────
        if not decision.allowed:
            feedback = format_block_feedback(decision, intent)
            return ToolOutput(
                content=feedback,
                tool_name=self._name,
                raw_input={"input": input},
                raw_output={
                    "decision_id": decision.decision_id,
                    "status": decision.status.value,
                    "violated_invariants": list(decision.violated_invariants),
                },
                is_error=False,
            )

        # ── 6. ALLOW path — forward to query engine ────────────────────────────
        engine = self._engine
        if hasattr(engine, "aquery"):
            result = engine.aquery(input)
            if asyncio.iscoroutine(result):
                result = await result
        elif hasattr(engine, "query"):
            result = engine.query(input)
            if asyncio.iscoroutine(result):
                result = await result
        else:
            result = str(engine)

        result_str = str(result)
        return ToolOutput(
            content=result_str,
            tool_name=self._name,
            raw_input={"input": input},
            raw_output={"result": result_str},
            is_error=False,
        )

    # ── Sync wrapper ──────────────────────────────────────────────────────────

    def call(self, input: str, **kwargs: Any) -> ToolOutput:
        """Synchronous wrapper around :meth:`acall`.

        If no event loop is running, uses ``asyncio.run()``.  If an event loop
        is already running, offloads to a dedicated thread with its own event
        loop.

        Args:
            input: The query string.

        Returns:
            Same as :meth:`acall`.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.acall(input, **kwargs))

        # Use the lifecycle-managed shared executor — never allocate one per call.
        future = self._executor.submit(lambda: asyncio.run(self.acall(input, **kwargs)))
        return future.result()

    # ── State retrieval ───────────────────────────────────────────────────────

    async def _get_state(self) -> dict[str, Any]:
        """Retrieve current state, awaiting if the provider is a coroutine."""
        result = self._state_provider()
        if asyncio.iscoroutine(result):
            result = await result
        return cast(dict[str, Any], result)
