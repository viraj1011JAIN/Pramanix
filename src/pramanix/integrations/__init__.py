# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix ecosystem integrations — Phase 9: The 1-Line Takeover.

One import, one line of configuration. Mathematical safety for:

* **FastAPI/ASGI** — ``PramanixMiddleware``, ``pramanix_route``
* **LangChain**   — ``PramanixGuardedTool``, ``wrap_tools``
* **LlamaIndex**  — ``PramanixFunctionTool``, ``PramanixQueryEngineTool``
* **AutoGen**     — ``PramanixToolCallback``

Each integration module is lazily imported so the corresponding framework
package is only required when that specific integration is actually used.

Quick-start::

    # FastAPI
    from pramanix.integrations.fastapi import PramanixMiddleware
    app.add_middleware(PramanixMiddleware, policy=MyPolicy, ...)

    # LangChain
    from pramanix.integrations.langchain import PramanixGuardedTool

    # LlamaIndex
    from pramanix.integrations.llamaindex import PramanixFunctionTool

    # AutoGen
    from pramanix.integrations.autogen import PramanixToolCallback
"""
from __future__ import annotations

__all__ = [
    # FastAPI
    "PramanixMiddleware",
    "pramanix_route",
    # LangChain
    "PramanixGuardedTool",
    "wrap_tools",
    # LlamaIndex
    "PramanixFunctionTool",
    "PramanixQueryEngineTool",
    # AutoGen
    "PramanixToolCallback",
]

_FASTAPI_NAMES = {"PramanixMiddleware", "pramanix_route"}
_LANGCHAIN_NAMES = {"PramanixGuardedTool", "wrap_tools"}
_LLAMA_NAMES = {"PramanixFunctionTool", "PramanixQueryEngineTool"}
_AUTOGEN_NAMES = {"PramanixToolCallback"}


def __getattr__(name: str) -> object:
    if name in _FASTAPI_NAMES:
        from pramanix.integrations import fastapi as _m
        return getattr(_m, name)
    if name in _LANGCHAIN_NAMES:
        from pramanix.integrations import langchain as _m  # type: ignore[no-redef]
        return getattr(_m, name)
    if name in _LLAMA_NAMES:
        from pramanix.integrations import llamaindex as _m  # type: ignore[no-redef]
        return getattr(_m, name)
    if name in _AUTOGEN_NAMES:
        from pramanix.integrations import autogen as _m  # type: ignore[no-redef]
        return getattr(_m, name)
    raise AttributeError(f"module 'pramanix.integrations' has no attribute {name!r}")
