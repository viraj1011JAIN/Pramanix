# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
    "INTEGRATION_STATUS",
    # Agent orchestration (framework-agnostic Protocol)
    "AgentOrchestrationAdapter",
    # FastAPI
    "PramanixMiddleware",
    "pramanix_route",
    # LangChain
    "PramanixGuardedTool",
    "wrap_tools",
    # LangGraph
    "GuardNodeAdapterProtocol",
    "PramanixGuardNode",
    "PramanixNodeBlockedError",
    "pramanix_node",
    # LlamaIndex
    "PramanixFunctionTool",
    "PramanixQueryEngineTool",
    # AutoGen
    "PramanixToolCallback",
    # Phase F-1 — present, minimal framework test coverage (install optional extra first)
    "HaystackGuardedComponent",
    "PramanixCrewAITool",
    "PramanixGuardedModule",
    "PramanixPydanticAIValidator",
    "PramanixSemanticKernelPlugin",
]

# Runtime-inspectable maturity labels.  Operators can call
# ``pramanix.integrations.INTEGRATION_STATUS`` from health checks or
# support scripts to determine which integrations are production-ready.
INTEGRATION_STATUS: dict[str, str] = {
    # ── Production-ready integrations ─────────────────────────────────────────
    "AgentOrchestrationAdapter": "stable",
    "GuardNodeAdapterProtocol": "stable",
    "PramanixMiddleware": "stable",
    "pramanix_route": "stable",
    "PramanixGuardedTool": "stable",
    "wrap_tools": "stable",
    "PramanixGuardNode": "stable",
    "PramanixNodeBlockedError": "stable",
    "pramanix_node": "stable",
    "PramanixFunctionTool": "stable",
    "PramanixQueryEngineTool": "stable",
    "PramanixToolCallback": "stable",
    # ── Phase F-1 — beta (framework package required; minimal live test coverage)
    "HaystackGuardedComponent": "beta",
    "PramanixCrewAITool": "beta",
    "PramanixGuardedModule": "beta",
    "PramanixPydanticAIValidator": "beta",
    "PramanixSemanticKernelPlugin": "beta",
}

# Dispatch table: public name → submodule path.
# Using importlib.import_module avoids the repeated `_m` local-variable
# redefinitions that mypy flags as no-redef errors.
_NAME_TO_MODULE: dict[str, str] = {
    # Agent orchestration (framework-agnostic Protocol)
    "AgentOrchestrationAdapter": "pramanix.integrations.agent_orchestration",
    # FastAPI / ASGI
    "PramanixMiddleware": "pramanix.integrations.fastapi",
    "pramanix_route": "pramanix.integrations.fastapi",
    # LangChain
    "PramanixGuardedTool": "pramanix.integrations.langchain",
    "wrap_tools": "pramanix.integrations.langchain",
    # LangGraph
    "GuardNodeAdapterProtocol": "pramanix.integrations.langgraph",
    "PramanixGuardNode": "pramanix.integrations.langgraph",
    "PramanixNodeBlockedError": "pramanix.integrations.langgraph",
    "pramanix_node": "pramanix.integrations.langgraph",
    # LlamaIndex
    "PramanixFunctionTool": "pramanix.integrations.llamaindex",
    "PramanixQueryEngineTool": "pramanix.integrations.llamaindex",
    # AutoGen
    "PramanixToolCallback": "pramanix.integrations.autogen",
    # CrewAI
    "PramanixCrewAITool": "pramanix.integrations.crewai",
    # DSPy
    "PramanixGuardedModule": "pramanix.integrations.dspy",
    # Haystack
    "HaystackGuardedComponent": "pramanix.integrations.haystack",
    # Semantic Kernel
    "PramanixSemanticKernelPlugin": "pramanix.integrations.semantic_kernel",
    # PydanticAI
    "PramanixPydanticAIValidator": "pramanix.integrations.pydantic_ai",
}


def __getattr__(name: str) -> object:
    import importlib
    import types

    module_path = _NAME_TO_MODULE.get(name)
    if module_path is not None:
        mod: types.ModuleType = importlib.import_module(module_path)
        return getattr(mod, name)
    raise AttributeError(f"module 'pramanix.integrations' has no attribute {name!r}")
