# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Privilege separation for the Pramanix agentic runtime."""
from pramanix.privilege.scope import (
    CapabilityManifest,
    ExecutionContext,
    ExecutionScope,
    ScopeEnforcer,
    ToolCapability,
)

__all__ = [
    "CapabilityManifest",
    "ExecutionContext",
    "ExecutionScope",
    "ScopeEnforcer",
    "ToolCapability",
]
