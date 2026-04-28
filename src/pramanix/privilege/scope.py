# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""ExecutionScope, CapabilityManifest, and ScopeEnforcer for privilege separation.

Every tool, action, or capability in the Pramanix runtime must declare the
:class:`ExecutionScope` it requires.  The :class:`ScopeEnforcer` validates that
the current execution context holds the necessary scope before the action is
allowed to proceed.

Design principles
-----------------
* **Least privilege by default** — tools start with no scope; each required
  scope must be explicitly granted via a :class:`CapabilityManifest`.
* **Composable scopes** — :class:`ExecutionScope` uses ``IntFlag`` so
  compound scopes are expressed naturally:
  ``ExecutionScope.WRITE | ExecutionScope.NETWORK``.
* **Immutable manifests** — :class:`CapabilityManifest` instances are frozen;
  scope grants cannot be mutated after construction.
* **Dual-control for destructive scopes** — ``FINANCIAL`` and ``DESTRUCTIVE``
  actions require an ``approved_by`` evidence reference in the execution context
  unless dual-control is explicitly disabled in the manifest.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import IntFlag, auto
from typing import Any

from pramanix.exceptions import PrivilegeEscalationError

__all__ = [
    "CapabilityManifest",
    "ExecutionContext",
    "ExecutionScope",
    "ScopeEnforcer",
    "ToolCapability",
]

_log = logging.getLogger(__name__)


class ExecutionScope(IntFlag):
    """Capability flags for execution privilege separation.

    Scopes compose via bitwise OR.  The numeric ordering has no security
    meaning — all flag checks use ``in`` / ``&`` operations.

    * **READ_ONLY** — may query data but not modify it.
    * **WRITE** — may modify state (e.g. update a database record).
    * **NETWORK** — may make outbound network connections.
    * **FINANCIAL** — may initiate financial transactions.  Requires
      dual-control approval by default.
    * **DESTRUCTIVE** — may permanently delete or overwrite data.  Requires
      dual-control approval by default.
    * **ADMIN** — may modify policy, user privileges, or system configuration.
      Highest-risk scope; should be granted to no automated agent.
    """

    NONE = 0
    READ_ONLY = auto()
    WRITE = auto()
    NETWORK = auto()
    FINANCIAL = auto()
    DESTRUCTIVE = auto()
    ADMIN = auto()

    # ── Helpers ───────────────────────────────────────────────────────────

    def requires_dual_control(self) -> bool:
        """True for scopes that mandate human approval by default."""
        return bool(self & (ExecutionScope.FINANCIAL | ExecutionScope.DESTRUCTIVE | ExecutionScope.ADMIN))

    def scope_names(self) -> list[str]:
        """Return list of flag names present in this compound scope."""
        return [
            s.name
            for s in ExecutionScope
            if s != ExecutionScope.NONE and s in self
        ]


@dataclass(frozen=True)
class ToolCapability:
    """Declaration of the scopes a single tool requires.

    Attributes:
        tool_name:           Canonical tool identifier.
        required_scopes:     The :class:`ExecutionScope` flags this tool needs.
        description:         Human-readable description of what the tool does.
        allows_dual_control_bypass: When ``True``, dual-control checks are
            skipped for this tool even when it holds FINANCIAL/DESTRUCTIVE scope.
            Should be ``False`` in production.
    """

    tool_name: str
    required_scopes: ExecutionScope = ExecutionScope.NONE
    description: str = ""
    allows_dual_control_bypass: bool = False


@dataclass(frozen=True)
class ExecutionContext:
    """Active execution context presented to the :class:`ScopeEnforcer`.

    Attributes:
        granted_scopes:  The scopes currently held by the executing principal.
        principal_id:    Identifier of the agent/service executing (for audit).
        approved_by:     Evidence reference for dual-control approval
                         (e.g. oversight request ID).  Required for FINANCIAL
                         and DESTRUCTIVE actions unless bypass is permitted.
        metadata:        Arbitrary key-value pairs for audit correlation.
    """

    granted_scopes: ExecutionScope = ExecutionScope.NONE
    principal_id: str = ""
    approved_by: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class CapabilityManifest:
    """Registry of :class:`ToolCapability` declarations for a deployment.

    A manifest describes every tool the agent may invoke, along with the
    scopes each tool requires.  The :class:`ScopeEnforcer` uses the manifest
    as its authoritative source when evaluating capability checks.

    The manifest is **deny-by-default for unknown tools**: any tool not
    registered in the manifest will be denied regardless of the context's
    granted scopes.

    Args:
        capabilities:   List of :class:`ToolCapability` declarations.
        deny_unknown:   When ``True`` (default), unregistered tool names are
                        denied.  Set to ``False`` to allow tools not in the
                        manifest (development only).

    Example::

        manifest = CapabilityManifest(
            capabilities=[
                ToolCapability(
                    "read_account",
                    ExecutionScope.READ_ONLY,
                    description="Read account balance.",
                ),
                ToolCapability(
                    "transfer_funds",
                    ExecutionScope.WRITE | ExecutionScope.FINANCIAL,
                    description="Transfer funds between accounts.",
                ),
            ]
        )
    """

    def __init__(
        self,
        capabilities: list[ToolCapability],
        *,
        deny_unknown: bool = True,
    ) -> None:
        self._capabilities: dict[str, ToolCapability] = {
            cap.tool_name: cap for cap in capabilities
        }
        self._deny_unknown = deny_unknown

    def get(self, tool_name: str) -> ToolCapability | None:
        """Return the :class:`ToolCapability` for *tool_name*, or ``None``."""
        return self._capabilities.get(tool_name)

    def registered_tools(self) -> list[str]:
        """Return sorted list of registered tool names."""
        return sorted(self._capabilities.keys())

    @property
    def deny_unknown(self) -> bool:
        """True when unregistered tool names are denied."""
        return self._deny_unknown


class ScopeEnforcer:
    """Validates that an :class:`ExecutionContext` holds required scopes.

    Checks performed for each call to :meth:`enforce`:

    1. **Tool registration** — the tool must be in the
       :class:`CapabilityManifest` (if ``deny_unknown=True``).
    2. **Scope presence** — every scope bit required by the tool's
       :class:`ToolCapability` must be present in ``context.granted_scopes``.
    3. **Dual-control** — if the required scope includes ``FINANCIAL``,
       ``DESTRUCTIVE``, or ``ADMIN``, and the capability does not explicitly
       allow bypass, ``context.approved_by`` must be non-empty.

    Every enforcement event is recorded in the audit log.

    Args:
        manifest:  The :class:`CapabilityManifest` describing all tools.

    Example::

        enforcer = ScopeEnforcer(manifest)
        ctx = ExecutionContext(
            granted_scopes=ExecutionScope.READ_ONLY,
            principal_id="agent-001",
        )
        enforcer.enforce("read_account", ctx)    # OK
        enforcer.enforce("transfer_funds", ctx)  # raises PrivilegeEscalationError
    """

    def __init__(self, manifest: CapabilityManifest) -> None:
        self._manifest = manifest
        self._lock = threading.Lock()
        self._audit_log: list[dict[str, object]] = []

    def enforce(self, tool_name: str, context: ExecutionContext) -> None:
        """Assert that *context* holds the scopes required by *tool_name*.

        Args:
            tool_name: The tool being invoked.
            context:   The active :class:`ExecutionContext`.

        Raises:
            PrivilegeEscalationError: When any required scope is absent or
                dual-control evidence is missing.
        """
        capability = self._manifest.get(tool_name)

        if capability is None:
            permitted = not self._manifest.deny_unknown
            self._record(tool_name, context, permitted, "unknown tool")
            if not permitted:
                _log.warning(
                    "privilege.unknown_tool: '%s' not in manifest (principal=%s)",
                    tool_name,
                    context.principal_id,
                )
                raise PrivilegeEscalationError(
                    f"Tool '{tool_name}' is not registered in the capability manifest. "
                    "Register it with a ToolCapability before use.",
                    required_scope="REGISTERED",
                    held_scopes=frozenset(context.granted_scopes.scope_names()),
                    tool=tool_name,
                )
            return

        required = capability.required_scopes
        held = context.granted_scopes

        # Check every required scope bit.
        missing = required & ~held
        if missing:
            missing_names = missing.scope_names()
            self._record(tool_name, context, False, f"missing scopes: {missing_names}")
            _log.warning(
                "privilege.scope_missing: tool=%s required=%s held=%s principal=%s",
                tool_name,
                required.scope_names(),
                held.scope_names(),
                context.principal_id,
            )
            raise PrivilegeEscalationError(
                f"Tool '{tool_name}' requires scope(s) "
                f"{missing_names} which are not in the execution context "
                f"(principal='{context.principal_id}').",
                required_scope=", ".join(missing_names),
                held_scopes=frozenset(held.scope_names()),
                tool=tool_name,
            )

        # Dual-control check for high-risk scopes.
        if required.requires_dual_control() and not capability.allows_dual_control_bypass:
            if not context.approved_by:
                self._record(tool_name, context, False, "dual-control approval missing")
                _log.warning(
                    "privilege.dual_control_required: tool=%s principal=%s",
                    tool_name,
                    context.principal_id,
                )
                raise PrivilegeEscalationError(
                    f"Tool '{tool_name}' requires dual-control approval "
                    f"(scopes: {required.scope_names()}). "
                    "Set ExecutionContext.approved_by to the oversight approval ID.",
                    required_scope="DUAL_CONTROL_APPROVAL",
                    held_scopes=frozenset(held.scope_names()),
                    tool=tool_name,
                )

        self._record(tool_name, context, True, "permitted")
        _log.debug(
            "privilege.granted: tool=%s principal=%s scopes=%s",
            tool_name,
            context.principal_id,
            required.scope_names(),
        )

    def audit_log(self) -> list[dict[str, object]]:
        """Return a copy of all enforcement events."""
        with self._lock:
            return list(self._audit_log)

    def _record(
        self,
        tool_name: str,
        context: ExecutionContext,
        permitted: bool,
        reason: str,
    ) -> None:
        entry: dict[str, object] = {
            "tool": tool_name,
            "principal_id": context.principal_id,
            "granted_scopes": context.granted_scopes.scope_names(),
            "approved_by": context.approved_by,
            "permitted": permitted,
            "reason": reason,
        }
        with self._lock:
            self._audit_log.append(entry)
