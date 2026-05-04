# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""GovernanceConfig — validated bundle of Guard governance subsystems.

This dataclass groups the four optional governance pillars (IFC, privilege,
oversight, and execution scope) that Guard enforces inline after a Z3 SAFE
result.  Structural cross-validation in ``__post_init__`` prevents
misconfiguration at construction time — not at runtime.

Usage::

    from pramanix import Guard, GuardConfig, GovernanceConfig
    from pramanix.ifc import FlowPolicy
    from pramanix.privilege import CapabilityManifest, ExecutionScope

    gov = GovernanceConfig(
        capability_manifest=manifest,
        execution_scope=ExecutionScope.FILE_READ | ExecutionScope.NET_EGRESS,
    )

    guard = Guard(BankingPolicy, GuardConfig(governance=gov))

Placing all governance fields inside ``GovernanceConfig`` (rather than flat
on ``GuardConfig``) enforces a clean separation of concerns and enables
structural validation — for example, ``execution_scope`` without a
``capability_manifest`` to enforce it against is caught immediately at
construction time rather than silently failing at verify time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["GovernanceConfig"]


@dataclass(frozen=True)
class GovernanceConfig:
    """Immutable, cross-validated bundle of Guard governance subsystems.

    All four fields are optional; omitting ``GovernanceConfig`` entirely (or
    leaving all fields at their defaults) disables every governance gate.

    Cross-validation rules (enforced in ``__post_init__``):

    * :attr:`execution_scope` requires :attr:`capability_manifest` — setting
      granted scopes without a manifest to enforce them against is always a
      misconfiguration that would be silently ignored at runtime.

    Attributes:
        ifc_policy:          Optional :class:`~pramanix.ifc.FlowPolicy`.
        capability_manifest: Optional :class:`~pramanix.privilege.CapabilityManifest`.
        execution_scope:     Granted :class:`~pramanix.privilege.ExecutionScope` flags.
        oversight_workflow:  Optional human-in-the-loop approval workflow.
    """

    ifc_policy: Any | None = field(default=None)
    """Optional :class:`~pramanix.ifc.FlowPolicy` for information-flow control.

    When set, Guard enforces IFC inline after a Z3 SAFE result.  Callers
    signal IFC context via four reserved intent keys:

    * ``_ifc_source_label`` — integer :class:`~pramanix.ifc.TrustLabel` value
      of the data source (e.g. ``0`` for UNTRUSTED, ``2`` for INTERNAL).
    * ``_ifc_sink_label`` — trust label of the destination component.
    * ``_ifc_source_component`` — name of the originating component.
    * ``_ifc_sink_component`` — name of the receiving component.

    If any of these keys are absent the IFC gate is skipped for that call.
    On denial, :meth:`~pramanix.decision.Decision.governance_blocked` is
    returned with ``stage="ifc"``.

    Default: ``None`` (IFC not enforced).
    """

    capability_manifest: Any | None = field(default=None)
    """Optional :class:`~pramanix.privilege.CapabilityManifest` for privilege
    separation.

    When set, Guard enforces least-privilege inline after a Z3 SAFE result.
    The tool name is read from ``intent["tool"]``; if absent the privilege
    gate is skipped.  Granted scopes come from :attr:`execution_scope`.

    On denial, :meth:`~pramanix.decision.Decision.governance_blocked` is
    returned with ``stage="privilege"``.

    Default: ``None`` (privilege separation not enforced).
    """

    execution_scope: Any | None = field(default=None)
    """Granted :class:`~pramanix.privilege.ExecutionScope` flags for this
    Guard's principal.

    Used by the inline privilege gate when :attr:`capability_manifest` is set.
    Represents the maximum scope the calling agent is allowed to exercise.
    Requires :attr:`capability_manifest` to be set (validated in
    ``__post_init__``).

    Default: ``None`` → treated as ``ExecutionScope.NONE`` (deny all
    capability checks).
    """

    oversight_workflow: Any | None = field(default=None)
    """Optional :class:`~pramanix.oversight.InMemoryApprovalWorkflow` (or any
    compatible approval workflow implementation).

    When set, Guard enforces human oversight inline after a Z3 SAFE result:

    * If ``intent["oversight_request_id"]`` is present, Guard calls
      ``workflow.check(request_id)`` — if not approved it returns
      :meth:`~pramanix.decision.Decision.governance_blocked` with
      ``stage="oversight"``.
    * If absent, Guard calls ``workflow.request_approval(...)`` which raises
      :exc:`~pramanix.oversight.OversightRequiredError`; Guard catches it
      and returns GOVERNANCE_BLOCKED with
      ``metadata["oversight_request_id"]`` set so callers can route the
      approval request to a human reviewer, then retry with that ID.

    Default: ``None`` (human oversight not enforced).
    """

    def __post_init__(self) -> None:
        # Lazy import inside __post_init__ to prevent circular imports at
        # module load time — governance_config is imported by guard_config
        # which is imported by guard, so the import chain must not form a cycle.
        from pramanix.exceptions import ConfigurationError

        if self.execution_scope is not None and self.capability_manifest is None:
            raise ConfigurationError(
                "GovernanceConfig: execution_scope requires capability_manifest. "
                "Provide a CapabilityManifest that defines which tools map to which "
                "scopes, or remove execution_scope."
            )
