# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Trust labels and classified data — the foundation of information-flow control.

The trust lattice is total-ordered (PUBLIC < INTERNAL < CUSTOMER < CONFIDENTIAL
< REGULATED < UNTRUSTED).  The ordering is used for dominance checks:
data at label *L* may flow to a sink at label *L'* only if *L'* >= *L*
(the Bell–LaPadula "no-read-up" direction for integrity, inverted here for
secrecy enforcement in the data-movement sense used by IFC libraries).

Pramanix uses the following semantics:

* **PUBLIC** — freely shareable; no restrictions.
* **INTERNAL** — internal systems only; must not leave the deployment perimeter.
* **CUSTOMER** — customer-scoped; tenant isolation required.
* **CONFIDENTIAL** — need-to-know; explicit authorization per component.
* **REGULATED** — PII, PHI, or PCI data; only regulated-approved sinks allowed;
  all flows must be audit-logged.
* **UNTRUSTED** — raw prompt material, user input, or tool output that has not
  been validated.  Cannot directly authorize privileged actions.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

__all__ = [
    "ClassifiedData",
    "TrustLabel",
]


class TrustLabel(IntEnum):
    """Sensitivity levels for data flowing through the Pramanix runtime.

    Labels are totally ordered: ``PUBLIC < INTERNAL < CUSTOMER <
    CONFIDENTIAL < REGULATED < UNTRUSTED``.

    The ordering means **a higher integer value denotes a label that places
    more restrictions** on where data may flow.

    ``UNTRUSTED`` occupies the highest integer position because untrusted data
    is the most constrained: it must not propagate to components that can take
    privileged actions without first passing sanitization.
    """

    PUBLIC = 0
    INTERNAL = 1
    CUSTOMER = 2
    CONFIDENTIAL = 3
    REGULATED = 4
    UNTRUSTED = 5

    # ── Convenience predicates ─────────────────────────────────────────────

    def requires_audit(self) -> bool:
        """True for REGULATED and above — every flow must be audit-logged."""
        return self >= TrustLabel.REGULATED

    def requires_authorization(self) -> bool:
        """True for CONFIDENTIAL and above."""
        return self >= TrustLabel.CONFIDENTIAL

    def is_tenant_scoped(self) -> bool:
        """True for CUSTOMER and above — cross-tenant isolation is mandatory."""
        return self >= TrustLabel.CUSTOMER


@dataclass(frozen=True)
class ClassifiedData:
    """Immutable wrapper that binds a piece of data to its trust label.

    All data entering the Pramanix runtime should be wrapped in a
    :class:`ClassifiedData` object so that the :class:`~pramanix.ifc.FlowEnforcer`
    can track its classification through the full processing pipeline.

    Attributes:
        data:       The actual payload — any Python object.
        label:      The :class:`TrustLabel` of this data.
        source:     Canonical name of the component that produced this data
                    (e.g. ``"user_input"``, ``"retriever"``, ``"tool:web_search"``).
        created_at: Unix timestamp of creation.
        lineage:    Ordered tuple of component names this data has transited.
                    Appended to by :meth:`taint`; never modified in-place.

    Example::

        raw = ClassifiedData(
            data=user_prompt,
            label=TrustLabel.UNTRUSTED,
            source="user_input",
        )
        sanitised = raw.taint("injection_filter").downgrade(
            TrustLabel.INTERNAL,
            redactor=lambda s: html.escape(s),
        )
    """

    data: Any
    label: TrustLabel
    source: str
    created_at: float = field(default_factory=time.time)
    lineage: tuple[str, ...] = field(default_factory=tuple)

    # ── Transformation helpers ─────────────────────────────────────────────

    def taint(self, component: str) -> "ClassifiedData":
        """Return a copy marking transit through *component*.

        Does not change the trust label — use :meth:`downgrade` or the
        :class:`~pramanix.ifc.FlowEnforcer` gate for that.

        Args:
            component: Name of the component processing this data.

        Returns:
            A new :class:`ClassifiedData` with *component* appended to lineage.
        """
        return ClassifiedData(
            data=self.data,
            label=self.label,
            source=self.source,
            created_at=self.created_at,
            lineage=(*self.lineage, component),
        )

    def downgrade(
        self,
        to_label: TrustLabel,
        redactor: Callable[[Any], Any],
    ) -> "ClassifiedData":
        """Return a copy with a *lower* label after applying *redactor*.

        Downgrading (moving to a less-sensitive label) requires a transformation
        because the original high-sensitivity representation must not be passed
        through unchanged.

        Args:
            to_label:  Target label.  Must be strictly *less than* the current
                       label (no-op upgrades are rejected to prevent accidents).
            redactor:  Callable applied to ``self.data`` to produce the
                       sanitised version.  Examples: ``str.lower``,
                       ``anonymise_pii``, ``lambda x: "[REDACTED]"``.

        Returns:
            A new :class:`ClassifiedData` with the redacted data and *to_label*.

        Raises:
            ValueError: If *to_label* is not strictly less than the current label.
        """
        if to_label >= self.label:
            raise ValueError(
                f"downgrade() requires to_label < current label; "
                f"got {to_label.name} >= {self.label.name}."
            )
        return ClassifiedData(
            data=redactor(self.data),
            label=to_label,
            source=self.source,
            created_at=self.created_at,
            lineage=(
                *self.lineage,
                f"downgrade:{self.label.name}->{to_label.name}",
            ),
        )

    def upgrade(self, to_label: TrustLabel, reason: str) -> "ClassifiedData":
        """Return a copy with a *higher* label.

        Upgrading is used when new context reveals that data is more sensitive
        than originally classified (e.g. a tool returns PII).

        Args:
            to_label: Target label.  Must be strictly *greater than* current.
            reason:   Audit note explaining why the upgrade is warranted.

        Raises:
            ValueError: If *to_label* is not strictly greater than current label.
        """
        if to_label <= self.label:
            raise ValueError(
                f"upgrade() requires to_label > current label; "
                f"got {to_label.name} <= {self.label.name}."
            )
        return ClassifiedData(
            data=self.data,
            label=to_label,
            source=self.source,
            created_at=self.created_at,
            lineage=(
                *self.lineage,
                f"upgrade:{self.label.name}->{to_label.name}:{reason}",
            ),
        )

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_audit_dict(self) -> dict[str, object]:
        """Return a JSON-safe audit representation (data payload is excluded)."""
        return {
            "label": self.label.name,
            "source": self.source,
            "created_at": self.created_at,
            "lineage": list(self.lineage),
        }
