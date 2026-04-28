# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Flow rules and policy — what data is allowed to flow where."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pramanix.ifc.labels import TrustLabel

__all__ = [
    "FlowDecision",
    "FlowPolicy",
    "FlowRule",
]


@dataclass(frozen=True)
class FlowRule:
    """A single data-flow permission (or prohibition).

    Rules are evaluated in declaration order; the first matching rule wins.
    If *permitted* is ``False``, the flow is explicitly forbidden even if a
    later rule would permit it.

    Attributes:
        source_label:     The trust label of the data being moved.
        sink_label:       The required label of the sink receiving the data.
        source_component: Glob-style component name pattern for the sender
                          (``None`` matches any component).
        sink_component:   Glob-style component name pattern for the receiver
                          (``None`` matches any component).
        permitted:        ``True`` = this flow is allowed; ``False`` = denied.
        requires_redaction: When ``True`` and the flow is permitted, the
                            :class:`~pramanix.ifc.FlowEnforcer` will demand
                            that a redactor callable is provided before
                            passing data to the sink.
        reason:           Human-readable rationale for the rule (shown in errors).
    """

    source_label: TrustLabel
    sink_label: TrustLabel
    source_component: str | None = None
    sink_component: str | None = None
    permitted: bool = True
    requires_redaction: bool = False
    reason: str = ""

    def matches(
        self,
        data_label: TrustLabel,
        sink_label: TrustLabel,
        source_component: str,
        sink_component: str,
    ) -> bool:
        """Return True if this rule applies to the given flow parameters."""
        if data_label != self.source_label:
            return False
        if sink_label != self.sink_label:
            return False
        if (
            self.source_component is not None
            and self.source_component != source_component
        ):
            return False
        if (
            self.sink_component is not None
            and self.sink_component != sink_component
        ):
            return False
        return True


@dataclass(frozen=True)
class FlowDecision:
    """Result of a single flow-policy evaluation.

    Attributes:
        permitted:           Whether the flow is allowed.
        requires_redaction:  When ``True`` the caller must supply a redactor.
        matched_rule:        The :class:`FlowRule` that matched, or ``None``
                             when the decision came from the default policy.
        reason:              Human-readable explanation.
    """

    permitted: bool
    requires_redaction: bool = False
    matched_rule: FlowRule | None = None
    reason: str = ""


class FlowPolicy:
    """Immutable ordered collection of :class:`FlowRule` objects.

    Evaluation is first-match-wins.  If no rule matches and
    ``default_deny=True`` (the default), the flow is denied.

    Pramanix ships with three built-in presets accessible via class methods:

    * :meth:`permissive` — allows all flows (development / testing only).
    * :meth:`strict` — denies all cross-label flows; data stays at its
      original label unless explicitly downgraded.
    * :meth:`regulated` — preset for PCI/HIPAA deployments: REGULATED data
      may only flow to approved sinks and never to PUBLIC or INTERNAL ones.

    Args:
        rules:        Ordered list of :class:`FlowRule` objects.
        default_deny: When ``True`` (the default), flows not matched by any
                      rule are denied.  Set to ``False`` only for development.

    Example::

        policy = FlowPolicy(
            rules=[
                FlowRule(
                    source_label=TrustLabel.REGULATED,
                    sink_label=TrustLabel.REGULATED,
                    sink_component="audit_sink",
                    permitted=True,
                    reason="REGULATED data may flow to the audit sink.",
                ),
                FlowRule(
                    source_label=TrustLabel.UNTRUSTED,
                    sink_label=TrustLabel.PUBLIC,
                    permitted=False,
                    reason="Untrusted data must not reach public outputs.",
                ),
            ],
            default_deny=True,
        )
    """

    def __init__(
        self,
        rules: list[FlowRule],
        *,
        default_deny: bool = True,
    ) -> None:
        self._rules: tuple[FlowRule, ...] = tuple(rules)
        self._default_deny = default_deny

    # ── Evaluation ────────────────────────────────────────────────────────

    def evaluate(
        self,
        data_label: TrustLabel,
        sink_label: TrustLabel,
        source_component: str = "",
        sink_component: str = "",
    ) -> FlowDecision:
        """Evaluate whether *data_label* → *sink_label* is permitted.

        Args:
            data_label:       Trust label of the data being moved.
            sink_label:       Trust label of the destination sink.
            source_component: Name of the sending component.
            sink_component:   Name of the receiving component.

        Returns:
            A :class:`FlowDecision` describing the result and which rule matched.
        """
        for rule in self._rules:
            if rule.matches(
                data_label, sink_label, source_component, sink_component
            ):
                return FlowDecision(
                    permitted=rule.permitted,
                    requires_redaction=rule.requires_redaction,
                    matched_rule=rule,
                    reason=rule.reason or (
                        "permitted" if rule.permitted else "explicitly forbidden"
                    ),
                )

        if self._default_deny:
            return FlowDecision(
                permitted=False,
                reason=(
                    f"Default-deny: no rule permits "
                    f"{data_label.name} → {sink_label.name} "
                    f"({source_component!r} → {sink_component!r})."
                ),
            )

        return FlowDecision(
            permitted=True,
            reason="Default-allow: no rule matched.",
        )

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def rules(self) -> tuple[FlowRule, ...]:
        """Read-only view of the registered rules."""
        return self._rules

    @property
    def default_deny(self) -> bool:
        """True when flows not matched by any rule are denied."""
        return self._default_deny

    # ── Built-in presets ──────────────────────────────────────────────────

    @classmethod
    def permissive(cls) -> "FlowPolicy":
        """Allow all flows (development and testing only)."""
        return cls(rules=[], default_deny=False)

    @classmethod
    def strict(cls) -> "FlowPolicy":
        """Deny all cross-label flows; same-label flows are permitted.

        Each label may only flow to an equal-label sink.  This is the most
        restrictive preset and requires explicit rules for any downgrade.
        """
        rules = [
            FlowRule(
                source_label=label,
                sink_label=label,
                permitted=True,
                reason=f"Same-label flow permitted: {label.name} → {label.name}.",
            )
            for label in TrustLabel
        ]
        return cls(rules=rules, default_deny=True)

    @classmethod
    def regulated(cls) -> "FlowPolicy":
        """Preset for PCI/HIPAA deployments.

        * REGULATED data may only flow to REGULATED sinks.
        * CONFIDENTIAL data may flow to CONFIDENTIAL or REGULATED sinks.
        * UNTRUSTED data may never flow to PUBLIC, INTERNAL, or CUSTOMER sinks.
        * All other same-label flows are permitted.
        * All cross-downgrade flows are denied (no implicit downgrades).
        """
        rules: list[FlowRule] = [
            # REGULATED: only to REGULATED
            FlowRule(
                TrustLabel.REGULATED,
                TrustLabel.REGULATED,
                permitted=True,
                reason="REGULATED → REGULATED: approved.",
            ),
            FlowRule(
                TrustLabel.REGULATED,
                TrustLabel.PUBLIC,
                permitted=False,
                reason="REGULATED data must not reach PUBLIC sinks.",
            ),
            FlowRule(
                TrustLabel.REGULATED,
                TrustLabel.INTERNAL,
                permitted=False,
                reason="REGULATED data must not flow to INTERNAL sinks.",
            ),
            # UNTRUSTED: never to low-trust outputs
            FlowRule(
                TrustLabel.UNTRUSTED,
                TrustLabel.PUBLIC,
                permitted=False,
                reason="UNTRUSTED data must not reach PUBLIC outputs.",
            ),
            FlowRule(
                TrustLabel.UNTRUSTED,
                TrustLabel.INTERNAL,
                permitted=False,
                reason="UNTRUSTED data must not flow directly to INTERNAL sinks.",
            ),
            FlowRule(
                TrustLabel.UNTRUSTED,
                TrustLabel.CUSTOMER,
                permitted=False,
                reason="UNTRUSTED data must not flow to CUSTOMER sinks without sanitisation.",
            ),
            # Same-label flows for remaining labels
            *[
                FlowRule(
                    label,
                    label,
                    permitted=True,
                    reason=f"Same-label flow: {label.name}.",
                )
                for label in TrustLabel
            ],
        ]
        return cls(rules=rules, default_deny=True)
