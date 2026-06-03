# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Information-flow control for the Pramanix agentic runtime.

Provides a complete data-classification and flow-policy enforcement layer:

* :class:`TrustLabel` — ordered sensitivity lattice
  (PUBLIC → INTERNAL → CUSTOMER → CONFIDENTIAL → REGULATED → UNTRUSTED).
* :class:`ClassifiedData` — immutable wrapper binding any data to its label
  with lineage tracking.
* :class:`FlowRule` / :class:`FlowPolicy` — declarative flow permission rules
  with a default-deny option and built-in presets.
* :class:`FlowEnforcer` — stateful runtime gate that enforces the policy,
  applies redaction, and records every enforcement event.

Quick-start::

    from pramanix.ifc import TrustLabel, ClassifiedData, FlowPolicy, FlowEnforcer

    enforcer = FlowEnforcer(FlowPolicy.regulated())

    user_input = ClassifiedData(
        data="transfer $500 to alice",
        label=TrustLabel.UNTRUSTED,
        source="user_input",
    )

    # Gate before passing to the LLM extractor:
    safe = enforcer.gate(
        user_input,
        sink_label=TrustLabel.UNTRUSTED,
        sink_component="llm_extractor",
    )
"""

from pramanix.ifc.enforcer import FlowEnforcer
from pramanix.ifc.flow_policy import FlowDecision, FlowPolicy, FlowRule
from pramanix.ifc.labels import ClassifiedData, TrustLabel

__all__ = [
    "ClassifiedData",
    "FlowDecision",
    "FlowEnforcer",
    "FlowPolicy",
    "FlowRule",
    "TrustLabel",
]
