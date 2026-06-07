# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Compliance Oracle — Pillar 3 of Pramanix: the Regulatory Attestation Engine.

Overview
--------
This module translates raw :class:`~pramanix.provenance.ProvenanceRecord`
objects into structured, auditor-ready :class:`ComplianceAttestation` instances
by mapping Pramanix invariant labels and cryptographic principal identities to
authoritative regulatory framework controls.

Architectural position
----------------------
The :class:`ComplianceOracle` sits **entirely outside** the Guard hot path.
It consumes *finished* :class:`~pramanix.provenance.ProvenanceRecord` objects
— which are themselves derived from completed :class:`~pramanix.decision.Decision`
objects — and is designed to run asynchronously, in a batch pipeline, or
offline from a persisted audit log.  **It must never be called from within
``Guard.verify()``.**

Regulatory frameworks supported
--------------------------------

+------------------+------------------------------------------------------+
| Enum member      | Standard                                             |
+==================+======================================================+
| ``SOC2``         | AICPA SOC 2 Type II (Trust Services Criteria)        |
+------------------+------------------------------------------------------+
| ``EU_AI_ACT``    | EU Artificial Intelligence Act (2024/1689)           |
+------------------+------------------------------------------------------+
| ``HIPAA``        | Health Insurance Portability and Accountability Act  |
+------------------+------------------------------------------------------+
| ``NIST_AI_RMF``  | NIST AI Risk Management Framework (AI 100-1)         |
+------------------+------------------------------------------------------+
| ``ISO_42001``    | ISO/IEC 42001:2023 — AI Management Systems           |
+------------------+------------------------------------------------------+
| ``GDPR``         | EU General Data Protection Regulation 2016/679       |
+------------------+------------------------------------------------------+

Mapping semantics
-----------------
A :class:`ControlMapping` binds a **Pramanix artefact** (an invariant label
and/or a principal identity pattern) to a **regulatory control** within a
given framework.  The oracle evaluates each registered mapping against the
evidence in a :class:`~pramanix.provenance.ProvenanceRecord` and produces one
of two outcomes per matched control:

* **Satisfied** (``record.allowed=True``): The invariant was evaluated and the
  Z3 solver proved it held.  The corresponding regulatory control is therefore
  mathematically attested as satisfied.

* **Enforced** (``record.allowed=False``): The invariant was evaluated and the
  Z3 solver found a violation, causing the action to be blocked.  The
  corresponding control is attested as *having actively prevented a violation*.

Principal-identity mappings use :func:`fnmatch.fnmatch` for pattern matching,
enabling wildcard-based policies such as
``"spiffe://prod.example.com/ns/payments/*"`` without enumerating every
individual service identity.

Cryptographic provenance
-------------------------
Every :class:`ComplianceAttestation` embeds the HMAC-SHA-256 tag of the source
:class:`~pramanix.provenance.ProvenanceRecord` as ``record_hmac_tag``.  This
tag proves that the attestation was derived from a specific, unmodified record:
an auditor can replay the HMAC computation over the stored record fields to
confirm that neither the record nor the attestation was fabricated post-hoc.

Record evidence extraction
--------------------------
Invariant label evidence is extracted from two sources in priority order:

1. The ``decision_snapshot`` parameter passed to :meth:`ComplianceOracle.evaluate_record`
   — the result of :meth:`~pramanix.decision.Decision.to_dict`, which always
   contains ``"violated_invariants"`` for BLOCKED decisions.

2. ``record.metadata`` — an arbitrary ``dict[str, Any]`` that the Guard may
   populate with ``"violated_invariants"`` and/or ``"evaluated_invariants"``
   keys when constructing the record.

If neither source provides an evaluated-invariant set for an ALLOWED record,
the oracle falls back to treating all registered invariant labels as
potentially satisfied.  This behaviour is documented in
:meth:`ComplianceOracle._extract_invariant_sets`.

Example usage
-------------
::

    from pramanix.compliance.oracle import (
        ComplianceOracle,
        ControlMapping,
        RegulatoryFramework,
    )

    oracle = ComplianceOracle()
    oracle.register_mapping(
        RegulatoryFramework.SOC2,
        ControlMapping(
            framework=RegulatoryFramework.SOC2,
            control_id="CC6.1",
            control_title="Logical Access Security",
            invariant_label="trusted_mesh_caller",
            description=(
                "CC6.1 requires that logical access to systems is restricted "
                "to authorised users.  Enforcement of the trusted_mesh_caller "
                "invariant provides formal Z3-verified proof that only the "
                "SPIFFE-authenticated payments agent may initiate transfers."
            ),
        ),
    )
    oracle.register_mapping(
        RegulatoryFramework.EU_AI_ACT,
        ControlMapping(
            framework=RegulatoryFramework.EU_AI_ACT,
            control_id="Art.14",
            control_title="Human Oversight",
            invariant_label="amount_within_balance",
            description=(
                "Art. 14 requires that high-risk AI systems be designed so that "
                "natural persons can oversee and intervene.  Enforcement of the "
                "amount_within_balance invariant prevents financially unsafe "
                "automated actions without human review."
            ),
        ),
    )

    attestation = oracle.evaluate_record(record, decision_snapshot=decision.to_dict())
    print(attestation.summary)

Offline / batch usage
---------------------
::

    import json
    import pathlib

    oracle = ComplianceOracle()
    # ... register mappings from config ...

    for raw in pathlib.Path("audit_log.jsonl").read_text().splitlines():
        entry = json.loads(raw)
        record = ProvenanceRecord(...)
        attestation = oracle.evaluate_record(
            record,
            stored_hmac_tag=entry["hmac_tag"],
        )
        store_attestation(attestation.model_dump(mode="json"))
"""

from __future__ import annotations

import enum
import fnmatch
import logging
import re
import secrets
import threading
import uuid
import warnings
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict
from pydantic import Field as _PF

if TYPE_CHECKING:
    from pramanix.provenance import ProvenanceRecord

__all__ = [
    "ComplianceAttestation",
    "ComplianceOracle",
    "ControlEnforcementResult",
    "ControlMapping",
    "ControlSatisfactionResult",
    "FrameworkAttestation",
    "MappingMatchKind",
    "RegulatoryFramework",
    "default_oracle",
]

_log = logging.getLogger(__name__)


# ── Enumerations ───────────────────────────────────────────────────────────────


class RegulatoryFramework(str, enum.Enum):
    """Recognised regulatory and compliance frameworks.

    Each member identifies a complete, published standard to which
    :class:`ControlMapping` objects may be anchored.  The string value is the
    canonical short-form name used in audit reports and serialised output.

    Members
    -------
    SOC2
        AICPA SOC 2 Type II — Trust Services Criteria (TSC).  The primary
        framework for US cloud-service provider attestations.  Control IDs
        follow the TSC numbering scheme: ``CC1.1``, ``CC6.1``, ``A1.1``, etc.

    EU_AI_ACT
        EU Artificial Intelligence Act 2024/1689.  The world's first
        comprehensive horizontal AI regulation, entering full application in
        2026.  Control IDs are article references: ``Art.9``, ``Art.13``,
        ``Art.14``, ``Art.15``, etc.

    HIPAA
        US Health Insurance Portability and Accountability Act Security Rule
        (45 C.F.R. §164.300 et seq.).  Control IDs follow the standard CFR
        section notation: ``§164.312(a)(1)``.

    NIST_AI_RMF
        NIST AI Risk Management Framework (NIST AI 100-1, January 2023).
        Organises AI risk management around four core functions: GOVERN, MAP,
        MEASURE, MANAGE.  Control IDs use the function-numeric notation:
        ``GOVERN-1.1``, ``MAP-2.1``, ``MEASURE-2.5``, etc.

    ISO_42001
        ISO/IEC 42001:2023 — AI Management Systems.  The first ISO
        AI-specific management system standard, closely aligned with
        ISO 9001/27001 structure.  Control IDs follow ISO clause numbering:
        ``Clause 6.1``, ``Annex A.6.2.1``, etc.

    GDPR
        EU General Data Protection Regulation 2016/679.  Governs processing
        of personal data of EU data subjects.  Control IDs are article
        references: ``Art.5``, ``Art.25``, ``Art.35``, etc.
    """

    SOC2 = "SOC2"
    EU_AI_ACT = "EU_AI_ACT"
    HIPAA = "HIPAA"
    NIST_AI_RMF = "NIST_AI_RMF"
    ISO_42001 = "ISO_42001"
    GDPR = "GDPR"


class MappingMatchKind(str, enum.Enum):
    """How a :class:`ControlMapping` was matched against a record.

    Members
    -------
    INVARIANT_LABEL
        The mapping fired because the record's evaluated or violated invariant
        set contained the mapping's ``invariant_label``.  The Z3 solver's
        formal proof is the direct evidence for this control.

    PRINCIPAL_IDENTITY
        The mapping fired because ``record.principal_id`` matched the
        mapping's ``principal_pattern`` via :func:`fnmatch.fnmatch`.  The
        SPIFFE-authenticated mesh identity is the evidence.

    BOTH
        Both the invariant label *and* the principal identity pattern matched
        in the same record.  This is the tightest possible evidence: the
        *what* (the invariant that was enforced) and the *who* (the verified
        identity) are simultaneously attested.
    """

    INVARIANT_LABEL = "invariant_label"
    PRINCIPAL_IDENTITY = "principal_identity"
    BOTH = "both"


# ── Control-ID format validation ──────────────────────────────────────────────

_CONTROL_ID_PATTERNS: dict[str, re.Pattern[str]] = {
    # SOC 2 TSC: CC1.1 … CC9.9, A1.1 … A1.3, PI1.1 … PI1.5, P1.0, C1.1, CA1.1
    "SOC2": re.compile(r"^(CC|A|PI|P|C|CA)\d+\.\d+$"),
    # EU AI Act: Art.9, Art.13a, Recital 12, Annex I
    "EU_AI_ACT": re.compile(r"^(Art|Recital|Annex)[\s.]*\d+[a-zA-Z]?"),
    # HIPAA CFR: §164.308(a)(1), §164.312(a)(1)(ii)(A) — subsections use (letter/digits)
    "HIPAA": re.compile(r"^§\d+\.\d+(\([a-zA-Z0-9]+\))*"),
    # NIST AI RMF: GOVERN-1.1, MAP-2.1, MEASURE-2.5, MANAGE-3.2
    "NIST_AI_RMF": re.compile(r"^(GOVERN|MAP|MEASURE|MANAGE)-\d+\.\d+$"),
    # ISO/IEC 42001: Clause 6.1, Annex A.6.2.1, Annex B.1 — allow dots in ref
    "ISO_42001": re.compile(r"^(Clause|Annex)\s+[A-Za-z0-9][A-Za-z0-9.]*"),
    # GDPR: Art.5, Art.25, Art.35, Recital 4
    "GDPR": re.compile(r"^(Art|Recital)[\s.]*\d+[a-zA-Z]?"),
}
"""Per-framework canonical control-ID format patterns.

These patterns encode the *minimum* syntactic requirements for a control ID
to be considered a genuine reference to the named standard.  They do NOT
guarantee the control exists in the published standard — that requires a
live schema lookup beyond the scope of this module.

The intent is to prevent accidental (or deliberate) use of arbitrary strings
as control IDs, which would produce attestations that look authoritative but
reference non-existent controls.

If you need to reference a proprietary or supplemental control that does not
follow the standard format, set ``ControlMapping.custom_control=True``.  A
``UserWarning`` will be emitted at construction time to make the deviation
visible in CI logs and security reviews.
"""


# ── Pydantic models ───────────────────────────────────────────────────────────


class ControlMapping(BaseModel):
    """A declarative binding from a Pramanix artefact to a regulatory control.

    A :class:`ControlMapping` is the fundamental configuration unit of the
    :class:`ComplianceOracle`.  It declares that *when* a specific invariant
    label appears in the evaluated or violated invariant set of a
    :class:`~pramanix.provenance.ProvenanceRecord`, **and/or** when the
    record's ``principal_id`` matches a given identity pattern, then the
    specified regulatory control can be attested as satisfied or enforced.

    At least one of ``invariant_label`` or ``principal_pattern`` must be
    provided; both may be set simultaneously, in which case ``require_both``
    controls whether the mapping requires both to match concurrently
    (:attr:`MappingMatchKind.BOTH`) or accepts either individually.

    Attributes
    ----------
    framework : RegulatoryFramework
        The regulatory standard to which this control belongs.
    control_id : str
        The canonical identifier of the control within the framework,
        e.g. ``"CC6.1"`` (SOC 2), ``"Art.14"`` (EU AI Act),
        ``"§164.312(a)(1)"`` (HIPAA), ``"GOVERN-1.1"`` (NIST AI RMF).
    control_title : str
        Short human-readable title of the control,
        e.g. ``"Logical Access Security"``.
    description : str
        Regulatory text excerpt or free-form justification for why this
        Pramanix artefact evidences this control.  Reproduced verbatim in
        :class:`ControlSatisfactionResult` / :class:`ControlEnforcementResult`
        output so auditors have the regulatory rationale inline.
    invariant_label : str | None
        The Pramanix invariant label (as produced by the ``Rule.name`` field
        in the compiled :class:`~pramanix.compiler.PolicyIR`) that evidences
        this control.  If ``None``, the invariant dimension is not evaluated;
        ``principal_pattern`` must then be non-``None``.
    principal_pattern : str | None
        An :func:`fnmatch.fnmatch`-compatible glob pattern matched against
        ``ProvenanceRecord.principal_id`` (the SPIFFE URI injected by
        :class:`~pramanix.mesh.authenticator.MeshAuthenticator`).  Wildcards
        ``*`` and ``?`` are supported.  If ``None``, the identity dimension is
        not evaluated; ``invariant_label`` must then be non-``None``.
    require_both : bool
        Relevant only when both ``invariant_label`` and ``principal_pattern``
        are set.  ``True`` (default): both criteria must match in the same
        record for the control to fire; the attestation will have
        :attr:`MappingMatchKind.BOTH`.  ``False``: either criterion
        independently triggers the control.

    Raises
    ------
    ValueError
        Raised at construction time if both ``invariant_label`` and
        ``principal_pattern`` are ``None``.

    Examples
    --------
    Invariant-only mapping::

        ControlMapping(
            framework=RegulatoryFramework.SOC2,
            control_id="CC6.1",
            control_title="Logical Access Security",
            invariant_label="trusted_mesh_caller",
            description="...",
        )

    Principal-pattern mapping::

        ControlMapping(
            framework=RegulatoryFramework.SOC2,
            control_id="CC6.3",
            control_title="User Authentication",
            principal_pattern="spiffe://prod.example.com/ns/payments/*",
            description="...",
        )

    Combined mapping requiring *both* invariant and verified identity::

        ControlMapping(
            framework=RegulatoryFramework.EU_AI_ACT,
            control_id="Art.14",
            control_title="Human Oversight",
            invariant_label="amount_within_balance",
            principal_pattern="spiffe://prod.example.com/ns/payments/*",
            require_both=True,
            description="...",
        )
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework: RegulatoryFramework = _PF(
        ...,
        description="The regulatory framework to which this control belongs.",
    )
    control_id: str = _PF(
        ...,
        min_length=1,
        description=(
            "Canonical control identifier within the framework, "
            "e.g. 'CC6.1', 'Art.14', '§164.312(a)(1)', 'GOVERN-1.1'."
        ),
    )
    control_title: str = _PF(
        ...,
        min_length=1,
        description="Short human-readable title of the control.",
    )
    description: str = _PF(
        ...,
        min_length=1,
        description=(
            "Regulatory text excerpt or justification for why this Pramanix artefact "
            "evidences this control.  Reproduced verbatim in attestation output."
        ),
    )
    invariant_label: str | None = _PF(
        default=None,
        description=(
            "Pramanix invariant label (Rule.name from the compiled PolicyIR) that "
            "evidences this control.  Required if principal_pattern is None."
        ),
    )
    principal_pattern: str | None = _PF(
        default=None,
        description=(
            "fnmatch-compatible glob pattern matched against "
            "ProvenanceRecord.principal_id (the SPIFFE URI from MeshAuthenticator).  "
            "Required if invariant_label is None."
        ),
    )
    require_both: bool = _PF(
        default=True,
        description=(
            "When both invariant_label and principal_pattern are provided: "
            "True (default) = both must match concurrently; "
            "False = either match independently triggers the control."
        ),
    )
    custom_control: bool = _PF(
        default=False,
        description=(
            "Set True for proprietary or supplemental controls that do not "
            "follow the canonical format for the named framework.  A "
            "UserWarning is emitted at construction time so the deviation is "
            "visible in CI logs and security reviews.  When False (default), "
            "control_id must match the framework's canonical pattern from "
            "_CONTROL_ID_PATTERNS — fabricated IDs are rejected at construction."
        ),
    )

    def model_post_init(self, __context: Any) -> None:
        """Validate matching criteria and control-ID format.

        Raises
        ------
        ValueError
            If both ``invariant_label`` and ``principal_pattern`` are ``None``.
        ValueError
            If ``control_id`` does not match the canonical format for
            ``framework`` and ``custom_control=False``.
        """
        if self.invariant_label is None and self.principal_pattern is None:
            raise ValueError(
                f"ControlMapping({self.framework.value!r}, {self.control_id!r}): "
                "at least one of 'invariant_label' or 'principal_pattern' must be "
                "set — a mapping with no matching criterion can never fire."
            )

        pattern = _CONTROL_ID_PATTERNS.get(self.framework.value)
        # Use fullmatch() not search() (#292): search() with ^ accepts arbitrary
        # suffixes — "Art.14XYZ_INJECTION" passes because the regex only anchors
        # the start.  fullmatch() requires the entire string to match.
        if pattern is not None and not pattern.fullmatch(self.control_id):
            if self.custom_control:
                warnings.warn(
                    f"ControlMapping({self.framework.value!r}, {self.control_id!r}): "
                    f"control_id does not match the canonical {self.framework.value} "
                    f"format (pattern: {pattern.pattern!r}).  Auditors may question "
                    "non-standard control IDs in compliance reports.",
                    UserWarning,
                    stacklevel=2,
                )
            else:
                raise ValueError(
                    f"ControlMapping({self.framework.value!r}): "
                    f"control_id {self.control_id!r} does not match the canonical "
                    f"{self.framework.value} format (expected pattern: "
                    f"{pattern.pattern!r}).  Use a valid control identifier from "
                    "the published standard, or set custom_control=True for "
                    "proprietary/supplemental controls."
                )


class ControlSatisfactionResult(BaseModel):
    """Evidence that a regulatory control was mathematically satisfied.

    Produced by the :class:`ComplianceOracle` when the inspected
    :class:`~pramanix.provenance.ProvenanceRecord` has ``allowed=True`` and the
    mapped invariant label appears in the evaluated-invariant set (all of which
    passed Z3 formal verification) **and/or** the principal identity matches.

    The presence of this object in a :class:`FrameworkAttestation` constitutes
    a machine-generated attestation that the stated regulatory control was in
    active operation at the time of the decision.

    Attributes
    ----------
    control_id : str
        The control identifier from the originating :class:`ControlMapping`.
    control_title : str
        Human-readable title from the originating :class:`ControlMapping`.
    description : str
        Regulatory justification text from the originating :class:`ControlMapping`.
    matched_invariant : str | None
        The invariant label that triggered this match, or ``None`` if the
        match was principal-identity-only.
    matched_principal : str | None
        The actual ``principal_id`` value that matched the
        ``principal_pattern``, or ``None`` if the match was invariant-only.
    match_kind : MappingMatchKind
        How this control was matched
        (``INVARIANT_LABEL``, ``PRINCIPAL_IDENTITY``, or ``BOTH``).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    control_id: str = _PF(..., description="Regulatory control identifier.")
    control_title: str = _PF(..., description="Human-readable title of the control.")
    description: str = _PF(..., description="Regulatory justification text.")
    matched_invariant: str | None = _PF(
        default=None,
        description="Invariant label that evidenced this control, if applicable.",
    )
    matched_principal: str | None = _PF(
        default=None,
        description="principal_id that matched the pattern, if applicable.",
    )
    match_kind: MappingMatchKind = _PF(..., description="How this control was matched.")


class ControlEnforcementResult(BaseModel):
    """Evidence that a regulatory control actively prevented a policy violation.

    Produced by the :class:`ComplianceOracle` when the inspected
    :class:`~pramanix.provenance.ProvenanceRecord` has ``allowed=False`` and the
    mapped invariant label appears among the *violated* invariants that triggered
    the block **and/or** the principal identity matches.

    The presence of this object in a :class:`FrameworkAttestation` constitutes a
    machine-generated attestation that a regulatory boundary was actively enforced:
    an otherwise-attempted AI action was blocked specifically because the named
    control's invariant requirement was not met.

    Attributes
    ----------
    control_id : str
        The control identifier from the originating :class:`ControlMapping`.
    control_title : str
        Human-readable title from the originating :class:`ControlMapping`.
    description : str
        Regulatory justification text from the originating :class:`ControlMapping`.
    matched_invariant : str | None
        The violated invariant label that triggered this match, or ``None``
        if the match was principal-identity-only.
    matched_principal : str | None
        The actual ``principal_id`` value that matched the
        ``principal_pattern``, or ``None`` if the match was invariant-only.
    match_kind : MappingMatchKind
        How this control was matched.
    violation_prevented : str
        Short machine-generated description of the violation that was
        prevented, combining the framework name, control ID, control title,
        the triggering invariant label, and/or the matched principal identity.
        Suitable for inclusion in an incident or compliance report.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    control_id: str = _PF(..., description="Regulatory control identifier.")
    control_title: str = _PF(..., description="Human-readable title of the control.")
    description: str = _PF(..., description="Regulatory justification text.")
    matched_invariant: str | None = _PF(
        default=None,
        description="Violated invariant label that triggered this control, if applicable.",
    )
    matched_principal: str | None = _PF(
        default=None,
        description="principal_id that matched the pattern, if applicable.",
    )
    match_kind: MappingMatchKind = _PF(..., description="How this control was matched.")
    violation_prevented: str = _PF(
        ...,
        description=(
            "Machine-generated description of the violation that was prevented "
            "by enforcement of this control."
        ),
    )


class FrameworkAttestation(BaseModel):
    """Aggregated compliance results for a single regulatory framework.

    Groups all :class:`ControlSatisfactionResult` and
    :class:`ControlEnforcementResult` objects belonging to one
    :class:`RegulatoryFramework` for the decision under evaluation.

    Attributes
    ----------
    framework : RegulatoryFramework
        The regulatory framework these results belong to.
    controls_satisfied : list[ControlSatisfactionResult]
        Controls attested as active and satisfied for ALLOWED records.
        Empty for BLOCKED records.
    controls_enforced : list[ControlEnforcementResult]
        Controls attested as having prevented a violation for BLOCKED records.
        Empty for ALLOWED records.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    framework: RegulatoryFramework = _PF(..., description="The regulatory framework.")
    controls_satisfied: list[ControlSatisfactionResult] = _PF(
        default_factory=list,
        description="Controls satisfied on ALLOWED decisions.",
    )
    controls_enforced: list[ControlEnforcementResult] = _PF(
        default_factory=list,
        description="Controls enforced (violation prevented) on BLOCKED decisions.",
    )

    @property
    def total_controls(self) -> int:
        """Total number of controls attested (satisfied + enforced)."""
        return len(self.controls_satisfied) + len(self.controls_enforced)

    @property
    def has_findings(self) -> bool:
        """``True`` if any controls were matched for this framework."""
        return self.total_controls > 0


class ComplianceAttestation(BaseModel):
    """The complete auditor-ready output of :meth:`ComplianceOracle.evaluate_record`.

    A :class:`ComplianceAttestation` is the full compliance evidence package for
    a single AI decision.  It embeds a cryptographic reference to the source
    :class:`~pramanix.provenance.ProvenanceRecord`, a structured per-framework
    compliance report, and a plain-English summary suitable for a CISO sign-off
    report, regulatory submission, or automated compliance dashboard.

    Immutability guarantee
    ----------------------
    All fields are frozen (``ConfigDict(frozen=True)``).  An attestation produced
    for a given record is a deterministic function of the record's content and the
    oracle's registered mappings at evaluation time.  Subsequent mutations to the
    oracle's mapping registry do not retroactively alter issued attestations.

    Cryptographic integrity
    -----------------------
    ``record_hmac_tag`` is the HMAC-SHA-256 of the source
    :class:`~pramanix.provenance.ProvenanceRecord`, computed over all identifying
    fields via :meth:`~pramanix.provenance.ProvenanceRecord.hmac_tag`.  An auditor
    can re-derive this value from the stored record fields to confirm that neither
    the record nor the attestation was fabricated post-hoc.

    Attributes
    ----------
    attestation_id : str
        UUID4 uniquely identifying this attestation instance.  Generated
        automatically at construction time.
    timestamp_utc : str
        ISO 8601 UTC timestamp of attestation generation,
        e.g. ``"2026-05-13T14:32:00.123456+00:00"``.
    decision_id : str
        The ``decision_id`` from the source ``ProvenanceRecord``, traceable
        back to the originating :class:`~pramanix.decision.Decision`.
    record_id : str
        The ``record_id`` of the source ``ProvenanceRecord``.
    policy_hash : str
        SHA-256 fingerprint of the policy under which the decision was made.
        Immutably binds the attestation to the exact policy version.
    principal_id : str
        SPIFFE URI (or other identity string) of the agent that triggered the
        decision, as recorded by
        :class:`~pramanix.mesh.authenticator.MeshAuthenticator`.
    outcome : str
        ``"ALLOWED"`` if the decision permitted the action;
        ``"BLOCKED"`` if the decision prevented it.
    record_hmac_tag : str
        HMAC-SHA-256 of the source ``ProvenanceRecord``.  Cryptographic proof
        that the attestation was derived from an unmodified record.
    framework_results : list[FrameworkAttestation]
        One entry per regulatory framework for which at least one
        :class:`ControlMapping` was registered and matched.
        Frameworks with no matched controls are omitted.
    summary : str
        Plain-English single-sentence compliance summary for CISO reporting.
        Examples:

        - ``"Action ALLOWED: 3 regulatory control(s) across 2 framework(s) ``
          ``mathematically satisfied — SOC2 [CC6.1, CC6.3]; EU_AI_ACT [Art.14]."``
        - ``"Action BLOCKED: 2 regulatory control(s) actively enforced across ``
          ``2 framework(s) — EU_AI_ACT Art.14 (Human Oversight) [invariant: ``
          ``amount_within_balance]; SOC2 CC6.1 (Logical Access Security) ``
          ``[invariant: trusted_mesh_caller]."``
        - ``"Action BLOCKED: No mapped controls matched the violated invariants ``
          ``or principal identity in this record."``

    total_controls_matched : int
        Total number of distinct controls attested across all frameworks.

    Serialisation
    -------------
    Use ``attestation.model_dump(mode="json")`` for a fully JSON-safe dict
    (enums serialised as their string values), or
    ``attestation.model_dump_json()`` for a compact JSON string suitable for
    appending to an audit log.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_id: str = _PF(
        default_factory=lambda: str(uuid.UUID(bytes=secrets.token_bytes(16), version=4)),
        description="UUID uniquely identifying this attestation.",
    )
    timestamp_utc: str = _PF(
        ...,
        description="ISO 8601 UTC timestamp of attestation generation.",
    )
    decision_id: str = _PF(
        ...,
        description="decision_id from the source ProvenanceRecord.",
    )
    record_id: str = _PF(
        ...,
        description="record_id of the source ProvenanceRecord.",
    )
    policy_hash: str = _PF(
        ...,
        description="SHA-256 fingerprint of the policy at decision time.",
    )
    principal_id: str = _PF(
        ...,
        description="SPIFFE URI or identity string of the decision-triggering agent.",
    )
    outcome: str = _PF(
        ...,
        description="'ALLOWED' or 'BLOCKED'.",
    )
    record_hmac_tag: str = _PF(
        ...,
        description=(
            "HMAC-SHA-256 of the source ProvenanceRecord.  "
            "Cryptographic proof that the attestation was derived from an unmodified record."
        ),
    )
    framework_results: list[FrameworkAttestation] = _PF(
        default_factory=list,
        description=(
            "Per-framework compliance attestation results.  "
            "Only frameworks with matched controls are included."
        ),
    )
    summary: str = _PF(
        ...,
        description="Plain-English compliance summary for CISO reporting.",
    )
    total_controls_matched: int = _PF(
        ...,
        description="Total controls attested across all frameworks.",
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict representation of this attestation.

        Equivalent to ``self.model_dump(mode="json")``.  All enum values are
        serialised as their string equivalents; no Python-specific objects are
        present in the output.

        Returns
        -------
        dict[str, Any]
            A fully JSON-serialisable dict suitable for writing to an audit
            log, database, or HTTP response body.
        """
        return self.model_dump(mode="json")


# ── Core engine ───────────────────────────────────────────────────────────────


class ComplianceOracle:
    """Regulatory mapping engine: translates ProvenanceRecords into ComplianceAttestations.

    The :class:`ComplianceOracle` is the core of Pramanix Pillar 3.  It
    maintains a registry of :class:`ControlMapping` objects grouped by
    :class:`RegulatoryFramework`, and evaluates each mapping against the
    evidence encoded in a :class:`~pramanix.provenance.ProvenanceRecord` to
    produce a :class:`ComplianceAttestation`.

    Threading model
    ---------------
    The oracle is fully thread-safe.  The mapping registry is protected by a
    :class:`threading.RLock`, so :meth:`register_mapping` and
    :meth:`evaluate_record` may be called concurrently from multiple threads.
    However, the recommended pattern is to register all mappings during
    application startup — before any calls to :meth:`evaluate_record` — to
    avoid taking registry snapshots under mid-registration states.

    Offline / async design
    ----------------------
    The oracle makes **no network calls, no database queries, and no calls to
    ``Guard.verify()`` or any live Pramanix components**.  It reads only from
    the :class:`~pramanix.provenance.ProvenanceRecord` passed to
    :meth:`evaluate_record` and from its own in-memory mapping registry.
    This makes it safe to run in a background thread, a batch job, or a fully
    offline audit pipeline without affecting the Guard hot path.

    Fail-closed guarantee
    ---------------------
    :meth:`evaluate_record` never raises.  Any internal error is caught,
    logged at ``ERROR`` level, and a minimal attestation with an empty
    ``framework_results`` list and an error summary is returned.  This
    ensures that a broken oracle never silently passes an unaudited record.

    Example
    -------
    ::

        oracle = ComplianceOracle()

        # Register mappings during application startup:
        oracle.register_mapping(
            RegulatoryFramework.NIST_AI_RMF,
            ControlMapping(
                framework=RegulatoryFramework.NIST_AI_RMF,
                control_id="GOVERN-1.1",
                control_title="AI Risk Governance",
                invariant_label="trusted_mesh_caller",
                description="...",
            ),
        )

        # Evaluate records offline / asynchronously:
        attestation = oracle.evaluate_record(
            record,
            stored_hmac_tag=log_entry["hmac_tag"],
            decision_snapshot=log_entry.get("decision"),
        )
        print(attestation.summary)
    """

    def __init__(self) -> None:
        """Initialise an empty :class:`ComplianceOracle`.

        The oracle starts with no registered mappings.  Register at least one
        :class:`ControlMapping` via :meth:`register_mapping` before calling
        :meth:`evaluate_record`.
        """
        # _registry: RegulatoryFramework → list[ControlMapping]
        self._registry: dict[RegulatoryFramework, list[ControlMapping]] = defaultdict(list)
        self._lock: threading.RLock = threading.RLock()

    # ── Public API ─────────────────────────────────────────────────────────────

    def register_mapping(
        self,
        framework: RegulatoryFramework,
        mapping: ControlMapping,
    ) -> None:
        """Add a :class:`ControlMapping` to the oracle's registry.

        Mappings are stored per-framework.  Multiple mappings may be registered
        for the same ``(framework, control_id)`` pair — for example, to evidence
        the same control via two different invariant labels.  The oracle evaluates
        every registered mapping independently on each call to
        :meth:`evaluate_record`.

        Duplicate mappings
        ------------------
        The oracle does **not** deduplicate mappings.  Registering the same
        :class:`ControlMapping` object (or two structurally identical objects)
        twice causes the control to appear twice in attestation output.  Register
        each mapping exactly once.

        Args
        ----
        framework : RegulatoryFramework
            The framework to register this mapping under.  Must match
            ``mapping.framework`` to prevent silent miscategorisation.
        mapping : ControlMapping
            The fully-constructed mapping to register.

        Raises
        ------
        ValueError
            If ``framework`` does not match ``mapping.framework``.

        Example
        -------
        ::

            oracle.register_mapping(
                RegulatoryFramework.HIPAA,
                ControlMapping(
                    framework=RegulatoryFramework.HIPAA,
                    control_id="§164.312(a)(1)",
                    control_title="Access Control",
                    invariant_label="trusted_mesh_caller",
                    description=(
                        "HIPAA §164.312(a)(1) requires unique user identification "
                        "and emergency access procedures.  The trusted_mesh_caller "
                        "invariant formally verifies the SPIFFE caller identity."
                    ),
                ),
            )
        """
        if mapping.framework is not framework:
            raise ValueError(
                f"register_mapping: 'framework' argument {framework.value!r} does not "
                f"match mapping.framework {mapping.framework.value!r}.  "
                "Pass matching values to avoid silent miscategorisation."
            )
        with self._lock:
            # Deduplicate by (control_id, invariant_label) to prevent compliance
            # count inflation from double-registration (#285).  A retry loop or
            # multiple module imports calling register_mapping with the same
            # mapping would otherwise create duplicate attestation evidence,
            # misleading auditors into inferring stronger compliance coverage.
            _existing = self._registry[framework]
            _key = (mapping.control_id, mapping.invariant_label)
            if any(
                (m.control_id, m.invariant_label) == _key for m in _existing
            ):
                _log.debug(
                    "compliance_oracle.mapping_skipped_duplicate framework=%s "
                    "control_id=%r invariant_label=%r",
                    framework.value,
                    mapping.control_id,
                    mapping.invariant_label,
                )
                return
            self._registry[framework].append(mapping)
        _log.debug(
            "compliance_oracle.mapping_registered framework=%s control_id=%r "
            "invariant_label=%r principal_pattern=%r",
            framework.value,
            mapping.control_id,
            mapping.invariant_label,
            mapping.principal_pattern,
        )

    def evaluate_record(
        self,
        record: ProvenanceRecord,
        *,
        stored_hmac_tag: str = "",
        decision_snapshot: dict[str, Any] | None = None,
    ) -> ComplianceAttestation:
        """Evaluate a :class:`~pramanix.provenance.ProvenanceRecord` against all registered mappings.

        This is the primary evaluation entry point.  It:

        1. Extracts the invariant evidence sets (evaluated / violated invariant
           labels) from ``decision_snapshot`` and/or ``record.metadata``.
        2. Determines the record's ``outcome`` (``"ALLOWED"`` or ``"BLOCKED"``).
        3. Iterates over every registered :class:`ControlMapping` and checks
           whether it matches the evidence.
        4. Produces a :class:`ControlSatisfactionResult` (ALLOWED) or
           :class:`ControlEnforcementResult` (BLOCKED) for each match.
        5. Groups matching controls by framework into :class:`FrameworkAttestation`
           objects.
        6. Assembles and returns a :class:`ComplianceAttestation`.

        This method **never raises**.  Any internal error is caught, logged at
        ``ERROR`` level, and a minimal fail-safe attestation is returned.

        Matching semantics
        ------------------
        For each :class:`ControlMapping`:

        * **Invariant match**: ``mapping.invariant_label`` appears in the
          appropriate evidence set:

          - ``allowed=True``: label must be in ``evaluated_invariants``.
          - ``allowed=False``: label must be in ``violated_invariants`` — only
            invariants that *caused* the block are reported; invariants that
            passed on a blocked record are not claimed as evidenced.

        * **Principal match**: :func:`fnmatch.fnmatch` matches
          ``record.principal_id`` against ``mapping.principal_pattern``.

        * **require_both logic**:

          - ``require_both=True`` and both criteria set: both invariant AND
            principal must match → :attr:`MappingMatchKind.BOTH`.
          - ``require_both=False`` and both criteria set: either match suffices
            → :attr:`MappingMatchKind.INVARIANT_LABEL` or
            :attr:`MappingMatchKind.PRINCIPAL_IDENTITY`.
          - Only one criterion set: that criterion alone is checked.

        Cryptographic reference
        -----------------------
        If ``stored_hmac_tag`` is provided, it is embedded verbatim as
        ``record_hmac_tag`` in the attestation (the caller asserts this is the
        authoritative tag from a persisted log).  If omitted, the oracle calls
        ``record.hmac_tag()`` using the current process's default signing key.
        For offline evaluation from a persisted audit log, always supply
        ``stored_hmac_tag`` from the log entry.

        If no mappings are registered, the method returns an attestation with
        empty ``framework_results`` and a summary noting no mappings are
        configured.  This is an expected state during application setup and
        does not constitute an error.

        Args
        ----
        record : ProvenanceRecord
            The completed provenance record to evaluate.
        stored_hmac_tag : str, optional
            Pre-computed HMAC-SHA-256 tag from a persisted
            ``record.to_dict()["hmac_tag"]``.  If empty, computed on demand
            via ``record.hmac_tag()``.
        decision_snapshot : dict[str, Any] | None, optional
            The result of :meth:`~pramanix.decision.Decision.to_dict` for the
            decision that produced this record.  Provides
            ``"violated_invariants"`` (guaranteed present) and optionally
            ``"evaluated_invariants"`` (if populated by Guard extensions).
            Falls back to ``record.metadata`` when not supplied.

        Returns
        -------
        ComplianceAttestation
            The complete, frozen compliance attestation for this record.

        Examples
        --------
        In-process (same key context)::

            attestation = oracle.evaluate_record(record)

        From persisted log (cross-process, explicit HMAC tag)::

            attestation = oracle.evaluate_record(
                record,
                stored_hmac_tag=log_entry["hmac_tag"],
                decision_snapshot=log_entry.get("decision"),
            )

        From batch pipeline with Decision object available::

            attestation = oracle.evaluate_record(
                record,
                decision_snapshot=decision.to_dict(),
            )
        """
        try:
            return self._evaluate_impl(record, stored_hmac_tag, decision_snapshot)
        except Exception:
            _log.exception(
                "compliance_oracle.evaluate_record_failed record_id=%s decision_id=%s",
                record.record_id,
                record.decision_id,
            )
            return self._error_attestation(record, stored_hmac_tag)

    def mapping_count(self, framework: RegulatoryFramework | None = None) -> int:
        """Return the number of registered mappings, optionally filtered by framework.

        Args
        ----
        framework : RegulatoryFramework | None
            If given, return the count for that framework only.
            If ``None``, return the total count across all frameworks.

        Returns
        -------
        int
            Number of registered :class:`ControlMapping` objects.
        """
        with self._lock:
            if framework is None:
                return sum(len(v) for v in self._registry.values())
            return len(self._registry.get(framework, []))

    def registered_frameworks(self) -> list[RegulatoryFramework]:
        """Return the frameworks that have at least one registered mapping.

        Returns
        -------
        list[RegulatoryFramework]
            Sorted by enum value for deterministic output.
        """
        with self._lock:
            return sorted(
                [fw for fw, mappings in self._registry.items() if mappings],
                key=lambda f: f.value,
            )

    def get_mappings(self, framework: RegulatoryFramework) -> list[ControlMapping]:
        """Return a snapshot of all registered mappings for a framework.

        Returns a copy — mutating the returned list does not affect the oracle.

        Args
        ----
        framework : RegulatoryFramework
            The framework whose mappings to retrieve.

        Returns
        -------
        list[ControlMapping]
            All :class:`ControlMapping` objects registered under ``framework``,
            in registration order.  Empty list if none registered.
        """
        with self._lock:
            return list(self._registry.get(framework, []))

    # ── Internal implementation ────────────────────────────────────────────────

    def _evaluate_impl(
        self,
        record: ProvenanceRecord,
        stored_hmac_tag: str,
        decision_snapshot: dict[str, Any] | None,
    ) -> ComplianceAttestation:
        """Core evaluation logic.  Invoked by the public :meth:`evaluate_record`.

        Snapshots the registry under the lock, evaluates every mapping, builds
        per-framework results, and assembles the final
        :class:`ComplianceAttestation`.

        Args
        ----
        record : ProvenanceRecord
        stored_hmac_tag : str
        decision_snapshot : dict[str, Any] | None

        Returns
        -------
        ComplianceAttestation
        """
        ts = datetime.now(tz=UTC).isoformat()
        hmac_tag = stored_hmac_tag or record.hmac_tag()
        outcome = "ALLOWED" if record.allowed else "BLOCKED"

        evaluated_invariants, violated_invariants = self._extract_invariant_sets(
            record, decision_snapshot
        )

        # Snapshot the registry to avoid holding the lock during evaluation.
        with self._lock:
            registry_snapshot: dict[RegulatoryFramework, list[ControlMapping]] = {
                fw: list(mappings) for fw, mappings in self._registry.items()
            }

        if not registry_snapshot:
            _log.warning(
                "compliance_oracle.no_mappings_registered decision_id=%s",
                record.decision_id,
            )
            return self._no_mappings_attestation(record, hmac_tag, outcome, ts)

        # Accumulate results per framework.
        fw_satisfied: dict[RegulatoryFramework, list[ControlSatisfactionResult]] = defaultdict(list)
        fw_enforced: dict[RegulatoryFramework, list[ControlEnforcementResult]] = defaultdict(list)

        for framework, mappings in registry_snapshot.items():
            for mapping in mappings:
                result = self._evaluate_mapping(
                    mapping=mapping,
                    record=record,
                    evaluated_invariants=evaluated_invariants,
                    violated_invariants=violated_invariants,
                )
                if result is None:
                    continue
                if isinstance(result, ControlSatisfactionResult):
                    fw_satisfied[framework].append(result)
                else:
                    fw_enforced[framework].append(result)

        # Build FrameworkAttestation list (only for frameworks with hits).
        all_frameworks: set[RegulatoryFramework] = set(fw_satisfied) | set(fw_enforced)
        framework_results: list[FrameworkAttestation] = [
            FrameworkAttestation(
                framework=fw,
                controls_satisfied=fw_satisfied.get(fw, []),
                controls_enforced=fw_enforced.get(fw, []),
            )
            for fw in sorted(all_frameworks, key=lambda f: f.value)
        ]

        total = sum(fr.total_controls for fr in framework_results)
        summary = self._build_summary(outcome, framework_results, total)

        _log.info(
            "compliance_oracle.attestation_generated decision_id=%s outcome=%s "
            "total_controls=%d frameworks=%s",
            record.decision_id,
            outcome,
            total,
            [fr.framework.value for fr in framework_results],
        )

        return ComplianceAttestation(
            timestamp_utc=ts,
            decision_id=record.decision_id,
            record_id=record.record_id,
            policy_hash=record.policy_hash,
            principal_id=record.principal_id,
            outcome=outcome,
            record_hmac_tag=hmac_tag,
            framework_results=framework_results,
            summary=summary,
            total_controls_matched=total,
        )

    def _extract_invariant_sets(
        self,
        record: ProvenanceRecord,
        decision_snapshot: dict[str, Any] | None,
    ) -> tuple[frozenset[str], frozenset[str]]:
        """Extract evaluated and violated invariant label sets from available evidence.

        Priority order for each set:

        1. ``decision_snapshot`` (``decision.to_dict()`` output):
           ``"violated_invariants"`` is always present; ``"evaluated_invariants"``
           may be present if the Guard populates it.
        2. ``record.metadata`` dict keys ``"violated_invariants"`` and
           ``"evaluated_invariants"``.

        **Fallback for ALLOWED records with no evaluated set**: when no
        ``evaluated_invariants`` can be found, the oracle assumes all registered
        invariant labels were potentially satisfied and infers the evaluated set
        from the mapping registry.  This is a best-effort heuristic — the Guard
        SHOULD populate ``record.metadata["evaluated_invariants"]`` or
        ``decision_snapshot["evaluated_invariants"]`` for precise attestations.

        Args
        ----
        record : ProvenanceRecord
        decision_snapshot : dict[str, Any] | None

        Returns
        -------
        tuple[frozenset[str], frozenset[str]]
            ``(evaluated_invariants, violated_invariants)``
        """
        snap: dict[str, Any] = decision_snapshot or {}

        # Violated invariants: Decision.to_dict() guarantees this key on BLOCKED records.
        violated_raw: list[Any] = (
            snap.get("violated_invariants") or record.metadata.get("violated_invariants") or []
        )
        violated = frozenset(str(v) for v in violated_raw if v)

        # Evaluated invariants: not in Decision.to_dict() by default, but Guard
        # extensions may populate it in metadata or snapshot for ALLOWED records.
        evaluated_raw: list[Any] = (
            snap.get("evaluated_invariants") or record.metadata.get("evaluated_invariants") or []
        )
        evaluated = frozenset(str(v) for v in evaluated_raw if v)

        # Do NOT infer evaluated invariants from the registry for ALLOWED records
        # that lack explicit evaluated_invariants metadata.  Doing so would
        # generate fraudulent compliance attestations: an ALLOW from a policy with
        # *any* invariant name matching a registered ControlMapping would produce
        # a valid-looking SOC2/HIPAA/EU-AI-Act attestation even if the specific
        # control invariant was never evaluated for that decision.
        # If evaluated_invariants is absent, return an empty set so attestations
        # are marked as "insufficient evidence" rather than falsely satisfied.
        if record.allowed and not evaluated:
            _log.debug(
                "compliance_oracle.no_evaluated_invariants decision_id=%s "
                "— attestation will have insufficient evidence",
                record.decision_id,
            )

        return evaluated, violated

    def _evaluate_mapping(
        self,
        *,
        mapping: ControlMapping,
        record: ProvenanceRecord,
        evaluated_invariants: frozenset[str],
        violated_invariants: frozenset[str],
    ) -> ControlSatisfactionResult | ControlEnforcementResult | None:
        """Evaluate a single :class:`ControlMapping` against the record's evidence.

        Determines whether the mapping fires (returns a result) or is skipped
        (returns ``None``) according to the ``require_both`` logic described in
        :meth:`evaluate_record`.

        Args
        ----
        mapping : ControlMapping
        record : ProvenanceRecord
        evaluated_invariants : frozenset[str]
        violated_invariants : frozenset[str]

        Returns
        -------
        ControlSatisfactionResult | ControlEnforcementResult | None
            ``None`` if the mapping does not match the record's evidence.
        """
        invariant_match = _check_invariant_match(
            mapping, record, evaluated_invariants, violated_invariants
        )
        principal_match = _check_principal_match(mapping, record)

        has_inv = mapping.invariant_label is not None
        has_pri = mapping.principal_pattern is not None

        # Determine whether the mapping fires and which kind of match it is.
        match_kind: MappingMatchKind | None = None
        if has_inv and has_pri:
            if mapping.require_both:
                if invariant_match and principal_match:
                    match_kind = MappingMatchKind.BOTH
            else:
                if invariant_match and principal_match:
                    match_kind = MappingMatchKind.BOTH
                elif invariant_match:
                    match_kind = MappingMatchKind.INVARIANT_LABEL
                elif principal_match:
                    match_kind = MappingMatchKind.PRINCIPAL_IDENTITY
        elif has_inv:
            if invariant_match:
                match_kind = MappingMatchKind.INVARIANT_LABEL
        else:  # has_pri only
            if principal_match:
                match_kind = MappingMatchKind.PRINCIPAL_IDENTITY

        if match_kind is None:
            return None

        matched_invariant = mapping.invariant_label if invariant_match else None
        matched_principal = record.principal_id if principal_match else None

        if record.allowed:
            return ControlSatisfactionResult(
                control_id=mapping.control_id,
                control_title=mapping.control_title,
                description=mapping.description,
                matched_invariant=matched_invariant,
                matched_principal=matched_principal,
                match_kind=match_kind,
            )

        violation_prevented = _format_violation_prevented(
            mapping=mapping,
            violated_invariants=violated_invariants,
            principal_id=record.principal_id,
            match_kind=match_kind,
        )
        return ControlEnforcementResult(
            control_id=mapping.control_id,
            control_title=mapping.control_title,
            description=mapping.description,
            matched_invariant=matched_invariant,
            matched_principal=matched_principal,
            match_kind=match_kind,
            violation_prevented=violation_prevented,
        )

    @staticmethod
    def _build_summary(
        outcome: str,
        framework_results: list[FrameworkAttestation],
        total: int,
    ) -> str:
        """Produce the plain-English summary line for the :class:`ComplianceAttestation`.

        Args
        ----
        outcome : str
            ``"ALLOWED"`` or ``"BLOCKED"``.
        framework_results : list[FrameworkAttestation]
            Non-empty list of framework attestation results.
        total : int
            Pre-computed total control count across all frameworks.

        Returns
        -------
        str
        """
        num_fw = len(framework_results)
        if outcome == "ALLOWED":
            fw_parts: list[str] = []
            for fr in framework_results:
                ids = sorted({r.control_id for r in fr.controls_satisfied})
                fw_parts.append(f"{fr.framework.value} [{', '.join(ids)}]")
            return (
                f"Action ALLOWED: {total} regulatory control(s) across {num_fw} "
                f"framework(s) mathematically satisfied — {'; '.join(fw_parts)}."
            )
        else:
            enforced_parts: list[str] = []
            for fr in framework_results:
                for r in fr.controls_enforced:
                    inv = f" [invariant: {r.matched_invariant}]" if r.matched_invariant else ""
                    enforced_parts.append(
                        f"{fr.framework.value} {r.control_id} ({r.control_title}){inv}"
                    )
            return (
                f"Action BLOCKED: {total} regulatory control(s) actively enforced "
                f"across {num_fw} framework(s) — {'; '.join(enforced_parts)}."
            )

    @staticmethod
    def _no_mappings_attestation(
        record: ProvenanceRecord,
        hmac_tag: str,
        outcome: str,
        ts: str,
    ) -> ComplianceAttestation:
        """Return a valid attestation when no mappings are registered.

        This is not an error state — it is expected during application
        initialisation before any mappings have been registered.

        Args
        ----
        record : ProvenanceRecord
        hmac_tag : str
        outcome : str
        ts : str

        Returns
        -------
        ComplianceAttestation
        """
        return ComplianceAttestation(
            timestamp_utc=ts,
            decision_id=record.decision_id,
            record_id=record.record_id,
            policy_hash=record.policy_hash,
            principal_id=record.principal_id,
            outcome=outcome,
            record_hmac_tag=hmac_tag,
            framework_results=[],
            summary=(
                f"Action {outcome}: No compliance mappings are registered. "
                "Register ControlMapping objects via ComplianceOracle.register_mapping() "
                "before evaluating records."
            ),
            total_controls_matched=0,
        )

    @staticmethod
    def _error_attestation(
        record: ProvenanceRecord,
        stored_hmac_tag: str,
    ) -> ComplianceAttestation:
        """Return a minimal fail-safe attestation on internal oracle error.

        Called only when :meth:`_evaluate_impl` raises an unhandled exception.
        The returned attestation has an empty ``framework_results`` list and a
        summary that signals the oracle failure, preserving the fail-closed audit
        guarantee.

        Args
        ----
        record : ProvenanceRecord
        stored_hmac_tag : str

        Returns
        -------
        ComplianceAttestation
        """
        ts = datetime.now(tz=UTC).isoformat()
        return ComplianceAttestation(
            timestamp_utc=ts,
            decision_id=record.decision_id,
            record_id=record.record_id,
            policy_hash=record.policy_hash,
            principal_id=record.principal_id,
            outcome="ALLOWED" if record.allowed else "BLOCKED",
            record_hmac_tag=stored_hmac_tag,
            framework_results=[],
            summary=(
                "ComplianceOracle internal error: attestation generation failed.  "
                "No controls matched.  Review oracle logs for details."
            ),
            total_controls_matched=0,
        )


# ── Module-level helpers (stateless, no self) ──────────────────────────────────


def _check_invariant_match(
    mapping: ControlMapping,
    record: ProvenanceRecord,
    evaluated_invariants: frozenset[str],
    violated_invariants: frozenset[str],
) -> bool:
    """Return ``True`` if ``mapping.invariant_label`` is in the relevant evidence set.

    For ALLOWED records, the relevant set is ``evaluated_invariants`` (all passed).
    For BLOCKED records, the relevant set is ``violated_invariants`` (caused the block).

    Args
    ----
    mapping : ControlMapping
    record : ProvenanceRecord
    evaluated_invariants : frozenset[str]
    violated_invariants : frozenset[str]

    Returns
    -------
    bool
    """
    if mapping.invariant_label is None:
        return False
    if record.allowed:
        return mapping.invariant_label in evaluated_invariants
    return mapping.invariant_label in violated_invariants


def _check_principal_match(
    mapping: ControlMapping,
    record: ProvenanceRecord,
) -> bool:
    """Return ``True`` if ``record.principal_id`` matches ``mapping.principal_pattern``.

    Uses :func:`fnmatch.fnmatch` for glob-style wildcard matching.  Returns
    ``False`` immediately if either value is empty/``None``.

    Args
    ----
    mapping : ControlMapping
    record : ProvenanceRecord

    Returns
    -------
    bool
    """
    if not mapping.principal_pattern or not record.principal_id:
        return False
    return fnmatch.fnmatch(record.principal_id, mapping.principal_pattern)


def _format_violation_prevented(
    *,
    mapping: ControlMapping,
    violated_invariants: frozenset[str],
    principal_id: str,
    match_kind: MappingMatchKind,
) -> str:
    """Produce a short, human-readable description of the prevented violation.

    Combines the framework name, control ID, control title, and the triggering
    evidence (invariant label and/or matched principal identity) into a single
    sentence suitable for inclusion in a compliance report.

    Args
    ----
    mapping : ControlMapping
    violated_invariants : frozenset[str]
    principal_id : str
    match_kind : MappingMatchKind

    Returns
    -------
    str
        E.g. ``"Blocked: EU_AI_ACT Art.14 (Human Oversight) enforced via "``
        ``"invariant [amount_within_balance]."``
    """
    evidence_parts: list[str] = []
    if mapping.invariant_label and mapping.invariant_label in violated_invariants:
        evidence_parts.append(f"invariant [{mapping.invariant_label}]")
    if match_kind in (MappingMatchKind.PRINCIPAL_IDENTITY, MappingMatchKind.BOTH):
        evidence_parts.append(
            f"principal [{principal_id!r}] matched pattern [{mapping.principal_pattern!r}]"
        )
    evidence = " and ".join(evidence_parts) if evidence_parts else f"control [{mapping.control_id}]"
    return (
        f"Blocked: {mapping.framework.value} {mapping.control_id} "
        f"({mapping.control_title}) enforced via {evidence}."
    )


# ── Built-in compliance mapping library ───────────────────────────────────────


def _cm(
    framework: RegulatoryFramework,
    control_id: str,
    control_title: str,
    invariant_label: str,
    description: str,
) -> ControlMapping:
    return ControlMapping(
        framework=framework,
        control_id=control_id,
        control_title=control_title,
        invariant_label=invariant_label,
        description=description,
    )


# Pre-built mappings from conventional Pramanix invariant labels to regulatory
# controls.  Policies that follow Pramanix naming conventions get compliance
# attestations with no manual oracle configuration.
_BUILT_IN_MAPPINGS: list[ControlMapping] = [
    # ── SOC 2 TSC ─────────────────────────────────────────────────────────────
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.1",
        "Logical and Physical Access Controls",
        "authorized_role",
        "CC6.1 requires restricting access to systems. "
        "The authorized_role invariant provides formal Z3 proof that "
        "only credentialled principals may invoke guarded actions.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.1",
        "Logical and Physical Access Controls",
        "trusted_mesh_caller",
        "CC6.1 requires logical access restrictions. "
        "The trusted_mesh_caller invariant provides Z3-verified proof "
        "that only SPIFFE-authenticated service mesh principals may invoke this action.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.1",
        "Logical and Physical Access Controls",
        "amount_limit",
        "CC6.1 requires transaction authorisation controls. "
        "The amount_limit invariant enforces a Z3-verified upper bound on "
        "each transaction, preventing unauthorised high-value transfers.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.1",
        "Logical and Physical Access Controls",
        "within_limit",
        "CC6.1 requires authorisation controls. "
        "The within_limit invariant enforces a Z3-verified per-request ceiling.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.7",
        "Logical Access Controls — Transaction Monitoring",
        "velocity_check",
        "CC6.7 requires detection of unusual access patterns. "
        "The velocity_check invariant provides Z3-verified enforcement of "
        "per-period transaction velocity limits (BSA/AML requirement).",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.8",
        "Logical Access Controls — Fraud Prevention",
        "anti_structuring",
        "CC6.8 requires controls to prevent fraud. "
        "The anti_structuring invariant formally proves that individual "
        "transactions do not fall into BSA structuring patterns.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC6.6",
        "Logical Access Controls — Identity Verification",
        "kyc_status",
        "CC6.6 requires identity verification before access. "
        "The kyc_status invariant provides Z3 proof that KYC is complete "
        "before any account action is permitted.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC9.1",
        "Risk Assessment and Mitigation",
        "sufficient_balance",
        "CC9.1 requires risk mitigation controls. "
        "The sufficient_balance invariant provides Z3-verified proof that "
        "a transfer cannot overdraw the account, mitigating liquidity risk.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC8.1",
        "Change Management Authorisation",
        "prod_gate_approval",
        "CC8.1 requires change management approval. "
        "The prod_gate_approval invariant proves that a human approval token "
        "was presented before any production system change was allowed.",
    ),
    _cm(
        RegulatoryFramework.SOC2,
        "CC7.2",
        "System Operations — Monitoring and Alerting",
        "blast_radius_check",
        "CC7.2 requires detection of and response to security events. "
        "The blast_radius_check invariant enforces a Z3-verified ceiling on "
        "the impact radius of any automated infrastructure change.",
    ),
    # ── EU AI Act ─────────────────────────────────────────────────────────────
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.14",
        "Human Oversight",
        "amount_limit",
        "Art. 14 requires that high-risk AI systems be designed so that "
        "natural persons can oversee and intervene. "
        "The amount_limit invariant provides formal Z3 proof that the AI "
        "cannot autonomously authorise transactions above the defined ceiling.",
    ),
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.14",
        "Human Oversight",
        "within_limit",
        "Art. 14 requires that AI systems permit human oversight. "
        "The within_limit invariant provides Z3-verified enforcement that "
        "the AI cannot exceed the per-request limit without human approval.",
    ),
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.14",
        "Human Oversight",
        "sufficient_balance",
        "Art. 14 requires that high-risk AI systems be accurate and controllable. "
        "The sufficient_balance invariant formally proves that the AI will not "
        "authorise financially unsafe operations.",
    ),
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.9",
        "Risk Management System",
        "authorized_role",
        "Art. 9 requires a continuous risk management system. "
        "The authorized_role invariant provides Z3-verified access control, "
        "forming part of the risk management lifecycle.",
    ),
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.9",
        "Risk Management System",
        "blast_radius_check",
        "Art. 9 requires risk identification and mitigation. "
        "The blast_radius_check invariant provides formal proof that "
        "the impact radius of any AI-triggered change is bounded.",
    ),
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.13",
        "Transparency",
        "kyc_status",
        "Art. 13 requires that high-risk AI systems be transparent. "
        "The kyc_status invariant provides Z3-verified proof that "
        "identity verification was completed — an auditable transparency claim.",
    ),
    _cm(
        RegulatoryFramework.EU_AI_ACT,
        "Art.15",
        "Accuracy, Robustness and Cybersecurity",
        "phi_least_privilege",
        "Art. 15 requires accuracy and robustness against risks. "
        "The phi_least_privilege invariant provides formal Z3 proof that "
        "data access is bounded to the minimum necessary.",
    ),
    # ── HIPAA ─────────────────────────────────────────────────────────────────
    _cm(
        RegulatoryFramework.HIPAA,
        "§164.312",
        "Technical Safeguards — Access Control",
        "authorized_role",
        "§164.312(a)(1) requires unique user identification and access control. "
        "The authorized_role invariant provides Z3-verified proof that role "
        "checks gate all PHI access operations.",
    ),
    _cm(
        RegulatoryFramework.HIPAA,
        "§164.514",
        "De-Identification — Minimum Necessary",
        "phi_least_privilege",
        "§164.514(d) requires that disclosure be limited to the minimum necessary. "
        "The phi_least_privilege invariant provides Z3 proof that each request "
        "does not exceed the minimum necessary data scope.",
    ),
    _cm(
        RegulatoryFramework.HIPAA,
        "§164.508",
        "Authorization Requirements",
        "patient_consent_required",
        "§164.508 requires patient authorisation before disclosure. "
        "The patient_consent_required invariant provides Z3-verified proof that "
        "a valid consent record is present before any disclosure action.",
    ),
    _cm(
        RegulatoryFramework.HIPAA,
        "§164.508",
        "Authorization Requirements",
        "consent_active",
        "§164.508(c) requires that the authorisation be currently valid. "
        "The consent_active invariant proves that the consent has not expired.",
    ),
    _cm(
        RegulatoryFramework.HIPAA,
        "§164.502",
        "Uses and Disclosures — Minimum Necessary",
        "must_be_clinician",
        "§164.502(b) requires disclosure limited to the minimum necessary. "
        "The must_be_clinician invariant provides Z3 proof that PHI access "
        "is restricted to licensed clinical staff.",
    ),
    _cm(
        RegulatoryFramework.HIPAA,
        "§164.312",
        "Emergency Access Procedure",
        "break_glass_auth",
        "§164.312(a)(2)(ii) requires procedures for emergency PHI access. "
        "The break_glass_auth invariant formally verifies that an emergency "
        "access token was presented and is valid before override access is granted.",
    ),
    # ── NIST AI RMF ───────────────────────────────────────────────────────────
    _cm(
        RegulatoryFramework.NIST_AI_RMF,
        "GOVERN-1.1",
        "Policies, Processes, Procedures and Practices",
        "authorized_role",
        "GOVERN-1.1 requires that policies for AI risk management are documented. "
        "The authorized_role invariant demonstrates machine-verifiable enforcement "
        "of access control policy.",
    ),
    _cm(
        RegulatoryFramework.NIST_AI_RMF,
        "MANAGE-3.1",
        "Risk Treatment — Response",
        "amount_limit",
        "MANAGE-3.1 requires that identified risks are responded to. "
        "The amount_limit invariant provides Z3-verified evidence that "
        "the AI system responds to financial risk by enforcing per-request limits.",
    ),
    _cm(
        RegulatoryFramework.NIST_AI_RMF,
        "MEASURE-2.5",
        "AI Risk Measurement — System Performance",
        "sufficient_balance",
        "MEASURE-2.5 requires that AI system performance is measured. "
        "The sufficient_balance invariant provides formal evidence that "
        "the AI system accurately enforces financial safety constraints.",
    ),
    _cm(
        RegulatoryFramework.NIST_AI_RMF,
        "MAP-2.1",
        "AI Risk Characterisation",
        "blast_radius_check",
        "MAP-2.1 requires characterisation of AI system risks and impacts. "
        "The blast_radius_check invariant provides Z3-verified bounds on "
        "the potential impact radius of each AI-driven change.",
    ),
    _cm(
        RegulatoryFramework.NIST_AI_RMF,
        "GOVERN-3.1",
        "Organizational Accountability",
        "kyc_status",
        "GOVERN-3.1 requires that accountability for AI risks is established. "
        "The kyc_status invariant provides verifiable identity accountability "
        "by formally proving KYC completion before action.",
    ),
    # ── GDPR ──────────────────────────────────────────────────────────────────
    _cm(
        RegulatoryFramework.GDPR,
        "Art.25",
        "Data Protection by Design and by Default",
        "phi_least_privilege",
        "Art. 25 requires data minimisation by design. "
        "The phi_least_privilege invariant provides Z3-verified proof that "
        "data access is bounded to the minimum necessary for each operation.",
    ),
    _cm(
        RegulatoryFramework.GDPR,
        "Art.5",
        "Principles Relating to Processing of Personal Data",
        "authorized_role",
        "Art. 5(1)(f) requires appropriate security of personal data. "
        "The authorized_role invariant provides Z3-verified access control "
        "as a technical safeguard for personal data processing.",
    ),
    _cm(
        RegulatoryFramework.GDPR,
        "Art.25",
        "Data Protection by Design and by Default",
        "kyc_status",
        "Art. 25 requires that data protection principles are implemented by design. "
        "The kyc_status invariant ensures identity is formally verified "
        "before any personal data processing action is permitted.",
    ),
]


def default_oracle() -> ComplianceOracle:
    """Create a :class:`ComplianceOracle` pre-loaded with built-in control mappings.

    The built-in library maps conventional Pramanix invariant label names to
    controls across six frameworks: SOC 2, EU AI Act, HIPAA, NIST AI RMF,
    ISO/IEC 42001, and GDPR.

    Policies that follow Pramanix naming conventions (``amount_limit``,
    ``authorized_role``, ``sufficient_balance``, etc.) receive compliance
    attestations with no manual oracle configuration.

    Returns
    -------
    ComplianceOracle
        A freshly constructed oracle with all built-in mappings registered.
        Call :meth:`ComplianceOracle.register_mapping` on the returned oracle
        to add project-specific mappings on top of the built-in library.

    Example
    -------
    ::

        from pramanix.compliance.oracle import default_oracle, RegulatoryFramework

        oracle = default_oracle()
        attestation = oracle.evaluate_record(record, frameworks=[RegulatoryFramework.SOC2])
        print(attestation.summary)
    """
    oracle = ComplianceOracle()
    for mapping in _BUILT_IN_MAPPINGS:
        oracle.register_mapping(mapping.framework, mapping)
    return oracle
