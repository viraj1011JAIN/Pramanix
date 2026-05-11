# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real tests for the three inline governance gates in Guard.

Each gate is exercised in both sync (verify) and async (verify_async) modes.
Tests use only real objects — no mocks, no stubs.

Gates covered
-------------
* Privilege scope gate  (guard.py 497-535, 895-897, 1280-1282)
* Human oversight gate  (guard.py 538-591, 895-897, 1280-1282)
* IFC flow gate         (guard.py 594-638, 895-897, 1355-1357)

Also covers Decision.governance_blocked (decision.py 618-621).
"""
from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix.decision import Decision, SolverStatus
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.governance_config import GovernanceConfig
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.ifc.flow_policy import FlowPolicy, FlowRule
from pramanix.ifc.labels import TrustLabel
from pramanix.oversight.workflow import InMemoryApprovalWorkflow
from pramanix.policy import Policy
from pramanix.privilege.scope import (
    CapabilityManifest,
    ExecutionScope,
    ToolCapability,
)


# ── Shared policy that always ALLOWs ─────────────────────────────────────────


class _AlwaysAllowModel(BaseModel):
    amount: Decimal
    balance: Decimal


class _AlwaysAllowPolicy(Policy):
    """Policy whose Z3 invariants are always satisfied (amount <= balance)."""

    class Meta:
        version = "1.0"
        intent_model = _AlwaysAllowModel
        state_model = _AlwaysAllowModel

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= E(cls.balance)).named("within_balance")
        ]


_ALLOW_INTENT = {"amount": Decimal("10"), "balance": Decimal("1000")}
_ALLOW_STATE: dict = {}  # all fields in intent_model, state_model shares same fields

# Actually both intent and state need non-overlapping keys.  Use a policy
# where intent has 'amount' and state has 'balance'.


class _IntentModel(BaseModel):
    amount: Decimal
    tool: str = ""
    principal_id: str = ""
    oversight_request_id: str = ""
    _ifc_source_component: str = ""
    _ifc_sink_component: str = ""
    _ifc_source_label: int | None = None
    _ifc_sink_label: int | None = None


class _StateModel(BaseModel):
    balance: Decimal
    state_version: str = "1.0"


class _GovernancePolicy(Policy):
    """Policy with separate intent/state models for governance gate tests."""

    class Meta:
        version = "1.0"
        intent_model = _IntentModel
        state_model = _StateModel

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= E(cls.balance)).named("within_balance")
        ]


_GOV_INTENT_ALLOW = {"amount": Decimal("10")}
_GOV_STATE = {"balance": Decimal("1000"), "state_version": "1.0"}


class _IFCTestPolicy(Policy):
    """Policy for IFC tests: NO intent/state models so raw dict passes through.

    IFC intent keys start with underscore (e.g. _ifc_source_component).
    Pydantic strips underscore-prefixed fields, so the policy must have no
    intent_model — the intent dict is used as-is, preserving those keys.
    """

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= E(cls.balance)).named("within_balance")
        ]


_IFC_ALLOW_INTENT = {"amount": Decimal("10"), "balance": Decimal("1000")}


# ═══════════════════════════════════════════════════════════════════════════════
# Privilege scope gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestPrivilegeGate:
    """Privilege scope gate: guard.py 497-535."""

    def _make_manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            capabilities=[
                ToolCapability(
                    tool_name="transfer_funds",
                    required_scopes=ExecutionScope.WRITE | ExecutionScope.FINANCIAL,
                    description="Transfer funds.",
                    allows_dual_control_bypass=True,  # skip dual-control for simplicity
                ),
            ]
        )

    def _make_guard(self, execution_mode: str = "sync") -> Guard:
        manifest = self._make_manifest()
        gov = GovernanceConfig(
            capability_manifest=manifest,
            execution_scope=ExecutionScope.READ_ONLY,  # insufficient scope
        )
        cfg = GuardConfig(governance=gov, execution_mode=execution_mode, worker_warmup=False)
        return Guard(_GovernancePolicy, cfg)

    def test_sync_privilege_gate_blocks_insufficient_scope(self) -> None:
        guard = self._make_guard()
        intent = {**_GOV_INTENT_ALLOW, "tool": "transfer_funds"}
        decision = guard.verify(intent=intent, state=_GOV_STATE)

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "privilege"

    def test_sync_privilege_gate_allows_no_tool_key(self) -> None:
        """When intent has no 'tool' key, the privilege gate is skipped."""
        guard = self._make_guard()
        decision = guard.verify(intent=_GOV_INTENT_ALLOW, state=_GOV_STATE)

        assert decision.allowed

    def test_sync_privilege_gate_allows_unknown_tool_when_deny_unknown_false(self) -> None:
        """deny_unknown=False manifest passes unregistered tools through."""
        manifest = CapabilityManifest(capabilities=[], deny_unknown=False)
        gov = GovernanceConfig(
            capability_manifest=manifest,
            execution_scope=ExecutionScope.NONE,
        )
        guard = Guard(_GovernancePolicy, GuardConfig(governance=gov))
        intent = {**_GOV_INTENT_ALLOW, "tool": "some_unregistered_tool"}
        decision = guard.verify(intent=intent, state=_GOV_STATE)
        assert decision.allowed

    @pytest.mark.asyncio
    async def test_async_privilege_gate_blocks_insufficient_scope(self) -> None:
        guard = self._make_guard(execution_mode="async-thread")
        intent = {**_GOV_INTENT_ALLOW, "tool": "transfer_funds"}
        decision = await guard.verify_async(intent=intent, state=_GOV_STATE)

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "privilege"

    @pytest.mark.asyncio
    async def test_async_privilege_gate_allows_no_tool_key(self) -> None:
        guard = self._make_guard(execution_mode="async-thread")
        decision = await guard.verify_async(intent=_GOV_INTENT_ALLOW, state=_GOV_STATE)
        assert decision.allowed


# ═══════════════════════════════════════════════════════════════════════════════
# Human oversight gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestOversightGate:
    """Human oversight gate: guard.py 538-591."""

    def _make_guard(self, execution_mode: str = "sync") -> tuple[Guard, InMemoryApprovalWorkflow]:
        workflow = InMemoryApprovalWorkflow()
        gov = GovernanceConfig(oversight_workflow=workflow)
        guard = Guard(_GovernancePolicy, GuardConfig(governance=gov, execution_mode=execution_mode, worker_warmup=False))
        return guard, workflow

    def test_sync_no_request_id_triggers_new_request(self) -> None:
        """Missing oversight_request_id → request_approval → GOVERNANCE_BLOCKED."""
        guard, workflow = self._make_guard()
        decision = guard.verify(intent=_GOV_INTENT_ALLOW, state=_GOV_STATE)

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "oversight"
        assert "oversight_request_id" in decision.metadata

    def test_sync_invalid_request_id_blocks(self) -> None:
        """Unknown/unapproved oversight_request_id → check returns False → BLOCKED."""
        guard, _ = self._make_guard()
        intent = {**_GOV_INTENT_ALLOW, "oversight_request_id": "nonexistent-id-xyz"}
        decision = guard.verify(intent=intent, state=_GOV_STATE)

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "oversight"

    def test_sync_approved_request_id_allows(self) -> None:
        """Approved oversight_request_id → check returns True → ALLOW."""
        guard, workflow = self._make_guard()

        # First call creates a request (BLOCKED but we get the request ID).
        blocked = guard.verify(intent=_GOV_INTENT_ALLOW, state=_GOV_STATE)
        assert not blocked.allowed
        rid = blocked.metadata["oversight_request_id"]

        # Reviewer approves the request.
        workflow.approve(rid, reviewer_id="test_reviewer", comment="Approved for test")

        # Retry with the approved request ID.
        intent = {**_GOV_INTENT_ALLOW, "oversight_request_id": rid}
        decision = guard.verify(intent=intent, state=_GOV_STATE)
        assert decision.allowed

    @pytest.mark.asyncio
    async def test_async_no_request_id_triggers_new_request(self) -> None:
        guard, workflow = self._make_guard(execution_mode="async-thread")
        decision = await guard.verify_async(intent=_GOV_INTENT_ALLOW, state=_GOV_STATE)

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "oversight"

    @pytest.mark.asyncio
    async def test_async_invalid_request_id_blocks(self) -> None:
        guard, _ = self._make_guard(execution_mode="async-thread")
        intent = {**_GOV_INTENT_ALLOW, "oversight_request_id": "bad-id"}
        decision = await guard.verify_async(intent=intent, state=_GOV_STATE)

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "oversight"


# ═══════════════════════════════════════════════════════════════════════════════
# IFC flow gate
# ═══════════════════════════════════════════════════════════════════════════════


class TestIFCGate:
    """IFC flow gate: guard.py 594-638."""

    def _make_strict_policy(self) -> FlowPolicy:
        """Policy that blocks UNTRUSTED → PUBLIC flows."""
        return FlowPolicy(
            rules=[
                FlowRule(
                    source_label=TrustLabel.UNTRUSTED,
                    sink_label=TrustLabel.PUBLIC,
                    permitted=False,
                    reason="Untrusted data must not flow to public sinks.",
                ),
                FlowRule(
                    source_label=TrustLabel.INTERNAL,
                    sink_label=TrustLabel.INTERNAL,
                    permitted=True,
                ),
            ],
            default_deny=True,
        )

    def _make_guard(self, execution_mode: str = "sync") -> Guard:
        gov = GovernanceConfig(ifc_policy=self._make_strict_policy())
        # Use _IFCTestPolicy (no intent_model) so underscore-prefixed IFC keys
        # are preserved in intent_values and reach the gate.
        return Guard(_IFCTestPolicy, GuardConfig(governance=gov, execution_mode=execution_mode, worker_warmup=False))

    def _ifc_intent(
        self,
        src_label: int,
        snk_label: int,
        src_comp: str = "user_input",
        snk_comp: str = "executor",
    ) -> dict:
        return {
            **_IFC_ALLOW_INTENT,
            "_ifc_source_component": src_comp,
            "_ifc_sink_component": snk_comp,
            "_ifc_source_label": src_label,
            "_ifc_sink_label": snk_label,
        }

    def test_sync_ifc_gate_blocks_denied_flow(self) -> None:
        guard = self._make_guard()
        intent = self._ifc_intent(
            src_label=TrustLabel.UNTRUSTED.value,
            snk_label=TrustLabel.PUBLIC.value,
        )
        decision = guard.verify(intent=intent, state={})

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "ifc"

    def test_sync_ifc_gate_allows_permitted_flow(self) -> None:
        guard = self._make_guard()
        intent = self._ifc_intent(
            src_label=TrustLabel.INTERNAL.value,
            snk_label=TrustLabel.INTERNAL.value,
        )
        decision = guard.verify(intent=intent, state={})
        assert decision.allowed

    def test_sync_ifc_gate_skipped_when_labels_absent(self) -> None:
        """No IFC keys → gate is skipped → ALLOW."""
        guard = self._make_guard()
        decision = guard.verify(intent=_IFC_ALLOW_INTENT, state={})
        assert decision.allowed

    def test_sync_ifc_gate_passes_on_malformed_labels(self) -> None:
        """Non-integer label values → ValueError silently skipped → ALLOW."""
        guard = self._make_guard()
        intent = {
            **_IFC_ALLOW_INTENT,
            "_ifc_source_component": "src",
            "_ifc_sink_component": "snk",
            "_ifc_source_label": "not_an_int",
            "_ifc_sink_label": "also_bad",
        }
        decision = guard.verify(intent=intent, state={})
        assert decision.allowed

    @pytest.mark.asyncio
    async def test_async_ifc_gate_blocks_denied_flow(self) -> None:
        guard = self._make_guard(execution_mode="async-thread")
        intent = self._ifc_intent(
            src_label=TrustLabel.UNTRUSTED.value,
            snk_label=TrustLabel.PUBLIC.value,
        )
        decision = await guard.verify_async(intent=intent, state={})

        assert not decision.allowed
        assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
        assert decision.metadata.get("stage") == "ifc"

    @pytest.mark.asyncio
    async def test_async_ifc_gate_allows_permitted_flow(self) -> None:
        guard = self._make_guard(execution_mode="async-thread")
        intent = self._ifc_intent(
            src_label=TrustLabel.INTERNAL.value,
            snk_label=TrustLabel.INTERNAL.value,
        )
        decision = await guard.verify_async(intent=intent, state={})
        assert decision.allowed


# ═══════════════════════════════════════════════════════════════════════════════
# Async-process governance gate (guard.py lines 1351-1357)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAsyncProcessGovernanceGate:
    """guard.py lines 1351-1357: governance gate fires in async-process mode."""

    def _make_guard(self) -> Guard:
        flow_policy = FlowPolicy(
            rules=[
                FlowRule(
                    source_label=TrustLabel.UNTRUSTED,
                    sink_label=TrustLabel.PUBLIC,
                    permitted=False,
                    reason="Untrusted data must not flow to public sinks.",
                ),
                FlowRule(
                    source_label=TrustLabel.INTERNAL,
                    sink_label=TrustLabel.INTERNAL,
                    permitted=True,
                ),
            ],
            default_deny=True,
        )
        gov = GovernanceConfig(ifc_policy=flow_policy)
        return Guard(
            _IFCTestPolicy,
            GuardConfig(governance=gov, execution_mode="async-process", worker_warmup=False),
        )

    @pytest.mark.asyncio
    async def test_async_process_ifc_gate_blocks_denied_flow(self) -> None:
        """async-process mode: IFC gate fires after Z3 ALLOW → GOVERNANCE_BLOCKED (1351-1357)."""
        guard = self._make_guard()
        try:
            intent = {
                **_IFC_ALLOW_INTENT,
                "_ifc_source_component": "user_input",
                "_ifc_sink_component": "executor",
                "_ifc_source_label": TrustLabel.UNTRUSTED.value,
                "_ifc_sink_label": TrustLabel.PUBLIC.value,
            }
            decision = await guard.verify_async(intent=intent, state={})
            assert not decision.allowed
            assert decision.status == SolverStatus.GOVERNANCE_BLOCKED
            assert decision.metadata.get("stage") == "ifc"
        finally:
            await guard.shutdown()

    @pytest.mark.asyncio
    async def test_async_process_ifc_gate_allows_permitted_flow(self) -> None:
        """async-process mode: IFC gate passes → Decision allowed (1357)."""
        guard = self._make_guard()
        try:
            intent = {
                **_IFC_ALLOW_INTENT,
                "_ifc_source_component": "internal",
                "_ifc_sink_component": "internal",
                "_ifc_source_label": TrustLabel.INTERNAL.value,
                "_ifc_sink_label": TrustLabel.INTERNAL.value,
            }
            decision = await guard.verify_async(intent=intent, state={})
            assert decision.allowed
        finally:
            await guard.shutdown()

    @pytest.mark.asyncio
    async def test_async_process_z3_blocks_skips_governance_gate(self) -> None:
        """Z3 returns UNSAFE in async-process → decision.allowed False → branch 1351->1357."""
        guard = self._make_guard()
        try:
            # amount=2000 > balance=1000 → within_balance invariant violated → Z3 BLOCK
            # governance gate is skipped because decision.allowed is False
            intent = {
                "amount": Decimal("2000"),
                "balance": Decimal("1000"),
                "_ifc_source_component": "src",
                "_ifc_sink_component": "snk",
                "_ifc_source_label": TrustLabel.INTERNAL.value,
                "_ifc_sink_label": TrustLabel.INTERNAL.value,
            }
            decision = await guard.verify_async(intent=intent, state={})
            assert not decision.allowed
            assert decision.status == SolverStatus.UNSAFE
        finally:
            await guard.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.governance_blocked factory
# ═══════════════════════════════════════════════════════════════════════════════


class TestGovernanceBlockedFactory:
    """Decision.governance_blocked covers decision.py 618-621."""

    def test_governance_blocked_basic(self) -> None:
        d = Decision.governance_blocked(
            stage="privilege",
            reason="Insufficient scope.",
        )
        assert not d.allowed
        assert d.status == SolverStatus.GOVERNANCE_BLOCKED
        assert d.metadata["stage"] == "privilege"
        assert d.explanation == "Insufficient scope."

    def test_governance_blocked_with_metadata(self) -> None:
        d = Decision.governance_blocked(
            stage="oversight",
            reason="Approval required.",
            metadata={"oversight_request_id": "req-123"},
            intent_dump={"amount": "100"},
            state_dump={"balance": "500"},
        )
        assert d.metadata["stage"] == "oversight"
        assert d.metadata["oversight_request_id"] == "req-123"
        assert d.intent_dump == {"amount": "100"}
        assert d.state_dump == {"balance": "500"}

    def test_governance_blocked_can_be_hashed(self) -> None:
        """Decision.__hash__ covers decision.py 301-303."""
        d1 = Decision.governance_blocked(stage="ifc", reason="flow denied")
        d2 = Decision.safe()
        s = {d1, d2}
        assert len(s) == 2

    def test_cache_hit_wraps_base_decision(self) -> None:
        """Decision.cache_hit covers decision.py 650."""
        base = Decision.safe()
        cached = Decision.cache_hit(base=base)
        assert cached.allowed
        assert cached.status == base.status
        assert cached.metadata.get("_solver_status_tag") == "cache_hit"


# ═══════════════════════════════════════════════════════════════════════════════
# GovernanceConfig validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestGovernanceConfigValidation:
    """GovernanceConfig.__post_init__ (governance_config.py)."""

    def test_execution_scope_without_manifest_raises(self) -> None:
        from pramanix.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="execution_scope requires capability_manifest"):
            GovernanceConfig(execution_scope=ExecutionScope.WRITE)

    def test_all_none_is_valid(self) -> None:
        gov = GovernanceConfig()
        assert gov.capability_manifest is None
        assert gov.oversight_workflow is None
        assert gov.ifc_policy is None

    def test_manifest_with_scope_is_valid(self) -> None:
        manifest = CapabilityManifest(capabilities=[])
        gov = GovernanceConfig(
            capability_manifest=manifest,
            execution_scope=ExecutionScope.READ_ONLY,
        )
        assert gov.capability_manifest is manifest
