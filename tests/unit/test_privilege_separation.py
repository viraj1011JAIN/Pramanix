# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for privilege separation (pramanix.privilege).

All tests use real objects — no mocks, no monkeypatching of Pramanix internals.
"""
from __future__ import annotations

import pytest

from pramanix.exceptions import PrivilegeEscalationError
from pramanix.privilege import (
    CapabilityManifest,
    ExecutionContext,
    ExecutionScope,
    ScopeEnforcer,
    ToolCapability,
)


# ── ExecutionScope tests ──────────────────────────────────────────────────────


class TestExecutionScope:
    def test_none_is_zero(self):
        assert ExecutionScope.NONE == 0

    def test_compose_with_or(self):
        combined = ExecutionScope.READ_ONLY | ExecutionScope.NETWORK
        assert ExecutionScope.READ_ONLY in combined
        assert ExecutionScope.NETWORK in combined
        assert ExecutionScope.WRITE not in combined

    def test_requires_dual_control_financial(self):
        assert ExecutionScope.FINANCIAL.requires_dual_control()

    def test_requires_dual_control_destructive(self):
        assert ExecutionScope.DESTRUCTIVE.requires_dual_control()

    def test_requires_dual_control_admin(self):
        assert ExecutionScope.ADMIN.requires_dual_control()

    def test_no_dual_control_for_read_write(self):
        assert not ExecutionScope.READ_ONLY.requires_dual_control()
        assert not ExecutionScope.WRITE.requires_dual_control()
        assert not ExecutionScope.NETWORK.requires_dual_control()

    def test_compound_requires_dual_control(self):
        compound = ExecutionScope.WRITE | ExecutionScope.FINANCIAL
        assert compound.requires_dual_control()

    def test_scope_names_single(self):
        names = ExecutionScope.WRITE.scope_names()
        assert names == ["WRITE"]

    def test_scope_names_compound(self):
        compound = ExecutionScope.READ_ONLY | ExecutionScope.NETWORK
        names = compound.scope_names()
        assert "READ_ONLY" in names
        assert "NETWORK" in names

    def test_scope_names_none_empty(self):
        assert ExecutionScope.NONE.scope_names() == []


# ── ToolCapability and CapabilityManifest tests ───────────────────────────────


class TestCapabilityManifest:
    def _make_manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            capabilities=[
                ToolCapability(
                    "read_account",
                    ExecutionScope.READ_ONLY,
                    description="Read account balance.",
                ),
                ToolCapability(
                    "transfer_funds",
                    ExecutionScope.WRITE | ExecutionScope.FINANCIAL,
                    description="Transfer funds.",
                ),
                ToolCapability(
                    "delete_account",
                    ExecutionScope.DESTRUCTIVE,
                    description="Delete account.",
                ),
            ]
        )

    def test_get_known_tool(self):
        manifest = self._make_manifest()
        cap = manifest.get("read_account")
        assert cap is not None
        assert cap.tool_name == "read_account"

    def test_get_unknown_tool_returns_none(self):
        manifest = self._make_manifest()
        assert manifest.get("nonexistent") is None

    def test_deny_unknown_property(self):
        manifest = self._make_manifest()
        assert manifest.deny_unknown is True

    def test_registered_tools_sorted(self):
        manifest = self._make_manifest()
        tools = manifest.registered_tools()
        assert tools == sorted(tools)
        assert "read_account" in tools
        assert "transfer_funds" in tools

    def test_allow_unknown_flag(self):
        manifest = CapabilityManifest(capabilities=[], deny_unknown=False)
        assert manifest.deny_unknown is False


# ── ScopeEnforcer tests ───────────────────────────────────────────────────────


class TestScopeEnforcer:
    def _make(self) -> tuple[ScopeEnforcer, CapabilityManifest]:
        manifest = CapabilityManifest(
            capabilities=[
                ToolCapability("read", ExecutionScope.READ_ONLY),
                ToolCapability("write", ExecutionScope.WRITE),
                ToolCapability(
                    "transfer",
                    ExecutionScope.WRITE | ExecutionScope.FINANCIAL,
                ),
                ToolCapability(
                    "destroy",
                    ExecutionScope.DESTRUCTIVE,
                ),
                ToolCapability(
                    "bypass_tool",
                    ExecutionScope.FINANCIAL,
                    allows_dual_control_bypass=True,
                ),
            ]
        )
        return ScopeEnforcer(manifest), manifest

    def _ctx(
        self,
        scopes: ExecutionScope = ExecutionScope.READ_ONLY,
        principal: str = "agent-001",
        approved_by: str = "",
    ) -> ExecutionContext:
        return ExecutionContext(
            granted_scopes=scopes,
            principal_id=principal,
            approved_by=approved_by,
        )

    def test_allowed_read(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        enforcer.enforce("read", ctx)  # must not raise

    def test_missing_scope_raises(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        with pytest.raises(PrivilegeEscalationError) as exc_info:
            enforcer.enforce("write", ctx)
        assert "WRITE" in str(exc_info.value)

    def test_dual_control_required_without_approval(self):
        enforcer, _ = self._make()
        ctx = self._ctx(
            ExecutionScope.WRITE | ExecutionScope.FINANCIAL,
            approved_by="",
        )
        with pytest.raises(PrivilegeEscalationError) as exc_info:
            enforcer.enforce("transfer", ctx)
        assert "dual-control" in str(exc_info.value).lower()

    def test_dual_control_satisfied(self):
        enforcer, _ = self._make()
        ctx = self._ctx(
            ExecutionScope.WRITE | ExecutionScope.FINANCIAL,
            approved_by="oversight-req-abc123",
        )
        enforcer.enforce("transfer", ctx)  # must not raise

    def test_dual_control_bypass_allowed(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.FINANCIAL, approved_by="")
        enforcer.enforce("bypass_tool", ctx)  # must not raise

    def test_unknown_tool_raises_when_deny(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        with pytest.raises(PrivilegeEscalationError) as exc_info:
            enforcer.enforce("unknown_tool", ctx)
        assert "not registered" in str(exc_info.value).lower()

    def test_unknown_tool_allowed_when_deny_false(self):
        manifest = CapabilityManifest(capabilities=[], deny_unknown=False)
        enforcer = ScopeEnforcer(manifest)
        ctx = self._ctx(ExecutionScope.NONE)
        enforcer.enforce("anything", ctx)  # must not raise

    def test_destructive_requires_dual_control(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.DESTRUCTIVE, approved_by="")
        with pytest.raises(PrivilegeEscalationError):
            enforcer.enforce("destroy", ctx)

    def test_destructive_with_approval(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.DESTRUCTIVE, approved_by="req-xyz")
        enforcer.enforce("destroy", ctx)  # must not raise

    def test_audit_log_records_permit(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        enforcer.enforce("read", ctx)
        log = enforcer.audit_log()
        assert len(log) == 1
        assert log[0]["permitted"] is True
        assert log[0]["tool"] == "read"

    def test_audit_log_records_deny(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        with pytest.raises(PrivilegeEscalationError):
            enforcer.enforce("write", ctx)
        log = enforcer.audit_log()
        assert len(log) == 1
        assert log[0]["permitted"] is False

    def test_audit_log_is_copy(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        enforcer.enforce("read", ctx)
        log1 = enforcer.audit_log()
        log2 = enforcer.audit_log()
        assert log1 is not log2

    def test_privilege_escalation_error_attributes(self):
        enforcer, _ = self._make()
        ctx = self._ctx(ExecutionScope.READ_ONLY)
        with pytest.raises(PrivilegeEscalationError) as exc_info:
            enforcer.enforce("write", ctx)
        err = exc_info.value
        assert err.tool == "write"
        assert "WRITE" in err.required_scope
        assert isinstance(err.held_scopes, frozenset)

    def test_multiple_calls_accumulate_audit(self):
        enforcer, _ = self._make()
        ctx_r = self._ctx(ExecutionScope.READ_ONLY)
        ctx_w = self._ctx(ExecutionScope.WRITE)
        enforcer.enforce("read", ctx_r)
        enforcer.enforce("write", ctx_w)
        assert len(enforcer.audit_log()) == 2
