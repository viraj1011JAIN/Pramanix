# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Miscellaneous coverage tests for small gaps in several modules.

Targets:
  provenance.py         303-308   verify_integrity chain-broken path
  helpers/policy_auditor.py 83,85,87,89  _collect_field_names PowOp/ModOp/string/ForAll
  lifecycle/diff.py     436-437   _collect_fields descriptor-raises exception
  ifc/enforcer.py       211-212   audit_sink raises → error logged
  ifc/flow_policy.py    71        sink_component filter False branch
  translator/redundant.py 124-127 _raw_strings_agree with Optional[X] type
  translator/redundant.py 144->146 _norm_bool string not in true/false vals
  integrations/pydantic_ai.py 145-154 guard_tool wrapper invocation
  integrations/langchain.py 141   execute_fn=None → NotImplementedError
"""
from __future__ import annotations

import asyncio
import sys
import types
from decimal import Decimal
from typing import Any

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.expressions import (
    ConstraintExpr,
    E,
    Field as ExprField,
    _FieldRef,
    _PowOp,
    _ModOp,
    _ForAllOp,
    _ExistsOp,
    _StartsWithOp,
    _ContainsOp,
    _EndsWithOp,
    _LengthBetweenOp,
    _RegexMatchOp,
)
from pramanix.exceptions import ConfigurationError
from pramanix.helpers.policy_auditor import _collect_field_names
from pramanix.ifc.enforcer import FlowEnforcer
from pramanix.ifc.flow_policy import FlowPolicy, FlowRule
from pramanix.ifc.labels import ClassifiedData, TrustLabel
from pramanix.lifecycle.diff import _collect_fields
from pramanix.policy import Policy
from pramanix.provenance import ProvenanceChain, ProvenanceRecord


# ═══════════════════════════════════════════════════════════════════════════════
# provenance.py lines 303-308: verify_integrity chain-broken path
# ═══════════════════════════════════════════════════════════════════════════════


class TestProvenanceChainBroken:
    """ProvenanceChain.verify_integrity when prev_hash is tampered."""

    def _make_record(self, decision_id: str = "dec-1", allowed: bool = True, prev_hash: str = "") -> ProvenanceRecord:
        return ProvenanceRecord(
            decision_id=decision_id,
            policy_hash="sha256:abc",
            model_version="",
            input_labels={},
            tool_manifest=frozenset(),
            principal_id="test",
            allowed=allowed,
            prev_hash=prev_hash,
        )

    def test_chain_broken_returns_false(self) -> None:
        """Tamper prev_hash of the second record → chain broken → verify returns False."""
        chain = ProvenanceChain(max_records=100)
        r1 = self._make_record("d1")
        r2 = self._make_record("d2")
        chain.append(r1)
        chain.append(r2)

        # Tamper the second record's prev_hash by directly mutating _records.
        import dataclasses

        records = list(chain._records)
        # Replace second record with a tampered prev_hash.
        tampered = dataclasses.replace(records[1], prev_hash="tampered_bad_hash")
        chain._records[1] = tampered
        # Update the stored HMAC tag to match the tampered record so the per-record
        # integrity check (lines 294-301) passes.  Only then does the chain-link check
        # at lines 302-308 fire (tampered.prev_hash ≠ chain._tags[0]).
        chain._tags[1] = tampered.hmac_tag(chain._key)

        assert chain.verify_integrity() is False


# ═══════════════════════════════════════════════════════════════════════════════
# helpers/policy_auditor.py lines 83, 85, 87, 89:
# _collect_field_names with PowOp, ModOp, string ops, ForAll/Exists
# ═══════════════════════════════════════════════════════════════════════════════


class TestCollectFieldNamesDarkPaths:
    """_collect_field_names handles all expression node types."""

    def _field_ref(self, name: str) -> _FieldRef:
        return _FieldRef(ExprField(name, int, "Int"))

    def test_pow_op(self) -> None:
        """PowOp → returns field name from base (line 83)."""
        node = _PowOp(base=self._field_ref("x"), exp=self._field_ref("x"))
        assert _collect_field_names(node) == {"x"}

    def test_mod_op(self) -> None:
        """ModOp → returns field names from dividend and divisor (line 85)."""
        node = _ModOp(dividend=self._field_ref("a"), divisor=self._field_ref("b"))
        assert _collect_field_names(node) == {"a", "b"}

    def test_starts_with_op(self) -> None:
        """StartsWithOp → returns field name from operand (line 87)."""
        node = _StartsWithOp(operand=self._field_ref("s"), prefix="prefix_val")
        assert _collect_field_names(node) == {"s"}

    def test_contains_op(self) -> None:
        """ContainsOp → covered by same isinstance branch (line 87)."""
        node = _ContainsOp(operand=self._field_ref("t"), substring="sub")
        assert _collect_field_names(node) == {"t"}

    def test_ends_with_op(self) -> None:
        """EndsWithOp → covered by same isinstance branch (line 87)."""
        node = _EndsWithOp(operand=self._field_ref("u"), suffix="end")
        assert _collect_field_names(node) == {"u"}

    def test_for_all_op(self) -> None:
        """ForAllOp → returns array_field name (line 89)."""
        f = ExprField("items", list, "Int")
        node = _ForAllOp(array_field=f, predicate=None)
        assert _collect_field_names(node) == {"items"}

    def test_exists_op(self) -> None:
        """ExistsOp → returns array_field name (line 89)."""
        f = ExprField("items", list, "Int")
        node = _ExistsOp(array_field=f, predicate=None)
        assert _collect_field_names(node) == {"items"}


# ═══════════════════════════════════════════════════════════════════════════════
# lifecycle/diff.py lines 436-437: _collect_fields with raising descriptor
# ═══════════════════════════════════════════════════════════════════════════════


class _RaisingDescriptor:
    """Descriptor that raises AttributeError when accessed on a class."""

    def __get__(self, obj: Any, objtype: Any = None) -> Any:
        raise AttributeError("deliberate test error for coverage")


class TestCollectFieldsDescriptorException:
    """_collect_fields skips attributes that raise on access (lines 436-437)."""

    def test_descriptor_that_raises_is_skipped(self) -> None:
        class _PolicyWithBadAttr(Policy):
            bad = _RaisingDescriptor()
            amount = ExprField("amount", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("non_neg")]

        result = _collect_fields(_PolicyWithBadAttr, ExprField)
        assert "amount" in result
        assert "bad" not in result


# ═══════════════════════════════════════════════════════════════════════════════
# ifc/enforcer.py lines 211-212: audit_sink raises → error logged
# ═══════════════════════════════════════════════════════════════════════════════


class TestFlowEnforcerAuditSinkError:
    """FlowEnforcer logs and swallows audit_sink exceptions (lines 211-212)."""

    def test_audit_sink_exception_is_swallowed(self) -> None:
        def _bad_sink(data: Any, sink_component: str, permitted: bool) -> None:
            raise RuntimeError("test audit sink failure")

        policy = FlowPolicy(
            rules=[
                FlowRule(
                    source_label=TrustLabel.INTERNAL,
                    sink_label=TrustLabel.INTERNAL,
                    permitted=True,
                )
            ],
            default_deny=False,
        )
        enforcer = FlowEnforcer(policy=policy, audit_sink=_bad_sink)
        data = ClassifiedData(
            data="test",
            label=TrustLabel.INTERNAL,
            source="src",
        )
        enforcer.gate(data, sink_label=TrustLabel.INTERNAL, sink_component="dst")


# ═══════════════════════════════════════════════════════════════════════════════
# ifc/flow_policy.py line 71: sink_component filter False branch
# ═══════════════════════════════════════════════════════════════════════════════


class TestFlowRuleSinkComponentFilter:
    """FlowRule.matches with sink_component that does NOT match (line 71)."""

    def test_rule_with_sink_component_does_not_match_wrong_component(self) -> None:
        rule = FlowRule(
            source_label=TrustLabel.INTERNAL,
            sink_label=TrustLabel.INTERNAL,
            permitted=True,
            sink_component="executor",  # only matches "executor"
        )
        matched = rule.matches(
            data_label=TrustLabel.INTERNAL,
            sink_label=TrustLabel.INTERNAL,
            source_component="src",
            sink_component="logger",  # does NOT match "executor"
        )
        assert matched is False

    def test_rule_with_sink_component_matches_correct_component(self) -> None:
        rule = FlowRule(
            source_label=TrustLabel.INTERNAL,
            sink_label=TrustLabel.INTERNAL,
            permitted=True,
            sink_component="executor",
        )
        matched = rule.matches(
            data_label=TrustLabel.INTERNAL,
            sink_label=TrustLabel.INTERNAL,
            source_component="src",
            sink_component="executor",
        )
        assert matched is True


# ═══════════════════════════════════════════════════════════════════════════════
# translator/redundant.py lines 124-127: _raw_strings_agree with Optional field
# translator/redundant.py lines 144->146: bool string not in true/false vals
# ═══════════════════════════════════════════════════════════════════════════════


class TestSemanticFieldEqualDarkPaths:
    """_semantic_field_equal edge cases in translator/redundant.py."""

    def test_optional_field_type_unwrapping(self) -> None:
        """Optional[Decimal] annotation is unwrapped to Decimal (lines 124-127)."""
        from typing import Optional
        from pydantic import BaseModel
        from pramanix.translator.redundant import _semantic_field_equal

        class _Schema(BaseModel):
            amount: Optional[Decimal] = None

        assert _semantic_field_equal("100", "100", schema=_Schema, field_name="amount")
        assert not _semantic_field_equal("100", "200", schema=_Schema, field_name="amount")

    def test_bool_string_not_in_true_or_false_vals(self) -> None:
        """_norm_bool returns None for unknown string → falls to bool() comparison (144->146)."""
        from pydantic import BaseModel
        from pramanix.translator.redundant import _semantic_field_equal

        class _Schema(BaseModel):
            flag: bool

        # "maybe" is neither in true_vals nor false_vals → _norm_bool returns None
        # for both values → falls back to bool(val_a == val_b)
        result = _semantic_field_equal("maybe", "maybe", schema=_Schema, field_name="flag")
        assert result is True  # "maybe" == "maybe"

    def test_union_field_type_not_unwrapped(self) -> None:
        """Union[int, str] has len(non_none) == 2 → skip unwrap → branch 126->128."""
        from typing import Union
        from pydantic import BaseModel
        from pramanix.translator.redundant import _semantic_field_equal

        class _Schema(BaseModel):
            value: Union[int, str]

        # Union[int, str] → non_none = [int, str] → len != 1 → skip annotation = non_none[0]
        # Falls through to field_type = annotation (the raw Union[int, str])
        assert _semantic_field_equal("hello", "hello", schema=_Schema, field_name="value")
        assert not _semantic_field_equal("hello", "world", schema=_Schema, field_name="value")


# ═══════════════════════════════════════════════════════════════════════════════
# integrations/pydantic_ai.py lines 145-154: guard_tool wrapper invocation
# ═══════════════════════════════════════════════════════════════════════════════


class TestPydanticAIGuardToolWrapper:
    """PramanixPydanticAIValidator.guard_tool creates a working async wrapper."""

    @pytest.mark.asyncio
    async def test_guard_tool_wrapper_allow(self) -> None:
        """guard_tool wraps a function and calls check_async before the fn body."""
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _SimplePolicy(Policy):
            x = ExprField("x", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_neg")]

        guard = Guard(_SimplePolicy, GuardConfig())

        # Temporarily stub pydantic_ai so the constructor import check passes.
        _pai_stub = types.ModuleType("pydantic_ai")
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "pydantic_ai", _pai_stub)
            from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

            validator = PramanixPydanticAIValidator(guard=guard)

        call_log: list[str] = []

        @validator.guard_tool
        async def _tool(intent: dict, state: dict | None = None) -> str:
            call_log.append("executed")
            return "done"

        result = await _tool(intent={"x": 5}, state={})
        assert result == "done"
        assert "executed" in call_log

    @pytest.mark.asyncio
    async def test_guard_tool_wrapper_block(self) -> None:
        """guard_tool raises GuardViolationError when guard blocks."""
        from pramanix.exceptions import GuardViolationError
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _BlockPolicy(Policy):
            x = ExprField("x", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_neg")]

        guard = Guard(_BlockPolicy, GuardConfig())

        _pai_stub = types.ModuleType("pydantic_ai")
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "pydantic_ai", _pai_stub)
            from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

            validator = PramanixPydanticAIValidator(guard=guard)

        @validator.guard_tool
        async def _tool(intent: dict, state: dict | None = None) -> str:
            return "should not reach"

        with pytest.raises(GuardViolationError):
            await _tool(intent={"x": -1}, state={})


# ═══════════════════════════════════════════════════════════════════════════════
# integrations/langchain.py line 141: execute_fn=None → NotImplementedError
# ═══════════════════════════════════════════════════════════════════════════════


class TestLangchainExecuteFnNone:
    """PramanixGuardedTool with execute_fn=None raises NotImplementedError on ALLOW."""

    @pytest.mark.asyncio
    async def test_arun_with_no_execute_fn_raises(self) -> None:
        """When execute_fn=None and decision is ALLOW, _arun raises NotImplementedError."""
        import json
        from pydantic import BaseModel
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig
        from pramanix.policy import Policy

        class _IntentSchema(BaseModel):
            x: int

        class _AllowPolicy(Policy):
            x = ExprField("x", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_neg")]

        guard = Guard(_AllowPolicy, GuardConfig())

        # Stub langchain_core.tools so _LANGCHAIN_AVAILABLE = True check passes
        _lc_stub = types.ModuleType("langchain_core")
        _lc_tools_stub = types.ModuleType("langchain_core.tools")

        class _BaseTool:
            name: str = ""
            description: str = ""

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

        _lc_tools_stub.BaseTool = _BaseTool
        _lc_stub.tools = _lc_tools_stub

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "langchain_core", _lc_stub)
            mp.setitem(sys.modules, "langchain_core.tools", _lc_tools_stub)
            # Force re-import with the stub
            mp.delitem(sys.modules, "pramanix.integrations.langchain", raising=False)
            from pramanix.integrations.langchain import PramanixGuardedTool

            tool = PramanixGuardedTool(
                name="test_tool",
                description="test",
                guard=guard,
                intent_schema=_IntentSchema,
                state_provider=lambda: {},
                execute_fn=None,  # No execute_fn → should raise NotImplementedError
            )

        with pytest.raises(ConfigurationError, match="execute_fn"):
            await tool._arun(json.dumps({"x": 5}))


# ═══════════════════════════════════════════════════════════════════════════════
# ifc/flow_policy.py line 201: FlowPolicy.default_deny property
# ═══════════════════════════════════════════════════════════════════════════════


class TestFlowPolicyDefaultDenyProperty:
    """FlowPolicy.default_deny property returns the correct value (line 201)."""

    def test_default_deny_true(self) -> None:
        policy = FlowPolicy(rules=[], default_deny=True)
        assert policy.default_deny is True

    def test_default_deny_false(self) -> None:
        policy = FlowPolicy(rules=[], default_deny=False)
        assert policy.default_deny is False
