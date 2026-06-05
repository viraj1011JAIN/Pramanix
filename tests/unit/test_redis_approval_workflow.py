# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Unit tests for RedisApprovalWorkflow.

Uses fakeredis (synchronous) so tests run without a real Redis server.
Covers all five protocol methods and the persistence guarantee.

Addresses audit finding #29: no persistent ApprovalWorkflow existed;
SOC2 CC6.3 dual-control authorization could not be satisfied.
"""

from __future__ import annotations

import pytest
import fakeredis

from pramanix.exceptions import OversightRequiredError
from pramanix.oversight.workflow import ApprovalStatus, RedisApprovalWorkflow


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def workflow() -> RedisApprovalWorkflow:
    redis = fakeredis.FakeRedis()
    return RedisApprovalWorkflow(
        redis_client=redis,
        signing_key=b"test-signing-key-32-bytes-exactly",
        default_ttl_s=300.0,
        key_prefix="pramanix:test",
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_request_approval_raises_oversight_required_error(
    workflow: RedisApprovalWorkflow,
) -> None:
    """request_approval() always raises OversightRequiredError with request_id."""
    with pytest.raises(OversightRequiredError) as exc_info:
        workflow.request_approval(
            principal_id="agent-001",
            action="transfer $50,000",
            decision_id="dec-abc",
            policy_hash="sha256:abc",
            intent_dump={"amount": "50000"},
            required_scopes=["FINANCIAL"],
            blast_radius="$50,000",
            reason="FINANCIAL scope requires dual-control approval",
        )
    err = exc_info.value
    assert err.request_id
    assert "agent-001" not in err.request_id  # request_id is a UUID, not the principal
    assert err.action == "transfer $50,000"


def test_check_returns_false_before_decision(workflow: RedisApprovalWorkflow) -> None:
    """check() returns False for a request that hasn't been decided yet."""
    try:
        workflow.request_approval(
            principal_id="agent-001",
            action="action-A",
            decision_id="",
            policy_hash="",
            intent_dump=None,
            required_scopes=None,
            blast_radius="low",
            reason="test",
        )
    except OversightRequiredError as exc:
        request_id = exc.request_id

    assert workflow.check(request_id) is False


def test_approve_makes_check_return_true(workflow: RedisApprovalWorkflow) -> None:
    """After approve(), check() returns True."""
    try:
        workflow.request_approval(
            principal_id="agent-001",
            action="deploy to prod",
            decision_id="dec-1",
            policy_hash="",
            intent_dump={"env": "production"},
            required_scopes=["DEPLOY"],
            blast_radius="full fleet",
            reason="deployment gate",
        )
    except OversightRequiredError as exc:
        request_id = exc.request_id

    record = workflow.approve(request_id, reviewer_id="alice@corp.com", comment="Looks good")

    assert record.decision.status == ApprovalStatus.APPROVED
    assert workflow.check(request_id) is True


def test_reject_makes_check_return_false(workflow: RedisApprovalWorkflow) -> None:
    """After reject(), check() returns False."""
    try:
        workflow.request_approval(
            principal_id="agent-002",
            action="delete database",
            decision_id="dec-2",
            policy_hash="",
            intent_dump={"table": "users"},
            required_scopes=["ADMIN"],
            blast_radius="entire DB",
            reason="DR test",
        )
    except OversightRequiredError as exc:
        request_id = exc.request_id

    record = workflow.reject(request_id, reviewer_id="bob@corp.com", comment="Denied")

    assert record.decision.status == ApprovalStatus.REJECTED
    assert workflow.check(request_id) is False


def test_records_returns_all_decided_records(workflow: RedisApprovalWorkflow) -> None:
    """records() returns all decided OversightRecords."""
    ids = []
    for i in range(3):
        try:
            workflow.request_approval(
                principal_id=f"agent-{i}",
                action=f"action-{i}",
                decision_id="",
                policy_hash="",
                intent_dump=None,
                required_scopes=None,
                blast_radius="low",
                reason="test",
            )
        except OversightRequiredError as exc:
            ids.append(exc.request_id)

    workflow.approve(ids[0], reviewer_id="alice", comment="")
    workflow.reject(ids[1], reviewer_id="bob", comment="")
    workflow.approve(ids[2], reviewer_id="carol", comment="")

    records = workflow.records()
    assert len(records) == 3
    statuses = {r.decision.status for r in records}
    assert ApprovalStatus.APPROVED in statuses
    assert ApprovalStatus.REJECTED in statuses


def test_pending_returns_undecided_requests(workflow: RedisApprovalWorkflow) -> None:
    """pending() returns all requests not yet decided."""
    pending_ids = []
    for i in range(2):
        try:
            workflow.request_approval(
                principal_id=f"agent-{i}",
                action=f"pending-action-{i}",
                decision_id="",
                policy_hash="",
                intent_dump=None,
                required_scopes=None,
                blast_radius="low",
                reason="pending test",
            )
        except OversightRequiredError as exc:
            pending_ids.append(exc.request_id)

    # Decide only the first one.
    workflow.approve(pending_ids[0], reviewer_id="alice", comment="")

    pending = workflow.pending()
    pending_req_ids = {r.request_id for r in pending}
    assert pending_ids[1] in pending_req_ids
    assert pending_ids[0] not in pending_req_ids


def test_double_decide_raises_key_error(workflow: RedisApprovalWorkflow) -> None:
    """Deciding the same request twice raises KeyError."""
    try:
        workflow.request_approval(
            principal_id="agent-001",
            action="one-shot action",
            decision_id="",
            policy_hash="",
            intent_dump=None,
            required_scopes=None,
            blast_radius="low",
            reason="double decide test",
        )
    except OversightRequiredError as exc:
        request_id = exc.request_id

    workflow.approve(request_id, reviewer_id="alice", comment="First decision")

    with pytest.raises(KeyError):
        workflow.approve(request_id, reviewer_id="alice", comment="Second decision")


def test_unknown_request_id_raises_key_error(workflow: RedisApprovalWorkflow) -> None:
    """Deciding an unknown request_id raises KeyError."""
    with pytest.raises(KeyError):
        workflow.approve("nonexistent-id", reviewer_id="alice", comment="")


def test_oversight_record_integrity_survives_serialization(
    workflow: RedisApprovalWorkflow,
) -> None:
    """OversightRecord stored in Redis verifies correctly on retrieval."""
    try:
        workflow.request_approval(
            principal_id="agent-integrity",
            action="integrity test",
            decision_id="dec-integrity",
            policy_hash="sha256:test",
            intent_dump={"amount": "100"},
            required_scopes=["TEST"],
            blast_radius="minimal",
            reason="integrity check",
        )
    except OversightRequiredError as exc:
        request_id = exc.request_id

    workflow.approve(request_id, reviewer_id="alice", comment="Verified")

    records = workflow.records()
    assert len(records) == 1
    record = records[0]
    assert record.verify(), "OversightRecord must verify after Redis round-trip"
    assert record.request.principal_id == "agent-integrity"
    assert record.decision.reviewer_id == "alice"


def test_check_unknown_id_returns_false(workflow: RedisApprovalWorkflow) -> None:
    """check() returns False for a completely unknown request_id."""
    assert workflow.check("does-not-exist") is False


def test_satisfies_approval_workflow_protocol(workflow: RedisApprovalWorkflow) -> None:
    """RedisApprovalWorkflow satisfies the ApprovalWorkflow Protocol."""
    from pramanix.oversight.workflow import ApprovalWorkflow

    assert isinstance(workflow, ApprovalWorkflow)
