# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for human oversight workflows (pramanix.oversight).

All tests use real objects — no mocks, no monkeypatching of Pramanix internals.
"""
from __future__ import annotations

import time

import pytest

from pramanix.exceptions import OversightRequiredError
from pramanix.oversight import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    EscalationQueue,
    InMemoryApprovalWorkflow,
    OversightRecord,
)


# ── ApprovalRequest tests ─────────────────────────────────────────────────────


class TestApprovalRequest:
    def _make(self, ttl: float = 300.0) -> ApprovalRequest:
        return ApprovalRequest(
            principal_id="agent-001",
            action="transfer $50,000",
            decision_id="dec-abc123",
            policy_hash="sha256:cafebabe",
            reason="FINANCIAL scope",
            ttl_seconds=ttl,
        )

    def test_not_expired_fresh(self):
        req = self._make(ttl=300.0)
        assert not req.is_expired()

    def test_expired_zero_ttl(self):
        req = self._make(ttl=0.0)
        assert req.is_expired()

    def test_expired_past_ttl(self):
        req = ApprovalRequest(
            principal_id="a",
            action="b",
            created_at=time.time() - 400.0,
            ttl_seconds=300.0,
        )
        assert req.is_expired()

    def test_request_id_is_unique(self):
        r1 = self._make()
        r2 = self._make()
        assert r1.request_id != r2.request_id

    def test_frozen(self):
        req = self._make()
        with pytest.raises((AttributeError, TypeError)):
            req.action = "modified"  # type: ignore[misc]


# ── ApprovalDecision tests ────────────────────────────────────────────────────


class TestApprovalDecision:
    def test_fields(self):
        dec = ApprovalDecision(
            request_id="req-001",
            status=ApprovalStatus.APPROVED,
            reviewer_id="alice@co.com",
            comment="Verified OK",
        )
        assert dec.status == ApprovalStatus.APPROVED
        assert dec.reviewer_id == "alice@co.com"

    def test_decided_at_set(self):
        t0 = time.time()
        dec = ApprovalDecision(request_id="r", status=ApprovalStatus.REJECTED)
        assert dec.decided_at >= t0


# ── OversightRecord tests ─────────────────────────────────────────────────────


class TestOversightRecord:
    def _make(self, signing_key: bytes | None = None) -> OversightRecord:
        req = ApprovalRequest(principal_id="agent", action="delete bucket")
        dec = ApprovalDecision(
            request_id=req.request_id,
            status=ApprovalStatus.APPROVED,
            reviewer_id="bob@co.com",
        )
        return OversightRecord(req, dec, signing_key=signing_key)

    def test_verify_fresh(self):
        record = self._make()
        assert record.verify()

    def test_verify_with_explicit_key(self):
        key = b"a" * 32
        record = self._make(signing_key=key)
        assert record.verify()

    def test_to_dict_contains_required_keys(self):
        record = self._make()
        d = record.to_dict()
        for k in (
            "request_id",
            "action",
            "status",
            "reviewer_id",
            "hmac_tag",
        ):
            assert k in d

    def test_to_dict_status_is_string(self):
        record = self._make()
        d = record.to_dict()
        assert isinstance(d["status"], str)

    def test_tamper_detection_via_different_key(self):
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        record = self._make(signing_key=key1)
        # Retrieve tag computed with key1, then verify using key2
        # verify() re-computes with self._key (key1), so tag == tag → True.
        # To test tamper detection we make a second record with different key.
        record2 = self._make(signing_key=key2)
        tag1 = record.to_dict()["hmac_tag"]
        tag2 = record2.to_dict()["hmac_tag"]
        assert tag1 != tag2


# ── EscalationQueue tests ─────────────────────────────────────────────────────


class TestEscalationQueue:
    def _req(self, ttl: float = 300.0) -> ApprovalRequest:
        return ApprovalRequest(
            principal_id="agent",
            action="action",
            ttl_seconds=ttl,
        )

    def test_enqueue_and_size(self):
        q = EscalationQueue()
        req = self._req()
        q.enqueue(req)
        assert q.size() == 1

    def test_dequeue_removes(self):
        q = EscalationQueue()
        req = self._req()
        q.enqueue(req)
        retrieved = q.dequeue(req.request_id)
        assert retrieved is req
        assert q.size() == 0

    def test_dequeue_unknown_returns_none(self):
        q = EscalationQueue()
        assert q.dequeue("nonexistent") is None

    def test_get_non_destructive(self):
        q = EscalationQueue()
        req = self._req()
        q.enqueue(req)
        assert q.get(req.request_id) is req
        assert q.size() == 1  # still there

    def test_pending_excludes_expired(self):
        q = EscalationQueue()
        fresh = self._req(ttl=300.0)
        expired = ApprovalRequest(
            principal_id="a",
            action="b",
            created_at=time.time() - 400.0,
            ttl_seconds=300.0,
        )
        q.enqueue(fresh)
        q.enqueue(expired)
        pending = q.pending()
        ids = [r.request_id for r in pending]
        assert fresh.request_id in ids
        assert expired.request_id not in ids

    def test_pending_sorted_oldest_first(self):
        q = EscalationQueue()
        r1 = ApprovalRequest(
            principal_id="a", action="1",
            created_at=time.time() - 10,
        )
        r2 = ApprovalRequest(
            principal_id="a", action="2",
            created_at=time.time() - 5,
        )
        q.enqueue(r2)
        q.enqueue(r1)
        pending = q.pending()
        assert pending[0].request_id == r1.request_id
        assert pending[1].request_id == r2.request_id

    def test_expire_stale_returns_ids(self):
        q = EscalationQueue()
        expired = ApprovalRequest(
            principal_id="a",
            action="b",
            created_at=time.time() - 400.0,
            ttl_seconds=300.0,
        )
        q.enqueue(expired)
        stale_ids = q.expire_stale()
        assert expired.request_id in stale_ids
        assert q.size() == 0

    def test_expire_stale_leaves_fresh(self):
        q = EscalationQueue()
        fresh = self._req()
        q.enqueue(fresh)
        q.expire_stale()
        assert q.size() == 1


# ── InMemoryApprovalWorkflow tests ────────────────────────────────────────────


class TestInMemoryApprovalWorkflow:
    def _workflow(self, ttl: float = 300.0) -> InMemoryApprovalWorkflow:
        return InMemoryApprovalWorkflow(auto_reject_after_s=ttl)

    def test_request_approval_raises(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(
                principal_id="agent",
                action="delete all data",
                reason="DESTRUCTIVE scope",
            )
        err = exc_info.value
        assert err.request_id
        assert err.action == "delete all data"

    def test_approve_flow(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(
                principal_id="agent",
                action="transfer $10,000",
                reason="FINANCIAL",
            )
        rid = exc_info.value.request_id
        record = wf.approve(rid, reviewer_id="alice@co.com", comment="OK")
        assert record.decision.status == ApprovalStatus.APPROVED
        assert wf.check(rid) is True

    def test_reject_flow(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="agent", action="delete", reason="DESTRUCTIVE")
        rid = exc_info.value.request_id
        record = wf.reject(rid, reviewer_id="bob@co.com", comment="Not authorized")
        assert record.decision.status == ApprovalStatus.REJECTED
        assert wf.check(rid) is False

    def test_check_unknown_returns_false(self):
        wf = self._workflow()
        assert wf.check("nonexistent-id") is False

    def test_check_expired_auto_rejects(self):
        wf = InMemoryApprovalWorkflow(auto_reject_after_s=0.001)
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="c")
        rid = exc_info.value.request_id
        time.sleep(0.01)
        assert wf.check(rid) is False
        # Auto-rejected record should appear in audit trail
        records = wf.records()
        statuses = [r.decision.status for r in records]
        assert ApprovalStatus.TIMEOUT in statuses

    def test_decide_expired_request_becomes_timeout(self):
        wf = InMemoryApprovalWorkflow(auto_reject_after_s=0.001)
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="c")
        rid = exc_info.value.request_id
        time.sleep(0.01)
        record = wf.approve(rid, reviewer_id="reviewer")
        assert record.decision.status == ApprovalStatus.TIMEOUT

    def test_approve_unknown_raises_key_error(self):
        wf = self._workflow()
        with pytest.raises(KeyError):
            wf.approve("no-such-id", reviewer_id="reviewer")

    def test_reject_unknown_raises_key_error(self):
        wf = self._workflow()
        with pytest.raises(KeyError):
            wf.reject("no-such-id", reviewer_id="reviewer")

    def test_pending_lists_open_requests(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="r")
        rid = exc_info.value.request_id
        pending = wf.pending()
        assert any(r.request_id == rid for r in pending)

    def test_records_returns_audit_trail(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="r")
        rid = exc_info.value.request_id
        wf.approve(rid, reviewer_id="carol")
        records = wf.records()
        assert len(records) == 1
        assert records[0].verify()

    def test_oversight_record_verifies(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="r")
        rid = exc_info.value.request_id
        record = wf.approve(rid, reviewer_id="dave")
        assert record.verify()

    def test_oversight_record_to_dict_hmac_present(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="r")
        rid = exc_info.value.request_id
        record = wf.approve(rid, reviewer_id="eve")
        d = record.to_dict()
        assert "hmac_tag" in d
        assert d["hmac_tag"]

    def test_oversight_required_error_carries_request_id(self):
        wf = self._workflow()
        with pytest.raises(OversightRequiredError) as exc_info:
            wf.request_approval(principal_id="a", action="b", reason="r")
        assert exc_info.value.request_id
        assert exc_info.value.action == "b"
