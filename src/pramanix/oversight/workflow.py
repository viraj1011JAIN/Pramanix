# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Human-in-the-loop oversight workflows for high-impact agentic actions.

Formal oversight ensures that actions with large blast radius, financial
consequences, or irreversible side-effects receive explicit human review
before execution.  The system provides:

* :class:`ApprovalRequest` — an evidence bundle describing the proposed
  action (decision, intent, policy_hash, blast_radius, scopes required).
* :class:`ApprovalDecision` — a reviewer's verdict (APPROVED / REJECTED /
  TIMEOUT) bound to the request by its ID.
* :class:`ApprovalWorkflow` — the pluggable workflow engine.
  :class:`InMemoryApprovalWorkflow` ships for testing and single-process
  deployments; production deployments should provide a persistent backend.
* :class:`EscalationQueue` — thread-safe queue of pending
  :class:`ApprovalRequest` objects for reviewer consumption.
* :class:`OversightRecord` — tamper-evident HMAC-signed record of every
  oversight decision for the audit trail.

Design constraints
------------------
* All oversight records are HMAC-signed with the deployment signing key
  (or an ephemeral key when none is configured) so tampering is detectable.
* A request that times out without a reviewer decision is treated as
  REJECTED — fail-safe.
* Workflows are pluggable: swap in a Slack-bot, PagerDuty, or JIRA backend
  by implementing :class:`ApprovalWorkflow`.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pramanix.exceptions import OversightRequiredError

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "EscalationQueue",
    "InMemoryApprovalWorkflow",
    "OversightRecord",
]

_log = logging.getLogger(__name__)

# ── Enumerations ──────────────────────────────────────────────────────────────


class ApprovalStatus(str, Enum):
    """Possible states of an :class:`ApprovalRequest`."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    REVOKED = "REVOKED"


# ── Core data types ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ApprovalRequest:
    """An evidence bundle requesting human approval for a high-impact action.

    Created by the :class:`InMemoryApprovalWorkflow` (or any workflow backend)
    and placed in the :class:`EscalationQueue`.  Reviewers read this object
    to understand the proposed action and decide whether to approve it.

    Attributes:
        request_id:     UUID of this request (for correlation with the audit).
        principal_id:   Identity of the agent requesting approval.
        action:         Human-readable description of the action.
        decision_id:    UUID of the :class:`~pramanix.decision.Decision` that
                        would be executed.
        policy_hash:    SHA-256 of the policy that produced the decision.
        intent_dump:    JSON-safe representation of the intent being verified.
        required_scopes: Scope names the action requires.
        blast_radius:   Operator-provided estimate of impact (e.g. ``"$50,000"``).
        reason:         Why oversight is required (e.g. ``"FINANCIAL scope"``).
        created_at:     Unix timestamp of request creation.
        ttl_seconds:    How long the request is valid before timing out.
        metadata:       Arbitrary key-value pairs for routing/display.
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    principal_id: str = ""
    action: str = ""
    decision_id: str = ""
    policy_hash: str = ""
    intent_dump: dict[str, Any] = field(default_factory=dict)
    required_scopes: list[str] = field(default_factory=list)
    blast_radius: str = "unknown"
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """True when the request has outlived its TTL."""
        return time.time() > self.created_at + self.ttl_seconds


@dataclass(frozen=True)
class ApprovalDecision:
    """A reviewer's verdict on an :class:`ApprovalRequest`.

    Attributes:
        request_id:   The request this decision answers.
        status:       ``APPROVED`` or ``REJECTED`` (or ``TIMEOUT``/``REVOKED``).
        reviewer_id:  Identity of the human reviewer.
        comment:      Free-text comment from the reviewer.
        decided_at:   Unix timestamp of the decision.
    """

    request_id: str
    status: ApprovalStatus
    reviewer_id: str = ""
    comment: str = ""
    decided_at: float = field(default_factory=time.time)


# ── Tamper-evident record ────────────────────────────────────────────────────


class OversightRecord:
    """Tamper-evident HMAC-SHA256 record of a single oversight decision.

    The record binds the :class:`ApprovalRequest` and the :class:`ApprovalDecision`
    together with an HMAC tag so that offline audit tools can verify that
    neither was altered after the fact.

    Args:
        request:   The original approval request.
        decision:  The reviewer's decision.
        signing_key: HMAC signing key bytes.  Defaults to a stable per-process
                     key derived from ``os.urandom(32)`` — supply a persistent
                     key in production (``PRAMANIX_SIGNING_KEY`` env var or
                     a :class:`~pramanix.key_provider.KeyProvider`).

    Example::

        record = OversightRecord(request, decision)
        assert record.verify()
    """

    def __init__(
        self,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        signing_key: bytes | None = None,
    ) -> None:
        self.request = request
        self.decision = decision
        self._key: bytes = signing_key or _process_key()
        self._tag: str = self._compute_tag()

    def verify(self) -> bool:
        """Return True when the record has not been tampered with."""
        expected = self._compute_tag()
        return hmac.compare_digest(self._tag, expected)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe audit representation."""
        return {
            "request_id": self.request.request_id,
            "principal_id": self.request.principal_id,
            "action": self.request.action,
            "decision_id": self.request.decision_id,
            "policy_hash": self.request.policy_hash,
            "required_scopes": self.request.required_scopes,
            "blast_radius": self.request.blast_radius,
            "reason": self.request.reason,
            "created_at": self.request.created_at,
            "status": self.decision.status.value,
            "reviewer_id": self.decision.reviewer_id,
            "comment": self.decision.comment,
            "decided_at": self.decision.decided_at,
            "hmac_tag": self._tag,
        }

    def _compute_tag(self) -> str:
        payload = (
            f"{self.request.request_id}|"
            f"{self.request.principal_id}|"
            f"{self.request.action}|"
            f"{self.request.decision_id}|"
            f"{self.request.policy_hash}|"
            f"{self.decision.status.value}|"
            f"{self.decision.reviewer_id}|"
            f"{self.decision.decided_at}"
        ).encode()
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()


# ── Escalation queue ─────────────────────────────────────────────────────────


class EscalationQueue:
    """Thread-safe queue of pending :class:`ApprovalRequest` objects.

    Reviewers consume requests from this queue to process approvals.
    The queue automatically expires requests that exceed their TTL.

    Example::

        q = EscalationQueue()
        q.enqueue(request)
        pending = q.pending()   # list of non-expired requests
        q.dequeue(request_id)   # remove after processing
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, ApprovalRequest] = {}

    def enqueue(self, request: ApprovalRequest) -> None:
        """Add *request* to the queue."""
        with self._lock:
            self._requests[request.request_id] = request
        _log.info(
            "oversight.escalated: request_id=%s action=%s principal=%s",
            request.request_id,
            request.action,
            request.principal_id,
        )

    def dequeue(self, request_id: str) -> ApprovalRequest | None:
        """Remove and return the request with *request_id*, or ``None``."""
        with self._lock:
            return self._requests.pop(request_id, None)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Return the request without removing it, or ``None``."""
        with self._lock:
            return self._requests.get(request_id)

    def pending(self) -> list[ApprovalRequest]:
        """Return all non-expired pending requests, sorted oldest-first."""
        with self._lock:
            return sorted(
                (r for r in self._requests.values() if not r.is_expired()),
                key=lambda r: r.created_at,
            )

    def expire_stale(self) -> list[str]:
        """Remove and return request IDs that have exceeded their TTL."""
        with self._lock:
            expired = [
                rid for rid, r in self._requests.items() if r.is_expired()
            ]
            for rid in expired:
                del self._requests[rid]
        return expired

    def size(self) -> int:
        """Number of requests currently in the queue (including expired)."""
        with self._lock:
            return len(self._requests)


# ── Approval workflow ─────────────────────────────────────────────────────────


class InMemoryApprovalWorkflow:
    """Synchronous in-memory approval workflow for single-process deployments.

    In production replace this with a persistent backend (database + notification
    system) by following the same public API:

    * :meth:`request_approval` — submit a request and receive its ID.
    * :meth:`approve` / :meth:`reject` — reviewer decisions.
    * :meth:`check` — poll whether a previous request was approved.
    * :meth:`records` — full audit trail of oversight records.

    Args:
        signing_key: HMAC key for :class:`OversightRecord` integrity.
                     Defaults to a per-process ephemeral key.
        auto_reject_after_s: TTL in seconds; requests not decided within this
                             window are auto-rejected by :meth:`check`.

    Example::

        workflow = InMemoryApprovalWorkflow()
        rid = workflow.request_approval(
            principal_id="agent-001",
            action="transfer $50,000 to external account",
            decision_id=str(decision.decision_id),
            policy_hash=guard.policy_hash or "",
            intent_dump={"amount": "50000"},
            required_scopes=["FINANCIAL"],
            blast_radius="$50,000",
            reason="FINANCIAL scope requires dual-control approval",
        )
        workflow.approve(rid, reviewer_id="alice@company.com", comment="Verified OK")
        assert workflow.check(rid)
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        *,
        auto_reject_after_s: float = 300.0,
    ) -> None:
        self._key = signing_key or _process_key()
        self._ttl = auto_reject_after_s
        self._queue = EscalationQueue()
        self._decisions: dict[str, ApprovalDecision] = {}
        self._records: list[OversightRecord] = []
        self._lock = threading.Lock()

    def request_approval(
        self,
        *,
        principal_id: str,
        action: str,
        decision_id: str = "",
        policy_hash: str = "",
        intent_dump: dict[str, Any] | None = None,
        required_scopes: list[str] | None = None,
        blast_radius: str = "unknown",
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Submit a new approval request; returns the request ID.

        Raises:
            OversightRequiredError: Always — callers should catch this exception,
                retrieve the ``request_id``, present the request to a reviewer,
                and retry after :meth:`approve` has been called.
        """
        req = ApprovalRequest(
            principal_id=principal_id,
            action=action,
            decision_id=decision_id,
            policy_hash=policy_hash,
            intent_dump=intent_dump or {},
            required_scopes=required_scopes or [],
            blast_radius=blast_radius,
            reason=reason,
            ttl_seconds=self._ttl,
            metadata=metadata or {},
        )
        self._queue.enqueue(req)
        raise OversightRequiredError(
            f"Action '{action}' requires human approval "
            f"(request_id={req.request_id}).",
            request_id=req.request_id,
            action=action,
            reason=reason,
        )

    def approve(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        comment: str = "",
    ) -> OversightRecord:
        """Record an approval decision and return the signed :class:`OversightRecord`.

        Raises:
            KeyError: If *request_id* does not exist or has already been decided.
            OversightRequiredError: If the request has expired (TTL exceeded).
        """
        return self._decide(
            request_id,
            ApprovalStatus.APPROVED,
            reviewer_id=reviewer_id,
            comment=comment,
        )

    def reject(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        comment: str = "",
    ) -> OversightRecord:
        """Record a rejection decision and return the signed record."""
        return self._decide(
            request_id,
            ApprovalStatus.REJECTED,
            reviewer_id=reviewer_id,
            comment=comment,
        )

    def check(self, request_id: str) -> bool:
        """Return True if *request_id* was APPROVED.

        Returns False for REJECTED, TIMEOUT, REVOKED, or unknown IDs.
        Auto-rejects expired requests on first check.
        """
        with self._lock:
            decision = self._decisions.get(request_id)
        if decision is not None:
            return decision.status == ApprovalStatus.APPROVED

        # Check for expiry.
        req = self._queue.get(request_id)
        if req is not None and req.is_expired():
            self._auto_reject(req)
            return False

        return False

    def pending(self) -> list[ApprovalRequest]:
        """Return all non-expired pending requests."""
        return self._queue.pending()

    def records(self) -> list[OversightRecord]:
        """Return the full ordered audit trail of oversight decisions."""
        with self._lock:
            return list(self._records)

    # ── Internal ──────────────────────────────────────────────────────────

    def _decide(
        self,
        request_id: str,
        status: ApprovalStatus,
        *,
        reviewer_id: str,
        comment: str,
    ) -> OversightRecord:
        req = self._queue.dequeue(request_id)
        if req is None:
            raise KeyError(f"ApprovalRequest '{request_id}' not found or already decided.")
        if req.is_expired():
            status = ApprovalStatus.TIMEOUT
            _log.warning(
                "oversight.timeout: request_id=%s principal=%s",
                request_id,
                req.principal_id,
            )
        dec = ApprovalDecision(
            request_id=request_id,
            status=status,
            reviewer_id=reviewer_id,
            comment=comment,
        )
        record = OversightRecord(req, dec, signing_key=self._key)
        with self._lock:
            self._decisions[request_id] = dec
            self._records.append(record)
        _log.info(
            "oversight.decided: request_id=%s status=%s reviewer=%s",
            request_id,
            status.value,
            reviewer_id,
        )
        return record

    def _auto_reject(self, req: ApprovalRequest) -> None:
        self._queue.dequeue(req.request_id)
        dec = ApprovalDecision(
            request_id=req.request_id,
            status=ApprovalStatus.TIMEOUT,
            reviewer_id="system:timeout",
            comment="Auto-rejected: TTL exceeded.",
        )
        record = OversightRecord(req, dec, signing_key=self._key)
        with self._lock:
            self._decisions[req.request_id] = dec
            self._records.append(record)


# ── Process-level key ─────────────────────────────────────────────────────────

_PROCESS_KEY: bytes | None = None
_KEY_LOCK = threading.Lock()


def _process_key() -> bytes:
    """Return the stable per-process HMAC key (generated once on first call)."""
    global _PROCESS_KEY
    if _PROCESS_KEY is None:
        with _KEY_LOCK:
            if _PROCESS_KEY is None:
                _PROCESS_KEY = os.urandom(32)
    return _PROCESS_KEY
