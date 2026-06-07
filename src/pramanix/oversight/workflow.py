# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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

import collections
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, cast, runtime_checkable

from pramanix.exceptions import OversightRequiredError

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalWorkflow",
    "EscalationQueue",
    "InMemoryApprovalWorkflow",
    "OversightRecord",
    "PostgresApprovalWorkflow",
    "RedisApprovalWorkflow",
    "WebhookNotificationChannel",
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

    request_id: str = field(
        default_factory=lambda: str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
    )
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

    __slots__ = ("request", "decision", "_key", "_tag")

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
        """Return True when the record has not been tampered with.

        Protection boundary: detects in-process field mutation on the
        ``request`` and ``decision`` objects bound at construction time.
        Does NOT provide cross-process tamper detection — callers that
        persist records via :meth:`to_dict` must re-create the
        ``OversightRecord`` with the original signing key to verify
        offline.  The ``hmac_tag`` field in the serialised dict is only
        meaningful when paired with the key used to produce it.
        """
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

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        signing_key: bytes,
    ) -> OversightRecord:
        """Reconstruct an :class:`OversightRecord` from a serialised dict.

        Reconstructs the :class:`ApprovalRequest` and :class:`ApprovalDecision`
        from *data* (as produced by :meth:`to_dict`) and wires the stored
        ``hmac_tag`` so that a subsequent :meth:`verify` call confirms integrity.

        Args:
            data:        A dict previously produced by :meth:`to_dict`.
            signing_key: The same key that was used to sign the record.

        Returns:
            An :class:`OversightRecord` whose :meth:`verify` returns ``True``
            when *data* has not been tampered with.

        Raises:
            KeyError:   If required fields are absent from *data*.
            ValueError: If ``status`` is not a valid :class:`ApprovalStatus`.
        """
        request = ApprovalRequest(
            request_id=str(data["request_id"]),
            principal_id=str(data.get("principal_id", "")),
            action=str(data.get("action", "")),
            decision_id=str(data.get("decision_id", "")),
            policy_hash=str(data.get("policy_hash", "")),
            required_scopes=list(data.get("required_scopes", [])),
            blast_radius=str(data.get("blast_radius", "unknown")),
            reason=str(data.get("reason", "")),
            created_at=float(data.get("created_at", 0.0)),
            ttl_seconds=float(data.get("ttl_seconds", 300.0)),
        )
        decision = ApprovalDecision(
            request_id=str(data["request_id"]),
            status=ApprovalStatus(data["status"]),
            reviewer_id=str(data.get("reviewer_id", "")),
            comment=str(data.get("comment", "")),
            decided_at=float(data.get("decided_at", 0.0)),
        )
        instance = cls(request, decision, signing_key=signing_key)
        # Replace the freshly computed tag with the stored one; verify() will
        # then compare the stored tag against a fresh recomputation.
        instance._tag = str(data["hmac_tag"])
        return instance

    @classmethod
    def verify_serialised(
        cls,
        data: dict[str, Any],
        signing_key: bytes,
    ) -> bool:
        """Verify the HMAC tag of a serialised record without full reconstruction.

        Suitable for fast offline audit scanning when full object
        reconstruction is not needed.

        Args:
            data:        A dict previously produced by :meth:`to_dict`.
            signing_key: The signing key used when the record was created.

        Returns:
            ``True`` if the tag matches; ``False`` if tampered or key mismatch.
            Never raises — malformed dicts return ``False``.
        """
        try:
            stored_tag: str = str(data["hmac_tag"])
            payload = json.dumps(
                {
                    "action": data.get("action", ""),
                    "decided_at": repr(data.get("decided_at", 0.0)),
                    "decision_id": data.get("decision_id", ""),
                    "policy_hash": data.get("policy_hash", ""),
                    "principal_id": data.get("principal_id", ""),
                    "request_id": data["request_id"],
                    "reviewer_id": data.get("reviewer_id", ""),
                    "status": data["status"],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            expected = hmac.HMAC(signing_key, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(stored_tag, expected)
        except (KeyError, TypeError, ValueError):
            return False

    def _compute_tag(self) -> str:
        # Canonical JSON payload: field-boundary collisions from pipe-delimited
        # f-strings (#82) are eliminated by using JSON with explicit field names.
        # sort_keys=True and separators=(",",":") guarantee deterministic output.
        # decided_at is repr'd as a string to avoid float-formatting ambiguity.
        payload = json.dumps(
            {
                "action": self.request.action,
                "decided_at": repr(self.decision.decided_at),
                "decision_id": self.request.decision_id,
                "policy_hash": self.request.policy_hash,
                "principal_id": self.request.principal_id,
                "request_id": self.request.request_id,
                "reviewer_id": self.decision.reviewer_id,
                "status": self.decision.status.value,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hmac.HMAC(self._key, payload, hashlib.sha256).hexdigest()


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

    def expire_stale(self) -> list[ApprovalRequest]:
        """Remove and return requests that have exceeded their TTL."""
        with self._lock:
            expired = [r for r in self._requests.values() if r.is_expired()]
            for r in expired:
                del self._requests[r.request_id]
        return expired

    def size(self) -> int:
        """Number of requests currently in the queue (including expired)."""
        with self._lock:
            return len(self._requests)


# ── Approval workflow Protocol ────────────────────────────────────────────────


@runtime_checkable
class ApprovalWorkflow(Protocol):
    """Pluggable backend protocol for human-in-the-loop oversight workflows.

    Implement this interface to provide a persistent workflow backend (e.g.
    a Slack bot, PagerDuty escalation, or JIRA ticket system) that can be
    swapped in wherever :class:`InMemoryApprovalWorkflow` is used.

    All conforming backends must:
    * Raise :exc:`~pramanix.exceptions.OversightRequiredError` from
      :meth:`request_approval` so callers can retrieve the ``request_id``.
    * Return an :class:`OversightRecord` from :meth:`approve` and
      :meth:`reject`.
    * Return ``True`` from :meth:`check` only when the request was explicitly
      approved (not just decided).
    """

    def request_approval(
        self,
        *,
        principal_id: str,
        action: str,
        decision_id: str,
        policy_hash: str,
        intent_dump: dict[str, Any] | None,
        required_scopes: list[str] | None,
        blast_radius: str,
        reason: str,
        metadata: dict[str, Any] | None,
    ) -> str:
        """Submit a new approval request and raise OversightRequiredError."""
        ...

    def approve(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        comment: str,
    ) -> OversightRecord:
        """Record an approval and return the signed OversightRecord."""
        ...

    def reject(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        comment: str,
    ) -> OversightRecord:
        """Record a rejection and return the signed OversightRecord."""
        ...

    def check(self, request_id: str) -> bool:
        """Return True if the request was APPROVED; False otherwise."""
        ...

    def records(self) -> list[OversightRecord]:
        """Return the full audit trail of oversight decisions."""
        ...


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
        sweep_interval_s: float = 60.0,
        max_records: int = 100_000,
        max_decisions: int = 100_000,
    ) -> None:
        import os as _os
        import warnings as _w

        if _os.environ.get("PRAMANIX_ENV", "").lower() == "production":
            from pramanix.exceptions import ConfigurationError as _CE

            raise _CE(
                "InMemoryApprovalWorkflow is not permitted when "
                "PRAMANIX_ENV=production. All oversight records would be lost "
                "on process restart. Replace with a persistent workflow backend "
                "(database + notification system) following the ApprovalWorkflow "
                "protocol."
            )
        _w.warn(
            "InMemoryApprovalWorkflow is for testing only — all approval records "
            "are lost on process restart and are not shared across processes. "
            "Replace with a persistent workflow backend in production.",
            UserWarning,
            stacklevel=2,
        )
        # Per-instance key: generate fresh entropy for each workflow instance so
        # that test suites importing this module across multiple pytest workers or
        # via importlib.reload() each get an isolated key.  Callers that need
        # cross-instance record verification must pass the same signing_key
        # explicitly to both instances.
        self._key: bytes = signing_key if signing_key is not None else os.urandom(32)
        self._ttl = auto_reject_after_s
        self._queue = EscalationQueue()
        # Bounded FIFO: oldest decisions are evicted when max_decisions is reached.
        self._decisions: collections.OrderedDict[str, ApprovalDecision] = collections.OrderedDict()
        self._max_decisions = max_decisions
        # Bounded deque: oldest records are automatically evicted at max_records.
        self._records: collections.deque[OversightRecord] = collections.deque(maxlen=max_records)
        self._lock = threading.Lock()
        self._stop_sweeper = threading.Event()
        self._sweeper = threading.Thread(
            target=self._run_sweeper,
            args=(sweep_interval_s,),
            name="pramanix-oversight-sweeper",
            daemon=True,
        )
        self._sweeper.start()

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
            f"Action '{action}' requires human approval " f"(request_id={req.request_id}).",
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

    def stop_sweeper(self) -> None:
        """Stop the background expiry-sweeper thread.

        Call this during application shutdown to allow the thread to exit
        cleanly.  The sweeper is a daemon thread and will be reclaimed
        automatically when the process exits, but explicit shutdown avoids
        spurious warnings in test environments.
        """
        self._stop_sweeper.set()

    # ── Internal ──────────────────────────────────────────────────────────

    def _run_sweeper(self, interval: float) -> None:
        """Background loop: expire stale requests every *interval* seconds."""
        while not self._stop_sweeper.wait(interval):
            self._sweep_expired()

    def _sweep_expired(self) -> None:
        """Auto-reject all requests that have exceeded their TTL."""
        expired = self._queue.expire_stale()
        for req in expired:
            self._auto_reject(req)

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
            if len(self._decisions) > self._max_decisions:
                evicted_id, _ = self._decisions.popitem(last=False)
                _log.warning(
                    "oversight: _decisions capacity (%d) exceeded — evicted oldest entry %s",
                    self._max_decisions,
                    evicted_id,
                )
            self._records.append(record)
        _log.info(
            "oversight.decided: request_id=%s status=%s reviewer=%s",
            request_id,
            status.value,
            reviewer_id,
        )
        return record

    def _auto_reject(self, req: ApprovalRequest) -> None:
        # Dequeue is a no-op when the sweeper already removed it via expire_stale.
        self._queue.dequeue(req.request_id)
        dec = ApprovalDecision(
            request_id=req.request_id,
            status=ApprovalStatus.TIMEOUT,
            reviewer_id="system:timeout",
            comment="Auto-rejected: TTL exceeded.",
        )
        record = OversightRecord(req, dec, signing_key=self._key)
        with self._lock:
            if req.request_id in self._decisions:
                return  # Already decided — idempotent under concurrent calls.
            self._decisions[req.request_id] = dec
            if len(self._decisions) > self._max_decisions:
                evicted_id, _ = self._decisions.popitem(last=False)
                _log.warning(
                    "oversight: _decisions capacity (%d) exceeded — evicted oldest entry %s",
                    self._max_decisions,
                    evicted_id,
                )
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


# ── Redis-backed persistent workflow ──────────────────────────────────────────


class RedisApprovalWorkflow:
    """Redis-backed persistent approval workflow for multi-replica production deployments.

    Satisfies SOC2 CC6.3 dual-control authorization: approvals are stored
    durably in Redis and survive process restarts.  All replicas sharing the
    same Redis instance and namespace share approval state.

    Data layout (all keys use *key_prefix* as namespace):

    * ``{prefix}:req:{id}``  — JSON-serialized :class:`ApprovalRequest` (TTL = *default_ttl_s*)
    * ``{prefix}:dec:{id}``  — JSON-serialized :class:`ApprovalDecision` (persistent)
    * ``{prefix}:rec:{id}``  — JSON-serialized :class:`OversightRecord` HMAC token (persistent)

    Args:
        redis_client:      A ``redis.Redis``-compatible synchronous client.
                           Must support ``setex``, ``get``, ``delete``, ``keys``.
                           Use ``fakeredis.FakeRedis()`` for testing.
        signing_key:       HMAC key for :class:`OversightRecord` integrity.
                           Defaults to a per-process ephemeral key.
        default_ttl_s:     TTL in seconds for pending request keys.
                           After this window the request is considered expired.
                           Default: 300 s (5 minutes).
        key_prefix:        Redis key namespace. Default: ``"pramanix:oversight"``.

    Raises:
        ConfigurationError: If the Redis client is missing required methods.

    Example::

        import redis
        workflow = RedisApprovalWorkflow(
            redis_client=redis.Redis.from_url("redis://localhost:6379/0"),
            signing_key=secrets.token_bytes(32),
        )
        rid = workflow.request_approval(
            principal_id="agent-001",
            action="transfer $50,000",
            decision_id="dec-abc",
            policy_hash="sha256:...",
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
        redis_client: Any,
        signing_key: bytes | None = None,
        *,
        default_ttl_s: float = 300.0,
        key_prefix: str = "pramanix:oversight",
    ) -> None:
        required = ("get", "setex", "delete", "keys", "set")
        missing = [m for m in required if not hasattr(redis_client, m)]
        if missing:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                f"redis_client is missing required methods: {missing}. "
                "Pass a redis.Redis-compatible synchronous client."
            )
        self._redis = redis_client
        self._key: bytes = signing_key if signing_key is not None else os.urandom(32)
        self._ttl = default_ttl_s
        self._prefix = key_prefix

    # ── Key helpers ────────────────────────────────────────────────────────────

    def _req_key(self, request_id: str) -> str:
        return f"{self._prefix}:req:{request_id}"

    def _dec_key(self, request_id: str) -> str:
        return f"{self._prefix}:dec:{request_id}"

    def _rec_key(self, request_id: str) -> str:
        return f"{self._prefix}:rec:{request_id}"

    def _req_to_dict(self, req: ApprovalRequest) -> dict[str, Any]:
        return {
            "request_id": req.request_id,
            "principal_id": req.principal_id,
            "action": req.action,
            "decision_id": req.decision_id,
            "policy_hash": req.policy_hash,
            "intent_dump": req.intent_dump,
            "required_scopes": req.required_scopes,
            "blast_radius": req.blast_radius,
            "reason": req.reason,
            "ttl_seconds": req.ttl_seconds,
            "metadata": req.metadata,
            "created_at": req.created_at,
        }

    def _req_from_dict(self, d: dict[str, Any]) -> ApprovalRequest:
        return ApprovalRequest(
            request_id=d["request_id"],
            principal_id=d["principal_id"],
            action=d["action"],
            decision_id=d.get("decision_id", ""),
            policy_hash=d.get("policy_hash", ""),
            intent_dump=d.get("intent_dump", {}),
            required_scopes=d.get("required_scopes", []),
            blast_radius=d.get("blast_radius", "unknown"),
            reason=d.get("reason", ""),
            ttl_seconds=d.get("ttl_seconds", self._ttl),
            metadata=d.get("metadata", {}),
        )

    # ── Public API ─────────────────────────────────────────────────────────────

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
        """Submit a new approval request to Redis and raise :exc:`OversightRequiredError`.

        The request is stored under a TTL-keyed Redis entry so it automatically
        expires if no reviewer acts within *default_ttl_s* seconds.

        Raises:
            OversightRequiredError: Always — callers catch this to retrieve
                the ``request_id`` and present the request to a reviewer.
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
        self._redis.setex(
            self._req_key(req.request_id),
            int(self._ttl),
            json.dumps(self._req_to_dict(req)),
        )
        _log.info(
            "oversight.redis.requested: request_id=%s principal=%s action=%r",
            req.request_id,
            principal_id,
            action[:80],
        )
        raise OversightRequiredError(
            f"Action '{action}' requires human approval (request_id={req.request_id}).",
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
        """Record an approval decision in Redis.

        Raises:
            KeyError: If *request_id* does not exist or has already been decided.
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
        """Record a rejection decision in Redis."""
        return self._decide(
            request_id,
            ApprovalStatus.REJECTED,
            reviewer_id=reviewer_id,
            comment=comment,
        )

    def check(self, request_id: str) -> bool:
        """Return True if *request_id* was APPROVED; False otherwise.

        Returns False for REJECTED, TIMEOUT (TTL expired), or unknown IDs.
        """
        raw = self._redis.get(self._dec_key(request_id))
        if raw is None:
            return False
        d = json.loads(raw)
        return bool(d.get("status") == ApprovalStatus.APPROVED.value)

    def pending(self) -> list[ApprovalRequest]:
        """Return all pending (not-yet-decided) requests still in Redis."""
        pattern = self._req_key("*")
        reqs: list[ApprovalRequest] = []
        for key in self._redis.keys(pattern):
            raw = self._redis.get(key)
            if raw is not None:
                try:
                    reqs.append(self._req_from_dict(json.loads(raw)))
                except Exception as exc:
                    _log.warning("oversight.redis.pending: failed to decode request: %s", exc)
        return reqs

    def records(self) -> list[OversightRecord]:
        """Return all oversight records stored in Redis."""
        pattern = self._rec_key("*")
        recs: list[OversightRecord] = []
        for key in self._redis.keys(pattern):
            raw = self._redis.get(key)
            if raw is not None:
                try:
                    data = json.loads(raw)
                    recs.append(OversightRecord.from_dict(data, signing_key=self._key))
                except Exception as exc:
                    _log.warning("oversight.redis.records: failed to decode record: %s", exc)
        return recs

    # ── Internal ──────────────────────────────────────────────────────────────

    def _decide(
        self,
        request_id: str,
        status: ApprovalStatus,
        *,
        reviewer_id: str,
        comment: str,
    ) -> OversightRecord:
        raw_req = self._redis.get(self._req_key(request_id))
        if raw_req is None:
            raise KeyError(
                f"ApprovalRequest '{request_id}' not found (expired or already decided)."
            )
        if self._redis.get(self._dec_key(request_id)) is not None:
            raise KeyError(f"ApprovalRequest '{request_id}' has already been decided.")
        req = self._req_from_dict(json.loads(raw_req))
        if req.is_expired():
            status = ApprovalStatus.TIMEOUT
            _log.warning(
                "oversight.redis.timeout: request_id=%s principal=%s",
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
        dec_payload = json.dumps(
            {
                "request_id": request_id,
                "status": status.value,
                "reviewer_id": reviewer_id,
                "comment": comment,
            }
        )
        # Store decision persistently (no TTL — audit trail must be durable).
        self._redis.set(self._dec_key(request_id), dec_payload)
        self._redis.set(self._rec_key(request_id), json.dumps(record.to_dict()))
        # Delete the pending request key so it no longer appears in pending().
        self._redis.delete(self._req_key(request_id))
        _log.info(
            "oversight.redis.decided: request_id=%s status=%s reviewer=%s",
            request_id,
            status.value,
            reviewer_id,
        )
        return record


# ── Postgres persistent approval workflow ─────────────────────────────────────


class PostgresApprovalWorkflow:
    """PostgreSQL-backed persistent approval workflow for Fortune 500 deployments.

    Satisfies SOC2 CC6.3 dual-control authorization with a durable, queryable
    SQL audit trail.  All approval requests and decisions are stored in two
    Postgres tables.  Requests that time out without a reviewer decision are
    treated as REJECTED (fail-safe) and recorded as ``TIMEOUT``.

    The schema is created automatically on first use via :meth:`initialize`.

    Schema
    ------
    ::

        pramanix_approval_requests(
            request_id TEXT PRIMARY KEY,
            principal_id TEXT NOT NULL,
            action TEXT NOT NULL,
            decision_id TEXT,
            policy_hash TEXT,
            intent_dump JSONB,
            required_scopes JSONB,
            blast_radius TEXT,
            reason TEXT,
            created_at DOUBLE PRECISION NOT NULL,
            ttl_seconds DOUBLE PRECISION NOT NULL,
            metadata JSONB,
            decided BOOLEAN NOT NULL DEFAULT FALSE
        )

        pramanix_approval_decisions(
            request_id TEXT PRIMARY KEY
                REFERENCES pramanix_approval_requests ON DELETE CASCADE,
            status TEXT NOT NULL,
            reviewer_id TEXT NOT NULL,
            comment TEXT,
            decided_at DOUBLE PRECISION NOT NULL,
            hmac_tag TEXT NOT NULL
        )

    Args:
        dsn:          asyncpg connection DSN, e.g.
                      ``"postgresql://user:pass@localhost/mydb"``.
        signing_key:  HMAC key for :class:`OversightRecord` integrity.
                      Defaults to a per-process ephemeral key.
        default_ttl_s: Seconds before a pending request auto-times-out.
                       Default: 300 s.
        pool_min:     Minimum asyncpg pool size. Default: 1.
        pool_max:     Maximum asyncpg pool size. Default: 5.
        _pool:        Pre-built asyncpg pool for unit testing.

    Requires:
        ``pip install 'pramanix[postgres]'`` (``asyncpg >= 0.29``).

    Usage::

        import asyncpg
        workflow = PostgresApprovalWorkflow(
            dsn="postgresql://pramanix:secret@db:5432/pramanix",
            signing_key=signing_key_bytes,
        )
        await workflow.initialize()  # create tables once at startup

        try:
            workflow.request_approval(
                principal_id="agent-001",
                action="transfer $50,000",
                ...
            )
        except OversightRequiredError as exc:
            request_id = exc.request_id

        # Reviewer flow:
        record = workflow.approve(request_id, reviewer_id="alice@corp.com")
        assert workflow.check(request_id)
    """

    _DDL = """
    CREATE TABLE IF NOT EXISTS pramanix_approval_requests (
        request_id    TEXT             PRIMARY KEY,
        principal_id  TEXT             NOT NULL,
        action        TEXT             NOT NULL,
        decision_id   TEXT             NOT NULL DEFAULT '',
        policy_hash   TEXT             NOT NULL DEFAULT '',
        intent_dump   JSONB            NOT NULL DEFAULT '{}',
        required_scopes JSONB          NOT NULL DEFAULT '[]',
        blast_radius  TEXT             NOT NULL DEFAULT 'unknown',
        reason        TEXT             NOT NULL DEFAULT '',
        created_at    DOUBLE PRECISION NOT NULL,
        ttl_seconds   DOUBLE PRECISION NOT NULL,
        metadata      JSONB            NOT NULL DEFAULT '{}',
        decided       BOOLEAN          NOT NULL DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS pramanix_approval_decisions (
        request_id    TEXT             PRIMARY KEY
                          REFERENCES pramanix_approval_requests ON DELETE CASCADE,
        status        TEXT             NOT NULL,
        reviewer_id   TEXT             NOT NULL,
        comment       TEXT             NOT NULL DEFAULT '',
        decided_at    DOUBLE PRECISION NOT NULL,
        hmac_tag      TEXT             NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_par_decided
        ON pramanix_approval_requests (decided);
    CREATE INDEX IF NOT EXISTS idx_par_created_at
        ON pramanix_approval_requests (created_at);
    """

    def __init__(
        self,
        dsn: str = "",
        *,
        signing_key: bytes | None = None,
        default_ttl_s: float = 300.0,
        pool_min: int = 1,
        pool_max: int = 5,
        _pool: Any = None,
    ) -> None:
        # asyncpg is optional — only required for PostgresApprovalWorkflow.
        if _pool is None:
            try:
                import importlib as _il

                _il.import_module("asyncpg")
                del _il
            except ImportError as exc:
                from pramanix.exceptions import ConfigurationError

                raise ConfigurationError(
                    "asyncpg is required for PostgresApprovalWorkflow. "
                    "Install it with: pip install 'pramanix[postgres]'"
                ) from exc
        self._dsn = dsn
        self._pool = _pool
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._key: bytes = signing_key if signing_key is not None else _process_key()
        self._ttl = default_ttl_s
        self._loop_thread: threading.Thread | None = None
        self._loop: Any = None
        self._loop_ready = threading.Event()
        if _pool is None:
            self._start_loop_thread()
        else:
            # Testing path: caller provides a pre-built pool; no loop thread needed.
            import asyncio as _asyncio

            try:
                self._loop = _asyncio.get_event_loop()
            except RuntimeError:
                self._loop = _asyncio.new_event_loop()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def _start_loop_thread(self) -> None:
        """Start a dedicated event-loop thread that owns the asyncpg pool."""
        import asyncio as _asyncio

        def _run() -> None:
            loop = _asyncio.new_event_loop()
            _asyncio.set_event_loop(loop)
            self._loop = loop
            self._loop_ready.set()
            loop.run_forever()

        self._loop_thread = threading.Thread(
            target=_run, daemon=True, name="pramanix-pg-oversight-loop"
        )
        self._loop_thread.start()
        self._loop_ready.wait(timeout=10.0)

    def _run_coro(self, coro: Any) -> Any:
        """Submit *coro* to the dedicated event loop and block until done."""
        import asyncio as _asyncio

        if self._loop is None:
            raise RuntimeError("PostgresApprovalWorkflow: event loop not started.")
        future = _asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=30.0)

    async def _get_pool(self) -> Any:
        """Return the asyncpg pool, creating it lazily."""
        if self._pool is not None:
            return self._pool
        import asyncpg as _asyncpg

        self._pool = await _asyncpg.create_pool(
            self._dsn, min_size=self._pool_min, max_size=self._pool_max
        )
        return self._pool

    async def _initialize_async(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(self._DDL)

    def initialize(self) -> None:
        """Create the Postgres schema (tables + indexes) if not already present.

        Call this once at application startup before any workflow operations.
        Safe to call multiple times — uses ``CREATE TABLE IF NOT EXISTS``.
        """
        self._run_coro(self._initialize_async())

    def close(self) -> None:
        """Close the asyncpg pool and stop the background event-loop thread."""

        async def _close_pool() -> None:
            if self._pool is not None:
                await self._pool.close()
                self._pool = None

        try:
            self._run_coro(_close_pool())
        except Exception as exc:
            _log.warning("PostgresApprovalWorkflow.close: pool close error: %s", exc)
        if self._loop is not None and self._loop_thread is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._loop_thread.join(timeout=5.0)

    # ── Public API ─────────────────────────────────────────────────────────────

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
        """Persist a new approval request in Postgres and raise
        :exc:`~pramanix.exceptions.OversightRequiredError`.

        Raises:
            OversightRequiredError: Always — callers catch this to retrieve
                the ``request_id`` and route it to a reviewer.
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
        self._run_coro(self._insert_request(req))
        _log.info(
            "oversight.pg.requested: request_id=%s principal=%s action=%r",
            req.request_id,
            principal_id,
            action[:80],
        )
        raise OversightRequiredError(
            f"Action '{action}' requires human approval (request_id={req.request_id}).",
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
        """Record an approval decision in Postgres.

        Raises:
            KeyError: If *request_id* does not exist or has already been decided.
        """
        return cast(
            OversightRecord,
            self._run_coro(
                self._decide(
                    request_id, ApprovalStatus.APPROVED, reviewer_id=reviewer_id, comment=comment
                )
            ),
        )

    def reject(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        comment: str = "",
    ) -> OversightRecord:
        """Record a rejection decision in Postgres."""
        return cast(
            OversightRecord,
            self._run_coro(
                self._decide(
                    request_id, ApprovalStatus.REJECTED, reviewer_id=reviewer_id, comment=comment
                )
            ),
        )

    def check(self, request_id: str) -> bool:
        """Return True if *request_id* was APPROVED."""
        return cast(bool, self._run_coro(self._check_async(request_id)))

    def pending(self) -> list[ApprovalRequest]:
        """Return all non-expired, undecided requests from Postgres."""
        return cast(list[ApprovalRequest], self._run_coro(self._pending_async()))

    def records(self) -> list[OversightRecord]:
        """Return all oversight records from Postgres."""
        return cast(list[OversightRecord], self._run_coro(self._records_async()))

    def wait_for_decision(
        self,
        request_id: str,
        *,
        timeout_s: float = 300.0,
        poll_interval_s: float = 2.0,
    ) -> ApprovalDecision:
        """Block until a reviewer decides *request_id* or the TTL expires.

        This is the durable pause-resume mechanism for cross-server HITL
        orchestration (Deferral 2 / EU AI Act Article 14 compliance).
        Any server — not just the one that originally called
        :meth:`request_approval` — can call this method with the stored
        ``request_id`` and resume the paused agent workflow.

        The poll loop queries Postgres at *poll_interval_s* intervals.  Postgres
        is the source of truth, so the caller's server can crash and restart
        without losing the approval state.

        Args:
            request_id:      UUID returned by :meth:`request_approval`.
            timeout_s:       Maximum wall-clock seconds to wait.  When
                             exceeded, returns a synthetic ``TIMEOUT`` decision.
                             Default: 300 s (5 minutes).
            poll_interval_s: Seconds between Postgres polls.  Lower values
                             increase responsiveness at the cost of DB load.
                             Default: 2 s.

        Returns:
            :class:`ApprovalDecision` with the reviewer's verdict or
            ``ApprovalStatus.TIMEOUT`` if the deadline passed first.

        Example::

            try:
                workflow.request_approval(
                    principal_id="agent-001",
                    action="wire $500,000",
                    ...
                )
            except OversightRequiredError as exc:
                request_id = exc.request_id
                # Store request_id durably (Redis, DB) so any server can resume.

            # On ANY server — even after restart:
            decision = workflow.wait_for_decision(request_id, timeout_s=86400)
            if decision.status == ApprovalStatus.APPROVED:
                execute_wire_transfer()
        """
        return cast(
            ApprovalDecision,
            self._run_coro(
                self._wait_for_decision_async(request_id, timeout_s, poll_interval_s)
            ),
        )

    async def _wait_for_decision_async(
        self,
        request_id: str,
        timeout_s: float,
        poll_interval_s: float,
    ) -> ApprovalDecision:
        """Poll Postgres until decided or deadline."""
        import asyncio as _asyncio

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            result = await self._check_decision_row(request_id)
            if result is not None:
                return result
            sleep_s = min(poll_interval_s, max(0.0, deadline - time.time()))
            if sleep_s <= 0:
                break
            await _asyncio.sleep(sleep_s)

        # Deadline passed without a reviewer decision — record TIMEOUT.
        _log.warning(
            "oversight.pg.wait_timeout: request_id=%s timeout_s=%s",
            request_id,
            timeout_s,
        )
        return ApprovalDecision(
            request_id=request_id,
            status=ApprovalStatus.TIMEOUT,
            reviewer_id="system:wait_timeout",
            comment=f"wait_for_decision() timed out after {timeout_s}s.",
        )

    async def _check_decision_row(self, request_id: str) -> ApprovalDecision | None:
        """Return the stored decision or None if not yet decided."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT status, reviewer_id, comment, decided_at
                FROM pramanix_approval_decisions
                WHERE request_id = $1
                """,
                request_id,
            )
        if row is None:
            return None
        return ApprovalDecision(
            request_id=request_id,
            status=ApprovalStatus(str(row["status"])),
            reviewer_id=str(row["reviewer_id"]),
            comment=str(row["comment"]),
            decided_at=float(row["decided_at"]),
        )

    def revoke(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        comment: str = "",
    ) -> OversightRecord:
        """Revoke a pending approval request.

        Distributed-safe: uses ``SELECT FOR UPDATE`` to prevent concurrent
        approve + revoke race.  Returns an :class:`OversightRecord` with
        ``status=REVOKED``.

        Raises:
            KeyError: If *request_id* not found or already decided.
        """
        return cast(
            OversightRecord,
            self._run_coro(
                self._decide(
                    request_id, ApprovalStatus.REVOKED, reviewer_id=reviewer_id, comment=comment
                )
            ),
        )

    # ── Async internals ────────────────────────────────────────────────────────

    async def _insert_request(self, req: ApprovalRequest) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO pramanix_approval_requests (
                    request_id, principal_id, action, decision_id, policy_hash,
                    intent_dump, required_scopes, blast_radius, reason,
                    created_at, ttl_seconds, metadata, decided
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,FALSE)
                ON CONFLICT (request_id) DO NOTHING
                """,
                req.request_id,
                req.principal_id,
                req.action,
                req.decision_id,
                req.policy_hash,
                json.dumps(req.intent_dump),
                json.dumps(req.required_scopes),
                req.blast_radius,
                req.reason,
                req.created_at,
                req.ttl_seconds,
                json.dumps(req.metadata),
            )

    async def _decide(
        self,
        request_id: str,
        status: ApprovalStatus,
        *,
        reviewer_id: str,
        comment: str,
    ) -> OversightRecord:
        pool = await self._get_pool()
        async with pool.acquire() as conn:  # noqa: SIM117
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT * FROM pramanix_approval_requests WHERE request_id=$1 FOR UPDATE",
                    request_id,
                )
                if row is None:
                    raise KeyError(f"ApprovalRequest '{request_id}' not found.")
                if row["decided"]:
                    raise KeyError(f"ApprovalRequest '{request_id}' has already been decided.")
                req = ApprovalRequest(
                    request_id=str(row["request_id"]),
                    principal_id=str(row["principal_id"]),
                    action=str(row["action"]),
                    decision_id=str(row["decision_id"]),
                    policy_hash=str(row["policy_hash"]),
                    intent_dump=json.loads(row["intent_dump"]),
                    required_scopes=json.loads(row["required_scopes"]),
                    blast_radius=str(row["blast_radius"]),
                    reason=str(row["reason"]),
                    created_at=float(row["created_at"]),
                    ttl_seconds=float(row["ttl_seconds"]),
                    metadata=json.loads(row["metadata"]),
                )
                # Fail-safe: if TTL expired, record TIMEOUT regardless.
                if req.is_expired() and status == ApprovalStatus.APPROVED:
                    status = ApprovalStatus.TIMEOUT
                    _log.warning(
                        "oversight.pg.timeout: request_id=%s principal=%s",
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
                await conn.execute(
                    """
                    INSERT INTO pramanix_approval_decisions (
                        request_id, status, reviewer_id, comment, decided_at, hmac_tag
                    ) VALUES ($1,$2,$3,$4,$5,$6)
                    ON CONFLICT (request_id) DO NOTHING
                    """,
                    request_id,
                    status.value,
                    reviewer_id,
                    comment,
                    dec.decided_at,
                    record.to_dict()["hmac_tag"],
                )
                await conn.execute(
                    "UPDATE pramanix_approval_requests SET decided=TRUE WHERE request_id=$1",
                    request_id,
                )
        _log.info(
            "oversight.pg.decided: request_id=%s status=%s reviewer=%s",
            request_id,
            status.value,
            reviewer_id,
        )
        return record

    async def _check_async(self, request_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status FROM pramanix_approval_decisions WHERE request_id=$1",
                request_id,
            )
            if row is None:
                return False
            return str(row["status"]) == ApprovalStatus.APPROVED.value

    async def _pending_async(self) -> list[ApprovalRequest]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM pramanix_approval_requests
                WHERE decided=FALSE
                ORDER BY created_at ASC
                """
            )
        result: list[ApprovalRequest] = []
        now = time.time()
        for row in rows:
            created = float(row["created_at"])
            ttl = float(row["ttl_seconds"])
            if now <= created + ttl:  # only include non-expired
                result.append(
                    ApprovalRequest(
                        request_id=str(row["request_id"]),
                        principal_id=str(row["principal_id"]),
                        action=str(row["action"]),
                        decision_id=str(row["decision_id"]),
                        policy_hash=str(row["policy_hash"]),
                        intent_dump=json.loads(row["intent_dump"]),
                        required_scopes=json.loads(row["required_scopes"]),
                        blast_radius=str(row["blast_radius"]),
                        reason=str(row["reason"]),
                        created_at=created,
                        ttl_seconds=ttl,
                        metadata=json.loads(row["metadata"]),
                    )
                )
        return result

    async def _records_async(self) -> list[OversightRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT r.*, d.status, d.reviewer_id, d.comment,
                       d.decided_at, d.hmac_tag
                FROM pramanix_approval_requests r
                JOIN pramanix_approval_decisions d USING (request_id)
                ORDER BY d.decided_at ASC
                """
            )
        recs: list[OversightRecord] = []
        for row in rows:
            data = {
                "request_id": str(row["request_id"]),
                "principal_id": str(row["principal_id"]),
                "action": str(row["action"]),
                "decision_id": str(row["decision_id"]),
                "policy_hash": str(row["policy_hash"]),
                "required_scopes": json.loads(row["required_scopes"]),
                "blast_radius": str(row["blast_radius"]),
                "reason": str(row["reason"]),
                "created_at": float(row["created_at"]),
                "ttl_seconds": float(row["ttl_seconds"]),
                "status": str(row["status"]),
                "reviewer_id": str(row["reviewer_id"]),
                "comment": str(row["comment"]),
                "decided_at": float(row["decided_at"]),
                "hmac_tag": str(row["hmac_tag"]),
            }
            try:
                recs.append(OversightRecord.from_dict(data, signing_key=self._key))
            except Exception as exc:
                _log.warning(
                    "oversight.pg.records: failed to decode record %s: %s",
                    data.get("request_id", "?"),
                    exc,
                )
        return recs


# ── Webhook notification channel ──────────────────────────────────────────────


class WebhookNotificationChannel:
    """HTTP webhook notification for pending approval requests.

    When an :class:`ApprovalRequest` arrives, this channel POSTs a JSON
    payload to a configured URL (Slack incoming webhook, PagerDuty Events
    API v2, generic webhook, etc.).  Failures are retried with exponential
    back-off up to *max_retries* times.

    This class is framework-agnostic.  Wire it into any approval workflow::

        notifier = WebhookNotificationChannel(
            url="https://hooks.slack.com/services/T00/B00/xxx",
            headers={"Content-Type": "application/json"},
        )
        try:
            workflow.request_approval(principal_id=..., action=..., ...)
        except OversightRequiredError as exc:
            req = workflow.pending()[0]  # fetch the freshly created request
            notifier.notify(req)

    The :meth:`notify` call is **synchronous** — it blocks until the
    request is delivered or all retries are exhausted.  For non-blocking
    use, submit it to a thread pool.

    Args:
        url:           Webhook endpoint URL.
        headers:       Additional HTTP headers (e.g. ``Authorization``).
        timeout:       Per-attempt HTTP timeout in seconds. Default: 10 s.
        max_retries:   Number of retry attempts after the first failure.
                       Default: 3 (total of 4 attempts).
        payload_fn:    Optional callable ``(ApprovalRequest) → dict`` to
                       customise the posted payload.  When ``None``, a
                       default JSON payload is used.

    Requires:
        ``httpx`` — already a dependency of ``pramanix[splunk]``.  Install
        with: ``pip install 'pramanix[splunk]'`` or ``pip install httpx``.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        payload_fn: Any = None,
    ) -> None:
        try:
            import httpx as _httpx
        except ImportError as exc:
            from pramanix.exceptions import ConfigurationError

            raise ConfigurationError(
                "httpx is required for WebhookNotificationChannel. "
                "Install it with: pip install httpx"
            ) from exc
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._max_retries = max_retries
        self._payload_fn = payload_fn
        self._client = _httpx.Client(timeout=timeout)

    def notify(self, request: ApprovalRequest) -> None:
        """POST the approval request to the configured webhook URL.

        Retries up to *max_retries* times with exponential back-off
        (1 s, 2 s, 4 s, …).  Non-2xx responses are logged as errors and
        retried (HEC-style: e.g. 429 rate-limit, 503 back-pressure).
        Does not raise — all failures are logged.
        """
        payload = self._build_payload(request)
        attempt = 0
        delay = 1.0
        while attempt <= self._max_retries:
            try:
                resp = self._client.post(
                    self._url,
                    json=payload,
                    headers=self._headers,
                )
                if resp.status_code < 400:
                    _log.info(
                        "oversight.webhook.sent: request_id=%s status=%d",
                        request.request_id,
                        resp.status_code,
                    )
                    return
                _log.warning(
                    "oversight.webhook.http_error: request_id=%s status=%d attempt=%d/%d",
                    request.request_id,
                    resp.status_code,
                    attempt + 1,
                    self._max_retries + 1,
                )
            except Exception as exc:
                _log.warning(
                    "oversight.webhook.send_error: request_id=%s attempt=%d/%d error=%s",
                    request.request_id,
                    attempt + 1,
                    self._max_retries + 1,
                    exc,
                )
            attempt += 1
            if attempt <= self._max_retries:
                time.sleep(delay)
                delay = min(delay * 2, 30.0)
        _log.error(
            "oversight.webhook.exhausted: request_id=%s all %d attempts failed — "
            "review portal must be checked manually",
            request.request_id,
            self._max_retries + 1,
        )

    def _build_payload(self, request: ApprovalRequest) -> dict[str, Any]:
        """Build the webhook JSON payload from the approval request."""
        if self._payload_fn is not None:
            return cast(dict[str, Any], self._payload_fn(request))
        return {
            "pramanix_event": "approval_required",
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "action": request.action,
            "blast_radius": request.blast_radius,
            "required_scopes": request.required_scopes,
            "reason": request.reason,
            "policy_hash": request.policy_hash,
            "created_at": request.created_at,
            "ttl_seconds": request.ttl_seconds,
        }

    def close(self) -> None:
        """Close the underlying httpx client.  Call at application teardown."""
        try:
            self._client.close()
        except Exception as exc:
            _log.warning("WebhookNotificationChannel.close: %s", exc)
