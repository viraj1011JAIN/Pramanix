# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Pramanix — Hardening Patches (Patches 1–5)
===========================================
Standalone integration of the five hardening patches.  Designed to be
imported by ``test_integrity.py`` and used as a reference implementation
that validates the full five-layer defence before production merge.

Layers implemented here
-----------------------
Layer 1  — Dual-model extraction consensus (parameter-based mock).
Layer 2  — Pydantic TransactionIntent with strict boundary validators.
Layer 2b — Semantic post-consensus check (business-rule guard).
Layer 3  — Z3 policy with closed minimum-reserve boundary.
Layer 4  — Spawn-isolated subprocess with HMAC-SHA256 result seal.
Layer 5  — Unified Decision pipeline (evaluate_transaction).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import re
import secrets
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

import z3
from pydantic import BaseModel, Field, field_validator, model_validator

# Optional telemetry — silently disabled if pramanix_telemetry is not installed.
try:
    from pramanix_telemetry import get_telemetry as _get_telemetry
    _TELEMETRY = _get_telemetry()
except ImportError:
    _TELEMETRY = None  # type: ignore[assignment]

# ===========================================================================
# Key Lifecycle: _EphemeralKey
# Guarantees: repr/str never expose the raw bytes (safe for logging);
# __reduce__ blocks disk serialisation; rotates on every process restart.
# ===========================================================================


class _EphemeralKey:
    """Wraps a secret key bytes object with logging and serialisation guards.

    * ``repr()`` / ``str()`` → ``"<EphemeralKey: redacted>"`` (log-safe).
    * ``__reduce__()`` raises :class:`TypeError` to prevent ``pickle.dump``
      to disk.  Pass ``.bytes`` explicitly for IPC forwarding only.
    * Fresh key generated via :mod:`secrets` at every process import;
      restarting the process automatically rotates the key.
    """

    __slots__ = ("_b",)

    def __init__(self, raw: bytes) -> None:
        self._b = raw

    @property
    def bytes(self) -> bytes:
        """Return raw key bytes for HMAC operations and explicit IPC forwarding."""
        return self._b

    def __repr__(self) -> str:
        return "<EphemeralKey: redacted>"

    __str__ = __repr__  # type: ignore[assignment]

    def __reduce__(self):  # type: ignore[override]
        raise TypeError(
            "_EphemeralKey must not be serialised to disk. "
            "Use .bytes to forward via IPC explicitly."
        )


# ===========================================================================
# PATCH 1 — Semantic post-consensus validator
# ===========================================================================


class SemanticPolicyViolation(Exception):
    """Raised when the LLM-extracted intent violates a host-side business rule."""


class HumanApprovalUnavailable(SemanticPolicyViolation):
    """No human-approval backend is configured; full-drain transfer BLOCKED."""


class HumanApprovalTimeout(SemanticPolicyViolation):
    """Approval gateway did not respond in time; transaction BLOCKED (fail-closed)."""


class HumanApprovalBackend(Protocol):
    """Interface that an external human-approval system must implement."""

    def request_approval(
        self,
        *,
        amount: Decimal,
        balance: Decimal,
        timeout_s: float,
    ) -> bool:
        """Return True iff a human reviewer explicitly approves the transfer."""
        ...


class _FailClosedApprovalGateway:
    """Routes full-drain transactions to an external human-approval backend.

    **Fail-closed by design**: any exception from the backend (network error,
    timeout, misconfiguration) is treated as a denial.
    :class:`HumanApprovalTimeout` or :class:`HumanApprovalUnavailable` is
    raised so the caller keeps the transaction BLOCKED.  Absence of an explicit
    approval is always equivalent to denial.

    Args:
        backend:   Object implementing :class:`HumanApprovalBackend`.
                   ``None`` (the default) means no system is configured —
                   the full-drain path is always blocked.
        timeout_s: Maximum seconds to wait for a human decision.
    """

    def __init__(
        self,
        backend: "HumanApprovalBackend | None" = None,
        timeout_s: float = 30.0,
    ) -> None:
        self._backend   = backend
        self._timeout_s = timeout_s

    def approve_or_raise(self, *, amount: Decimal, balance: Decimal) -> None:
        """Attempt to obtain human approval; raise if approval is not granted.

        Raises:
            HumanApprovalUnavailable: No backend configured.
            HumanApprovalTimeout:     Backend raised any exception (network,
                                      timeout, or unexpected error).
            SemanticPolicyViolation:  Reviewer explicitly denied the transfer.
        """
        if self._backend is None:
            raise HumanApprovalUnavailable(
                "No human-approval backend is configured — "
                "full-drain transfer BLOCKED (fail-closed)."
            )
        try:
            approved = self._backend.request_approval(
                amount=amount,
                balance=balance,
                timeout_s=self._timeout_s,
            )
        except (HumanApprovalUnavailable, SemanticPolicyViolation):
            raise  # re-raise Pramanix-domain exceptions unchanged
        except Exception as exc:
            raise HumanApprovalTimeout(
                f"Human-approval gateway error ({type(exc).__name__}: {exc}) — "
                "transaction BLOCKED (fail-closed)."
            ) from exc

        if not approved:
            raise SemanticPolicyViolation("Human reviewer denied the full-drain transfer.")


# Module-level gateway singleton.  Replace backend before deploying.
# Default (no backend) is always fail-closed: no approval == blocked.
_HUMAN_APPROVAL_GATEWAY = _FailClosedApprovalGateway()


def semantic_post_consensus_check(intent: dict, account_context: dict) -> None:
    """Apply fast pure-Python semantic rules after LLM consensus, before Z3.

    Raises:
        SemanticPolicyViolation: on any detected business-rule violation.
    """
    amount = Decimal(str(intent.get("amount", 0)))
    balance = Decimal(str(account_context.get("balance", 0)))
    daily_limit = Decimal(str(account_context.get("daily_limit", "10000")))
    daily_spent = Decimal(str(account_context.get("daily_spent", "0")))
    minimum_reserve = Decimal(str(account_context.get("minimum_reserve", "0.01")))

    if balance - amount < minimum_reserve:
        raise SemanticPolicyViolation(
            f"Transfer would leave balance below minimum reserve "
            f"(balance={balance}, amount={amount}, reserve={minimum_reserve})"
        )

    remaining_daily = daily_limit - daily_spent
    if amount > remaining_daily:
        raise SemanticPolicyViolation(
            f"Transfer exceeds daily limit "
            f"(remaining={remaining_daily}, amount={amount})"
        )

    if amount <= 0:
        raise SemanticPolicyViolation(f"Amount must be positive, got {amount}")

    if amount == balance:
        # FAIL-CLOSED: any exception from the gateway (no backend configured,
        # network timeout, explicit denial) keeps the transaction BLOCKED.
        # Absence of explicit human approval is always treated as a denial.
        _HUMAN_APPROVAL_GATEWAY.approve_or_raise(amount=amount, balance=balance)


# ===========================================================================
# PATCH 2 — Hardened Pydantic model with boundary semantics
# ===========================================================================


class TransactionIntent(BaseModel):
    amount: Decimal = Field(gt=Decimal("0"), lt=Decimal("1000000"))
    recipient_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-]+$",
    )
    currency: str = Field(pattern=r"^[A-Z]{3}$")   # ISO 4217
    memo: str = Field(default="", max_length=128)

    @field_validator("amount", mode="before")
    @classmethod
    def coerce_decimal(cls, v: Any) -> Decimal:
        try:
            d = Decimal(str(v))
            if d != round(d, 8):
                raise ValueError("Too many decimal places")
            return d
        except (InvalidOperation, ValueError) as e:
            raise ValueError(f"Invalid amount: {e}") from e

    @field_validator("recipient_id", mode="before")
    @classmethod
    def sanitise_recipient(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError("recipient_id must be a string")
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", str(v))
        if cleaned != v:
            raise ValueError("recipient_id contains control characters")
        return cleaned

    @model_validator(mode="after")
    def cross_field_check(self) -> "TransactionIntent":
        if not self.amount.is_finite():
            raise ValueError("Amount must be a finite number")
        return self


def safe_validate_intent(raw_json: dict) -> "TransactionIntent | None":
    """Return a validated TransactionIntent, or None on any validation failure."""
    try:
        return TransactionIntent(**raw_json)
    except Exception:
        return None


# ===========================================================================
# PATCH 3 — Z3 policy with closed boundary conditions
# ===========================================================================


def build_z3_policy(
    balance: Decimal,
    amount: Decimal,
    daily_remaining: Decimal,
    minimum_reserve: Decimal = Decimal("0.01"),
) -> z3.Solver:
    """Construct a Z3 Solver encoding the core transaction safety constraints."""
    solver = z3.Solver()
    bal  = z3.RealVal(str(balance))
    amt  = z3.RealVal(str(amount))
    rem  = z3.RealVal(str(daily_remaining))
    res  = z3.RealVal(str(minimum_reserve))
    zero = z3.RealVal("0")

    solver.add(amt > zero)            # amount must be positive
    solver.add(bal - amt >= res)      # minimum-reserve floor (CLOSED boundary)
    solver.add(amt <= rem)            # within remaining daily limit
    solver.add(bal >= zero)           # balance cannot start negative
    return solver


def evaluate_z3_policy(solver: z3.Solver) -> bool:
    """Return True iff the solver constraints are satisfiable."""
    try:
        result = solver.check()
        return result == z3.sat
    except Exception:
        return False


# ===========================================================================
# PATCH 4 — Spawn-isolated subprocess with HMAC integrity seal
# ===========================================================================

# Per-process key — ephemeral, repr-safe, never serialisable to disk.
# Rotates automatically on every process restart (secrets.token_bytes at import).
# Always pass .bytes explicitly when forwarding to child processes via IPC.
_RESULT_SEAL_KEY = _EphemeralKey(secrets.token_bytes(32))


def _worker_evaluate(
    balance_str: str,
    amount_str: str,
    daily_remaining_str: str,
    minimum_reserve_str: str,
    seal_key: bytes,
    result_queue: "multiprocessing.Queue[dict]",
) -> None:
    """Worker body executed inside the spawned subprocess.

    Signs the result with *seal_key* before writing to *result_queue* so the
    host can verify integrity after IPC deserialization.
    """
    try:
        balance         = Decimal(balance_str)
        amount          = Decimal(amount_str)
        daily_remaining = Decimal(daily_remaining_str)
        minimum_reserve = Decimal(minimum_reserve_str)

        solver  = build_z3_policy(balance, amount, daily_remaining, minimum_reserve)
        allowed = evaluate_z3_policy(solver)

        payload = json.dumps({"allowed": allowed}).encode()
        seal    = hmac.new(seal_key, payload, hashlib.sha256).hexdigest()
        result_queue.put({"payload": payload.decode(), "seal": seal})
    except Exception:
        payload = json.dumps({"allowed": False}).encode()
        seal    = hmac.new(seal_key, payload, hashlib.sha256).hexdigest()
        result_queue.put({"payload": payload.decode(), "seal": seal})


def spawn_evaluate(
    balance: Decimal,
    amount: Decimal,
    daily_remaining: Decimal,
    minimum_reserve: Decimal = Decimal("0.01"),
    timeout_s: float = 15.0,
) -> bool:
    """Evaluate the Z3 policy in an isolated spawned subprocess.

    Security properties:
    * Subprocess is spawned (not forked) — no shared memory state.
    * Z3 context is private to the child — cannot leak or corrupt parent.
    * Result is HMAC-signed; host verifies before trusting the decision.
    * Timeout enforced; hanging subprocesses are killed hard.

    Returns:
        True iff the Z3 policy is SAT (transaction is safe to allow).
    """
    ctx          = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue()

    proc = ctx.Process(
        target=_worker_evaluate,
        args=(
            str(balance),
            str(amount),
            str(daily_remaining),
            str(minimum_reserve),
            _RESULT_SEAL_KEY.bytes,  # raw bytes — wrapper stays in host process only
            result_queue,
        ),
        daemon=True,
    )

    proc.start()
    proc.join(timeout=timeout_s)

    if proc.is_alive():
        proc.kill()
        proc.join()
        if _TELEMETRY is not None:
            try:
                _TELEMETRY.record_z3_evaluation(timed_out=True)
            except Exception:
                pass
        return False

    if proc.exitcode != 0:
        return False

    try:
        msg     = result_queue.get(timeout=2.0)
        payload = msg["payload"].encode()
        seal    = msg["seal"]

        expected_seal = hmac.new(_RESULT_SEAL_KEY.bytes, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(seal, expected_seal):
            return False  # HMAC mismatch — IPC tampering or corruption

        result = json.loads(payload)
        allowed = result.get("allowed", False) is True
        if _TELEMETRY is not None:
            try:
                _TELEMETRY.record_z3_evaluation(timed_out=False)
            except Exception:
                pass
        return allowed
    except Exception:
        return False


# ===========================================================================
# PATCH 5 — Unified Decision pipeline
# ===========================================================================


@dataclass
class Decision:
    """Immutable policy decision returned by evaluate_transaction."""

    allowed: bool
    reason: str
    layer_blocked: int | None = None


def evaluate_transaction(
    raw_intent_gpt4o: dict,
    raw_intent_claude: dict,
    account_context: dict,
) -> Decision:
    """Run the full five-layer evaluation pipeline.

    Layers:
        1. Dual-model consensus             — intents must match exactly.
        2. Pydantic schema validation       — strict boundary enforcement.
        2b. Semantic policy check           — fast Python business rules.
        3. Z3 formal verification           — closed-boundary arithmetic.
        4. HMAC result integrity            — subprocess seal verified.

    Args:
        raw_intent_gpt4o:  Dict extracted by (simulated) GPT-4o.
        raw_intent_claude: Dict extracted by (simulated) Claude.
        account_context:   Host-provided state (balance, limits, reserve).

    Returns:
        A :class:`Decision`.  ``allowed=True`` only when ALL layers pass.
    """
    # Layer 1 — Dual-model consensus
    _consensus_matched = raw_intent_gpt4o == raw_intent_claude
    if _TELEMETRY is not None:
        try:
            _TELEMETRY.record_consensus_attempt(_consensus_matched)
        except Exception:
            pass
    if not _consensus_matched:
        return Decision(allowed=False, reason="extraction_mismatch", layer_blocked=1)

    # Layer 2 — Pydantic schema validation
    intent = safe_validate_intent(raw_intent_gpt4o)
    if intent is None:
        return Decision(allowed=False, reason="schema_validation_failed", layer_blocked=2)

    # Layer 2b — Semantic post-consensus check
    try:
        semantic_post_consensus_check(
            intent=intent.model_dump(),
            account_context=account_context,
        )
    except SemanticPolicyViolation as e:
        return Decision(
            allowed=False,
            reason=f"semantic_policy: {e}",
            layer_blocked=2,
        )

    # Layer 3+4 — Z3 formal verification in isolated subprocess with HMAC seal
    balance         = Decimal(str(account_context["balance"]))
    daily_remaining = (
        Decimal(str(account_context["daily_limit"]))
        - Decimal(str(account_context["daily_spent"]))
    )
    minimum_reserve = Decimal(str(account_context.get("minimum_reserve", "0.01")))

    allowed = spawn_evaluate(
        balance=balance,
        amount=intent.amount,
        daily_remaining=daily_remaining,
        minimum_reserve=minimum_reserve,
    )

    if not allowed:
        return Decision(allowed=False, reason="z3_policy_blocked", layer_blocked=3)

    return Decision(allowed=True, reason="all_layers_passed")
