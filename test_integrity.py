"""
Pramanix — Integrity Test Suite
================================
Validates the five-layer defence implemented in pramanix_hardened.py.

Run with:  python test_integrity.py
"""
from __future__ import annotations

from pramanix_hardened import (
    SemanticPolicyViolation,
    evaluate_transaction,
    safe_validate_intent,
    semantic_post_consensus_check,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0


def check(label: str, condition: bool) -> None:
    global PASS, FAIL
    icon = "\u2713" if condition else "\u2717"
    print(f"  {icon}  {label}")
    if condition:
        PASS += 1
    else:
        FAIL += 1


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

BASE_CONTEXT: dict = {
    "balance":         "1000.00",
    "daily_limit":     "5000.00",
    "daily_spent":     "0.00",
    "minimum_reserve": "0.01",
}

VALID_INTENT: dict = {
    "amount":       "100.00",
    "recipient_id": "alice_wallet",
    "currency":     "USD",
    "memo":         "lunch",
}

def sem_check(intent_overrides: dict, ctx_overrides: dict | None = None) -> bool:
    ctx_overrides = ctx_overrides or {}
    try:
        semantic_post_consensus_check(
            {**VALID_INTENT, **intent_overrides},
            {**BASE_CONTEXT, **ctx_overrides},
        )
        return True
    except SemanticPolicyViolation:
        return False


def full_eval(amount: str, balance: str = "1000.00") -> bool:
    """
    IMPORTANT: must inject *amount* into the intent dict so the near-drain
    and insufficient-balance test cases exercise the correct code paths.
    """
    intent = {**VALID_INTENT, "amount": amount}
    return evaluate_transaction(
        intent,
        intent,
        {**BASE_CONTEXT, "balance": balance},
    ).allowed


if __name__ == "__main__":
    # -----------------------------------------------------------------------
    # Layer 1 — Dual-model consensus
    # -----------------------------------------------------------------------

    print("\nLayer 1 \u2014 Dual-model consensus")

    d_mismatch = evaluate_transaction(
        {**VALID_INTENT, "amount": "100.00"},
        {**VALID_INTENT, "amount": "101.00"},
        BASE_CONTEXT,
    )
    check("Mismatched intents \u2192 BLOCK", not d_mismatch.allowed and d_mismatch.layer_blocked == 1)
    check(
        "Matching valid intents \u2192 ALLOW",
        evaluate_transaction(VALID_INTENT, VALID_INTENT, BASE_CONTEXT).allowed,
    )

    # -----------------------------------------------------------------------
    # Layer 2 — Pydantic schema validation
    # -----------------------------------------------------------------------

    print("\nLayer 2 \u2014 Pydantic schema")

    check("Negative amount \u2192 BLOCK",   safe_validate_intent({**VALID_INTENT, "amount": "-1"}) is None)
    check("Zero amount \u2192 BLOCK",       safe_validate_intent({**VALID_INTENT, "amount": "0"}) is None)
    check("Null byte in ID \u2192 BLOCK",   safe_validate_intent({**VALID_INTENT, "recipient_id": "abc\x00def"}) is None)
    check("Valid intent \u2192 passes",     safe_validate_intent(VALID_INTENT) is not None)

    # -----------------------------------------------------------------------
    # Layer 2b — Semantic policy
    # -----------------------------------------------------------------------

    print("\nLayer 2b \u2014 Semantic policy")

    check("Drain to exactly zero \u2192 BLOCK",    not sem_check({"amount": "1000.00"}))
    check(
        "Exceeds daily limit \u2192 BLOCK",
        not sem_check({"amount": "4001.00"}, {"daily_spent": "1000.00"}),
    )
    check("Normal transaction \u2192 passes",      sem_check({"amount": "100.00"}))

    # -----------------------------------------------------------------------
    # Layers 3–5 — Z3 policy + subprocess isolation + HMAC seal
    # -----------------------------------------------------------------------

    print("\nLayers 3\u20135 \u2014 Z3 policy + subprocess isolation")

    check("Valid transaction \u2192 ALLOW",              full_eval("100.00"))
    check("Near-drain transaction \u2192 BLOCK",         not full_eval("999.995"))
    check("Insufficient balance \u2192 BLOCK",           not full_eval("100.00", balance="50.00"))
    check("Exact minimum-reserve boundary \u2192 ALLOW", full_eval("999.99"))

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print(f"\nResults: {PASS} passed, {FAIL} failed")
    if FAIL:
        raise SystemExit(1)
