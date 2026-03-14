# Pramanix — Policy Authoring Guide

> **Audience:** Engineers writing or reviewing `Policy` subclasses.
> **Prerequisite:** Read [architecture.md](architecture.md) for the Five-Layer Defence overview.

---

## 1. The Policy Authoring Surface

A Pramanix policy is a plain Python class that inherits from `Policy`. It has
three responsibilities:

1. **Schema** — declare `Field` descriptors for every input the solver will receive.
2. **Invariants** — return a list of `ConstraintExpr` objects that Z3 will prove.
3. **Meta** — link Pydantic models for strict intent and state validation.

```python
from decimal import Decimal
from pydantic import BaseModel
from pramanix import E, Field, Policy
from pramanix.expressions import ConstraintExpr


class TransferIntent(BaseModel):
    amount: Decimal


class AccountState(BaseModel):
    state_version: str
    balance: Decimal
    daily_limit: Decimal
    minimum_reserve: Decimal
    is_frozen: bool


class TransferPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = TransferIntent
        state_model  = AccountState

    # ── Field declarations ──────────────────────────────────────────────
    amount          = Field("amount",          Decimal, "Real")
    balance         = Field("balance",         Decimal, "Real")
    daily_limit     = Field("daily_limit",     Decimal, "Real")
    minimum_reserve = Field("minimum_reserve", Decimal, "Real")
    is_frozen       = Field("is_frozen",       bool,    "Bool")

    # ── Invariants ──────────────────────────────────────────────────────
    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
            .named("minimum_reserve_floor")
            .explain("Overdraft: balance={balance}, amount={amount}, reserve={minimum_reserve}"),

            (E(cls.amount) <= E(cls.daily_limit))
            .named("within_daily_limit")
            .explain("Exceeds daily limit: amount={amount}, limit={daily_limit}"),

            (E(cls.amount) > 0)
            .named("positive_amount")
            .explain("Non-positive transfer: amount={amount}"),

            (E(cls.is_frozen) == False)  # noqa: E712 — Z3 Bool comparison
            .named("account_not_frozen")
            .explain("Account is frozen"),
        ]
```

---

## 2. DSL Reference

### 2.1 `Field`

```python
Field(name: str, python_type: type, z3_type: Z3Type)
```

| Parameter | Type | Description |
|---|---|---|
| `name` | `str` | Key in the `values` dict passed to `Guard.verify`. Must be unique within the policy. |
| `python_type` | `type` | Expected Python type (`Decimal`, `int`, `bool`, `str`). Used by the Pydantic validator layer. |
| `z3_type` | `"Real"` \| `"Int"` \| `"Bool"` | Z3 sort. Use `"Real"` for monetary values. Never use `"Int"` for currency — it silently truncates fractional amounts. |

**Supported Z3 type mappings:**

| Python type | Recommended Z3 sort | Notes |
|---|---|---|
| `Decimal` | `"Real"` | Exact rational — no floating-point drift |
| `int` | `"Int"` | Safe only for counts / quantities with no fractional semantics |
| `bool` | `"Bool"` | Must compare with `== True` / `== False` in constraints |
| `str` | — | Strings are not Z3-native; encode as enum `Int` or validate pre-Z3 |

### 2.2 `E(field)` — Expression Builder

`E()` wraps a `Field` reference and returns an `ExpressionNode`. All Python
arithmetic and comparison operators are overloaded to return new `ExpressionNode`
objects — they do **not** evaluate anything; they build a lazy AST that the
transpiler later converts to a Z3 expression.

```python
# All of these return ExpressionNode / ConstraintExpr, not Python values:
E(cls.balance) - E(cls.amount)              # arithmetic subtraction
E(cls.balance) - E(cls.amount) >= Decimal("0.01")  # comparison
E(cls.amount) > 0                           # literal on right side
E(cls.amount) <= E(cls.daily_limit)         # field-to-field comparison
```

**Supported operators:**

| Category | Operators |
|---|---|
| Arithmetic | `+`, `-`, `*`, `/` |
| Comparison | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| Boolean | `&` (AND), `\|` (OR), `~` (NOT) |

> **Do not use `and` / `or` / `not`.** Python's short-circuit boolean operators
> cannot be overloaded. Use `&`, `|`, `~` with parentheses around each operand.

```python
# Correct:
(E(cls.amount) > 0) & (E(cls.balance) >= E(cls.amount))

# WRONG — Python evaluates this as a truthiness check, not a Z3 expression:
E(cls.amount) > 0 and E(cls.balance) >= E(cls.amount)
```

### 2.3 `.named(label)` and `.explain(template)`

Every constraint **must** be named. The name appears in `Decision.violated_invariants`
and in structured logs.

```python
(E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
.named("minimum_reserve_floor")           # required — used for violation attribution
.explain("Overdraft: balance={balance}")  # optional — human-readable, {key} interpolated
```

The `explain` template uses `{field_name}` placeholders. At BLOCK time,
Pramanix substitutes the concrete values to produce the human-readable reason:

```
Overdraft: balance=100.00, amount=200.00, reserve=0.01
```

---

## 3. Common Mistakes and Hardening Patterns

The following patterns were identified during Phase 4 adversarial review.
Every one of them is a real vulnerability that led to a silent policy bypass
in early versions.

---

### 3.1 Near-Drain Attack — Open vs. Closed Boundary

**Vulnerability:** Using a strict `>` instead of `>=` for the minimum-reserve
floor creates a gap of exactly one unit at the boundary.

```python
# ❌ VULNERABLE — open boundary
(E(cls.balance) - E(cls.amount) > E(cls.minimum_reserve))
.named("minimum_reserve_floor")
# A transfer that leaves balance == minimum_reserve PASSES.
# With minimum_reserve=0.01 and balance=100.01, amount=100.00 passes.
```

```python
# ✅ CORRECT — closed boundary
(E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
.named("minimum_reserve_floor")
# Balance after transfer must be AT LEAST minimum_reserve. Exact matches blocked.
```

**Rule:** For every minimum-floor or maximum-ceiling invariant, use `>=` or `<=`
respectively. Reserve `>` and `<` only for strict exclusion of zero or
similarly unambiguous boundaries.

---

### 3.2 Minimum Reserve — Missing the Cross-Field Dependency

**Vulnerability:** Declaring `minimum_reserve` as a constant literal in the
policy instead of a `Field` makes it impossible to vary the reserve per
account tier without deploying a new policy.

More critically, hardcoding `0.01` while the account actually requires
`100.00` (VIP reserve) means the policy is silently wrong.

```python
# ❌ VULNERABLE — hardcoded constant (misconfiguration risk)
(E(cls.balance) - E(cls.amount) >= Decimal("0.01"))
.named("minimum_reserve_floor")
```

```python
# ✅ CORRECT — reserve is a field, validated by Pydantic at the state boundary
minimum_reserve = Field("minimum_reserve", Decimal, "Real")

(E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
.named("minimum_reserve_floor")
```

Always drive the reserve from the account-state model so the value is
validated and version-locked alongside the balance.

---

### 3.3 Full-Drain Bypass — Missing the Semantic Gateway

**Vulnerability:** Z3 proves invariants purely mathematically. If
`balance = amount` and `minimum_reserve = 0`, Z3 will return SAT — because
`0 >= 0` is true. This is mathematically correct but business-policy wrong.

Full-drain transfers are exceptional events that require human oversight. Z3
cannot capture the business rule "always get a human to approve this."

```python
# ❌ VULNERABLE — Z3 alone evaluates balance=100, amount=100, reserve=0 as SAT
(E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
# result: 100 - 100 >= 0  →  0 >= 0  →  SAT  →  ALLOW  ← wrong
```

**Fix:** The semantic gateway (`semantic_post_consensus_check`) intercepts
`amount == balance` **before** Z3 and routes it through the
`_FailClosedApprovalGateway`:

```python
if amount == balance:
    _HUMAN_APPROVAL_GATEWAY.approve_or_raise(amount=amount, balance=balance)
    # Raises HumanApprovalUnavailable if no backend is configured.
    # Raises HumanApprovalTimeout if the backend fails for any reason.
    # Only an explicit True from the backend allows.
```

**Rule:** Z3 enforces mathematical invariants. Business rules that depend on
context, risk tier, or human judgment must be implemented in Layer 2b semantic
checks — never delegated entirely to Z3.

---

### 3.4 Daily Limit — Snapshot vs. Live State Race

**Vulnerability:** If `daily_remaining` is computed at request time as
`daily_limit - daily_spent`, but `daily_spent` is read from a cache that is
stale, a rapid sequence of transfers can each see `daily_remaining = daily_limit`
(the full un-decremented limit) and all pass individually even though their
sum exceeds the limit.

This is a Time-of-Check / Time-of-Use (TOCTOU) race. Pramanix cannot solve
TOCTOU on its own — it verifies a snapshot, not live state.

```
# Correct operational pattern:
1. Read account state atomically (SELECT … FOR UPDATE or optimistic lock).
2. Pass the locked snapshot to Guard.verify().
3. Only commit the transfer (and update daily_spent) if Guard returns ALLOW.
4. Rollback on BLOCK.
```

**Rule:** Always pass **locked state** to `Guard.verify()`. Pramanix is a
verification gate, not a concurrency controller.

---

### 3.5 Frozen Account — Bool Z3 Comparison

**Vulnerability:** Python's `==` on a Bool `ExpressionNode` must compare
against a Python `bool` literal. Comparing against `1` or `"true"` produces
a type mismatch in Z3 that silently evaluates differently.

```python
# ❌ WRONG — compares Bool node against integer 0, not Python bool
(E(cls.is_frozen) == 0).named("account_not_frozen")
```

```python
# ✅ CORRECT — compare against Python bool
(E(cls.is_frozen) == False).named("account_not_frozen")  # noqa: E712
```

The `# noqa: E712` suppresses the flake8 warning about `== False`; this is
intentional because we are building a Z3 expression, not evaluating Python
truthiness.

---

### 3.6 Injection Scoring — Allowlist vs. Blocklist for Recipient ID

**Vulnerability:** An allowlist for `recipient_id` characters (e.g.,
`[a-zA-Z0-9_\-]+`) may sound safe, but it silently fails to permit legitimate
identifiers like `alice-smith`, `user+tag@domain`, or `acct.001` if not
carefully specified. Worse, any allowlist omission becomes a silent block that
looks identical to an injection detection to the caller.

```python
# ❌ FRAGILE — allowlist; innocent hyphens cause false positives
re.fullmatch(r"[a-zA-Z0-9_\-]+", recipient_id)  # "alice-smith" → score +0.30
```

```python
# ✅ CORRECT — blocklist; only actual dangerous chars scored
_DANGEROUS_RECIPIENT_CHARS_RE = re.compile(
    r"[;|()\\/\x27\x22`<>&$%#{}\x00-\x1f\x7f]"
)
# "alice-smith" → no match → +0.00
# "../../etc;rm" → match → +0.30
```

The blocklist approach is explicit about what is dangerous and never penalises
legitimate separators.

---

### 3.7 Sub-Penny Threshold — Per-Currency Configuration

**Vulnerability:** Using a single `0.01` threshold for all currencies treats
JPY as a "sub-penny" amount when `1 JPY` is in fact the minimum monetary unit.
This false-positive blocks legitimate micro-payments in zero-decimal currencies.

```python
# Per-currency thresholds (from pramanix_llm_hardened._PENNY_THRESHOLDS):
# JPY, KRW, VND, CLP, ISK, HUF, UGX, RWF, GNF, XAF, XOF, XPF → 1
# KWD, BHD, OMR, IQD, TND, JOD, LYD                            → 0.001
# BTC, ETH                                                      → 0.0001
# all others                                                    → 0.01  (default)
```

Pass the transaction currency to `injection_confidence_score`:

```python
score = injection_confidence_score(
    user_input, extracted_intent, warnings, currency="JPY"
)
```

---

## 4. Policy Versioning

Every policy must declare a `Meta.version`. Pramanix embeds the version string
in every `Decision` object. Use semantic versioning (`"major.minor"`). Increment
the major version for any change that narrows invariants (more things blocked)
or widens the schema. Increment the minor version for documentation-only changes
or new optional fields.

```python
class TransferPolicy(Policy):
    class Meta:
        version = "2.0"   # increment when invariants change
        intent_model = TransferIntent
        state_model  = AccountState
```

**Never deploy a new policy version without running the full test suite.**
Even a seemingly harmless boundary change (e.g., `>` → `>=`) can cause a
latent bypass to become active.

---

## 5. Testing Policies

### Minimal test structure

```python
import pytest
from decimal import Decimal
from pramanix import Guard, GuardConfig

guard = Guard(TransferPolicy, GuardConfig())

class TestTransferPolicy:
    def test_normal_transfer_allows(self):
        d = guard.verify({"amount": Decimal("100"), "balance": Decimal("500"),
                          "daily_limit": Decimal("1000"), "minimum_reserve": Decimal("0.01"),
                          "is_frozen": False})
        assert d.allowed

    def test_overdraft_blocks(self):
        d = guard.verify({"amount": Decimal("600"), "balance": Decimal("500"),
                          "daily_limit": Decimal("1000"), "minimum_reserve": Decimal("0.01"),
                          "is_frozen": False})
        assert not d.allowed
        assert "minimum_reserve_floor" in d.violated_invariants

    def test_boundary_exact_reserve_blocks(self):
        # Leaving balance == minimum_reserve must BLOCK (closed boundary)
        d = guard.verify({"amount": Decimal("499.99"), "balance": Decimal("500"),
                          "daily_limit": Decimal("1000"), "minimum_reserve": Decimal("0.01"),
                          "is_frozen": False})
        assert not d.allowed

    def test_frozen_account_blocks(self):
        d = guard.verify({"amount": Decimal("100"), "balance": Decimal("500"),
                          "daily_limit": Decimal("1000"), "minimum_reserve": Decimal("0.01"),
                          "is_frozen": True})
        assert not d.allowed
        assert "account_not_frozen" in d.violated_invariants
```

### Property-based testing

Use `hypothesis` to generate random valid and invalid inputs. Pramanix ships
with hypothesis strategies in `tests/property/`. The strategy for
`TransactionIntent` covers edge cases that manual test design misses (e.g.,
amounts with 8 decimal places, exact-boundary values, very large Decimals).

---

## 6. Policy Checklist (Pre-Merge)

Before merging any new or changed policy:

- [ ] All invariants are named with `.named()`
- [ ] All floor invariants use `>=` (not `>`)
- [ ] All ceiling invariants use `<=` (not `<`)
- [ ] `minimum_reserve` is a `Field`, not a hardcoded literal
- [ ] `bool` fields compare with `== True` / `== False`, not integers
- [ ] A test exists for the exact boundary value (e.g., `balance - amount == reserve`)
- [ ] `Meta.version` has been incremented
- [ ] Full test suite (705+ tests) passes with zero failures
- [ ] `radar_test.py` passes 13/13 (telemetry red flags exercised)
