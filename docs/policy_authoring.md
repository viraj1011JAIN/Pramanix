# Pramanix -- Policy Authoring Guide

> **Version:** v0.9.0
> **Audience:** Engineers writing or reviewing `Policy` subclasses.
> **Prerequisite:** Read [architecture.md](architecture.md) for the pipeline overview.

---

## 1. Policy Structure

A Pramanix policy is a plain Python class inheriting from `Policy`. It has three responsibilities:

- **Schema** -- declare `Field` descriptors for every input the solver will receive
- **Invariants** -- return a list of `ConstraintExpr` objects that Z3 will prove
- **Meta** -- link Pydantic models for strict intent and state validation

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

    # Field declarations
    amount          = Field("amount",          Decimal, "Real")
    balance         = Field("balance",         Decimal, "Real")
    daily_limit     = Field("daily_limit",     Decimal, "Real")
    minimum_reserve = Field("minimum_reserve", Decimal, "Real")
    is_frozen       = Field("is_frozen",       bool,    "Bool")

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

            (E(cls.is_frozen) == False)  # noqa: E712 -- Z3 Bool comparison
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
|-----------|------|-------------|
| `name` | `str` | Key in the `values` dict passed to `Guard.verify()`. Must be unique within the policy. |
| `python_type` | `type` | Expected Python type (`Decimal`, `int`, `bool`, `str`). Used by the Pydantic validator layer. |
| `z3_type` | `"Real"` / `"Int"` / `"Bool"` | Z3 sort. Use `"Real"` for monetary values. Never use `"Int"` for currency -- it silently truncates fractional amounts. |

**Supported type mappings:**

| Python type | Z3 sort | Notes |
|-------------|---------|-------|
| `Decimal` | `"Real"` | Exact rational arithmetic. Converted via `as_integer_ratio()`. Never loses precision. |
| `int` | `"Int"` | Safe for counts and quantities with no fractional semantics. |
| `bool` | `"Bool"` | Compare with `== True` / `== False` in constraints. Never compare with `0` or `1`. |
| `str` | (not supported natively) | Strings are not Z3-native. Encode as enum `Int` or validate pre-Z3 via Pydantic. |

**Warning -- never use `float` for monetary values:**
- `float` cannot represent `0.1` exactly in IEEE 754.
- If you must use `float`, Pramanix converts it via `Decimal(str(v))` before `as_integer_ratio()`.
- The resulting Z3 value is the decimal representation of the float string, not the actual float.
- For money, quantities, and anything requiring exact arithmetic: always use `Decimal`.

---

### 2.2 `E(field)` -- Expression Builder

- `E()` wraps a `Field` reference and returns an `ExpressionNode`.
- All Python arithmetic and comparison operators are overloaded to return new `ExpressionNode` objects.
- They build a lazy AST. Nothing is evaluated until the transpiler converts the tree to Z3.

```python
E(cls.balance) - E(cls.amount)                    # arithmetic
E(cls.balance) - E(cls.amount) >= Decimal("0.01") # comparison with literal
E(cls.amount) <= E(cls.daily_limit)               # field-to-field comparison
E(cls.amount) > 0                                 # comparison with int literal
```

---

### 2.3 Arithmetic Operators

| Operator | DSL usage | Z3 equivalent |
|----------|-----------|---------------|
| `+` | `E(cls.a) + E(cls.b)` | `z3.ArithRef.__add__` |
| `-` | `E(cls.a) - E(cls.b)` | `z3.ArithRef.__sub__` |
| `*` | `E(cls.a) * E(cls.b)` | `z3.ArithRef.__mul__` |
| `/` | `E(cls.a) / E(cls.b)` | `z3.ArithRef.__truediv__` |
| `**` | BANNED | Raises `PolicyCompilationError` -- exponentiation creates non-linear arithmetic that is undecidable in general |

**Literal values on the right side of operators are allowed:**
```python
E(cls.amount) * 3              # amount * 3
E(cls.balance) - Decimal("10") # balance - 10.00
```

**Literals on the left side: always wrap in E() for clarity:**
```python
# Technically works but avoid -- confusing
Decimal("10") - E(cls.amount)

# Prefer
E(cls.amount) * -1 + Decimal("10")
```

---

### 2.4 Comparison Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `>=` | greater than or equal | `E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve)` |
| `<=` | less than or equal | `E(cls.amount) <= E(cls.daily_limit)` |
| `>` | strictly greater than | `E(cls.amount) > 0` |
| `<` | strictly less than | `E(cls.risk_score) < Decimal("0.75")` |
| `==` | equal | `E(cls.is_frozen) == False` |
| `!=` | not equal | `E(cls.status) != 0` |

**Floor vs. ceiling boundary -- this matters:**
- `>=` (closed): value at exact boundary **passes**
- `>` (open): value at exact boundary **fails**
- See Rule 1 in Section 3 for when to use which.

---

### 2.5 Boolean Composition

| Operator | DSL | Z3 | Note |
|----------|-----|----|------|
| AND | `expr_a & expr_b` | `z3.And(a, b)` | Must wrap each operand in parentheses |
| OR | `expr_a \| expr_b` | `z3.Or(a, b)` | Must wrap each operand in parentheses |
| NOT | `~expr_a` | `z3.Not(a)` | Prefix operator |

**Do not use Python `and`, `or`, `not`:**

```python
# WRONG -- Python evaluates this as boolean truthiness, not Z3 expression
E(cls.amount) > 0 and E(cls.balance) >= E(cls.amount)

# CORRECT -- Z3 AND composition
(E(cls.amount) > 0) & (E(cls.balance) >= E(cls.amount))
```

**Why:** Python's `and` / `or` call `__bool__` on the left operand. Pramanix's `ConstraintExpr.__bool__` raises `PolicyCompilationError` to catch this mistake at compile time.

---

### 2.6 `.named(label)` and `.explain(template)`

- Every constraint **must** call `.named()`. A constraint without a name raises `PolicyCompilationError` at `Guard.__init__()` time.
- `.named()` label appears in `Decision.violated_invariants` and in structured logs.
- `.explain()` is optional. Its template uses `{field_name}` placeholders substituted with actual values at BLOCK time.

```python
(E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
.named("minimum_reserve_floor")
.explain("Overdraft: balance={balance}, amount={amount}, reserve={minimum_reserve}")
```

**Naming conventions:**
- Use snake_case.
- Names must be unique within the policy. Duplicates raise `PolicyCompilationError`.
- Names appear in audit logs, so make them human-readable and specific.

---

### 2.7 `.is_in(values)`

- Produces an OR expression: `(var == v1) | (var == v2) | ...`
- Use for enum-style field validation.

```python
# Allow only specific currencies
E(cls.currency_code).is_in(["USD", "EUR", "GBP"])
.named("approved_currency")

# Allow only specific role levels
E(cls.access_level).is_in([1, 2, 3])
.named("valid_access_level")
```

- **Empty list raises `PolicyCompilationError`.** `.is_in([])` is always UNSAT and would block every request -- this is almost certainly a programming error, so it is caught at compile time.

---

## 3. Common Mistakes -- 30 Production Rules

These patterns come from adversarial review and real policy bugs found during Phase 3-4 testing.

### Rules 1-5: Boundary Conditions

**Rule 1 -- Use `>=` for floor invariants, never `>`.**
- `balance - amount >= reserve` means: balance after transfer must be AT LEAST reserve.
- `balance - amount > reserve` has a gap: leaving exactly `reserve` passes.
- Gap exploits: attacker finds the exact boundary and operates there repeatedly.

**Rule 2 -- Use `<=` for ceiling invariants, never `<`.**
- `amount <= daily_limit`: exactly hitting the limit is allowed.
- `amount < daily_limit`: someone wanting to spend exactly their daily limit is blocked silently.
- Only use `<` when the boundary value itself must be excluded (e.g., risk score strictly below 1.0).

**Rule 3 -- Test the exact boundary value explicitly.**
- If your floor is `reserve=0.01`, write a test where `balance - amount == 0.01`.
- If your ceiling is `daily_limit=1000`, write a test where `amount == 1000`.
- The closed/open boundary distinction matters most exactly at the boundary.

**Rule 4 -- Never use hardcoded literals for business values.**
- `balance - amount >= Decimal("0.01")` -- what if different accounts have different reserves?
- Drive all business values from fields validated by Pydantic at the state boundary.

**Rule 5 -- Always test zero and near-zero amounts.**
- `amount > 0` blocks zero. Does your policy have this check?
- `amount == 0` can pass many invariants silently (no overdraft, no daily limit exceeded) and represent a no-op transfer that looks valid.

---

### Rules 6-10: Boolean Fields

**Rule 6 -- Compare Bool fields with `== False` / `== True`, not `== 0` / `== 1`.**
- Z3 Bool sort is not an integer. `is_frozen == 0` is a type-mixed comparison.
- Use `(E(cls.is_frozen) == False).named("account_not_frozen")`.
- Add `# noqa: E712` to suppress flake8's "comparison to False" warning -- this is intentional Z3 DSL, not Python.

**Rule 7 -- Do not negate with `~` on non-Bool fields.**
- `~E(cls.amount)` (negation of a Real value) is invalid in Z3.
- For Real/Int fields, express the inverse as a comparison: `E(cls.amount) <= 0`.

**Rule 8 -- Multi-state booleans should be Int enum fields, not Bool.**
- If a field has three states (active, suspended, closed), use `Int` not `Bool`.
- Use `.is_in([0, 1, 2])` or individual invariants per allowed state.

---

### Rules 9-12: Field Design

**Rule 9 -- Name fields to match the values dict key exactly.**
- `Field("amount", ...)` means the caller must pass `values={"amount": ...}`.
- A typo in the Field name causes a `KeyError` at Z3 solve time -- caught as `Decision.error()`, but confusing.

**Rule 10 -- Never use `"Int"` for currency amounts.**
- `Int` sort silently truncates fractional values. `Decimal("99.99")` → `z3.IntVal(99)`.
- All monetary values must use `"Real"` sort.

**Rule 11 -- Keep field names stable across policy versions.**
- Renaming a field is a breaking change for all callers passing that key in `values`.
- If you must rename, add a migration note to the changelog and increment the major version.

**Rule 12 -- Do not declare Fields that are not used in any invariant.**
- Unused fields waste Pydantic validation overhead and confuse readers.
- If a field is for future use, add a comment but not a Field declaration yet.

---

### Rules 13-17: Invariant Design

**Rule 13 -- Every invariant must express a distinct safety property.**
- Do not duplicate invariants. Two invariants that encode the same mathematical constraint add overhead without safety benefit.
- If two invariants are always violated together, consider combining them with `&`.

**Rule 14 -- Complex OR conditions need extra testing.**
- `(A) | (B)` passes if either A or B is satisfied.
- Test the case where A is false and B is true, and the case where A is true and B is false.
- Also test where both are false (should BLOCK) and both are true (should ALLOW).

**Rule 15 -- Do not use invariants to validate input format.**
- Format validation belongs in Pydantic field validators (`@validator`, `@field_validator`).
- Z3 invariants should only express mathematical relationships between already-valid values.

**Rule 16 -- Invariant names must be stable across deployments.**
- Names appear in decision audit logs. Renaming them creates audit gaps where old names and new names overlap.
- Treat invariant names the same as a public API: stable across minor versions.

**Rule 17 -- Do not write invariants that are always true or always false.**
- `(E(cls.amount) >= 0) | True` is always SAT and provides no safety guarantee.
- `(E(cls.amount) > E(cls.amount))` is always UNSAT and blocks every request.
- Both are caught by Pramanix's compile-time validation in strict mode.

---

### Rules 18-22: Policy Versioning and Deployment

**Rule 18 -- Always increment Meta.version when invariants change.**
- The version string is embedded in every `Decision.metadata` dict.
- Audit tools and compliance reporters use the version to identify which policy was active at verification time.

**Rule 19 -- Use `expected_policy_hash` in production to detect silent drift.**
- Compute the policy fingerprint with `Guard.policy_hash()` after construction.
- Set `GuardConfig(expected_policy_hash=fingerprint)`.
- If a deployment accidentally runs a different policy class, `Guard.__init__` raises `ConfigurationError` immediately.

**Rule 20 -- Never deploy a new policy to production without first running the full test suite.**
- Even a `>` to `>=` change can activate a latent bypass for edge-case inputs.

**Rule 21 -- Run Hypothesis property-based tests on any new invariant.**
- Hypothesis generates boundary values you would not think to write manually.
- See `tests/property/` for example strategies.

**Rule 22 -- Lock state reads before calling Guard.verify().**
- Pramanix verifies a snapshot. It cannot prevent concurrent modifications.
- Use database row locks (`SELECT FOR UPDATE`) or optimistic concurrency control.
- Only commit the action if Guard returns ALLOW and the lock is still held.

---

### Rules 23-27: Multi-Invariant Interactions

**Rule 23 -- Test all combinations of violations, not just individual ones.**
- If your policy has 4 invariants, test cases where 2 or 3 are violated simultaneously.
- Verify that `violated_invariants` contains all violated constraint names.

**Rule 24 -- Per-invariant solver instances guarantee complete attribution.**
- Pramanix uses the fast-path shared solver first, then per-invariant solvers only on UNSAT.
- This is why `violated_invariants` always contains all violated invariants, not just the minimal core Z3 would return from a shared solver.

**Rule 25 -- Compound constraints can mask individual violations.**
- `(A & B).named("compound")` reports one violation name `compound`, not `A` and `B` separately.
- Prefer separate named invariants for each distinct safety property.
- Compound invariants are acceptable only for properties that are truly inseparable.

**Rule 26 -- Cross-field invariants increase solver complexity.**
- Every additional cross-field comparison adds an O(1) constraint but can increase solver time non-linearly for complex formulas.
- Always test P99 latency after adding cross-field invariants to a production policy.

**Rule 27 -- `is_in` with large lists adds significant solver overhead.**
- `.is_in([...])` expands to an OR of N equalities. Lists of 100+ values can push P99 above the SLA.
- For large allowlists, consider validating them in Pydantic pre-Z3 instead.

---

### Rules 28-30: Testing Discipline

**Rule 28 -- Every policy must have a test for the exact-boundary case.**
- Test where the constraint is exactly satisfied (e.g., `balance - amount == minimum_reserve`).
- This is where closed vs. open boundary bugs hide.

**Rule 29 -- Every policy must have a test where all invariants are satisfied (ALLOW path).**
- And a test where each invariant is individually violated (BLOCK path).
- A policy that always blocks is as broken as one that always allows.

**Rule 30 -- Include at least one Hypothesis test per policy.**
- Use `@given(...)` strategies that generate random amounts, balances, and limits.
- Hypothesis will find the boundary cases you did not think to write manually.
- Minimum required: one strategy covering the main numeric fields.

---

## 4. Policy Versioning

- Every policy must declare `Meta.version`.
- Version is embedded in every `Decision.metadata` dict.
- **Semantic versioning:** `"major.minor"`
  - Increment **major** for any change that narrows invariants (more things blocked) or changes the schema.
  - Increment **minor** for documentation-only changes or new optional fields that do not affect existing invariants.
- Never deploy a new version without running the full test suite (1,821 tests).

```python
class TransferPolicy(Policy):
    class Meta:
        version = "2.0"   # increment when invariants change
        intent_model = TransferIntent
        state_model  = AccountState
```

---

## 5. Primitives Quick Reference

Pre-built constraints from `pramanix.primitives.*`. Each factory returns a `ConstraintExpr` with `.named()` and `.explain()` pre-configured. See [primitives.md](primitives.md) for full documentation with SAT/UNSAT examples.

### Finance (`pramanix.primitives.finance`)

| Primitive | Enforces |
|-----------|----------|
| `NonNegativeBalance(balance, amount)` | `balance - amount >= 0` |
| `UnderDailyLimit(amount, daily_limit)` | `amount <= daily_limit` |
| `UnderSingleTxLimit(amount, tx_limit)` | `amount <= tx_limit` |
| `RiskScoreBelow(score, threshold)` | `score < threshold` |

### FinTech (`pramanix.primitives.fintech`)

| Primitive | Enforces |
|-----------|----------|
| `SufficientBalance(balance, amount)` | balance covers the amount |
| `VelocityCheck(tx_count, max_tx)` | transaction count within window |
| `AntiStructuring(amount, reporting_threshold)` | amount > 10% of reporting threshold (anti-structuring) |
| `WashSaleDetection(buy_date, sell_date, wash_days)` | wash sale window check |
| `CollateralHaircut(collateral, haircut_pct, exposure)` | collateral after haircut covers exposure |
| `MaxDrawdown(current_value, peak_value, max_drawdown_pct)` | drawdown within allowed range |
| `SanctionsScreen(risk_score, threshold)` | risk score below threshold |
| `KYCTierCheck(kyc_tier, required_tier)` | KYC tier meets or exceeds requirement |
| `TradingWindowCheck(current_hour, open_hour, close_hour)` | trade within market hours |
| `MarginRequirement(equity, notional, min_margin_pct)` | margin ratio above minimum |

### RBAC (`pramanix.primitives.rbac`)

| Primitive | Enforces |
|-----------|----------|
| `RoleMustBeIn(role, allowed_roles)` | role is one of the allowed values |
| `ConsentRequired(consent_flag)` | consent flag is True |
| `DepartmentMustBeIn(dept, allowed_depts)` | department is one of the allowed values |

### Healthcare (`pramanix.primitives.healthcare`)

| Primitive | Enforces |
|-----------|----------|
| `PHILeastPrivilege(access_level, max_level)` | access level does not exceed maximum |
| `ConsentActive(consent_status)` | consent status is active |
| `DosageGradientCheck(new_dose, current_dose, max_increase_pct)` | dose increase within safe gradient |
| `BreakGlassAuth(break_glass_flag, auth_code_present)` | break-glass access has authorization code |
| `PediatricDoseBound(dose_mg_per_kg, weight_kg, max_mg_per_kg)` | pediatric dose within safe bound |

### Infrastructure (`pramanix.primitives.infra`)

| Primitive | Enforces |
|-----------|----------|
| `MinReplicas(replicas, min_replicas)` | replica count does not go below minimum |
| `MaxReplicas(replicas, max_replicas)` | replica count does not exceed maximum |
| `WithinCPUBudget(cpu_request, cpu_limit)` | CPU request within budget |
| `WithinMemoryBudget(mem_request, mem_limit)` | memory request within budget |
| `BlastRadiusCheck(affected_instances, max_blast_radius)` | affected instance count within limit |
| `CircuitBreakerState(error_rate, threshold)` | error rate below circuit breaker threshold |
| `ProdDeployApproval(approval_count, required_approvals)` | deployment has required approvals |
| `ReplicaBudget(requested, available)` | requested replicas within available budget |
| `CPUMemoryGuard(cpu_pct, mem_pct, cpu_limit, mem_limit)` | both CPU and memory within limits |

### Time (`pramanix.primitives.time`)

| Primitive | Enforces |
|-----------|----------|
| `WithinTimeWindow(current, window_start, window_end)` | current timestamp within window |
| `After(current, earliest)` | current timestamp is after earliest |
| `Before(current, deadline)` | current timestamp is before deadline |
| `NotExpired(expiry_ts, current_ts)` | token or credential has not expired |

### Common (`pramanix.primitives.common`)

| Primitive | Enforces |
|-----------|----------|
| `NotSuspended(is_suspended)` | account/entity is not suspended |
| `StatusMustBe(status, required_status)` | status matches exactly one required value |
| `FieldMustEqual(field, expected_value)` | field equals expected value |

---

## 6. Multi-Policy Composition Patterns

### Pattern 1 -- Layered Policies (Sequential)

Run two policies in sequence. Both must return ALLOW.

```python
from pramanix import Guard, GuardConfig

fraud_guard  = Guard(FraudPolicy,  GuardConfig())
limits_guard = Guard(LimitsPolicy, GuardConfig())

def verify_transfer(intent: dict, state: dict):
    fraud_decision = fraud_guard.verify(intent=intent, state=state)
    if not fraud_decision.allowed:
        return fraud_decision  # return immediately on BLOCK

    limits_decision = limits_guard.verify(intent=intent, state=state)
    return limits_decision  # return ALLOW only if both pass
```

**When to use:** Different teams own different policies (fraud team owns FraudPolicy, risk team owns LimitsPolicy). Separate test suites. Separate deployment cycles.

---

### Pattern 2 -- Single Composite Policy

Merge all invariants into one policy class. One Z3 solve covers all invariants.

```python
class CompositeTransferPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = TransferIntent
        state_model  = AccountState

    # Fields from both fraud and limits policies
    amount          = Field("amount",          Decimal, "Real")
    balance         = Field("balance",         Decimal, "Real")
    daily_limit     = Field("daily_limit",     Decimal, "Real")
    risk_score      = Field("risk_score",      Decimal, "Real")
    is_frozen       = Field("is_frozen",       bool,    "Bool")

    @classmethod
    def invariants(cls):
        from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit
        from pramanix.primitives.fintech import RiskScoreBelow
        return [
            NonNegativeBalance(cls.balance, cls.amount),
            UnderDailyLimit(cls.amount, cls.daily_limit),
            RiskScoreBelow(cls.risk_score, Decimal("0.75")),
            (E(cls.is_frozen) == False).named("account_not_frozen"),
        ]
```

**When to use:** All invariants are owned by one team. Single test suite. Lower latency (one Z3 solve vs. N).

---

### Pattern 3 -- Tiered Policies (Conditional Routing)

Different policies for different transaction types or risk tiers.

```python
def get_policy_for_tier(tier: str) -> type[Policy]:
    return {
        "retail": RetailTransferPolicy,
        "institutional": InstitutionalTransferPolicy,
        "internal": InternalTransferPolicy,
    }[tier]

guards = {
    tier: Guard(policy)
    for tier, policy in [
        ("retail", RetailTransferPolicy),
        ("institutional", InstitutionalTransferPolicy),
        ("internal", InternalTransferPolicy),
    ]
}

def verify_tiered(intent: dict, state: dict, tier: str):
    return guards[tier].verify(intent=intent, state=state)
```

**Guard instances are created once at startup and reused. Never create a Guard per request -- that triggers policy recompilation on every call.**

---

### Pattern 4 -- Policy Inheritance

Extend a base policy with additional invariants.

```python
class BaseTransferPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = TransferIntent
        state_model  = AccountState

    amount  = Field("amount",  Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= 0).named("non_negative_balance"),
        ]


class HighRiskTransferPolicy(BaseTransferPolicy):
    class Meta:
        version = "1.0"
        intent_model = TransferIntent
        state_model  = HighRiskAccountState

    risk_score = Field("risk_score", Decimal, "Real")
    kyc_tier   = Field("kyc_tier",   int,     "Int")

    @classmethod
    def invariants(cls):
        return super().invariants() + [
            (E(cls.risk_score) < Decimal("0.5")).named("risk_score_low"),
            (E(cls.kyc_tier) >= 2).named("minimum_kyc_tier"),
        ]
```

**Important:** Always call `super().invariants()` and extend the list. Do not call `super().invariants()` in a method that overrides it without including the parent invariants.

---

## 7. Phase 12 Hardening in Policies

### Using `expected_policy_hash` (H09)

```python
# Step 1: compute the hash of your policy class after development
import hashlib, json
guard = Guard(TransferPolicy)
print(guard.policy_hash())  # e.g., "a3f2b1c9..."

# Step 2: pin it in GuardConfig for all production deployments
config = GuardConfig(expected_policy_hash="a3f2b1c9...")
guard  = Guard(TransferPolicy, config=config)
# If TransferPolicy has been modified or a different class is used,
# Guard.__init__() raises ConfigurationError immediately.
```

### Using `redact_violations` (H04)

```python
# Production: do not expose which invariant failed to callers
config = GuardConfig(redact_violations=True)
guard  = Guard(TransferPolicy, config=config)

decision = guard.verify(intent=..., state=...)
# If BLOCK:
# decision.explanation       = "Policy Violation: Action Blocked"
# decision.violated_invariants = ()
# But on the server side, the audit log has the full unredacted details.
# decision.decision_hash is computed over the real fields before redaction.
```

### Using `min_response_ms` (H13)

```python
# Pad all responses to minimum 50 ms to prevent timing side-channels
config = GuardConfig(min_response_ms=50.0)
guard  = Guard(TransferPolicy, config=config)
# ALLOW decisions (which can be faster) are padded to 50 ms
# BLOCK decisions (which can be slower due to per-invariant attribution) vary less
```

---

## 8. Pre-Merge Policy Checklist

Before merging any new or changed policy:

- [ ] All invariants have `.named()` -- no unnamed constraints
- [ ] All floor invariants use `>=` (not `>`)
- [ ] All ceiling invariants use `<=` (not `<`)
- [ ] `minimum_reserve` and similar threshold values are `Field` declarations, not hardcoded literals
- [ ] `bool` fields compare with `== True` / `== False`, not integers
- [ ] A test exists for the exact boundary value
- [ ] A test exists where all invariants are satisfied (ALLOW path)
- [ ] A test exists for each invariant individually violated (BLOCK path)
- [ ] `Meta.version` has been incremented
- [ ] At least one Hypothesis property-based test is present
- [ ] Full test suite (1,821 tests) passes with zero failures
