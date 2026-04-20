# Pramanix -- Primitives Library Reference

> **Version:** v0.9.0
> **Import path:** `pramanix.primitives.*`
> Each primitive factory returns a `ConstraintExpr` with `.named()` and `.explain()` pre-configured, ready to include in a `Policy.invariants()` list.

---

## How to Use Primitives

```python
from decimal import Decimal
from pramanix import Policy, Field
from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit

class BankingPolicy(Policy):
    balance     = Field("balance",     Decimal, "Real")
    amount      = Field("amount",      Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            NonNegativeBalance(cls.balance, cls.amount),
            UnderDailyLimit(cls.amount, cls.daily_limit),
        ]
```

- Primitives accept `Field` references as arguments, not values.
- All primitives assign a default `.named()` label. You can call `.named("custom_name")` to override.
- Combine primitives freely with custom invariants in the same list.

---

## Finance Primitives

**Import:** `from pramanix.primitives.finance import ...`

---

### `NonNegativeBalance(balance, amount)`

**DSL:** `(E(balance) - E(amount) >= 0)`
**Label:** `non_negative_balance`
**What it enforces:** Post-transaction balance must be non-negative.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT (normal transfer) | balance=1000, amount=500 | ALLOW: 1000 - 500 = 500 >= 0 |
| UNSAT (overdraft) | balance=100, amount=200 | BLOCK: 100 - 200 = -100 < 0 |
| SAT (boundary exact) | balance=100, amount=100 | ALLOW: 100 - 100 = 0 >= 0 |

---

### `UnderDailyLimit(amount, daily_limit)`

**DSL:** `(E(amount) <= E(daily_limit))`
**Label:** `under_daily_limit`
**What it enforces:** Transaction amount does not exceed the daily transfer cap.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT (within limit) | amount=500, daily_limit=1000 | ALLOW |
| SAT (exact limit) | amount=1000, daily_limit=1000 | ALLOW |
| UNSAT (over limit) | amount=1001, daily_limit=1000 | BLOCK |

---

### `UnderSingleTxLimit(amount, tx_limit)`

**DSL:** `(E(amount) <= E(tx_limit))`
**Label:** `under_single_tx_limit`
**What it enforces:** Transaction amount does not exceed the per-transaction cap.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | amount=4999, tx_limit=5000 | ALLOW |
| SAT (exact) | amount=5000, tx_limit=5000 | ALLOW |
| UNSAT | amount=5001, tx_limit=5000 | BLOCK |

---

### `RiskScoreBelow(risk_score, threshold)`

**DSL:** `(E(risk_score) < E(threshold))`
**Label:** `risk_score_below_threshold`
**What it enforces:** Computed risk score is strictly below the danger threshold. Uses strict `<` -- a risk score exactly at the threshold is blocked.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | risk_score=0.4, threshold=0.75 | ALLOW |
| UNSAT (at threshold) | risk_score=0.75, threshold=0.75 | BLOCK |
| UNSAT (above) | risk_score=0.80, threshold=0.75 | BLOCK |

---

### `SecureBalance(balance, amount, minimum_reserve)`

**DSL:** `(E(balance) - E(amount) >= E(minimum_reserve))`
**Label:** `minimum_reserve_maintained`
**What it enforces:** Post-transaction balance stays at or above the minimum reserve floor. Use this instead of `NonNegativeBalance` for policies that require a non-zero residual.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | balance=1000, amount=900, reserve=10 | ALLOW: 1000-900=100 >= 10 |
| UNSAT (below reserve) | balance=1000, amount=995, reserve=10 | BLOCK: 1000-995=5 < 10 |
| SAT (at reserve boundary) | balance=1000, amount=990, reserve=10 | ALLOW: 1000-990=10 >= 10 |

---

### `MinimumReserve(balance, amount, minimum_reserve)`

**Alias for `SecureBalance`.** Identical semantics. Use when the field is named `minimum_reserve` for readability.

---

## FinTech Primitives

**Import:** `from pramanix.primitives.fintech import ...`

These primitives carry regulatory references embedded in their `.explain()` text.

---

### `SufficientBalance(balance, amount)`

**DSL:** `(E(balance) - E(amount) >= 0)`
**Label:** `sufficient_balance`
**Regulatory:** BSA / Reg. E pre-authorization balance check
**What it enforces:** Balance covers the requested transfer. BSA-aware explanation text.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | balance=500, amount=100 | ALLOW |
| UNSAT | balance=50, amount=100 | BLOCK |

---

### `VelocityCheck(tx_count, window_limit)`

**DSL:** `(E(tx_count) <= window_limit)`
**Label:** `velocity_check`
**Regulatory:** EBA PSD2 / Reg. E velocity-monitoring guidance
**Note:** `window_limit` is a literal integer, not a Field.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | tx_count=3, window_limit=5 | ALLOW |
| SAT (at limit) | tx_count=5, window_limit=5 | ALLOW |
| UNSAT | tx_count=6, window_limit=5 | BLOCK |

---

### `AntiStructuring(cumulative_amount, threshold)`

**DSL:** `(E(cumulative_amount) < threshold)`
**Label:** `anti_structuring`
**Regulatory:** 31 CFR § 1020.320 (BSA Currency Transaction Report structuring rule)
**Note:** `threshold` is a `Decimal` literal (typically `Decimal("10000")` for USD CTR). VIOLATION (UNSAT) indicates the cumulative amount has reached the CTR filing threshold. `AntiStructuring` is a policy gate, not a SAR filing system. Route violations to your SAR evaluation workflow separately and use the Pramanix violation log as the trigger signal.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT (below threshold) | cumulative_amount=9999, threshold=10000 | ALLOW |
| UNSAT (at threshold) | cumulative_amount=10000, threshold=10000 | BLOCK: SAR-worthy |
| UNSAT (above) | cumulative_amount=15000, threshold=10000 | BLOCK |

---

### `WashSaleDetection(sell_epoch, buy_epoch, wash_window_days=30)`

**DSL:** `(E(sell) - E(buy) >= window_secs) | (E(buy) - E(sell) >= window_secs)`
**Label:** `wash_sale_detection`
**Regulatory:** IRC § 1091 (30-day wash-sale disallowance window)
**Note:** Uses Unix epoch integers. The absolute-value condition is expressed as a disjunction because Z3 has no symbolic `abs()`.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT (outside window) | sell_epoch=1740000000, buy_epoch=1737000000 (35 days apart) | ALLOW |
| UNSAT (inside window) | sell_epoch=1740000000, buy_epoch=1739500000 (6 days apart) | BLOCK |

---

### `CollateralHaircut(collateral_value, loan_value, haircut_pct)`

**DSL:** `(E(collateral_value) * (1 - haircut_pct) >= E(loan_value))`
**Label:** `collateral_haircut`
**Regulatory:** Basel III LCR / ISDA CSA haircut schedule
**Note:** `haircut_pct` is a `Decimal` in `[0, 1)`. Typical values: G10 govvies 0-2%, IG corps 5-15%, equities 15-25%.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | collateral=1200, loan=1000, haircut=0.10 | ALLOW: 1200*(1-0.10)=1080 >= 1000 |
| UNSAT | collateral=1000, loan=1000, haircut=0.10 | BLOCK: 1000*(1-0.10)=900 < 1000 |

---

### `MaxDrawdown(current_nav, peak_nav, max_drawdown_pct)`

**DSL:** `(E(peak_nav) - E(current_nav) <= max_drawdown_pct * E(peak_nav))`
**Label:** `max_drawdown`
**Regulatory:** AIFMD Annex IV / NFA CFTC CPO drawdown disclosure
**Note:** Division avoided to prevent Z3 non-linear performance issues. Equivalent to `(peak - current) / peak <= max_pct` assuming `peak > 0`.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | current_nav=900, peak_nav=1000, max_pct=0.20 | ALLOW: 1000-900=100 <= 0.20*1000=200 |
| UNSAT | current_nav=700, peak_nav=1000, max_pct=0.20 | BLOCK: 1000-700=300 > 200 |

---

### `SanctionsScreen(counterparty_status)`

**DSL:** `(E(counterparty_status) != "SANCTIONED")`
**Label:** `sanctions_screen`
**Regulatory:** 31 CFR § 501.805 (OFAC SDN list)
**Note:** Field must be `Field(..., str, "String")`. Supported states: `"CLEAR"`, `"SANCTIONED"`, `"REVIEW"`.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | counterparty_status="CLEAR" | ALLOW |
| SAT | counterparty_status="REVIEW" | ALLOW -- "REVIEW" is not "SANCTIONED", so it passes |
| UNSAT | counterparty_status="SANCTIONED" | BLOCK |

> **Note:** `SanctionsScreen` only blocks `"SANCTIONED"`. A `"REVIEW"` status is **not** blocked by default -- it passes the `!= "SANCTIONED"` check. For strict mode (block both "SANCTIONED" and "REVIEW"), use a separate invariant: `(E(cls.status) == "CLEAR").named("sanctions_clear_only")`. See [compliance.md](compliance.md) for a full StrictSanctionsPolicy example.

---

### `KYCTierCheck(kyc_tier, required_tier)`

**DSL:** `(E(kyc_tier) >= E(required_tier))`
**Label:** `kyc_tier_check`
**Regulatory:** FATF Recommendation 10 / FinCEN CDD rule
**Note:** Integer-encoded tiers. Higher value = higher verification level.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | kyc_tier=3, required_tier=2 | ALLOW |
| SAT (exact) | kyc_tier=2, required_tier=2 | ALLOW |
| UNSAT | kyc_tier=1, required_tier=2 | BLOCK |

---

### `TradingWindowCheck(current_hour, open_hour, close_hour)`

**DSL:** `(E(current_hour) >= E(open_hour)) & (E(current_hour) <= E(close_hour))`
**Label:** `trading_window_check`
**Regulatory:** SEC Rule 10b5-1 / FINRA MRVP trading window
**Note:** Integer-encoded hour of day (0-23).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | current_hour=10, open=9, close=16 | ALLOW |
| UNSAT (before open) | current_hour=8, open=9, close=16 | BLOCK |
| UNSAT (after close) | current_hour=17, open=9, close=16 | BLOCK |

---

### `MarginRequirement(equity, notional, min_margin_pct)`

**DSL:** `(E(equity) >= min_margin_pct * E(notional))`
**Label:** `margin_requirement`
**Regulatory:** Reg. T (12 CFR § 220) initial margin
**Note:** `min_margin_pct` is a `Decimal` literal (e.g., `Decimal("0.25")` for 25% Reg. T).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | equity=30000, notional=100000, min_pct=0.25 | ALLOW: 30000 >= 0.25*100000=25000 |
| UNSAT | equity=20000, notional=100000, min_pct=0.25 | BLOCK: 20000 < 25000 |

---

## RBAC Primitives

**Import:** `from pramanix.primitives.rbac import ...`

---

### `RoleMustBeIn(role, allowed_roles)`

**DSL:** `E(role).is_in(allowed_roles)`
**Label:** `role_must_be_in_allowed_set`
**Note:** Roles must be integer-encoded (Z3 has no string sort). Maintain a mapping constant (`CLINICIAN=1, NURSE=2, ADMIN=3`).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | role=1 (CLINICIAN), allowed=[1,2,3] | ALLOW |
| UNSAT | role=5 (UNKNOWN), allowed=[1,2,3] | BLOCK |

---

### `ConsentRequired(consent)`

**DSL:** `(E(consent) == True)`
**Label:** `consent_required`
**Note:** Field must be `Bool`-sorted. Blocks if consent is `False`.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | consent=True | ALLOW |
| UNSAT | consent=False | BLOCK |

---

### `DepartmentMustBeIn(department, allowed_departments)`

**DSL:** `E(department).is_in(allowed_departments)`
**Label:** `department_must_be_in_allowed_set`
**Note:** Department must be integer-encoded.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | department=2, allowed=[1,2,4] | ALLOW |
| UNSAT | department=3, allowed=[1,2,4] | BLOCK |

---

## Healthcare Primitives

**Import:** `from pramanix.primitives.healthcare import ...`

---

### `PHILeastPrivilege(requestor_role, allowed_roles)`

**DSL:** `E(requestor_role).is_in(allowed_roles)`
**Label:** `phi_least_privilege`
**Regulatory:** HIPAA 45 CFR § 164.502(b) (minimum-necessary rule)
**Note:** Role must be integer-encoded (`CLINICIAN=1, NURSE=2, ADMIN=3, AUDITOR=4`).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | requestor_role=1 (CLINICIAN), allowed=[1,2] | ALLOW |
| UNSAT | requestor_role=3 (ADMIN), allowed=[1,2] | BLOCK |

---

### `ConsentActive(consent_status, consent_expiry_epoch, current_epoch)`

**DSL:** `(E(consent_status) == "ACTIVE") & (E(consent_expiry_epoch) > current_epoch)`
**Label:** `consent_active`
**Regulatory:** HIPAA 45 CFR § 164.508 (authorization expiry)
**Note:** `consent_status` is a `String`-sorted field. Supported states: `"ACTIVE"`, `"REVOKED"`, `"EXPIRED"`. `current_epoch` is a literal int (request timestamp).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | status="ACTIVE", expiry=9999999999, current=1735000000 | ALLOW |
| UNSAT (revoked) | status="REVOKED", expiry=9999999999, current=1735000000 | BLOCK |
| UNSAT (expired) | status="ACTIVE", expiry=1700000000, current=1735000000 | BLOCK |

---

### `DosageGradientCheck(new_dose, current_dose, max_increase_pct)`

**DSL:** `(E(new_dose) <= E(current_dose) * (1 + max_increase_pct))`
**Label:** `dosage_gradient_check`
**Regulatory:** Joint Commission NPSG 03.06.01 (titration safety)
**Note:** `max_increase_pct` is a `Decimal` (e.g., `Decimal("0.25")` for max 25% increase). Prevents sudden dangerous dose escalations.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | new_dose=120, current_dose=100, max_pct=0.25 | ALLOW: 120 <= 100*1.25=125 |
| UNSAT | new_dose=130, current_dose=100, max_pct=0.25 | BLOCK: 130 > 125 |

---

### `BreakGlassAuth(break_glass_flag, auth_code_present)`

**DSL:** `~E(break_glass_flag) | E(auth_code_present)`
**Label:** `break_glass_auth`
**Regulatory:** HIPAA 45 CFR § 164.312(a)(2)(ii) (emergency access procedure)
**Note:** If `break_glass_flag=True` (emergency access requested), `auth_code_present` must also be `True`. If break_glass is not requested, the invariant is trivially satisfied.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT (normal access) | break_glass=False, auth_code=False | ALLOW |
| SAT (authorized emergency) | break_glass=True, auth_code=True | ALLOW |
| UNSAT (unauthorized emergency) | break_glass=True, auth_code=False | BLOCK |

---

### `PediatricDoseBound(dose_mg_per_kg, weight_kg, max_mg_per_kg)`

**DSL:** `(E(dose_mg_per_kg) * E(weight_kg) <= max_mg_per_kg * E(weight_kg))`
**Simplified DSL:** `(E(dose_mg_per_kg) <= max_mg_per_kg)`
**Label:** `pediatric_dose_bound`
**Regulatory:** AAP / FDA weight-based pediatric dosing cap
**Note:** `max_mg_per_kg` is a `Decimal` literal. Enforces that the prescribed dose per kilogram does not exceed the weight-based safety cap.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | dose=10, weight=20kg, max=15 mg/kg | ALLOW: 10 <= 15 |
| UNSAT | dose=20, weight=20kg, max=15 mg/kg | BLOCK: 20 > 15 |

---

## Infrastructure Primitives

**Import:** `from pramanix.primitives.infra import ...`

---

### `MinReplicas(replicas, min_replicas)`

**DSL:** `(E(replicas) >= E(min_replicas))`
**Label:** `min_replicas`
**What it enforces:** Scale-down operations cannot reduce replica count below the configured minimum.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | replicas=3, min_replicas=2 | ALLOW |
| SAT (at minimum) | replicas=2, min_replicas=2 | ALLOW |
| UNSAT | replicas=1, min_replicas=2 | BLOCK |

---

### `MaxReplicas(replicas, max_replicas)`

**DSL:** `(E(replicas) <= E(max_replicas))`
**Label:** `max_replicas`
**What it enforces:** Scale-up operations cannot exceed the maximum replica cap.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | replicas=8, max_replicas=10 | ALLOW |
| SAT (at maximum) | replicas=10, max_replicas=10 | ALLOW |
| UNSAT | replicas=11, max_replicas=10 | BLOCK |

---

### `WithinCPUBudget(cpu_request, cpu_limit)`

**DSL:** `(E(cpu_request) <= E(cpu_limit))`
**Label:** `within_cpu_budget`
**What it enforces:** CPU resource request does not exceed the configured budget (in millicores).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | cpu_request=500m, cpu_limit=1000m | ALLOW |
| UNSAT | cpu_request=1500m, cpu_limit=1000m | BLOCK |

---

### `WithinMemoryBudget(mem_request, mem_limit)`

**DSL:** `(E(mem_request) <= E(mem_limit))`
**Label:** `within_memory_budget`
**What it enforces:** Memory resource request does not exceed the configured budget (in MiB).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | mem_request=256, mem_limit=512 | ALLOW |
| UNSAT | mem_request=600, mem_limit=512 | BLOCK |

---

### `BlastRadiusCheck(affected_instances, max_blast_radius)`

**DSL:** `(E(affected_instances) <= E(max_blast_radius))`
**Label:** `blast_radius_check`
**What it enforces:** A deployment or configuration change cannot affect more instances than the configured blast radius cap. Prevents runaway rollouts.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | affected=5, max_blast_radius=10 | ALLOW |
| UNSAT | affected=15, max_blast_radius=10 | BLOCK |

---

### `CircuitBreakerState(error_rate, threshold)`

**DSL:** `(E(error_rate) < E(threshold))`
**Label:** `circuit_breaker_state`
**What it enforces:** Service error rate is below the circuit breaker threshold. Blocks operations when the downstream service is unhealthy. Uses strict `<` -- exactly at threshold triggers the breaker.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | error_rate=0.03, threshold=0.05 | ALLOW |
| UNSAT (at threshold) | error_rate=0.05, threshold=0.05 | BLOCK |
| UNSAT | error_rate=0.10, threshold=0.05 | BLOCK |

---

### `ProdDeployApproval(approval_count, required_approvals)`

**DSL:** `(E(approval_count) >= E(required_approvals))`
**Label:** `prod_deploy_approval`
**What it enforces:** Production deployment has received the required number of approvals (4-eyes principle). Integer fields.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | approval_count=2, required_approvals=2 | ALLOW |
| UNSAT | approval_count=1, required_approvals=2 | BLOCK |

---

### `ReplicaBudget(requested, available)`

**DSL:** `(E(requested) <= E(available))`
**Label:** `replica_budget`
**What it enforces:** Requested replica count does not exceed available capacity.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | requested=5, available=8 | ALLOW |
| UNSAT | requested=10, available=8 | BLOCK |

---

### `CPUMemoryGuard(cpu_pct, mem_pct, cpu_limit, mem_limit)`

**DSL:** `(E(cpu_pct) <= E(cpu_limit)) & (E(mem_pct) <= E(mem_limit))`
**Label:** `cpu_memory_guard`
**What it enforces:** Both CPU utilization percentage and memory utilization percentage are within their respective limits. Composite single-invariant guard for resource headroom.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | cpu_pct=60, mem_pct=70, cpu_limit=80, mem_limit=80 | ALLOW |
| UNSAT (CPU over) | cpu_pct=90, mem_pct=70, cpu_limit=80, mem_limit=80 | BLOCK |
| UNSAT (both over) | cpu_pct=90, mem_pct=90, cpu_limit=80, mem_limit=80 | BLOCK |

---

## Time Primitives

**Import:** `from pramanix.primitives.time import ...`

---

### `WithinTimeWindow(current, window_start, window_end)`

**DSL:** `(E(current) >= E(window_start)) & (E(current) <= E(window_end))`
**Label:** `within_time_window`
**Note:** All fields are integer Unix timestamps.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | current=1735000000, start=1734000000, end=1736000000 | ALLOW |
| UNSAT (before window) | current=1733000000, start=1734000000, end=1736000000 | BLOCK |
| UNSAT (after window) | current=1737000000, start=1734000000, end=1736000000 | BLOCK |

---

### `After(current, earliest)`

**DSL:** `(E(current) >= E(earliest))`
**Label:** `after_earliest`
**What it enforces:** Current timestamp is at or after the earliest allowed time (embargo check, scheduled release, etc.).

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | current=1735000000, earliest=1734000000 | ALLOW |
| UNSAT | current=1733000000, earliest=1734000000 | BLOCK |

---

### `Before(current, deadline)`

**DSL:** `(E(current) <= E(deadline))`
**Label:** `before_deadline`
**What it enforces:** Current timestamp is at or before the deadline.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | current=1735000000, deadline=1736000000 | ALLOW |
| UNSAT | current=1737000000, deadline=1736000000 | BLOCK |

---

### `NotExpired(expiry_ts, current_ts)`

**DSL:** `(E(expiry_ts) > E(current_ts))`
**Label:** `not_expired`
**What it enforces:** Token, credential, or authorization has not expired. Uses strict `>` -- expiry at exactly the current time means expired.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | expiry=1736000000, current=1735000000 | ALLOW |
| UNSAT (exactly expired) | expiry=1735000000, current=1735000000 | BLOCK |
| UNSAT (past expiry) | expiry=1734000000, current=1735000000 | BLOCK |

---

## Common Primitives

**Import:** `from pramanix.primitives.common import ...`

---

### `NotSuspended(is_suspended)`

**DSL:** `(E(is_suspended) == False)`
**Label:** `not_suspended`
**Note:** `Bool`-sorted field. Blocks if the account or entity is suspended.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | is_suspended=False | ALLOW |
| UNSAT | is_suspended=True | BLOCK |

---

### `StatusMustBe(status, required_status)`

**DSL:** `(E(status) == required_status)`
**Label:** `status_must_be`
**Note:** `required_status` is a literal value. Status field must match exactly.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | status=1 (ACTIVE), required=1 | ALLOW |
| UNSAT | status=2 (INACTIVE), required=1 | BLOCK |

---

### `FieldMustEqual(field, expected_value)`

**DSL:** `(E(field) == expected_value)`
**Label:** `field_must_equal`
**What it enforces:** A field must match a specific value exactly. General-purpose equality gate.

| Scenario | Values | Result |
|----------|--------|--------|
| SAT | field=42, expected_value=42 | ALLOW |
| UNSAT | field=43, expected_value=42 | BLOCK |

---

## Complete Primitive Count

| Domain | Primitives |
|--------|-----------|
| Finance | NonNegativeBalance, UnderDailyLimit, UnderSingleTxLimit, RiskScoreBelow, SecureBalance, MinimumReserve |
| FinTech | SufficientBalance, VelocityCheck, AntiStructuring, WashSaleDetection, CollateralHaircut, MaxDrawdown, SanctionsScreen, KYCTierCheck, TradingWindowCheck, MarginRequirement |
| RBAC | RoleMustBeIn, ConsentRequired, DepartmentMustBeIn |
| Healthcare | PHILeastPrivilege, ConsentActive, DosageGradientCheck, BreakGlassAuth, PediatricDoseBound |
| Infrastructure | MinReplicas, MaxReplicas, WithinCPUBudget, WithinMemoryBudget, BlastRadiusCheck, CircuitBreakerState, ProdDeployApproval, ReplicaBudget, CPUMemoryGuard |
| Time | WithinTimeWindow, After, Before, NotExpired |
| Common | NotSuspended, StatusMustBe, FieldMustEqual |
