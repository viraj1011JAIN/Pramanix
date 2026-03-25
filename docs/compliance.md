# Pramanix -- Compliance Patterns

> **Version:** v0.8.0
> **Audience:** Compliance engineers, legal teams, and architects implementing regulated workflows.
> **Prerequisite:** Read [primitives.md](primitives.md) for the pre-built constraints used in these examples.

---

## Overview

- Pramanix policies produce formal proofs (Z3 SAT/UNSAT) for every decision.
- Every decision is immutably recorded with a SHA-256 hash and optional Ed25519 signature.
- The audit trail is tamper-evident via Merkle chaining.
- Regulators can request the decision log and verify it offline using `pramanix audit verify`.

---

## 1. HIPAA -- Protected Health Information

**Applicable regulations:**
- HIPAA 45 CFR § 164.502(b) -- minimum-necessary access rule
- HIPAA 45 CFR § 164.308(a)(3) -- workforce access controls
- HIPAA 45 CFR § 164.508 -- authorization expiry for non-TPO disclosures
- HIPAA 45 CFR § 164.312(a)(2)(ii) -- emergency access procedure (break-glass)

### PHI Access Policy

```python
from decimal import Decimal
from pramanix import Guard, GuardConfig, Policy, Field
from pramanix.primitives.healthcare import PHILeastPrivilege, ConsentActive, BreakGlassAuth
import time

# Role encoding (Z3 has no string sort)
CLINICIAN = 1
NURSE     = 2
ADMIN     = 3
AUDITOR   = 4

class PHIAccessPolicy(Policy):
    class Meta:
        version = "1.0"

    requestor_role        = Field("requestor_role",        int,  "Int")
    consent_status        = Field("consent_status",        str,  "String")
    consent_expiry_epoch  = Field("consent_expiry_epoch",  int,  "Int")
    # current_epoch MUST be a field, not a literal -- it is evaluated at
    # request time, not at policy compilation time. Passing int(time.time())
    # as a constructor argument would bake in the startup timestamp and make
    # every decision after startup check against a stale clock.
    current_epoch         = Field("current_epoch",         int,  "Int")
    break_glass_flag      = Field("break_glass_flag",      bool, "Bool")
    auth_code_present     = Field("auth_code_present",     bool, "Bool")

    @classmethod
    def invariants(cls):
        return [
            PHILeastPrivilege(cls.requestor_role, [CLINICIAN, NURSE]),
            ConsentActive(cls.consent_status, cls.consent_expiry_epoch,
                         cls.current_epoch),
            BreakGlassAuth(cls.break_glass_flag, cls.auth_code_present),
        ]

guard = Guard(PHIAccessPolicy, GuardConfig())

# Normal PHI access by nurse
decision = guard.verify(
    intent={"requestor_role": NURSE},
    state={
        "consent_status": "ACTIVE",
        "consent_expiry_epoch": int(time.time()) + 86400,  # expires tomorrow
        "current_epoch": int(time.time()),                 # evaluated at request time
        "break_glass_flag": False,
        "auth_code_present": False,
    }
)
# decision.allowed = True

# Admin trying to access PHI (minimum-necessary violation)
decision = guard.verify(
    intent={"requestor_role": ADMIN},
    state={
        "consent_status": "ACTIVE",
        "consent_expiry_epoch": int(time.time()) + 86400,
        "current_epoch": int(time.time()),
        "break_glass_flag": False,
        "auth_code_present": False,
    }
)
# decision.allowed = False
# decision.violated_invariants = ("phi_least_privilege",)
```

### HIPAA Audit Log Pattern

- Configure `GuardConfig(signer=PramanixSigner.generate())` to produce Ed25519-signed decisions
- Store every decision JSON in immutable audit storage (e.g., AWS S3 + Object Lock, Azure Blob + Immutable Storage)
- The `decision_hash` field is the primary audit record identifier
- Run `pramanix audit verify decisions.jsonl --public-key public.pem` for periodic chain verification

### HIPAA-Specific Notes

- **Minimum-necessary enforcement:** `PHILeastPrivilege` enforces role-based access. Any role not in `allowed_roles` produces a provably blocked decision with the violation logged.
- **Consent expiry:** `ConsentActive` checks both status (`"ACTIVE"`) and expiry timestamp. A revoked consent produces a violation even if the expiry date has not passed. HIPAA § 164.508(b)(5) requires immediate effect of patient revocation.
- **Break-glass:** `BreakGlassAuth` ensures emergency access requires an authorization code. The break-glass flag and authorization result are recorded in the decision audit log.
- **Minimum security standard:** For covered entities, configure `GuardConfig(redact_violations=True)` only for external-facing APIs. Internal audit systems must receive unredacted violation details for HIPAA audit trail requirements.

---

## 2. BSA/AML -- Bank Secrecy Act / Anti-Money Laundering

**Applicable regulations:**
- 31 CFR § 1020.320 -- Currency Transaction Report (CTR) structuring (31 U.S.C. 5324)
- 31 CFR § 1010.311 -- CTR filing threshold ($10,000)
- FinCEN Customer Due Diligence (CDD) rule -- KYC tier requirements
- EBA PSD2 / Reg. E -- transaction velocity monitoring

### Wire Transfer Policy with BSA Controls

```python
from decimal import Decimal
from pramanix import Guard, GuardConfig, Policy, Field
from pramanix.primitives.fintech import (
    SufficientBalance, AntiStructuring, VelocityCheck, KYCTierCheck, SanctionsScreen
)

class BSAWirePolicy(Policy):
    class Meta:
        version = "1.0"

    balance               = Field("balance",               Decimal, "Real")
    amount                = Field("amount",                Decimal, "Real")
    cumulative_24h        = Field("cumulative_24h",        Decimal, "Real")
    tx_count_24h          = Field("tx_count_24h",          int,     "Int")
    kyc_tier              = Field("kyc_tier",              int,     "Int")
    counterparty_status   = Field("counterparty_status",   str,     "String")

    @classmethod
    def invariants(cls):
        return [
            SufficientBalance(cls.balance, cls.amount),
            AntiStructuring(cls.cumulative_24h, Decimal("10000")),  # 31 CFR § 1020.320
            VelocityCheck(cls.tx_count_24h, 5),                     # PSD2 low-value cap
            KYCTierCheck(cls.kyc_tier, required_tier=2),            # FinCEN CDD rule
            SanctionsScreen(cls.counterparty_status),               # OFAC SDN
        ]

guard = Guard(BSAWirePolicy, GuardConfig())
```

### Structuring Pattern Detection

- `AntiStructuring` uses a strict `<` comparison. The constraint is `cumulative_amount < threshold`, so it requires cumulative_amount to be strictly less than the threshold to ALLOW.
- At exactly $10,000 (with `threshold=Decimal("10000")`): `10000 < 10000` is False, so the constraint is UNSAT and the transaction is BLOCKED. This is intentional -- the CTR filing threshold under 31 CFR § 1020.320 applies at $10,000 exactly.
- If the comparison were `<=`, then `10000 <= 10000` would be True (ALLOW), which would incorrectly permit a transaction at the exact threshold. The `<` comparison is the correct choice.
- Violation produces `violated_invariants = ("anti_structuring",)`.
- The decision audit log shows the exact cumulative amount at the time of violation.
- **Important:** `AntiStructuring` is a policy gate, not a SAR filing system. Integrate with your SAR workflow separately; use the Pramanix violation log as the trigger signal.

### AML Audit Integration

- Every BLOCK decision from `anti_structuring` should trigger downstream SAR evaluation
- Decision `decision_id` and `decision_hash` serve as the primary key for AML case management
- The `violated_invariants` list in each decision identifies which AML rule triggered
- For multi-bank deployments, use `PersistentMerkleAnchor` with a shared immutable store

---

## 3. OFAC Sanctions Screening

**Applicable regulations:**
- 31 CFR § 501.805 -- OFAC SDN (Specially Designated Nationals) list
- Executive Order 13694 / 13757 -- Cyber-related sanctions
- Penalties: up to $1,000,000 per violation (civil), criminal prosecution possible

### Sanctions Screen Policy

```python
from pramanix import Guard, GuardConfig, Policy, Field
from pramanix.primitives.fintech import SanctionsScreen

class SanctionsPolicy(Policy):
    class Meta:
        version = "1.0"

    counterparty_status = Field("counterparty_status", str, "String")
    originator_status   = Field("originator_status",   str, "String")

    @classmethod
    def invariants(cls):
        return [
            # Block if counterparty is sanctioned
            SanctionsScreen(cls.counterparty_status),
            # Block if originator (sender) is sanctioned
            SanctionsScreen(cls.originator_status).named("originator_sanctions_screen"),
        ]

guard = Guard(SanctionsPolicy, GuardConfig())
```

### Strict Mode (block REVIEW as well as SANCTIONED)

```python
from pramanix import E

class StrictSanctionsPolicy(Policy):
    class Meta:
        version = "1.0"

    counterparty_status = Field("counterparty_status", str, "String")

    @classmethod
    def invariants(cls):
        return [
            # Only allow "CLEAR" -- block both "SANCTIONED" and "REVIEW"
            (E(cls.counterparty_status) == "CLEAR")
            .named("counterparty_must_be_clear")
            .explain("Transaction blocked: counterparty_status={counterparty_status}. "
                     "Only 'CLEAR' counterparties are permitted."),
        ]
```

### OFAC Workflow Notes

- **Pre-screen** counterparties against the OFAC SDN list before calling `Guard.verify()`. The `counterparty_status` field carries the result of your external sanctions database lookup.
- **Do not** rely solely on string matching -- OFAC lookups require fuzzy matching, transliteration, and alias handling that Pramanix does not perform. Pramanix enforces the result of your external lookup.
- **Every blocked transaction** should be reported to your compliance system with the full decision JSON (including `decision_hash`).
- **Voluntary Self-Disclosure:** OFAC provides reduced penalties for violations that are self-reported with a compliance program. Pramanix's cryptographically signed audit log is evidence of the compliance program.

---

## 4. SOC 2 -- Security, Availability, Processing Integrity

**Trust Service Criteria (TSC) addressed by Pramanix:**
- CC6.1: Logical access security (role-based policy enforcement)
- CC6.2: Authentication and authorization before sensitive system access
- CC7.2: Monitoring security incidents (structured audit log + red-flag telemetry)
- PI1.1: Processing integrity -- complete and accurate processing (formal verification of every action)
- PI1.2: System processing is complete, valid, accurate, timely, and authorized

### SOC 2 Access Control Policy

```python
from pramanix import Guard, GuardConfig, Policy, Field, E
from pramanix.primitives.rbac import RoleMustBeIn, ConsentRequired

# Role encoding
ADMIN_ROLES       = [1, 2]      # sysadmin=1, dbadmin=2
READ_ONLY_ROLES   = [3, 4, 5]   # analyst=3, auditor=4, viewer=5
SENSITIVE_ROLES   = [1]         # only sysadmin for sensitive ops

class SensitiveDataAccessPolicy(Policy):
    class Meta:
        version = "1.0"

    requestor_role     = Field("requestor_role",     int,  "Int")
    mfa_verified       = Field("mfa_verified",       bool, "Bool")
    session_active     = Field("session_active",     bool, "Bool")

    @classmethod
    def invariants(cls):
        return [
            RoleMustBeIn(cls.requestor_role, SENSITIVE_ROLES),
            (E(cls.mfa_verified) == True).named("mfa_required")
            .explain("MFA not verified for sensitive data access."),
            (E(cls.session_active) == True).named("session_valid")
            .explain("No active session for this request."),
        ]

guard = Guard(SensitiveDataAccessPolicy, GuardConfig())
```

### SOC 2 Audit Evidence

Pramanix provides the following evidence items for SOC 2 Type II audits:

| Evidence Item | How Pramanix Provides It |
|--------------|--------------------------|
| Access control policy is documented | `Policy` class with `invariants()` is the machine-readable policy. Version-controlled in Git. |
| All access attempts are logged | Every `Guard.verify()` call emits a structured JSON log line with decision_id, outcome, and timestamp |
| Unauthorized access is prevented | Z3 UNSAT means the invariant is provably violated. No probability -- mathematical proof. |
| Audit log is tamper-evident | Merkle chain hash on every decision log. `pramanix audit verify` detects any modification. |
| Access changes are tracked | Policy version in `Decision.metadata`. Policy hash via `GuardConfig.expected_policy_hash`. |
| Incident detection | Red-flag telemetry counters: `injection_spikes`, `consensus_mismatches`, `z3_timeouts` |

### Deployment Checklist for SOC 2

- [ ] `GuardConfig(signer=PramanixSigner.generate())` enabled -- all decisions are Ed25519 signed
- [ ] Decision log shipped to immutable storage (S3 + Object Lock, Azure Blob + Immutable Storage, Worm storage)
- [ ] `pramanix audit verify` runs nightly in CI against the decision log
- [ ] `GuardConfig(expected_policy_hash=fingerprint)` set for all production Guard instances
- [ ] Prometheus metrics enabled: `GuardConfig(metrics_enabled=True)` -- decision rate, latency, error rate
- [ ] OpenTelemetry traces enabled: `GuardConfig(otel_enabled=True)` -- per-request traces for PI1 evidence
- [ ] `GuardConfig(redact_violations=False)` for internal audit systems (full violation details needed)
- [ ] Worker warmup enabled (default) -- ensures availability SLA is met at startup

---

## 5. PCI DSS (Payment Card Industry)

**Relevant requirements:**
- PCI DSS Requirement 7: Restrict access to cardholder data (role enforcement)
- PCI DSS Requirement 10: Track and monitor all access (audit log)
- PCI DSS Requirement 8: Identify and authenticate access (MFA enforcement)

### Cardholder Data Access Policy

```python
from pramanix import Guard, GuardConfig, Policy, Field, E
from pramanix.primitives.rbac import RoleMustBeIn
from pramanix.primitives.time import NotExpired

# PCI DSS roles (integer-encoded)
PAYMENT_PROCESSOR = 1
FRAUD_ANALYST     = 2
AUDITOR           = 3

class CardholderDataPolicy(Policy):
    class Meta:
        version = "1.0"

    requestor_role    = Field("requestor_role",    int,  "Int")
    token_expiry      = Field("token_expiry",      int,  "Int")
    current_timestamp = Field("current_timestamp", int,  "Int")
    is_mfa_verified   = Field("is_mfa_verified",   bool, "Bool")

    @classmethod
    def invariants(cls):
        return [
            RoleMustBeIn(cls.requestor_role, [PAYMENT_PROCESSOR, FRAUD_ANALYST]),
            NotExpired(cls.token_expiry, cls.current_timestamp),
            (E(cls.is_mfa_verified) == True).named("mfa_required")
            .explain("PCI DSS Req. 8: MFA required for cardholder data access."),
        ]
```

---

## 6. GDPR / Data Subject Rights

**Relevant articles:**
- GDPR Art. 5(1)(b): Purpose limitation -- data used only for declared purposes
- GDPR Art. 17: Right to erasure -- access to data for users who have requested deletion
- GDPR Art. 22: Automated decision-making -- decisions must be explainable

### Notes for GDPR Compliance

- **Explainability (Art. 22):** Every Pramanix BLOCK decision includes `violated_invariants` listing exactly which policy rules were violated, and `explanation` with human-readable text. This satisfies the GDPR requirement for human-readable explanations of automated decisions.
- **Purpose limitation:** Policy invariants encode the permitted purposes. Any action outside those purposes produces a formal BLOCK with a logged reason.
- **Audit trail for erasure:** When a data subject requests deletion, the audit log shows all past access decisions involving that subject. Identifiers in the log are those passed by the caller -- use pseudonymous identifiers (UUIDs) rather than personal data.
- **Decision review:** The signed `decision_hash` and Ed25519 signature provide proof of what was decided and when -- enabling review of automated decisions when requested.

---

## 7. General Compliance Configuration Checklist

For any regulated deployment, apply these settings:

```python
from pramanix.guard import GuardConfig
from pramanix.crypto import PramanixSigner

# Load private key from secrets manager
signer = PramanixSigner.from_pem(os.environ["PRAMANIX_SIGNING_KEY_PEM"].encode())

# Compute and pin policy hash
from pramanix.guard import Guard
guard = Guard(MyPolicy)
fingerprint = guard.policy_hash()  # compute once after development

# Production config
config = GuardConfig(
    signer=signer,                            # Ed25519 sign every decision
    expected_policy_hash=fingerprint,         # detect policy drift
    execution_mode="async-thread",
    solver_timeout_ms=5000,
    max_input_bytes=65536,                    # 64 KiB cap (H06)
    solver_rlimit=10_000_000,                 # operation cap (H08)
    redact_violations=False,                  # Full details for internal audit
    # For external APIs:
    # redact_violations=True,
    min_response_ms=50.0,                     # timing oracle prevention (H13)
)
```
