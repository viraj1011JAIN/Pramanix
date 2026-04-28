# Pramanix Migration Guide

This document covers every breaking change across Pramanix releases and
provides concrete before/after code examples for each one.

---

## Table of Contents

- [Upgrading to 1.0.x from 0.9.x](#upgrading-to-10x-from-09x)
  - [H-03 — LangChain: `execute_fn=None` now raises instead of returning "OK"](#h-03--langchain-execute_fnnone-now-raises-instead-of-returning-ok)
  - [H-04 — CrewAI: `underlying_fn=None` now raises instead of returning a string](#h-04--crewai-underlying_fnnone-now-raises-instead-of-returning-a-string)
  - [R1 — `VerificationResult.policy` renamed to `policy_hash`](#r1--verificationresultpolicy-renamed-to-policy_hash)
- [Upgrading to 0.9.x from 0.8.x](#upgrading-to-09x-from-08x)
- [Upgrading to 0.8.x from 0.7.x](#upgrading-to-08x-from-07x)
  - [`issued_at` is always `0` in signed payloads](#issued_at-is-always-0-in-signed-payloads)
  - [New `GuardConfig` fields with validation](#new-guardconfig-fields-with-validation)
- [Production observability checklist](#production-observability-checklist)

---

## Upgrading to 1.0.x from 0.9.x

### H-03 — LangChain: `execute_fn=None` now raises instead of returning "OK"

**Severity: Breaking**

**What changed:**

`PramanixGuardedTool` previously accepted construction without an
`execute_fn` and silently defaulted it to `lambda i: "OK"`. Every call
to `_arun()` returned the string `"OK"` without executing any real logic,
completely defeating the purpose of the guarded tool wrapper.

This was a silent correctness failure: tests could pass (the guard ran,
the decision was made) while production actions were never taken.

**Before (v0.9.x behaviour — broken):**

```python
from pramanix.integrations.langchain import PramanixGuardedTool

# Constructed without execute_fn — silently defaults to lambda i: "OK"
tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer funds between accounts",
    policy=TransferPolicy,
    intent_model=TransferIntent,
)

# Called by the LangChain agent — returns "OK" without doing anything.
# No funds transferred; no error raised; agent believes action succeeded.
result = await tool._arun('{"amount": "500", "currency": "USD"}')
# result == "OK"  ← silent no-op
```

**After (v1.0.x behaviour — correct):**

```python
from pramanix.integrations.langchain import PramanixGuardedTool

# Option A: provide execute_fn at construction time (correct usage)
async def _do_transfer(intent: dict) -> str:
    await payment_gateway.transfer(
        amount=intent["amount"],
        currency=intent["currency"],
    )
    return f"Transferred {intent['amount']} {intent['currency']}"

tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer funds between accounts",
    policy=TransferPolicy,
    intent_model=TransferIntent,
    execute_fn=_do_transfer,   # required
)

# Called by the agent — executes the real action after guard approval.
result = await tool._arun('{"amount": "500", "currency": "USD"}')
# result == "Transferred 500 USD"


# Option B: if you construct without execute_fn, _arun() raises immediately
tool_no_fn = PramanixGuardedTool(
    name="transfer_funds",
    description="...",
    policy=TransferPolicy,
    intent_model=TransferIntent,
    # no execute_fn
)
# A UserWarning is emitted at construction time.

try:
    result = await tool_no_fn._arun('{"amount": "500"}')
except NotImplementedError as exc:
    # "PramanixGuardedTool 'transfer_funds' has no execute_fn.
    #  Pass execute_fn= at construction time."
    pass
```

**How to migrate:**

1. Audit every `PramanixGuardedTool(...)` call site.
2. Supply the real `execute_fn=` coroutine or sync callable.
3. If you were relying on the no-op behaviour in tests, replace it with an
   explicit mock execute function that returns a controlled value.

---

### H-04 — CrewAI: `underlying_fn=None` now raises instead of returning a string

**Severity: Breaking**

**What changed:**

`PramanixCrewAITool._run()` previously returned a blocked-action string
when `underlying_fn=None`:

```
"[pramanix] Action 'tool_name' blocked — policy violation."
```

CrewAI agent frameworks may interpret any string return from `_run()` as
a successful (non-error) tool execution. Returning a string instead of
raising means the agent may continue execution believing the action
succeeded, potentially causing cascading failures downstream.

**Before (v0.9.x behaviour — broken):**

```python
from pramanix.integrations.crewai import PramanixCrewAITool

tool = PramanixCrewAITool(
    name="send_email",
    description="Send an email to a recipient",
    policy=EmailPolicy,
    intent_model=EmailIntent,
)

result = tool._run({"recipient": "user@example.com", "subject": "Hello"})
# result == "[pramanix] Action 'send_email' blocked — policy violation."
# ← string return; CrewAI may treat this as success
```

**After (v1.0.x behaviour — correct):**

```python
from pramanix.integrations.crewai import PramanixCrewAITool

def _do_send_email(intent: dict) -> str:
    email_client.send(to=intent["recipient"], subject=intent["subject"])
    return f"Email sent to {intent['recipient']}"

tool = PramanixCrewAITool(
    name="send_email",
    description="Send an email to a recipient",
    policy=EmailPolicy,
    intent_model=EmailIntent,
    underlying_fn=_do_send_email,  # required
)

result = tool._run({"recipient": "user@example.com", "subject": "Hello"})
# result == "Email sent to user@example.com"


# _run() raises NotImplementedError when underlying_fn is None
tool_no_fn = PramanixCrewAITool(
    name="send_email",
    description="...",
    policy=EmailPolicy,
    intent_model=EmailIntent,
)

try:
    result = tool_no_fn._run({"recipient": "user@example.com"})
except NotImplementedError as exc:
    # "PramanixCrewAITool 'send_email' has no underlying_fn configured.
    #  Pass underlying_fn= at construction time."
    pass
```

**How to migrate:**

1. Audit every `PramanixCrewAITool(...)` call site.
2. Supply the real `underlying_fn=` callable.
3. For read-only tools with no side effect, pass `underlying_fn=lambda intent: "no-op"` explicitly.

---

### R1 — `VerificationResult.policy` renamed to `policy_hash`

**Severity: Breaking** (if using `DecisionVerifier` offline audit CLI or programmatic API)

**What changed:**

`VerificationResult` (returned by `DecisionVerifier.verify()`) renamed the
policy fingerprint field from `.policy` to `.policy_hash`. The old key
`"policy"` never existed in the signed JWS payload — it was always `"policy_hash"`.
Code that read `.policy` got an empty string silently.

**Before (v0.8.x and below — silently wrong):**

```python
result = verifier.verify(signed_decision)
print(result.policy)       # always "" — the field never existed in the payload
```

**After (v1.0.x — correct):**

```python
result = verifier.verify(signed_decision)
print(result.policy_hash)  # "sha256:a1b2c3..."
```

The CLI JSON output key was also updated from `"policy"` to `"policy_hash"`.

---

## Upgrading to 0.9.x from 0.8.x

No breaking API changes in v0.9.0. All changes are additive.

**New fields added to `GuardConfig` (all optional, backward-compatible):**

| Field | Default | Description |
|---|---|---|
| `solver_rlimit` | `10_000_000` | Z3 elementary operation cap per solve |
| `max_input_bytes` | `65_536` | Intent + state payload size cap (bytes) |
| `min_response_ms` | `0.0` | Minimum response time pad (timing side-channel mitigation) |
| `redact_violations` | `False` | Replace `violated_invariants` + `explanation` in BLOCK responses to callers |
| `expected_policy_hash` | `None` | Policy fingerprint for rolling-deploy drift detection |

**Production recommendation:** set `expected_policy_hash` to detect silent policy drift.

```python
# One-time: get the fingerprint from your reference build
guard = Guard(TransferPolicy)
print(guard.policy_hash)  # "sha256:a1b2c3d4e5f6..."

# In every replica's config:
import os
config = GuardConfig(
    expected_policy_hash=os.environ["PRAMANIX_EXPECTED_POLICY_HASH"],
)
guard = Guard(TransferPolicy, config=config)
# ConfigurationError raised immediately if the running policy hash mismatches
```

When `PRAMANIX_ENV=production` and `expected_policy_hash=None`, `GuardConfig.__post_init__`
emits `UserWarning` and `pramanix doctor` reports `WARN` on the `policy-hash-binding` check.

---

## Upgrading to 0.8.x from 0.7.x

### `issued_at` is always `0` in signed payloads

**Severity: Low-impact**

In v0.7.x, `iat` was embedded in the JWS body. In v0.8.x it was removed to
make HMAC computation deterministic. `VerificationResult.issued_at` is now
always `0`. `SignedDecision.issued_at` remains available outside the HMAC
boundary for display.

---

### New `GuardConfig` fields with validation

`GuardConfig` gained several new validated fields. Existing code that relied on
`GuardConfig()` with no arguments continues to work with default values. However,
if you pass **invalid** values, `ConfigurationError` is now raised at construction
time rather than at first `verify()` call.

| Field | Constraint |
|---|---|
| `solver_timeout_ms` | `> 0` |
| `injection_threshold` | `(0.0, 1.0]` |
| `min_response_ms` | `>= 0.0` |
| `max_input_bytes` | `>= 0` |
| `max_decisions_per_worker` | `>= 1` |

---

## Production observability checklist

After upgrading to 1.0.x, verify your deployment:

```bash
# Check all environment conditions
pramanix doctor

# --strict exits 1 on warnings (use in CI / container entrypoint)
pramanix doctor --strict

# Machine-readable for health check endpoints
pramanix doctor --json
```

Expected output for a correctly configured production deployment:

```
[OK]   z3-solver              z3-solver 4.x installed
[OK]   pydantic               Pydantic 2.x installed
[OK]   policy-hash-binding    PRAMANIX_EXPECTED_POLICY_HASH is set (a1b2c3...)
[OK]   logging-handlers       1 handler(s) reachable for 'pramanix': StreamHandler(<stderr>)
[OK]   execution-mode         async-process
[OK]   signer                 Ed25519 signer configured
[OK]   audit-sinks            1 sink(s) configured
[OK]   rlimit                 solver_rlimit=10000000
[OK]   max-input              max_input_bytes=65536
[OK]   env                    PRAMANIX_ENV=production
Doctor: all checks passed (10/10)
```

Configure logging at application startup:

```python
from pramanix.logging_helpers import configure_production_logging
configure_production_logging(level="WARNING", fmt="json")
```

Verify logging handlers are configured:

```python
from pramanix.logging_helpers import check_logging_configuration
status = check_logging_configuration()
# {"ok": True, "level": "WARNING", "handlers": ["StreamHandler(stderr)"], ...}
```


---

## Table of Contents

- [Upgrading to 1.0.x from 0.9.x](#upgrading-to-10x-from-09x)
  - [H-03 — LangChain: `execute_fn=None` now raises instead of returning "OK"](#h-03--langchain-execute_fnnone-now-raises-instead-of-returning-ok)
  - [H-04 — CrewAI: `underlying_fn=None` now raises instead of returning a string](#h-04--crewai-underlying_fnnone-now-raises-instead-of-returning-a-string)
- [Upgrading to 0.9.x from 0.8.x](#upgrading-to-09x-from-08x)
- [Upgrading to 0.8.x from 0.7.x](#upgrading-to-08x-from-07x)
  - [`VerificationResult.policy` renamed to `policy_hash`](#verificationresultpolicy-renamed-to-policy_hash)
  - [`issued_at` is always `0` in signed payloads](#issued_at-is-always-0-in-signed-payloads)
  - [New `GuardConfig` fields with validation](#new-guardconfig-fields-with-validation)

---

## Upgrading to 1.0.x from 0.9.x

### H-03 — LangChain: `execute_fn=None` now raises instead of returning "OK"

**Severity: Breaking**

**What changed:**

`PramanixGuardedTool` previously accepted construction without an
`execute_fn` and silently defaulted it to `lambda i: "OK"`. Every call
to `_arun()` returned the string `"OK"` without executing any real logic,
completely defeating the purpose of the guarded tool wrapper.

This was a silent correctness failure: tests could pass (the guard ran,
the decision was made) while production actions were never taken.

**Before (v0.9.x behaviour — broken):**

```python
from pramanix.integrations.langchain import PramanixGuardedTool

# Constructed without execute_fn — silently defaults to lambda i: "OK"
tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer funds between accounts",
    policy=TransferPolicy,
    intent_model=TransferIntent,
)

# Called by the LangChain agent — returns "OK" without doing anything.
# No funds transferred; no error raised; agent believes action succeeded.
result = await tool._arun('{"amount": "500", "currency": "USD"}')
# result == "OK"  ← silent no-op
```

**After (v1.0.x behaviour — correct):**

```python
from pramanix.integrations.langchain import PramanixGuardedTool

# Option A: provide execute_fn at construction time (correct usage)
async def _do_transfer(intent: dict) -> str:
    await payment_gateway.transfer(
        amount=intent["amount"],
        currency=intent["currency"],
    )
    return f"Transferred {intent['amount']} {intent['currency']}"

tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer funds between accounts",
    policy=TransferPolicy,
    intent_model=TransferIntent,
    execute_fn=_do_transfer,   # required
)

# Called by the agent — executes the real action after guard approval.
result = await tool._arun('{"amount": "500", "currency": "USD"}')
# result == "Transferred 500 USD"


# Option B: if you construct without execute_fn, _arun() raises immediately
tool_no_fn = PramanixGuardedTool(
    name="transfer_funds",
    description="...",
    policy=TransferPolicy,
    intent_model=TransferIntent,
    # no execute_fn
)
# A UserWarning is emitted at construction time.

try:
    result = await tool_no_fn._arun('{"amount": "500"}')
except NotImplementedError as exc:
    # "PramanixGuardedTool 'transfer_funds' has no execute_fn.
    #  Pass execute_fn= at construction time."
    pass
```

**How to migrate:**

1. Audit every `PramanixGuardedTool(...)` call site.
2. Supply the real `execute_fn=` coroutine or sync callable.
3. If you were relying on the no-op behaviour in tests, replace it with an
   explicit `_FixedTranslator` / mock execute function that returns a
   controlled value.

---

### H-04 — CrewAI: `underlying_fn=None` now raises instead of returning a string

**Severity: Breaking**

**What changed:**

`PramanixCrewAITool._run()` previously returned a blocked-action string
when `underlying_fn=None`:

```
"[pramanix] Action 'tool_name' blocked — policy violation."
```

CrewAI agent frameworks may interpret any string return from `_run()` as
a successful (non-error) tool execution. Returning a string instead of
raising means the agent may continue execution believing the action
succeeded, potentially causing cascading failures downstream.

**Before (v0.9.x behaviour — broken):**

```python
from pramanix.integrations.crewai import PramanixCrewAITool

# Constructed without underlying_fn
tool = PramanixCrewAITool(
    name="send_email",
    description="Send an email to a recipient",
    policy=EmailPolicy,
    intent_model=EmailIntent,
)

# _run() returns a string — CrewAI may not detect the failure.
result = tool._run({"recipient": "user@example.com", "subject": "Hello"})
# result == "[pramanix] Action 'send_email' blocked — policy violation."
# ← string return; agent may treat this as success
```

**After (v1.0.x behaviour — correct):**

```python
from pramanix.integrations.crewai import PramanixCrewAITool

# Option A: provide underlying_fn at construction time (correct usage)
def _do_send_email(intent: dict) -> str:
    email_client.send(
        to=intent["recipient"],
        subject=intent["subject"],
    )
    return f"Email sent to {intent['recipient']}"

tool = PramanixCrewAITool(
    name="send_email",
    description="Send an email to a recipient",
    policy=EmailPolicy,
    intent_model=EmailIntent,
    underlying_fn=_do_send_email,  # required
)

result = tool._run({"recipient": "user@example.com", "subject": "Hello"})
# result == "Email sent to user@example.com"


# Option B: _run() raises NotImplementedError when underlying_fn is None
tool_no_fn = PramanixCrewAITool(
    name="send_email",
    description="...",
    policy=EmailPolicy,
    intent_model=EmailIntent,
    # no underlying_fn
)

try:
    result = tool_no_fn._run({"recipient": "user@example.com"})
except NotImplementedError as exc:
    # "PramanixCrewAITool 'send_email' has no underlying_fn configured.
    #  Pass underlying_fn= at construction time."
    pass
```

**How to migrate:**

1. Audit every `PramanixCrewAITool(...)` call site.
2. Supply the real `underlying_fn=` callable that executes the action.
3. If a tool is intentionally read-only (no action required), pass
   `underlying_fn=lambda intent: "no-op"` explicitly so the intent is
   clear at the call site.

---

## Upgrading to 0.9.x from 0.8.x

No breaking API changes in v0.9.0. All changes are additive.

**New fields added to `GuardConfig` (all optional, backward-compatible):**

| Field | Default | Description |
|---|---|---|
| `solver_rlimit` | `10_000_000` | Z3 elementary operation cap |
| `max_input_bytes` | `65_536` | Intent + state payload size cap |
| `min_response_ms` | `0.0` | Minimum response time (timing pad) |
| `redact_violations` | `False` | Hide `violated_invariants` from callers |
| `expected_policy_hash` | `None` | Policy fingerprint for drift detection |

**Production recommendation:** set `expected_policy_hash` to the SHA-256
fingerprint of your compiled policy. Obtain it once:

```python
from pramanix.guard import Guard
from myapp.policies import TransferPolicy

guard = Guard(TransferPolicy)
print(guard.policy_hash)
# "sha256:a1b2c3d4e5f6..."
```

Then pin it in `GuardConfig`:

```python
import os
from pramanix.guard import GuardConfig

config = GuardConfig(
    expected_policy_hash=os.environ["PRAMANIX_EXPECTED_POLICY_HASH"],
)
```

When `PRAMANIX_ENV=production` and `expected_policy_hash=None`, Pramanix
emits a `UserWarning` at `GuardConfig` construction time and the
`pramanix doctor` command reports `WARN` on the `policy-hash-binding`
check.

---

## Upgrading to 0.8.x from 0.7.x

### `VerificationResult.policy` renamed to `policy_hash`

**Severity: Breaking**

The field that holds the policy fingerprint in `VerificationResult`
(returned by `DecisionVerifier.verify()`) was renamed from `policy` to
`policy_hash` to match the key name used in `DecisionSigner._canonicalize()`.

**Before:**

```python
result = verifier.verify(signed_decision)
print(result.policy)         # AttributeError in 0.8.x
```

**After:**

```python
result = verifier.verify(signed_decision)
print(result.policy_hash)    # "sha256:a1b2c3..."
```

The CLI JSON output key was also updated from `"policy"` to `"policy_hash"`.

---

### `issued_at` is always `0` in signed payloads

**Severity: Low-impact**

In v0.7.x, `iat` (issued-at) was embedded in the JWS body. In v0.8.x the
`iat` field was removed from the signed payload to make HMAC computation
deterministic (same decision always produces the same signature, regardless
of wall-clock time). `VerificationResult.issued_at` is now always `0`.

The `SignedDecision.issued_at` field remains available *outside* the HMAC
boundary for display purposes.

---

### New `GuardConfig` fields with validation

`GuardConfig` gained several new validated fields. Existing code that
relied on `GuardConfig()` with no arguments continues to work with
default values. However, if you pass **invalid** values, `ConfigurationError`
is now raised at construction time rather than at first `verify()` call.

Known validations added in v0.8.x:

| Field | Constraint |
|---|---|
| `solver_timeout_ms` | Must be `> 0` |
| `injection_threshold` | Must be in `(0.0, 1.0]` |
| `min_response_ms` | Must be `>= 0.0` |
| `max_input_bytes` | Must be `>= 0` |
| `max_decisions_per_worker` | Must be `>= 1` |

---

## Production observability checklist

After upgrading to 1.0.x, verify your deployment with:

```bash
# Check all doctor conditions pass
pramanix doctor

# Verify logging handlers are configured
python -c "
from pramanix.logging_helpers import check_logging_configuration
status = check_logging_configuration()
print(status['level'], status['detail'])
"

# Configure production logging at application startup
# (add to your main.py / app factory):
from pramanix.logging_helpers import configure_production_logging
configure_production_logging(level='WARNING', fmt='json')
```

Expected `pramanix doctor` output for a production deployment:

```
[OK]   z3-solver          z3-solver 4.x installed
[OK]   pydantic           Pydantic 2.x installed
[OK]   policy-hash-binding PRAMANIX_EXPECTED_POLICY_HASH is set (a1b2c3d4e5f6...)
[OK]   logging-handlers   1 handler(s) reachable for 'pramanix': StreamHandler(<stderr>)
...
```
