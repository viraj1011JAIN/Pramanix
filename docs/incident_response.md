# Pramanix Incident Response Playbook

Operational guide for diagnosing and responding to incidents involving Pramanix-protected systems.

---

## Severity levels

| Severity | Description | Response SLA |
|----------|-------------|-------------|
| **P0 — Critical** | False ALLOW: a blocked action was permitted | Immediate / <15 min |
| **P0 — Critical** | Audit log tamper detected | Immediate / <15 min |
| **P1 — High** | Elevated solver timeout rate (>5%) | <1 hour |
| **P1 — High** | Circuit breaker ISOLATED state | <1 hour |
| **P2 — Medium** | Policy version drift across deployment | <4 hours |
| **P2 — Medium** | HMAC seal violation logged | <4 hours |
| **P3 — Low** | Sustained latency above P99 threshold | Next business day |

---

## P0: False ALLOW detected

A decision with `allowed=True` was issued when it should have been blocked.

### Immediate actions

1. **Isolate**: Remove the affected Guard instance from serving traffic.
2. **Preserve evidence**: Copy the full decision token, the audit log JSONL, and the policy
   version hash (`GuardConfig.expected_policy_hash` or `Guard._policy_hash`).
3. **Verify the token**: Run `pramanix verify-proof <token> --json` to confirm the HMAC
   signature is valid. If `valid=false`, the token was forged or tampered — treat as P0 security
   breach.
4. **Check solver status**: Inspect `decision.status`. A false ALLOW should never have
   `status=SolverStatus.SAFE`. If it does, the policy has a gap.

### Root cause categories

| Observation | Likely cause |
|-------------|-------------|
| `status=safe`, `allowed=True`, token valid | Policy gap — invariant does not cover the case |
| Token `valid=false` | Token forged; check for key compromise |
| `status=error` or `status=timeout`, `allowed=True` | **Critical SDK bug** — fail-safe contract violated; file P0 bug |
| Policy hash mismatch | Wrong policy version deployed; see P2 playbook |

### Post-incident

- Replay the raw intent and state through the current policy in an isolated environment.
- Add a regression invariant that covers the failing case.
- Update `tests/unit/` with a failing test for the specific input.

---

## P0: Audit log tampering detected

The `pramanix audit verify` CLI reports `[TAMPERED]` or `[INVALID_SIG]` for records that were
previously verified clean.

### Immediate actions

1. **Stop writes** to the audit log file until investigation is complete.
2. **Identify the first tampered record**: use `--fail-fast` to locate the record index.
3. **Preserve the log** at rest (snapshot or copy to immutable storage before any rotation).
4. **Cross-reference** with the Merkle root checkpoint if `PersistentMerkleAnchor` is configured.
   The checkpoint provides a tamper-evident anchor independent of the JSONL file.

### Verification commands

```bash
# Find first tampered record
pramanix audit verify audit.jsonl --public-key pub.pem --fail-fast

# Full JSON report
pramanix audit verify audit.jsonl --public-key pub.pem --json | jq .

# Check Merkle root (if stored separately)
python -c "
from pramanix.audit.merkle import MerkleAnchor
import json, hashlib

anchor = MerkleAnchor()
with open('audit.jsonl') as f:
    for line in f:
        rec = json.loads(line.strip())
        anchor.add(rec['decision_id'])
print(anchor.root())
"
```

---

## P1: Elevated solver timeout rate

Solver timeouts produce `status=SolverStatus.TIMEOUT` and `allowed=False` (fail-safe). They do
not cause false ALLOWs but degrade service quality.

### Diagnosis

```python
# Check Prometheus counter (if metrics enabled)
# pramanix_solver_timeouts_total{policy="..."} — rate over 5m

# Or inspect decision logs
grep '"status": "timeout"' audit.jsonl | wc -l
```

### Remediation options

| Root cause | Action |
|-----------|--------|
| Z3 logic-bomb in policy | Add `solver_rlimit` guard: `GuardConfig(solver_rlimit=5_000_000)` |
| Input too large | Lower `max_input_bytes` or add input validation upstream |
| Worker pool exhausted | Increase `max_workers` or enable load shedding |
| Legitimate complex formula | Increase `solver_timeout_ms` (last resort) |

The `solver_rlimit` guard (default: 10M elementary operations) fires before the wall-clock
timeout for adversarial non-linear inputs. If you see `status=timeout` without high wall-clock
latency, the rlimit is triggering — inspect the formula complexity.

---

## P1: Circuit breaker ISOLATED state

The `AdaptiveCircuitBreaker` enters `CircuitState.ISOLATED` after three consecutive OPEN episodes,
requiring **manual reset**. All `verify_async()` calls return `allowed=False` until reset.

### Recovery

```python
from pramanix.circuit_breaker import AdaptiveCircuitBreaker

# breaker is your AdaptiveCircuitBreaker instance
assert breaker.state == CircuitState.ISOLATED
breaker.reset()  # returns to CLOSED — verify solver health before doing this
assert breaker.state == CircuitState.CLOSED
```

Before resetting, confirm the underlying Z3 latency has returned to normal.
Check `breaker.status.open_episodes` to understand how many consecutive trips occurred.

---

## P2: Policy version drift

`Guard.__init__` raises `ConfigurationError` if `expected_policy_hash` is set and the running
policy hash does not match. In a rolling deployment, instances with the old binary may see this
on startup.

### Expected deployment sequence

1. Deploy new policy + new binary together (blue/green or rolling with health checks).
2. `GuardConfig(expected_policy_hash="<new-hash>")` will reject startup on instances that have
   the new config but old policy code.
3. Health probe failure prevents traffic being routed to misconfigured instances.

### Getting the current policy hash

```python
from pramanix.guard import Guard
from pramanix.policy import Policy  # your policy class

guard = Guard(MyPolicy)
print(guard._policy_hash)  # SHA-256 of compiled policy
```

---

## P2: HMAC seal violation logged

The log line `"WorkerPool: HMAC seal violation"` at ERROR level indicates a worker process
returned a result that failed the HMAC-SHA256 integrity check.

### Causes

- **Benign**: A worker process was recycled mid-flight and the ephemeral key rotated. The result
  was discarded and `Decision.error(allowed=False)` was returned to the caller — fail-safe
  behaviour.
- **Concerning**: A compromised or corrupted worker process attempted to forge a result. The seal
  ensures the forgery was detected before it reached the caller.

### Action

Check the frequency. A single occurrence during recycle is expected. Multiple occurrences within
a short window suggest worker process instability or potential compromise — restart the service,
audit the process environment, and investigate any unusual child process activity.

---

## HMAC signing key rotation

The `PRAMANIX_SIGNING_KEY` used by `DecisionSigner` / `DecisionVerifier` should be rotated
periodically. The SDK does not enforce rotation — implement it at the deployment layer.

**Safe rotation procedure:**
1. Generate a new key: `python -c "import secrets; print(secrets.token_hex(64))"`
2. Deploy new key alongside old key (dual-verify period).
3. Re-sign any tokens that must remain verifiable after the old key is retired.
4. Remove old key after all live tokens have expired or been re-signed.

The IPC seal key (`_RESULT_SEAL_KEY`) is ephemeral — it is re-generated on every process start
and requires no manual rotation.

---

## Useful log queries

All Pramanix logs are structured JSON via structlog. The `event` field is the primary search key.

```bash
# Solver timeouts in last hour
jq 'select(.event == "solver_timeout" or .status == "timeout")' pramanix.log

# Circuit breaker state changes
jq 'select(.event | test("circuit"))' pramanix.log

# HMAC violations
jq 'select(.event | test("seal|hmac|integrity"; "i"))' pramanix.log

# Worker recycles
jq 'select(.event | test("recycle|recycl"; "i"))' pramanix.log
```

---

## Contacts and escalation

Maintain this section with your organisation's on-call rotation and escalation paths.
For SDK bugs, open an issue at [https://github.com/anthropics/pramanix/issues](https://github.com/anthropics/pramanix/issues).
For security vulnerabilities, follow [SECURITY.md](../SECURITY.md).
