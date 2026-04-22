# Pramanix Migration Guide

Migration notes for upgrading between major versions and across significant v0.x releases.

---

## v0.8.x → v0.9.x

### Breaking changes

#### `VerificationResult.policy` renamed to `policy_hash`

The `policy` field on `VerificationResult` has been removed. It was always empty because the
signed JWS payload never contained a `"policy"` key. The correct field, `policy_hash`, now
surfaces the SHA-256 fingerprint written by `DecisionSigner`.

```python
# Before (v0.8.x) — silently returned ""
result = verifier.verify(token)
print(result.policy)        # always ""

# After (v0.9.x) — correct value
print(result.policy_hash)   # SHA-256 fingerprint string
```

Any code that references `result.policy` will raise `AttributeError`. Search for `.policy` on
`VerificationResult` objects and rename to `.policy_hash`.

#### `issued_at` is always `0` in verified tokens

The `iat` (issued-at) field was removed from the signed JWS payload in v0.5.x to make signing
deterministic and replay-verifiable. `VerificationResult.issued_at` is therefore always `0` for
any token produced by SDK v0.5.x or later.

If you need the issue timestamp for display or audit purposes, use `SignedDecision.issued_at`
(available on the object returned by `DecisionSigner.sign()`). It is not embedded in the
HMAC-protected body and is therefore not part of the proof.

```python
# Signing side — timestamp available here
signed = signer.sign(decision)
print(signed.issued_at)     # Unix milliseconds

# Verifying side — always 0 for current tokens
result = verifier.verify(signed.token)
assert result.issued_at == 0
```

#### `Decision.to_dict()` now includes `policy_hash`

The serialized decision dictionary gains a `policy_hash` key (13 keys total, up from 12). Code
that validates the exact key set of `to_dict()` output must be updated.

```python
d = Decision.safe()
d.to_dict()  # now contains 'policy_hash'
```

#### New `GuardConfig` validations that raise `ConfigurationError`

`GuardConfig.__post_init__` now validates six additional fields. Construction that previously
succeeded silently may now raise:

| Field | Constraint |
| ------- | ----------- |
| `solver_rlimit` | Must be `>= 0` |
| `max_input_bytes` | Must be `>= 0` |
| `min_response_ms` | Must be `>= 0.0` |
| `shed_worker_pct` | Must be in `(0.0, 100.0]` |
| `shed_latency_threshold_ms` | Must be `> 0.0` |
| `injection_threshold` | Must be in `(0.0, 1.0]` |

If any of these was previously set via environment variable to an out-of-range value that happened
to be ignored, `GuardConfig()` will now raise `ConfigurationError` at startup.

#### `GuardConfig(otel_enabled=True)` emits `UserWarning` when OpenTelemetry is absent

Code that calls `GuardConfig(otel_enabled=True)` in environments without
`opentelemetry-sdk` installed will now emit a `UserWarning`. This is a warning, not an
exception — no action is required unless you want to suppress it.

```python
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    config = GuardConfig(otel_enabled=True)
```

Or install the extra to make the warning disappear:

```bash
pip install 'pramanix[otel]'
```

### New fields (additive, no migration required)

These `GuardConfig` fields are new in v0.9.x. They default to backwards-compatible values and
require no changes to existing configurations:

| Field | Default | Purpose |
| ------- | ------- | ------- |
| `solver_rlimit` | `10_000_000` | Z3 resource limit per solve call |
| `max_input_bytes` | `65_536` | Max serialised intent+state size |
| `min_response_ms` | `0.0` (disabled) | Timing side-channel mitigation |
| `redact_violations` | `False` | Redact BLOCK explanation from callers |
| `expected_policy_hash` | `None` (disabled) | Policy drift detection |
| `injection_threshold` | `0.5` | Injection confidence threshold |

---

## v0.7.x → v0.8.x

### Breaking changes (v0.7.x → v0.8.x)

#### `guard_config._resolver_registry` is now the module singleton

`guard_config._resolver_registry` was previously a private `ResolverRegistry()` instance
created inside `guard_config.py`. It is now an alias for the public
`pramanix.resolvers.resolver_registry` singleton.

If your code registered resolvers via `from pramanix.resolvers import resolver_registry` and
found them ignored by `Guard`, this was the bug. From v0.8.x onwards, both references point to
the same object. No API change — this is a correctness fix.

#### Process-mode IPC now HMAC-sealed

In `execution_mode="async-process"` mode, worker results are now signed with an ephemeral
HMAC-SHA256 key before crossing the process boundary. A compromised worker process can no longer
forge `allowed=True` results. This is transparent to callers — the seal is verified before
`verify()` returns.

If you override `WorkerPool` internals (not part of the public API), verify your subclass is
compatible with the `_worker_solve_sealed` / `_unseal_decision` envelope format.

---

## v0.6.x / v0.7.x — `MerkleAnchor._build_root`

The internal `_build_root` method is iterative from v0.7.x onward. The previous recursive
implementation hit Python's default 1,000-frame recursion limit for audit batches with more than
roughly 2,000 decisions. If you call `_build_root` directly (it is not part of the public API),
note that it is now an iterative algorithm — behaviour is identical, stack usage is O(1).

---

## v0.9.x → v1.0.x

### Breaking changes (v0.9.x → v1.0.x)

#### musl/Alpine now rejected at import time (C-1)

`import pramanix` on an Alpine Linux host now raises `ConfigurationError` immediately. If you
are running in a musl libc environment for testing only, set `PRAMANIX_SKIP_MUSL_CHECK=1` before
importing. For production, switch your base image to `python:3.13-slim-bookworm` (Debian glibc).
See `Dockerfile.slim` in the project root for a ready-to-use template.

#### `pramanix.__all__` is now frozen at v1.0 surface

The public API is locked. Adding a name to `__all__` is now a minor-version change, not a patch.
Removing or renaming a name requires a major version bump. The exact locked set is tested in
`tests/unit/test_api_contract.py`.

#### `Policy.Meta.semver` validation (B-4)

If you add `class Meta: semver = (...)` to a Policy and the tuple is not exactly three
non-negative integers, `Guard.__init__` now raises `ConfigurationError` before the first request.
Previously, an invalid tuple would raise `IndexError` or `ValueError` deep inside `meta_version()`
at an unpredictable call site.

### New APIs (no migration required, additive only)

The following were added in v1.0 and are immediately available without any code changes:

- **`PolicyMigration`** — dataclass for schema evolution. `migrate(state)` returns a new dict
  with renamed/removed fields applied. `can_migrate(state)` checks compatibility without mutating.
- **`MerkleArchiver`** — use instead of unbounded `MerkleAnchor` in long-running deployments.
  Drop-in: replace `MerkleAnchor()` with `MerkleArchiver(max_active_entries=10_000)`.
- **Execution token backends** — `InMemoryExecutionTokenVerifier` (in-process), `SQLiteExecutionTokenVerifier`
  (single-host persistent), `PostgresExecutionTokenVerifier` (multi-server). All implement the
  same `consume(token, expected_state_version)` protocol as the existing `ExecutionTokenVerifier`.
- **Audit sinks** — pass `GuardConfig(audit_sink=StdoutAuditSink())` (or Datadog/Kafka/S3/Splunk)
  to route every decision to an external observability system.
- **Framework adapters** — `pramanix.integrations.crewai`, `.dspy`, `.pydantic_ai`, `.haystack`,
  `.semantic_kernel`, `.grpc`, `.kafka`, `.k8s` — all optional; install the matching extra.
- **Translator backends** — `GeminiTranslator`, `CohereTranslator`, `MistralTranslator`,
  `LlamaCppTranslator` in `pramanix.translator.*`; same `Translator` protocol as `OllamaTranslator`.
- **CLI subcommands** — `pramanix policy migrate`, `pramanix policy dry-run`,
  `pramanix schema export`, `pramanix calibrate-injection`.

### Stable API guarantees (v1.0+)

The following are part of the stable public API and will not change without a major version bump
and deprecation cycle:

- `Guard`, `GuardConfig`, `Policy`, `Field`, `E` — all public methods and their signatures
- `Decision` — all factory methods (`safe`, `unsafe`, `error`, `timeout`) and `to_dict()` schema
- `SolverStatus` enum members and their string values
- `PramanixError` and its subclasses
- `VerificationResult` — all fields (including `policy_hash`, `issued_at`)
- `MerkleAnchor`, `PersistentMerkleAnchor`, `MerkleArchiver` — public methods only
- `DecisionSigner` / `DecisionVerifier` — JWS token format
- `ExecutionToken`, `ExecutionTokenSigner`, `ExecutionTokenVerifier` and all backend subclasses
- CLI command structure: `pramanix verify-proof`, `pramanix audit verify`, `pramanix policy *`,
  `pramanix schema export`

### Not stable (v1.0+)

- Internal module structure (`pramanix.worker`, `pramanix.solver`, `pramanix.transpiler`)
- Private names (leading underscore)
- `GuardConfig` field defaults may be tightened in minor versions where current defaults are
  documented as provisional

For the full API compatibility contract, see [docs/api-compatibility.md](docs/api-compatibility.md).
