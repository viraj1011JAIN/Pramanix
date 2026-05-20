# Pramanix

Deterministic neuro-symbolic execution firewall for autonomous AI agents.

## SDK Snapshot (evidence-backed, 2026-05-20)

| Item | Current value | Evidence |
|---|---|---|
| Package version | 1.0.0 | [src/pramanix/__init__.py](src/pramanix/__init__.py), [pyproject.toml](pyproject.toml) |
| Python support | >=3.11,<4.0 (tested on 3.13.7) | [pyproject.toml](pyproject.toml), [docs/PROOF_DOSSIER.md](docs/PROOF_DOSSIER.md) |
| License | AGPL-3.0-only | [pyproject.toml](pyproject.toml) |
| Latest validated full-pass baseline | 4,118 passed, 166 skipped, 0 failed | [docs/PROOF_DOSSIER.md](docs/PROOF_DOSSIER.md) |
| Latest branch coverage baseline | 98.26% | [docs/PROOF_DOSSIER.md](docs/PROOF_DOSSIER.md) |
| Current collection size | 4,299 tests collected | latest local pytest collection output |
| Stability contract source | pramanix.__stability__ | [src/pramanix/__init__.py](src/pramanix/__init__.py), [docs/PUBLIC_API.md](docs/PUBLIC_API.md) |

## 1. Purpose and Scope

Pramanix is an enforcement layer between AI intent and side effects.

It does three core things:

1. Validates typed intent and state payloads.
2. Verifies policy invariants with Z3.
3. Returns a deterministic Decision that gates execution.

It does not attempt to be an LLM safety benchmark suite, content moderation service, or general API gateway.

## 2. Security Model and Trust Boundaries

### 2.1 What is inside scope

- Deterministic constraint verification (sat or unsat semantics from Z3).
- Fail-closed decision construction when validation, solver, translator, or infrastructure paths fail.
- Optional cryptographic decision signing.
- Optional replay-resistance via execution tokens.

### 2.2 What is outside scope

- Inferring truthfulness of intent from hidden model reasoning.
- Detecting all semantic abuse patterns without explicit policy constraints.
- Replacing IAM, ABAC, firewalling, or data-plane ACLs.

### 2.3 Trust assumptions

- Policy authors encode correct invariants.
- State loader returns accurate state.
- Downstream execution path consumes only approved decisions/tokens.

## 3. Core Contract

Pramanix returns Decision outcomes that satisfy the invariant:

- allowed=True only when status=SAFE
- status!=SAFE implies allowed=False

This contract is enforced in Decision model validation and Guard pipeline behavior.

Practical outcome:

- policy violation -> deny
- validation failure -> deny
- solver timeout/error -> deny
- internal runtime error -> deny

## 4. End-to-End Verification Pipeline

The effective execution path is:

1. Strict schema validation (intent/state)
2. Optional fast-path pre-screen (BLOCK-only)
3. Optional translator extraction or consensus (beta)
4. Constraint lowering from DSL/IR to Z3 AST
5. Solver run and violation attribution
6. Deterministic Decision construction
7. Optional decision signing
8. Optional audit sink emission
9. Metrics/logging/tracing hooks

Pipeline references:

- [src/pramanix/guard.py](src/pramanix/guard.py)
- [src/pramanix/solver.py](src/pramanix/solver.py)
- [src/pramanix/transpiler.py](src/pramanix/transpiler.py)
- [src/pramanix/decision.py](src/pramanix/decision.py)

## 5. Evidence-Backed Claims

| Claim | Status | Proof |
|---|---|---|
| Fail-closed verification semantics | Implemented and tested | [docs/PROOF_DOSSIER.md](docs/PROOF_DOSSIER.md), [tests/adversarial/test_fail_safe_invariant.py](tests/adversarial/test_fail_safe_invariant.py) |
| Deterministic SMT verification with Z3 | Implemented and tested | [src/pramanix/solver.py](src/pramanix/solver.py), [tests/unit/test_solver.py](tests/unit/test_solver.py) |
| Exact decimal-to-rational lowering | Implemented and tested | [src/pramanix/transpiler.py](src/pramanix/transpiler.py), [tests/unit/test_transpiler.py](tests/unit/test_transpiler.py) |
| Policy IR compiler and decompiler | Implemented (beta) | [src/pramanix/compiler.py](src/pramanix/compiler.py), [docs/CHANGELOG.md](docs/CHANGELOG.md) |
| Ed25519, RS256, ES256 support | Implemented and tested | [src/pramanix/crypto.py](src/pramanix/crypto.py), [tests/unit/test_rs256_es256.py](tests/unit/test_rs256_es256.py) |
| FastAPI middleware optional signer startup behavior | Fixed in latest sprint | [docs/CHANGELOG.md](docs/CHANGELOG.md), [docs/MIGRATION.md](docs/MIGRATION.md), [src/pramanix/integrations/fastapi.py](src/pramanix/integrations/fastapi.py) |
| Doctor compatibility check-name contract | Fixed in latest sprint | [docs/CHANGELOG.md](docs/CHANGELOG.md), [tests/unit/test_doctor_cli.py](tests/unit/test_doctor_cli.py) |
| Worker finalizer shutdown-noise guard | Fixed in latest sprint | [docs/CHANGELOG.md](docs/CHANGELOG.md), [src/pramanix/worker.py](src/pramanix/worker.py) |

## 6. Stability Tiers

Authoritative source: pramanix.__stability__.

Stable modules:

- core
- audit
- crypto
- circuit_breaker
- execution_token
- key_provider
- compliance
- audit_sinks
- worker
- primitives

Beta modules:

- translator
- integrations
- fast_path
- ifc
- privilege
- oversight
- memory
- lifecycle
- provenance
- mesh

References:

- [src/pramanix/__init__.py](src/pramanix/__init__.py)
- [docs/PUBLIC_API.md](docs/PUBLIC_API.md)

## 7. Public API Highlights

Core objects:

- Guard, GuardConfig
- Policy, Field, E, ConstraintExpr
- Decision, SolverStatus
- guard decorator

Security and integrity:

- PramanixSigner, PramanixVerifier
- RS256Signer, RS256Verifier
- ES256Signer, ES256Verifier
- DecisionSigner, DecisionVerifier
- MerkleAnchor, MerkleArchiver

Execution safety:

- ExecutionToken, ExecutionTokenSigner
- RedisExecutionTokenVerifier
- SQLiteExecutionTokenVerifier
- PostgresExecutionTokenVerifier
- AdaptiveCircuitBreaker, DistributedCircuitBreaker

Policy lifecycle:

- PolicyCompiler, PolicyIR, Decompiler (beta)
- PolicyDiff, ShadowEvaluator (beta)

Additional beta surfaces:

- IFC: FlowEnforcer, TrustLabel
- Privilege: ScopeEnforcer, CapabilityManifest
- Oversight: InMemoryApprovalWorkflow, EscalationQueue
- Mesh: MeshAuthenticator, SpiffeIdentity

## 8. Installation and Dependency Profiles

Repository install (recommended):

    git clone https://github.com/viraj1011JAIN/Pramanix
    cd Pramanix
    python -m venv .venv
    .venv\Scripts\activate   # Windows
    pip install -e .

Common extras:

    pip install -e '.[all]'
    pip install -e '.[translator,fastapi,crypto]'
    pip install -e '.[postgres,redis,circuit-breaker]'
    pip install -e '.[aws,azure,gcp,vault]'
    pip install -e '.[kafka,s3,datadog,splunk,pdf]'
    pip install -e '.[dspy,crewai,pydantic-ai,semantic-kernel,haystack]'
    pip install -e '.[security]'

Notes:

- security extra installs google-re2 for safer regex behavior under adversarial input.
- several enterprise/cloud adapters are tested with mocks in CI; see Known Limits.

Dependency source:

- [pyproject.toml](pyproject.toml)

## 9. Minimal Usage Example

    from decimal import Decimal
    from pramanix import Guard, Policy, Field, E

    class TransferPolicy(Policy):
        amount = Field("amount", Decimal, "Real")
        balance = Field("balance", Decimal, "Real")

        @classmethod
        def invariants(cls):
            return [
                (E(cls.amount) > 0).named("amount_positive"),
                (E(cls.amount) <= E(cls.balance)).named("no_overdraft"),
            ]

    guard = Guard(TransferPolicy)

    decision = guard.verify(
        intent={"amount": Decimal("500.00")},
        state={"balance": Decimal("1200.00")},
    )

    print(decision.allowed, decision.status)

Expected behavior:

- valid request -> allowed=True, status=SAFE
- violating request -> allowed=False and violated_invariants populated

## 10. Integration Notes

FastAPI:

- PramanixMiddleware is available.
- signer is optional; startup no longer fails when signing key is absent.
- proof headers are emitted only when signer is configured.

LangChain and CrewAI:

- silent stub defaults were removed.
- missing execute/underlying function now raises NotImplementedError.
- migration guidance is in [docs/MIGRATION.md](docs/MIGRATION.md).

Translator stack:

- translator and consensus behavior are beta.
- production use should include explicit timeout budgets and monitoring.

## 11. Operations Runbook

### 11.1 Health and diagnostics

    pramanix doctor
    pramanix doctor --strict
    pramanix doctor --json

Doctor currently supports compatibility check naming for both:

- audit-sink-reachability
- audit-sink-policy

### 11.2 Policy simulation and proof verification

    pramanix simulate --intent intent.json --policy myapp.policies:TransferPolicy
    pramanix explain --intent intent.json --policy myapp.policies:TransferPolicy
    pramanix schema export --policy myapp.policies:TransferPolicy
    pramanix verify-proof --key public.pem < signed_decision.json

### 11.3 Production alerts to wire

Recommended minimum alerts:

- sustained Decision.error rate above baseline
- sustained translator extraction/timeout failures
- audit sink emission failures
- circuit breaker frequent open/isolated transitions

## 12. Observability

Supported telemetry surfaces:

- Prometheus metrics (optional)
- OpenTelemetry spans (optional)
- structured logs via structlog

References:

- [src/pramanix/logging_helpers.py](src/pramanix/logging_helpers.py)
- [src/pramanix/guard.py](src/pramanix/guard.py)

## 13. Performance and Scaling Notes

Execution modes:

- sync: simplest path, in-process solve
- async-thread: background thread solve path
- async-process: stronger isolation with process boundary

Scaling guidance:

- use process mode for strict isolation requirements
- use replay-safe token verifiers (Redis/Postgres) for distributed execution
- set solver timeout and rlimit budgets explicitly in GuardConfig

## 14. Known Limits and Open Risk

Current important limits:

- some cloud/enterprise integrations are mock-backed in CI rather than live endpoint tested
- translator subsystem remains beta and depends on external model providers
- in-memory token verifier is not durable across restart

Detailed inventories:

- [docs/KNOWN_GAPS.md](docs/KNOWN_GAPS.md)
- [flaws.md](flaws.md)

## 15. Verification Evidence Index

Primary evidence files:

- [docs/PROOF_DOSSIER.md](docs/PROOF_DOSSIER.md)
- [docs/THESIS.tex](docs/THESIS.tex)
- [docs/PUBLIC_API.md](docs/PUBLIC_API.md)
- [docs/CHANGELOG.md](docs/CHANGELOG.md)
- [docs/MIGRATION.md](docs/MIGRATION.md)
- [docs/ARCHITECTURE_NOTES.md](docs/ARCHITECTURE_NOTES.md)

Representative test suites:

- [tests/adversarial](tests/adversarial)
- [tests/integration](tests/integration)
- [tests/property](tests/property)
- [tests/unit](tests/unit)

## 16. Development Validation Commands

Core unit suite:

    pytest tests/unit -q

Full suite:

    pytest tests -q

Coverage gate:

    pytest --cov=pramanix --cov-branch --cov-fail-under=98

## 17. License

AGPL-3.0-only.

Commercial licensing for proprietary deployments: viraj@pramanix.dev
