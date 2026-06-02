# BLUEPRINT.md — Pramanix Architecture and Roadmap

> **Purpose**: Single canonical source for architectural decisions, implementation roadmap,
> and competitive positioning. Consolidates:
> - `docs/PRAMANIX_MASTER_BLUEPRINT.md` (construction manual)
> - `docs/PRAMANIX_BLUEPRINT_PART2.md`
> - `docs/Ideal_Architecture.md` (competitive gap analysis)
>
> **Last Updated**: 2026-06-02
> **Owner**: Viraj Jain

---

## The Single Driving Question

> *"Was this AI action formally proven safe — before execution — and can I produce a signed,
> tamper-evident, regulator-readable proof of that right now, in under 15 milliseconds?"*

No competitor in 2026 answers this. Pramanix is built to answer it.

---

## PART 1 — THE ARCHITECTURAL POSITION

### The Boundary Pramanix Governs

```
┌──────────────────────────────────────────────────────────────────┐
│  THE REAL WORLD                                                   │
│  (bank accounts, patient records, infrastructure, trades)        │
└─────────────────────────┬────────────────────────────────────────┘
                          │  State mutations
             ◄── PRAMANIX GOVERNS THIS BOUNDARY ──►
┌─────────────────────────┴────────────────────────────────────────┐
│  PRAMANIX — Formal Proof + Signed Audit Trail                    │
│  Guard.verify(intent, state) → Decision (proven, signed)         │
└─────────────────────────┬────────────────────────────────────────┘
     LangChain    LangGraph    LlamaIndex    NeMo    AutoGen
```

Pramanix **wraps** everything above it. It does not replace any framework. It is the gate
every agent action must pass through before touching real-world state.

### The Twelve Architectural Laws

These are CI-enforced invariants, not guidelines:

1. **Fail closed, always.** Any exception, timeout, or unknown state → BLOCK. Never ALLOW on uncertainty.
2. **No eval/exec/ast.parse.** Policy DSL compiles to a pure tree. Z3 sees AST, not strings.
3. **Every ALLOW is a proof.** The Z3 solver produces a satisfying assignment. Not "probably safe."
4. **Every BLOCK is a counterexample.** The solver produces the minimal violating assignment.
5. **Every decision is signed.** Ed25519/RS256/ES256 — callers can verify without Pramanix.
6. **Every decision is Merkle-chained.** Tamper-evident append-only log.
7. **No InMemory* in production.** `PRAMANIX_ENV=production` → `ConfigurationError`.
8. **No `unittest.mock.patch`.** Zero mock doubles. Real fakeredis. Real Z3. Real OTel.
9. **Solver DI via `solver_factory`.** The ONLY correct way to inject solver failures in tests.
10. **`model_dump()` before ProcessPoolExecutor.** Never pickle Pydantic models directly.
11. **`assert_and_track`, never bare `add`.** Unsat core attribution requires this.
12. **`google-re2` is required.** stdlib `re` is banned for regex operations.

---

## PART 2 — IMPLEMENTATION MAP (WHAT IS BUILT)

### Core Pipeline (`guard.py`, 1,674 lines)

8 phases in `Guard.verify(intent, state)`:

| Phase | What Happens | Fail Mode |
| ------- |-------------| ----------- |
| 0 | Input size guard (`max_input_bytes`) | BLOCK if oversized |
| 1 | Resolver cache population | BLOCK on resolver error |
| 2 | Pydantic validation (if `intent_model`/`state_model` set) | BLOCK on schema violation |
| 3 | State version check | BLOCK if state stale |
| 4 | Z3 solve (fast path → attribution) | BLOCK on timeout or violation |
| 5 | Governance gates (optional human-in-loop) | BLOCK if approval required |
| 6 | Timing jitter (if `allow_insecure_timing_leaks=False`) | Non-blocking |
| 7 | Ed25519 signing (if signer configured) | Non-blocking |
| 8 | Audit sinks + Merkle | Non-blocking |

### Decision Object (`decision.py`)

Immutable frozen dataclass. Wire format: **17 keys**.

```python
{
  "decision_id": "uuid4",
  "allowed": bool,
  "status": "SolverStatus.SAFE | UNSAFE | TIMEOUT | ERROR",
  "violated_invariants": ["label1", ...],
  "explanation": "str",
  "policy_hash": "sha256hex",
  "decision_hash": "sha256hex",
  "signature": "base64 | null",
  "timestamp": "ISO8601",
  "latency_ms": float,
  "model_id": "str | null",
  "intent_snapshot": {...},
  "state_snapshot": {...},
  "error_domain": "str | null",       # Phase 2 addition
  "stack_trace_hash": "str | null",   # Phase 2 addition
  "consensus_quorum": "int | null",
  "consensus_agreement": "float | null"
}
```

### Subsystems and Source Files

| Subsystem | Files | Lines | Status |
| ----------- |-------| ------- |--------|
| Guard pipeline | `guard.py`, `guard_config.py`, `guard_pipeline.py` | ~3,000 | Production |
| Transpiler | `transpiler.py` | 970 | Production |
| Solver | `solver.py` | 491 | Production |
| Policy DSL | `policy.py`, `expressions.py`, `compiler.py` | ~1,900 | Production |
| Cryptographic audit | `audit/`, `crypto.py` | ~1,500 | Production |
| Compliance oracle | `compliance/oracle.py` | 1,482 | Production |
| Circuit breaker | `circuit_breaker.py` | 1,340 | Production |
| Worker pool | `worker.py` | 1,018 | Production |
| NLP validators | `nlp/validators.py` | 775 | Beta (keyword/regex) |
| Translators | `translator/` (10 files) | ~3,500 | Production (where API available) |
| Integrations | `integrations/` (12 files) | ~4,000 | Beta |
| Primitives | `primitives/` (8 files) | ~2,000 | Production |
| Execution tokens | `execution_token.py` | ~1,200 | Production |
| IFC | `ifc/` | ~600 | Production |
| Oversight | `oversight/workflow.py` | ~800 | Beta (in-memory only) |
| Key providers | `key_provider.py` | ~800 | Production (3 cloud providers) |
| Fast path | `fast_path.py` | 297 | Production |

---

## PART 3 — COMPETITIVE POSITIONING

### The Honest Differentiation Matrix

| Capability | Pramanix | NeMo Guardrails | Guardrails AI | LangChain |
| ----------- |----------| ---------------- |---------------| ----------- |
| Formal verification | ✅ Z3 SMT | ❌ None | ❌ None | ❌ None |
| Deterministic ALLOW | ✅ Mathematical proof | ❌ Probabilistic | ❌ None | ❌ None |
| Counterexample on BLOCK | ✅ Z3 model | ❌ None | ❌ None | ❌ None |
| Audit trail with signatures | ✅ Ed25519/Merkle | ⚠️ Limited | ❌ None | ❌ None |
| Regulatory mapping (SOC2/HIPAA) | ✅ 31 built-in | ❌ None | ❌ None | ❌ None |
| fail-closed on error | ✅ All paths | ⚠️ Some | ❌ None | ❌ None |
| AGPL-compatible | ❌ Blocker | ✅ Apache-2.0 | ✅ Apache-2.0 | ✅ MIT |
| Community validator library | ❌ Limited | ✅ Many Colang | ✅ 50+ validators | ✅ Callbacks |
| LLM output validation | ⚠️ Basic NLP | ✅ Colang rules | ✅ Pydantic + validators | ✅ Output parsers |

### The Moat (What Competitors Cannot Copy)

1. **Z3 formal verification**: NeMo/Guardrails AI are probabilistic. Adding formal verification requires rebuilding their entire architecture. They cannot ship this without starting over.
2. **Counterexample attribution**: When Pramanix blocks, it tells you exactly which invariant was violated and with what values. No competitor does this.
3. **Cryptographic chain-of-custody**: Ed25519-signed, Merkle-chained decisions that remain verifiable after Pramanix is removed. Regulators can verify independently.
4. **Compliance oracle**: Direct mapping from Z3 invariant labels to SOC2/EU AI Act/HIPAA/NIST AI RMF/GDPR controls. No competitor has this.

### Honest Limitations vs Competitors

1. **Community validators**: NeMo has Colang. Guardrails AI has 50+ community validators. Pramanix has primitives (FinTech, Healthcare, RBAC) but no community plugin ecosystem.
2. **LLM output validation**: Guardrails AI is stronger for validating LLM output schemas. Pramanix validates intent before action — a different (and stronger) guarantee for agent safety.
3. **License**: AGPL-3.0 is a GA blocker for enterprise. NeMo (Apache-2.0) and Guardrails AI (Apache-2.0) have no such restriction.

---

## PART 4 — OPEN GAPS (PRIORITIZED)

### P1 — Critical (GA Blockers)

| Gap | Description | Resolution Path |
| ---- |-------------| ---------------- |
| P1-L | AGPL-3.0 license | Business decision: relicense or establish enterprise tier |
| P1-CI | LLM consensus CI | Commit API keys to CI secrets + run nightly |
| P1-DB | Persistent `ApprovalWorkflow` | DB schema design + asyncpg implementation |

### P2 — Important (Post-GA)

| Gap | Description |
| ---- |-------------|
| P2-ENC | Merkle archive encryption (plaintext today) |
| P2-ML | Real ML for ToxicityScorer (sentence-transformers) |
| P2-COMM | Community validator plugin ecosystem |
| P2-PPL | Pramanix Policy Language (YAML → DSL) improvements |

### P3 — Nice to Have

| Gap | Description |
| ---- |-------------|
| P3-BENCH | Publish verified benchmark results |
| P3-DOCS | API reference generated from docstrings |
| P3-CERT | Integration certification badges (LangChain, CrewAI, etc.) |

---

## PART 5 — ROADMAP

### v1.0.0 (Current — GA Target)

- [x] Z3 formal verification core
- [x] 8-phase guard pipeline
- [x] Cryptographic audit trail (Ed25519/RS256/ES256)
- [x] Compliance oracle (31 mappings, 5 frameworks)
- [x] Circuit breaker (distributed)
- [x] 10 LLM translators
- [x] 12 framework integrations
- [x] 5,687 tests / ≥98% coverage
- [ ] License decision
- [ ] Persistent ApprovalWorkflow
- [ ] Real LLM consensus CI

### v1.1.0 (Post-GA)

- [ ] Merkle archive encryption
- [ ] Real ML NLP (sentence-transformers)
- [ ] Community validator framework
- [ ] Published benchmark results
- [ ] Policy Language (YAML DSL) stable

### v2.0.0 (Future)

- [ ] Multi-region distributed audit
- [ ] Privacy-preserving proofs (ZK-SNARK)
- [ ] Policy marketplace
- [ ] Enterprise management dashboard

---

## PART 6 — DECISION LOG

Key architectural decisions made and why:

| Decision | Rationale | Date |
| ---------- |-----------| ------ |
| Z3 over LLM-as-judge | Determinism: Z3 proves; LLM guesses | Founding |
| AGPL-3.0 + commercial dual | Copyleft community + paid enterprise | Founding |
| python:3.11-slim (not Alpine) | z3-solver doesn't compile with musl libc | Early |
| `assert_and_track` over bare `add` | Unsat core needs tracking per-invariant | v0.5 |
| `threading.local` for Z3 context | Per-thread isolation; Z3 C lib is not thread-safe | v0.5 |
| `fakeredis` over `unittest.mock` | Real behavior (TTL, SETNX) tested | v0.8 |
| Zero-Mock Sprint | False confidence from mock doubles eliminated | v0.9 |
| `ClockProtocol` injection | Deterministic time in tests (no `time.time()` mocking) | v0.9 |
| `solver_factory` DI | Inject solver failures without patching Z3 C lib | v0.9 |
| `_DYNAMIC_POLICY_CACHE` LRU at 256 | Bound memory in multi-tenant deployments | v0.9 |
| `ForAll(allow_empty=False)` | Vacuous truth is a security vulnerability | v1.0 |
| `error_domain` + `stack_trace_hash` | Attribution without exposing stack traces | v1.0 |
| `ControlMapping` per-framework validation | Prevent fabricated control IDs | v1.0 |
| `default_oracle()` factory | Pre-built compliance mappings out-of-box | v1.0 |
