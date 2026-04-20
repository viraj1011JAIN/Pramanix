# Claims Matrix

Status values:
- `verified`
- `partially verified`
- `unverified`
- `wording too strong`

| claim | source file/section | evidence file/test/benchmark | status | action required |
|---|---|---|---|---|
| Every `ALLOW` has formal Z3 evidence and every `BLOCK` has violated invariant attribution | README.md Overview + architecture diagram | src/pramanix/solver.py, src/pramanix/decision.py, tests/unit/test_decision.py, tests/unit/test_guard.py | partially verified | Keep wording as "formal solver-backed decision"; avoid overpromising "proof" for all operational statuses (e.g. `ERROR`, `TIMEOUT`). |
| Fail-safe behavior: internal exceptions return blocked decision | README.md "Core Guarantees" | src/pramanix/guard.py, tests/adversarial/test_fail_safe_invariant.py, tests/unit/test_guard_dark_paths.py | verified | No change needed. |
| TOCTOU is not globally solved by verification alone | README.md Known Limitations | README.md limitation text, src/pramanix/execution_token.py docs/tests | verified | Keep limitation explicit in docs and examples. |
| Injection threshold in Phase 1 is hardcoded at 0.5 | README.md Known Limitations (pre-0.9.1 text) | src/pramanix/guard_config.py (`injection_threshold`), src/pramanix/guard.py parse path, tests/unit/test_guard.py, tests/unit/test_guard_dark_paths.py | wording too strong | Updated: threshold is configurable (`GuardConfig`/env), default `0.5`. |
| `VALIDATION_ERROR` is a public status value | README.md SolverStatus table (pre-0.9.1 text) | src/pramanix/decision.py (`VALIDATION_FAILURE`) and tests/unit/test_decision.py | unverified | Updated README to `VALIDATION_FAILURE`. |
| `INJECTION_BLOCKED` is a public status value | README.md SolverStatus table (pre-0.9.1 text) | src/pramanix/decision.py `SolverStatus` enum and src/pramanix/guard.py `parse_and_verify` mapping | unverified | Removed status-table claim; current behavior maps translator failures to `ERROR` except consensus mismatch. |
| `decision.signature` is bytes | README.md Decision Object (pre-0.9.1 text) | src/pramanix/decision.py (`signature: str | None`), tests/unit/test_crypto.py | unverified | Updated README type to `str | None`. |
| Process isolation recommendation (`async-process`) for production | README.md Known Limitations + docs/architecture.md | src/pramanix/worker.py lifecycle/recycle logic, tests/integration/test_process_mode.py | partially verified | Keep recommendation, but avoid claiming complete crash immunity across all host failure modes. |
| Distributed replay protection is available with Redis-backed verifier | README.md + docs/security.md + API docs | src/pramanix/execution_token.py (`RedisExecutionTokenVerifier`), tests/unit/test_redis_token.py | verified | No change needed; keep "recommended in production" wording. |
| Release workflow is SLSA-style with provenance/signing | CHANGELOG.md + .github/workflows/release.yml | .github/workflows/release.yml | verified | Add docs/release checklist and integrity process doc for user-facing transparency. |
| PyPI installability is fully proven in CI | repository-level claim intent | release.yml post-release smoke only; no CI wheel-install smoke in ci.yml | partially verified | Add CI job to build wheel/sdist and smoke-install from built wheel before release. |
| Compatibility policy/semver contract is documented | project release messaging | No `docs/api-compatibility.md` yet | unverified | Add `docs/api-compatibility.md` and contract tests for exports/schema in Phase 1.2. |
| Translator security is a binding guarantee | README + docs phrasing in some sections | src/pramanix/guard.py always runs Phase 2 verify after parse; adversarial tests under tests/adversarial | partially verified | Keep wording: "Phase 1 is heuristic pre-screening; Phase 2 is binding safety layer." |
| Compliance mappings are available (HIPAA/BSA/OFAC examples) | docs/compliance.md | docs/compliance.md, tests/unit/test_compliance_reporter.py | verified | Keep as implementation examples, not certification claim. |
| Z3 encoding scope — Z3 verifies submitted values only, not data accuracy, invariant completeness, or executor intent | README.md Known Limitations + docs/architecture.md §12 | Design limitation; no direct unit test | verified | Keep explicit in Known Limitations and architecture.md §12. |
| Z3 string theory performance — `String` sort (sequence theory) is slower than arithmetic sorts; prefer int-encoded enumerations | README.md Known Limitations | No benchmark test; documented guidance only | verified | Add to architecture.md §12; tune `solver_timeout_ms` when string constraints are required. |
| Merkle anchor is process-scoped without `PersistentMerkleAnchor` — `root_hash` is lost on crash | README.md Known Limitations + docs/security.md H05 | tests/unit/test_hardening.py H05 checkpoint tests | verified | Keep limitation explicit; require `PersistentMerkleAnchor` + append-only callback in production deployments. |
| Small LLM models (< ~3B params) cannot reliably perform structured intent extraction | README.md Known Limitations | No automated test (requires LLM runtime) | unverified | Add to architecture.md §12; warn users to use `llama3.2` (3B+) or a hosted model for Phase 1. |

## Notes

- This matrix intentionally separates protocol-level guarantees from operational assumptions.
- Claims marked `partially verified`, `unverified`, or `wording too strong` must be resolved before making stronger public "production-grade" statements.
