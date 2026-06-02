# RELEASE_READINESS.md — Pramanix v1.0.0 GA Gate Checklist

> **Purpose**: Binary pass/fail checklist for v1.0.0 GA release.
> Every item must be ✅ before tagging `v1.0.0` on PyPI.
> No item may be marked ✅ without evidence. "Aspirational" = NOT ✅.
>
> **Last Updated**: 2026-06-02
> **Target**: PyPI v1.0.0 release

---

## BLOCKING — Must be ✅ before release

### License

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| L1 | License decision (AGPL-3.0 vs Apache-2.0) | ❌ BLOCKED | Business/legal decision required |
| L2 | `LICENSE` file present and accurate | ✅ | `LICENSE` file exists, AGPL-3.0-only |
| L3 | `LICENSE-COMMERCIAL` file present | ✅ | Dual-license model documented |
| L4 | PyPI license classifier matches file | ✅ | `pyproject.toml:25-26` has both AGPL + proprietary classifiers |

### Code Quality

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| C1 | All unit + adversarial + property tests pass | ⚠️ Check | Run before release |
| C2 | Coverage ≥ 98% (`fail_under = 98`) | ⚠️ Check | `pyproject.toml:393` |
| C3 | mypy strict — 0 errors | ⚠️ Check | `pyproject.toml:154-155` |
| C4 | ruff lint — 0 violations | ⚠️ Check | `pyproject.toml:266` |
| C5 | `# type: ignore` (16 in 9 files) | ⚠️ | All legitimate: lazy optional imports + mypy inference limits. Audit 2026-06-02. |
| C6 | 0 `# pragma: no cover` in production source | ✅ | Verified in deep audit |
| C7 | 0 `unittest.mock.patch`/`MagicMock` in tests | ✅ | Zero-Mock Sprint `a0ee71c` |
| C8 | `assert_and_track` used (not bare `add`) | ✅ | `solver.py:395` |

### Packaging

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| P1 | `pyproject.toml` metadata complete | ✅ | Name, version, authors, description, classifiers |
| P2 | All extras accurate (no phantom dependencies) | ✅ | `pyproject.toml:86-128` |
| P3 | `pramanix.scripts` entry point works | ⚠️ Check | `pramanix = "pramanix.cli:main"` |
| P4 | Wheel builds without error | ✅ | 570KB, 119 files, verified 2026-06-02 |
| P5 | `pip install pramanix` smoke test passes | ⚠️ Check | Run in clean venv (not yet done) |
| P6 | `pip install 'pramanix[all]'` smoke test passes | ⚠️ Check | Run in clean venv (not yet done) |
| P7 | `setup.cfg` consistent with `pyproject.toml` | ✅ | setup.cfg has only `[mypy]` compat |
| P8 | `MANIFEST.in` accurate (if needed) | N/A | Poetry handles MANIFEST |
| P9 | No dev files included in wheel | ⚠️ Check | Verify `poetry build` output |

### Security

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| S1 | Trivy container scan: 0 critical/high CVEs | ⚠️ Check | CI job: `trivy` |
| S2 | pip-audit: 0 known vulnerabilities | ⚠️ Check | CI job: `license-scan` |
| S3 | SAST (bandit/semgrep): 0 high severity | ⚠️ Check | CI job: `sast` |
| S4 | No secrets in repository history | ⚠️ Check | `git log --all -S 'sk-'` etc. |
| S5 | `PRAMANIX_ENV=production` blocks InMemory* | ✅ | All 4 guards verified |
| S6 | `result_seal_key` injectable | ✅ | `guard_config.py:528` Phase 1 fix |
| S7 | Nonce replay prevention | ✅ | `verify_async` Phase 1 fix |
| S8 | fail-closed on all error paths | ✅ | `_verify_core()` blanket catch |
| S9 | `ForAll(empty_array)` not vacuously true | ✅ | Phase 3 STOP 4 fix |
| S10 | `ControlMapping.control_id` validated | ✅ | Phase 4 fix |
| S11 | Alpine Docker banned | ✅ | CI: alpine-ban job |
| S12 | Docker runs as non-root | ✅ | `Dockerfile.production` |
| S13 | Docker has HEALTHCHECK | ✅ | `Dockerfile.production` |

### API Surface

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| A1 | `pramanix.__all__` count locked (157 exports) | ✅ | `test_api_contract.py` |
| A2 | `Decision.to_dict()` has 17 keys | ✅ | `test_api_contract.py` |
| A3 | `GuardConfig` has 32 fields | ✅ | `test_api_contract.py` |
| A4 | `SolverStatus` has 9 members | ✅ | `test_api_contract.py` |
| A5 | All `__all__` exports importable | ✅ | `test_api_contract.py` |
| A6 | CHANGELOG.md up-to-date | ⚠️ Check | Verify all commits since last entry |

### Documentation

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| D1 | `README.md` source-verified (no aspirational claims) | ✅ | Verified in deep audit Pass 4 |
| D2 | `ENVIRONMENT.md` complete | ✅ | Created 2026-06-02 |
| D3 | `REPO_AUDIT.md` complete | ✅ | Created 2026-06-02 |
| D4 | `BLUEPRINT.md` complete | ⚠️ In progress | Phase 0 work |
| D5 | `WHITEPAPER.md` complete | ⚠️ In progress | Phase 0 work |
| D6 | CLI help text accurate for all subcommands | ⚠️ Check | `pramanix --help` |
| D7 | Known gaps documented honestly | ✅ | `REPO_AUDIT.md` Part 3 |

---

## NON-BLOCKING — Must have plan, not necessarily done

### Performance

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| F1 | Benchmark baseline captured | ⚠️ Pending | `BENCHMARK_STATUS.md` |
| F2 | Latency targets documented | ⚠️ Pending | targets not measured production values |
| F3 | Memory stability tests pass | ⚠️ Check | `tests/perf/test_memory_stability.py` |

### Enterprise Features

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| E1 | `ApprovalWorkflow` durability (DB-backed) | ❌ Not done | Documented gap; in-memory only |
| E2 | LLM consensus real-CI evidence | ❌ Not done | No API keys in standard CI |
| E3 | Merkle archive encryption | ❌ Not done | Compression only; documented |
| E4 | Commercial support tier defined | ❌ Not done | Business decision |

---

## RELEASE PROCEDURE

1. Verify all BLOCKING items are ✅
2. Run `poetry build` → verify wheel contents
3. Run `pip install dist/pramanix-1.0.0-py3-none-any.whl` in clean venv
4. Run smoke test: `python -c "import pramanix; print(pramanix.__version__)"`
5. Tag `v1.0.0` in git
6. `poetry publish --repository pypi`
7. Create GitHub Release with CHANGELOG.md entry as body
8. Update `WORK_LEDGER.md` with release date

---

## BLOCKING COUNT SUMMARY

| Category | ✅ Done | ⚠️ Check | ❌ Blocked |
|----------|---------|----------|-----------|
| License | 3 | 0 | 1 |
| Code Quality | 5 | 4 | 0 |
| Packaging | 4 | 5 | 0 |
| Security | 10 | 4 | 0 |
| API Surface | 5 | 1 | 0 |
| Documentation | 3 | 4 | 0 |
| **Total** | **30** | **18** | **1** |

**Hard blockers**: L1 (license) — requires business decision.
**Soft blockers**: 18 items require verification runs (code quality, packaging smoke test, CI check).
