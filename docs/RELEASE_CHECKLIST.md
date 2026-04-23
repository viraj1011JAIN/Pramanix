# Release Checklist

**Pramanix 1.0.0** — Steps required before every release.

These gates are not optional. Each item exists because a past failure mode was discovered — it is not here for ceremony.

---

## CI Gates (must be green on the release commit)

All 9 CI jobs must pass. The dependency chain is:

```
sast → alpine-ban → lint-typecheck → test → coverage → wheel-smoke → extras-smoke → trivy → license-scan
```

If any job fails, the release is blocked.

### Job 1 — SAST
- `pip-audit` — zero known CVEs in installed deps. To accept a CVE with a documented rationale, add `--ignore-vuln VULN-ID` and record the justification in ci.yml.
- `bandit -ll -ii` — zero HIGH/CRITICAL severity findings.
- `semgrep` — zero ERROR-level findings across `p/python`, `p/security-audit`, `p/owasp-top-ten`.
- Secrets scan — no hardcoded API keys or signing keys in `*.py`, `*.yml`, `*.yaml`, `*.toml` (excluding `tests/`).

### Job 2 — Alpine ban
- All `Dockerfile.*` files (except `Dockerfile.test`) must use glibc base images. Alpine/musl causes Z3 segfaults.
- `docker-compose*.yml` and `deploy/` must contain no Alpine/musl references.

### Job 3 — Lint + Type check
- `ruff check src/ tests/` — zero violations.
- `ruff format --check src/ tests/` — no formatting drift.
- `mypy src/pramanix/ --strict` — zero errors.

### Job 4 — Test Gauntlet
Tests run in order. Each step must pass before the next runs.

1. `pytest tests/unit/` — all unit tests pass.
2. `pytest tests/integration/` — all integration tests pass.
3. `pytest tests/property/ --hypothesis-seed=0` — all property-based tests pass under the CI hypothesis profile.
4. `pytest tests/adversarial/` — all adversarial security tests pass.
5. `pytest tests/perf/ -m "not slow"` — performance tests pass (main branch only; PR jobs continue-on-error).

The full test run (`poetry install --with dev --extras all`) must install successfully. The test matrix is Python 3.13 only.

### Job 5 — Coverage gate
- `coverage report --fail-under=95` — branch coverage ≥ 95%.
- Codecov delta ≤ -0.5% from the previous baseline (enforced by `codecov.yml`).

### Job 6 — Wheel smoke
- `poetry build` produces a `.whl` and a `.tar.gz` in `dist/`.
- Clean venv install from the `.whl` (no dev deps, no source tree). Verifies that:
  - All names in `pramanix.__all__` are importable.
  - `pramanix.__version__` is present and non-empty.
  - A minimal `Guard.verify()` call returns `allowed=True` (not just importable — also runnable).
- Clean venv install from the `.tar.gz` verifies the sdist is buildable.

### Job 7 — Extras smoke
- Installs the wheel with each advertised extra in an isolated venv and verifies that the key module is importable.
- All extras listed in `pyproject.toml [project.optional-dependencies]` must pass.

### Job 8 — Trivy
- Builds `Dockerfile.production` and scans it.
- Zero CRITICAL or HIGH CVEs. `ignore-unfixed: true` (unfixed CVEs are excluded).

### Job 9 — License scan
- All dependency licenses must be in the allowlist: MIT, Apache-2.0, BSD-2/3, LGPL-2.1/3, PSF, ISC, MPL-2.0.
- AGPL-3.0-only (Pramanix itself) is explicitly permitted.
- `GPL-2.0-only` and `UNKNOWN` are blocked.

---

## Nightly Benchmark Gate

The nightly CI job (02:00 UTC, schedule trigger) runs `benchmarks/latency_benchmark.py`.

- P99 latency < 15 ms — hard gate.
- Benchmark is not run on PRs by default (only on `main` and nightly schedule).
- If the nightly gate fails, **do not release until it is fixed**. A P99 regression above 15 ms means the Guard is no longer within contract.

---

## Pre-release Checklist (manual)

### Version bump
- [ ] `pyproject.toml`: bump `version = "X.Y.Z"` to the new version.
- [ ] `src/pramanix/__init__.py`: bump `__version__ = "X.Y.Z"` to match.
- [ ] Confirm `[project] classifiers` contains `Development Status :: 5 - Production/Stable`. (Already correct for 1.0.0.)
- [ ] Run `poetry check --lock` — lock file must be consistent.

### Stability contract review
- [ ] Confirm `__stability__` in `__init__.py` reflects any changed surfaces. If a beta surface became stable, update the dict and document the decision in DECISIONS.md.
- [ ] Confirm `__all__` in `__init__.py` reflects any new public names.

### API contract test
- [ ] `pytest tests/unit/test_api_contract.py -v` passes. This test enforces that `__all__` matches `_EXPECTED_ALL`. If you added a new public name, update `_EXPECTED_ALL` in that test file.

### `pramanix doctor` check
- [ ] Run `PRAMANIX_ENV=production pramanix doctor --strict` on the release environment. Exit code must be 0.
- [ ] Run `pramanix doctor --json` and verify all checks pass.

### Manual smoke test against production config
- [ ] Install the wheel from `dist/` into a clean environment.
- [ ] Run a `Guard.verify()` call with `PRAMANIX_ENV=production` and a configured signer + audit sink. Confirm:
  - No `UserWarning` is emitted (all production-safety checks pass).
  - Decision is signed (`decision.signature` is non-empty).
  - Audit sink receives the decision.

---

## PyPI Publish

**Current status: Not published.** Version 1.0.0 is not on PyPI. The release workflow must be set up before publishing.

When ready to publish:

1. Create a PyPI API token and store it in `PYPI_API_TOKEN` GitHub secret.
2. Create a GitHub release from the release tag. The publish workflow (if present in `.github/workflows/`) should trigger automatically.
3. If no publish workflow exists yet, run manually:
   ```bash
   poetry publish --build
   ```
4. After publish, verify the package installs from PyPI:
   ```bash
   pip install pramanix==X.Y.Z
   python -c "import pramanix; print(pramanix.__version__)"
   ```
5. Update any README badges that reference the version or PyPI status.

---

## Post-release

- [ ] Tag the release commit: `git tag vX.Y.Z && git push origin vX.Y.Z`.
- [ ] Confirm CI passes on the tag.
- [ ] If any stable API was changed without a major bump, this is a breaking change. Create a hotfix or revert before continuing.
